#!/usr/bin/env python3
"""Independently compare GuardianAI dependency findings with live OSV advisories.
Requires: pip install requests
Usage: python verify_guardian.py guardian-report.json --out verification
"""
import argparse, collections, csv, json, pathlib, time
import requests

API = 'https://api.osv.dev/v1'

def request_json(session, method, url, **kwargs):
    for attempt in range(5):
        try:
            r = session.request(method, url, timeout=40, **kwargs)
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(min(2 ** attempt, 20)); continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException:
            if attempt == 4: raise
            time.sleep(min(2 ** attempt, 20))
    raise RuntimeError('OSV request failed: ' + url)

def advisory_match(gid, actual, alias_map):
    # Exact identity must win over another advisory's overlapping alias list.
    if gid in actual:
        return gid
    return next((oid for oid in sorted(actual) if gid in alias_map.get(oid, {oid})), None)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', help='GuardianAI JSON export')
    p.add_argument('--out', default='verification', help='Output directory')
    p.add_argument('--batch-size', type=int, default=100)
    args = p.parse_args()
    data = json.loads(pathlib.Path(args.report).read_text(encoding='utf-8'))
    output = pathlib.Path(args.out); output.mkdir(parents=True, exist_ok=True)

    # Distinct package/version identities; repeated node_modules installations
    # do not inflate vulnerability precision/recall.
    packages = {}
    for node in data.get('graph', {}).get('nodes', []):
        if node.get('type') != 'package': continue
        eco, name, version = node.get('ecosystem'), node.get('name'), node.get('version')
        if eco and name and version and node.get('resolved', True):
            packages[(eco, name, version)] = True
    if not packages:
        raise SystemExit('No resolved packages found under graph.nodes')

    # Guardian findings are linked to the exact graph component ID.
    nodes_by_id = {n.get('id'): n for n in data['graph']['nodes']}
    guardian = collections.defaultdict(set)
    unresolved = []
    for f in data.get('findings', []):
        if f.get('rule') != 'known-vulnerability' and f.get('category') != 'known CVE':
            continue
        n = nodes_by_id.get(f.get('component'))
        if not n:
            unresolved.append(f.get('id')); continue
        key = (n.get('ecosystem'), n.get('name'), n.get('version'))
        if key not in packages:
            unresolved.append(f.get('id')); continue
        advisory = f.get('advisory')
        if advisory:
            guardian[key].add(advisory)
        else:
            unresolved.append(f.get('id'))

    session = requests.Session()
    session.headers.update({'User-Agent': 'GuardianAI-independent-evaluation/1.0'})
    keys = sorted(packages)
    osv = collections.defaultdict(set)
    errors = {}
    print(f'Checking {len(keys)} unique resolved package/version identities against live OSV...')
    size = max(1, min(args.batch_size, 1000))
    for start in range(0, len(keys), size):
        chunk = keys[start:start+size]
        queries = [{'package': {'ecosystem': eco, 'name': name}, 'version': version}
                   for eco, name, version in chunk]
        try:
            result = request_json(session, 'POST', API + '/querybatch', json={'queries': queries})
            matches = result.get('results', [])
            if len(matches) != len(chunk):
                raise ValueError('OSV returned an unexpected number of results')
            for key, entry in zip(chunk, matches):
                osv[key].update(v['id'] for v in entry.get('vulns', []) if v.get('id'))
        except Exception as e:
            for key in chunk: errors[key] = str(e)
        print(f'  {min(start+size, len(keys))}/{len(keys)} checked')

    # Advisory aliases are needed to match GHSA IDs to CVE IDs. OSV batch
    # responses contain only IDs, so fetch details for distinct matched IDs.
    all_ids = sorted(set().union(*osv.values()) if osv else set())
    alias_map = {}
    detail_errors = []
    print(f'Resolving aliases for {len(all_ids)} OSV advisory IDs...')
    for i, advisory in enumerate(all_ids):
        try:
            detail = request_json(session, 'GET', API + '/vulns/' + advisory)
            alias_map[advisory] = set([advisory] + detail.get('aliases', []))
        except Exception as e:
            alias_map[advisory] = {advisory}
            detail_errors.append({'id': advisory, 'error': str(e)})
        if (i+1) % 100 == 0: print(f'  {i+1}/{len(all_ids)} aliases resolved')

    rows = []
    for key in keys:
        eco, name, version = key
        actual = osv.get(key, set())
        reported = guardian.get(key, set())
        if key in errors:
            rows.append({'ecosystem':eco,'package':name,'version':version,
                         'status':'UNVERIFIED','guardian_id':'','osv_id':'',
                         'details':errors[key]})
            continue
        matched_osv = set()
        for gid in sorted(reported):
            found = advisory_match(gid, actual, alias_map)
            if found:
                matched_osv.add(found)
                status, details = 'TP', 'Guardian advisory matches OSV ID or alias'
            else:
                status, details = 'FP_CANDIDATE', 'Not found in current OSV response; manually review'
            rows.append({'ecosystem':eco,'package':name,'version':version,
                         'status':status,'guardian_id':gid,'osv_id':found or '',
                         'details':details})
        for oid in sorted(actual - matched_osv):
            rows.append({'ecosystem':eco,'package':name,'version':version,
                         'status':'FN_CANDIDATE','guardian_id':'','osv_id':oid,
                         'details':'OSV advisory not matched by GuardianAI; manually review'})

    counts = collections.Counter(r['status'] for r in rows)
    tp, fp, fn = (counts[x] for x in ('TP','FP_CANDIDATE','FN_CANDIDATE'))
    summary = {
        'repository': data.get('repo'), 'scan_id': data.get('id'),
        'unique_resolved_package_versions': len(keys),
        'guardian_total_findings': len(data.get('findings', [])),
        'guardian_known_vulnerability_findings': sum(
            f.get('rule') == 'known-vulnerability' or f.get('category') == 'known CVE'
            for f in data.get('findings', [])),
        'guardian_unique_package_advisory_pairs': sum(map(len, guardian.values())),
        'osv_unique_package_advisory_pairs': sum(map(len, osv.values())),
        'counts': dict(counts),
        'provisional_precision': round(tp/(tp+fp), 4) if tp+fp else None,
        'provisional_recall': round(tp/(tp+fn), 4) if tp+fn else None,
        'unresolved_guardian_findings': unresolved,
        'osv_query_errors': len(errors), 'osv_advisory_detail_errors': detail_errors,
        'limitations': [
            'OSV is an independent advisory reference, not a complete ground truth.',
            'FP_CANDIDATE and FN_CANDIDATE require manual adjudication.',
            'Metrics count distinct ecosystem/package/version/advisory pairs, not file occurrences.',
            'Different advisory aliases may lead to remaining duplicate matches.',
            'Non-CVE findings (CI, typosquat, install scripts, backdoors) are excluded.',
            'This checks the inventory from GuardianAI; missing dependencies cannot be measured.',
            'OSV results are current, not a historical snapshot of the original scan.'
        ]
    }
    with (output/'comparison.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=['ecosystem','package','version','status',
                                                'guardian_id','osv_id','details'])
        writer.writeheader(); writer.writerows(rows)
    (output/'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print('\nResults:', json.dumps({k: summary[k] for k in
          ('unique_resolved_package_versions','guardian_known_vulnerability_findings',
           'guardian_unique_package_advisory_pairs','osv_unique_package_advisory_pairs',
           'counts','provisional_precision','provisional_recall','osv_query_errors')}, indent=2))
    print('\nSaved:', output/'comparison.csv', 'and', output/'summary.json')

if __name__ == '__main__': main()
