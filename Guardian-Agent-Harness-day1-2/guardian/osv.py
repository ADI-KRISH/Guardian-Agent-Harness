import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from .detectors import finding


def request(payload):
    req = urllib.request.Request('https://api.osv.dev/v1/query', data=json.dumps(payload).encode(), headers={'Content-Type':'application/json','User-Agent':'GuardianAI/0.1'})
    with urllib.request.urlopen(req, timeout=12) as response:
        raw = response.read(8*1024*1024+1)
        if len(raw)>8*1024*1024: raise ValueError('OSV response exceeded size budget')
        return json.loads(raw)


def query(node, store, offline=False):
    key = 'osv:' + str(node['ecosystem']) + ':' + node['name'] + ':' + node['version']
    cached = store.cached(key)
    if cached is not None: return cached, 'cached'
    if offline: return [], 'unavailable (offline; no fresh cache)'
    payload = {'package':{'name':node['name'],'ecosystem':node['ecosystem']},'version':node['version']}
    advisories = []
    for _ in range(12):
        page = request(payload); advisories.extend(page.get('vulns',[]))
        if not page.get('next_page_token'):
            store.cache(key,advisories); return advisories, 'live'
        payload['page_token'] = page['next_page_token']
    raise ValueError('OSV pagination budget exhausted')


def scan(graph, store, offline=False):
    findings, coverage, unique = [], [], {}
    for n in graph['nodes']:
        if n['type'] != 'package': continue
        if not n.get('ecosystem') or n.get('resolved') is False or not re.fullmatch(r'v?\d[\w.+!\-]*',n['version']):
            coverage.append({'component':n['id'],'status':'unresolved version or unsupported ecosystem'})
        else: unique.setdefault((n['ecosystem'],n['name'],n['version']),[]).append(n)
    items=list(unique.values())
    if len(items)>10000:
        for nodes in items[10000:]:
            coverage.extend({'component':n['id'],'status':'query budget exceeded'} for n in nodes)
        items=items[:10000]
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = {pool.submit(query,nodes[0],store,offline):nodes for nodes in items}
        for future in as_completed(jobs):
            nodes=jobs[future]
            try: advisories,status=future.result()
            except Exception as exc: advisories,status=[], 'failed: '+str(exc)[:180]
            for n in nodes:
                coverage.append({'component':n['id'],'status':status})
                for advisory in advisories:
                    if advisory.get('withdrawn'): continue
                    severity=str(advisory.get('database_specific',{}).get('severity','Unknown')).title()
                    if severity == 'Moderate': severity='Medium'
                    if severity not in ('Critical','High','Medium','Low'): severity='Unknown'
                    fixes=set()
                    for affected in advisory.get('affected',[]):
                        pkg=affected.get('package',{})
                        if pkg.get('name')!=n['name'] or pkg.get('ecosystem')!=n['ecosystem']: continue
                        for r in affected.get('ranges',[]):
                            for event in r.get('events',[]):
                                if event.get('fixed'): fixes.add(event['fixed'])
                    f=finding('known-vulnerability',advisory.get('summary') or advisory['id'],'known CVE',severity,n['file'],n.get('line',1),advisory['id'],n['id'],advisory=advisory['id'],aliases=advisory.get('aliases',[]),fix_versions=sorted(fixes),references=advisory.get('references',[]),cvss=advisory.get('severity',[]))
                    f['id'] += '-' + advisory['id']
                    f['verified_evidence']=[{'tool':'OSV API','kind':'verified','advisory':advisory['id'],'package':n['name'],'version':n['version'],'source':status}]
                    f['score_explanation'] += '; raw CVSS retained; missing qualitative severity remains Unknown'
                    findings.append(f)
    return findings,coverage
