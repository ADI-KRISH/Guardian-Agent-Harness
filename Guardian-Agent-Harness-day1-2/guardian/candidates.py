"""Validate advisory candidates against public registries and OSV, not example versions."""
from urllib.parse import quote
from .references import metadata
from . import osv


def choose(node, finding, store, parse_version):
    current = parse_version(node.get('version'))
    if current is None: raise ValueError('Version ordering is unsupported for this ecosystem/version')
    # Query current identity again, using only the OSV cache while fresh (24 hours).
    advisories, status = osv.query(node, store)
    if status not in ('live', 'cached'): raise ValueError('Advisory lookup unavailable')
    fixes = set()
    matched = False
    ids = {finding.get('advisory'), *finding.get('aliases', [])} - {None}
    for advisory in advisories:
        if advisory.get('withdrawn'): continue
        if ids & {advisory['id'], *advisory.get('aliases', [])}: matched = True
        for affected in advisory.get('affected', []):
            package = affected.get('package', {})
            if package.get('name') != node['name'] or package.get('ecosystem') != node['ecosystem']: continue
            for interval in affected.get('ranges', []):
                if interval.get('type') == 'GIT': continue
                fixes.update(e['fixed'] for e in interval.get('events', []) if e.get('fixed'))
    if not matched: raise ValueError('Original advisory is no longer matched; rescan before recommending a change')
    # A release fixing the original advisory may introduce a different advisory.
    # Also consider the registry's current stable release, then verify it the same way.
    if node['ecosystem'] in ('npm','PyPI'):
        latest_url = ('https://registry.npmjs.org/'+quote(node['name'],safe='')+'/latest' if node['ecosystem']=='npm' else 'https://pypi.org/pypi/'+quote(node['name'],safe='')+'/json')
        try:
            latest, _ = metadata(latest_url)
            latest_version = latest.get('version') if node['ecosystem']=='npm' else latest.get('info',{}).get('version')
            if latest_version: fixes.add(latest_version)
        except (OSError,ValueError):
            pass  # Advisory candidates still require their individual registry checks.
    candidates = sorted((v for v in fixes if parse_version(v) is not None and parse_version(v) > current), key=parse_version)
    attempts = []
    for target in candidates[:12]:
        if node['ecosystem'] == 'npm':
            url = 'https://registry.npmjs.org/'+quote(node['name'], safe='')+'/'+quote(target, safe='')
        elif node['ecosystem'] == 'PyPI':
            url = 'https://pypi.org/pypi/'+quote(node['name'], safe='')+'/'+quote(target, safe='')+'/json'
        else: raise ValueError('Registry verification adapter is not implemented for this ecosystem')
        package, _ = metadata(url)
        if node['ecosystem'] == 'npm':
            exists = package.get('version') == target and not package.get('deprecated')
        else:
            exists = package.get('info', {}).get('version') == target and any(not f.get('yanked') for f in package.get('urls', []))
        if not exists:
            attempts.append({'version':target,'result':'release unavailable, deprecated or yanked'}); continue
        remaining, candidate_status = osv.query(dict(node, version=target), store)
        remaining = [a for a in remaining if not a.get('withdrawn')]
        attempts.append({'version':target,'remaining_advisories':[a['id'] for a in remaining]})
        if candidate_status in ('live', 'cached') and not remaining:
            return target, {'registry':url, 'advisories':candidate_status, 'result':'No known advisories returned for candidate identity; runtime compatibility unverified', 'attempts':attempts}
    raise ValueError('No verified candidate found among advisory boundaries and the current stable release (maximum 12 candidates); attempts: '+str(attempts))
