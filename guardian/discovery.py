"""Bounded, non-executing inventory readers. Unknown edges are never invented."""
import hashlib
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote
from .formats import parse_extra, sibling

EXCLUDED = {'.git', 'node_modules', '.guardian-python', '.venv', 'venv', '__pycache__', '.guardian', 'dist', 'build', '.next'}
MAX_FILES = 12000
MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_TOTAL_SIZE = 64 * 1024 * 1024


def read_tree(root):
    files, warnings, total, count = {}, [], 0, 0
    for folder, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(folder) / d).is_symlink())
        for name in sorted(names):
            p = Path(folder) / name
            rel = p.relative_to(root).as_posix()
            count += 1
            if count > MAX_FILES:
                warnings.append('File-count limit reached; inventory is incomplete')
                return files, warnings
            if p.is_symlink() or not p.is_file():
                warnings.append(f'Skipped symbolic link or special file: {rel}')
                continue
            size = p.stat().st_size
            if size > MAX_FILE_SIZE or total + size > MAX_TOTAL_SIZE:
                warnings.append(f'Size budget exceeded: {rel}')
                continue
            raw = p.read_bytes()
            total += len(raw)
            files[rel] = {'hash': hashlib.sha256(raw).hexdigest(), 'size': len(raw), 'text': raw.decode('utf-8', errors='replace') if b'\0' not in raw else ''}
    return files, warnings


def discover(root, files):
    nodes = {'app': {'id': 'app', 'name': root.name, 'version': '', 'type': 'application', 'direct': True}}
    edges, warnings, edge_keys = [], [], set()
    line_cache={}
    def component(name, version, eco, location, **extra):
        purl_name = name.replace(':', '/', 1) if eco == 'Maven' else name
        exact = bool(re.fullmatch(r'v?\d[\w.+!\-]*', str(version)))
        purl = f'pkg:{dict(npm="npm", PyPI="pypi", Maven="maven", Go="golang", **{"crates.io":"cargo","Pub":"pub","NuGet":"nuget"}).get(eco, eco.lower())}/{quote(purl_name, safe="/")}' + ('@' + quote(str(version), safe='.') if exact else '')
        key = purl + '#' + location
        source=location.split('#')[0]
        info=files.get(source,{})
        if source not in line_cache:
            source_lines=info.get('text','').splitlines()
            key_lines={}
            for i,l in enumerate(source_lines,1):
                m=re.match(r'\s*"([^"]+)"\s*:',l)
                if m:key_lines.setdefault(m[1],i)
            line_cache[source]=(source_lines,key_lines)
        lines,key_lines=line_cache[source]
        locator=location.split('#',1)[1] if '#' in location else name
        line=key_lines.get(locator) or key_lines.get(name)
        if line is None: line=next((i for i,l in enumerate(lines,1) if name in l),1)
        metadata={'line':line,'resolved':exact,'declaration':str(version) if not exact else None,'generated':bool(info.get('generated')),'source_manifest':info.get('source_manifest'),'artifact':info.get('artifact'),'evidence_excerpt':lines[line-1][:500] if lines else ''}
        nodes[key] = dict(id=key, purl=purl, name=name, version=str(version), ecosystem=eco, type='package', file=location.split('#')[0], direct=False, **metadata, **extra)
        return key
    def edge(source, target, relation='depends_on'):
        if source != target and (source,target,relation) not in edge_keys:
            edge_keys.add((source,target,relation))
            edges.append(dict(source=source, target=target, relation=relation))
    for file, info in sorted(files.items(), key=lambda item: (Path(item[0]).name=='go.sum',item[0])):
        name = Path(file).name
        try:
            if parse_extra(file,files,component,edge,nodes,warnings):
                continue
            if name in ('package-lock.json', 'npm-shrinkwrap.json'):
                data = json.loads(info['text']); packages = data.get('packages')
                if packages is None:
                    warnings.append(f'{file}: lockfile v1 unsupported; generate v2/v3 for reliable edges')
                    continue
                locations = {}
                for loc, pkg in packages.items():
                    if not loc or pkg.get('link'):
                        continue
                    package_name = pkg.get('name') or loc.rsplit('node_modules/', 1)[-1]
                    locations[loc] = component(package_name, pkg.get('version', 'unresolved'), 'npm', file + '#' + loc, integrity=pkg.get('integrity'), install_script=bool(pkg.get('hasInstallScript')), dev=bool(pkg.get('dev')))
                def resolve(loc, dep):
                    current = loc
                    while True:
                        candidate = (current + '/' if current else '') + 'node_modules/' + dep
                        if candidate in locations:
                            return locations[candidate]
                        if not current:
                            return None
                        current = current.rsplit('/node_modules/', 1)[0] if '/node_modules/' in current else ''
                for loc, pkg in packages.items():
                    parent = locations.get(loc, 'app' if not loc else None)
                    if not parent:
                        continue
                    deps = dict(pkg.get('dependencies', {}), **pkg.get('optionalDependencies', {}))
                    if not loc:
                        deps.update(pkg.get('devDependencies', {}))
                    for dep in deps:
                        target = resolve(loc, dep)
                        if target:
                            edge(parent, target)
                            if not loc: nodes[target]['direct'] = True
                        elif dep not in pkg.get('optionalDependencies', {}):
                            warnings.append(f'{file}: unresolved dependency edge {loc or "app"} → {dep}')
            elif name == 'package.json' and not any(str(Path(file).parent / lock).removeprefix('./') in files for lock in ('package-lock.json', 'npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml')):
                data = json.loads(info['text'])
                for dep, version in {**data.get('dependencies', {}), **data.get('devDependencies', {})}.items():
                    key = component(dep, version, 'npm', file + '#' + dep, dev=dep in data.get('devDependencies', {}) and dep not in data.get('dependencies', {}))
                    nodes[key]['direct'] = True; edge('app', key)
                warnings.append(f'{file}: no npm lockfile; transitive dependencies unavailable and ranges are not resolved')
            elif name.startswith('requirements') and name.endswith('.txt'):
                for line_no, line in enumerate(info['text'].splitlines(), 1):
                    if not line.strip() or line.lstrip().startswith('#'): continue
                    match = re.match(r'^\s*([\w.-]+)(?:\[[^]]+\])?\s*==\s*([\w.+!-]+)', line)
                    if match:
                        dep, version = match.groups(); key = component(re.sub(r'[-_.]+', '-', dep).lower(), version, 'PyPI', file + '#' + str(line_no))
                        edge('app', key, 'declares'); nodes[key]['direct'] = True
                    else: warnings.append(f'{file}:{line_no}: unpinned or unsupported requirement')
                warnings.append(f'{file}: requirements inventory has no transitive edge information')
            elif name == 'pyproject.toml' and not any(sibling(file,lock) in files for lock in ('poetry.lock','uv.lock')):
                data = tomllib.loads(info['text'])
                requirements = list(data.get('project', {}).get('dependencies', []))
                for group in data.get('project', {}).get('optional-dependencies', {}).values():
                    requirements.extend(group)
                for i, requirement in enumerate(requirements):
                    match = re.match(r'^\s*([\w.-]+)(?:\[[^]]+\])?\s*==\s*([\w.+!-]+)', requirement)
                    if match:
                        dep, version = match.groups()
                        dep = re.sub(r'[-_.]+', '-', dep).lower()
                        key = component(dep, version, 'PyPI', file + '#' + str(i))
                        nodes[key]['direct'] = True; edge('app', key, 'declares')
                    else:
                        warnings.append(f'{file}: unresolved project requirement {requirement}')
                if requirements or data.get('tool', {}).get('poetry'):
                    warnings.append(f'{file}: project declarations only; import a resolved SBOM for Python transitive relationships')
            # yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock, Pipfile.lock, pubspec.lock/yaml,
            # packages.lock.json, .csproj, build.gradle, gradle.lockfile, go.sum, composer.lock,
            # Gemfile.lock are all handled by parse_extra (formats.py).
            # If we reach here, it's truly unsupported.
            elif name in ('composer.lock', 'Gemfile.lock'):
                warnings.append(f'{file}: {name} reader is not implemented; import a CycloneDX SBOM')
            elif name == 'Cargo.lock':
                data = tomllib.loads(info['text']); lookup = {}
                for p in data.get('package', []):
                    key = component(p['name'], p['version'], 'crates.io', file + '#' + p['name'] + '@' + p['version'], integrity=p.get('checksum'))
                    lookup[(p['name'], p['version'])] = key
                for p in data.get('package', []):
                    parent = lookup[(p['name'], p['version'])]
                    for dep in p.get('dependencies', []):
                        parts = dep.split(); matches = [v for (n, ver), v in lookup.items() if n == parts[0] and (len(parts) == 1 or ver == parts[1])]
                        if len(matches) == 1: edge(parent, matches[0])
                warnings.append(f'{file}: package edges resolved; application roots require Cargo metadata and remain unknown')
            elif name == 'go.mod':
                block = False
                for line in info['text'].splitlines():
                    s = line.strip()
                    if s.startswith('require ('): block = True; continue
                    if s == ')': block = False; continue
                    m = re.match(r'(?:require\s+)?([\w.\-/]+)\s+(v[^\s]+)', s)
                    if m and (block or s.startswith('require ')):
                        dep, version = m.groups(); key = component(dep, version, 'Go', file + '#' + dep)
                        nodes[key]['direct'] = '// indirect' not in s
                        edge('app', key, 'declares' if nodes[key]['direct'] else 'contains')
                warnings.append(f'{file}: Go module dependency edges unavailable without go mod graph')
            elif name == 'pom.xml':
                tree = ET.fromstring(info['text']); ns = {'m': 'http://maven.apache.org/POM/4.0.0'} if tree.tag.startswith('{') else {}; pre = 'm:' if ns else ''
                for dep in tree.findall(f'./{pre}dependencies/{pre}dependency', ns):
                    get = lambda n: dep.findtext(pre+n, '', ns)
                    artifact, group, version = get('artifactId'), get('groupId'), get('version')
                    if artifact and group:
                        key = component(group + ':' + artifact, version or 'unresolved', 'Maven', file + '#' + artifact)
                        nodes[key]['direct'] = True; edge('app', key)
                warnings.append(f'{file}: Maven declared dependencies only; import an SBOM for resolved transitive dependencies')
            elif name.endswith('.json') and ('sbom' in name.lower() or 'cyclonedx' in name.lower()):
                data = json.loads(info['text'])
                if data.get('bomFormat') != 'CycloneDX': continue
                refs = {}
                for p in data.get('components', []):
                    key = p.get('bom-ref') or p.get('purl') or p['name']
                    refs[key] = key
                    nodes[key] = dict(id=key, purl=p.get('purl'), name=p['name'], version=p.get('version', 'unresolved'), type='package', direct=False, file=file, ecosystem=None)
                    if p.get('purl'):
                        kind = p['purl'].split(':',1)[1].split('/',1)[0]
                        nodes[key]['ecosystem'] = {'npm':'npm','pypi':'PyPI','maven':'Maven','golang':'Go','cargo':'crates.io','pub':'Pub','nuget':'NuGet'}.get(kind)
                root_ref = data.get('metadata', {}).get('component', {}).get('bom-ref')
                for dep in data.get('dependencies', []):
                    parent = 'app' if dep['ref'] == root_ref else refs.get(dep['ref'])
                    for target in dep.get('dependsOn', []):
                        if parent and target in refs:
                            edge(parent, refs[target]); nodes[target]['direct'] |= parent == 'app'
        except (ValueError, KeyError, TypeError, ET.ParseError) as exc:
            warnings.append(f'{file}: parse failed: {exc}')
    if len(nodes) == 1:
        warnings.append('No resolved packages discovered; no dependencies is not proof of a complete inventory')
    return {'nodes': list(nodes.values()), 'edges': edges}, warnings


def dependency_path(graph, target):
    from collections import deque
    queue = deque([['app']]); seen = {'app'}; adjacency = {}
    for edge in graph['edges']:
        if edge['relation'] in ('depends_on', 'declares'):
            adjacency.setdefault(edge['source'], []).append(edge['target'])
    while queue:
        path = queue.popleft()
        if path[-1] == target: return path
        for nxt in adjacency.get(path[-1], []):
            if nxt not in seen: seen.add(nxt); queue.append(path + [nxt])
    return []


def sbom(graph):
    packages = [n for n in graph['nodes'] if n['type'] == 'package']
    refs = {'app'} | {n['id'] for n in packages}
    return {'bomFormat':'CycloneDX', 'specVersion':'1.5', 'version':1,
            'metadata': {'component': {'type':'application', 'bom-ref':'app', 'name':graph['nodes'][0]['name']}},
            'components':[dict({'type':'library', 'bom-ref':n['id'], 'name':n['name'], **({'version':n['version']} if n.get('resolved',bool(re.fullmatch(r'v?\d[\w.+!\-]*',n['version']))) else {'properties':[{'name':'guardian:declared-constraint','value':n['version']}]})}, **({'purl':n['purl']} if n.get('purl') else {})) for n in packages],
            'dependencies':[{'ref':ref, 'dependsOn':sorted({e['target'] for e in graph['edges'] if e['source']==ref and e['target'] in refs and e['relation'] in ('depends_on','declares')})} for ref in sorted(refs)]}
