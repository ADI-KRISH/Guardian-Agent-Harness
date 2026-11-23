"""Non-executing readers for the lockfile formats supported by Guardian."""
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path


def yaml_data(text):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError('YAML support requires PyYAML: run .venv/bin/python -m pip install -e .') from exc
    # Reject aliases to avoid expansion attacks and ambiguous shared structures.
    if any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in yaml.scan(text)):
        raise ValueError('YAML aliases/anchors are not supported in dependency inventories')
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError('Invalid YAML: ' + str(exc)[:160]) from exc
    return data or {}


def sibling(file, name):
    return (Path(file).parent / name).as_posix().removeprefix('./')


def parse_extra(file, files, add, edge, nodes, warnings):
    """Returns whether this module handled the file. Edges only reflect supplied facts."""
    name=Path(file).name; text=files[file]['text']
    def package(n,v,eco,**extra): return add(n,str(v or 'unresolved'),eco,file+'#'+n,**extra)
    def declared(n,v,eco,**extra):
        key=package(n,v,eco,**extra); nodes[key]['direct']=True; edge('app',key,'declares'); return key
    if name in ('pubspec.lock','pubspec.yaml'):
        data=yaml_data(text)
        if name=='pubspec.lock':
            for n,p in data.get('packages',{}).items():
                if p.get('source')!='hosted':
                    warnings.append(f'{file}: {n} is an SDK/path/git dependency; no pub.dev match attempted'); continue
                description=p.get('description',{})
                key=package(n,p.get('version'),'Pub',integrity=description.get('sha256') if isinstance(description,dict) else None)
                direct=str(p.get('dependency','')).startswith('direct'); nodes[key]['direct']=direct
                edge('app',key,'declares' if direct else 'contains')
            warnings.append(f'{file}: exact package inventory; pubspec.lock does not encode package-to-package edges')
        elif sibling(file,'pubspec.lock') not in files:
            for section in ('dependencies','dev_dependencies'):
                for n,v in data.get(section,{}).items():
                    if isinstance(v,dict):
                        if v.get('sdk') or v.get('path') or v.get('git'):
                            warnings.append(f'{file}: {n} uses an SDK/path/git source'); continue
                        v=v.get('version','unresolved')
                    declared(n,v,'Pub')
            warnings.append(f'{file}: manifest constraints; supply pubspec.lock for exact versions')
    elif name in ('poetry.lock','uv.lock'):
        data=tomllib.loads(text); entries=data.get('package',[]); lookup={}
        for p in entries:
            if p.get('source',{}).get('editable')=='.' or p.get('source',{}).get('virtual')=='.':
                lookup.setdefault(p['name'],[]).append(('app',p)); continue
            key=package(p['name'],p.get('version'),'PyPI',integrity=json.dumps(p.get('files') or p.get('wheels') or [],sort_keys=True))
            lookup.setdefault(p['name'],[]).append((key,p))
        for p in entries:
            parents=[k for k,q in lookup.get(p['name'],[]) if q is p]
            for dep in p.get('dependencies',[]):
                n=dep if isinstance(dep,str) else dep.get('name')
                matches=lookup.get(n,[])
                if isinstance(dep,dict) and dep.get('version'): matches=[(k,q) for k,q in matches if q.get('version')==dep['version']]
                if len(matches)==1:
                    for parent in parents:
                        edge(parent,matches[0][0]); nodes[matches[0][0]]['direct'] |= parent=='app'
                elif matches: warnings.append(f'{file}: ambiguous conditional dependency edge to {n}')
        project_file=sibling(file,'pyproject.toml')
        if project_file in files:
            project=tomllib.loads(files[project_file]['text']); names=[]
            for dep in project.get('project',{}).get('dependencies',[]):
                m=re.match(r'[\w.-]+',dep)
                if m:names.append(m[0])
            poetry=project.get('tool',{}).get('poetry',{})
            names.extend(n for n in poetry.get('dependencies',{}) if n!='python')
            for group in poetry.get('group',{}).values(): names.extend(group.get('dependencies',{}))
            for n in names:
                for key,_ in lookup.get(n,[]):
                    if key!='app':edge('app',key,'declares');nodes[key]['direct']=True
        if not any(n.get('direct') for n in nodes.values() if n.get('ecosystem')=='PyPI'):
            warnings.append(f'{file}: root dependency declarations unavailable; package inventory retained')
    elif name=='Pipfile.lock':
        data=json.loads(text)
        for section in ('default','develop'):
            for n,p in data.get(section,{}).items():
                package(n,str(p.get('version','unresolved')).removeprefix('=='),'PyPI',integrity=json.dumps(p.get('hashes',[])))
        warnings.append(f'{file}: exact inventory; Pipfile.lock does not include transitive edge provenance')
    elif name=='pnpm-lock.yaml':
        data=yaml_data(text); lookup={}; entries=data.get('packages',{}); snapshots=data.get('snapshots',entries)
        def identity(raw):
            raw=raw.lstrip('/').split('(',1)[0]
            m=re.match(r'^(@[^/]+/[^@/]+|[^@/]+)(?:@|/)(.+)$',raw)
            return m.groups() if m else (raw,'unresolved')
        for ref,p in entries.items():
            n,v=identity(str(ref)); key=add(n,v,'npm',file+'#'+str(ref),integrity=(p or {}).get('resolution',{}).get('integrity'))
            lookup[str(ref).lstrip('/')]=key
        def resolve(n,ref):
            if isinstance(ref,dict): ref=ref.get('version',ref.get('specifier',''))
            ref=str(ref); candidates=[ref.lstrip('/'),n+'@'+ref,n+'/'+ref]
            for c in candidates:
                if c in lookup:return lookup[c]
                base=c.split('(',1)[0]
                if base in lookup:return lookup[base]
            return None
        for ref,p in snapshots.items():
            n,v=identity(str(ref)); parent=resolve(n,str(ref)) or resolve(n,v)
            if not parent:continue
            for dep,value in {**(p or {}).get('dependencies',{}),**(p or {}).get('optionalDependencies',{})}.items():
                target=resolve(dep,value)
                if target:edge(parent,target)
                elif not str(value).startswith(('link:','file:')):warnings.append(f'{file}: unresolved edge {n} → {dep}')
        importers=data.get('importers') or {'.':data}
        for importer,p in importers.items():
            for section in ('dependencies','devDependencies','optionalDependencies'):
                for n,v in p.get(section,{}).items():
                    key=resolve(n,v)
                    if key:edge('app',key);nodes[key]['direct']=True
                    else:warnings.append(f'{file}: unresolved importer {importer} dependency {n}')
    elif name=='yarn.lock':
        # Yarn Berry is YAML; Yarn classic is a small indentation-based format.
        if '__metadata:' in text:
            data=yaml_data(text)
        else:
            data={}; current=None; section=None
            for line in text.splitlines():
                if not line or line.startswith('#'):continue
                if not line.startswith(' ') and line.endswith(':'):
                    current={};data[line[:-1]]=current;section=None
                elif current is not None:
                    m=re.match(r'^  (version|resolved|integrity)\s+"?([^"\n]+)"?$',line)
                    if m:current[m[1]]=m[2].strip('"');continue
                    m=re.match(r'^  (dependencies|optionalDependencies):',line)
                    if m:section=m[1];current[section]={};continue
                    m=re.match(r'^    ("[^"]+"|\S+)\s+"?([^"\n]+)"?$',line)
                    if m and section:current[section][m[1].strip('"')]=m[2].strip('"')
        lookup={}; records=[]
        for selectors,p in data.items():
            if selectors=='__metadata' or not isinstance(p,dict):continue
            selectors=[x.strip().strip('"') for x in selectors.split(',')]
            first=selectors[0];split=first.rfind('@');n=first[:split] if split>0 else first
            if not p.get('version'):continue
            key=add(n,str(p['version']),'npm',file+'#'+first,integrity=p.get('integrity') or p.get('checksum'))
            for selector in selectors:lookup[selector]=key
            records.append((key,p))
        def resolve(n,v):return lookup.get(n+'@'+str(v)) or lookup.get(n+'@npm:'+str(v))
        for key,p in records:
            for dep,v in {**p.get('dependencies',{}),**p.get('optionalDependencies',{})}.items():
                target=resolve(dep,v)
                if target:edge(key,target)
                else:warnings.append(f'{file}: unresolved Yarn edge to {dep}@{v}')
        manifest=sibling(file,'package.json')
        if manifest in files:
            data=json.loads(files[manifest]['text'])
            for dep,v in {**data.get('dependencies',{}),**data.get('devDependencies',{}),**data.get('optionalDependencies',{})}.items():
                key=resolve(dep,v)
                if key:edge('app',key);nodes[key]['direct']=True
                else:warnings.append(f'{file}: unresolved Yarn root dependency {dep}')
        else:warnings.append(f'{file}: package.json missing; roots unknown')
    elif name=='packages.lock.json':
        data=json.loads(text)
        for framework,packages in data.get('dependencies',{}).items():
            lookup={}
            for n,p in packages.items():
                key=add(n,p.get('resolved','unresolved'),'NuGet',file+'#'+framework+'/'+n,integrity=p.get('contentHash'))
                lookup[n.lower()]=key;nodes[key]['direct']=p.get('type','').lower()=='direct'
                if nodes[key]['direct']:edge('app',key)
            for n,p in packages.items():
                for dep in p.get('dependencies',{}):
                    if dep.lower() in lookup:edge(lookup[n.lower()],lookup[dep.lower()])
                    else:warnings.append(f'{file}: unresolved NuGet dependency {dep}')
    elif name.endswith(('.csproj','.fsproj','.vbproj')):
        if sibling(file,'packages.lock.json') in files:return True
        root=ET.fromstring(text)
        props={e.tag.split('}')[-1]:e.text for g in root if g.tag.split('}')[-1]=='PropertyGroup' for e in g}
        for p in root.iter():
            if p.tag.split('}')[-1]!='PackageReference':continue
            n=p.get('Include') or p.get('Update');v=p.get('Version') or next((e.text for e in p if e.tag.split('}')[-1]=='Version'),'unresolved')
            for prop,val in props.items():v=v.replace('$('+prop+')',val or '')
            if n:declared(n,v,'NuGet')
        warnings.append(f'{file}: project references only; packages.lock.json required for transitives')
    elif name in ('build.gradle','build.gradle.kts','gradle.lockfile'):
        if name=='gradle.lockfile':
            for line in text.splitlines():
                m=re.match(r'^([^:#\s]+):([^:\s]+):([^=\s]+)=',line)
                if m:package(m[1]+':'+m[2],m[3],'Maven')
            warnings.append(f'{file}: locked inventory; Gradle lockfile does not contain dependency edges')
        elif sibling(file,'gradle.lockfile') not in files:
            for m in re.finditer(r'\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*[\'"]([^:\s\'"]+):([^:\s\'"]+):([^\'"]+)[\'"]',text):
                declared(m[1]+':'+m[2],m[3],'Maven')
            warnings.append(f'{file}: static literal declarations only; Gradle code is never executed; supply lockfile/SBOM for resolved inventory')
    elif name=='go.sum':
        existing={(n['name'],n.get('version')):n for n in nodes.values() if n.get('ecosystem')=='Go'}
        for line in text.splitlines():
            bits=line.split()
            if len(bits)!=3:continue
            n,v,checksum=bits
            if v.endswith('/go.mod'):continue
            if (n,v) in existing:existing[(n,v)]['integrity']=checksum
        if not sibling(file,'go.mod') in files:
            warnings.append(f'{file}: checksum history alone cannot establish the selected Go module inventory')
    else:return False
    return True
