import difflib
import hashlib
import json
import re
from pathlib import Path
from .flow import exfiltration_flows

SCORES = {'Critical': 9.5, 'High': 8.0, 'Medium': 5.5, 'Low': 2.5, 'Unknown': 0}


def finding(rule, what, category, severity, file='', line=1, excerpt='', component='app', **extra):
    evidence = {'tool': 'guardian-static', 'rule': rule, 'file': file, 'line': line, 'excerpt': excerpt[:500], 'kind': 'verified'}
    return dict(id='G-' + hashlib.sha256(f'{rule}|{component}|{file}|{line}|{what}'.encode()).hexdigest()[:12], rule=rule, what=what, category=category, risk_level=severity, score=SCORES[severity], score_explanation=f'{severity} policy score {SCORES[severity]}/10; reachability not assessed', component=component, file=file, line=line, verified_evidence=[evidence], ai_inference=[], confidence='Medium', status='open', **extra)


def static_scan(files, graph, baseline=None):
    out = []
    old_files = baseline.get('files', {}) if baseline else {}
    for file, entry in files.items():
        text = entry['text']; lines = text.splitlines()
        changed = not baseline or old_files.get(file, {}).get('hash') != entry['hash']
        is_workflow = file.startswith('.github/workflows/') and file.endswith(('.yml','.yaml'))
        is_source = Path(file).suffix in ('.py','.js','.ts','.mjs','.cjs','.sh','.m4','.go','.java','.rs','.yaml','.yml') or Path(file).name in ('Makefile','Dockerfile','configure','package.json')
        if is_workflow:
            for num, line in enumerate(lines,1):
                m = re.search(r'\buses:\s*[\'\"]?([^\s\'\"#]+)', line)
                if m and not m[1].startswith('./'):
                    value = m[1]
                    pinned = bool(re.search(r'@[0-9a-fA-F]{40}$', value)) or (value.startswith('docker://') and bool(re.search(r'@sha256:[0-9a-f]{64}$', value)))
                    if not pinned:
                        out.append(finding('unpinned-action','Workflow action is not pinned to an immutable commit','CI-container','Medium',file,num,line))
                if re.search(r'\b(?:permissions:\s*write-all|pull_request_target\s*:)', line):
                    out.append(finding('privileged-workflow','Privileged workflow requires review','CI-container','High',file,num,line))
        if Path(file).name.startswith('Dockerfile'):
            stages = set()
            for num, line in enumerate(lines,1):
                m = re.match(r'\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?',line,re.I)
                if m:
                    ref = m[1]
                    if ref.lower() != 'scratch' and ref.lower() not in stages and not re.search(r'@sha256:[0-9a-f]{64}$',ref):
                        out.append(finding('floating-image','Container base image is not digest-pinned','CI-container','Medium',file,num,line))
                    if m[2]: stages.add(m[2].lower())
                if re.match(r'\s*USER\s+(?:root|0)\s*$',line,re.I):
                    out.append(finding('root-container','Container explicitly runs as root','CI-container','Medium',file,num,line))
        if not is_source: continue
        for num, line in enumerate(lines,1):
            if re.search(r'(?:eval|exec)\s*\(.*(?:base64|b64decode|atob|fromCharCode)|(?:base64|b64decode|atob).*\b(?:eval|exec)\s*\(',line):
                out.append(finding('obfuscated-execution','Encoded data passed to dynamic execution','backdoor signal','High',file,num,line))
            if any(c in line for c in '\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069'):
                out.append(finding('bidi-source','Bidirectional control character in source','backdoor signal','High',file,num,ascii(line)))
            if re.search(r'curl\b.*\|\s*(?:ba)?sh|wget\b.*\|\s*(?:ba)?sh',line):
                out.append(finding('download-execute','Build or source downloads and executes a script','source change','High',file,num,line))
        for flow in exfiltration_flows(text):
            f=finding('secret-exfiltration','Sensitive value flows into an outbound network call (static candidate)','backdoor signal','High',file,flow['line'],flow['excerpt'])
            f['flow']=flow
            f['confidence']='Medium'
            f['confidence_explanation']='Matched a sensitive source inside network-call arguments; limited static flow analysis, no runtime proof'
            out.append(f)
        if baseline and changed and (Path(file).name in ('setup.py','Makefile','configure','package.json') or file.endswith('.m4') or Path(file).name.startswith('Dockerfile')):
            out.append(finding('build-change','Build configuration changed since comparison snapshot','source change','Medium',file,1,lines[0] if lines else ''))
        if Path(file).name == 'package.json':
            try:
                scripts = json.loads(text).get('scripts',{})
                for hook in ('preinstall','install','postinstall'):
                    if hook in scripts:
                        num = next((i for i,l in enumerate(lines,1) if '"'+hook+'"' in l),1)
                        out.append(finding('install-script',f'Package declares {hook} lifecycle script','dependency change','High',file,num,lines[num-1]))
            except (ValueError,TypeError): pass
    popular = ['requests','urllib3','numpy','pandas','express','lodash','react','cross-env','chalk','axios','django','flask']
    for n in graph['nodes']:
        if n['type'] != 'package': continue
        if n.get('install_script'):
            out.append(finding('install-script',f'{n["name"]} declares an install script','dependency change','High',n['file'],n.get('line',1),'Lockfile hasInstallScript=true',n['id'], evidence_field='hasInstallScript'))
        if len(n['name']) > 4 and n['name'] not in popular:
            similar = difflib.get_close_matches(n['name'],popular,n=1,cutoff=.86)
            if similar:
                out.append(finding('typosquat',f'Lookalike package name: {n["name"]} resembles {similar[0]} (heuristic)','backdoor signal','Medium',n['file'],n.get('line',1),n['name'],n['id']))
    return out


def changes(graph, files, baseline):
    if not baseline: return {'baseline':None,'available':False,'reason':'No prior scan or Git history is available; first scan establishes an observation, not trust','added':[],'removed':[],'updated':[],'files':[]}, []
    key = lambda n: (n.get('ecosystem'), n['name'], n.get('file'), n['id'].split('#',1)[-1])
    old = {key(n):n for n in baseline['graph']['nodes'] if n['type']=='package'}
    new = {key(n):n for n in graph['nodes'] if n['type']=='package'}
    added = [new[k] for k in new.keys()-old.keys()]; removed = [old[k] for k in old.keys()-new.keys()]
    updated, findings = [], []
    for k in old.keys() & new.keys():
        a,b=old[k],new[k]
        if a['version'] != b['version'] or a.get('integrity') != b.get('integrity'):
            updated.append({'before':a,'after':b})
            if a['version']==b['version'] and a.get('integrity') != b.get('integrity'):
                findings.append(finding('integrity-change',f'{b["name"]}: same version, changed integrity hash','dependency change','Critical',b['file'],1,f'{a.get("integrity")} → {b.get("integrity")}',b['id'],previous_integrity=a.get('integrity'),current_integrity=b.get('integrity')))
    for n in added:
        findings.append(finding('dependency-added',f'New dependency: {n["name"]}@{n["version"]}','dependency change','Low',n['file'],1,n['name'],n['id']))
    changed_files = [{'path':f,'change':'added' if f not in baseline['files'] else 'modified'} for f,v in files.items() if not v.get('generated') and baseline['files'].get(f,{}).get('hash') != v['hash']]
    changed_files += [{'path':f,'change':'removed'} for f in baseline['files'] if f not in files and not baseline['files'][f].get('generated')]
    return {'baseline':baseline['id'],'available':True,'comparison':baseline.get('comparison',{'kind':'trusted-baseline','trusted':True}),'added':added,'removed':removed,'updated':updated,'files':changed_files}, findings
