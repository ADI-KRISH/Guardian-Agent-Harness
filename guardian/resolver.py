"""Resolve missing npm lockfiles in an isolated, manifest-only temporary directory."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from .formats import sibling


def npm_command():
    npm=os.environ.get('GUARDIAN_NPM') or shutil.which('npm')
    node=os.environ.get('GUARDIAN_NODE') or shutil.which('node')
    fallback=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
    for candidate in dict.fromkeys(filter(None,[node,str(fallback) if fallback.exists() else None])):
        try:
            result=subprocess.run([candidate,'--version'],capture_output=True,timeout=5)
            if result.returncode==0 and npm:return [candidate,str(Path(npm).resolve())]
        except (OSError,subprocess.TimeoutExpired):pass
    raise ValueError('A working Node.js and npm are required for missing-lockfile resolution; set GUARDIAN_NODE and GUARDIAN_NPM if needed')


def sanitized_manifest(data):
    result={'name':'guardian-analysis','version':'0.0.0','private':True}
    for section in ('dependencies','devDependencies','optionalDependencies'):
        result[section]={}
        for name,spec in data.get(section,{}).items():
            if not re.fullmatch(r'(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+',name):
                raise ValueError('Invalid npm package name')
            # Only registry versions, ranges, dist-tags and npm aliases. No arbitrary URLs/local paths.
            if not isinstance(spec,str) or not re.fullmatch(r'[a-zA-Z0-9@/^~*<>=| ._+!-]+',spec) or ':' in spec or '/' in spec:
                if not (isinstance(spec,str) and re.fullmatch(r'npm:(?:@[\w.-]+/)?[\w.-]+@[\w.*~^<>=| +!-]+',spec)):
                    raise ValueError(f'Non-registry dependency {name}: {spec}; supply a reviewed lockfile instead')
            result[section][name]=spec
    # Root scripts, overrides with non-registry sources, .npmrc, extensions and workspaces are never copied.
    return result


def resolve_missing(files, store, offline=False, enabled=True):
    results=[]
    for file in list(files):
        if Path(file).name!='package.json':continue
        if any(sibling(file,n) in files for n in ('package-lock.json','npm-shrinkwrap.json','pnpm-lock.yaml','yarn.lock')):continue
        status={'manifest':file,'status':'unavailable','method':'npm install --package-lock-only --ignore-scripts','generated':True}
        results.append(status)
        try:
            manifest=json.loads(files[file]['text']); clean=sanitized_manifest(manifest)
            if not any(clean[s] for s in ('dependencies','devDependencies','optionalDependencies')):
                status['status']='not needed';continue
            key=hashlib.sha256(json.dumps(clean,sort_keys=True).encode()).hexdigest()
            cached=store.cached('resolution:'+key)
            if cached:
                content=cached['content'];status['status']='cached';status['resolved_at']=cached['resolved_at']
            elif offline or not enabled:
                status['error']='Missing lockfile; resolution disabled or offline with no fresh resolution cache';continue
            else:
                command=npm_command()
                with tempfile.TemporaryDirectory(prefix='guardian-resolve-') as tmp:
                    work=Path(tmp);(work/'package.json').write_text(json.dumps(clean))
                    (work/'empty.npmrc').write_text('')
                    (work/'global.npmrc').write_text('')
                    env={'PATH':str(Path(command[0]).parent)+os.pathsep+'/usr/bin:/bin:/usr/local/bin','HOME':tmp,'TMPDIR':tmp,'CI':'true','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','npm_config_cache':str(work/'cache'),'npm_config_ignore_scripts':'true','npm_config_registry':'https://registry.npmjs.org/'}
                    args=command+['install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund','--legacy-peer-deps','--registry=https://registry.npmjs.org/','--userconfig='+str(work/'empty.npmrc'),'--globalconfig='+str(work/'global.npmrc')]
                    proc=subprocess.run(args,cwd=work,env=env,capture_output=True,text=True,timeout=180)
                    if proc.returncode:raise ValueError('npm resolution failed: '+proc.stderr[-1000:])
                    lock=work/'package-lock.json'
                    if not lock.exists() or lock.stat().st_size>16*1024*1024:raise ValueError('Generated lockfile missing or above 16 MiB budget')
                    if (work/'node_modules').exists():raise ValueError('Resolver unexpectedly created node_modules')
                    content=lock.read_text()
                from .store import now
                status.update(status='resolved',resolved_at=now())
                store.cache('resolution:'+key,{'content':content,'resolved_at':status['resolved_at']})
            artifact=store.directory/'resolutions'/key/'package-lock.json';artifact.parent.mkdir(parents=True,exist_ok=True);artifact.write_text(content)
            lockfile=sibling(file,'package-lock.json')
            files[lockfile]={'text':content,'hash':hashlib.sha256(content.encode()).hexdigest(),'size':len(content.encode()),'generated':True,'source_manifest':file,'artifact':str(artifact),'resolved_at':status['resolved_at']}
            status.update(lockfile=lockfile,artifact=str(artifact),packages=len(json.loads(content).get('packages',{}))-1)
        except (ValueError,OSError,subprocess.TimeoutExpired) as exc:status['error']=str(exc)
    return results
