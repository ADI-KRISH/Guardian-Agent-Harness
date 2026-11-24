"""Dockerfile / Compose inspection and optional remote-image Trivy vulnerability scans."""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from .formats import yaml_data
from .detectors import finding


def inspect(files,store,scan_images=False,offline=False):
    findings=[];images=[];warnings=[]
    def record(ref,file,line):
        if not any(i['reference']==ref for i in images):images.append({'reference':ref,'file':file,'line':line,'status':'static only'})
    for file,entry in files.items():
        name=Path(file).name;text=entry['text'];lines=text.splitlines()
        if name.startswith('Dockerfile') or name.endswith('.Dockerfile') or name=='Containerfile':
            args={};stages=set()
            for num,line in enumerate(lines,1):
                arg=re.match(r'\s*ARG\s+(\w+)=(\S+)',line,re.I)
                if arg:args[arg[1]]=arg[2].strip('"\'')
                match=re.match(r'\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?',line,re.I)
                if match:
                    ref=match[1]
                    for k,v in args.items():ref=ref.replace('${'+k+'}',v).replace('$'+k,v)
                    if ref.lower()!='scratch' and ref.lower() not in stages:
                        record(ref,file,num)
                        if not re.search(r'@sha256:[a-f0-9]{64}$',ref):
                            findings.append(finding('floating-image','Container base image is not digest-pinned','CI-container','Medium',file,num,line))
                    if match[2]:stages.add(match[2].lower())
                if re.match(r'\s*(?:ENV|ARG)\s+\w*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\w*\s*[= ]\s*\S+',line,re.I):
                    findings.append(finding('docker-secret-config','Secret-like build argument or environment declaration requires review','CI-container','Medium',file,num,line))
        elif name in ('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml'):
            try:
                data=yaml_data(text)
                for service,config in data.get('services',{}).items():
                    if not isinstance(config,dict):continue
                    ref=config.get('image');num=next((i for i,l in enumerate(lines,1) if service+':' in l),1)
                    if ref:
                        image_line=next((i for i,l in enumerate(lines,1) if str(ref) in l),num);record(str(ref),file,image_line)
                        if '@sha256:' not in str(ref):findings.append(finding('floating-image',f'Compose service {service} uses an image without a digest','CI-container','Medium',file,image_line,lines[image_line-1]))
                    if config.get('privileged') is True:findings.append(finding('privileged-container',f'Compose service {service} is privileged','CI-container','High',file,num,lines[num-1]))
                    if any('docker.sock' in str(v) for v in config.get('volumes',[])):findings.append(finding('docker-socket',f'Compose service {service} mounts the Docker control socket','CI-container','High',file,num,lines[num-1]))
                    if config.get('network_mode')=='host':findings.append(finding('host-network',f'Compose service {service} shares the host network','CI-container','Medium',file,num,lines[num-1]))
            except (ValueError,TypeError) as exc:warnings.append(f'{file}: {exc}')
    trivy=shutil.which('trivy') or os.environ.get('GUARDIAN_TRIVY')
    for image in images:
        if not scan_images:continue
        if offline:image.update(status='unavailable',error='Offline mode: remote image scan disabled');continue
        if not trivy:image.update(status='unavailable',error='Install Trivy or set GUARDIAN_TRIVY for OS/image-layer CVE scanning');continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@-]*',image['reference']):
            image.update(status='unavailable',error='Unresolved or unsupported image reference');continue
        try:
            with tempfile.TemporaryDirectory(prefix='guardian-trivy-') as tmp:
                output=Path(tmp)/'report.json';config=Path(tmp)/'trivy.yaml';config.write_text('{}')
                env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':tmp,'TMPDIR':tmp}
                command=[trivy,'image','--config',str(config),'--image-src','remote','--scanners','vuln','--format','json','--output',str(output),'--timeout','120s','--cache-dir',str(store.directory/'trivy-cache'),'--',image['reference']]
                result=subprocess.run(command,cwd=tmp,env=env,capture_output=True,text=True,timeout=150)
                if result.returncode:raise ValueError(result.stderr[-600:])
                if output.stat().st_size>32*1024*1024:raise ValueError('Trivy response exceeded budget')
                report=json.loads(output.read_text())
            image.update(status='complete',digest=report.get('Metadata',{}).get('RepoDigests',[]))
            for target in report.get('Results',[]):
                for vuln in target.get('Vulnerabilities',[]) or []:
                    severity=vuln.get('Severity','Unknown').title()
                    if severity not in ('Critical','High','Medium','Low'):severity='Unknown'
                    f=finding('image-vulnerability',vuln.get('Title') or vuln['VulnerabilityID'],'container CVE',severity,image['file'],image['line'],image['reference'],advisory=vuln['VulnerabilityID'],image=image['reference'],package=vuln.get('PkgName'),installed_version=vuln.get('InstalledVersion'),fix_versions=[vuln['FixedVersion']] if vuln.get('FixedVersion') else [])
                    f['id']+='-'+vuln['VulnerabilityID']+'-'+str(vuln.get('PkgName',''))
                    f['verified_evidence'].append({'kind':'verified','tool':'Trivy','image':image['reference'],'package':vuln.get('PkgName'),'version':vuln.get('InstalledVersion'),'advisory':vuln['VulnerabilityID'],'target':target.get('Target')})
                    findings.append(f)
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:image.update(status='failed',error=str(exc))
    return findings,{'images':images,'warnings':warnings,'image_scanner':'Trivy' if trivy else 'not installed','requested':scan_images}
