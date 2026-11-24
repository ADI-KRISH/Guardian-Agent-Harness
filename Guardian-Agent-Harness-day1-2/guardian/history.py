"""Historical comparison does not imply human approval or trusted-baseline promotion."""
import hashlib
import subprocess
from pathlib import Path
from .discovery import EXCLUDED, MAX_FILES, MAX_FILE_SIZE, MAX_TOTAL_SIZE


def git(path, args, **kwargs):
    return subprocess.run(['git','--no-pager','-c','core.hooksPath=/dev/null','-C',str(path),*args],capture_output=True,timeout=30,**kwargs)


def snapshot(path, reference='HEAD^'):
    if not reference or reference.startswith('-') or len(reference)>200:
        raise ValueError('Invalid Git comparison reference')
    result=git(path,['rev-parse','--verify','--end-of-options',reference+'^{commit}'])
    if result.returncode:raise ValueError(f'Comparison ref {reference} is unavailable in local Git history')
    commit=result.stdout.decode().strip()
    listing=git(path,['ls-tree','-r','-l','-z',commit])
    if listing.returncode:raise ValueError('Unable to list comparison tree')
    selected=[];total=0;warnings=[]
    for record in listing.stdout.split(b'\0'):
        if not record:continue
        header,raw_name=record.split(b'\t',1);mode,kind,oid,size=header.split();name=raw_name.decode('utf-8','replace')
        if any(part in EXCLUDED for part in Path(name).parts) or kind!=b'blob':continue
        if mode==b'120000':warnings.append('Historical symlink skipped: '+name);continue
        length=int(size)
        if len(selected)>=MAX_FILES or length>MAX_FILE_SIZE or total+length>MAX_TOTAL_SIZE:
            warnings.append('Historical input budget exceeded: '+name);continue
        selected.append((name,oid,length));total+=length
    objects=git(path,['cat-file','--batch'],input=b''.join(oid+b'\n' for _,oid,_ in selected)).stdout if selected else b''
    offset=0;files={}
    for name,oid,length in selected:
        end=objects.find(b'\n',offset)
        if end<0:raise ValueError('Truncated Git object response')
        header=objects[offset:end].split()
        if len(header)!=3 or header[0]!=oid or header[1]!=b'blob' or int(header[2])!=length:raise ValueError('Git object verification failed')
        raw=objects[end+1:end+1+length];offset=end+length+2
        files[name]={'text':raw.decode('utf-8','replace') if b'\0' not in raw else '', 'hash':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
    return files,{'kind':'git-reference','ref':reference,'commit':commit,'trusted':False,'warnings':warnings}
