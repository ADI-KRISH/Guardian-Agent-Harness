"""Recheck observations against immutable scan inputs and explain confidence."""
def verify(finding, files, graph):
    file=finding.get('file');line=finding.get('line',1)
    if file not in files:return False,'Evidence file missing from the scan snapshot'
    lines=files[file]['text'].splitlines()
    if not isinstance(line,int) or line<1 or line>max(1,len(lines)):return False,'Evidence line outside snapshot'
    if finding['rule']=='known-vulnerability':
        node=next((n for n in graph['nodes'] if n['id']==finding['component']),None)
        if not node or not node.get('resolved',True):return False,'Advisory match lacks an exact inventory version'
        evidence=finding['verified_evidence'][0]
        if evidence.get('package')!=node['name'] or evidence.get('version')!=node['version']:return False,'Advisory does not match the inventory identity'
        finding['verified_evidence'].append({'kind':'verified','tool':'guardian-inventory-verifier','file':file,'line':line,'excerpt':node.get('evidence_excerpt',''),'package':node['name'],'version':node['version'],'generated':node.get('generated',False),'artifact':node.get('artifact')})
        finding['confidence']='High'
        finding['confidence_explanation']='Exact inventory identity independently rechecked against the OSV package/version match; exploit reachability remains unknown'
    elif finding['rule']=='typosquat':
        finding['confidence']='Low';finding['confidence_explanation']='Name similarity only; no corroborating malicious-package evidence'
    elif finding['rule']=='integrity-change':
        finding['confidence']='High';finding['confidence_explanation']='Two recorded snapshots show different integrity values for the same package version; this establishes change, not malicious intent'
    else:
        finding['confidence']=finding.get('confidence','Medium')
        finding.setdefault('confidence_explanation','One deterministic rule observation; file and line rechecked, no independent behavioral proof')
    finding['verification']={'file_checked':True,'line_checked':True,'source_hash':files[file]['hash'],'generated':bool(files[file].get('generated'))}
    return True,finding['confidence_explanation']
