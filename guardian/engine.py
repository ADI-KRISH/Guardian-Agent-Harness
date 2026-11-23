import hashlib
import json
import re
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .store import now, suppressed
from .discovery import read_tree, discover, dependency_path, sbom
from .detectors import static_scan, changes
from .osv import scan as vulnerability_scan
from .resolver import resolve_missing
from .history import snapshot as git_snapshot
from .containers import inspect as inspect_containers
from .verifier import verify
from .ai import investigate
from .selfcheck import checks as self_checks


def source_path(source, store):
    if re.fullmatch(r'https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?', source):
        target=store.directory/'repositories'/hashlib.sha256(source.encode()).hexdigest()[:16]
        target.parent.mkdir(exist_ok=True)
        # Unique checkout: no stale results and no hooks, submodules or package installs.
        target=target.with_name(target.name+'-'+uuid.uuid4().hex[:8])
        proc=subprocess.run(['git','-c','core.hooksPath=/dev/null','clone','--depth','50','--no-recurse-submodules','--',source,str(target)],capture_output=True,text=True,timeout=120,env={'PATH':'/usr/bin:/bin:/usr/local/bin','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'})
        if proc.returncode: raise ValueError('Git clone failed: '+proc.stderr[-800:])
        return target, source.rstrip('/').removesuffix('.git')
    if '://' in source: raise ValueError('Only public HTTPS github.com owner/repository URLs are supported')
    path=Path(source).expanduser().resolve()
    if not path.is_dir(): raise ValueError('Repository directory does not exist')
    if path == store.directory or (store.directory in path.parents and (store.directory/'repositories') not in path.parents): raise ValueError('Cannot scan internal Guardian storage')
    return path, str(path)


def run_scan(source, store, offline=False, planted=False, progress=None, resolve=True, baseline_ref=None, ai=False, model=None, scan_images=False):
    start=time.monotonic(); scan_id=uuid.uuid4().hex[:12]; stages=[]
    def stage(agent, decision, reason):
        stages.append({'agent':agent,'decision':decision,'time':now()})
        store.audit(scan_id,agent,decision,reason)
        if progress: progress(agent)
    path, repo=source_path(source,store)
    baseline=store.baseline(repo); lessons=store.lessons(repo)
    selfcheck=self_checks()
    if not selfcheck['passed']:raise ValueError('Detector/policy self-check failed; scan blocked')
    comparison_note=None
    if baseline_ref or not baseline:
        previous=next((r for r in store.list() if r['repo']==repo),None)
        if previous and not baseline_ref:
            baseline=store.get(previous['id']);baseline['comparison']={'kind':'previous-observation','trusted':False,'scan_id':baseline['id']}
        else:
            try:
                if not (path/'.git').exists():raise ValueError('No Git history or prior scan is available for comparison')
                old_files,comparison=git_snapshot(path,baseline_ref or 'HEAD^')
                old_resolutions=resolve_missing(old_files,store,offline,resolve)
                old_graph,old_warnings=discover(path,old_files)
                comparison.update(warnings=comparison['warnings']+old_warnings,resolutions=old_resolutions)
                baseline={'id':comparison['commit'],'files':old_files,'graph':old_graph,'comparison':comparison}
            except ValueError as exc:
                if baseline_ref:raise
                comparison_note=str(exc)

    stage('Orchestrator','Read-only scan planned','Inventory and vulnerability checks cover all components; source signals rechecked each run so existing risks remain visible. Repository content is untrusted data.')
    files,warnings=read_tree(path)
    stage('Resolver','Resolving missing lockfiles','Registry-only npm manifests copied to disposable directory; lifecycle scripts disabled; original repository untouched')
    resolutions=resolve_missing(files,store,offline,resolve)
    for result in resolutions:
        if result.get('error'):warnings.append(result['manifest']+': '+result['error'])
    graph,discovery_warnings=discover(path,files); warnings.extend(discovery_warnings)
    if repo.startswith('https://'): graph['nodes'][0]['name']=repo.rsplit('/',1)[-1]
    change_set,change_findings=changes(graph,files,baseline)
    if comparison_note and not baseline:change_set['reason']=comparison_note
    if baseline and baseline.get('comparison',{}).get('kind')=='git-reference':
        change_set['comparison']['resolution_note']='Historical manifests are resolved now where no committed lockfile exists; this is not a reconstruction of historically installed transitives' 
    stage('Discovery agent',f'Discovered {len(graph["nodes"])-1} packages',f'{len(files)} files; baseline '+(baseline['id'] if baseline else 'not set'))
    with ThreadPoolExecutor(max_workers=3) as pool:
        container_job=pool.submit(inspect_containers,files,store,scan_images,offline)
        static_job=pool.submit(static_scan,files,graph,baseline)
        osv_job=pool.submit(vulnerability_scan,graph,store,offline)
        static_findings=static_job.result(); vuln_findings,vuln_coverage=osv_job.result()
        container_findings,container_coverage=container_job.result()
        warnings.extend(container_coverage["warnings"])
    stage('Backdoor / CI agent',f'{len(static_findings)} static signals','Deterministic source, lockfile, workflow and Dockerfile rules; signals do not prove malicious intent')
    stage('Vulnerability agent',f'{len(vuln_findings)} advisory matches','OSV exact-version queries; 24-hour cache; unavailable checks are explicitly recorded')
    findings=[]; seen=set(); suppressed_count=0
    for f in change_findings+static_findings+container_findings+vuln_findings:
        if f['id'] in seen: continue
        seen.add(f['id'])
        valid,explanation=verify(f,files,graph)
        if not valid:
            stage('Verifier','Rejected '+f['id'],explanation);continue
        if f['rule']=='integrity-change':
            f['verified_evidence'][0]['tool']='guardian-baseline-diff'
        f['dependency_path']=dependency_path(graph,f['component'])
        f['planted']=planted
        f['change']={'baseline':baseline['id'] if baseline else None,'current':scan_id}
        if suppressed(f,lessons):
            f['suppressed']=True; suppressed_count+=1
            store.audit(scan_id,'Learning agent','Suppression applied',f['id']+': approved scoped unexpired lesson')
        else: f['suppressed']=False
        findings.append(f)
        store.audit(scan_id,'Evidence agent','Recorded '+f['id'],f['score_explanation']+'; '+f['confidence_explanation'])
    findings.sort(key=lambda f:(f['suppressed'],-f['score'],f['id']))
    stage('Verifier',f'{len(findings)} evidence records validated','Exact advisory identities, file references and lines checked; confidence reflects evidence type')
    ai_result=investigate(findings,model,ai)
    stage('AI investigator',ai_result['status'],'Local Ollama only; model inferences cannot alter severity, trust, suppression or verified observations')
    graph_nodes={n['id'] for n in graph['nodes']}
    for file in sorted({f['file'] for f in findings if f['file']}):
        fid='file:'+file
        graph['nodes'].append({'id':fid,'name':file,'type':'file','version':''})
        graph['edges'].append({'source':'app','target':fid,'relation':'contains'})
        graph_nodes.add(fid)
    for f in findings:
        if f['suppressed']: continue
        graph['nodes'].append({'id':f['id'],'name':f.get('advisory',f['rule']),'type':'finding','risk_level':f['risk_level'],'version':'','finding_id':f['id']})
        graph['edges'].append({'source':f['component'] if f['component'] in graph_nodes else 'app','target':f['id'],'relation':'affected_by'})
        if f['file']:
            graph['edges'].append({'source':f['id'],'target':'file:'+f['file'],'relation':'evidenced_by'})
    coverage={'inventory':'partial' if warnings else 'complete','warnings':warnings,'vulnerabilities':vuln_coverage,'vulnerability_status':'complete' if vuln_coverage and all(c['status'] in ('live','cached') for c in vuln_coverage) else 'partial' if vuln_coverage else 'not applicable','source_files':len(files),'suppressed':suppressed_count,'resolutions':resolutions,'containers':container_coverage,'selfcheck':selfcheck,'checked_packages':sum(c['status'] in ('live','cached') for c in vuln_coverage),'total_packages':len(vuln_coverage)}
    stage('Evidence agent','Report and knowledge graph saved','Repository → package → advisory → evidence-file relationships; no fabricated dependency paths')
    scan={'id':scan_id,'repo':repo,'name':path.name if not repo.startswith('https://') else repo.rsplit('/',1)[-1], 'created':now(),'planted':planted,'duration_seconds':round(time.monotonic()-start,2),'graph':graph,'sbom':sbom(graph),'findings':findings,'changes':change_set,'coverage':coverage,'ai':ai_result,'stages':stages,'files':{f:{k:v for k,v in info.items() if k!='text'} for f,info in files.items()},'limitations':['Static signals are not proof of a backdoor.','Reachability, package/source provenance and nested remote actions are not analyzed. Image CVEs require enabled Trivy scanning.','AI explanations are optional local Ollama inference; they never establish verified facts or approve changes.','Use imported CycloneDX for unsupported ecosystems.','The local process is not a security sandbox; use the provided container for isolation.']}
    store.save(scan)
    return store.get(scan_id)
