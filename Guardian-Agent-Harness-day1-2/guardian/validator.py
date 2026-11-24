"""Human-approved edits in disposable Docker workspaces; no host repository execution."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from .discovery import read_tree
from .engine import run_scan
from .store import now


class Blocked(ValueError):
    pass


def runtime(profile):
    """Resolve Docker and an immutable local image ID. Never falls back to running repository code on the host."""
    kind = profile.get('runtime')
    if kind not in ('node','python'): raise Blocked(profile.get('reason','Unsupported sandbox runtime'))
    docker = shutil.which('docker')
    if not docker:
        candidate = Path('/Applications/Docker.app/Contents/Resources/bin/docker')
        if candidate.is_file(): docker = str(candidate)
    if not docker: raise Blocked('Docker is not installed or not on PATH; build/test is never run on the host')
    image = os.environ.get('GUARDIAN_SANDBOX_'+kind.upper()+'_IMAGE', 'node:22-bookworm-slim' if kind=='node' else 'python:3.12-slim')
    try:
        proc = subprocess.run([docker,'image','inspect','--format','{{.Id}}',image], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Blocked('Docker daemon is unreachable: '+str(exc)[:200])
    image_id = proc.stdout.strip()
    if proc.returncode != 0 or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise Blocked(f'Sandbox image {image} is not available locally; run: docker pull {image}')
    return docker, image_id


def copy_snapshot(scan, destination, artifact_root=None, strict=True):
    root = Path(scan.get('source_root',scan['repo'])).resolve()
    if not root.is_dir(): raise Blocked('Original checkout unavailable; rescan first')
    current, warnings = read_tree(root)
    expected = {name:info for name,info in scan['files'].items() if not info.get('generated')}
    if warnings: raise Blocked('Source snapshot has unreadable files or exceeds scanning limits')
    # In strict mode (for package upgrades that edit manifests) we require the repo
    # to be byte-for-byte identical to the scan. For digest-pin / investigation plans
    # the repo may have changed innocuously; we just copy what was scanned and still exists.
    if strict and (set(current) != set(expected) or any(current[n]['hash'] != expected[n]['hash'] for n in expected)):
        raise Blocked('Repository changed since the scan; rescan and approve a fresh proposal')
    omitted = []
    for name, info in expected.items():
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts: raise Blocked('Unsafe snapshot path')
        if rel.name in {'.npmrc','.pypirc','.netrc','.git-credentials'} or rel.name.startswith('.env') or any(part in {'.ssh','.aws','.azure','.gcloud'} for part in rel.parts):
            omitted.append(name); continue
        source = root/rel
        # Recheck the actual copied bytes, including binary inputs, after inventory.
        if source.is_symlink() or any(p.is_symlink() for p in source.parents if root in p.parents): raise Blocked('Symlink appeared in snapshot')
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != info['hash']: raise Blocked('Source changed while copying')
        target = destination/rel; target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw); target.chmod(0o755 if os.access(source,os.X_OK) else 0o644)
    for name, info in scan['files'].items():
        if not info.get('generated'): continue
        artifact = Path(info.get('artifact','')).resolve()
        if artifact_root is None or Path(artifact_root).resolve() not in artifact.parents:
            raise Blocked('Generated lockfile artifact is unavailable; rescan first')
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts: raise Blocked('Invalid generated artifact path')
        raw = artifact.read_bytes()
        if hashlib.sha256(raw).hexdigest() != info['hash']: raise Blocked('Generated lockfile changed since scan')
        target = destination/rel; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(raw)
    return omitted


def apply_edits(work, plan):
    if not plan.get('edits'): raise Blocked('Plan has no executable edits; regenerate the recommendation')
    for edit in plan['edits']:
        rel = Path(edit['file'])
        if rel.is_absolute() or '..' in rel.parts: raise Blocked('Unsafe edit path')
        target = work/rel
        if not target.is_file() or target.is_symlink(): raise Blocked('Edit target is unavailable')
        if hashlib.sha256(target.read_bytes()).hexdigest() != edit['before_hash']: raise Blocked('Approved patch no longer matches source')
        target.write_bytes(edit['after'].encode('utf-8'))


def validate_install_inputs(work, profile):
    cwd = work/profile.get('cwd','.')
    if profile['runtime'] == 'node' and any(c['network'] for c in profile['commands']):
        from .resolver import sanitized_manifest
        manifest = json.loads((cwd/'package.json').read_text())
        sanitized_manifest(manifest)
        if manifest.get('workspaces'):
            raise Blocked('Workspace installation requires an explicit adapter')
        if manifest.get('overrides'):
            if any(not isinstance(v,str) for v in manifest['overrides'].values()): raise Blocked('Nested overrides require an adapter')
            sanitized_manifest({'dependencies':manifest['overrides']})
        for name in ('package-lock.json','npm-shrinkwrap.json'):
            path = cwd/name
            if not path.exists(): continue
            lock = json.loads(path.read_text())
            if not isinstance(lock.get('packages'),dict): raise Blocked('Supported npm lockfile v2/v3 required')
            for package in lock['packages'].values():
                ref = package.get('resolved','')
                if package.get('link') or ref and not ref.startswith('https://registry.npmjs.org/'):
                    raise Blocked('Sandbox install only allows public npm registry artifacts; local/git/custom registry dependency needs review')
                sanitized_manifest(package)
    if profile['runtime'] == 'python':
        import re
        for command in profile['commands']:
            if command['name'] != 'install': continue
            requirement = cwd/command['argv'][-1]
            for line in requirement.read_text().splitlines():
                if line.strip() and not line.lstrip().startswith('#') and not re.fullmatch(r'\s*[\w.-]+(?:\[[\w, .-]+\])?\s*==\s*[\w.+!-]+(?:\s*;[^\n]+)?(?:\s*#.*)?',line):
                    raise Blocked('Python sandbox install requires exact registry requirements; URLs, includes and pip options need an adapter')


def container_step(docker, image, work, profile, command):
    name = 'guardian-'+uuid.uuid4().hex[:16]
    cwd = Path(profile.get('cwd','.'))
    if cwd.is_absolute() or '..' in cwd.parts: raise Blocked('Invalid sandbox working directory')
    args = [docker,'run','--name',name,'--rm','--pull=never','--read-only',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128',
            '--memory=2g','--cpus=2','--ulimit','fsize=134217728:134217728',
            '--network=bridge' if command['network'] else '--network=none',
            '--user',str(os.getuid())+':'+str(os.getgid()),
            '--tmpfs','/tmp:rw,nosuid,nodev,size=512m',
            '--mount','type=bind,source='+str(work)+',target=/work',
            '--workdir','/work/'+cwd.as_posix(),
            '--env','HOME=/tmp','--env','CI=true',
            '--env','npm_config_cache=/tmp/npm-cache','--env','npm_config_ignore_scripts=true',
            '--env','npm_config_registry=https://registry.npmjs.org/',
            '--env','npm_config_userconfig=/tmp/guardian-user.npmrc','--env','npm_config_globalconfig=/tmp/guardian-global.npmrc',
            '--env','PIP_CONFIG_FILE=/dev/null','--env','PIP_INDEX_URL=https://pypi.org/simple',
            '--env','PYTHONPATH=/work/.guardian-python',image,*command['argv']]
    started = time.monotonic(); timed_out = False; oversized = False
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                timed_out = time.monotonic()-started > 300
                oversized = os.fstat(output.fileno()).st_size > 1024*1024
                if timed_out or oversized:
                    process.kill(); break
                time.sleep(.1)
            process.wait(timeout=10)
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)
            subprocess.run([docker,'rm','--force',name],capture_output=True,timeout=15)
        output.seek(0); log = output.read(65536).decode('utf-8',errors='replace')
    return {'name':command['name'],'argv':command['argv'],'network':command['network'],
            'exit_code':process.returncode,'passed':process.returncode==0 and not timed_out and not oversized,
            'timeout':timed_out,'log_limit_exceeded':oversized,'output':log,'duration_seconds':round(time.monotonic()-started,2)}


def prune_nested_overrides(lock_data, pkg_name, target_ver):
    packages = lock_data.get('packages', {})
    pruned = []
    for k in list(packages.keys()):
        if k.endswith('/node_modules/' + pkg_name):
            del packages[k]
            pruned.append(k)
    top_key = 'node_modules/' + pkg_name
    if top_key in packages:
        packages[top_key]['version'] = target_ver
    def clean_deps(deps):
        if not isinstance(deps, dict): return
        for k, v in list(deps.items()):
            if isinstance(v, dict):
                if 'dependencies' in v and pkg_name in v['dependencies']:
                    del v['dependencies'][pkg_name]
                    pruned.append(f'deps:{k}->{pkg_name}')
                clean_deps(v.get('dependencies', {}))
    clean_deps(lock_data.get('dependencies', {}))
    return pruned


def identity(scan, finding):
    node = next((n for n in scan['graph']['nodes'] if n['id']==finding['component']), {})
    return (finding['rule'], node.get('ecosystem'), node.get('name') if node.get('type')=='package' else None,
            finding.get('advisory') if finding['rule']=='known-vulnerability' else finding.get('file'))


def identity_with_version(scan, finding):
    """Stricter identity including the specific installed version — used for before/after matching
    so that the same advisory on a different (upgraded) version does NOT count as the same finding."""
    node = next((n for n in scan['graph']['nodes'] if n['id']==finding['component']), {})
    return (finding['rule'], node.get('ecosystem'), node.get('name') if node.get('type')=='package' else None,
            node.get('version'),
            finding.get('advisory') if finding['rule']=='known-vulnerability' else finding.get('file'))


def compare(before, after, target, original):
    # Use strict version-aware identity for target (so advisory on old version 4.0.11 is
    # considered absent if no finding for that exact version/advisory combo remains in after)
    target_key_strict = identity_with_version(original, target)
    # Use loose identity for new-finding detection (advisory name + package, any version)
    target_key_loose = identity(original, target)
    before_keys_strict = {identity_with_version(before,f) for f in before['findings']}
    after_keys_strict  = {identity_with_version(after,f)  for f in after['findings']}
    before_keys_loose  = {identity(before,f) for f in before['findings']}
    # A finding is "new" only if it wasn't observed in the before scan at all
    new = [f for f in after['findings'] if identity_with_version(after,f) not in before_keys_strict]
    high = [f['id'] for f in new if f['risk_level'] in ('Critical','High','Unknown')]
    def packages(scan):
        return {(n.get('ecosystem'),n['name'],n['version']) for n in scan['graph']['nodes'] if n['type']=='package'}
    old, current = packages(before), packages(after)
    complete = all(s['coverage']['inventory']=='complete' and s['coverage']['vulnerability_status'] in ('complete','not applicable') for s in (before,after))
    # target_absent_after: the specific vulnerable version/advisory combo is gone
    target_absent = target_key_strict not in after_keys_strict
    return {'target_observed_before': target_key_strict in before_keys_strict,
            'target_absent_after': target_absent,
            'coverage_complete': complete,
            'new_high_or_unknown_findings': high,
            'new_findings': [f['id'] for f in new],
            'remaining_findings': [f['id'] for f in after['findings']],
            'sbom_added': [list(p) for p in sorted(current-old,key=str)],
            'sbom_removed': [list(p) for p in sorted(old-current,key=str)]}


def summarize_checks(steps, profile, mode):
    """Per-phase build/test outcome for the report. 'skipped_auth' is not a pass."""
    by_name = {s['name']: s for s in steps if not s.get('skipped')}
    def state(name):
        if mode == 'rescan_only': return 'not_run'
        if name in by_name: return 'passed' if by_name[name]['passed'] else 'failed'
        if any(s.get('skipped') and name in s['name'] for s in steps): return 'skipped_auth'
        return 'not_configured'
    install = [by_name[n] for n in ('lockfile','install') if n in by_name]
    install_state = 'not_run' if mode == 'rescan_only' else ('not_configured' if not install else 'passed' if all(s['passed'] for s in install) else 'failed')
    return {'install': install_state, 'build': state('build'), 'test': state('test'),
            'integrity': 'failed' if 'evidence integrity' in by_name and not by_name['evidence integrity']['passed'] else 'passed',
            'missing': list(profile.get('missing_checks', []))}


def decide(result, checks_summary, comparison, mode):
    """Status rules. 'verified' needs: build/test gates passed, a test really ran, target gone,
    no new high/critical/unknown findings and complete scanner coverage."""
    steps = [s for s in result['steps'] if not s.get('skipped')]
    failed_steps = [s['name'] for s in steps if not s['passed']]
    if failed_steps:
        return 'failed', 'Sandbox step(s) failed: '+', '.join(failed_steps)+'. See step logs.'
    if not comparison['target_absent_after']:
        return 'failed', ('Target finding still detected after the fix. If the package appears in nested node_modules '
                          'paths, an override may need a parent upgrade. Review remaining_findings and sbom_removed.')
    if comparison['new_high_or_unknown_findings']:
        return 'failed', 'The change introduced new high/critical/unknown findings; see comparison.new_findings.'
    if mode == 'rescan_only':
        return 'inconclusive', 'Rescan-only mode: target finding is gone and nothing new appeared, but build and tests were NOT run.'
    if checks_summary['test'] == 'skipped_auth':
        return 'inconclusive', 'Test script needs external service authentication and was skipped in the sandbox; run the full suite before merging.'
    if checks_summary['test'] != 'passed':
        return 'inconclusive', 'No test step was executed. Add a "test" script or .guardian-validation.json so correctness can be verified.'
    if not comparison['coverage_complete']:
        return 'inconclusive', 'Scanner coverage was incomplete; rescan with full advisory data before merging.'
    return 'verified', 'Verification is limited to configured checks and scanner coverage. Review remaining/new findings before merging; the original repository was not modified.'


def validate(store, plan_id, validation_id, progress=None, mode='full'):
    """Approved plan -> strict sandbox copy -> baseline scan -> patch -> install/build/test in Docker -> rescan -> compare.
    mode='rescan_only' skips install/build/test, never yields 'verified'."""
    progress = progress or (lambda _:None)
    if mode not in ('full','rescan_only'): mode = 'full'
    result = {'id':validation_id,'plan_id':plan_id,'status':'running','created':now(),'steps':[],'original_modified':False,
              'mode':mode,'verification_level':'build+test' if mode=='full' else 'rescan-only'}
    try:
        plan = store.remediation_plan(plan_id)
        if plan['status'] != 'approved': raise Blocked('Human approval is required before sandbox execution')
        if not plan.get('execution_ready'): raise Blocked('Plan is not executable; regenerate or complete its required investigation')
        profile = plan['validation_profile']
        original = store.get(plan['scan_id'])
        target = next(f for f in original['findings'] if f['id']==plan['finding_id'])
        run_commands = mode == 'full' and bool(profile.get('commands'))
        docker, image = None, 'not-used'
        if run_commands:
            progress('Checking Docker sandbox'); docker, image = runtime(profile)
        result['image_id'] = image; result['profile'] = profile
        work = store.directory/'repositories'/('sandbox-'+validation_id)
        work.mkdir(parents=True,exist_ok=False); result['workspace'] = str(work)

        progress('Copying approved source snapshot')
        # Strict for every executable plan: any drift outside the approved diff blocks before execution.
        result['omitted_credentials'] = copy_snapshot(original, work, store.directory/'resolutions')

        progress('Scanning sandbox snapshot before patch')
        before = run_scan(str(work), store, resolve=False, ai=False)
        result['before_scan_id'] = before['id']
        if identity(original, target) not in {identity(before,f) for f in before['findings']}:
            result['steps'].append({'name':'baseline-check','passed':True,'network':False,'informational':True,
                'output':'Target finding was not reproduced verbatim in the sandbox baseline (possible lockfile vs installed version mismatch). Proceeding with after-scan comparison.'})
        apply_edits(work, plan)
        if plan.get('transitive_override'):
            target_pkg = plan.get('target_package') or (target.get('component','').split('@')[0].split('/')[-1] if target else None)
            target_ver = plan.get('target_version')
            if target_pkg and target_ver:
                for fname in ('package-lock.json','npm-shrinkwrap.json'):
                    lpath = work/Path(profile.get('cwd','.'))/fname
                    if lpath.is_file():
                        try:
                            ldata = json.loads(lpath.read_text(encoding='utf-8'))
                            if prune_nested_overrides(ldata, target_pkg, target_ver):
                                lpath.write_text(json.dumps(ldata, indent=2)+'\n', encoding='utf-8')
                        except (OSError, ValueError):
                            pass
        if run_commands:
            validate_install_inputs(work, profile)
            evidence_hashes = None
            for command in profile['commands']:
                if not command['network'] and evidence_hashes is None:
                    observed, _ = read_tree(work)
                    evidence_hashes = {name:info['hash'] for name,info in observed.items() if Path(name).name in ('package.json','package-lock.json','npm-shrinkwrap.json') or Path(name).name.startswith('requirements') or name in plan['preconditions']}
                progress('Sandbox: '+command['name'])
                step = container_step(docker,image,work,profile,command)
                result['steps'].append(step)
                # Install/lockfile failures make later steps meaningless; build/test failures are still recorded and fail the run.
                if not step['passed'] and command['name'] in ('lockfile','install'): break
            if evidence_hashes is not None:
                observed, _ = read_tree(work)
                if any(observed.get(name,{}).get('hash') != digest for name,digest in evidence_hashes.items()):
                    result['steps'].append({'name':'evidence integrity','passed':False,'output':'Build/test modified approved source or dependency manifests; result cannot be trusted'})
        for note in profile.get('skipped_auth_checks', []):
            result['steps'].append({'name':'test (skipped)','passed':True,'network':False,'skipped':True,'output':'Skipped: '+note})

        progress('Rescanning patched sandbox')
        after = run_scan(str(work), store, resolve=False, ai=False)
        result['after_scan_id'] = after['id']
        result['comparison'] = compare(before, after, target, original)
        result['checks'] = summarize_checks(result['steps'], profile, mode)
        result['status'], result['note'] = decide(result, result['checks'], result['comparison'], mode)
    except Blocked as exc:
        result.update(status='blocked',error=str(exc))
    except Exception as exc:
        import traceback
        result.update(status='failed',error=str(exc)[:1000],traceback=traceback.format_exc()[:3000])
    result['finished'] = now()
    store.finish_validation(result)
    return result
