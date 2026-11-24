"""Second human gate: commit a sandbox-validated fix to a NEW branch of the scanned repository.

Uses git plumbing against a temporary index, so the user's working tree, index and checked-out
branch are never touched. Never pushes, merges, force-updates or deploys. Hooks are disabled."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from .store import now


class CommitBlocked(ValueError):
    pass


LOCKFILES = ('package-lock.json', 'npm-shrinkwrap.json')


def _git(root, args, env_extra=None, input_bytes=None):
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin:/usr/local/bin'), 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_TERMINAL_PROMPT': '0', **(env_extra or {})}
    proc = subprocess.run(['git', '--no-pager', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-C', str(root), *args],
                          capture_output=True, input=input_bytes, timeout=60, env=env)
    if proc.returncode:
        raise CommitBlocked('git '+args[0]+' failed: '+proc.stderr.decode('utf-8', 'replace')[-400:])
    return proc.stdout


def _safe_rel(name):
    rel = Path(name)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts: raise CommitBlocked('Unsafe file path in plan')
    return rel.as_posix()


def files_to_commit(plan, scan, sandbox):
    """Approved edits plus the regenerated npm lockfile; nothing else from the sandbox is ever copied."""
    files = {}
    for edit in plan.get('edits', []):
        rel = _safe_rel(edit['file'])
        path = sandbox/rel
        if path.is_symlink() or not path.is_file(): raise CommitBlocked('Sandbox copy of '+rel+' is missing')
        content = path.read_bytes()
        if content != edit['after'].encode('utf-8'):
            raise CommitBlocked('Sandbox file '+rel+' no longer matches the approved patch; rerun validation')
        files[rel] = {'content': content, 'expected_head_hash': edit['before_hash'], 'kind': 'approved-edit'}
    profile = plan.get('validation_profile') or {}
    if profile.get('runtime') == 'node' and any(c['name'] == 'lockfile' for c in profile.get('commands', [])):
        cwd = Path(profile.get('cwd', '.'))
        for name in LOCKFILES:
            rel = _safe_rel((cwd/name).as_posix())
            path = sandbox/rel
            if path.is_symlink() or not path.is_file(): continue
            if path.stat().st_size > 16*1024*1024: raise CommitBlocked('Lockfile is too large to commit')
            info = scan['files'].get(rel)
            # A scan-time lockfile that Guardian generated (not in the repo) is added; a committed one must still match the scan.
            files[rel] = {'content': path.read_bytes(), 'expected_head_hash': None if (not info or info.get('generated')) else info['hash'],
                          'kind': 'regenerated-lockfile'}
    if not files: raise CommitBlocked('Nothing to commit')
    return files


def commit_validated_fix(store, validation_id, actor, reason, accept_inconclusive=False):
    store.identity(actor, reason)
    validation = store.validation(validation_id)
    if validation.get('commit'): raise CommitBlocked('This validation was already committed to '+validation['commit']['branch'])
    status = validation.get('status')
    if status == 'inconclusive' and not accept_inconclusive:
        raise CommitBlocked('Validation is inconclusive ('+validation.get('note', 'tests not run')+'). Confirm explicitly to commit anyway.')
    if status not in ('verified', 'inconclusive'): raise CommitBlocked('Only verified or explicitly accepted inconclusive validations can be committed (status: '+str(status)+')')
    plan = store.remediation_plan(validation['plan_id'])
    if plan['status'] != 'approved': raise CommitBlocked('The remediation plan is not approved')
    scan = store.get(plan['scan_id'])
    root = Path(scan.get('source_root', '')).resolve()
    if not (root/'.git').exists(): raise CommitBlocked('Scanned source is not a Git checkout; export the patch instead')
    sandbox = Path(validation.get('workspace', '')).resolve()
    if store.directory.resolve() not in sandbox.parents or not sandbox.is_dir(): raise CommitBlocked('Validation sandbox is unavailable; rerun validation')

    files = files_to_commit(plan, scan, sandbox)
    head = _git(root, ['rev-parse', '--verify', 'HEAD']).decode().strip()
    try: base_branch = _git(root, ['symbolic-ref', '--short', 'HEAD']).decode().strip()
    except CommitBlocked: base_branch = 'detached HEAD'
    modes = {}
    for rel, info in files.items():
        try:
            blob = _git(root, ['cat-file', 'blob', 'HEAD:'+rel])
            listing = _git(root, ['ls-tree', 'HEAD', '--', rel]).split()
            modes[rel] = listing[0].decode() if listing else '100644'
        except CommitBlocked:
            blob = None; modes[rel] = '100644'
        if info['expected_head_hash'] is not None:
            if blob is None or hashlib.sha256(blob).hexdigest() != info['expected_head_hash']:
                raise CommitBlocked(rel+' at HEAD differs from the version that was scanned and approved. Commit/stash local changes or rescan.')
        elif blob is not None and info['kind'] == 'regenerated-lockfile':
            raise CommitBlocked(rel+' now exists at HEAD but did not when scanned. Rescan and approve again.')

    branch = 'guardian/fix-'+plan['id'][2:14]
    if _git(root, ['for-each-ref', 'refs/heads/'+branch]).strip(): raise CommitBlocked('Branch '+branch+' already exists')
    checks = validation.get('checks', {})
    message = '\n'.join([
        'Guardian: '+plan.get('action', 'remediation')[:70]+' ('+str(plan.get('current_version'))+' -> '+str(plan.get('target_version'))+')', '',
        'Finding: '+plan['finding_id']+'  Plan: '+plan['id'],
        'Validation '+validation_id+': '+status+' ('+validation.get('verification_level', '')+')',
        'Install: '+str(checks.get('install'))+'  Build: '+str(checks.get('build'))+'  Tests: '+str(checks.get('test')),
        ('Note: '+validation['note']) if validation.get('note') else 'Note: none', '',
        'Rollback: git revert <this commit>',
        'Approved-by: '+actor+' ('+reason[:200].replace('\n', ' ')+')'])
    with tempfile.TemporaryDirectory() as tmp:
        index = {'GIT_INDEX_FILE': str(Path(tmp)/'index')}
        _git(root, ['read-tree', 'HEAD'], index)
        for rel, info in files.items():
            oid = _git(root, ['hash-object', '-w', '--stdin'], input_bytes=info['content']).decode().strip()
            _git(root, ['update-index', '--add', '--cacheinfo', modes[rel]+','+oid+','+rel], index)
        tree = _git(root, ['write-tree'], index).decode().strip()
    author = {'GIT_AUTHOR_NAME': actor[:100], 'GIT_AUTHOR_EMAIL': 'noreply@guardian.local',
              'GIT_COMMITTER_NAME': 'GuardianAI', 'GIT_COMMITTER_EMAIL': 'noreply@guardian.local'}
    commit = _git(root, ['commit-tree', tree, '-p', head, '-m', message], author).decode().strip()
    _git(root, ['update-ref', 'refs/heads/'+branch, commit, ''])  # empty old value: create only, never overwrite
    patch_dir = store.directory/'patches'; patch_dir.mkdir(exist_ok=True)
    patch = patch_dir/(plan['id']+'.patch')
    patch.write_bytes(_git(root, ['format-patch', '-1', '--stdout', commit]))
    info = {'branch': branch, 'commit': commit, 'base_commit': head, 'base_branch': base_branch, 'repository': str(root),
            'files': sorted(files), 'patch': str(patch), 'approved_by': actor, 'reason': reason, 'created': now(), 'pushed': False}
    store.record_commit(validation_id, info, plan['scan_id'], plan['id'])
    return info
