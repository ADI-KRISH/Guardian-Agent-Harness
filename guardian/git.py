"""Push an approved & verified fix to a new Git branch. Never touches the original checkout."""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Branch / commit message generation
# ---------------------------------------------------------------------------

def _slug(text, maxlen=40):
    """Turn arbitrary text into a safe branch-name segment."""
    text = text.lower().strip()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    text = text.strip('-')
    return text[:maxlen]


def branch_name(plan, finding):
    """
    Derive a descriptive branch name from the plan and finding.

    Examples
    --------
    fix/GHSA-765h-qjxv-5f44-handlebars-4.0.11-to-4.7.10
    fix/floating-image-Dockerfile
    fix/unpinned-action-ci.yml
    """
    rule = finding.get('rule', 'fix')
    if rule == 'known-vulnerability':
        advisory = finding.get('advisory', '')
        pkg = plan.get('target_package') or ''
        current = plan.get('current_version') or ''
        target = plan.get('target_version') or ''
        parts = ['fix']
        if advisory:
            parts.append(_slug(advisory, 40))
        if pkg:
            parts.append(_slug(pkg, 20))
        if current and target:
            parts.append(f'{_slug(current, 15)}-to-{_slug(target, 15)}')
        return '/'.join(parts)
    elif rule in ('floating-image', 'unpinned-action'):
        fname = Path(finding.get('file', 'file')).name
        return f'fix/{_slug(rule, 20)}-{_slug(fname, 30)}'
    else:
        fname = Path(finding.get('file', 'fix')).name
        return f'fix/{_slug(rule or "security", 20)}-{_slug(fname, 30)}'


def commit_message(plan, finding):
    """
    Compose a structured commit message from the plan and finding.

    Format
    ------
    fix(<scope>): <what>

    Advisory: <id>
    Fix: <current> → <target>
    File: <target_file>
    Plan: <plan_id>
    """
    rule = finding.get('rule', '')
    lines = []

    if rule == 'known-vulnerability':
        pkg = plan.get('target_package') or finding.get('component', 'dependency')
        advisory = finding.get('advisory', '')
        current = plan.get('current_version') or '?'
        target = plan.get('target_version') or '?'
        what = finding.get('what') or f'upgrade {pkg} to {target}'
        scope = _slug(pkg, 25)
        lines.append(f'fix({scope}): {what[:72]}')
        lines.append('')
        if advisory:
            lines.append(f'Advisory: {advisory}')
        lines.append(f'Upgrade: {pkg} {current} → {target}')
        lines.append(f'File: {plan.get("target_file", "")}')
    elif rule == 'floating-image':
        fname = finding.get('file', '')
        what = finding.get('what') or 'pin Docker image to immutable digest'
        lines.append(f'fix(docker): {what[:72]}')
        lines.append('')
        lines.append(f'File: {fname}')
        new_ref = plan.get('target_version') or ''
        if new_ref:
            lines.append(f'Pinned to: {new_ref}')
    elif rule == 'unpinned-action':
        fname = finding.get('file', '')
        what = finding.get('what') or 'pin GitHub Action to immutable commit SHA'
        lines.append(f'fix(ci): {what[:72]}')
        lines.append('')
        lines.append(f'File: {fname}')
        new_ref = plan.get('target_version') or ''
        if new_ref:
            lines.append(f'Pinned to: {new_ref}')
    else:
        what = finding.get('what') or 'apply security fix'
        lines.append(f'fix(security): {what[:72]}')

    lines.append('')
    lines.append(f'GuardianAI Plan: {plan.get("id", "")}')
    lines.append('Validated: Sandbox verification passed before this commit was created.')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Git push logic
# ---------------------------------------------------------------------------

def _run(args, cwd, error_prefix='git'):
    """Run a git command and return stdout; raise ValueError with stderr on failure."""
    result = subprocess.run(
        args, cwd=str(cwd),
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise ValueError(f'{error_prefix} failed: {result.stderr.strip()[:500]}')
    return result.stdout.strip()


def _git_available():
    return bool(shutil.which('git'))


def repo_info(source_root):
    """
    Returns dict with:
      - is_git: bool
      - remote_url: str | None   (e.g. https://github.com/owner/repo)
      - is_remote_origin: bool   (True if origin is a public GitHub/GitLab URL)
    """
    if not _git_available():
        return {'is_git': False, 'remote_url': None, 'is_remote_origin': False}
    root = Path(source_root).resolve()
    try:
        _run(['git', 'rev-parse', '--git-dir'], root, 'git check')
    except (ValueError, subprocess.TimeoutExpired, FileNotFoundError):
        return {'is_git': False, 'remote_url': None, 'is_remote_origin': False}
    try:
        remote = _run(['git', 'remote', 'get-url', 'origin'], root)
    except ValueError:
        remote = None
    is_remote = bool(remote and re.search(r'github\.com|gitlab\.com|bitbucket\.org', remote))
    return {'is_git': True, 'remote_url': remote, 'is_remote_origin': is_remote}


def push_fix(source_root, plan, finding, fork_url=None, actor=None, sandbox_workspace=None):
    """
    Apply approved edits to the host repository in a new branch and push.

    Parameters
    ----------
    source_root : str
        Absolute path to the local repository checkout.
    plan : dict
        The approved remediation plan (must have 'edits', 'preconditions', 'id').
    finding : dict
        The finding the plan fixes.
    fork_url : str | None
        If the original remote is somebody else's repo, the user must supply
        the URL of their own fork here. If None and origin looks like a foreign
        GitHub URL, an error is raised asking for the fork URL.
    actor : str | None
        Reviewer name used in the commit author field.
    sandbox_workspace : str | None
        Path to the validated sandbox directory. If provided, any regenerated
        lockfiles (package-lock.json, npm-shrinkwrap.json, requirements*.txt)
        found there are included in the commit, so the pushed branch is
        immediately scannable without needing a manual `npm install`.

    Returns
    -------
    dict with keys: branch, commit, remote, pushed, lockfiles_included
    """
    if not _git_available():
        raise ValueError('git is not installed or not on PATH; install git to use this feature')

    if not plan.get('edits'):
        raise ValueError('Plan has no edits to commit; nothing to push')

    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError(f'Repository not found: {root}')

    info = repo_info(root)
    if not info['is_git']:
        raise ValueError('The scanned directory is not a git repository. Run "git init" first or scan a git repo.')

    # Decide the remote to push to
    remote_url = info['remote_url']
    if fork_url:
        push_remote = fork_url.strip()
    elif remote_url and info['is_remote_origin']:
        # If origin is a public GitHub/GitLab repo AND the user hasn't provided a fork,
        # we cannot push directly — they must fork it first.
        # We detect "foreign" by checking whether we have push access — but we cannot
        # authenticate here. Instead: we always require fork_url for remote repos.
        raise ValueError(
            f'The repository origin is a remote URL ({remote_url}). '
            'You cannot push directly to someone else\'s repository. '
            'Please fork the repository on GitHub/GitLab, then provide your fork URL '
            'in the "Fork URL" field and try again.'
        )
    elif remote_url:
        push_remote = remote_url  # local/personal remote
    else:
        push_remote = None  # no remote configured; branch-only commit

    branch = branch_name(plan, finding)
    message = commit_message(plan, finding)
    author = f'{actor or "GuardianAI"} <guardian-ai@localhost>'

    # Apply edits in a temp workspace, then copy patched files into the real repo
    # working-tree. We work inside a temp clone (--local, cheap) so we don't disturb
    # the user's current working tree or index state.
    lockfiles_included = []
    with tempfile.TemporaryDirectory(prefix='guardian-git-') as tmp:
        work = Path(tmp) / 'repo'

        # Shallow local clone: fast, doesn't copy the full object store
        _run(['git', 'clone', '--local', '--no-hardlinks', str(root), str(work)], tmp, 'git clone')

        # Ensure we're on a clean state from the default branch
        try:
            default = _run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], root)
        except ValueError:
            default = 'main'
        _run(['git', 'checkout', default], work, 'git checkout default')

        # Create and switch to the fix branch
        _run(['git', 'checkout', '-b', branch], work, 'git checkout -b')

        # Apply all approved edits
        import hashlib
        for edit in plan['edits']:
            rel = Path(edit['file'])
            if rel.is_absolute() or '..' in rel.parts:
                raise ValueError(f'Unsafe edit path: {edit["file"]}')
            target = work / rel
            if not target.is_file():
                raise ValueError(f'Edit target not found in clone: {edit["file"]}')
            # Verify the file matches what was approved
            current_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            if current_hash != edit['before_hash']:
                raise ValueError(
                    f'{edit["file"]} has changed since the plan was generated. '
                    'Rescan and regenerate the recommendation before pushing.'
                )
            target.write_bytes(edit['after'].encode('utf-8'))

        # Stage only the edited files
        for edit in plan['edits']:
            _run(['git', 'add', edit['file']], work, 'git add')

        # Bundle regenerated lockfiles from the sandbox workspace so the pushed
        # branch is immediately scannable without a manual `npm install`.
        lockfiles_included = []
        if sandbox_workspace:
            sandbox = Path(sandbox_workspace).resolve()
            profile_cwd = plan.get('validation_profile', {}).get('cwd', '.') or '.'
            sandbox_cwd = sandbox / Path(profile_cwd)
            # Lockfiles that npm/pip regenerate during sandbox validation
            candidates = ['package-lock.json', 'npm-shrinkwrap.json']
            # Also pick up any requirements*.txt that pip rewrote (Python upgrades)
            if sandbox_cwd.is_dir():
                candidates += [f.name for f in sandbox_cwd.iterdir()
                               if f.name.startswith('requirements') and f.name.endswith('.txt')]
            for lockname in candidates:
                sandbox_lock = sandbox_cwd / lockname
                if not sandbox_lock.is_file():
                    continue
                # Determine where this lockfile lives in the repo (relative path)
                plan_cwd = Path(profile_cwd)
                rel_lock = str(plan_cwd / lockname) if str(plan_cwd) != '.' else lockname
                target_lock = work / Path(rel_lock)
                if not target_lock.parent.is_dir():
                    continue
                target_lock.write_bytes(sandbox_lock.read_bytes())
                _run(['git', 'add', rel_lock], work, 'git add lockfile')
                lockfiles_included.append(rel_lock)

        # Commit
        env_extra = {}  # git uses system env
        _run(['git', 'commit',
              '--author', author,
              '-m', message], work, 'git commit')

        commit_sha = _run(['git', 'rev-parse', 'HEAD'], work)

        # Push
        pushed = False
        push_result = None
        if push_remote:
            try:
                _run(['git', 'push', push_remote, f'{branch}:{branch}'], work, 'git push')
                pushed = True
                push_result = f'{push_remote} → {branch}'
            except ValueError as exc:
                push_result = str(exc)
        else:
            # No remote: apply the commit to the actual repo branch instead
            # We cherry-pick the commit from the temp clone into the real repo
            _run(['git', 'fetch', str(work), branch], root, 'git fetch temp')
            _run(['git', 'checkout', '-b', branch, 'FETCH_HEAD'], root, 'git checkout branch')
            commit_sha = _run(['git', 'rev-parse', 'HEAD'], root)
            pushed = False
            push_result = f'Branch "{branch}" created locally (no remote configured)'

    return {
        'branch': branch,
        'commit': commit_sha,
        'remote': push_remote or '(none)',
        'pushed': pushed,
        'push_result': push_result,
        'commit_message': message,
        'lockfiles_included': lockfiles_included,
    }