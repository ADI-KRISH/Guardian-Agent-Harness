"""Repository-derived commands, displayed as part of the approved proposal."""
import json
import re
from pathlib import PurePosixPath

# Test commands that require external service authentication and cannot run in an
# isolated sandbox with no credentials. We skip these and mark the check as
# "skipped-auth" rather than failing the entire validation.
SANDBOX_AUTH_BLOCKERS = re.compile(
    r'\bsnyk\b|\bsonar\b|\bcodecov\b|\bcoveralls\b|\bwhitesource\b|\bmend\b|\bfossa\b|\bblacklisted\b',
    re.IGNORECASE
)

def _skip_external_auth(script_text):
    """Return True if the npm script string requires external service auth."""
    return bool(SANDBOX_AUTH_BLOCKERS.search(script_text))


def profile(scan, plan, read_source):
    files = scan.get('files', {})
    config_text = read_source(scan, '.guardian-validation.json')
    config = json.loads(config_text) if config_text is not None else {}
    if not isinstance(config, dict): raise ValueError('Validation configuration must be an object')
    target = PurePosixPath(plan.get('target_file') or '')
    parents = [target.parent, *target.parent.parents]

    manifest = next((str(p/'package.json') for p in parents if str(p/'package.json') in files), None)
    commands = []
    skipped_auth = []
    if manifest:
        data = json.loads(read_source(scan, manifest) or '{}')
        cwd = str(PurePosixPath(manifest).parent)
        manager = data.get('packageManager', 'npm')
        if not manager.startswith('npm') or any(str(PurePosixPath(cwd)/f) in files for f in ('yarn.lock','pnpm-lock.yaml')):
            return {'runtime':'unsupported', 'commands':[], 'reason':'Package manager requires a validation adapter; npm must not rewrite yarn/pnpm lockfiles'}
        if data.get('workspaces'):
            return {'runtime':'unsupported', 'commands':[], 'reason':'Workspace dependency installation requires an explicit workspace adapter'}
        commands = [
            {'name':'lockfile', 'argv':['npm','install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund'], 'network':True},
            {'name':'install', 'argv':['npm','ci','--ignore-scripts','--no-audit','--no-fund'], 'network':True},
        ]
        scripts = data.get('scripts', {})
        for name in ('build','test'):
            if name in scripts:
                script_text = scripts[name]
                if _skip_external_auth(script_text):
                    # Mark as skipped rather than adding a command that will fail
                    skipped_auth.append(f'{name} ({script_text[:80]}) — requires external service auth, skipped in sandbox')
                else:
                    commands.append({'name':name, 'argv':['npm','run','--ignore-scripts',name], 'network':False})
        runtime = 'node'
    elif target.name.startswith('requirements') and target.suffix == '.txt':
        cwd = str(target.parent); runtime = 'python'
        commands = [{'name':'install','argv':['python','-m','pip','install','--only-binary=:all:','--target=/work/.guardian-python','-r',target.name], 'network':True}]
    else:
        cwd = '.'; runtime = config.get('runtime','node')
    if runtime not in ('node','python'): raise ValueError('Supported validation runtimes are node and python')
    for name in ('build','test'):
        if name in config:
            argv = config[name]
            if not isinstance(argv, list) or not argv or len(argv) > 32 or any(not isinstance(v,str) or not v or len(v)>1000 or '\0' in v for v in argv):
                raise ValueError('Validation commands must be non-empty argument arrays')
            commands = [c for c in commands if c['name'] != name]
            commands.append({'name':name,'argv':argv,'network':False})
    missing = [name for name in ('build','test') if not any(c['name']==name for c in commands)]
    return {'runtime':runtime,'cwd':cwd,'commands':commands,
            'missing_checks': missing,
            'skipped_auth_checks': skipped_auth,
            'network_policy':'Registry installation only; repository build/test commands run with networking disabled. No host credentials, Docker socket or original checkout are mounted.'}
