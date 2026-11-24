"""Opt-in live integration smoke test; Docker, registry and OSV network required.
Run: .venv/bin/python tests/smoke_docker.py
Creates an intentionally vulnerable test fixture, not a user-repository approval.
"""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guardian.store import Store
from guardian.engine import run_scan
from guardian.validator import runtime, container_step, validate


def main():
    root = Path(tempfile.mkdtemp(prefix='guardian-docker-e2e-')).resolve()
    repo = root/'fixture'; repo.mkdir()
    manifest = {'name':'guardian-live-integration-fixture','version':'1.0.0','private':True,
                'dependencies':{'lodash':'4.17.20'},'scripts':{'test':'node test.js'}}
    (repo/'package.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (repo/'test.js').write_text("const assert = require('node:assert/strict');\nconst _ = require('lodash');\nassert.deepEqual(_.chunk([1,2,3],2), [[1,2],[3]]);\nconsole.log('Functional smoke test passed');\n")
    store = Store(root/'data')
    print('Integration fixture:',root,flush=True)
    profile = {'runtime':'node','cwd':'.'}
    docker,image = runtime(profile)
    step = container_step(docker,image,repo,profile,{'name':'fixture-lockfile','argv':['npm','install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund'],'network':True})
    if not step['passed']: raise RuntimeError(step)
    baseline = run_scan(str(repo),store,resolve=False)
    finding = next(f for f in baseline['findings'] if f['rule']=='known-vulnerability')
    plan = store.recommend(baseline['id'],finding['id'])
    print('Generated target from live data:',plan.get('target_version'),flush=True)
    if not plan.get('execution_ready'): raise RuntimeError(plan['blockers'])
    original = (repo/'package.json').read_bytes()
    store.decide_remediation(plan['id'],'approved','Automated integration fixture','Test-only approval of disposable synthetic fixture; no user repository approval')
    vid = store.begin_validation(plan['id'])
    result = validate(store,plan['id'],vid,lambda message:print(message,flush=True))
    assert (repo/'package.json').read_bytes() == original, 'Original fixture was modified'
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'error':result.get('error'),'result':str(root/'result.json'),'target':plan['target_version'],'comparison':result.get('comparison')},indent=2),flush=True)
    if result['status']!='verified': raise SystemExit(1)


if __name__=='__main__': main()
