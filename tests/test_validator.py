import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from guardian.engine import run_scan
from guardian.store import Store
from guardian.validator import validate, copy_snapshot, Blocked, runtime
from guardian.patching import replace_values
from guardian.candidates import choose
from guardian.remediation import version


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'repo'; self.root.mkdir()
        self.store = Store(Path(self.tmp.name)/'store')
        (self.root/'package.json').write_text(json.dumps({'dependencies':{'arbitrary-package':'1.0.0'},'scripts':{'test':'node -e "process.exit(0)"'}}))
        (self.root/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'':{'dependencies':{'arbitrary-package':'1.0.0'}},'node_modules/arbitrary-package':{'version':'1.0.0'}}}))
        (self.root/'.github/workflows').mkdir(parents=True)
        self.workflow = self.root/'.github/workflows/check.yml'
        self.workflow.write_text('steps:\n  - uses: arbitrary-owner/custom-action@v7\n')
        self.store.cache('osv:npm:arbitrary-package:1.0.0',[])
        self.scan = run_scan(str(self.root),self.store,offline=True)
        self.finding = next(f for f in self.scan['findings'] if f['rule']=='unpinned-action')
        with patch('guardian.references.resolve',return_value=('arbitrary-owner/custom-action@v7','arbitrary-owner/custom-action@'+'b'*40,'https://api.github.com/fixture')):
            self.plan = self.store.recommend(self.scan['id'],self.finding['id'])
        self.real_scan = run_scan

    def approve(self):
        self.store.decide_remediation(self.plan['id'],'approved','Tester','Run approved sandbox checks')
        return self.store.begin_validation(self.plan['id'])

    def run_mocked_container_pipeline(self, step=None):
        vid = self.approve()
        def fake_step(docker,image,work,profile,command):
            if step: step(work,command)
            return {'name':command['name'],'passed':True,'exit_code':0,'output':'fixture runner'}
        def offline_scan(path,store,**kwargs):
            return self.real_scan(path,store,offline=True,**kwargs)
        with patch('guardian.validator.runtime',return_value=('/fixture/docker','sha256:'+'a'*64)), patch('guardian.validator.container_step',side_effect=fake_step), patch('guardian.validator.run_scan',side_effect=offline_scan):
            return validate(self.store,self.plan['id'],vid)

    def test_approved_patch_rescanned_original_untouched(self):
        original = self.workflow.read_bytes()
        result = self.run_mocked_container_pipeline()
        self.assertEqual(result['status'],'verified',result)
        self.assertTrue(result['comparison']['target_absent_after'])
        self.assertEqual(self.workflow.read_bytes(),original)
        self.assertIn('@'+'b'*40,(Path(result['workspace'])/'.github/workflows/check.yml').read_text())
        self.assertEqual(self.store.validation(result['id'])['status'],'verified')

    def test_approval_required(self):
        with self.assertRaisesRegex(ValueError,'approval'): self.store.begin_validation(self.plan['id'])

    def test_missing_runtime_is_blocked_not_faked(self):
        vid = self.approve()
        with patch('guardian.validator.runtime',side_effect=Blocked('Docker unavailable')):
            result = validate(self.store,self.plan['id'],vid)
        self.assertEqual(result['status'],'blocked')
        self.assertNotIn('after_scan_id',result)
        self.assertIn('@v7',self.workflow.read_text())

    def test_stale_repository_blocks_before_execution(self):
        (self.root/'new-file.txt').write_text('changed after approval')
        result = self.run_mocked_container_pipeline()
        self.assertEqual(result['status'],'blocked')
        self.assertIn('changed',result['error'])

    def test_new_high_risk_fails_validation(self):
        def step(work,command):
            if command['name']=='test': (work/'unsafe.py').write_text('exec(base64.b64decode("payload"))')
        result = self.run_mocked_container_pipeline(step)
        self.assertEqual(result['status'],'failed')
        self.assertTrue(result['comparison']['new_high_or_unknown_findings'])

    def test_tests_cannot_hide_findings_by_modifying_manifests(self):
        def step(work,command):
            if command['name']=='test': (work/'package-lock.json').write_text('{}')
        result = self.run_mocked_container_pipeline(step)
        self.assertEqual(result['status'],'failed')
        self.assertTrue(any(s['name']=='evidence integrity' for s in result['steps']))

    def test_failed_test_is_not_verified_even_when_target_removed(self):
        vid = self.approve()
        def fake_step(docker,image,work,profile,command):
            return {'name':command['name'],'passed':False,'exit_code':1,'output':'test failure'}
        with patch('guardian.validator.runtime',return_value=('docker','sha256:'+'a'*64)), patch('guardian.validator.container_step',side_effect=fake_step), patch('guardian.validator.run_scan',side_effect=lambda path,store,**kwargs:run_scan(path,store,offline=True,**kwargs)):
            result = validate(self.store,self.plan['id'],vid)
        self.assertEqual(result['status'],'failed')
        self.assertTrue(result['comparison']['target_absent_after'])

    def test_no_tests_is_inconclusive(self):
        # Use a fresh immutable proposal whose configured command list has no tests.
        plan = dict(self.plan, id='no-test-plan')
        plan['validation_profile'] = dict(plan['validation_profile'],commands=[])
        with self.store.connect() as db:
            db.execute('INSERT INTO remediation_plans VALUES(?,?,?)',(plan['id'],plan['scan_id'],json.dumps(plan)))
        self.plan = plan
        result = self.run_mocked_container_pipeline()
        self.assertEqual(result['status'],'inconclusive')

    def test_snapshot_omits_credentials(self):
        (self.root/'.env').write_text('TOKEN=private')
        scan = run_scan(str(self.root),self.store,offline=True)
        destination = Path(self.tmp.name)/'copy'; destination.mkdir()
        omitted = copy_snapshot(scan,destination)
        self.assertIn('.env',omitted); self.assertFalse((destination/'.env').exists())

    def test_restart_marks_running_job_interrupted(self):
        vid = self.approve(); self.store.recover_validations()
        self.assertEqual(self.store.validation(vid)['status'],'interrupted')


class GenerationTests(unittest.TestCase):
    def test_surgical_edit_preserves_every_other_byte(self):
        text = '{\r\n\t"dependencies": {"different-package" : "^1.2.3"},\r\n "scripts":{"test":"hello"}\r\n}\r\n'
        output = replace_values(text,{('dependencies','different-package'):'2.0.0'})
        self.assertEqual(output,text.replace('^1.2.3','2.0.0'))

    def test_ambiguous_json_is_rejected(self):
        with self.assertRaises(ValueError): replace_values('{"dependencies":{},"dependencies":{}}',{})

    def test_candidate_checks_registry_and_rejects_still_vulnerable_version(self):
        node = {'ecosystem':'npm','name':'not-a-demo-package','version':'1.0.0'}
        advisory = {'id':'ADVISORY-X','affected':[{'package':{'name':node['name'],'ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[{'fixed':'1.0.1'},{'fixed':'2.0.0'}]}]}]}
        with patch('guardian.candidates.osv.query',side_effect=[([advisory],'live'),([{'id':'OTHER-RISK'}],'live'),([],'live')]), patch('guardian.candidates.metadata',side_effect=[({'version':'2.0.0'},{}),({'version':'1.0.1'},{}),({'version':'2.0.0'},{})]) as registry:
            target, evidence = choose(node,{'advisory':'ADVISORY-X'},None,version)
        self.assertEqual(target,'2.0.0')
        self.assertIn('not-a-demo-package',registry.call_args[0][0])
        self.assertEqual(len(evidence['attempts']),2)

    def test_missing_advisory_does_not_guess(self):
        with patch('guardian.candidates.osv.query',return_value=([],'live')):
            with self.assertRaisesRegex(ValueError,'rescan'):
                choose({'ecosystem':'npm','name':'x','version':'1.0.0'},{'advisory':'missing'},None,version)
