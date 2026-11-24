import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from guardian.harness import draft
from guardian.remediation import source


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.text = 'const result = _.template(input);\n'
        (self.root/'app.js').write_text(self.text)
        self.scan = {'source_root': str(self.root), 'files': {'app.js': {'hash': hashlib.sha256(self.text.encode()).hexdigest()}}}
        self.finding = {'what': 'Unsafe `_.template` evaluates user input'}
        self.node = {'name': 'example', 'ecosystem': 'npm'}

    def reply(self, **overrides):
        edit = dict(file='app.js', line=1, old=self.text.rstrip('\n'), new='throw new Error("Feature disabled pending migration");')
        edit.update(overrides)
        return lambda *_: json.dumps({'edits': [edit]})

    def test_drafts_without_mutating_source(self):
        with patch('subprocess.run', side_effect=AssertionError('No execution permitted')):
            record, edits = draft(self.scan, self.finding, self.node, source, model_chat=self.reply())
        self.assertEqual(record['status'], 'drafted')
        self.assertEqual(edits[0]['before_hash'], self.scan['files']['app.js']['hash'])
        self.assertIn('Feature disabled', record['diff'])
        self.assertEqual((self.root/'app.js').read_text(), self.text)

    def test_rejects_traversal_and_fabricated_old_text(self):
        for replacement in ({'file': '../outside.js'}, {'old': 'invented'}, {'line': True}, {'new': ''}):
            record, edits = draft(self.scan, self.finding, self.node, source, model_chat=self.reply(**replacement))
            self.assertEqual(edits, [])
            self.assertEqual(record['status'], 'unavailable')

    def test_changed_source_is_not_sent_to_model(self):
        (self.root/'app.js').write_text('changed')
        record, edits = draft(self.scan, self.finding, self.node, source, model_chat=lambda *_: self.fail('Stale source used'))
        self.assertFalse(edits)

    def test_missing_model_does_not_invent_a_patch(self):
        def missing(*_): raise OSError('model unavailable')
        record, edits = draft(self.scan, self.finding, self.node, source, model_chat=missing)
        self.assertFalse(edits)
        self.assertIn('model unavailable', record['reason'])

    def test_no_feature_does_not_claim_unused_dependency(self):
        record, edits = draft(self.scan, {'what': 'Generic advisory'}, self.node, source,
                              model_chat=lambda *_: self.fail('No grounded source sites'))
        self.assertFalse(edits)
        self.assertIn('does not prove', record['reason'])

    def test_proposal_uses_harness_only_without_upgrade_candidate(self):
        from guardian.detectors import finding
        from guardian.remediation import propose
        node = dict(self.node, id='pkg', version='1.0.0', type='package', file='package-lock.json')
        f = finding('known-vulnerability', self.finding['what'], 'known CVE', 'High',
                    'app.js', component='pkg', fix_versions=[])
        scan = dict(self.scan, id='scan', graph={'nodes': [node]})
        with patch('guardian.harness.chat', side_effect=self.reply()):
            plan = propose(scan, f)
        self.assertEqual(plan['strategy'], 'ai_mitigation')
        self.assertEqual(plan['status'], 'pending')
        self.assertFalse(plan['execution_ready'])  # No runtime manifest/config in this fixture.
        self.assertFalse(plan['executable'])
        with patch('guardian.harness.draft', side_effect=AssertionError('Unnecessary fallback')):
            propose(scan, dict(f, fix_versions=['2.0.0']))

    def test_ai_validation_blocks_host_fallback(self):
        from guardian.validator import validate
        plan = dict(id='plan', scan_id='scan', finding_id='finding', status='approved',
                    execution_ready=True, strategy='ai_mitigation', validation_profile={'commands':[]})
        store = SimpleNamespace(directory=self.root,
            remediation_plan=lambda _: plan,
            get=lambda _: {'findings':[{'id':'finding'}]},
            finish_validation=lambda _: None)
        with patch('guardian.validator.runtime', return_value=(None, 'host')):
            result = validate(store, 'plan', 'validation')
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('Docker', result['error'])

    def test_harness_generates_diff_when_osv_has_no_fix(self):
        text = "const myPkg = require('my-pkg');\nmyPkg.doSomething(input);\n"
        (self.root / 'app.js').write_text(text)
        scan = {'source_root': str(self.root), 'files': {'app.js': {'hash': hashlib.sha256(text.encode()).hexdigest()}}}
        finding = {'what': 'Prototype Pollution in my-pkg without backticks', 'advisory': 'GHSA-xxxx'}
        node = {'name': 'my-pkg', 'ecosystem': 'npm'}
        def reply(system, user):
            return json.dumps({'edits': [{'file': 'app.js', 'line': 2, 'old': 'myPkg.doSomething(input);', 'new': 'myPkg.doSomething(sanitize(input));'}]})
        record, edits = draft(scan, finding, node, source, model_chat=reply)
        self.assertEqual(record['status'], 'drafted')
        self.assertTrue(record.get('diff'))
        self.assertIn('+myPkg.doSomething(sanitize(input));', record['diff'])
        self.assertEqual(len(edits), 1)


if __name__ == '__main__': unittest.main()
