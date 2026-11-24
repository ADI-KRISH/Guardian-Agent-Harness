import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from guardian.detectors import finding
from guardian.discovery import read_tree, discover
from guardian.remediation import propose, compatibility, source
from guardian.prioritizer import prioritize
from guardian.store import Store, now
from guardian.references import resolve


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'repo'; self.root.mkdir()
        self.store = Store(Path(self.tmp.name)/'store')
        self.manifest = self.root/'package.json'
        self.manifest.write_text('{"dependencies":{"example":"^1.0.0"}}\n')
        (self.root/'package-lock.json').write_text(json.dumps({'lockfileVersion':3, 'packages':{'':{'dependencies':{'example':'^1.0.0'}}, 'node_modules/example':{'version':'1.0.0'}}}))
        files, _ = read_tree(self.root)
        graph, _ = discover(self.root, files)
        node = next(n for n in graph['nodes'] if n['type'] == 'package')
        self.finding = finding('known-vulnerability', 'Test advisory', 'known CVE', 'High', 'package-lock.json', component=node['id'], fix_versions=['2.0.0','1.10.0','1.2.0'])
        self.finding['suppressed'] = False
        self.scan = dict(id='scan', repo=str(self.root), created=now(), graph=graph, files=files, findings=[self.finding])
        self.store.save(self.scan)
        candidate = patch('guardian.candidates.choose', return_value=('1.2.0', {'result':'fixture registry and OSV check'}))
        candidate.start(); self.addCleanup(candidate.stop)

    def test_candidate_numeric_order_and_exact_diff(self):
        plan = propose(self.scan, self.finding)
        self.assertEqual(plan['target_version'], '1.2.0')
        self.assertEqual(plan['compatibility'], 'minor')
        self.assertIn('+{"dependencies":{"example":"1.2.0"}}', plan['diff'])
        self.assertEqual(plan['status'], 'pending')
        self.assertFalse(plan['executable'])

    def test_approval_persists_without_execution_or_source_changes(self):
        before = self.manifest.read_bytes()
        with patch('subprocess.run', side_effect=AssertionError('Must not execute')):
            plan = self.store.recommend('scan', self.finding['id'])
            result = self.store.decide_remediation(plan['id'], 'approved', 'Reviewer', 'Review candidate in later sandbox')
        self.assertFalse(result['applied'])
        self.assertEqual(self.manifest.read_bytes(), before)
        reopened = Store(self.store.directory).get('scan')
        self.assertEqual(reopened['remediation_plans'][0]['status'], 'approved')
        self.assertEqual(reopened['findings'][0]['status'], 'open')
        self.assertIn('validation not run', reopened['audit'][-1]['reason'])
        with self.assertRaises(ValueError): self.store.decide_remediation(plan['id'], 'rejected', 'Other', 'Overwrite')

    def test_stale_source_cannot_be_approved(self):
        plan = self.store.recommend('scan', self.finding['id'])
        self.manifest.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Source changed'):
            self.store.decide_remediation(plan['id'], 'approved', 'Reviewer', 'Approve')
        self.store.decide_remediation(plan['id'], 'rejected', 'Reviewer', 'Stale')

    def test_invalid_decisions_and_identity(self):
        plan = self.store.recommend('scan', self.finding['id'])
        for status, actor, reason in [('approved','','reason'), ('approved','name',''), ('resolved','name','reason')]:
            with self.assertRaises(ValueError): self.store.decide_remediation(plan['id'], status, actor, reason)
        with self.assertRaises(ValueError): self.store.recommend('scan', 'missing')

    def test_transitive_generates_reviewable_override(self):
        self.scan['graph']['nodes'][1]['direct'] = False
        self.manifest.write_text('{"dependencies":{"parent":"1.0.0"}}')
        self.scan['files']['package.json']['hash'] = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        plan = propose(self.scan, self.finding)
        self.assertTrue(plan['diff']); self.assertTrue(plan['transitive_override'])
        self.assertEqual(json.loads(plan['edits'][0]['after'])['overrides'], {'example':'1.2.0'})

    def test_pre_one_and_major_compatibility(self):
        self.assertEqual(compatibility('0.4.0', '0.4.1'), 'pre-1.0')
        self.assertEqual(compatibility('1.0.0', '2.0.0'), 'major')
        self.assertEqual(compatibility('1.0.0', '1.0.1'), 'patch')
        self.assertEqual(compatibility('1.0.0', '1.0.1-beta'), 'unknown')

    def test_unknown_exposure_and_dev_do_not_hide_integrity(self):
        f = dict(self.finding, rule='integrity-change')
        priority = prioritize(f, {'dev':True})
        self.assertEqual(priority['tier'], 'P0')
        self.assertEqual(priority['exposure'], 'unknown')
        self.assertEqual(prioritize(dict(f, rule='other', risk_level='Unknown'), {})['tier'], 'P1')

    def test_symlink_or_path_escape_has_no_source(self):
        self.manifest.unlink(); self.manifest.symlink_to(self.root/'package-lock.json')
        self.assertIsNone(source(self.scan, 'package.json'))
        self.scan['files']['../outside'] = {'hash':'x'}
        self.assertIsNone(source(self.scan, '../outside'))

    def test_pin_lookup_success_and_failure(self):
        file = self.root/'Dockerfile'; file.write_text('FROM node:18\n')
        self.scan['files']['Dockerfile'] = {'hash':hashlib.sha256(file.read_bytes()).hexdigest()}
        f = finding('floating-image', 'Floating image', 'CI-container', 'Medium', 'Dockerfile')
        with patch('guardian.references.resolve', return_value=('node:18', 'node:18@sha256:'+'a'*64, 'https://registry-1.docker.io')):
            plan = propose(self.scan, f)
        self.assertIn('+FROM node:18@sha256:', plan['diff'])
        with patch('guardian.references.resolve', side_effect=OSError('offline')):
            plan = propose(self.scan, f)
        self.assertFalse(plan['diff']); self.assertIn('offline', plan['blockers'][0])

    def test_github_reference_preserves_subpath(self):
        with patch('guardian.references.metadata', return_value=({'sha':'a'*40}, {})):
            old, new, _ = resolve('unpinned-action', '  - uses: owner/repo/sub@v1')
        self.assertEqual(new, 'owner/repo/sub@'+'a'*40)

    def test_docker_digest_requires_valid_provider_response(self):
        with patch('guardian.references.metadata', side_effect=[({'token':'test'}, {}), ({}, {'Docker-Content-Digest':'bad'})]):
            with self.assertRaises(ValueError): resolve('floating-image', 'FROM node:18')

    def test_repeat_recommendation_reuses_plan(self):
        first = self.store.recommend('scan', self.finding['id'])
        second = self.store.recommend('scan', self.finding['id'])
        self.assertEqual(first['id'], second['id'])
        self.assertEqual(len(self.store.recommendations('scan')), 1)

    def test_comparison_prefers_exact_identity_over_alias(self):
        from verify_guardian import advisory_match
        aliases = {'GHSA-a': {'GHSA-a', 'GHSA-b'}, 'GHSA-b': {'GHSA-b'}}
        self.assertEqual(advisory_match('GHSA-b', set(aliases), aliases), 'GHSA-b')
        self.assertEqual(advisory_match('CVE-test', {'GHSA-a'}, {'GHSA-a': {'CVE-test'}}), 'GHSA-a')

    def test_changed_lockfile_blocks_approval(self):
        plan = self.store.recommend('scan', self.finding['id'])
        (self.root/'package-lock.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Source changed'):
            self.store.decide_remediation(plan['id'], 'approved', 'Reviewer', 'Approve')
