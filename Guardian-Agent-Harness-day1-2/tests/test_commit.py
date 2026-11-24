import subprocess
import unittest
from unittest.mock import patch
from guardian.commit import commit_validated_fix, CommitBlocked
from guardian.validator import validate
from guardian.engine import run_scan
from test_validator import SandboxTests


def git(root, *args):
    env = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'HOME': str(root), 'GIT_CONFIG_NOSYSTEM': '1'}
    return subprocess.run(['git', '-C', str(root), '-c', 'user.name=T', '-c', 'user.email=t@t', *args], capture_output=True, text=True, env=env, check=True).stdout.strip()


class CommitTests(SandboxTests):
    """Reuses the validator fixture, then turns the scanned repo into a real Git checkout."""
    def setUp(self):
        super().setUp()
        git(self.root, 'init', '-q', '-b', 'main'); git(self.root, 'add', '-A'); git(self.root, 'commit', '-q', '-m', 'initial')
        self.head = git(self.root, 'rev-parse', 'HEAD')

    def verified(self):
        result = self.run_mocked_container_pipeline()
        self.assertEqual(result['status'], 'verified', result)
        return result

    def test_commit_creates_branch_without_touching_working_tree(self):
        result = self.verified()
        info = commit_validated_fix(self.store, result['id'], 'Reviewer', 'Checked diff and sandbox result')
        self.assertEqual(git(self.root, 'rev-parse', '--abbrev-ref', 'HEAD'), 'main')
        self.assertEqual(git(self.root, 'rev-parse', 'HEAD'), self.head)
        self.assertEqual(git(self.root, 'status', '--porcelain'), '')
        self.assertIn('@v7', self.workflow.read_text())
        self.assertEqual(git(self.root, 'rev-parse', info['branch']), info['commit'])
        self.assertEqual(git(self.root, 'rev-parse', info['commit']+'^'), self.head)
        self.assertIn('@'+'b'*40, git(self.root, 'show', info['branch']+':.github/workflows/check.yml'))
        message = git(self.root, 'log', '-1', '--format=%B', info['branch'])
        self.assertIn('Approved-by: Reviewer', message); self.assertIn('Rollback', message)
        self.assertFalse(info['pushed'])
        self.assertEqual(self.store.validation(result['id'])['commit']['commit'], info['commit'])

    def test_second_commit_of_same_validation_is_refused(self):
        result = self.verified()
        commit_validated_fix(self.store, result['id'], 'Reviewer', 'ok')
        with self.assertRaisesRegex(CommitBlocked, 'already committed'):
            commit_validated_fix(self.store, result['id'], 'Reviewer', 'again')

    def test_inconclusive_needs_explicit_acceptance(self):
        vid = self.approve()
        with patch('guardian.validator.runtime', side_effect=AssertionError), patch('guardian.validator.run_scan', side_effect=lambda path, store, **kw: run_scan(path, store, offline=True, **kw)):
            result = validate(self.store, self.plan['id'], vid, mode='rescan_only')
        self.assertEqual(result['status'], 'inconclusive')
        with self.assertRaisesRegex(CommitBlocked, 'inconclusive'):
            commit_validated_fix(self.store, vid, 'Reviewer', 'ok')
        info = commit_validated_fix(self.store, vid, 'Reviewer', 'Accepting: no tests applicable', accept_inconclusive=True)
        self.assertTrue(info['commit'])

    def test_failed_or_blocked_validation_cannot_be_committed(self):
        (self.root/'new-file.txt').write_text('drift')
        result = self.run_mocked_container_pipeline()
        self.assertEqual(result['status'], 'blocked')
        with self.assertRaisesRegex(CommitBlocked, 'status: blocked'):
            commit_validated_fix(self.store, result['id'], 'Reviewer', 'ok')

    def test_head_drift_since_scan_blocks_commit(self):
        result = self.verified()
        self.workflow.write_text('steps:\n  - uses: arbitrary-owner/custom-action@v8\n')
        git(self.root, 'commit', '-q', '-am', 'someone else changed the workflow')
        with self.assertRaisesRegex(CommitBlocked, 'differs from the version'):
            commit_validated_fix(self.store, result['id'], 'Reviewer', 'ok')

    def test_reviewer_and_reason_required(self):
        result = self.verified()
        with self.assertRaises(ValueError): commit_validated_fix(self.store, result['id'], ' ', 'ok')
        with self.assertRaises(ValueError): commit_validated_fix(self.store, result['id'], 'Reviewer', '')

    def test_dirty_working_tree_is_left_alone(self):
        result = self.verified()
        (self.root/'scratch.txt').write_text('uncommitted user work')
        info = commit_validated_fix(self.store, result['id'], 'Reviewer', 'ok')
        self.assertEqual((self.root/'scratch.txt').read_text(), 'uncommitted user work')
        self.assertNotIn('scratch.txt', git(self.root, 'show', '--stat', '--format=', info['branch']))


if __name__ == '__main__':
    unittest.main()
