import tempfile
import unittest

from guardian.store import Store


class WebhookHistoryTests(unittest.TestCase):
    def test_git_clone_url_matches_github_payload_without_ignoring_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            store.add_watched('https://github.com/Example/Project.git', ['main'], 'Test')
            self.assertIsNotNone(store.match_webhook('https://github.com/example/project', 'main'))
            self.assertIsNone(store.match_webhook('https://github.com/example/project', 'other'))
            self.assertIsNone(store.match_webhook('https://github.com/example/another', 'main'))

    def test_completion_survives_restart_without_duplicate_run(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            run = dict(id='push-1', created='2026-11-24T10:00:00Z',
                       repo='https://github.com/example/project', branch='main',
                       commit='abc123', status='running')
            store.save_webhook_run(run)
            run.update(status='complete', scan_id='scan-1')
            store.save_webhook_run(run)
            self.assertEqual(Store(directory).webhook_runs(), [run])

    def test_newest_first_and_failed_or_skipped_pushes_remain_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            for index, status in enumerate(('failed', 'skipped', 'complete')):
                store.save_webhook_run(dict(id=str(index), created=str(index),
                                            status=status, error='reason'))
            runs = store.webhook_runs()
            self.assertEqual([r['status'] for r in runs], ['complete', 'skipped', 'failed'])
            self.assertEqual(runs[-1]['error'], 'reason')


if __name__ == '__main__':
    unittest.main()
