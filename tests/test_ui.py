"""Smoke test: the UI script renders the latest report without errors (headless)."""
import unittest
from pathlib import Path

from guardian import config


class UISmoke(unittest.TestCase):
    def test_ui_renders(self):
        if not list((config.WORKSPACE / "reports").glob("*/*/report.json")):
            self.skipTest("no report yet")
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(str(Path(__file__).resolve().parent.parent / "ui" / "app.py"), default_timeout=60).run()
        self.assertFalse(at.exception, [e.value for e in at.exception])
        self.assertGreaterEqual(len(at.tabs), 6)


if __name__ == "__main__":
    unittest.main()
