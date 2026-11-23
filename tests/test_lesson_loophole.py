"""Regression: a lesson that names a detector or rule id must not hide an attack finding."""
import tempfile
import unittest
from pathlib import Path

from guardian.agents import evidence, finding
from guardian.memory import Memory


class LessonLoophole(unittest.TestCase):
    def test_detector_named_lesson_cannot_hide_backdoor(self):
        mem = Memory(Path(tempfile.mkdtemp()) / "t.db")
        mem.add_lesson("p", "suppress", "backdoor-agent", "*", "noise", "alice")   # allowed: not a type name
        mem.add_lesson("p", "suppress", "exec-encoded", "*", "noise", "alice")
        f = finding("backdoor_signal", "x", location={"file": "a.js", "line": 1}, detector="backdoor-agent",
                    extra={"rule": "exec-encoded"})
        g = finding("unpinned_image", "y", location={"file": "test/Dockerfile"}, detector="backdoor-agent")
        evidence.apply_lessons([f, g], mem.active_lessons("p"), mem, "r", "p")
        self.assertNotIn("suppressed_by", f)       # attack finding stays visible
        self.assertIn("suppressed_by", g)          # ordinary finding can still be suppressed


if __name__ == "__main__":
    unittest.main()
