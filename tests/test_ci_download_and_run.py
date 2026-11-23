"""Whole-repo download-and-run check on workflow files (not only on the diff)."""
import tempfile
import unittest
from pathlib import Path

from guardian.agents import ci_container

WORKFLOW = """name: ci
jobs:
  build:
    steps:
      - run: echo hello
      - run: curl -fsSL https://example.com/install.sh | sh
      # - run: curl https://example.com/old.sh | bash
      - run: wget -qO- https://example.com/x.py | python
      - run: curl -o tool.tgz https://example.com/tool.tgz && sha256sum -c tool.sha
"""


class DownloadAndRun(unittest.TestCase):
    def test_flags_pipe_to_shell_lines_with_file_and_line_but_not_comments_or_checked_downloads(self):
        d = Path(tempfile.mkdtemp())
        (d / ".github" / "workflows").mkdir(parents=True)
        (d / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
        fs = ci_container.download_and_run(d)
        self.assertEqual([f["location"]["line"] for f in fs], [6, 8])
        self.assertTrue(all(f["type"] == "workflow_issue" and f["rule"] == "download-and-run" for f in fs))
        self.assertIn("curl -fsSL", fs[0]["verified_evidence"][0])

    def test_no_workflows_no_findings(self):
        self.assertEqual(ci_container.download_and_run(Path(tempfile.mkdtemp())), [])


if __name__ == "__main__":
    unittest.main()
