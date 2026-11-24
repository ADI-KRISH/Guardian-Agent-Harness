"""Sandbox-only build workaround: disable Angular font inlining (needs fonts.googleapis.com,
which offline/air-gapped sandboxes block). Applied to the build workspace only, never committed
to the fix branch. Usage: python3 sandbox_no_font_inline.py <frontend-dir>"""
import json
import sys
from pathlib import Path

p = Path(sys.argv[1]) / "angular.json"
a = json.loads(p.read_text())
for proj in a["projects"].values():
    conf = proj["architect"]["build"].get("configurations", {}).get("production")
    if conf is not None:
        conf["optimization"] = {"scripts": True, "styles": {"minify": True, "inlineCritical": False}, "fonts": False}
p.write_text(json.dumps(a, indent=2) + "\n")
print("font inlining disabled in", p)
