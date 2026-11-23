"""Python: requirements*.txt (pinned + ranges). Direct deps only unless a lock/SBOM is supplied."""
from __future__ import annotations

import re
from pathlib import Path

from ..models import Component, Inventory, ROOT_ID

REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|===|>=|~=|<=|>|<|!=)?\s*([^;#\s]*)")


def parse(project_dir: Path, inv: Inventory) -> bool:
    files = sorted(set(project_dir.glob("requirements*.txt")) | set(project_dir.glob("requirements/*.txt")))
    if not files:
        return False
    for f in files:
        rel = str(f.relative_to(project_dir))
        inv.sources.append(rel)
        scope = "dev" if re.search(r"dev|test", f.name) else "prod"
        for i, line in enumerate(f.read_text().splitlines(), 1):
            s = line.strip()
            if not s or s.startswith(("#", "-r", "--", "-c", "-e")):
                continue
            hashes = re.findall(r"--hash=(\S+)", s)
            m = REQ.match(s)
            if not m:
                continue
            name, op, ver = m.group(1), m.group(3), m.group(4)
            pinned = op in ("==", "===")
            c = Component(name=name.lower(), version=ver if pinned else None, ecosystem="pypi", scope=scope,
                          direct=True, source_files=[rel], locations=[f"{rel}:{i}"],
                          integrity=hashes[0] if hashes else None)
            if not pinned:
                c.properties["declared_range"] = f"{op or ''}{ver}" or "*"
            if re.search(r"(git\+|https?://)", s):
                c.resolved = s
            inv.link(ROOT_ID, inv.add(c).id)
    inv.notes.append("pypi: requirements files give direct dependencies only; transitive Python deps require "
                     "`pip freeze` / a lock file / an SBOM.")
    return True
