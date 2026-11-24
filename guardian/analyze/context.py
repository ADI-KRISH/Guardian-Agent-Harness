"""Application context for prioritisation.

Answers, per component, from the project's own source code and build files:
  * reachability  - is the package (or the direct dependency that pulls it in) imported by
                    production code, only by tests, or not at all?
  * exposure      - where does it run: network-facing server, browser bundle, build/install
                    tooling, CI pipeline, container base image?
  * production    - does it ship (prod scope, final image stage) or not?

Absence of an import is treated as WEAK evidence (packages can be loaded dynamically, e.g.
sequelize loading sqlite3), so it lowers priority only modestly and lowers confidence.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..models import Component, Inventory, ROOT_ID

SRC_EXT = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".vue"}
SKIP = {"node_modules", ".git", "build", "dist", "coverage", ".angular", "vendor", "target", ".nyc_output"}
TEST_HINT = re.compile(r"(^|/)(test|tests|__tests__|spec|cypress|e2e)(/|$)|\.(spec|test)\.[jt]sx?$")
IMPORT_RE = re.compile(
    r"""(?:require\(\s*|import\s*\(\s*|from\s+|import\s+)['"]([^'"\s]+)['"]""")


def _pkg_of(spec: str) -> Optional[str]:
    if spec.startswith((".", "/", "node:")) or ":" in spec:
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


class AppContext:
    def __init__(self, project_dir: Path, inv: Inventory):
        self.project_dir = Path(project_dir)
        self.inv = inv
        # subproject root ("" for repo root, "frontend" ...) -> {"prod": {pkg: [files]}, "test": {...}}
        self.imports: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        self.subprojects = [""] + sorted({c.properties["subproject"] for c in inv.components.values()
                                          if c.properties.get("subproject")})
        self.files_scanned = 0
        self.exposes_ports = self._docker_expose()
        self.script_bins = self._script_text()
        self._scan()

    # ---------------------------------------------------------------- scanning
    def _sub_for(self, rel: str) -> str:
        best = ""
        for s in self.subprojects:
            if s and (rel == s or rel.startswith(s + "/")) and len(s) > len(best):
                best = s
        return best

    def _scan(self):
        for p in self.project_dir.rglob("*"):
            if p.suffix not in SRC_EXT or not p.is_file():
                continue
            rel = p.relative_to(self.project_dir).as_posix()
            if any(part in SKIP for part in rel.split("/")[:-1]):
                continue
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            self.files_scanned += 1
            kind = "test" if TEST_HINT.search(rel) else "prod"
            sub = self._sub_for(rel)
            bucket = self.imports.setdefault(sub, {"prod": {}, "test": {}})[kind]
            for m in IMPORT_RE.finditer(text):
                pkg = _pkg_of(m.group(1))
                if pkg:
                    bucket.setdefault(pkg, [])
                    if rel not in bucket[pkg] and len(bucket[pkg]) < 20:
                        bucket[pkg].append(rel)

    def _docker_expose(self) -> List[str]:
        ports = []
        for f in self.project_dir.glob("Dockerfile*"):
            for line in f.read_text(errors="ignore").splitlines():
                m = re.match(r"\s*EXPOSE\s+(.+)", line, re.I)
                if m:
                    ports += m.group(1).split()
        return ports

    def _script_text(self) -> str:
        out = ""
        for s in self.subprojects:
            pj = self.project_dir / s / "package.json"
            if pj.exists():
                out += pj.read_text(errors="ignore")
        return out

    # ---------------------------------------------------------------- queries
    def subproject_of(self, c: Component) -> str:
        for loc in c.locations:
            for s in self.subprojects:
                if s and loc.startswith(s + "/"):
                    return s
        return ""

    def imported_in(self, pkg: str, sub: str, kind: str = "prod") -> List[str]:
        return self.imports.get(sub, {}).get(kind, {}).get(pkg, [])

    def reachability(self, c: Component) -> dict:
        """Package-level reachability along the dependency path."""
        if c.ecosystem != "npm":
            return {"level": "n/a", "detail": "not a code library (image / CI component)", "files": []}
        sub = self.subproject_of(c)
        own = self.imported_in(c.name, sub)
        if own:
            return {"level": "imported", "detail": f"imported directly by {len(own)} production source file(s)",
                    "files": own[:5]}
        paths = self.inv.paths_to(c.id, limit=5)
        firsts = []
        for p in paths:
            hops = [h for h in p[1:] if self.inv.components.get(h) and self.inv.components[h].type != "application"]
            if hops:
                firsts.append(self.inv.components[hops[0]])
        for d in firsts:
            f = self.imported_in(d.name, self.subproject_of(d))
            if f:
                return {"level": "parent-imported",
                        "detail": f"pulled in by '{d.name}', which production code imports ({f[0]})", "files": f[:5],
                        "via": d.name}
        for d in firsts + [c]:
            f = self.imported_in(d.name, self.subproject_of(d), "test")
            if f:
                return {"level": "test-only", "detail": f"only test code imports '{d.name}' ({f[0]})", "files": f[:5]}
        names = [d.name for d in firsts] or [c.name]
        cli = [n for n in names if re.search(r'["\s/]' + re.escape(n.split("/")[-1]) + r'[\s"@]', self.script_bins)]
        if cli:
            return {"level": "unknown", "detail": f"'{cli[0]}' not imported but referenced in package.json "
                                                  "(CLI / config use)", "files": []}
        if not paths:
            return {"level": "orphan", "detail": "no dependency path from the application", "files": []}
        return {"level": "unknown",
                "detail": f"no import of {', '.join(sorted(set(names))[:3])} found; may still be loaded dynamically",
                "files": []}

    def exposure(self, c: Component) -> dict:
        if c.ecosystem == "github-actions" or c.scope == "ci":
            return {"context": "ci-pipeline", "production": False,
                    "detail": "runs in CI with access to repository tokens/secrets"}
        if c.ecosystem == "docker":
            if c.scope == "build":
                return {"context": "image-build-stage", "production": False, "detail": "build stage only, not shipped"}
            return {"context": "runtime-image", "production": True,
                    "detail": "base image of a shipped container" + (f" (EXPOSE {', '.join(self.exposes_ports)})"
                                                                       if self.exposes_ports else "")}
        if c.scope == "dev":
            return {"context": "dev-tooling", "production": False, "detail": "devDependency: not installed in production"}
        if c.scope in ("optional", "build"):
            return {"context": "install-time", "production": False,
                    "detail": "optional / install-time dependency (e.g. native build tooling)"}
        sub = self.subproject_of(c)
        if sub:
            return {"context": "browser", "production": True,
                    "detail": f"shipped in the '{sub}' client bundle; runs in users' browsers"}
        return {"context": "server", "production": True,
                "detail": "runs in the server process" + (f", network-facing (EXPOSE {', '.join(self.exposes_ports)})"
                                                          if self.exposes_ports else "")}

    def summary(self) -> dict:
        return {"source_files_scanned": self.files_scanned, "subprojects": self.subprojects,
                "exposed_ports": self.exposes_ports,
                "packages_imported_by_prod_code": {s or "<root>": len(v["prod"]) for s, v in self.imports.items()}}
