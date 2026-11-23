"""Discovery agent (Day 1 steps 1-2): what is in the application.

Builds one snapshot of a checkout:
  sbom          CycloneDX from Syft
  packages      every locked package: ecosystem, name, version, scope (runtime/dev), origin URL, integrity hash,
                install-script flag, which lockfile it came from
  graph         dependency edges, so every package has a path back to the app
  workflows     every `uses:` in GitHub workflows, pinned or not
  images        every Dockerfile FROM, with tag and digest
"""
from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

from ..tools import run, scanners

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "__pycache__"}


def _walk(root: Path, names: set[str] | None = None, suffixes: tuple = ()):
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and ((names and p.name in names) or (suffixes and p.name.endswith(suffixes))):
            yield p


def pkey(eco: str, name: str, version: str) -> str:
    return f"{eco}:{name}@{version}"


# ---------------- npm ----------------
def _npm_lock(lock: Path, root: Path, packages: dict, graph: dict, roots: dict):
    data = json.loads(lock.read_text(encoding="utf-8"))
    rel = str(lock.relative_to(root)).replace("\\", "/")
    pk = data.get("packages")
    if not pk:  # lockfileVersion 1 is not supported in detail
        return
    path_to_key = {}
    for p, meta in pk.items():
        if not p:
            continue
        name = meta.get("name") or p.split("node_modules/")[-1]
        ver = meta.get("version", "")
        if not ver or meta.get("link"):
            continue
        k = pkey("npm", name, ver)
        path_to_key[p] = k
        entry = packages.setdefault(k, {"ecosystem": "npm", "name": name, "version": ver, "lockfiles": [],
                                        "scope": "dev" if meta.get("dev") else "runtime",
                                        "origin": meta.get("resolved", ""), "integrity": meta.get("integrity", ""),
                                        "install_script": bool(meta.get("hasInstallScript")),
                                        "license": meta.get("license", "")})
        if rel not in entry["lockfiles"]:
            entry["lockfiles"].append(rel)
        if not meta.get("dev"):
            entry["scope"] = "runtime"

    def resolve(from_path: str, dep: str) -> str | None:
        base = from_path
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in path_to_key:
                return path_to_key[cand]
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            base = base[:idx] if idx >= 0 else ""

    app = f"app:{rel}"
    root_meta = pk.get("", {})
    direct = {**root_meta.get("dependencies", {}), **root_meta.get("devDependencies", {}),
              **root_meta.get("optionalDependencies", {})}
    roots[app] = []
    for d in direct:
        k = resolve("", d)
        if k:
            roots[app].append(k)
            graph.setdefault(app, set()).add(k)
    for p, meta in pk.items():
        if p not in path_to_key:
            continue
        for d in {**meta.get("dependencies", {}), **meta.get("optionalDependencies", {})}:
            k = resolve(p, d)
            if k:
                graph.setdefault(path_to_key[p], set()).add(k)


# ---------------- Python ----------------
def _toml_lock(lock: Path, root: Path, packages: dict, graph: dict, roots: dict):
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    rel = str(lock.relative_to(root)).replace("\\", "/")
    by_name = {}
    for pkg in data.get("package", []):
        name, ver = pkg.get("name", ""), pkg.get("version", "")
        src = pkg.get("source", {}) or {}
        if src.get("editable") or src.get("virtual"):
            by_name[name.lower()] = f"app:{rel}"
            continue
        k = pkey("PyPI", name, ver)
        by_name[name.lower()] = k
        sd = pkg.get("sdist") or {}
        wh = (pkg.get("wheels") or [{}])[0]
        e = packages.setdefault(k, {"ecosystem": "PyPI", "name": name, "version": ver, "lockfiles": [],
                                    "scope": "dev" if pkg.get("category") == "dev" else "runtime",
                                    "origin": sd.get("url") or wh.get("url") or src.get("registry", ""),
                                    "integrity": sd.get("hash") or wh.get("hash", ""), "install_script": bool(sd) and not pkg.get("wheels"),
                                    "license": ""})
        if rel not in e["lockfiles"]:
            e["lockfiles"].append(rel)
    app = f"app:{rel}"
    roots.setdefault(app, [])
    for pkg in data.get("package", []):
        src = by_name.get(pkg.get("name", "").lower())
        deps = pkg.get("dependencies", [])
        names = [d.get("name", "") for d in deps] if isinstance(deps, list) else list(deps.keys())
        for n in names:
            tgt = by_name.get(n.lower())
            if src and tgt and src != tgt:
                graph.setdefault(src, set()).add(tgt)
                if src == app:
                    roots[app].append(tgt)
    if not roots[app]:  # poetry: direct deps come from pyproject
        pyp = lock.parent / "pyproject.toml"
        if pyp.exists():
            pd = tomllib.loads(pyp.read_text(encoding="utf-8"))
            names = list(pd.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
            names += [re.split(r"[ <>=!~\[;]", d)[0] for d in pd.get("project", {}).get("dependencies", [])]
            for n in names:
                tgt = by_name.get(n.lower())
                if tgt:
                    roots[app].append(tgt)
                    graph.setdefault(app, set()).add(tgt)


def _requirements(req: Path, root: Path, packages: dict, graph: dict, roots: dict):
    rel = str(req.relative_to(root)).replace("\\", "/")
    app = f"app:{rel}"
    roots.setdefault(app, [])
    for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#\\]+)", line)
        if not m:
            continue
        name, ver = m.groups()
        k = pkey("PyPI", name, ver)
        h = re.search(r"--hash=(\S+)", line)
        e = packages.setdefault(k, {"ecosystem": "PyPI", "name": name, "version": ver, "lockfiles": [], "scope": "runtime",
                                    "origin": "", "integrity": h.group(1) if h else "", "install_script": False, "license": ""})
        e["lockfiles"].append(rel)
        roots[app].append(k)
        graph.setdefault(app, set()).add(k)


# ---------------- CI and containers ----------------
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")


def _workflows(root: Path) -> list[dict]:
    out = []
    wf_dir = root / ".github" / "workflows"
    files = list(wf_dir.glob("*.y*ml")) if wf_dir.exists() else []
    files += list(_walk(root, names={"action.yml", "action.yaml"}))
    for f in files:
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            uses = m.group(1)
            local = uses.startswith("./") or uses.startswith("docker://")
            ref = uses.split("@", 1)[1] if "@" in uses else ""
            out.append({"file": str(f.relative_to(root)).replace("\\", "/"), "line": i, "uses": uses,
                        "local": local, "ref": ref, "pinned": bool(re.fullmatch(r"[0-9a-f]{40}", ref)) or local,
                        "first_party": uses.startswith(("actions/", "github/"))})
    return out


FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)


def _images(root: Path) -> list[dict]:
    out = []
    for f in _walk(root, suffixes=("Dockerfile", ".dockerfile", ".Dockerfile")):
        stages = set()
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = FROM.match(line)
            if not m:
                continue
            ref, alias = m.group(1), m.group(2)
            if alias:
                stages.add(alias.lower())
            if ref.lower() in stages or ref.lower() == "scratch" or "$" in ref:
                continue
            digest = ref.split("@", 1)[1] if "@" in ref else ""
            base = ref.split("@", 1)[0]
            name, _, tag = base.rpartition(":") if ":" in base.split("/")[-1] else (base, "", "")
            out.append({"file": str(f.relative_to(root)).replace("\\", "/"), "line": i, "image": name or base,
                        "tag": tag or "latest", "digest": digest, "ref": ref})
    return out


def paths_to(target: str, graph: dict, roots: dict, limit: int = 3) -> list[list[str]]:
    """Shortest dependency paths from an app root to target (BFS)."""
    out = []
    for app in roots:
        prev = {app: None}
        q = deque([app])
        while q:
            n = q.popleft()
            if n == target:
                path = []
                while n:
                    path.append(n)
                    n = prev[n]
                out.append(list(reversed(path)))
                break
            for c in graph.get(n, ()):
                if c not in prev:
                    prev[c] = n
                    q.append(c)
        if len(out) >= limit:
            break
    return out


GEN_MARK = ".guardian-generated-lock"


def ensure_npm_locks(root: Path, notes: list, max_projects: int = 3) -> list[str]:
    """If a package.json has dependencies but no lockfile, resolve one WITHOUT running any package code
    (npm install --package-lock-only --ignore-scripts). The lockfile is marked as generated."""
    made = []
    for pj in sorted(_walk(root, names={"package.json"}), key=lambda p: len(p.parts)):
        d = pj.parent
        if len(made) >= max_projects or len(d.relative_to(root).parts) > 2:
            continue
        if (d / "package-lock.json").exists() or (d / "yarn.lock").exists() or (d / "pnpm-lock.yaml").exists():
            continue
        try:
            meta = json.loads(pj.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not (meta.get("dependencies") or meta.get("devDependencies")):
            continue
        r = run("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--legacy-peer-deps"],
                cwd=d, timeout=900)
        rel = str(d.relative_to(root)).replace("\\", "/") or "."
        if r.ok and (d / "package-lock.json").exists():
            (d / GEN_MARK).write_text("generated by guardian at scan time", encoding="utf-8")
            made.append(rel)
        else:
            notes.append(f"could not resolve a lockfile for {rel}: {r.stderr[-200:]}")
    return made


def snapshot(root: Path, run_syft: bool = True, generate_locks: bool = True) -> dict:
    packages, graph, roots, notes = {}, {}, {}, []
    generated = ensure_npm_locks(root, notes) if generate_locks else []
    generated += [str(p.parent.relative_to(root)).replace("\\", "/") or "." for p in _walk(root, names={GEN_MARK})
                  if (str(p.parent.relative_to(root)).replace("\\", "/") or ".") not in generated]
    if generated:
        notes.append(f"no lockfile committed in {generated}: versions were resolved at scan time with --ignore-scripts "
                     "(no package code was run), so they show what a fresh install would get today")
    for lock in _walk(root, names={"package-lock.json", "npm-shrinkwrap.json"}):
        try:
            _npm_lock(lock, root, packages, graph, roots)
        except Exception as e:  # noqa: BLE001
            notes.append(f"could not parse {lock.name}: {e}")
    for lock in _walk(root, names={"uv.lock", "poetry.lock"}):
        try:
            _toml_lock(lock, root, packages, graph, roots)
        except Exception as e:  # noqa: BLE001
            notes.append(f"could not parse {lock.name}: {e}")
    for req in _walk(root, suffixes=("requirements.txt",)):
        _requirements(req, root, packages, graph, roots)
    manifests_without_lock = [str(p.relative_to(root)) for p in _walk(root, names={"package.json"})
                              if not (p.parent / "package-lock.json").exists() and not (p.parent / "yarn.lock").exists()
                              and not (p.parent / "pnpm-lock.yaml").exists()]
    if manifests_without_lock:
        notes.append(f"package.json without a lockfile (transitive versions unknown): {manifests_without_lock[:5]}")

    sbom, sbom_meta = None, None
    if run_syft:
        r = scanners.syft_sbom(root)
        sbom_meta = r.meta()
        sbom = r.json() if r.ok else None
        if not r.ok:
            notes.append(f"syft failed: {r.stderr[-200:]}")
    # Packages Syft found that no lockfile parser covered (other ecosystems, binaries, OS packages)
    if sbom:
        for c in sbom.get("components", []):
            purl = c.get("purl", "")
            if not purl.startswith("pkg:"):
                continue
            eco = purl[4:].split("/")[0]
            eco = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
                   "gem": "RubyGems", "nuget": "NuGet", "github": "GitHubActions"}.get(eco, eco)
            k = pkey(eco, c.get("name", ""), c.get("version", ""))
            if k not in packages and eco not in ("npm", "PyPI"):
                locs = [p["value"] for p in c.get("properties", []) if p.get("name", "").startswith("syft:location")]
                packages[k] = {"ecosystem": eco, "name": c.get("name", ""), "version": c.get("version", ""),
                               "lockfiles": locs[:1], "scope": "unknown", "origin": "", "integrity": "",
                               "install_script": False, "license": ""}
    for p in packages.values():
        p["origin_host"] = urlparse(p["origin"]).hostname or "" if p["origin"] else ""
    return {
        "packages": packages,
        "graph": {k: sorted(v) for k, v in graph.items()},
        "roots": roots,
        "workflows": _workflows(root),
        "images": _images(root),
        "sbom": sbom,
        "sbom_tool": sbom_meta,
        "notes": notes,
        "generated_locks": generated,
    }
