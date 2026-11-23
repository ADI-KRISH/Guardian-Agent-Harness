"""Change agent: what changed between the baseline snapshot and the head snapshot."""
from __future__ import annotations

from . import finding

# Small built-in list of very popular names, used for look-alike (typosquat) checks.
POPULAR = {
    "npm": ["react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "moment", "request",
            "cross-env", "dotenv", "webpack", "typescript", "eslint", "jest", "mocha", "underscore", "async", "uuid",
            "body-parser", "jquery", "vue", "angular", "next", "prettier", "yargs", "colors", "minimist", "semver",
            "glob", "rimraf", "mkdirp", "ws", "socket.io", "mongoose", "jsonwebtoken", "bcrypt", "node-fetch", "electron"],
    "PyPI": ["requests", "urllib3", "numpy", "pandas", "flask", "django", "pyyaml", "jinja2", "boto3", "setuptools",
             "cryptography", "pillow", "scipy", "matplotlib", "pytest", "click", "six", "certifi", "idna", "attrs",
             "beautifulsoup4", "sqlalchemy", "fastapi", "pydantic", "tensorflow", "torch", "scikit-learn", "colorama"],
}


def _norm(s: str) -> str:
    return s.lower().replace("-", "").replace("_", "").replace(".", "")


def _lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(name: str, eco: str, known: set[str]) -> str | None:
    n = name.lower().split("/")[-1]
    if n in POPULAR.get(eco, []):
        return None
    for p in POPULAR.get(eco, []):
        if len(p) >= 5 and (_norm(n) == _norm(p) or _lev(n, p) == 1):
            if p not in known:   # the real package is not also in the tree
                return p
    return None


def _vt(v: str):
    out = []
    for part in v.replace("-", ".").split("."):
        num = "".join(c for c in part if c.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out + [0] * (5 - len(out)))


def diff(base: dict, head: dict, cfg: dict) -> tuple[dict, list[dict]]:
    bp, hp = base["packages"], head["packages"]
    b_by_name, h_by_name = {}, {}
    for k, p in bp.items():
        b_by_name.setdefault((p["ecosystem"], p["name"]), set()).add(p["version"])
    for k, p in hp.items():
        h_by_name.setdefault((p["ecosystem"], p["name"]), set()).add(p["version"])
    known_names = {n.lower() for (_, n) in h_by_name}
    trusted = set(cfg["trusted_registries"])
    head_direct = {k for v in head["roots"].values() for k in v}

    added = [k for k in hp if k not in bp]
    removed = [k for k in bp if k not in hp]
    findings: list[dict] = []
    summary = {"packages_base": len(bp), "packages_head": len(hp), "added": [], "removed": sorted(removed)[:200],
               "updated": [], "new_names": []}

    for k in added:
        p = hp[k]
        key = (p["ecosystem"], p["name"])
        old = b_by_name.get(key)
        comp = k
        if old:
            oldv = max(old, key=_vt)
            summary["updated"].append(f"{p['name']} {oldv} -> {p['version']}")
            if max(h_by_name[key], key=_vt) == p["version"] and _vt(p["version"]) < _vt(oldv):  # the package's newest version went down
                findings.append(finding("version_downgrade", f"{p['name']} was downgraded {oldv} -> {p['version']}",
                                        component=comp, detector="change-agent", change=f"{oldv} -> {p['version']}",
                                        verified_evidence=[f"baseline had {p['name']}@{oldv}; head has @{p['version']} ({', '.join(p['lockfiles'])})"],
                                        recommendation="Confirm the downgrade was intended; pin the previous version if not."))
            base_scripts = any(bp[pkey]["install_script"] for pkey in bp if (bp[pkey]["ecosystem"], bp[pkey]["name"]) == key)
            if p["install_script"] and not base_scripts:
                findings.append(finding("new_install_script", f"{p['name']} {p['version']} now runs an install script (earlier versions did not)",
                                        component=comp, detector="change-agent", change=f"{oldv} -> {p['version']}",
                                        verified_evidence=[f"lockfile marks {p['name']}@{p['version']} hasInstallScript=true; baseline versions did not"],
                                        recommendation="Review the install script before installing; or install with --ignore-scripts."))
        else:
            summary["new_names"].append(f"{p['name']}@{p['version']}")
            if k in head_direct:
                findings.append(finding("new_dependency", f"New direct dependency {p['name']}@{p['version']}",
                                        component=comp, detector="change-agent", change="added",
                                        verified_evidence=[f"not present in baseline; declared in {', '.join(p['lockfiles'])}"],
                                        recommendation="Confirm who added it and why (link the PR)."))
            if p["install_script"]:
                findings.append(finding("new_install_script", f"New package {p['name']}@{p['version']} runs an install script",
                                        component=comp, detector="change-agent", change="added",
                                        verified_evidence=[f"lockfile hasInstallScript=true for {p['name']}@{p['version']}"],
                                        recommendation="Review the install script; prefer --ignore-scripts in CI."))
        sim = lookalike(p["name"], p["ecosystem"], known_names)
        if sim:
            findings.append(finding("typosquat", f"'{p['name']}' looks like a typosquat of '{sim}'", component=comp,
                                    detector="change-agent", change="added" if not old else "updated",
                                    verified_evidence=[f"name '{p['name']}' is one edit (or only punctuation) away from popular package '{sim}', which is not in the tree"],
                                    recommendation=f"Remove '{p['name']}'; use '{sim}' if that was intended."))
        summary["added"].append(k)

    for k, p in hp.items():
        b = bp.get(k)
        if b and b.get("integrity") and p.get("integrity") and b["integrity"] != p["integrity"]:
            findings.append(finding("integrity_change", f"{p['name']}@{p['version']}: same version, different integrity hash",
                                    component=k, detector="change-agent", change="hash changed",
                                    verified_evidence=[f"baseline {b['integrity'][:40]}...", f"head {p['integrity'][:40]}..."],
                                    recommendation="Block this artifact and restore the baseline lockfile entry; ask the maintainer."))
        if b and b.get("origin_host") and p.get("origin_host") and b["origin_host"] != p["origin_host"]:
            findings.append(finding("origin_change", f"{p['name']}@{p['version']} is now downloaded from {p['origin_host']} (was {b['origin_host']})",
                                    component=k, detector="change-agent", change="origin changed",
                                    verified_evidence=[f"baseline resolved {b['origin']}", f"head resolved {p['origin']}"],
                                    recommendation="Restore the registry URL; check for dependency confusion."))
        if p.get("origin_host") and p["origin_host"] not in trusted and not p["origin"].startswith(("file:", "git+")):
            if not b or b.get("origin_host") != p["origin_host"]:
                findings.append(finding("untrusted_registry", f"{p['name']}@{p['version']} comes from untrusted host {p['origin_host']}",
                                        component=k, detector="change-agent", change="added" if not b else "origin",
                                        verified_evidence=[f"lockfile resolved URL: {p['origin']}"],
                                        recommendation="Use the official registry or add the host to trusted_registries in guardian.yaml."))

    # CI / container changes summary
    bw = {(w["file"], w["uses"]) for w in base.get("workflows", [])}
    summary["workflow_changes"] = [f"{w['file']}: {w['uses']}" for w in head.get("workflows", []) if (w["file"], w["uses"]) not in bw]
    bi = {i["ref"] for i in base.get("images", [])}
    summary["image_changes"] = [f"{i['file']}: {i['ref']}" for i in head.get("images", []) if i["ref"] not in bi]
    summary["added_count"], summary["removed_count"], summary["updated_count"] = len(added), len(removed), len(summary["updated"])
    return summary, findings
