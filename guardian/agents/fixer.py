"""Fix agent: turns one known-vulnerability finding into a concrete, reviewable change proposal.

Nothing is applied here. `propose` only reads the scan report; `apply_edit` is called by the validation agent on a
sandbox copy, and only after a named human has approved the proposal (memory.decide_proposal).
Supported: npm (direct bump, or `overrides` for a transitive dependency) and pinned requirements.txt (direct).
Everything else is refused with a reason: a human decides.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

DISCLAIMER = "Deterministic proposal built from scanner evidence. No AI is used to choose the version."


def vt(v: str) -> tuple:
    nums = [int(n) for n in re.findall(r"\d+", re.split(r"[-+]", v, maxsplit=1)[0])[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def pick_fix(current: str, fixed: list[str]) -> str | None:
    """Lowest fixed version above the current one, staying inside the current major when a fix exists there."""
    above = sorted((f for f in fixed if re.match(r"\d+\.\d+", f) and vt(f) > vt(current)), key=vt)
    same = [f for f in above if vt(f)[0] == vt(current)[0]]
    return (same or above or [None])[0]


def _compat(cur: str, to: str, direct: bool, path: list[str]) -> tuple[bool, str]:
    major = vt(to)[0] != vt(cur)[0]
    if major:
        note = (f"Major version jump {cur} -> {to}: expect breaking changes (API, defaults, minimum Node/Python). The sandbox proves the "
                "dependency tree installs and the package loads; only your project's own tests prove behaviour is unchanged.")
    elif vt(cur)[0] == 0:
        note = f"{cur} -> {to} is a 0.x release: semver makes no compatibility promise, so review the changelog."
    else:
        note = f"Same major version ({cur} -> {to}): backwards compatible under semver."
    if not direct:
        note += (" Transitive dependency: an override forces every dependent to use this version, although they were built against another one"
                 f" (path: {' -> '.join(path[:4])}).")
    return major, note


def propose(report: dict, inventory: dict, finding_id: str) -> dict:
    """Returns {"ok": True, ...proposal} or {"ok": False, "reason": ...}."""
    f = next((x for x in report["findings"] if x["id"] == finding_id), None)
    if not f:
        return {"ok": False, "reason": f"no finding {finding_id} in this run"}
    if f["type"] != "known_vulnerability":
        return {"ok": False, "reason": f"'{f['type']}' findings have no automatic fix (a human must decide); only known vulnerabilities do"}
    comp = f["component"]
    pk = inventory["packages"].get(comp)
    if not pk:
        return {"ok": False, "reason": f"{comp} is not in the inventory"}
    eco, name, cur = pk["ecosystem"], pk["name"], pk["version"]
    lock = (pk.get("lockfiles") or [""])[0]
    direct = comp in {k for v in inventory["roots"].values() for k in v}
    if eco == "npm":
        d = str(Path(lock).parent).replace("\\", "/")
        manifest, kind = ("package.json" if d in ("", ".") else f"{d}/package.json"), ("dependency-bump" if direct else "override")
    elif eco == "PyPI" and lock.endswith("requirements.txt") and direct:
        manifest, kind = lock, "requirements-pin"
    else:
        return {"ok": False, "reason": f"no automatic fix for {eco} {'direct' if direct else 'transitive'} dependencies in {lock or 'this project'}: "
                                       "bump it in the manifest by hand"}
    same = [x for x in report["findings"] if x["type"] == "known_vulnerability" and x["component"] == comp and not x.get("suppressed_by")]
    picks = {x["id"]: pick_fix(cur, x.get("fixed_versions") or []) for x in same}
    target = max((v for v in picks.values() if v), key=vt, default=None)
    if not target:
        return {"ok": False, "reason": f"no fixed version is published for {name} {cur}: replace or mitigate it (human decision)"}
    resolved = [x for x in same if picks[x["id"]]]
    levels = {lv: sum(1 for x in resolved if x["risk_level"] == lv) for lv in ("Critical", "High", "Medium", "Low")}
    major, note = _compat(cur, target, direct, (f.get("dependency_paths") or [[]])[0])
    # Other (older) copies of the same package elsewhere in the tree would survive a plain bump: force them too.
    nested = sorted((k for k, q in inventory["packages"].items() if q["ecosystem"] == eco and q["name"] == name and vt(q["version"]) < vt(target) and k != comp),
                    key=lambda k: vt(inventory["packages"][k]["version"]))
    also_override = eco == "npm" and kind == "dependency-bump" and bool(nested)
    if nested and eco == "npm":
        users = sorted({s.split(":", 1)[-1] for s, deps in inventory["graph"].items() if s.startswith("npm:") and any(n in deps for n in nested)})
        note += (f" Also found nested copies ({', '.join(inventory['packages'][k]['version'] for k in nested)}) used by {', '.join(users[:4]) or 'other dependencies'}: "
                 f"they are forced to {target} too, and those dependents were written against the old API, so test them.")
    pid = "FIX-" + hashlib.sha1(f"{report['run_id']}|{finding_id}|{target}".encode()).hexdigest()[:8].upper()
    rel = manifest if kind != "requirements-pin" else lock
    return {
        "ok": True, "id": pid, "project": report["project"], "run_id": report["run_id"], "finding_id": finding_id,
        "package": name, "ecosystem": eco, "from": cur, "to": target, "kind": kind, "file": rel, "lockfile": lock, "direct": direct,
        "head_sha": (report.get("head_commit") or {}).get("sha", ""), "head_ref": report.get("head_ref", ""),
        "resolves": [x["id"] for x in resolved], "not_resolved": [x["id"] for x in same if not picks[x["id"]]],
        "advisories": sorted({a for x in resolved for a in x.get("advisory_ids", [])}),
        "expected_risk_reduction": {"findings_resolved": len(resolved), "levels": levels,
                                    "score_removed": round(sum(x["score"] for x in resolved), 1),
                                    "explanation": f"{len(resolved)} finding(s) on {name} {cur} should disappear once {target} is installed"},
        "major_bump": major, "compatibility_note": note, "also_override": also_override,
        "change": (f"{rel}: {name} {cur} -> {target}" + (f" and overrides.{name} = ${name} (forces nested copies to the same version)" if also_override else "")
                   if kind != "override" else f"{rel}: add overrides.{name} = {target} (forces the fixed version for every dependent)"),
        "rollback": "The change lives only on a local sandbox branch and in patch.diff; nothing is merged or pushed. To undo after applying: "
                    "`git apply -R patch.diff` (or restore the manifest and lockfile from version control).",
        "dependency_path": (f.get("dependency_paths") or [[]])[0], "ai_inference": [], "note": DISCLAIMER,
    }


def _indent(text: str) -> int:
    m = re.search(r"^( +)\"", text, re.M)
    return len(m.group(1)) if m else 2


def apply_edit(p: dict, root: Path) -> list[str]:
    """Apply the proposal to a sandbox working copy. Returns the files changed (relative to root)."""
    f = root / p["file"]
    text = f.read_text(encoding="utf-8")
    name, old, new = p["package"], p["from"], p["to"]
    if p["kind"] == "requirements-pin":
        out, n = re.subn(rf"(?im)^(\s*{re.escape(name)}\s*==\s*){re.escape(old)}\b", rf"\g<1>{new}", text)
        if not n:
            raise ValueError(f"{name}=={old} not found in {p['file']}")
        f.write_text(out, encoding="utf-8")
    elif p["kind"] == "override":
        data = json.loads(text)
        data.setdefault("overrides", {})[name] = new
        f.write_text(json.dumps(data, indent=_indent(text), ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        data = json.loads(text)
        sect = next((s for s in ("dependencies", "devDependencies", "optionalDependencies") if name in data.get(s, {})), None)
        if not sect:
            raise ValueError(f"{name} is not a direct dependency in {p['file']}")
        spec = data[sect][name]
        newspec = (spec[0] + new) if spec[:1] in ("^", "~") else new
        start = text.index(f'"{sect}"')
        out, n = re.subn(rf'("{re.escape(name)}"\s*:\s*")' + re.escape(spec) + '"', rf'\g<1>{newspec}"', text[start:], count=1)
        if not n:
            raise ValueError(f"could not edit {name} in {p['file']}")
        text = text[:start] + out
        if p.get("also_override"):   # "$name" = whatever version the direct dependency now has
            data = json.loads(text)
            data.setdefault("overrides", {})[name] = f"${name}"
            text = json.dumps(data, indent=_indent(text), ensure_ascii=False) + "\n"
        f.write_text(text, encoding="utf-8")
    return [p["file"]]
