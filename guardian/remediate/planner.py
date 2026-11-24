"""Remediation planner: prioritised findings -> remediation items, each with ranked options.

Every option states: the exact change (machine-applicable), the findings it is expected to
resolve and the risk score removed, the compatibility impact and why, and how to roll back.
Nothing is applied here; the plan waits for human approval.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from .. import net
from ..analyze.context import AppContext
from ..models import Component, Inventory, ROOT_ID
from ..versions import cmp, is_prerelease, satisfies, vkey

ACTION_HELP = {
    "upgrade": "upgrade the dependency to a safe version",
    "lock-refresh": "refresh the lockfile so the transitive dependency resolves to a safe version (no manifest change)",
    "upgrade-parent": "upgrade the direct dependency that pulls the vulnerable package in",
    "override": "force a safe version of the transitive dependency with npm `overrides`",
    "remove": "remove the dependency",
    "replace": "replace with the intended / trusted package",
    "pin": "pin to an immutable reference (commit SHA / digest)",
    "lock-regenerate": "regenerate the lockfile from package.json (drops injected entries)",
    "block": "block the component by policy",
    "mitigate": "apply a compensating control",
    "escalate": "request security review",
    "accept": "accept the risk with justification",
}


# ---------------------------------------------------------------- helpers
def _semver_delta(a: Optional[str], b: Optional[str]) -> str:
    if not a or not b:
        return "unknown"
    pa, pb = (re.findall(r"\d+", a) + ["0", "0"])[:3], (re.findall(r"\d+", b) + ["0", "0"])[:3]
    if pa[0] != pb[0] or (pa[0] == "0" and pa[1] != pb[1]):
        return "major"   # 0.x minor bumps are breaking by semver convention
    if pa[1] != pb[1]:
        return "minor"
    return "patch"


def _packument(name: str, full: bool = False) -> dict:
    hdr = None if full else {"Accept": "application/vnd.npm.install-v1+json"}
    try:
        return net.fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}", headers=hdr, ttl=86400)
    except net.NetError:
        return {}


def _affected_ranges(findings: List[dict]) -> List[str]:
    out = []
    for f in findings:
        for e in f["evidence"]:
            m = re.search(r"inside affected range (.+)$", e["detail"])
            if m and not m.group(1).startswith("("):
                out.append(m.group(1))
    return out


def _vulnerable(v: str, ranges: List[str]) -> bool:
    for r in ranges:
        if r.startswith(">=") or r.startswith("<") or r.startswith("=") or r[0].isdigit() or "||" in r:
            if satisfies(v, r):
                return True
    return False


def _safe_versions(c: Component, findings: List[dict]) -> List[str]:
    ranges = _affected_ranges(findings)
    doc = _packument(c.name)
    vers = [v for v in (doc.get("versions") or {}) if not is_prerelease(v)]
    if not vers:  # offline: fall back to advisory fixed versions
        fx = sorted({v for f in findings for v in (f.get("fix") or {}).get("fixed_versions", [])}, key=vkey)
        return [fx[-1]] if fx else []
    return sorted([v for v in vers if cmp(v, c.version or "0") > 0 and not _vulnerable(v, ranges)], key=vkey)


def _lock_entry(project: Path, comp: Component) -> dict:
    for src, loc in zip(comp.source_files * len(comp.locations), comp.locations):
        lf = project / src
        if lf.name != "package-lock.json" or not lf.exists():
            continue
        key = loc.split("/", 1)[1] if loc.split("/")[0] != "node_modules" and "/" in loc and \
            src.startswith(loc.split("/")[0] + "/") else loc
        entry = (json.loads(lf.read_text()).get("packages") or {}).get(key)
        if entry:
            return entry
    return {}


def _parents(inv: Inventory, cid: str) -> List[str]:
    return [p for p, kids in inv.edges.items() if cid in kids]


def _declared(project: Path, sub: str, name: str):
    pj = project / sub / "package.json"
    if not pj.exists():
        return None, None
    m = json.loads(pj.read_text())
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (m.get(sec) or {}):
            return sec, m[sec][name]
    return None, None


def _spec_like(old: str, new: str) -> str:
    if old and old[0] in "^~":
        return old[0] + new
    return new


# ---------------------------------------------------------------- planner
class Planner:
    def __init__(self, run_dir: Path, project: Path, online: bool = True):
        self.run_dir = Path(run_dir)
        self.project = Path(project)
        self.online = online
        self.doc = json.loads((self.run_dir / "findings.json").read_text())
        self.analysis = json.loads((self.run_dir / "analysis.json").read_text())
        self.inv = Inventory.from_dict(json.loads((self.run_dir / "inventory.json").read_text()))
        self.ctx = AppContext(self.project, self.inv)
        self.by_id = {f["id"]: f for f in self.doc["findings"]}
        self.rank = {r["finding_id"]: r for r in self.analysis["ranked"]}

    def plan(self, max_items: int = 12, min_priority: str = "P2-high") -> dict:
        order = ["P1-urgent", "P2-high", "P3-medium", "P4-low"]
        keep = set(order[: order.index(min_priority) + 1])
        groups: Dict[str, List[dict]] = {}
        for r in self.analysis["ranked"]:
            if r["priority"] not in keep:
                continue
            f = self.by_id[r["finding_id"]]
            key = (f.get("component") or {}).get("id") or f"{f['rule']}|{f['evidence'][0]['source']}|{f['evidence'][0].get('location')}"
            groups.setdefault(key, []).append(f)
        items = []
        for key, fs in groups.items():
            score = max(self.rank[f["id"]]["score"] for f in fs)
            items.append((score, key, fs))
        items.sort(key=lambda x: -x[0])
        out = []
        for n, (score, key, fs) in enumerate(items[:max_items], 1):
            item = self._item(f"R{n}", key, fs, score)
            out.append(item)
        return {"schema": "guardian.plan/v1", "project": self.doc["project"], "items": out,
                "policy": "No change is applied without an explicit human approval recorded in this plan. "
                          "The Guardian never pushes, merges, deploys or releases.",
                "deferred": [{"key": k, "score": s, "findings": [f["id"] for f in fs]} for s, k, fs in items[max_items:]]}

    # ------------------------------------------------------------
    def _item(self, item_id: str, key: str, fs: List[dict], score: int) -> dict:
        f0 = fs[0]
        c = self.inv.components.get(key)
        prio = min((self.rank[f["id"]]["priority"] for f in fs))
        item = {"item_id": item_id, "title": self._title(c, fs), "priority": prio, "score": score,
                "findings": [f["id"] for f in fs], "categories": sorted({f["category"] for f in fs}),
                "component": f0.get("component"), "dependency_paths": f0.get("dependency_paths", [])[:2],
                "reachability": self.rank[f0["id"]]["reachability"], "exposure": self.rank[f0["id"]]["exposure"],
                "status": "pending-approval", "approval": None}
        if c is not None and c.ecosystem == "npm":
            opts = self._npm_options(item_id, c, fs)
        elif c is not None and c.ecosystem == "github-actions":
            opts = self._action_options(item_id, c, fs)
        elif c is not None and c.ecosystem == "docker":
            opts = self._image_options(item_id, c, fs)
        else:
            opts = self._generic_options(item_id, fs)
        for o in opts:
            o.setdefault("rollback", "the change is a single commit on branch guardian/fix-*; "
                                     "`git revert <commit>` or delete the branch (nothing is merged automatically)")
        rec = [o for o in opts if o.get("recommended")]
        if not rec and opts:
            opts[0]["recommended"] = True
        item["options"] = opts
        return item

    def _title(self, c, fs):
        if c is None:
            return fs[0]["title"]
        cats = {f["category"] for f in fs}
        what = f"{len(fs)} known vulnerabilit{'ies' if len(fs) > 1 else 'y'}" if cats == {"vulnerability"} else ", ".join(sorted(cats))
        return f"{c.name}@{c.version}: {what}"

    def _reduction(self, fs: List[dict], note: str = "") -> dict:
        return {"findings_resolved": [f["id"] for f in fs],
                "score_removed": sum(self.rank[f["id"]]["score"] for f in fs),
                "estimate": True, "note": note or "expected; confirmed by rescan during validation"}

    # ------------------------------------------------------------ npm
    def _npm_options(self, iid: str, c: Component, fs: List[dict]) -> List[dict]:
        cats = {f["category"] for f in fs}
        sub = self.ctx.subproject_of(c)
        imports = self.ctx.imported_in(c.name, sub)
        opts = []
        if cats & {"malicious-package", "typosquat"}:
            sec, spec = _declared(self.project, sub, c.name)
            ch = [{"type": "package-json", "subproject": sub, "op": "remove-dep", "name": c.name}] if sec else \
                [{"type": "lockfile", "subproject": sub, "op": "regenerate"}]
            opts.append({"option_id": f"{iid}.a", "action": "remove", "recommended": True,
                         "description": f"Remove '{c.name}' and regenerate the lockfile; block it in policy",
                         "changes": ch, "risk_reduction": self._reduction(fs),
                         "compatibility": {"level": "low" if not imports else "high",
                                           "reasons": [f"{len(imports)} source file(s) import it" if imports else
                                                       "no source file imports it"]},
                         "follow_up": ["rotate any credentials present on machines that installed it"]})
            target = next((re.search(r"looks like '([^']+)'", f["title"]).group(1) for f in fs
                           if f["rule"] == "TYPOSQUAT" and "looks like" in f["title"]), None)
            if target:
                opts.append({"option_id": f"{iid}.b", "action": "replace",
                             "description": f"Replace '{c.name}' with the intended package '{target}'",
                             "changes": [{"type": "package-json", "subproject": sub, "op": "remove-dep", "name": c.name},
                                         {"type": "package-json", "subproject": sub, "op": "set-dep", "name": target,
                                          "value": "latest-at-apply", "section": sec or "dependencies"}],
                             "risk_reduction": self._reduction(fs),
                             "compatibility": {"level": "low", "reasons": ["same intended functionality"]}})
            opts.append(self._escalate(iid, "c", fs))
            return opts
        if cats & {"integrity", "unexpected-dependency"} and "vulnerability" not in cats:
            opts.append({"option_id": f"{iid}.a", "action": "lock-regenerate", "recommended": True,
                         "description": "Regenerate the lockfile from package.json using the public registry "
                                        "(drops injected entries and re-fetches trusted hashes)",
                         "changes": [{"type": "lockfile", "subproject": sub, "op": "regenerate"}],
                         "risk_reduction": self._reduction(fs),
                         "compatibility": {"level": "medium", "reasons": ["other transitive versions may move within their ranges"]}})
            opts.append(self._escalate(iid, "b", fs))
            return opts
        # ---- known vulnerabilities
        safe = _safe_versions(c, fs) if self.online else []
        is_direct = any(p == ROOT_ID or (self.inv.components.get(p) and self.inv.components[p].type == "application")
                        for p in _parents(self.inv, c.id))
        letter = iter("abcdefgh")
        if is_direct and safe:
            sec, spec = _declared(self.project, sub, c.name)
            same_major = [v for v in safe if _semver_delta(c.version, v) != "major"]
            pick = same_major[0] if same_major else safe[0]
            delta = _semver_delta(c.version, pick)
            opts.append({"option_id": f"{iid}.{next(letter)}", "action": "upgrade", "recommended": True,
                         "description": f"Upgrade {c.name} {c.version} -> {pick} ({delta})",
                         "changes": [{"type": "package-json", "subproject": sub, "op": "set-dep", "name": c.name,
                                      "value": _spec_like(spec or "", pick), "section": sec or "dependencies"}],
                         "risk_reduction": self._reduction(fs),
                         "compatibility": self._compat(delta, imports, c.name)})
        elif safe:
            parents = [self.inv.components[p] for p in _parents(self.inv, c.id) if p in self.inv.components]
            ranges = {p.name: (_lock_entry(self.project, p).get("dependencies") or {}).get(c.name) for p in parents}
            in_range = [v for v in safe if all(r is None or satisfies(v, r) for r in ranges.values())]
            if in_range:
                opts.append({"option_id": f"{iid}.{next(letter)}", "action": "lock-refresh", "recommended": True,
                             "description": f"Refresh lockfile: {c.name} {c.version} -> {in_range[0]} "
                                            f"(already allowed by {', '.join(f'{k} {v}' for k, v in ranges.items())})",
                             "changes": [{"type": "lockfile", "subproject": sub, "op": "update", "name": c.name}],
                             "risk_reduction": self._reduction(fs),
                             "compatibility": {"level": "low", "reasons": ["stays inside the range every parent declares",
                                                                          f"semver {_semver_delta(c.version, in_range[0])}"]}})
            up = self._parent_upgrade(c, parents, safe)
            if up:
                p, pv, why = up
                psub = self.ctx.subproject_of(p)
                sec, spec = _declared(self.project, psub, p.name)
                delta = _semver_delta(p.version, pv)
                opts.append({"option_id": f"{iid}.{next(letter)}", "action": "upgrade-parent", "recommended": not in_range,
                             "description": f"Upgrade direct dependency {p.name} {p.version} -> {pv} ({delta}); {why}",
                             "changes": [{"type": "package-json", "subproject": psub, "op": "set-dep", "name": p.name,
                                          "value": _spec_like(spec or "", pv), "section": sec or "dependencies"}],
                             "risk_reduction": self._reduction(fs, "expected; the parent upgrade may also change other transitive packages"),
                             "compatibility": self._compat(delta, self.ctx.imported_in(p.name, psub), p.name)})
            target = in_range[0] if in_range else safe[0]
            outside = [f"{k} declares {v}" for k, v in ranges.items() if v and not satisfies(target, v)]
            opts.append({"option_id": f"{iid}.{next(letter)}", "action": "override",
                         "description": f"Force {c.name}@{target} with npm overrides",
                         "changes": [{"type": "package-json", "subproject": sub, "op": "set-override",
                                      "name": c.name, "value": target}],
                         "risk_reduction": self._reduction(fs),
                         "compatibility": {"level": "high" if outside else "low",
                                           "reasons": ([f"outside the declared range ({'; '.join(outside)}): parent may break"]
                                                       if outside else ["inside declared ranges"])}})
        if not safe:
            opts.append({"option_id": f"{iid}.{next(letter)}", "action": "mitigate", "recommended": True,
                         "description": "No fixed version available: restrict use of the affected function / input, "
                                        "or replace the package",
                         "changes": [], "risk_reduction": {"findings_resolved": [], "score_removed": 0, "estimate": True,
                                                           "note": "manual mitigation; risk remains until replaced"},
                         "compatibility": {"level": "unknown", "reasons": ["manual change"]}})
        opts.append(self._accept(iid, next(letter), fs))
        opts.append(self._escalate(iid, next(letter), fs))
        return opts

    def _parent_upgrade(self, c: Component, parents: List[Component], safe: List[str]):
        """Find the smallest version of a DIRECT parent whose dependency range admits a safe version."""
        for p in parents:
            direct = any(pp == ROOT_ID or (self.inv.components.get(pp) and self.inv.components[pp].type == "application")
                         for pp in _parents(self.inv, p.id))
            if not direct:
                continue
            doc = _packument(p.name, full=True)
            for v in sorted((v for v in (doc.get("versions") or {}) if not is_prerelease(v) and cmp(v, p.version or "0") > 0),
                            key=vkey):
                deps = (doc["versions"][v].get("dependencies") or {})
                if c.name not in deps:
                    return p, v, f"{p.name}@{v} no longer depends on {c.name}"
                if any(satisfies(s, deps[c.name]) for s in safe):
                    return p, v, f"{p.name}@{v} requires {c.name} {deps[c.name]}, which admits a fixed version"
        return None

    def _compat(self, delta: str, imports: List[str], name: str) -> dict:
        lvl = {"patch": "low", "minor": "low", "major": "high", "unknown": "medium"}[delta]
        reasons = [f"semver {delta} change"]
        if imports:
            reasons.append(f"{len(imports)} source file(s) import {name}: {', '.join(imports[:3])}")
        if delta == "major":
            reasons.append("breaking API changes possible; build + tests must pass before approval is final")
        return {"level": lvl, "reasons": reasons}

    # ------------------------------------------------------------ CI / images / generic
    def _action_options(self, iid: str, c: Component, fs: List[dict]) -> List[dict]:
        ref = c.properties.get("ref") or ""
        repo = "/".join(c.name.split("/")[:2])
        sha = None
        try:
            out = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}", f"refs/tags/{ref}",
                                  f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"],
                                 capture_output=True, text=True, timeout=60).stdout
            lines = dict(reversed(l.split("\t")) for l in out.splitlines() if "\t" in l)
            sha = lines.get(f"refs/tags/{ref}^{{}}") or lines.get(f"refs/tags/{ref}") or lines.get(f"refs/heads/{ref}")
        except (OSError, subprocess.SubprocessError):
            pass
        opts = []
        if sha:
            changes = []
            for src, loc in zip(c.source_files, c.locations):
                line = int(loc.rsplit(":", 1)[1]) if ":" in loc else None
                changes.append({"type": "text-replace", "file": src, "line": line,
                                "old": f"{c.name}@{ref}", "new": f"{c.name}@{sha} # {ref}"})
            opts.append({"option_id": f"{iid}.a", "action": "pin", "recommended": True,
                         "description": f"Pin {c.name} to commit {sha[:12]} (what '{ref}' resolves to today)",
                         "changes": changes, "risk_reduction": self._reduction(fs),
                         "compatibility": {"level": "none", "reasons": ["identical code to what runs today; only future silent changes are blocked"]}})
        opts.append(self._escalate(iid, "b" if sha else "a", fs))
        return opts

    def _image_options(self, iid: str, c: Component, fs: List[dict]) -> List[dict]:
        return [{"option_id": f"{iid}.a", "action": "pin", "recommended": True,
                 "description": f"Pin '{c.name}' to an explicit version tag + sha256 digest from a trusted registry "
                                "(digest lookup needs registry access; filled in by the reviewer)",
                 "changes": [], "risk_reduction": self._reduction(fs),
                 "compatibility": {"level": "low", "reasons": ["same image if pinned to the current digest"]}},
                self._escalate(iid, "b", fs)]

    def _generic_options(self, iid: str, fs: List[dict]) -> List[dict]:
        return [self._escalate(iid, "a", fs, recommended=True), self._accept(iid, "b", fs)]

    def _escalate(self, iid, letter, fs, recommended=False):
        return {"option_id": f"{iid}.{letter}", "action": "escalate", "recommended": recommended,
                "description": "Request security review; keep the component blocked by policy meanwhile",
                "changes": [], "risk_reduction": {"findings_resolved": [], "score_removed": 0, "estimate": True,
                                                  "note": "risk unchanged until review decision"},
                "compatibility": {"level": "none", "reasons": ["no code change"]}}

    def _accept(self, iid, letter, fs):
        return {"option_id": f"{iid}.{letter}", "action": "accept",
                "description": "Accept the risk (requires a written justification and an expiry/review date)",
                "changes": [], "risk_reduction": {"findings_resolved": [], "score_removed": 0, "estimate": False,
                                                  "note": "risk accepted, recorded as residual"},
                "compatibility": {"level": "none", "reasons": ["no change"]}}
