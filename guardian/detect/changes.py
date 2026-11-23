"""Unexpected dependencies and suspicious changes.

* Manifest <-> lockfile consistency (dependencies injected into / missing from the lockfile).
* Orphan lockfile entries nobody depends on.
* Baseline diff: compare the current inventory with a trusted earlier SBOM / lockfile and flag
  new packages, downgrades, integrity changes for an unchanged version, and source-URL changes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import Component, Evidence, Finding, Inventory, ROOT_ID
from ..versions import cmp, satisfies, vkey
from .packages import _comp_dict, _paths


def manifest_consistency(inv: Inventory, project_dir: Path) -> List[Finding]:
    pkg = project_dir / "package.json"
    lock_decl = getattr(inv, "lock_root_declared", None)
    if not pkg.exists() or lock_decl is None:
        return []
    m = json.loads(pkg.read_text())
    declared = {}
    for fld in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        declared.update(m.get(fld) or {})
    findings = []
    for name in sorted(set(lock_decl) - set(declared)):
        c = _find_direct(inv, name)
        findings.append(Finding(
            rule="UNEXPECTED-LOCK-ONLY-DEP", category="unexpected-dependency", severity="high",
            title=f"Lockfile root declares '{name}' which is not in package.json",
            component=_comp_dict(c) if c else {"id": f"pkg:npm/{name}", "name": name, "version": None, "ecosystem": "npm"},
            dependency_paths=_paths(inv, c) if c else [],
            evidence=[Evidence("manifest-diff", "package-lock.json", f'packages[""] requires {name}@{lock_decl[name]}',
                               location='packages[""]'),
                      Evidence("manifest-diff", "package.json", f"'{name}' absent from all dependency sections")],
            fix={"suggestion": "lockfile was edited outside npm or is out of sync; regenerate and review the diff"}))
    for name in sorted(set(declared) - set(lock_decl)):
        findings.append(Finding(
            rule="LOCKFILE-STALE", category="unexpected-dependency", severity="low",
            title=f"package.json declares '{name}' but the lockfile does not", component=None,
            evidence=[Evidence("manifest-diff", "package.json", f"{name}: {declared[name]}"),
                      Evidence("manifest-diff", "package-lock.json", f"'{name}' missing from root entry")]))
    for name, spec in declared.items():
        c = _find_direct(inv, name)
        if c and c.version and _is_semver_range(spec) and not satisfies(c.version, spec):
            findings.append(Finding(
                rule="LOCKFILE-RANGE-MISMATCH", category="unexpected-dependency", severity="medium",
                title=f"Locked {name}@{c.version} does not satisfy declared range '{spec}'",
                component=_comp_dict(c), dependency_paths=_paths(inv, c),
                evidence=[Evidence("manifest-diff", "package.json", f"{name}: {spec}"),
                          Evidence("lockfile-entry", c.source_files[0], f"version: {c.version}",
                                   location=c.locations[0] if c.locations else None)]))
    # orphans: present in lockfile, not reachable from any root
    reach = inv.reachable()
    for c in inv.components.values():
        if c.ecosystem == "npm" and c.id not in reach and c.type != "application":
            findings.append(Finding(
                rule="UNEXPECTED-ORPHAN", category="unexpected-dependency", severity="medium",
                title=f"{c.name}@{c.version} is in the lockfile but nothing depends on it", component=_comp_dict(c),
                evidence=[Evidence("lockfile-entry", c.source_files[0], "no dependency edge leads to this package",
                                   location=c.locations[0] if c.locations else None)],
                fix={"suggestion": "remove (npm prune) unless intentionally vendored; check who added it"}))
    return findings


def _is_semver_range(spec: str) -> bool:
    return not any(spec.startswith(p) for p in ("file:", "git", "http", "github:", "npm:", "workspace:", "link:")) \
        and "/" not in spec and spec not in ("latest", "next", "*", "")


def _find_direct(inv: Inventory, name: str) -> Optional[Component]:
    for cid in inv.edges.get(ROOT_ID, ()):
        c = inv.components.get(cid)
        if c and c.name == name:
            return c
    return None


# ---------------------------------------------------------------- baseline diff

def _by_name(inv: Inventory) -> Dict[Tuple[str, str], List[Component]]:
    out: Dict[Tuple[str, str], List[Component]] = {}
    for c in inv.components.values():
        out.setdefault((c.ecosystem, c.name), []).append(c)
    return out


def diff_baseline(cur: Inventory, base: Inventory, base_label: str) -> Tuple[List[Finding], dict]:
    findings: List[Finding] = []
    cur_n, base_n = _by_name(cur), _by_name(base)
    base_ecos = {k[0] for k in base_n}
    # only compare ecosystems the baseline actually covers (a lockfile baseline says nothing about images/CI)
    cur_n = {k: v for k, v in cur_n.items() if k[0] in base_ecos}
    added, removed, changed = [], [], []
    for key, comps in cur_n.items():
        if key not in base_n:
            for c in comps:
                added.append(c)
                sev = "medium" if c.has_install_script else ("low" if c.direct else "info")
                ev = [Evidence("sbom-diff", base_label, f"{c.name} not present in baseline"),
                      Evidence("lockfile-entry", c.source_files[0] if c.source_files else "current",
                               f"added {c.name}@{c.version}", location=c.locations[0] if c.locations else None)]
                if c.has_install_script:
                    ev.append(Evidence("install-script", "lockfile", "new package runs install-time scripts"))
                findings.append(Finding(
                    rule="CHANGE-NEW-PACKAGE", category="unexpected-dependency", severity=sev,
                    title=f"New {'direct' if c.direct else 'transitive'} dependency: {c.name}@{c.version}",
                    component=_comp_dict(c), evidence=ev, dependency_paths=_paths(cur, c),
                    fix={"introduced_via": sorted({p[1] for p in _paths(cur, c) if len(p) > 1})}))
            continue
        bvers = {b.version: b for b in base_n[key]}
        for c in comps:
            b = bvers.get(c.version)
            if b is None:
                known = [v for v in bvers if v]
                down = bool(c.version and known and cmp(c.version, max(known, key=vkey)) < 0)
                changed.append((c, list(bvers)))
                findings.append(Finding(
                    rule="CHANGE-DOWNGRADE" if down else "CHANGE-VERSION", category="unexpected-dependency",
                    severity="medium" if down else "info",
                    title=f"{c.name} {'downgraded' if down else 'changed'}: {', '.join(str(v) for v in bvers)} -> {c.version}",
                    component=_comp_dict(c), dependency_paths=_paths(cur, c),
                    evidence=[Evidence("sbom-diff", base_label, f"baseline versions: {', '.join(str(v) for v in bvers)}"),
                              Evidence("lockfile-entry", c.source_files[0] if c.source_files else "current",
                                       f"current version: {c.version}", location=c.locations[0] if c.locations else None)]))
                continue
            if b.integrity and c.integrity and b.integrity != c.integrity:
                findings.append(Finding(
                    rule="CHANGE-INTEGRITY", category="integrity", severity="critical",
                    title=f"Integrity hash changed for unchanged version {c.name}@{c.version}",
                    component=_comp_dict(c), dependency_paths=_paths(cur, c),
                    evidence=[Evidence("sbom-diff", base_label, f"baseline integrity: {b.integrity[:48]}..."),
                              Evidence("lockfile-entry", c.source_files[0] if c.source_files else "current",
                                       f"current integrity: {c.integrity[:48]}...", location=c.locations[0] if c.locations else None)],
                    fix={"suggestion": "same version must always have the same bytes: treat as tampering, restore baseline lockfile"}))
            bh, ch = urlparse(b.resolved or "").hostname, urlparse(c.resolved or "").hostname
            if b.resolved and c.resolved and bh != ch:
                findings.append(Finding(
                    rule="CHANGE-SOURCE", category="integrity", severity="high",
                    title=f"Download source for {c.name}@{c.version} changed: {bh} -> {ch}",
                    component=_comp_dict(c), dependency_paths=_paths(cur, c),
                    evidence=[Evidence("sbom-diff", base_label, f"baseline resolved: {b.resolved}"),
                              Evidence("lockfile-entry", c.source_files[0] if c.source_files else "current",
                                       f"current resolved: {c.resolved}", location=c.locations[0] if c.locations else None)]))
            if c.has_install_script and not b.has_install_script:
                findings.append(Finding(
                    rule="CHANGE-NEW-INSTALL-SCRIPT", category="install-script", severity="high",
                    title=f"{c.name}@{c.version} gained an install script compared with baseline",
                    component=_comp_dict(c), dependency_paths=_paths(cur, c),
                    evidence=[Evidence("sbom-diff", base_label, "baseline: no install script; current: hasInstallScript")]))
    for key, comps in base_n.items():
        if key not in cur_n:
            removed.extend(comps)
    summary = {"baseline": base_label, "added": len(added), "removed": len(removed), "version_changed": len(changed),
               "added_list": [f"{c.name}@{c.version}" for c in added][:200],
               "removed_list": [f"{c.name}@{c.version}" for c in removed][:200],
               "changed_list": [f"{c.name}: {','.join(str(v) for v in vs)} -> {c.version}" for c, vs in changed][:200]}
    return findings, summary
