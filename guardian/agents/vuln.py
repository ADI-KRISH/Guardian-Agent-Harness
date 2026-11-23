"""Vulnerability agent: known vulnerabilities (OSV) traced back through the dependency graph."""
from __future__ import annotations

from pathlib import Path

from ..tools import scanners
from . import finding
from .discovery import paths_to, pkey

GHSA_SEV = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}


def _fixed(v: dict, name: str) -> list[str]:
    out = []
    for aff in v.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out))


def scan(head_dir: Path, head: dict, base: dict | None) -> tuple[list[dict], dict]:
    r = scanners.osv_scan(head_dir)
    data = r.json() or {}
    findings = []
    base_pk = (base or {}).get("packages", {})
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "")
        try:
            src_rel = str(Path(src).resolve().relative_to(head_dir.resolve())).replace("\\", "/")
        except ValueError:
            src_rel = src
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            name, ver, eco = p.get("name", ""), p.get("version", ""), p.get("ecosystem", "")
            k = pkey(eco, name, ver)
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for g in pkg.get("groups", []) or [{"ids": [i]} for i in vulns]:
                ids = g.get("ids", [])
                v = next((vulns[i] for i in ids if i in vulns), {})
                aliases = sorted(set(ids + g.get("aliases", []) + v.get("aliases", [])))
                cves = [a for a in aliases if a.startswith("CVE-")]
                sev = None
                try:
                    sev = float(g.get("max_severity")) if g.get("max_severity") not in (None, "") else None
                except ValueError:
                    sev = None
                if sev is None:
                    sev = GHSA_SEV.get(str(v.get("database_specific", {}).get("severity", "")).upper(), 5.0)
                fixed = _fixed(v, name)
                meta = head["packages"].get(k, {})
                is_new = k not in base_pk
                primary = (cves or ids or ["?"])[0]
                f = finding("known_vulnerability", f"{name} {ver}: {primary} {v.get('summary', '')}".strip(),
                            component=k, detector="osv-scanner", severity=sev,
                            location={"file": src_rel},
                            change="introduced since baseline" if (base and is_new) else ("present in baseline" if base else ""),
                            verified_evidence=[f"OSV {', '.join(ids)} matches {name}@{ver} in {src_rel}",
                                               f"severity {sev} ({'CVSS' if g.get('max_severity') else 'advisory rating'})",
                                               f"fixed in: {', '.join(fixed) or 'no fixed version published'}"],
                            extra={"id": primary, "advisory_ids": ids, "aliases": aliases, "fixed_versions": fixed,
                                   "scope": meta.get("scope", "unknown")},
                            recommendation=(f"Upgrade {name} to {fixed[0]} or later" if fixed else "No fix published: consider replacing or mitigating") )
                f["dependency_paths"] = paths_to(k, head["graph"], head["roots"])
                findings.append(f)
    return findings, r.meta()
