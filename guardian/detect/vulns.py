"""Known-vulnerability correlation.

Sources, in order (each finding records which one produced it):
  1. OSV.dev batch API  - all ecosystems; includes MAL-* malicious-package entries.
  2. npm registry bulk advisory API (GitHub Advisory DB) - npm only, used if OSV is unreachable.
  3. Offline OSV-format JSON database (data/offline-advisories.json or --vuln-db) - air-gapped demo / CI.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .. import net
from ..models import Component, Evidence, Finding, Inventory
from ..versions import in_osv_range, lowest_safe, satisfies, cmp
from . import cvss

OSV_ECO = {"npm": "npm", "maven": "Maven", "pypi": "PyPI", "go": "Go", "cargo": "crates.io",
           "rubygems": "RubyGems", "nuget": "NuGet", "deb": "Debian", "apk": "Alpine"}
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _pkgs(inv: Inventory) -> List[Component]:
    return [c for c in inv.components.values() if c.version and c.ecosystem in OSV_ECO]


# ---------------------------------------------------------------- OSV online
def _osv_online(comps: List[Component]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    ids_needed = set()
    for i in range(0, len(comps), 500):
        chunk = comps[i:i + 500]
        body = {"queries": [{"package": {"name": c.name, "ecosystem": OSV_ECO[c.ecosystem]}, "version": c.version}
                            for c in chunk]}
        res = net.fetch_json("https://api.osv.dev/v1/querybatch", body=body, timeout=60)
        for c, r in zip(chunk, res.get("results", [])):
            vids = [v["id"] for v in r.get("vulns") or []]
            if vids:
                out[c.id] = vids
                ids_needed.update(vids)
    with ThreadPoolExecutor(max_workers=16) as ex:
        details = dict(zip(ids_needed, ex.map(lambda v: net.fetch_json(f"https://api.osv.dev/v1/vulns/{v}", ttl=86400),
                                              ids_needed)))
    return {cid: [details[v] for v in vids if "id" in details.get(v, {})] for cid, vids in out.items()}


# ---------------------------------------------------------------- npm advisories
def _npm_bulk(comps: List[Component]) -> Dict[str, List[dict]]:
    npm_comps = [c for c in comps if c.ecosystem == "npm"]
    body: Dict[str, List[str]] = {}
    for c in npm_comps:
        body.setdefault(c.name, [])
        if c.version not in body[c.name]:
            body[c.name].append(c.version)
    res = {}
    items = list(body.items())
    for i in range(0, len(items), 400):
        part = net.fetch_json("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
                              body=dict(items[i:i + 400]), timeout=60)
        res.update({k: v for k, v in part.items() if not k.startswith("__")})
    out: Dict[str, List[dict]] = {}
    for c in npm_comps:
        for adv in res.get(c.name, []):
            if satisfies(c.version, adv.get("vulnerable_versions", "")):
                out.setdefault(c.id, []).append(_npm_adv_to_osv(c.name, adv))
    return out


def _npm_adv_to_osv(name: str, adv: dict) -> dict:
    ghsa = (adv.get("url") or "").rsplit("/", 1)[-1]
    return {
        "id": ghsa or f"NPM-{adv.get('id')}", "summary": adv.get("title"),
        "aliases": [], "references": [{"url": adv.get("url")}] if adv.get("url") else [],
        "database_specific": {"severity": (adv.get("severity") or "").upper(), "cwe_ids": adv.get("cwe") or [],
                              "npm_range": adv.get("vulnerable_versions")},
        "severity": [{"type": "CVSS_V3", "score": (adv.get("cvss") or {}).get("vectorString")}]
        if (adv.get("cvss") or {}).get("vectorString") else [],
        "affected": [{"package": {"ecosystem": "npm", "name": name}, "npm_range": adv.get("vulnerable_versions")}],
    }


# ---------------------------------------------------------------- offline DB
def _offline(comps: List[Component], db_path: Optional[Path]) -> Dict[str, List[dict]]:
    path = db_path or DATA_DIR / "offline-advisories.json"
    if not path.exists():
        return {}
    db = json.loads(path.read_text())
    index: Dict[Tuple[str, str], List[dict]] = {}
    for v in db:
        for a in v.get("affected", []):
            p = a.get("package", {})
            index.setdefault((p.get("ecosystem", "").lower(), p.get("name", "")), []).append(v)
    out = {}
    for c in comps:
        for v in index.get((OSV_ECO[c.ecosystem].lower(), c.name), []):
            if _affects(v, c):
                out.setdefault(c.id, []).append(v)
    return out


def _affects(v: dict, c: Component) -> bool:
    for a in v.get("affected", []):
        p = a.get("package", {})
        if p.get("name") != c.name or p.get("ecosystem", "").lower() != OSV_ECO[c.ecosystem].lower():
            continue
        if a.get("npm_range") and satisfies(c.version, a["npm_range"]):
            return True
        if c.version in (a.get("versions") or []):
            return True
        for r in a.get("ranges", []):
            if r.get("type") in ("ECOSYSTEM", "SEMVER") and in_osv_range(c.version, r.get("events", [])):
                return True
    return False


# ---------------------------------------------------------------- normalisation
def _severity(v: dict) -> Tuple[str, Optional[float], Optional[str]]:
    vec = None
    best = None
    for s in v.get("severity") or []:
        if s.get("type", "").startswith("CVSS_V3") and s.get("score"):
            vec = s["score"]
            best = cvss.score(vec)
    ds = (v.get("database_specific") or {}).get("severity")
    if ds:
        label = {"MODERATE": "medium"}.get(ds.upper(), ds.lower())
        if label in ("critical", "high", "medium", "low"):
            return label, best, vec
    if v.get("id", "").startswith("MAL-"):
        return "critical", best, vec
    return cvss.severity_from_score(best) or "medium", best, vec


def _fixed_versions(v: dict, c: Component) -> List[str]:
    fixes = []
    for a in v.get("affected", []):
        if a.get("package", {}).get("name") != c.name:
            continue
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev and cmp(ev["fixed"], c.version) > 0:
                    fixes.append(ev["fixed"])
    return sorted(set(fixes), key=lambda x: [int(p) if p.isdigit() else 0 for p in x.replace("-", ".").split(".")])


def _registry_versions(name: str) -> List[str]:
    try:
        doc = net.fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}",
                             headers={"Accept": "application/vnd.npm.install-v1+json"}, ttl=86400)
        return list((doc.get("versions") or {}).keys())
    except net.NetError:
        return []


def detect(inv: Inventory, source: str = "auto", db_path: Optional[Path] = None) -> Tuple[List[Finding], dict]:
    comps = _pkgs(inv)
    meta = {"source": None, "queried": len(comps), "errors": []}
    hits: Dict[str, List[dict]] = {}
    order = {"auto": ["osv", "npm", "offline"], "osv": ["osv"], "npm": ["npm"], "offline": ["offline"]}[source]
    for src in order:
        try:
            if src == "osv":
                hits = _osv_online(comps)
            elif src == "npm":
                hits = _npm_bulk(comps)
                non_npm = [c for c in comps if c.ecosystem != "npm"]
                if non_npm:
                    off = _offline(non_npm, db_path)
                    hits.update(off)
                    meta["errors"].append(f"{len(non_npm)} non-npm components checked against offline DB only")
            else:
                hits = _offline(comps, db_path)
            meta["source"] = {"osv": "osv.dev", "npm": "registry.npmjs.org advisories (GitHub Advisory DB)",
                              "offline": f"offline DB ({(db_path or DATA_DIR / 'offline-advisories.json').name})"}[src]
            break
        except net.NetError as e:
            meta["errors"].append(f"{src}: {e}")
    findings: List[Finding] = []
    for cid, vulns in hits.items():
        c = inv.components[cid]
        paths = inv.paths_to(cid)
        seen = set()
        for v in vulns:
            if v["id"] in seen:
                continue
            seen.add(v["id"])
            sev, score, vec = _severity(v)
            fixes = _fixed_versions(v, c)
            if not fixes and c.ecosystem == "npm" and any(a.get("npm_range") for a in v.get("affected", [])):
                rng = next(a["npm_range"] for a in v["affected"] if a.get("npm_range"))
                safe = lowest_safe(c.version, _registry_versions(c.name), lambda x: satisfies(x, rng))
                fixes = [safe] if safe else []
            malicious = v["id"].startswith("MAL-") or bool(re.search(r"malicious|malware|backdoor|compromised (package|version)",
                                                                      (v.get("summary") or "").lower()))
            ids = [v["id"]] + [a for a in v.get("aliases") or [] if a != v["id"]]
            refs = [r["url"] for r in v.get("references") or [] if r.get("url")][:5]
            ev = [Evidence("advisory", meta["source"], f"{v['id']}: {v.get('summary') or v.get('details', '')[:160]}",
                           location=None)]
            rng_txt = _range_text(v, c)
            ev.append(Evidence("version-match", c.source_files[0] if c.source_files else "inventory",
                               f"installed {c.name}@{c.version} is inside affected range {rng_txt}",
                               location=c.locations[0] if c.locations else None))
            if score is not None:
                ev.append(Evidence("cvss", meta["source"], f"CVSS {score} ({vec})"))
            via = sorted({inv.label(p[1]) for p in paths if len(p) > 1})
            findings.append(Finding(
                rule="VULN-KNOWN" if not malicious else "MAL-KNOWN",
                category="malicious-package" if malicious else "vulnerability",
                title=f"{'Known malicious package' if malicious else 'Known vulnerability'} in {c.name}@{c.version}: "
                      f"{(v.get('summary') or v['id'])[:120]}",
                severity="critical" if malicious else sev,
                component={"id": c.id, "name": c.name, "version": c.version, "ecosystem": c.ecosystem,
                           "direct": c.direct, "scope": c.scope},
                evidence=ev, dependency_paths=[[inv.label(x) for x in p] for p in paths],
                identifiers=ids, references=refs,
                fix={"fixed_versions": fixes, "available": bool(fixes), "introduced_via": via,
                     "cvss_score": score, "cwe": (v.get("database_specific") or {}).get("cwe_ids", [])},
            ))
    return findings, meta


def _range_text(v: dict, c: Component) -> str:
    for a in v.get("affected", []):
        if a.get("package", {}).get("name") != c.name:
            continue
        if a.get("npm_range"):
            return a["npm_range"]
        parts = []
        for r in a.get("ranges", []):
            evs = r.get("events", [])
            intro = next((e["introduced"] for e in evs if "introduced" in e), "0")
            fixed = next((e["fixed"] for e in evs if "fixed" in e), None)
            last = next((e["last_affected"] for e in evs if "last_affected" in e), None)
            parts.append(f">={intro}" + (f" <{fixed}" if fixed else f" <={last}" if last else ""))
        if parts:
            return " || ".join(parts)
        if a.get("versions"):
            return "versions " + ", ".join(a["versions"][:5])
    return "(see advisory)"
