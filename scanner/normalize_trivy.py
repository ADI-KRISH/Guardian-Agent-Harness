#!/usr/bin/env python3
"""Normalize a Trivy JSON report into the Guardian findings format (data/vulns.json).

Usage (repo scan):
  python3 scanner/normalize_trivy.py \
      --input data/raw/trivy-repo.json --output data/vulns.json \
      --target-name juice-shop --ref v20.4.0 --commit 266448aba68cd8ba5915f526a128da4fa7bc3f9f

Usage (image scan; different id prefix so ids never collide with repo findings):
  python3 scanner/normalize_trivy.py \
      --input data/raw/trivy-image.json --output data/vulns-image.json \
      --scan-kind image --id-prefix F-IMG ...

Expects the repo scan to be run with --list-all-pkgs so dependency paths can be built.
Everything written here comes straight from the scanner, so verified=true.
"""
import argparse
import json
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


# ---------- version helpers ----------
def clean_version(v):
    return re.sub(r"^[<>=~^\s]+", "", v.strip())


def ver_key(v):
    nums = re.findall(r"\d+", v)[:4]
    return tuple(int(n) for n in nums) or (0,)


def parse_fixed(fixed_str):
    """'5.2.5, 6.2.4, 8.21.0' or '>=3.0.0' -> sorted list of clean versions."""
    if not fixed_str:
        return []
    parts = [clean_version(p) for p in fixed_str.split(",") if p.strip()]
    return sorted({p for p in parts if p}, key=ver_key)


def best_fix(installed, fixed):
    """Prefer the lowest fixed version in the same major as the installed one."""
    if not fixed:
        return None
    newer = [f for f in fixed if ver_key(f) > ver_key(installed)] or fixed
    same_major = [f for f in newer if ver_key(f)[0] == ver_key(installed)[0]]
    return (same_major or newer)[0]


# ---------- identity helpers ----------
def make_purl(name, version, identifier, res_type):
    purl = (identifier or {}).get("PURL")
    if purl:
        return purl
    eco = (res_type or "npm").lower()
    if name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{eco}/{name}@{version}"


def ecosystem_of(purl):
    m = re.match(r"pkg:([^/]+)/", purl)
    return m.group(1) if m else "unknown"


def pick_cvss(cvss):
    if not cvss:
        return None
    order = ["nvd", "ghsa", "redhat"] + [k for k in cvss if k not in ("nvd", "ghsa", "redhat")]
    for src in order:
        c = cvss.get(src) or {}
        if c.get("V3Score") is not None:
            return {"score": c["V3Score"], "vector": c.get("V3Vector"), "source": src}
    for src in order:
        c = cvss.get(src) or {}
        if c.get("V2Score") is not None:
            return {"score": c["V2Score"], "vector": c.get("V2Vector"), "source": src}
    return None


# ---------- dependency graph (from --list-all-pkgs) ----------
def package_id(p):
    return p.get("ID") or f'{p.get("Name")}@{p.get("Version")}'


def build_index(packages):
    by_id = {package_id(p): p for p in packages}
    directs = [i for i, p in by_id.items() if p.get("Relationship") == "direct"]
    if not directs:  # fallback: children of the root/workspace package
        for p in by_id.values():
            if p.get("Relationship") in ("root", "workspace"):
                directs += [d for d in p.get("DependsOn") or [] if d in by_id]
    return by_id, directs


def shortest_paths(by_id, directs):
    paths, q = {}, deque()
    for d in directs:
        if d not in paths:
            paths[d] = [d]
            q.append(d)
    while q:
        cur = q.popleft()
        for nxt in by_id.get(cur, {}).get("DependsOn") or []:
            if nxt in by_id and nxt not in paths \
                    and by_id[nxt].get("Relationship") not in ("root", "workspace"):
                paths[nxt] = paths[cur] + [nxt]
                q.append(nxt)
    return paths


# ---------- main conversion ----------
def normalize(report, args):
    root_purl = f"pkg:npm/{args.target_name}@{args.ref.lstrip('v')}"
    merged = {}

    for res in report.get("Results") or []:
        vulns = res.get("Vulnerabilities") or []
        if not vulns:
            continue
        res_type = res.get("Type")
        target = res.get("Target", "")
        by_id, directs = build_index(res.get("Packages") or [])
        paths = shortest_paths(by_id, directs)

        def purl_of_id(pid):
            p = by_id[pid]
            return make_purl(p.get("Name", pid), p.get("Version", ""), p.get("Identifier"), res_type)

        for v in vulns:
            name, version = v.get("PkgName", ""), v.get("InstalledVersion", "")
            pid = v.get("PkgID") or f"{name}@{version}"
            pkg = by_id.get(pid, {})
            purl = make_purl(name, version, v.get("PkgIdentifier") or pkg.get("Identifier"), res_type)
            adv = v.get("VulnerabilityID", "UNKNOWN")
            key = (adv, purl)

            id_path = paths.get(pid)
            path = [root_purl] + [purl_of_id(i) for i in id_path] if id_path else None
            if id_path:
                rel = "direct" if len(id_path) == 1 else "transitive"
            else:
                rel = {"direct": "direct", "indirect": "transitive"}.get(pkg.get("Relationship"), "unknown")

            if key in merged:  # same package in two lockfiles: merge sources, keep shorter path
                f = merged[key]
                srcs = f["evidence"]["source_file"].split(", ")
                if target not in srcs:
                    f["evidence"]["source_file"] = ", ".join(srcs + [target])
                if path and (not f["dependency_path"] or len(path) < len(f["dependency_path"])):
                    f["dependency_path"], f["relationship"] = path, rel
                continue

            fixed_versions = parse_fixed(v.get("FixedVersion"))
            fixed = best_fix(version, fixed_versions)
            sev = (v.get("Severity") or "unknown").lower()
            if sev not in SEV_RANK:
                sev = "unknown"
            reason = f"Severity {sev}; " + (f"fix available in {fixed}" if fixed else "no fix available")

            merged[key] = {
                "type": "cve",
                "title": v.get("Title") or f"{adv} in {name}",
                "component": {"purl": purl, "name": name, "version": version,
                              "ecosystem": ecosystem_of(purl)},
                "relationship": rel,
                "dependency_path": path,
                "severity": sev,
                "cvss": pick_cvss(v.get("CVSS")),
                "advisory_ids": [adv],
                "fixed_version": fixed,
                "fixed_versions": fixed_versions,
                "fix_available": bool(fixed),
                "status": v.get("Status"),
                "description": v.get("Description", ""),
                "evidence": {
                    "tool": "trivy", "tool_version": args.tool_version,
                    "scan_kind": args.scan_kind, "source_file": target,
                    "raw_ref": f"raw/{Path(args.input).name}",
                    "reference_url": v.get("PrimaryURL"),
                },
                "verified": True,
                "initial_risk": {"level": sev, "reason": reason},
            }

    findings = sorted(
        merged.values(),
        key=lambda f: (SEV_RANK[f["severity"]], f["component"]["name"],
                       f["component"]["version"], f["advisory_ids"][0]),
    )
    for i, f in enumerate(findings, 1):
        f["id"] = f"{args.id_prefix}-{i:03d}"
        # put id first for readability
    findings = [{"id": f.pop("id"), **f} for f in findings]

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {"name": args.target_name, "ref": args.ref, "commit": args.commit},
        "findings": findings,
    }


def print_summary(out):
    fs = out["findings"]
    print(f"{len(fs)} findings written\n")
    groups = {}
    for f in fs:
        groups.setdefault(f["component"]["purl"], []).append(f)
    rows = []
    for purl, items in groups.items():
        worst = min(items, key=lambda f: SEV_RANK[f["severity"]])["severity"]
        fixes = [f["fixed_version"] for f in items if f["fixed_version"]]
        all_fixable = all(f["fix_available"] for f in items)
        fix_all = max(fixes, key=ver_key) if fixes and all_fixable else ("partial" if fixes else "none")
        rows.append((SEV_RANK[worst], purl, len(items), worst, items[0]["relationship"],
                     len(items[0]["dependency_path"] or []), fix_all))
    rows.sort()
    print(f"{'package':45} {'#':>3} {'worst':9} {'rel':11} {'path':>4}  fix-for-all")
    for _, purl, n, worst, rel, plen, fix in rows:
        print(f"{purl[:45]:45} {n:>3} {worst:9} {rel:11} {plen:>4}  {fix}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--target-name", default="juice-shop")
    ap.add_argument("--ref", default="v20.4.0")
    ap.add_argument("--commit", default="")
    ap.add_argument("--scan-kind", default="repo", choices=["repo", "image"])
    ap.add_argument("--id-prefix", default="F-CVE")
    ap.add_argument("--tool-version", default="0.76.2")
    args = ap.parse_args()

    with open(args.input) as fh:
        report = json.load(fh)
    out = normalize(report, args)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(out, fh, indent=2)
    print_summary(out)


if __name__ == "__main__":
    sys.exit(main())
