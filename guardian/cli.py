"""CLI.

  python -m guardian scan <project_dir> [-o out/] [--baseline <sbom|lockfile|dir>] [--sbom extra.json]
                          [--image name:tag] [--vuln-source auto|osv|npm|offline] [--vuln-db db.json]
                          [--verify-registry] [--policy policy.json] [--fail-on high]
  python -m guardian discover <project_dir> [-o out/]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import discover as disc
from . import detect as det
from . import report
from .models import SEVERITY_ORDER


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian: Discover + Detect")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "discover"):
        p = sub.add_parser(name)
        p.add_argument("project", type=Path)
        p.add_argument("-o", "--out", type=Path, default=Path("guardian-out"))
        p.add_argument("--sbom", type=Path, action="append", default=[], help="extra CycloneDX/SPDX SBOM to merge (e.g. syft image SBOM)")
        p.add_argument("--image", action="append", default=[], help="container image to inspect with syft")
        p.add_argument("--maven-tree", type=Path, help="output of mvn dependency:tree -DoutputType=tgf")
        if name == "scan":
            p.add_argument("--baseline", type=Path, help="trusted earlier SBOM / inventory.json / package-lock.json / project dir")
            p.add_argument("--vuln-source", choices=["auto", "osv", "npm", "offline"], default="auto")
            p.add_argument("--vuln-db", type=Path, help="OSV-format JSON list for offline matching")
            p.add_argument("--verify-registry", action="store_true", help="compare every lockfile hash with the npm registry")
            p.add_argument("--policy", type=Path, help="JSON policy overrides (trusted images, action owners...)")
            p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any finding at/above this severity")
    a = ap.parse_args(argv)

    inv, ctx = disc.discover(a.project, a.sbom, a.image, a.maven_tree)
    disc.write_outputs(inv, a.out)
    st = disc.stats(inv)
    print(f"[discover] {inv.project}: {st['components']} components ({st['direct']} direct, {st['transitive']} transitive), "
          f"depth {st['max_depth']}, ecosystems {st['by_ecosystem']}")
    for n in inv.notes:
        print(f"  note: {n}")
    if a.cmd == "discover":
        print(f"[discover] wrote {a.out}/sbom.cdx.json, inventory.json, dependency-graph.json/.dot")
        return 0

    result = det.detect(inv, ctx, a.vuln_source, a.vuln_db, a.baseline, a.verify_registry, det.load_policy(a.policy))
    doc = report.build_doc(inv, st, result, ctx)
    report.write_json(doc, a.out / "findings.json")
    report.write_sarif(doc, a.out / "findings.sarif")
    report.write_html(doc, a.out / "report.html")
    s = doc["summary"]
    print(f"[detect] vulnerability source: {doc['vulnerability_source']}")
    for k, v in doc["checks"].items():
        print(f"  {k:22s} {v['status']:5s} {v.get('findings', v.get('error', ''))}")
    print(f"[detect] {s['total']} findings  " + "  ".join(f"{k}:{v}" for k, v in s["by_severity"].items()))
    for f in result["findings"][:15]:
        if f.severity in ("critical", "high"):
            path = " > ".join(f.dependency_paths[0]) if f.dependency_paths else ""
            print(f"  [{f.severity.upper():8s}] {f.title}" + (f"\n             path: {path}" if path else ""))
    print(f"[detect] wrote {a.out}/findings.json, findings.sarif, report.html")
    if a.fail_on:
        th = SEVERITY_ORDER[a.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= th for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
