"""Detect stage: Inventory (+ context, + optional baseline) -> evidence-backed Findings."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from .. import net
from ..models import Finding, Inventory, SEVERITY_ORDER
from . import changes, infra, packages, vulns


def load_policy(path: Optional[Path]) -> dict:
    pol = dict(infra.DEFAULT_POLICY)
    if path:
        pol.update(json.loads(Path(path).read_text()))
    return pol


def load_baseline(path: Path) -> Inventory:
    """Baseline can be: our inventory.json, a CycloneDX/SPDX SBOM, a lockfile, or a project directory."""
    from ..discover import discover
    from ..discover.sbom import read_sbom
    path = Path(path)
    if path.is_dir():
        return discover(path)[0]
    data = json.loads(path.read_text())
    if "components" in data and "edges" in data and "bomFormat" not in data:
        return Inventory.from_dict(data)
    if data.get("bomFormat") or data.get("spdxVersion"):
        inv = Inventory(project="baseline")
        read_sbom(path, inv)
        return inv
    if "lockfileVersion" in data:
        tmp = Path(tempfile.mkdtemp())
        shutil.copy(path, tmp / "package-lock.json")
        sib = path.parent / "package.json"
        if sib.exists():
            shutil.copy(sib, tmp / "package.json")
        return discover(tmp)[0]
    raise ValueError(f"unrecognised baseline: {path}")


def detect(inv: Inventory, context: dict, vuln_source: str = "auto", vuln_db: Optional[Path] = None,
           baseline: Optional[Path] = None, verify_registry: bool = False, policy: Optional[dict] = None,
           online: Optional[bool] = None) -> dict:
    project_dir = Path(context["project_dir"])
    policy = policy or load_policy(None)
    if online is None:
        online = not net.OFFLINE and vuln_source != "offline"
    findings: List[Finding] = []
    meta = {"checks": {}}

    def run(name, fn):
        try:
            res = fn()
            if isinstance(res, tuple):
                res, extra = res
                meta[name] = extra
            findings.extend(res)
            meta["checks"][name] = {"status": "ok", "findings": len(res)}
        except Exception as e:  # a failing check must never hide the others
            meta["checks"][name] = {"status": "error", "error": f"{e.__class__.__name__}: {e}"}

    run("vulnerabilities", lambda: vulns.detect(inv, vuln_source, vuln_db))
    run("typosquatting", lambda: packages.typosquat(inv, online))
    run("install_scripts", lambda: packages.install_scripts(inv, project_dir, online))
    run("lockfile_integrity", lambda: packages.integrity(inv))
    run("manifest_consistency", lambda: changes.manifest_consistency(inv, project_dir))
    run("container_images", lambda: infra.images(inv, policy))
    run("dockerfile", lambda: infra.dockerfile(context.get("dockerfile", [])))
    run("cicd_workflows", lambda: infra.workflows(inv, context.get("workflows", []), policy))
    if verify_registry and online:
        run("registry_verification", lambda: packages.verify_registry(inv))
    if baseline:
        run("baseline_diff", lambda: changes.diff_baseline(inv, load_baseline(baseline), str(baseline)))

    # dedupe by id, sort by severity then category
    uniq = {}
    for f in findings:
        uniq.setdefault(f.id, f)
    ordered = sorted(uniq.values(), key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.title))
    return {"findings": ordered, "meta": meta}
