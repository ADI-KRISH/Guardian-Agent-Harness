"""Validate stage: approved plan -> isolated branch -> build + tests (before vs after) -> rescan ->
before/after SBOM + findings comparison -> verdict. The branch is left for a human to review/merge."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ..audit import Audit, file_sha
from ..models import Inventory, SEVERITY_ORDER
from ..remediate import option_hash
from .apply import apply_changes, commit, diff_stat, make_workspace, manifest_diff, parse_tests, sh


def _key(f: dict):
    c = f.get("component") or {}
    return (f["rule"], c.get("name"), c.get("version"), tuple(sorted(f.get("identifiers") or [])),
            None if c else f["title"])


def _run_steps(ws: Path, cfg: dict, label: str) -> dict:
    res = {"workspace": label, "steps": []}
    phases = ("setup", "before_setup", "build") if label.startswith("before") else ("setup", "build")
    for name in phases:
        for cmd in cfg.get(name) or []:
            r = sh(cmd, ws, timeout=cfg.get("timeout", 2400))
            r["step"] = name
            res["steps"].append(r)
            if r["exit"] != 0:
                res["build_ok"] = False
                return res
    res["build_ok"] = True
    res["tests"] = []
    for cmd in cfg.get("test") or []:
        r = sh(cmd, ws, timeout=cfg.get("timeout", 2400))
        r["step"] = "test"
        r["summary"] = parse_tests(r["tail"])
        res["steps"].append(r)
        res["tests"].append({"cmd": cmd, "exit": r["exit"], **r["summary"]})
    return res


def _copy_reuse(before: Path, after: Path, reuse: List[str]) -> List[str]:
    """Reuse build outputs (e.g. frontend/dist) when the source tree they come from is unchanged."""
    done = []
    for spec in reuse or []:
        artifact, _, src = spec.partition(":")
        changed = subprocess.run(["git", "-C", str(after), "diff", "--name-only", "HEAD~1", "HEAD", "--", src or artifact],
                                 capture_output=True, text=True).stdout.strip()
        if changed:
            done.append(f"{artifact}: NOT reused ({src} changed)")
            continue
        if (before / artifact).exists():
            shutil.copytree(before / artifact, after / artifact, dirs_exist_ok=True)
            done.append(f"{artifact}: reused from baseline build ({src or artifact} unchanged)")
    return done


def _covering_tests(ws: Path, packages: List[str]) -> dict:
    """Which test files exercise code that imports the changed packages (one hop)."""
    from ..analyze.context import AppContext
    inv = Inventory.from_dict(json.loads((ws.parent.parent / "after-scan" / "inventory.json").read_text())) \
        if (ws.parent.parent / "after-scan" / "inventory.json").exists() else Inventory(project="x")
    ctx = AppContext(ws, inv)
    out = {}
    tests = [p for p in ws.rglob("*.test.ts") if "node_modules" not in p.parts] + \
            [p for p in ws.rglob("*.spec.ts") if "node_modules" not in p.parts]
    for pkg in packages:
        users = [u for sub in ctx.imports for u in ctx.imports[sub]["prod"].get(pkg, [])]
        hits = set()
        for t in tests:
            txt = t.read_text(errors="ignore")
            for u in users:
                stem = re.sub(r"\.[jt]sx?$", "", u.split("/")[-1])
                if re.search(r"['\"][./]*[\w/]*" + re.escape(stem) + r"['\"]", txt):
                    hits.add(str(t.relative_to(ws)))
        out[pkg] = {"imported_by": users[:10], "tests_exercising_importers": sorted(hits)[:10]}
    return out


def validate(run_dir: Path, project: Optional[Path] = None, cfg: Optional[dict] = None,
             vuln_source: str = "auto") -> dict:
    from ..analyze import analyze
    from ..analyze.ai import Analyst
    from ..detect import detect
    from ..discover import discover, prod_only, provenance, write_outputs, stats
    from ..detect.changes import diff_baseline
    from .. import report as rep
    run_dir = Path(run_dir)
    cfg = cfg or {}
    audit = Audit(run_dir)
    prov = json.loads((run_dir / "provenance.json").read_text())
    project = Path(project or prov["project_dir"])
    plan = json.loads((run_dir / "plan.json").read_text())

    approved = []
    for it in plan["items"]:
        if it["status"] != "approved":
            continue
        opt = next(o for o in it["options"] if o["option_id"] == it["approval"]["option_id"])
        if option_hash(opt) != it["approval"]["option_sha256"]:
            raise SystemExit(f"{it['item_id']}: option changed after approval - refusing to apply")
        if not opt["changes"]:
            continue
        approved.append((it, opt))
    if not approved:
        raise SystemExit("no approved items with applicable changes - approve something first")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    branch = f"guardian/fix-{run_id}"
    audit.log("validate", "guardian", "start", {"items": [i["item_id"] for i, _ in approved], "branch": branch,
                                                "plan_sha256": file_sha(run_dir / "plan.json")})

    work = run_dir / "work"
    before = make_workspace(project, work / "before")
    after = make_workspace(project, work / "after", branch)
    changes, msg_lines = [], []
    for it, opt in approved:
        changes += [dict(c) for c in opt["changes"]]
        msg_lines.append(f"- {it['item_id']} {opt['action']}: {opt['description']} "
                         f"(approved by {it['approval']['by']}: {it['approval']['reason']})")
    apply_log = apply_changes(after, changes, cfg.get("npm_flags", ""))
    lock_fail = [l for l in apply_log if l.get("exit", 0) != 0]
    sha = commit(after, "guardian: supply-chain remediation\n\n" + "\n".join(msg_lines) +
                 f"\n\nFindings: {', '.join(f for it, _ in approved for f in it['findings'])}"
                 "\nRollback: git revert this commit, or delete this branch (nothing was merged or pushed).")
    audit.log("validate", "guardian", "applied", {"branch": branch, "commit": sha, "files": diff_stat(after),
                                                  "lockfile_errors": len(lock_fail)})

    b_res = _run_steps(before, cfg, "before (baseline)")
    reused = _copy_reuse(before, after, cfg.get("reuse"))
    a_res = _run_steps(after, cfg, "after (fix branch)")
    audit.log("validate", "guardian", "build-test", {"before_build_ok": b_res.get("build_ok"), "after_build_ok": a_res.get("build_ok"),
                                                     "before_tests": b_res.get("tests"), "after_tests": a_res.get("tests"),
                                                     "reused": reused})

    # ---- rescan the fixed branch with the same settings
    scan_dir = run_dir / "after-scan"
    inv_a, ctx_a = discover(after)
    if cfg.get("prod_only"):
        inv_a = prod_only(inv_a)
    write_outputs(inv_a, scan_dir, provenance(after, inv_a, ["validate-rescan"]))
    det = detect(inv_a, ctx_a, vuln_source)
    st = stats(inv_a)
    doc_a = rep.build_doc(inv_a, st, det, ctx_a)
    rep.write_json(doc_a, scan_dir / "findings.json")
    ana_a = analyze(scan_dir, after, ai_limit=0, analyst=Analyst())

    doc_b = json.loads((run_dir / "findings.json").read_text())
    ana_b = json.loads((run_dir / "analysis.json").read_text())
    inv_b = Inventory.from_dict(json.loads((run_dir / "inventory.json").read_text()))
    kb = {_key(f): f for f in doc_b["findings"]}
    ka = {_key(f): f for f in doc_a["findings"]}
    score_b = {r["finding_id"]: r for r in ana_b["ranked"]}
    score_a = {r["finding_id"]: r for r in ana_a["ranked"]}
    new = [f for k, f in ka.items() if k not in kb and f["severity"] != "info"]
    sbom_diff = diff_baseline(inv_a, inv_b, "before")[1]

    # Regression = more failures, a newly failing test, or a worse exit code. Pass counts are NOT compared:
    # some runners (e.g. node --test with --test-force-exit) report a different total from run to run.
    tests_ok, test_notes = True, []
    for tb, ta in zip(b_res.get("tests", []), a_res.get("tests", [])):
        newly = sorted(set(ta.get("failed_tests", [])) - set(tb.get("failed_tests", [])))
        if ta.get("fail", 0) > tb.get("fail", 0) or newly or (tb["exit"] == 0 and ta["exit"] != 0):
            tests_ok = False
            test_notes.append(f"{ta['cmd']}: regression (fail {tb.get('fail')} -> {ta.get('fail')}; newly failing: {newly[:5]})")
        else:
            test_notes.append(f"{ta['cmd']}: no regression (fail {tb.get('fail', 0)} -> {ta.get('fail', 0)}"
                              + (f"; {tb.get('fail')} pre-existing failure(s) also fail on baseline" if tb.get("fail") else "") + ")")
        if ta.get("total") is not None and tb.get("total") is not None and ta["total"] != tb["total"]:
            test_notes.append(f"{ta['cmd']}: reported test total differs ({tb['total']} -> {ta['total']}); "
                              "this runner's totals vary between runs, so failures are compared instead")
    items = []
    for it, opt in approved:
        targets = [kb_f for kb_f in doc_b["findings"] if kb_f["id"] in it["findings"]]
        resolved = [f["id"] for f in targets if _key(f) not in ka]
        remaining = [f["id"] for f in targets if _key(f) in ka]
        pkgs = [c["name"] for c in opt["changes"] if c.get("name")]
        cover = _covering_tests(after, pkgs) if pkgs else {}
        covered = any(v["tests_exercising_importers"] for v in cover.values())
        ok = not remaining and a_res.get("build_ok") and tests_ok and not lock_fail
        conf = "high" if ok and covered else "medium" if ok else "low"
        items.append({"item_id": it["item_id"], "option": opt["option_id"], "action": opt["action"],
                      "description": opt["description"], "approved_by": it["approval"]["by"],
                      "approval_reason": it["approval"]["reason"], "findings_targeted": it["findings"],
                      "resolved": resolved, "still_present": remaining,
                      "score_before": sum(score_b[f]["score"] for f in it["findings"] if f in score_b),
                      "test_coverage": cover, "verdict": "VERIFIED" if ok else "NOT VERIFIED", "confidence": conf})

    def total(ana, prod=True):
        return sum(r["score"] for r in ana["ranked"] if (r["production"] or not prod))

    pb = {p: ana_b["summary"].get(p, 0) for p in ("P1-urgent", "P2-high", "P3-medium", "P4-low")}
    pa = {p: ana_a["summary"].get(p, 0) for p in ("P1-urgent", "P2-high", "P3-medium", "P4-low")}
    new_serious = [f for f in new if SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER["high"]]
    overall = "VERIFIED" if all(i["verdict"] == "VERIFIED" for i in items) and not new_serious else \
        "PARTIAL" if any(i["verdict"] == "VERIFIED" for i in items) else "FAILED"
    result = {
        "schema": "guardian.validation/v1", "run_id": run_id, "branch": branch, "commit": sha,
        "workspace": str(after), "overall": overall,
        "items": items,
        "apply_log": [{k: v for k, v in l.items() if k != "tail"} | ({"tail": l["tail"][-800:]} if l.get("exit") else {})
                      for l in apply_log],
        "manifest_diff": manifest_diff(after), "files_changed": diff_stat(after),
        "build_test": {"before": b_res, "after": a_res, "tests_no_regression": tests_ok, "test_notes": test_notes, "reused_artifacts": reused},
        "rescan": {"findings_before": len(doc_b["findings"]), "findings_after": len(doc_a["findings"]),
                   "priority_before": pb, "priority_after": pa,
                   "risk_score_production_before": total(ana_b), "risk_score_production_after": total(ana_a),
                   "newly_introduced": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                                         "path": f["dependency_paths"][0] if f.get("dependency_paths") else []} for f in new],
                   "newly_introduced_high_or_critical": len(new_serious)},
        "sbom_diff": sbom_diff,
        "rollback": f"Nothing was merged or pushed. Discard with `git branch -D {branch}` in {after}, "
                    f"or after a merge, `git revert {sha[:12]}`.",
        "human_next_step": "Review the branch diff and the evidence below, then open a PR / merge yourself.",
    }
    (run_dir / "validation.json").write_text(json.dumps(result, indent=2))
    audit.log("validate", "guardian", "verdict", {"overall": overall, "items": {i["item_id"]: i["verdict"] for i in items},
                                                  "new_findings": len(new), "new_high_or_critical": len(new_serious),
                                                  "risk_before": result["rescan"]["risk_score_production_before"],
                                                  "risk_after": result["rescan"]["risk_score_production_after"]})
    return result
