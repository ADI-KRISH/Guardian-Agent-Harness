"""Policy-as-code gate (JSON rules). Exit non-zero when a run violates the policy, so CI can block a build."""
from __future__ import annotations

import json
from pathlib import Path

from .audit import Audit
from .models import SEVERITY_ORDER


def gate(run_dir: Path, policy_path: Path, use_after: bool = False) -> dict:
    run_dir = Path(run_dir)
    pol = json.loads(Path(policy_path).read_text())
    base = run_dir / "after-scan" if use_after else run_dir
    findings = json.loads((base / "findings.json").read_text())["findings"]
    analysis = json.loads((base / "analysis.json").read_text()) if (base / "analysis.json").exists() else {"ranked": []}
    plan = json.loads((run_dir / "plan.json").read_text()) if (run_dir / "plan.json").exists() else {"items": []}
    accepted = {f for it in plan["items"] if it["status"] == "risk-accepted" for f in it["findings"]} \
        if pol.get("allow_accepted_risk", True) else set()
    viol = []
    for f in findings:
        if f["id"] in accepted:
            continue
        for b in pol.get("block", []):
            if b.get("category") and b["category"] != f["category"]:
                continue
            if b.get("rule") and b["rule"] != f["rule"]:
                continue
            if b.get("min_severity") and SEVERITY_ORDER[f["severity"]] < SEVERITY_ORDER[b["min_severity"]]:
                continue
            viol.append({"type": "blocked-component", "finding": f["id"], "title": f["title"], "why": b.get("why", "blocked by policy")})
            break
    for prio, mx in (pol.get("max_open_production") or {}).items():
        open_ = [r for r in analysis["ranked"] if r["priority"] == prio and r["production"] and r["finding_id"] not in accepted]
        if len(open_) > mx:
            viol.append({"type": "risk-budget", "priority": prio, "open": len(open_), "max": mx,
                         "examples": [r["title"] for r in open_[:3]]})
    pin = pol.get("require_actions_pinned")
    if pin:
        for f in findings:
            if f["rule"] == "CICD-UNPINNED-ACTION" and f["id"] not in accepted and (pin == "all" or f["severity"] != "low"):
                viol.append({"type": "unpinned-action", "finding": f["id"], "title": f["title"]})
    res = {"policy": str(policy_path), "passed": not viol, "violations": viol}
    Audit(run_dir).log("policy", "guardian", "gate", {"policy": str(policy_path), "passed": res["passed"],
                                                      "violations": len(viol), "scope": "after" if use_after else "before"})
    return res
