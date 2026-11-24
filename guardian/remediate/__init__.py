"""Remediate stage: plan options, then record human decisions. Never applies anything itself."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..audit import Audit
from .planner import ACTION_HELP, Planner


def option_hash(opt: dict) -> str:
    return hashlib.sha256(json.dumps({k: opt[k] for k in ("option_id", "action", "changes")}, sort_keys=True).encode()).hexdigest()


def make_plan(run_dir: Path, project: Optional[Path] = None, max_items: int = 12, min_priority: str = "P2-high",
              online: bool = True) -> dict:
    run_dir = Path(run_dir)
    prov = json.loads((run_dir / "provenance.json").read_text())
    project = Path(project or prov["project_dir"])
    plan = Planner(run_dir, project, online).plan(max_items, min_priority)
    plan["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=2))
    Audit(run_dir).log("remediate", "guardian", "plan-created",
                       {"items": len(plan["items"]), "plan_sha256": hashlib.sha256((run_dir / "plan.json").read_bytes()).hexdigest()})
    return plan


def decide(run_dir: Path, item_id: str, decision: str, by: str, reason: str, option_id: Optional[str] = None,
           review_by: Optional[str] = None) -> dict:
    """decision: approve | reject | accept-risk. Requires a named human and a reason."""
    if not by or not reason:
        raise SystemExit("a named approver (--by) and a reason (--reason) are required")
    if by.lower().startswith(("guardian", "ai", "bot")):
        raise SystemExit("approvals must come from a human")
    run_dir = Path(run_dir)
    plan = json.loads((run_dir / "plan.json").read_text())
    item = next((i for i in plan["items"] if i["item_id"] == item_id), None)
    if item is None:
        raise SystemExit(f"no item {item_id}")
    opt = None
    if decision == "approve":
        opt = next((o for o in item["options"] if o["option_id"] == (option_id or "")), None) or \
            (next((o for o in item["options"] if o.get("recommended")), None) if not option_id else None)
        if opt is None:
            raise SystemExit(f"no option {option_id} in {item_id}")
        if opt["action"] == "accept":
            decision = "accept-risk"
    if decision == "accept-risk" and not review_by:
        review_by = "90 days"
    item["status"] = {"approve": "approved", "reject": "rejected", "accept-risk": "risk-accepted"}[decision]
    item["approval"] = {"decision": decision, "by": by, "reason": reason,
                        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "option_id": opt["option_id"] if opt else None,
                        "option_sha256": option_hash(opt) if opt else None, "review_by": review_by}
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=2))
    Audit(run_dir).log("approve", f"human:{by}", decision, {"item": item_id, **item["approval"]})
    return item


def render_plan_md(plan: dict) -> str:
    L = [f"# Remediation plan: {plan['project']}", "", plan["policy"], ""]
    for it in plan["items"]:
        L += [f"## {it['item_id']} · {it['priority']} · score {it['score']} · {it['title']}",
              f"Status: **{it['status']}**" + (f" (by {it['approval']['by']}: {it['approval']['reason']})" if it.get("approval") else ""),
              "", "Path: " + (" > ".join(it["dependency_paths"][0]) if it["dependency_paths"] else "—"),
              f"Reachability: {it['reachability']['level']} · Exposure: {it['exposure']['context']}", ""]
        for o in it["options"]:
            star = " ⭐ recommended" if o.get("recommended") else ""
            rr = o["risk_reduction"]
            L += [f"- **{o['option_id']} {o['action']}**{star}: {o['description']}",
                  f"  - risk reduction: {len(rr['findings_resolved'])} finding(s), score -{rr['score_removed']} ({rr['note']})",
                  f"  - compatibility: {o['compatibility']['level']} ({'; '.join(o['compatibility']['reasons'])})",
                  f"  - rollback: {o['rollback']}"]
        L += ["", f"Approve: `python3 -m guardian approve <run> --item {it['item_id']} --option <id> --by \"Name\" --reason \"...\"`", ""]
    return "\n".join(L)
