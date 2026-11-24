"""Analyze stage: findings + inventory + source code -> prioritised, explained risk list."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import Inventory
from ..audit import Audit
from .ai import Analyst, build_facts
from .context import AppContext
from .scoring import score_finding

ORDER = {"P1-urgent": 0, "P2-high": 1, "P3-medium": 2, "P4-low": 3}


def analyze(run_dir: Path, project_dir: Optional[Path] = None, ai_limit: int = 15, analyst: Optional[Analyst] = None) -> dict:
    run_dir = Path(run_dir)
    doc = json.loads((run_dir / "findings.json").read_text())
    inv = Inventory.from_dict(json.loads((run_dir / "inventory.json").read_text()))
    prov = json.loads((run_dir / "provenance.json").read_text()) if (run_dir / "provenance.json").exists() else {}
    project_dir = Path(project_dir or prov.get("project_dir") or ".")
    audit = Audit(run_dir)
    ctx = AppContext(project_dir, inv)
    analyst = analyst or Analyst(cache_dir=run_dir / ".ai-cache")

    rows = []
    for f in doc["findings"]:
        cid = (f.get("component") or {}).get("id")
        c = inv.components.get(cid) if cid else None
        if c is not None:
            reach, expo = ctx.reachability(c), ctx.exposure(c)
        else:
            reach = {"level": "n/a", "detail": "finding is about a file, not a package", "files": []}
            loc = next((e["source"] for e in f["evidence"] if e.get("source")), "")
            ctxname = "ci-pipeline" if ".github/" in loc else "runtime-image" if "Dockerfile" in loc else "server"
            expo = {"context": ctxname, "production": ctxname != "ci-pipeline", "detail": f"defined in {loc}"}
        s = score_finding(f, reach, expo)
        rows.append({"finding_id": f["id"], "title": f["title"], "category": f["category"], "rule": f["rule"],
                     "severity": f["severity"], "component": f.get("component"),
                     "score": s["score"], "priority": s["priority"], "factors": s["factors"],
                     "confidence": s["confidence"], "reachability": reach, "exposure": expo,
                     "production": expo["production"], "fix": f.get("fix"),
                     "dependency_paths": f.get("dependency_paths", [])[:3]})
    rows.sort(key=lambda r: (-r["score"], ORDER[r["priority"]], r["title"]))

    by_id = {f["id"]: f for f in doc["findings"]}
    explained = 0
    for r in rows:
        if explained >= ai_limit or r["priority"] not in ("P1-urgent", "P2-high"):
            r["ai"] = None
            continue
        facts = build_facts(by_id[r["finding_id"]], r, r["reachability"], r["exposure"])
        r["ai"] = analyst.explain(facts)
        explained += 1
        if r["ai"].get("recommended_priority") and r["ai"]["recommended_priority"] != r["priority"] \
                and r["ai"]["by"] != "deterministic-template":
            r["ai_priority_suggestion"] = r["ai"]["recommended_priority"]   # shown, never auto-applied
        audit.log("analyze", f"ai:{analyst.model}" if analyst.enabled else "guardian", "explain",
                  {"finding": r["finding_id"], "by": r["ai"]["by"], "rejected": r["ai"].get("ai_rejected"),
                   "error": r["ai"].get("ai_error")})

    summary = {p: sum(1 for r in rows if r["priority"] == p) for p in ORDER}
    out = {"schema": "guardian.analysis/v1", "project": doc["project"],
           "ai": {"provider": analyst.provider, "model": analyst.model, "enabled": analyst.enabled,
                  "prompt": "prompts/analyst_system.md", "prompt_sha": analyst.prompt_sha, **analyst.stats},
           "context": ctx.summary(), "summary": summary,
           "urgent": [r["finding_id"] for r in rows if r["priority"] == "P1-urgent"],
           "production_findings": sum(1 for r in rows if r["production"]),
           "ranked": rows}
    (run_dir / "analysis.json").write_text(json.dumps(out, indent=2))
    audit.log("analyze", "guardian", "prioritised", {"summary": summary, "ai": out["ai"]})
    return out
