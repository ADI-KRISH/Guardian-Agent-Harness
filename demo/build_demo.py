"""Build the self-contained HTML demo from REAL scan and remediation data.

  .venv\\Scripts\\python demo\\build_demo.py [--project juice-shop] [--run RUNID] [--remediation path\\remediation.json] [--open]

Output: workspace/demo/index.html (one file, no network needed to view it). Re-run after every scan or validation.
Nothing is invented: a stage with no data yet shows the command that produces it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import webbrowser
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from guardian import config, remediate  # noqa: E402
from guardian.memory import Memory  # noqa: E402

LEVELS = ("Critical", "High", "Medium", "Low")


def _latest(project: str | None) -> Path:
    runs = sorted(config.WORKSPACE.glob(f"reports/{project or '*'}/*/report.json"), key=lambda p: p.parent.name, reverse=True)
    if not runs:
        sys.exit("No report found. Run a scan first: .venv\\Scripts\\guardian scan <repo> --base <tag>")
    return runs[0].parent


def _finding(f: dict) -> dict:
    ai = next((a for a in f.get("ai_inference", []) if a.get("kind") == "agentic-investigation"), None) or (f.get("ai_inference") or [None])[0]
    return {**{k: f.get(k) for k in ("id", "title", "type", "category", "risk_level", "score", "confidence", "confidence_reason", "score_explanation",
                                      "detector", "change", "fixed_versions", "recommendation", "location", "component")},
            "evidence": (f.get("verified_evidence") or [])[:4], "paths": (f.get("dependency_paths") or [])[:2],
            "ai": ai and {"model": ai.get("model"), "text": (ai.get("text") or "")[:700], "verdict": ai.get("verdict"), "tools": ai.get("tool_calls", [])[:6]}}


def build(rdir: Path, remediation: Path | None) -> dict:
    r = json.loads((rdir / "report.json").read_text(encoding="utf-8"))
    inv = json.loads((rdir / "inventory.json").read_text(encoding="utf-8"))
    dec = json.loads((rdir / "decisions.json").read_text(encoding="utf-8"))
    act = [f for f in r["findings"] if not f.get("suppressed_by")]
    ranked = sorted(act, key=lambda f: -f["score"])
    top = ranked[:14]
    for cat in ("CI-container", "dependency change", "backdoor signal", "source change"):   # show every kind of evidence the harness produces
        for extra in [f for f in ranked if f["category"] == cat and f not in top][:3]:
            top.append(extra)
    fixable = [{"id": f["id"], "title": f["title"][:120], "risk_level": f["risk_level"], "score": f["score"]}
               for f in ranked if f["type"] == "known_vulnerability"][:20]
    files = [n for n in ("report.html", "report.md", "report.json", "sbom.cdx.json", "inventory.json", "decisions.json") if (rdir / n).exists()]
    files += [str(p.relative_to(rdir)).replace("\\", "/") for p in sorted(rdir.glob("remediation-*/*"))
              if p.suffix in (".html", ".md", ".json", ".diff") and p.name != "sbom.after.cdx.json"]
    pk = inv["packages"]
    hosts = Counter(p.get("origin_host") or "(not from a registry)" for p in pk.values())
    c = r["change"]
    models = Counter()
    for f in r["findings"]:
        for a in f.get("ai_inference", []):
            m = re.search(r"\(served by ([^)]+)\)", a.get("text", ""))
            models[(m.group(1) if m else a.get("model", "?")).replace("[fallback endpoint]", "").strip()] += 1
    actors = Counter(d["actor"] for d in dec)
    story_actors = ("orchestrator", "lead-agent", "investigator-agent", "verifier-agent")
    res = None
    if remediation is None:
        found = sorted(rdir.glob("remediation-*/remediation.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        remediation = found[0] if found else None
    if remediation and remediation.exists():
        res = json.loads(remediation.read_text(encoding="utf-8"))
        patch = (remediation.parent / "patch.diff")
        res["patch"] = patch.read_text(encoding="utf-8", errors="replace").splitlines()[:90] if patch.exists() else []
        for k in ("resolved", "remaining", "introduced"):
            res[k] = res.get(k, [])[:15]
        d = res.get("sbom_diff", {})
        res["sbom_diff"] = {k: v[:25] for k, v in d.items()} | {"counts": {k: len(v) for k, v in d.items()}}
        res["decisions"] = [{k: x[k] for k in ("seq", "actor", "decision", "why")} for x in res.get("decisions", [])][:60]
        res.pop("sandbox", None)
    props = []
    try:
        props = [{k: p.get(k) for k in ("id", "package", "from", "to", "change", "kind", "direct", "resolves", "expected_risk_reduction", "major_bump",
                                          "compatibility_note", "rollback", "status", "decided_by", "decided_reason", "finding_id")}
                 for p in Memory().list_proposals(r["project"], r["run_id"])]
    except Exception:  # noqa: BLE001 - the demo must build even without a database
        pass
    return {
        "meta": {"project": r["project"], "source": r["source"], "run_id": r["run_id"], "base": r.get("base_ref"), "head": r["head_ref"],
                 "head_commit": r["head_commit"], "base_commit": r.get("base_commit"), "seconds": r["summary"]["seconds"], "models": dict(models)},
        "summary": r["summary"], "levels": {k: r["summary"]["by_level"][k] for k in LEVELS},
        "inventory": {"hosts": hosts.most_common(6), "images": inv["images"][:8], "workflow_steps": len(inv["workflows"]),
                      "unpinned": sum(1 for w in inv["workflows"] if not w["pinned"] and not w["local"]), "notes": r.get("notes", []),
                      "sample": [{"name": p["name"], "version": p["version"], "scope": p["scope"], "host": p.get("origin_host", ""), "hash": bool(p.get("integrity"))}
                                 for p in list(pk.values())[:14]]},
        "change": {"added_count": c["added_count"], "removed_count": c["removed_count"], "updated_count": c["updated_count"],
                   "updated": c["updated"][:30], "added": c["added"][:30], "workflows": c["workflow_changes"][:12], "images": c["image_changes"][:8],
                   "files_changed": r["backdoor_stats"].get("files_changed", 0), "build_files": r["backdoor_stats"].get("build_files_changed", [])[:10]},
        "categories": dict(Counter(f["category"] for f in act)),
        "top": [_finding(f) for f in top],
        "agents": {"summary": r.get("agent_summary", ""), "counts": dict(actors), "canary": r["canary"], "skipped": r.get("skipped", []),
                   "story": [{"actor": d["actor"], "decision": d["decision"][:130], "why": str(d["why"])[:160]} for d in dec if d["actor"] in story_actors][:46]},
        "proposals": props, "remediation": res, "responsible_ai": remediate.RESPONSIBLE_AI, "fixable": fixable, "files": files,
        "shown": {"top": len(top), "total": len(act)},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project"); ap.add_argument("--run"); ap.add_argument("--remediation"); ap.add_argument("--open", action="store_true")
    a = ap.parse_args()
    rdir = config.WORKSPACE / "reports" / a.project / a.run if a.project and a.run else _latest(a.project)
    data = build(rdir, Path(a.remediation) if a.remediation else None)
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    out = config.WORKSPACE / "demo" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text((Path(__file__).parent / "template.html").read_text(encoding="utf-8").replace("__DATA__", blob).replace("__TOKEN__", ""), encoding="utf-8")
    print(f"Demo built from {rdir.name} ({'with' if data['remediation'] else 'without'} a sandbox result): {out}")
    if a.open:
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    main()
