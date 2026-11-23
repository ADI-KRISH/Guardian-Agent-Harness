"""Day 2 flow: propose a fix -> a named human approves -> validate in the sandbox -> verified-remediation report."""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import config
from .agents import fixer, validator

RESPONSIBLE_AI = """\
- **Human in the loop.** Nothing is built, tested or applied until a named person approves this exact change with a reason. The Guardian never merges, pushes, publishes or deploys: it produces a patch and a report for a human to act on.
- **Evidence is not AI.** Findings come from scanners (OSV, lockfiles, git diff) and are re-checked by a verifier. The fixed version is chosen by a deterministic rule from advisory data. AI text, where present, is labelled inference and never changes a score, a confidence or this verdict.
- **Sandboxed.** The change is made on a local throw-away branch. The dependency tree is built in a Docker container with install scripts disabled; code from the package runs only in a container with no network, no capabilities, no secrets and CPU/memory limits. The operator, not the scanned repository, chooses the image and test command.
- **Honest about gaps.** A step that was not run is reported as skipped and lowers the verdict to "verified with gaps". A major-version bump needs the project's own tests to prove behaviour is unchanged.
- **Auditable.** Every agent step and the human approval are in an append-only decision log (included below).
- **Limits.** The rescan covers known vulnerabilities and dependency changes introduced by the fix. It does not re-audit application source, CI workflows or container images, and it cannot find vulnerabilities that are not yet published."""

VERDICT_TEXT = {"verified": "VERIFIED", "verified-with-gaps": "VERIFIED WITH GAPS", "not-verified": "NOT VERIFIED"}


def run_dir(project: str, run_id: str | None = None) -> Path:
    base = config.WORKSPACE / "reports" / project
    if run_id:
        return base / run_id
    runs = sorted((p for p in base.glob("*/report.json")), key=lambda p: p.parent.name, reverse=True)
    if not runs:
        raise FileNotFoundError(f"No report for project '{project}'. Run a scan first.")
    return runs[0].parent


def load_run(project: str, run_id: str | None = None) -> tuple[Path, dict, dict]:
    d = run_dir(project, run_id)
    return d, json.loads((d / "report.json").read_text(encoding="utf-8")), json.loads((d / "inventory.json").read_text(encoding="utf-8"))


def propose(mem, project: str, finding_id: str, run_id: str | None = None, log=print) -> dict:
    _, report, inv = load_run(project, run_id)
    p = fixer.propose(report, inv, finding_id)
    if not p["ok"]:
        mem.decide(f"fix-{finding_id}", project, "fix-agent", f"no automatic fix for {finding_id}", p["reason"], rule="fix-proposal")
        log(f"  [fix-agent] no automatic fix: {p['reason']}")
        return p
    mem.save_proposal(p)
    mem.decide(f"fix-{p['id']}", project, "fix-agent", f"propose {p['change']}", p["expected_risk_reduction"]["explanation"],
               {"finding": finding_id, "resolves": p["resolves"]}, rule="fix-proposal")
    log(f"  [fix-agent] {p['id']}: {p['change']}")
    return p


def validate(mem, proposal_id: str, test_cmd: str = "", log=print) -> dict:
    p = mem.get_proposal(proposal_id)
    if p["status"] != "approved" or not p.get("decided_by"):   # guardrail: no sandbox work without a named human approval
        raise PermissionError(f"Fix {proposal_id} is '{p['status']}': it must be approved by a named human before anything is built or tested.")
    d, report, inv = load_run(p["project"], p["run_id"])
    src = report.get("source", "")
    repo = Path(src).resolve() if src and Path(src).exists() else config.WORKSPACE / "repos" / p["project"]
    out = d / f"remediation-{proposal_id}"
    res = validator.validate(p, repo, report, inv, mem, out, test_cmd, log)
    res["report_dir"] = str(out)
    res["approval"] = {"by": p["decided_by"], "reason": p["decided_reason"]}
    res["decisions"] = mem.decisions(f"fix-{proposal_id}")
    mem.save_result(proposal_id, res)
    write_report(res, out)
    return res


def _levels(d: dict) -> str:
    return ", ".join(f"{v} {k}" for k, v in d.items() if v) or "none"


def markdown(r: dict) -> str:
    p, b, a = r["proposal"], r.get("before", {}), r.get("after", {})
    L = [f"# Verified remediation {p['id']}: {p['package']} {p['from']} -> {p['to']}", "",
         f"**Verdict: {VERDICT_TEXT[r['verdict']]}** - {r['verdict_reason']}", "",
         f"Project `{p['project']}` · scan run `{p['run_id']}` · finding `{p['finding_id']}` · validated in {r['seconds']} s", "",
         "## 1. Prioritised finding and proposed fix", f"- Change: `{p['change']}` ({p['kind']}, {'direct' if p['direct'] else 'transitive'} dependency)",
         f"- Resolves: {', '.join(p['resolves'])} (advisories {', '.join(p['advisories'])})",
         f"- Expected risk reduction: {p['expected_risk_reduction']['explanation']} ({_levels(p['expected_risk_reduction']['levels'])}, score {p['expected_risk_reduction']['score_removed']})",
         f"- Compatibility: {p['compatibility_note']}", f"- Rollback: {p['rollback']}", "",
         "## 2. Human approval", f"Approved by **{r['approval']['by']}**: {r['approval']['reason']}", "",
         "## 3. Sandbox validation", "| Step | Result | Detail |", "|---|---|---|"]
    L += [f"| {s['name']} | {s['status']} | {s['detail'][:200].replace('|', '/').replace(chr(10), ' ')} |" for s in r["steps"]]
    if b:
        L += ["", "## 4. Before and after", f"- Packages: {b['packages']} -> {a['packages']}",
              f"- Known vulnerabilities: {b['count']} ({_levels(b['known_vulnerabilities'])}) -> {a['count']} ({_levels(a['known_vulnerabilities'])})",
              f"- Resolved: {len(r['resolved'])} · still present: {len(r['remaining'])} · newly introduced: {len(r['introduced'])}", ""]
        L += [f"  - resolved: {x['risk_level']} {x['id']} {x['title']}" for x in r["resolved"][:15]]
        L += [f"  - still present: {x['risk_level']} {x['id']} {x['title']}" for x in r["remaining"][:10]]
        L += [f"  - NEW: {x['risk_level']} {x['id']} {x['title']}" for x in r["introduced"][:15]]
        d = r["sbom_diff"]
        L += ["", f"### SBOM diff (before -> after): {len(d['added'])} added, {len(d['removed'])} removed, {len(d['updated'])} updated"]
        L += [f"  - updated: {x}" for x in d["updated"][:15]] + [f"  - added: {x}" for x in d["added"][:15]] + [f"  - removed: {x}" for x in d["removed"][:15]]
    L += ["", "## 5. How to apply", f"Local sandbox branch `{r['branch']}` (never pushed). Review `patch.diff`, then `git apply patch.diff` in your own checkout. Nothing was merged or deployed.", "",
          "## 6. Responsible AI note", RESPONSIBLE_AI, "", "## 7. Audit trail (append-only)", "| # | Actor | Decision | Why |", "|---|---|---|---|"]
    L += [f"| {x['seq']} | {x['actor']} | {x['decision'][:90]} | {str(x['why'])[:120].replace('|', '/')} |" for x in r["decisions"]]
    return "\n".join(L) + "\n"


def html_report(r: dict) -> str:
    md = markdown(r)
    color = {"verified": "#16a34a", "verified-with-gaps": "#ca8a04", "not-verified": "#dc2626"}[r["verdict"]]
    return (f"<!doctype html><meta charset='utf-8'><title>Verified remediation {html.escape(r['proposal']['id'])}</title>"
            f"<body style='font-family:system-ui;max-width:1000px;margin:24px auto;padding:0 16px'>"
            f"<div style='border-left:8px solid {color};padding:8px 14px;background:{color}18;font-size:1.2rem'><b>{VERDICT_TEXT[r['verdict']]}</b> - {html.escape(r['verdict_reason'])}</div>"
            f"<pre style='white-space:pre-wrap;font:14px/1.5 system-ui'>{html.escape(md)}</pre></body>")


def write_report(r: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "remediation.json").write_text(json.dumps(r, indent=1, default=str), encoding="utf-8")
    (out / "remediation.md").write_text(markdown(r), encoding="utf-8")
    (out / "remediation.html").write_text(html_report(r), encoding="utf-8")
