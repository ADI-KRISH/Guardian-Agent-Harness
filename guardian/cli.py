"""guardian CLI.

  guardian scan <repo-url-or-path> [--base REF] [--head REF] [--no-llm] [--fail-on High]
  guardian approve-baseline <repo-url-or-path> <ref> --by NAME --reason TEXT
  guardian label <project> <finding-id> <confirmed|false_positive|accepted|open> --by NAME --reason TEXT
  guardian add-lesson <project> --rule TYPE_OR_RULE --scope GLOB --by NAME --reason TEXT [--days 30]
  guardian tags <repo-url-or-path>
Exit codes: 0 ok, 1 findings at or above --fail-on, 2 usage error.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import config
from .agents import discovery
from .memory import Memory
from .tools import git


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):   # LLM text has non-cp1252 characters; a log line must never kill a scan on Windows
        getattr(stream, "reconfigure", lambda **k: None)(errors="replace")
    ap = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("repo"); s.add_argument("--base"); s.add_argument("--head")
    s.add_argument("--no-llm", action="store_true"); s.add_argument("--fail-on", choices=["Critical", "High", "Medium", "Low"])
    b = sub.add_parser("approve-baseline"); b.add_argument("repo"); b.add_argument("ref"); b.add_argument("--by", required=True); b.add_argument("--reason", required=True)
    l = sub.add_parser("label"); l.add_argument("project"); l.add_argument("finding"); l.add_argument("status")
    l.add_argument("--by", required=True); l.add_argument("--reason", required=True)
    le = sub.add_parser("add-lesson"); le.add_argument("project"); le.add_argument("--rule", required=True); le.add_argument("--scope", required=True)
    le.add_argument("--by", required=True); le.add_argument("--reason", required=True); le.add_argument("--days", type=int, default=30)
    t = sub.add_parser("tags"); t.add_argument("repo")
    pr = sub.add_parser("propose", help="Day 2: propose a fix for one finding of the latest scan")
    pr.add_argument("project"); pr.add_argument("finding"); pr.add_argument("--run")
    for nm in ("approve", "reject"):
        x = sub.add_parser(nm, help=f"Day 2: a named human {nm}s a fix proposal"); x.add_argument("proposal")
        x.add_argument("--by", required=True); x.add_argument("--reason", required=True)
    va = sub.add_parser("validate", help="Day 2: build and test an APPROVED fix in the Docker sandbox, rescan, write the report")
    va.add_argument("proposal"); va.add_argument("--test", default=os.getenv("GUARDIAN_VALIDATE_TEST", ""), help="project test command to run in the sandbox")
    sv = sub.add_parser("serve", help="live presenter page: paste a repo link and watch the harness work")
    sv.add_argument("--port", type=int, default=8765); sv.add_argument("--no-open", action="store_true")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "scan":
            from .orchestrator import Run
            from .report import write
            r = Run(a.repo, a.base, a.head, use_llm=not a.no_llm).execute()
            out = write(r)
            s = r["summary"]
            print(f"\nDone in {s['seconds']} s: {s['findings']} findings {s['by_level']}")
            print(f"Report: {out / 'report.html'}")
            if a.fail_on:
                order = ["Low", "Medium", "High", "Critical"]
                if any(order.index(f["risk_level"]) >= order.index(a.fail_on) for f in r["findings"] if not f.get("suppressed_by")):
                    return 1
        elif a.cmd == "approve-baseline":
            proj = git.project_name(a.repo)
            repo = git.clone(a.repo, config.WORKSPACE / "repos" / proj)
            d = git.checkout(repo, a.ref, config.WORKSPACE / "checkouts" / proj / a.ref.replace("/", "_"))
            snap = discovery.snapshot(d, run_syft=False)
            Memory().approve_baseline(proj, a.ref, snap, a.by, a.reason)
            print(f"Baseline {a.ref} for {proj} approved by {a.by} ({len(snap['packages'])} packages).")
        elif a.cmd == "label":
            Memory().label(a.project, a.finding, a.status, a.by, a.reason)
            print("Label saved and logged.")
        elif a.cmd == "add-lesson":
            Memory().add_lesson(a.project, "suppress", a.rule, a.scope, a.reason, a.by, a.days)
            print("Lesson saved (expires in %d days)." % a.days)
        elif a.cmd == "propose":
            from . import remediate
            p = remediate.propose(Memory(), a.project, a.finding, a.run)
            if not p["ok"]:
                print(f"No automatic fix: {p['reason']}")
                return 1
            print(f"\nProposal {p['id']}: {p['change']}\n  resolves {len(p['resolves'])} finding(s): {p['expected_risk_reduction']['levels']}\n"
                  f"  compatibility: {p['compatibility_note']}\n  rollback: {p['rollback']}\n"
                  f"Next: guardian approve {p['id']} --by NAME --reason TEXT   then   guardian validate {p['id']}")
        elif a.cmd in ("approve", "reject"):
            Memory().decide_proposal(a.proposal, "approved" if a.cmd == "approve" else "rejected", a.by, a.reason)
            print(f"Fix {a.proposal} {a.cmd}d by {a.by} (logged).")
        elif a.cmd == "validate":
            from . import remediate
            res = remediate.validate(Memory(), a.proposal, a.test)
            print(f"\nVerdict: {res['verdict']} - {res['verdict_reason']}\nReport: {Path(res['report_dir']) / 'remediation.html'}")
            return 0 if res["verdict"] != "not-verified" else 1
        elif a.cmd == "serve":
            from .serve import serve
            serve(a.port, not a.no_open)
        elif a.cmd == "tags":
            proj = git.project_name(a.repo)
            repo = git.clone(a.repo, config.WORKSPACE / "repos" / proj)
            print("\n".join(git.latest_tags(repo, 20)))
    except (ValueError, KeyError, RuntimeError, PermissionError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
