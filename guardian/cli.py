"""Supply Chain Guardian CLI: Discover -> Detect -> Analyze -> Remediate (human approval) -> Validate -> Report.

  guardian run <project> -o RUN            discover+detect+analyze+investigate+plan, then STOP for approval
  guardian approve RUN --item R1 --option R1.a --by "Name" --reason "..."   (or --reject / --accept-risk)
  guardian validate RUN --setup ... --build ... --test ...   apply approved fixes on a branch, build, test, rescan
  guardian report RUN                       final Guardian report (HTML + JSON)
  guardian gate RUN --policy policies/default.json [--after]   policy-as-code gate (exit 1 on violation)
  guardian audit RUN                        verify the hash-chained audit trail
Individual stages: scan, discover, analyze, investigate, plan.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import discover as disc
from . import detect as det
from . import report
from . import graph as gviews
from .models import SEVERITY_ORDER


def _scan(a, argv) -> int:
    inv, ctx = disc.discover(a.project, a.sbom, a.image, a.maven_tree)
    if a.prod_only:
        inv = disc.prod_only(inv)
    prov = disc.provenance(Path(ctx["project_dir"]), inv, argv)
    disc.write_outputs(inv, a.out, prov)
    st = disc.stats(inv)
    if prov.get("git"):
        g = prov["git"]
        print(f"[discover] git {g['remote']} @ {g['branch']} {g['commit']}{' (DIRTY working tree)' if g['dirty'] else ''}")
    print(f"[discover] {inv.project}: {st['components']} components ({st['direct']} direct, {st['transitive']} transitive), "
          f"depth {st['max_depth']}, ecosystems {st['by_ecosystem']}")
    for n in inv.notes:
        print(f"  note: {n}")
    if a.cmd == "discover":
        print(f"[discover] wrote {a.out}/sbom.cdx.json, inventory.json, dependency-graph.json/.dot, provenance.json")
        return 0
    from .audit import Audit
    result = det.detect(inv, ctx, a.vuln_source, a.vuln_db, a.baseline, a.verify_registry, det.load_policy(a.policy))
    doc = report.build_doc(inv, st, result, ctx)
    report.write_json(doc, a.out / "findings.json")
    report.write_sarif(doc, a.out / "findings.sarif")
    dot = gviews.risk_subgraph_dot(inv, result["findings"], a.graph_min)
    (a.out / "risk-graph.dot").write_text(dot)
    svg = gviews.render_svg(dot, a.out / "risk-graph.svg")
    tree = gviews.tree_data(inv, result["findings"])
    svg_text = svg.read_text() if svg else None
    report.write_html(doc, a.out / "report.html", tree, svg_text)
    from . import graph_html
    graph_html.write(a.out / "dependency-graph.html", st, tree, svg_text, prov, inv.project, doc["summary"])
    s = doc["summary"]
    Audit(a.out).log("discover+detect", "guardian", "scanned", {"git": prov.get("git"), "inputs": prov.get("inputs"),
                                                               "components": st["components"], "findings": s})
    print(f"[detect] vulnerability source: {doc['vulnerability_source']}")
    for k, v in doc["checks"].items():
        print(f"  {k:22s} {v['status']:5s} {v.get('findings', v.get('error', ''))}")
    print(f"[detect] {s['total']} findings  " + "  ".join(f"{k}:{v}" for k, v in s["by_severity"].items()))
    if a.fail_on and any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[a.fail_on] for f in result["findings"]):
        return 1
    return 0


def _ai_check() -> int:
    from .analyze import ai
    c = ai.resolve()
    print(f"AI backend: {c['provider']}" + (f"  model: {c['model']}" if c["model"] else "")
          + (f"  endpoint: {c['base']}" if c.get("base") else ""))
    if c["provider"] == "none":
        print("No model configured -> deterministic explanations. Enable one of:\n"
              "  export GEMINI_API_KEY=...      (free key: Google AI Studio)\n"
              "  export GROQ_API_KEY=...        (free key: console.groq.com)\n"
              "  export ANTHROPIC_API_KEY=...   (Claude)\n"
              "  ollama pull llama3.1 && ollama serve   (local, free, nothing leaves the machine)")
        return 1
    facts = {"finding": {"title": "Known vulnerability in demo-lib@1.0.0: prototype pollution", "category": "vulnerability",
                         "rule": "VULN-KNOWN", "detector_severity": "high", "identifiers": ["GHSA-test-test-test"],
                         "component": {"name": "demo-lib", "version": "1.0.0"}, "fix": {"fixed_versions": ["1.0.1"]}},
             "evidence": [{"id": "E1", "kind": "advisory", "source": "test", "detail": "GHSA-test-test-test: prototype pollution in demo-lib <1.0.1"},
                          {"id": "E2", "kind": "reachability", "source": "test", "detail": "imported: imported by server.js"},
                          {"id": "E3", "kind": "exposure", "source": "test", "detail": "server: network-facing"}],
             "computed_score": 80, "computed_priority": "P1-urgent", "score_factors": []}
    import time
    t0 = time.time()
    try:
        raw = ai.get_caller()(ai.PROMPT.read_text(), "Finding facts (JSON):\n" + json.dumps(facts), c["model"])
    except Exception as e:
        print(f"FAILED to reach the model: {e.__class__.__name__}: {e}")
        return 1
    ans, why = ai.validate_answer(raw, facts)
    print(f"answer in {time.time() - t0:.1f}s; guardrails: {'PASSED' if ans else 'REJECTED (' + why + ')'}")
    print((ans or {}).get("summary") or raw[:400])
    return 0 if ans else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="guardian", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "discover", "run"):
        p = sub.add_parser(name)
        p.add_argument("project", type=Path)
        p.add_argument("-o", "--out", type=Path, default=Path("guardian-out"))
        p.add_argument("--sbom", type=Path, action="append", default=[])
        p.add_argument("--image", action="append", default=[])
        p.add_argument("--prod-only", action="store_true")
        p.add_argument("--maven-tree", type=Path)
        if name != "discover":
            p.add_argument("--baseline", type=Path)
            p.add_argument("--vuln-source", choices=["auto", "osv", "npm", "offline"], default="auto")
            p.add_argument("--vuln-db", type=Path)
            p.add_argument("--verify-registry", action="store_true")
            p.add_argument("--policy", type=Path, help="detector policy (trusted images / action owners)")
            p.add_argument("--graph-min", choices=list(SEVERITY_ORDER), default="high")
            p.add_argument("--fail-on", choices=list(SEVERITY_ORDER))
        if name == "run":
            p.add_argument("--ai-limit", type=int, default=15)
            p.add_argument("--max-items", type=int, default=20)
            p.add_argument("--investigate", help="finding id to investigate (default: auto-pick a non-CVE risk)")
    p = sub.add_parser("analyze"); p.add_argument("run", type=Path); p.add_argument("--project", type=Path); p.add_argument("--ai-limit", type=int, default=15)
    p = sub.add_parser("investigate"); p.add_argument("run", type=Path); p.add_argument("--finding"); p.add_argument("--baseline", type=Path); p.add_argument("--project", type=Path)
    p = sub.add_parser("plan"); p.add_argument("run", type=Path); p.add_argument("--project", type=Path)
    p.add_argument("--max-items", type=int, default=20); p.add_argument("--min-priority", default="P2-high")
    p = sub.add_parser("approve")
    p.add_argument("run", type=Path); p.add_argument("--item", required=True); p.add_argument("--option")
    p.add_argument("--by", required=True); p.add_argument("--reason", required=True); p.add_argument("--review-by")
    g = p.add_mutually_exclusive_group(); g.add_argument("--reject", action="store_true"); g.add_argument("--accept-risk", action="store_true")
    p = sub.add_parser("validate")
    p.add_argument("run", type=Path); p.add_argument("--project", type=Path)
    p.add_argument("--setup", action="append", default=[], help="command run before build (repeatable)")
    p.add_argument("--before-setup", action="append", default=[], help="baseline-only step, e.g. build an artifact to --reuse")
    p.add_argument("--build", action="append", default=[]); p.add_argument("--test", action="append", default=[])
    p.add_argument("--npm-flags", default="", help="extra flags for lockfile regeneration, e.g. --legacy-peer-deps")
    p.add_argument("--reuse", action="append", default=[], help="ARTIFACT:SOURCE reuse a build output if SOURCE is unchanged")
    p.add_argument("--prod-only", action="store_true"); p.add_argument("--vuln-source", default="auto")
    p.add_argument("--timeout", type=int, default=2400)
    p = sub.add_parser("report"); p.add_argument("run", type=Path)
    p = sub.add_parser("gate"); p.add_argument("run", type=Path); p.add_argument("--policy", type=Path, required=True); p.add_argument("--after", action="store_true")
    p = sub.add_parser("audit"); p.add_argument("run", type=Path)
    sub.add_parser("ai-check", help="show which AI backend is active and test it with the guardrails")
    a = ap.parse_args(argv)

    if a.cmd in ("scan", "discover"):
        return _scan(a, argv)
    if a.cmd == "run":
        a.cmd = "scan"
        rc = _scan(a, argv)
        from .analyze import analyze
        from .analyze.investigate import investigate
        from .remediate import make_plan, render_plan_md
        from . import final_report
        an = analyze(a.out, a.project, a.ai_limit)
        aiinfo = an["ai"]
        print(f"[analyze] {an['summary']}")
        print(f"[ai] {aiinfo['provider']}:{aiinfo['model']} " + (f"explained {aiinfo['accepted']} findings, rejected {aiinfo['rejected']}, errors {aiinfo['errors']}"
              if aiinfo["enabled"] else "not configured -> deterministic explanations (run `guardian ai-check`)"))
        for r in an["ranked"][:8]:
            print(f"  {r['score']:3d} {r['priority']:10s} {r['reachability']['level']:16s} {r['exposure']['context']:12s} {r['title'][:70]}")
        try:
            iv = investigate(a.out, a.investigate, a.project, a.baseline)
            print(f"[investigate] {iv['finding']['title'][:70]} -> {iv['inference']['verdict']} "
                  f"({len(iv['verified_evidence'])} verified facts)")
        except SystemExit as e:
            print(f"[investigate] skipped: {e}")
        plan = make_plan(a.out, a.project, a.max_items)
        (a.out / "plan.md").write_text(render_plan_md(plan))
        final_report.build(a.out)
        print(f"[plan] {len(plan['items'])} remediation items -> {a.out}/plan.md")
        print(f"[stop] waiting for human approval: python3 -m guardian approve {a.out} --item R1 --option R1.a --by \"Name\" --reason \"...\"")
        return rc
    if a.cmd == "analyze":
        from .analyze import analyze
        an = analyze(a.run, a.project, a.ai_limit)
        print(json.dumps(an["summary"]))
        return 0
    if a.cmd == "investigate":
        from .analyze.investigate import investigate
        iv = investigate(a.run, a.finding, a.project, a.baseline)
        print((a.run / f"investigation-{iv['finding']['id']}.md").read_text())
        return 0
    if a.cmd == "plan":
        from .remediate import make_plan, render_plan_md
        plan = make_plan(a.run, a.project, a.max_items, a.min_priority)
        (a.run / "plan.md").write_text(render_plan_md(plan))
        print((a.run / "plan.md").read_text())
        return 0
    if a.cmd == "approve":
        from .remediate import decide, render_plan_md
        d = "reject" if a.reject else "accept-risk" if a.accept_risk else "approve"
        it = decide(a.run, a.item, d, a.by, a.reason, a.option, a.review_by)
        (a.run / "plan.md").write_text(render_plan_md(json.loads((a.run / "plan.json").read_text())))
        print(f"{it['item_id']}: {it['status']} by {a.by} ({it['approval'].get('option_id') or '-'})")
        return 0
    if a.cmd == "validate":
        from .validate import validate
        from . import final_report
        cfg = {"setup": a.setup, "before_setup": a.before_setup, "build": a.build, "test": a.test, "npm_flags": a.npm_flags, "reuse": a.reuse,
               "prod_only": a.prod_only, "timeout": a.timeout}
        v = validate(a.run, a.project, cfg, a.vuln_source)
        final_report.build(a.run)
        rs = v["rescan"]
        print(f"[validate] {v['overall']}  branch {v['branch']} ({v['commit'][:10]})")
        for i in v["items"]:
            print(f"  {i['item_id']} {i['action']}: {len(i['resolved'])}/{len(i['findings_targeted'])} resolved -> {i['verdict']} (confidence {i['confidence']})")
        bt = v["build_test"]
        print(f"  build after: {'ok' if bt['after'].get('build_ok') else 'FAILED'}; tests before {bt['before'].get('tests')} after {bt['after'].get('tests')}")
        print(f"  production risk {rs['risk_score_production_before']} -> {rs['risk_score_production_after']}; "
              f"P1 {rs['priority_before']['P1-urgent']} -> {rs['priority_after']['P1-urgent']}; new findings {len(rs['newly_introduced'])} "
              f"({rs['newly_introduced_high_or_critical']} high/critical)")
        print(f"  report: {a.run}/guardian-report.html")
        return 0 if v["overall"] == "VERIFIED" else 2
    if a.cmd == "report":
        from . import final_report
        r = final_report.build(a.run)
        print(f"wrote {a.run}/guardian-report.html and .json (final confidence: {r['final_confidence']}; "
              f"executive summary by {r['executive_summary']['by']})")
        return 0
    if a.cmd == "gate":
        from .policy import gate
        r = gate(a.run, a.policy, a.after)
        print(("PASSED" if r["passed"] else "BLOCKED") + f" by {a.policy}")
        for v in r["violations"][:20]:
            print("  -", json.dumps(v)[:200])
        return 0 if r["passed"] else 1
    if a.cmd == "ai-check":
        return _ai_check()
    if a.cmd == "audit":
        from .audit import Audit
        r = Audit(a.run).verify()
        print(json.dumps(r))
        return 0 if r["ok"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
