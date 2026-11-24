"""Final Guardian report (human: guardian-report.html, machine: guardian-report.json).

Contents required by the brief: component inventory + dependency paths, findings + evidence,
risk ranking + recommended actions, approved action, build/test results, before/after risk,
remaining or accepted risk, final confidence, audit trail.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .audit import Audit

C = {"critical": "#b3261e", "high": "#d9480f", "medium": "#c08b00", "low": "#3b6fb6", "info": "#6b7280",
     "P1-urgent": "#b3261e", "P2-high": "#d9480f", "P3-medium": "#c08b00", "P4-low": "#3b6fb6",
     "VERIFIED": "#16703a", "PARTIAL": "#c08b00", "FAILED": "#b3261e", "NOT VERIFIED": "#b3261e"}


def _load(p: Path):
    return json.loads(p.read_text()) if p.exists() else None


def build(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    findings = _load(run_dir / "findings.json")
    analysis = _load(run_dir / "analysis.json")
    plan = _load(run_dir / "plan.json")
    val = _load(run_dir / "validation.json")
    prov = _load(run_dir / "provenance.json") or {}
    invs = sorted(run_dir.glob("investigation-*.json"))
    audit = Audit(run_dir)
    chain = audit.verify()
    residual, accepted = [], []
    resolved = {f for i in (val or {}).get("items", []) for f in i["resolved"]}
    rank = {r["finding_id"]: r for r in (analysis or {}).get("ranked", [])}
    for it in (plan or {}).get("items", []):
        if it["status"] == "risk-accepted":
            accepted.append({"item": it["item_id"], "title": it["title"], "by": it["approval"]["by"],
                             "reason": it["approval"]["reason"], "review_by": it["approval"].get("review_by")})
    for r in (analysis or {}).get("ranked", []):
        if r["priority"] in ("P1-urgent", "P2-high") and r["finding_id"] not in resolved:
            residual.append({"finding": r["finding_id"], "title": r["title"], "priority": r["priority"], "score": r["score"],
                             "accepted": any(r["finding_id"] in it["findings"] and it["status"] == "risk-accepted"
                                             for it in (plan or {}).get("items", []))})
    if val:
        conf = "high" if val["overall"] == "VERIFIED" and all(i["confidence"] == "high" for i in val["items"]) else \
            "medium" if val["overall"] in ("VERIFIED", "PARTIAL") else "low"
    else:
        conf = "n/a (not validated yet)"
    rep = {
        "schema": "guardian.report/v1", "tool": f"supply-chain-guardian {__version__}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project": findings["project"], "provenance": prov,
        "inventory": findings["inventory"], "coverage_notes": findings["coverage_notes"],
        "findings_summary": findings["summary"],
        "analysis": {k: analysis[k] for k in ("summary", "ai", "context", "urgent")} if analysis else None,
        "top_risks": (analysis or {}).get("ranked", [])[:25],
        "investigations": [_load(p) for p in invs],
        "plan": plan, "validation": val,
        "residual_risk": residual, "accepted_risk": accepted,
        "final_confidence": conf,
        "audit": {"chain": chain, "entries": audit.entries()},
        "artifacts": ["sbom.cdx.json", "dependency-graph.json", "dependency-graph.html", "findings.json", "analysis.json",
                      "plan.json", "validation.json", "after-scan/sbom.cdx.json", "audit.jsonl"],
    }
    from .ai_summary import summarize
    es = summarize(rep)
    rep["executive_summary"] = es
    audit.log("report", es["by"] if es["by"] != "deterministic-template" else "guardian", "executive-summary",
              {"by": es["by"], "rejected": es.get("ai_rejected"), "facts": len(es["facts"])})
    rep["audit"] = {"chain": audit.verify(), "entries": audit.entries()}
    (run_dir / "guardian-report.json").write_text(json.dumps(rep, indent=2))
    (run_dir / "guardian-report.html").write_text(to_html(rep))
    return rep


def _exec(es) -> str:
    if not es:
        return ""
    e = lambda s: html.escape(str(s))
    ai_used = es["by"] != "deterministic-template"
    who = (f"🤖 AI executive summary · {e(es['by'])} · inference, every number checked against the facts"
           if ai_used else "Executive summary · deterministic (no AI model configured)"
                           + (f" · AI answer rejected: {e(es['ai_rejected'])}" if es.get("ai_rejected") else ""))
    pts = "".join(f"<li>{e(p)}</li>" for p in es.get("key_points", []))
    facts = "".join(f"<li><b>{e(f['id'])}</b> {e(f['fact'])}</li>" for f in es["facts"])
    bg = "#fff8e1" if ai_used else "#ffffff"
    return (f'<section class="card" style="background:{bg};border-left:5px solid #c08b00"><h2>{e(es["headline"])}</h2>'
            f'<p><small>{who}</small></p><p>{e(es["summary"])}</p><ul>{pts}</ul>'
            f'<p><b>Decision needed:</b> {e(es.get("decision_needed", ""))}</p>'
            f'<details><summary><small>verified facts given to the model ({len(es["facts"])})</small></summary><ul>{facts}</ul></details></section>')


def _b(text, color):
    return f'<span class="b" style="background:{color}">{html.escape(str(text))}</span>'


def to_html(r: dict) -> str:
    e = lambda s: html.escape(str(s))
    inv, val, plan, ana = r["inventory"], r["validation"], r["plan"], r["analysis"]
    g = (r["provenance"] or {}).get("git") or {}
    # ---- validation hero
    hero = ""
    if val:
        rs = val["rescan"]
        bt = val["build_test"]
        tb = bt["before"].get("tests", [])
        ta = bt["after"].get("tests", [])
        trow = "".join(f"<tr><td><code>{e(x['cmd'])}</code></td><td>{x.get('pass', '?')} pass / {x.get('fail', '?')} fail"
                       f"</td><td>{y.get('pass', '?')} pass / {y.get('fail', '?')} fail</td></tr>" for x, y in zip(tb, ta))
        items = "".join(
            f"<tr><td>{e(i['item_id'])}</td><td>{e(i['description'])}<br><small>approved by <b>{e(i['approved_by'])}</b>: "
            f"{e(i['approval_reason'])}</small></td><td>{len(i['resolved'])}/{len(i['findings_targeted'])} resolved"
            f"{'<br><small>still present: ' + e(', '.join(i['still_present'])) + '</small>' if i['still_present'] else ''}</td>"
            f"<td>{_b(i['verdict'], C[i['verdict']])}<br><small>confidence {e(i['confidence'])}</small></td>"
            f"<td><small>{'<br>'.join(e(t) for v in i['test_coverage'].values() for t in v['tests_exercising_importers'][:4]) or 'no test imports the changed code'}</small></td></tr>"
            for i in val["items"])
        newf = "".join(f"<li>{_b(n['severity'], C[n['severity']])} {e(n['title'])}</li>" for n in rs["newly_introduced"][:15]) \
            or "<li>none</li>"
        sd = val["sbom_diff"]
        steps = lambda res: "".join(f"<li><code>{e(s['cmd'])}</code>: exit {s['exit']} ({s['seconds']}s)</li>" for s in res["steps"])
        hero = f'''<section class="card hero"><h2>Detection → verified remediation {_b(val["overall"], C[val["overall"]])}</h2>
<div class="kpis"><div><b>{rs["risk_score_production_before"]} → {rs["risk_score_production_after"]}</b>production risk score</div>
<div><b>{rs["priority_before"]["P1-urgent"]} → {rs["priority_after"]["P1-urgent"]}</b>P1 urgent findings</div>
<div><b>{rs["findings_before"]} → {rs["findings_after"]}</b>findings</div>
<div><b>{rs["newly_introduced_high_or_critical"]}</b>new high/critical introduced</div>
<div><b>{"yes" if bt["after"].get("build_ok") else "NO"}</b>fix branch builds</div>
<div><b>{"yes" if bt["tests_no_regression"] else "NO"}</b>no test regressions</div></div>
<table><tr><th>item</th><th>approved action</th><th>rescan</th><th>verdict</th><th>tests exercising the changed code</th></tr>{items}</table>
<h3>Build &amp; tests (same commands, before vs after)</h3><table><tr><th>test command</th><th>before (baseline)</th><th>after (fix branch)</th></tr>{trow}</table>
<div class="grid2"><div><b>Before</b><ul>{steps(bt["before"])}</ul></div><div><b>After</b><ul>{steps(bt["after"])}</ul></div></div>
<p><small>{"<br>".join(e(x) for x in bt.get("test_notes", []) + bt.get("reused_artifacts", []))}</small></p>
<h3>Before/after SBOM</h3><p>{sd["added"]} added · {sd["removed"]} removed · {sd["version_changed"]} version changes</p>
<div class="grid3"><div><b>added</b><ul>{"".join(f"<li>{e(x)}</li>" for x in sd["added_list"][:25]) or "<li>none</li>"}</ul></div>
<div><b>removed</b><ul>{"".join(f"<li>{e(x)}</li>" for x in sd["removed_list"][:25]) or "<li>none</li>"}</ul></div>
<div><b>changed</b><ul>{"".join(f"<li>{e(x)}</li>" for x in sd["changed_list"][:25]) or "<li>none</li>"}</ul></div></div>
<h3>Newly introduced findings (after vs before)</h3><ul>{newf}</ul>
<h3>Change</h3><p>Branch <code>{e(val["branch"])}</code> · commit <code>{e(val["commit"][:12])}</code> · not pushed, not merged</p>
<pre>{e(val["manifest_diff"][:3500])}</pre><p><b>Rollback:</b> {e(val["rollback"])}<br><b>Next:</b> {e(val["human_next_step"])}</p></section>'''
    # ---- ranking
    rows = []
    for x in r["top_risks"]:
        ai = x.get("ai") or {}
        fac = "".join(f"<li>{'+' if f['points'] > 0 and f['factor'] != 'severity' else ''}{f['points']} {e(f['factor'])}: {e(f['why'])}</li>" for f in x["factors"])
        aitxt = ""
        if ai:
            aitxt = (f"<p><b>Explanation</b> <small>({e(ai['by'])}{', AI answer rejected: ' + e(ai['ai_rejected']) if ai.get('ai_rejected') else ''}"
                     f"; inference, cites {e(', '.join(ai.get('cited_evidence', [])))})</small><br>{e(ai.get('summary', ''))}<br>"
                     f"{e(ai.get('reachability', ''))}</p>")
        rows.append(f"<tr><td>{_b(x['priority'], C[x['priority']])}<br><b>{x['score']}</b></td><td><details><summary>{e(x['title'])}</summary>"
                    f"<ul>{fac}</ul>{aitxt}<small>path: {e(' > '.join(x['dependency_paths'][0]) if x['dependency_paths'] else '—')}</small></details></td>"
                    f"<td>{e(x['reachability']['level'])}</td><td>{e(x['exposure']['context'])}</td><td>{e(x['confidence']['label'])} ({x['confidence']['value']})</td></tr>")
    # ---- investigations
    invh = ""
    for iv in r["investigations"]:
        inf = iv["inference"]
        facts = "".join(f"<tr><td>{e(f['id'])}</td><td>{e(f['kind'])}</td><td><small>{e(f['source'])}</small></td><td>{e(f['detail'])}</td></tr>" for f in iv["verified_evidence"])
        invh += f'''<section class="card"><h2>Investigation: {e(iv["finding"]["title"])}</h2>
<div class="grid2"><div><h3>✅ Verified evidence <small>(deterministic sources)</small></h3><table>{facts}</table></div>
<div class="inf"><h3>🤖 Inference <small>({e(inf["by"])}, NOT verified)</small></h3><p><b>Verdict:</b> {e(inf["verdict"])} · confidence {e(inf["confidence"])}</p>
<p><b>Hypothesis:</b> {e(inf["hypothesis"])}</p><p>{e(inf.get("assessment", ""))}</p><p><small>cites {e(", ".join(inf.get("cited_facts", [])))}</small></p>
<b>Safe next steps</b><ul>{"".join(f"<li>{e(s)}</li>" for s in inf.get("next_steps", []))}</ul></div></div></section>'''
    # ---- plan
    plan_rows = ""
    for it in (plan or {}).get("items", []):
        rec = next((o for o in it["options"] if o.get("recommended")), it["options"][0])
        ap = it.get("approval") or {}
        st = it["status"]
        plan_rows += (f"<tr><td>{e(it['item_id'])}</td><td>{_b(it['priority'], C[it['priority']])}</td><td>{e(it['title'])}</td>"
                      f"<td>{e(rec['action'])}: {e(rec['description'])}<br><small>compatibility {e(rec['compatibility']['level'])}: "
                      f"{e('; '.join(rec['compatibility']['reasons']))}</small></td>"
                      f"<td><b>{e(st)}</b>{('<br><small>' + e(ap.get('option_id') or '') + ' by ' + e(ap['by']) + ': ' + e(ap['reason']) + '</small>') if ap else ''}</td></tr>")
    resid = "".join(f"<tr><td>{_b(x['priority'], C[x['priority']])}</td><td>{x['score']}</td><td>{e(x['title'])}</td><td>{'accepted' if x['accepted'] else 'open'}</td></tr>"
                    for x in r["residual_risk"][:40])
    acc = "".join(f"<li><b>{e(a['title'])}</b>: accepted by {e(a['by'])} ({e(a['reason'])}), review by {e(a['review_by'])}</li>" for a in r["accepted_risk"]) or "<li>none</li>"
    aud = "".join(f"<tr><td><small>{e(x['ts'][:19])}</small></td><td>{e(x['stage'])}</td><td>{e(x['actor'])}</td><td>{e(x['action'])}</td>"
                  f"<td><small>{e(json.dumps(x['details'])[:220])}</small></td><td><small><code>{e(x['hash'][:10])}</code></small></td></tr>" for x in r["audit"]["entries"])
    ch = r["audit"]["chain"]
    aistat = ana["ai"] if ana else {}
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardian report · {e(r["project"])}</title><style>
body{{margin:0;font:14px/1.5 Inter,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1b2430;background:#f5f6f8}}
header{{background:#0f2537;color:#fff;padding:20px 30px}} header h1{{margin:0;font-size:22px}} header p{{margin:4px 0 0;opacity:.8;font-size:13px}}
main{{padding:20px 30px;max-width:1350px}} .card{{background:#fff;border-radius:12px;padding:16px 20px;margin:0 0 18px;box-shadow:0 1px 3px #0001}}
.hero{{border-top:5px solid #16703a}} h2{{font-size:18px;margin:0 0 10px}} h3{{font-size:15px;margin:16px 0 6px}}
.kpis{{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 14px}} .kpis div{{background:#f3f5f8;border-radius:8px;padding:8px 14px;min-width:150px;color:#5b6573;font-size:12.5px}}
.kpis b{{display:block;font-size:20px;color:#1b2430}} table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border-bottom:1px solid #eef0f3;padding:6px 8px;text-align:left;vertical-align:top}} th{{background:#f7f8fa}}
.b{{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;white-space:nowrap}} small{{color:#6b7480}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}} .grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}}
.inf{{background:#fff8e6;border-radius:8px;padding:6px 14px}} pre{{background:#0f2537;color:#e6edf3;padding:12px;border-radius:8px;overflow:auto;font-size:12px;max-height:340px}}
details summary{{cursor:pointer}} ul{{margin:4px 0;padding-left:20px}} code{{font-size:12px}}
</style></head><body>
<header><h1>Supply Chain Guardian report · {e(r["project"])}</h1>
<p>{e(g.get("remote", ""))} @ {e(g.get("branch", ""))} · commit {e((g.get("commit") or "")[:9])} · generated {e(r["generated_at"])} · final confidence: <b>{e(r["final_confidence"])}</b></p></header>
<main>
{_exec(r.get("executive_summary"))}
{hero}
<section class="card"><h2>Inventory</h2><p><b>{inv["components"]:,}</b> components ({inv["direct"]} direct, {inv["transitive"]:,} transitive), <b>{inv["edges"]:,}</b> dependency edges, depth {inv["max_depth"]}.
Ecosystems: {e(", ".join(f"{k} {v}" for k, v in inv["by_ecosystem"].items()))}. Full graph + paths: <code>dependency-graph.html</code>, SBOM: <code>sbom.cdx.json</code>.</p>
<p><small>{"<br>".join(e(n) for n in r["coverage_notes"])}</small></p></section>
<section class="card"><h2>Risk ranking ({e(", ".join(f"{k}: {v}" for k, v in (ana or {}).get("summary", {}).items()))})</h2>
<p><small>Score = severity/CVSS + exploitability + reachability + exposure (all from verified facts; factors shown per finding). AI: {e(aistat.get("provider"))} {e(aistat.get("model"))}
{"(enabled)" if aistat.get("enabled") else "(disabled: deterministic explanations)"} · accepted {aistat.get("accepted", 0)}, rejected {aistat.get("rejected", 0)} · prompt sha {e(aistat.get("prompt_sha", ""))}</small></p>
<table><tr><th>priority</th><th>finding (click for factors + explanation)</th><th>reachability</th><th>exposure</th><th>confidence</th></tr>{"".join(rows)}</table></section>
{invh}
<section class="card"><h2>Recommended actions &amp; human decisions</h2><table><tr><th>item</th><th>priority</th><th>risk</th><th>recommended</th><th>decision</th></tr>{plan_rows}</table></section>
<section class="card"><h2>Remaining &amp; accepted risk</h2><ul>{acc}</ul><table><tr><th>priority</th><th>score</th><th>open P1/P2 finding</th><th>status</th></tr>{resid}</table></section>
<section class="card"><h2>Audit trail {_b("chain intact" if ch["ok"] else "CHAIN BROKEN", "#16703a" if ch["ok"] else "#b3261e")}</h2>
<p><small>Hash-chained, append-only log (audit.jsonl). Head <code>{e(ch.get("head", "")[:16])}</code>, {ch.get("entries", 0)} entries.</small></p>
<table><tr><th>time (UTC)</th><th>stage</th><th>actor</th><th>action</th><th>details</th><th>hash</th></tr>{aud}</table></section>
</main></body></html>'''
