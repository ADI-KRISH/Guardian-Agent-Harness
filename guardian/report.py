"""Outputs: findings.json (machine-readable hand-off to Analyze), findings.sarif, report.html."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import Finding, SEVERITY_ORDER

SEV_COLOR = {"critical": "#b3261e", "high": "#d9480f", "medium": "#c08b00", "low": "#3b6fb6", "info": "#6b7280"}


def build_doc(inv, stats, det, context) -> dict:
    fs = det["findings"]
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_cat = {}
    for f in fs:
        by_sev[f.severity] += 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "schema": "guardian.findings/v1",
        "tool": {"name": "supply-chain-guardian", "stage": "discover+detect", "version": __version__},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project": inv.project,
        "inputs": inv.sources,
        "ecosystems": context.get("ecosystems", []),
        "coverage_notes": inv.notes,
        "inventory": stats,
        "vulnerability_source": (det["meta"].get("vulnerabilities") or {}).get("source"),
        "vulnerability_source_errors": (det["meta"].get("vulnerabilities") or {}).get("errors", []),
        "checks": det["meta"]["checks"],
        "baseline_diff": det["meta"].get("baseline_diff"),
        "summary": {"total": len(fs), "by_severity": by_sev, "by_category": by_cat},
        "findings": [f.to_dict() for f in fs],
        "artifacts": {"sbom": "sbom.cdx.json", "inventory": "inventory.json", "graph": "dependency-graph.json"},
    }


def write_json(doc: dict, path: Path):
    path.write_text(json.dumps(doc, indent=2))


def write_sarif(doc: dict, path: Path):
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for f in doc["findings"]:
        rules.setdefault(f["rule"], {"id": f["rule"], "name": f["rule"], "shortDescription": {"text": f["category"]}})
        loc_ev = next((e for e in f["evidence"] if e.get("source") and "/" not in (e["source"] or "")[:8]
                       and not e["source"].startswith(("guardian", "osv", "registry"))), None)
        locs = []
        if loc_ev:
            line = loc_ev.get("location") or ""
            region = {"startLine": int(line.split(":")[-1])} if str(line).split(":")[-1].isdigit() else None
            pl = {"artifactLocation": {"uri": loc_ev["source"]}}
            if region:
                pl["region"] = region
            locs = [{"physicalLocation": pl}]
        results.append({"ruleId": f["rule"], "level": lvl[f["severity"]],
                        "message": {"text": f["title"] + (" | path: " + " > ".join(f["dependency_paths"][0])
                                                         if f["dependency_paths"] else "")},
                        "locations": locs, "properties": {"severity": f["severity"], "guardianId": f["id"]}})
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "supply-chain-guardian", "version": __version__,
                                           "rules": list(rules.values())}}, "results": results}]}
    path.write_text(json.dumps(sarif, indent=2))


def write_html(doc: dict, path: Path):
    e = html.escape
    s = doc["summary"]
    inv = doc["inventory"]
    sev_cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLOR[k]}"><div class="n">{v}</div><div>{k}</div></div>'
        for k, v in s["by_severity"].items())
    cat_opts = "".join(f'<option value="{e(c)}">{e(c)} ({n})</option>' for c, n in sorted(s["by_category"].items()))
    rows = []
    for f in doc["findings"]:
        comp = f.get("component") or {}
        comp_txt = f'{comp.get("name")}@{comp.get("version")}' if comp else "—"
        paths = "".join(f"<li>{' &rarr; '.join(e(x) for x in p)}</li>" for p in f["dependency_paths"]) or "<li>—</li>"
        evid = "".join(
            f'<li><b>{e(ev["kind"])}</b> <span class="src">[{e(str(ev["source"]))}{(":" + e(str(ev["location"]))) if ev.get("location") else ""}]</span> {e(ev["detail"])}</li>'
            for ev in f["evidence"])
        fix = ""
        if f.get("fix"):
            fx = f["fix"]
            parts = []
            if fx.get("fixed_versions"):
                parts.append("fixed in: " + ", ".join(e(v) for v in fx["fixed_versions"]))
            elif "available" in fx:
                parts.append("no fixed version published")
            if fx.get("introduced_via"):
                parts.append("introduced via: " + ", ".join(e(v) for v in fx["introduced_via"][:6]))
            if fx.get("suggestion"):
                parts.append(e(fx["suggestion"]))
            fix = "<p><b>Fix info:</b> " + " · ".join(parts) + "</p>" if parts else ""
        ids = ", ".join(f'<a href="{e(r)}" target="_blank">{e(r.split("/")[-1])}</a>' for r in f["references"][:3]) \
            or ", ".join(e(i) for i in f["identifiers"][:3])
        rows.append(f'''<tr class="f" data-sev="{f["severity"]}" data-cat="{e(f["category"])}">
<td><span class="sev" style="background:{SEV_COLOR[f["severity"]]}">{f["severity"]}</span></td>
<td>{e(f["category"])}</td><td><details><summary>{e(f["title"])}</summary>
<p class="meta">{e(f["id"])} · rule {e(f["rule"])} · {e(f["evidence_type"])} evidence · confidence {e(f["confidence"])}
{(" · " + ids) if ids else ""}</p>
<p><b>Dependency path(s):</b></p><ul>{paths}</ul><p><b>Evidence:</b></p><ul>{evid}</ul>{fix}</details></td>
<td>{e(comp_txt)}<br><small>{"direct" if comp.get("direct") else ("transitive" if comp else "")} {e(comp.get("scope", "") or "")}</small></td></tr>''')
    bd = doc.get("baseline_diff")
    changes = ""
    if bd:
        def lst(xs):
            return "".join(f"<li>{e(x)}</li>" for x in xs[:40]) or "<li>none</li>"
        changes = f'''<h2>What changed (vs {e(bd["baseline"])})</h2><div class="grid3">
<div><h3>Added ({bd["added"]})</h3><ul>{lst(bd["added_list"])}</ul></div>
<div><h3>Removed ({bd["removed"]})</h3><ul>{lst(bd["removed_list"])}</ul></div>
<div><h3>Version changed ({bd["version_changed"]})</h3><ul>{lst(bd["changed_list"])}</ul></div></div>'''
    notes = "".join(f"<li>{e(n)}</li>" for n in doc["coverage_notes"] + doc.get("vulnerability_source_errors", []))
    checks = "".join(f'<li>{e(k)}: {e(v["status"])}{" (" + str(v.get("findings")) + ")" if v.get("status") == "ok" else " — " + e(v.get("error", ""))}</li>'
                     for k, v in doc["checks"].items())
    eco = ", ".join(f"{e(k)}: {v}" for k, v in inv["by_ecosystem"].items())
    scope = ", ".join(f"{e(k)}: {v}" for k, v in inv["by_scope"].items())
    page = f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>Guardian report — {e(doc["project"])}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1f2328;background:#f6f7f9}}
header{{background:#0f2537;color:#fff;padding:18px 28px}} header h1{{margin:0;font-size:20px}} header p{{margin:4px 0 0;opacity:.8}}
main{{padding:20px 28px;max-width:1300px}} h2{{font-size:16px;margin:26px 0 10px}}
.cards{{display:flex;gap:10px;flex-wrap:wrap}} .card{{background:#fff;padding:10px 16px;border-radius:6px;min-width:90px;box-shadow:0 1px 2px #0001}}
.card .n{{font-size:22px;font-weight:600}} .grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
.grid3>div{{background:#fff;padding:8px 14px;border-radius:6px}} table{{width:100%;border-collapse:collapse;background:#fff}}
td,th{{padding:8px 10px;border-bottom:1px solid #e6e8eb;vertical-align:top;text-align:left}}
.sev{{color:#fff;border-radius:4px;padding:2px 7px;font-size:12px;text-transform:uppercase}} summary{{cursor:pointer;font-weight:500}}
.meta{{color:#57606a;font-size:12px}} .src{{color:#57606a;font-family:ui-monospace,monospace;font-size:12px}}
.filters{{display:flex;gap:10px;margin:8px 0}} select,input{{padding:5px 8px;border:1px solid #ccd;border-radius:4px}}
ul{{margin:4px 0 8px;padding-left:20px}} small{{color:#57606a}}
</style></head><body>
<header><h1>Software Supply Chain Guardian — Discover &amp; Detect</h1>
<p>{e(doc["project"])} · generated {e(doc["generated_at"])} · vulnerability data: {e(str(doc["vulnerability_source"]))}</p></header>
<main>
<h2>What is in the application</h2>
<div class="cards"><div class="card"><div class="n">{inv["components"]}</div><div>components</div></div>
<div class="card"><div class="n">{inv["direct"]}</div><div>direct</div></div>
<div class="card"><div class="n">{inv["transitive"]}</div><div>transitive</div></div>
<div class="card"><div class="n">{inv["max_depth"]}</div><div>max depth</div></div>
<div class="card"><div class="n">{inv["edges"]}</div><div>edges</div></div></div>
<p><b>Ecosystems:</b> {eco}<br><b>Scopes:</b> {scope}<br><b>Inputs:</b> {", ".join(e(x) for x in doc["inputs"][:12])}{" …" if len(doc["inputs"]) > 12 else ""}</p>
{changes}
<h2>What appears risky ({s["total"]} findings)</h2>
<div class="cards">{sev_cards}</div>
<div class="filters"><select id="sev"><option value="">all severities</option>
{"".join(f'<option>{k}</option>' for k in SEVERITY_ORDER)}</select>
<select id="cat"><option value="">all categories</option>{cat_opts}</select>
<input id="q" placeholder="search…" size="30"><label><input type="checkbox" id="hideinfo" checked> hide info</label></div>
<table><thead><tr><th>Severity</th><th>Category</th><th>Finding (click for evidence)</th><th>Component</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<h2>Checks run</h2><ul>{checks}</ul>
<h2>Coverage notes &amp; limitations</h2><ul>{notes or "<li>none</li>"}</ul>
<p class="meta">Severity here is the initial, detector-assigned risk level. Contextual prioritisation (reachability, exposure, exploitability) is done by the Analyze stage from findings.json. "verified" evidence comes from deterministic data (lockfiles, advisories, registry); "heuristic" evidence is pattern-based and needs review.</p>
</main>
<script>
const f=()=>{{const s=sev.value,c=cat.value,t=q.value.toLowerCase(),h=hideinfo.checked;
document.querySelectorAll("tr.f").forEach(r=>{{r.style.display=((!s||r.dataset.sev==s)&&(!c||r.dataset.cat==c)&&(!t||r.textContent.toLowerCase().includes(t))&&!(h&&!s&&r.dataset.sev=="info"))?"":"none"}})}};
[sev,cat,q,hideinfo].forEach(x=>x.addEventListener("input",f));f();
</script></body></html>'''
    path.write_text(page)
