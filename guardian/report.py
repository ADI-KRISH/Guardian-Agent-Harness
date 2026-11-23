"""Guardian report: human-readable (Markdown + HTML) and machine-readable (JSON + CycloneDX SBOM)."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .config import WORKSPACE


def _md_findings(fs: list[dict]) -> list[str]:
    L = ["| Risk | Score | Conf. | Finding | Component / place | Detector |", "|---|---|---|---|---|---|"]
    for f in fs:
        loc = f.get("location") or {}
        place = f"{loc.get('file', '')}:{loc.get('line', '')}".strip(":") if loc.get("file") else f.get("component", "")
        L.append(f"| {f['risk_level']} | {f['score']} | {f.get('confidence', '')} | `{f['id']}` {f['title'][:90]} | {place[:60]} | {f['detector']} |")
    return L


def markdown(r: dict) -> str:
    s, c = r["summary"], r.get("change") or {}
    active = [f for f in r["findings"] if not f.get("suppressed_by")]
    L = [f"# Guardian report: {r['project']}", "",
         f"Run `{r['run_id']}` · compared **{r.get('base_ref') or 'no baseline'}** -> **{r['head_ref']}** "
         f"({(r.get('head_commit') or {}).get('sha', '')[:10]}) · {s['seconds']} s", "",
         *([f"> **Lead agent summary (AI inference, not evidence):** {r['agent_summary']}", ""] if r.get("agent_summary") else []),
         "## What is in it", "",
         f"- {s['packages']} packages ({s['direct']} direct, {s['runtime']} runtime, {s['dev']} dev-only) across {', '.join(s['ecosystems']) or 'no'} ecosystems",
         f"- Lockfiles: {', '.join(s['lockfiles'][:8]) or 'none found'}",
         f"- {s['workflow_steps']} GitHub workflow steps, {s['images']} container base images", ""]
    if r.get("notes"):
        L += ["Notes: " + "; ".join(r["notes"]), ""]
    if r.get("skipped"):
        L += ["**Not run this time:** " + "; ".join(r["skipped"]), ""]
    L += ["## What changed", ""]
    if c:
        L += [f"- Packages: {c.get('added_count', 0)} added, {c.get('removed_count', 0)} removed, {c.get('updated_count', 0)} version updates",
              f"- New package names: {', '.join(c.get('new_names', [])[:15]) or 'none'}",
              f"- Workflow `uses:` changes: {len(c.get('workflow_changes', []))}; base image changes: {len(c.get('image_changes', []))}",
              f"- Changed files: {r.get('backdoor_stats', {}).get('files_changed', 0)}; build files changed: {', '.join(r.get('backdoor_stats', {}).get('build_files_changed', [])[:10]) or 'none'}", ""]
    else:
        L += ["No baseline to compare against.", ""]
    L += ["## What appears risky", "",
          f"**{s['findings']} findings:** " + ", ".join(f"{v} {k}" for k, v in s["by_level"].items()) + f" ({s['suppressed']} suppressed by approved lessons)", ""]
    L += _md_findings(active[:40]) + [""]
    L += ["## Evidence for the top findings", ""]
    for f in active[:15]:
        L += [f"### `{f['id']}` {f['title']}", "",
              f"- **Risk:** {f['risk_level']} ({f['score']}): {f['score_explanation']}",
              f"- **Confidence:** {f.get('confidence')} ({f.get('confidence_reason', '')})",
              f"- **Component:** {f.get('component', '')} · **Change:** {f.get('change') or 'n/a'}"]
        for p in (f.get("dependency_paths") or [])[:2]:
            L.append("- **Dependency path:** " + " -> ".join(p))
        L += [f"- **Verified evidence:** {e}" for e in f["verified_evidence"]]
        for a in f.get("ai_inference", []):
            L.append(f"- **AI inference** ({a['model']}, not verified): {a['text']}")
        L += [f"- **Initial recommendation:** {f.get('recommendation', '')}", ""]
    L += ["## Detector self-check (canary)", ""] + [f"- {'caught' if x['caught'] else 'MISSED'}: {x['detector']} ({x['detail']})" for x in r.get("canary", [])]
    L += ["", f"Full decision log: {len(r.get('decisions', []))} entries in `decisions.json`."]
    return "\n".join(L)


def _h(s) -> str:
    return html.escape(str(s))


def html_report(r: dict) -> str:
    s = r["summary"]
    active = [f for f in r["findings"] if not f.get("suppressed_by")]
    colors = {"Critical": "#b91c1c", "High": "#c2410c", "Medium": "#a16207", "Low": "#4b5563"}
    edges = set()
    for f in active[:8]:
        for p in (f.get("dependency_paths") or [])[:1]:
            for a, b in zip(p, p[1:]):
                edges.add((a, b))
    def nid(x): return "n" + str(abs(hash(x)) % 10**8)
    mer = "graph LR\n" + "\n".join(f'  {nid(a)}["{a.replace(chr(34), "")}"] --> {nid(b)}["{b.replace(chr(34), "")}"]' for a, b in sorted(edges))
    rows = "".join(
        f"<tr><td style='color:{colors[f['risk_level']]};font-weight:600'>{f['risk_level']}</td><td>{f['score']}</td><td>{_h(f.get('confidence'))}</td>"
        f"<td><details><summary><code>{_h(f['id'])}</code> {_h(f['title'][:110])}</summary>"
        f"<p><b>Why this score:</b> {_h(f['score_explanation'])}<br><b>Confidence:</b> {_h(f.get('confidence_reason'))}<br>"
        f"<b>Change:</b> {_h(f.get('change') or 'n/a')}</p>"
        + "".join(f"<p><b>Path:</b> {_h(' → '.join(p))}</p>" for p in (f.get('dependency_paths') or [])[:2])
        + "<ul>" + "".join(f"<li><b>Verified:</b> {_h(e)}</li>" for e in f['verified_evidence'])
        + "".join(f"<li><b>AI inference</b> ({_h(a['model'])}, not verified): {_h(a['text'])}</li>" for a in f.get('ai_inference', [])) + "</ul>"
        f"<p><b>Initial recommendation:</b> {_h(f.get('recommendation'))}</p></details></td><td>{_h(f['detector'])}</td></tr>"
        for f in active)
    c = r.get("change") or {}
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Guardian report: {_h(r['project'])}</title>
<style>body{{font-family:system-ui,Segoe UI,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{border:1px solid #ddd;border-radius:8px;padding:12px}}
.card b{{font-size:24px;display:block}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #eee;padding:6px;text-align:left;vertical-align:top;font-size:14px}}
code{{background:#f3f4f6;padding:1px 4px;border-radius:4px}}details summary{{cursor:pointer}}</style>
<script type="module">import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';mermaid.initialize({{startOnLoad:true}});</script>
</head><body><h1>Guardian report: {_h(r['project'])}</h1>
<p>Compared <b>{_h(r.get('base_ref') or 'no baseline')}</b> → <b>{_h(r['head_ref'])}</b> · run {_h(r['run_id'])} · {s['seconds']} s</p>
{f"<p style='background:#eff6ff;padding:8px;border-radius:6px'><b>Lead agent summary</b> (AI inference, not evidence): {_h(r['agent_summary'])}</p>" if r.get('agent_summary') else ''}
{''.join(f"<p style='background:#fff7ed;padding:8px;border-radius:6px'><b>Not run this time:</b> {_h(x)}</p>" for x in r.get('skipped', []))}
{''.join(f"<p style='color:#555'>Note: {_h(x)}</p>" for x in r.get('notes', []))}
<h2>What is in it</h2><div class="cards"><div class="card"><b>{s['packages']}</b>packages</div><div class="card"><b>{s['direct']}</b>direct dependencies</div>
<div class="card"><b>{s['workflow_steps']}</b>workflow steps</div><div class="card"><b>{s['images']}</b>base images</div></div>
<h2>What changed</h2><p>{c.get('added_count', 0)} packages added, {c.get('removed_count', 0)} removed, {c.get('updated_count', 0)} updated;
{len(c.get('workflow_changes', []))} workflow changes; {len(c.get('image_changes', []))} image changes.</p>
<h2>What appears risky</h2><div class="cards">{''.join(f"<div class='card' style='border-color:{colors[k]}'><b style='color:{colors[k]}'>{v}</b>{k}</div>" for k, v in s['by_level'].items())}</div>
<h3>Dependency paths of the top findings</h3><pre class="mermaid">{_h(mer) if edges else 'graph LR\n  none["no dependency paths for the top findings"]'}</pre>
<table><tr><th>Risk</th><th>Score</th><th>Conf.</th><th>Finding (click for evidence)</th><th>Detector</th></tr>{rows}</table>
<h2>Detector self-check</h2><ul>{''.join(f"<li>{'✅' if x['caught'] else '❌ MISSED'} {_h(x['detector'])}</li>" for x in r.get('canary', []))}</ul>
<p style="color:#666">AI inference is labelled and never counts as evidence. Every decision is in decisions.json.</p></body></html>"""


def write(r: dict) -> Path:
    out = WORKSPACE / "reports" / r["project"] / r["run_id"]
    out.mkdir(parents=True, exist_ok=True)
    head = r.pop("head")
    if head.get("sbom"):
        (out / "sbom.cdx.json").write_text(json.dumps(head["sbom"], indent=1), encoding="utf-8")
    inventory = {"packages": head["packages"], "roots": head["roots"], "graph": head["graph"],
                 "workflows": head["workflows"], "images": head["images"]}
    (out / "inventory.json").write_text(json.dumps(inventory, indent=1, default=str), encoding="utf-8")
    (out / "decisions.json").write_text(json.dumps(r.get("decisions", []), indent=1, default=str), encoding="utf-8")
    report = {k: v for k, v in r.items() if k != "decisions"}
    report["schema_version"] = "1.0"
    (out / "report.json").write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    (out / "report.md").write_text(markdown(r), encoding="utf-8")
    (out / "report.html").write_text(html_report(r), encoding="utf-8")
    return out
