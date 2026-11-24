"""Standalone, self-contained dependency-graph page (dependency-graph.html).

Tabs: risk-path graph (Graphviz SVG with zoom/pan + hover), full-graph explorer (tree with
search and risky-only filter), and a sortable component table. No external scripts.
"""
from __future__ import annotations

import html
import re
import json
from pathlib import Path
from typing import Optional

from .report import GRAPH_JS


def write(path: Path, inv_stats: dict, tree: dict, risk_svg: Optional[str], prov: Optional[dict],
          project: str, findings_summary: Optional[dict] = None) -> None:
    e = html.escape
    g = (prov or {}).get("git") or {}
    src = f'{e(g.get("remote") or "")} @ {e(g.get("branch") or "")} · commit {e((g.get("commit") or "")[:9])}' if g else ""
    inputs = ", ".join(e(i["path"]) for i in (prov or {}).get("inputs", []) if re.search(r"(package-lock|npm-shrinkwrap|yarn\.lock|pnpm-lock|poetry\.lock|requirements.*\.txt|pom\.xml|\.tgf)", i["path"])) or "—"
    sev = (findings_summary or {}).get("by_severity", {})
    st = inv_stats
    cards = [("components", st["components"]), ("dependency edges", st["edges"]), ("direct", st["direct"]),
             ("transitive", st["transitive"]), ("max depth", st["max_depth"]),
             ("unreachable", st["unreachable_from_root"])]
    card_html = "".join(f'<div class="c"><b>{v:,}</b><span>{k}</span></div>' for k, v in cards)
    sev_html = "".join(f'<i class="s-{k}">{v} {k}</i>' for k, v in sev.items() if v and k != "info")
    eco = " · ".join(f"{v:,} {k}" for k, v in st["by_ecosystem"].items())
    scope = " · ".join(f"{v:,} {k}" for k, v in st["by_scope"].items())
    svg_body = risk_svg[risk_svg.find("<svg"):] if risk_svg else "<p>Graphviz not installed: risk graph unavailable.</p>"
    rows = []
    for i, n in enumerate(tree["nodes"]):
        if i == 0:
            continue
        rows.append([n["l"], n.get("e", ""), n["sc"], "direct" if n["d"] else "transitive", n["s"] or "", n["n"],
                     len(tree["kids"][i])])
    data = json.dumps(tree, separators=(",", ":")).replace("</", "<\\/")
    table = json.dumps(rows, separators=(",", ":")).replace("</", "<\\/")
    page = f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Dependency graph · {e(project)}</title>
<style>
*{{box-sizing:border-box}} body{{margin:0;font:14px/1.45 Inter,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1b2430;background:#f5f6f8}}
header{{background:#0f2537;color:#fff;padding:18px 28px}} header h1{{margin:0;font-size:21px}} header p{{margin:4px 0 0;opacity:.8;font-size:13px}}
main{{padding:18px 28px 40px}} .cards{{display:flex;gap:10px;flex-wrap:wrap}}
.c{{background:#fff;border-radius:10px;padding:10px 16px;min-width:120px;box-shadow:0 1px 2px #0001}} .c b{{font-size:22px;display:block}} .c span{{color:#5b6573;font-size:12.5px}}
.meta{{color:#5b6573;font-size:13px;margin:10px 0}} .sev i{{font-style:normal;color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;margin-right:5px}}
.s-critical{{background:#b3261e}} .s-high{{background:#d9480f}} .s-medium{{background:#c08b00}} .s-low{{background:#3b6fb6}}
.tabs{{display:flex;gap:4px;margin:18px 0 0}} .tabs button{{border:0;background:#e4e7eb;padding:9px 16px;border-radius:8px 8px 0 0;cursor:pointer;font:inherit}}
.tabs button.on{{background:#fff;font-weight:600}} .panel{{display:none;background:#fff;border-radius:0 10px 10px 10px;padding:14px;box-shadow:0 1px 2px #0001}} .panel.on{{display:block}}
.zoom{{height:calc(100vh - 320px);min-height:420px;overflow:hidden;border:1px solid #eef0f3;border-radius:8px;cursor:grab;position:relative;background:#fff}}
.zoom svg{{transform-origin:0 0;position:absolute;left:0;top:0}} .ztools{{margin-bottom:8px;display:flex;gap:6px;align-items:center}}
button.sm{{border:1px solid #ccd;background:#fff;border-radius:5px;padding:4px 10px;cursor:pointer;font:inherit;font-size:13px}}
.filters{{display:flex;gap:10px;margin:4px 0 10px;align-items:center;flex-wrap:wrap}} input,select{{padding:5px 8px;border:1px solid #ccd;border-radius:5px;font:inherit}}
.tree{{font:13px/1.6 ui-monospace,Menlo,Consolas,monospace;max-height:70vh;overflow:auto}}
.tree ul{{list-style:none;padding-left:18px;margin:0;border-left:1px dotted #ccd}} .tree>ul{{border:0;padding-left:0}}
.tw{{display:inline-block;width:14px;cursor:pointer;color:#57606a}} .tn.hit{{background:#fff3a3}} .dev{{color:#8b949e}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin:0 4px 1px 2px}}
.bdg{{color:#fff;border-radius:3px;padding:0 5px;font-size:11px;margin-left:6px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{padding:6px 8px;border-bottom:1px solid #eef0f3;text-align:left}}
th{{cursor:pointer;background:#f7f8fa;position:sticky;top:0}} .tbl{{max-height:70vh;overflow:auto}} small{{color:#6b7480}}
</style></head><body>
<header><h1>Dependency graph · {e(project)}</h1><p>{src} · inputs: {inputs} · generated {e((prov or {}).get("generated_at", ""))}</p></header>
<main>
<div class="cards">{card_html}</div>
<div class="meta"><b>Ecosystems:</b> {e(eco)} &nbsp; <b>Scopes:</b> {e(scope)} &nbsp; <span class="sev">{sev_html}</span></div>
<div class="tabs"><button class="on" data-p="p1">Risk paths</button><button data-p="p2">Full graph explorer</button><button data-p="p3">All components</button></div>
<section class="panel on" id="p1">
 <div class="ztools"><button class="sm" id="zin">+</button><button class="sm" id="zout">−</button><button class="sm" id="zfit">fit</button>
 <small>Only routes from the app to high/critical findings. Drag to pan, scroll to zoom, hover a box for its findings. Dashed = dev / build / CI / optional.</small></div>
 <div class="zoom" id="zbox">{svg_body}</div>
</section>
<section class="panel" id="p2">
 <div class="filters"><label><input type="checkbox" id="gRisky" checked> only branches that lead to findings</label>
 <input id="gQ" placeholder="find package, e.g. lodash" size="28"><button class="sm" id="gGo">find</button>
 <button class="sm" id="gExpand">expand risky</button><button class="sm" id="gCollapse">collapse all</button><span id="gMsg" class="meta"></span></div>
 <div id="gTree" class="tree"></div>
 <script id="gData" type="application/json">{data}</script>
</section>
<section class="panel" id="p3">
 <div class="filters"><input id="tQ" placeholder="filter…" size="30"><select id="tS"><option value="">all scopes</option><option>prod</option><option>dev</option><option>optional</option><option>build</option><option>ci</option></select>
 <label><input type="checkbox" id="tF"> with findings only</label><span id="tN" class="meta"></span></div>
 <div class="tbl"><table><thead><tr><th data-k="0">package</th><th data-k="1">ecosystem</th><th data-k="2">scope</th><th data-k="3">relation</th><th data-k="4">worst finding</th><th data-k="5">findings</th><th data-k="6">dependencies</th></tr></thead><tbody id="tB"></tbody></table></div>
</section>
</main>
<script>
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.tabs button,.panel').forEach(x=>x.classList.remove('on'));b.classList.add('on');document.getElementById(b.dataset.p).classList.add('on');if(b.dataset.p==='p1')fit();}});
// zoom / pan on the risk SVG
const box=document.getElementById('zbox'), svg=box.querySelector('svg'); let s=1,x=0,y=0,drag=null;
const ap=()=>{{if(svg)svg.style.transform=`translate(${{x}}px,${{y}}px) scale(${{s}})`}};
function fit(){{ if(!svg)return; const w=svg.viewBox.baseVal.width||svg.getBBox().width, h=svg.viewBox.baseVal.height||svg.getBBox().height;
  svg.setAttribute('width',w); svg.setAttribute('height',h); s=Math.min(box.clientWidth/w,box.clientHeight/h)*0.97; x=(box.clientWidth-w*s)/2; y=(box.clientHeight-h*s)/2; ap(); }}
const zoom=(f,cx=box.clientWidth/2,cy=box.clientHeight/2)=>{{x=cx-(cx-x)*f;y=cy-(cy-y)*f;s*=f;ap();}};
box.addEventListener('wheel',ev=>{{ev.preventDefault();const r=box.getBoundingClientRect();zoom(ev.deltaY<0?1.15:1/1.15,ev.clientX-r.left,ev.clientY-r.top);}},{{passive:false}});
box.onmousedown=ev=>{{drag=[ev.clientX-x,ev.clientY-y];box.style.cursor='grabbing'}}; window.onmouseup=()=>{{drag=null;box.style.cursor='grab'}};
window.onmousemove=ev=>{{if(drag){{x=ev.clientX-drag[0];y=ev.clientY-drag[1];ap();}}}};
zin.onclick=()=>zoom(1.25); zout.onclick=()=>zoom(0.8); zfit.onclick=fit; window.onload=fit; window.onresize=fit;
// component table
const ROWS={table}, R={{critical:4,high:3,medium:2,low:1,info:0,'':-1}}; let sk=4, sd=-1;
function tbl(){{ const q=tQ.value.toLowerCase(), sc=tS.value, f=tF.checked;
  let r=ROWS.filter(o=>(!q||o[0].toLowerCase().includes(q))&&(!sc||o[2]===sc)&&(!f||o[5]>0));
  r.sort((a,b)=>{{let A=a[sk],B=b[sk]; if(sk===4){{A=R[A];B=R[B]}} return (A>B?1:A<B?-1:0)*sd;}});
  tN.textContent=` ${{r.length.toLocaleString()}} of ${{ROWS.length.toLocaleString()}}`;
  tB.innerHTML=r.slice(0,2000).map(o=>`<tr><td>${{o[0].replace(/</g,'&lt;')}}</td><td>${{o[1]}}</td><td>${{o[2]}}</td><td>${{o[3]}}</td><td>${{o[4]?`<span class="bdg s-${{o[4]}}">${{o[4]}}</span>`:''}}</td><td>${{o[5]||''}}</td><td>${{o[6]}}</td></tr>`).join(''); }}
document.querySelectorAll('th').forEach(t=>t.onclick=()=>{{const k=+t.dataset.k; sd=(sk===k)?-sd:-1; sk=k; tbl();}});
[tQ,tS,tF].forEach(el=>el.addEventListener('input',tbl)); tbl();
</script>
{GRAPH_JS}
</body></html>'''
    path.write_text(page)
