"""Supply Chain Guardian - web UI.   Run: run-ui.bat  (or .venv\\Scripts\\streamlit run ui\\app.py)"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from collections import deque
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guardian import config  # noqa: E402
from guardian.memory import Memory  # noqa: E402

REPORTS = config.WORKSPACE / "reports"
LEVELS = ["Critical", "High", "Medium", "Low"]
COLOR = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#64748b", None: "#94a3b8"}
RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

AGENTS = [
    ("orchestrator", "🧭", "Orchestrator", "The planner. Picks which two versions to compare, loads memory and approved lessons, runs the canary self-check, then hands work to the other agents."),
    ("discovery-agent", "🔎", "Discovery", "Builds the inventory: every package and version, where it is downloaded from, runtime or dev-only, and who depends on whom (the dependency graph)."),
    ("change-agent", "🔁", "Change", "Compares the new version with the trusted baseline: new, removed and updated packages, look-alike (typosquat) names, changed hashes, new install scripts."),
    ("vulnerability-agent", "🐞", "Vulnerability", "Checks every package against the public OSV vulnerability database and traces each hit back to the direct dependency that pulled it in."),
    ("backdoor-agent", "🕵️", "Backdoor", "Reads only the lines that changed and hunts for hidden tricks: encoded code being run, download-and-run, secret theft, hidden characters, text aimed at AI reviewers."),
    ("ci-container-agent", "⚙️", "Container & CI", "Checks GitHub workflows and Dockerfiles: actions not pinned to a commit, risky workflow settings, untrusted or unpinned base images."),
    ("verifier-agent", "✅", "Verifier", "The sceptic. Re-opens every cited file, line and package to prove the evidence is real, merges duplicates and sets a confidence level."),
    ("evidence-agent", "📊", "Evidence", "Scores every finding (severity × reach × new-since-baseline), explains the score in words, applies approved lessons and asks the AI for a short explanation."),
]

st.set_page_config(page_title="Supply Chain Guardian", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.2rem;}
.hero {background: linear-gradient(90deg,#0f172a,#1e293b); color:#f8fafc; padding:18px 22px; border-radius:14px; margin-bottom:12px}
.hero h1 {font-size:1.6rem; margin:0; color:#f8fafc}
.hero p {margin:4px 0 0 0; color:#cbd5e1; font-size:.92rem}
.verdict {padding:10px 16px; border-radius:10px; font-weight:600; margin:6px 0 12px 0}
.card {border:1px solid rgba(148,163,184,.35); border-radius:12px; padding:14px 16px; height:100%}
.card h4 {margin:0 0 6px 0; font-size:1rem}
.big {font-size:1.9rem; font-weight:700; line-height:1.1}
.muted {color:#94a3b8; font-size:.85rem}
.badge {display:inline-block; padding:2px 9px; border-radius:999px; color:white; font-size:.78rem; font-weight:600; margin-right:6px}
.risk {border-left:5px solid; padding:8px 12px; margin:6px 0; border-radius:8px; background:rgba(148,163,184,.08)}
.agent {border:1px solid rgba(148,163,184,.35); border-radius:12px; padding:12px 14px; margin-bottom:10px}
.agent b {font-size:1rem}
</style>""", unsafe_allow_html=True)


# ============================================================== data helpers
def list_runs() -> list[Path]:
    return sorted(REPORTS.glob("*/*/report.json"), key=lambda p: p.parent.name, reverse=True)


@st.cache_data(show_spinner=False)
def _load(path: str, mtime: float):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def jload(p: Path):
    return _load(str(p), p.stat().st_mtime) if p.exists() else None


def badge(level: str | None, text: str | None = None) -> str:
    return f"<span class='badge' style='background:{COLOR.get(level, '#64748b')}'>{text or level}</span>"


def short(node: str) -> str:
    if node.startswith("app:"):
        return "APP (" + node[4:] + ")"
    return node.split(":", 1)[-1]


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


@st.cache_data(show_spinner=False, ttl=60)
def ai_status(provider: str, model: str, base_url: str) -> tuple[bool, str]:
    try:
        if provider == "openai":
            from guardian import llm
            key = llm._key(os.getenv("GUARDIAN_API_KEY") or os.getenv("OPENAI_API_KEY"))
            if not key:
                return False, "no API key set"
            req = urllib.request.Request(base_url.rstrip("/") + "/models", headers={"Authorization": f"Bearer {key}", "User-Agent": "supply-chain-guardian"})
            with urllib.request.urlopen(req, timeout=4) as r:
                n = len(json.loads(r.read()).get("data", []))
            return True, f"connected · {n} models available"
        if provider == "ollama":
            with urllib.request.urlopen(base_url.rstrip("/") + "/api/tags", timeout=3) as r:
                return True, "connected · " + ", ".join(m["name"] for m in json.loads(r.read()).get("models", [])[:4])
        if provider == "none":
            return False, "AI disabled"
        return True, "configured"
    except Exception as e:  # noqa: BLE001
        return False, f"not reachable ({type(e).__name__})"


# ============================================================== graph helpers
@st.cache_data(show_spinner=False)
def graph_index(graph: dict, roots: dict, comp_level: dict):
    parents: dict[str, list[str]] = {}
    for a, kids in graph.items():
        for k in kids:
            parents.setdefault(k, []).append(a)
    # worst risk and number of risky packages underneath each direct dependency
    direct_info = {}
    for app, direct in roots.items():
        for d in direct:
            seen, q, worst, risky = {d}, deque([d]), comp_level.get(d), 0
            while q and len(seen) < 4000:
                n = q.popleft()
                if n in comp_level:
                    risky += 1
                    if RANK[comp_level[n]] > RANK.get(worst, 0):
                        worst = comp_level[n]
                for c in graph.get(n, []):
                    if c not in seen:
                        seen.add(c); q.append(c)
            direct_info[d] = {"worst": worst, "risky_below": risky, "size": len(seen)}
    return parents, direct_info


def paths_to(target: str, parents: dict, roots: dict, limit: int = 6) -> list[list[str]]:
    rootset = set(roots)
    out, q = [], deque([[target]])
    while q and len(out) < limit:
        path = q.popleft()
        head = path[0]
        if head in rootset:
            out.append(path); continue
        if len(path) > 12:
            continue
        for p in parents.get(head, [])[:6]:
            if p not in path:
                q.append([p] + path)
    return out


def dot(nodes: dict[str, str | None], edges: set, highlight: str | None = None, rankdir="LR") -> str:
    L = [f"digraph G {{ rankdir={rankdir}; bgcolor=transparent; node [shape=box, style=\"rounded,filled\", fontname=Helvetica, fontsize=10, fillcolor=\"#f8fafc\", color=\"#94a3b8\"]; edge [color=\"#94a3b8\", arrowsize=.6];"]
    for n, lvl in nodes.items():
        attrs = []
        if n.startswith("app:"):
            attrs += ['fillcolor="#0f172a"', 'fontcolor="white"', 'color="#0f172a"']
        elif lvl:
            attrs += [f'fillcolor="{COLOR[lvl]}22"', f'color="{COLOR[lvl]}"', "penwidth=2"]
        if n == highlight:
            attrs += ["penwidth=3.5"]
        label = short(n) if not isinstance(lvl, tuple) else lvl[1]
        L.append(f'"{esc(n)}" [label="{esc(label)}", {", ".join(attrs)}];' if attrs else f'"{esc(n)}" [label="{esc(label)}"];')
    for a, b in edges:
        L.append(f'"{esc(a)}" -> "{esc(b)}";')
    L.append("}")
    return "\n".join(L)


def nx_desc(G, n):
    import networkx as nx
    return nx.descendants(G, n)


# ============================================================== sidebar
llm = config.load()["llm"]
ok, ai_msg = ai_status(llm["provider"], llm["model"] or "", llm["base_url"] or "")
with st.sidebar:
    st.markdown("## 🛡️ Supply Chain Guardian")
    st.caption("Know what you build. Trust what you ship.")
    with st.container(border=True):
        st.markdown("**AI in use**")
        via = "FreeLLMAPI router" if "31415" in (llm["base_url"] or "") else llm["provider"]
        st.markdown(f"{'🟢' if ok else '🔴'} `{llm['model']}` via **{via}**")
        st.caption(ai_msg)
    st.markdown("### ▶ New scan")
    repo = st.text_input("Public repo URL or local path", value=st.session_state.get("repo", "https://github.com/juice-shop/juice-shop"))
    base = st.text_input("Baseline (tag/commit)", value=st.session_state.get("base", "v20.0.0"),
                         help="Empty = latest human-approved baseline, else latest release tag")
    head = st.text_input("Head (optional)", value="", help="Empty = default branch")
    use_ai = st.toggle("AI explanations", value=llm["provider"] != "none")
    if st.button("Run Guardian", type="primary", width="stretch"):
        st.session_state.update(repo=repo, base=base)
        log = config.WORKSPACE / f"ui-run-{int(time.time())}.log"
        args = [sys.executable, "-m", "guardian.cli", "scan", repo] + (["--base", base] if base else []) + \
               (["--head", head] if head else []) + ([] if use_ai else ["--no-llm"])
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen(args, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        with st.status("Agents at work...", expanded=True) as box:
            area = st.empty()
            while proc.poll() is None:
                text = log.read_text(encoding="utf-8", errors="replace")
                done = [f"{ic} {nm}" for key, ic, nm, _ in AGENTS if f"[{key}]" in text]
                area.markdown("**Finished:** " + (" → ".join(done) or "starting...") + "\n\n```\n" + "\n".join(text.splitlines()[-6:])[-900:] + "\n```")
                time.sleep(1.2)
            box.update(label="Scan finished" if proc.returncode == 0 else "Scan failed - see log", state="complete" if proc.returncode == 0 else "error")
        st.cache_data.clear()
        st.rerun()
    runs = list_runs()
    st.markdown("### 📂 Reports")
    if not runs:
        st.info("No reports yet. Run a scan.")
        st.stop()
    choice = st.selectbox("Open report", range(len(runs)), label_visibility="collapsed",
                          format_func=lambda i: f"{runs[i].parent.parent.name} · {datetime.strptime(runs[i].parent.name, '%Y%m%d-%H%M%S'):%d %b %H:%M}")

# ============================================================== load report
rdir = runs[choice].parent
r = jload(rdir / "report.json")
inv = jload(rdir / "inventory.json") or {}
decisions = jload(rdir / "decisions.json") or []
s, ch = r["summary"], r.get("change") or {}
findings = r["findings"]
active = [f for f in findings if not f.get("suppressed_by")]
mem = Memory()
labels_db = {row[0]: row[1] for row in mem.db.execute("SELECT id, status FROM findings WHERE project=? AND run_id=?", (r["project"], r["run_id"]))}
comp_level: dict[str, str] = {}
for f in active:
    c = f.get("component", "")
    if c and RANK[f["risk_level"]] > RANK.get(comp_level.get(c), 0):
        comp_level[c] = f["risk_level"]
models_used = {}
for f in findings:
    for a in f.get("ai_inference", []):
        served = a["text"].split("(served by ")[-1].rstrip(")") if "(served by " in a["text"] else a["model"]
        models_used[served] = models_used.get(served, 0) + 1

# ============================================================== header
st.markdown(f"""<div class='hero'><h1>{r['project']}</h1>
<p>Compared <b>{r.get('base_ref') or 'no baseline'}</b> → <b>{r['head_ref']}</b>
({(r.get('head_commit') or {}).get('sha', '')[:10]}, {(r.get('head_commit') or {}).get('date', '')[:16]})
· scan took {s['seconds']} s · {len(decisions)} logged decisions</p></div>""", unsafe_allow_html=True)
lv = s["by_level"]
if lv["Critical"]:
    st.markdown(f"<div class='verdict' style='background:#dc262622;border:1px solid #dc2626'>🚨 Needs attention: {lv['Critical']} critical and {lv['High']} high risks found</div>", unsafe_allow_html=True)
elif lv["High"]:
    st.markdown(f"<div class='verdict' style='background:#ea580c22;border:1px solid #ea580c'>⚠️ Review: {lv['High']} high risks found</div>", unsafe_allow_html=True)
else:
    st.markdown("<div class='verdict' style='background:#16a34a22;border:1px solid #16a34a'>✅ No critical or high risks found</div>", unsafe_allow_html=True)
if r.get("agent_summary"):
    st.info(f"**Lead agent summary** (AI inference, not evidence): {r['agent_summary']}")
for x in r.get("skipped", []):
    st.warning(f"Not run this time: {x}")

tabs = st.tabs(["🏠 Overview", "🕸️ Dependency graph", "🚨 Risks", "🔁 What changed", "🤖 Agents & AI", "🧑‍⚖️ Human review", "🔧 Fix & verify", "🧾 Audit & exports"])

# ============================================================== 1. overview
with tabs[0]:
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""<div class='card'><h4>📦 What is in it</h4><div class='big'>{s['packages']}</div>
        <div class='muted'>packages · {s['direct']} direct · {s['runtime']} runtime · {s['dev']} dev-only</div>
        <div class='muted'>{', '.join(s['ecosystems'])} · {s['workflow_steps']} CI steps · {s['images']} base images</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='card'><h4>🔁 What changed</h4><div class='big'>{ch.get('added_count', 0)} / {ch.get('removed_count', 0)} / {ch.get('updated_count', 0)}</div>
        <div class='muted'>packages added / removed / updated</div>
        <div class='muted'>{(r.get('backdoor_stats') or {}).get('files_changed', 0)} files changed · {len((r.get('backdoor_stats') or {}).get('build_files_changed', []))} build files</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='card'><h4>🚨 What appears risky</h4><div class='big'>{s['findings']}</div>
        <div>{''.join(badge(l, f"{lv[l]} {l}") for l in LEVELS)}</div>
        <div class='muted'>every finding carries verified evidence</div></div>""", unsafe_allow_html=True)
    st.markdown("#### Top risks")
    for f in active[:6]:
        ai = f["ai_inference"][0]["text"].split("\n(served by")[0] if f.get("ai_inference") else ""
        path = " → ".join(short(x) for x in (f.get("dependency_paths") or [[]])[0])
        st.markdown(f"""<div class='risk' style='border-color:{COLOR[f['risk_level']]}'>{badge(f['risk_level'], f"{f['risk_level']} {f['score']}")}
        <b>{f['title'][:120]}</b><br><span class='muted'>{f['detector']} · confidence {f.get('confidence')}{' · path: ' + path if path else ''}</span>
        {'<br>🤖 <i>' + (ai if len(ai) <= 320 else ai[:320].rsplit(' ', 1)[0] + '…') + '</i>' if ai else ''}</div>""", unsafe_allow_html=True)
    st.caption("Detector self-check: " + " ".join(("✅" if x["caught"] else "❌") + " " + x["detector"] for x in r.get("canary", [])))

# ============================================================== 2. dependency graph
with tabs[1]:
    from graphview import LEGEND, analytics, build, render, risk_subgraph, trace_subgraph

    if not inv.get("graph"):
        st.warning("This report was made before the dependency graph was saved. Run a new scan to explore the full graph.")
    else:
        titles: dict[str, list[str]] = {}
        for f in active:
            if f.get("component"):
                titles.setdefault(f["component"], []).append(f"{f['risk_level']}: {f['title']}")

        @st.cache_resource(show_spinner="Building the dependency network...")
        def _net(run_id: str):
            G = build(inv, comp_level, titles)
            return G, analytics(G)

        G, A = _net(r["run_id"])
        m = st.columns(5)
        m[0].metric("Packages (nodes)", G.number_of_nodes() - sum(1 for _, d in G.nodes(data=True) if d.get("kind") == "app"))
        m[1].metric("Dependency links (edges)", G.number_of_edges())
        m[2].metric("Direct dependencies", sum(1 for _, d in G.nodes(data=True) if d.get("kind") == "direct"))
        m[3].metric("Deepest chain", f"{A['max_depth']} levels")
        m[4].metric("Packages with findings", A["risky"])

        view = st.radio("View", ["How risk enters the app", "Trace one package", "Whole dependency network"], horizontal=True)
        st.markdown(LEGEND, unsafe_allow_html=True)
        if view == "How risk enters the app":
            lv = st.multiselect("Show packages with these risk levels", ["Critical", "High", "Medium", "Low"], default=["Critical", "High"])
            H = risk_subgraph(G, set(lv))
            st.caption(f"{H.number_of_nodes()} packages: every route from your app to each risky package (NetworkX shortest paths).")
            st.iframe(render(H), height=660)
            c1, c2 = st.columns([3, 2])
            c1.markdown("**Blast radius of each direct dependency** (NetworkX descendants)")
            c1.dataframe(pd.DataFrame(A["blast"]), hide_index=True, width="stretch", height=300)
            c2.markdown("**Most depended-on packages** (in-degree)")
            c2.dataframe(pd.DataFrame(A["most_used"]), hide_index=True, width="stretch", height=300)
        elif view == "Trace one package":
            order = sorted((n for n, d in G.nodes(data=True) if d.get("kind") != "app"),
                           key=lambda n: (-RANK.get(G.nodes[n].get("risk"), 0), n))
            target = st.selectbox("Package (risky ones first)", order,
                                  format_func=lambda n: (f"● {G.nodes[n]['risk']} · " if G.nodes[n].get("risk") else "") + short(n))
            H, ps = trace_subgraph(G, target)
            st.iframe(render(H, highlight=target, hierarchical=True, height=520), height=540)
            d = G.nodes[target]
            st.markdown(f"**{short(target)}** · {d.get('kind')} · scope **{d.get('scope')}** · from `{d.get('origin') or 'n/a'}` · "
                        f"install script **{'yes' if d.get('install_script') else 'no'}** · used by {G.in_degree(target)} packages · "
                        f"pulls in {len(nx_desc(G, target))} packages")
            st.markdown(f"**{len(ps)} route(s) from your app:**")
            for p in ps:
                st.markdown("- " + " → ".join(f"`{short(x)}`" for x in p))
            for t in d.get("findings", []):
                st.markdown(f"- 🚨 {t}")
        else:
            st.caption("All packages and links. Large graphs take a few seconds to settle; zoom in on a cluster and hover the dots.")
            st.iframe(render(G, height=760), height=780)

# ============================================================== 3. risks
with tabs[2]:
    f1, f2, f3 = st.columns([2, 2, 3])
    lvsel = f1.multiselect("Risk level", LEVELS, default=["Critical", "High", "Medium"])
    cats = sorted({f["category"] for f in active})
    csel = f2.multiselect("Category", cats, default=cats)
    q = f3.text_input("Search", "", placeholder="package, CVE, file...")
    view = [f for f in active if f["risk_level"] in lvsel and f["category"] in csel and (q.lower() in (f["title"] + f.get("component", "")).lower())]
    st.dataframe(pd.DataFrame([{"risk": f["risk_level"], "score": f["score"], "finding": f["title"], "category": f["category"],
                                "confidence": f.get("confidence"), "detector": f["detector"], "status": labels_db.get(f["id"], "open"),
                                "AI": "🤖" if f.get("ai_inference") else "", "id": f["id"]} for f in view]),
                 hide_index=True, width="stretch", height=320,
                 column_config={"score": st.column_config.ProgressColumn("score", min_value=0, max_value=10, format="%.1f")})
    if view:
        sel = st.selectbox("Open evidence for", range(len(view)), format_func=lambda i: f"{view[i]['risk_level']} · {view[i]['title'][:110]}")
        f = view[sel]
        with st.container(border=True):
            st.markdown(f"{badge(f['risk_level'], f['risk_level'] + ' ' + str(f['score']))} **{f['title']}**", unsafe_allow_html=True)
            a, b = st.columns(2)
            a.markdown(f"**Why this score:** {f['score_explanation']}")
            b.markdown(f"**Confidence:** {f.get('confidence')} — {f.get('confidence_reason', '')}")
            st.markdown(f"**Component:** `{f.get('component', '')}` · **Change:** {f.get('change') or 'n/a'} · **Found by:** {f['detector']}")
            for p in (f.get("dependency_paths") or [])[:3]:
                st.markdown("**Path:** " + " → ".join(f"`{short(x)}`" for x in p))
            st.markdown("**✔ Verified evidence** (from tools, re-checked by the Verifier)")
            for e in f["verified_evidence"]:
                st.markdown(f"- {e}")
            for ai in f.get("ai_inference", []):
                st.info(f"🤖 **AI explanation — not evidence** ({ai['model']}):\n\n{ai['text']}")
            st.success(f"**Suggested action:** {f.get('recommendation', '')}")
            why = [d for d in decisions if f["id"] in (d.get("decision", "") + d.get("inputs", ""))]
            if why:
                with st.expander(f"Why? Decision chain ({len(why)})"):
                    st.dataframe(pd.DataFrame(why)[["actor", "decision", "why", "rule"]], hide_index=True, width="stretch")

# ============================================================== 4. changes
with tabs[3]:
    if not ch:
        st.info("No baseline was compared in this run.")
    else:
        bs = r.get("backdoor_stats") or {}
        m = st.columns(5)
        m[0].metric("Added", ch.get("added_count", 0)); m[1].metric("Removed", ch.get("removed_count", 0))
        m[2].metric("Updated", ch.get("updated_count", 0)); m[3].metric("Files changed", bs.get("files_changed", 0))
        m[4].metric("Build files changed", len(bs.get("build_files_changed", [])))
        c1, c2 = st.columns(2)
        c1.markdown("**New packages**"); c1.dataframe(pd.DataFrame({"package": ch.get("new_names", [])}), hide_index=True, width="stretch", height=240)
        c2.markdown("**Version updates**"); c2.dataframe(pd.DataFrame({"update": ch.get("updated", [])}), hide_index=True, width="stretch", height=240)
        c1.markdown("**Build files changed**"); c1.write(bs.get("build_files_changed") or "none")
        c2.markdown("**CI / image changes**"); c2.write((ch.get("workflow_changes") or []) + (ch.get("image_changes") or []) or "none")
        chf = [f for f in active if f.get("change")]
        st.markdown(f"**{len(chf)} findings are linked to a change since the baseline**")
        st.dataframe(pd.DataFrame([{"risk": f["risk_level"], "score": f["score"], "finding": f["title"], "change": f["change"]} for f in chf]),
                     hide_index=True, width="stretch")

# ============================================================== 5. agents
with tabs[4]:
    st.markdown("#### How the Guardian works")
    counts = {key: sum(1 for d in decisions if d["actor"] == key) for key, *_ in AGENTS}
    flow = f"""digraph A {{ rankdir=LR; bgcolor=transparent; node [shape=box, style="rounded,filled", fillcolor="#f1f5f9", fontname=Helvetica, fontsize=11, color="#64748b"];
    repo [label="📁 Repo\\n{esc(r['project'])}", fillcolor="#0f172a", fontcolor=white];
    mem [label="🧠 Memory\\nbaseline · lessons · audit log", shape=cylinder, fillcolor="#e0e7ff"];
    orch [label="🧭 Orchestrator\\nplan + canary"]; disc [label="🔎 Discovery\\n{s['packages']} packages"];
    chg [label="🔁 Change\\n{ch.get('added_count', 0)} added"]; vul [label="🐞 Vulnerability\\n{sum(1 for f in active if f['type'] == 'known_vulnerability')} CVEs"];
    bd [label="🕵️ Backdoor\\n{sum(1 for f in active if f['category'] == 'backdoor signal')} signals"]; ci [label="⚙️ Container & CI\\n{sum(1 for f in active if f['category'] == 'CI-container')} issues"];
    ver [label="✅ Verifier\\nre-checks evidence"]; ev [label="📊 Evidence + 🤖 AI\\nscore & explain"];
    hum [label="🧑‍⚖️ Human\\nlabel · approve", fillcolor="#dcfce7"]; rep [label="📄 Report", fillcolor="#fef9c3"];
    repo -> orch; mem -> orch; orch -> disc; disc -> chg; disc -> vul; disc -> bd; disc -> ci; chg -> ver; vul -> ver; bd -> ver; ci -> ver;
    ver -> ev -> rep -> hum; hum -> mem [label="lessons, baselines", fontsize=9, style=dashed]; }}"""
    st.graphviz_chart(flow, width="stretch")
    st.caption("Change, Vulnerability, Backdoor and Container & CI run in parallel. The AI only explains; every finding comes from tools and is re-checked by the Verifier.")
    times = {}
    for d in decisions:
        times.setdefault(d["actor"], []).append(d["ts"])
    cols = st.columns(2)
    for i, (key, icon, name, desc) in enumerate(AGENTS):
        mine = [d for d in decisions if d["actor"] == key]
        with cols[i % 2]:
            st.markdown(f"<div class='agent'><b>{icon} {name} agent</b><br><span class='muted'>{desc}</span></div>", unsafe_allow_html=True)
            with st.expander(f"What it did in this run ({len(mine)} decisions)"):
                for d in mine[:12]:
                    st.markdown(f"- **{d['decision'][:110]}** — {d['why'][:160]}")
    st.markdown("#### AI model")
    st.markdown(f"Configured: `{llm['model']}` via **{via}** ({'🟢 ' if ok else '🔴 '}{ai_msg}).")
    if models_used:
        st.markdown("Models that actually answered in this report: " + ", ".join(f"**{m}** ×{n}" for m, n in models_used.items()))
    st.caption("AI answers are stored as 'AI inference' with the model name and a prompt fingerprint. They never count as evidence and never change a score.")

# ============================================================== 6. human review
with tabs[5]:
    c1, c2 = st.columns(2)
    with c1, st.form("label"):
        st.markdown("**Label a finding**")
        fid = st.selectbox("Finding", [f["id"] for f in active], format_func=lambda i: next(f"{f['risk_level']} · {f['title'][:80]}" for f in active if f["id"] == i))
        stt = st.radio("Status", ["confirmed", "false_positive", "accepted", "open"], horizontal=True)
        who = st.text_input("Your name"); why = st.text_input("Reason (required)")
        if st.form_submit_button("Save label", type="primary"):
            try:
                mem.label(r["project"], fid, stt, who, why); st.success("Saved and written to the audit log.")
            except Exception as e:  # noqa: BLE001
                st.error(str(e))
    with c2, st.form("lesson"):
        st.markdown("**Teach a lesson** (scoped suppression, expires)")
        rule = st.text_input("Finding type or rule", placeholder="e.g. unpinned_image")
        scope = st.text_input("Scope glob", placeholder="e.g. test/*")
        who3 = st.text_input("Your name", key="l2"); why3 = st.text_input("Reason (required)", key="l3")
        days = st.number_input("Expires after (days)", 1, 365, 30)
        if st.form_submit_button("Save lesson"):
            try:
                mem.add_lesson(r["project"], "suppress", rule, scope, why3, who3, int(days)); st.success("Lesson saved; applies from the next scan.")
            except Exception as e:  # noqa: BLE001
                st.error(str(e))
    with st.form("baseline"):
        st.markdown("**Approve a trusted baseline** — future scans compare against it")
        ref = st.text_input("Ref to trust", value=r.get("head_ref", ""))
        who2 = st.text_input("Your name", key="b2"); why2 = st.text_input("Reason (required)", key="b3")
        if st.form_submit_button("Approve baseline"):
            open_crit = [f for f in active if f["risk_level"] == "Critical" and labels_db.get(f["id"], "open") == "open"]
            if open_crit:
                st.error(f"Blocked by guardrail: {len(open_crit)} Critical findings are still open. Label them first.")
            else:
                try:
                    from guardian.agents import discovery
                    from guardian.tools import git
                    d = git.checkout(config.WORKSPACE / "repos" / r["project"], ref, config.WORKSPACE / "checkouts" / r["project"] / ref.replace("/", "_"))
                    mem.approve_baseline(r["project"], ref, discovery.snapshot(d, run_syft=False), who2, why2)
                    st.success(f"Baseline {ref} approved.")
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))
    les = mem.active_lessons(r["project"])
    if les:
        st.dataframe(pd.DataFrame(les), hide_index=True, width="stretch")

# ============================================================== 7. fix & verify (Day 2)
VERDICT_UI = {"verified": ("#16a34a", "✅ VERIFIED"), "verified-with-gaps": ("#ca8a04", "🟡 VERIFIED WITH GAPS"), "not-verified": ("#dc2626", "❌ NOT VERIFIED")}


def show_result(res: dict):
    col, label = VERDICT_UI[res["verdict"]]
    st.markdown(f"<div class='verdict' style='background:{col}22;border:1px solid {col}'>{label} — {res['verdict_reason']}</div>", unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(res["steps"]), hide_index=True, width="stretch")
    if res.get("before"):
        b, a = res["before"], res["after"]
        m = st.columns(4)
        m[0].metric("Known vulnerabilities", a["count"], a["count"] - b["count"], delta_color="inverse")
        m[1].metric("Critical", a["known_vulnerabilities"]["Critical"], a["known_vulnerabilities"]["Critical"] - b["known_vulnerabilities"]["Critical"], delta_color="inverse")
        m[2].metric("Packages", a["packages"], a["packages"] - b["packages"], delta_color="off")
        m[3].metric("Newly introduced", len(res["introduced"]))
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Resolved**")
            for x in res["resolved"][:12]:
                st.markdown(f"{badge(x['risk_level'])} {x['id']} — {x['title'][:70]}", unsafe_allow_html=True)
            if res["remaining"]:
                st.markdown("**Still present**")
                for x in res["remaining"][:8]:
                    st.markdown(f"{badge(x['risk_level'])} {x['id']} — {x['title'][:70]}", unsafe_allow_html=True)
        with c2:
            st.markdown("**Newly introduced by the fix**" if res["introduced"] else "**Nothing new introduced**")
            for x in res["introduced"][:12]:
                st.markdown(f"{badge(x['risk_level'])} {x['id']} — {x['title'][:70]}", unsafe_allow_html=True)
        d = res["sbom_diff"]
        with st.expander(f"SBOM diff: {len(d['updated'])} updated, {len(d['added'])} added, {len(d['removed'])} removed"):
            st.code("\n".join([f"~ {x}" for x in d["updated"]] + [f"+ {x}" for x in d["added"]] + [f"- {x}" for x in d["removed"]]) or "no change")
    rd = Path(res.get("report_dir", ""))
    cols = st.columns(4)
    for i, (nm, mime) in enumerate([("remediation.html", "text/html"), ("remediation.md", "text/markdown"), ("remediation.json", "application/json"), ("patch.diff", "text/plain")]):
        if (rd / nm).exists():
            cols[i].download_button(nm, (rd / nm).read_bytes(), file_name=nm, mime=mime, key=f"dl-{res['proposal']['id']}-{nm}", width="stretch")
    st.caption(f"Local sandbox branch `{res['branch']}` — nothing was merged, pushed or deployed. Folder: {rd}")


with tabs[6]:
    from guardian import remediate  # noqa: E402
    st.markdown("**From detection to a verified fix.** The Fix agent proposes → **a named human approves** → the Validation agent builds and tests it in a "
                "Docker sandbox → rescan and before/after comparison. Nothing is merged, pushed or deployed.")
    cand = sorted((f for f in active if f["type"] == "known_vulnerability"), key=lambda f: -f["score"])
    if not cand:
        st.info("No known-vulnerability findings in this run, so there is nothing the Fix agent can propose.")
    else:
        c1, c2 = st.columns([4, 1])
        fix_id = c1.selectbox("1 · Pick a finding", [f["id"] for f in cand], format_func=lambda i: next(f"{f['risk_level']} {f['score']} · {f['title'][:90]}" for f in cand if f["id"] == i))
        if c2.button("Propose fix", type="primary", width="stretch"):
            pr = remediate.propose(mem, r["project"], fix_id, r["run_id"], log=lambda m: None)
            (st.success if pr["ok"] else st.warning)(f"Proposal {pr['id']} created" if pr["ok"] else f"No automatic fix: {pr['reason']}")
    for p in mem.list_proposals(r["project"], r["run_id"]):
        icon = {"proposed": "📝", "approved": "👍", "rejected": "🚫"}[p["status"]]
        done = (p.get("result") or {}).get("verdict")
        with st.expander(f"{icon} {p['id']} · {p['package']} {p['from']} → {p['to']} · {p['status']}" + (f" · {VERDICT_UI[done][1]}" if done else ""), expanded=p["status"] != "rejected" and not done):
            st.markdown(f"**Change:** `{p['change']}`  \n**Resolves:** {len(p['resolves'])} finding(s) — {p['expected_risk_reduction']['levels']}, score {p['expected_risk_reduction']['score_removed']}  \n"
                        f"**Compatibility:** {p['compatibility_note']}  \n**Rollback:** {p['rollback']}")
            if p["status"] == "proposed":
                with st.form(f"appr-{p['id']}"):
                    st.markdown("**2 · Human approval** (required before anything is built or tested)")
                    who = st.text_input("Your name", key=f"w-{p['id']}"); why = st.text_input("Reason (required)", key=f"y-{p['id']}")
                    ca, cr = st.columns(2)
                    ok_, no_ = ca.form_submit_button("Approve", type="primary"), cr.form_submit_button("Reject")
                    if ok_ or no_:
                        try:
                            mem.decide_proposal(p["id"], "approved" if ok_ else "rejected", who, why)
                            st.rerun()
                        except ValueError as e:
                            st.error(str(e))
            else:
                st.caption(f"{p['status'].title()} by **{p['decided_by']}**: {p['decided_reason']}")
            if p["status"] == "approved":
                test_cmd = st.text_input("Project test command to run in the sandbox (optional, e.g. `npm test`)", key=f"t-{p['id']}",
                                         help="Without it the verdict is capped at 'verified with gaps'.")
                if st.button("3 · Validate in sandbox", key=f"v-{p['id']}", type="primary"):
                    log = config.WORKSPACE / f"ui-validate-{int(time.time())}.log"
                    args = [sys.executable, "-m", "guardian.cli", "validate", p["id"]] + (["--test", test_cmd] if test_cmd else [])
                    with open(log, "w", encoding="utf-8") as fh:
                        proc = subprocess.Popen(args, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, env={**os.environ, "PYTHONUNBUFFERED": "1"})
                    with st.status("Validation agent at work (docker build can take a few minutes)...", expanded=True) as box:
                        area = st.empty()
                        while proc.poll() is None:
                            area.code("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-8:])[-1200:])
                            time.sleep(1.5)
                        box.update(label="Validation finished" if proc.returncode in (0, 1) else "Validation crashed - see log",
                                   state="complete" if proc.returncode in (0, 1) else "error")
                    st.rerun()
            if p.get("result"):
                st.markdown("**4 · Result**")
                show_result(p["result"])
                with st.expander("Responsible AI note"):
                    st.markdown(remediate.RESPONSIBLE_AI)

# ============================================================== 8. audit & exports
with tabs[7]:
    st.markdown("**Detector self-check (canary)** — each detector must catch a planted sample before the scan counts")
    st.markdown(" ".join(("✅ " if x["caught"] else "❌ ") + f"`{x['detector']}`" for x in r.get("canary", [])))
    st.markdown("**Append-only decision log**")
    if decisions:
        st.dataframe(pd.DataFrame(decisions)[["seq", "actor", "decision", "why", "rule", "confidence"]], hide_index=True, width="stretch", height=380)
    cols = st.columns(6)
    for i, (name, mime) in enumerate([("report.html", "text/html"), ("report.md", "text/markdown"), ("report.json", "application/json"),
                                      ("sbom.cdx.json", "application/json"), ("inventory.json", "application/json"), ("decisions.json", "application/json")]):
        p = rdir / name
        if p.exists():
            cols[i].download_button(name, p.read_bytes(), file_name=name, mime=mime, key=name, width="stretch")
    st.caption(f"Folder: {rdir}")
