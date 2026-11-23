"""Dependency graph: NetworkX model + analytics, rendered as an interactive pyvis (vis.js) network."""
from __future__ import annotations

import html
import json

import networkx as nx
from pyvis.network import Network

COLOR = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#64748b"}
RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def short(n: str) -> str:
    return "YOUR APP" if n.startswith("app:") else n.split(":", 1)[-1]


def build(inv: dict, comp_level: dict, comp_titles: dict) -> nx.DiGraph:
    """Whole dependency graph: app roots -> direct deps -> transitive deps, with risk and package facts on each node."""
    G = nx.DiGraph()
    pk = inv.get("packages", {})
    direct = {d for v in inv.get("roots", {}).values() for d in v}
    for app in inv.get("roots", {}):
        G.add_node(app, kind="app", label="YOUR APP", detail=app[4:])
    for k, p in pk.items():
        G.add_node(k, kind="direct" if k in direct else "transitive", label=short(k), risk=comp_level.get(k),
                   scope=p.get("scope"), origin=p.get("origin_host", ""), install_script=bool(p.get("install_script")),
                   findings=comp_titles.get(k, []))
    for a, kids in inv.get("graph", {}).items():
        for b in kids:
            G.add_edge(a, b)
    return G


def analytics(G: nx.DiGraph) -> dict:
    """Graph facts for the side panel: how deep the tree is, who is depended on most, and each direct dep's blast radius."""
    apps = [n for n, d in G.nodes(data=True) if d.get("kind") == "app"]
    depth = {}
    for a in apps:
        for n, dist in nx.single_source_shortest_path_length(G, a).items():
            depth[n] = min(depth.get(n, 99), dist)
    risky = [n for n, d in G.nodes(data=True) if d.get("risk")]
    blast = []
    for a in apps:
        for d in G.successors(a):
            below = nx.descendants(G, d) | {d}
            bad = [n for n in below if G.nodes[n].get("risk")]
            worst = max((G.nodes[n]["risk"] for n in bad), key=lambda r: RANK[r], default=None)
            blast.append({"direct dependency": short(d), "packages pulled in": len(below), "risky packages": len(bad), "worst risk": worst})
    indeg = sorted(((n, G.in_degree(n)) for n in G if G.nodes[n].get("kind") != "app"), key=lambda x: -x[1])[:10]
    return {"max_depth": max(depth.values(), default=0), "reachable": len(depth), "risky": len(risky),
            "blast": sorted(blast, key=lambda x: (-RANK.get(x["worst risk"], 0), -x["risky packages"], -x["packages pulled in"])),
            "most_used": [{"package": short(n), "used by (packages)": d} for n, d in indeg]}


def risk_subgraph(G: nx.DiGraph, levels: set[str], limit: int = 220) -> nx.DiGraph:
    """Every shortest path from the app to every risky package: shows exactly how risk enters the application."""
    apps = [n for n, d in G.nodes(data=True) if d.get("kind") == "app"]
    targets = sorted((n for n, d in G.nodes(data=True) if d.get("risk") in levels), key=lambda n: -RANK[G.nodes[n]["risk"]])
    keep = set(apps)
    for t in targets:
        for a in apps:
            try:
                keep.update(nx.shortest_path(G, a, t))
            except nx.NetworkXNoPath:
                continue
        if len(keep) >= limit:
            break
    return G.subgraph(keep).copy()


def trace_subgraph(G: nx.DiGraph, target: str, max_paths: int = 8, children: int = 15) -> tuple[nx.DiGraph, list[list[str]]]:
    """Who pulls `target` in (up to max_paths distinct paths from the app) and what it pulls in."""
    apps = [n for n, d in G.nodes(data=True) if d.get("kind") == "app"]
    paths = []
    for a in apps:
        try:
            for p in nx.all_shortest_paths(G, a, target):
                paths.append(p)
                if len(paths) >= max_paths:
                    break
        except nx.NetworkXNoPath:
            continue
    # also add other routes through different direct dependencies (not only the shortest)
    anc = nx.ancestors(G, target)
    for a in apps:
        for d in G.successors(a):
            if d in anc and not any(len(p) > 1 and p[1] == d for p in paths) and len(paths) < max_paths:
                try:
                    paths.append([a] + nx.shortest_path(G, d, target))
                except nx.NetworkXNoPath:
                    pass
    keep = {n for p in paths for n in p} | {target} | set(list(G.successors(target))[:children])
    return G.subgraph(keep).copy(), paths


def _tooltip(n: str, d: dict) -> str:
    if d.get("kind") == "app":
        return f"Your application ({d.get('detail', '')})"
    lines = [short(n), f"{d.get('kind')} dependency · scope {d.get('scope')}", f"from: {d.get('origin') or 'n/a'}"]
    if d.get("install_script"):
        lines.append("runs an install script")
    lines += [f"• {t[:90]}" for t in d.get("findings", [])[:4]]
    return "\n".join(lines)   # vis.js shows plain-text titles safely


def render(H: nx.DiGraph, highlight: str | None = None, hierarchical: bool = False, height: int = 640) -> str:
    net = Network(height=f"{height}px", width="100%", directed=True, bgcolor="#0b1220", font_color="#e2e8f0", cdn_resources="in_line")
    for n, d in H.nodes(data=True):
        kind, risk = d.get("kind"), d.get("risk")
        if kind == "app":
            net.add_node(n, label="YOUR APP", title=_tooltip(n, d), shape="star", size=38, color="#38bdf8",
                         font={"size": 18, "color": "#f8fafc", "face": "Segoe UI"})
            continue
        size = 10 + (8 if kind == "direct" else 0) + (RANK.get(risk, 0) * 3)
        col = COLOR.get(risk, "#475569")
        node = dict(label=d.get("label", short(n)), title=_tooltip(n, d), size=size, shape="dot",
                    color={"background": col, "border": "#f8fafc" if n == highlight else col,
                           "highlight": {"background": "#38bdf8", "border": "#f8fafc"}},
                    borderWidth=4 if n == highlight else (2 if kind == "direct" else 1),
                    font={"size": 13 if (risk or kind == "direct") else 10, "color": "#e2e8f0", "face": "Segoe UI"})
        if d.get("scope") == "dev":
            node["shapeProperties"] = {"borderDashes": [4, 3]}
        net.add_node(n, **node)
    for a, b in H.edges():
        hot = H.nodes[b].get("risk")
        net.add_edge(a, b, color=COLOR.get(hot, "#334155") if hot else "#334155", width=2 if hot else 1, arrows="to")
    opts = {
        "interaction": {"hover": True, "tooltipDelay": 80, "navigationButtons": True, "keyboard": True},
        "edges": {"smooth": {"type": "continuous"}, "arrows": {"to": {"scaleFactor": 0.5}}},
        "physics": {"solver": "forceAtlas2Based", "forceAtlas2Based": {"gravitationalConstant": -60, "springLength": 110, "avoidOverlap": 0.6},
                    "stabilization": {"iterations": 250}},
    }
    if hierarchical:
        opts["layout"] = {"hierarchical": {"enabled": True, "direction": "LR", "sortMethod": "directed", "levelSeparation": 220, "nodeSpacing": 70}}
        opts["physics"] = {"enabled": False}
    net.set_options(json.dumps(opts))
    return net.generate_html(notebook=False)


LEGEND = (
    "<div style='display:flex;gap:14px;flex-wrap:wrap;font-size:.85rem;margin:4px 0 8px 0'>"
    "<span>★ <b style='color:#38bdf8'>your app</b></span>"
    + "".join(f"<span><span style='display:inline-block;width:11px;height:11px;border-radius:50%;background:{c};margin-right:4px'></span>{html.escape(k)}</span>" for k, c in COLOR.items())
    + "<span><span style='display:inline-block;width:11px;height:11px;border-radius:50%;background:#475569;margin-right:4px'></span>no finding</span>"
    "<span>bigger dot = direct dependency / higher risk · dashed = dev-only · hover for details · drag, scroll to zoom</span></div>")
