"""Dependency-graph views that humans can read.

* risk subgraph: only the paths root -> components with findings, coloured by worst severity
  (DOT + SVG via Graphviz when installed). This is the "where does the risk come from" picture.
* graph data for the interactive tree in report.html (all nodes, edges, per-node severity,
  and whether a node has risk somewhere below it).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from .models import Finding, Inventory, ROOT_ID, SEVERITY_ORDER

COLORS = {"critical": "#b3261e", "high": "#d9480f", "medium": "#e0a800", "low": "#6c9bd2", "info": "#c4c9d0"}
FILL = {"critical": "#f9dedc", "high": "#ffe8d9", "medium": "#fff4cc", "low": "#e3edf9", "info": "#f3f4f6"}


def node_severity(findings: List[Finding]) -> Dict[str, dict]:
    """component id -> {"sev": worst severity, "n": count, "titles": [...]}"""
    out: Dict[str, dict] = {}
    for f in findings:
        cid = (f.component or {}).get("id")
        if not cid:
            continue
        e = out.setdefault(cid, {"sev": "info", "n": 0, "titles": []})
        e["n"] += 1
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[e["sev"]]:
            e["sev"] = f.severity
        if len(e["titles"]) < 6:
            e["titles"].append(f"[{f.severity}] {f.title}")
    return out


def risk_subgraph_dot(inv: Inventory, findings: List[Finding], min_sev: str = "high", max_paths: int = 3) -> str:
    sev = node_severity([f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]])
    nodes, edges = {ROOT_ID}, set()
    for cid in sev:
        if cid not in inv.components:
            continue
        paths = inv.paths_to(cid, limit=max_paths)
        if not paths and inv.components[cid]:
            nodes.add(cid)       # orphan: show it unattached, that is the point
            continue
        for p in paths:
            nodes.update(p)
            edges.update(zip(p, p[1:]))

    def q(s):
        return '"' + str(s).replace('"', '\\"') + '"'
    lines = ["digraph risk {",
             '  rankdir=LR; graph [fontname="Helvetica", fontsize=11, nodesep=0.25, ranksep=0.6, '
             f'label="Risk paths: {inv.project} (findings >= {min_sev})", labelloc=t];',
             '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fillcolor=white, color="#9aa1a9"];',
             '  edge [color="#9aa1a9", arrowsize=0.6];',
             f'  {q(ROOT_ID)} [label={q(inv.project)}, fillcolor="#0f2537", fontcolor=white, color="#0f2537"];']
    for n in sorted(nodes - {ROOT_ID}):
        c = inv.components.get(n)
        if not c:
            continue
        label = f"{c.name}@{c.version}"
        attrs = []
        if n in sev:
            s = sev[n]
            label += f"\\n{s['n']} finding{'s' if s['n'] > 1 else ''} · {s['sev']}"
            attrs += [f'fillcolor="{FILL[s["sev"]]}"', f'color="{COLORS[s["sev"]]}"', "penwidth=2"]
            attrs.append(f"tooltip={q(chr(10).join(s['titles']))}")
        if c.scope != "prod":
            attrs.append('style="rounded,filled,dashed"')
            label += f"\\n({c.scope})"
        if c.ecosystem in ("docker", "github-actions"):
            attrs.append("shape=component")
        lines.append(f"  {q(n)} [label={q(label)}{', ' + ', '.join(attrs) if attrs else ''}];")
    for a, b in sorted(edges):
        col = COLORS[sev[b]["sev"]] if b in sev else "#9aa1a9"
        lines.append(f'  {q(a)} -> {q(b)} [color="{col}"];')
    lines += ['  subgraph cluster_legend { label="legend"; fontsize=9; color="#dddddd";',
              *[f'    "lg_{k}" [label="{k}", fillcolor="{FILL[k]}", color="{COLORS[k]}", penwidth=2, fontsize=9];'
                for k in ("critical", "high", "medium")],
              '    "lg_dev" [label="dev / build / ci scope", style="rounded,dashed", fontsize=9]; }', "}"]
    return "\n".join(lines)


def render_svg(dot_text: str, out: Path) -> Optional[Path]:
    exe = shutil.which("dot")
    if not exe:
        return None
    try:
        subprocess.run([exe, "-Tsvg", "-o", str(out)], input=dot_text.encode(), check=True, timeout=120,
                       capture_output=True)
        return out
    except (subprocess.SubprocessError, OSError):
        return None


def tree_data(inv: Inventory, findings: List[Finding]) -> dict:
    """Compact graph for the interactive tree: index-based to keep the HTML small."""
    sev = node_severity(findings)
    ids = [ROOT_ID] + sorted(inv.components)
    idx = {cid: i for i, cid in enumerate(ids)}
    nodes = []
    for cid in ids:
        if cid == ROOT_ID:
            nodes.append({"l": inv.project, "s": None, "n": 0, "sc": "prod", "d": 1})
            continue
        c = inv.components[cid]
        s = sev.get(cid)
        nodes.append({"l": f"{c.name}@{c.version}", "s": s["sev"] if s else None, "n": s["n"] if s else 0,
                      "sc": c.scope, "e": c.ecosystem, "d": 1 if c.direct else 0,
                      "t": s["titles"] if s else []})
    kids = [sorted(idx[k] for k in inv.edges.get(cid, ()) if k in idx) for cid in ids]
    # worst severity found anywhere below each node (memoised DFS, cycle-safe)
    below: Dict[int, int] = {}

    def walk(i, stack):
        if i in below:
            return below[i]
        own = SEVERITY_ORDER[nodes[i]["s"]] if nodes[i]["s"] else -1
        best = own
        stack.add(i)
        for k in kids[i]:
            if k not in stack:
                best = max(best, walk(k, stack))
        stack.discard(i)
        below[i] = best
        return best
    import sys
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 10000))
    for i in range(len(ids)):
        walk(i, set())
    sys.setrecursionlimit(old)
    inv_sev = {v: k for k, v in SEVERITY_ORDER.items()}
    for i, n in enumerate(nodes):
        n["b"] = inv_sev.get(below[i])   # worst severity in subtree (incl. self)
    orphans = [idx[c] for c in inv.components if c not in inv.reachable()]
    return {"nodes": nodes, "kids": kids, "orphans": orphans}
