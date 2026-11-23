"""Discover stage: repository (+ optional image / external SBOMs) -> Inventory -> CycloneDX SBOM + graph."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from ..models import Inventory, ROOT_ID
from . import containers, maven, npm, python_reqs, sbom


def discover(project_dir: Path, extra_sboms: Optional[List[Path]] = None, images: Optional[List[str]] = None,
             maven_tree: Optional[Path] = None) -> tuple:
    project_dir = Path(project_dir).resolve()
    inv = Inventory(project=project_dir.name)
    found = []
    if npm.parse(project_dir, inv):
        found.append("npm")
    if maven.parse(project_dir, inv, tgf_file=maven_tree):
        found.append("maven")
    if python_reqs.parse(project_dir, inv):
        found.append("pypi")
    docker_instrs = containers.parse_dockerfiles(project_dir, inv)
    if docker_instrs:
        found.append("dockerfile")
    workflow_lines = containers.parse_workflows(project_dir, inv)
    if workflow_lines:
        found.append("github-actions")

    for s in extra_sboms or []:
        fmt = sbom.read_sbom(Path(s), inv)
        found.append(f"sbom:{fmt}")

    for image in images or []:
        if shutil.which("syft"):
            out = Path(tempfile.mkdtemp()) / "image.cdx.json"
            try:
                subprocess.run(["syft", image, "-o", f"cyclonedx-json={out}", "-q"], check=True, timeout=900)
                sub = Inventory(project=image)
                sbom.read_sbom(out, sub)
                _graft_image(inv, sub, image)
                found.append(f"image:{image}")
            except (subprocess.SubprocessError, OSError) as e:
                inv.notes.append(f"image {image}: syft failed ({e}).")
        else:
            inv.notes.append(f"image {image}: syft not installed - generate an SBOM with "
                             f"`syft {image} -o cyclonedx-json` and pass it with --sbom.")

    if not found:
        inv.notes.append("No supported manifests found (package.json, pom.xml, requirements.txt, Dockerfile, workflows, SBOM).")
    context = {"dockerfile": docker_instrs, "workflows": workflow_lines, "ecosystems": found,
               "project_dir": str(project_dir)}
    return inv, context


def _graft_image(inv: Inventory, sub: Inventory, image: str) -> None:
    """Attach an image's OS/app packages under the image node."""
    from ..models import Component
    img = inv.add(Component(name=image.split("@")[0].rsplit(":", 1)[0], version=image.rsplit(":", 1)[-1] if ":" in image else "latest",
                            ecosystem="docker", type="container", direct=True, source_files=["--image"]))
    inv.link(ROOT_ID, img.id)
    for cid, c in sub.components.items():
        inv.add(c)
    for parent, kids in sub.edges.items():
        for k in kids:
            inv.link(img.id if parent == ROOT_ID else parent, k)


def write_outputs(inv: Inventory, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    sbom.write_cyclonedx(inv, out_dir / "sbom.cdx.json")
    (out_dir / "inventory.json").write_text(json.dumps(inv.to_dict(), indent=2))
    graph = graph_json(inv)
    (out_dir / "dependency-graph.json").write_text(json.dumps(graph, indent=2))
    (out_dir / "dependency-graph.dot").write_text(to_dot(inv))
    return graph


def graph_json(inv: Inventory) -> dict:
    nodes = [{"id": ROOT_ID, "label": inv.project, "type": "root"}]
    for c in inv.components.values():
        nodes.append({"id": c.id, "label": f"{c.name}@{c.version}", "ecosystem": c.ecosystem, "type": c.type,
                      "scope": c.scope, "direct": c.direct})
    edges = [{"from": a, "to": b} for a, bs in inv.edges.items() for b in sorted(bs)]
    return {"nodes": nodes, "edges": edges}


def to_dot(inv: Inventory, only: Optional[set] = None) -> str:
    def q(s):
        return '"' + s.replace('"', '\\"') + '"'
    lines = ["digraph deps {", "  rankdir=LR; node [shape=box, fontsize=10];",
             f"  {q(ROOT_ID)} [label={q(inv.project)}, style=filled, fillcolor=lightblue];"]
    for c in inv.components.values():
        if only and c.id not in only:
            continue
        style = ', style=dashed' if c.scope != "prod" else ""
        lines.append(f"  {q(c.id)} [label={q(c.name + '@' + str(c.version))}{style}];")
    for a, bs in inv.edges.items():
        for b in bs:
            if only and (a not in only or b not in only):
                continue
            lines.append(f"  {q(a)} -> {q(b)};")
    lines.append("}")
    return "\n".join(lines)


def stats(inv: Inventory) -> dict:
    by_eco, by_scope = {}, {}
    for c in inv.components.values():
        by_eco[c.ecosystem] = by_eco.get(c.ecosystem, 0) + 1
        by_scope[c.scope] = by_scope.get(c.scope, 0) + 1
    direct = sum(1 for c in inv.components.values() if c.direct)
    reach = inv.reachable()
    depth = _max_depth(inv)
    return {"components": len(inv.components), "direct": direct, "transitive": len(inv.components) - direct,
            "by_ecosystem": by_eco, "by_scope": by_scope,
            "edges": sum(len(v) for v in inv.edges.values()),
            "unreachable_from_root": len([c for c in inv.components if c not in reach]),
            "max_depth": depth}


def _max_depth(inv: Inventory) -> int:
    depth = {ROOT_ID: 0}
    frontier = [ROOT_ID]
    while frontier:
        nxt = []
        for n in frontier:
            for c in inv.edges.get(n, ()):
                if c not in depth:
                    depth[c] = depth[n] + 1
                    nxt.append(c)
        frontier = nxt
    return max(depth.values())
