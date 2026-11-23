"""Maven: pom.xml (direct deps, property + dependencyManagement resolution) and, when
available, the full transitive tree via `mvn dependency:tree -DoutputType=tgf`
(or a pre-generated TGF file passed with --maven-tree)."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..models import Component, Inventory, ROOT_ID

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
SCOPE_MAP = {"compile": "prod", "runtime": "prod", "provided": "prod", "system": "prod",
             "test": "dev", "import": "build"}


def _t(el, path):
    x = el.find(path, NS)
    if x is None:
        x = el.find(path.replace("m:", ""))
    return x.text.strip() if x is not None and x.text else None


def _subst(val: Optional[str], props: dict) -> Optional[str]:
    if not val:
        return val
    for _ in range(5):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), val)
        if new == val:
            break
        val = new
    return val


def parse(project_dir: Path, inv: Inventory, tgf_file: Optional[Path] = None, run_mvn: bool = True) -> bool:
    pom = project_dir / "pom.xml"
    if not pom.exists():
        return False
    inv.sources.append("pom.xml")
    root = ET.parse(pom).getroot()
    props = {}
    pe = root.find("m:properties", NS)
    if pe is None:
        pe = root.find("properties")
    if pe is not None:
        for p in pe:
            props[p.tag.split("}")[-1]] = (p.text or "").strip()
    gid = _t(root, "m:groupId") or _t(root, "m:parent/m:groupId")
    aid = _t(root, "m:artifactId")
    ver = _t(root, "m:version") or _t(root, "m:parent/m:version")
    props.update({"project.groupId": gid or "", "project.artifactId": aid or "", "project.version": ver or "",
                  "project.parent.version": _t(root, "m:parent/m:version") or ""})
    inv.project = f"{gid}:{aid}@{ver}"

    managed = {}
    for d in root.findall("m:dependencyManagement/m:dependencies/m:dependency", NS):
        k = f"{_subst(_t(d, 'm:groupId'), props)}:{_subst(_t(d, 'm:artifactId'), props)}"
        managed[k] = _subst(_t(d, "m:version"), props)

    direct_ids = {}
    for d in root.findall("m:dependencies/m:dependency", NS):
        g, a = _subst(_t(d, "m:groupId"), props), _subst(_t(d, "m:artifactId"), props)
        v = _subst(_t(d, "m:version"), props) or managed.get(f"{g}:{a}")
        scope = SCOPE_MAP.get(_t(d, "m:scope") or "compile", "prod")
        c = Component(name=f"{g}:{a}", version=v, ecosystem="maven", scope=scope, direct=True,
                      source_files=["pom.xml"])
        if v and "${" in v:
            c.properties["unresolved_version"] = v
        cid = inv.add(c).id
        inv.link(ROOT_ID, cid)
        direct_ids[f"{g}:{a}"] = cid

    tgf = tgf_file
    if tgf is None and run_mvn and shutil.which("mvn"):
        tmp = Path(tempfile.mkdtemp()) / "tree.tgf"
        try:
            subprocess.run(["mvn", "-q", "-B", "dependency:tree", "-DoutputType=tgf", f"-DoutputFile={tmp}"],
                           cwd=project_dir, check=True, timeout=600, capture_output=True)
            tgf = tmp
        except (subprocess.SubprocessError, OSError) as e:
            inv.notes.append(f"maven: `mvn dependency:tree` failed ({e.__class__.__name__}); transitive deps not captured.")
    if tgf and Path(tgf).exists():
        _parse_tgf(Path(tgf), inv, direct_ids)
        inv.sources.append(str(tgf))
    elif tgf is None:
        inv.notes.append("maven: only direct dependencies from pom.xml captured. Provide `--maven-tree` "
                         "(mvn dependency:tree -DoutputType=tgf) or a CycloneDX SBOM for the transitive tree.")
    return True


def _parse_tgf(path: Path, inv: Inventory, direct_ids: dict) -> None:
    """TGF: 'id label' lines, '#', then 'from to scope' edges. label = g:a:type[:classifier]:v[:scope]."""
    nodes, edges, in_edges = {}, [], False
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "#":
            in_edges = True
            continue
        if not in_edges:
            nid, label = line.split(" ", 1)
            parts = label.split(":")
            if len(parts) < 4:
                continue
            g, a = parts[0], parts[1]
            if len(parts) >= 6:
                v, scope = parts[4], parts[5]
            elif len(parts) == 5:
                v, scope = parts[3], parts[4]
            else:
                v, scope = parts[3], "compile"
            nodes[nid] = (g, a, v, SCOPE_MAP.get(scope, "prod"))
        else:
            bits = line.split()
            edges.append((bits[0], bits[1]))
    if not nodes:
        return
    root_nid = next(iter(nodes))
    ids = {}
    for nid, (g, a, v, scope) in nodes.items():
        if nid == root_nid:
            ids[nid] = ROOT_ID
            continue
        c = inv.add(Component(name=f"{g}:{a}", version=v, ecosystem="maven", scope=scope,
                              source_files=[path.name]))
        ids[nid] = c.id
    for f, t in edges:
        if f in ids and t in ids:
            inv.link(ids[f], ids[t])
            if ids[f] == ROOT_ID:
                inv.components[ids[t]].direct = True
