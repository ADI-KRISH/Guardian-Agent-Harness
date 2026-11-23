"""npm: package.json + package-lock.json (lockfileVersion 1, 2, 3) / npm-shrinkwrap.json.

Edges are resolved with Node's real lookup algorithm (walk up node_modules directories),
so the graph reflects what actually gets loaded, including duplicated/nested versions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from ..models import Component, Inventory, ROOT_ID

DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


def _name_from_key(key: str) -> str:
    # "node_modules/a/node_modules/@s/b" -> "@s/b"
    tail = key.rsplit("node_modules/", 1)[-1]
    return tail


def _lic(v):
    if isinstance(v, dict):
        return v.get("type")
    if isinstance(v, list):
        parts = [x.get("type") if isinstance(x, dict) else str(x) for x in v]
        parts = [x for x in parts if x]
        return parts[0] if len(parts) == 1 else ("(" + " OR ".join(parts) + ")" if parts else None)
    return v


def _scope(entry: dict) -> str:
    if entry.get("dev"):
        return "dev"
    if entry.get("devOptional"):
        return "dev"
    if entry.get("optional"):
        return "optional"
    return "prod"


def parse(project_dir: Path, inv: Inventory) -> bool:
    pkg_path = project_dir / "package.json"
    lock_path = None
    for cand in ("npm-shrinkwrap.json", "package-lock.json"):
        if (project_dir / cand).exists():
            lock_path = project_dir / cand
            break
    if not pkg_path.exists() and not lock_path:
        return False

    manifest = json.loads(pkg_path.read_text()) if pkg_path.exists() else {}
    if manifest.get("name"):
        inv.project = manifest.get("name") + (f"@{manifest['version']}" if manifest.get("version") else "")
    rel_pkg = str(pkg_path.relative_to(project_dir)) if pkg_path.exists() else None
    if rel_pkg:
        inv.sources.append(rel_pkg)

    declared: Dict[str, tuple] = {}
    for fld, scope in (("dependencies", "prod"), ("devDependencies", "dev"),
                       ("optionalDependencies", "optional"), ("peerDependencies", "prod")):
        for n, spec in (manifest.get(fld) or {}).items():
            declared.setdefault(n, (spec, scope, fld))

    if not lock_path:
        inv.notes.append("npm: no package-lock.json found - only direct dependencies (unresolved ranges) captured; "
                         "run `npm install --package-lock-only --ignore-scripts` for the full transitive tree.")
        for n, (spec, scope, fld) in declared.items():
            c = inv.add(Component(name=n, version=None, ecosystem="npm", scope=scope, direct=True,
                                  source_files=[rel_pkg], properties={"declared_range": spec}))
            inv.link(ROOT_ID, c.id)
        return True

    rel_lock = str(lock_path.relative_to(project_dir))
    inv.sources.append(rel_lock)
    lock = json.loads(lock_path.read_text())
    lv = lock.get("lockfileVersion", 1)
    if "packages" in lock and lv >= 2:
        _parse_v2(lock, declared, rel_lock, rel_pkg, inv)
    else:
        _parse_v1(lock, declared, rel_lock, rel_pkg, inv)
    return True


def _parse_v2(lock: dict, declared: dict, rel_lock: str, rel_pkg: Optional[str], inv: Inventory) -> None:
    packages: Dict[str, dict] = lock["packages"]
    key_to_id: Dict[str, str] = {}

    # resolve workspace links: key -> target key
    def real_key(key: str) -> str:
        e = packages.get(key, {})
        if e.get("link") and e.get("resolved") is not None:
            return e["resolved"]
        return key

    for key, entry in packages.items():
        if key == "":
            continue
        if entry.get("link"):
            continue
        name = entry.get("name") or _name_from_key(key)
        if not key.startswith("node_modules/") and "/node_modules/" not in key:
            # workspace package folder (e.g. "frontend")
            ctype = "application"
        else:
            ctype = "library"
        comp = Component(
            name=name, version=entry.get("version"), ecosystem="npm", type=ctype,
            scope=_scope(entry), source_files=[rel_lock], locations=[key],
            resolved=entry.get("resolved"), integrity=entry.get("integrity"),
            has_install_script=bool(entry.get("hasInstallScript")), license=_lic(entry.get("license")),
        )
        if entry.get("inBundle"):
            comp.properties["inBundle"] = "true"
        if entry.get("deprecated"):
            comp.properties["deprecated"] = str(entry["deprecated"])[:200]
        key_to_id[key] = inv.add(comp).id

    def lookup(from_key: str, dep: str) -> Optional[str]:
        base = from_key
        while True:
            cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
            if cand in packages:
                return real_key(cand)
            if not base:
                return None
            idx = base.rfind("/node_modules/")
            if idx == -1:
                base = ""
            else:
                base = base[:idx]
            # strip the package's own name segment: base now ends at parent package dir

    root_entry = packages.get("", {})
    root_deps = {}
    for fld in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        root_deps.update(root_entry.get(fld) or {})
    inv.lock_root_declared = dict(root_deps)  # for manifest/lockfile consistency checks

    unresolved = []
    for key, entry in packages.items():
        if entry.get("link"):
            continue
        parent_id = ROOT_ID if key == "" else key_to_id.get(key)
        if parent_id is None:
            continue
        deps = {}
        fields = DEP_FIELDS + (("devDependencies",) if key == "" or parent_id and inv.components[parent_id].type == "application" else ())
        for fld in fields:
            deps.update(entry.get(fld) or {})
        for dep in deps:
            tk = lookup(key, dep)
            if tk is None or tk not in key_to_id:
                if tk is None and dep not in (entry.get("peerDependencies") or {}) and dep not in (entry.get("optionalDependencies") or {}):
                    unresolved.append(f"{key or '<root>'} -> {dep}")
                continue
            child = key_to_id[tk]
            inv.link(parent_id, child)
            if key == "" or inv.components[parent_id].type == "application":
                inv.components[child].direct = True
                if dep in declared:
                    inv.components[child].properties["declared_range"] = declared[dep][0]
                    inv.components[child].properties["declared_in"] = declared[dep][2]
    # workspaces: link root -> workspace apps
    for key, entry in packages.items():
        if entry.get("link") and entry.get("resolved") in key_to_id:
            inv.link(ROOT_ID, key_to_id[entry["resolved"]])
    if unresolved:
        inv.notes.append(f"npm: {len(unresolved)} dependency edges could not be resolved in the lockfile "
                         f"(e.g. {', '.join(unresolved[:3])}) - lockfile may be stale or hand-edited.")


def _parse_v1(lock: dict, declared: dict, rel_lock: str, rel_pkg: Optional[str], inv: Inventory) -> None:
    """lockfileVersion 1: nested "dependencies" with "requires"."""
    inv.lock_root_declared = {n: v for n, (v, _, _) in declared.items()}

    def walk(deps: dict, prefix: str, scopes: list):
        out = {}
        for name, e in (deps or {}).items():
            key = f"{prefix}node_modules/{name}"
            comp = Component(name=name, version=e.get("version"), ecosystem="npm",
                             scope="dev" if e.get("dev") else ("optional" if e.get("optional") else "prod"),
                             source_files=[rel_lock], locations=[key], resolved=e.get("resolved"),
                             integrity=e.get("integrity"))
            cid = inv.add(comp).id
            out[name] = (key, cid, e)
            walk_children = walk(e.get("dependencies"), key + "/", scopes + [out])
            out[name] = (key, cid, e, walk_children)
        return out

    tree = walk(lock.get("dependencies"), "", [])

    def resolve(name, stack):
        for level in reversed(stack):
            if name in level:
                return level[name][1]
        return None

    def link_all(level, stack):
        for name, (key, cid, e, children) in level.items():
            for req in (e.get("requires") or {}):
                child = resolve(req, stack + [level, children])
                if child:
                    inv.link(cid, child)
            link_all(children, stack + [level])

    for name in declared:
        if name in tree:
            cid = tree[name][1]
            inv.components[cid].direct = True
            inv.components[cid].properties["declared_range"] = declared[name][0]
            inv.link(ROOT_ID, cid)
    link_all(tree, [])
