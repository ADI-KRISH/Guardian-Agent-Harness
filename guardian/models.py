"""Shared data model for the Guardian pipeline.

Discover produces an Inventory (components + dependency graph).
Detect produces Findings that point back into the Inventory.
Both serialize to plain JSON so the Analyze / Remediate stages can consume them.
"""
from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set
from urllib.parse import quote

ROOT_ID = "root"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def purl_for(ecosystem: str, name: str, version: Optional[str]) -> str:
    ver = f"@{quote(version, safe='.-+_')}" if version else ""
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            return f"pkg:npm/{quote(scope)}/{quote(pkg)}{ver}"
        return f"pkg:npm/{quote(name)}{ver}"
    if ecosystem == "maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}{ver}"
    if ecosystem == "pypi":
        return f"pkg:pypi/{name.lower().replace('_', '-')}{ver}"
    if ecosystem == "docker":
        return f"pkg:docker/{quote(name, safe='/')}{ver}"
    if ecosystem == "github-actions":
        return f"pkg:githubactions/{name}{ver}"
    return f"pkg:generic/{quote(name, safe='/')}{ver}"


@dataclass
class Component:
    name: str
    version: Optional[str]
    ecosystem: str                 # npm | maven | pypi | docker | github-actions | generic
    type: str = "library"          # library | container | application | action | tool
    scope: str = "prod"            # prod | dev | optional | build | ci
    direct: bool = False
    purl: str = ""
    source_files: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)   # e.g. lockfile keys like node_modules/a/node_modules/b
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    has_install_script: bool = False
    license: Optional[str] = None
    properties: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.purl:
            self.purl = purl_for(self.ecosystem, self.name, self.version)

    @property
    def id(self) -> str:
        return self.purl

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d

    @staticmethod
    def from_dict(d: dict) -> "Component":
        d = {k: v for k, v in d.items() if k != "id"}
        return Component(**d)


@dataclass
class Inventory:
    project: str
    components: Dict[str, Component] = field(default_factory=dict)
    edges: Dict[str, Set[str]] = field(default_factory=dict)   # parent id -> child ids
    sources: List[str] = field(default_factory=list)            # files / SBOMs analysed
    notes: List[str] = field(default_factory=list)              # coverage gaps, warnings

    def add(self, comp: Component) -> Component:
        """Add or merge a component (same purl => same node)."""
        existing = self.components.get(comp.id)
        if existing is None:
            self.components[comp.id] = comp
            return comp
        existing.direct = existing.direct or comp.direct
        # prod wins over dev/optional when the same package is reachable both ways
        if existing.scope != "prod" and comp.scope == "prod":
            existing.scope = "prod"
        for f in comp.source_files:
            if f not in existing.source_files:
                existing.source_files.append(f)
        for loc in comp.locations:
            if loc not in existing.locations:
                existing.locations.append(loc)
        existing.has_install_script = existing.has_install_script or comp.has_install_script
        existing.integrity = existing.integrity or comp.integrity
        existing.resolved = existing.resolved or comp.resolved
        existing.license = existing.license or comp.license
        existing.properties.update(comp.properties)
        return existing

    def link(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.setdefault(parent, set()).add(child)

    # ---- graph queries -------------------------------------------------
    def paths_to(self, target: str, limit: int = 3, max_len: int = 25) -> List[List[str]]:
        """Shortest dependency paths from the project root to target (as component ids)."""
        if target == ROOT_ID:
            return [[ROOT_ID]]
        results: List[List[str]] = []
        queue = deque([[ROOT_ID]])
        best_seen: Dict[str, int] = {ROOT_ID: 0}
        while queue and len(results) < limit:
            path = queue.popleft()
            if len(path) > max_len:
                continue
            for child in sorted(self.edges.get(path[-1], ())):
                if child in path:
                    continue
                new = path + [child]
                if child == target:
                    results.append(new)
                    if len(results) >= limit:
                        break
                    continue
                # allow a node to be visited at most twice at the same depth (keeps alt paths)
                depth = len(new)
                if best_seen.get(child, 10**9) + 1 < depth:
                    continue
                best_seen[child] = min(best_seen.get(child, 10**9), depth)
                queue.append(new)
        return results

    def reachable(self) -> Set[str]:
        seen, stack = {ROOT_ID}, [ROOT_ID]
        while stack:
            for c in self.edges.get(stack.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        return seen

    def label(self, cid: str) -> str:
        if cid == ROOT_ID:
            return self.project
        c = self.components.get(cid)
        return f"{c.name}@{c.version}" if c else cid

    def to_dict(self) -> dict:
        return {
            "project": self.project,
            "sources": self.sources,
            "notes": self.notes,
            "components": [c.to_dict() for c in sorted(self.components.values(), key=lambda c: c.id)],
            "edges": {k: sorted(v) for k, v in sorted(self.edges.items())},
        }

    @staticmethod
    def from_dict(d: dict) -> "Inventory":
        inv = Inventory(project=d["project"], sources=d.get("sources", []), notes=d.get("notes", []))
        for c in d["components"]:
            comp = Component.from_dict(c)
            inv.components[comp.id] = comp
        inv.edges = {k: set(v) for k, v in d.get("edges", {}).items()}
        return inv


@dataclass
class Evidence:
    kind: str          # e.g. advisory, lockfile-entry, manifest-diff, script, dockerfile-line
    source: str        # file path or data source (osv.dev, registry.npmjs.org, ...)
    detail: str
    location: Optional[str] = None   # line number, json pointer, lockfile key


@dataclass
class Finding:
    rule: str
    category: str      # vulnerability | malicious-package | typosquat | unexpected-dependency |
                       # install-script | untrusted-image | integrity | cicd
    title: str
    severity: str      # critical | high | medium | low | info
    component: Optional[dict]
    evidence: List[Evidence]
    dependency_paths: List[List[str]] = field(default_factory=list)
    confidence: str = "high"      # how sure the detector is that the finding is real
    evidence_type: str = "verified"   # verified = deterministic data; heuristic = pattern-based signal
    references: List[str] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)   # CVE / GHSA / MAL ids
    fix: Optional[dict] = None
    id: str = ""

    def __post_init__(self):
        if not self.id:
            key = "|".join([self.rule, (self.component or {}).get("id", ""), ",".join(self.identifiers), self.title])
            self.id = "GRD-" + hashlib.sha1(key.encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        d = asdict(self)
        return d
