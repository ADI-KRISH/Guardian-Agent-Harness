"""Container + CI/CD discovery: Dockerfiles, docker-compose files, GitHub Actions workflows.

Base images and actions become first-class components so Detect can reason about
image trust and pinning. RUN / run: lines are retained as evidence for script checks.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

from ..models import Component, Inventory, ROOT_ID

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", ".venv", "venv"}


def _walk(project_dir: Path, patterns: List[str]) -> List[Path]:
    out = []
    for pat in patterns:
        for p in project_dir.rglob(pat):
            if not any(part in SKIP_DIRS for part in p.relative_to(project_dir).parts[:-1]):
                out.append(p)
    return sorted(set(out))


def split_image(ref: str) -> Tuple[str, str, str]:
    """-> (name, tag, digest). name keeps registry prefix if present."""
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    return ref, tag, digest


def parse_dockerfiles(project_dir: Path, inv: Inventory) -> List[dict]:
    """Returns parsed instructions (for Detect) and adds base images as components."""
    parsed = []
    files = _walk(project_dir, ["Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile"])
    for f in files:
        rel = str(f.relative_to(project_dir))
        inv.sources.append(rel)
        args, stages = {}, set()
        lines = f.read_text(errors="replace").splitlines()
        # join continuation lines but keep the starting line number
        joined, buf, start = [], "", 0
        for i, line in enumerate(lines, 1):
            if not buf:
                start = i
            if line.rstrip().endswith("\\"):
                buf += line.rstrip()[:-1] + " "
                continue
            buf += line
            joined.append((start, buf.strip()))
            buf = ""
        instrs = []
        for ln, text in joined:
            if not text or text.startswith("#"):
                continue
            instr, _, rest = text.partition(" ")
            instr = instr.upper()
            if instr == "ARG":
                k, _, v = rest.partition("=")
                args[k.strip()] = v.strip().strip("'\"")
            if instr == "FROM":
                toks = [t for t in rest.split() if not t.startswith("--")]
                ref = toks[0] if toks else ""
                ref = re.sub(r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1), m.group(0)), ref)
                alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
                if ref.lower() != "scratch" and ref not in stages:
                    name, tag, digest = split_image(ref)
                    c = Component(name=name, version=(tag or "latest") + (f"@{digest}" if digest else ""),
                                  ecosystem="docker", type="container", scope="build" if alias else "prod",
                                  direct=True, source_files=[rel], locations=[f"{rel}:{ln}"],
                                  properties={"image_ref": ref, "tag": tag, "digest": digest})
                    inv.link(ROOT_ID, inv.add(c).id)
                if alias:
                    stages.add(alias)
            instrs.append({"file": rel, "line": ln, "instr": instr, "text": text})
        parsed.extend(instrs)
    # final stage of each Dockerfile is what ships; mark earlier FROMs as build stages already done via alias
    for f in _walk(project_dir, ["docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"]):
        rel = str(f.relative_to(project_dir))
        inv.sources.append(rel)
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            m = re.match(r"\s*image:\s*['\"]?([^'\"\s#]+)", line)
            if m:
                ref = m.group(1)
                name, tag, digest = split_image(ref)
                c = Component(name=name, version=(tag or "latest") + (f"@{digest}" if digest else ""),
                              ecosystem="docker", type="container", scope="prod", direct=True,
                              source_files=[rel], locations=[f"{rel}:{i}"],
                              properties={"image_ref": ref, "tag": tag, "digest": digest})
                inv.link(ROOT_ID, inv.add(c).id)
    return parsed


def parse_workflows(project_dir: Path, inv: Inventory) -> List[dict]:
    """GitHub Actions: `uses:` references become components; returns raw lines for Detect."""
    wf_dir = project_dir / ".github" / "workflows"
    out = []
    if not wf_dir.is_dir():
        return out
    for f in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        rel = str(f.relative_to(project_dir))
        inv.sources.append(rel)
        lines = f.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines, 1):
            out.append({"file": rel, "line": i, "text": line})
            m = re.match(r"\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                name, tag, digest = split_image(ref[len("docker://"):])
                c = Component(name=name, version=(tag or "latest") + (f"@{digest}" if digest else ""),
                              ecosystem="docker", type="container", scope="ci", direct=True,
                              source_files=[rel], locations=[f"{rel}:{i}"],
                              properties={"image_ref": ref, "tag": tag, "digest": digest})
            else:
                name, _, version = ref.partition("@")
                c = Component(name=name, version=version or None, ecosystem="github-actions", type="action",
                              scope="ci", direct=True, source_files=[rel], locations=[f"{rel}:{i}"],
                              properties={"ref": version})
            inv.link(ROOT_ID, inv.add(c).id)
    return out
