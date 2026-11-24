"""Apply approved changes in an isolated clone on a new branch. Never touches the user's checkout,
never pushes, never merges."""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import List

from .. import net


def sh(cmd: str, cwd: Path, timeout: int = 1800, env: dict = None) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout, env=env)
        out = (p.stdout or "") + (p.stderr or "")
        return {"cmd": cmd, "exit": p.returncode, "seconds": round(time.time() - t0, 1), "tail": out[-4000:]}
    except subprocess.TimeoutExpired as e:
        return {"cmd": cmd, "exit": 124, "seconds": round(time.time() - t0, 1), "tail": f"timeout after {timeout}s"}


def make_workspace(project: Path, dest: Path, branch: str = None) -> Path:
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(project), str(dest)], check=True)
    if branch:
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", "-b", branch], check=True)
    return dest


def _edit_json(path: Path, fn):
    raw = path.read_text()
    indent = 2
    m = re.search(r'\n( +)"', raw)
    if m:
        indent = len(m.group(1))
    data = json.loads(raw)
    fn(data)
    path.write_text(json.dumps(data, indent=indent, ensure_ascii=False) + ("\n" if raw.endswith("\n") else ""))


def _latest(name: str) -> str:
    try:
        d = net.fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}",
                           headers={"Accept": "application/vnd.npm.install-v1+json"}, ttl=3600)
        return "^" + d["dist-tags"]["latest"]
    except (net.NetError, KeyError):
        return "latest"


def apply_changes(ws: Path, changes: List[dict], npm_flags: str = "") -> List[dict]:
    """Apply change specs. Returns a log of what happened per change and per lockfile regeneration."""
    log, relock, update = [], set(), {}
    for ch in changes:
        t = ch["type"]
        if t == "package-json":
            pj = ws / ch.get("subproject", "") / "package.json"

            def edit(d, ch=ch):
                if ch["op"] == "set-dep":
                    val = _latest(ch["name"]) if ch["value"] == "latest-at-apply" else ch["value"]
                    sec = ch.get("section") or "dependencies"
                    d.setdefault(sec, {})[ch["name"]] = val
                    ch["applied_value"] = val
                elif ch["op"] == "remove-dep":
                    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                        (d.get(sec) or {}).pop(ch["name"], None)
                elif ch["op"] == "set-override":
                    d.setdefault("overrides", {})[ch["name"]] = ch["value"]
            _edit_json(pj, edit)
            relock.add(ch.get("subproject", ""))
            log.append({"change": ch, "result": "edited " + str(pj.relative_to(ws))})
        elif t == "lockfile":
            if ch["op"] == "update":
                update.setdefault(ch.get("subproject", ""), []).append(ch["name"])
            else:
                lf = ws / ch.get("subproject", "") / "package-lock.json"
                if lf.exists():
                    lf.unlink()
                relock.add(ch.get("subproject", ""))
            log.append({"change": ch, "result": "scheduled lockfile " + ch["op"]})
        elif t == "text-replace":
            f = ws / ch["file"]
            lines = f.read_text().splitlines(keepends=True)
            idx = (ch.get("line") or 0) - 1
            if 0 <= idx < len(lines) and ch["old"] in lines[idx]:
                lines[idx] = lines[idx].replace(ch["old"], ch["new"], 1)
                ok = True
            else:
                txt = "".join(lines)
                ok = ch["old"] in txt
                lines = [txt.replace(ch["old"], ch["new"], 1)]
            f.write_text("".join(lines))
            log.append({"change": ch, "result": "replaced" if ok else "NOT FOUND"})
    base = f"--package-lock-only --ignore-scripts --no-audit --no-fund {npm_flags}".strip()
    for sub, names in update.items():
        r = sh(f"npm update {' '.join(shlex.quote(n) for n in names)} {base}", ws / sub)
        log.append({"lockfile": sub or ".", "op": "update", **r})
    for sub in sorted(relock):
        r = sh(f"npm install {base}", ws / sub)
        log.append({"lockfile": sub or ".", "op": "regenerate", **r})
    return log


def commit(ws: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(ws), "add", "-A"], check=True)
    env = {"GIT_AUTHOR_NAME": "Supply Chain Guardian", "GIT_AUTHOR_EMAIL": "guardian@localhost",
           "GIT_COMMITTER_NAME": "Supply Chain Guardian", "GIT_COMMITTER_EMAIL": "guardian@localhost",
           "PATH": "/usr/bin:/bin:/usr/local/bin"}
    subprocess.run(["git", "-C", str(ws), "commit", "-q", "-m", message], check=True, env=env)
    return subprocess.run(["git", "-C", str(ws), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def diff_stat(ws: Path) -> str:
    return subprocess.run(["git", "-C", str(ws), "show", "--stat", "--format=", "HEAD"], capture_output=True, text=True).stdout.strip()


def manifest_diff(ws: Path) -> str:
    out = subprocess.run(["git", "-C", str(ws), "show", "--format=", "HEAD", "--", ":(exclude)*package-lock.json"],
                         capture_output=True, text=True).stdout
    return out[:6000]


TEST_PATTERNS = [
    (r"^# pass (\d+)", "pass"), (r"^# fail (\d+)", "fail"), (r"^# skipped (\d+)", "skipped"), (r"^# tests (\d+)", "total"),
    (r"(\d+) passing", "pass"), (r"(\d+) failing", "fail"), (r"(\d+) pending", "skipped"),
    (r"Tests:\s+(?:(\d+) failed, )?(\d+) passed", None),
]


def parse_tests(text: str) -> dict:
    res = {}
    for pat, key in TEST_PATTERNS:
        m = re.findall(pat, text, re.M)
        if not m:
            continue
        if key is None:
            f, p = m[-1]
            res.setdefault("fail", int(f or 0))
            res.setdefault("pass", int(p))
        else:
            res.setdefault(key, int(m[-1]))
    failed = re.findall(r"^not ok \d+ - (.+)$", text, re.M)
    if failed:
        res["failed_tests"] = failed[:30]
    return res
