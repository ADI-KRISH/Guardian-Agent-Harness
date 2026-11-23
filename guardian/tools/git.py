"""Git tools: clone safely, check out two refs side by side, and diff them."""
from __future__ import annotations

import re
from pathlib import Path

from . import run

SAFE = ["-c", "core.hooksPath=NUL", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false"]


def project_name(src: str) -> str:
    name = re.sub(r"\.git$", "", src.rstrip("/\\").split("/")[-1].split("\\")[-1])
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def clone(url: str, dest: Path) -> Path:
    """Clone (or fetch) into dest with hooks disabled. Local paths are used in place."""
    if Path(url).exists():
        return Path(url).resolve()
    if (dest / ".git").exists():
        r = run("git", [*SAFE, "-C", str(dest), "fetch", "--tags", "--force", "origin"], timeout=900)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = run("git", [*SAFE, "clone", "--filter=blob:none", "--no-checkout", url, str(dest)], timeout=1800)
    if not r.ok:
        raise RuntimeError(f"git failed: {r.stderr[-500:]}")
    return dest


def resolve(repo: Path, ref: str) -> str:
    r = run("git", ["-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"])
    if not r.ok:
        raise RuntimeError(f"Unknown ref '{ref}': {r.stderr.strip()}")
    return r.stdout.strip()


def latest_tags(repo: Path, n: int = 10) -> list[str]:
    r = run("git", ["-C", str(repo), "tag", "--sort=-creatordate"])
    return [t for t in r.stdout.splitlines() if t][:n]


def checkout(repo: Path, ref: str, dest: Path) -> Path:
    """A clean, read-only-intent working copy of ref (git worktree, hooks off)."""
    sha = resolve(repo, ref)
    if (dest / ".git").exists():
        cur = run("git", ["-C", str(dest), "rev-parse", "HEAD"]).stdout.strip()
        if cur == sha:
            return dest
        run("git", ["-C", str(repo), "worktree", "remove", "--force", str(dest)])
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run("git", [*SAFE, "-C", str(repo), "worktree", "add", "--force", "--detach", str(dest), sha], timeout=1800)
    if not r.ok:
        raise RuntimeError(f"checkout of {ref} failed: {r.stderr[-500:]}")
    return dest


IDENT = ["-c", "user.name=supply-chain-guardian", "-c", "user.email=guardian@localhost", "-c", "commit.gpgsign=false"]


def branch_worktree(repo: Path, sha: str, dest: Path, branch: str) -> Path:
    """A fresh local sandbox branch at sha (never pushed). Any older copy of the same sandbox is removed first."""
    if dest.exists():
        run("git", ["-C", str(repo), "worktree", "remove", "--force", str(dest)])
    run("git", ["-C", str(repo), "worktree", "prune"])
    run("git", ["-C", str(repo), "branch", "-D", branch])   # fine if it does not exist
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run("git", [*SAFE, "-C", str(repo), "worktree", "add", "-b", branch, str(dest), sha], timeout=1800)
    if not r.ok:
        raise RuntimeError(f"sandbox branch failed: {r.stderr[-400:]}")
    return dest


def commit_paths(dest: Path, paths: list[str], message: str) -> bool:
    """Commit only the named files on the sandbox branch. False when nothing changed."""
    run("git", [*SAFE, "-C", str(dest), "add", "-f", "--", *paths])
    r = run("git", [*SAFE, *IDENT, "-C", str(dest), "commit", "-m", message, "--no-verify"])
    return r.ok


def patch_since(dest: Path, base_sha: str) -> str:
    return run("git", [*SAFE, "-C", str(dest), "diff", base_sha, "HEAD"], timeout=300).stdout


def changed_files(repo: Path, base: str, head: str) -> list[tuple[str, str]]:
    """[(status, path)] between two refs. Status: A added, M modified, D deleted, R renamed."""
    r = run("git", ["-C", str(repo), "diff", "--name-status", "--no-renames", base, head], timeout=600)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            out.append((parts[0][0], parts[-1]))
    return out


def file_diff(repo: Path, base: str, head: str, path: str, max_chars: int = 20000) -> str:
    r = run("git", ["-C", str(repo), "diff", "-U2", base, head, "--", path], timeout=300)
    return r.stdout[:max_chars]


def commit_info(repo: Path, ref: str) -> dict:
    r = run("git", ["-C", str(repo), "log", "-1", "--format=%H%x1f%an%x1f%ae%x1f%ad%x1f%s", ref])
    p = (r.stdout.strip().split("\x1f") + [""] * 5)[:5]
    return {"sha": p[0], "author": p[1], "email": p[2], "date": p[3], "subject": p[4]}
