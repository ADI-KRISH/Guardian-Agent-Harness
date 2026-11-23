"""Wrappers for the open-source scanners. Each returns a ToolResult; parsing lives in the agents."""
from __future__ import annotations

from pathlib import Path

from . import ToolResult, find_exe, run

EXCLUDES = ["./node_modules/**", "./**/node_modules/**", "./.git/**"]
GUARDDOG_IMAGE = "ghcr.io/datadog/guarddog:latest"


def syft_sbom(path: Path, timeout: int = 600) -> ToolResult:
    """CycloneDX SBOM of a directory (lockfiles, manifests, binaries)."""
    args = [f"dir:{path}", "-o", "cyclonedx-json", "-q"]
    for e in EXCLUDES:
        args += ["--exclude", e]
    return run("syft", args, timeout=timeout)


def osv_scan(path: Path, timeout: int = 600) -> ToolResult:
    """Known vulnerabilities for every lockfile under path. Exit code 1 just means 'vulns found'."""
    # --no-ignore: many repos gitignore their lockfile; we still want to scan it (or the one we generated).
    return run("osv-scanner", ["scan", "source", "-r", "--no-ignore", "--format", "json", str(path)], timeout=timeout, ok_codes=(0, 1))


def zizmor(path: Path, timeout: int = 300) -> ToolResult:
    """GitHub Actions security audit. --offline avoids GitHub API calls (and rate limits)."""
    return run("zizmor", ["--offline", "--format", "json", "--no-progress", str(path)], timeout=timeout,
               ok_codes=tuple(range(0, 20)))


def actionlint(repo: Path, timeout: int = 300) -> ToolResult:
    return run("actionlint", ["-format", "{{json .}}"], cwd=repo, timeout=timeout, ok_codes=(0, 1))


_docker_ok: bool | None = None


def docker_available() -> bool:
    global _docker_ok
    if _docker_ok is None:
        r = run("docker", ["info", "--format", "{{.ServerVersion}}"], timeout=15)
        _docker_ok = r.ok and bool(r.stdout.strip())
    return _docker_ok


def docker_build(context: Path, tag: str, dockerfile: Path | None = None, timeout: int = 1800) -> ToolResult:
    """Build the sandbox image (default <context>/Dockerfile). Installs run with --ignore-scripts where the ecosystem allows it."""
    return run("docker", ["build", "-t", tag, "--progress=plain", *(["-f", str(dockerfile)] if dockerfile else []), str(context)], timeout=timeout)


def docker_run_sandboxed(image: str, cmd: list[str], timeout: int = 300, read_only: bool = True) -> ToolResult:
    """Run code inside the sandbox image: no network, no capabilities, no secrets, memory/CPU/pid limits, throw-away container."""
    args = ["run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "2g", "--cpus", "2", "--pids-limit", "512", "-e", "HOME=/tmp", "--tmpfs", "/tmp"]
    return run("docker", [*args, *(["--read-only"] if read_only else []), image, *cmd], timeout=timeout, ok_codes=(0, 1))


def docker_rmi(tag: str) -> ToolResult:
    return run("docker", ["rmi", "-f", tag], timeout=120, ok_codes=(0, 1))


def guarddog(ecosystem: str, name: str, version: str, timeout: int = 300) -> ToolResult:
    """Malicious-package heuristics on a published package (downloads it from the registry, never runs it).
    Uses a local install if present, otherwise the official Docker image (GuardDog 3.x does not build on Windows)."""
    eco = {"npm": "npm", "pypi": "pypi", "PyPI": "pypi", "go": "go"}.get(ecosystem, ecosystem)
    args = [eco, "scan", name, "--version", version, "--output-format", "json"]
    if find_exe("guarddog"):
        return run("guarddog", args, timeout=timeout, ok_codes=(0, 1))
    if docker_available():
        return run("docker", ["run", "--rm", "--network", "bridge", "--cap-drop", "ALL", "--read-only", "--tmpfs", "/tmp",
                              GUARDDOG_IMAGE, *args], timeout=timeout, ok_codes=(0, 1))
    return ToolResult("guarddog", ["guarddog", *args], -1, "", "guarddog not installed and Docker is not running", False, "not installed")
