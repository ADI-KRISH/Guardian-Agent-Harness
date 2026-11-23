"""Named tools. Agents call these functions, never a free shell (guardrail).

Every call: fixed argument list (no shell parsing), timeout, environment with secrets removed,
and a record of the exact command and tool version for the audit log.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..config import TOOLS_DIR

SECRET_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE|CREDENTIAL|NPM_AUTH)", re.I)
UV_BIN = Path.home() / ".local" / "bin"


@dataclass
class ToolResult:
    tool: str
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    ok: bool
    version: str = ""
    notes: list[str] = field(default_factory=list)

    def json(self):
        try:
            return json.loads(self.stdout) if self.stdout.strip() else None
        except json.JSONDecodeError:
            return None

    def meta(self) -> dict:
        return {"tool": self.tool, "cmd": " ".join(self.cmd), "rc": self.returncode, "version": self.version,
                "stderr_tail": self.stderr[-300:]}


def find_exe(name: str) -> str | None:
    for cand in (TOOLS_DIR / f"{name}.exe", TOOLS_DIR / name, UV_BIN / f"{name}.exe", UV_BIN / name):
        if cand.exists():
            return str(cand)
    return shutil.which(name)


def safe_env() -> dict:
    """Child processes never see credentials from the parent environment."""
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["NO_COLOR"] = "1"
    return env


_versions: dict[str, str] = {}


def tool_version(name: str) -> str:
    if name not in _versions:
        exe = find_exe(name)
        if not exe:
            _versions[name] = "not installed"
        else:
            try:
                p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30, env=safe_env())
                _versions[name] = (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr).strip() else "?"
            except Exception as e:  # noqa: BLE001
                _versions[name] = f"error: {e}"
    return _versions[name]


def run(name: str, args: list[str], cwd: str | Path | None = None, timeout: int = 600, ok_codes=(0,)) -> ToolResult:
    exe = find_exe(name)
    if not exe:
        return ToolResult(name, [name, *args], -1, "", f"{name} is not installed (run setup-tools.ps1)", False, "not installed")
    cmd = [exe, *args]
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=safe_env())
        return ToolResult(name, [name, *args], p.returncode, p.stdout, p.stderr, p.returncode in ok_codes, tool_version(name))
    except subprocess.TimeoutExpired:
        return ToolResult(name, [name, *args], -2, "", f"timed out after {timeout}s", False, tool_version(name))
