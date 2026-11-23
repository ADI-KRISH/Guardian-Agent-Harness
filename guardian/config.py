"""Settings. Defaults work on any repo; a repo may add an optional guardian.yaml to override them."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """KEY=value lines from <repo>/.env. The file wins over stale shell/setx variables. No dependency needed."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and k and not k.startswith("#"):
            os.environ[k.strip()] = v.strip().strip("\"'")


_load_dotenv(ROOT / ".env")
WORKSPACE = Path(os.getenv("GUARDIAN_WORKSPACE", ROOT / "workspace"))
TOOLS_DIR = ROOT / ".tools"

DEFAULTS: dict = {
    # Base images we trust (prefix match). Anything else is flagged as an untrusted publisher.
    "trusted_image_prefixes": [
        "python", "node", "golang", "alpine", "debian", "ubuntu", "nginx", "eclipse-temurin",
        "gcr.io/distroless/", "mcr.microsoft.com/", "cgr.dev/chainguard/", "docker.io/library/",
    ],
    # Registries packages may be downloaded from. A lockfile URL outside these is flagged.
    "trusted_registries": ["registry.npmjs.org", "files.pythonhosted.org", "pypi.org", "repo.maven.apache.org"],
    # Paths never scanned (generated or vendored code).
    "ignore_paths": ["node_modules/", "dist/", "build/", ".git/", "vendor/"],
    # Files whose change means build-time code changed.
    "build_files": [
        "package.json", "setup.py", "setup.cfg", "pyproject.toml", "Makefile", "configure", "configure.ac",
        "Dockerfile", "docker-compose.yml", ".npmrc", "build.gradle", "pom.xml",
    ],
    "build_file_suffixes": [".m4", ".sh", ".ps1", ".mk", ".cmake"],
    "llm": {
        # openai (when OPENAI_API_KEY is set) | ollama (local, free) | anthropic | none
        "provider": os.getenv("GUARDIAN_LLM") or ("anthropic" if os.getenv("ANTHROPIC_API_KEY") else "openai" if os.getenv("OPENAI_API_KEY") else "ollama"),
        "model": None,       # filled in by load(): GUARDIAN_MODEL or the provider default below
        "base_url": None,
        "max_findings_explained": int(os.getenv("GUARDIAN_EXPLAIN_TOP", "10")),
        "max_findings_investigated": int(os.getenv("GUARDIAN_INVESTIGATE_TOP", "5")),
        "max_tool_steps": int(os.getenv("GUARDIAN_TOOL_STEPS", "6")),
    },
    # Day 2 sandbox validation. `test` is the project's own test command run inside the sandbox image (empty = not run, reported as a gap).
    "validate": {"test": "", "node_image": "node:22-slim", "python_image": "python:3.12-slim", "build_timeout_s": 1800, "test_timeout_s": 1200},
    "limits": {"max_guarddog_packages": 15, "tool_timeout_s": 600, "max_file_bytes": 2_000_000},
}


LLM_DEFAULTS = {
    "openai": ("gpt-4o-mini", "https://api.openai.com/v1"),
    "ollama": ("llama3.2", "http://localhost:11434"),
    "anthropic": ("claude-haiku-4-5", "https://api.anthropic.com"),
    "none": ("", ""),
}


def load(repo_dir: Path | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    prov = cfg["llm"]["provider"]
    model, url = LLM_DEFAULTS.get(prov, ("", ""))
    cfg["llm"]["model"] = os.getenv("GUARDIAN_MODEL") or model
    cfg["llm"]["base_url"] = os.getenv("GUARDIAN_LLM_URL") or url
    if repo_dir:
        f = Path(repo_dir) / "guardian.yaml"
        if f.exists():
            user = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
    return cfg
