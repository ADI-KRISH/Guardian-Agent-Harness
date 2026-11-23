"""Backdoor agent: source and build-code changes between baseline and head, plus malicious-package heuristics.

Looks only at what changed (the diff), so it stays fast on large repos.
Rules are deterministic; the LLM may later add an explanation, always labelled as inference.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from ..tools import git, scanners
from . import finding

CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".ps1", ".rb", ".php", ".go",
                 ".java", ".m4", ".mk", ".cmake", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ac", ".in", ".gradle")

# (rule id, severity, regex, explanation)
RULES = [
    ("exec-encoded", 8.5, re.compile(r"(exec|eval|Function)\s*\(.*(b64decode|base64|atob|fromCharCode|Buffer\.from\([^)]*['\"](base64|hex)['\"])", re.I),
     "decodes hidden data and executes it"),
    ("download-and-run", 8.5, re.compile(r"(curl|wget|iwr|Invoke-WebRequest)[^\n|]*\|\s*(sh|bash|iex|python|node)\b|IEX\s*\(|powershell[^\n]*-e(nc|ncodedcommand)?\s", re.I),
     "downloads code and runs it"),
    ("secret-file-read", 7.5, re.compile(r"(\.npmrc|\.pypirc|\.netrc|\.ssh[/\\]id_|\.aws[/\\]credentials|\.docker[/\\]config\.json|\.git-credentials|kubeconfig)", re.I),
     "reads a credential file"),
    ("env-exfil", 7.0, re.compile(r"\b(fetch|axios\.\w+|https?\.(request|get)|requests\.(post|get|put)|urlopen|net\.connect|socket\.connect)\s*\([^\n]{0,200}"
                                  r"(process\.env\b(?!\.\w+\s*=[^=])|os\.environ)|"
                                  r"(JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.items\(\))"
                                  r"[^\n]{0,200}\b(fetch|axios|request|urlopen|post|send|write)", re.I),
     "sends environment variables over the network"),
    ("install-hook", 6.5, re.compile(r"\"(preinstall|install|postinstall|prepare)\"\s*:|cmdclass\s*=|class\s+\w+\(\s*install\s*\)", re.I),
     "adds code that runs automatically at install time"),
    ("child-process-net", 6.0, re.compile(r"(child_process|subprocess|os\.system|Runtime\.getRuntime\(\)\.exec)[^\n]{0,160}(https?://|\bcurl\s|\bwget\s|\bnc\s|/dev/tcp)", re.I),
     "starts a process that talks to the network"),
    ("trigger-condition", 4.0, re.compile(r"(process\.env\.(CI|GITHUB_ACTIONS)|os\.environ(\.get)?\(?\[?['\"](CI|GITHUB_ACTIONS)['\"]|process\.platform\s*===?\s*['\"]linux)[^\n]{0,120}(exec|spawn|eval|system|require\()", re.I),
     "runs code only in CI or on a specific platform (a known backdoor trick)"),
]
BIDI = re.compile("[‪-‮⁦-⁩]")
INJECTION = re.compile(r"(ignore (all |any )?(previous|prior|above) instructions|you are (now )?an? (ai|assistant)|"
                       r"(mark|report|treat) (this|it) (package |file )?as (safe|benign|clean)|do not (report|flag) this)", re.I)
B64BLOB = re.compile(r"[A-Za-z0-9+/=]{200,}")
BINARY_EXT = (".xz", ".lzma", ".gz", ".bin", ".so", ".dll", ".exe", ".node", ".wasm", ".o", ".a", ".jar", ".pyc")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _added_lines(patch: str):
    """Yield (new_line_number, text) for lines added in a unified diff."""
    line_no = 0
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            line_no = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            line_no += 1
            yield line_no, raw[1:]
        elif not raw.startswith("-"):
            line_no += 1


def scan_diff(repo: Path, base_ref: str, head_ref: str, head_dir: Path, cfg: dict) -> tuple[list[dict], dict]:
    findings = []
    changed = git.changed_files(repo, base_ref, head_ref)
    ignore = tuple(cfg["ignore_paths"])
    build_names = set(cfg["build_files"])
    build_suffixes = tuple(cfg["build_file_suffixes"])
    stats = {"files_changed": len(changed), "build_files_changed": [], "files_scanned": 0, "binary_added": []}

    for status, path in changed:
        if path.startswith(ignore) or status == "D":
            continue
        name = Path(path).name
        is_build = name in build_names or name.endswith(build_suffixes) or path.startswith(".github/workflows/")
        if is_build:
            stats["build_files_changed"].append(path)
        if path.lower().endswith(BINARY_EXT) and status == "A":
            stats["binary_added"].append(path)
            findings.append(finding("backdoor_signal", f"Binary file added: {path}", location={"file": path},
                                    detector="backdoor-agent", severity=6.0 if "test" in path.lower() else 5.0,
                                    change="added", component=path,
                                    verified_evidence=[f"git diff {base_ref}..{head_ref}: A {path}",
                                                       "binary or compressed files in source can hide payloads (as the xz Utils backdoor did in test files)"],
                                    extra={"id": f"binary:{path}", "rule": "binary-added"},
                                    recommendation="Check what the file is, who added it and whether any code reads it."))
            continue
        if not path.endswith(CODE_SUFFIXES) and not is_build:
            continue
        patch = git.file_diff(repo, base_ref, head_ref, path)
        stats["files_scanned"] += 1
        hits_in_file = 0
        for line_no, text in _added_lines(patch):
            if hits_in_file >= 5:
                break
            snippet = text.strip()[:200]
            for rid, sev, rx, why in RULES:
                if rx.search(text):
                    hits_in_file += 1
                    findings.append(finding("backdoor_signal", f"{path}:{line_no} {why}", location={"file": path, "line": line_no},
                                            detector="backdoor-agent", severity=sev + (1 if is_build else 0), component=path,
                                            change="added line", verified_evidence=[f"rule {rid} matched added line {path}:{line_no}: {snippet}"],
                                            extra={"id": f"{rid}:{path}:{line_no}", "rule": rid, "snippet": snippet},
                                            recommendation="Review this change with its author before it ships."))
                    break
            if BIDI.search(text):
                findings.append(finding("backdoor_signal", f"{path}:{line_no} contains hidden bidirectional Unicode characters",
                                        location={"file": path, "line": line_no}, detector="backdoor-agent", severity=7.0, component=path,
                                        verified_evidence=[f"rule bidi matched {path}:{line_no} (Trojan Source technique)"],
                                        extra={"id": f"bidi:{path}:{line_no}", "rule": "bidi"},
                                        recommendation="Remove the control characters; review what the code really does."))
            if INJECTION.search(text):
                findings.append(finding("prompt_injection_attempt", f"{path}:{line_no} contains text aimed at AI reviewers",
                                        location={"file": path, "line": line_no}, detector="backdoor-agent", component=path,
                                        verified_evidence=[f"rule ai-injection matched {path}:{line_no}: {snippet}",
                                                           "the Guardian treats this as data and does not follow it"],
                                        extra={"id": f"inject:{path}:{line_no}", "rule": "ai-injection"},
                                        recommendation="Remove the text; review the surrounding change closely."))
            for blob in B64BLOB.findall(text):
                if _entropy(blob) > 5.0:
                    findings.append(finding("backdoor_signal", f"{path}:{line_no} adds a long encoded blob ({len(blob)} chars)",
                                            location={"file": path, "line": line_no}, detector="backdoor-agent", severity=5.5, component=path,
                                            verified_evidence=[f"high-entropy string of {len(blob)} characters (entropy {_entropy(blob):.2f} bits/char) at {path}:{line_no}"],
                                            extra={"id": f"blob:{path}:{line_no}", "rule": "encoded-blob"},
                                            recommendation="Find out what the blob decodes to and why it is in the source."))
                    break
        if is_build and patch.strip() and hits_in_file == 0 and not path.startswith(".github/"):
            findings.append(finding("build_script_change", f"Build file changed: {path}", location={"file": path},
                                    detector="backdoor-agent", component=path, change="modified" if status == "M" else "added",
                                    verified_evidence=[f"git diff {base_ref}..{head_ref}: {status} {path}"],
                                    extra={"id": f"build:{path}"},
                                    recommendation="Build files run with full privileges; review the diff."))
    return findings, stats


def guarddog_new_packages(added_keys: list[str], head: dict, cfg: dict, memory) -> tuple[list[dict], list[dict]]:
    """Run GuardDog on newly added or updated npm/PyPI packages (capped). Results are cached in memory."""
    findings, metas = [], []
    limit = cfg["limits"]["max_guarddog_packages"]
    cands = [head["packages"][k] for k in added_keys if head["packages"][k]["ecosystem"] in ("npm", "PyPI")]
    cands.sort(key=lambda p: (p["scope"] != "runtime", p["name"]))   # runtime first
    for p in cands[:limit]:
        key = f"guarddog:{p['ecosystem']}:{p['name']}@{p['version']}"
        res = memory.cache_get(key, max_age_s=7 * 86400)
        if res is None:
            r = scanners.guarddog(p["ecosystem"], p["name"], p["version"])
            metas.append(r.meta())
            if not r.ok and r.returncode == -1:
                break   # not installed
            res = r.json() or {}
            memory.cache_put(key, res)
        issues = res.get("issues", 0) if isinstance(res, dict) else 0
        if issues:
            rules = [rid for rid, v in (res.get("results") or {}).items() if v]
            findings.append(finding("malicious_package_heuristic", f"GuardDog flags {p['name']}@{p['version']}: {', '.join(rules[:5])}",
                                    component=f"{p['ecosystem']}:{p['name']}@{p['version']}", detector="guarddog",
                                    severity=8.0 if any(r in rules for r in ("exec-base64", "download-executable", "npm-exfiltrate-sensitive-data", "exfiltrate-sensitive-data", "code-execution", "npm-install-script")) else 5.0,
                                    verified_evidence=[f"guarddog {p['ecosystem']} scan {p['name']} --version {p['version']}: {issues} issue(s): {', '.join(rules)}"],
                                    extra={"id": ",".join(rules)},
                                    recommendation="Read the flagged code in the package before allowing it."))
    return findings, metas
