import re
from pathlib import Path
from common import read_json, finding

HOOKS = ("preinstall", "install", "postinstall")
RISKY = {
    "network call": r"\b(curl|wget|Invoke-WebRequest)\b|https?://",
    "pipe to shell": r"\|\s*(sh|bash)\b",
    "env var access": r"process\.env|printenv|\$ENV",
    "obfuscation": r"base64|atob\(|eval\(|\\x[0-9a-f]{2}",
}

def scan(repo, ref):
    root = Path(repo).name
    out = []
    pkg = read_json(repo, ref, "package.json") or {}
    for hook in HOOKS:
        script = pkg.get("scripts", {}).get(hook)
        if not script:
            continue
        hits = [label for label, rx in RISKY.items() if re.search(rx, script, re.I)]
        title = f"{hook} script in package.json" + (f" ({', '.join(hits)})" if hits else "")
        out.append(finding("install_script", pkg.get("name", root), pkg.get("version", "0.0.0"),
                           "high" if hits else "low", title, f"{hook}: {script}", root,
                           "install-script-detector"))
    lock = read_json(repo, ref, "package-lock.json") or {}
    for key, meta in lock.get("packages", {}).items():
        if key and meta.get("hasInstallScript"):
            name = key.split("node_modules/")[-1]
            out.append(finding("install_script", name, meta.get("version", "unknown"), "medium",
                               "Dependency runs an install script",
                               f"hasInstallScript=true for {key} in package-lock.json", root,
                               "install-script-detector"))
    return out
