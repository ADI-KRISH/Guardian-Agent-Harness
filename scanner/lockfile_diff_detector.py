from pathlib import Path
from urllib.parse import urlparse
from common import read_json, finding

TRUSTED_HOSTS = {"registry.npmjs.org"}
SRC = "lockfile-diff-detector"

def host(url):
    return urlparse(url or "").hostname

def scan(repo, base, new):
    root = Path(repo).name
    a = (read_json(repo, base, "package-lock.json") or {}).get("packages", {})
    b = (read_json(repo, new, "package-lock.json") or {}).get("packages", {})
    out = []
    for key, meta in b.items():
        if not key:
            continue
        name, ver = key.split("node_modules/")[-1], meta.get("version", "unknown")
        old = a.get(key)
        if old is None:
            out.append(finding("lockfile_diff", name, ver, "medium", "New dependency added",
                               f"+ {key} {ver} (resolved: {meta.get('resolved')})", root, SRC))
            continue
        if old.get("version") != ver:
            out.append(finding("lockfile_diff", name, ver, "medium", "Dependency version changed",
                               f"{key}: {old.get('version')} -> {ver}", root, SRC))
        elif old.get("integrity") != meta.get("integrity"):
            out.append(finding("lockfile_diff", name, ver, "high", "Same version, different integrity hash",
                               f"{key}@{ver}: integrity {old.get('integrity')} -> {meta.get('integrity')}",
                               root, SRC))
        if old.get("resolved") != meta.get("resolved") and (
                host(old.get("resolved")) != host(meta.get("resolved"))
                or host(meta.get("resolved")) not in TRUSTED_HOSTS):
            out.append(finding("lockfile_diff", name, ver, "high", "Download link moved to a different host",
                               f"{key}: resolved {old.get('resolved')} -> {meta.get('resolved')}", root, SRC))
    for key, meta in a.items():
        if key and key not in b:
            out.append(finding("lockfile_diff", key.split("node_modules/")[-1], meta.get("version", "unknown"),
                               "low", "Dependency removed", f"- {key} {meta.get('version')}", root, SRC))
    return out
