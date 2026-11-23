"""Package-level supply-chain checks: typosquatting, install scripts, lockfile integrity,
registry verification (integrity drift / dependency confusion)."""
from __future__ import annotations

import base64
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .. import net
from ..models import Component, Evidence, Finding, Inventory

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TRUSTED_NPM_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com"}

# ---------------------------------------------------------------- helpers

def _comp_dict(c: Component) -> dict:
    return {"id": c.id, "name": c.name, "version": c.version, "ecosystem": c.ecosystem,
            "direct": c.direct, "scope": c.scope}


def _paths(inv, c):
    return [[inv.label(x) for x in p] for p in inv.paths_to(c.id)]


def _load_list(name: str) -> List[str]:
    out = []
    for line in (DATA_DIR / name).read_text().splitlines():
        if line.strip().startswith("#"):
            continue
        out.extend(line.split())
    return out


def damerau(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "i": "l", "_": "", "-": "", ".": ""})


def _norm(n: str) -> str:
    return n.lower().replace("rn", "m").replace("vv", "w").translate(HOMO)


# ---------------------------------------------------------------- typosquatting

def typosquat(inv: Inventory, online: bool) -> List[Finding]:
    lists = {"npm": set(_load_list("popular-npm.txt")), "pypi": set(_load_list("popular-pypi.txt"))}
    legit = set(_load_list("known-legit.txt"))
    norm_index = {eco: {_norm(p): p for p in pop} for eco, pop in lists.items()}
    in_tree = {c.name for c in inv.components.values()}
    groups: Dict[tuple, List[Component]] = {}
    for c in inv.components.values():
        groups.setdefault((c.ecosystem, c.name), []).append(c)
    findings = []
    for (eco, name), comps in groups.items():
        pop = lists.get(eco)
        if not pop or name in pop or name in legit or len(name) < 5:
            continue
        target, how = None, None
        n = _norm(name)
        if n in norm_index[eco] and norm_index[eco][n] != name:
            target, how = norm_index[eco][n], "same name after separator/homoglyph normalisation"
        else:
            best = None
            for p in pop:
                if abs(len(p) - len(name)) > 2 or (p[0] != name[0] and p[-1] != name[-1]):
                    continue
                d = damerau(name, p)
                limit = 1 if len(p) < 10 else 2
                if d <= limit and (best is None or d < best[0]):
                    best = (d, p)
            if best:
                target, how = best[1], f"edit distance {best[0]} from popular package"
        if not target:
            continue
        if name.startswith("@") and target.split("/")[-1] == name.split("/")[-1]:
            continue
        c = comps[0]
        ev = [Evidence("name-similarity", "guardian popular-package list",
                       f"'{name}' resembles popular package '{target}' ({how})",
                       location=c.locations[0] if c.locations else None)]
        sev, conf = "medium", "low"
        successor = (name.rstrip("0123456789") == target or target.rstrip("0123456789") == name) and name != target
        if successor:
            sev = "low"
            ev.append(Evidence("context", "guardian rules", "numeric suffix: often a legitimate successor package (e.g. foo2)"))
        if target in in_tree:
            ev.append(Evidence("context", "inventory", f"the legitimate '{target}' is also in this dependency tree"))
        if any(x.has_install_script for x in comps):
            ev.append(Evidence("install-script", c.source_files[0] if c.source_files else "lockfile",
                               "package runs an install-time script (hasInstallScript)"))
            sev, conf = "high", "medium"
        if online and eco == "npm":
            established, sig = _npm_meta_signals(name)
            if established:
                continue   # long-lived, actively published package with a linked repo: not a squat
            for s_ in sig:
                ev.append(Evidence("registry-metadata", "registry.npmjs.org", s_))
            if sig:
                sev, conf = "high", "high"
        findings.append(Finding(
            rule="TYPOSQUAT", category="typosquat", severity=sev, confidence=conf, evidence_type="heuristic",
            title=f"Possible typosquat: '{name}' looks like '{target}'", component=_comp_dict(c),
            evidence=ev, dependency_paths=_paths(inv, c),
            fix={"suggestion": f"verify intent; if '{target}' was meant, replace '{name}' with '{target}'",
                 "versions_in_tree": sorted({x.version or "" for x in comps})}))
    return findings


def _npm_meta_signals(name: str):
    """-> (established, [suspicious signals])"""
    try:
        doc = net.fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}", ttl=86400)
    except net.NetError:
        return False, []
    if doc.get("__status__") == 404:
        return False, ["package does not exist on the public npm registry (unpublished for malware, or a private / dependency-confusion name)"]
    out = []
    age = None
    holder = _security_holder(doc)
    if holder:
        out.append(holder)
    created = (doc.get("time") or {}).get("created")
    if created:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
        if age < 180:
            out.append(f"package first published only {age} days ago ({created[:10]})")
    nver = len(doc.get("versions") or {})
    if nver <= 3:
        out.append(f"only {nver} version(s) ever published")
    if not doc.get("repository"):
        out.append("no source repository linked")
    established = bool(age and age > 730 and nver >= 5 and doc.get("repository") and not holder)
    return established, out


def _security_holder(doc: dict) -> Optional[str]:
    latest = (doc.get("dist-tags") or {}).get("latest", "")
    repo = json.dumps(doc.get("repository") or "")
    if latest.endswith("-security") or "security-holder" in repo:
        return (f"npm replaced this package with a security holding placeholder (latest = {latest}); "
                "this happens when a package is removed for malicious code")
    return None


# ---------------------------------------------------------------- install scripts

SUSPICIOUS = [
    (r"(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh", "downloads and pipes a remote script into a shell", "critical"),
    (r"(curl|wget|Invoke-WebRequest|iwr)\s", "network download during install", "high"),
    (r"https?://(?!registry\.npmjs\.org|github\.com/[^ ]+/releases)", "contacts a hard-coded URL", "high"),
    (r"node\s+-e|eval\(|Function\(", "executes inline / dynamically constructed code", "high"),
    (r"base64|atob\(|Buffer\.from\([^)]*['\"]base64", "decodes base64 payload", "high"),
    (r"child_process|exec(Sync)?\(|spawn\(", "spawns system processes", "medium"),
    (r"/dev/tcp/|nc\s+-e|bash\s+-i", "reverse-shell pattern", "critical"),
    (r"process\.env|\$\{?(NPM_TOKEN|AWS_|GITHUB_TOKEN)", "reads environment variables / secrets", "medium"),
    (r"\.npmrc|\.ssh/|id_rsa|\.aws/credentials", "touches credential files", "critical"),
    (r"powershell|cmd\.exe|-enc(odedcommand)?\s", "Windows shell / encoded command", "high"),
]
BENIGN = [r"^node-gyp rebuild$", r"^prebuild-install", r"node-pre-gyp install", r"^node install\.js$",
          r"^node (scripts/)?postinstall\.js$", r"^husky install", r"^patch-package", r"^opencollective",
          r"^node-gyp-build", r"^node ./install\.js", r"^node lib/install\.js"]
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


def _scan_script(text: str):
    hits = []
    for pat, why, sev in SUSPICIOUS:
        if re.search(pat, text, re.I):
            hits.append((why, sev))
    network = re.search(r"require\(['\"](https?|net|dns)['\"]\)|fetch\(|https?://|curl|wget|\bhost\s*:", text, re.I)
    secrets = re.search(r"process\.env|NPM_TOKEN|AWS_|GITHUB_TOKEN|\.npmrc|\.ssh", text)
    if network and secrets:
        hits.append(("reads environment/credentials AND sends data over the network (exfiltration pattern)", "critical"))
    return hits


def _max_sev(sevs):
    order = ["info", "low", "medium", "high", "critical"]
    return max(sevs, key=order.index) if sevs else "info"


def install_scripts(inv: Inventory, project_dir: Path, online: bool, fetch_limit: int = 80) -> List[Finding]:
    findings = []
    # 1) the project's own manifest
    pkg = project_dir / "package.json"
    if pkg.exists():
        scripts = (json.loads(pkg.read_text()).get("scripts") or {})
        for hook in INSTALL_HOOKS:
            if hook in scripts:
                hits = _scan_script(scripts[hook])
                if hits:
                    findings.append(Finding(
                        rule="INSTALL-SCRIPT-ROOT", category="install-script", severity=_max_sev([h[1] for h in hits]),
                        title=f"Project '{hook}' script contains risky behaviour", component=None, evidence_type="verified",
                        evidence=[Evidence("script", "package.json", f"{hook}: {scripts[hook]}", location=f"scripts.{hook}")] +
                                 [Evidence("pattern", "guardian rules", w) for w, _ in hits]))
    # 2) dependencies with install hooks
    candidates = [c for c in inv.components.values() if c.has_install_script and c.ecosystem == "npm"]
    to_fetch = []
    for c in candidates:
        scripts = None
        src = None
        for loc in c.locations:
            p = project_dir / loc / "package.json"
            if p.exists():
                try:
                    scripts = json.loads(p.read_text()).get("scripts") or {}
                    src = str(p.relative_to(project_dir))
                except ValueError:
                    pass
                break
        if scripts is None:
            to_fetch.append(c)
            continue
        findings.append(_install_finding(inv, c, scripts, src))
    fetched = {}
    if online and to_fetch:
        def get(c):
            try:
                return c.id, net.fetch_json(f"https://registry.npmjs.org/{c.name.replace('/', '%2F')}/{c.version}", ttl=86400)
            except net.NetError:
                return c.id, None
        with ThreadPoolExecutor(max_workers=12) as ex:
            fetched = dict(ex.map(get, to_fetch[:fetch_limit]))
    for c in to_fetch:
        doc = fetched.get(c.id)
        if doc and "__status__" not in doc:
            findings.append(_install_finding(inv, c, doc.get("scripts") or {}, f"registry.npmjs.org/{c.name}/{c.version}"))
        else:
            findings.append(Finding(
                rule="INSTALL-SCRIPT", category="install-script", severity="low", confidence="medium",
                title=f"{c.name}@{c.version} runs an install-time script (contents not inspected)",
                component=_comp_dict(c), dependency_paths=_paths(inv, c),
                evidence=[Evidence("lockfile-entry", c.source_files[0], "hasInstallScript: true",
                                   location=c.locations[0] if c.locations else None)],
                fix={"suggestion": "inspect script; consider `npm ci --ignore-scripts` + allowlist"}))
    return findings


def _install_finding(inv, c, scripts: dict, src: str) -> Finding:
    hooks = {h: scripts[h] for h in INSTALL_HOOKS if h in scripts and h != "prepare"}
    ev = [Evidence("lockfile-entry", c.source_files[0] if c.source_files else "lockfile", "hasInstallScript: true",
                   location=c.locations[0] if c.locations else None)]
    ev += [Evidence("script", src, f"{h}: {s}") for h, s in hooks.items()]
    if not hooks and "binding.gyp" not in json.dumps(scripts):
        hooks = {"install": "node-gyp rebuild (implicit: binding.gyp)"}
    hits = []
    for s in hooks.values():
        hits += _scan_script(s)
    benign = all(any(re.search(b, s.strip()) for b in BENIGN) for s in hooks.values()) if hooks else True
    if hits:
        ev += [Evidence("pattern", "guardian rules", w) for w, _ in hits]
        sev, title, conf = _max_sev([h[1] for h in hits]), f"Suspicious install script in {c.name}@{c.version}", "high"
    elif benign:
        sev, title, conf = "info", f"{c.name}@{c.version} runs a standard native-build install script", "high"
    else:
        sev, title, conf = "low", f"{c.name}@{c.version} runs a custom install script", "medium"
    return Finding(rule="INSTALL-SCRIPT", category="install-script", severity=sev, confidence=conf,
                   evidence_type="verified" if not hits else "heuristic",
                   title=title, component=_comp_dict(c), evidence=ev, dependency_paths=_paths(inv, c),
                   fix={"suggestion": "install with --ignore-scripts and allowlist required builds; pin version"})


# ---------------------------------------------------------------- lockfile integrity

def integrity(inv: Inventory) -> List[Finding]:
    findings = []
    for c in inv.components.values():
        if c.ecosystem != "npm" or c.type == "application" or c.properties.get("inBundle"):
            continue
        if not any("node_modules/" in l for l in c.locations):
            continue
        loc = c.locations[0]
        src = c.source_files[0] if c.source_files else "lockfile"
        r = c.resolved or ""
        u = urlparse(r)
        if r.startswith("http://"):
            findings.append(Finding(
                rule="INTEGRITY-INSECURE-URL", category="integrity", severity="high",
                title=f"{c.name}@{c.version} is fetched over plain HTTP", component=_comp_dict(c),
                evidence=[Evidence("lockfile-entry", src, f"resolved: {r}", location=loc)], dependency_paths=_paths(inv, c)))
        elif r.startswith(("git", "github:")) or "codeload.github.com" in r or (u.scheme == "https" and u.hostname not in TRUSTED_NPM_HOSTS and u.hostname):
            pinned = bool(re.search(r"#[0-9a-f]{40}$", r))
            findings.append(Finding(
                rule="INTEGRITY-UNTRUSTED-SOURCE", category="integrity", severity="low" if pinned else "medium",
                title=f"{c.name}@{c.version} resolved from outside the npm registry ({u.hostname or r.split(':')[0]})",
                component=_comp_dict(c), evidence=[Evidence("lockfile-entry", src, f"resolved: {r}", location=loc)],
                dependency_paths=_paths(inv, c)))
        if u.hostname in TRUSTED_NPM_HOSTS and c.version:
            base = c.name.split("/")[-1]
            m = re.search(r"/-/([^/]+)\.tgz$", u.path)
            expected_path = f"/{c.name}/-/{base}-{c.version}.tgz"
            if m and u.path.replace("%2f", "/").replace("%2F", "/") != expected_path:
                findings.append(Finding(
                    rule="INTEGRITY-RESOLVED-MISMATCH", category="integrity", severity="high",
                    title=f"Lockfile entry {c.name}@{c.version} points at a different tarball ({m.group(1)}.tgz)",
                    component=_comp_dict(c), dependency_paths=_paths(inv, c),
                    evidence=[Evidence("lockfile-entry", src, f"version: {c.version}; resolved: {r}", location=loc)],
                    fix={"suggestion": "regenerate the lockfile from a trusted state and review the change that introduced this"}))
        if r and not r.startswith(("git", "file:", "github:")) and not c.integrity:
            findings.append(Finding(
                rule="INTEGRITY-MISSING", category="integrity", severity="medium",
                title=f"{c.name}@{c.version} has no integrity hash in the lockfile", component=_comp_dict(c),
                evidence=[Evidence("lockfile-entry", src, "integrity field missing", location=loc)], dependency_paths=_paths(inv, c)))
        elif c.integrity and c.integrity.startswith("sha1-") and "sha512-" not in c.integrity:
            findings.append(Finding(
                rule="INTEGRITY-WEAK-HASH", category="integrity", severity="low",
                title=f"{c.name}@{c.version} is only protected by a SHA-1 hash", component=_comp_dict(c),
                evidence=[Evidence("lockfile-entry", src, f"integrity: {c.integrity}", location=loc)], dependency_paths=_paths(inv, c)))
    return findings


def verify_registry(inv: Inventory, limit: int = 3000) -> List[Finding]:
    """Compare every lockfile integrity hash with what the public registry serves for that version."""
    comps = [c for c in inv.components.values() if c.ecosystem == "npm" and c.version and c.integrity
             and urlparse(c.resolved or "").hostname in TRUSTED_NPM_HOSTS | {None}][:limit]
    names = sorted({c.name for c in comps})

    def get(n):
        try:
            return n, net.fetch_json(f"https://registry.npmjs.org/{n.replace('/', '%2F')}",
                                     headers={"Accept": "application/vnd.npm.install-v1+json"}, ttl=86400)
        except net.NetError:
            return n, None
    with ThreadPoolExecutor(max_workers=16) as ex:
        docs = dict(ex.map(get, names))
    findings = []
    for c in comps:
        doc = docs.get(c.name)
        if doc is None:
            continue
        src = c.source_files[0] if c.source_files else "lockfile"
        if doc.get("__status__") == 404:
            findings.append(Finding(
                rule="REGISTRY-NOT-FOUND", category="unexpected-dependency", severity="high",
                title=f"{c.name} does not exist on the public npm registry", component=_comp_dict(c),
                dependency_paths=_paths(inv, c),
                evidence=[Evidence("registry", "registry.npmjs.org", f"GET /{c.name} -> 404"),
                          Evidence("lockfile-entry", src, f"resolved: {c.resolved}", location=c.locations[0] if c.locations else None)],
                fix={"suggestion": "possible dependency confusion or a package unpublished for malware; confirm source"}))
            continue
        holder = _security_holder(doc)
        if holder:
            findings.append(Finding(
                rule="REGISTRY-SECURITY-HOLDER", category="malicious-package", severity="critical",
                title=f"{c.name} was taken down by npm security (malicious package)", component=_comp_dict(c),
                dependency_paths=_paths(inv, c),
                evidence=[Evidence("registry", "registry.npmjs.org", holder),
                          Evidence("lockfile-entry", src, f"installed version {c.version}", location=c.locations[0] if c.locations else None)],
                fix={"suggestion": "remove immediately; rotate any secrets present on machines that installed it"}))
            continue
        ver = (doc.get("versions") or {}).get(c.version)
        if not ver:
            findings.append(Finding(
                rule="REGISTRY-VERSION-MISSING", category="integrity", severity="high",
                title=f"{c.name}@{c.version} is not published on the registry (unpublished or fabricated version)",
                component=_comp_dict(c), dependency_paths=_paths(inv, c),
                evidence=[Evidence("registry", "registry.npmjs.org", f"version {c.version} absent from packument")]))
            continue
        reg = (ver.get("dist") or {}).get("integrity")
        if reg and not _same_hash(c.integrity, reg):
            findings.append(Finding(
                rule="INTEGRITY-REGISTRY-MISMATCH", category="integrity", severity="critical",
                title=f"Lockfile hash for {c.name}@{c.version} does not match the registry", component=_comp_dict(c),
                dependency_paths=_paths(inv, c),
                evidence=[Evidence("lockfile-entry", src, f"integrity: {c.integrity[:40]}...", location=c.locations[0] if c.locations else None),
                          Evidence("registry", "registry.npmjs.org", f"dist.integrity: {reg[:40]}...")],
                fix={"suggestion": "treat as tampering: do not install; restore lockfile from trusted commit"}))
    return findings


def _same_hash(a: str, b: str) -> bool:
    da = {p.split("-", 1)[0]: p.split("-", 1)[1] for p in a.split() if "-" in p}
    db = {p.split("-", 1)[0]: p.split("-", 1)[1] for p in b.split() if "-" in p}
    common = set(da) & set(db)
    return all(da[k] == db[k] for k in common) if common else True
