"""Container image trust + Dockerfile hygiene + GitHub Actions (CI/CD) checks."""
from __future__ import annotations

import re
from typing import List

from ..models import Evidence, Finding, Inventory
from .packages import _comp_dict

DEFAULT_POLICY = {
    # registries / namespaces trusted for base images
    "trusted_image_prefixes": ["gcr.io/distroless/", "mcr.microsoft.com/", "cgr.dev/chainguard/",
                               "registry.access.redhat.com/", "public.ecr.aws/docker/library/",
                               "docker.io/library/", "ghcr.io/actions/"],
    # GitHub orgs whose actions are first-party
    "first_party_action_owners": ["actions", "github"],
    "require_action_sha_pin": True,
    "require_image_digest": False,
}

# runtime images that are end-of-life as of 2026-11 (major version -> EOL date)
EOL = {
    "node": {**{str(v): "EOL" for v in range(0, 20)}, "20": "2026-04-30", "21": "2024-06-01", "23": "2025-06-01",
             "25": "2026-06-01"},
    "python": {"2": "2020-01-01", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31"},
    "alpine": {f"3.{v}": "EOL" for v in range(0, 20)},
    "debian": {"buster": "2024-06-30", "stretch": "2022-06-30", "jessie": "2020-06-30"},
    "ubuntu": {"18.04": "2023-05-31", "20.04": "2025-05-31", "bionic": "2023-05-31", "focal": "2025-05-31"},
}


def _is_official(name: str) -> bool:
    n = name[len("docker.io/"):] if name.startswith("docker.io/") else name
    return "/" not in n or n.startswith("library/")


def _registry(name: str) -> str:
    first = name.split("/")[0]
    return first if ("." in first or ":" in first or first == "localhost") and "/" in name else "docker.io"


def images(inv: Inventory, policy: dict) -> List[Finding]:
    findings = []
    trusted = policy["trusted_image_prefixes"]
    for c in inv.components.values():
        if c.ecosystem != "docker" or "image_ref" not in c.properties:
            continue
        ref, tag, digest = c.properties["image_ref"], c.properties.get("tag", ""), c.properties.get("digest", "")
        loc = c.locations[0] if c.locations else None
        src = c.source_files[0] if c.source_files else "Dockerfile"
        ev0 = Evidence("image-reference", src, f"image: {ref}", location=loc)
        official = _is_official(c.name)
        is_trusted = official or any(c.name.startswith(p) or (c.name + "/").startswith(p) for p in trusted)
        if not is_trusted:
            reg = _registry(c.name)
            findings.append(Finding(
                rule="IMAGE-UNTRUSTED-SOURCE", category="untrusted-image",
                severity="high" if reg == "docker.io" and c.scope == "prod" else "medium",
                title=f"Image '{c.name}' comes from a non-allowlisted publisher ({reg})",
                component=_comp_dict(c), evidence=[ev0, Evidence("policy", "guardian policy",
                    f"not a Docker Official Image and not under trusted prefixes: {', '.join(trusted[:4])}...")],
                confidence="medium", evidence_type="verified",
                fix={"suggestion": "use an official / verified-publisher image or add the publisher to the allowlist after review"}))
        if not tag and not digest or tag == "latest":
            findings.append(Finding(
                rule="IMAGE-MUTABLE-TAG", category="untrusted-image", severity="medium",
                title=f"Image '{c.name}' uses a mutable tag ({tag or 'implicit latest'})", component=_comp_dict(c),
                evidence=[ev0], fix={"suggestion": f"pin to a version tag and digest, e.g. {c.name}:<version>@sha256:<digest>"}))
        elif not digest and (policy.get("require_image_digest") or c.scope == "prod"):
            findings.append(Finding(
                rule="IMAGE-NO-DIGEST", category="untrusted-image", severity="low",
                title=f"Image '{c.name}:{tag}' is not pinned by digest", component=_comp_dict(c), evidence=[ev0],
                fix={"suggestion": "append @sha256:<digest> so the tag cannot be silently re-pointed"}))
        base = c.name.split("/")[-1]
        if base in EOL and tag:
            t = tag.split("-")[0]
            for ver, date in EOL[base].items():
                if t == ver or t.startswith(ver + ".") or (not t[0].isdigit() and tag.find(ver) >= 0):
                    findings.append(Finding(
                        rule="IMAGE-EOL", category="untrusted-image", severity="medium",
                        title=f"Base image {base}:{tag} is end-of-life ({date})", component=_comp_dict(c),
                        evidence=[ev0, Evidence("eol-table", "guardian EOL data (2026-11)", f"{base} {ver} EOL {date}")],
                        fix={"suggestion": "move to a supported release line"}))
                    break
    return findings


DOCKER_RULES = [
    (r"(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh", "IMAGE-PIPE-TO-SHELL", "high", "RUN pipes a downloaded script into a shell"),
    (r"--no-check-certificate|curl\s+[^\n]*-k\b|--insecure|strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED=0|--trusted-host",
     "IMAGE-INSECURE-TLS", "high", "TLS verification disabled during build"),
    (r"chmod\s+(-R\s+)?777", "IMAGE-WORLD-WRITABLE", "low", "world-writable permissions"),
]


def dockerfile(instrs: List[dict]) -> List[Finding]:
    findings = []
    for ins in instrs:
        t = ins["text"]
        if ins["instr"] == "RUN":
            for pat, rule, sev, why in DOCKER_RULES:
                if re.search(pat, t, re.I):
                    findings.append(Finding(rule=rule, category="untrusted-image", severity=sev, title=f"Dockerfile: {why}",
                                            component=None, evidence=[Evidence("dockerfile-line", ins["file"], t[:300], location=str(ins["line"]))]))
            m = re.search(r"npm\s+(i|install)\s+(-g|--global)\s+(\S+)", t)
            if m and ("@" not in m.group(3).lstrip("@") or re.search(r"@[\^~*]|@latest|\|\|", m.group(3) + t)):
                findings.append(Finding(
                    rule="IMAGE-UNPINNED-TOOL", category="untrusted-image", severity="low",
                    title=f"Dockerfile installs build tool '{m.group(3)}' without an exact version",
                    component=None, evidence=[Evidence("dockerfile-line", ins["file"], t[:300], location=str(ins["line"]))],
                    fix={"suggestion": "pin exact tool versions in images so rebuilds are reproducible"}))
            if re.search(r"pip3?\s+install\s+(?!-r)(?!.*==)[A-Za-z]", t):
                findings.append(Finding(
                    rule="IMAGE-UNPINNED-TOOL", category="untrusted-image", severity="low",
                    title="Dockerfile pip-installs packages without exact versions", component=None,
                    evidence=[Evidence("dockerfile-line", ins["file"], t[:300], location=str(ins["line"]))]))
        if ins["instr"] == "ADD" and re.search(r"https?://", t) and "--checksum" not in t:
            findings.append(Finding(
                rule="IMAGE-REMOTE-ADD", category="untrusted-image", severity="medium",
                title="Dockerfile ADDs a remote URL without checksum verification", component=None,
                evidence=[Evidence("dockerfile-line", ins["file"], t[:300], location=str(ins["line"]))]))
    return findings


def workflows(inv: Inventory, lines: List[dict], policy: dict) -> List[Finding]:
    findings = []
    fp = set(policy["first_party_action_owners"])
    for c in inv.components.values():
        if c.ecosystem != "github-actions":
            continue
        ref = c.properties.get("ref") or ""
        owner = c.name.split("/")[0]
        loc = c.locations[0] if c.locations else None
        ev = [Evidence("workflow-line", c.source_files[0], f"uses: {c.name}@{ref}", location=loc)]
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        if ref in ("main", "master", "dev", "develop", "") or not re.match(r"v?\d", ref):
            sev, why = "high", f"branch/unversioned ref '{ref or 'none'}' (code changes on every run)"
        elif owner in fp:
            sev, why = "low", f"first-party action pinned to mutable tag '{ref}'"
        else:
            sev, why = "medium", f"third-party action pinned to mutable tag '{ref}'"
        if owner in fp and sev == "low" and not policy.get("require_action_sha_pin"):
            continue
        findings.append(Finding(
            rule="CICD-UNPINNED-ACTION", category="cicd", severity=sev, title=f"GitHub Action {c.name}: {why}",
            component=_comp_dict(c), evidence=ev,
            fix={"suggestion": f"pin to a full commit SHA: uses: {c.name}@<40-char-sha> # {ref}"}))
    by_file = {}
    for l in lines:
        by_file.setdefault(l["file"], []).append(l)
    for f, ls in by_file.items():
        text = "\n".join(x["text"] for x in ls)
        prt = re.search(r"^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", text, re.M)
        for l in ls:
            t = l["text"]
            if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh", t):
                findings.append(Finding(rule="CICD-PIPE-TO-SHELL", category="cicd", severity="high",
                                        title="Workflow pipes a downloaded script into a shell", component=None,
                                        evidence=[Evidence("workflow-line", f, t.strip()[:300], location=str(l["line"]))]))
            if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|pages)[^}]*(title|body|message|name|ref|label)", t) \
                    and not re.match(r"\s*(if:|name:)", t):
                findings.append(Finding(rule="CICD-SCRIPT-INJECTION", category="cicd", severity="high",
                                        title="Untrusted event data interpolated into a workflow step", component=None,
                                        evidence_type="heuristic", confidence="medium",
                                        evidence=[Evidence("workflow-line", f, t.strip()[:300], location=str(l["line"]))],
                                        fix={"suggestion": "pass the value via env: and reference it as \"$VAR\""}))
            if prt and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", t):
                findings.append(Finding(rule="CICD-PRT-CHECKOUT", category="cicd", severity="high",
                                        title="pull_request_target workflow checks out untrusted PR code", component=None,
                                        evidence=[Evidence("workflow-line", f, t.strip()[:300], location=str(l["line"]))]))
            if re.match(r"\s*permissions:\s*write-all", t):
                findings.append(Finding(rule="CICD-BROAD-PERMISSIONS", category="cicd", severity="medium",
                                        title="Workflow grants write-all token permissions", component=None,
                                        evidence=[Evidence("workflow-line", f, t.strip(), location=str(l["line"]))]))
    return findings
