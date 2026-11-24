"""Investigate one non-CVE supply-chain risk.

Collects VERIFIED facts from deterministic sources:
  * the finding's own evidence
  * before/after comparison with a trusted baseline (version, source URL, integrity, install script,
    presence in package.json)
  * package registry provenance: publish date of this version, maintainers, repository link,
    npm provenance attestation present or not, npm security take-down
  * install-script text
  * for GitHub Actions: what the mutable ref resolves to right now (git ls-remote), whether it is
    a branch or a tag, and the commit date (GitHub API)
  * git history of the affected file in the project
Then asks the AI Investigator (or the rule-based fallback) for an INFERENCE, kept separate.
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .. import net
from ..models import Inventory
from ..audit import Audit
from . import ai

PROMPT = Path(__file__).resolve().parents[2] / "prompts" / "investigator_system.md"
NON_CVE = ("typosquat", "unexpected-dependency", "install-script", "integrity", "cicd", "untrusted-image",
           "malicious-package")
PREFERENCE = ["CHANGE-INTEGRITY", "TYPOSQUAT", "INTEGRITY-REGISTRY-MISMATCH", "UNEXPECTED-LOCK-ONLY-DEP",
              "INSTALL-SCRIPT", "CICD-UNPINNED-ACTION", "CICD-PIPE-TO-SHELL", "IMAGE-UNTRUSTED-SOURCE"]


def pick(findings: List[dict]) -> Optional[dict]:
    cands = [f for f in findings if f["category"] in NON_CVE and f["rule"] not in ("VULN-KNOWN",)]
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cands.sort(key=lambda f: (sev[f["severity"]], PREFERENCE.index(f["rule"]) if f["rule"] in PREFERENCE else 99))
    return cands[0] if cands else None


def _git(project: Path, *a) -> str:
    try:
        return subprocess.run(["git", "-C", str(project), *a], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def gather(f: dict, inv: Inventory, project: Path, baseline: Optional[Inventory], online: bool = True) -> List[dict]:
    facts = []

    def add(kind, source, detail):
        facts.append({"id": f"F{len(facts) + 1}", "kind": kind, "source": source, "detail": detail})

    for e in f["evidence"]:
        loc = e.get("location") or ""
        src = loc if loc.startswith(e["source"]) else e["source"] + (f":{loc}" if loc else "")
        add(e["kind"], src, e["detail"])
    comp = f.get("component") or {}
    c = inv.components.get(comp.get("id", "")) if comp else None
    if f.get("dependency_paths"):
        add("dependency-path", "dependency graph", " > ".join(f["dependency_paths"][0]))

    # ---- baseline comparison
    if baseline is not None and c is not None:
        prev = [b for b in baseline.components.values() if b.name == c.name and b.ecosystem == c.ecosystem]
        if not prev:
            add("baseline-diff", "baseline", f"'{c.name}' did not exist in the trusted baseline; it is new")
        for b in prev:
            for fld in ("version", "resolved", "integrity", "has_install_script", "scope", "direct"):
                bv, cv = getattr(b, fld), getattr(c, fld)
                if bv != cv:
                    add("baseline-diff", "baseline vs current", f"{fld}: {str(bv)[:90]} -> {str(cv)[:90]}")
                elif fld in ("version", "integrity") and bv:
                    add("baseline-diff", "baseline vs current", f"{fld} unchanged: {str(cv)[:90]}")
    if c is not None and c.ecosystem == "npm" and c.properties.get("declared_range"):
        add("manifest", "package.json", f"declared as {c.name}: {c.properties['declared_range']} "
                                         f"({c.properties.get('declared_in', 'dependencies')})")
    elif c is not None and c.ecosystem == "npm" and c.direct:
        add("manifest", "package.json", f"'{c.name}' is NOT declared in package.json")

    # ---- local install-script text
    if c is not None:
        for loc in c.locations:
            pj = project / loc / "package.json"
            if pj.exists():
                sc = (json.loads(pj.read_text()).get("scripts") or {})
                for h in ("preinstall", "install", "postinstall"):
                    if h in sc:
                        add("install-script", str(pj.relative_to(project)), f"{h}: {sc[h][:300]}")

    # ---- registry provenance (npm)
    if online and c is not None and c.ecosystem == "npm":
        try:
            doc = net.fetch_json(f"https://registry.npmjs.org/{c.name.replace('/', '%2F')}", ttl=3600)
            if doc.get("__status__") == 404:
                add("registry", "registry.npmjs.org", f"'{c.name}' does not exist on the public registry")
            else:
                latest = (doc.get("dist-tags") or {}).get("latest")
                add("registry", "registry.npmjs.org", f"latest dist-tag: {latest}; {len(doc.get('versions') or {})} versions published")
                if latest and latest.endswith("-security"):
                    add("registry", "registry.npmjs.org", "package has been replaced by an npm security placeholder (taken down)")
                t = (doc.get("time") or {})
                if t.get("created"):
                    add("registry", "registry.npmjs.org", f"package first published {t['created'][:10]}")
                if c.version and t.get(c.version):
                    add("registry", "registry.npmjs.org", f"version {c.version} published {t[c.version][:10]}")
                v = (doc.get("versions") or {}).get(c.version or "")
                if v is not None:
                    att = (v.get("dist") or {}).get("attestations")
                    add("provenance", "registry.npmjs.org",
                        "npm provenance attestation present" if att else
                        f"no npm provenance attestation for {c.version} (build origin not verifiable)")
                    if v.get("_npmUser"):
                        add("registry", "registry.npmjs.org", f"version published by npm user '{v['_npmUser'].get('name')}'")
                elif c.version:
                    add("registry", "registry.npmjs.org", f"version {c.version} is not available on the registry")
                repo = doc.get("repository")
                add("provenance", "registry.npmjs.org",
                    f"source repository: {repo.get('url') if isinstance(repo, dict) else repo}" if repo else
                    "no source repository linked")
        except net.NetError as e:
            add("registry", "registry.npmjs.org", f"lookup failed: {e}")

    # ---- GitHub Action ref resolution
    if c is not None and c.ecosystem == "github-actions":
        ref = c.properties.get("ref") or ""
        repo = "/".join(c.name.split("/")[:2])
        out = _git(project, "ls-remote", f"https://github.com/{repo}", f"refs/heads/{ref}", f"refs/tags/{ref}")
        for line in out.splitlines():
            sha, r = line.split("\t")
            add("git-remote", f"github.com/{repo}", f"{r} currently resolves to commit {sha} "
                                                     f"({'branch: moves with every push' if r.startswith('refs/heads') else 'tag: can be re-pointed'})")
            if online:
                try:
                    cm = net.fetch_json(f"https://api.github.com/repos/{repo}/commits/{sha}", ttl=3600)
                    d = ((cm.get("commit") or {}).get("committer") or {}).get("date")
                    if d:
                        add("git-remote", "api.github.com", f"that commit is dated {d[:10]}")
                except net.NetError:
                    pass
        add("provenance", "workflow", f"workflow uses '{c.name}@{ref}' without a commit-SHA pin; the code that runs "
                                      "is whatever the ref points to at run time")

    # ---- history of the affected file in this repo
    loc_file = None
    for e in f["evidence"]:
        if e.get("source") and (project / e["source"]).is_file():
            loc_file = e["source"]
            break
    if loc_file:
        log = _git(project, "log", "-n", "3", "--format=%h %ad %an: %s", "--date=short", "--", loc_file)
        add("git-history", f"git log {loc_file}", log.replace("\n", " | ") if log else
            "no history available (shallow clone or untracked file)")
    return facts


def rule_inference(f: dict, facts: List[dict]) -> dict:
    t = " ".join(x["detail"] for x in facts).lower()
    cited = [x["id"] for x in facts][:6]
    verdict, hyp = "suspicious", f"{f['title']}."
    if "security placeholder" in t or "exfiltration" in t:
        verdict, hyp = "likely-malicious", "The package matches known-malicious signals (registry take-down and/or data-exfiltration script)."
    elif f["rule"] == "TYPOSQUAT" and ("install" in t or "did not exist in the trusted baseline" in t):
        verdict, hyp = "likely-malicious", "A newly added, look-alike package name with an install script is a classic typosquat pattern."
    elif f["rule"] in ("CHANGE-INTEGRITY", "INTEGRITY-REGISTRY-MISMATCH"):
        hyp = "The same version now has different bytes than before, which points to lockfile tampering or a compromised mirror."
    elif f["rule"] == "CICD-UNPINNED-ACTION":
        hyp = "The workflow runs third-party code from a mutable reference; a compromise of that repository would run in this CI with its secrets."
    return {"by": "rule-based", "hypothesis": hyp,
            "assessment": "Rule-based inference from the verified facts; no AI model was used.",
            "verdict": verdict, "cited_facts": cited, "missing_evidence": [],
            "next_steps": ["block the component in policy until reviewed", "restore from the trusted baseline / pin to a reviewed commit",
                           "escalate to security review"], "confidence": "medium"}


def investigate(run_dir: Path, finding_id: Optional[str] = None, project_dir: Optional[Path] = None,
                baseline: Optional[Path] = None, online: bool = True, call=None) -> dict:
    from ..detect import load_baseline
    run_dir = Path(run_dir)
    doc = json.loads((run_dir / "findings.json").read_text())
    inv = Inventory.from_dict(json.loads((run_dir / "inventory.json").read_text()))
    prov = json.loads((run_dir / "provenance.json").read_text()) if (run_dir / "provenance.json").exists() else {}
    project = Path(project_dir or prov.get("project_dir", "."))
    f = next((x for x in doc["findings"] if x["id"] == finding_id), None) if finding_id else pick(doc["findings"])
    if f is None:
        raise SystemExit("no matching non-CVE finding to investigate")
    base_inv = load_baseline(baseline) if baseline else None
    facts = gather(f, inv, project, base_inv, online)

    p, model = ai.provider()
    caller = call or ai.get_caller()
    inference = None
    if caller:
        raw = ""
        try:
            raw = caller(PROMPT.read_text(), "Verified facts (JSON):\n" + json.dumps(
                {"finding": {"title": f["title"], "rule": f["rule"], "category": f["category"]}, "facts": facts}, indent=1), model)
            inference = _validate(raw, facts)
            inference["by"] = f"{p}:{model}"
        except Exception as e:
            inference = {**rule_inference(f, facts), "ai_rejected": f"{e}"[:200], "ai_raw": raw[:400]}
    else:
        inference = rule_inference(f, facts)
    out = {"schema": "guardian.investigation/v1", "finding": {k: f[k] for k in ("id", "rule", "category", "title", "severity")},
           "component": f.get("component"), "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "verified_evidence": facts, "inference": inference,
           "note": "verified_evidence comes from deterministic sources; inference is model/rule output and must be reviewed"}
    (run_dir / f"investigation-{f['id']}.json").write_text(json.dumps(out, indent=2))
    (run_dir / f"investigation-{f['id']}.md").write_text(to_markdown(out))
    Audit(run_dir).log("investigate", inference["by"] if inference["by"] != "rule-based" else "guardian", "investigated",
                       {"finding": f["id"], "facts": len(facts), "verdict": inference["verdict"],
                        "rejected": inference.get("ai_rejected")})
    return out


def _validate(raw: str, facts: List[dict]) -> dict:
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        raise ValueError("no JSON in answer")
    a = json.loads(m.group(0))
    ids = {x["id"] for x in facts}
    if not a.get("cited_facts") or not set(a["cited_facts"]) <= ids:
        raise ValueError("missing or unknown cited facts")
    if a.get("verdict") not in ("likely-malicious", "suspicious", "likely-benign", "insufficient-evidence"):
        raise ValueError("bad verdict")
    corpus = json.dumps(facts)
    text = a.get("hypothesis", "") + " " + a.get("assessment", "")
    for tok in re.findall(r"\b(?:CVE-\d{4}-\d{3,}|GHSA-[\w-]{14}|\d+\.\d+\.\d+|https?://\S+)", text):
        if tok.rstrip(".,)") not in corpus:
            raise ValueError(f"unsupported token in answer: {tok}")
    return a


def to_markdown(o: dict) -> str:
    f, inf = o["finding"], o["inference"]
    lines = [f"# Investigation: {f['title']}", "", f"Finding `{f['id']}` · rule `{f['rule']}` · severity {f['severity']}", "",
             "## Verified evidence (deterministic sources)", "", "| id | kind | source | fact |", "|---|---|---|---|"]
    for x in o["verified_evidence"]:
        lines.append(f"| {x['id']} | {x['kind']} | {x['source']} | {x['detail'].replace('|', '/')} |")
    lines += ["", f"## Inference ({inf['by']}, NOT verified)", "", f"**Verdict:** {inf['verdict']} (confidence {inf['confidence']})", "",
              f"**Hypothesis:** {inf['hypothesis']}", "", inf.get("assessment", ""), "",
              f"Based on facts: {', '.join(inf.get('cited_facts', []))}", ""]
    if inf.get("missing_evidence"):
        lines += ["**Missing evidence:** " + "; ".join(inf["missing_evidence"]), ""]
    lines += ["**Safe next steps:**"] + [f"- {s}" for s in inf.get("next_steps", [])]
    return "\n".join(lines) + "\n"
