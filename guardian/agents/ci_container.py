"""Container & CI agent: GitHub workflows (pinning, zizmor, actionlint) and Dockerfile base images."""
from __future__ import annotations

import json
from pathlib import Path

from ..tools import scanners
from . import backdoor, finding

ZIZMOR_SEV = {"high": 7.5, "medium": 5.0, "low": 3.0, "informational": 1.5, "unknown": 3.0}


def download_and_run(head_dir: Path) -> list[dict]:
    """Whole-repo check (not just the diff): workflow lines that download code and pipe it straight into a shell."""
    rx = next(r for rid, _, r, _ in backdoor.RULES if rid == "download-and-run")
    out, wf = [], head_dir / ".github" / "workflows"
    for p in sorted(wf.glob("*.y*ml")) if wf.is_dir() else []:
        rel = f".github/workflows/{p.name}"
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#") or not rx.search(line):
                continue
            snip = line.strip()[:200]
            out.append(finding("workflow_issue", f"{rel}:{n} downloads code and runs it", location={"file": rel, "line": n},
                               detector="workflow-parser", severity=6.5, component=rel,
                               verified_evidence=[f"rule download-and-run matched {rel}:{n}: {snip}",
                                                  "the script is fetched and executed unchecked, so whoever controls that URL controls this CI job"],
                               extra={"id": f"download-and-run:{rel}:{n}", "rule": "download-and-run", "snippet": snip},
                               recommendation="Download to a file, verify a pinned checksum or signature, then run it (or use a pinned action)."))
    return out


def scan(head_dir: Path, head: dict, base: dict | None, cfg: dict) -> tuple[list[dict], list[dict]]:
    findings, metas = download_and_run(head_dir), []
    base_uses = {(w["file"], w["uses"]) for w in (base or {}).get("workflows", [])}

    for w in head.get("workflows", []):
        if w["pinned"] or w["local"]:
            continue
        new = (w["file"], w["uses"]) not in base_uses and base is not None
        sev = 4.0 if w["first_party"] else 6.0
        findings.append(finding("unpinned_action", f"Action {w['uses']} is pinned to a tag, not a commit SHA",
                                location={"file": w["file"], "line": w["line"]}, component=w["uses"].split("@")[0],
                                detector="workflow-parser", severity=sev + (1 if new else 0),
                                change="introduced since baseline" if new else "",
                                verified_evidence=[f"{w['file']}:{w['line']}: uses: {w['uses']}",
                                                   "a tag can be moved to a different commit (as in the tj-actions/changed-files compromise, CVE-2025-30066)"],
                                extra={"id": w["uses"]},
                                recommendation="Pin to the full 40-character commit SHA of the release, keeping the tag as a comment."))

    if head.get("workflows"):
        z = scanners.zizmor(head_dir)
        metas.append(z.meta())
        for item in (z.json() or []):
            ident = item.get("ident", "zizmor")
            if ident == "unpinned-uses":
                continue  # already covered by our own parser above
            det = item.get("determinations", {})
            sev = ZIZMOR_SEV.get(str(det.get("severity", "unknown")).lower(), 3.0)
            loc = {}
            for l in item.get("locations", []):
                try:
                    local = l["symbolic"]["key"]["Local"]
                    given = Path(local.get("given_path") or local.get("verbatim_path"))
                    row = l["concrete"]["location"]["start_point"]["row"] + 1
                    loc = {"file": str(given.resolve().relative_to(head_dir.resolve())).replace("\\", "/"), "line": row}
                    feature = (l["concrete"].get("feature") or "").strip().splitlines()
                    loc["snippet"] = feature[0][:160] if feature else ""
                    loc["annotation"] = l["symbolic"].get("annotation", "")
                    break
                except Exception:  # noqa: BLE001
                    continue
            findings.append(finding("workflow_issue", f"zizmor {ident}: {item.get('desc', '')}", location=loc,
                                    detector="zizmor", severity=sev, component=loc.get("file", ""),
                                    verified_evidence=[f"zizmor rule {ident} (confidence {det.get('confidence', '?')}) at {loc.get('file', '?')}:{loc.get('line', '?')}: {loc.get('annotation', '')}",
                                                       f"code: {loc.get('snippet', '')}"],
                                    extra={"id": f"{ident}:{loc.get('file', '')}:{loc.get('line', '')}"},
                                    recommendation=f"See https://docs.zizmor.sh/audits/#{ident}"))
        a = scanners.actionlint(head_dir)
        metas.append(a.meta())
        try:
            items = json.loads(a.stdout) if a.stdout.strip() else []
        except json.JSONDecodeError:
            items = []
        for it in items:
            if it.get("kind") not in ("expression", "shellcheck", "permissions", "credentials"):
                continue
            findings.append(finding("workflow_issue", f"actionlint {it.get('kind')}: {it.get('message', '')[:120]}",
                                    location={"file": it.get("filepath", ""), "line": it.get("line")},
                                    detector="actionlint", severity=3.0, component=it.get("filepath", ""),
                                    verified_evidence=[f"{it.get('filepath')}:{it.get('line')}: {it.get('message', '')[:200]}"],
                                    extra={"id": f"{it.get('kind')}:{it.get('filepath')}:{it.get('line')}"},
                                    recommendation="Fix the workflow so actionlint passes."))

    trusted = tuple(cfg["trusted_image_prefixes"])
    base_imgs = {i["ref"] for i in (base or {}).get("images", [])}
    for img in head.get("images", []):
        new = base is not None and img["ref"] not in base_imgs
        loc = {"file": img["file"], "line": img["line"]}
        if not img["image"].startswith(trusted):
            findings.append(finding("untrusted_image", f"Base image {img['image']} is not from an allow-listed publisher",
                                    location=loc, component=img["image"], detector="dockerfile-parser",
                                    change="introduced since baseline" if new else "",
                                    verified_evidence=[f"{img['file']}:{img['line']}: FROM {img['ref']}"], extra={"id": img["ref"]},
                                    recommendation="Use an official or allow-listed image, or add it to trusted_image_prefixes."))
        if not img["digest"]:
            findings.append(finding("unpinned_image", f"Base image {img['image']}:{img['tag']} is not pinned by digest",
                                    location=loc, component=img["image"], detector="dockerfile-parser",
                                    severity=4.5 if img["tag"] == "latest" else 3.5,
                                    change="introduced since baseline" if new else "",
                                    verified_evidence=[f"{img['file']}:{img['line']}: FROM {img['ref']} (no @sha256 digest)"],
                                    extra={"id": img["ref"]},
                                    recommendation="Pin with @sha256:<digest> so the same tag cannot silently change."))
    return findings, metas
