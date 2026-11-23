"""Verifier agent: re-check every cited fact against the real checkout, dedupe, and set confidence.

Rules (design doc: Evidence format + Safety):
- A cited file:line must exist and contain the quoted text, otherwise the evidence is marked unverified.
- A cited package must exist in the head snapshot.
- Confidence: high = 2+ independent detectors agree on the component, medium = 1 verified detector,
  low = evidence could not be re-checked. AI inference never raises confidence.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path


def _line(head_dir: Path, rel: str, line: int | None) -> str | None:
    f = head_dir / rel
    if not f.exists() or not f.is_file():
        return None
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line is None:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else None


def verify(findings: list[dict], head_dir: Path, head: dict) -> tuple[list[dict], dict]:
    stats = {"checked": 0, "rejected": 0, "duplicates": 0}
    seen: dict[str, dict] = {}
    for f in findings:
        if f["fingerprint"] in seen:
            stats["duplicates"] += 1
            seen[f["fingerprint"]]["verified_evidence"] += [e for e in f["verified_evidence"] if e not in seen[f["fingerprint"]]["verified_evidence"]]
            continue
        seen[f["fingerprint"]] = f
        ok, why = True, "re-checked"
        loc = f.get("location") or {}
        if loc.get("file") and f["type"] not in ("known_vulnerability",):
            text = _line(head_dir, loc["file"], loc.get("line"))
            snippet = f.get("snippet")
            if text is None:
                ok, why = False, f"cited location {loc['file']}:{loc.get('line')} not found in the checkout"
            elif snippet and snippet[:60] not in text:
                ok, why = False, f"quoted text not found at {loc['file']}:{loc.get('line')}"
        if f["type"] in ("known_vulnerability", "typosquat", "integrity_change", "new_install_script", "origin_change",
                         "untrusted_registry", "version_downgrade", "new_dependency", "malicious_package_heuristic"):
            if f["component"] and f["component"] not in head["packages"]:
                ok, why = False, f"package {f['component']} not present in the head snapshot"
        stats["checked"] += 1
        f["evidence_check"] = {"passed": ok, "detail": why}
        if not ok:
            stats["rejected"] += 1

    out = list(seen.values())
    detectors_by_comp = defaultdict(set)
    for f in out:
        if f["evidence_check"]["passed"] and f["component"]:
            detectors_by_comp[f["component"]].add(f["detector"])
    for f in out:
        if not f["evidence_check"]["passed"]:
            f["confidence"] = "low"
            f["confidence_reason"] = f["evidence_check"]["detail"]
        else:
            n = len(detectors_by_comp.get(f["component"], {f["detector"]}))
            f["confidence"] = "high" if n >= 2 else "medium"
            f["confidence_reason"] = (f"{n} independent detectors agree: {', '.join(sorted(detectors_by_comp[f['component']]))}"
                                      if n >= 2 else f"1 verified detector ({f['detector']})")
    return out, stats
