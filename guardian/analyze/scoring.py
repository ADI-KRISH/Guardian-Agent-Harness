"""Explainable risk score (0-100) + confidence, from verified facts only.

score = base (severity / CVSS) + exploitability + reachability + exposure adjustments.
Every adjustment is recorded as a factor with its points and its evidence, so the number can
be explained line by line and audited. AI may comment on the score but never sets it silently.
"""
from __future__ import annotations

from typing import List

BASE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
PRIORITY = [(80, "P1-urgent"), (60, "P2-high"), (35, "P3-medium"), (0, "P4-low")]

REACH = {
    "imported": (+10, "vulnerable package is imported directly by production code"),
    "parent-imported": (+5, "pulled in by a dependency that production code imports"),
    "unknown": (-10, "no import found (weak evidence: may be loaded dynamically or via CLI)"),
    "test-only": (-25, "only test code uses it"),
    "orphan": (-15, "not reachable from the application's dependency graph"),
    "n/a": (0, "not a code library"),
}
EXPOSE = {
    "server": (+10, "runs in a network-facing server process"),
    "browser": (0, "runs client-side in the browser bundle"),
    "runtime-image": (+5, "part of a shipped container image"),
    "ci-pipeline": (+5, "runs in CI with access to repository secrets"),
    "image-build-stage": (-15, "build-stage image, not shipped"),
    "install-time": (-20, "install-time / optional tooling, not in the running app"),
    "dev-tooling": (-30, "dev-only dependency, not shipped to production"),
}


INSTALL_TIME = ("typosquat", "install-script", "integrity", "unexpected-dependency")


def priority(score: int) -> str:
    for th, name in PRIORITY:
        if score >= th:
            return name
    return "P4-low"


def _cvss_vector(f: dict) -> str:
    for e in f.get("evidence", []):
        if e["kind"] == "cvss" and "(" in e["detail"]:
            return e["detail"].split("(", 1)[1].rstrip(")")
    return ""


def score_finding(f: dict, reach: dict, expo: dict) -> dict:
    factors: List[dict] = []
    cvss = (f.get("fix") or {}).get("cvss_score")
    if f["category"] == "malicious-package" or f["rule"] in ("REGISTRY-SECURITY-HOLDER", "MAL-KNOWN"):
        factors.append({"factor": "malicious", "points": 100, "why": "known malicious package: always urgent"})
        return {"score": 100, "priority": "P1-urgent", "factors": factors,
                "confidence": _confidence(f, reach, malicious=True)}
    base = round(cvss * 10) if cvss else BASE[f["severity"]]
    factors.append({"factor": "severity", "points": base,
                    "why": f"CVSS {cvss}" if cvss else f"detector severity '{f['severity']}'"})
    vec = _cvss_vector(f)
    if vec:
        m = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
        ex = 0
        why = []
        if m.get("AV") == "N" and m.get("PR") == "N" and m.get("UI") == "N":
            ex += 5
            why.append("remotely exploitable without credentials or user action")
        if m.get("PR") == "H":
            ex -= 10
            why.append("needs high privileges")
        if m.get("UI") == "R":
            ex -= 5
            why.append("needs user interaction")
        if m.get("AV") in ("L", "P"):
            ex -= 10
            why.append("needs local/physical access")
        if ex:
            factors.append({"factor": "exploitability", "points": ex, "why": "; ".join(why) + f" ({vec})"})
    if f["category"] in INSTALL_TIME:
        # supply-chain attacks execute at `npm install` on developer and CI machines: runtime
        # reachability and prod/dev scope do not reduce this risk
        factors.append({"factor": "exposure", "points": 5,
                        "why": "executes at install time on developer and CI machines (scope does not reduce this)"})
    else:
        if f["category"] == "vulnerability":
            pts, why = REACH.get(reach["level"], (0, ""))
            if pts:
                factors.append({"factor": "reachability", "points": pts, "why": f"{why}: {reach['detail']}"})
        pts, why = EXPOSE.get(expo["context"], (0, ""))
        if pts:
            factors.append({"factor": "exposure", "points": pts, "why": f"{why} ({expo['detail']})"})
    if f["category"] in ("integrity",) and f["rule"] in ("CHANGE-INTEGRITY", "INTEGRITY-REGISTRY-MISMATCH"):
        factors.append({"factor": "tamper-signal", "points": 10, "why": "same version, different bytes: possible tampering"})
    score = max(0, min(100, sum(x["points"] for x in factors)))
    return {"score": score, "priority": priority(score), "factors": factors, "confidence": _confidence(f, reach)}


def _confidence(f: dict, reach: dict, malicious: bool = False) -> dict:
    c, why = 0.9, []
    if f.get("evidence_type") == "heuristic":
        c -= 0.25
        why.append("finding is pattern-based (heuristic)")
    if f.get("confidence") == "low":
        c -= 0.15
        why.append("detector confidence low")
    elif f.get("confidence") == "medium":
        c -= 0.05
    if f["category"] == "vulnerability":
        c -= 0.05
        why.append("version match only; vulnerable function use not proven")
    if reach["level"] == "unknown":
        c -= 0.1
        why.append("reachability unknown")
    if malicious:
        c = max(c, 0.9)
    c = round(max(0.3, min(0.95, c)), 2)
    label = "high" if c >= 0.8 else "medium" if c >= 0.6 else "low"
    return {"value": c, "label": label, "reasons": why or ["verified advisory + exact version + reachability evidence"]}
