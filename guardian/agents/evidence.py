"""Evidence agent: explainable risk score, risk level and lesson handling for every finding."""
from __future__ import annotations

import fnmatch
import re

TEST_PATH = re.compile(r"(^|/)(test|tests|__tests__|spec|specs|e2e|cypress|fixtures?)/|\.(test|spec)\.[jt]sx?$", re.I)
STRONG_RULES = {"exec-encoded", "download-and-run", "install-hook", "binary-added", "secret-file-read"}

BUILD_TIME = {"typosquat", "integrity_change", "new_install_script", "malicious_package_heuristic", "origin_change",
              "untrusted_registry", "backdoor_signal", "build_script_change", "prompt_injection_attempt"}


def _reach(f: dict, head: dict) -> tuple[float, str]:
    if f["type"] == "backdoor_signal" and TEST_PATH.search((f.get("location") or {}).get("file", "")) and f.get("rule") not in STRONG_RULES:
        return 0.6, "in test code, which does not ship but does run in CI"
    if f["type"] in BUILD_TIME:
        return 1.0, "runs at install or build time on developer and CI machines"
    if f["type"] in ("unpinned_action", "workflow_issue"):
        return 0.9, "runs in CI with access to repository secrets"
    if f["type"] in ("untrusted_image", "unpinned_image"):
        return 0.9, "base image of the shipped container"
    if f["type"] == "known_vulnerability":
        paths = f.get("dependency_paths") or []
        direct = any(len(p) == 2 for p in paths)
        scope = f.get("scope", "unknown")
        w = 1.0 if direct else (0.8 if paths else 0.7)
        if scope == "dev":
            return w * 0.6, f"{'direct' if direct else 'transitive'} dependency used only in development/test"
        return w, ("direct" if direct else ("transitive" if paths else "location in graph unknown")) + f" dependency, scope {scope}"
    return 0.8, "default"


def score(findings: list[dict], head: dict) -> None:
    for f in findings:
        base = f["base_severity"]
        rw, rwhy = _reach(f, head)
        new = 1.1 if "introduced" in (f.get("change") or "") or f.get("change") in ("added", "added line") else 1.0
        ev = 1.0 if f.get("evidence_check", {}).get("passed", True) else 0.7
        s = round(min(10.0, base * rw * new * ev), 1)
        level = "Critical" if s >= 8 else "High" if s >= 6 else "Medium" if s >= 4 else "Low"
        if level == "Critical" and f.get("confidence") == "low":
            level = "High"   # guardrail: nothing unverified is Critical without a human
        f["score"], f["risk_level"] = s, level
        f["score_explanation"] = (f"severity {base} x reach {rw:.2f} ({rwhy})" + (f" x new-since-baseline {new}" if new != 1.0 else "")
                                  + (f" x unverified-evidence {ev}" if ev != 1.0 else "") + f" = {s}")


def apply_lessons(findings: list[dict], lessons: list[dict], memory, run_id: str, project: str) -> None:
    from ..memory import UNSUPPRESSIBLE
    for f in findings:
        # Guardrail enforced on the FINDING, not on the lesson's wording: a lesson that names a detector or rule id
        # (e.g. "backdoor-agent", "exec-encoded") must still never hide a backdoor, integrity, typosquat or canary finding.
        if f["type"] in UNSUPPRESSIBLE:
            continue
        for les in lessons:
            if les["kind"] != "suppress":
                continue
            rule_match = les["rule"] in (f["type"], f.get("rule"), f["detector"])
            target = (f.get("location") or {}).get("file") or f.get("component", "")
            if rule_match and fnmatch.fnmatch(target, les["scope"]):
                f["suppressed_by"] = f"lesson #{les['id']} ({les['reason']}; approved by {les['approved_by']})"
                memory.decide(run_id, project, "evidence-agent", f"suppress {f['id']}", f["suppressed_by"],
                              {"finding": f["id"], "lesson": les["id"]}, rule="lesson")
                break
