"""Shared finding format (see design doc: Evidence format)."""
from __future__ import annotations

import hashlib

# type -> (category, default base severity 0-10)
TYPES = {
    "known_vulnerability": ("known CVE", 5.0),
    "typosquat": ("dependency change", 9.0),
    "integrity_change": ("dependency change", 9.5),
    "origin_change": ("dependency change", 7.5),
    "untrusted_registry": ("dependency change", 7.0),
    "new_install_script": ("dependency change", 6.5),
    "version_downgrade": ("dependency change", 5.0),
    "new_dependency": ("dependency change", 2.0),
    "malicious_package_heuristic": ("backdoor signal", 8.0),
    "backdoor_signal": ("backdoor signal", 8.0),
    "build_script_change": ("source change", 4.0),
    "prompt_injection_attempt": ("backdoor signal", 6.0),
    "unpinned_action": ("CI-container", 5.0),
    "workflow_issue": ("CI-container", 5.0),
    "untrusted_image": ("CI-container", 6.0),
    "unpinned_image": ("CI-container", 3.5),
    "canary_missed": ("harness", 10.0),
}


def finding(ftype: str, title: str, *, component: str = "", location: dict | None = None,
            verified_evidence: list[str] | None = None, detector: str, severity: float | None = None,
            change: str = "", extra: dict | None = None, recommendation: str = "") -> dict:
    cat, base = TYPES[ftype]
    loc = location or {}
    fp_src = f"{ftype}|{component}|{loc.get('file', '')}|{(extra or {}).get('id', '')}|{title if not component else ''}"
    fp = hashlib.sha1(fp_src.encode()).hexdigest()[:12]
    return {
        "id": f"SSCG-{fp[:8].upper()}",
        "fingerprint": fp,
        "type": ftype,
        "category": cat,
        "title": title,
        "component": component,
        "location": loc,
        "change": change,
        "dependency_paths": [],
        "verified_evidence": verified_evidence or [],
        "ai_inference": [],
        "base_severity": float(severity if severity is not None else base),
        "detector": detector,
        "recommendation": recommendation,
        **(extra or {}),
    }
