"""AI Reporter: executive summary of a Guardian run, grounded in numbered facts.

Guardrail: every number, CVE/GHSA id and version in the AI text must occur in the facts, and every
cited fact id must exist. Otherwise the deterministic summary is used and the rejection is recorded.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

from .analyze import ai

PROMPT = Path(__file__).resolve().parents[1] / "prompts" / "reporter_system.md"


def facts_from_report(r: dict) -> List[dict]:
    F = []

    def add(text):
        F.append({"id": f"S{len(F) + 1}", "fact": text})
    g = ((r.get("provenance") or {}).get("git") or {})
    inv = r["inventory"]
    add(f"Application {r['project']} at commit {(g.get('commit') or '')[:9]} of {g.get('remote', '')}")
    add(f"The application has {inv['components']} components: {inv['direct']} direct and {inv['transitive']} transitive")
    fs = r["findings_summary"]["by_severity"]
    add(f"Detection produced {r['findings_summary']['total']} findings: {fs['critical']} critical, {fs['high']} high, "
        f"{fs['medium']} medium, {fs['low']} low")
    if r.get("analysis"):
        s = r["analysis"]["summary"]
        add(f"After context scoring: {s.get('P1-urgent', 0)} P1-urgent, {s.get('P2-high', 0)} P2-high, "
            f"{s.get('P3-medium', 0)} P3-medium, {s.get('P4-low', 0)} P4-low")
    for x in r.get("top_risks", [])[:4]:
        add(f"Top risk: {x['title'][:110]} (score {x['score']}, {x['priority']}, reachability {x['reachability']['level']}, "
            f"exposure {x['exposure']['context']})")
    for iv in r.get("investigations", [])[:1]:
        add(f"Investigation of '{iv['finding']['title'][:90]}': verdict {iv['inference']['verdict']} "
            f"(inference by {iv['inference']['by']})")
    for it in (r.get("plan") or {}).get("items", []):
        if it["status"] in ("approved", "risk-accepted", "rejected"):
            ap = it["approval"]
            add(f"Human decision on {it['title'][:70]}: {it['status']} (reason: {ap['reason'][:100]})")
    v = r.get("validation")
    if v:
        rs = v["rescan"]
        add(f"Validation verdict {v['overall']}; branch {v['branch']} was not pushed or merged")
        for i in v["items"]:
            add(f"{i['description'][:100]}: {len(i['resolved'])} of {len(i['findings_targeted'])} targeted findings resolved, "
                f"verdict {i['verdict']}")
        for tb, ta in zip(v["build_test"]["before"].get("tests", []), v["build_test"]["after"].get("tests", [])):
            add(f"Tests '{ta['cmd']}': {tb.get('fail', 0)} failures before, {ta.get('fail', 0)} failures after")
        add(f"P1-urgent findings went from {rs['priority_before']['P1-urgent']} to {rs['priority_after']['P1-urgent']}; "
            f"{rs['newly_introduced_high_or_critical']} new high or critical findings were introduced")
    open_p1 = sum(1 for x in r.get("residual_risk", []) if x["priority"] == "P1-urgent" and not x["accepted"])
    add(f"{open_p1} P1-urgent findings remain open and {len(r.get('accepted_risk', []))} risks were formally accepted")
    return F


def _check(raw: str, facts: List[dict]) -> Tuple[Optional[dict], str]:
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None, "no JSON object"
    try:
        a = json.loads(m.group(0))
    except ValueError as e:
        return None, f"invalid JSON: {e}"
    for k in ("headline", "summary", "key_points", "cited_facts"):
        if k not in a:
            return None, f"missing {k}"
    ids = {f["id"] for f in facts}
    cited = set(a["cited_facts"]) | set(re.findall(r"\bS\d+\b", " ".join(a["key_points"])))
    if not cited or not cited <= ids:
        return None, f"unknown or missing fact ids: {sorted(cited - ids)}"
    corpus = " ".join(f["fact"] for f in facts)
    nums_ok = set(re.findall(r"\d+(?:[.,]\d+)*", corpus))
    text = " ".join([a["headline"], a["summary"], a.get("decision_needed", "")] + list(a["key_points"]))
    text_wo_ids = re.sub(r"\bS\d+\b", "", text)
    for n in re.findall(r"\d+(?:[.,]\d+)*", text_wo_ids):
        if n not in nums_ok:
            return None, f"number not in facts: {n}"
    for tok in re.findall(r"\b(?:CVE-\d{4}-\d{3,}|GHSA-[\w-]{14})\b", text):
        if tok not in corpus:
            return None, f"identifier not in facts: {tok}"
    return a, ""


def deterministic(facts: List[dict]) -> dict:
    return {"headline": facts[2]["fact"] + ".", "summary": " ".join(f["fact"] + "." for f in facts[1:4]),
            "key_points": [f"{f['fact']} ({f['id']})" for f in facts[4:10]],
            "decision_needed": facts[-1]["fact"] + ": decide which to fix next or accept.",
            "cited_facts": [f["id"] for f in facts[:10]], "confidence": "high"}


def summarize(report: dict, call=None) -> dict:
    facts = facts_from_report(report)
    caller = call or ai.get_caller()
    prov, model = ai.provider()
    if not caller:
        return {"by": "deterministic-template", "facts": facts, **deterministic(facts)}
    raw = ""
    try:
        raw = caller(PROMPT.read_text(), "Verified facts:\n" + "\n".join(f"{f['id']}: {f['fact']}" for f in facts), model)
        ans, why = _check(raw, facts)
    except Exception as e:
        ans, why = None, f"{e.__class__.__name__}: {e}"[:200]
    if ans is None:
        return {"by": "deterministic-template", "ai_rejected": why, "ai_raw": raw[:500], "facts": facts, **deterministic(facts)}
    return {"by": f"{prov}:{model}", "facts": facts, **ans}
