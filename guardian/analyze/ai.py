"""AI Analyst with hallucination controls.

Providers (env GUARDIAN_LLM):
  anthropic  - Anthropic Messages API, needs ANTHROPIC_API_KEY (model: GUARDIAN_LLM_MODEL)
  openai     - any OpenAI-compatible endpoint, e.g. local Ollama:
               OPENAI_BASE_URL=http://localhost:11434/v1  GUARDIAN_LLM_MODEL=llama3.1
  none       - (default when no key) deterministic, template-based explanation

Controls applied to every AI answer before it is accepted:
  * strict JSON schema; anything else is rejected
  * cited evidence ids must exist in the input
  * any CVE/GHSA/version string in the text must appear in the input facts
  * priority may move at most one level from the computed score
  * output is stored as "inference" next to (never instead of) the verified evidence
Rejected answers fall back to the deterministic explanation and the rejection is audited.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Callable, Optional, Tuple

PROMPT = (Path(__file__).resolve().parents[2] / "prompts" / "analyst_system.md")
LEVELS = ["P1-urgent", "P2-high", "P3-medium", "P4-low"]


GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"
GROQ_BASE = "https://api.groq.com/openai/v1"
OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_resolved = None


def _ollama_models() -> list:
    try:
        with urllib.request.urlopen(OLLAMA_BASE + "/api/tags", timeout=1.5) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        return []


def resolve() -> dict:
    """Pick the AI backend. Order: explicit GUARDIAN_LLM, Anthropic, Gemini, Groq, any OpenAI-compatible
    endpoint, a running local Ollama, else none. Keys are read from the environment only."""
    global _resolved
    env = os.environ.get
    sig = tuple(env(k) or "" for k in ("GUARDIAN_LLM", "GUARDIAN_LLM_MODEL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                                         "GROQ_API_KEY", "OPENAI_BASE_URL", "OPENAI_API_KEY"))
    if _resolved is not None and _resolved[0] == sig:
        return _resolved[1]
    want = (env("GUARDIAN_LLM") or "").lower()
    model = env("GUARDIAN_LLM_MODEL")
    cfg = {"provider": "none", "model": "", "base": None, "key_env": None}
    if want == "none":
        pass
    elif want == "anthropic" or (not want and env("ANTHROPIC_API_KEY")):
        cfg = {"provider": "anthropic", "model": model or "claude-sonnet-5-5", "base": None, "key_env": "ANTHROPIC_API_KEY"}
    elif want == "gemini" or (not want and env("GEMINI_API_KEY")):
        cfg = {"provider": "gemini", "model": model or "gemini-3.8-flash", "base": GEMINI_BASE, "key_env": "GEMINI_API_KEY"}
    elif want == "groq" or (not want and env("GROQ_API_KEY")):
        cfg = {"provider": "groq", "model": model or "llama-3.3-70b-versatile", "base": GROQ_BASE, "key_env": "GROQ_API_KEY"}
    elif want == "openai" or (not want and (env("OPENAI_BASE_URL") or env("OPENAI_API_KEY"))):
        cfg = {"provider": "openai", "model": model or "gpt-4o-mini",
               "base": (env("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/"), "key_env": "OPENAI_API_KEY"}
    elif want in ("", "ollama"):
        models = _ollama_models()
        if models:
            pick = model if model in models else next((m for m in models if "llama3" in m or "qwen" in m), models[0])
            cfg = {"provider": "ollama", "model": pick, "base": OLLAMA_BASE + "/v1", "key_env": None}
    _resolved = (sig, cfg)
    return cfg


def provider() -> Tuple[str, str]:
    c = resolve()
    return c["provider"], c["model"]


def get_caller():
    """Returns call(system, user, model) -> str for the configured backend, or None."""
    c = resolve()
    if c["provider"] == "none":
        return None
    if c["provider"] == "anthropic":
        return _call_anthropic
    return lambda system, user, model: _call_openai(system, user, model, c["base"],
                                                    os.environ.get(c["key_env"]) if c["key_env"] else None)


def _call_anthropic(system: str, user: str, model: str) -> str:
    body = {"model": model, "max_tokens": 1200, "temperature": 0, "system": system,
            "messages": [{"role": "user", "content": user}]}
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                                 headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                                          "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = json.loads(r.read())
    return "".join(b.get("text", "") for b in data.get("content", []))


def _call_openai(system: str, user: str, model: str, base: Optional[str] = None, key: Optional[str] = None) -> str:
    base = (base or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
    key = key if key is not None else os.environ.get("OPENAI_API_KEY")
    body = {"model": model, "temperature": 0, "messages": [{"role": "system", "content": system},
                                                            {"role": "user", "content": user}]}
    hdr = {"content-type": "application/json"}
    if key:
        hdr["authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base + "/chat/completions", data=json.dumps(body).encode(), headers=hdr)
    with urllib.request.urlopen(req, timeout=180) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"]


def build_facts(f: dict, scored: dict, reach: dict, expo: dict) -> dict:
    """The ONLY information the model sees. No source code, no secrets, no file contents."""
    ev = [{"id": f"E{i + 1}", "kind": e["kind"], "source": e["source"], "detail": e["detail"][:400]}
          for i, e in enumerate(f["evidence"])]
    n = len(ev)
    ev.append({"id": f"E{n + 1}", "kind": "reachability", "source": "guardian import scan",
               "detail": f"{reach['level']}: {reach['detail']}"})
    ev.append({"id": f"E{n + 2}", "kind": "exposure", "source": "guardian context",
               "detail": f"{expo['context']}: {expo['detail']}"})
    for i, p in enumerate(f.get("dependency_paths", [])[:2]):
        ev.append({"id": f"E{n + 3 + i}", "kind": "dependency-path", "source": "dependency graph",
                   "detail": " > ".join(p)})
    return {
        "finding": {"title": f["title"], "category": f["category"], "rule": f["rule"],
                    "detector_severity": f["severity"], "identifiers": f.get("identifiers", []),
                    "component": f.get("component"), "fix": f.get("fix")},
        "evidence": ev,
        "computed_score": scored["score"], "computed_priority": scored["priority"],
        "score_factors": scored["factors"],
    }


def validate_answer(raw: str, facts: dict) -> Tuple[Optional[dict], str]:
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None, "no JSON object in answer"
    try:
        a = json.loads(m.group(0))
    except ValueError as e:
        return None, f"invalid JSON: {e}"
    need = {"summary", "exploitability", "reachability", "recommended_priority", "cited_evidence", "confidence"}
    if not need <= set(a):
        return None, f"missing fields: {sorted(need - set(a))}"
    ids = {e["id"] for e in facts["evidence"]}
    cited = set(a.get("cited_evidence") or [])
    if not cited:
        return None, "no evidence cited"
    if not cited <= ids:
        return None, f"cites unknown evidence {sorted(cited - ids)}"
    if a["recommended_priority"] not in LEVELS:
        return None, "invalid priority"
    if abs(LEVELS.index(a["recommended_priority"]) - LEVELS.index(facts["computed_priority"])) > 1:
        return None, "priority moved more than one level"
    corpus = json.dumps(facts)
    text = " ".join(str(a.get(k, "")) for k in ("summary", "exploitability", "reachability", "priority_change_reason"))
    for tok in re.findall(r"\b(?:CVE-\d{4}-\d{3,}|GHSA-[\w-]{14})\b", text):
        if tok not in corpus:
            return None, f"mentions identifier not in the evidence: {tok}"
    for tok in re.findall(r"\b\d+\.\d+\.\d+\b", text):
        if tok not in corpus:
            return None, f"mentions version not in the evidence: {tok}"
    if a["confidence"] not in ("high", "medium", "low"):
        a["confidence"] = "low"
    return a, ""


def deterministic(facts: dict) -> dict:
    f = facts["finding"]
    comp = f.get("component") or {}
    ev = {e["kind"]: e for e in facts["evidence"]}
    reach = ev.get("reachability", {}).get("detail", "")
    expo = ev.get("exposure", {}).get("detail", "")
    path = ev.get("dependency-path", {}).get("detail", "")
    fix = (f.get("fix") or {}).get("fixed_versions") or []
    s = f"{f['title']}."
    if path:
        s += f" It enters the app via {path}."
    if fix:
        s += f" A fixed version exists ({fix[0]})."
    return {"summary": s,
            "exploitability": next((x["why"] for x in facts["score_factors"] if x["factor"] == "exploitability"),
                                   "No CVSS vector available; exploitability not assessed."),
            "reachability": f"{reach}. Exposure: {expo}.",
            "recommended_priority": facts["computed_priority"], "priority_change_reason": "",
            "cited_evidence": [e["id"] for e in facts["evidence"] if e["kind"] in ("advisory", "reachability", "exposure", "dependency-path")][:4] or ["E1"],
            "unknowns": ["whether the vulnerable function is actually called (function-level reachability)"]
            if f["category"] == "vulnerability" else [],
            "confidence": "medium"}


class Analyst:
    def __init__(self, cache_dir: Optional[Path] = None, call: Optional[Callable[[str, str, str], str]] = None):
        self.provider, self.model = provider()
        self.system = PROMPT.read_text()
        self.prompt_sha = hashlib.sha256(self.system.encode()).hexdigest()[:12]
        self.cache_dir = cache_dir
        self._call = call or get_caller()
        self.stats = {"calls": 0, "accepted": 0, "rejected": 0, "errors": 0}

    @property
    def enabled(self) -> bool:
        return self._call is not None

    def explain(self, facts: dict) -> dict:
        if not self.enabled:
            return {"by": "deterministic-template", "accepted": True, **deterministic(facts)}
        user = "Finding facts (JSON):\n" + json.dumps(facts, indent=1)
        key = hashlib.sha256((self.model + self.prompt_sha + user).encode()).hexdigest()
        cpath = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if cpath and cpath.exists():
            return json.loads(cpath.read_text())
        self.stats["calls"] += 1
        try:
            raw = self._call(self.system, user, self.model)
        except Exception as e:  # network / auth errors -> safe fallback
            self.stats["errors"] += 1
            return {"by": "deterministic-template", "accepted": True, "ai_error": f"{e.__class__.__name__}: {e}"[:200],
                    **deterministic(facts)}
        ans, why = validate_answer(raw, facts)
        if ans is None:
            self.stats["rejected"] += 1
            out = {"by": "deterministic-template", "accepted": True, "ai_rejected": why, "ai_raw": raw[:600],
                   **deterministic(facts)}
        else:
            self.stats["accepted"] += 1
            out = {"by": f"{self.provider}:{self.model}", "accepted": True, "prompt_sha": self.prompt_sha, **ans}
        if cpath:
            cpath.parent.mkdir(parents=True, exist_ok=True)
            cpath.write_text(json.dumps(out))
        return out
