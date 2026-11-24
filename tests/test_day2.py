"""Day 2 tests (offline): python -m unittest discover -s tests -v"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["GUARDIAN_OFFLINE"] = "1"
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ["GUARDIAN_LLM"] = "none"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guardian import net  # noqa: E402
net.OFFLINE = True
from guardian.analyze import ai, analyze  # noqa: E402
from guardian.analyze.scoring import score_finding  # noqa: E402
from guardian.audit import Audit  # noqa: E402
from guardian.cli import main  # noqa: E402
from guardian.remediate import decide, make_plan, option_hash  # noqa: E402
from guardian.validate.apply import apply_changes, parse_tests  # noqa: E402


def demo_run() -> Path:
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_demo.py")], check=True, capture_output=True)
    out = Path(tempfile.mkdtemp()) / "run"
    main(["scan", str(ROOT / "demo" / "compromised"), "-o", str(out), "--vuln-source", "offline",
          "--baseline", str(ROOT / "demo" / "baseline" / "package-lock.json")])
    return out


class Scoring(unittest.TestCase):
    F = {"id": "x", "rule": "VULN-KNOWN", "category": "vulnerability", "severity": "high", "title": "t",
         "evidence_type": "verified", "confidence": "high", "fix": {"cvss_score": 7.5},
         "evidence": [{"kind": "cvss", "source": "s", "detail": "CVSS 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"}]}

    def test_context_changes_priority(self):
        srv = score_finding(self.F, {"level": "imported", "detail": "d"}, {"context": "server", "detail": "d"})
        dev = score_finding(self.F, {"level": "unknown", "detail": "d"}, {"context": "dev-tooling", "detail": "d"})
        self.assertGreater(srv["score"], dev["score"])
        self.assertEqual(srv["priority"], "P1-urgent")
        self.assertEqual(dev["priority"], "P3-medium")
        self.assertEqual(sum(f["points"] for f in srv["factors"]), srv["score"])   # fully explainable
        self.assertLess(dev["confidence"]["value"], srv["confidence"]["value"])

    def test_malicious_always_urgent(self):
        f = dict(self.F, category="malicious-package", rule="MAL-KNOWN")
        s = score_finding(f, {"level": "unknown", "detail": ""}, {"context": "dev-tooling", "detail": ""})
        self.assertEqual((s["score"], s["priority"]), (100, "P1-urgent"))


class AIGuardrails(unittest.TestCase):
    def facts(self):
        f = dict(Scoring.F, identifiers=["GHSA-aaaa-bbbb-cccc"], component={"name": "lodash", "version": "2.4.2"},
                 dependency_paths=[["app", "lodash@2.4.2"]])
        s = score_finding(f, {"level": "imported", "detail": "d"}, {"context": "server", "detail": "d"})
        return ai.build_facts(f, s, {"level": "imported", "detail": "d"}, {"context": "server", "detail": "d"})

    def ans(self, **kw):
        a = {"summary": "lodash 2.4.2 is affected.", "exploitability": "x", "reachability": "y",
             "recommended_priority": "P1-urgent", "priority_change_reason": "", "cited_evidence": ["E1"],
             "unknowns": [], "confidence": "medium"}
        a.update(kw)
        return json.dumps(a)

    def test_accepts_grounded(self):
        a, why = ai.validate_answer(self.ans(), self.facts())
        self.assertIsNotNone(a, why)

    def test_rejects_invented_cve(self):
        a, why = ai.validate_answer(self.ans(summary="Also CVE-2099-12345 applies."), self.facts())
        self.assertIsNone(a)
        self.assertIn("CVE-2099-12345", why)

    def test_rejects_invented_version_and_unknown_evidence(self):
        self.assertIsNone(ai.validate_answer(self.ans(summary="upgrade to 9.9.9"), self.facts())[0])
        self.assertIsNone(ai.validate_answer(self.ans(cited_evidence=["E99"]), self.facts())[0])

    def test_rejects_big_priority_jump_and_falls_back(self):
        an = ai.Analyst(call=lambda s, u, m: self.ans(recommended_priority="P4-low"))
        out = an.explain(self.facts())
        self.assertEqual(out["by"], "deterministic-template")
        self.assertIn("more than one level", out["ai_rejected"])

    def test_prompt_contains_no_source_code(self):
        user = json.dumps(self.facts())
        self.assertNotIn("require(", user)


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundir = demo_run()
        analyze(cls.rundir, ROOT / "demo" / "compromised", ai_limit=5)
        cls.plan = make_plan(cls.rundir, ROOT / "demo" / "compromised", online=False)

    def test_plan_removes_malicious_and_typosquat(self):
        acts = {(it["component"] or {}).get("name"): [o["action"] for o in it["options"]] for it in self.plan["items"]}
        self.assertIn("remove", acts["crossenv"])
        self.assertIn("remove", acts["flatmap-stream"])
        for it in self.plan["items"]:
            self.assertEqual(it["status"], "pending-approval")
            for o in it["options"]:
                self.assertIn("rollback", o)
                self.assertIn("compatibility", o)

    def test_approval_requires_human_and_reason(self):
        with self.assertRaises(SystemExit):
            decide(self.rundir, "R1", "approve", "guardian-bot", "auto")
        with self.assertRaises(SystemExit):
            decide(self.rundir, "R1", "approve", "Alice", "")
        it = decide(self.rundir, "R1", "approve", "Alice", "reviewed")
        self.assertEqual(it["status"], "approved")
        opt = next(o for o in it["options"] if o["option_id"] == it["approval"]["option_id"])
        self.assertEqual(option_hash(opt), it["approval"]["option_sha256"])

    def test_audit_chain_detects_tampering(self):
        a = Audit(self.rundir)
        self.assertTrue(a.verify()["ok"])
        lines = a.path.read_text().splitlines()
        e = json.loads(lines[1]); e["actor"] = "human:mallory"; lines[1] = json.dumps(e, sort_keys=True)
        bad = Path(tempfile.mkdtemp()); (bad / "audit.jsonl").write_text("\n".join(lines) + "\n")
        self.assertFalse(Audit(bad).verify()["ok"])

    def test_policy_gate_blocks_malicious(self):
        from guardian.policy import gate
        r = gate(self.rundir, ROOT / "policies" / "default.json")
        self.assertFalse(r["passed"])
        self.assertTrue(any(v["type"] == "blocked-component" for v in r["violations"]))

    def test_investigation_separates_evidence_and_inference(self):
        from guardian.analyze.investigate import investigate
        o = investigate(self.rundir, None, ROOT / "demo" / "compromised", ROOT / "demo" / "baseline" / "package-lock.json",
                        online=False)
        self.assertTrue(o["verified_evidence"])
        self.assertIn(o["inference"]["verdict"], ("likely-malicious", "suspicious", "likely-benign", "insufficient-evidence"))
        ids = {f["id"] for f in o["verified_evidence"]}
        self.assertTrue(set(o["inference"]["cited_facts"]) <= ids)


class Apply(unittest.TestCase):
    def test_package_json_and_text_edits(self):
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text(json.dumps({"name": "x", "dependencies": {"a": "1.0.0", "bad": "1.0.0"}}, indent=2) + "\n")
        (d / "wf.yml").write_text("steps:\n  - uses: org/act@main\n")
        log = apply_changes(d, [
            {"type": "package-json", "subproject": "", "op": "set-dep", "name": "a", "value": "^2.0.0"},
            {"type": "package-json", "subproject": "", "op": "remove-dep", "name": "bad"},
            {"type": "package-json", "subproject": "", "op": "set-override", "name": "c", "value": "3.0.0"},
            {"type": "text-replace", "file": "wf.yml", "line": 2, "old": "org/act@main", "new": "org/act@" + "a" * 40 + " # main"},
        ], npm_flags="--offline")
        pj = json.loads((d / "package.json").read_text())
        self.assertEqual(pj["dependencies"], {"a": "^2.0.0"})
        self.assertEqual(pj["overrides"], {"c": "3.0.0"})
        self.assertIn("a" * 40, (d / "wf.yml").read_text())
        self.assertTrue(any(l.get("result") == "replaced" for l in log))

    def test_parse_node_test_output(self):
        r = parse_tests("# tests 10\n# pass 8\n# fail 1\n# skipped 1\nnot ok 3 - broken thing\n")
        self.assertEqual((r["pass"], r["fail"], r["skipped"]), (8, 1, 1))
        self.assertEqual(r["failed_tests"], ["broken thing"])


if __name__ == "__main__":
    unittest.main()


class LLMEndToEnd(unittest.TestCase):
    """Real HTTP round-trip through the OpenAI-compatible client against a local mock server."""
    def test_openai_compatible_roundtrip(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        seen = {}

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                seen["body"] = body
                facts = json.loads(body["messages"][1]["content"].split("\n", 1)[1])
                ans = {"summary": "Grounded summary.", "exploitability": "x", "reachability": "y",
                       "recommended_priority": facts["computed_priority"], "priority_change_reason": "",
                       "cited_evidence": [facts["evidence"][0]["id"]], "unknowns": [], "confidence": "medium"}
                out = json.dumps({"choices": [{"message": {"content": json.dumps(ans)}}]}).encode()
                self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        env = {"GUARDIAN_LLM": "openai", "OPENAI_BASE_URL": f"http://127.0.0.1:{srv.server_port}/v1",
               "GUARDIAN_LLM_MODEL": "mock-model"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            an = ai.Analyst()
            out = an.explain(AIGuardrails().facts())
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            srv.shutdown()
        self.assertEqual(out["by"], "openai:mock-model")
        self.assertEqual(out["summary"], "Grounded summary.")
        self.assertEqual(seen["body"]["temperature"], 0)
        self.assertIn("Use ONLY the facts", seen["body"]["messages"][0]["content"])


class AIProviders(unittest.TestCase):
    KEYS = ("GUARDIAN_LLM", "GUARDIAN_LLM_MODEL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
            "OPENAI_BASE_URL", "OPENAI_API_KEY")

    def with_env(self, **kw):
        old = {k: os.environ.get(k) for k in self.KEYS}
        for k in self.KEYS:
            os.environ.pop(k, None)
        os.environ.update(kw)
        try:
            return ai.resolve()
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_detects_free_providers(self):
        g = self.with_env(GEMINI_API_KEY="x")
        self.assertEqual((g["provider"], g["base"]), ("gemini", ai.GEMINI_BASE))
        q = self.with_env(GROQ_API_KEY="x")
        self.assertEqual((q["provider"], q["model"]), ("groq", "llama-3.3-70b-versatile"))
        c = self.with_env(ANTHROPIC_API_KEY="x", GEMINI_API_KEY="y")
        self.assertEqual(c["provider"], "anthropic")
        self.assertEqual(self.with_env(GUARDIAN_LLM="none", GEMINI_API_KEY="x")["provider"], "none")


class AISummary(unittest.TestCase):
    FACTS = [{"id": "S1", "fact": "The application has 1692 components: 190 direct and 1502 transitive"},
             {"id": "S2", "fact": "P1-urgent findings went from 26 to 24; 0 new high or critical findings were introduced"}]

    def ans(self, **kw):
        a = {"headline": "Two urgent risks fixed.", "summary": "Urgent findings dropped from 26 to 24.",
             "key_points": ["1692 components inventoried (S1)", "0 new high findings (S2)"],
             "decision_needed": "Decide on the rest.", "cited_facts": ["S1", "S2"], "confidence": "high"}
        a.update(kw)
        return json.dumps(a)

    def test_accepts_grounded_and_rejects_invented_numbers(self):
        from guardian.ai_summary import _check
        self.assertIsNotNone(_check(self.ans(), self.FACTS)[0])
        bad, why = _check(self.ans(summary="Risk fell by 7.7% overall."), self.FACTS)
        self.assertIsNone(bad)
        self.assertIn("7.7", why)
        self.assertIsNone(_check(self.ans(key_points=["x (S9)"]), self.FACTS)[0])

    def test_summary_falls_back_when_model_invents(self):
        from guardian import ai_summary
        rep = json.loads((ROOT / "examples" / "juice-shop" / "guardian-report.json").read_text())
        out = ai_summary.summarize(rep, call=lambda s, u, m: self.ans(summary="Risk fell by 99 percent."))
        self.assertEqual(out["by"], "deterministic-template")
        self.assertIn("99", out["ai_rejected"])
        good = ai_summary.summarize(rep, call=lambda s, u, m: json.dumps(
            {"headline": "Fix verified.", "summary": "See facts.", "key_points": ["validated (S1)"],
             "decision_needed": "", "cited_facts": ["S1"], "confidence": "medium"}))
        self.assertNotEqual(good["by"], "deterministic-template")
