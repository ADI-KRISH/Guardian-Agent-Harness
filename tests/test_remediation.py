"""Day 2: fix proposals, the human approval gate, edits and the verdict rule. No Docker needed."""
import json
import tempfile
import unittest
from pathlib import Path

from guardian import remediate
from guardian.agents import fixer, validator
from guardian.memory import Memory


def vuln(fid, comp, fixed, level="Critical", score=9.0):
    return {"id": fid, "type": "known_vulnerability", "component": comp, "fixed_versions": fixed, "risk_level": level, "score": score,
            "advisory_ids": [fid], "dependency_paths": [["app:package-lock.json", comp]]}


def fixture(direct=True):
    comp = "npm:jsonwebtoken@0.4.0"
    report = {"run_id": "R1", "project": "demo", "head_ref": "origin/HEAD", "head_commit": {"sha": "abc123"},
              "findings": [vuln("CVE-A", comp, ["4.2.2"]), vuln("CVE-B", comp, ["9.0.0"], "High", 7.0),
                           {"id": "SSCG-1", "type": "backdoor_signal", "component": "", "risk_level": "High", "score": 7.0}]}
    inv = {"packages": {comp: {"ecosystem": "npm", "name": "jsonwebtoken", "version": "0.4.0", "lockfiles": ["package-lock.json"]}},
           "roots": {"app:package-lock.json": [comp] if direct else []}}
    return report, inv


class Proposal(unittest.TestCase):
    def test_pick_fix_stays_in_major_when_possible_else_lowest_above(self):
        self.assertEqual(fixer.pick_fix("4.1.0", ["4.2.2", "9.0.0"]), "4.2.2")
        self.assertEqual(fixer.pick_fix("0.4.0", ["4.2.2", "9.0.0"]), "4.2.2")
        self.assertIsNone(fixer.pick_fix("9.0.0", ["4.2.2", "9.0.0"]))
        self.assertIsNone(fixer.pick_fix("1.0.0", ["deadbeefcommit"]))

    def test_target_fixes_every_advisory_and_reports_expected_reduction(self):
        p = fixer.propose(*fixture(), "CVE-A")
        self.assertTrue(p["ok"])
        self.assertEqual((p["to"], p["kind"], p["file"]), ("9.0.0", "dependency-bump", "package.json"))   # max of the picks fixes both
        self.assertEqual(sorted(p["resolves"]), ["CVE-A", "CVE-B"])
        self.assertEqual(p["expected_risk_reduction"]["levels"]["Critical"], 1)
        self.assertTrue(p["major_bump"] and "Major version jump" in p["compatibility_note"] and p["rollback"])

    def test_transitive_dependency_becomes_an_override_with_a_warning(self):
        p = fixer.propose(*fixture(direct=False), "CVE-A")
        self.assertEqual(p["kind"], "override")
        self.assertIn("Transitive", p["compatibility_note"])

    def test_nested_older_copies_are_forced_too_and_the_edit_writes_a_dollar_override(self):
        rep, inv = fixture()
        old = "npm:jsonwebtoken@0.1.0"
        inv["packages"][old] = {"ecosystem": "npm", "name": "jsonwebtoken", "version": "0.1.0", "lockfiles": ["package-lock.json"]}
        inv["graph"] = {"npm:express-jwt@0.1.3": [old]}
        p = fixer.propose(rep, inv, "CVE-A")
        self.assertTrue(p["also_override"])
        self.assertIn("express-jwt", p["compatibility_note"])
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text('{\n  "dependencies": {\n    "jsonwebtoken": "0.4.0"\n  }\n}\n', encoding="utf-8")
        fixer.apply_edit(p, d)
        out = json.loads((d / "package.json").read_text(encoding="utf-8"))
        self.assertEqual((out["dependencies"]["jsonwebtoken"], out["overrides"]["jsonwebtoken"]), ("9.0.0", "$jsonwebtoken"))

    def test_refuses_what_it_cannot_fix(self):
        rep, inv = fixture()
        self.assertFalse(fixer.propose(rep, inv, "SSCG-1")["ok"])          # not a known vulnerability
        self.assertFalse(fixer.propose(rep, inv, "NOPE")["ok"])
        for f in rep["findings"][:2]:
            f["fixed_versions"] = []
        self.assertIn("no fixed version", fixer.propose(rep, inv, "CVE-A")["reason"])


class Edits(unittest.TestCase):
    def _apply(self, kind, manifest_text, name="jsonwebtoken", old="0.4.0", new="9.0.0", file="package.json"):
        d = Path(tempfile.mkdtemp())
        (d / file).write_text(manifest_text, encoding="utf-8")
        fixer.apply_edit({"kind": kind, "package": name, "from": old, "to": new, "file": file}, d)
        return (d / file).read_text(encoding="utf-8")

    def test_direct_bump_keeps_formatting_and_caret(self):
        src = '{\n  "name": "x",\n  "dependencies": {\n    "jsonwebtoken": "0.4.0",\n    "other": "1.0.0"\n  }\n}\n'
        out = self._apply("dependency-bump", src)
        self.assertEqual(out, src.replace('"jsonwebtoken": "0.4.0"', '"jsonwebtoken": "9.0.0"'))
        self.assertIn('"jsonwebtoken": "^9.0.0"', self._apply("dependency-bump", src.replace('"0.4.0"', '"^0.4.0"')))

    def test_override_is_added_without_losing_other_keys(self):
        out = json.loads(self._apply("override", '{\n    "name": "x",\n    "dependencies": {"a": "1.0.0"}\n}\n'))
        self.assertEqual(out["overrides"], {"jsonwebtoken": "9.0.0"})
        self.assertEqual(out["dependencies"], {"a": "1.0.0"})

    def test_requirements_pin(self):
        out = self._apply("requirements-pin", "flask==2.0.0\nRequests==2.19.0\n", "requests", "2.19.0", "2.32.0", "requirements.txt")
        self.assertEqual(out, "flask==2.0.0\nRequests==2.32.0\n")

    def test_missing_dependency_is_an_error_not_a_silent_noop(self):
        with self.assertRaises(ValueError):
            self._apply("dependency-bump", '{"dependencies": {"other": "1.0.0"}}')


class ApprovalGate(unittest.TestCase):
    def setUp(self):
        self.mem = Memory(Path(tempfile.mkdtemp()) / "t.db")
        self.p = fixer.propose(*fixture(), "CVE-A")
        self.mem.save_proposal(self.p)

    def test_validate_refuses_until_a_named_human_approves(self):
        with self.assertRaises(PermissionError):
            remediate.validate(self.mem, self.p["id"])
        with self.assertRaises(ValueError):
            self.mem.decide_proposal(self.p["id"], "approved", "", "looks fine")
        with self.assertRaises(ValueError):
            self.mem.decide_proposal(self.p["id"], "approved", "Asha", " ")
        self.mem.decide_proposal(self.p["id"], "rejected", "Asha", "too risky")
        with self.assertRaises(PermissionError):                      # a rejected fix is not validated either
            remediate.validate(self.mem, self.p["id"])

    def test_approval_is_in_the_append_only_audit_log(self):
        self.mem.decide_proposal(self.p["id"], "approved", "Asha", "reviewed the changelog")
        row = [d for d in self.mem.decisions(f"fix-{self.p['id']}") if d["actor"] == "human:Asha"]
        self.assertEqual(len(row), 1)
        self.assertEqual(self.mem.get_proposal(self.p["id"])["status"], "approved")


class Verdict(unittest.TestCase):
    ok = [{"name": "docker build", "status": "pass", "detail": ""}, {"name": "project tests", "status": "pass", "detail": ""}]

    def test_verified_needs_everything(self):
        self.assertEqual(validator.decide_verdict(self.ok, True, [])[0], "verified")

    def test_skipped_tests_cap_the_verdict_at_verified_with_gaps(self):
        steps = self.ok[:1] + [{"name": "project tests", "status": "skipped", "detail": ""}]
        self.assertEqual(validator.decide_verdict(steps, True, [])[0], "verified-with-gaps")

    def test_any_failure_target_still_present_or_new_high_risk_is_not_verified(self):
        self.assertEqual(validator.decide_verdict(self.ok + [{"name": "smoke import", "status": "fail", "detail": "x"}], True, [])[0], "not-verified")
        self.assertEqual(validator.decide_verdict(self.ok, False, [])[0], "not-verified")
        self.assertEqual(validator.decide_verdict(self.ok, True, [{"id": "CVE-NEW"}])[0], "not-verified")

    def test_sbom_diff(self):
        b = {"a": {"ecosystem": "npm", "name": "jwt", "version": "0.4.0"}, "b": {"ecosystem": "npm", "name": "gone", "version": "1.0.0"}}
        a = {"c": {"ecosystem": "npm", "name": "jwt", "version": "9.0.0"}, "d": {"ecosystem": "npm", "name": "new", "version": "2.0.0"}}
        d = validator.sbom_diff(b, a)
        self.assertEqual((d["updated"], d["added"], d["removed"]), (["npm:jwt 0.4.0 -> 9.0.0"], ["npm:new@2.0.0"], ["npm:gone@1.0.0"]))


if __name__ == "__main__":
    unittest.main()
