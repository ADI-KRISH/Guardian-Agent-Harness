"""Memory: one SQLite file with five stores.

baselines  - trusted snapshots; written ONLY by a human approval (approve_baseline)
findings   - every finding of every run, with status set by humans
decisions  - append-only audit log: every decision by an agent or a human, with its reason
lessons    - human-approved rules learned from labels (scoped, with expiry)
cache      - knowledge cache (tool/registry lookups) with fetch time
Working memory for a run lives in the Run object and only its summary is stored.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .config import WORKSPACE

SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (project TEXT, ref TEXT, snapshot TEXT, approved_by TEXT, reason TEXT, ts REAL,
  PRIMARY KEY (project, ref));
CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, project TEXT, base_ref TEXT, head_ref TEXT, started REAL, finished REAL, summary TEXT);
CREATE TABLE IF NOT EXISTS findings (id TEXT, run_id TEXT, project TEXT, fingerprint TEXT, data TEXT,
  status TEXT DEFAULT 'open', label_by TEXT, label_reason TEXT, PRIMARY KEY (id, run_id));
CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, project TEXT, actor TEXT,
  decision TEXT, why TEXT, inputs TEXT, rule TEXT, confidence TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS lessons (id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, kind TEXT, rule TEXT, scope TEXT,
  reason TEXT, approved_by TEXT, expires REAL, ts REAL);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, project TEXT, run_id TEXT, finding_id TEXT, data TEXT,
  status TEXT DEFAULT 'proposed', decided_by TEXT, decided_reason TEXT, result TEXT, ts REAL);
CREATE TRIGGER IF NOT EXISTS decisions_append_only_u BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_append_only_d BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

# Finding types a lesson may never suppress (guardrail).
UNSUPPRESSIBLE = {"backdoor_signal", "integrity_change", "typosquat", "canary_missed"}


class Memory:
    def __init__(self, path: Path | None = None):
        path = path or WORKSPACE / "guardian.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    # ---------- audit log ----------
    def decide(self, run_id: str, project: str, actor: str, decision: str, why: str,
               inputs: dict | None = None, rule: str = "", confidence: str = "") -> None:
        self.db.execute(
            "INSERT INTO decisions (run_id, project, actor, decision, why, inputs, rule, confidence, ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, project, actor, decision, why, json.dumps(inputs or {}, default=str), rule, confidence, time.time()))
        self.db.commit()

    def decisions(self, run_id: str) -> list[dict]:
        cur = self.db.execute("SELECT seq, actor, decision, why, inputs, rule, confidence, ts FROM decisions WHERE run_id=? ORDER BY seq", (run_id,))
        return [dict(zip(["seq", "actor", "decision", "why", "inputs", "rule", "confidence", "ts"], r)) for r in cur]

    # ---------- baselines (human-only writes) ----------
    def approve_baseline(self, project: str, ref: str, snapshot: dict, approved_by: str, reason: str) -> None:
        if not approved_by or not reason:
            raise ValueError("A baseline can only be approved by a named human with a reason.")
        self.db.execute("INSERT OR REPLACE INTO baselines VALUES (?,?,?,?,?,?)",
                        (project, ref, json.dumps(snapshot), approved_by, reason, time.time()))
        self.db.commit()
        self.decide("-", project, f"human:{approved_by}", f"approve baseline {ref}", reason, rule="baseline-human-only")

    def get_baseline(self, project: str, ref: str | None = None) -> tuple[str, dict] | None:
        q = "SELECT ref, snapshot FROM baselines WHERE project=?" + (" AND ref=?" if ref else "") + " ORDER BY ts DESC LIMIT 1"
        row = self.db.execute(q, (project, ref) if ref else (project,)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    # ---------- runs and findings ----------
    def start_run(self, run_id: str, project: str, base_ref: str, head_ref: str) -> None:
        self.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?)", (run_id, project, base_ref, head_ref, time.time(), None, None))
        self.db.commit()

    def finish_run(self, run_id: str, summary: dict) -> None:
        self.db.execute("UPDATE runs SET finished=?, summary=? WHERE id=?", (time.time(), json.dumps(summary), run_id))
        self.db.commit()

    def save_findings(self, run_id: str, project: str, findings: list[dict]) -> None:
        for f in findings:
            prev = self.db.execute("SELECT status, label_by, label_reason FROM findings WHERE project=? AND fingerprint=? AND status!='open' ORDER BY rowid DESC LIMIT 1",
                                   (project, f["fingerprint"])).fetchone()
            status = prev or ("open", None, None)
            f["status"] = status[0]
            self.db.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)",
                            (f["id"], run_id, project, f["fingerprint"], json.dumps(f, default=str), *status))
        self.db.commit()

    def label(self, project: str, finding_id: str, status: str, by: str, reason: str) -> None:
        if status not in {"confirmed", "false_positive", "accepted", "open"}:
            raise ValueError("status must be confirmed | false_positive | accepted | open")
        if not by or not reason:
            raise ValueError("A label needs the reviewer's name and a reason.")
        n = self.db.execute("UPDATE findings SET status=?, label_by=?, label_reason=? WHERE project=? AND id=?",
                            (status, by, reason, project, finding_id)).rowcount
        self.db.commit()
        if not n:
            raise KeyError(f"No finding {finding_id} in {project}")
        self.decide("-", project, f"human:{by}", f"label {finding_id} as {status}", reason, rule="human-label")

    # ---------- lessons ----------
    def active_lessons(self, project: str) -> list[dict]:
        cur = self.db.execute("SELECT id, kind, rule, scope, reason, approved_by, expires FROM lessons WHERE project=? AND (expires IS NULL OR expires>?)",
                              (project, time.time()))
        return [dict(zip(["id", "kind", "rule", "scope", "reason", "approved_by", "expires"], r)) for r in cur]

    def add_lesson(self, project: str, kind: str, rule: str, scope: str, reason: str, approved_by: str, days: int = 30) -> None:
        if kind == "suppress" and rule in UNSUPPRESSIBLE:
            raise ValueError(f"Guardrail: findings of type '{rule}' can never be suppressed by a lesson.")
        if not approved_by:
            raise ValueError("Lessons need human approval.")
        self.db.execute("INSERT INTO lessons (project, kind, rule, scope, reason, approved_by, expires, ts) VALUES (?,?,?,?,?,?,?,?)",
                        (project, kind, rule, scope, reason, approved_by, time.time() + days * 86400, time.time()))
        self.db.commit()
        self.decide("-", project, f"human:{approved_by}", f"approve lesson {kind}:{rule} on {scope}", reason, rule="lesson-human-approval")

    # ---------- fix proposals (human approval gate) ----------
    def save_proposal(self, p: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO proposals (id, project, run_id, finding_id, data, status, ts) VALUES (?,?,?,?,?,'proposed',?)",
                        (p["id"], p["project"], p["run_id"], p["finding_id"], json.dumps(p, default=str), time.time()))
        self.db.commit()

    def get_proposal(self, pid: str) -> dict:
        row = self.db.execute("SELECT data, status, decided_by, decided_reason, result FROM proposals WHERE id=?", (pid,)).fetchone()
        if not row:
            raise KeyError(f"No fix proposal {pid}")
        p = json.loads(row[0])
        p.update(status=row[1], decided_by=row[2], decided_reason=row[3], result=json.loads(row[4]) if row[4] else None)
        return p

    def list_proposals(self, project: str, run_id: str | None = None) -> list[dict]:
        q, a = "SELECT id FROM proposals WHERE project=?" + (" AND run_id=?" if run_id else "") + " ORDER BY ts DESC", ((project, run_id) if run_id else (project,))
        return [self.get_proposal(r[0]) for r in self.db.execute(q, a).fetchall()]

    def decide_proposal(self, pid: str, status: str, by: str, reason: str) -> None:
        """Only a named human can approve or reject a fix; nothing is built or tested before approval."""
        if status not in {"approved", "rejected"}:
            raise ValueError("status must be approved | rejected")
        if not by.strip() or not reason.strip():
            raise ValueError("A fix can only be approved or rejected by a named human with a reason.")
        p = self.get_proposal(pid)
        self.db.execute("UPDATE proposals SET status=?, decided_by=?, decided_reason=? WHERE id=?", (status, by.strip(), reason.strip(), pid))
        self.db.commit()
        self.decide(f"fix-{pid}", p["project"], f"human:{by.strip()}", f"{status} fix {pid} ({p['package']} {p['from']} -> {p['to']})",
                    reason.strip(), rule="human-approval", confidence="")

    def save_result(self, pid: str, result: dict) -> None:
        self.db.execute("UPDATE proposals SET result=? WHERE id=?", (json.dumps(result, default=str), pid))
        self.db.commit()

    # ---------- knowledge cache ----------
    def cache_get(self, key: str, max_age_s: float = 86400):
        row = self.db.execute("SELECT value, ts FROM cache WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row and time.time() - row[1] < max_age_s else None

    def cache_put(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?)", (key, json.dumps(value, default=str), time.time()))
        self.db.commit()
