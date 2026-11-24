"""Tamper-evident audit trail: append-only JSON lines, each entry hash-chained to the previous one.

Every stage logs what it did, who did it (guardian | ai:<model> | human:<name>), and hashes of
the inputs it used. `verify()` recomputes the chain; any edited or deleted line breaks it.
"""
from __future__ import annotations

import getpass
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class Audit:
    def __init__(self, run_dir: Path):
        self.path = Path(run_dir) / "audit.jsonl"

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        lines = [l for l in self.path.read_text().splitlines() if l.strip()]
        return json.loads(lines[-1])["hash"] if lines else "0" * 64

    def log(self, stage: str, actor: str, action: str, details: dict) -> dict:
        entry = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "stage": stage,
                 "actor": actor, "action": action, "details": details, "host_user": _user(),
                 "prev": self._last_hash()}
        entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def verify(self) -> dict:
        prev = "0" * 64
        for i, e in enumerate(self.entries()):
            h = e.pop("hash")
            if e["prev"] != prev:
                return {"ok": False, "broken_at": i, "reason": "prev-hash mismatch (entry removed or reordered)"}
            if hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
                return {"ok": False, "broken_at": i, "reason": "entry content modified"}
            prev = h
        return {"ok": True, "entries": len(self.entries()), "head": prev}


def file_sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else ""


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
