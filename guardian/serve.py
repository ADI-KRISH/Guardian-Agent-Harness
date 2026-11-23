"""Live presenter server: paste a repo link, watch the harness work, walk the panel through evidence, fix and report.

  .venv\\Scripts\\guardian serve [--port 8765] [--no-open]

Standard library only. Listens on 127.0.0.1 only; every POST needs the per-start token that is embedded in the page, and every
input is validated against a strict pattern before it reaches a subprocess (argument lists, never a shell). Scans and
validations run as `guardian` CLI subprocesses, so the live page exercises exactly the same code path as the terminal.
"""
from __future__ import annotations

import importlib.util
import json
import mimetypes
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import config, remediate
from .memory import Memory
from .tools import git

ROOT = Path(__file__).resolve().parent.parent
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
PROJ_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
RUN_RE = re.compile(r"^\d{8}-\d{6}$")
FIX_RE = re.compile(r"^FIX-[0-9A-F]{8}$")
FIND_RE = re.compile(r"^[A-Za-z0-9._:@/-]{1,160}$")
EVENT = re.compile(r"^\s*\[([\w-]+)\]\s+(.*)$")
FILE_OK = {".html", ".md", ".json", ".diff"}

_job: dict | None = None
_lock = threading.Lock()


def _builder():
    spec = importlib.util.spec_from_file_location("build_demo", ROOT / "demo" / "build_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _check(rx: re.Pattern, v, what: str) -> str:
    if not isinstance(v, str) or not rx.match(v) or ".." in v:
        raise ValueError(f"invalid {what}")
    return v


def _report_dir(project: str, run: str) -> Path:
    d = config.WORKSPACE / "reports" / _check(PROJ_RE, project, "project") / _check(RUN_RE, run, "run")
    if not (d / "report.json").exists():
        raise FileNotFoundError("no such report")
    return d


def start_job(kind: str, argv: list[str], project: str) -> dict:
    global _job
    with _lock:
        if _job and _job["proc"].poll() is None:
            raise ValueError(f"a {_job['kind']} is already running; wait for it to finish")
        log = config.WORKSPACE / "live" / f"{kind}-{int(time.time())}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        fh = open(log, "w", encoding="utf-8")
        proc = subprocess.Popen([sys.executable, "-m", "guardian.cli", *argv], cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                                env={**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"})
        _job = {"kind": kind, "proc": proc, "log": log, "t0": time.time(), "project": project, "fh": fh}
        return {"started": True}


def job_status() -> dict:
    j = _job
    if not j:
        return {"state": "idle"}
    rc = j["proc"].poll()
    lines = j["log"].read_text(encoding="utf-8", errors="replace").splitlines()
    events = [{"actor": m[1], "text": m[2][:240]} for ln in lines if (m := EVENT.match(ln))]
    other = [ln.strip() for ln in lines if ln.strip() and not EVENT.match(ln)]
    out = {"state": "running" if rc is None else ("done" if rc in (0, 1) else "failed"), "kind": j["kind"], "project": j["project"],
           "elapsed": round(time.time() - j["t0"]), "events": events[-120:], "n_events": len(events), "phase": (other[-1] if other else "starting")[:200],
           "tail": "\n".join(lines[-12:])[-1500:], "code": rc}
    if rc is not None and j["kind"] == "scan":
        runs = sorted((config.WORKSPACE / "reports" / j["project"]).glob("*/report.json"), key=lambda p: p.parent.name, reverse=True)
        out["run_id"] = runs[0].parent.name if runs else None
        if rc not in (0, 1) or not runs:
            out["state"] = "failed"
    return out


def known_runs() -> list[dict]:
    runs = sorted(config.WORKSPACE.glob("reports/*/*/report.json"), key=lambda p: p.parent.name, reverse=True)
    return [{"project": p.parent.parent.name, "run_id": p.parent.name} for p in runs[:10]]


class Handler(BaseHTTPRequestHandler):
    token = ""
    port = 0
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):   # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json", extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, default=str).encode())

    def _local(self) -> bool:
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def do_GET(self):  # noqa: N802
        if not self._local():
            return self._json({"error": "forbidden"}, 403)
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == "/":
                html = (ROOT / "demo" / "template.html").read_text(encoding="utf-8").replace("__DATA__", "null").replace("__TOKEN__", self.token)
                return self._send(200, html.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"})
            if u.path == "/api/state":
                return self._json({"runs": known_runs(), "job": job_status(), "ai": config.load()["llm"]["provider"] != "none"})
            if u.path == "/api/job":
                return self._json(job_status())
            if u.path == "/api/data":
                d = _report_dir(q.get("project", ""), q.get("run", ""))
                return self._json(_builder().build(d, None))
            if u.path.startswith("/files/"):
                parts = u.path[len("/files/"):].split("/", 2)
                if len(parts) != 3:
                    raise FileNotFoundError("bad path")
                base = _report_dir(parts[0], parts[1]).resolve()
                f = (base / parts[2]).resolve()
                if not f.is_relative_to(base) or f.suffix not in FILE_OK or not f.is_file():
                    raise FileNotFoundError("not available")
                # sandbox: report files hold text from the scanned repo; they may run their own scripts but cannot touch this page or its token
                return self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "text/plain",
                                  {"Content-Security-Policy": "sandbox allow-scripts allow-popups"})
            return self._json({"error": "not found"}, 404)
        except (ValueError, KeyError, FileNotFoundError, PermissionError) as e:
            return self._json({"error": str(e)}, 400)
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"{type(e).__name__}"}, 500)

    def do_POST(self):  # noqa: N802
        origin = self.headers.get("Origin")
        if not self._local() or self.headers.get("X-Guardian-Token") != self.token or (origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost")):
            return self._json({"error": "forbidden"}, 403)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 10_000:
                raise ValueError("request too large")
            b = json.loads(self.rfile.read(n) or b"{}")
            p = urlparse(self.path).path
            if p == "/api/scan":
                repo = str(b.get("repo", "")).strip()
                if re.match(r"^(www\.)?github\.com/", repo):
                    repo = "https://" + repo
                repo = _check(URL_RE, repo, "repository link (use an https:// URL)")
                base = str(b.get("base", "")).strip()
                argv = ["scan", repo] + (["--base", _check(REF_RE, base, "baseline ref")] if base else []) + ([] if b.get("ai", True) else ["--no-llm"])
                return self._json(start_job("scan", argv, git.project_name(repo)))
            if p == "/api/propose":
                d = _report_dir(b.get("project", ""), b.get("run", ""))
                return self._json(remediate.propose(Memory(), d.parent.name, _check(FIND_RE, b.get("finding", ""), "finding id"), d.name, log=lambda m: None))
            if p == "/api/approve":
                st = "approved" if b.get("decision", "approved") == "approved" else "rejected"
                Memory().decide_proposal(_check(FIX_RE, b.get("proposal", ""), "proposal id"), st, str(b.get("by", ""))[:80], str(b.get("reason", ""))[:300])
                return self._json({"ok": True, "status": st})
            if p == "/api/validate":
                pid = _check(FIX_RE, b.get("proposal", ""), "proposal id")
                prop = Memory().get_proposal(pid)
                if prop["status"] != "approved":
                    raise PermissionError("this fix has not been approved by a named human yet")
                test = str(b.get("test", "")).strip()
                if len(test) > 200 or "\n" in test:
                    raise ValueError("test command too long")
                return self._json(start_job("validate", ["validate", pid] + (["--test", test] if test else []), prop["project"]))
            return self._json({"error": "not found"}, 404)
        except (ValueError, KeyError, FileNotFoundError, PermissionError) as e:
            return self._json({"error": str(e)}, 400)
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"{type(e).__name__}"}, 500)


def serve(port: int = 8765, open_browser: bool = True) -> None:
    Handler.token = secrets.token_urlsafe(24)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    Handler.port = srv.server_address[1]
    url = f"http://127.0.0.1:{Handler.port}/"
    print(f"Guardian live presenter: {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
