"""Tiny HTTP helper with on-disk cache and an offline switch."""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

CACHE_DIR = Path(os.environ.get("GUARDIAN_CACHE", Path.home() / ".cache" / "guardian"))
OFFLINE = os.environ.get("GUARDIAN_OFFLINE") == "1"
UA = "supply-chain-guardian/0.1 (+hackathon)"


class NetError(Exception):
    pass


def _ctx():
    cafile = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def fetch_json(url: str, body: Optional[dict] = None, headers: Optional[dict] = None,
               ttl: int = 6 * 3600, timeout: int = 20):
    if OFFLINE:
        raise NetError("offline mode")
    key = hashlib.sha256((url + json.dumps(body, sort_keys=True) + json.dumps(headers or {}, sort_keys=True)).encode()).hexdigest()
    cpath = CACHE_DIR / key[:2] / f"{key}.json"
    if cpath.exists() and time.time() - cpath.stat().st_mtime < ttl:
        try:
            return json.loads(cpath.read_text())
        except ValueError:
            pass
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            payload = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            payload = {"__status__": 404}
        else:
            raise NetError(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise NetError(f"{url}: {e}") from e
    try:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        cpath.write_text(json.dumps(payload))
    except OSError:
        pass
    return payload
