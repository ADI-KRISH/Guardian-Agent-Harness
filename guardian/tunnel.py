"""Local tunnel manager — creates a public HTTPS URL for GitHub webhooks.

Supports cloudflared (preferred, no account) and ngrok (account required).
The tunnel process runs as a daemon; its public URL is returned via the API.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

_state = {
    'process': None,
    'url': None,
    'tool': None,
    'status': 'stopped',   # stopped | starting | running | error
    'error': None,
    'log': '',
}
_lock = threading.Lock()


def status():
    with _lock:
        return {k: v for k, v in _state.items() if k != 'process'}


def _set(**kw):
    with _lock:
        _state.update(kw)


def detect():
    """Return ('cloudflared'|'ngrok'|None, path)."""
    for name in ('cloudflared', 'ngrok'):
        path = shutil.which(name)
        if path:
            return name, path
    # Common macOS install locations
    for candidate in ('/usr/local/bin/cloudflared', '/opt/homebrew/bin/cloudflared',
                      '/usr/local/bin/ngrok', '/opt/homebrew/bin/ngrok'):
        if os.path.isfile(candidate):
            tool = 'cloudflared' if 'cloudflared' in candidate else 'ngrok'
            return tool, candidate
    return None, None


def _extract_cloudflared_url(text):
    m = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', text)
    return m.group(0) if m else None


def _extract_ngrok_url_from_api():
    """ngrok exposes its tunnel URL via a local REST API on port 4040."""
    try:
        with urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=3) as r:
            data = json.loads(r.read())
        for t in data.get('tunnels', []):
            if t.get('proto') == 'https':
                return t['public_url']
    except Exception:
        pass
    return None


def _run_cloudflared(binary, port):
    _set(status='starting', url=None, error=None, log='')
    cmd = [binary, 'tunnel', '--url', f'http://localhost:{port}', '--no-autoupdate']
    buf = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        with _lock:
            _state['process'] = proc
        for line in proc.stdout:
            buf.append(line)
            log_text = ''.join(buf[-40:])
            with _lock:
                _state['log'] = log_text
            url = _extract_cloudflared_url(log_text)
            if url and _state['status'] == 'starting':
                _set(status='running', url=url, tool='cloudflared')
        proc.wait()
        _set(status='stopped', url=None)
    except Exception as exc:
        _set(status='error', error=str(exc))


def _run_ngrok(binary, port):
    _set(status='starting', url=None, error=None, log='')
    cmd = [binary, 'http', str(port)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with _lock:
            _state['process'] = proc
        # Poll the ngrok local API until a tunnel URL appears (up to 15 s)
        for _ in range(30):
            time.sleep(0.5)
            if proc.poll() is not None:
                _set(status='error', error='ngrok exited unexpectedly (check auth token)')
                return
            url = _extract_ngrok_url_from_api()
            if url:
                _set(status='running', url=url, tool='ngrok')
                break
        else:
            _set(status='error', error='ngrok started but no HTTPS tunnel URL found after 15 s. '
                 'Ensure you are logged in: run "ngrok config add-authtoken YOUR_TOKEN" first.')
            proc.terminate()
            return
        proc.wait()
        _set(status='stopped', url=None)
    except Exception as exc:
        _set(status='error', error=str(exc))


def start(port=8787):
    with _lock:
        if _state['status'] in ('starting', 'running'):
            return {'ok': False, 'error': 'Tunnel already running', **status()}
        proc = _state.get('process')
        if proc and proc.poll() is None:
            proc.terminate()

    tool, binary = detect()
    if not tool:
        return {
            'ok': False,
            'status': 'not_installed',
            'error': 'No tunnel tool found',
            'install_options': [
                {
                    'name': 'cloudflared (recommended — free, no account)',
                    'mac': 'brew install cloudflared',
                    'linux': 'wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && sudo dpkg -i cloudflared-linux-amd64.deb',
                    'download': 'https://github.com/cloudflare/cloudflared/releases/latest',
                },
                {
                    'name': 'ngrok (requires free account + authtoken)',
                    'mac': 'brew install ngrok/ngrok/ngrok',
                    'linux': 'snap install ngrok',
                    'download': 'https://ngrok.com/download',
                },
            ],
        }

    worker = threading.Thread(
        target=_run_cloudflared if tool == 'cloudflared' else _run_ngrok,
        args=(binary, port),
        daemon=True,
    )
    worker.start()
    # Wait up to 12 s for the URL to appear
    for _ in range(24):
        time.sleep(0.5)
        s = status()
        if s['status'] == 'running':
            return {'ok': True, **s}
        if s['status'] == 'error':
            return {'ok': False, **s}
    s = status()
    return {'ok': False, 'error': 'Tunnel URL not found in time; check logs', **s}


def stop():
    with _lock:
        proc = _state.get('process')
        if proc and proc.poll() is None:
            proc.terminate()
        _state.update(status='stopped', url=None, process=None)
    return {'ok': True, 'status': 'stopped'}
