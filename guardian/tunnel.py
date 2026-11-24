"""Non-blocking public tunnel lifecycle with bounded startup and process cleanup."""
import atexit
import codecs
import json
import os
import re
import selectors
import shutil
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlsplit

STARTUP_TIMEOUT = 30
LOG_LIMIT = 12000
_state = dict(process=None, url=None, tool=None, status='stopped', error=None, log='')
_lock = threading.Lock()
_generation = 0
_ANSI = re.compile(r'\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]')


def _snapshot():
    """Caller owns _lock; never recursively acquire it."""
    return {k:v for k,v in _state.items() if k != 'process'}


def status():
    with _lock:
        return _snapshot()


def _update(generation, **values):
    with _lock:
        if generation != _generation: return False
        _state.update(values)
        return True


def detect():
    for name in ('cloudflared','ngrok'):
        path = shutil.which(name)
        if path: return name,path
        for prefix in ('/usr/local/bin','/opt/homebrew/bin'):
            path = os.path.join(prefix,name)
            if os.path.isfile(path) and os.access(path,os.X_OK): return name,path
    ssh = shutil.which('ssh')
    return ('localhost.run',ssh) if ssh else (None,None)


def extract_url(text, tool):
    """Parse complete provider hosts, including ANSI output and nested lhr.life names."""
    # Extract before stripping OSC hyperlinks (whose label may be truncated).
    clean = text.replace('\\/','/')
    for candidate in re.findall(r'https://[a-zA-Z0-9.-]+(?=[^a-zA-Z0-9.-]|$)',clean):
        host = urlsplit(candidate).hostname or ''
        suffixes = ('trycloudflare.com',) if tool=='cloudflared' else ('lhr.life','localhost.run')
        if any(host.endswith('.'+suffix) and host != 'admin.localhost.run' for suffix in suffixes):
            return candidate
    return None


def _extract_cloudflared_url(text):
    return extract_url(text,'cloudflared')


def _extract_ngrok_url_from_api(port):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://127.0.0.1:4040/api/tunnels',timeout=.5) as response:
            data = json.loads(response.read(65536))
        for tunnel in data.get('tunnels',[]):
            address = str(tunnel.get('config',{}).get('addr',''))
            if address.isdigit(): address = 'http://127.0.0.1:'+address
            elif '://' not in address: address = 'http://'+address
            parsed = urlsplit(address)
            url = tunnel.get('public_url','')
            if tunnel.get('proto')=='https' and urlsplit(url).scheme=='https' and parsed.hostname in ('localhost','127.0.0.1') and parsed.port==port:
                return url
    except (OSError,ValueError,TypeError):
        pass
    return None


def command(tool,binary,port):
    if tool=='cloudflared':
        return [binary,'tunnel','--url',f'http://127.0.0.1:{port}','--no-autoupdate']
    if tool=='ngrok':
        return [binary,'http',f'http://127.0.0.1:{port}','--log','stdout','--log-format','json']
    return [binary,'-T','-F',os.devnull,
            '-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new',
            '-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=10',
            '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
            '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','IdentityFile=none',
            '-R',f'80:127.0.0.1:{port}','nokey@localhost.run','--','--output','json']


def _terminate(process):
    if process is None: return
    try:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
    except OSError:
        pass


def _run(generation,tool,binary,port):
    proc = None
    try:
        proc = subprocess.Popen(command(tool,binary,port),stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
        if not _update(generation,process=proc): return
        started = time.monotonic(); last_ngrok_poll = 0; found = False; raw = ''
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ)
            while True:
                with _lock:
                    if generation != _generation: return
                events = selector.select(.15)
                for key,_ in events:
                    chunk = os.read(key.fd,4096)
                    if chunk:
                        raw = (raw+decoder.decode(chunk))[-LOG_LIMIT:]
                        _update(generation,log=_ANSI.sub('',raw)[-LOG_LIMIT:])
                        url = extract_url(raw,tool) if tool!='ngrok' else None
                        if url:
                            found = True
                            _update(generation,status='running',url=url,error=None)
                    else:
                        selector.unregister(key.fileobj)
                elapsed = time.monotonic()-started
                if proc.poll() is not None:
                    detail = _ANSI.sub('',raw).strip()[-700:]
                    raise RuntimeError(f'{tool} exited (code {proc.returncode}). '+(detail or 'No diagnostic output was received.'))
                if tool=='ngrok' and not found and elapsed-last_ngrok_poll>=.5:
                    last_ngrok_poll=elapsed
                    url = _extract_ngrok_url_from_api(port)
                    if url:
                        found=True; _update(generation,status='running',url=url,error=None)
                if not found and elapsed>=STARTUP_TIMEOUT:
                    raise TimeoutError(f'{tool} did not supply a public URL within {STARTUP_TIMEOUT}s. Check outbound network access and the tunnel log.')
    except Exception as exc:
        _update(generation,status='error',url=None,error=str(exc))
    finally:
        _terminate(proc)
        if proc and proc.stdout: proc.stdout.close()
        _update(generation,process=None)


def start(port=8787):
    global _generation
    if isinstance(port,bool) or not isinstance(port,int) or not 1<=port<=65535:
        raise ValueError('Invalid tunnel port')
    with _lock:
        if _state['status'] in ('starting','running'):
            return dict(ok=True,**_snapshot())
        tool,binary = detect()
        if not tool:
            _state.update(status='not_installed',error='No tunnel client found. Install OpenSSH or cloudflared.',url=None,tool=None)
            return dict(ok=False,**_snapshot())
        old = _state['process']
        _generation += 1
        generation = _generation
        _state.update(process=None,url=None,tool=tool,status='starting',error=None,log='')
        result = dict(ok=True,**_snapshot())
    # Never wait for network startup in the HTTP request. All cleanup is bounded.
    def launch():
        _terminate(old)
        _run(generation,tool,binary,port)
    threading.Thread(target=launch,daemon=True,name='guardian-tunnel').start()
    return result


def stop():
    global _generation
    with _lock:
        _generation += 1  # Stale workers cannot overwrite a newer run's state.
        proc = _state['process']
        _state.update(process=None,url=None,tool=None,status='stopped',error=None,log='')
    _terminate(proc)
    return dict(ok=True,**status())


atexit.register(stop)
