"""Opt-in live tunnel smoke test using a disposable server, never app data."""
import json
from pathlib import Path
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guardian import tunnel

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        data=b'{"guardian_tunnel_smoke":"ok"}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)

server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    result=tunnel.start(server.server_port);print(json.dumps(result),flush=True)
    until=time.monotonic()+35
    while time.monotonic()<until:
        result=tunnel.status()
        if result['status'] in ('running','error'):break
        time.sleep(.25)
    print(json.dumps({k:v for k,v in result.items() if k!='log'}),flush=True)
    if result['status']!='running': print(result.get('log','')[-1500:],flush=True)
    if result['status']!='running':raise SystemExit(1)
    request=urllib.request.Request(result['url']+'/api/webhook/github',data=b'{}',headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=15) as response:
        payload=json.load(response)
    assert payload=={'guardian_tunnel_smoke':'ok'},payload
    print('Public HTTPS POST reached disposable local server.',flush=True)
finally:
    tunnel.stop();server.shutdown();server.server_close()
