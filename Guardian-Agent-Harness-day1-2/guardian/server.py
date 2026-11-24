import json
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from .engine import run_scan
from .evaluation import evaluate


def serve(store, host='127.0.0.1', port=8787):
    store.recover_validations()
    token=secrets.token_urlsafe(32); jobs={}; lock=threading.Lock()
    static=Path(__file__).parent/'static'
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,status,payload,mime='application/json'):
            data=json.dumps(payload).encode() if mime=='application/json' else payload
            self.send_response(status)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; worker-src blob:; frame-ancestors 'none'; base-uri 'self'")
            self.end_headers(); self.wfile.write(data)
        def valid_host(self):
            return self.headers.get('Host','') in {f'127.0.0.1:{port}',f'localhost:{port}'}
        def do_GET(self):
            if not self.valid_host(): return self.send(403,{'error':'Invalid Host'})
            path=urlparse(self.path).path
            try:
                if path=='/api/session': return self.send(200,{'token':token})
                if path.startswith('/api/validations/'):
                    return self.send(200,store.validation(path.rsplit('/',1)[-1]))
                if path=='/api/scans': return self.send(200,store.list())
                if path=='/api/lessons': return self.send(200,store.lessons())
                if path=='/api/evaluation': return self.send(200,evaluate())
                if path.startswith('/api/jobs/'):
                    with lock: job=dict(jobs.get(path.rsplit('/',1)[-1],{}))
                    return self.send(200,job) if job else self.send(404,{'error':'Job not found'})
                if path.startswith('/api/scans/'):
                    parts=path.strip('/').split('/'); scan=store.get(parts[2])
                    if len(parts)==4 and parts[3]=='remediations': return self.send(200,store.recommendations(scan['id']))
                    if len(parts)==4 and parts[3]=='sbom': return self.send(200,scan['sbom'])
                    return self.send(200,scan)
                names={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/cytoscape.min.js':'cytoscape.min.js'}
                if path not in names: return self.send(404,{'error':'Not found'})
                mime={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8','/cytoscape.min.js':'text/javascript; charset=utf-8'}[path]
                return self.send(200,(static/names[path]).read_bytes(),mime)
            except ValueError as exc: self.send(404,{'error':str(exc)})
        def do_POST(self):
            if not self.valid_host() or self.headers.get('X-Guardian-Token')!=token:
                return self.send(403,{'error':'Invalid same-origin session token'})
            origin=self.headers.get('Origin')
            if origin and origin not in {f'http://127.0.0.1:{port}',f'http://localhost:{port}'}:
                return self.send(403,{'error':'Cross-origin writes are blocked'})
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=65536: raise ValueError('Invalid request size')
                data=json.loads(self.rfile.read(size))
                if not isinstance(data,dict): raise ValueError('Expected a JSON object')
                path=urlparse(self.path).path
                if path=='/api/scans':
                    demo=bool(data.get('demo'))
                    source=str(Path(__file__).parent.parent/'examples'/'demo') if demo else str(data.get('source','')).strip()
                    if not source: raise ValueError('Enter a local repository path or public GitHub URL')
                    with lock:
                        if any(j['status']=='running' for j in jobs.values()): return self.send(409,{'error':'A scan is already running'})
                        jid=uuid.uuid4().hex[:12]; jobs[jid]={'status':'running','stage':'Preparing repository'}
                    def work():
                        def progress(stage):
                            with lock: jobs[jid]['stage']=stage
                        try:
                            scan=run_scan(source,store,offline=bool(data.get('offline')),planted=demo,progress=progress,resolve=bool(data.get('resolve',True)),ai=bool(data.get('ai')),model=data.get('model') or None,scan_images=bool(data.get('scan_images')))
                            with lock: jobs[jid]={'status':'complete','scan_id':scan['id']}
                        except Exception as exc:
                            with lock: jobs[jid]={'status':'failed','error':str(exc)}
                    threading.Thread(target=work,daemon=True).start()
                    return self.send(202,{'job_id':jid})
                if path=='/api/remediation/recommend':
                    return self.send(200,store.recommend(data['scan_id'],data['finding_id']))
                if path in ('/api/remediation/decision','/api/remediation/validate'):
                    if path.endswith('/decision'):
                        result=store.decide_remediation(data['plan_id'],data['status'],data.get('actor',''),data.get('reason',''))
                        if data['status']!='approved' or not data.get('validate'):
                            return self.send(200,result)
                    mode='rescan_only' if data.get('mode')=='rescan_only' else 'full'
                    validation_id=store.begin_validation(data['plan_id'])
                    def validation_work():
                        from .validator import validate
                        validate(store,data['plan_id'],validation_id,lambda stage:store.validation_progress(validation_id,stage),mode=mode)
                    threading.Thread(target=validation_work,daemon=True).start()
                    return self.send(202,{'validation_id':validation_id,'status':'running','applied':False})
                if path=='/api/remediation/commit':
                    from .commit import commit_validated_fix
                    return self.send(200,commit_validated_fix(store,data['validation_id'],data.get('actor',''),data.get('reason',''),bool(data.get('accept_inconclusive'))))
                if path=='/api/review': store.review(data['scan_id'],data['finding_id'],data['status'],data.get('actor',''),data.get('reason',''))
                elif path=='/api/baseline': store.promote(data['scan_id'],data.get('actor',''),data.get('reason',''))
                elif path=='/api/lessons/approve': store.approve_lesson(int(data['lesson_id']),data.get('actor',''),data.get('reason',''))
                else: return self.send(404,{'error':'Not found'})
                self.send(200,{'ok':True})
            except (ValueError,KeyError,TypeError) as exc: self.send(400,{'error':str(exc)})
            except Exception: self.send(500,{'error':'Internal error; see local database and server logs'})
    server=ThreadingHTTPServer((host,port),Handler)
    print(f'GuardianAI is running at http://127.0.0.1:{port}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
