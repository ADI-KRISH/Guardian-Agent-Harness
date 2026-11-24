import hashlib
import hmac
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
                if path=='/api/tunnel': 
                    from . import tunnel; return self.send(200,tunnel.status())
                if path=='/api/watched': return self.send(200,store.list_watched())
                if path.startswith('/api/watched/secret/'):
                    wid=path.rsplit('/',1)[-1]
                    row=store.get_watched_secret(wid)
                    return self.send(200,{'webhook_secret':row['webhook_secret']})
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
        def do_WEBHOOK(self):
            """GitHub webhook — no session token; uses HMAC-SHA256 per watch entry."""
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=2*1024*1024: raise ValueError('Bad size')
                body=self.rfile.read(size)
                event=self.headers.get('X-GitHub-Event','')
                if event not in ('push','ping'): return self.send(200,{'ok':True,'skipped':'irrelevant event'})
                payload=json.loads(body)
                if event=='ping': return self.send(200,{'ok':True,'pong':True})
                # Extract repo URL and branch from payload
                repo_url=(payload.get('repository',{}).get('html_url') or '').rstrip('/')
                ref=payload.get('ref','')
                branch=ref.removeprefix('refs/heads/')
                if not repo_url or not branch: return self.send(200,{'ok':True,'skipped':'no repo or branch'})
                watch=store.match_webhook(repo_url,branch)
                if not watch: return self.send(200,{'ok':True,'skipped':'repo/branch not watched'})
                # Verify HMAC
                sig=self.headers.get('X-Hub-Signature-256','')
                expected='sha256='+hmac.new(watch['webhook_secret'].encode(),body,hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig,expected): return self.send(403,{'error':'Invalid webhook signature'})
                # Queue auto-scan of the pushed branch
                branch_url=f'{repo_url}/tree/{branch}'
                with lock:
                    if any(j['status']=='running' for j in jobs.values()):
                        return self.send(200,{'ok':True,'queued':False,'note':'A scan is already running; push recorded but not scanned yet'})
                    jid=uuid.uuid4().hex[:12]
                    jobs[jid]={'status':'running','stage':'Auto-scan from webhook push','trigger':'webhook','repo':repo_url,'branch':branch}
                def webhook_work():
                    try:
                        scan=run_scan(branch_url,store,offline=False,progress=lambda s: None)
                        with lock: jobs[jid].update({'status':'complete','scan_id':scan['id'],'trigger':'webhook','branch':branch})
                    except Exception as exc:
                        with lock: jobs[jid].update({'status':'failed','error':str(exc),'trigger':'webhook'})
                threading.Thread(target=webhook_work,daemon=True).start()
                return self.send(202,{'ok':True,'job_id':jid,'branch':branch,'repo':repo_url})
            except Exception as exc: return self.send(400,{'error':str(exc)[:200]})

        def do_POST(self):
            # Webhook endpoint bypasses session token auth (uses HMAC instead)
            if urlparse(self.path).path=='/api/webhook/github':
                return self.do_WEBHOOK()
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
                    validation_id=store.begin_validation(data['plan_id'])
                    def validation_work():
                        from .validator import validate
                        validate(store,data['plan_id'],validation_id,lambda stage:store.validation_progress(validation_id,stage))
                    threading.Thread(target=validation_work,daemon=True).start()
                    return self.send(202,{'validation_id':validation_id,'status':'running','applied':False})
                if path=='/api/remediation/push':
                    plan_id=data.get('plan_id',''); actor=data.get('actor',''); fork_url=data.get('fork_url') or None
                    plan=store.remediation_plan(plan_id)
                    if plan.get('status')!='approved': raise ValueError('Human approval is required before pushing')
                    validation_id=data.get('validation_id','')
                    if validation_id:
                        v=store.validation(validation_id)
                        if v.get('status') not in ('verified',): raise ValueError('Sandbox validation must be verified before pushing (status: '+str(v.get('status'))+')')
                    original=store.get(plan['scan_id'])
                    target_finding=next((f for f in original['findings'] if f['id']==plan['finding_id']),None)
                    if not target_finding: raise ValueError('Finding not found in scan')
                    source_root=original.get('source_root',original.get('repo',''))
                    if not source_root or source_root.startswith('https://'): raise ValueError('Source root is a remote URL. Clone the repository locally (or your fork) and rescan before pushing.')
                    from .git import push_fix
                    validation_id_push=data.get('validation_id','')
                    sandbox_workspace=None
                    if validation_id_push:
                        try:
                            vr=store.validation(validation_id_push)
                            if vr.get('status') not in ('verified',): raise ValueError('Sandbox validation must be verified before pushing (status: '+str(vr.get('status'))+')')
                            sandbox_workspace=vr.get('workspace')
                        except ValueError as exc: raise
                    git_result=push_fix(source_root,plan,target_finding,fork_url=fork_url,actor=actor,sandbox_workspace=sandbox_workspace)
                    store.record_git_push(data.get('plan_id',''),git_result)
                    store.audit(plan_id,actor or 'system','Git push',f'branch={git_result["branch"]} commit={git_result["commit"]} pushed={git_result["pushed"]}')
                    return self.send(200,git_result)
                if path=='/api/remediation/repo_info':
                    plan_id=data.get('plan_id',''); plan=store.remediation_plan(plan_id)
                    original=store.get(plan['scan_id']); source_root=original.get('source_root',original.get('repo',''))
                    if not source_root or source_root.startswith('https://'): return self.send(200,{'is_git':False,'needs_fork':True,'remote_url':source_root,'message':'This was scanned from a remote URL. Clone the repository (or your fork) locally and rescan to enable git push.'})
                    from .git import repo_info
                    info=repo_info(source_root); info['needs_fork']=info.get('is_remote_origin',False)
                    return self.send(200,info)
                if path=='/api/watched':
                    branches=[b.strip() for b in str(data.get('branches','*')).split(',') if b.strip()] or ['*']
                    result=store.add_watched(str(data.get('url','')),branches,str(data.get('actor','')))
                    return self.send(200,result)
                if path=='/api/watched/toggle':
                    store.toggle_watched(str(data.get('id','')),bool(data.get('enabled',True)))
                    return self.send(200,{'ok':True})
                if path=='/api/tunnel/start':
                    from . import tunnel
                    result=tunnel.start(port)
                    return self.send(200,result)
                if path=='/api/tunnel/stop':
                    from . import tunnel
                    return self.send(200,tunnel.stop())
                if path=='/api/watched/remove':
                    store.remove_watched(str(data.get('id','')))
                    return self.send(200,{'ok':True})
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
