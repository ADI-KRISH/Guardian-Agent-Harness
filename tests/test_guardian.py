import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from guardian.discovery import read_tree, discover, dependency_path, sbom
from guardian.detectors import static_scan, changes, finding
from guardian.engine import run_scan
from guardian.store import Store, suppressed, now
from guardian.evaluation import evaluate
from guardian import osv


class GuardianTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'repo'; self.root.mkdir()
        self.store=Store(Path(self.temp.name)/'memory')
    def write(self,name,data):
        p=self.root/name; p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(json.dumps(data) if isinstance(data,dict) else data)
    def npm(self,version='1.0.0',integrity='sha512-old'):
        self.write('package-lock.json',{'lockfileVersion':3,'packages':{'':{'dependencies':{'parent':'1.0.0'}},'node_modules/parent':{'version':'1.0.0','dependencies':{'child':version}},'node_modules/child':{'version':version,'integrity':integrity}}})
    def test_transitive_graph_and_sbom(self):
        self.npm(); files,_=read_tree(self.root); g,w=discover(self.root,files)
        child=next(n for n in g['nodes'] if n['name']=='child')
        path=dependency_path(g,child['id']); self.assertEqual(len(path),3)
        self.assertFalse(child['direct']); self.assertFalse(w)
        self.assertEqual(len(sbom(g)['components']),2)
    def test_nested_npm_resolution_prefers_nearest(self):
        self.npm(); p=self.root/'package-lock.json'; data=json.loads(p.read_text())
        data['packages']['node_modules/parent/node_modules/child']={'version':'2.0.0'}; p.write_text(json.dumps(data))
        files,_=read_tree(self.root); g,_=discover(self.root,files)
        nested=next(n for n in g['nodes'] if n.get('version')=='2.0.0')
        self.assertEqual(len(dependency_path(g,nested['id'])),3)
    def test_no_fake_path_for_orphan(self):
        self.assertEqual(dependency_path({'nodes':[],'edges':[]},'missing'),[])
    def test_symlink_not_read(self):
        outside=Path(self.temp.name)/'secret'; outside.write_text('do not read')
        (self.root/'escape.py').symlink_to(outside)
        files,w=read_tree(self.root); self.assertNotIn('escape.py',files); self.assertTrue(w)
    def test_oversized_input_visible(self):
        self.write('huge.txt','x'*100)
        with patch('guardian.discovery.MAX_FILE_SIZE',10): files,w=read_tree(self.root)
        self.assertFalse(files); self.assertTrue(w)
    def test_malformed_lockfile_visible(self):
        self.write('package-lock.json','{'); files,_=read_tree(self.root); _,w=discover(self.root,files)
        self.assertIn('parse failed',w[0])
    def test_unresolved_versions_not_queried(self):
        self.write('package.json',{'dependencies':{'example':'^1.0.0'}})
        files,_=read_tree(self.root); g,_=discover(self.root,files)
        with patch('guardian.osv.request') as request:
            f,c=osv.scan(g,self.store); request.assert_not_called()
        self.assertFalse(f); self.assertIn('unresolved',c[0]['status'])
    def test_offline_not_reported_as_clean(self):
        self.npm(); result=run_scan(str(self.root),self.store,offline=True)
        self.assertEqual(result['coverage']['vulnerability_status'],'partial')
        self.assertTrue(all('unavailable' in c['status'] for c in result['coverage']['vulnerabilities']))
    def test_osv_pagination_cache_withdrawn(self):
        n={'name':'example','version':'1.0','ecosystem':'npm','type':'package','id':'p','file':'package-lock.json'}
        pages=[{'vulns':[{'id':'TEST-1','summary':'test','database_specific':{'severity':'HIGH'},'affected':[{'package':{'name':'other','ecosystem':'npm'},'ranges':[{'events':[{'fixed':'99'}]}]},{'package':{'name':'example','ecosystem':'npm'},'ranges':[{'events':[{'fixed':'1.1'}]}]}]}],'next_page_token':'next'}, {'vulns':[{'id':'WITHDRAWN','withdrawn':'2020-01-01'}]}]
        with patch('guardian.osv.request',side_effect=pages) as request:
            f,c=osv.scan({'nodes':[n]},self.store)
            self.assertEqual(request.call_count,2); self.assertEqual(request.call_args[0][0]['page_token'],'next')
        self.assertEqual(len(f),1); self.assertEqual(f[0]['fix_versions'],['1.1']); self.assertEqual(f[0]['risk_level'],'High')
        with patch('guardian.osv.request') as request:
            _,c=osv.scan({'nodes':[n]},self.store);request.assert_not_called()
        self.assertEqual(c[0]['status'],'cached')
    def test_osv_network_failure_explicit(self):
        self.npm(); files,_=read_tree(self.root); g,_=discover(self.root,files)
        with patch('guardian.osv.request',side_effect=TimeoutError('timeout')): f,c=osv.scan(g,self.store)
        self.assertFalse(f); self.assertTrue(all(x['status'].startswith('failed:') for x in c))
    def test_baseline_integrity_and_review(self):
        self.npm(); first=run_scan(str(self.root),self.store,offline=True)
        self.assertIsNone(self.store.baseline(str(self.root)))
        self.store.promote(first['id'],'Reviewer','Reviewed snapshot')
        self.npm(integrity='sha512-changed'); second=run_scan(str(self.root),self.store,offline=True)
        f=next(f for f in second['findings'] if f['rule']=='integrity-change')
        self.assertEqual(f['risk_level'],'Critical')
        with self.assertRaises(ValueError): self.store.promote(second['id'],'Reviewer','Unchecked critical')
        self.store.review(second['id'],f['id'],'confirmed','Reviewer','Artifact changed; confirmed')
        self.store.promote(second['id'],'Reviewer','Explicitly approved after review')
        self.assertEqual(self.store.baseline(str(self.root))['id'],second['id'])
        self.assertGreater(len(self.store.get(second['id'])['audit']),5)
    def test_review_requires_identity_and_reason(self):
        with self.assertRaises(ValueError): self.store.identity('','reason')
        with self.assertRaises(ValueError): self.store.identity('person','')
    def test_audit_append_only(self):
        self.store.audit('s','actor','decision','reason')
        import sqlite3
        with self.store.connect() as db:
            with self.assertRaises(sqlite3.IntegrityError): db.execute('DELETE FROM audit')
            with self.assertRaises(sqlite3.IntegrityError): db.execute("UPDATE audit SET reason='changed'")
    def test_suppression_protected_and_expired(self):
        f=finding('obfuscated-execution','test','backdoor signal','High','x.py')
        lesson={'approved':1,'expires':'2999-01-01','rule':f['rule'],'path':'x.py'}
        self.assertFalse(suppressed(f,[lesson]))
        f['rule']='build-change'; lesson['rule']='build-change'; self.assertTrue(suppressed(f,[lesson]))
        lesson['expires']='2000-01-01'; self.assertFalse(suppressed(f,[lesson]))
    def test_learning_requires_approval(self):
        self.write('Dockerfile','FROM node:18')
        result=run_scan(str(self.root),self.store,offline=True); f=result['findings'][0]
        self.store.review(result['id'],f['id'],'false positive','Reviewer','Intentional test image')
        lesson=self.store.lessons()[0]; self.assertFalse(lesson['approved'])
        before=run_scan(str(self.root),self.store,offline=True); self.assertFalse(before['findings'][0]['suppressed'])
        # A candidate scoped exactly to the planted fixture must fail the evaluation gate.
        with self.assertRaises(ValueError): self.store.approve_lesson(lesson['id'],'Reviewer','Approve')
    def test_no_repository_code_execution(self):
        self.write('package.json',{'scripts':{'postinstall':'touch /tmp/guardian-should-never-exist'}})
        with patch('subprocess.run',side_effect=AssertionError('unexpected execution')):
            result=run_scan(str(self.root),self.store,offline=True)
        self.assertTrue(any(f['rule']=='install-script' for f in result['findings']))
    def test_clean_docker_stages_and_sha_actions(self):
        self.write('Dockerfile','FROM scratch AS builder\nFROM builder\n')
        self.write('.github/workflows/test.yml','uses: actions/checkout@'+'a'*40)
        files,_=read_tree(self.root)
        self.assertFalse(static_scan(files,{'nodes':[],'edges':[]}))
    def test_regression_suite(self):
        self.assertTrue(evaluate()['passed'])
    def test_sbom_import_links(self):
        self.write('sbom.json',{'bomFormat':'CycloneDX','metadata':{'component':{'bom-ref':'root'}},'components':[{'bom-ref':'p','name':'pkg','version':'1.0','purl':'pkg:npm/pkg@1.0'}],'dependencies':[{'ref':'root','dependsOn':['p']}]})
        files,_=read_tree(self.root); g,_=discover(self.root,files)
        self.assertEqual(dependency_path(g,'p'),['app','p'])
    def test_approved_scoped_lesson_reduces_noise(self):
        self.npm(); self.write('generated/Dockerfile','FROM node:18')
        first=run_scan(str(self.root),self.store,offline=True)
        f=next(f for f in first['findings'] if f['rule']=='floating-image')
        self.store.review(first['id'],f['id'],'false positive','Reviewer','Generated educational file')
        lesson=self.store.lessons()[0]
        self.store.approve_lesson(lesson['id'],'Reviewer','Scoped generated fixture; regressions pass')
        second=run_scan(str(self.root),self.store,offline=True)
        self.assertTrue(next(f for f in second['findings'] if f['rule']=='floating-image')['suppressed'])
        self.assertTrue(evaluate()['passed'])
    def test_pyproject_exact_pins_and_unresolved_ranges(self):
        self.write('pyproject.toml','[project]\nname="example"\ndependencies=["requests==2.31.0", "flask>=2"]')
        files,_=read_tree(self.root); graph,warnings=discover(self.root,files)
        self.assertEqual([n['name'] for n in graph['nodes'] if n['type']=='package'],['requests'])
        self.assertTrue(any('flask' in w for w in warnings))
    def test_unchanged_source_signal_survives_baseline(self):
        self.npm()
        self.write('src/risk.py','exec(base64.b64decode("payload"))')
        first=run_scan(str(self.root),self.store,offline=True)
        self.store.promote(first['id'],'Reviewer','Explicitly trust snapshot with documented risk')
        second=run_scan(str(self.root),self.store,offline=True)
        self.assertTrue(any(f['rule']=='obfuscated-execution' for f in second['findings']))
    def test_empty_inventory_is_not_complete(self):
        result=run_scan(str(self.root),self.store,offline=True)
        self.assertEqual(result['coverage']['inventory'],'partial')
        with self.assertRaises(ValueError):self.store.promote(result['id'],'Reviewer','Empty')
    def test_http_local_session_guard(self):
        import subprocess,sys,time,urllib.request,urllib.error,socket
        with socket.socket() as sock: sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        process=subprocess.Popen([sys.executable,'-m','guardian','--data',str(Path(self.temp.name)/'http'),'serve','--port',str(port)],stdout=subprocess.DEVNULL)
        self.addCleanup(lambda:(process.terminate(),process.wait(timeout=5)))
        url=f'http://127.0.0.1:{port}'
        for _ in range(40):
            try:
                with urllib.request.urlopen(url+'/api/session',timeout=1) as r: token=json.load(r)['token']
                break
            except OSError:time.sleep(.05)
        else:self.fail('Server did not start')
        req=urllib.request.Request(url+'/api/baseline',data=b'{}',headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as ctx:urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code,403); ctx.exception.close()
        req=urllib.request.Request(url+'/api/baseline',data=b'{}',headers={'X-Guardian-Token':token,'Origin':'https://evil.invalid'})
        with self.assertRaises(urllib.error.HTTPError) as ctx:urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code,403); ctx.exception.close()
        req=urllib.request.Request(url+'/api/session',headers={'Host':'evil.invalid'})
        with self.assertRaises(urllib.error.HTTPError) as ctx:urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code,403); ctx.exception.close()
        with urllib.request.urlopen(url+'/app.js') as r:self.assertEqual(r.status,200)

if __name__=='__main__':unittest.main()
