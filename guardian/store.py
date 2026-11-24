import json
from contextlib import contextmanager
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, directory='.guardian'):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'guardian.db'
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, repo TEXT, created TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS baselines(id INTEGER PRIMARY KEY, repo TEXT, scan_id TEXT, actor TEXT, reason TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS reviews(scan_id TEXT, finding_id TEXT, status TEXT, actor TEXT, reason TEXT, created TEXT, PRIMARY KEY(scan_id,finding_id));
            CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY, repo TEXT, rule TEXT, path TEXT, reason TEXT, expires TEXT, approved INTEGER DEFAULT 0, actor TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS validations(id TEXT PRIMARY KEY, plan_id TEXT, status TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS remediation_plans(id TEXT PRIMARY KEY, scan_id TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS remediation_decisions(plan_id TEXT PRIMARY KEY, status TEXT, actor TEXT, reason TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, created TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, scan_id TEXT, actor TEXT, decision TEXT, reason TEXT, created TEXT);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def audit(self, scan_id, actor, decision, reason):
        with self.connect() as db:
            db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)', (scan_id, actor, decision, reason, now()))

    def save(self, scan):
        with self.connect() as db:
            db.execute('INSERT INTO scans VALUES(?,?,?,?)', (scan['id'], scan['repo'], scan['created'], json.dumps(scan)))
        snapshots = self.directory / 'snapshots'
        snapshots.mkdir(exist_ok=True)
        (snapshots / (scan['id'] + '.json')).write_text(json.dumps(scan, indent=2))

    def get(self, scan_id):
        with self.connect() as db:
            row = db.execute('SELECT data FROM scans WHERE id=?', (scan_id,)).fetchone()
            if not row:
                raise ValueError('Scan not found')
            scan = json.loads(row['data'])
            reviews = {r['finding_id']: dict(r) for r in db.execute('SELECT * FROM reviews WHERE scan_id=?', (scan_id,))}
            for f in scan['findings']:
                if f['id'] in reviews:
                    f['review'] = reviews[f['id']]
                    f['status'] = f['review']['status']
            scan['audit'] = [dict(r) for r in db.execute('SELECT * FROM audit WHERE scan_id=? ORDER BY id', (scan_id,))]
            from .prioritizer import prioritize
            nodes = {n['id']: n for n in scan['graph']['nodes']}
            for finding in scan['findings']:
                finding['priority'] = prioritize(finding, nodes.get(finding['component'], {}))
            scan['findings'].sort(key=lambda f: (f['suppressed'], f['priority']['tier'], -f['score'], f['id']))
            scan['remediation_plans'] = self.recommendations(scan_id)
            return scan

    def recommendations(self, scan_id):
        with self.connect() as db:
            rows = db.execute('SELECT p.data, d.status, d.actor, d.reason, d.created FROM remediation_plans p LEFT JOIN remediation_decisions d ON p.id=d.plan_id WHERE p.scan_id=? ORDER BY p.rowid DESC', (scan_id,))
            result = []
            for row in rows:
                plan = json.loads(row['data'])
                if row['status']:
                    plan['status'] = row['status']
                    plan['decision'] = {k: row[k] for k in ('status', 'actor', 'reason', 'created')}
                validation = db.execute('SELECT data FROM validations WHERE plan_id=? ORDER BY rowid DESC LIMIT 1', (plan['id'],)).fetchone()
                if validation:
                    plan['validation'] = json.loads(validation['data'])
                    plan['validation_status'] = plan['validation']['status']
                result.append(plan)
            return result

    def remediation_plan(self, plan_id):
        with self.connect() as db:
            row = db.execute('SELECT scan_id FROM remediation_plans WHERE id=?', (plan_id,)).fetchone()
        if not row: raise ValueError('Remediation plan not found')
        return next(p for p in self.recommendations(row['scan_id']) if p['id']==plan_id)

    def begin_validation(self, plan_id):
        import uuid
        plan = self.remediation_plan(plan_id)
        if plan['status'] != 'approved': raise ValueError('Human approval required')
        if not plan.get('execution_ready'): raise ValueError('Plan has no supported sandbox patch; regenerate or investigate')
        vid = uuid.uuid4().hex[:16]
        result = {'id':vid,'plan_id':plan_id,'status':'running','created':now(),'stage':'Preparing sandbox'}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM validations WHERE status='running'").fetchone():
                raise ValueError('Another validation is running')
            db.execute('INSERT INTO validations VALUES(?,?,?,?)',(vid,plan_id,'running',json.dumps(result)))
        return vid

    def validation(self, validation_id):
        with self.connect() as db:
            row = db.execute('SELECT data FROM validations WHERE id=?',(validation_id,)).fetchone()
        if not row: raise ValueError('Validation not found')
        return json.loads(row['data'])

    def validation_progress(self, validation_id, stage):
        result = self.validation(validation_id); result['stage'] = stage
        with self.connect() as db:
            db.execute('UPDATE validations SET data=? WHERE id=?',(json.dumps(result),validation_id))

    def finish_validation(self, result):
        plan = self.remediation_plan(result['plan_id'])
        with self.connect() as db:
            db.execute('UPDATE validations SET status=?,data=? WHERE id=?',(result['status'],json.dumps(result),result['id']))
            db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)',
                       (plan['scan_id'],'Sandbox validator',result['plan_id']+': '+result['status'],
                        plan['finding_id']+'; validation '+result['id']+'; original repository unchanged',now()))

    def record_git_push(self, plan_id, git_result):
        """Persist the git push outcome into the latest validation row for this plan."""
        with self.connect() as db:
            row = db.execute('SELECT id,data FROM validations WHERE plan_id=? ORDER BY rowid DESC LIMIT 1', (plan_id,)).fetchone()
            if row:
                data = json.loads(row['data'])
                data['git_push'] = git_result
                db.execute('UPDATE validations SET data=? WHERE id=?', (json.dumps(data), row['id']))

    def recover_validations(self):
        with self.connect() as db:
            for row in db.execute("SELECT id,data FROM validations WHERE status='running'").fetchall():
                result = json.loads(row['data']); result.update(status='interrupted',error='Server restarted during validation; inspect retained sandbox and retry')
                db.execute('UPDATE validations SET status=?,data=? WHERE id=?',('interrupted',json.dumps(result),row['id']))

    def recommend(self, scan_id, finding_id):
        from .remediation import propose
        scan = self.get(scan_id)
        finding = next((f for f in scan['findings'] if f['id'] == finding_id), None)
        if not finding:
            raise ValueError('Finding not found')
        plan = propose(scan, finding, self)
        with self.connect() as db:
            inserted = db.execute('INSERT OR IGNORE INTO remediation_plans VALUES(?,?,?)', (plan['id'], scan_id, json.dumps(plan))).rowcount
            if inserted:
                db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)', (scan_id, 'Remediation engine', 'Proposed '+plan['id'], finding_id+'; '+plan['action'], now()))
        return next(p for p in self.recommendations(scan_id) if p['id'] == plan['id'])

    def decide_remediation(self, plan_id, status, actor, reason):
        self.identity(actor, reason)
        if status not in ('approved', 'rejected'):
            raise ValueError('Decision must be approved or rejected')
        with self.connect() as db:
            row = db.execute('SELECT data FROM remediation_plans WHERE id=?', (plan_id,)).fetchone()
        if not row:
            raise ValueError('Remediation plan not found')
        plan = json.loads(row['data'])
        if status == 'approved':
            from .remediation import source
            scan = self.get(plan['scan_id'])
            for name, digest in plan['preconditions'].items():
                if scan['files'].get(name, {}).get('hash') != digest or source(scan, name) is None:
                    raise ValueError('Source changed since scanning. Rescan and generate a new recommendation.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM remediation_decisions WHERE plan_id=?', (plan_id,)).fetchone():
                raise ValueError('This plan already has a final human decision')
            created = now()
            db.execute('INSERT INTO remediation_decisions VALUES(?,?,?,?,?)', (plan_id, status, actor, reason, created))
            db.execute('INSERT INTO audit(scan_id,actor,decision,reason,created) VALUES(?,?,?,?,?)', (plan['scan_id'], actor, plan_id+': '+status, plan['finding_id']+'; '+reason+'; decision only; validation not run', created))
        return dict(plan_id=plan_id, status=status, validation_status='not_run', applied=False)

    def list(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT id,repo,created FROM scans ORDER BY created DESC LIMIT 100')]

    def baseline(self, repo):
        with self.connect() as db:
            row = db.execute('SELECT scan_id FROM baselines WHERE repo=? ORDER BY id DESC LIMIT 1', (repo,)).fetchone()
        return self.get(row['scan_id']) if row else None

    @staticmethod
    def identity(actor, reason):
        if not str(actor).strip() or not str(reason).strip():
            raise ValueError('A reviewer name and written reason are required')

    def promote(self, scan_id, actor, reason):
        self.identity(actor, reason)
        scan = self.get(scan_id)
        if any(f['risk_level'] == 'Critical' and f['status'] == 'open' for f in scan['findings']):
            raise ValueError('Review all open Critical findings before promoting a baseline')
        if scan['coverage']['inventory'] != 'complete':
            raise ValueError('An incomplete inventory cannot become a trusted baseline')
        with self.connect() as db:
            db.execute('INSERT INTO baselines(repo,scan_id,actor,reason,created) VALUES(?,?,?,?,?)', (scan['repo'], scan_id, actor, reason, now()))
        self.audit(scan_id, actor, 'Baseline promoted', reason)

    def review(self, scan_id, finding_id, status, actor, reason):
        self.identity(actor, reason)
        if status not in ('open', 'confirmed', 'false positive', 'accepted'):
            raise ValueError('Invalid review status')
        scan = self.get(scan_id)
        finding = next((f for f in scan['findings'] if f['id'] == finding_id), None)
        if not finding:
            raise ValueError('Finding not found')
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reviews VALUES(?,?,?,?,?,?)', (scan_id, finding_id, status, actor, reason, now()))
        self.audit(scan_id, actor, f'{finding_id}: {status}', reason)
        if status == 'false positive' and finding['rule'] not in PROTECTED and finding.get('file'):
            from datetime import timedelta
            expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            with self.connect() as db:
                db.execute('INSERT INTO lessons(repo,rule,path,reason,expires,actor,created) VALUES(?,?,?,?,?,?,?)', (scan['repo'], finding['rule'], finding['file'], reason, expiry, actor, now()))
            self.audit(scan_id, 'Learning agent', 'Proposed a scoped 30-day suppression', 'Human false-positive label; approval and evaluation still required')

    def lessons(self, repo=None):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM lessons' + (' WHERE repo=?' if repo else ''), (repo,) if repo else ())
            return [dict(r) for r in rows]

    def approve_lesson(self, lesson_id, actor, reason):
        self.identity(actor, reason)
        with self.connect() as db:
            row = db.execute('SELECT * FROM lessons WHERE id=?', (lesson_id,)).fetchone()
        if not row or row['rule'] in PROTECTED or row['expires'] <= now():
            raise ValueError('Lesson missing, expired, or targets a protected rule')
        from .evaluation import evaluate
        result = evaluate(dict(row))
        if not result['passed']:
            raise ValueError('Lesson failed the regression evaluation')
        with self.connect() as db:
            db.execute('UPDATE lessons SET approved=1,actor=? WHERE id=?', (actor, lesson_id))
        self.audit('', actor, f'Lesson {lesson_id} approved', reason + '; regression evaluation passed')

    def cached(self, key, max_age=86400):
        with self.connect() as db:
            row = db.execute('SELECT * FROM cache WHERE key=?', (key,)).fetchone()
        if row and (datetime.now(timezone.utc) - datetime.fromisoformat(row['created'])).total_seconds() < max_age:
            return json.loads(row['data'])
        return None

    def cache(self, key, value):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO cache VALUES(?,?,?)', (key, now(), json.dumps(value)))


PROTECTED = {'integrity-change', 'typosquat', 'obfuscated-execution', 'secret-exfiltration', 'bidi-source', 'package-source-mismatch'}


def suppressed(finding, lessons):
    return finding['rule'] not in PROTECTED and any(l['approved'] and l['expires'] > now() and l['rule'] == finding['rule'] and l['path'] == finding.get('file') for l in lessons)
