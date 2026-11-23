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
            return scan

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
