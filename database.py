"""SQLite accounts, revocable sessions and private lookup history."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
import uuid

HASH_SLOTS = threading.BoundedSemaphore(2)


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        raise ValueError('Use a password of 15 to 128 characters.')
    salt = salt or secrets.token_hex(16)
    with HASH_SLOTS:
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768,
                                r=8, p=3, maxmem=64 * 1024 * 1024).hex()
    return 'scrypt$' + salt + '$' + digest


def password_matches(password, encoded):
    try:
        _, salt, _ = encoded.split('$')
        return hmac.compare_digest(password_hash(password, salt), encoded)
    except (ValueError, TypeError, AttributeError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE NOT NULL,
                    password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')),
                    active INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 0,
                    created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                    csrf TEXT NOT NULL, created REAL NOT NULL, seen REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS history (
                    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                    kind TEXT NOT NULL, subject TEXT NOT NULL, status TEXT NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS history_owner ON history(user_id,created DESC);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, actor INTEGER, action TEXT NOT NULL,
                    target TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT OR IGNORE INTO settings VALUES ('retention_days','90');
                CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, count INTEGER, started REAL);
            ''')
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        self.dummy_hash = password_hash(secrets.token_urlsafe(24))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def public_user(row):
        return {key: row[key] for key in ('id', 'username', 'role', 'active', 'must_change', 'created')}

    def audit(self, actor, action, target=''):
        with self.connect() as db:
            db.execute('INSERT INTO audit(actor,action,target,created) VALUES (?,?,?,?)',
                       (actor, action, str(target)[:100], time.time()))

    def create_user(self, username, password, role='user', actor=None, must_change=True):
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', username):
            raise ValueError('Username must contain 3–64 letters, numbers, dots, underscores or hyphens.')
        if role not in ('admin', 'user'):
            raise ValueError('Choose admin or user.')
        encoded = password_hash(password)
        try:
            with self.connect() as db:
                result = db.execute('INSERT INTO users(username,password,role,must_change,created) VALUES (?,?,?,?,?)',
                                    (username, encoded, role, int(must_change), time.time()))
                user_id = result.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError('That username is already in use.') from None
        self.audit(actor, 'user.created', user_id)
        return user_id

    def users(self):
        with self.connect() as db:
            return [self.public_user(row) for row in db.execute('SELECT * FROM users ORDER BY username')]

    def login(self, username, password, address):
        username = username if isinstance(username, str) else ''
        keys = ['ip:' + address, 'user:' + token_hash(username.casefold())]
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE started<?', (now - 900,))
            for key in keys:
                row = db.execute('SELECT count FROM attempts WHERE key=?', (key,)).fetchone()
                if row and row['count'] >= (30 if key.startswith('ip:') else 10):
                    return None, 'Too many sign-in attempts. Try again in 15 minutes.'
            for key in keys:
                db.execute('INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key, now))
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        valid = password_matches(password, user['password'] if user else self.dummy_hash)
        if not valid or not user or not user['active']:
            self.audit(None, 'login.failed')
            return None, 'Username or password is incorrect.'
        with self.connect() as db:
            db.execute('DELETE FROM attempts WHERE key=?', (keys[1],))
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            # Recheck after the expensive password hash: a concurrent reset/disable wins.
            current = db.execute('SELECT * FROM users WHERE id=? AND password=? AND active=1',
                                 (user['id'], user['password'])).fetchone()
            if not current:
                return None, 'Username or password is incorrect.'
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)',
                       (token_hash(token), user['id'], secrets.token_urlsafe(32), now, now))
        self.audit(user['id'], 'login.success')
        return token, None

    def session(self, token):
        if not token or len(token) > 100:
            return None
        now = time.time()
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE created<? OR seen<?', (now - 28800, now - 1800))
            row = db.execute('SELECT users.*, sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND active=1',
                             (token_hash(token),)).fetchone()
            if not row:
                return None
            db.execute('UPDATE sessions SET seen=? WHERE token=?', (now, token_hash(token)))
            return {**self.public_user(row), 'csrf': row['csrf']}

    def logout(self, token):
        with self.connect() as db:
            db.execute('DELETE FROM sessions WHERE token=?', (token_hash(token),))

    @staticmethod
    def revoke_security_tokens(db, user_id):
        # Security tables are installed separately; keep account operations atomic
        # with invalidation of outstanding reset links and enrolment challenges.
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('mail_tokens', 'challenges'):
            if table in tables:
                db.execute('DELETE FROM '+table+' WHERE user_id=?', (user_id,))
        if 'security_profiles' in tables:
            db.execute('UPDATE security_profiles SET pending=NULL,pending_at=NULL WHERE user_id=?', (user_id,))

    def change_password(self, user_id, current_password, new_password):
        with self.connect() as db:
            row = db.execute('SELECT password FROM users WHERE id=?', (user_id,)).fetchone()
        if not row or not password_matches(current_password, row['password']):
            raise ValueError('Current password is incorrect.')
        encoded = password_hash(new_password)
        if password_matches(new_password, row['password']):
            raise ValueError('Choose a different password.')
        with self.connect() as db:
            changed = db.execute('UPDATE users SET password=?,must_change=0 WHERE id=? AND password=?',
                                 (encoded, user_id, row['password'])).rowcount
            if not changed:
                raise ValueError('Account changed. Sign in again.')
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            self.revoke_security_tokens(db, user_id)
        self.audit(user_id, 'password.changed', user_id)

    def update_user(self, actor, user_id, data):
        encoded = password_hash(data['password']) if data.get('password') else None
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
            if not row:
                raise ValueError('User not found.')
            role = data.get('role', row['role'])
            active = data.get('active', bool(row['active']))
            if role not in ('admin', 'user') or not isinstance(active, bool):
                raise ValueError('Invalid role or account status.')
            if row['role'] == 'admin' and row['active'] and (role != 'admin' or not active):
                count = db.execute("SELECT count(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
                if count <= 1:
                    raise ValueError('Keep at least one active administrator.')
            db.execute('UPDATE users SET role=?,active=? WHERE id=?', (role, int(active), user_id))
            if encoded:
                db.execute('UPDATE users SET password=?,must_change=1 WHERE id=?', (encoded, user_id))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            self.revoke_security_tokens(db, user_id)
        self.audit(actor, 'user.updated', user_id)

    def save(self, user_id, kind, subject, payload, record_id=None, status='complete'):
        record_id = record_id or uuid.uuid4().hex
        now = time.time()
        with self.connect() as db:
            db.execute('INSERT INTO history VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,updated=excluded.updated,payload=excluded.payload',
                       (record_id, user_id, kind, subject[:1000], status, now, now, json.dumps(payload)))
        return record_id

    def record(self, record_id, user):
        with self.connect() as db:
            row = db.execute('SELECT * FROM history WHERE id=? AND (user_id=? OR ?=1)',
                             (record_id, user['id'], int(user['role'] == 'admin'))).fetchone()
            if not row:
                return None
            result = dict(row)
            result['payload'] = json.loads(result['payload'])
            return result

    def history(self, user, query='', kind='', page=1, all_users=False):
        args = (user['id'], int(all_users and user['role'] == 'admin'), kind, kind, query[:200].lower())
        where = "(h.user_id=? OR ?=1) AND (?='' OR kind=?) AND instr(lower(subject || ' ' || payload || ' ' || u.username),?)>0"
        with self.connect() as db:
            total = db.execute('SELECT count(*) FROM history h JOIN users u ON u.id=h.user_id WHERE ' + where, args).fetchone()[0]
            items = db.execute('SELECT h.id,h.kind,h.subject,h.status,h.created,h.updated,u.username FROM history h JOIN users u ON u.id=h.user_id WHERE ' + where + ' ORDER BY h.created DESC LIMIT 50 OFFSET ?', (*args, (page - 1) * 50)).fetchall()
            return {'items': [dict(row) for row in items], 'total': total, 'page': page}

    def delete_record(self, record_id, user):
        with self.connect() as db:
            row = db.execute('SELECT status FROM history WHERE id=? AND (user_id=? OR ?=1)',
                             (record_id, user['id'], int(user['role'] == 'admin'))).fetchone()
            if not row:
                raise ValueError('Saved result not found.')
            if row['status'] == 'running':
                raise ValueError('Wait until the scan finishes before deleting it.')
            db.execute('DELETE FROM history WHERE id=?', (record_id,))
        self.audit(user['id'], 'history.deleted', record_id)

    def retention(self, days=None, actor=None):
        with self.connect() as db:
            if days is not None:
                if type(days) is not int or not 1 <= days <= 3650:
                    raise ValueError('Retention must be 1–3650 days.')
                db.execute("UPDATE settings SET value=? WHERE key='retention_days'", (str(days),))
            value = int(db.execute("SELECT value FROM settings WHERE key='retention_days'").fetchone()[0])
        if days is not None:
            self.audit(actor, 'retention.changed', days)
        return value

    def cleanup(self):
        cutoff = time.time() - self.retention() * 86400
        with self.connect() as db:
            db.execute("DELETE FROM history WHERE updated<? AND status!='running'", (cutoff,))
            db.execute('DELETE FROM audit WHERE created<?', (cutoff,))
            db.execute('DELETE FROM sessions WHERE created<? OR seen<?', (time.time()-28800, time.time()-1800))
            db.execute('DELETE FROM attempts WHERE started<?', (time.time()-900,))

    def interrupt_scans(self):
        with self.connect() as db:
            for row in db.execute("SELECT id,payload FROM history WHERE kind='ip' AND status='running'").fetchall():
                payload = json.loads(row['payload'])
                payload.update(status='failed', finished_at=time.time(), error='Server restarted during this scan. Completed results were saved.')
                db.execute("UPDATE history SET status='failed',updated=?,payload=? WHERE id=?",
                           (time.time(), json.dumps(payload), row['id']))

    def admin_summary(self):
        with self.connect() as db:
            return {'users': self.users(), 'retention_days': self.retention(),
                    'counts': {row['kind']: row['n'] for row in db.execute('SELECT kind,count(*) n FROM history GROUP BY kind')},
                    'audit': [dict(row) for row in db.execute('SELECT a.action,a.target,a.created,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 100')]}
