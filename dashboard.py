#!/usr/bin/env python3
"""Authenticated dashboard and persistent lookup history for IP Checker."""
import argparse
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import email_lookup
import domain_lookup
from database import Database, token_hash
from http.cookies import SimpleCookie, CookieError
from urllib.parse import parse_qs
import hmac
import getpass
from security import Security
import mailer

ROOT = Path(__file__).resolve().parent
DB = None
AUTH = None
KEYS = {'IPinfo': 'IPINFO_KEY', 'IP2Location': 'IP2_KEY',
        'proxycheck.io': 'PROXY_KEY', 'Spamhaus': 'SPAMHAUS_KEY', 'IPQS': 'IPQS_KEY'}


def secret_values(path=None):
    """Read simple assignments without executing the configuration."""
    path = Path(path or os.environ.get('IP_CHECKER_SECRETS', str(ROOT / '.secrets')))
    values = {}
    try:
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            match = re.match(r'^\s*(?:export\s+)?([A-Z0-9_]+)=(.*)$', line)
            if match:
                try:
                    parts = shlex.split(match[2], comments=True)
                    values[match[1]] = ' '.join(parts)
                except ValueError:
                    pass
    except (OSError, UnicodeError):
        pass
    return values


def configuration():
    """Report presence only; never return secrets or execute the config."""
    values = secret_values()
    providers = [{'name': name, 'configured': bool(values.get(key)), 'required': name != 'IPQS'} for name, key in KEYS.items()]
    missing = [cmd for cmd in ('bash', 'curl', 'jq', 'dig', 'python3') if not shutil.which(cmd)]
    return {'providers': providers, 'missing_dependencies': missing,
            'ready': all(p['configured'] for p in providers if p['required']) and not missing}


def parse_ips(text):
    if not isinstance(text, str):
        raise ValueError('Enter IP addresses as text.')
    addresses, skipped = [], []
    seen = set()
    for line in text.lstrip('\ufeff').splitlines():
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 4 or not ip.is_global:
                raise ValueError()
        except ValueError:
            skipped.append(value[:100])
            continue
        canonical = str(ip)
        if canonical not in seen:
            seen.add(canonical)
            addresses.append(canonical)
    if not addresses:
        raise ValueError('Add at least one valid public IPv4 address, one per line.')
    if len(addresses) > 500:
        raise ValueError('A scan can contain up to 500 unique public IPv4 addresses.')
    return addresses, skipped


def safe_cell(value):
    # Prevent spreadsheet formula evaluation when reports are opened in Excel.
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value


class ScanStore:
    def __init__(self):
        self.lock = threading.RLock()
        self.scans = {}
        self.active = None

    def create(self, addresses, skipped, owner=None):
        with self.lock:
            if self.active:
                raise ValueError('A scan is already running. Wait for it to finish.')
            scan_id = uuid.uuid4().hex
            scan = {'id': scan_id, 'status': 'running', 'total': len(addresses),
                    'completed': 0, 'rows': [], 'skipped': skipped,
                    'started_at': time.time(), 'finished_at': None, 'error': None}
            if owner is not None:
                scan['owner'] = owner
                DB.save(owner, 'ip', ', '.join(addresses), scan, scan_id, 'running')
            # Keep a bounded, in-memory history. Nothing is written to the repo.
            while len(self.scans) >= 20:
                self.scans.pop(next(iter(self.scans)))
            self.scans[scan_id] = scan
            self.active = scan_id
        threading.Thread(target=self.run, args=(scan_id, addresses), daemon=True).start()
        return scan_id

    def snapshot(self, scan_id, user=None):
        with self.lock:
            if DB and user:
                record = DB.record(scan_id, user)
                return record['payload'] if record and record['kind'] == 'ip' else None
            scan = self.scans.get(scan_id)
            return json.loads(json.dumps(scan)) if scan else None

    def persist(self, scan_id):
        scan = self.scans[scan_id]
        if DB and 'owner' in scan:
            DB.save(scan['owner'], 'ip', ', '.join(row['IP Address'] for row in scan['rows']) or 'IP scan',
                    scan, scan_id, scan['status'])

    def run(self, scan_id, addresses):
        process = None
        try:
            with tempfile.TemporaryDirectory(prefix='ip-checker-') as directory:
                base = Path(directory)
                base.chmod(0o700)
                input_file, output_file = base / 'input.txt', base / 'results.csv'
                input_file.write_text('\n'.join(addresses) + '\n', encoding='utf-8')
                env = dict(os.environ)
                env['IP_CHECKER_SECRETS'] = str(Path(env.get('IP_CHECKER_SECRETS', str(ROOT / '.secrets'))).resolve())
                process = subprocess.Popen(['bash', str(ROOT / 'ip-checker.sh'), str(input_file), str(output_file)],
                                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + max(240, len(addresses) * 240)
                while True:
                    done = process.poll() is not None
                    if output_file.exists():
                        # Read only complete newline-terminated records while Bash appends.
                        contents = output_file.read_text(encoding='utf-8')
                        contents = contents[:contents.rfind('\n') + 1]
                        rows = list(csv.DictReader(io.StringIO(contents)))
                        rows = [row for row in rows if len(row) == 40 and None not in row and all(v is not None for v in row.values())]
                        rows = [{k: ('UNKNOWN' if v is None or not str(v).strip() else v) for k, v in row.items()} for row in rows]
                        with self.lock:
                            self.scans[scan_id]['rows'] = rows
                            self.scans[scan_id]['completed'] = len(rows)
                            self.persist(scan_id)
                    if done:
                        if process.returncode:
                            raise RuntimeError('The checker could not complete. Check .secrets, dependencies and provider access on the server.')
                        break
                    if time.monotonic() > deadline:
                        process.kill()
                        process.wait()
                        raise RuntimeError('Scan timed out. Completed rows remain available to export.')
                    time.sleep(0.3)
            with self.lock:
                self.scans[scan_id]['status'] = 'complete'
        except Exception:
            with self.lock:
                self.scans[scan_id]['status'] = 'failed'
                self.scans[scan_id]['error'] = 'The scan stopped. Check server dependencies, .secrets and provider access. Completed results are still available.'
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            with self.lock:
                self.scans[scan_id]['finished_at'] = time.time()
                self.active = None
                self.persist(scan_id)


STORE = ScanStore()
EMAIL_SLOTS = threading.BoundedSemaphore(2)
DOMAIN_SLOTS = threading.BoundedSemaphore(2)
MAIL_SLOTS = threading.BoundedSemaphore(4)


def mail_config():
    return secret_values(os.environ.get('IP_CHECKER_MAIL_SECRETS', str(ROOT / '.mail_secrets')))


def queue_mail(user_id, kind):
    if not MAIL_SLOTS.acquire(blocking=False):
        return
    def deliver():
        try:
            issued = AUTH.issue_mail_token(user_id, kind)
            if issued:
                address, token = issued
                mailer.send_link(mail_config(), address, kind, token)
                DB.audit(user_id, 'mail.sent', kind)
        except Exception:
            DB.audit(user_id, 'mail.failed', kind)
        finally:
            MAIL_SLOTS.release()
    threading.Thread(target=deliver, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server_version = 'IPChecker'

    def log_message(self, *args):
        pass  # Do not log submitted addresses or configuration.

    def send(self, status, body, content_type='application/json; charset=utf-8', extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def trusted_request(self):
        # Reject cross-site writes and DNS rebinding; trusted proxy may retain Host.
        host = self.headers.get('Host', '')
        allowed = {'localhost', '127.0.0.1', '[::1]'}
        allowed.update(x.strip() for x in os.environ.get('IP_CHECKER_ALLOWED_HOSTS', '').split(',') if x.strip())
        hostname = urlsplit('//' + host).hostname
        if hostname not in allowed and f'[{hostname}]' not in allowed:
            return False
        origin = self.headers.get('Origin')
        return not origin or urlsplit(origin).netloc == host

    def session_token(self):
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            return cookies['ipchecker_session'].value if 'ipchecker_session' in cookies else ''
        except CookieError:
            return ''

    def current_user(self):
        return DB.session(self.session_token()) if DB else None

    def cookie(self, token='', clear=False):
        secure = '; Secure' if os.environ.get('IP_CHECKER_SECURE_COOKIE') == '1' else ''
        return 'ipchecker_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + ('0' if clear else '28800') + secure

    def require_user(self, write=False):
        user = self.current_user()
        if not user:
            self.send(401, {'error': 'Sign in to continue.'})
            return None
        if write and not hmac.compare_digest(self.headers.get('X-CSRF-Token', '').encode(), user['csrf'].encode()):
            self.send(403, {'error': 'Session verification failed. Refresh and try again.'})
            return None
        return user

    def security_gate(self, user, path):
        if not AUTH:
            return True
        state = AUTH.state(user, self.session_token())
        allowed = {'/api/security/state', '/api/logout', '/api/password'}
        if state['needs_mfa']:
            allowed.update(('/api/security/verify', '/api/security/passkey-options', '/api/security/passkey-verify'))
        elif state['needs_setup']:
            allowed.update(('/api/security/totp-start', '/api/security/totp-confirm', '/api/security/passkey-register-options', '/api/security/passkey-register'))
        if (state['needs_mfa'] or state['needs_setup']) and path not in allowed:
            self.send(403, {'error': 'Complete two-factor verification or enrolment in Account before continuing.'})
            return False
        return True

    def do_GET(self):
        if not self.trusted_request():
            return self.send(403, {'error': 'Host or origin is not allowed.'})
        path = urlsplit(self.path).path
        if path == '/api/health':
            return self.send(200, {'ok': DB is not None})
        if path == '/api/session':
            user = self.current_user()
            return self.send(200, {'user': user, 'setup_required': not DB or not DB.users()})
        if path == '/' and not self.current_user():
            return self.send(302, '', extra={'Location': '/login'})
        static = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/login': ('login.html', 'text/html; charset=utf-8'),
                  '/login.js': ('login.js', 'text/javascript; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/signals.js': ('signals.js', 'text/javascript; charset=utf-8'),
                  '/theme.js': ('theme.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in static:
            name, content_type = static[path]
            return self.send(200, (ROOT / 'web' / name).read_bytes(), content_type)
        # Unknown routes (including secrets and source files) never serve disk content.
        if not path.startswith('/api/'):
            return self.send(404, {'error': 'Not found.'})
        user = self.require_user()
        if not user:
            return
        if path == '/api/security/state' and AUTH:
            return self.send(200, {**AUTH.state(user, self.session_token()), 'mail_configured': mailer.configured(mail_config())})
        if not self.security_gate(user, path):
            return
        if user['must_change']:
            return self.send(403, {'error': 'Change your temporary password in Account before continuing.'})
        if path == '/api/history':
            query = parse_qs(urlsplit(self.path).query)
            try:
                page = max(1, min(100000, int(query.get('page', ['1'])[0])))
            except ValueError:
                return self.send(400, {'error': 'Invalid page.'})
            return self.send(200, DB.history(user, query.get('q', [''])[0], query.get('kind', [''])[0], page,
                                              query.get('scope', [''])[0] == 'all'))
        history_match = re.fullmatch(r'/api/history/([a-f0-9]{32})', path)
        if history_match:
            record = DB.record(history_match[1], user)
            return self.send(200, record) if record else self.send(404, {'error': 'Saved result not found.'})
        if path == '/api/admin':
            return self.send(200, {**DB.admin_summary(), **(AUTH.admin_state() if AUTH else {}), 'mail_configured': mailer.configured(mail_config())}) if user['role'] == 'admin' else self.send(403, {'error': 'Administrator access required.'})
        if path == '/api/config':
            config = configuration()
            config['active_scan'] = STORE.active if STORE.active and STORE.snapshot(STORE.active, user) else None
            return self.send(200, config)
        match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(/csv)?', path)
        if match:
            scan = STORE.snapshot(match[1], user)
            if not scan:
                return self.send(404, {'error': 'Scan not found or no longer retained.'})
            if match[2]:
                if not scan['rows']:
                    return self.send(409, {'error': 'No completed results to export yet.'})
                output = io.StringIO(newline='')
                writer = csv.writer(output)
                writer.writerow(scan['rows'][0].keys())
                for row in scan['rows']:
                    writer.writerow(safe_cell(str(v)) for v in row.values())
                return self.send(200, output.getvalue(), 'text/csv; charset=utf-8',
                                 {'Content-Disposition': 'attachment; filename="ip-results.csv"'})
            return self.send(200, scan)
        self.send(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.trusted_request() or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.send(403, {'error': 'Use a same-origin JSON request.'})
        path = urlsplit(self.path).path
        if path not in ('/api/scans', '/api/email', '/api/domain', '/api/login', '/api/logout',
                        '/api/password', '/api/admin/users', '/api/admin/retention', '/api/admin/mfa-policy',
                        '/api/forgot-password', '/api/reset-password', '/api/verify-email') and not re.fullmatch(r'/api/(?:admin/users/\d+|history/[a-f0-9]{32}/delete|security/[a-z-]+)', path):
            return self.send(404, {'error': 'Not found.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 100_000:
                raise ValueError('Input must be smaller than 100 KB.')
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            if AUTH and path == '/api/forgot-password':
                message = {'message': 'If an active account has this verified email, a password reset link will be sent. Check your inbox.'}
                try:
                    address = email_lookup.validate_email(data.get('email'))
                    AUTH.throttle('reset-ip:'+self.client_address[0], 10)
                    AUTH.throttle('reset-email:'+token_hash(address.casefold()), 3)
                    with DB.connect() as sql:
                        row = sql.execute('SELECT p.user_id FROM security_profiles p JOIN users u ON u.id=p.user_id WHERE p.email=? AND p.verified=1 AND u.active=1', (address,)).fetchone()
                    if row and mailer.configured(mail_config()):
                        queue_mail(row[0], 'reset')
                except ValueError:
                    pass
                return self.send(200, message)
            if AUTH and path in ('/api/reset-password', '/api/verify-email'):
                AUTH.throttle('mail-token:'+self.client_address[0], 20)
                AUTH.consume_mail_token(data.get('token'), 'reset' if path == '/api/reset-password' else 'verify', data.get('password'))
                return self.send(200, {'ok': True})
            if path == '/api/login':
                if not DB:
                    return self.send(503, {'error': 'Database is unavailable.'})
                token, error = DB.login(data.get('username'), data.get('password'), self.client_address[0])
                return self.send(401 if error else 200, {'error': error} if error else {'ok': True},
                                 extra={} if error else {'Set-Cookie': self.cookie(token)})
            user = self.require_user(write=True)
            if not user:
                return
            if not self.security_gate(user, path):
                return
            if path == '/api/logout':
                DB.logout(self.session_token())
                return self.send(200, {'ok': True}, extra={'Set-Cookie': self.cookie(clear=True)})
            if path == '/api/password':
                DB.change_password(user['id'], data.get('current_password'), data.get('new_password'))
                return self.send(200, {'ok': True}, extra={'Set-Cookie': self.cookie(clear=True)})
            if user['must_change']:
                return self.send(403, {'error': 'Change your temporary password in Account before continuing.'})
            if AUTH and path.startswith('/api/security/'):
                token = self.session_token()
                if path == '/api/security/verify':
                    AUTH.verify_factor(user, data.get('code'), token)
                    return self.send(200, {'ok': True})
                if path == '/api/security/totp-start':
                    return self.send(200, AUTH.begin_totp(user, data.get('password')))
                if path == '/api/security/totp-confirm':
                    return self.send(200, AUTH.confirm_totp(user, data.get('code'), token))
                if path in ('/api/security/passkey-options', '/api/security/passkey-register-options'):
                    registration = path.endswith('register-options')
                    AUTH.throttle('passkey-options:'+str(user['id']), 20)
                    if registration:
                        AUTH.require_password(user, data.get('password'))
                    return self.send(200, AUTH.passkey_options(user, token, registration))
                if path in ('/api/security/passkey-verify', '/api/security/passkey-register'):
                    return self.send(200, AUTH.finish_passkey(user, token, data, path.endswith('register')))
                if path == '/api/security/remove-factor':
                    AUTH.remove_factor(user, token, data.get('password'), data.get('passkey_id'))
                    return self.send(200, {'ok': True})
                if path == '/api/security/recovery-codes':
                    AUTH.require_password(user, data.get('password'))
                    state = AUTH.state(user, token)
                    if not state['totp_enabled'] and not state['passkeys']:
                        raise ValueError('Enrol an authenticator or passkey first.')
                    return self.send(200, {'recovery_codes': AUTH.recovery_codes(user['id'])})
                if path == '/api/security/verify-email':
                    AUTH.require_password(user, data.get('password'))
                    AUTH.throttle('verify-mail:'+str(user['id']), 3)
                    if not mailer.configured(mail_config()):
                        raise ValueError('Ask your administrator to configure .mail_secrets on the server.')
                    if not AUTH.profile(user['id'])['email']:
                        raise ValueError('Ask your administrator to add an email address to your account.')
                    queue_mail(user['id'], 'verify')
                    return self.send(200, {'ok': True})
                return self.send(404, {'error': 'Not found.'})
            if path.startswith('/api/admin/'):
                if user['role'] != 'admin':
                    return self.send(403, {'error': 'Administrator access required.'})
                if path == '/api/admin/users':
                    if AUTH:
                        AUTH.validate_email(data.get('email', ''))
                        if type(data.get('require_mfa', False)) is not bool:
                            raise ValueError('Invalid second-factor requirement.')
                    user_id = DB.create_user(data.get('username'), data.get('password'), data.get('role', 'user'), user['id'])
                    if AUTH:
                        AUTH.set_email(user_id, data.get('email', ''))
                        AUTH.admin_policy(user['id'], user_id, bool(data.get('require_mfa')))
                    return self.send(201, {'id': user_id})
                if path == '/api/admin/mfa-policy' and AUTH:
                    state = AUTH.state(user, self.session_token())
                    if data.get('required') and not (state['mfa_verified'] and (state['totp_enabled'] or state['passkeys'])):
                        raise ValueError('Enrol and verify your own second factor before requiring it globally.')
                    AUTH.admin_policy(user['id'], required=data.get('required'))
                    return self.send(200, {'ok': True})
                if path == '/api/admin/retention':
                    days = DB.retention(data.get('days'), user['id'])
                    DB.cleanup()
                    return self.send(200, {'retention_days': days})
                target = int(path.rsplit('/', 1)[1])
                if AUTH:
                    if 'email' in data:
                        AUTH.validate_email(data['email'], target)
                    for flag in ('require_mfa', 'reset_mfa'):
                        if flag in data and type(data[flag]) is not bool:
                            raise ValueError('Invalid second-factor setting.')
                DB.update_user(user['id'], target, data)
                if AUTH:
                    if 'email' in data:
                        AUTH.set_email(target, data['email'])
                    if 'require_mfa' in data or data.get('reset_mfa'):
                        AUTH.admin_policy(user['id'], target, data.get('require_mfa', bool(AUTH.profile(target)['required'])), bool(data.get('reset_mfa')))
                return self.send(200, {'ok': True})
            deleted = re.fullmatch(r'/api/history/([a-f0-9]{32})/delete', path)
            if deleted:
                with STORE.lock:
                    DB.delete_record(deleted[1], user)
                    STORE.scans.pop(deleted[1], None)
                return self.send(200, {'ok': True})
            if path == '/api/domain':
                domain = domain_lookup.validate_domain(data.get('domain'))
                if not DOMAIN_SLOTS.acquire(blocking=False):
                    return self.send(429, {'error': 'Domain lookups are busy. Try again shortly.'})
                try:
                    result = domain_lookup.lookup(domain, secret_values().get('SPAMHAUS_KEY'))
                    result['history_id'] = DB.save(user['id'], 'domain', domain, result)
                    DB.audit(user['id'], 'lookup.domain', result['history_id'])
                    return self.send(200, result)
                finally:
                    DOMAIN_SLOTS.release()
            if path == '/api/email':
                email = email_lookup.validate_email(data.get('email'))
                key = secret_values().get('IPQS_KEY')
                if not key:
                    return self.send(409, {'error': 'Add IPQS_KEY to the server .secrets file to enable email lookups.'})
                if not EMAIL_SLOTS.acquire(blocking=False):
                    return self.send(429, {'error': 'Email lookups are busy. Try again shortly.'})
                try:
                    result = {'report': email_lookup.lookup(email, key)}
                    result['history_id'] = DB.save(user['id'], 'email', email, result)
                    DB.audit(user['id'], 'lookup.email', result['history_id'])
                    return self.send(200, result)
                except email_lookup.LookupError as error:
                    return self.send(502, {'error': str(error)})
                finally:
                    EMAIL_SLOTS.release()
            addresses, skipped = parse_ips(data.get('ips'))
            if not configuration()['ready']:
                return self.send(409, {'error': 'Finish server setup first. All four provider keys and runtime dependencies are required.'})
            scan_id = STORE.create(addresses, skipped, user['id'])
            DB.audit(user['id'], 'lookup.ip', scan_id)
            self.send(202, {'id': scan_id})
        except (ValueError, UnicodeError) as error:
            self.send(400, {'error': str(error)})


def main():
    global DB, AUTH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--create-admin', metavar='USERNAME', help='Create a local admin using a hidden password prompt, then exit.')
    parser.add_argument('--reset-password', metavar='USERNAME', help='Reset an existing account password from the server terminal.')
    parser.add_argument('--reset-mfa', metavar='USERNAME', help='Recover a lost second factor from the server terminal; preserve the required-enrolment policy.')
    args = parser.parse_args()
    os.umask(0o077)
    DB = Database(os.environ.get('IP_CHECKER_DB', str(ROOT / 'data' / 'ip-checker.sqlite3')))
    AUTH = Security(DB, secret_values())
    if args.reset_mfa:
        user = next((u for u in DB.users() if u['username'].casefold() == args.reset_mfa.casefold()), None)
        if not user:
            parser.error('User not found.')
        AUTH.admin_policy(None, user['id'], bool(AUTH.profile(user['id'])['required']), reset=True)
        print('Second factors cleared and sessions revoked. Required users must enrol again.')
        return
    if args.create_admin or args.reset_password:
        password = getpass.getpass('New password (15–128 characters): ')
        if password != getpass.getpass('Confirm password: '):
            parser.error('Passwords do not match.')
        try:
            if args.create_admin:
                DB.create_user(args.create_admin, password, 'admin', must_change=False)
            else:
                user = next((u for u in DB.users() if u['username'].casefold() == args.reset_password.casefold()), None)
                if not user:
                    raise ValueError('User not found.')
                DB.update_user(None, user['id'], {'password': password})
        except ValueError as error:
            parser.error(str(error))
        print('Account saved. No password was written to configuration or logs.')
        return
    DB.interrupt_scans()
    DB.cleanup()
    AUTH.cleanup()
    def maintenance():
        while True:
            time.sleep(3600)
            DB.cleanup()
            AUTH.cleanup()
    threading.Thread(target=maintenance, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f'IP Checker dashboard: http://{args.host}:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
