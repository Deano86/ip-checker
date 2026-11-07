#!/usr/bin/env python3
"""Local dashboard for the IP checker. No Python packages required."""
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

ROOT = Path(__file__).resolve().parent
KEYS = {'IPinfo': 'IPINFO_KEY', 'IP2Location': 'IP2_KEY',
        'proxycheck.io': 'PROXY_KEY', 'Spamhaus': 'SPAMHAUS_KEY', 'IPQS': 'IPQS_KEY'}


def secret_values():
    """Read simple assignments without executing the configuration."""
    path = Path(os.environ.get('IP_CHECKER_SECRETS', str(ROOT / '.secrets')))
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

    def create(self, addresses, skipped):
        with self.lock:
            if self.active:
                raise ValueError('A scan is already running. Wait for it to finish.')
            scan_id = uuid.uuid4().hex
            scan = {'id': scan_id, 'status': 'running', 'total': len(addresses),
                    'completed': 0, 'rows': [], 'skipped': skipped,
                    'started_at': time.time(), 'finished_at': None, 'error': None}
            # Keep a bounded, in-memory history. Nothing is written to the repo.
            while len(self.scans) >= 20:
                self.scans.pop(next(iter(self.scans)))
            self.scans[scan_id] = scan
            self.active = scan_id
        threading.Thread(target=self.run, args=(scan_id, addresses), daemon=True).start()
        return scan_id

    def snapshot(self, scan_id):
        with self.lock:
            scan = self.scans.get(scan_id)
            return json.loads(json.dumps(scan)) if scan else None

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


STORE = ScanStore()
EMAIL_SLOTS = threading.BoundedSemaphore(2)
DOMAIN_SLOTS = threading.BoundedSemaphore(2)


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

    def do_GET(self):
        if not self.trusted_request():
            return self.send(403, {'error': 'Host or origin is not allowed.'})
        path = urlsplit(self.path).path
        static = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/signals.js': ('signals.js', 'text/javascript; charset=utf-8'),
                  '/theme.js': ('theme.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in static:
            name, content_type = static[path]
            return self.send(200, (ROOT / 'web' / name).read_bytes(), content_type)
        if path == '/api/config':
            config = configuration()
            config['active_scan'] = STORE.active
            return self.send(200, config)
        match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(/csv)?', path)
        if match:
            scan = STORE.snapshot(match[1])
            if not scan:
                return self.send(404, {'error': 'Scan not found. History is cleared when the server restarts.'})
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
        if path not in ('/api/scans', '/api/email', '/api/domain'):
            return self.send(404, {'error': 'Not found.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 100_000:
                raise ValueError('Input must be smaller than 100 KB.')
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object.')
            if path == '/api/domain':
                domain = domain_lookup.validate_domain(data.get('domain'))
                if not DOMAIN_SLOTS.acquire(blocking=False):
                    return self.send(429, {'error': 'Domain lookups are busy. Try again shortly.'})
                try:
                    return self.send(200, domain_lookup.lookup(domain))
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
                    return self.send(200, {'report': email_lookup.lookup(email, key)})
                except email_lookup.LookupError as error:
                    return self.send(502, {'error': str(error)})
                finally:
                    EMAIL_SLOTS.release()
            addresses, skipped = parse_ips(data.get('ips'))
            if not configuration()['ready']:
                return self.send(409, {'error': 'Finish server setup first. All four provider keys and runtime dependencies are required.'})
            scan_id = STORE.create(addresses, skipped)
            self.send(202, {'id': scan_id})
        except (ValueError, UnicodeError) as error:
            self.send(400, {'error': str(error)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    os.umask(0o077)
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
