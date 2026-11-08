"""Authenticator codes, WebAuthn passkeys, recovery and emailed reset tokens."""
import base64
import io
import json
import secrets
import sqlite3
import time
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
import pyotp
import qrcode
import qrcode.image.svg
from webauthn import (generate_registration_options, verify_registration_response,
                      generate_authentication_options, verify_authentication_response)
from webauthn.helpers import options_to_json, bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, UserVerificationRequirement,
                                     ResidentKeyRequirement, PublicKeyCredentialDescriptor)
from database import password_hash, password_matches, token_hash


class Security:
    def __init__(self, db, config=None):
        self.db = db
        self.config = config or {}
        key = self.config.get('AUTH_ENCRYPTION_KEY')
        if not key:
            path = db.path.parent / 'auth.key'
            try:
                with path.open('xb') as file:
                    file.write(Fernet.generate_key())
                path.chmod(0o600)
            except FileExistsError:
                pass
            key = path.read_bytes()
        self.cipher = Fernet(key)
        with db.connect() as sql:
            sql.executescript('''
                CREATE TABLE IF NOT EXISTS security_profiles (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id), email TEXT UNIQUE COLLATE NOCASE,
                    verified INTEGER NOT NULL DEFAULT 0, totp TEXT, pending TEXT, pending_at REAL,
                    last_step INTEGER NOT NULL DEFAULT -1, required INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS passkeys (
                    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL, name TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS recovery (
                    hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id));
                CREATE TABLE IF NOT EXISTS assurance (
                    token TEXT PRIMARY KEY REFERENCES sessions(token) ON DELETE CASCADE, verified INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS challenges (
                    id TEXT PRIMARY KEY, user_id INTEGER, kind TEXT NOT NULL, value TEXT NOT NULL,
                    binding TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS mail_tokens (
                    hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
                    address TEXT NOT NULL, expires REAL NOT NULL);
                INSERT OR IGNORE INTO settings VALUES ('require_mfa','0');
            ''')

    def throttle(self, key, limit=10, window=900):
        now = time.time()
        with self.db.connect() as sql:
            sql.execute('BEGIN IMMEDIATE')
            sql.execute('DELETE FROM attempts WHERE key=? AND started<?', (key, now-window))
            row = sql.execute('SELECT count FROM attempts WHERE key=?', (key,)).fetchone()
            if row and row[0] >= limit:
                raise ValueError('Too many attempts. Try again later.')
            sql.execute('INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key, now))

    def profile(self, user_id):
        with self.db.connect() as sql:
            sql.execute('INSERT OR IGNORE INTO security_profiles(user_id) VALUES (?)', (user_id,))
            return dict(sql.execute('SELECT * FROM security_profiles WHERE user_id=?', (user_id,)).fetchone())

    def state(self, user, token):
        profile = self.profile(user['id'])
        with self.db.connect() as sql:
            keys = [dict(row) for row in sql.execute('SELECT id,name,created FROM passkeys WHERE user_id=?', (user['id'],))]
            required = bool(profile['required'] or sql.execute("SELECT value FROM settings WHERE key='require_mfa'").fetchone()[0] == '1')
            assurance = sql.execute('SELECT verified FROM assurance WHERE token=?', (token_hash(token),)).fetchone()
            verified = bool(assurance and assurance[0])
            recovery = sql.execute('SELECT count(*) FROM recovery WHERE user_id=?', (user['id'],)).fetchone()[0]
        enrolled = bool(profile['totp'] or keys)
        return {'totp_enabled': bool(profile['totp']), 'passkeys': keys, 'required': required,
                'mfa_verified': verified, 'needs_mfa': enrolled and not verified,
                'needs_setup': required and not enrolled, 'email': profile['email'] or '',
                'email_verified': bool(profile['verified']), 'recovery_remaining': recovery,
                'passkeys_available': self.rp() is not None}

    def require_password(self, user, password):
        self.throttle('reauth:'+str(user['id']))
        with self.db.connect() as sql:
            row = sql.execute('SELECT password FROM users WHERE id=? AND active=1', (user['id'],)).fetchone()
        if not row or not password_matches(password, row['password']):
            raise ValueError('Current password is incorrect.')

    def mark_verified(self, token):
        with self.db.connect() as sql:
            sql.execute('INSERT INTO assurance VALUES (?,1) ON CONFLICT(token) DO UPDATE SET verified=1', (token_hash(token),))

    def recovery_codes(self, user_id):
        codes = [secrets.token_hex(8) for _ in range(10)]
        with self.db.connect() as sql:
            sql.execute('DELETE FROM recovery WHERE user_id=?', (user_id,))
            sql.executemany('INSERT INTO recovery VALUES (?,?)', [(token_hash(code), user_id) for code in codes])
        return codes

    def verify_factor(self, user, code, token):
        self.throttle('mfa:'+str(user['id']))
        if not isinstance(code, str) or len(code) > 100:
            raise ValueError('Enter an authenticator or recovery code.')
        code = code.strip().replace(' ', '')
        with self.db.connect() as sql:
            sql.execute('BEGIN IMMEDIATE')
            profile = sql.execute('SELECT * FROM security_profiles WHERE user_id=?', (user['id'],)).fetchone()
            used = sql.execute('DELETE FROM recovery WHERE hash=? AND user_id=?', (token_hash(code.lower()), user['id'])).rowcount
            if not used and profile and profile['totp']:
                totp = pyotp.TOTP(self.cipher.decrypt(profile['totp'].encode()).decode())
                step = int(time.time()//30)
                for n in (step-1, step, step+1):
                    if n > profile['last_step'] and secrets.compare_digest(totp.at(n*30).encode(), code.encode()):
                        sql.execute('UPDATE security_profiles SET last_step=? WHERE user_id=?', (n, user['id']))
                        used = True
                        break
            if not used:
                raise ValueError('Code is invalid or already used.')
        self.mark_verified(token)
        self.db.audit(user['id'], 'mfa.verified')

    def begin_totp(self, user, password):
        self.require_password(user, password)
        if self.profile(user['id'])['totp']:
            raise ValueError('An authenticator is already enrolled.')
        secret = pyotp.random_base32()
        with self.db.connect() as sql:
            sql.execute('UPDATE security_profiles SET pending=?,pending_at=? WHERE user_id=?',
                        (self.cipher.encrypt(secret.encode()).decode(), time.time(), user['id']))
        uri = pyotp.TOTP(secret).provisioning_uri(user['username'], issuer_name='IP Checker')
        buffer = io.BytesIO()
        qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(buffer)
        return {'secret': secret, 'uri': uri, 'qr': 'data:image/svg+xml;base64,'+base64.b64encode(buffer.getvalue()).decode()}

    def confirm_totp(self, user, code, token):
        self.throttle('mfa:'+str(user['id']))
        profile = self.profile(user['id'])
        if profile['totp'] or not profile['pending'] or profile['pending_at'] < time.time()-600:
            raise ValueError('Start authenticator setup again.')
        secret = self.cipher.decrypt(profile['pending'].encode()).decode()
        step = int(time.time()//30)
        matched_step = next((n for n in (step-1, step, step+1)
                             if isinstance(code, str) and secrets.compare_digest(pyotp.TOTP(secret).at(n*30).encode(), code.strip().encode())), None)
        if matched_step is None:
            raise ValueError('Code is invalid. Check your device time and try again.')
        with self.db.connect() as sql:
            changed = sql.execute('UPDATE security_profiles SET totp=pending,pending=NULL,last_step=? WHERE user_id=? AND pending=? AND totp IS NULL',
                                 (matched_step, user['id'], profile['pending'])).rowcount
            if not changed:
                raise ValueError('Setup changed. Start again.')
        self.mark_verified(token)
        self.db.audit(user['id'], 'totp.enrolled')
        return {'recovery_codes': self.recovery_codes(user['id'])}

    def set_email(self, user_id, address):
        address = self.validate_email(address, user_id)
        self.profile(user_id)
        try:
            with self.db.connect() as sql:
                old = sql.execute('SELECT email FROM security_profiles WHERE user_id=?', (user_id,)).fetchone()[0]
                if (old or '') != address:
                    sql.execute('UPDATE security_profiles SET email=?,verified=0 WHERE user_id=?', (address or None, user_id))
                    sql.execute('DELETE FROM mail_tokens WHERE user_id=?', (user_id,))
        except sqlite3.IntegrityError:
            raise ValueError('That email address is already assigned to an account.') from None

    def validate_email(self, address, user_id=-1):
        address = address.strip() if isinstance(address, str) else ''
        if address:
            from email_lookup import validate_email
            address = validate_email(address)
            with self.db.connect() as sql:
                if sql.execute('SELECT 1 FROM security_profiles WHERE email=? AND user_id!=?', (address, user_id)).fetchone():
                    raise ValueError('That email address is already assigned to an account.')
        return address

    def issue_mail_token(self, user_id, kind):
        profile = self.profile(user_id)
        if not profile['email'] or (kind == 'reset' and not profile['verified']):
            return None
        token = secrets.token_urlsafe(32)
        with self.db.connect() as sql:
            sql.execute('DELETE FROM mail_tokens WHERE user_id=? AND kind=?', (user_id, kind))
            sql.execute('INSERT INTO mail_tokens VALUES (?,?,?,?,?)', (token_hash(token), user_id, kind,
                        profile['email'], time.time() + (900 if kind == 'reset' else 3600)))
        return profile['email'], token

    def consume_mail_token(self, token, kind, password=None):
        if not isinstance(token, str) or len(token) > 100:
            raise ValueError('Link is invalid or expired.')
        encoded = password_hash(password) if kind == 'reset' else None
        with self.db.connect() as sql:
            sql.execute('BEGIN IMMEDIATE')
            row = sql.execute('SELECT t.* FROM mail_tokens t JOIN security_profiles p ON p.user_id=t.user_id JOIN users u ON u.id=t.user_id WHERE t.hash=? AND t.kind=? AND t.expires>? AND p.email=t.address AND u.active=1',
                              (token_hash(token), kind, time.time())).fetchone()
            if not row:
                raise ValueError('Link is invalid or expired. Request a new one.')
            sql.execute('DELETE FROM mail_tokens WHERE hash=?', (token_hash(token),))
            if kind == 'verify':
                sql.execute('UPDATE security_profiles SET verified=1 WHERE user_id=?', (row['user_id'],))
            else:
                sql.execute('UPDATE users SET password=?,must_change=0 WHERE id=?', (encoded, row['user_id']))
                sql.execute('DELETE FROM sessions WHERE user_id=?', (row['user_id'],))
                sql.execute('DELETE FROM mail_tokens WHERE user_id=?', (row['user_id'],))
                self.db.revoke_security_tokens(sql, row['user_id'])
        self.db.audit(row['user_id'], 'email.verified' if kind == 'verify' else 'password.reset')

    def rp(self):
        origin = self.config.get('WEBAUTHN_ORIGIN', '')
        rp_id = self.config.get('WEBAUTHN_RP_ID', '')
        parsed = urlsplit(origin)
        secure = parsed.scheme == 'https' or (parsed.scheme == 'http' and parsed.hostname == 'localhost')
        if not secure or parsed.hostname != rp_id or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username:
            return None
        return rp_id, origin.rstrip('/')

    def challenge(self, user_id, kind, value, binding):
        challenge_id = secrets.token_urlsafe(32)
        with self.db.connect() as sql:
            sql.execute('DELETE FROM challenges WHERE expires<?', (time.time(),))
            sql.execute('INSERT INTO challenges VALUES (?,?,?,?,?,?)', (challenge_id, user_id, kind, value, binding, time.time()+300))
        return challenge_id

    def take_challenge(self, challenge_id, kind, binding):
        with self.db.connect() as sql:
            sql.execute('BEGIN IMMEDIATE')
            row = sql.execute('SELECT * FROM challenges WHERE id=? AND kind=? AND binding=? AND expires>?',
                              (challenge_id, kind, binding, time.time())).fetchone()
            if not row:
                raise ValueError('Passkey challenge expired. Start again.')
            sql.execute('DELETE FROM challenges WHERE id=?', (challenge_id,))
            return dict(row)

    def passkey_options(self, user, token, registration=False):
        if not self.rp():
            raise ValueError('Set WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN in .secrets first.')
        rp_id, _ = self.rp()
        with self.db.connect() as sql:
            keys = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(row['id'])) for row in sql.execute('SELECT id FROM passkeys WHERE user_id=?', (user['id'],))]
        if registration:
            if len(keys) >= 10:
                raise ValueError('An account can have up to ten passkeys.')
            options = generate_registration_options(rp_id=rp_id, rp_name='IP Checker',
                user_id=str(user['id']).encode(), user_name=user['username'], exclude_credentials=keys,
                authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,
                                                                       user_verification=UserVerificationRequirement.REQUIRED))
        else:
            options = generate_authentication_options(rp_id=rp_id, allow_credentials=keys or [PublicKeyCredentialDescriptor(id=secrets.token_bytes(32))],
                                                       user_verification=UserVerificationRequirement.REQUIRED)
        kind = 'register' if registration else 'authenticate'
        challenge_id = self.challenge(user['id'], kind, bytes_to_base64url(options.challenge), token_hash(token))
        return {'challenge_id': challenge_id, 'options': json.loads(options_to_json(options))}

    def finish_passkey(self, user, token, data, registration=False):
        if not self.rp():
            raise ValueError('Passkeys are not configured.')
        self.throttle('passkey:'+str(user['id']))
        kind = 'register' if registration else 'authenticate'
        challenge = self.take_challenge(data.get('challenge_id'), kind, token_hash(token))
        if challenge['user_id'] != user['id']:
            raise ValueError('Passkey challenge is invalid.')
        rp_id, origin = self.rp()
        credential = data.get('credential', {})
        try:
            if registration:
                verified = verify_registration_response(credential=credential, expected_challenge=base64url_to_bytes(challenge['value']),
                    expected_rp_id=rp_id, expected_origin=origin, require_user_verification=True)
                with self.db.connect() as sql:
                    sql.execute('INSERT INTO passkeys VALUES (?,?,?,?,?,?)',
                                (bytes_to_base64url(verified.credential_id), user['id'], verified.credential_public_key,
                                 verified.sign_count, str(data.get('name', 'Passkey'))[:64] or 'Passkey', time.time()))
            else:
                with self.db.connect() as sql:
                    key = sql.execute('SELECT * FROM passkeys WHERE id=? AND user_id=?', (credential.get('id'), user['id'])).fetchone()
                if not key:
                    raise ValueError()
                verified = verify_authentication_response(credential=credential, expected_challenge=base64url_to_bytes(challenge['value']),
                    expected_rp_id=rp_id, expected_origin=origin, credential_public_key=key['public_key'],
                    credential_current_sign_count=key['sign_count'], require_user_verification=True)
                with self.db.connect() as sql:
                    changed = sql.execute('UPDATE passkeys SET sign_count=? WHERE id=? AND sign_count=?',
                                         (verified.new_sign_count, key['id'], key['sign_count'])).rowcount
                    if not changed:
                        raise ValueError()
        except Exception:
            raise ValueError('Passkey verification failed. Try again.') from None
        self.mark_verified(token)
        self.db.audit(user['id'], 'passkey.enrolled' if registration else 'passkey.verified')
        if registration and not self.state(user, token)['recovery_remaining']:
            return {'recovery_codes': self.recovery_codes(user['id'])}
        return {'ok': True}

    def remove_factor(self, user, token, password, passkey_id=None):
        self.require_password(user, password)
        state = self.state(user, token)
        if passkey_id and not any(key['id'] == passkey_id for key in state['passkeys']):
            raise ValueError('Passkey not found.')
        if not passkey_id and not state['totp_enabled']:
            raise ValueError('Authenticator not enrolled.')
        remaining = len(state['passkeys']) + int(state['totp_enabled']) - 1
        if state['required'] and remaining < 1:
            raise ValueError('Enrol another factor before removing your last required factor.')
        with self.db.connect() as sql:
            if passkey_id:
                sql.execute('DELETE FROM passkeys WHERE id=? AND user_id=?', (passkey_id, user['id']))
            else:
                sql.execute('UPDATE security_profiles SET totp=NULL,pending=NULL,last_step=-1 WHERE user_id=?', (user['id'],))
            sql.execute('DELETE FROM sessions WHERE user_id=? AND token!=?', (user['id'], token_hash(token)))
            if remaining <= 0:
                sql.execute('DELETE FROM recovery WHERE user_id=?', (user['id'],))
        self.db.audit(user['id'], 'factor.removed')

    def admin_policy(self, actor, user_id=None, required=None, reset=False):
        if type(required) is not bool and not reset:
            raise ValueError('Choose a two-factor policy.')
        with self.db.connect() as sql:
            if user_id is None:
                sql.execute("UPDATE settings SET value=? WHERE key='require_mfa'", ('1' if required else '0',))
            else:
                self.profile(user_id)
                sql.execute('UPDATE security_profiles SET required=? WHERE user_id=?', (int(bool(required)), user_id))
                if reset:
                    sql.execute('UPDATE security_profiles SET totp=NULL,pending=NULL,last_step=-1 WHERE user_id=?', (user_id,))
                    sql.execute('DELETE FROM passkeys WHERE user_id=?', (user_id,))
                    sql.execute('DELETE FROM recovery WHERE user_id=?', (user_id,))
                    sql.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
                    self.db.revoke_security_tokens(sql, user_id)
        self.db.audit(actor, 'mfa.policy' if not reset else 'mfa.admin_reset', user_id or 'all')

    def admin_state(self):
        with self.db.connect() as sql:
            return {'require_mfa': sql.execute("SELECT value FROM settings WHERE key='require_mfa'").fetchone()[0] == '1',
                    'profiles': [dict(row) for row in sql.execute('SELECT p.user_id,p.email,p.verified,p.required,(p.totp IS NOT NULL) totp_enabled,(SELECT count(*) FROM passkeys k WHERE k.user_id=p.user_id) passkey_count FROM security_profiles p')]}

    def cleanup(self):
        with self.db.connect() as sql:
            sql.execute('DELETE FROM mail_tokens WHERE expires<?', (time.time(),))
            sql.execute('DELETE FROM challenges WHERE expires<?', (time.time(),))
            sql.execute('UPDATE security_profiles SET pending=NULL,pending_at=NULL WHERE pending_at<?', (time.time()-600,))
