import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pyotp
from webauthn.helpers import bytes_to_base64url as b64, base64url_to_bytes

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dashboard
import test_dashboard as legacy
from database import Database, token_hash
from security import Security
import mailer


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / 'test.sqlite3')
        self.user_id = self.db.create_user('tester', 'testing password for security', 'admin', must_change=False)
        self.user = {'id': self.user_id, 'username': 'tester', 'role': 'admin'}
        self.token, _ = self.db.login('tester', 'testing password for security', 'test')
        self.auth = Security(self.db, {'WEBAUTHN_RP_ID':'checker.example', 'WEBAUTHN_ORIGIN':'https://checker.example'})

    def enrol_totp(self):
        result = self.auth.begin_totp(self.user, 'testing password for security')
        codes = self.auth.confirm_totp(self.user, pyotp.TOTP(result['secret']).now(), self.token)
        return result, codes['recovery_codes']

    def test_totp_encryption_replay_protection_and_single_use_recovery(self):
        setup, codes = self.enrol_totp()
        self.assertTrue(setup['qr'].startswith('data:image/svg+xml;base64,'))
        with self.db.connect() as sql:
            secret = sql.execute('SELECT totp FROM security_profiles').fetchone()[0]
            self.assertNotIn(setup['secret'], secret)
            self.assertNotIn(codes[0], str(sql.execute('SELECT * FROM recovery').fetchall()))
        token, _ = self.db.login('tester', 'testing password for security', 'test')
        self.assertTrue(self.auth.state(self.user, token)['needs_mfa'])
        with self.assertRaises(ValueError):
            self.auth.verify_factor(self.user, pyotp.TOTP(setup['secret']).now(), token)
        self.auth.verify_factor(self.user, codes[0], token)
        self.assertTrue(self.auth.state(self.user, token)['mfa_verified'])
        with self.assertRaises(ValueError):
            self.auth.verify_factor(self.user, codes[0], token)
        self.auth.admin_policy(self.user_id, required=True)
        with self.assertRaises(ValueError):
            self.auth.remove_factor(self.user, token, 'testing password for security')

    def test_reset_links_expire_are_single_use_and_do_not_clear_factors(self):
        self.auth.set_email(self.user_id, 'tester@example.com')
        self.assertIsNone(self.auth.issue_mail_token(self.user_id, 'reset'))
        _, verification = self.auth.issue_mail_token(self.user_id, 'verify')
        self.auth.consume_mail_token(verification, 'verify')
        self.enrol_totp()
        _, token = self.auth.issue_mail_token(self.user_id, 'reset')
        with self.db.connect() as sql:
            self.assertEqual(sql.execute("SELECT hash FROM mail_tokens WHERE kind='reset'").fetchone()[0], token_hash(token))
        self.auth.consume_mail_token(token, 'reset', 'a replacement reset password')
        self.assertIsNone(self.db.session(self.token))
        self.assertTrue(self.auth.profile(self.user_id)['totp'])
        with self.assertRaises(ValueError):
            self.auth.consume_mail_token(token, 'reset', 'yet another new password')
        _, expired = self.auth.issue_mail_token(self.user_id, 'reset')
        with self.db.connect() as sql:
            sql.execute('UPDATE mail_tokens SET expires=0')
        with self.assertRaises(ValueError):
            self.auth.consume_mail_token(expired, 'reset', 'yet another new password')

    def test_changed_email_invalidates_old_links_and_admin_recovery_preserves_policy(self):
        self.auth.set_email(self.user_id, 'tester@example.com')
        _, token = self.auth.issue_mail_token(self.user_id, 'verify')
        self.auth.set_email(self.user_id, 'new@example.com')
        with self.assertRaises(ValueError):
            self.auth.consume_mail_token(token, 'verify')
        self.enrol_totp()
        self.auth.admin_policy(self.user_id, self.user_id, required=True, reset=True)
        self.assertIsNone(self.db.session(self.token))
        self.assertTrue(self.auth.state(self.user, '')['needs_setup'])

    def test_account_changes_revoke_outstanding_reset_links(self):
        self.auth.set_email(self.user_id, 'tester@example.com')
        _, verification = self.auth.issue_mail_token(self.user_id, 'verify')
        self.auth.consume_mail_token(verification, 'verify')
        _, token = self.auth.issue_mail_token(self.user_id, 'reset')
        self.db.change_password(self.user_id, 'testing password for security', 'a changed account password')
        with self.assertRaises(ValueError):
            self.auth.consume_mail_token(token, 'reset', 'attacker chosen password')

    def registration(self, origin='https://checker.example', uv=True):
        options = self.auth.passkey_options(self.user, self.token, registration=True)
        private = ec.generate_private_key(ec.SECP256R1())
        public = private.public_key().public_numbers()
        cose = {1:2, 3:-7, -1:1, -2:public.x.to_bytes(32,'big'), -3:public.y.to_bytes(32,'big')}
        credential_id = secrets.token_bytes(24)
        auth_data = hashlib.sha256(b'checker.example').digest() + bytes([0x45 if uv else 0x41]) + bytes(4) + bytes(16) + len(credential_id).to_bytes(2,'big') + credential_id + cbor2.dumps(cose)
        client = json.dumps({'type':'webauthn.create','challenge':options['options']['challenge'],'origin':origin}).encode()
        credential = {'id':b64(credential_id),'rawId':b64(credential_id),'type':'public-key',
                      'response':{'attestationObject':b64(cbor2.dumps({'fmt':'none','attStmt':{},'authData':auth_data})), 'clientDataJSON':b64(client)}}
        return private, credential_id, {'challenge_id':options['challenge_id'],'credential':credential,'name':'Test passkey'}

    def test_real_passkey_signature_origin_uv_and_challenge_replay(self):
        private, credential_id, data = self.registration()
        self.auth.finish_passkey(self.user, self.token, data, registration=True)
        with self.assertRaises(ValueError):
            self.auth.finish_passkey(self.user, self.token, data, registration=True)
        options = self.auth.passkey_options(self.user, self.token)
        client = json.dumps({'type':'webauthn.get','challenge':options['options']['challenge'],'origin':'https://checker.example'}).encode()
        auth_data = hashlib.sha256(b'checker.example').digest() + b'\x05' + (1).to_bytes(4,'big')
        signature = private.sign(auth_data+hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        assertion = {'challenge_id':options['challenge_id'],'credential':{'id':b64(credential_id),'rawId':b64(credential_id),'type':'public-key',
                     'response':{'authenticatorData':b64(auth_data),'clientDataJSON':b64(client),'signature':b64(signature),'userHandle':b64(str(self.user_id).encode())}}}
        self.auth.finish_passkey(self.user, self.token, assertion)
        self.assertTrue(self.auth.state(self.user, self.token)['mfa_verified'])
        _, _, wrong_origin = self.registration(origin='https://evil.example')
        with self.assertRaises(ValueError):
            self.auth.finish_passkey(self.user, self.token, wrong_origin, registration=True)
        _, _, no_uv = self.registration(uv=False)
        with self.assertRaises(ValueError):
            self.auth.finish_passkey(self.user, self.token, no_uv, registration=True)

    def test_mail_requires_tls_and_fixed_safe_origin(self):
        base = {'APP_URL':'https://checker.example','SMTP_HOST':'smtp.example','SMTP_FROM':'checker@example.com','SMTP_SECURITY':'starttls'}
        self.assertTrue(mailer.configured(base))
        self.assertFalse(mailer.configured({**base,'SMTP_SECURITY':'none'}))
        self.assertFalse(mailer.configured({**base,'APP_URL':'http://public.example'}))
        self.assertFalse(mailer.configured({**base,'APP_URL':'https://checker.example/other'}))
        with patch.object(mailer.smtplib, 'SMTP') as smtp:
            mailer.send_link(base,'user@example.com','reset','token')
            instance=smtp.return_value.__enter__.return_value
            instance.starttls.assert_called_once()
            message=instance.send_message.call_args.args[0]
            self.assertIn('https://checker.example/login#reset=token', message.get_content())


class SecurityHTTPTests(unittest.TestCase):
    close = legacy.HTTPTests.close
    request = legacy.HTTPTests.request

    def setUp(self):
        legacy.HTTPTests.setUp(self)
        self.auth = Security(self.db, {})
        self.auth_patch = patch.object(dashboard, 'AUTH', self.auth)
        self.auth_patch.start()
        self.addCleanup(self.auth_patch.stop)

    def test_mandatory_enrolment_and_mfa_gate_every_saved_result_route(self):
        self.auth.admin_policy(self.user_id, self.user_id, required=True)
        for path in ('/api/config','/api/history','/api/admin','/api/scans/'+'a'*32+'/csv'):
            self.assertEqual(self.request(path)[0], 403)
        self.assertEqual(self.request('/api/security/state')[0], 200)
        self.assertEqual(self.request('/api/domain', {'domain':'example.com'})[0], 403)
        self.assertEqual(self.request('/api/security/totp-start', {'password':'wrong'})[0], 400)
        setup=json.loads(self.request('/api/security/totp-start', {'password':'testing password for dashboard'})[1])
        status, body, _=self.request('/api/security/totp-confirm', {'code':pyotp.TOTP(setup['secret']).now()})
        self.assertEqual(status, 200)
        recovery=json.loads(body)['recovery_codes'][0]
        self.assertEqual(self.request('/api/history')[0], 200)
        self.token, _=self.db.login('tester','testing password for dashboard','local')
        self.csrf=self.db.session(self.token)['csrf']
        self.assertEqual(self.request('/api/history')[0], 403)
        self.assertEqual(self.request('/api/security/verify', {'code':recovery})[0], 200)
        self.assertEqual(self.request('/api/history')[0], 200)

    def test_reset_request_is_generic_and_never_returns_tokens(self):
        first=self.request('/api/forgot-password', {'email':'absent@example.com'}, {'Cookie':''})
        self.auth.set_email(self.user_id,'tester@example.com')
        second=self.request('/api/forgot-password', {'email':'tester@example.com'}, {'Cookie':''})
        self.assertEqual(first[0], 200)
        self.assertEqual(first[1], second[1])
        self.assertNotIn(b'token', first[1])


if __name__ == '__main__':
    unittest.main()
