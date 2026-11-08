import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import Database, token_hash
import test_dashboard as legacy
import dashboard


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'db.sqlite3'
        self.db = Database(self.path)
        self.admin = self.db.create_user('admin', 'a long admin password', 'admin', must_change=False)
        self.user = self.db.create_user('user1', 'a long user password')
        self.admin_session = {'id': self.admin, 'role': 'admin'}
        self.user_session = {'id': self.user, 'role': 'user'}

    def test_passwords_are_salted_and_session_tokens_are_not_stored_raw(self):
        token, error = self.db.login('admin', 'a long admin password', 'local')
        self.assertIsNone(error)
        with self.db.connect() as db:
            row = db.execute('SELECT * FROM users WHERE id=?', (self.admin,)).fetchone()
            self.assertTrue(row['password'].startswith('scrypt$'))
            self.assertNotIn('a long admin password', row['password'])
            self.assertEqual(db.execute('SELECT token FROM sessions').fetchone()[0], token_hash(token))
        self.assertNotIn('password', self.db.session(token))

    def test_private_history_search_and_restart(self):
        item = self.db.save(self.admin, 'email', 'private@example.com', {'report': {'Fraud Score': '75'}})
        self.assertIsNone(self.db.record(item, self.user_session))
        self.assertEqual(self.db.history(self.user_session, all_users=True)['total'], 0)
        self.assertEqual(self.db.history(self.admin_session, query='75')['total'], 1)
        reopened = Database(self.path)
        self.assertEqual(reopened.record(item, self.admin_session)['payload']['report']['Fraud Score'], '75')

    def test_disable_reset_and_password_change_revoke_sessions(self):
        token, _ = self.db.login('user1', 'a long user password', 'local')
        self.db.update_user(self.admin, self.user, {'password': 'new temporary password'})
        self.assertIsNone(self.db.session(token))
        token, _ = self.db.login('user1', 'new temporary password', 'local')
        self.assertTrue(self.db.session(token)['must_change'])
        self.db.change_password(self.user, 'new temporary password', 'my replacement password')
        self.assertIsNone(self.db.session(token))
        token, _ = self.db.login('user1', 'my replacement password', 'local')
        self.assertFalse(self.db.session(token)['must_change'])
        self.db.update_user(self.admin, self.user, {'active': False})
        self.assertIsNone(self.db.session(token))
        self.assertIsNone(self.db.login('user1', 'my replacement password', 'local')[0])

    def test_last_admin_guard_and_invalid_roles(self):
        for data in ({'active': False}, {'role': 'user'}, {'role': 'owner'}):
            with self.assertRaises(ValueError):
                self.db.update_user(self.admin, self.admin, data)
        with self.assertRaises(ValueError):
            self.db.create_user('short', 'too short')

    def test_expiry_throttling_and_logout(self):
        token, _ = self.db.login('admin', 'a long admin password', 'local')
        with self.db.connect() as db:
            db.execute('UPDATE sessions SET seen=?', (time.time()-1801,))
        self.assertIsNone(self.db.session(token))
        for _ in range(10):
            self.db.login('absent', 'a sufficiently long password', 'other')
        token, error = self.db.login('absent', 'a sufficiently long password', 'other')
        self.assertIsNone(token)
        self.assertIn('Too many', error)

    def test_retention_deletion_and_interrupted_scan(self):
        scan = {'status': 'running', 'rows': [{'IP Address': '1.1.1.1'}]}
        item = self.db.save(self.user, 'ip', '1.1.1.1', scan, status='running')
        with self.assertRaises(ValueError):
            self.db.delete_record(item, self.user_session)
        self.db.interrupt_scans()
        saved = self.db.record(item, self.user_session)
        self.assertEqual(saved['payload']['status'], 'failed')
        self.assertEqual(len(saved['payload']['rows']), 1)
        with self.db.connect() as db:
            db.execute('UPDATE history SET updated=?', (time.time()-86400*10,))
        self.db.retention(7, self.admin)
        self.db.cleanup()
        self.assertIsNone(self.db.record(item, self.user_session))


class AccountHTTPTests(unittest.TestCase):
    setUp = legacy.HTTPTests.setUp
    close = legacy.HTTPTests.close
    request = legacy.HTTPTests.request

    def test_unauthenticated_and_csrf_requests_cannot_read_or_write(self):
        for path in ('/api/config', '/api/history', '/api/admin', '/api/scans/'+'a'*32):
            self.assertEqual(self.request(path, headers={'Cookie': ''})[0], 401)
        self.assertEqual(self.request('/api/scans', {'ips': '1.1.1.1'}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('/api/login', {'username': 'tester', 'password': 'testing password for dashboard'}, {'Origin':'https://evil.example'})[0], 403)

    def test_login_cookie_logout_and_temporary_password_enforcement(self):
        status, _, headers = self.request('/api/login', {'username':'tester','password':'testing password for dashboard'})
        self.assertEqual(status, 200)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        user_id = self.db.create_user('new-user', 'temporary test password')
        token, _ = self.db.login('new-user', 'temporary test password', '127.0.0.1')
        self.token, self.csrf = token, self.db.session(token)['csrf']
        self.assertEqual(self.request('/api/history')[0], 403)
        self.assertEqual(self.request('/api/password', {'current_password':'temporary test password', 'new_password':'a different user password'})[0], 200)
        self.assertEqual(self.request('/api/history')[0], 401)

    def test_roles_and_direct_record_access_are_enforced(self):
        private = self.db.save(self.user_id, 'email', 'owner@example.com', {'report': {}})
        self.db.create_user('regular', 'regular account password', must_change=False)
        self.token, _ = self.db.login('regular', 'regular account password', '127.0.0.1')
        self.csrf = self.db.session(self.token)['csrf']
        self.assertEqual(self.request('/api/history/'+private)[0], 404)
        self.assertEqual(self.request('/api/history/'+private+'/delete', {})[0], 400)
        self.assertEqual(self.request('/api/admin')[0], 403)
        self.assertEqual(self.request('/api/admin/users', {'username':'evil','password':'some strong password','role':'admin'})[0], 403)
        self.assertEqual(json.loads(self.request('/api/history?scope=all')[1])['total'], 0)

    def test_lookup_results_are_saved_and_reopen_after_memory_reset(self):
        with patch.object(dashboard.domain_lookup, 'lookup', return_value={'report':{'Domain':'example.com'},'records':[],'queries':[],'reputation':[],'health':'OK'}):
            status, body, _ = self.request('/api/domain', {'domain':'example.com'})
        self.assertEqual(status, 200)
        record_id = json.loads(body)['history_id']
        self.assertEqual(json.loads(self.request('/api/history/'+record_id)[1])['payload']['report']['Domain'], 'example.com')
        self.assertEqual(json.loads(self.request('/api/history?q=example.com')[1])['total'], 1)
        self.assertEqual(self.request('/api/history/'+record_id+'/delete', {})[0], 200)
        self.assertEqual(self.request('/api/history/'+record_id)[0], 404)


if __name__ == '__main__':
    unittest.main()
