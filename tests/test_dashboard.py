import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dashboard


class InputTests(unittest.TestCase):
    def test_validation_and_deduplication(self):
        addresses, skipped = dashboard.parse_ips('\ufeff1.1.1.1\n1.1.1.1 # duplicate\n8.8.8.8\n127.0.0.1\n::1\ninvalid')
        self.assertEqual(addresses, ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(len(skipped), 3)

    def test_empty_input_and_wrong_types(self):
        for value in ('# nothing', '192.168.0.1', None, []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dashboard.parse_ips(value)

    def test_batch_limit(self):
        value = '\n'.join(f'11.0.{n // 256}.{n % 256}' for n in range(501))
        with self.assertRaises(ValueError):
            dashboard.parse_ips(value)

    def test_configuration_exposes_no_values_or_executes_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / '.secrets'
            marker = base / 'must-not-exist'
            config.write_text("IPINFO_KEY='private-sentinel'\nIP2_KEY=''\nPROXY_KEY='test'\nSPAMHAUS_KEY='test'\n" + f'touch {marker}\n')
            with patch.dict(os.environ, IP_CHECKER_SECRETS=str(config)):
                result = dashboard.configuration()
            self.assertNotIn('private-sentinel', json.dumps(result))
            self.assertFalse(marker.exists())
            self.assertFalse(result['ready'])

    def test_spreadsheet_formulas_are_escaped(self):
        for value in ('=1+1', '+cmd', '-cmd', '@SUM(1)', '  =1'):
            self.assertTrue(dashboard.safe_cell(value).startswith("'"))
        self.assertEqual(dashboard.safe_cell('AS123 Provider'), 'AS123 Provider')

    def test_ipqs_is_optional_and_key_is_not_exposed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / '.secrets'
            config.write_text("IPINFO_KEY='test'\nIP2_KEY='test'\nPROXY_KEY='test'\nSPAMHAUS_KEY='test'\n")
            with patch.dict(os.environ, IP_CHECKER_SECRETS=str(config)), patch.object(dashboard.shutil, 'which', return_value='/bin/mock'):
                result = dashboard.configuration()
                self.assertTrue(result['ready'])
                ipqs = next(p for p in result['providers'] if p['name'] == 'IPQS')
                self.assertFalse(ipqs['required'])
                self.assertFalse(ipqs['configured'])
                with config.open('a') as handle:
                    handle.write("IPQS_KEY='private-ipqs-sentinel'\nKICKBOX_KEY='private-kickbox-sentinel'\n")
                result = dashboard.configuration()
                self.assertTrue(next(p for p in result['providers'] if p['name'] == 'IPQS')['configured'])
                self.assertNotIn('private-ipqs-sentinel', json.dumps(result))
                kickbox=next(p for p in result['providers'] if p['name']=='Kickbox')
                self.assertTrue(kickbox['configured'])
                self.assertFalse(kickbox['required'])
                self.assertTrue(result['ready'])
                self.assertNotIn('private-kickbox-sentinel',json.dumps(result))


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = dashboard.Database(Path(self.tmp.name) / 'test.sqlite3')
        self.user_id = self.db.create_user('tester', 'testing password for dashboard', 'admin', must_change=False)
        self.db_patch = patch.object(dashboard, 'DB', self.db)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.token, _ = self.db.login('tester', 'testing password for dashboard', '127.0.0.1')
        self.csrf = self.db.session(self.token)['csrf']
        self.store = dashboard.ScanStore()
        self.store_patch = patch.object(dashboard, 'STORE', self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)
        self.server = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, data=None, headers=None):
        request = Request(self.url + path, data=json.dumps(data).encode() if data is not None else None,
                          headers={'Content-Type': 'application/json', 'Cookie': 'ipchecker_session='+self.token, 'X-CSRF-Token': self.csrf, **(headers or {})})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers
        except HTTPError as response:
            return response.code, response.read(), response.headers

    def test_each_page_refresh_emits_a_redacted_access_event(self):
        with patch('builtins.print') as output:
            self.assertEqual(self.request('/login?token=private-first')[0], 200)
            self.assertEqual(self.request('/login?token=private-second')[0], 200)
        events = [json.loads(call.args[0]) for call in output.call_args_list]
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event['path'] == '/login' and event['status'] == 200 for event in events))
        self.assertNotIn('private-', json.dumps(events))
    def test_home_and_secrets_are_not_served(self):
        status, body, headers = self.request('/')
        self.assertEqual(status, 200)
        self.assertIn(b'IP intelligence', body)
        self.assertIn("default-src 'self'", headers['Content-Security-Policy'])
        for path in ('/.secrets', '/../.secrets', '/dashboard.py'):
            self.assertEqual(self.request(path)[0], 404)

    def test_cross_origin_and_unknown_host_are_rejected(self):
        status, _, _ = self.request('/api/scans', {'ips': '1.1.1.1'}, {'Origin': 'https://evil.example'})
        self.assertEqual(status, 403)
        self.assertEqual(self.request('/', headers={'Host': 'evil.example'})[0], 403)

    def test_invalid_input_is_rejected(self):
        self.assertEqual(self.request('/api/scans', {'ips': 'not-an-ip'})[0], 400)

    def test_missing_setup_blocks_scan(self):
        with patch.object(dashboard, 'configuration', return_value={'ready': False}):
            self.assertEqual(self.request('/api/scans', {'ips': '1.1.1.1'})[0], 409)

    def test_scan_start_progress_and_csv(self):
        def fake_run(scan_id, addresses):
            with self.store.lock:
                scan = self.store.scans[scan_id]
                scan.update(status='complete', completed=1, rows=[{'IP Address': addresses[0], 'Provider': '=bad()'}])
                self.store.active = None
                self.store.persist(scan_id)
        with patch.object(dashboard, 'configuration', return_value={'ready': True}), patch.object(self.store, 'run', side_effect=fake_run):
            status, body, _ = self.request('/api/scans', {'ips': '1.1.1.1'})
            self.assertEqual(status, 202)
            scan_id = json.loads(body)['id']
            status, body, _ = self.request('/api/scans/' + scan_id)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['completed'], 1)
            status, body, headers = self.request('/api/scans/' + scan_id + '/csv')
            self.assertEqual(status, 200)
            self.assertIn(b"'=bad()", body)
            self.assertIn('attachment', headers['Content-Disposition'])

    def test_unknown_scan_returns_404(self):
        self.assertEqual(self.request('/api/scans/'+'a'*32)[0], 404)

    def test_email_lookup_only_requires_ipqs_and_returns_no_key(self):
        with patch.object(dashboard, 'secret_values', return_value={'IPQS_KEY': 'secret-key-sentinel'}), patch.object(dashboard.email_lookup, 'lookup', return_value={'Email Address': 'test@example.com', 'Valid': 'YES'}) as lookup:
            status, body, _ = self.request('/api/email', {'email': 'test@example.com'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['report']['Valid'], 'YES')
        self.assertNotIn(b'secret-key-sentinel', body)
        lookup.assert_called_once_with('test@example.com', 'secret-key-sentinel')

    def test_email_missing_key_invalid_input_and_cross_origin(self):
        with patch.object(dashboard, 'secret_values', return_value={}):
            self.assertEqual(self.request('/api/email', {'email': 'test@example.com'})[0], 409)
        self.assertEqual(self.request('/api/email', {'email': 'invalid'})[0], 400)
        self.assertEqual(self.request('/api/email', {'email': 'test@example.com'}, {'Origin': 'https://evil.example'})[0], 403)

    def test_kickbox_email_works_without_ip_scan_or_ipqs_keys(self):
        with patch.object(dashboard,'secret_values',return_value={'KICKBOX_KEY':'private-kickbox-sentinel'}), patch.object(dashboard.email_lookup,'lookup_kickbox',return_value={'Kickbox Result':'deliverable','Kickbox Sendex':'0.9','Kickbox Lookup Health':'OK'}) as lookup:
            status,body,_=self.request('/api/email',{'email':'test@example.com','provider':'kickbox'})
        self.assertEqual(status,200)
        result=json.loads(body)
        self.assertEqual(result['report']['Provider'],'Kickbox')
        self.assertEqual(result['report']['Kickbox Sendex'],'0.9')
        self.assertIn('history_id',result)
        self.assertNotIn(b'private-kickbox-sentinel',body)
        lookup.assert_called_once_with('test@example.com','private-kickbox-sentinel')

    def test_email_invalid_provider_and_explicit_missing_key(self):
        with patch.object(dashboard,'secret_values',return_value={'KICKBOX_KEY':'test'}):
            self.assertEqual(self.request('/api/email',{'email':'test@example.com','provider':'ipqs'})[0],409)
            self.assertEqual(self.request('/api/email',{'email':'test@example.com','provider':'invalid'})[0],400)

    def test_email_provider_failure_is_reported(self):
        with patch.object(dashboard, 'secret_values', return_value={'IPQS_KEY': 'test'}), patch.object(dashboard.email_lookup, 'lookup', side_effect=dashboard.email_lookup.LookupError('IPQS denied email API access.')):
            status, body, _ = self.request('/api/email', {'email': 'test@example.com'})
        self.assertEqual(status, 502)
        self.assertIn(b'denied email API access', body)

    def test_domain_lookup_needs_no_secrets(self):
        result = {'report': {'Domain': 'example.com', 'Registration Lookup': 'OK'}, 'records': [], 'queries': [], 'health': 'OK'}
        with patch.object(dashboard, 'secret_values', return_value={}), patch.object(dashboard.domain_lookup, 'lookup', return_value=result) as lookup:
            status, body, _ = self.request('/api/domain', {'domain': 'EXAMPLE.COM'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['report']['Domain'], 'example.com')
        lookup.assert_called_once_with('example.com', None)

    def test_domain_key_stays_on_server(self):
        result = {'report': {'Domain': 'example.com'}, 'records': [], 'queries': [], 'health': 'OK', 'reputation': []}
        with patch.object(dashboard, 'secret_values', return_value={'SPAMHAUS_KEY': 'private-sentinel'}), patch.object(dashboard.domain_lookup, 'lookup', return_value=result) as lookup:
            status, body, _ = self.request('/api/domain', {'domain': 'example.com'})
        self.assertEqual(status, 200)
        self.assertNotIn(b'private-sentinel', body)
        lookup.assert_called_once_with('example.com', 'private-sentinel')

    def test_invalid_and_cross_origin_domain_requests_are_rejected(self):
        self.assertEqual(self.request('/api/domain', {'domain': '127.0.0.1'})[0], 400)
        self.assertEqual(self.request('/api/domain', {'domain': 'example.com'}, {'Origin': 'https://evil.example'})[0], 403)



class AccessLogTests(unittest.TestCase):
    def event(self, path, method='GET', status=200):
        handler = dashboard.Handler.__new__(dashboard.Handler)
        handler.path = path
        handler.command = method
        handler.client_address = ('127.0.0.1', 12345)
        with patch('builtins.print') as output:
            handler.log_request(status)
        output.assert_called_once()
        self.assertTrue(output.call_args.kwargs['flush'])
        return json.loads(output.call_args.args[0])

    def test_access_event_excludes_queries_and_request_secrets(self):
        event = self.event('/api/history?q=private-email&token=private-token')
        self.assertEqual(event['event'], 'http_access')
        self.assertEqual(event['path'], '/api/history')
        self.assertEqual(event['status'], 200)
        self.assertNotIn('private-', json.dumps(event))

    def test_identifiers_and_unknown_paths_are_redacted(self):
        self.assertEqual(self.event('/api/scans/'+'a'*32+'/csv')['path'], '/api/scans/{id}/csv')
        self.assertEqual(self.event('/api/admin/users/42')['path'], '/api/admin/users/{id}')
        self.assertEqual(self.event('/private-token-here')['path'], '[unmatched]')
        self.assertEqual(self.event('/private-token-here', 'private-method')['method'], 'OTHER')
        self.assertEqual(self.event('/login', status=403)['status'], 403)

    def test_raw_server_log_messages_remain_suppressed(self):
        handler = dashboard.Handler.__new__(dashboard.Handler)
        with patch('builtins.print') as output:
            handler.log_message('private token %s', 'not-for-logs')
        output.assert_not_called()


class ForwardedAddressTests(unittest.TestCase):
    def client(self, peer, forwarded=None, trusted=''):
        handler = dashboard.Handler.__new__(dashboard.Handler)
        handler.client_address = (peer, 12345)
        handler.headers = {} if forwarded is None else {'X-Forwarded-For': forwarded}
        with patch.dict(os.environ, IP_CHECKER_TRUSTED_PROXIES=trusted):
            return handler.forwarded_client_ip()

    def test_untrusted_peers_cannot_spoof_the_client(self):
        self.assertEqual(self.client('192.0.2.10', '198.51.100.5'), '192.0.2.10')
        self.assertEqual(self.client('192.0.2.10', '198.51.100.5', '203.0.113.10'), '192.0.2.10')
        self.assertEqual(self.client('192.0.2.10', '198.51.100.5', 'not-a-network'), '192.0.2.10')

    def test_trusted_nginx_proxy_manager_resolves_the_rightmost_client(self):
        self.assertEqual(self.client('192.0.2.10', '198.51.100.5', '192.0.2.10/32'), '198.51.100.5')
        self.assertEqual(self.client('192.0.2.10', '198.51.100.99, 198.51.100.5', '192.0.2.10/32'), '198.51.100.5')

        self.assertEqual(self.client('192.0.2.10', 'garbage, 198.51.100.5', '192.0.2.10/32'), '198.51.100.5')

    def test_multiple_proxy_hops_and_ipv6(self):
        self.assertEqual(self.client('192.0.2.10', '198.51.100.5, 203.0.113.9', '192.0.2.10,203.0.113.0/24'), '198.51.100.5')
        self.assertEqual(self.client('2001:db8::10', '2001:db8:1::7', '2001:db8::10/128'), '2001:db8:1::7')
        self.assertEqual(self.client('::ffff:192.0.2.10', '198.51.100.5', '192.0.2.10'), '198.51.100.5')

    def test_missing_malformed_and_oversized_headers_fail_closed(self):
        for value in (None, '', 'unknown', '198.51.100.5, garbage', '198.51.100.5,', 'x'*2049, ','.join(['198.51.100.5']*33), 'fe80::1%scope'):
            with self.subTest(value=value):
                self.assertEqual(self.client('192.0.2.10', value, '192.0.2.10'), '192.0.2.10')
if __name__ == '__main__':
    unittest.main()
