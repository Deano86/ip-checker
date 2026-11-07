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
                    handle.write("IPQS_KEY='private-ipqs-sentinel'\n")
                result = dashboard.configuration()
                self.assertTrue(next(p for p in result['providers'] if p['name'] == 'IPQS')['configured'])
                self.assertNotIn('private-ipqs-sentinel', json.dumps(result))


class HTTPTests(unittest.TestCase):
    def setUp(self):
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
                          headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers
        except HTTPError as response:
            return response.code, response.read(), response.headers

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

    def test_email_provider_failure_is_reported(self):
        with patch.object(dashboard, 'secret_values', return_value={'IPQS_KEY': 'test'}), patch.object(dashboard.email_lookup, 'lookup', side_effect=dashboard.email_lookup.LookupError('IPQS denied email API access.')):
            status, body, _ = self.request('/api/email', {'email': 'test@example.com'})
        self.assertEqual(status, 502)
        self.assertIn(b'denied email API access', body)


if __name__ == '__main__':
    unittest.main()
