import json
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import spamhaus_domain as sh
import domain_lookup


def answer(status='NOERROR', codes=()):
    return f';; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n' + ''.join(f'example.test.private-sentinel.dbl.dq.spamhaus.net. 60 IN A {code}\n' for code in codes)


class SpamhausDomainTests(unittest.TestCase):
    def test_negative_requires_nxdomain(self):
        self.assertEqual(sh.parse_dns('dbl', answer('NXDOMAIN'))['listed'], 'NO')
        self.assertEqual(sh.parse_dns('dbl', answer())['listed'], 'UNKNOWN')
        self.assertEqual(sh.parse_dns('dbl', answer('SERVFAIL'))['status'], 'SERVFAIL')

    def test_dbl_categories_and_multiple_answers(self):
        result = sh.parse_dns('dbl', answer(codes=['127.0.1.4', '127.0.1.105']))
        self.assertEqual(result['listed'], 'YES')
        self.assertIn('Phishing-related domain', result['categories'])
        self.assertIn('Abused domain used by malware', result['categories'])
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_zrd_is_domain_age_information(self):
        result = sh.parse_dns('zrd', answer(codes=['127.0.2.2', '127.0.2.24']))
        self.assertEqual(result['listed'], 'YES')
        self.assertIn('First observed 0–2 hours ago', result['categories'])
        self.assertIn('First observed 23–24 hours ago', result['categories'])

    def test_query_errors_and_mixed_replies_never_become_listings(self):
        for code in ('127.255.255.250', '127.255.255.251', '127.255.255.252', '127.255.255.254', '127.0.1.255', '8.8.8.8', '127.0.0.2'):
            with self.subTest(code=code):
                result = sh.parse_dns('dbl', answer(codes=['127.0.1.2', code]))
                self.assertEqual(result['listed'], 'UNKNOWN')

    def test_disabled_or_invalid_key_does_not_query_dns(self):
        with patch.object(sh.subprocess, 'run') as run:
            self.assertEqual(sh.lookup('example.com', None)['status'], 'NOT_CONFIGURED')
            self.assertEqual(sh.lookup('example.com', 'bad key')['status'], 'INVALID_KEY_FORMAT')
            run.assert_not_called()

    def test_query_uses_server_dns_and_never_returns_keyed_name(self):
        with patch.object(sh.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=answer('NXDOMAIN'))) as run:
            result = sh.lookup('example.com', 'private-sentinel')
        self.assertIn('example.com.private-sentinel.dbl.dq.spamhaus.net', run.call_args.args[0])
        self.assertNotIn('private-sentinel', json.dumps(result))
        self.assertEqual(result['listed'], 'NO')

    def test_timeouts_and_missing_dependency_stay_unknown(self):
        for failure, status in ((FileNotFoundError(), 'DEPENDENCY_MISSING'), (subprocess.TimeoutExpired('dig', 5), 'TIMEOUT')):
            with self.subTest(status=status), patch.object(sh.subprocess, 'run', side_effect=failure):
                result = sh.lookup('example.com', 'testkey')
                self.assertEqual(result['status'], status)
                self.assertEqual(result['listed'], 'UNKNOWN')

    def test_domain_report_is_partial_when_enabled_check_fails(self):
        def data(url, accept):
            return ({'ldhName': 'EXAMPLE.COM'}, 'OK') if 'rdap.org' in url else ({'Status': 0}, 'OK')
        with patch.object(domain_lookup, 'get_json', side_effect=data), patch.object(sh, 'lookup', return_value=sh.result('dbl', 'KEY_OR_ACCESS_ERROR')):
            result = domain_lookup.lookup('example.com', 'testkey')
        self.assertEqual(result['health'], 'PARTIAL')
        self.assertEqual(len(result['reputation']), 2)


if __name__ == '__main__':
    unittest.main()
