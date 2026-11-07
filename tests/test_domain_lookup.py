import io
import json
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
import domain_lookup


class DomainTests(unittest.TestCase):
    def test_normalises_domains_urls_and_idna(self):
        self.assertEqual(domain_lookup.validate_domain(' EXAMPLE.COM. '), 'example.com')
        self.assertEqual(domain_lookup.validate_domain('https://example.com/path?q=1'), 'example.com')
        self.assertEqual(domain_lookup.validate_domain('bücher.de'), 'xn--bcher-kva.de')

    def test_rejects_non_domain_and_url_credentials(self):
        for value in (None, '', 'localhost', '127.0.0.1', '::1', 'a@example.com', '*.example.com', '-bad.com', 'https://user:pass@example.com', 'file:///etc/passwd'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain_lookup.validate_domain(value)

    def test_registration_parses_fields_and_handles_redaction(self):
        data = {'ldhName': 'EXAMPLE.COM', 'handle': 'EXAMPLE-HANDLE', 'status': ['active'],
                'nameservers': [{'ldhName': 'NS1.EXAMPLE.COM'}], 'secureDNS': {'delegationSigned': True},
                'events': [{'eventAction': 'registration', 'eventDate': '2000-01-01T00:00:00Z'}, {'eventAction': 'expiration', 'eventDate': '2030-01-01T00:00:00Z'}],
                'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Registrar']]]}, {'roles': None}]}
        result = domain_lookup.registration('example.com', data, 'OK')
        self.assertEqual(result['Registrar'], 'Example Registrar')
        self.assertEqual(result['Created'], '2000-01-01T00:00:00Z')
        self.assertEqual(result['DNSSEC Delegation Signed'], 'YES')
        self.assertEqual(result['Registrant Organisation'], 'NOT_PUBLISHED')

    def test_dns_status_distinguishes_absence_from_failures(self):
        for data, state, expected in (({'Status': 0}, 'OK', 'NO_RECORDS'), ({'Status': 3}, 'OK', 'NXDOMAIN'), ({'Status': 2}, 'OK', 'SERVFAIL'), ({}, 'TIMEOUT', 'TIMEOUT')):
            with self.subTest(expected=expected), patch.object(domain_lookup, 'get_json', return_value=(data, state)):
                self.assertEqual(domain_lookup.dns_query('example.com', 'MX')['status'], expected)

    def test_partial_registration_does_not_hide_dns_records(self):
        def fake_get(url, accept):
            if 'rdap.org' in url:
                return {}, 'NOT_FOUND_OR_UNSUPPORTED'
            return {'Status': 0, 'Answer': [{'name': 'example.com.', 'type': 1, 'data': '93.184.215.14', 'TTL': 300}]}, 'OK'
        with patch.object(domain_lookup, 'get_json', side_effect=fake_get):
            result = domain_lookup.lookup('example.com')
        self.assertEqual(result['health'], 'PARTIAL')
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(len(result['queries']), 7)

    def test_http_errors_are_safe_and_not_availability_claims(self):
        opener = MagicMock()
        opener.open.side_effect = HTTPError('https://example.test', 404, 'private-server-detail', {}, None)
        with patch.object(domain_lookup, 'build_opener', return_value=opener):
            data, status = domain_lookup.get_json('https://rdap.org/domain/example.com', 'application/rdap+json')
        self.assertEqual(status, 'NOT_FOUND_OR_UNSUPPORTED')
        self.assertNotIn('private-server-detail', str(data))

    def test_non_public_and_insecure_redirects_are_rejected(self):
        handler = domain_lookup.PublicHTTPSRedirects()
        for url in ('http://example.com/domain/x', 'https://user:pass@example.com/'):
            with self.assertRaises(Exception):
                handler.redirect_request(None, None, 302, '', {}, url)
        with patch.object(domain_lookup.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(Exception):
                handler.redirect_request(None, None, 302, '', {}, 'https://localhost/')


if __name__ == '__main__':
    unittest.main()
