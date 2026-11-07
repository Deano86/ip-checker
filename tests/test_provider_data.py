import unittest
from provider_data import enrich, status


class ProviderDataTests(unittest.TestCase):
    def test_ipqs_fallback_normalises_numeric_asn(self):
        result = enrich({}, {}, {}, {}, {'success': True, 'ASN': 24940, 'ISP': 'Example host'}, '1.1.1.1')
        self.assertEqual(result['ASN'], 'AS24940')
        self.assertEqual(result['Provider'], 'Example host')
        self.assertEqual(result['ASN Source'], 'IPQS')
        self.assertEqual(result['Lookup Health'], 'PARTIAL')

    def test_proxycheck_fallback_and_source(self):
        pc = {'status': 'ok', '1.1.1.1': {'network': {'asn': 'AS13335', 'organisation': 'Example network'}}}
        result = enrich({}, {}, {}, pc, {}, '1.1.1.1')
        self.assertEqual(result['Provider'], 'Example network')
        self.assertEqual(result['Provider Source'], 'Proxycheck')

    def test_failed_providers_cannot_supply_fallback_identity(self):
        result = enrich({'_http_status': 401, 'org': 'AS123 Untrusted'}, {}, {}, {},
                        {'success': False, 'ASN': 456, 'ISP': 'Untrusted'}, '1.1.1.1')
        self.assertEqual(result['ASN'], 'UNKNOWN')
        self.assertEqual(result['Provider'], 'UNKNOWN')

    def test_no_raw_error_text_is_exposed(self):
        result = status({'error': {'error_code': 10000, 'error_message': 'private-key-sentinel'}}, 'IP2Location')
        self.assertEqual(result, 'AUTH_OR_QUOTA_ERROR')
        self.assertNotIn('private-key-sentinel', result)

    def test_http_and_transport_errors(self):
        for code, expected in ((401, 'AUTH_ERROR'), (403, 'ACCESS_DENIED'), (429, 'RATE_LIMIT_OR_QUOTA'), (503, 'HTTP_503')):
            self.assertEqual(status({'_http_status': code}, 'IPinfo'), expected)
        self.assertEqual(status({'_lookup_error': 'TIMEOUT'}, 'IPinfo'), 'TIMEOUT')

    def test_empty_values_and_zero_asn_do_not_become_names(self):
        result = enrich({'org': ''}, {}, {'is_proxy': False, 'as': '-'}, {}, {}, '1.1.1.1')
        self.assertEqual(result['Provider'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
