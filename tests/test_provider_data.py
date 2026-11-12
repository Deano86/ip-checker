import unittest
from provider_data import enrich, status, geolocation, rdap_fields, REPORT_COLUMNS, LEGACY_COLUMNS


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


class ReportAccuracyTests(unittest.TestCase):
    def test_appended_schema_keeps_legacy_order(self):
        self.assertEqual(len(REPORT_COLUMNS), 69)
        self.assertEqual(REPORT_COLUMNS[:40], LEGACY_COLUMNS)
        self.assertEqual(len(set(REPORT_COLUMNS)), len(REPORT_COLUMNS))

    def test_location_uses_one_successful_source_and_preserves_zero(self):
        result = geolocation({'org':'AS1 Other','country':'US','city':'Other city'},
                             {'country_code':'GB','country_name':'United Kingdom','city_name':'London','latitude':0,'longitude':0}, {})
        self.assertEqual(result['Geolocation Source'], 'IP2Location')
        self.assertEqual(result['City'], 'London')
        self.assertEqual(result['Latitude'], '0')
        self.assertEqual(result['Country Code'], 'GB')

    def test_failed_location_data_and_out_of_range_coordinates_are_not_used(self):
        result = geolocation({'country':'GB','city':'Example','loc':'200,-999'},
                             {'_http_status':401,'country_code':'US','city_name':'Untrusted'}, {})
        self.assertEqual(result['Geolocation Source'], 'IPinfo')
        self.assertEqual(result['City'], 'Example')
        self.assertEqual(result['Latitude'], 'UNKNOWN')
        self.assertEqual(result['Longitude'], 'UNKNOWN')

    def test_rdap_range_and_dates_are_separate_from_location(self):
        result = rdap_fields({'startAddress':'1.1.1.0','endAddress':'1.1.1.255','name':'Example allocation','country':'AU','handle':'EXAMPLE',
                              'events':[{'eventAction':'registration','eventDate':'2000-01-01T00:00:00Z'}]}, '1.1.1.1')
        self.assertEqual(result['CIDR'], '1.1.1.0/24')
        self.assertEqual(result['Network Country'], 'AU')
        self.assertEqual(result['Network Registered'], '2000-01-01T00:00:00Z')
        self.assertEqual(result['RDAP Status'], 'OK')
        invalid = rdap_fields({'startAddress':'2.2.2.0','endAddress':'2.2.2.255','name':'Wrong allocation'}, '1.1.1.1')
        self.assertEqual(invalid['CIDR'], 'UNKNOWN')
        self.assertEqual(invalid['RDAP Status'], 'INVALID_NETWORK_RESPONSE')

    def test_score_only_high_risk_is_not_a_no_detection_verdict(self):
        pc = {'status':'ok','1.1.1.1':{'detections':{'risk':95,'confidence':0}}}
        result = enrich({}, {}, {}, pc, {'success':True,'fraud_score':95}, '1.1.1.1')
        self.assertEqual(result['Score Review'], 'IPQS_HIGH_RISK+PC_HIGH_RISK')
        self.assertEqual(result['PC Confidence'], '0')
        pc['1.1.1.1']['detections']['risk'] = 999
        result = enrich({}, {}, {}, pc, {'success':True,'fraud_score':0}, '1.1.1.1')
        self.assertEqual(result['PC Risk'], 'UNKNOWN')
        self.assertEqual(result['Score Review'], '')


if __name__ == '__main__':
    unittest.main()
