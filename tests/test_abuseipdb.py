import unittest
from provider_data import abuse_fields, enrich, REPORT_COLUMNS, PRE_ABUSE_COLUMNS


class AbuseIPDBTests(unittest.TestCase):
    def payload(self, **changes):
        entry=dict(ipAddress='1.1.1.1',abuseConfidenceScore=0,totalReports=0,numDistinctUsers=0,lastReportedAt=None,isWhitelisted=False)
        entry.update(changes)
        return {'data':entry}

    def test_zero_false_and_no_reports_are_preserved(self):
        report=abuse_fields(self.payload(),'1.1.1.1')
        self.assertEqual(report['AbuseIPDB Status'],'OK')
        self.assertEqual(report['AbuseIPDB Confidence'],'0')
        self.assertEqual(report['AbuseIPDB Total Reports'],'0')
        self.assertEqual(report['AbuseIPDB Last Reported'],'NONE')
        self.assertEqual(report['AbuseIPDB Whitelisted'],'NO')
        self.assertEqual(report['AbuseIPDB Lookback Days'],'30')

    def test_missing_key_is_distinct_from_invalid_response(self):
        self.assertEqual(abuse_fields(None,'1.1.1.1')['AbuseIPDB Status'],'NOT_CONFIGURED')
        for data in ({},[],False,{'data':[]},{'data':{}}):
            self.assertEqual(abuse_fields(data,'1.1.1.1')['AbuseIPDB Status'],'INVALID_RESPONSE')

    def test_error_statuses_do_not_expose_provider_text_or_become_zero(self):
        for code,expected in [(401,'AUTH_ERROR'),(403,'ACCESS_DENIED'),(429,'RATE_LIMIT_OR_QUOTA'),(500,'HTTP_500')]:
            report=abuse_fields({'_http_status':code,'errors':[{'detail':'private-sentinel'}]},'1.1.1.1')
            self.assertEqual(report['AbuseIPDB Status'],expected)
            self.assertEqual(report['AbuseIPDB Confidence'],'UNKNOWN')
            self.assertNotIn('private-sentinel',str(report))

    def test_mismatched_ip_cannot_supply_scores(self):
        report=abuse_fields(self.payload(ipAddress='8.8.8.8',abuseConfidenceScore=100),'1.1.1.1')
        self.assertEqual(report['AbuseIPDB Status'],'INVALID_RESPONSE')
        self.assertEqual(report['AbuseIPDB Confidence'],'UNKNOWN')

    def test_missing_or_invalid_core_values_are_partial(self):
        for value in (True,-1,101,'50',None,[],float('nan')):
            report=abuse_fields(self.payload(abuseConfidenceScore=value),'1.1.1.1')
            self.assertEqual(report['AbuseIPDB Status'],'PARTIAL')
            self.assertEqual(report['AbuseIPDB Confidence'],'UNKNOWN')
        report=abuse_fields(self.payload(totalReports=3,lastReportedAt='private-sentinel'),'1.1.1.1')
        self.assertEqual(report['AbuseIPDB Last Reported'],'UNKNOWN')
        self.assertNotIn('private-sentinel',str(report))

    def test_reports_add_review_flag_without_changing_other_models(self):
        data=self.payload(abuseConfidenceScore=80,totalReports=12,numDistinctUsers=3,lastReportedAt='2026-01-01T12:00:00Z')
        result=enrich({}, {}, {}, {}, {}, '1.1.1.1',abuse=data)
        self.assertIn('ABUSEIPDB_REPORTS',result['Score Review'])
        self.assertEqual(result['AbuseIPDB Last Reported'],'2026-01-01T12:00:00+00:00')
        self.assertEqual(result['PC Risk'],'UNKNOWN')
        self.assertNotIn('reports',result)

    def test_history_schema_preserves_previous_columns(self):
        self.assertEqual(len(REPORT_COLUMNS),69)
        self.assertEqual(REPORT_COLUMNS[:61],PRE_ABUSE_COLUMNS)

    def test_failed_abuse_check_keeps_other_positive_detections(self):
        result=enrich({}, {}, {}, {'status':'ok','1.1.1.1':{'detections':{'risk':95}}}, {}, '1.1.1.1',abuse={'_http_status':429})
        self.assertEqual(result['Lookup Health'],'PARTIAL')
        self.assertEqual(result['PC Risk'],'95')
        self.assertIn('PC_HIGH_RISK',result['Score Review'])
