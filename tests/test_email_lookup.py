import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
import email_lookup
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock


class KickboxTests(unittest.TestCase):
    def payload(self, **changes):
        return dict(success=True, result='deliverable', reason='accepted_email', sendex=0.9,
                    disposable=False, accept_all=False, role=False, free=False, **changes)

    def test_quality_zero_and_false_flags_are_preserved(self):
        data=self.payload(); data['sendex']=0
        report=email_lookup.normalise_kickbox('test@example.com',data)
        self.assertEqual(report['Kickbox Sendex'],'0')
        self.assertEqual(report['Kickbox Disposable'],'NO')
        self.assertEqual(report['Kickbox Lookup Health'],'OK')
        self.assertNotIn('Fraud Score',report)

    def test_unknown_and_accept_all_are_not_invalid_mailboxes(self):
        data=self.payload(); data.update(result='unknown',reason='timeout',accept_all=True)
        report=email_lookup.normalise_kickbox('test@example.com',data)
        self.assertEqual(report['Kickbox Result'],'unknown')
        self.assertEqual(report['Kickbox Lookup Health'],'PARTIAL')
        self.assertIn('individual mailbox cannot be confirmed',report['Kickbox Notes'])
        self.assertNotIn('Valid',report)

    def test_rejected_and_invalid_results_are_errors(self):
        for data in ([],{}, {'success':False,'message':'private-sentinel'}, {'success':True,'result':'private-sentinel'}, {'success':True,'result':[]}):
            with self.subTest(data=data), self.assertRaises(email_lookup.LookupError) as error:
                email_lookup.normalise_kickbox('test@example.com',data)
            self.assertNotIn('private-sentinel',str(error.exception))

    def test_sendex_is_finite_numeric_in_range(self):
        for value in (True, '0.9', -1, 1.1, float('nan'), float('inf'),None):
            data=self.payload(); data['sendex']=value
            report=email_lookup.normalise_kickbox('test@example.com',data)
            self.assertEqual(report['Kickbox Sendex'],'UNKNOWN')
            self.assertEqual(report['Kickbox Lookup Health'],'PARTIAL')

    def test_private_raw_fields_and_unknown_reason_are_not_echoed(self):
        data=self.payload(); data.update(reason='private-sentinel',message='private-sentinel',apikey='private-sentinel',user='private-sentinel')
        report=email_lookup.normalise_kickbox('test@example.com',data)
        self.assertNotIn('private-sentinel',json.dumps(report))

    def test_request_encodes_email_and_authenticates_in_header(self):
        opener=Mock(); opener.open.return_value=io.BytesIO(json.dumps(self.payload()).encode())
        with patch.object(email_lookup,'build_opener',return_value=opener):
            email_lookup.lookup_kickbox('test+tag@example.com','key-sentinel')
        request=opener.open.call_args.args[0]
        self.assertEqual(urlsplit(request.full_url).netloc,'api.kickbox.com')
        self.assertEqual(parse_qs(urlsplit(request.full_url).query)['email'],['test+tag@example.com'])
        self.assertNotIn('key-sentinel',request.full_url)
        self.assertEqual(request.get_header('Authorization'),'token key-sentinel')

    def test_transport_and_http_failures_are_safe(self):
        failures=[HTTPError('https://example.test?apikey=key-sentinel',code,'key-sentinel',{},None) for code in (401,403,429,500)]
        failures += [URLError('key-sentinel'),TimeoutError('key-sentinel'),OSError('key-sentinel')]
        for failure in failures:
            opener=Mock(); opener.open.side_effect=failure
            with self.subTest(failure=failure), patch.object(email_lookup,'build_opener',return_value=opener):
                with self.assertRaises(email_lookup.LookupError) as error:
                    email_lookup.lookup_kickbox('test@example.com','key-sentinel')
                self.assertNotIn('key-sentinel',str(error.exception))

    def test_redirects_are_refused(self):
        with self.assertRaises(URLError):
            email_lookup.NoKickboxRedirects().redirect_request(None,None,302,'',{},'https://evil.example')

    def test_provider_selection_and_missing_keys(self):
        self.assertEqual(email_lookup.selected_providers('configured',{'KICKBOX_KEY':'test'}),['Kickbox'])
        self.assertEqual(email_lookup.selected_providers('configured',{'KICKBOX_KEY':'test','IPQS_KEY':'test'}),['IPQS','Kickbox'])
        self.assertEqual(email_lookup.selected_providers('ipqs',{'KICKBOX_KEY':'test','IPQS_KEY':'test'}),['IPQS'])
        with self.assertRaises(email_lookup.LookupError): email_lookup.selected_providers('both',{'KICKBOX_KEY':'test'})
        with self.assertRaises(ValueError): email_lookup.selected_providers([], {})

    def test_partial_failure_retains_other_provider_and_sources(self):
        with patch.object(email_lookup,'lookup',side_effect=email_lookup.LookupError('IPQS denied access.')), patch.object(email_lookup,'lookup_kickbox',return_value=email_lookup.normalise_kickbox('test@example.com',self.payload())):
            report=email_lookup.lookup_selected('test@example.com',{'IPQS_KEY':'private','KICKBOX_KEY':'private'},['IPQS','Kickbox'])
        self.assertEqual(report['IPQS Status'],'ERROR')
        self.assertEqual(report['Kickbox Result'],'deliverable')
        self.assertEqual(report['Lookup Health'],'PARTIAL')
        self.assertNotIn('private',json.dumps(report))

    def test_all_failed_providers_raise(self):
        with patch.object(email_lookup,'lookup_kickbox',side_effect=email_lookup.LookupError('Kickbox unavailable.')):
            with self.assertRaises(email_lookup.LookupError):
                email_lookup.lookup_selected('test@example.com',{'KICKBOX_KEY':'test'},['Kickbox'])


class EmailTests(unittest.TestCase):
    def test_email_validation(self):
        self.assertEqual(email_lookup.validate_email(' Test+tag@EXAMPLE.COM '), 'Test+tag@example.com')
        for value in (None, '', 'no-email', 'a@@example.com', '.a@example.com', 'a..b@example.com', 'a@localhost', 'a b@example.com', 'a@-bad.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                email_lookup.validate_email(value)

    def test_boolean_false_and_zero_score_are_preserved(self):
        report = email_lookup.normalise('test@example.com', {'success': True, 'valid': False, 'fraud_score': 0, 'disposable': False})
        self.assertEqual(report['Valid'], 'NO')
        self.assertEqual(report['Fraud Score'], '0')
        self.assertEqual(report['Disposable'], 'NO')
        self.assertEqual(report['Recent Abuse'], 'UNKNOWN')

    def test_timed_out_negative_is_not_confirmed_invalid(self):
        report = email_lookup.normalise('test@example.com', {'success': True, 'valid': False, 'timed_out': True})
        self.assertEqual(report['Valid'], 'UNKNOWN')
        self.assertEqual(report['Verification Timed Out'], 'YES')

    def test_only_selected_fields_are_returned(self):
        report = email_lookup.normalise('test@example.com', {'success': True, 'valid': True, 'private_key': 'private-sentinel', 'first_name': 'Sensitive', 'message': 'private-sentinel'})
        self.assertNotIn('private-sentinel', json.dumps(report))
        self.assertNotIn('Sensitive', json.dumps(report))

    def test_rejected_or_empty_responses_are_errors(self):
        for value in ({}, [], {'success': False, 'message': 'secret-key-sentinel'}):
            with self.subTest(value=value), self.assertRaises(email_lookup.LookupError) as context:
                email_lookup.normalise('test@example.com', value)
            self.assertNotIn('secret-key-sentinel', str(context.exception))

    def test_post_uses_header_authentication_without_key_in_url(self):
        with patch.object(email_lookup, 'urlopen', return_value=io.BytesIO(b'{"success":true,"valid":true,"fraud_score":25}')) as request:
            report = email_lookup.lookup('test@example.com', 'secret-key-sentinel')
        actual = request.call_args.args[0]
        self.assertEqual(actual.get_method(), 'POST')
        self.assertNotIn('secret-key-sentinel', actual.full_url)
        self.assertEqual(actual.get_header('Ipqs-key'), 'secret-key-sentinel')
        self.assertEqual(json.loads(actual.data)['email'], 'test@example.com')
        self.assertEqual(report['Fraud Score'], '25')

    def test_failures_never_echo_provider_text(self):
        failures = [HTTPError('https://example.test', 401, 'secret-key-sentinel', {}, None),
                    HTTPError('https://example.test', 403, 'secret-key-sentinel', {}, None),
                    HTTPError('https://example.test', 429, 'secret-key-sentinel', {}, None),
                    URLError('secret-key-sentinel'), TimeoutError('secret-key-sentinel')]
        for failure in failures:
            with self.subTest(failure=failure), patch.object(email_lookup, 'urlopen', side_effect=failure):
                with self.assertRaises(email_lookup.LookupError) as context:
                    email_lookup.lookup('test@example.com', 'secret-key-sentinel')
                self.assertNotIn('secret-key-sentinel', str(context.exception))


class EmailReportAccuracyTests(unittest.TestCase):
    def test_missing_success_flag_is_not_a_verified_provider_response(self):
        with self.assertRaises(email_lookup.LookupError):
            email_lookup.normalise('test@example.com', {'valid':True,'fraud_score':0})

    def test_missing_fields_and_catch_all_are_explained(self):
        report=email_lookup.normalise('test@example.com', {'success':True,'valid':True,'catch_all':True,'fraud_score':0})
        self.assertEqual(report['Lookup Health'], 'PARTIAL')
        self.assertIn('individual mailbox cannot be confirmed', report['Lookup Notes'])
        self.assertEqual(report['Fraud Score'], '0')

    def test_score_risk_and_provider_errors_remain_separate(self):
        report=email_lookup.normalise('test@example.com', {'success':True,'valid':True,'disposable':False,'deliverability':'high','fraud_score':95})
        self.assertEqual(report['Lookup Health'], 'OK')
        self.assertIn('High IPQS email fraud score', report['Review'])
        self.assertIn('not a delivery probability', report['Score Source'])


if __name__ == '__main__':
    unittest.main()
