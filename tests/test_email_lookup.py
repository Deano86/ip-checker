import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
import email_lookup


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
        report = email_lookup.normalise('test@example.com', {'valid': False, 'timed_out': True})
        self.assertEqual(report['Valid'], 'UNKNOWN')
        self.assertEqual(report['Verification Timed Out'], 'YES')

    def test_only_selected_fields_are_returned(self):
        report = email_lookup.normalise('test@example.com', {'valid': True, 'private_key': 'private-sentinel', 'first_name': 'Sensitive', 'message': 'private-sentinel'})
        self.assertNotIn('private-sentinel', json.dumps(report))
        self.assertNotIn('Sensitive', json.dumps(report))

    def test_rejected_or_empty_responses_are_errors(self):
        for value in ({}, [], {'success': False, 'message': 'secret-key-sentinel'}):
            with self.subTest(value=value), self.assertRaises(email_lookup.LookupError) as context:
                email_lookup.normalise('test@example.com', value)
            self.assertNotIn('secret-key-sentinel', str(context.exception))

    def test_post_uses_header_authentication_without_key_in_url(self):
        with patch.object(email_lookup, 'urlopen', return_value=io.BytesIO(b'{"valid":true,"fraud_score":25}')) as request:
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


if __name__ == '__main__':
    unittest.main()
