import csv
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import time
from unittest.mock import patch

import dashboard


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'ip-checker.sh'


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.script = self.base / 'ip-checker.sh'
        shutil.copyfile(SCRIPT, self.script)
        (self.base / '.secrets').write_text(
            "IPINFO_KEY='test'\nIP2_KEY='test'\nPROXY_KEY='test'\nSPAMHAUS_KEY='test'\n"
        )
        self.input = self.base / 'ip-addresses.txt'
        self.input.write_text('1.1.1.1\n1.1.1.1 # duplicate\n127.0.0.1\ninvalid\n::1\n')
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.stub('curl', '''#!/usr/bin/env bash
case "$*" in
  *rdap*) echo '{"cidr0_cidrs":[{"v4prefix":"1.1.1.0","length":24}]}' ;;
  *ipinfo*) echo '{"org":"AS13335 Example Provider"}' ;;
  *ip2location*) echo '{"is_proxy":false}' ;;
  *ipqualityscore*)
    case ${MOCK_IPQS:-negative} in
      error) echo '{"success":false,"message":"Invalid key"}' ;;
      malformed) echo 'not json' ;;
      missing) echo '{"success":true}' ;;
      positive) echo '{"success":true,"fraud_score":95,"proxy":true,"vpn":true,"tor":true,"recent_abuse":true,"bot_status":true}' ;;
      *) echo '{"success":true,"fraud_score":0,"proxy":false,"vpn":false,"tor":false,"recent_abuse":false,"bot_status":false}' ;;
    esac ;;
  *proxycheck*)
    if [[ ${MOCK_PC:-ok} == error ]]; then echo '{"status":"error"}'; else
      echo '{"status":"ok","1.1.1.1":{"detections":{"anonymous":false,"vpn":false,"proxy":false,"tor":false,"risk":0,"confidence":0},"network":{"type":"residential"}}}'
    fi ;;
  *) exit 99 ;;
esac
''')
        self.stub('dig', '''#!/usr/bin/env bash
case ${MOCK_DNS:-negative} in
  negative) echo ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1' ;;
  failure) echo ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1' ;;
  pbl) printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nquery. 60 IN A 127.0.0.10\n' ;;
  threat) printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nquery. 60 IN A 127.0.0.2\n' ;;
  query_error) printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nquery. 60 IN A 127.255.255.254\n' ;;
esac
''')
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'])
        for key in ('IP_CHECKER_SECRETS', 'MOCK_PC', 'MOCK_DNS', 'MOCK_IPQS', 'IPQS_KEY'):
            self.env.pop(key, None)

    def stub(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def run_checker(self, *args, **env):
        return subprocess.run(['bash', str(self.script), *map(str, args)],
                              cwd=self.base.parent, env=dict(self.env, **env),
                              text=True, capture_output=True, timeout=20)

    def row(self, **env):
        result = self.run_checker(**env)
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.base / 'ip-results.csv').open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]), 26)
        self.assertIn('Skipping invalid/non-public IP', result.stderr)
        return rows[0]

    def test_explicit_false_remains_negative(self):
        row = self.row()
        self.assertEqual(row['PC VPN'], 'NO')
        self.assertEqual(row['IP2 Proxy'], 'NO')
        self.assertEqual(row['Anonymisation'], 'NO')
        self.assertEqual(row['Review'], 'NO_POSITIVE_DETECTION')
        self.assertEqual(row['CIDR'], '1.1.1.0/24')
        self.assertEqual(row['IPQS Status'], 'NOT_CONFIGURED')

    def enable_ipqs(self):
        with (self.base / '.secrets').open('a') as handle:
            handle.write("IPQS_KEY='test-ipqs'\n")

    def test_ipqs_zero_and_false_are_preserved(self):
        self.enable_ipqs()
        row = self.row()
        self.assertEqual(row['IPQS Status'], 'OK')
        self.assertEqual(row['IPQS Fraud Score'], '0')
        self.assertEqual(row['IPQS Proxy'], 'NO')
        self.assertEqual(row['Review'], 'NO_POSITIVE_DETECTION')

    def test_ipqs_detections_contribute_to_review(self):
        self.enable_ipqs()
        row = self.row(MOCK_IPQS='positive')
        self.assertEqual(row['Anonymisation'], 'YES')
        self.assertEqual(row['IPQS Fraud Score'], '95')
        for flag in ('VPN', 'TOR', 'PROXY', 'IPQS_RECENT_ABUSE', 'IPQS_BOT'):
            self.assertIn(flag, row['Review'])
        self.assertEqual(row['Threat Listing'], 'NO')

    def test_ipqs_errors_never_become_negative(self):
        self.enable_ipqs()
        for state in ('error', 'malformed'):
            with self.subTest(state=state):
                row = self.row(MOCK_IPQS=state)
                self.assertEqual(row['IPQS Status'], 'ERROR')
                self.assertEqual(row['IPQS Fraud Score'], 'UNKNOWN')
                self.assertEqual(row['Anonymisation'], 'UNKNOWN')
                self.assertEqual(row['Review'], 'INCOMPLETE')

    def test_ipqs_missing_fields_remain_unknown(self):
        self.enable_ipqs()
        row = self.row(MOCK_IPQS='missing')
        self.assertEqual(row['IPQS Proxy'], 'UNKNOWN')
        self.assertEqual(row['Review'], 'INCOMPLETE')

    def test_partial_provider_failure_is_incomplete(self):
        row = self.row(MOCK_PC='error')
        self.assertEqual(row['IP2 Proxy'], 'NO')
        self.assertEqual(row['Anonymisation'], 'UNKNOWN')
        self.assertEqual(row['Review'], 'INCOMPLETE')

    def test_dns_failure_and_query_error_stay_unknown(self):
        for state in ('failure', 'query_error'):
            with self.subTest(state=state):
                row = self.row(MOCK_DNS=state)
                self.assertEqual(row['Spamhaus Status'], 'UNKNOWN')
                self.assertEqual(row['Threat Listing'], 'UNKNOWN')

    def test_pbl_is_not_threat(self):
        row = self.row(MOCK_DNS='pbl')
        self.assertEqual(row['Spamhaus Lists'], 'PBL')
        self.assertEqual(row['Threat Listing'], 'NO')

    def test_sbl_is_threat(self):
        row = self.row(MOCK_DNS='threat')
        self.assertEqual(row['Threat Listing'], 'YES')
        self.assertEqual(row['Review'], 'SPAMHAUS_THREAT')

    def test_missing_secrets_fails_before_output(self):
        (self.base / '.secrets').unlink()
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing secrets file', result.stderr)
        self.assertFalse((self.base / 'ip-results.csv').exists())

    def test_empty_key_fails_without_echoing_keys(self):
        (self.base / '.secrets').write_text("IPINFO_KEY='private-sentinel'\nIP2_KEY=''\n")
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing key', result.stderr)
        self.assertNotIn('private-sentinel', result.stdout + result.stderr)

    def test_output_cannot_overwrite_input_or_secrets(self):
        for target in (self.input, self.base / '.secrets'):
            with self.subTest(target=target.name):
                before = target.read_bytes()
                result = self.run_checker(self.input, target)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), before)

    def test_dashboard_worker_runs_checker_and_reads_csv(self):
        store = dashboard.ScanStore()
        with patch.object(dashboard, 'ROOT', self.base), patch.dict(os.environ, self.env, clear=True):
            scan_id = store.create(['1.1.1.1'], [])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                scan = store.snapshot(scan_id)
                if scan['status'] != 'running':
                    break
                time.sleep(0.1)
        self.assertEqual(scan['status'], 'complete', scan)
        self.assertEqual(scan['completed'], 1)
        self.assertEqual(scan['rows'][0]['Review'], 'NO_POSITIVE_DETECTION')


if __name__ == '__main__':
    unittest.main()
