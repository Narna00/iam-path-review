import json
from pathlib import Path
from datetime import date
import unittest
from iam_paths import review


class PathTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(Path(__file__).with_name('iam.example.json').read_text())

    def findings(self):
        return review(self.data, date(2026, 10, 20))['findings']

    def test_transitive_witness(self):
        result = self.findings()[0]
        self.assertEqual(result['witnesses']['payment:approve'], ['user:analyst', 'group:finance', 'group:approvers'])
        self.assertEqual(result['status'], 'open')

    def test_cycle_terminates(self):
        self.data['memberships'].append({'member': 'group:approvers', 'group': 'group:finance'})
        self.assertEqual(len(self.findings()), 1)

    def test_different_resources_not_combined(self):
        self.data['grants'][1]['resource'] = 'ledger:development'
        self.assertEqual(self.findings(), [])

    def test_exception_expiry(self):
        self.data['exceptions'] = [{'principal': 'user:analyst', 'rule': 'SOD-PAYMENT', 'resource': 'ledger:production', 'approved_by': 'Risk owner', 'reason': 'Temporary cover', 'expires_on': '2026-10-20'}]
        self.assertEqual(self.findings()[0]['status'], 'accepted_exception')
        self.data['exceptions'][0]['expires_on'] = '2026-10-19'
        self.assertTrue(self.findings()[0]['exception_expired'])

    def test_unknown_membership_fails(self):
        self.data['memberships'][0]['group'] = 'missing'
        with self.assertRaises(ValueError):
            self.findings()


if __name__ == '__main__':
    unittest.main()
