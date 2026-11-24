from contextlib import closing
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vpn_orbit.runtime import authority, diagnostics


class ControllerDiagnosticsTests(unittest.TestCase):
    def test_authority_binding_checks_host_and_policy_without_exposing_either(self):
        with closing(sqlite3.connect(':memory:')) as db, patch.object(
                diagnostics.Policy, 'load', return_value=SimpleNamespace(digest='fixture-policy')), patch.object(
                diagnostics.backup, 'pin_database', return_value=db), patch.object(
                authority, 'host_binding', return_value='fixture-host'):
            db.execute('CREATE TABLE gate(id, policy_digest, host_binding)')
            db.execute("INSERT INTO gate VALUES(1, 'fixture-policy', 'fixture-host')")
            cfg = {'targets': 'unused'}
            self.assertEqual(diagnostics.authority_status(cfg), ('OK', 'AUTHORITY_POLICY_AND_HOST_BOUND'))
            for policy, host in (('wrong-policy', 'fixture-host'), ('fixture-policy', 'wrong-host')):
                with self.subTest(policy=policy, host=host):
                    db.execute('UPDATE gate SET policy_digest=?, host_binding=?', (policy, host))
                    self.assertEqual(diagnostics.authority_status(cfg), ('ERROR', 'AUTHORITY_BINDING_MISMATCH'))

    def test_authority_report_distinguishes_missing_journal(self):
        with patch.object(diagnostics.Policy, 'load'), patch.object(
                diagnostics.backup, 'pin_database', side_effect=FileNotFoundError):
            self.assertEqual(diagnostics.authority_status({'targets': 'unused'}), ('NO_DATA', 'AUTHORITY_STATE_NOT_FOUND'))
