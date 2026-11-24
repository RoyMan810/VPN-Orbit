import copy
import hashlib
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HELPER = Path(__file__).resolve().parents[2] / "remote/firewall-apply"
OP = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
RULES = [{"action": "allow", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"}]


class FirewallHelperTests(unittest.TestCase):
    def setUp(self):
        self.helper = runpy.run_path(str(HELPER))
        self.ns = self.helper["dispatch"].__globals__
        self.saved = None
        self.order = []
        self.table = "previous"
        self.timer = {"kind": "systemd", "unit": "vpn-orbit-firewall-" + OP}
        self.digest = hashlib.sha256(self.helper["canonical"](RULES).encode()).hexdigest()
        self.request = {"operation": "apply", "operation_id": OP, "rules": RULES,
                        "rules_digest": self.digest, "previous_rules_digest": "0" * 64, "ssh_port": 22}
        self.enterContext(patch.dict(self.ns, {
            "open_journal": Mock(return_value=9999),
            "read_journal": lambda *_: copy.deepcopy(self.saved),
            "write_journal": self.save,
            "read_policy": Mock(return_value={"ssh_port": 22, "max_rules": 32, "rollback_seconds": 60}),
            "snapshot": lambda: self.table,
            "other_armed": Mock(return_value=None),
            "baseline_digest": Mock(return_value="0" * 64),
            "apply_table": self.apply,
            "verify_table": Mock(),
            "restore": self.restore,
            "arm_timer": self.arm,
            "cancel_timer": Mock(),
        }))
        self.enterContext(patch.object(self.ns["os"], "close"))

    def save(self, _, value):
        self.saved = copy.deepcopy(value)
        self.order.append("journal")

    def arm(self, *_):
        self.order.append("timer")
        return self.timer

    def apply(self, script):
        self.order.append("apply")
        self.assertEqual(self.saved["timer"], self.timer)
        self.table = script

    def restore(self, previous):
        self.table = previous

    def test_timer_is_durable_before_any_firewall_effect(self):
        self.assertEqual(self.helper["dispatch"](self.request)[:2], ("SUCCEEDED", "FIREWALL_APPLIED"))
        self.assertLess(self.order.index("timer"), self.order.index("apply"))
        self.assertEqual(self.saved["applied_table"], self.table)

    def test_process_death_during_apply_leaves_armed_timer_and_rollback_works(self):
        def killed(script):
            self.apply(script)
            raise SystemExit("SIGKILL fault")
        self.ns["apply_table"] = killed
        with self.assertRaises(SystemExit):
            self.helper["dispatch"](self.request)
        self.assertEqual(self.saved["timer"], self.timer)
        self.assertEqual(self.saved["state"], "ARMED")
        self.assertEqual(self.helper["dispatch"]({"operation": "rollback", "operation_id": OP})[0], "SUCCEEDED")
        self.assertEqual(self.table, "previous")

    def test_timer_failure_refuses_before_apply(self):
        self.ns["arm_timer"] = Mock(side_effect=self.helper["Refused"]("TIMER_UNAVAILABLE"))
        self.assertEqual(self.helper["dispatch"](self.request)[0], "DENIED")
        self.assertNotIn("apply", self.order)
        self.assertEqual(self.table, "previous")

    def test_remote_baseline_drift_refuses_before_timer_or_effect(self):
        self.ns["baseline_digest"] = Mock(return_value="1" * 64)
        with self.assertRaisesRegex(self.helper["Refused"], "STALE_BASELINE"):
            self.helper["dispatch"](self.request)
        self.assertEqual(self.order, [])

    def test_rollback_failure_stays_unknown_and_does_not_cancel_watchdog(self):
        self.helper["dispatch"](self.request)
        self.ns["restore"] = Mock(side_effect=OSError)
        self.assertEqual(self.helper["dispatch"]({"operation": "rollback", "operation_id": OP})[0], "UNKNOWN_OUTCOME")
        self.assertEqual(self.saved["state"], "ROLLBACK_FAILED")
        self.ns["cancel_timer"].assert_not_called()
        self.ns["other_armed"] = Mock(return_value=self.saved)
        self.ns["read_journal"] = Mock(return_value=None)
        with self.assertRaisesRegex(self.helper["Refused"], "INCIDENT_OPEN"):
            self.helper["dispatch"]({**self.request, "operation_id": OP[:-1] + "B"})

    def test_confirmation_drift_rolls_back_instead_of_reporting_success(self):
        self.helper["dispatch"](self.request)
        self.table = "external drift"
        result = self.helper["dispatch"]({"operation": "confirm", "operation_id": OP, "rules_digest": self.digest})
        self.assertEqual(result[0], "UNKNOWN_OUTCOME")
        self.assertEqual(self.table, "previous")

    def test_confirmed_state_is_persisted_before_timer_cancellation(self):
        self.helper["dispatch"](self.request)
        def cancel(value):
            self.assertEqual(self.saved["state"], "CONFIRMED")
        self.ns["cancel_timer"] = cancel
        self.assertEqual(self.helper["dispatch"]({"operation": "confirm", "operation_id": OP,
                                                 "rules_digest": self.digest})[0], "SUCCEEDED")
        self.assertEqual(self.helper["internal_rollback"](OP), 0)

    def test_rolled_back_operation_is_never_reapplied(self):
        self.helper["dispatch"](self.request)
        self.helper["dispatch"]({"operation": "rollback", "operation_id": OP})
        with self.assertRaisesRegex(self.helper["Refused"], "TERMINAL"):
            self.helper["dispatch"](self.request)
        self.assertEqual(self.order.count("apply"), 1)

    def test_rules_keep_address_family_even_for_wildcard(self):
        script = self.helper["nft_script"]([
            {**RULES[0], "cidr": "0.0.0.0/0", "action": "deny", "port": 443},
            {**RULES[0], "cidr": "::/0", "action": "deny", "port": 443},
        ], 22)
        self.assertIn("meta nfproto ipv4 tcp dport 443 drop", script)
        self.assertIn("meta nfproto ipv6 tcp dport 443 drop", script)

    def test_replace_is_one_checked_atomic_nft_transaction(self):
        helper = runpy.run_path(str(HELPER))
        ns = helper["apply_table"].__globals__
        nft = Mock(return_value=SimpleNamespace(returncode=0))
        with patch.dict(ns, {"snapshot": Mock(return_value="previous"), "run_nft": nft}):
            helper["apply_table"]("table inet vpn_orbit {}")
        self.assertEqual([call.args[0] for call in nft.call_args_list], [["-c", "-f", "-"], ["-f", "-"]])
        for call in nft.call_args_list:
            self.assertTrue(call.kwargs["input_text"].startswith("delete table inet vpn_orbit\n"))

    def test_parser_rejects_shell_duplicate_keys_and_extra_fields(self):
        for raw in (b'{"operation":"exec","command":"nft flush ruleset"}',
                    b'{"operation":"status","operation":"apply"}',
                    b'{"operation":"status","operation_id":"../../etc/passwd"}'):
            with self.assertRaises(self.helper["Refused"]):
                self.helper["parse"](raw)
