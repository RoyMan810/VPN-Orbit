from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.policy import Policy, Target
from vpn_orbit.runtime.protocol import checksum, firewall_payload, firewall_rules
from vpn_orbit.runtime import ssh
from fixtures import ACTOR, OTHER, SECRET, TARGET, policy, trusted_time


OP = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
RULES = [
    {"action": "allow", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
    {"action": "allow", "direction": "in", "protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"},
    {"action": "deny", "direction": "in", "protocol": "udp", "port": 53, "cidr": "10.0.0.0/8"},
]


def payload(**changes):
    value = {"operation_id": OP, "rules": RULES, "rules_digest": checksum(RULES),
             "previous_rules_digest": checksum([]), "ssh_port": 22}
    value.update(changes)
    return value


def firewall_policy():
    base = policy().targets[TARGET].value
    return Policy([{**base, "capabilities": ["host.probe", "firewall.apply"], "firewall_secret_ref": OTHER + ":v1"}])


class FirewallProtocolTests(unittest.TestCase):
    def test_free_form_commands_and_noncanonical_networks_are_not_rules(self):
        for change in (
            {"action": "allow", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0; nft flush ruleset"},
            {"action": "allow", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "10.0.0.1/8"},
            {"action": "allow", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "fe80::1%eth0"},
            {"action": "exec", "direction": "in", "protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
            {"action": "allow", "direction": "in", "protocol": "sctp", "port": 22, "cidr": "0.0.0.0/0"},
            {"action": "allow", "direction": "in", "protocol": "tcp", "port": 0, "cidr": "0.0.0.0/0"},
        ):
            with self.subTest(change=change), self.assertRaises(Denied):
                firewall_rules([change])
        for value in ([], [RULES[0]] * 2, RULES + [RULES[0]], [{"port": 22}], RULES * 20):
            with self.subTest(value=str(value)[:60]), self.assertRaises(Denied):
                firewall_rules(value)

    def test_payload_is_digest_bound_and_always_preserves_ssh(self):
        self.assertEqual(firewall_payload(payload())["rules"], RULES)
        for change in ({"rules_digest": "0" * 64}, {"ssh_port": 2222}, {"operation_id": "not-a-ulid"},
                       {"rules": RULES[1:], "rules_digest": checksum(RULES[1:])}):
            with self.subTest(change=change), self.assertRaises(Denied):
                firewall_payload(payload(**change))

    def test_capability_requires_a_distinct_broker_credential(self):
        base = policy().targets[TARGET].value
        for change in ({"capabilities": ["host.probe", "firewall.apply"]},
                       {"capabilities": ["host.probe", "firewall.apply"], "firewall_secret_ref": SECRET + ":v1"},
                       {"capabilities": ["host.probe", "firewall.apply"], "firewall_secret_ref": SECRET + ":v1"},
                       {"capabilities": ["host.probe", "docker.restart", "firewall.apply"],
                        "restart_secret_ref": OTHER + ":v1", "firewall_secret_ref": OTHER + ":v1"}):
            with self.subTest(change=change), self.assertRaises(Denied):
                Target.parse({**base, **change})
        value = Target.parse({**base, "capabilities": ["host.probe", "firewall.apply"],
                              "firewall_secret_ref": OTHER + ":v1"})
        self.assertEqual(value.value["firewall_secret_ref"], OTHER + ":v1")


class FirewallAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = 1_800_000_000
        self.policy = firewall_policy()
        self.authority = Authority.initialize(self.directory / "gate", self.policy, clock=lambda: self.now,
                                              time_health=trusted_time(self.directory / "time", lambda: self.now))
        self.addCleanup(self.authority.close)

    def request(self, value=None):
        payload_value = value if value is not None else payload()
        plan_id = OP
        anchor = self.authority.time_anchor({"plan_id": plan_id, "revision": 1})
        return {"job_id": OP, "plan_id": plan_id, "revision": 1, "plan_digest": "a" * 64,
                "approval_id": OP, "actor_id": ACTOR, "target": TARGET, "capability": "firewall.apply",
                "scope_digest": self.policy.targets[TARGET].scope_digest, "time_anchor": anchor,
                "firewall": payload_value}

    def test_permit_binds_the_exact_typed_ruleset(self):
        permit = self.authority.admit(self.request())
        self.assertEqual(permit["claims"]["firewall"]["rules"], RULES)
        self.assertEqual(self.authority.status(OP)["state"], "ISSUED")
        with self.assertRaisesRegex(Denied, "ALREADY_ADMITTED"):
            self.authority.admit(self.request())

    def test_unapproved_capability_and_tampered_rules_fail_before_signing(self):
        disabled_policy = policy()
        disabled = Authority.initialize(
            self.directory / "disabled", disabled_policy, clock=lambda: self.now,
            time_health=trusted_time(self.directory / "disabled-time", lambda: self.now),
        )
        self.addCleanup(disabled.close)
        self.authority = disabled
        with self.assertRaisesRegex(Denied, "CAPABILITY_DISABLED"):
            self.authority.admit({
                **self.request(),
                "scope_digest": disabled_policy.targets[TARGET].scope_digest,
            })
        self.authority.policy = self.policy
        with self.assertRaises(Denied):
            self.authority.admit(self.request(payload(rules_digest="0" * 64)))
        with self.assertRaises(Denied):
            self.authority.admit(self.request(payload(operation_id=OTHER)))


class FirewallOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.target = object()
        self.apply = patch.object(ssh, "firewall")
        self.control = patch.object(ssh, "firewall_control")
        self.apply_mock = self.apply.start()
        self.control_mock = self.control.start()
        self.addCleanup(self.apply.stop)
        self.addCleanup(self.control.stop)

    def run_apply(self):
        return ssh.apply_firewall(self.target, b"key", "known_hosts", payload())

    def controls(self, operation, payload_value):
        return [call for call in self.control_mock.call_args_list if call.args[3] == operation]

    def test_apply_then_fresh_ssh_status_then_confirm(self):
        self.apply_mock.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_APPLIED", "state": "ARMED", "rules_digest": checksum(RULES)}
        self.control_mock.side_effect = [
            {"outcome": "SUCCEEDED", "code": "FIREWALL_STATUS", "state": "ARMED", "rules_digest": checksum(RULES)},
            {"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED", "state": "CONFIRMED"},
        ]
        self.assertEqual(self.run_apply(), {"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED"})
        self.assertEqual([call.args[3] for call in self.control_mock.call_args_list], ["status", "confirm"])
        self.assertEqual(self.control_mock.call_args.args[4]["rules_digest"], checksum(RULES))

    def test_already_confirmed_operation_is_idempotent_without_rollback(self):
        self.apply_mock.return_value = {
            "outcome": "SUCCEEDED", "code": "FIREWALL_ALREADY_APPLIED",
            "state": "CONFIRMED", "rules_digest": checksum(RULES),
        }
        self.assertEqual(self.run_apply(), {"outcome": "SUCCEEDED", "code": "FIREWALL_ALREADY_CONFIRMED"})
        self.control_mock.assert_not_called()

    def test_failed_fresh_connection_rolls_back_locally(self):
        self.apply_mock.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_APPLIED", "state": "ARMED", "rules_digest": checksum(RULES)}
        self.control_mock.side_effect = [Denied("SSH_FIREWALL_CONTROL_UNCONFIRMED"),
                                         {"outcome": "SUCCEEDED", "code": "FIREWALL_ROLLED_BACK", "state": "ROLLED_BACK"}]
        self.assertEqual(self.run_apply(), {"outcome": "FAILED", "code": "FIREWALL_SSH_UNCONFIRMED_ROLLED_BACK"})
        self.assertEqual([call.args[3] for call in self.control_mock.call_args_list], ["status", "rollback"])

    def test_lost_apply_verification_and_lost_rollback_are_never_success(self):
        self.apply_mock.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_APPLIED", "state": "ARMED", "rules_digest": checksum(RULES)}
        self.control_mock.side_effect = Denied("SSH_FIREWALL_CONTROL_UNCONFIRMED")
        self.assertEqual(self.run_apply(), {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_SSH_UNCONFIRMED"})

    def test_lost_confirm_reply_is_unknown(self):
        self.apply_mock.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_APPLIED", "state": "ARMED", "rules_digest": checksum(RULES)}
        self.control_mock.side_effect = [
            {"outcome": "SUCCEEDED", "code": "FIREWALL_STATUS", "state": "ARMED", "rules_digest": checksum(RULES)},
            Denied("SSH_FIREWALL_CONTROL_UNCONFIRMED"),
        ]
        self.assertEqual(self.run_apply(), {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_CONFIRM_UNCONFIRMED"})

    def test_refused_apply_is_returned_without_confirmation(self):
        self.apply_mock.return_value = {"outcome": "DENIED", "code": "FIREWALL_SSH_RULE_REQUIRED"}
        self.assertEqual(self.run_apply(), {"outcome": "DENIED", "code": "FIREWALL_SSH_RULE_REQUIRED"})
        self.control_mock.assert_not_called()

    def test_typed_requests_reject_arbitrary_commands(self):
        with self.assertRaisesRegex(Denied, "RPC_INVALID_REQUEST"):
            ssh._firewall_request("exec", {"command": "nft flush ruleset"})
        with self.assertRaises(Denied):
            ssh._firewall_request("apply", payload(rules_digest="0" * 64))
        self.apply_mock.assert_not_called()
        self.control_mock.assert_not_called()


class FirewallReplyTests(unittest.TestCase):
    def test_outcome_must_match_the_process_exit_status(self):
        for outcome, status in (("SUCCEEDED", 0), ("DENIED", 65), ("UNKNOWN_OUTCOME", 70)):
            self.assertEqual(ssh.firewall_reply({"outcome": outcome, "code": "FIREWALL_STATUS",
                                                 "state": "ABSENT"}, status)["outcome"], outcome)
        for value, status in (({"outcome": "SUCCEEDED", "code": "X"}, 1),
                              ({"outcome": "SUCCEEDED", "code": "ARBITRARY"}, 0),
                              ({"outcome": "SUCCEEDED", "code": "FIREWALL_STATUS", "command": "sh"}, 0),
                              ({"outcome": "SUCCEEDED", "code": "FIREWALL_STATUS", "state": "OTHER"}, 0),
                              ({"outcome": "SUCCEEDED", "code": "FIREWALL_APPLIED", "state": "ARMED"}, 0),
                              ({"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED"}, 0)):
            with self.subTest(value=value), self.assertRaises(Denied):
                ssh.firewall_reply(value, status)


if __name__ == "__main__":
    unittest.main()
