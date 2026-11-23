from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from fixtures import ACTOR, BROKER_UID, OTHER, SECRET, TARGET, WORKER_UID, binding, policy, private_key, trusted_time
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.ipc import Peer
from vpn_orbit.runtime.policy import Policy, Target
from vpn_orbit.runtime.protocol import application_payload
from vpn_orbit.runtime.storage import new_private_file
from vpn_orbit.runtime.vault import Vault


class ApplicationTransportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = 1_800_000_000
        self.value = {**policy().targets[TARGET].value, "capabilities": ["host.probe", "apps.lifecycle"],
                      "application_secret_ref": OTHER + ":v1", "applications": {ACTOR: "d" * 64}}
        self.policy = Policy([self.value])
        self.gate = Authority.initialize(self.root / "gate", self.policy, clock=lambda: self.now,
                                        time_health=trusted_time(self.root / "time", lambda: self.now))
        self.addCleanup(self.gate.close)
        new_private_file(self.root / "dek", b"x" * 32)
        self.vault = Vault.initialize(self.root / "vault", self.root / "dek")
        self.vault.import_application_ssh(OTHER, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        Broker.initialize(self.root / "broker", self.policy)
        self.execute = Mock(return_value={"outcome": "SUCCEEDED", "code": "APP_HEALTH_VERIFIED"})
        self.broker = Broker(self.root / "broker", self.policy, self.vault,
                             Mock(call=lambda op, data: self.gate.dispatch("broker", Peer(1, BROKER_UID, BROKER_UID), op, data)),
                             bytes(self.gate.key.verify_key), worker_uid=WORKER_UID, clock=lambda: self.now,
                             execute_application=self.execute)

    def request(self):
        request = {**binding(self.policy, SECRET), "capability": "apps.lifecycle",
                   "time_anchor": self.gate.time_anchor({"plan_id": SECRET, "revision": 1}),
                   "application": {"operation_id": SECRET, "installation_id": ACTOR, "spec_digest": "d" * 64, "action": "install"}}
        return request

    def test_exact_protected_scope_and_dedicated_key_are_required(self):
        request = self.request()
        permit = self.gate.admit(request)
        response = self.broker.use({"permit": permit, "policy_ref": OTHER + ":v1"}, Peer(1, WORKER_UID, WORKER_UID))
        self.assertEqual(response["outcome"], "SUCCEEDED")
        self.assertEqual(self.execute.call_args.args[-1], request["application"])
        with self.assertRaisesRegex(Denied, "PERMIT_REPLAY"):
            self.broker.use({"permit": permit, "policy_ref": OTHER + ":v1"}, Peer(1, WORKER_UID, WORKER_UID))
        self.execute.assert_called_once()

    def test_scope_injection_fails_before_permit_or_ssh(self):
        for changed in ({"spec_digest": "e" * 64}, {"installation_id": OTHER}, {"action": "shell"}):
            request = self.request()
            request["application"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(Denied):
                self.gate.admit(request)
        self.execute.assert_not_called()
        with self.assertRaises(Denied):
            application_payload({**self.request()["application"], "command": "id"})

    def test_application_key_cannot_reuse_probe_or_firewall_identity(self):
        for changed in ({"application_secret_ref": self.value["secret_ref"]}, {"applications": {}},
                        {"capabilities": ["host.probe"]}):
            with self.subTest(changed=changed), self.assertRaises(Denied):
                Target.parse({**self.value, **changed})

    def test_lost_reply_is_unknown_and_blocks_another_permit(self):
        self.execute.side_effect = Denied("SSH_APP_UNCONFIRMED")
        permit = self.gate.admit(self.request())
        self.assertEqual(self.broker.use({"permit": permit, "policy_ref": OTHER + ":v1"},
                                        Peer(1, WORKER_UID, WORKER_UID))["outcome"], "UNKNOWN_OUTCOME")
        request = self.request()
        request["job_id"] = OTHER
        request["application"]["operation_id"] = OTHER
        with self.assertRaisesRegex(Denied, "OPEN_INCIDENT"):
            self.gate.admit(request)
        self.execute.side_effect = None
        self.execute.return_value = {"outcome": "RECONCILED_SUCCEEDED", "code": "APP_READBACK_VERIFIED"}
        remote = self.broker.dispatch("worker", Peer(1, WORKER_UID, WORKER_UID), "apps.reconcile", {"job_id": SECRET})
        self.assertEqual(remote["outcome"], "RECONCILED_SUCCEEDED")
        self.assertEqual(self.gate.status(SECRET)["state"], "RECONCILED_SUCCEEDED")
        with self.broker.journal.connect() as db:
            self.assertEqual(db.execute("SELECT state FROM receipts WHERE job_id=?", (SECRET,)).fetchone()["state"], "UNKNOWN_OUTCOME")
        self.execute.assert_called_with(self.policy.targets[TARGET], private_key(), self.root / "broker/known_hosts",
                                       self.request()["application"], operation="reconcile")
