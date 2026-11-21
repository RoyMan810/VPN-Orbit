from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from vpn_orbit.auth import AuthService
from vpn_orbit.database import Store, identifier
from vpn_orbit.errors import Denied
from vpn_orbit.firewall_requests import (record_firewall_approval, request_firewall_apply,
                                         request_firewall_reconciliation, save_firewall_draft)
from vpn_orbit.queue import JobQueue
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.ipc import Peer
from vpn_orbit.runtime.storage import new_private_file
from vpn_orbit.runtime.vault import Vault
from vpn_orbit.worker import Worker
from fixtures import ACTOR, BROKER_UID, OTHER, PASSWORD, TARGET, WORKER_UID, private_key, trusted_time
from test_firewall_protocol import RULES, firewall_policy


class FirewallOperationsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = 1_800_000_000
        self.store = Store.initialize(self.root / "app/controller.sqlite3")
        self.auth = AuthService(self.store, clock=lambda: self.now)
        self.owner = self.auth.create_owner(self.auth.issue_bootstrap(), "roman", PASSWORD)
        self.tokens = self.auth.login("roman", PASSWORD, ip="fixture", correlation="fixture")[0]
        self.policy = firewall_policy()
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        self.queue.register_resource(TARGET, self.policy.targets[TARGET].scope_digest, 1)
        self.gate = Authority.initialize(self.root / "gate", self.policy, clock=lambda: self.now,
                                        time_health=trusted_time(self.root / "time", lambda: self.now))
        self.addCleanup(self.gate.close)
        new_private_file(self.root / "dek", b"x" * 32)
        self.vault = Vault.initialize(self.root / "vault", self.root / "dek")
        self.vault.import_firewall_ssh(OTHER, 1, private_key(), owner_id=ACTOR, worker_uid=WORKER_UID, target=TARGET)
        Broker.initialize(self.root / "broker", self.policy)
        self.peer = Peer(1, WORKER_UID, WORKER_UID)
        gate_client = Mock(call=lambda name, args: self.gate.dispatch("broker", Peer(1, BROKER_UID, BROKER_UID), name, args))
        self.execute = Mock(return_value={"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED"})
        self.broker = Broker(self.root / "broker", self.policy, self.vault, gate_client,
                             bytes(self.gate.key.verify_key), worker_uid=WORKER_UID,
                             clock=lambda: self.now, execute_firewall=self.execute)
        self.worker = Worker(self.queue,
                             Mock(call=lambda name, args: self.gate.dispatch("worker", self.peer, name, args)),
                             Mock(call=lambda name, args: self.broker.dispatch("worker", self.peer, name, args)),
                             secret_refs={}, firewall_refs={TARGET: OTHER + ":v1"})

    def enqueue(self, rules=RULES):
        with self.store.write() as db:
            draft, tag = save_firewall_draft(db, self.auth, self.tokens.session, self.tokens.csrf, TARGET, rules, 22)
        grant = self.auth.reauthenticate(self.tokens.session, self.tokens.csrf, PASSWORD, draft["plan_hash"],
                                         correlation=identifier())
        with self.store.write() as db:
            approved = record_firewall_approval(db, self.auth, self.tokens.session, self.tokens.csrf,
                                                draft["id"], if_match=tag, reauth_id=grant["id"])
            result = request_firewall_apply(db, self.queue, self.auth, self.tokens.session, self.tokens.csrf,
                                            draft["id"], if_match=tag, approval_id=approved["approval_id"])
        return draft, result

    def test_approval_dispatch_receipt_and_public_result(self):
        draft, request = self.enqueue()
        self.assertTrue(self.worker.run_one())
        public = self.queue.get(self.auth, self.tokens.session, request["id"])[0]
        self.assertEqual(public["status"], "SUCCEEDED")
        self.assertEqual(public["result"]["rules"], RULES)
        self.assertIsNone(public["observed_at"])
        self.execute.assert_called_once()
        self.store.verify_audit()

    def test_expired_approval_never_reaches_broker(self):
        draft, request = self.enqueue()
        self.now += 301
        self.worker.run_one()
        self.assertEqual(self.queue.get(self.auth, self.tokens.session, request["id"])[0]["status"], "CANCELLED_SAFE")
        self.execute.assert_not_called()

    def test_unknown_requires_digest_bound_remote_reconciliation_before_next_apply(self):
        self.execute.return_value = {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_CONFIRM_UNCONFIRMED"}
        draft, request = self.enqueue()
        self.worker.run_one()
        job = self.queue.get(self.auth, self.tokens.session, request["id"])[0]
        self.assertEqual(job["status"], "UNKNOWN_OUTCOME")
        with self.assertRaisesRegex(Denied, "RPC_OPERATION_DENIED"):
            self.gate.dispatch("worker", self.peer, "firewall.reconcile", {})
        self.broker.firewall_status = Mock(return_value={"outcome": "SUCCEEDED", "code": "FIREWALL_STATUS",
                                                         "state": "ROLLED_BACK", "rules_digest": "0" * 64})
        with self.store.write() as db:
            request_firewall_reconciliation(db, self.auth, self.tokens.session, self.tokens.csrf,
                                            draft["id"], request["id"], 1)
        self.worker.run_one()
        self.assertEqual(self.gate.status(request["id"])["state"], "UNKNOWN_OUTCOME")
        with self.store.read() as db:
            self.assertIsNotNone(db.execute("SELECT * FROM job_incidents").fetchone())
        digest = self.execute.call_args.args[3]["rules_digest"]
        self.broker.firewall_status.return_value["rules_digest"] = digest
        with self.store.write() as db:
            request_firewall_reconciliation(db, self.auth, self.tokens.session, self.tokens.csrf,
                                            draft["id"], request["id"], 2)
        self.worker.run_one()
        self.assertEqual(self.gate.status(request["id"])["state"], "RECONCILED_FAILED")
        self.assertEqual(self.queue.get(self.auth, self.tokens.session, request["id"])[0]["status"], "UNKNOWN_OUTCOME")
        self.execute.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED"}
        _, second = self.enqueue()
        self.worker.run_one()
        self.assertEqual(self.queue.get(self.auth, self.tokens.session, second["id"])[0]["status"], "SUCCEEDED")
        self.store.verify_audit()

    def test_confirmed_reconciliation_updates_baseline_without_rewriting_unknown_job(self):
        self.execute.return_value = {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_CONFIRM_UNCONFIRMED"}
        draft, request = self.enqueue()
        self.worker.run_one()
        self.broker.firewall_status = Mock(return_value={
            "outcome": "SUCCEEDED", "code": "FIREWALL_STATUS", "state": "CONFIRMED",
            "rules_digest": self.execute.call_args.args[3]["rules_digest"]})
        with self.store.write() as db:
            request_firewall_reconciliation(db, self.auth, self.tokens.session, self.tokens.csrf,
                                            draft["id"], request["id"], 1)
        self.worker.run_one()
        self.assertEqual(self.gate.status(request["id"])["state"], "RECONCILED_SUCCEEDED")
        self.now += 900
        self.execute.return_value = {"outcome": "SUCCEEDED", "code": "FIREWALL_CONFIRMED"}
        next_draft, second = self.enqueue()
        self.assertEqual(next_draft["baseline"]["previous_rules"], RULES)
        self.worker.run_one()
        self.assertEqual(self.queue.get(self.auth, self.tokens.session, second["id"])[0]["status"], "SUCCEEDED")
