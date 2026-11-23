from unittest.mock import Mock
import unittest

from fixtures import OTHER, TARGET
import test_application_transport as transport
from vpn_orbit.application_requests import approve, enqueue, reconcile, save
from vpn_orbit.auth import AuthService
from vpn_orbit.database import Store
from vpn_orbit.errors import Denied
from vpn_orbit.queue import JobQueue
from vpn_orbit.runtime.ipc import Peer
from vpn_orbit.worker import Worker


class ApplicationOperationsTests(unittest.TestCase):
    def setUp(self):
        transport.ApplicationTransportTests.setUp(self)
        from fixtures import ACTOR, PASSWORD, WORKER_UID
        self.actor, self.password = ACTOR, PASSWORD
        self.store = Store.initialize(self.root / "app/controller.sqlite3")
        self.auth = AuthService(self.store, clock=lambda: self.now)
        self.auth.create_owner(self.auth.issue_bootstrap(), "roman", PASSWORD)
        self.tokens = self.auth.login("roman", PASSWORD, ip="fixture", correlation="fixture")[0]
        self.queue = JobQueue(self.store, clock=lambda: self.now)
        self.queue.register_resource(TARGET, self.policy.targets[TARGET].scope_digest, 1)
        self.peer = Peer(1, WORKER_UID, WORKER_UID)
        self.worker = Worker(self.queue,
                             Mock(call=lambda op, body: self.gate.dispatch("worker", self.peer, op, body)),
                             Mock(call=lambda op, body: self.broker.dispatch("worker", self.peer, op, body)),
                             secret_refs={}, application_refs={TARGET: OTHER + ":v1"})

    def enqueue_operation(self):
        with self.store.write() as db:
            draft, tag = save(db, self.auth, self.tokens.session, self.tokens.csrf, TARGET, self.actor, "d" * 64, "install")
        grant = self.auth.reauthenticate(self.tokens.session, self.tokens.csrf, self.password, draft["plan_hash"], correlation=OTHER)
        with self.store.write() as db:
            approval = approve(db, self.auth, self.tokens.session, self.tokens.csrf, draft["id"], tag, grant["id"])
        with self.store.write() as db:
            result = enqueue(db, self.queue, self.auth, self.tokens.session, self.tokens.csrf,
                             draft["id"], tag, approval["approval_id"])
        return result["id"]

    def test_durable_worker_uses_signed_application_payload(self):
        operation = self.enqueue_operation()
        self.assertTrue(self.worker.run_one())
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT status FROM jobs WHERE id=?", (operation,)).fetchone()[0], "SUCCEEDED")
        self.execute.assert_called_once()
        self.store.verify_audit()

    def test_worker_lost_reply_then_reconciliation_preserves_unknown_job(self):
        operation = self.enqueue_operation()
        self.execute.side_effect = Denied("SSH_APP_UNCONFIRMED")
        self.worker.run_one()
        with self.store.write() as db:
            reconcile(db, self.queue, self.auth, self.tokens.session, self.tokens.csrf, operation, 1)
        self.execute.side_effect = None
        self.execute.return_value = {"outcome": "RECONCILED_SUCCEEDED", "code": "APP_READBACK_VERIFIED"}
        self.assertTrue(self.worker.run_one())
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT status FROM jobs WHERE id=?", (operation,)).fetchone()[0], "UNKNOWN_OUTCOME")
            self.assertEqual(db.execute("SELECT count(*) FROM job_incidents").fetchone()[0], 0)
        self.store.verify_audit()
