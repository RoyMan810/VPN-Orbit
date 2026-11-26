from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import tempfile
from threading import Event
import time
import unittest
from unittest.mock import Mock, patch

from vpn_orbit.database import Store, identifier
from vpn_orbit.errors import Denied
from vpn_orbit.queue import JobQueue
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.ipc import Client, Peer, handle
from vpn_orbit.runtime.storage import new_private_file
from vpn_orbit.runtime.vault import Vault
from vpn_orbit.runtime.vps_preparation import PHASES
from vpn_orbit.worker import Worker
from .fixtures import ACTOR, BROKER_UID, TARGET, WORKER_UID, policy, private_key, trusted_time


def preparation_runtime(directory, approved_policy, actor, observation_key, *, clock=time.time, store=None):
    if store is None:
        store = Store.initialize(directory / "app/controller.sqlite3")
        with store.write() as db:
            db.execute("""INSERT INTO users(id,username,password_hash,password_profile,role,created_at,updated_at)
                          VALUES(?,'owner','unused',1,'Owner',0,0)""", (actor,))
    queue = JobQueue(store, clock=clock)
    authority = Authority.initialize(directory / "gate", approved_policy, clock=clock,
                                     time_health=trusted_time(directory / "time", clock))
    new_private_file(directory / "dek", b"x" * 32)
    vault = Vault.initialize(directory / "vault", directory / "dek")
    target, = approved_policy.targets.values()
    anchor, version = target.value["secret_ref"].split(":v")
    vault.import_ssh(anchor, int(version), observation_key, owner_id=actor, worker_uid=WORKER_UID,
                     target=target.id, policy_revision=target.revision)
    Broker.initialize(directory / "broker", approved_policy)
    gate = Mock(call=lambda op, data: authority.dispatch("broker", Peer(1, BROKER_UID, BROKER_UID), op, data))
    broker = Broker(directory / "broker", approved_policy, vault, gate, bytes(authority.key.verify_key),
                    worker_uid=WORKER_UID, clock=clock)
    worker = Worker(queue, Mock(call=lambda op, data: authority.dispatch(
        "worker", Peer(1, WORKER_UID, WORKER_UID), op, data)),
        Mock(call=lambda op, data, **options: broker.dispatch("worker", Peer(1, WORKER_UID, WORKER_UID), op, data, **options)),
        secret_refs={target.id: target.value["secret_ref"]})
    return queue, authority, broker, worker


class PreparationJobTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.policy = policy(capabilities=["host.probe", "host.prepare"])
        self.target = self.policy.targets[TARGET]
        self.queue, self.authority, self.broker, self.worker = preparation_runtime(
            self.root, self.policy, ACTOR, private_key(), clock=lambda: 1_800_000_000)
        self.addCleanup(self.authority.close)
        self.job = identifier()
        self.credentials = {"job_id": self.job, "actor_id": ACTOR, "target": TARGET, "scope_digest": self.target.scope_digest,
                            "username": "root", "password": "lab-credential-canary", "private_key": None}
        self.root_peer = Peer(1, 0, 0)

    def state(self):
        with self.queue.store.read() as db:
            row = db.execute("SELECT status,reason FROM jobs WHERE id=?", (self.job,)).fetchone()
            enabled, = db.execute("SELECT enabled FROM resources WHERE id=?", (TARGET,)).fetchone()
            return row["status"], row["reason"], enabled

    def submit(self):
        self.broker.dispatch("local-root", self.root_peer, "prepare.credentials", self.credentials)
        return self.queue.enqueue_preparation(self.job, ACTOR, self.target)

    def test_worker_applies_only_missing_phases_under_one_permit_and_enables_resource(self):
        with self.assertRaisesRegex(Denied, "RPC_OPERATION_DENIED"):
            self.broker.dispatch("worker", Peer(1, WORKER_UID, WORKER_UID), "prepare.credentials", self.credentials)
        self.assertEqual(self.policy.enrollment_catalog(ssh_endpoints=True), {})
        self.assertEqual(self.submit()["status"], "QUEUED")
        self.assertEqual(self.state(), ("QUEUED", None, 0))
        with self.assertRaisesRegex(Denied, "ALREADY_PENDING"):
            self.queue.enqueue_preparation(identifier(), ACTOR, self.target)
        effects = set()
        auth = Mock(_session=lambda db, token: db.execute("SELECT * FROM users WHERE id=?", (ACTOR,)).fetchone())
        jobs = []

        async def phase(name, *, inspect):
            self.assertEqual(self.authority.status(self.job)["state"], "DISPATCHING")
            progress, current_etag = self.queue.get(auth, "fixture", self.job)
            jobs.append((progress["revision"], current_etag))
            self.assertEqual(progress["status"], "DISPATCHING")
            self.assertEqual(progress["preparation"]["phase"], name)
            if inspect:
                return "VERIFIED" if name in effects else "INCOMPLETE"
            self.assertEqual(progress["preparation"]["stage"], "DISPATCHING")
            with self.broker.journal.connect() as db:
                mark = db.execute("SELECT phase,stage FROM preparation_phases WHERE job_id=?", (self.job,)).fetchone()
                self.assertEqual(tuple(mark), (name, "DISPATCHING"))
            self.assertNotIn(name, effects)
            effects.add(name)
            return "APPLIED"

        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            ssh.return_value.phase.side_effect = phase
            self.assertTrue(self.worker.run_one())
            ssh.return_value.verify_access.assert_awaited_once()
        self.assertEqual(effects, set(PHASES))
        self.assertEqual({revision for revision, _ in jobs}, {3})
        self.assertEqual(len({tag for _, tag in jobs}), len(PHASES) * 2)
        self.assertEqual(self.state(), ("SUCCEEDED", "VPS_PREPARATION_VERIFIED", 1))
        job, _ = self.queue.get(auth, "fixture", self.job)
        self.assertEqual(job["preparation"], {"phase": "access", "stage": "VERIFIED"})
        self.assertEqual(self.queue.timeline(auth, "fixture", self.job)["items"][-1]["status"], "SUCCEEDED")
        self.assertEqual(self.authority.status(self.job)["state"], "SUCCEEDED")
        self.assertEqual(self.broker._preparation_credentials, {})
        for path in self.root.rglob("*.sqlite3*"):
            self.assertNotIn(b"lab-credential-canary", path.read_bytes())

    def test_unix_rpc_reports_a_phase_before_the_final_reply_and_limits_the_stream(self):
        seen = Event()
        reports = []
        phase = {"phase": "preflight", "stage": "CHECKING"}

        def dispatch(role, peer, operation, payload, *, progress):
            self.assertEqual((role, operation), ("worker", "prepare.run"))
            for _ in range(payload["count"]):
                progress(phase)
            if payload["count"] == 1:
                self.assertTrue(seen.wait(2))
            return {"outcome": "SUCCEEDED"}

        def observe(value):
            self.assertEqual(value, phase)
            reports.append(value)
            seen.set()

        class ConnectedSocket(socket.socket):
            def connect(self, _):
                pass

        identities = {(os.geteuid(), os.getegid()): "worker"}
        for count in (1, 21):
            with self.subTest(count=count):
                reports.clear()
                client, server_peer = socket.socketpair()
                with client, server_peer, ThreadPoolExecutor(max_workers=1) as pool:
                    connection = ConnectedSocket(fileno=client.detach())
                    done = pool.submit(handle, server_peer, dispatch, identities, progress_operation="prepare.run")
                    rpc = Client("/unused", server_uids={os.geteuid()}, timeout=4)
                    payload = {"count": count}
                    with patch("vpn_orbit.runtime.ipc.socket.socket", return_value=connection):
                        if count == 1:
                            self.assertEqual(rpc.call("prepare.run", payload, progress=observe), {"outcome": "SUCCEEDED"})
                        else:
                            with self.assertRaisesRegex(Denied, "RPC_INVALID_RESPONSE"):
                                rpc.call("prepare.run", payload, progress=observe)
                    done.result(4)
                self.assertEqual(len(reports), min(count, 20))

    def test_lost_reply_holds_authority_until_readback_proves_all_phases(self):
        self.submit()

        async def phase(name, *, inspect):
            if not inspect:
                raise Denied("VPS_PREPARATION_SSH_UNCONFIRMED")
            return "INCOMPLETE"

        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            ssh.return_value.phase.side_effect = phase
            self.assertTrue(self.worker.run_one())
            self.assertEqual(self.state(), ("UNKNOWN_OUTCOME", "VPS_PREPARATION_SSH_UNCONFIRMED", 0))
            with self.assertRaisesRegex(Denied, "RECONCILIATION_UNVERIFIED"):
                self.broker.dispatch("local-root", self.root_peer, "prepare.reconcile", self.credentials)
            self.assertEqual(self.authority.status(self.job)["state"], "UNKNOWN_OUTCOME")
            ssh.return_value.phase.reset_mock(side_effect=True, return_value=True)
            ssh.return_value.phase.return_value = "VERIFIED"
            receipt = self.broker.dispatch("local-root", self.root_peer, "prepare.reconcile", self.credentials)
            self.assertTrue(all(call.kwargs == {"inspect": True} for call in ssh.return_value.phase.await_args_list))
            self.queue.reconcile_preparation(self.job, self.target, receipt)
        self.assertEqual(self.state(), ("SUCCEEDED", "VPS_PREPARATION_RECONCILED", 1))
        session = Mock(_session=lambda db, token: db.execute("SELECT * FROM users WHERE id=?", (ACTOR,)).fetchone())
        timeline = self.queue.timeline(session, "test-token", self.job)["items"]
        self.assertEqual([event["status"] for event in timeline[-2:]], ["UNKNOWN_OUTCOME", "SUCCEEDED"])
        self.assertEqual(timeline[-1]["reason"], "VPS_PREPARATION_RECONCILED")
        with self.authority.journal.connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM incidents").fetchone())

    def test_worker_restart_after_dispatch_commit_cancels_unconsumed_permit(self):
        for restart_authority in (False, True):
            with self.subTest(restart_authority=restart_authority):
                self.queue.enqueue_preparation(self.job, ACTOR, self.target)
                claim, row = self.queue.claim(self.worker.id)
                binding = self.queue.binding(row)
                binding["time_anchor"] = self.authority.time_anchor({"plan_id": self.job, "revision": 1})
                permit = self.authority.admit(binding)
                self.queue.advance(claim, "INTENT_PREPARED", permit=permit, binding=binding)
                self.queue.advance(claim, "DISPATCHING")
                with patch.object(self.worker.gate, "call", side_effect=Denied("RPC_UNAVAILABLE")):
                    with self.assertRaisesRegex(Denied, "RPC_UNAVAILABLE"):
                        self.queue.recover(self.worker._recover_result)
                self.assertEqual(self.state(), ("DISPATCHING", None, 0))
                if restart_authority:
                    self.authority.recover()
                self.queue.recover(self.worker._recover_result)
                self.assertEqual(self.state(), ("FAILED", "WORKER_RESTART", 0))
                self.assertEqual(self.authority.status(self.job)["state"], "CANCELLED_SAFE")
                with self.authority.journal.connect() as db:
                    self.assertIsNone(db.execute("SELECT 1 FROM incidents").fetchone())
                    self.assertEqual(db.execute("SELECT state FROM gate").fetchone()["state"], "NORMAL")
                self.job = identifier()

    def test_broker_can_prove_no_changes_after_worker_recovers_during_preflight(self):
        self.submit()
        claim, row = self.queue.claim(self.worker.id)
        binding = self.queue.binding(row)
        binding["time_anchor"] = self.authority.time_anchor({"plan_id": self.job, "revision": 1})
        permit = self.authority.admit(binding)
        self.queue.advance(claim, "INTENT_PREPARED", permit=permit, binding=binding)
        self.queue.advance(claim, "DISPATCHING")

        async def preflight(name, *, inspect):
            self.assertEqual((name, inspect), ("preflight", True))
            self.queue.recover(self.worker._recover_result)
            self.assertEqual(self.state(), ("UNKNOWN_OUTCOME", "WORKER_RESTART", 0))
            return "CONFLICT"

        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            ssh.return_value.phase.side_effect = preflight
            self.worker.broker.call("use_for_scoped_ssh", {"permit": permit, "policy_ref": self.target.value["secret_ref"]})
        self.assertEqual(self.authority.status(self.job)["state"], "FAILED")
        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            receipt = self.broker.dispatch("local-root", self.root_peer, "prepare.reconcile", self.credentials)
            ssh.assert_not_called()
        self.queue.reconcile_preparation(self.job, self.target, receipt)
        self.assertEqual(self.state(), ("FAILED", "VPS_PREPARATION_NO_CHANGES", 0))
        session = Mock(_session=lambda db, token: db.execute("SELECT * FROM users WHERE id=?", (ACTOR,)).fetchone())
        timeline = self.queue.timeline(session, "test-token", self.job)["items"]
        self.assertEqual([event["status"] for event in timeline[-2:]], ["UNKNOWN_OUTCOME", "FAILED"])
        self.queue.enqueue_preparation(identifier(), ACTOR, self.target)

    def test_lost_ephemeral_credentials_fail_without_contacting_host(self):
        self.queue.enqueue_preparation(self.job, ACTOR, self.target)
        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            self.assertTrue(self.worker.run_one())
            ssh.assert_not_called()
        self.assertEqual(self.state(), ("FAILED", "VPS_PREPARATION_CREDENTIALS_EXPIRED", 0))

    def test_web_api_can_only_supply_credentials_for_configured_targets(self):
        web_peer = Peer(1, 11003, 11004)
        role = "preparation-api"
        with self.assertRaisesRegex(Denied, "CAPABILITY_DISABLED"):
            self.broker.dispatch(role, web_peer, "prepare.credentials", self.credentials)
        self.broker.web_preparation_targets = frozenset({TARGET})
        for operation in ("prepare.reconcile", "prepare.run", "use_for_scoped_ssh", "receipt.get", "apps.reconcile", "firewall.status"):
            with self.subTest(operation=operation), self.assertRaisesRegex(Denied, "RPC_OPERATION_DENIED"):
                self.broker.dispatch(role, web_peer, operation, {})
        with self.assertRaisesRegex(Denied, "STALE_SCOPE"):
            self.broker.dispatch(role, web_peer, "prepare.credentials", {**self.credentials, "scope_digest": "a" * 64})
        self.assertEqual(self.broker.dispatch(role, web_peer, "prepare.credentials", self.credentials), {"job_id": self.job})
        with self.broker.journal.connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM receipts").fetchone())
        self.queue.enqueue_preparation(self.job, ACTOR, self.target)
        with patch("vpn_orbit.runtime.broker.PreparationSSH", autospec=True) as ssh:
            ssh.return_value.phase.return_value = "VERIFIED"
            self.assertTrue(self.worker.run_one())
        self.assertEqual(self.state(), ("SUCCEEDED", "VPS_PREPARATION_VERIFIED", 1))
