from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from nacl.secret import Aead

from vpn_orbit.admission import Admission
from vpn_orbit.database import Store, identifier
from vpn_orbit.errors import Denied
from vpn_orbit.queue import JobQueue
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.policy import Policy
from vpn_orbit.runtime.protocol import canonical, checksum
from vpn_orbit.runtime.recovery import quarantine_state, remap_vault, swap_entries
from vpn_orbit.runtime.vault import Vault
from vpn_orbit.worker import Worker


class RecoveryTests(unittest.TestCase):
    def test_portable_vault_rewraps_consumer_binding_for_destination_uid(self):
        import hashlib
        import json

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = bytes(range(32))
            credential = root / "dek"
            credential.write_bytes(key)
            credential.chmod(0o600)
            vault = Vault.initialize(root / "vault", credential)
            consumer = 24001
            info = {"allowed_consumers": [consumer], "allowed_consumers_digest": checksum([consumer])}
            old = bytes(Aead(key).encrypt(b"fixture-content", canonical(info)))
            digest = hashlib.sha256(old).hexdigest()
            (vault.directory / "objects" / digest).write_bytes(old)
            with vault.journal.write() as db:
                db.execute("INSERT INTO secrets VALUES ('fixture', ?, ?, 'ACTIVE')", (canonical(info).decode(), digest))
            remap_vault(vault.directory, key, {"worker_uid": consumer, "broker_uid": 24002},
                        {"worker_uid": 23001, "broker_uid": 23002})
            with vault.journal.connect() as db:
                row = db.execute("SELECT metadata,object_digest FROM secrets").fetchone()
            updated = json.loads(row["metadata"])
            self.assertEqual(updated, {"allowed_consumers": [23001], "allowed_consumers_digest": checksum([23001])})
            self.assertFalse((vault.directory / "objects" / digest).exists())
            restored = (vault.directory / "objects" / row["object_digest"]).read_bytes()
            self.assertEqual(Aead(key).decrypt(restored, canonical(updated)), b"fixture-content")

    def test_quarantine_preserves_incidents_and_audit_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = Store.initialize(root / "app/controller.sqlite3")
            policy = Policy([])
            gate = Authority.initialize(root / "control-gate", policy)
            gate.close()
            Broker.initialize(root / "broker", policy)
            actor, target = identifier(), identifier()
            queued, claimed, historical = identifier(), identifier(), identifier()
            queue = JobQueue(store, clock=lambda: 100)
            queue.register_resource(target, "f" * 64, 1)
            with store.write() as db:
                db.execute("INSERT INTO users VALUES(?, 'owner', 'fixture', 1, 'Owner', 0, 1, 100, 100)", (actor,))
                for job in (queued, claimed, historical):
                    queue._enqueue_mutation(db, job, actor, target, "f" * 64, 1, "c" * 64, "docker.restart")
                queue._finish(db, db.execute("SELECT * FROM jobs WHERE id=?", (historical,)).fetchone(),
                              "UNKNOWN_OUTCOME", "WORKER_RESTART")
                db.execute("UPDATE jobs SET claimed_by=? WHERE id=?", (identifier(), claimed))
                db.execute("INSERT INTO sessions VALUES(?, ?, ?, 100, 100)", (bytes(32), actor, bytes(32)))
                db.execute("INSERT INTO request_keys VALUES(?, 'fixture', 'idempotency', ?, ?, 1000)",
                           (actor, "c" * 64, claimed))
            quarantine_state(root, policy, identifier(), "b" * 64)
            hold = Admission(root / "writer-admission", owner=os.geteuid())
            self.assertEqual(hold.state()["phase"], "READ_ONLY_RECOVERY")
            with self.assertRaisesRegex(Denied, "RECOVERY_ACTIVATION_REQUIRED"):
                hold.publish("OPEN")
            store.writers = hold
            with self.assertRaisesRegex(Denied, "WRITER_ADMISSION_CLOSED"):
                queue.claim(identifier())
            worker = Worker(queue, None, None, secret_refs={})
            with patch.object(worker.restart, "reconcile_pending") as reconcile:
                self.assertFalse(worker.run_one())
                reconcile.assert_not_called()
            with store.read() as db:
                self.assertEqual(dict(db.execute("SELECT id,status FROM jobs")), {
                    queued: "CANCELLED_SAFE", claimed: "UNKNOWN_OUTCOME", historical: "UNKNOWN_OUTCOME"})
                self.assertEqual(db.execute("SELECT count(*) FROM job_incidents").fetchone()[0], 2)
                self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT count(*) FROM request_keys").fetchone()[0], 1)
            store.verify_audit()
            with closing(sqlite3.connect(root / "control-gate/gate.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT activated,state FROM gate").fetchone(), (0, "RECOVERY_HOLD"))

    def test_data_swap_resumes_after_first_rename_without_losing_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live, work = root / "live", root / "transaction"
            live.mkdir()
            (work / "next").mkdir(parents=True)
            (work / "previous").mkdir()
            (live / "state").write_text("original")
            (work / "next/state").write_text("restored")
            rename = os.rename

            def fail_second(source, dest):
                if source == work / "next/state":
                    raise OSError("interrupted")
                rename(source, dest)

            with patch("vpn_orbit.runtime.recovery.os.rename", side_effect=fail_second):
                with self.assertRaises(OSError):
                    swap_entries(live, work, ["state"])
            self.assertFalse((live / "state").exists())
            swap_entries(live, work, ["state"])
            swap_entries(live, work, ["state"])
            self.assertEqual((live / "state").read_text(), "restored")
            self.assertEqual((work / "previous/state").read_text(), "original")
