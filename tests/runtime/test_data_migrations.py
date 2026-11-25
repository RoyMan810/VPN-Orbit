from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from vpn_orbit.database import Store, _JOBS_SCHEMA
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.migrations import Layout, Step, _apply, migrate_staged, path_to
from vpn_orbit.runtime.policy import Policy
from vpn_orbit.runtime.vault import Vault, _AUDIT_SCHEMA


class DataMigrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        Store.initialize(self.root / "app/controller.sqlite3")
        policy = Policy([])
        Authority.initialize(self.root / "control-gate", policy).close()
        Broker.initialize(self.root / "broker", policy)
        key = self.root / "key"
        key.write_bytes(bytes(32))
        key.chmod(0o600)
        vault = Vault.initialize(self.root / "vault", key)
        with vault.journal.write() as db:
            db.execute("DROP TABLE secret_lifecycle")
            db.execute("INSERT INTO secrets VALUES('fixture:v1','{}','fixture-object','ACTIVE')")
        self.path = self.root / "vault/vault.sqlite3"

    def test_legacy_vault_is_migrated_once_without_changing_existing_rows(self):
        self.assertEqual(migrate_staged(self.root), ["vault-lifecycle-audit"])
        self.assertEqual(migrate_staged(self.root), [])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(db.execute("SELECT ref,state FROM secrets").fetchall(), [("fixture:v1", "ACTIVE")])
            self.assertEqual(db.execute("SELECT name,revision_after FROM orbit_migration_history").fetchall(),
                             [("vault-lifecycle-audit", 1)])

    def test_failure_does_not_commit_ddl_or_the_history_entry(self):
        transition = Step("fixture", Layout(1), Layout(1, 1), (_AUDIT_SCHEMA, "INSERT INTO missing VALUES (1)"))
        with closing(sqlite3.connect(self.path, autocommit=True)) as db:
            with self.assertRaises(sqlite3.OperationalError):
                _apply(db, "vault/vault.sqlite3", transition)
            self.assertFalse(db.in_transaction)
            self.assertEqual(db.execute("SELECT name FROM sqlite_schema WHERE name IN "
                                        "('secret_lifecycle', 'orbit_migration_history')").fetchall(), [])
        self.assertEqual(migrate_staged(self.root), ["vault-lifecycle-audit"])

    def test_all_contracts_are_planned_before_any_migration(self):
        with closing(sqlite3.connect(self.root / "control-gate/time-health/time.sqlite3")) as db:
            db.execute("PRAGMA user_version=99")
        with self.assertRaisesRegex(Denied, "SCHEMA_TRANSITION_UNSUPPORTED"):
            migrate_staged(self.root)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_schema WHERE name='secret_lifecycle'").fetchone())

    def test_chain_requires_exact_forward_path(self):
        start, middle, end = Layout(1), Layout(2), Layout(3)
        first = Step("first", start, middle, ())
        second = Step("second", middle, end, ())
        self.assertEqual(path_to(start, end, (second, first)), [first, second])
        for edges in ((first,), (first, Step("ambiguous", start, end, ()), second),
                      (Step("cyclic", start, start, ()),)):
            with self.assertRaisesRegex(Denied, "SCHEMA_TRANSITION_UNSUPPORTED"):
                path_to(start, end, edges)

    def test_preparation_jobs_migrate_without_losing_existing_job_references(self):
        path = self.root / "app/controller.sqlite3"
        with closing(sqlite3.connect(path, autocommit=True)) as db:
            db.execute("DROP TABLE jobs")
            db.execute(_JOBS_SCHEMA.replace(",'host.prepare'", ""))
            db.execute("CREATE INDEX job_queue ON jobs(status,claimed_by,created_at)")
            db.execute("CREATE INDEX jobs_resource_time ON jobs(resource_id,updated_at)")
            db.execute("INSERT INTO users VALUES('owner','owner','unused',1,'Owner',0,1,0,0)")
            db.execute("INSERT INTO resources VALUES('target','scope',1,1,1,0,0)")
            db.execute("""INSERT INTO jobs(id,actor_id,resource_id,action,payload_hash,scope_digest,policy_revision,
                          status,created_at,updated_at) VALUES('job','owner','target','host.probe','hash','scope',1,'UNKNOWN_OUTCOME',0,0)""")
            db.execute("INSERT INTO request_keys VALUES('owner','host.probe','request','hash','job',1000)")
            db.execute("INSERT INTO job_incidents VALUES('incident','job','OPEN',0)")
        self.assertEqual(migrate_staged(self.root), ["vps-preparation-jobs", "vault-lifecycle-audit"])
        self.assertEqual(migrate_staged(self.root), [])
        with closing(sqlite3.connect(path, autocommit=True)) as db:
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute("SELECT job_id FROM request_keys").fetchall(), [("job",)])
            self.assertEqual(db.execute("SELECT job_id FROM job_incidents").fetchall(), [("job",)])
            self.assertEqual(db.execute("SELECT action,status FROM jobs").fetchall(), [("host.probe", "UNKNOWN_OUTCOME")])
            db.execute("UPDATE jobs SET action='host.prepare' WHERE id='job'")
