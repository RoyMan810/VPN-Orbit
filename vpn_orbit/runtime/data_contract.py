"""The versioned data contracts used by local maintenance tools."""

from contextlib import ExitStack

from ..admission import Admission
from ..database import SCHEMA_VERSION
from ..errors import Denied
from .policy import Policy


DATABASES = {"app/controller.sqlite3": SCHEMA_VERSION, "broker/receipts.sqlite3": 1,
             "vault/vault.sqlite3": 1, "control-gate/gate.sqlite3": 1, "control-gate/time-health/time.sqlite3": 1}
FORMATS = {"runtime": 1, "targets": 1}
REQUIRED_TABLES = {
    "app/controller.sqlite3": {"users", "grants", "resources", "audit", "outbox", "jobs", "request_keys", "job_incidents"},
    "broker/receipts.sqlite3": {"receipts"},
    "vault/vault.sqlite3": {"secrets"},  # v1 also accepts the optional secret_lifecycle table.
    "control-gate/gate.sqlite3": {"gate", "attempts", "incidents"},
    "control-gate/time-health/time.sqlite3": {"state", "anchors"},
}


def require_authority_binding(db, policy):
    from .authority import host_binding

    if db.execute("SELECT policy_digest, host_binding FROM gate WHERE id=1").fetchone() != (policy.digest, host_binding()):
        raise Denied("SCHEMA_AUTHORITY_BINDING_MISMATCH")


def inspect(config, *, target_schema=SCHEMA_VERSION):
    """Read one protected view of the current database and policy contracts.

    A layout with a known forward route is compatible but requires explicit
    migration in staging. This check never rewrites a database.
    """
    from . import backup
    from .migrations import plan

    if type(target_schema) is not int or target_schema != SCHEMA_VERSION:
        raise Denied("SCHEMA_TRANSITION_UNSUPPORTED")
    backup.bound_layout(config)
    writers = Admission(config["writer_directory"])
    migrations = []
    with writers.exclusive(timeout=5), ExitStack() as reads:
        phase = writers.state()["phase"]
        policy = Policy.load(config["targets"])
        for name, expected in DATABASES.items():
            try:
                db = backup.pin_database(name, expected, config, reads)
            except Denied as error:
                if error.code == "BACKUP_SCHEMA_UNSUPPORTED":
                    raise Denied("SCHEMA_CURRENT_UNSUPPORTED") from None
                raise
            migrations.extend(step.name for step in plan(db, name))
            if name == "control-gate/gate.sqlite3":
                require_authority_binding(db, policy)
        return {"status": "COMPATIBLE", "migration": "REQUIRED" if migrations else "NOT_REQUIRED",
                "migration_steps": migrations, "databases": DATABASES, "formats": FORMATS, "writer_phase": phase}
