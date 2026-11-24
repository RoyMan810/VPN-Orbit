"""The versioned data contracts used by local maintenance tools."""

from contextlib import ExitStack

from ..admission import Admission
from ..database import SCHEMA_VERSION
from ..errors import Denied
from .policy import Policy


DATABASES = {"app/controller.sqlite3": SCHEMA_VERSION, "broker/receipts.sqlite3": 1,
             "vault/vault.sqlite3": 1, "control-gate/gate.sqlite3": 1, "control-gate/time-health/time.sqlite3": 1}
FORMATS = {"runtime": 1, "targets": 1, "vault_keys": 1, "operations": 1}


def inspect(config, *, target_schema=SCHEMA_VERSION):
    """Read one protected view of the current database and policy contracts.

    There are no schema-changing transitions in this release. Only an exact
    recognized on-disk state is compatible; this tool never rewrites a DB.
    """
    from . import backup

    if type(target_schema) is not int or target_schema != SCHEMA_VERSION:
        raise Denied("SCHEMA_TRANSITION_UNSUPPORTED")
    backup.bound_layout(config)
    writers = Admission(config["writer_directory"])
    with writers.exclusive(timeout=5), ExitStack() as reads:
        phase = writers.state()["phase"]
        for name, expected in DATABASES.items():
            backup.pin_database(name, expected, config, reads)
        Policy.load(config["targets"])
        return {"status": "COMPATIBLE", "migration": "NOT_REQUIRED", "databases": DATABASES,
                "formats": FORMATS, "writer_phase": phase}
