"""Host-only helpers run from the authenticated candidate wheel."""

import argparse
from contextlib import ExitStack, closing
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

from ..admission import Admission
from ..errors import Denied
from . import backup
from .cli import configuration
from .data_contract import inspect
from .migrations import migrate_staged
from .storage import directory_sync


def admissions(config, target):
    writers = Admission(config["writer_directory"])
    with writers.exclusive(timeout=10):
        current = writers.state()["phase"]
        if current not in ("OPEN", "RECOVERY_HOLD"):
            raise Denied("UPDATE_ADMISSION_NOT_AVAILABLE")
        if current != target:
            writers.publish(target)


def busy(config):
    with ExitStack() as stack:
        app = backup.pin_database("app/controller.sqlite3", 6, config, stack)
        gate = backup.pin_database("control-gate/gate.sqlite3", 1, config, stack)
        receipts = backup.pin_database("broker/receipts.sqlite3", 1, config, stack)
        return any(
            db.execute(statement).fetchone() is not None for db, statement in (
                (app, "SELECT 1 FROM jobs WHERE claimed_by IS NOT NULL AND status NOT IN "
                      "('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE') LIMIT 1"),
                (gate, "SELECT 1 FROM attempts WHERE state IN ('ISSUED','DISPATCHING') LIMIT 1"),
                (receipts, "SELECT 1 FROM receipts WHERE state IN ('PREPARED','DISPATCHING') LIMIT 1"),
            )
        )


def migrate(config):
    if not (backup.DATA / "update.blocked").is_file():
        raise Denied("UPDATE_NOT_FENCED")
    contract = inspect(config)
    if contract["writer_phase"] != "RECOVERY_HOLD" or busy(config):
        raise Denied("UPDATE_ADMISSION_NOT_AVAILABLE")
    if not contract["migration_steps"]:
        return {"migrations": []}
    publications = {"vps-preparation-jobs": "app/controller.sqlite3", "vault-lifecycle-audit": "vault/vault.sqlite3"}
    if any(name not in publications for name in contract["migration_steps"]):
        raise Denied("UPDATE_MIGRATION_NOT_REVERSIBLE")
    # Plan and validate all migrations on unpublished copies before replacing anything.
    with tempfile.TemporaryDirectory(prefix=".upgrade-migrate-", dir=backup.DATA) as temp, ExitStack() as reads:
        root = Path(temp)
        for name, version in backup.DBS.items():
            source = backup.pin_database(name, version, config, reads)
            output = root / name
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with closing(sqlite3.connect(output, autocommit=True)) as target:
                source.backup(target)
            source.close()
        completed = migrate_staged(root)
        for step in completed:
            relative = publications[step]
            candidate, live = root / relative, backup.DATA / relative
            with closing(sqlite3.connect(live.as_uri() + "?mode=rw", uri=True, autocommit=True)) as db:
                if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                    raise Denied("UPDATE_DATABASE_STILL_OPEN")
            for path in (candidate, live):
                if any(os.path.lexists(str(path) + suffix) for suffix in ("-wal", "-shm")):
                    raise Denied("UPDATE_DATABASE_STILL_OPEN")
            role = "app" if relative.startswith("app/") else "broker"
            os.chown(candidate, config[f"{role}_uid"], config[f"{role}_gid"])
            candidate.chmod(0o660 if role == "app" else 0o600)
            with candidate.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(candidate, live)
            directory_sync(live.parent)
    return {"migrations": completed}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("inspect", "busy", "close", "open", "migrate"):
        sub.add_parser(action)
    capture = sub.add_parser("capture")
    capture.add_argument("directory", type=Path)
    capture.add_argument("recipient")
    capture.add_argument("identity", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    fd = os.open(backup.RUN / "maintenance.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise Denied("UPDATE_COORDINATOR_REQUIRED")
    finally:
        os.close(fd)
    config = configuration(backup.CONFIG / "runtime.json")
    backup.bound_layout(config)
    if args.action == "inspect":
        result = inspect(config)
    elif args.action == "busy":
        result = {"busy": busy(config)}
    elif args.action == "migrate":
        result = migrate(config)
    elif args.action in ("open", "close"):
        admissions(config, "OPEN" if args.action == "open" else "RECOVERY_HOLD")
        result = {}
    else:
        result = backup.create(args.directory, args.recipient, age=backup.AGE, maintenance=True)
        checks = backup.verify(args.directory / result["archive"], args.identity, age=backup.AGE,
                               expected_sha256=result["sha256"])
        if checks["status"] != "VERIFIED":
            raise Denied("UPDATE_BACKUP_NOT_VERIFIED")
        result = {**result, "decryption_verified": True}
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (Denied, OSError, RuntimeError, ValueError) as exc:
        print(exc.code if isinstance(exc, Denied) else "UPDATE_RUNTIME_UNAVAILABLE", file=sys.stderr)
        raise SystemExit(1) from None
