"""Explicit local Owner authorization after independent fencing and review."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from argon2.exceptions import InvalidHashError, VerificationError

from ..admission import Admission
from ..auth import AuthService, password as validate_password, username as normalize_username
from ..database import DataAccess, Store, identifier
from ..errors import Denied
from . import backup
from .authority import host_binding
from .policy import Policy
from .protocol import canonical, checksum, fields
from .storage import directory_sync, new_private_file, process_lock, protected_bytes


def _baseline(config):
    binding = json.loads(protected_bytes(backup.DATA / "restored.json", owner=0, exact_mode=0o600))
    policy = Policy.load(config["targets"])
    value = {"v": 1, "archive_sha256": binding["archive_sha256"], "destination": host_binding(),
             "policy_sha256": policy.digest, "targets": sorted(policy.targets)}
    return binding, policy, value


def review(config):
    writers = Admission(config["writer_directory"])
    if writers.state()["phase"] != "READ_ONLY_RECOVERY":
        raise Denied("ACTIVATION_REQUIRES_QUARANTINE")
    _, _, value = _baseline(config)
    return value


def validate_review(document, expected, *, continuing=False):
    value = fields(document, ("binding", "source_fenced", "evidence", "targets", "confirmed_at"))
    if value["binding"] != expected or value["source_fenced"] is not True or not isinstance(value["evidence"], str):
        raise Denied("ACTIVATION_FENCING_REQUIRED")
    if not 1 <= len(value["evidence"]) <= 512 or not value["evidence"].isprintable():
        raise Denied("ACTIVATION_FENCING_REQUIRED")
    now = int(time.time())
    if type(value["confirmed_at"]) is not int or value["confirmed_at"] > now or (
            not continuing and value["confirmed_at"] < now - 3600):
        raise Denied("ACTIVATION_CONFIRMATION_EXPIRED")
    targets = value["targets"]
    if not isinstance(targets, dict) or set(targets) != set(expected["targets"]):
        raise Denied("ACTIVATION_INVENTORY_INCOMPLETE")
    for row in targets.values():
        fields(row, ("no_outstanding_effects", "postconditions_verified"))
        if any(item is not True for item in row.values()):
            raise Denied("ACTIVATION_RECONCILIATION_REQUIRED")
    return checksum(value)


def activate(config, report, user, password):
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    backup.bound_layout(config)
    backup.secure_directory(backup.RUN)
    writers = Admission(config["writer_directory"])
    store = Store(config["database"], access=DataAccess(config["app_uid"], config["app_gid"]))
    gate_path = Path(config["supervisor_directory"]) / "gate.sqlite3"
    pending = writers.directory / "activation.pending"
    record = backup.DATA / "activation.json"
    with process_lock(backup.RUN / "maintenance.lock"):
        if (backup.DATA / "restore.pending").exists() or (backup.DATA / "update.blocked").exists():
            raise Denied("ACTIVATION_MAINTENANCE_IN_PROGRESS")
        if writers.state()["phase"] != "READ_ONLY_RECOVERY":
            raise Denied("ACTIVATION_REQUIRES_QUARANTINE")
        binding, policy, expected = _baseline(config)
        digest = validate_review(report, expected, continuing=record.exists())
        with store.read() as db:
            owner = db.execute("SELECT * FROM users WHERE username=? AND role='Owner' AND disabled=0",
                               (normalize_username(user),)).fetchone()
        try:
            verifier = AuthService(store).hasher
            if owner is None or verifier.check_needs_rehash(owner["password_hash"]) or not verifier.verify(
                    owner["password_hash"], validate_password(password)):
                raise Denied("ACTIVATION_OWNER_AUTH_REQUIRED")
        except (InvalidHashError, VerificationError):
            raise Denied("ACTIVATION_OWNER_AUTH_REQUIRED") from None
        with writers.exclusive(timeout=10), closing(sqlite3.connect(gate_path.as_uri() + "?mode=rw", uri=True,
                                                                    autocommit=True)) as gate:
            gate.execute("PRAGMA trusted_schema=OFF")
            gate.execute("PRAGMA synchronous=FULL")
            row = gate.execute("SELECT activated,state,instance_id,host_binding,policy_digest FROM gate WHERE id=1").fetchone()
            if not row or row[3:] != (expected["destination"], policy.digest):
                raise Denied("ACTIVATION_BASELINE_CHANGED")
            if gate.execute("SELECT 1 FROM incidents LIMIT 1").fetchone() or gate.execute(
                    "SELECT 1 FROM attempts WHERE mutating=1 AND state IN ('ISSUED','DISPATCHING','UNKNOWN_OUTCOME') LIMIT 1").fetchone():
                raise Denied("ACTIVATION_RECONCILIATION_REQUIRED")
            if not os.path.lexists(record):
                if row[:2] != (0, "RECOVERY_HOLD") or os.path.lexists(pending):
                    raise Denied("ACTIVATION_BASELINE_CHANGED")
                saved = {"v": 1, "digest": digest, "instance": identifier(), "source": row[2],
                         "archive_sha256": binding["archive_sha256"], "owner_id": owner["id"]}
                new_private_file(record, canonical(saved))
            else:
                saved = json.loads(protected_bytes(record, owner=0, exact_mode=0o600))
            if (saved["digest"] != digest or saved["owner_id"] != owner["id"] or
                    saved["archive_sha256"] != binding["archive_sha256"]):
                raise Denied("ACTIVATION_BASELINE_CHANGED")
            if not os.path.lexists(pending):
                fd, path = tempfile.mkstemp(prefix=".activation-", dir=pending.parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        os.fchmod(stream.fileno(), 0o644)
                        stream.write(b"ACTIVATION_PENDING\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(path, pending)
                    directory_sync(pending.parent)
                finally:
                    Path(path).unlink(missing_ok=True)
            elif protected_bytes(pending, owner=0, maximum=32) != b"ACTIVATION_PENDING\n":
                raise Denied("ACTIVATION_BASELINE_CHANGED")
            with store.write(kind="control") as db:
                current = db.execute("SELECT revision,role,disabled FROM users WHERE id=?", (owner["id"],)).fetchone()
                if tuple(current or ()) != (owner["revision"], "Owner", 0):
                    raise Denied("ACTIVATION_OWNER_AUTH_REQUIRED")
                if db.execute("SELECT 1 FROM job_incidents LIMIT 1").fetchone() or db.execute(
                        "SELECT 1 FROM jobs WHERE status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')").fetchone():
                    raise Denied("ACTIVATION_RECONCILIATION_REQUIRED")
                resources = db.execute("SELECT id,scope_digest,policy_revision FROM resources WHERE enabled=1")
                for item in resources:
                    target = policy.targets.get(item["id"])
                    if target is None or (item["scope_digest"], item["policy_revision"]) != (target.scope_digest, target.revision):
                        raise Denied("ACTIVATION_INVENTORY_DRIFT")
                db.execute("DELETE FROM change_plan_drafts")
                db.execute("DELETE FROM reauth")
                if not db.execute("SELECT 1 FROM audit WHERE event='recovery.activated' AND correlation_id=?",
                                  (saved["instance"],)).fetchone():
                    Store.event(db, at=int(time.time()), actor=owner["id"], kind="recovery.activated", target=saved["instance"],
                                outcome="SUCCEEDED", correlation=saved["instance"],
                                details={"archive_sha256": binding["archive_sha256"], "operator_attestation_sha256": digest})
            if row[:3] == (0, "RECOVERY_HOLD", saved["source"]):
                gate.execute("BEGIN IMMEDIATE")
                gate.execute("UPDATE gate SET activated=1,state='NORMAL',instance_id=?,epoch=epoch+1,update_ticket=NULL WHERE id=1",
                             (saved["instance"],))
                gate.execute("COMMIT")
            elif row[:3] != (1, "NORMAL", saved["instance"]):
                raise Denied("ACTIVATION_BASELINE_CHANGED")
            writers._activate_verified(digest)
            pending.unlink()
            directory_sync(pending.parent)
        return {"status": "ACTIVE", "instance_id": saved["instance"], "fencing": "OWNER_ATTESTED"}
