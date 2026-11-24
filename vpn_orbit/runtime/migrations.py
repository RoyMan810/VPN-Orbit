"""Known SQLite transitions, applied only to unpublished maintenance copies."""

from contextlib import closing
from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import stat

from ..errors import Denied
from .data_contract import DATABASES, REQUIRED_TABLES
from .vault import _AUDIT_SCHEMA


@dataclass(frozen=True)
class Layout:
    version: int
    revision: int = 0


@dataclass(frozen=True)
class Step:
    name: str
    before: Layout
    after: Layout
    statements: tuple[str, ...]


_VAULT = "vault/vault.sqlite3"
_VAULT_COLUMNS = {
    "ref": "TEXT", "replacement": "TEXT", "purpose": "TEXT", "target": "TEXT", "owner_id": "TEXT",
    "policy_revision": "INTEGER", "scope_digest": "TEXT", "broker_uid": "INTEGER", "recorded_at": "INTEGER",
}
TARGETS = {name: Layout(version, int(name == _VAULT)) for name, version in DATABASES.items()}
STEPS = {
    _VAULT: (Step("vault-lifecycle-audit", Layout(1), Layout(1, 1), (_AUDIT_SCHEMA,)),),
}


def layout(db, name):
    version, = db.execute("PRAGMA user_version").fetchone()
    if db.execute("PRAGMA journal_mode").fetchone() != ("wal",):
        raise Denied("SCHEMA_CURRENT_UNSUPPORTED")
    objects = dict(db.execute("SELECT name,type FROM sqlite_schema"))
    if any(objects.get(table) != "table" for table in REQUIRED_TABLES[name]):
        raise Denied("SCHEMA_CURRENT_UNSUPPORTED")
    revision = 0
    if name == _VAULT and "secret_lifecycle" in objects:
        columns = dict(db.execute("SELECT name,type FROM pragma_table_info('secret_lifecycle')"))
        fk = set(db.execute('SELECT "from", "table", "to" FROM pragma_foreign_key_list(\'secret_lifecycle\')'))
        if (objects["secret_lifecycle"] != "table" or columns != _VAULT_COLUMNS
                or fk != {("ref", "secrets", "ref"), ("replacement", "secrets", "ref")}):
            raise Denied("SCHEMA_CURRENT_UNSUPPORTED")
        revision = 1
    return Layout(version, revision)


def path_to(current, target, steps):
    result = []
    while current != target:
        routes = [step for step in steps if step.before == current]
        if len(routes) != 1:
            raise Denied("SCHEMA_TRANSITION_UNSUPPORTED")
        step, = routes
        if not (current.version, current.revision) < (step.after.version, step.after.revision) <= (target.version, target.revision):
            raise Denied("SCHEMA_TRANSITION_UNSUPPORTED")
        result.append(step)
        current = step.after
    return result


def plan(db, name):
    return path_to(layout(db, name), TARGETS[name], STEPS.get(name, ()))


def _integrity(db):
    if db.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",) or db.execute("PRAGMA foreign_key_check").fetchone():
        raise Denied("MIGRATION_DATA_INTEGRITY_FAILED")


def _apply(db, name, step):
    db.execute("BEGIN IMMEDIATE")
    try:
        if layout(db, name) != step.before:
            raise Denied("MIGRATION_SOURCE_CHANGED")
        _integrity(db)
        for sql in step.statements:
            db.execute(sql)
        db.execute(f"PRAGMA user_version={step.after.version}")
        if layout(db, name) != step.after:
            raise Denied("MIGRATION_POSTCONDITION_FAILED")
        db.execute("""CREATE TABLE IF NOT EXISTS orbit_migration_history(
            name TEXT PRIMARY KEY, version_before INTEGER NOT NULL, revision_before INTEGER NOT NULL,
            version_after INTEGER NOT NULL, revision_after INTEGER NOT NULL, applied_at INTEGER NOT NULL) STRICT""")
        db.execute("INSERT INTO orbit_migration_history VALUES(?,?,?,?,?,unixepoch())",
                   (step.name, step.before.version, step.before.revision, step.after.version, step.after.revision))
        _integrity(db)
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _file(root, name):
    current = root
    for component in Path(name).parts:
        current /= component
        info = current.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Denied("MIGRATION_STAGE_UNTRUSTED")
        if current == root / name:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Denied("MIGRATION_STAGE_UNTRUSTED")
        elif not stat.S_ISDIR(info.st_mode):
            raise Denied("MIGRATION_STAGE_UNTRUSTED")
    return current


def _connect(path, mode):
    db = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, autocommit=True, timeout=5)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
    except BaseException:
        db.close()
        raise
    return closing(db)


def migrate_staged(root):
    """Return completed transitions; never edit an installed or published tree."""
    from .backup import DATA

    root = Path(root).absolute()
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or root.resolve() != root or root == DATA or root in DATA.parents
            or (root.is_relative_to(DATA) and root.parts[len(DATA.parts)] in {
                "app", "broker", "vault", "control-gate", "writer-admission"})):
        raise Denied("MIGRATION_STAGE_UNTRUSTED")
    files = {name: _file(root, name) for name in TARGETS}
    planned = {}
    for name, path in files.items():
        with _connect(path, "ro") as db:
            planned[name] = plan(db, name)
    completed = []
    for name, steps in planned.items():
        if steps:
            with _connect(files[name], "rw") as db:
                for step in steps:
                    _apply(db, name, step)
                    completed.append(step.name)
    return completed
