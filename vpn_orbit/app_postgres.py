"""Local-root PostgreSQL capture and restore for an owned product installation."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import subprocess
import tempfile
import time

from .app_lifecycle import Lifecycle, refuse
from .app_profiles import canonical
from .runtime import backup
from .runtime.storage import directory_sync


SERVICES = {"panel-db", "bot-db"}
MAGIC = b"vpn-orbit-app-postgres-v1\n"
MAX_DUMP = 4 * 1024**3


def execute(*argv, stdin=None, stdout=None, timeout=240):
    try:
        result = subprocess.run(argv, stdin=stdin, stdout=stdout if stdout is not None else subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, env=backup.ENV)
    except (OSError, subprocess.SubprocessError):
        refuse("APP_POSTGRES_COMMAND_FAILED")
    if result.returncode:
        refuse("APP_POSTGRES_COMMAND_FAILED")
    return result.stdout


def docker(*argv, **kwargs):
    return execute("/usr/bin/docker", "--host", "unix:///run/docker.sock", *argv, **kwargs)


def settings(app, service, binding):
    if service not in SERVICES:
        refuse("APP_POSTGRES_SERVICE_INVALID")
    spec, document, installation = app.configuration()
    if installation["spec_digest"] != binding or service not in document["services"] or installation["removed"]:
        refuse("APP_POSTGRES_SCOPE_MISMATCH")
    with app.journal.connect() as db:
        if db.execute("SELECT 1 FROM operations WHERE resolution IS NULL AND state IN ('DISPATCHING','UNKNOWN_OUTCOME')").fetchone():
            refuse("APP_RECONCILIATION_REQUIRED")
    inventory = app.verify_inventory(document, installation)
    database = inventory["containers"][service]["Id"]
    if not app.inspect("container", database)["State"]["Running"]:
        refuse("APP_POSTGRES_OFFLINE")
    return database, {"v": 1, "installation": app.identity, "spec_sha256": binding, "service": service,
                      "image": spec["images"]["postgres"]}, inventory


def write_encrypted(path, header, container, recipient):
    if not backup.RECIPIENT.fullmatch(recipient):
        refuse("BACKUP_RECIPIENT_UNSUPPORTED")
    destination = backup.secure_directory(path.absolute().parent, private=True) / path.name
    if os.path.lexists(destination):
        refuse("APP_POSTGRES_ARCHIVE_EXISTS")
    fd, temp = tempfile.mkstemp(prefix=".postgres-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w+b") as out, subprocess.Popen(
                [backup.AGE, "-e", "-r", recipient], env=backup.ENV,
                stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL) as encryption:
            try:
                with subprocess.Popen(
                        ["/usr/bin/docker", "--host", "unix:///run/docker.sock", "exec", container,
                         "pg_dump", "--format=custom", "--no-owner", "--no-acl", "--username=orbit", "--dbname=orbit"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=backup.ENV) as dump:
                    # Write magic and scope before streaming; never persist plaintext.
                    encryption.stdin.write(MAGIC + canonical(header) + b"\n")
                    finish = time.monotonic() + 240
                    size = 0
                    while True:
                        ready, _, _ = select.select([dump.stdout], [], [], max(0, finish - time.monotonic()))
                        if not ready:
                            dump.kill()
                            refuse("APP_POSTGRES_EXPORT_TIMED_OUT")
                        chunk = os.read(dump.stdout.fileno(), 256 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_DUMP:
                            dump.kill()
                            refuse("APP_POSTGRES_DUMP_TOO_LARGE")
                        encryption.stdin.write(chunk)
                    if dump.wait(timeout=5):
                        refuse("APP_POSTGRES_EXPORT_FAILED")
                encryption.stdin.close()
                if encryption.wait(timeout=10):
                    refuse("APP_POSTGRES_ENCRYPTION_FAILED")
            except BaseException:
                encryption.kill()
                raise
            out.flush()
            os.fsync(out.fileno())
            out.seek(0)
            sha256 = hashlib.file_digest(out, "sha256").hexdigest()
        os.link(temp, destination)
    finally:
        Path(temp).unlink(missing_ok=True)
    directory_sync(destination.parent)
    return sha256


@contextmanager
def decrypt(path, identity, expected):
    for item in (path, identity):
        backup.secure_directory(item.absolute().parent)
    with backup.open_private(path) as ciphertext, backup.open_private(identity) as private:
        if not backup.SHA256.fullmatch(expected) or hashlib.file_digest(ciphertext, "sha256").hexdigest() != expected:
            refuse("APP_POSTGRES_DIGEST_MISMATCH")
        ciphertext.seek(0)
        raw = private.read(4097)
        lines = [line for line in raw.splitlines() if line and not line.startswith(b"#")]
        if len(raw) > 4096 or len(lines) != 1 or not backup.IDENTITY.fullmatch(lines[0]):
            refuse("BACKUP_IDENTITY_UNSUPPORTED")
        private.seek(0)
        with subprocess.Popen([backup.AGE, "-d", "-i", f"/proc/self/fd/{private.fileno()}"], env=backup.ENV,
                              stdin=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              pass_fds=(private.fileno(),)) as process:
            try:
                if process.stdout.readline(64) != MAGIC:
                    refuse("APP_POSTGRES_FORMAT_INVALID")
                raw = process.stdout.readline(8192)
                if not raw.endswith(b"\n"):
                    refuse("APP_POSTGRES_FORMAT_INVALID")
                header = json.loads(raw)
                if canonical(header) + b"\n" != raw:
                    refuse("APP_POSTGRES_FORMAT_INVALID")
                yield header, process.stdout
                if process.wait(timeout=10):
                    refuse("APP_POSTGRES_DECRYPTION_FAILED")
            except BaseException:
                process.kill()
                raise


def query(container, database, sql):
    return docker("exec", container, "psql", "--no-psqlrc", "--no-align", "--tuples-only", "--username=orbit",
                  "--dbname=" + database, "--set=ON_ERROR_STOP=1", "--command", sql, timeout=20).strip().decode()


def restore(app, service, binding, path, identity, expected):
    with app.locked():
        container, scope, inventory = settings(app, service, binding)
        # The restore uses a new database. Existing PostgreSQL `orbit`, Redis,
        # and application volumes are never overwritten or promoted implicitly.
        name = "orbit_recovery_" + expected[:16] if backup.SHA256.fullmatch(expected) else None
        if name is None:
            refuse("APP_POSTGRES_DIGEST_MISMATCH")
        scratch = Path("/run")
        if execute("/usr/bin/stat", "-f", "-c", "%T", scratch).strip() != b"tmpfs":
            refuse("BACKUP_TMPFS_REQUIRED")
        with tempfile.TemporaryFile(dir=scratch) as data:
            with decrypt(path, identity, expected) as (header, stream):
                if header != scope or stream.peek(5)[:5] != b"PGDMP":
                    refuse("APP_POSTGRES_SCOPE_MISMATCH")
                total = 0
                for chunk in iter(lambda: stream.read(1024**2), b""):
                    total += len(chunk)
                    if total > MAX_DUMP:
                        refuse("APP_POSTGRES_DUMP_TOO_LARGE")
                    data.write(chunk)
            data.seek(0)
            if query(container, "postgres", f"SELECT 1 FROM pg_database WHERE datname='{name}'"):
                refuse("APP_POSTGRES_DESTINATION_EXISTS")
            query(container, "postgres", f'CREATE DATABASE "{name}" TEMPLATE template0')
            # The decrypted archive is fully authenticated before DDL. On a
            # bad restore the transaction rolls back and the named DB remains
            # reserved for manual inspection, never automatically retried.
            docker("exec", "-i", container, "pg_restore", "--exit-on-error", "--single-transaction", "--no-owner",
                   "--no-acl", "--username=orbit", "--dbname=" + name, stdin=data)
        if query(container, name, "SELECT current_database()") != name:
            refuse("APP_POSTGRES_VERIFICATION_FAILED")
        _, document, saved = app.configuration()
        if app.verify_inventory(document, saved) != inventory:
            refuse("APP_RESOURCE_DRIFT")
        return {"status": "RESTORED_ISOLATED_DATABASE", "database": name, "service": service, "sha256": expected}


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "restore"))
    parser.add_argument("--id", required=True)
    parser.add_argument("--service", choices=sorted(SERVICES), required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            refuse("LOCAL_ROOT_REQUIRED")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        backup.secure_directory(backup.AGE.parent)
        app = Lifecycle(args.id)
        if args.action == "capture":
            if not args.recipient:
                refuse("BACKUP_RECIPIENT_UNSUPPORTED")
            with app.locked():
                container, header, _ = settings(app, args.service, args.spec_sha256)
                sha256 = write_encrypted(args.archive, header, container, args.recipient)
            result = {"status": "CAPTURED", "service": args.service, "sha256": sha256}
        else:
            if not args.identity or not args.sha256:
                refuse("APP_POSTGRES_DIGEST_REQUIRED")
            result = restore(app, args.service, args.spec_sha256, args.archive, args.identity, args.sha256)
        print(json.dumps(result))
    except Exception as error:
        from .errors import Denied
        print(json.dumps({"status": "REFUSED", "code": error.code if isinstance(error, Denied) else "APP_POSTGRES_UNAVAILABLE"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
