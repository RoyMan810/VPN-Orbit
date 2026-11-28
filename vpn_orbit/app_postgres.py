"""Local-root PostgreSQL capture and restore for an owned product installation."""

from contextlib import contextmanager
from importlib.resources import files
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import resource
import select
import subprocess
import tempfile
import time
from urllib.parse import unquote, urlsplit

from .app_adoption import ExternalLifecycle, attached_networks
from .app_lifecycle import Lifecycle, refuse
from .app_profiles import canonical, digest
from .runtime import backup
from .runtime.storage import directory_sync, new_private_file, protected_bytes


APPLICATION_ROLES = {"panel-db": "remnawave-panel", "bot-db": "bedolaga-bot"}
SERVICES = APPLICATION_ROLES.keys()
MAGIC = b"vpn-orbit-app-postgres-v1\n"
MAX_DUMP = 4 * 1024**3
POSTGRES_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")
POSTGRES_ENV = ("env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "PGPASSFILE=/dev/null")


def execute(*argv, stdin=None, input_data=None, stdout=None, timeout=240):
    try:
        result = subprocess.run(argv, stdin=stdin, input=input_data, stdout=stdout if stdout is not None else subprocess.PIPE,
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


def panel_database(url):
    if not isinstance(url, str) or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    try:
        parsed = urlsplit(url)
        database, role, alias = parsed.path.removeprefix("/"), parsed.username, parsed.hostname
        password = unquote(parsed.password or "", errors="strict")
        if (parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname
                or parsed.port not in (None, 5432) or parsed.query or parsed.fragment
                or not isinstance(role, str) or not POSTGRES_NAME.fullmatch(role)
                or not POSTGRES_NAME.fullmatch(database)
                or any(char in password for char in ("\n", "\r", "\x00"))):
            refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    except ValueError:
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    return database, role, alias, password


def local_postgres(tool, database, role, *, host="/var/run/postgresql"):
    return (*POSTGRES_ENV, tool, "--host=" + host, "--port=5432", "--no-password",
            "--username=" + role, "--dbname=" + database)


def pinned_container(app, pinned):
    actual = app.inspect("container", pinned["Id"])
    if (app.stable(actual, expected=pinned["configuration"]) !=
            {key: pinned[key] for key in ("Id", "configuration")}
            or actual["State"].get("StartedAt") != pinned["started_at"]
            or digest(attached_networks(actual)) != pinned["network_bindings"]):
        refuse("APP_RESOURCE_DRIFT")
    return actual


def database_endpoints(application, postgres, alias):
    source = attached_networks(application)
    endpoints = [(source[name], endpoint) for name, endpoint in attached_networks(postgres).items()
                 if name in source and endpoint.get("NetworkID") == source[name].get("NetworkID")
                 and alias in (endpoint.get("Aliases") or [])]
    if len(endpoints) != 1:
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    return endpoints[0]


def endpoint_ipv4(endpoint):
    if endpoint.get("GlobalIPv6Address"):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    try:
        return str(IPv4Address(endpoint.get("IPAddress")))
    except ValueError:
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")


def postgres_identity(container, database, role, address, password):
    options = ("--no-psqlrc", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
               "--command", """SELECT current_database(), current_user, oid,
                   (pg_catalog.pg_control_system()).system_identifier
                   FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()""")
    identity = docker("exec", container, *local_postgres("psql", database, role), *options, timeout=20)
    # Pass the existing credential on stdin, avoiding command arguments and Docker exec settings.
    command = local_postgres("psql", database, role, host=address)
    tcp = docker("exec", "-i", container, *POSTGRES_ENV, "sh", "-c",
                 'IFS= read -r PGPASSWORD || exit 1; export PGPASSWORD; exec "$@"', "sh",
                 *command[len(POSTGRES_ENV):], *options,
                 input_data=(password + "\n").encode(), timeout=20)
    fields = identity.decode().strip().split("|")
    if (tcp != identity or len(fields) != 4 or fields[:2] != [database, role]
            or any(not item.isascii() or not item.isdecimal() for item in fields[2:])):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    return fields[2:]


def container_env(container):
    return dict(entry.split("=", 1) for entry in container["Config"]["Env"])


def bedolaga_database(application, postgres):
    env = container_env(application)
    database, role = env.get("POSTGRES_DB", ""), env.get("POSTGRES_USER", "")
    if (env.get("DATABASE_URL") or env.get("DATABASE_READ_REPLICA_URL")
            or env.get("DATABASE_MODE") not in ("postgresql", "auto")
            or not POSTGRES_NAME.fullmatch(database) or not POSTGRES_NAME.fullmatch(role)):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    source, _ = database_endpoints(application, postgres, env.get("POSTGRES_HOST"))
    client = endpoint_ipv4(source)
    administrator = container_env(postgres).get("POSTGRES_USER", "postgres")
    if not POSTGRES_NAME.fullmatch(administrator):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    # The pinned Bedolaga primary engine identifies its sessions as remnawave_bot.
    # Observe that connection in the cluster used by pg_dump instead of inferring a DSN.
    rows = docker("exec", postgres["Id"], *local_postgres("psql", "postgres", administrator),
                  "--no-psqlrc", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
                  "--command", f"""SELECT datname, usename, datid, usesysid,
                         (pg_catalog.pg_control_system()).system_identifier,
                         bool_or(application_name='remnawave_bot')
                         FROM pg_catalog.pg_stat_activity
                         WHERE backend_type='client backend' AND client_addr='{client}'
                           AND NOT pg_catalog.pg_is_in_recovery()
                         GROUP BY datname, usename, datid, usesysid""", timeout=20).decode().splitlines()
    fields = rows[0].split("|") if len(rows) == 1 else []
    if (len(fields) != 6 or fields[:2] != [database, role] or fields[5] != "t"
            or any(not item.isascii() or not item.isdecimal() for item in fields[2:5])):
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")
    return fields[:5]


def adopted_scope(app, service, binding):
    if service not in APPLICATION_ROLES:
        refuse("APP_POSTGRES_SERVICE_INVALID")
    definition = app.definition()
    with app.journal.connect() as db:
        installation = db.execute("SELECT spec_digest,inventory FROM installation WHERE id=1").fetchone()
        if (installation is None or installation["inventory"] is None
                or installation["spec_digest"] != binding or digest(definition) != binding):
            refuse("APP_POSTGRES_SCOPE_MISMATCH")
        if db.execute("SELECT 1 FROM operations WHERE state IN ('DISPATCHING','UNKNOWN_OUTCOME')").fetchone():
            refuse("APP_RECONCILIATION_REQUIRED")
        registration = db.execute("""SELECT id FROM operations WHERE action='adopt' AND state='SUCCEEDED'
                                     ORDER BY rowid DESC LIMIT 1""").fetchone()
        if registration is None:
            refuse("APP_POSTGRES_SCOPE_MISMATCH")
    inventory = json.loads(installation["inventory"])
    if app.capture(definition["layout"], expected=inventory) != inventory:
        refuse("APP_RESOURCE_DRIFT")
    name = next((name for name, role in inventory["roles"].items() if role == APPLICATION_ROLES[service]), None)
    if name is None:
        refuse("APP_POSTGRES_SERVICE_INVALID")
    peers = [peer for peer in inventory["dependencies"][name] if inventory["roles"][peer] == "postgres"]
    if len(peers) != 1:
        refuse("APP_POSTGRES_SOURCE_UNVERIFIED")

    application = pinned_container(app, inventory["containers"][name])
    postgres = pinned_container(app, inventory["containers"][peers[0]])
    container = postgres["Id"]
    extra_scope = {}
    if service == "panel-db":
        database, role, alias, password = panel_database(container_env(application).get("DATABASE_URL"))
        _, target = database_endpoints(application, postgres, alias)
        database_oid, cluster = postgres_identity(container, database, role, endpoint_ipv4(target), password)
    else:
        database, role, database_oid, role_oid, cluster = bedolaga_database(application, postgres)
        extra_scope["role_oid"] = role_oid
    catalog = json.loads(files("vpn_orbit").joinpath("application-images.json").read_text(encoding="utf-8"))
    return container, {"v": 1, "installation": app.identity, "spec_sha256": binding, "service": service,
                       "source": "adopted", "registration": registration["id"], "database": database,
                       "role": role, "database_oid": database_oid, "cluster": cluster,
                       "image": catalog["images"]["postgres"], **extra_scope}


def capture(app, service, binding, path, recipient):
    with app.locked():
        if not isinstance(app, ExternalLifecycle):
            container, scope, _ = settings(app, service, binding)
            return write_encrypted(path, scope, container, recipient)
        container, scope = adopted_scope(app, service, binding)

        def verify():
            if adopted_scope(app, service, binding) != (container, scope):
                refuse("APP_RESOURCE_DRIFT")

        return write_encrypted(path, scope, container, recipient, verify=verify)


def write_encrypted(path, header, container, recipient, *, verify=None):
    if not backup.RECIPIENT.fullmatch(recipient):
        refuse("BACKUP_RECIPIENT_UNSUPPORTED")
    destination = backup.secure_directory(path.absolute().parent, private=True) / path.name
    if os.path.lexists(destination):
        refuse("APP_POSTGRES_ARCHIVE_EXISTS")
    command = ("pg_dump", "--username=orbit", "--dbname=orbit")
    if header.get("source") == "adopted":
        command = local_postgres("pg_dump", header["database"], header["role"])
    fd, temp = tempfile.mkstemp(prefix=".postgres-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w+b") as out, subprocess.Popen(
                [backup.AGE, "-e", "-r", recipient], env=backup.ENV,
                stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL) as encryption:
            try:
                with subprocess.Popen(
                        ["/usr/bin/docker", "--host", "unix:///run/docker.sock", "exec", container,
                         *command, "--format=custom", "--no-owner", "--no-acl"],
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
        if verify is not None:
            verify()
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


def database_oid(container, name):
    value = query(container, "postgres", f"SELECT oid FROM pg_database WHERE datname='{name}'")
    if not value:
        return None
    if not value.isascii() or not value.isdecimal():
        refuse("APP_POSTGRES_VERIFICATION_FAILED")
    return int(value)


def assessment(app, service, checksum):
    if not backup.SHA256.fullmatch(checksum):
        refuse("APP_POSTGRES_DIGEST_MISMATCH")
    return app.directory / f"postgres-{service}-{checksum}.json"


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
        evidence = {"v": 1, "scope": scope, "archive_sha256": expected, "restored_oid": database_oid(container, name),
                    "original_oid": database_oid(container, "orbit")}
        if None in (evidence["restored_oid"], evidence["original_oid"]):
            refuse("APP_POSTGRES_VERIFICATION_FAILED")
        new_private_file(assessment(app, service, expected), canonical(evidence))
        return {"status": "RESTORED_ISOLATED_DATABASE", "database": name, "service": service, "sha256": expected}


def promote(app, service, binding, expected):
    with app.locked():
        container, scope, inventory = settings(app, service, binding)
        path = assessment(app, service, expected)
        evidence = json.loads(protected_bytes(path, owner=0, exact_mode=0o600, maximum=8192))
        if evidence.get("v") != 1 or evidence.get("scope") != scope or evidence.get("archive_sha256") != expected:
            refuse("APP_POSTGRES_SCOPE_MISMATCH")
        for service_name, entry in inventory["containers"].items():
            if service_name not in SERVICES and app.inspect("container", entry["Id"])["State"]["Running"]:
                refuse("APP_POSTGRES_STOP_APPLICATION_FIRST")
        staged = "orbit_recovery_" + expected[:16]
        prior = "orbit_previous_" + expected[:16]
        before = (evidence["original_oid"], evidence["restored_oid"], None)
        after = (evidence["restored_oid"], None, evidence["original_oid"])

        def state():
            return tuple(database_oid(container, name) for name in ("orbit", staged, prior))

        actual = state()
        if actual == before:
            # Renames fail if any connection is still using either database;
            # PostgreSQL rolls back the entire publication in that case.
            query(container, "postgres", f'BEGIN; ALTER DATABASE "orbit" RENAME TO "{prior}"; '
                  f'ALTER DATABASE "{staged}" RENAME TO "orbit"; COMMIT;')
        elif actual != after:
            refuse("APP_POSTGRES_DATABASE_DRIFT")
        if state() != after or query(container, "orbit", "SELECT current_database()") != "orbit":
            refuse("APP_POSTGRES_VERIFICATION_FAILED")
        return {"status": "PROMOTED", "service": service, "sha256": expected, "previous_database": prior}


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "restore", "promote"))
    parser.add_argument("--id", required=True)
    parser.add_argument("--service", choices=sorted(SERVICES), required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--archive", type=Path)
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
        if os.path.lexists(app.directory / "external.json"):
            if args.action != "capture":
                refuse("APP_POSTGRES_ADOPTED_CAPTURE_ONLY")
            app = ExternalLifecycle(args.id)
        if args.action == "capture":
            if not (args.recipient and args.archive):
                refuse("BACKUP_RECIPIENT_UNSUPPORTED")
            sha256 = capture(app, args.service, args.spec_sha256, args.archive, args.recipient)
            result = {"status": "CAPTURED", "service": args.service, "sha256": sha256}
        elif args.action == "restore":
            if not (args.identity and args.sha256 and args.archive):
                refuse("APP_POSTGRES_DIGEST_REQUIRED")
            result = restore(app, args.service, args.spec_sha256, args.archive, args.identity, args.sha256)
        else:
            if not args.sha256:
                refuse("APP_POSTGRES_DIGEST_REQUIRED")
            result = promote(app, args.service, args.spec_sha256, args.sha256)
        print(json.dumps(result))
    except Exception as error:
        from .errors import Denied
        print(json.dumps({"status": "REFUSED", "code": error.code if isinstance(error, Denied) else "APP_POSTGRES_UNAVAILABLE"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
