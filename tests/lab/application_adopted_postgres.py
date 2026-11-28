"""Capture a running adopted Panel database and restore it in a separate cluster."""

from contextlib import ExitStack, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import traceback

from tests.lab.application_panel_node import detach, panel_api, register, start_external
from vpn_orbit.app_adoption import ExternalLifecycle
from vpn_orbit.app_lifecycle import Docker, ROOT
from vpn_orbit.app_postgres import capture, decrypt, docker as postgres_docker, local_postgres, main as cli
from vpn_orbit.errors import Denied


INSTALLATION = "01JCYQZ4T9V8MNVYEH3D2M7Q1P"


def query(container, database, role, sql):
    return postgres_docker("exec", container, *local_postgres("psql", database, role),
                           "--no-psqlrc", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
                           "--command", sql, timeout=20).decode().strip()


def require_unregistered(app, service, binding, archive, recipient):
    try:
        capture(app, service, binding, archive, recipient)
    except Denied as error:
        assert error.code == "APP_POSTGRES_SCOPE_MISMATCH"
    else:
        raise AssertionError("An unregistered database was backed up")
    assert not archive.exists()


def backup_key(private):
    keygen = os.environ["VPN_ORBIT_PG_AGE_KEYGEN"]
    identity = private / "fixture.identity"
    subprocess.run([keygen, "-o", identity], check=True, capture_output=True)
    return identity, subprocess.check_output([keygen, "-y", identity], text=True).strip()


def capture_archive(app, service, binding, archive, recipient):
    output = StringIO()
    with redirect_stdout(output):
        code = cli(["capture", "--id", app.identity, "--service", service, "--spec-sha256", binding,
                    "--archive", str(archive), "--recipient", recipient, "--confirm"])
    result = json.loads(output.getvalue())
    assert code == 0 and result["status"] == "CAPTURED", result
    assert archive.stat().st_mode & 0o777 == 0o600
    return result["sha256"]


def restore_isolated(stack, docker, private, archive, identity, sha256, expected):
    recovery = docker("run", "--detach", "--pull", "never", "--network", "none",
                      "--env", "POSTGRES_PASSWORD=" + secrets.token_hex(32), "--env", "POSTGRES_DB=orbit",
                      expected["image"]).strip()
    stack.callback(docker, "container", "rm", "--force", "--volumes", recovery)
    deadline = time.monotonic() + 90
    while True:
        try:
            docker("exec", recovery, "pg_isready", "--host", "127.0.0.1", "--dbname", "orbit")
        except Denied:
            if time.monotonic() >= deadline:
                raise RuntimeError("The separate recovery PostgreSQL did not start") from None
            time.sleep(1)
        else:
            break
    with tempfile.TemporaryFile(dir=private) as payload:
        with decrypt(archive, identity, sha256) as (header, stream):
            assert {key: header.get(key) for key in expected} == expected
            assert stream.peek(5)[:5] == b"PGDMP"
            shutil.copyfileobj(stream, payload)
        payload.seek(0)
        postgres_docker("exec", "-i", recovery, *local_postgres("pg_restore", "orbit", "postgres"),
                        "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", stdin=payload)
    return recovery


def acceptance():
    if os.path.lexists(ROOT):
        raise RuntimeError("Disposable app namespace must be absent")
    pins = json.loads((Path(__file__).resolve().parents[2] / "vpn_orbit/application-images.json").read_text())["images"]
    images = {name: pins[name] for name in ("remnawave-panel", "postgres", "redis")}
    docker = Docker()
    with ExitStack() as stack:
        source = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vo-adopted-db-", dir="/var/lib")))
        private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vo-adopted-backup-", dir="/run")))
        for image in images.values():
            docker("pull", "--platform", "linux/amd64", image, timeout=300)
        password = secrets.token_hex(32)

        def configure_default_database(document):
            postgres = document["services"]["panel-db"]
            postgres["environment"].update(POSTGRES_USER="postgres", POSTGRES_DB="postgres")
            postgres["healthcheck"]["test"] = ["CMD", "pg_isready", "-U", "postgres", "-d", "postgres"]
            panel = document["services"]["remnawave-panel"]
            panel["environment"]["DATABASE_URL"] = f"postgresql://postgres:{password}@panel-db:5432/postgres"

        layout = start_external(
            stack, docker, source, "fixture-adopted-panel", INSTALLATION, "remnawave-panel", images,
            {"database_password": password, "app_secret": secrets.token_hex(32),
             "metrics_password": secrets.token_hex(32), "domain": "panel.test.invalid",
             "subscription_domain": "sub.test.invalid"}, customize=configure_default_database,
        )
        assert isinstance(panel_api("auth/status"), dict)
        staged = ExternalLifecycle.stage(layout)
        app = ExternalLifecycle(INSTALLATION)
        before = app.capture(layout)
        primary = before["containers"]["panel-db"]["Id"]
        query(primary, "postgres", "postgres",
              "CREATE TABLE orbit_backup_fixture(value text); INSERT INTO orbit_backup_fixture VALUES('captured')")

        identity, recipient = backup_key(private)
        archive = private / "panel.age"
        require_unregistered(app, "panel-db", staged["spec_digest"], archive, recipient)
        binding = register(layout, app, staged)
        sha256 = capture_archive(app, "panel-db", binding, archive, recipient)
        assert app.capture(layout) == before
        query(primary, "postgres", "postgres", "UPDATE orbit_backup_fixture SET value='live'")
        print("PASS the root CLI captured the adopted Panel's PostgreSQL database without altering its Docker inventory.",
              flush=True)

        recovery = restore_isolated(stack, docker, private, archive, identity, sha256, {
            "source": "adopted", "registration": INSTALLATION, "spec_sha256": binding, "service": "panel-db",
            "database": "postgres", "role": "postgres", "image": images["postgres"],
        })
        assert query(recovery, "orbit", "postgres", "SELECT value FROM orbit_backup_fixture") == "captured"
        assert query(primary, "postgres", "postgres", "SELECT value FROM orbit_backup_fixture") == "live"
        assert isinstance(panel_api("auth/status"), dict)
        assert app.capture(layout) == before
        detach(app, layout, binding)
        require_unregistered(app, "panel-db", binding, private / "detached.age", recipient)
        print("PASS the archive restored in a separate networkless PostgreSQL and the source database remained live.",
              flush=True)


if __name__ == "__main__":
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        acceptance()
    except Exception as error:
        sites = ",".join(f"{Path(frame.filename).name}:{frame.lineno}" for frame in traceback.extract_tb(error.__traceback__))
        code = error.code if isinstance(error, Denied) else type(error).__name__
        print(f"Adopted PostgreSQL acceptance diagnostic {code} at {sites}", flush=True)
        raise SystemExit("Adopted PostgreSQL acceptance failed") from None
