"""Real product effects through pinned SSH, Broker and durable Controller jobs."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from vpn_orbit.application_requests import approve, enqueue, reconcile, save
from vpn_orbit.app_lifecycle import Lifecycle, ROOT
from vpn_orbit.app_profiles import digest
from vpn_orbit.auth import AuthService
from vpn_orbit.database import Store
from vpn_orbit.errors import Denied
from vpn_orbit.queue import JobQueue
from vpn_orbit.runtime.authority import Authority
from vpn_orbit.runtime.broker import Broker
from vpn_orbit.runtime.ipc import Peer
from vpn_orbit.runtime.policy import Policy
from vpn_orbit.runtime.ssh import application
from vpn_orbit.runtime.storage import new_private_file
from vpn_orbit.runtime.timehealth import TimeHealth
from vpn_orbit.runtime.vault import Vault
from vpn_orbit.worker import Worker

from .application_lifecycle import IDENTITY


ACCOUNT = "vpn-orbit-apps"
REPOSITORY = Path(__file__).resolve().parents[2]
WORKER_UID = 11001
BROKER_UID = 11002
SECRET = IDENTITY[:-1] + "S"
ACTOR = IDENTITY[:-1] + "T"


class Direct:
    """Exercise the actual Authority/Broker dispatch handlers with fixture peers."""

    def __init__(self, function):
        self.call = function


class FixtureCrash(BaseException):
    """Interrupt fixture handlers without running their normal error handling."""


def run(*argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, capture_output=True, timeout=60, **kwargs)


def ssh_acceptance():
    if ROOT.exists():
        raise RuntimeError("Application fixture namespace exists")
    with tempfile.TemporaryDirectory(prefix="vo-app-ssh-", dir="/run") as location, ExitStack() as cleanup:
        lab = Path(location)
        lab.chmod(0o755)
        if Path("/opt/vpn-orbit").exists() or Path("/usr/local/libexec/vpn-orbit").exists():
            raise RuntimeError("Fixture code namespace exists")
        if subprocess.run(["getent", "passwd", ACCOUNT], capture_output=True).returncode == 0:
            raise RuntimeError("Fixture account exists")
        account_created = False
        try:
            Path("/opt/vpn-orbit/venv/bin").mkdir(parents=True, mode=0o755)
            code = Path("/opt/vpn-orbit/code")
            shutil.copytree(REPOSITORY / "vpn_orbit", code / "vpn_orbit")
            for item in code.rglob("*"):
                item.chmod(0o755 if item.is_dir() else 0o644)
            code.chmod(0o755)
            # The helper has root-owned fixed code and no request-controlled paths.
            executable = Path("/opt/vpn-orbit/venv/bin/vpn-orbit-app-helper")
            executable.write_text(
                f"#!{sys.executable} -I\nimport sys\nsys.path.insert(0,{str(code)!r})\n"
                "from vpn_orbit.app_helper import main\nraise SystemExit(main())\n")
            executable.chmod(0o755)
            helper = Path("/usr/local/libexec/vpn-orbit")
            helper.mkdir(parents=True, mode=0o755)
            shutil.copyfile(REPOSITORY / "remote/apps-gateway", helper / "apps-gateway")
            (helper / "apps-gateway").chmod(0o755)
            run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/",
                "--shell", "/bin/sh", "--password", "*", ACCOUNT)
            account_created = True
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", lab / "key")
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", lab / "host")
            (lab / "authorized").write_bytes((lab / "key.pub").read_bytes())
            (lab / "authorized").chmod(0o644)
            sudoers = Path("/etc/sudoers.d/vpn-orbit-app-lab")
            if sudoers.exists():
                raise RuntimeError("Fixture sudo rule exists")
            sudoers.write_text(f'{ACCOUNT} ALL=(root) NOPASSWD: {executable} ""\n')
            sudoers.chmod(0o440)
            cleanup.callback(sudoers.unlink)
            run("visudo", "-cf", sudoers)
            addresses = json.loads(run("ip", "-4", "-j", "addr", "show", "scope", "global").stdout)
            ip = next(info["local"] for item in addresses for info in item["addr_info"])
            cfg = lab / "sshd.conf"
            cfg.write_text(f"""Port 2229
ListenAddress {ip}
HostKey {lab}/host
PidFile {lab}/sshd.pid
AuthorizedKeysFile {lab}/authorized
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes yes
AllowUsers {ACCOUNT}
ForceCommand {helper}/apps-gateway
DisableForwarding yes
PermitTTY no
PermitUserRC no
LogLevel ERROR
""")
            Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
            sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(cfg)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cleanup.callback(lambda: sshd.wait(timeout=5))
            cleanup.callback(sshd.terminate)
            for _ in range(50):
                try:
                    with socket.create_connection((ip, 2229), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            images = json.loads((REPOSITORY / "vpn_orbit/application-images.json").read_text())["images"]
            import secrets
            spec = {"v": 1, "id": ACTOR, "profiles": ["remnawave-panel"],
                    "images": {name: images[name] for name in ("remnawave-panel", "postgres", "redis")},
                    "settings": {"remnawave-panel": {"database_password": secrets.token_hex(32),
                                 "app_secret": secrets.token_hex(32), "metrics_password": secrets.token_hex(32),
                                 "domain": "panel.test.invalid", "subscription_domain": "sub.test.invalid"}}}
            Lifecycle.configure(spec)
            target = {"id": IDENTITY, "ip": ip, "port": 2229, "allowed_cidrs": [ip + "/32"],
                      "host_key": " ".join((lab / "host.pub").read_text().split()[:2]),
                      "secret_ref": (IDENTITY[:-1] + "V") + ":v1", "application_secret_ref": SECRET + ":v1",
                      "capabilities": ["host.probe", "apps.lifecycle"], "policy_revision": 1,
                      "dependencies": [], "applications": {ACTOR: digest(spec)}}
            policy = Policy([target])
            store = Store.initialize(lab / "app/controller.sqlite3")
            auth = AuthService(store)
            password = secrets.token_urlsafe(40)
            owner = auth.create_owner(auth.issue_bootstrap(), "staging-owner", password)
            tokens = auth.login("staging-owner", password, ip="lab", correlation=ACTOR)[0]
            queue = JobQueue(store)
            queue.register_resource(IDENTITY, policy.targets[IDENTITY].scope_digest, 1)
            # Deterministic source only in this lab. Native real-daemon TimeHealth
            # faults remain covered by their independent disposable workflows.
            class Watch:
                def changed(self):
                    return False
                def close(self):
                    pass
            def clock():
                return {"wall_ns": time.time_ns(), "tick_ns": time.monotonic_ns(), "mono_ns": time.monotonic_ns(),
                        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
            def source():
                return {"source": "chrony", "last_sync_utc": time.time(), "offset_ms": 0, "max_error_ms": 10,
                        "rate_ppm": 500, "measurement_id": str(time.time_ns())}
            health = TimeHealth.initialize(lab / "time", source=source, clock=clock, watch=Watch())
            gate = Authority.initialize(lab / "gate", policy, time_health=health)
            cleanup.callback(lambda: gate.close())
            new_private_file(lab / "dek", os.urandom(32))
            vault = Vault.initialize(lab / "vault", lab / "dek")
            vault.import_application_ssh(SECRET, 1, (lab / "key").read_bytes(), owner_id=owner,
                                         worker_uid=WORKER_UID, target=IDENTITY)
            Broker.initialize(lab / "broker", policy)
            def open_broker():
                peer = Peer(1, BROKER_UID, BROKER_UID)
                return Broker(lab / "broker", policy, vault, Direct(lambda op, data: gate.dispatch("broker", peer, op, data)),
                              bytes(gate.key.verify_key), worker_uid=WORKER_UID)

            broker = open_broker()
            worker_peer = Peer(1, WORKER_UID, WORKER_UID)
            def open_worker():
                return Worker(queue, Direct(lambda op, data: gate.dispatch("worker", worker_peer, op, data)),
                              Direct(lambda op, data: broker.dispatch("worker", worker_peer, op, data)),
                              secret_refs={}, application_refs={IDENTITY: SECRET + ":v1"})

            worker = open_worker()

            def submit(action):
                with store.write() as db:
                    draft, tag = save(db, auth, tokens.session, tokens.csrf, IDENTITY, ACTOR, digest(spec), action)
                grant = auth.reauthenticate(tokens.session, tokens.csrf, password, draft["plan_hash"], correlation=ACTOR)
                with store.write() as db:
                    approval = approve(db, auth, tokens.session, tokens.csrf, draft["id"], tag, grant["id"])
                with store.write() as db:
                    return enqueue(db, queue, auth, tokens.session, tokens.csrf, draft["id"], tag, approval["approval_id"])

            def job_status(job):
                with store.read() as db:
                    return dict(db.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone())

            job = submit("install")
            assert job_status(job)["status"] == "QUEUED"
            assert Lifecycle(ACTOR).status()["state"] == "CONFIGURED"
            worker = open_worker()
            assert worker.run(once=True)
            job = job_status(job)
            if job["status"] != "SUCCEEDED":
                print("Application install diagnostic:", job["status"], job["reason"], flush=True)
            assert job["status"] == "SUCCEEDED", job["reason"]
            runtime = Lifecycle(ACTOR)
            _, document, installation = runtime.configuration()
            containers = runtime.verify_inventory(document, installation)["containers"]
            panel_id = containers["remnawave-panel"]["Id"]
            runtime.docker("container", "stop", panel_id)
            assert runtime.status()["state"] == "UNHEALTHY"

            def crash_after_effect(*args, **kwargs):
                result = application(*args, **kwargs)
                assert result["outcome"] == "SUCCEEDED", result["code"]
                raise FixtureCrash()

            broker.execute_application = crash_after_effect
            job = submit("start")
            try:
                worker.run_one()
            except FixtureCrash:
                pass
            else:
                raise AssertionError("Fixture did not interrupt dispatch")
            assert job_status(job)["status"] == "DISPATCHING"
            assert runtime.status()["state"] == "HEALTHY"
            started_at = runtime.inspect("container", panel_id)["State"]["StartedAt"]
            gate.close()
            gate = Authority(lab / "gate", policy, time_health=TimeHealth(lab / "time", source=source, clock=clock, watch=Watch()))
            gate.recover()
            broker = open_broker()
            broker.recover()
            worker = open_worker()
            assert not worker.run(once=True)
            assert job_status(job)["status"] == "UNKNOWN_OUTCOME"
            with store.write() as db:
                reconcile(db, queue, auth, tokens.session, tokens.csrf, job["id"], 1)
            assert worker.run_one()
            with store.read() as db:
                assert not db.execute("SELECT 1 FROM job_incidents").fetchone()
                assert db.execute("SELECT status FROM jobs WHERE id=?", (job["id"],)).fetchone()[0] == "UNKNOWN_OUTCOME"
                assert db.execute("""SELECT outcome FROM audit
                    WHERE event='application.reconciled' AND correlation_id=?""", (job["id"],)).fetchone()[0] == "RECONCILED_SUCCEEDED"
            assert runtime.inspect("container", panel_id)["State"]["StartedAt"] == started_at
            job = submit("remove")
            assert worker.run_one()
            job = job_status(job)
            assert job["status"] == "SUCCEEDED", job["reason"]
            assert Lifecycle(ACTOR).status()["state"] == "REMOVED"
            store.verify_audit()
            print("PASS actual SSH lifecycle, recovery before and after dispatch, reconciliation without replay and audit integrity.")
        finally:
            cleanup.close()
            if account_created:
                run("userdel", ACCOUNT)
            shutil.rmtree("/opt/vpn-orbit", ignore_errors=True)
            shutil.rmtree("/usr/local/libexec/vpn-orbit", ignore_errors=True)


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        ssh_acceptance()
    except Exception as error:
        import traceback
        sites = ",".join(f"{Path(frame.filename).name}:{frame.lineno}" for frame in traceback.extract_tb(error.__traceback__))
        code = error.code if isinstance(error, Denied) else type(error).__name__
        print(f"SSH acceptance diagnostic {code} at {sites}", flush=True)
        raise SystemExit("Application SSH acceptance failed") from None


if __name__ == "__main__":
    main()
