"""Exercise Web preparation against Debian 13 OpenSSH on a disposable CI runner."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from unittest.mock import Mock, patch

import asyncssh
from fastapi.testclient import TestClient

from tests.runtime.test_preparation_job import preparation_runtime
from vpn_orbit.api import create_app
from vpn_orbit.auth import AuthService
from vpn_orbit.config import Settings
from vpn_orbit.database import Store, identifier
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.ipc import Peer
from vpn_orbit.runtime.policy import Policy
from vpn_orbit.runtime.preparation_progress import PREPARATION_STEPS
from vpn_orbit.runtime.protocol import PARTIAL_PREPARATION
from vpn_orbit.runtime.ssh_preparation import PreparationSSH


ORIGIN = "https://vpn-orbit.test"
DOCKERFILE = Path(__file__).with_name("Dockerfile.debian-preparation")


def docker(*args, **options):
    return subprocess.run(["docker", *args], check=True, text=True, timeout=180, **options)


def verify_preparation(root, name, ip, password):
    host_key = docker("exec", name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub", capture_output=True).stdout
    policy = Policy([{
        "id": identifier(), "ip": ip, "port": 22, "allowed_cidrs": [ip + "/32"],
        "host_key": " ".join(host_key.split()[:2]), "secret_ref": identifier() + ":v1",
        "policy_revision": 1, "dependencies": [], "capabilities": ["host.probe", "host.prepare"],
    }])
    target, = policy.targets.values()
    store = Store.initialize(root / "app" / "controller.sqlite3")
    auth = AuthService(store)
    owner_password = secrets.token_urlsafe(32)
    owner = auth.create_owner(auth.issue_bootstrap(), "fixture-owner", owner_password)
    key = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh")
    queue, authority, broker, worker = preparation_runtime(root, policy, owner, key, store=store)
    broker.web_preparation_targets = frozenset({target.id})
    api_broker = Mock(call=lambda op, data: broker.dispatch("preparation-api", Peer(1, 11003, 11004), op, data))
    app = create_app(Settings(store.path, ORIGIN), auth=auth, preparation_broker=api_broker,
                     preparation_catalog=policy.enrollment_catalog(ssh_endpoints=True, preparation=True))
    try:
        with TestClient(app, base_url=ORIGIN) as client:
            login = client.post("/api/v1/auth/login", json={"username": "fixture-owner", "password": owner_password},
                                headers={"Origin": ORIGIN})
            assert login.status_code == 200, login.text
            body = {"ip": ip, "username": "fixtureadmin", "fingerprint": target.fingerprint, "password": password}
            headers = {"Origin": ORIGIN, "X-CSRF-Token": login.json()["csrf_token"], "Idempotency-Key": identifier()}
            preflight = client.post("/api/v1/enrollment/ssh/preflight", json=body, headers=headers)
            assert preflight.status_code == 200, preflight.text
            assert preflight.json() == {"platform": "DEBIAN_13", "ssh": "VERIFIED"}, preflight.text
            queued = client.post("/api/v1/enrollment/preparation", json=body, headers=headers)
            assert queued.status_code == 202, queued.text
            original_id = queued.json()["id"]
            real_phase = PreparationSSH.phase

            async def lost_reply(transport, phase, *, inspect):
                result = await real_phase(transport, phase, inspect=inspect)
                if phase == "helpers":
                    assert inspect and result == "INCOMPLETE"
                    raise Denied("VPS_PREPARATION_SSH_UNCONFIRMED")
                return result

            with patch.object(PreparationSSH, "phase", lost_reply):
                assert worker.run_one()
            assert authority.status(original_id)["state"] == "UNKNOWN_OUTCOME"
            assert client.get(queued.headers["location"]).json()["preparation"] == {"phase": "helpers", "stage": "CHECKING"}
            job_id = identifier()
            receipt = broker.dispatch("local-root", Peer(1, 0, 0), "prepare.resume", {
                "job_id": original_id, "successor_id": job_id, "target": target.id, "actor_id": owner,
                "scope_digest": target.scope_digest, "username": "fixtureadmin", "password": password, "private_key": None,
            })
            assert receipt["result_code"] == PARTIAL_PREPARATION, receipt
            resumed = queue.resume_preparation(original_id, target, receipt, job_id)
            assert resumed["status"] == "QUEUED" and resumed["id"] == job_id
            assert not client.get(f"/api/v1/resources/{target.id}").json()["enabled"]
            assert worker.run_one()
            current = client.get(f"/api/v1/jobs/{job_id}")
            assert current.status_code == 200, current.text
            assert current.json()["status"] == "SUCCEEDED", current.text
            assert current.json()["preparation"] == {"phase": "access", "stage": "VERIFIED"}, current.text
            assert authority.status(job_id)["state"] == "SUCCEEDED"
            assert client.get(f"/api/v1/resources/{target.id}").json()["enabled"] is True
            with queue.store.read() as db:
                completed = db.execute("""SELECT json_extract(details,'$.phase') FROM audit WHERE correlation_id=?
                                          AND event='job.preparation_phase' AND outcome='VERIFIED' ORDER BY seq""", (job_id,))
                assert tuple(row[0] for row in completed) == PREPARATION_STEPS
            store.verify_audit()
    finally:
        authority.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    args = parser.parse_args()
    if (not args.isolated_vm or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    name = "vpn-orbit-debian-" + secrets.token_hex(6)
    image = name + ":fixture"
    try:
        docker("build", "--platform", "linux/amd64", "--tag", image, "-", input=DOCKERFILE.read_text())
        docker("network", "create", "--internal", name)
        docker("run", "--detach", "--name", name, "--network", name, "--privileged", "--cgroupns=private",
               "--env", "container=docker", "--tmpfs", "/run", "--tmpfs", "/tmp", image)
        for _ in range(40):
            ready = subprocess.run(["docker", "exec", name, "systemctl", "is-active", "--quiet", "ssh.service"],
                                   capture_output=True, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Debian OpenSSH service did not start")
        ip = docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name,
                    capture_output=True).stdout.strip()
        password = secrets.token_urlsafe(32)
        docker("exec", "-i", name, "chpasswd", input=f"fixtureadmin:{password}\n")
        with tempfile.TemporaryDirectory(prefix="vpn-orbit-debian-") as temp:
            verify_preparation(Path(temp), name, ip, password)
        print("Debian 13: Web preflight, partial preparation, verified resume and both SSH logins passed.")
    except Exception:
        subprocess.run(["docker", "logs", "--tail", "45", name], timeout=15, check=False)
        raise
    finally:
        for command in (("rm", "--force", name), ("network", "rm", name), ("image", "rm", image)):
            subprocess.run(["docker", *command], timeout=20, check=False, capture_output=True)


if __name__ == "__main__":
    main()
