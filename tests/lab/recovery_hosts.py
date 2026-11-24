"""Source and destination roles for two distinct disposable hosted VMs."""

import argparse
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener

import installation


ADMIN = "/opt/vpn-orbit/admin"
PYTHON = "/opt/vpn-orbit/venv/bin/python"
RUNTIME = "/opt/vpn-orbit/venv/bin/vpn-orbit-runtime"
CONFIG = "/etc/vpn-orbit/runtime.json"
ORIGIN = "https://127.0.0.1:18443"
UNITS = ("vpn-orbit-web.service", "vpn-orbit-compose.service", "vpn-orbit-broker.socket", "vpn-orbit-supervisor.socket",
         "vpn-orbit-broker.service", "vpn-orbit-supervisor.service")
TARGETS = ["01JCYQZ4T9V8MNVYEH3D2M7Q1" + suffix for suffix in ("A", "B")]
REFS = ["01JCYQZ4T9V8MNVYEH3D2M7Q1" + suffix for suffix in ("C", "D")]
run = installation.run


def host():
    return hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()


def fixture(directory):
    with tempfile.TemporaryDirectory() as temp:
        key = Path(temp) / "host"
        run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
        public = " ".join(key.with_suffix(".pub").read_text().split()[:2])
    data = [{"id": target, "ip": f"198.18.0.{number + 2}", "port": 22, "allowed_cidrs": ["198.18.0.0/24"],
             "host_key": public, "secret_ref": REFS[number] + ":v1", "dependencies": [],
             "capabilities": ["host.probe"], "policy_revision": 1} for number, target in enumerate(TARGETS)]
    (directory / "targets.json").write_text(json.dumps({"v": 1, "targets": data}))


def call(client, path, body=None, **headers):
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": ORIGIN})
    return client.open(Request(ORIGIN + path, data=json.dumps(body).encode() if body is not None else None,
                               headers=headers), timeout=10)


def login():
    context = ssl.create_default_context(cafile="/opt/vpn-orbit-bootstrap/web-ca.pem")
    client = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(CookieJar()))
    with call(client, "/api/v1/auth/login", {"username": "roman", "password": installation.PASSWORD}) as response:
        return client, json.load(response)


def source(output, recipient):
    installation.owner_create()
    client, owner = login()
    run(RUNTIME, "--config", CONFIG, "register-observations")
    with call(client, "/api/v1/users") as reply:
        etag = reply.headers["ETag"]
    grants = [{"permission": "vps:read", "resource_id": TARGETS[0]}]
    with call(client, "/api/v1/users", {"username": "operator", "password": secrets.token_urlsafe(32), "role": "Operator",
                                        "grants": grants}, **{"If-Match": etag, "X-CSRF-Token": owner["csrf_token"]}) as reply:
        operator = json.load(reply)["id"]
    cfg = json.loads(Path(CONFIG).read_bytes())
    for target, ref in zip(TARGETS, REFS, strict=True):
        with tempfile.TemporaryDirectory(dir="/run/vpn-orbit") as temp:
            directory = Path(temp)
            key = directory / "observation"
            run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
            os.chown(directory, cfg["broker_uid"], cfg["broker_gid"])
            os.chown(key, cfg["broker_uid"], cfg["broker_gid"])
            imported = run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                           "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
                           "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
                           RUNTIME, "--config", CONFIG, "import-key", "--key-file", key, "--secret-id", ref,
                           "--owner-id", owner["user"]["id"], "--target", target)
            assert imported.stdout.strip() == (ref + ":v1").encode()
    with tempfile.TemporaryDirectory(dir="/run/vpn-orbit") as temp:
        private = Path(temp)
        result = json.loads(run(ADMIN, "backup", "--directory", private, "--recipient", recipient.read_text().strip()).stdout)
        shutil.copyfile(private / result["archive"], output / "fixture.age")
    review = {"source_host": host(), "digest": result["sha256"], "owner": owner["user"]["id"], "operator": operator,
              "old_credential_sha256": hashlib.sha256(Path(cfg["vault_credential"]).read_bytes()).hexdigest()}
    run("/usr/bin/systemctl", "stop", *UNITS, timeout=100)
    for unit in UNITS:
        assert run("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", unit).stdout.strip() == b"inactive"
    (output / "fixture.json").write_text(json.dumps(review))
    print("Source VM captured encrypted synthetic state and stopped all controller units.", flush=True)


def destination(transfer, identity):
    evidence = json.loads((transfer / "fixture.json").read_bytes())
    assert host() != evidence["source_host"]
    local = json.loads(Path(CONFIG).read_bytes())
    Path("/var/lib/vpn-orbit-recovery").mkdir(mode=0o700)
    run(ADMIN, "restore-stage", "--archive", transfer / "fixture.age", "--identity", identity, "--sha256", evidence["digest"])
    run("/usr/bin/systemctl", "stop", *UNITS, timeout=100)
    run("/usr/bin/docker", "--host", "unix:///run/docker.sock", "compose", "--project-name", "vpn-orbit",
        "--file", "/etc/vpn-orbit/compose.json", "rm", "--force")
    run(ADMIN, "restore-apply", "--sha256", evidence["digest"], "--confirm-replace")
    assert hashlib.sha256(Path(local["vault_credential"]).read_bytes()).hexdigest() != evidence["old_credential_sha256"]
    run("/usr/bin/systemctl", "start", *UNITS, timeout=150)
    client, owner = login()
    assert owner["user"]["id"] == evidence["owner"]
    with call(client, "/api/v1/users/" + evidence["operator"]) as reply:
        assert json.load(reply)["grants"] == [{"permission": "vps:read", "resource_id": TARGETS[0]}]
    with call(client, "/api/v1/audit/integrity") as reply:
        assert json.load(reply)["status"] == "verified"
    binding = json.loads(run(ADMIN, "activation-review").stdout)
    assert binding["destination"] == host() and binding["targets"] == TARGETS
    vault_code = """import json,os,sys
from pathlib import Path
from vpn_orbit.runtime.vault import Vault
c=json.load(open('/etc/vpn-orbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',systemd_credential=True)
for i in (1,3):
    assert v.use_ssh(sys.argv[i]+':v1',worker_uid=c['worker_uid'],target=sys.argv[i+1]).startswith(b'-----BEGIN OPENSSH')
print('VAULT_READBACK_OK')
"""
    readback = run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                   "--property=User=" + str(local["broker_uid"]), "--property=Group=" + str(local["broker_gid"]),
                   "--property=LoadCredentialEncrypted=broker-dek:" + local["vault_credential"], PYTHON, "-c", vault_code,
                   REFS[0], TARGETS[0], REFS[1], TARGETS[1])
    assert readback.stdout.strip() == b"VAULT_READBACK_OK"
    report = {"binding": binding, "source_fenced": True, "evidence": "Source runner ended; synthetic targets did not execute any operations.",
              "confirmed_at": int(time.time()), "targets": {target: {"no_outstanding_effects": True,
                                                                   "postconditions_verified": True} for target in TARGETS}}
    code = """import json,sys
from vpn_orbit.runtime.activation import activate
from vpn_orbit.runtime.cli import configuration
value=json.load(sys.stdin)
print(json.dumps(activate(configuration('/etc/vpn-orbit/runtime.json'),value['report'],'roman',value['password'])))
"""
    assert json.loads(run(PYTHON, "-c", code, input=json.dumps({"report": report, "password": installation.PASSWORD}).encode()).stdout)["status"] == "ACTIVE"
    with call(client, "/api/v1/controller/status") as reply:
        assert json.load(reply)["admission"] == "OPEN"
    print("Fresh independent VM restored Owner, grants, target policies and keys, then activated after source shutdown.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("fixture", "source", "destination"))
    parser.add_argument("--transfer", type=Path, required=True)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Disposable GitHub-hosted VM required")
    if args.role == "fixture":
        fixture(args.transfer)
    else:
        if os.geteuid() != 0 or args.key is None:
            raise SystemExit("Root in disposable VM required")
        (source if args.role == "source" else destination)(args.transfer, args.key)


if __name__ == "__main__":
    main()
