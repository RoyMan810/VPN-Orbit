"""Source and destination roles for two distinct disposable hosted VMs."""

import argparse
from contextlib import contextmanager
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
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


def boot():
    return hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest()


def fixture(directory, key):
    public = " ".join(key.read_text().split()[:2])
    data = [{"id": target, "ip": f"198.18.0.{number + 2}", "port": 22283, "allowed_cidrs": ["198.18.0.0/24"],
             "host_key": public, "secret_ref": REFS[number] + ":v1", "dependencies": [],
             "capabilities": ["host.probe"], "policy_revision": 1} for number, target in enumerate(TARGETS)]
    (directory / "targets.json").write_text(json.dumps({"v": 1, "targets": data}))


def call(client, path, body=None, **headers):
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": ORIGIN})
    return client.open(Request(ORIGIN + path, data=json.dumps(body).encode() if body is not None else None,
                               headers=headers), timeout=10)


def login():
    run("/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "*",
        "--retry", "8", "--retry-connrefused", "--retry-max-time", "30", "--max-time", "4",
        "--cacert", "/opt/vpn-orbit-bootstrap/web-ca.pem", "--output", "/dev/null", ORIGIN + "/healthz", timeout=40)
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
            if target == TARGETS[0]:
                shutil.copyfile(key.with_suffix(".pub"), output / "observation.pub")
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
        address = recipient.read_text().strip()
        code = """import os,signal,sys
from pathlib import Path
from vpn_orbit.runtime import backup
def interrupt(*a,**k):
    os.kill(os.getpid(),signal.SIGKILL)
backup.checked_snapshot=interrupt
backup.create(Path(sys.argv[1]),sys.argv[2],age=backup.AGE)
"""
        interrupted = run(PYTHON, "-c", code, private, address, check=False, timeout=60)
        assert interrupted.returncode == -signal.SIGKILL and not list(private.iterdir())
        with call(client, "/api/v1/controller/status") as reply:
            assert json.load(reply)["admission"] == "OPEN"
        cmd = """/usr/bin/mount -t tmpfs -o size=1m,mode=0700 tmpfs "$1" &&
            /opt/vpn-orbit/admin backup --directory "$1" --recipient "$2"
        """
        small = run("/usr/bin/unshare", "--mount", "--propagation", "private", "/bin/sh", "-c", cmd,
                    "small-backup-disk", private, address, timeout=60, check=False)
        assert small.returncode and b"BACKUP_DESTINATION_SPACE_INSUFFICIENT" in small.stderr
        assert not list(private.iterdir())
        result = json.loads(run(ADMIN, "backup", "--directory", private, "--recipient", address).stdout)
        shutil.copyfile(private / result["archive"], output / "fixture.age")
    review = {"source_boot": boot(), "digest": result["sha256"], "owner": owner["user"]["id"], "operator": operator,
              "recipient": address,
              "old_credential_sha256": hashlib.sha256(Path(cfg["vault_credential"]).read_bytes()).hexdigest()}
    run("/usr/bin/systemctl", "stop", *UNITS, timeout=100)
    for unit in UNITS:
        assert run("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", unit).stdout.strip() == b"inactive"
    (output / "fixture.json").write_text(json.dumps(review))
    print("Source VM captured encrypted synthetic state and stopped all controller units.", flush=True)


@contextmanager
def observation_target(transfer):
    """Use a real SSH transport with a bounded synthetic observation command."""
    code = """import asyncio,asyncssh,json,sys,time
from pathlib import Path
from vpn_orbit.runtime.protocol import PROBE_COMMAND, PROBE_REQUEST, PROBE_VERSION
key=asyncssh.read_public_key(sys.argv[2])
class Peer(asyncssh.SSHServer):
    def public_key_auth_supported(self):
        return True
    def validate_public_key(self, username, candidate):
        return username=='vpn-orbit-svc' and candidate.public_data == key.public_data
async def probe(process):
    payload=await process.stdin.read()
    if process.command != PROBE_COMMAND or payload != PROBE_REQUEST:
        process.exit(65)
        return
    result={'v':PROBE_VERSION,'uid':0,'observed_at':int(time.time()),
            'software':{'docker':'UNKNOWN','nginx':'UNKNOWN','nginx_service':'UNKNOWN'},
            'docker':{'status':'NOT_CONFIGURED','containers':[]},
            'compose':{'status':'NOT_CONFIGURED','containers':[]},
            'local_https':{'status':'NOT_CONFIGURED','sites':[]},
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    process.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\\n')
    process.exit(0)
async def main():
    await asyncssh.listen('198.18.0.2',22283,server_factory=Peer,
                          server_host_keys=[sys.argv[1]],process_factory=probe,encoding=None)
    Path(sys.argv[3]).touch()
    await asyncio.Event().wait()
asyncio.run(main())
"""
    run("/usr/sbin/ip", "address", "add", "198.18.0.2/32", "dev", "lo")
    try:
        with subprocess.Popen([PYTHON, "-c", code, transfer / "fixture-host", transfer / "observation.pub",
                               transfer / "target.ready"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as server:
            try:
                installation.wait_for(lambda: (transfer / "target.ready").exists(), "SSH fixture did not start", seconds=10)
                yield
            finally:
                server.terminate()
    finally:
        run("/usr/sbin/ip", "address", "del", "198.18.0.2/32", "dev", "lo")


def destination(transfer, identity):
    evidence = json.loads((transfer / "fixture.json").read_bytes())
    # Hosted images can share a template machine-id. Distinct kernel boot IDs
    # and separate OS credential envelopes are the relevant evidence here.
    assert boot() != evidence["source_boot"]
    local = json.loads(Path(CONFIG).read_bytes())
    Path("/var/lib/vpn-orbit-recovery").mkdir(mode=0o700)
    missing = run(ADMIN, "restore-stage", "--archive", transfer / "fixture.age", "--identity", transfer / "missing",
                  "--sha256", evidence["digest"], check=False)
    assert missing.returncode != 0
    corrupted = transfer / "corrupted.age"
    corrupted.write_bytes((transfer / "fixture.age").read_bytes()[:-5])
    corrupted.chmod(0o600)
    result = run(ADMIN, "restore-stage", "--archive", corrupted, "--identity", identity,
                 "--sha256", hashlib.sha256(corrupted.read_bytes()).hexdigest(), check=False)
    assert result.returncode and b"BACKUP_DECRYPTION_FAILED" in result.stderr
    incompatible = transfer / "incompatible.age"
    code = """import io,subprocess,sys
from vpn_orbit.runtime import backup
from vpn_orbit.runtime.protocol import canonical
payload=io.BytesIO()
backup.write_archive(payload,canonical({'v':2,'kind':'vpn-orbit-controller','databases':backup.DBS}),{})
with open(sys.argv[1],'xb') as out:
    subprocess.run([backup.AGE,'-e','-r',sys.argv[2]],input=payload.getvalue(),stdout=out,check=True)
"""
    run(PYTHON, "-c", code, incompatible, evidence["recipient"])
    incompatible.chmod(0o600)
    result = run(ADMIN, "restore-stage", "--archive", incompatible, "--identity", identity,
                 "--sha256", hashlib.sha256(incompatible.read_bytes()).hexdigest(), check=False)
    assert result.returncode and b"BACKUP_FORMAT_UNSUPPORTED" in result.stderr
    assert not list(Path("/var/lib/vpn-orbit-recovery").glob("restore-*"))
    run(ADMIN, "restore-stage", "--archive", transfer / "fixture.age", "--identity", identity, "--sha256", evidence["digest"])
    run("/usr/bin/systemctl", "stop", *UNITS, timeout=100)
    run("/usr/bin/docker", "--host", "unix:///run/docker.sock", "compose", "--project-name", "vpn-orbit",
        "--file", "/etc/vpn-orbit/compose.json", "rm", "--force")
    code = """import os,signal,sys
from vpn_orbit.runtime import recovery,backup
apply=recovery.swap_entries
def stop_after_data(live,work,names):
    apply(live,work,names)
    if live==backup.DATA:
        os.kill(os.getpid(),signal.SIGKILL)
recovery.swap_entries=stop_after_data
recovery.install(sys.argv[1],docker_host='unix:///run/docker.sock')
"""
    failed = run(PYTHON, "-c", code, evidence["digest"], check=False, timeout=100)
    assert failed.returncode == -signal.SIGKILL
    assert Path("/var/lib/vpn-orbit/restore.pending").is_file()
    run("/usr/bin/systemctl", "start", "vpn-orbit-compose.service", check=False)
    state = run("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", "vpn-orbit-compose.service")
    assert state.stdout.strip() == b"inactive"
    run("/usr/bin/systemctl", "stop", *UNITS, timeout=100)
    run(ADMIN, "restore-apply", "--sha256", evidence["digest"], "--confirm-replace", "--resume")
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
    diagnostics = json.loads(run(ADMIN, "diagnose").stdout)
    assert diagnostics["checks"]["restore"]["code"] == "RESTORE_ACTIVATED"
    assert diagnostics["checks"]["authority"] == {"status": "OK", "code": "AUTHORITY_POLICY_AND_HOST_BOUND"}
    with observation_target(transfer):
        with call(client, f"/api/v1/resources/{TARGETS[0]}/observations", {},
                  **{"X-CSRF-Token": owner["csrf_token"], "Idempotency-Key": "recovered-controller-observation"}) as reply:
            job = json.load(reply)["id"]

        def completed():
            with call(client, "/api/v1/jobs/" + job) as reply:
                state = json.load(reply)["status"]
            if state in ("FAILED", "CANCELLED_SAFE", "UNKNOWN_OUTCOME"):
                raise AssertionError("Restored controller did not authenticate to fixture SSH target: " + state)
            return state == "SUCCEEDED"

        installation.wait_for(completed, "Restored controller probe did not complete", seconds=20)
    print("Fresh independent VM restored Owner, grants and keys, activated after source shutdown, and authenticated a real SSH probe.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("fixture", "source", "destination"))
    parser.add_argument("--transfer", type=Path, required=True)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Disposable GitHub-hosted VM required")
    if args.role == "fixture":
        fixture(args.transfer, args.key)
    else:
        if os.geteuid() != 0 or args.key is None:
            raise SystemExit("Root in disposable VM required")
        (source if args.role == "source" else destination)(args.transfer, args.key)


if __name__ == "__main__":
    main()
