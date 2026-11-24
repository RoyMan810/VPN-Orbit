"""Upgrade the actual v1.0.0 bootstrap installation in a hosted lab VM."""

import argparse
from http.cookiejar import CookieJar
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import ssl
import tempfile
import sqlite3
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener

import installation


ORIGIN = "https://127.0.0.1:18443"
APP = Path("/opt/vpn-orbit")
WEB = Path("/opt/vpn-orbit-bootstrap")
REPO = Path(__file__).resolve().parents[2]
META = APP / "installation.json"
STATE = APP / "upgrade-1.1.0/transaction.json"
MARKER = Path("/var/lib/vpn-orbit/update.blocked")
TARGETS = ["01JCYQZ4T9V8MNVYEH3D2M7Q1" + suffix for suffix in ("A", "B")]
REFS = ["01JCYQZ4T9V8MNVYEH3D2M7Q1" + suffix for suffix in ("C", "D")]
ORBIT = APP / "venv/bin/python"
CONFIG = "/etc/vpn-orbit/runtime.json"


def request(client, path, body=None, **headers):
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": ORIGIN})
    return client.open(Request(ORIGIN + path, data=json.dumps(body).encode() if body is not None else None,
                               headers=headers), timeout=15)


def wait_https():
    installation.run("/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "*",
                     "--retry", "8", "--retry-connrefused", "--retry-max-time", "30", "--max-time", "4",
                     "--cacert", WEB / "web-ca.pem", "--output", "/dev/null", ORIGIN + "/healthz", timeout=40)


def read_state():
    return json.loads(STATE.read_bytes())


def interrupt_flags(python, script, checkpoint, args):
    code = """import os, signal, sys
sys.path.insert(0, sys.argv[1])
import upgrade
checkpoint = sys.argv[2]
sys.argv = [sys.argv[0], *sys.argv[3:]]
save = upgrade.save
def save_then_interrupt(state, phase, **extra):
    save(state, phase, **extra)
    if phase == checkpoint:
        os.kill(os.getpid(), signal.SIGKILL)
upgrade.save = save_then_interrupt
upgrade.main()
"""
    return (python, "-c", code, str(script.parent), checkpoint, *args)


def registry_unavailable(python, script, options):
    run = installation.run
    folder = Path("/etc/systemd/system/docker.service.d")
    folder.mkdir(mode=0o755, exist_ok=True)
    fixture = folder / "99-vpn-orbit-lab-unavailable-registry.conf"
    with fixture.open("x") as stream:
        stream.write('[Service]\nEnvironment="HTTPS_PROXY=http://127.0.0.1:1" "HTTP_PROXY=http://127.0.0.1:1" "NO_PROXY="\n')
    try:
        run("/usr/bin/systemctl", "daemon-reload")
        run("/usr/bin/systemctl", "restart", "docker.service", timeout=120)
        pull = run("/usr/bin/docker", "--host", "unix:///run/docker.sock", "info", "--format", "{{.HTTPSProxy}}")
        assert pull.stdout.strip() == b"http://127.0.0.1:1"
        result = run(python, script, *options, check=False, timeout=100)
        assert result.returncode and b"INSTALL_COMMAND_FAILED_DOCKER" in result.stderr
        assert not STATE.exists() and not MARKER.exists()
        assert json.loads(META.read_bytes())["version"] == "1.0.0"
    finally:
        fixture.unlink()
        run("/usr/bin/systemctl", "daemon-reload")
        run("/usr/bin/systemctl", "restart", "docker.service", timeout=120)
    wait_https()


def fixtures(path):
    with tempfile.TemporaryDirectory() as temp:
        key = Path(temp) / "host"
        installation.run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
        public = " ".join(key.with_suffix(".pub").read_text().split()[:2])
    spec = [{"id": target, "ip": f"198.18.0.{number + 2}", "port": 22, "allowed_cidrs": ["198.18.0.0/24"],
             "host_key": public, "secret_ref": REFS[number] + ":v1", "dependencies": [],
             "capabilities": ["host.probe"], "policy_revision": 1} for number, target in enumerate(TARGETS)]
    path.write_text(json.dumps({"v": 1, "targets": spec}))


def seed_data(owner, root):
    cfg = json.loads(Path(CONFIG).read_bytes())
    run = installation.run
    run(APP / "venv/bin/vpn-orbit-runtime", "--config", CONFIG, "register-observations")
    key = root / "ssh-fixture"
    run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
    os.chmod(root, 0o711)
    os.chown(key, cfg["broker_uid"], cfg["broker_gid"])
    code = """import json,os,sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.vault import Vault
c=json.load(open('/etc/vpn-orbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',
        systemd_credential=True,writers=Admission(c['writer_directory']))
v.import_ssh(sys.argv[3],1,Path(sys.argv[1]).read_bytes(),owner_id=sys.argv[2],worker_uid=c['worker_uid'],target=sys.argv[4])
with v.journal.write(kind='business') as db:
    db.execute('DROP TABLE secret_lifecycle')
"""
    run("/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--property=User=" + str(cfg["broker_uid"]),
        "--property=Group=" + str(cfg["broker_gid"]), "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
        ORBIT, "-c", code, key, owner, REFS[0], TARGETS[0])
    code = """import sys
from vpn_orbit.database import DataAccess, Store, identifier
from vpn_orbit.runtime.cli import configuration
from vpn_orbit.queue import JobQueue
cfg=configuration('/etc/vpn-orbit/runtime.json')
s=Store(cfg['database'],access=DataAccess(cfg['app_uid'],cfg['app_gid']))
queue=JobQueue(s)
job=identifier()
with s.write() as db:
    scope=db.execute('SELECT scope_digest FROM resources WHERE id=?',(sys.argv[2],)).fetchone()[0]
    queue._enqueue_mutation(db,job,sys.argv[1],sys.argv[2],scope,1,'a'*64,'host.probe')
    row=db.execute('SELECT * FROM jobs WHERE id=?',(job,)).fetchone()
    queue._finish(db,row,'UNKNOWN_OUTCOME','WORKER_RESTART')
print(job)
"""
    return run(ORBIT, "-c", code, owner, TARGETS[0]).stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--public", type=Path)
    parser.add_argument("--age-keygen", type=Path)
    parser.add_argument("--scenario", choices=("resume", "rollback"))
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Disposable GitHub-hosted VM required")
    if args.fixture is not None:
        fixtures(args.fixture)
        return
    if os.geteuid() != 0 or not all((args.bundle, args.public, args.age_keygen, args.scenario)):
        raise RuntimeError("Disposable GitHub-hosted VM required")

    run = installation.run
    assert json.loads(META.read_bytes())["version"] == "1.0.0"
    old_web = (WEB / "web/index.html").read_bytes()
    objects = ("/etc/vpn-orbit/runtime.json", "/etc/vpn-orbit/credentials/broker-dek.cred",
               "/etc/vpn-orbit/targets.json", "/var/lib/vpn-orbit/control-gate/signing.key")
    hashes = {name: hashlib.sha256(Path(name).read_bytes()).digest() for name in objects}
    installation.PASSWORD = secrets.token_urlsafe(32)
    installation.owner_create()
    wait_https()
    tls = ssl.create_default_context(cafile=WEB / "web-ca.pem")
    client = build_opener(HTTPSHandler(context=tls), HTTPCookieProcessor(CookieJar()))
    with request(client, "/api/v1/auth/login", {"username": "roman", "password": installation.PASSWORD}) as reply:
        owner = json.load(reply)
    with request(client, "/api/v1/users") as reply:
        tag = reply.headers["ETag"]
    with tempfile.TemporaryDirectory(prefix="upgrade-data-", dir="/run/vpn-orbit") as keys:
        unresolved = seed_data(owner["user"]["id"], Path(keys))
    grants = [{"permission": "vps:read", "resource_id": TARGETS[0]}]
    with request(client, "/api/v1/users", {"username": "operator", "password": secrets.token_urlsafe(32),
                 "role": "Operator", "grants": grants}, **{"X-CSRF-Token": owner["csrf_token"], "If-Match": tag}) as reply:
        operator = json.load(reply)["id"]

    with tempfile.TemporaryDirectory(prefix="upgrade-lab-", dir="/run/vpn-orbit") as name:
        root = Path(name)
        public, identity = root / "signer.pub", root / "offline.age-key"
        public.write_bytes(args.public.read_bytes())
        public.chmod(0o600)
        run(args.age_keygen, "-o", identity)
        recipient = run(args.age_keygen, "-y", identity).stdout.decode().strip()
        folder = root / "backups"
        folder.mkdir(mode=0o700)
        options = ("--confirm", "--bundle", args.bundle, "--trust-key", public, "--backup-directory", folder,
                   "--recipient", recipient, "--identity", identity)
        python = WEB / "python/bin/python3.15"
        script = REPO / "deploy/upgrade.py"
        if args.scenario == "resume":
            bad_signature = root / "unauthenticated"
            shutil.copytree(args.bundle, bad_signature)
            (bad_signature / "manifest.sig").write_bytes(bytes(64))
            invalid = run(python, script, "--bundle", bad_signature, "--trust-key", public, "--confirm", check=False)
            assert invalid.returncode and b"ARTIFACT_SIGNATURE_INVALID" in invalid.stderr
            assert not STATE.exists()
            wait_https()
            registry_unavailable(python, script, options)
        if args.scenario == "resume":
            result = run(*interrupt_flags(python, script, "BACKED_UP", options), check=False, timeout=600)
            if result.returncode != -signal.SIGKILL:
                raise RuntimeError("Expected interruption after verified backup, before migration: " + result.stderr.decode())
            assert read_state()["phase"] == "BACKED_UP" and MARKER.is_file()
            result = run(*interrupt_flags(python, script, "SWITCHING", ("--resume", "--confirm")),
                         check=False, timeout=240)
            if result.returncode != -signal.SIGKILL:
                raise RuntimeError("Expected interruption after migration, before switch: " + result.stderr.decode())
            assert read_state()["phase"] == "SWITCHING" and MARKER.is_file()
            outcome = json.loads(run(python, script, "--resume", "--confirm", timeout=240).stdout)
            assert outcome["phase"] == "COMPLETE"
            assert json.loads(run(python, script, "--resume", "--confirm", timeout=30).stdout) == outcome
            expected = "1.1.0"
            assert (WEB / "web/index.html").read_bytes() != old_web
            assert run(python, script, "--rollback", "--confirm", check=False).returncode != 0
        else:
            result = run(python, script, *options, check=False, timeout=600)
            assert result.returncode != 0
            assert read_state()["phase"] == "ROLLED_BACK", result.stderr.decode()
            expected = "1.0.0"
            assert (WEB / "web/index.html").read_bytes() == old_web

        assert not MARKER.exists()
        assert json.loads(META.read_bytes())["version"] == expected
        with request(client, "/healthz") as reply:
            assert json.load(reply)["version"] == expected
        with request(client, "/api/v1/auth/session") as reply:
            assert json.load(reply)["user"] == owner["user"]
        with request(client, "/api/v1/users/" + operator) as reply:
            item = json.load(reply)
            assert item["id"] == operator and item["grants"] == grants
        cfg = json.loads(Path(CONFIG).read_bytes())
        with sqlite3.connect(cfg["database"]) as db:
            assert {row[0] for row in db.execute("SELECT id FROM resources")} == set(TARGETS)
            assert db.execute("SELECT status FROM jobs WHERE id=?", (unresolved,)).fetchone() == ("UNKNOWN_OUTCOME",)
        with sqlite3.connect(Path(cfg["vault_directory"]) / "vault.sqlite3") as db:
            assert db.execute("SELECT ref,state FROM secrets").fetchone() == (REFS[0] + ":v1", "ACTIVE")
        with request(client, "/api/v1/audit/integrity") as reply:
            assert json.load(reply)["status"] == "verified"
        record = read_state()
        assert record["migrations"] == ["vault-lifecycle-audit"]
        assert record["backup_sha256"] == hashlib.sha256((folder / record["backup_file"]).read_bytes()).hexdigest()
        assert {name: hashlib.sha256(Path(name).read_bytes()).digest() for name in objects} == hashes
        if expected == "1.1.0":
            Path("/var/lib/vpn-orbit-recovery").mkdir(mode=0o700)
            evidence = json.loads(run(APP / "admin", "restore-stage", "--archive", folder / record["backup_file"],
                                      "--identity", identity, "--sha256", record["backup_sha256"]).stdout)
            assert evidence["status"] == "STAGED_READ_ONLY" and evidence["archive_version"] == "1.0.0"
            assert evidence["controller_version"] == "1.1.0"
            offline = run("/usr/bin/unshare", "--net", APP / "admin", "release-check", check=False, timeout=15)
            assert offline.returncode and b"UPDATE_RELEASE_DISCOVERY_UNAVAILABLE" in offline.stderr
        print(f"Released v1.0.0 installation, verified backup and preserved login/audit: {args.scenario} passed.", flush=True)


if __name__ == "__main__":
    main()
