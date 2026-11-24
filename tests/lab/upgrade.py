"""Upgrade the actual v1.0.0 bootstrap installation in a hosted lab VM."""

import argparse
from http.cookiejar import CookieJar
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import tempfile
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener

import installation


ORIGIN = "https://127.0.0.1:18443"
APP = Path("/opt/vpn-orbit")
WEB = Path("/opt/vpn-orbit-bootstrap")
REPO = Path(__file__).resolve().parents[2]
META = APP / "installation.json"
STATE = APP / "upgrade-1.1.0/transaction.json"
MARKER = Path("/var/lib/vpn-orbit/update.blocked")


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


def interrupt_flags(python, script, args):
    code = """import os, signal, sys
sys.path.insert(0, sys.argv[1])
import upgrade
sys.argv = [sys.argv[0], *sys.argv[2:]]
save = upgrade.save
def save_then_interrupt(state, phase, **extra):
    save(state, phase, **extra)
    if phase == 'SWITCHING':
        os.kill(os.getpid(), signal.SIGKILL)
upgrade.save = save_then_interrupt
upgrade.main()
"""
    return (python, "-c", code, str(script.parent), *args)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--age-keygen", type=Path, required=True)
    parser.add_argument("--scenario", choices=("resume", "rollback"), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
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
    with request(client, "/api/v1/users", {"username": "operator", "password": secrets.token_urlsafe(32),
                 "role": "Operator", "grants": []}, **{"X-CSRF-Token": owner["csrf_token"], "If-Match": tag}) as reply:
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
            result = run(*interrupt_flags(python, script, options), check=False, timeout=600)
            if result.returncode != -signal.SIGKILL:
                raise RuntimeError("Expected interruption after verified backup, before switch: " + result.stderr.decode())
            assert read_state()["phase"] == "SWITCHING" and MARKER.is_file()
            outcome = json.loads(run(python, script, "--resume", "--confirm", timeout=240).stdout)
            assert outcome["phase"] == "COMPLETE"
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
            assert json.load(reply)["id"] == operator
        with request(client, "/api/v1/audit/integrity") as reply:
            assert json.load(reply)["status"] == "verified"
        record = read_state()
        assert record["backup_sha256"] == hashlib.sha256((folder / record["backup_file"]).read_bytes()).hexdigest()
        assert {name: hashlib.sha256(Path(name).read_bytes()).digest() for name in objects} == hashes
        if expected == "1.1.0":
            Path("/var/lib/vpn-orbit-recovery").mkdir(mode=0o700)
            evidence = json.loads(run(APP / "admin", "restore-stage", "--archive", folder / record["backup_file"],
                                      "--identity", identity, "--sha256", record["backup_sha256"]).stdout)
            assert evidence["status"] == "STAGED_READ_ONLY" and evidence["archive_version"] == "1.0.0"
            assert evidence["controller_version"] == "1.1.0"
        print(f"Released v1.0.0 installation, verified backup and preserved login/audit: {args.scenario} passed.", flush=True)


if __name__ == "__main__":
    main()
