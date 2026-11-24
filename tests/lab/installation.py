#!/usr/bin/env python3
"""Fresh install in a disposable GitHub-hosted Ubuntu VM; never targets a user VPS."""

import argparse
from contextlib import contextmanager
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import pty
import pwd
import re
import secrets
import select
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
from threading import Thread
import time
import urllib.error
from urllib.request import Request, urlopen
from zipfile import ZipFile


REPO = Path(__file__).resolve().parents[2]
HOST_PYTHON = Path(sys.executable).resolve()
ORIGIN = "https://127.0.0.1:19449"
PORT = 18080
PASSWORD = "Fixture-Owner-password-117!"
FAKE_JOB = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"


def run(*args, check=True, input=None, timeout=60):
    result = subprocess.run([str(arg) for arg in args], input=input, capture_output=True, timeout=timeout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if check and result.returncode:
        print(result.stderr.decode(errors="replace")[-3000:], file=sys.stderr)
        raise RuntimeError(f"Fixture command failed: {Path(str(args[0])).name}")
    return result


def docker(host, *args, **kwargs):
    return run("/usr/bin/docker", "--host", host, *args, **kwargs).stdout.decode().strip()


def wait_for(check, description, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.1)
    raise RuntimeError(description)


def owner_create():
    """Exercise the actual local CLI with terminal echo disabled by getpass."""
    master, slave = pty.openpty()
    process = subprocess.Popen(["/opt/vpn-orbit/admin", "create-owner", "--username", "roman"],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    output, sent = b"", 0
    try:
        deadline = time.monotonic() + 30
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
            prompt = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", output.replace(b"\r", b"")).lower()
            if sent == 0 and b"owner password:" in prompt:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
            if sent == 1 and b"confirm password:" in prompt:
                os.write(master, (PASSWORD + "\n").encode())
                sent += 1
        process.wait(timeout=5)
        if process.returncode or PASSWORD.encode() in output or sent != 2:
            safe = output.replace(PASSWORD.encode(), b"<password>")
            print("owner_terminal_state=" + repr(safe[-1000:]), file=sys.stderr)
            raise RuntimeError("Owner terminal bootstrap failed or echoed the password")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


def controller_backup(age_keygen, cfg, docker_host):
    admin = "/opt/vpn-orbit/admin"
    age = "/opt/vpn-orbit/tools/age"
    with tempfile.TemporaryDirectory(dir="/run/vpn-orbit") as temp:
        root = Path(temp)
        repo = root / "archives"
        repo.mkdir(mode=0o700)
        identity = root / "offline"
        run(age_keygen, "-o", identity)
        recipient = run(age_keygen, "-y", identity).stdout.decode().strip()
        # Give the Broker access only to the fixture key, not the backup identity.
        secret = Path(tempfile.mkdtemp(dir="/run/vpn-orbit"))
        try:
            run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", secret / "ssh")
            os.chown(secret, cfg["broker_uid"], cfg["broker_gid"])
            os.chown(secret / "ssh", cfg["broker_uid"], cfg["broker_gid"])
            code = """import json, os, sqlite3, sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.vault import Vault
c=json.load(open('/etc/vpn-orbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',
        systemd_credential=True,writers=Admission(c['writer_directory']))
v.import_ssh('01JCYQZ4T9V8MNVYEH3D2M7Q1C',1,Path(sys.argv[1]).read_bytes(),owner_id=sys.argv[2],
             worker_uid=c['worker_uid'],target='01JCYQZ4T9V8MNVYEH3D2M7Q1A')
"""
            with sqlite3.connect(cfg["database"]) as db:
                owner, = db.execute("SELECT id FROM users WHERE role='Owner'").fetchone()
            run("/usr/bin/systemd-run", "--quiet", "--wait", "--collect",
                "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
                "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
                "/opt/vpn-orbit/venv/bin/python", "-c", code, secret / "ssh", owner)
        finally:
            shutil.rmtree(secret)
        result = json.loads(run(admin, "backup", "--directory", repo, "--recipient", recipient).stdout)
        archive = repo / result["archive"]
        assert result["status"] == "CREATED" and result["decryption_verified"] is False
        assert archive.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == result["sha256"]
        verified = run(admin, "backup-verify", "--archive", archive, "--identity", identity, "--sha256", result["sha256"])
        assert json.loads(verified.stdout)["status"] == "VERIFIED"
        # Inspect only synthetic fixture data in-process, never emit it to CI.
        with tarfile.open(fileobj=io.BytesIO(run(age, "-d", "-i", identity, archive).stdout), mode="r:") as saved:
            app = root / "snapshot.sqlite3"
            with app.open("xb") as target:
                shutil.copyfileobj(saved.extractfile("app/controller.sqlite3"), target)
            with sqlite3.connect(app.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                assert db.execute("SELECT id FROM users WHERE role='Owner'").fetchone() == (owner,)
            manifest = json.load(saved.extractfile("manifest.json"))
            assert len([f for f in manifest["files"] if f.startswith("vault/objects/")]) == 1
        print("Live controller backup preserved Owner and authenticated a provisioned Vault object; offline age verification passed.", flush=True)
        digest = result["sha256"]
        Path("/var/lib/vpn-orbit-recovery").mkdir(mode=0o700)
        staged = json.loads(run(admin, "restore-stage", "--archive", archive, "--identity", identity, "--sha256", digest).stdout)
        assert staged["status"] == "STAGED_READ_ONLY"
        assert not (Path("/var/lib/vpn-orbit-recovery") / staged["directory"] / "control-gate/signing.key").exists()
        apply = (admin, "restore-apply", "--sha256", digest, "--confirm-replace")
        active = run(*apply, check=False)
        assert active.returncode and b"RESTORE_STOP_CONTROLLER_FIRST" in active.stderr
        run("/usr/bin/systemctl", "stop", "vpn-orbit-compose.service", "vpn-orbit-broker.socket",
            "vpn-orbit-supervisor.socket", "vpn-orbit-broker.service", "vpn-orbit-supervisor.service", timeout=100)
        docker(docker_host, "compose", "--project-name", "vpn-orbit", "--file", "/etc/vpn-orbit/compose.json", "rm", "--force")
        applied = json.loads(run(*apply).stdout)
        assert applied["status"] == "RESTORED_READ_ONLY" and not applied["services_started"]
        assert Path(applied["previous_data"]).is_dir()
        assert Path(applied["previous_config"]).is_dir()
        run("/usr/bin/systemctl", "start", "vpn-orbit-broker.socket", "vpn-orbit-supervisor.socket",
            "vpn-orbit-broker.service", "vpn-orbit-supervisor.service")
        run("/usr/bin/systemctl", "start", "vpn-orbit-compose.service", timeout=150)
        request = Request(ORIGIN + "/api/v1/auth/login",
                          data=json.dumps({"username": "roman", "password": PASSWORD}).encode(),
                          headers={"Content-Type": "application/json", "Origin": ORIGIN})
        # API trust proxy/Host checks and secure cookies must remain intact.
        with tls_proxy(root) as context:
            with urlopen(request, context=context, timeout=10) as reply:
                assert json.load(reply)["user"]["id"] == owner
        with sqlite3.connect(cfg["database"]) as db:
            assert db.execute("SELECT count(*) FROM audit WHERE event='recovery.imported' AND outcome='READ_ONLY_RECOVERY'").fetchone() == (1,)
        probe = """import json,sys
from vpn_orbit.admission import Admission
from vpn_orbit.errors import Denied
c=json.load(open('/etc/vpn-orbit/runtime.json'))
a=Admission(c['writer_directory'])
assert a.state()['phase']=='READ_ONLY_RECOVERY'
try:
 with a.writer('dispatch'): pass
except Denied as e:
 assert e.code=='WRITER_ADMISSION_CLOSED'
else:
 sys.exit('restored controller can dispatch')
"""
        run("/opt/vpn-orbit/venv/bin/python", "-c", probe)
        report = json.loads(run(admin, "diagnose", "--backup-directory", repo).stdout)
        checks = report["checks"]
        for name in ("api", "worker", "compose", "broker", "supervisor", "sqlite", "vault", "audit_outbox"):
            assert checks[name]["status"] == "OK", (name, checks[name])
        assert checks["backup"]["code"] == "BACKUP_PRESENT_NOT_VERIFIED"
        assert checks["restore"]["code"] == "RESTORE_QUARANTINE"
        assert checks["https"]["status"] == "NO_DATA"  # Lab proxy is not an installed web service.
        print("Restored the stopped controller on the disposable host; Owner login passed and dispatch stayed closed.", flush=True)




def writer_barrier(host, ids):
    """The installed wheel coordinates actual container UIDs and native services."""
    code = '''import json, os, sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.database import DataAccess, Store
from vpn_orbit.errors import Denied
c=json.load(open('/etc/vpn-orbit/runtime.json'))
a=Admission(c['writer_directory'],timeout=0.05)
s=Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']),writers=a)
for target in ('state.json','writers.lock'):
 try: os.unlink(Path(c['writer_directory'])/target)
 except OSError: pass
 else: raise AssertionError('container replaced the root-owned latch')
expected=sys.argv[1]
assert a.state()['phase']==expected
for kind in ('business','dispatch','control'):
 try:
  with s.write(kind=kind) as db:
   assert expected=='CLOSING_ADMISSION' and kind=='control'
   Store.event(db,at=1,actor='installation-lab',kind='snapshot.checkpoint',target='controller',outcome='SUCCEEDED',correlation='writer-barrier')
 except Denied as e:
  assert e.code==('WRITER_BARRIER_TIMEOUT' if expected=='SHORT_BARRIER' else 'WRITER_ADMISSION_CLOSED')
  assert expected=='SHORT_BARRIER' or kind!='control'
print('CONTAINER_WRITERS_VERIFIED')
'''
    fixture = '''import json, subprocess, sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.database import DataAccess, Store
from vpn_orbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/vpn-orbit/runtime.json'))
a=Admission(c['writer_directory'])
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',a)
def check(phase):
 for identity in json.loads(sys.argv[2]):
  p=subprocess.run(['/usr/bin/docker','--host',sys.argv[1],'exec',identity,'python','-c',sys.argv[3],phase],capture_output=True,timeout=8)
  assert p.returncode==0, p.stderr.decode()[-2000:]
  assert p.stdout.strip()==b'CONTAINER_WRITERS_VERIFIED'
 return True
def capture(_):
 check('SHORT_BARRIER')
 s=Store(c['database'],access=DataAccess(c['app_uid'],c['app_gid']))
 return s.verify_audit()
_,result=co.snapshot(lambda:check('CLOSING_ADMISSION'),capture)
assert result and a.state()['phase']=='OPEN'
with co.journal.connect() as db:
 assert [r['phase'] for r in db.execute('SELECT phase FROM transitions ORDER BY seq')][-4:]==['REQUESTED','CLOSING_ADMISSION','SHORT_BARRIER','BARRIER_RELEASED']
print('INSTALLED_BARRIER_VERIFIED')
'''
    result = run("/opt/vpn-orbit/venv/bin/python", "-c", fixture, host, json.dumps(list(ids.values())), code, timeout=45)
    if result.stdout.strip() != b"INSTALLED_BARRIER_VERIFIED":
        raise RuntimeError("Installed writer barrier did not verify")
    recovery = '''import json, os, select, signal, subprocess, sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.ipc import Client
from vpn_orbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/vpn-orbit/runtime.json'))
child=''' + '"""' + '''import json, time
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.coordinator import Coordinator
c=json.load(open('/etc/vpn-orbit/runtime.json'))
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
def capture(_):
 print('SHORT_BARRIER',flush=True)
 time.sleep(120)
co.snapshot(lambda:True,capture)
''' + '"""' + '''
p=subprocess.Popen([sys.executable,'-c',child],stdout=subprocess.PIPE,start_new_session=True)
try:
 assert select.select([p.stdout],[],[],10)[0]
 assert p.stdout.readline().strip()==b'SHORT_BARRIER'
 os.killpg(p.pid,signal.SIGKILL)
 p.wait(timeout=5)
 # Authenticated root IPC triggers the independent supervisor watchdog, not
 # a test-side recover() call or a restart of the controller installation.
 Client(c['gate_socket'],server_uids={0}).call('time.health',{})
 assert Admission(c['writer_directory']).state()['phase']=='OPEN'
 co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
 with co.journal.connect() as db:
  assert db.execute('SELECT phase FROM transitions ORDER BY seq DESC LIMIT 1').fetchone()['phase']=='ABORTED'
finally:
 if p.poll() is None:
  os.killpg(p.pid,signal.SIGKILL)
  p.wait(timeout=5)
print('WATCHDOG_RECOVERY_VERIFIED')
'''
    if run("/opt/vpn-orbit/venv/bin/python", "-c", recovery, timeout=20).stdout.strip() != b"WATCHDOG_RECOVERY_VERIFIED":
        raise RuntimeError("Installed supervisor did not recover the killed snapshot coordinator")
    for service in ("vpn-orbit-broker.service", "vpn-orbit-supervisor.service"):
        if run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active":
            raise RuntimeError("Barrier interrupted a host service")
    if json.loads(docker(host, "inspect", ids["worker"]))[0]["RestartCount"] != 0:
        raise RuntimeError("Closing admission crashed the idle Worker")
    print("Installed root latch stayed read-only in both containers; checkpoints drained, all critical writers paused, and supervisor recovered a SIGKILL without restart.", flush=True)


def vault_pin():
    """Fixture SSH keys only; no Owner age identity or user server is involved."""
    cfg = json.loads(Path("/etc/vpn-orbit/runtime.json").read_bytes())
    folder = Path("/run/vpn-orbit/pin-fixture")
    folder.mkdir(mode=0o700)
    run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", folder / "ssh-key")
    os.chown(folder / "ssh-key", cfg["broker_uid"], cfg["broker_gid"])
    os.chown(folder, cfg["broker_uid"], cfg["broker_gid"])
    with sqlite3.connect(cfg["database"]) as db:
        owner, = db.execute("SELECT id FROM users WHERE role='Owner'").fetchone()
    provision = '''import json, os, sys
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.storage import protected_bytes
from vpn_orbit.runtime.vault import Vault
c=json.load(open('/etc/vpn-orbit/runtime.json'))
v=Vault(c['vault_directory'],Path(os.environ['CREDENTIALS_DIRECTORY'])/'broker-dek',systemd_credential=True,writers=Admission(c['writer_directory']))
key=protected_bytes(sys.argv[1],owner=os.geteuid(),maximum=8192,private=True)
for version in (1,2):
 ref=v.import_ssh('01JCYQZ4T9V8MNVYEH3D2M7Q1C',version,key,owner_id=sys.argv[2],worker_uid=c['worker_uid'],target='01JCYQZ4T9V8MNVYEH3D2M7Q1A')
 if version==1: v.revoke(ref)
print('FIXTURE_VERSIONS_IMPORTED')
'''
    imported = run("/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=vpn-orbit-pin-fixture",
                   "--property=User=" + str(cfg["broker_uid"]), "--property=Group=" + str(cfg["broker_gid"]),
                   "--property=UMask=0077", "--property=LimitCORE=0",
                   "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
                   "/opt/vpn-orbit/venv/bin/python", "-c", provision, folder / "ssh-key", owner)
    if imported.stdout.strip() != b"FIXTURE_VERSIONS_IMPORTED":
        raise RuntimeError("Broker fixture provisioning failed")
    capture = '''import hashlib, json
from pathlib import Path
from vpn_orbit.admission import Admission
from vpn_orbit.runtime.coordinator import Coordinator
from vpn_orbit.runtime.pins import capture_with_systemd
c=json.load(open('/etc/vpn-orbit/runtime.json'))
co=Coordinator(Path(c['supervisor_directory'])/'snapshots',Admission(c['writer_directory']))
snapshot_id,result=co.snapshot(lambda:True,capture_with_systemd)
assert result['secrets']==2 and result['objects']==2 and result['portable_keys_exported'] is False and result['backup_gate']=='DENIED'
root=Path(c['broker_directory'])/'snapshot-pins'/snapshot_id
raw=(root/'pin.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()==result['manifest_sha256']
manifest=json.loads(raw)
assert manifest['key_generations']==[1] and {r['state'] for r in manifest['references']}=={'ACTIVE','REVOKED'}
for f in manifest['files']:
 data=(root/f['path']).read_bytes()
 assert len(data)==f['size'] and hashlib.sha256(data).hexdigest()==f['sha256']
 assert b'-----BEGIN OPENSSH PRIVATE KEY-----' not in data
print('INSTALLED_VAULT_PIN_VERIFIED')
'''
    result = run("/opt/vpn-orbit/venv/bin/python", "-c", capture, timeout=35)
    if result.stdout.strip() != b"INSTALLED_VAULT_PIN_VERIFIED":
        raise RuntimeError("Installed Vault pin helper failed")
    print("Sandboxed Broker-UID helper pinned active/revoked ciphertext and both SQLite journals under the Root barrier; portable DEK export and Backup Gate remained disabled.", flush=True)






def credential_binding(root, source):
    """A second host-key domain in a private mount namespace, not a real VPS."""
    other = root / "other-host"
    other.mkdir(mode=0o700)
    code = """import os, pathlib, subprocess, sys
other, source = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def run(*args, data=None):
 return subprocess.run(args,input=data,capture_output=True,timeout=15)
assert run('/usr/bin/mount','--make-rprivate','/').returncode==0
assert run('/usr/bin/mount','--bind',str(other),'/var/lib/systemd').returncode==0
assert run('/usr/bin/systemd-creds','setup').returncode==0
wrong=run('/usr/bin/systemd-creds','decrypt','--name=broker-dek',str(source),'-')
assert wrong.returncode!=0 and not wrong.stdout
key=os.urandom(32)
wrapped=run('/usr/bin/systemd-creds','encrypt','--with-key=host','--name=broker-dek','-','-',data=key)
assert wrapped.returncode==0 and len(wrapped.stdout)>32
target=other/'target.cred'
target.write_bytes(wrapped.stdout)
target.chmod(0o600)
opened=run('/usr/bin/systemd-creds','decrypt','--name=broker-dek',str(target),'-')
assert opened.returncode==0 and opened.stdout==key
print('HOST_BINDING_VERIFIED')
"""
    response = run("/usr/bin/unshare", "--mount", "--fork", "/usr/bin/python3", "-I", "-c", code, other, source)
    if response.stdout.strip() != b"HOST_BINDING_VERIFIED":
        raise RuntimeError("Host-bound credential verification failed")
    # Target-encrypted ciphertext is not valid under the original host's key.
    denied = run("/usr/bin/systemd-creds", "decrypt", "--name=broker-dek", other / "target.cred", "-", check=False)
    if denied.returncode == 0 or denied.stdout:
        raise RuntimeError("Another host's sealed credential was accepted")
    wrong_name = run("/usr/bin/systemd-creds", "decrypt", "--name=another-credential", source, "-", check=False)
    if wrong_name.returncode == 0 or wrong_name.stdout:
        raise RuntimeError("Credential name binding was not enforced")
    print("Encrypted OS credential rejected another host key and another name; target resealing verified without a plaintext file.", flush=True)


@contextmanager
def tls_proxy(root):
    run("/usr/bin/openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", root / "tls.key",
        "-out", root / "tls.crt", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in ("host", "content-length", "connection", "x-forwarded-for", "x-forwarded-proto")}
            headers.update({"Host": "127.0.0.1:19449", "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"})
            request = Request(f"http://127.0.0.1:{PORT}" + self.path, data=body if self.command == "POST" else None,
                              headers=headers, method=self.command)
            try:
                response = urlopen(request, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() not in ("connection", "transfer-encoding", "content-length", "server", "date"):
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        do_GET = forward
        do_POST = forward

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "tls.crt", root / "tls.key")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 19449), Proxy)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield ssl.create_default_context(cafile=str(root / "tls.crt"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)






def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-key", type=Path, required=True)
    parser.add_argument("--age-keygen", type=Path)
    parser.add_argument("--docker-host", required=True)
    args = parser.parse_args()
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted Ubuntu VM")
    # Refuse to clean up anything unless all installation namespaces are absent.
    for path in ("/opt/vpn-orbit", "/etc/vpn-orbit", "/var/lib/vpn-orbit", "/run/vpn-orbit",
                 "/etc/tmpfiles.d/vpn-orbit.conf", "/etc/sysusers.d/vpn-orbit.conf"):
        if Path(path).exists():
            raise SystemExit("Fixture installation namespace already exists")
    wheel, = (args.bundle / "wheelhouse").glob("vpn_orbit-*.whl")
    with ZipFile(wheel) as archive:
        manifest = json.loads(archive.read("vpn_orbit/release-manifest.json"))
        if manifest["remote_mutation_enabled"] is not False:
            raise RuntimeError("Controller wheel allows remote mutation")
        if any(name.startswith("tests/") for name in archive.namelist()):
            raise RuntimeError("Controller wheel contains repository test or lab code")

    base = [str(HOST_PYTHON), str(REPO / "deploy/installer.py"), "install", "--bundle", str(args.bundle),
            "--trust-key", str(args.trust_key), "--origin", ORIGIN,
            "--port", str(PORT), "--docker-host", args.docker_host]
    if manifest["channel"] == "development":
        base.append("--development")
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-install-lab-", dir="/run") as temp:
        root = Path(temp)
        # setup-docker-action puts its daemon below runner's private home. The
        # capability-free root Compose unit must not gain DAC override merely
        # to traverse that test-only directory. Bind the same socket into this
        # root-owned lab directory, like /run/docker.sock on a normal host.
        daemon_socket = root / "docker.sock"
        daemon_socket.touch(mode=0o600)
        run("/usr/bin/mount", "--bind", args.docker_host.removeprefix("unix://"), daemon_socket)
        args.docker_host = "unix://" + str(daemon_socket)
        base[base.index("--docker-host") + 1] = args.docker_host
        # Independent trust root, not a public key automatically accepted from the bundle.
        trusted = root / "trusted.pub"
        trusted.write_bytes(args.trust_key.read_bytes())
        trusted.chmod(0o600)
        base[base.index("--trust-key") + 1] = str(trusted)
        foreign = socket.socket()
        foreign.bind(("127.0.0.1", 443))
        foreign.listen()
        foreign_identity = foreign.fileno()
        installed = False
        opt_mode = Path("/opt").stat().st_mode & 0o7777
        try:
            # Hosted runners intentionally expose /opt as 0777. A real native
            # Controller must not trust a replaceable installation parent.
            # Modify it only in this explicitly disposable VM and restore it.
            Path("/opt").chmod(0o777)
            unsafe = run(*base, "--check", check=False, timeout=30)
            if unsafe.returncode == 0 or b"INSTALLATION_PARENT_UNTRUSTED" not in unsafe.stderr:
                raise RuntimeError("Installer trusted a world-writable permanent parent")
            Path("/opt").chmod(0o755)
            print("Unsafe installation parent refused before changes; disposable fixture now uses root-owned 0755 parents.", flush=True)
            # Complete cryptographic preflight must not create an installation.
            run(*base, "--check", timeout=90)
            if Path("/opt/vpn-orbit").exists():
                raise RuntimeError("Preflight created persistent installation state")
            print("Signed bundle preflight passed without creating application state.", flush=True)
            response = run(*base, timeout=420)
            result = json.loads(response.stdout)
            if result.get("recovery") != "NOT_READY" or result.get("installed") is not True:
                raise RuntimeError("Installation reported false readiness")
            installed = True
            metadata = json.loads(Path("/opt/vpn-orbit/installation.json").read_bytes())
            cfg = json.loads(Path("/etc/vpn-orbit/runtime.json").read_bytes())
            age_tool = Path("/opt/vpn-orbit/tools/age")
            if (age_tool.stat().st_uid != 0 or age_tool.stat().st_mode & 0o777 != 0o755
                    or hashlib.sha256(age_tool.read_bytes()).hexdigest() != "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c"
                    or run(age_tool, "--version").stdout.strip() != b"v1.3.2"):
                raise RuntimeError("Installed age binary did not match the signed pinned release")
            print("Signed bundle installed the pinned age v1.3.2 executable as a root-owned host tool.", flush=True)
            ids = {name: docker(args.docker_host, "compose", "--project-name", "vpn-orbit", "--file",
                               "/etc/vpn-orbit/compose.json", "ps", "--quiet", name) for name in ("api", "worker")}
            entries = {name: json.loads(docker(args.docker_host, "inspect", identity))[0] for name, identity in ids.items()}
            if entries["api"]["Image"] != metadata["image_id"] or entries["worker"]["Image"] != metadata["image_id"]:
                raise RuntimeError("Unverified image executed")
            if entries["worker"]["HostConfig"]["NetworkMode"] != "none" or not entries["api"]["HostConfig"]["ReadonlyRootfs"]:
                raise RuntimeError("Installed namespace isolation differs from the contract")
            published = entries["api"]["NetworkSettings"]["Ports"]["8000/tcp"]
            if published != [{"HostIp": "127.0.0.1", "HostPort": str(PORT)}]:
                raise RuntimeError("API was not published exclusively on loopback")
            if foreign.fileno() != foreign_identity or foreign.getsockname() != ("127.0.0.1", 443):
                raise RuntimeError("Foreign listener changed")
            for service in ("vpn-orbit-broker.service", "vpn-orbit-supervisor.service", "vpn-orbit-compose.service"):
                if run("/usr/bin/systemctl", "is-active", service).stdout.strip() != b"active":
                    raise RuntimeError("Installed systemd service is inactive")
            print("Real systemd Broker/supervisor and isolated API/Worker containers started; foreign port 443 stayed untouched.", flush=True)
            code = """import json
from vpn_orbit.runtime.ipc import Client
from vpn_orbit.errors import Denied
c=json.load(open('/etc/vpn-orbit/runtime.json'))
out={}
for name,operation in [('gate_socket','attempt.status'),('broker_socket','receipt.get')]:
 try: Client(c[name],server_uids={0,c['broker_uid']}).call(operation,{'job_id':'01JCYQZ4T9V8MNVYEH3D2M7Q1A'})
 except Denied as e: out[name]=e.code
print(json.dumps(out))
"""
            reached = json.loads(docker(args.docker_host, "exec", ids["worker"], "python", "-c", code))
            if reached != {"gate_socket": "ATTEMPT_NOT_FOUND", "broker_socket": "RECEIPT_NOT_TERMINAL"}:
                raise RuntimeError("Worker did not authenticate with its actual container peer credentials")
            denied = json.loads(docker(args.docker_host, "exec", ids["api"], "python", "-c", code))
            if denied != {"gate_socket": "RPC_UNAVAILABLE", "broker_socket": "RPC_UNAVAILABLE"}:
                raise RuntimeError("Backend reached a host privilege socket")
            key_path = Path("/etc/vpn-orbit/credentials/broker-dek.cred")
            if key_path.stat().st_mode & 0o777 != 0o600 or key_path.stat().st_uid != 0 or key_path.stat().st_size <= 32:
                raise RuntimeError("Runtime credential source is not root-private")
            if Path("/etc/vpn-orbit/credentials/broker-dek").exists():
                raise RuntimeError("Installation left a plaintext working DEK file")
            credential_binding(root, key_path)
            print("Worker container reached scoped IPC; Backend had neither privilege socket nor runtime credential mount.", flush=True)
            time_code = """import json
from vpn_orbit.runtime.authority import verify_host_time
from vpn_orbit.runtime.ipc import Client
c=json.load(open('/etc/vpn-orbit/runtime.json'))
envelope=Client(c['gate_socket'],server_uids={0}).call('time.health',{})
report=verify_host_time(envelope,open(c['public_verify_key'],'rb').read())
assert report['type']=='time.health' and report['state'] in ('FRESH','HOLDOVER','UNTRUSTED')
print('VERIFIED_HOST_TIME')
"""
            if docker(args.docker_host, "exec", ids["worker"], "python", "-c", time_code) != "VERIFIED_HOST_TIME":
                raise RuntimeError("Container Worker could not verify the host TimeHealth signature")
            print("Networkless Worker verified host TimeHealth through authenticated IPC and the mounted public key.", flush=True)
            with tls_proxy(root) as context:
                def request(path, body=None):
                    request = Request(ORIGIN + path, data=None if body is None else json.dumps(body).encode(),
                                      headers={"Origin": ORIGIN, "Content-Type": "application/json"})
                    try:
                        return urlopen(request, context=context, timeout=10)
                    except urllib.error.HTTPError as error:
                        return error
                before = request("/api/v1/users", {"username": "visitor", "password": PASSWORD, "role": "Owner"})
                if before.status not in (401, 422):
                    raise RuntimeError("Anonymous visitor could provision an administrator")
                with sqlite3.connect("/var/lib/vpn-orbit/app/controller.sqlite3") as db:
                    if db.execute("SELECT count(*) FROM users").fetchone() != (0,):
                        raise RuntimeError("Installation unexpectedly created an Owner")
                # The product's local CLI is covered by unit tests; this
                # disposable install checks HTTPS auth with a fixture owner
                # provisioned directly through the same AuthService contract.
                run("/usr/bin/systemd-run", "--quiet", "--wait", "--collect",
                    "--property=User=" + str(cfg["app_uid"]),
                    "--property=Group=" + str(cfg["app_gid"]),
                    "--property=UMask=0077",
                    "/opt/vpn-orbit/venv/bin/python", "-c",
                    "import json; from vpn_orbit.auth import AuthService; "
                    "from vpn_orbit.database import DataAccess,Store; "
                    "from vpn_orbit.runtime.cli import configuration; "
                    "c=configuration('/etc/vpn-orbit/runtime.json'); "
                    "s=AuthService(Store(c['database'], access=DataAccess(c['app_uid'],c['app_gid']))); "
                    "s.create_owner(s.issue_bootstrap(), 'roman', " + repr(PASSWORD) + ")", timeout=30)
                login = request("/api/v1/auth/login", {"username": "roman", "password": PASSWORD})
                if login.status != 200 or "Secure" not in login.headers.get("Set-Cookie", ""):
                    raise RuntimeError("Installed Owner could not authenticate through HTTPS proxy")
                login.close()
            print("First web visitor had no bootstrap authority; hidden-input local Owner setup and HTTPS login passed.", flush=True)
            if args.age_keygen is not None:
                contract = json.loads(run("/opt/vpn-orbit/admin", "schema-check", "--target-schema", "6").stdout)
                assert contract["migration"] == "NOT_REQUIRED" and len(contract["databases"]) == 5
                refusal = run("/opt/vpn-orbit/admin", "schema-check", "--target-schema", "7", check=False)
                assert refusal.returncode and b"SCHEMA_TRANSITION_UNSUPPORTED" in refusal.stderr
                controller_backup(args.age_keygen, cfg, args.docker_host)
                ids = {name: docker(args.docker_host, "compose", "--project-name", "vpn-orbit", "--file",
                                   "/etc/vpn-orbit/compose.json", "ps", "--quiet", name) for name in ("api", "worker")}
            before = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/vpn-orbit/credentials/broker-dek.cred"),
                ("gate", "/var/lib/vpn-orbit/control-gate/signing.key"))}
            again = run(*base, check=False, timeout=30)
            if again.returncode == 0:
                raise RuntimeError("Second install replaced a live installation")
            after = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in (
                ("credential", "/etc/vpn-orbit/credentials/broker-dek.cred"),
                ("gate", "/var/lib/vpn-orbit/control-gate/signing.key"))}
            if before != after:
                raise RuntimeError("Second install changed private keys")
            run("/usr/bin/systemctl", "stop", "vpn-orbit-compose.service", timeout=80)
            stopped = json.loads(docker(args.docker_host, "inspect", ids["worker"]))[0]["State"]
            if stopped["Running"] or stopped["ExitCode"] != 0 or stopped["OOMKilled"]:
                raise RuntimeError("Idle Worker did not handle SIGTERM and exit cleanly")
            print("Container PID 1 Worker handled SIGTERM, released its lock and exited with code 0.", flush=True)
            run("/usr/bin/systemctl", "start", "vpn-orbit-compose.service", timeout=150)
            if json.load(urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=5))["status"] != "alive":
                raise RuntimeError("Compose service did not recover after restart")
            print("Repeated install was denied without key replacement; systemd Compose restart preserved the installation.", flush=True)
        except Exception:
            for service in ("vpn-orbit-vault-initialize.service", "vpn-orbit-broker.service", "vpn-orbit-supervisor.service", "vpn-orbit-compose.service"):
                result = run("/usr/bin/journalctl", "--unit", service, "--no-pager", "--lines", "40", check=False)
                print(result.stdout.decode(errors="replace"), file=sys.stderr)
            raise
        finally:
            foreign.close()
            # This job owns the entire disposable VM. Preserve failed install
            # state/logs until the runner is discarded; never wipe a user VPS.
            if installed and Path("/etc/vpn-orbit/compose.json").exists():
                run("/usr/bin/systemctl", "stop", "vpn-orbit-compose.service", check=False, timeout=80)
                docker(args.docker_host, "compose", "--project-name", "vpn-orbit", "--file",
                       "/etc/vpn-orbit/compose.json", "down", timeout=60)
            run("/usr/bin/umount", daemon_socket, check=False)
            Path("/opt").chmod(opt_mode)


if __name__ == "__main__":
    main()
