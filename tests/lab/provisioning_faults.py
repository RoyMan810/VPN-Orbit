#!/usr/bin/env python3
"""Disposable-VM provisioning fault injection over a real SSH network namespace."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from tools import prepare_vps
from tools.prepare_vps import SSH_PROFILE
from vpn_orbit.runtime.ssh_enrollment import verify_credentials

REPO = Path(__file__).resolve().parents[2]
PREPARE = REPO / "tools/prepare_vps.py"
NAMESPACE = "vpn-orbit-provision-lab"
ADMIN = "vpn-orbit-admin"
SERVICE = "vpn-orbit-svc"
PORT = 2222
ADDRESS = "10.231.0.2"
HOST_ADDRESS = "10.231.0.1"
PROFILE = Path("/etc/ssh/sshd_config.d/60-vpn-orbit-probe.conf")
LAB = Path("/run/vpn-orbit-provision-lab")
NAMESPACES = ("/usr/local/libexec/vpn-orbit", "/etc/ssh/vpn-orbit-keys",
              "/var/lib/vpn-orbit-provision", str(PROFILE))


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def output(argv):
    return subprocess.check_output(argv, text=True).strip()


def cleanup():
    subprocess.run(["ip", "netns", "del", NAMESPACE], stderr=subprocess.DEVNULL)
    subprocess.run(["userdel", "-r", ADMIN], stderr=subprocess.DEVNULL)
    for path in ("/etc/sudoers.d/vpn-orbit-provision-lab", str(PROFILE)):
        Path(path).unlink(missing_ok=True)
    shutil.rmtree(LAB, ignore_errors=True)
    for path in ("/usr/local/libexec/vpn-orbit", "/etc/ssh/vpn-orbit-keys", "/var/lib/vpn-orbit-provision"):
        shutil.rmtree(path, ignore_errors=True)
    subprocess.run(["userdel", SERVICE], stderr=subprocess.DEVNULL)
    subprocess.run(["groupdel", SERVICE], stderr=subprocess.DEVNULL)


def preflight():
    if (not os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.geteuid() != 0):
        raise SystemExit("Requires an explicitly disposable GitHub-hosted Ubuntu VM")
    for path in NAMESPACES:
        if Path(path).exists() or Path(path).is_symlink():
            raise SystemExit(f"Fixture namespace already exists: {path}")
    if subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout.find(NAMESPACE) >= 0:
        raise SystemExit("Fixture network namespace already exists")
    if subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode == 0:
        raise SystemExit("Fixture service account already exists")
    if not Path("/usr/sbin/sshd").is_file():
        raise SystemExit("OpenSSH server is required")
    if not Path("/usr/bin/sudo").is_file():
        raise SystemExit("sudo is required")


def setup_fixture(directory):
    LAB.mkdir(mode=0o700)
    run(["ip", "netns", "add", NAMESPACE])
    run(["ip", "link", "add", "vpnprobe0", "type", "veth", "peer", "name", "vpnprobe1"])
    run(["ip", "link", "set", "vpnprobe1", "netns", NAMESPACE])
    run(["ip", "addr", "add", f"{HOST_ADDRESS}/24", "dev", "vpnprobe0"])
    run(["ip", "link", "set", "vpnprobe0", "up"])
    run(["ip", "netns", "exec", NAMESPACE, "ip", "addr", "add", f"{ADDRESS}/24", "dev", "vpnprobe1"])
    run(["ip", "netns", "exec", NAMESPACE, "ip", "link", "set", "vpnprobe1", "up"])
    run(["ip", "netns", "exec", NAMESPACE, "ip", "link", "set", "lo", "up"])

    run(["useradd", "--create-home", "--shell", "/bin/bash", "--password", "*", ADMIN])
    key = directory / "admin"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    ssh_dir = Path("/home") / ADMIN / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    (ssh_dir / "authorized_keys").write_bytes((key.with_suffix(".pub")).read_bytes())
    ssh_dir.chmod(0o700)
    (ssh_dir / "authorized_keys").chmod(0o600)
    run(["chown", "-R", f"{ADMIN}:{ADMIN}", str(ssh_dir)])
    Path("/etc/sudoers.d/vpn-orbit-provision-lab").write_text(f"{ADMIN} ALL=(root) NOPASSWD: ALL\n")
    Path("/etc/sudoers.d/vpn-orbit-provision-lab").chmod(0o440)

    # OpenSSH reads ForceCommand at startup.  Install the exact profile before
    # starting the fixture so the phase's identical write needs no fixture reload.
    PROFILE.write_text(SSH_PROFILE)
    PROFILE.chmod(0o644)

    host_key = LAB / "host"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
    config = LAB / "sshd_config"
    config.write_text(
        f"Port {PORT}\nListenAddress {ADDRESS}\nHostKey {host_key}\nPidFile {LAB / 'sshd.pid'}\n"
        f"UsePAM yes\nStrictModes yes\nPermitRootLogin no\nPermitUserEnvironment no\n"
        f"AllowUsers {ADMIN} {SERVICE}\nAuthenticationMethods publickey\n"
        f"PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        f"PidFile {LAB / 'sshd.pid'}\nInclude /etc/ssh/sshd_config.d/*.conf\n"
    )
    run(["/usr/sbin/sshd", "-t", "-f", str(config)])
    log = open(LAB / "sshd.log", "wb")
    process = subprocess.Popen(["ip", "netns", "exec", NAMESPACE, "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    (LAB / "sshd.process").write_text(str(process.pid))
    fingerprint = output(["ssh-keygen", "-lf", str(host_key.with_suffix(".pub")), "-E", "sha256"]).split()[1]
    for _ in range(50):
        probe = subprocess.run(["ssh-keyscan", "-T", "1", "-p", str(PORT), ADDRESS],
                               capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip():
            break
        time.sleep(0.1)
    else:
        raise SystemExit("Fixture sshd did not start")
    return key, fingerprint


def provision(directory, key, fingerprint, *, fault=None, cleanup_on_failure=False, cleanup=False, check=False):
    environment = os.environ.copy()
    if fault:
        environment["VPN_ORBIT_PROVISION_FAULT"] = fault
    argv = [sys.executable, str(PREPARE), "--host", ADDRESS, "--port", str(PORT), "--user", ADMIN,
            "--identity", str(key), "--fingerprint", fingerprint]
    argv += ["--check"] if check else ["--output", str(directory / "output")]
    if cleanup_on_failure:
        argv.append("--cleanup-on-failure")
    if cleanup:
        argv.append("--cleanup")
    return subprocess.run(argv, env=environment, capture_output=True, text=True)


def probe(directory, key, fingerprint):
    known = directory / "known_hosts"
    known.write_text(f"[{ADDRESS}]:{PORT} {(LAB / 'host.pub').read_text().strip()}\n")
    del fingerprint
    return subprocess.run(
        ["ssh", "-F", "/dev/null", "-p", str(PORT), "-i", str(directory / "output" / "probe"),
         "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known}",
         f"{SERVICE}@{ADDRESS}", "vpn-orbit.v9.probe"],
        input='{"operation":"probe","version":9}\n', capture_output=True, text=True)


def state(directory):
    return json.loads((directory / "output" / ".provision-state.json").read_text())


def verify_existing_file_is_preserved(directory):
    scratch = directory / "existing-file"
    scratch.mkdir(mode=0o700)
    path = scratch / "existing"
    content = b"existing fixture\n"
    path.write_bytes(content)
    script = "set -eu\n" + prepare_vps.install_file(path, content, "0644", "test-file")
    env = {**os.environ, "work": str(scratch), "STATE": str(scratch)}
    for mode, accepted in ((0o640, False), (0o644, True)):
        path.chmod(mode)
        before = path.stat()
        result = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True)
        expect((result.returncode == 0) == accepted, "Only matching protected metadata may be reused", result)
        after = path.stat()
        expect((after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns) ==
               (before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns)
               and path.read_bytes() == content, "Existing file must stay untouched")
        expect(not (scratch / "created-test-file").exists(), "Existing file must not be marked for removal")

    managed = scratch / "created"
    run(["/bin/sh", "-c", "set -eu\n" + prepare_vps.install_file(managed, content, "0644", "test-file")], env=env)
    marker = scratch / "created-test-file"
    expect(marker.is_file(), "Installation must record the created file")
    remove = prepare_vps.CHECK_OWNED_FILE + f"owned_file {managed} test-file remove\n"
    managed.write_bytes(b"changed fixture\n")
    drift = subprocess.run(["/bin/sh", "-c", remove], env=env, capture_output=True, text=True)
    expect(drift.returncode != 0 and managed.read_bytes() == b"changed fixture\n",
           "Cleanup must preserve a changed file", drift)
    managed.write_bytes(content)
    run(["/bin/sh", "-c", remove], env=env)
    expect(not managed.exists(), "Cleanup must remove the exact file installed by this preparation")


def verify_cleanup_binding(directory):
    old_state = directory / "legacy-state"
    old_state.mkdir(mode=0o700)
    (old_state / "created-firewall-authorized").touch()
    key = b"ssh-ed25519 first fixture\n"
    protected_file = directory / "managed-outside-this-preparation"
    protected_file.write_text("existing fixture\n")
    with patch.multiple(prepare_vps, REMOTE_STATE=old_state, FIREWALL_AUTHORIZED=protected_file):
        legacy = subprocess.run(["/bin/sh", "-c", prepare_vps.cleanup_script(key)], capture_output=True, text=True)
        expect(legacy.returncode != 0 and protected_file.is_file(), "Legacy intent must not authorize file removal", legacy)

    with patch.multiple(prepare_vps, REMOTE_STATE=directory / "missing-state", FIREWALL_AUTHORIZED=protected_file):
        missing = subprocess.run(["/bin/sh", "-c", prepare_vps.cleanup_script(key)], capture_output=True, text=True)
        expect(missing.returncode != 0 and protected_file.is_file(), "A missing journal must not confirm cleanup", missing)

    bound_state = directory / "bound-state"
    bound_state.mkdir(mode=0o700)
    with patch.multiple(prepare_vps, REMOTE_STATE=bound_state, FIREWALL_AUTHORIZED=protected_file):
        run(["/bin/sh", "-c", "set -eu\numask 077\n" + prepare_vps._state_directory(key, create=True)])
        run(["/bin/sh", "-c", "set -eu\n" + prepare_vps._state_directory(key)])
        mismatch = subprocess.run(["/bin/sh", "-c", prepare_vps.cleanup_script(b"different key")],
                                  capture_output=True, text=True)
        expect(mismatch.returncode != 0, "A different preparation must not own an existing journal", mismatch)
        (bound_state / "unrelated").write_text("existing fixture\n")
        unknown = subprocess.run(["/bin/sh", "-c", prepare_vps.cleanup_script(key)], capture_output=True, text=True)
        expect(unknown.returncode != 0 and (bound_state / "unrelated").is_file(),
               "Cleanup must preserve unrelated files in the journal", unknown)


def expect(condition, message, result=None):
    if not condition:
        detail = "" if result is None else f"\nstdout: {result.stdout}\nstderr: {result.stderr}"
        raise AssertionError(message + detail)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    args = parser.parse_args()
    if not args.isolated_vm:
        raise SystemExit("Requires --isolated-vm")
    preflight()
    cleanup()
    directory = Path(tempfile.mkdtemp(prefix="vpn-orbit-provision-lab-"))
    try:
        key, fingerprint = setup_fixture(directory)
        verify_existing_file_is_preserved(LAB)
        verify_cleanup_binding(LAB)
        profile_before = PROFILE.stat()

        readiness = provision(directory, key, fingerprint, check=True)
        expect(readiness.returncode == 0, "Readiness must pass over the pinned administrator SSH connection", readiness)
        web_readiness = verify_credentials({"ip": ADDRESS, "port": PORT, "fingerprint": fingerprint}, ADMIN,
                                           password=None, private_key=key.read_text(), preflight=True)
        expect(web_readiness == {"platform": "UBUNTU_24_04", "ssh": "VERIFIED"},
               f"WebUI readiness must execute sshd -t through non-interactive sudo: {web_readiness}")
        expect(not (directory / "output").exists(), "Readiness must leave no provisioning state")
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode != 0,
               "Readiness must not create the service account")
        expect(not Path("/var/lib/vpn-orbit-provision").exists(), "Readiness must leave no remote provisioning state")

        first = provision(directory, key, fingerprint,
                          fault="phase=account,when=after,kind=disconnect")
        expect(first.returncode != 0, "A disconnect during account must fail the run", first)
        first_state = state(directory)
        expect(first_state["phases"]["account"] == "IN_PROGRESS",
               f"Partial account must be durable: {first_state}")
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode == 0,
               "The fixture account should exist after the partial phase")
        retry = provision(directory, key, fingerprint)
        expect(retry.returncode == 0, "Retry after an account disconnect must repair", retry)
        expect(state(directory)["status"] == "VERIFIED", "Retry must verify the postcondition")
        result = probe(directory, key, fingerprint)
        observation = json.loads(result.stdout) if result.returncode == 0 else {}
        expect(observation.get("v") == 9 and observation.get("uid") == 0
               and observation.get("compose") == {"status": "NOT_CONFIGURED", "containers": []},
               "A fresh SSH connection must observe uid 0 and opt-in Compose disabled", result)
        removed = provision(directory, key, fingerprint, cleanup=True)
        expect(removed.returncode == 0, "Cleanup after success must succeed", removed)
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode != 0,
               "Cleanup must remove the service account")
        expect(probe(directory, key, fingerprint).returncode != 0, "Cleanup must revoke the managed key")

        partial = provision(directory, key, fingerprint,
                            fault="phase=helpers,when=after,kind=fail")
        expect(partial.returncode != 0, "A helper failure must fail the run", partial)
        expect((Path("/usr/local/libexec/vpn-orbit") / "ssh-gateway").exists(),
               "The partially installed helper should be present")
        repaired = provision(directory, key, fingerprint)
        expect(repaired.returncode == 0, "Retry must repair a partial helper installation", repaired)
        expect(state(directory)["status"] == "VERIFIED", "Helper retry must verify")
        provision(directory, key, fingerprint, cleanup=True)

        interrupted = provision(directory, key, fingerprint,
                                fault="phase=keys,when=after,kind=crash")
        expect(interrupted.returncode != 0, "A local interruption must fail the run", interrupted)
        expect(state(directory)["phases"]["keys"] == "IN_PROGRESS", "Key phase must remain resumable")
        resumed = provision(directory, key, fingerprint)
        expect(resumed.returncode == 0, "Retry after a local interruption must succeed", resumed)
        provision(directory, key, fingerprint, cleanup=True)

        failed = provision(directory, key, fingerprint, fault="phase=verify,kind=fail",
                           cleanup_on_failure=True)
        expect(failed.returncode != 0, "A failed postcondition must fail the run", failed)
        expect(state(directory)["status"] == "CLEANED", "Failed verification must roll back")
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode != 0,
               "Rollback must remove the service account")
        expect(not (directory / "output" / "probe").exists(), "Rollback must remove the local key")
        expect(not (directory / "output" / "targets.json").exists(), "Rollback must remove the policy")

        final = provision(directory, key, fingerprint)
        expect(final.returncode == 0, "The fixture must remain usable after rollback", final)
        expect(probe(directory, key, fingerprint).returncode == 0, "The final probe must succeed")
        provision(directory, key, fingerprint, cleanup=True)
        for path in NAMESPACES[:-1]:
            expect(not Path(path).exists(), f"Fixture artifact remains: {path}")
        expect(PROFILE.read_text() == SSH_PROFILE, "Cleanup must preserve the pre-existing SSH profile")
        expect(PROFILE.stat().st_ino == profile_before.st_ino and PROFILE.stat().st_mtime_ns == profile_before.st_mtime_ns,
               "Preparation and cleanup must preserve the existing SSH profile inode and contents")
        print(json.dumps({"status": "PASSED", "scenarios": [
            "disconnect-account", "retry-repair", "partial-helpers", "local-interruption",
            "verify-rollback", "cleanup"]}, sort_keys=True))
    finally:
        subprocess.run(["ip", "netns", "del", NAMESPACE], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "del", "vpnprobe0"], stderr=subprocess.DEVNULL)
        cleanup()
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    main()
