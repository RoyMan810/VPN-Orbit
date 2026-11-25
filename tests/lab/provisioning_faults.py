#!/usr/bin/env python3
"""Disposable-VM provisioning fault injection over a real SSH network namespace."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from tools import prepare_vps
from vpn_orbit.runtime import vps_preparation as preparation
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
ADMIN_SUDOERS = Path("/etc/sudoers.d/vpn-orbit-provision-lab")
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
    for path in (ADMIN_SUDOERS, PROFILE):
        path.unlink(missing_ok=True)
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
    password = secrets.token_urlsafe(32)
    run(["chpasswd"], input=f"{ADMIN}:{password}\n")
    key = directory / "admin"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    ssh_dir = Path("/home") / ADMIN / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    (ssh_dir / "authorized_keys").write_bytes((key.with_suffix(".pub")).read_bytes())
    ssh_dir.chmod(0o700)
    (ssh_dir / "authorized_keys").chmod(0o600)
    run(["chown", "-R", f"{ADMIN}:{ADMIN}", str(ssh_dir)])
    ADMIN_SUDOERS.write_text(f"{ADMIN} ALL=(root) NOPASSWD: ALL\n")
    ADMIN_SUDOERS.chmod(0o440)

    # OpenSSH reads ForceCommand at startup.  Install the exact profile before
    # starting the fixture so the phase's identical write needs no fixture reload.
    PROFILE.write_text(preparation.SSH_PROFILE)
    PROFILE.chmod(0o644)

    host_key = LAB / "host"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
    config = LAB / "sshd_config"
    config.write_text(
        f"Port {PORT}\nListenAddress {ADDRESS}\nHostKey {host_key}\nPidFile {LAB / 'sshd.pid'}\n"
        f"UsePAM yes\nStrictModes yes\nPermitRootLogin no\nPermitUserEnvironment no\n"
        f"AllowUsers {ADMIN} {SERVICE}\n"
        f"PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        f"PidFile {LAB / 'sshd.pid'}\nInclude /etc/ssh/sshd_config.d/*.conf\n"
        f"Match User {ADMIN}\n    PasswordAuthentication yes\n"
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
    return key, fingerprint, password


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
    preamble = "set -eu\numask 077\norbit_missing=0\n"
    script = preamble + preparation.install_file(path, content, "0644", "test-file")
    readback = preamble + preparation.install_file(path, content, "0644", "test-file", inspect=True)
    env = {**os.environ, "work": str(scratch), "STATE": str(scratch)}
    for mode, accepted in ((0o640, False), (0o644, True)):
        path.chmod(mode)
        before = path.stat()
        result = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True)
        expect((result.returncode == 0) == accepted, "Only matching protected metadata may be reused", result)
        checked = subprocess.run(["/bin/sh", "-c", readback], env=env, capture_output=True, text=True)
        expect((checked.returncode == 0) == accepted, "Readback must require the same protected metadata", checked)
        after = path.stat()
        expect((after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns) ==
               (before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns)
               and path.read_bytes() == content, "Existing file must stay untouched")
        expect(not (scratch / "created-test-file").exists(), "Existing file must not be marked for removal")

    managed = scratch / "created"
    run(["/bin/sh", "-c", preamble + preparation.install_file(managed, content, "0644", "test-file")], env=env)
    marker = scratch / "created-test-file"
    expect(marker.is_file(), "Installation must record the created file")
    marker_before = marker.read_bytes()
    marker.write_bytes(b"incorrect signature\n")
    check_missing = preamble + preparation.install_file(managed, content, "0644", "test-file", inspect=True)
    managed.unlink()
    checked = subprocess.run(["/bin/sh", "-c", check_missing], env=env, capture_output=True, text=True)
    expect(checked.returncode != 0 and not managed.exists() and marker.read_bytes() == b"incorrect signature\n",
           "Readback must reject a missing file with an unexpected ownership marker", checked)
    marker.write_bytes(marker_before)
    run(["/bin/sh", "-c", check_missing + '\ntest "$orbit_missing" = 1'], env=env)
    expect(not managed.exists(), "Readback must leave a missing file untouched")
    run(["/bin/sh", "-c", preamble + preparation.install_file(managed, content, "0644", "test-file")], env=env)
    remove = preparation.CHECK_OWNED_FILE + f"owned_file {managed} test-file remove\n"
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
    pending = directory / "locked-state"
    pending.mkdir(0o700)
    lock = os.open(pending, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with patch.object(preparation, "REMOTE_STATE", pending):
            script = "set -eu\numask 077\n" + preparation._state_directory(key, inspect=True)
            busy = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
        expect(busy.returncode == preparation.REMOTE_BUSY and not list(pending.iterdir()),
               "Readback must report an outstanding remote command without changing state", busy)
    finally:
        os.close(lock)
    protected_file = directory / "managed-outside-this-preparation"
    protected_file.write_text("existing fixture\n")
    with patch.multiple(preparation, REMOTE_STATE=old_state, FIREWALL_AUTHORIZED=protected_file):
        legacy = subprocess.run(["/bin/sh", "-c", preparation.cleanup_script(key)], capture_output=True, text=True)
        expect(legacy.returncode != 0 and protected_file.is_file(), "Legacy intent must not authorize file removal", legacy)

    with patch.multiple(preparation, REMOTE_STATE=directory / "missing-state", FIREWALL_AUTHORIZED=protected_file):
        missing = subprocess.run(["/bin/sh", "-c", preparation.cleanup_script(key)], capture_output=True, text=True)
        expect(missing.returncode != 0 and protected_file.is_file(), "A missing journal must not confirm cleanup", missing)

    bound_state = directory / "bound-state"
    bound_state.mkdir(mode=0o700)
    with patch.multiple(preparation, REMOTE_STATE=bound_state, FIREWALL_AUTHORIZED=protected_file):
        run(["/bin/sh", "-c", "set -eu\numask 077\n" + preparation._state_directory(key, create=True)])
        run(["/bin/sh", "-c", "set -eu\n" + preparation._state_directory(key)])
        mismatch = subprocess.run(["/bin/sh", "-c", preparation.cleanup_script(b"different key")],
                                  capture_output=True, text=True)
        expect(mismatch.returncode != 0, "A different preparation must not own an existing journal", mismatch)
        account_marker = bound_state / f"account-created-{SERVICE}"
        account_marker.write_text("408\n")
        account_marker.chmod(0o600)
        fake_account = f"""
id() {{
    case "$1" in
        -u) printf '%s\\n' 408 ;;
        -Gn) printf '%s\\n' {SERVICE} ;;
    esac
}}
getent() {{ printf '%s\\n' '{SERVICE}:x:408:408::/changed-home:/bin/sh'; }}
passwd() {{ printf '%s\\n' '{SERVICE} L'; }}
pkill() {{ printf '%s\\n' unexpected-pkill; }}
userdel() {{ printf '%s\\n' unexpected-userdel; }}
"""
        isolated_cleanup = preparation.cleanup_script(key)
        for path in ("/etc", "/usr/local", "/var/lib"):
            isolated_cleanup = isolated_cleanup.replace(path, str(directory) + path)
        conflict = subprocess.run(["/bin/sh", "-c", fake_account + isolated_cleanup],
                                  capture_output=True, text=True)
        expect(conflict.returncode == preparation.ACCOUNT_CONFLICT and not conflict.stdout
               and account_marker.read_text() == "408\n", "Cleanup must stop before deleting a conflicting account", conflict)
        account_marker.unlink()
        (bound_state / "unrelated").write_text("existing fixture\n")
        unknown = subprocess.run(["/bin/sh", "-c", preparation.cleanup_script(key)], capture_output=True, text=True)
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
        key, fingerprint, password = setup_fixture(directory)
        verify_existing_file_is_preserved(LAB)
        verify_cleanup_binding(LAB)
        profile_before = PROFILE.stat()

        readiness = provision(directory, key, fingerprint, check=True)
        expect(readiness.returncode == 0, "Readiness must pass over the pinned administrator SSH connection", readiness)
        web_readiness = verify_credentials({"ip": ADDRESS, "port": PORT, "fingerprint": fingerprint}, ADMIN,
                                           password=None, private_key=key.read_text(), preflight=True)
        expect(web_readiness == {"platform": "UBUNTU_24_04", "ssh": "VERIFIED"},
               f"WebUI readiness must execute sshd -t through non-interactive sudo: {web_readiness}")
        sudoers = ADMIN_SUDOERS.read_text()
        try:
            ADMIN_SUDOERS.write_text(f"{ADMIN} ALL=(root) PASSWD: ALL\n")
            target = {"ip": ADDRESS, "port": PORT, "fingerprint": fingerprint}
            key_only = verify_credentials(target, ADMIN, password=None, private_key=key.read_text(), preflight=True)
            expect(key_only["ssh"] == "SUDO_OR_SSHD_UNVERIFIED",
                   f"SSH key alone must not pass password-protected sudo: {key_only}")
            with_password = verify_credentials(target, ADMIN, password=password, private_key=None, preflight=True)
            expect(with_password == {"platform": "UBUNTU_24_04", "ssh": "VERIFIED"},
                   f"WebUI readiness must verify password-protected sudo: {with_password}")
        finally:
            ADMIN_SUDOERS.write_text(sudoers)
        expect(not (directory / "output").exists(), "Readiness must leave no provisioning state")
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode != 0,
               "Readiness must not create the service account")
        expect(not Path("/var/lib/vpn-orbit-provision").exists(), "Readiness must leave no remote provisioning state")

        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
             "--shell", "/bin/false", SERVICE])
        try:
            mismatch = verify_credentials(target, ADMIN, password=None, private_key=key.read_text(), preflight=True)
            expect(mismatch["ssh"] == "OBSERVATION_ACCOUNT_CONFLICT",
                   f"WebUI must report a conflicting existing account: {mismatch}")
            cli_mismatch = provision(directory, key, fingerprint, check=True)
            expect(cli_mismatch.returncode != 0 and "Conflicting provisioning account" in cli_mismatch.stderr,
                   "CLI readiness must reject the same account", cli_mismatch)
            expect(not Path(preparation.REMOTE_STATE).exists() and not (directory / "output").exists(),
                   "Readiness must leave a conflicting VPS and local state untouched")
            expect(output(["getent", "passwd", SERVICE]).endswith(":/nonexistent:/bin/false"),
                   "Readiness must leave the conflicting account untouched")
        finally:
            run(["userdel", SERVICE])

        first = provision(directory, key, fingerprint,
                          fault="phase=account,when=after,kind=disconnect")
        expect(first.returncode != 0, "A disconnect during account must fail the run", first)
        first_state = state(directory)
        expect(first_state["phases"]["account"] == "IN_PROGRESS",
               f"Partial account must be durable: {first_state}")
        expect(subprocess.run(["getent", "passwd", SERVICE], capture_output=True).returncode == 0,
               "The fixture account should exist after the partial phase")
        retry = provision(directory, key, fingerprint, fault="phase=account,when=before,kind=fail")
        expect(retry.returncode == 0, "A confirmed account must not be created again after a disconnect", retry)
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
        gateway = Path("/usr/local/libexec/vpn-orbit/ssh-gateway")
        original = gateway.read_bytes()
        changed = original + b"\n# changed lab fixture\n"
        gateway.write_bytes(changed)
        conflict = provision(directory, key, fingerprint)
        expect(conflict.returncode != 0 and "READBACK_CONFLICT during helpers" in conflict.stderr,
               "Changed helpers must stop preparation", conflict)
        expect(gateway.read_bytes() == changed and state(directory)["phases"]["keys"] == "PENDING",
               "A conflict must leave the file and the next phase untouched")
        gateway.write_bytes(original)
        repaired = provision(directory, key, fingerprint, fault="phase=helpers,when=before,kind=fail")
        expect(repaired.returncode == 0, "Confirmed helpers must not be reinstalled", repaired)
        expect(state(directory)["status"] == "VERIFIED", "Helper retry must verify")
        provision(directory, key, fingerprint, cleanup=True)

        missing = provision(directory, key, fingerprint, fault="phase=helpers,when=before,kind=fail")
        expect(missing.returncode != 0, "An interruption before installing helpers must fail the run", missing)
        expect(not (Path("/usr/local/libexec/vpn-orbit") / "ssh-gateway").exists(), "Helpers must still be absent")
        repaired = provision(directory, key, fingerprint)
        expect(repaired.returncode == 0, "Readback must allow the installation of missing helpers", repaired)
        provision(directory, key, fingerprint, cleanup=True)

        interrupted = provision(directory, key, fingerprint,
                                fault="phase=keys,when=after,kind=crash")
        expect(interrupted.returncode != 0, "A local interruption must fail the run", interrupted)
        expect(state(directory)["phases"]["keys"] == "IN_PROGRESS", "Key phase must remain resumable")
        resumed = provision(directory, key, fingerprint, fault="phase=keys,when=before,kind=fail")
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
        admin_authorized = Path("/home") / ADMIN / ".ssh/authorized_keys"
        original_key = admin_authorized.read_bytes()
        try:
            admin_authorized.write_bytes(b'command="/bin/true" ' + original_key)
            inaccessible = provision(directory, key, fingerprint, cleanup_on_failure=True)
            expect(inaccessible.returncode != 0 and "SSH_ADMIN_ACCESS_UNCONFIRMED" in inaccessible.stderr,
                   "An administrative key which only runs a forced command must not verify", inaccessible)
            expect(state(directory)["phases"]["verify"] == "IN_PROGRESS"
                   and probe(directory, key, fingerprint).returncode == 0,
                   "An unconfirmed administrative session must leave preparation resumable and observation intact")
        finally:
            admin_authorized.write_bytes(original_key)
        retried = provision(directory, key, fingerprint, fault="phase=sshd,when=before,kind=fail")
        expect(retried.returncode == 0 and state(directory)["status"] == "VERIFIED",
               "A restored administrator session must verify without reapplying the SSH profile", retried)
        provision(directory, key, fingerprint, cleanup=True)
        for path in NAMESPACES[:-1]:
            expect(not Path(path).exists(), f"Fixture artifact remains: {path}")
        expect(PROFILE.read_text() == preparation.SSH_PROFILE, "Cleanup must preserve the pre-existing SSH profile")
        expect(PROFILE.stat().st_ino == profile_before.st_ino and PROFILE.stat().st_mtime_ns == profile_before.st_mtime_ns,
               "Preparation and cleanup must preserve the existing SSH profile inode and contents")
        print(json.dumps({"status": "PASSED", "scenarios": [
            "disconnect-account", "retry-repair", "partial-helpers", "local-interruption",
            "verify-rollback", "sudo-password", "account-conflict", "admin-access-recovery", "cleanup"]}, sort_keys=True))
    finally:
        subprocess.run(["ip", "netns", "del", NAMESPACE], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "del", "vpnprobe0"], stderr=subprocess.DEVNULL)
        cleanup()
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    main()
