"""Rollback drill for the single authorized VPN-Orbit disposable libvirt VM."""

from contextlib import contextmanager
import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from xml.etree import ElementTree as XML


VM = "416afd02-1ce6-4092-8e1c-ff3fd75375db"
ADDRESS = "192.168.122.244"
ACCOUNT = "ho"
FINGERPRINT = "SHA256:XfP6BdoBdAvoE0/sYqUayBDSWJXybJDuYXqh0eHRjfI"
SNAPSHOT = "vpn-orbit-release-review-2026-11-23"
BASE = "/var/lib/libvirt/images/ubuntu24.04.clear"


def capture(*args, timeout=15):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=timeout,
                                   env={**os.environ, "LC_ALL": "C"}).strip()


def virsh(*args):
    return capture("virsh", "--connect", "qemu:///system", *args)


def domain(xml):
    tree = XML.fromstring(xml)
    if tree.findtext("uuid") != VM:
        raise ValueError("STAGING_DOMAIN_IDENTITY")
    disks = [disk for disk in tree.findall("./devices/disk")
             if disk.get("device") == "disk"]
    if len(disks) != 1 or disks[0].find("target").get("dev") != "vda":
        raise ValueError("STAGING_DISK_LAYOUT")
    return tree, disks[0]


def overlay_xml(original, path):
    tree, disk = domain(original)
    disk.find("source").set("file", path)
    backing = disk.find("backingStore")
    if backing is not None:
        disk.remove(backing)
    return XML.tostring(tree, encoding="unicode")


def pinned_ssh(directory):
    lines = capture("ssh-keyscan", "-T", "5", "-t", "ed25519", ADDRESS).splitlines()
    keys = [line.split() for line in lines if line and not line.startswith("#")]
    if len(keys) != 1 or len(keys[0]) != 3 or keys[0][1] != "ssh-ed25519":
        raise ValueError("STAGING_HOST_KEY_UNAVAILABLE")
    digest = base64.b64encode(hashlib.sha256(base64.b64decode(keys[0][2], validate=True)).digest()).decode().rstrip("=")
    if "SHA256:" + digest != FINGERPRINT:
        raise ValueError("STAGING_HOST_KEY_MISMATCH")
    known = directory / "known_hosts"
    known.write_text(" ".join(keys[0]) + "\n")
    known.chmod(0o600)
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known}",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=3", f"{ACCOUNT}@{ADDRESS}"]


def wait_ssh(ssh):
    for _ in range(40):
        try:
            output = capture(*ssh, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256", timeout=5)
            if output.split()[1] != FINGERPRINT:
                raise ValueError("STAGING_HOST_KEY_MISMATCH")
            return
        except subprocess.CalledProcessError as error:
            if "Host key verification failed" in error.stderr or "IDENTIFICATION HAS CHANGED" in error.stderr:
                raise ValueError("STAGING_HOST_KEY_MISMATCH") from None
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1)
    raise TimeoutError("STAGING_SSH_UNAVAILABLE")


def stop():
    if virsh("domstate", VM) == "shut off":
        return
    virsh("shutdown", VM)
    for _ in range(45):
        if virsh("domstate", VM) == "shut off":
            return
        time.sleep(1)
    raise TimeoutError("STAGING_GRACEFUL_SHUTDOWN_TIMED_OUT")


def define(xml):
    # The restore input is the exact saved bytes, never a derived filename.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml") as stream:
        stream.write(xml)
        stream.flush()
        virsh("define", "--validate", stream.name)


@contextmanager
def disposable_disk(evidence):
    """Switch to a fresh baseline overlay, and restore the saved domain on every exit.

    The caller may run acceptance using the yielded pinned SSH argv. A failed
    restoration raises an error and leaves original.xml for emergency recovery.
    Disks are never deleted or force-stopped.
    """
    evidence = Path(evidence)
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    lock_root = Path.home() / ".cache/vpn-orbit-staging"
    lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (lock_root / "domain.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = virsh("dumpxml", "--inactive", VM)
        _, disk = domain(original)
        active = disk.find("source").get("file")
        if not active or not active.startswith("/var/lib/libvirt/images/ubuntu24.04."):
            raise ValueError("STAGING_SOURCE_DISK")
        snapshot = XML.fromstring(virsh("snapshot-dumpxml", VM, SNAPSHOT))
        if snapshot.find("domain/uuid").text != VM:
            raise ValueError("STAGING_SNAPSHOT_IDENTITY")
        if snapshot.find("domain/devices/disk/source").get("file") != BASE:
            raise ValueError("STAGING_SNAPSHOT_BASE")
        console = virsh("domdisplay", VM)
        if not console.startswith("spice://127.0.0.1:"):
            raise ValueError("STAGING_CONSOLE_UNAVAILABLE")
        with (evidence / "original.xml").open("x") as saved:
            os.fchmod(saved.fileno(), 0o600)
            saved.write(original)
            saved.flush()
            os.fsync(saved.fileno())
        ssh = pinned_ssh(evidence)
        wait_ssh(ssh)
        capture(*ssh, "test \"$(uname -m)\" = x86_64 && . /etc/os-release && test \"$ID\" = ubuntu && test \"$VERSION_ID\" = 24.04")
        name = "ubuntu24.04.vpn-orbit-drill-" + os.urandom(6).hex()
        virsh("vol-create-as", "default", name, "42949672960", "--allocation", "0",
              "--format", "qcow2", "--backing-vol", BASE, "--backing-vol-format", "qcow2")
        replacement = overlay_xml(original, "/var/lib/libvirt/images/" + name)
        (evidence / "overlay.xml").write_text(replacement)
        try:
            stop()
            define(replacement)
            virsh("start", VM)
            wait_ssh(ssh)
            capture(*ssh, "test ! -e /opt/vpn-orbit && test ! -e /var/lib/docker")
            yield ssh
        finally:
            stop()
            define(original)
            virsh("start", VM)
            wait_ssh(ssh)
            if domain(virsh("dumpxml", "--inactive", VM))[1].find("source").get("file") != active:
                raise ValueError("STAGING_RESTORE_DISK_MISMATCH")
            (evidence / "restored").write_text("Pinned SSH and original disk verified.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True, help="New private evidence directory")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise SystemExit("Staging drill interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    with disposable_disk(args.evidence):
        print("Clean rollback overlay booted; pinned SSH verified.", flush=True)
    print("Original staging disk and pinned SSH restored.", flush=True)


if __name__ == "__main__":
    main()
