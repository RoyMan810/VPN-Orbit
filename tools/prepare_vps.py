"""Prepare an Ubuntu or Debian VPS with resumable, fault-tolerant phases.

The remote side is changed only through small, idempotent phases.  A durable
local journal records the last completed phase, so an SSH disconnect, a failed
postcondition or a partially created account can be repaired by running the
same command again.  ``--cleanup`` removes every artifact this tool created,
including the managed key pair and remote authorized key.
"""

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import subprocess
import sys
import tempfile
import time


if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vpn_orbit.runtime import vps_preparation as preparation
from vpn_orbit.runtime.protocol import PROBE_COMMAND, PROBE_REQUEST, PROBE_VERSION


STATE_FILE = ".provision-state.json"
FAULT_PHASES = preparation.PHASES + ("verify",)
FAULT_ENV = "VPN_ORBIT_PROVISION_FAULT"
SSH_PHASE_TIMEOUT = 60
SSH_PROBE_TIMEOUT = 15


def identifier():
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = secrets.randbits(128)
    return "".join(alphabet[(value >> shift) & 31] for shift in range(125, -1, -5))


def identify_host(ip, port, expected):
    lines = subprocess.check_output(
        ["ssh-keyscan", "-T", "5", "-t", "ed25519", "-p", str(port), ip],
        text=True, stderr=subprocess.DEVNULL,
    )
    keys = {tuple(line.split()[1:]) for line in lines.splitlines() if line and not line.startswith("#")}
    if len(keys) != 1:
        raise ValueError("Could not identify a single Ed25519 host key")
    algorithm, encoded = next(iter(keys))
    key = base64.b64decode(encoded, validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    if algorithm != "ssh-ed25519" or fingerprint != expected:
        raise ValueError(f"SSH host fingerprint mismatch (received {fingerprint})")
    return f"{algorithm} {encoded}"


def fault_spec():
    """Parse VPN_ORBIT_PROVISION_FAULT=phase=helpers,when=after,kind=disconnect."""
    raw = os.environ.get(FAULT_ENV, "").strip()
    if not raw:
        return None
    parts = dict(item.split("=", 1) for item in raw.split(",") if "=" in item)
    phase, when, kind = parts.get("phase"), parts.get("when", "after"), parts.get("kind", "disconnect")
    if phase not in FAULT_PHASES or when not in ("before", "after") or kind not in ("disconnect", "fail", "crash"):
        raise ValueError("Invalid fault injection specification")
    return {"phase": phase, "when": when, "kind": kind}


def inject_fault(script, spec):
    if spec is None or spec["kind"] == "crash" or spec["when"] == "after":
        return script
    command = "exit 255" if spec["kind"] == "disconnect" else "exit 1"
    return (command + "\n" + script) if spec["when"] == "before" else (script + "\n" + command)


class State:
    def __init__(self, path):
        self.path = path

    def load(self):
        if not self.path.exists():
            return None
        info = self.path.lstat()
        if (self.path.is_symlink() or not self.path.is_file() or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("Provisioning state file is not private")
        value = json.loads(self.path.read_text())
        if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("phases"), dict):
            raise ValueError("Provisioning state file is invalid")
        return value

    def save(self, value):
        value = {**value, "updated_at": int(time.time())}
        temporary = self.path.with_name(self.path.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def remove(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class Provisioner:
    """Orchestrates idempotent phases over an injected SSH transport."""

    def __init__(self, *, host, port, user, identity, output, run_remote, probe, fingerprint, state,
                 fault=None, cleanup_on_failure=False, sleep=time.sleep, firewall=False):
        self.host, self.port, self.user = host, port, user
        self.identity, self.output = identity, output
        self.run_remote, self.probe = run_remote, probe
        self.fingerprint, self.state = fingerprint, state
        self.fault, self.cleanup_on_failure, self.sleep = fault, cleanup_on_failure, sleep
        self.firewall = firewall
        self.key = output / "probe"
        self.firewall_key = output / "firewall"

    def _context(self):
        if not self._managed_file(self.key) or not self._managed_file(self.key.with_suffix(".pub")):
            raise ValueError("The managed observation key pair is missing; run --cleanup and retry")
        context = {"probe_public_key": self.key.with_suffix(".pub").read_bytes(),
                   "firewall_public_key": None, "firewall": self.firewall, "ssh_port": self.port}
        if self.firewall:
            if not self._managed_file(self.firewall_key) or not self._managed_file(self.firewall_key.with_suffix(".pub")):
                raise ValueError("The managed firewall key pair is missing; run --cleanup and retry")
            context["firewall_public_key"] = self.firewall_key.with_suffix(".pub").read_bytes()
        return context

    @staticmethod
    def _managed_file(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        return path.is_file() and not path.is_symlink() and info.st_nlink == 1

    def _record(self, journal, phase, status, *, error=None):
        journal["phases"][phase] = status
        journal["status"] = "FAILED" if (error is not None or status == "FAILED") else "IN_PROGRESS"
        if error is not None:
            journal["error"] = error
        else:
            journal.pop("error", None)
        self.state.save(journal)

    def _remote(self, script, *, fault_phase=None):
        spec = self.fault if fault_phase is not None and self.fault and self.fault["phase"] == fault_phase else None
        result = self.run_remote(inject_fault(script, spec))
        if spec is not None and spec["when"] == "after" and spec["kind"] in ("disconnect", "fail"):
            code = 255 if spec["kind"] == "disconnect" else 1
            raise subprocess.CalledProcessError(code, ["ssh"])
        return result

    def _cleanup(self, journal):
        try:
            public_key = self.key.with_suffix(".pub")
            if not self._managed_file(public_key):
                raise OSError("The saved public observation key is missing or untrusted")
            self._remote("# vpn-orbit-phase: cleanup\n" + preparation.cleanup_script(public_key.read_bytes()))
        except (OSError, subprocess.SubprocessError):
            journal["status"] = "CLEANUP_FAILED"
            self.state.save(journal)
            raise ValueError("Remote cleanup is unconfirmed; managed credentials retained") from None
        paths = [self.key, self.key.with_suffix(".pub"), self.firewall_key,
                 self.firewall_key.with_suffix(".pub"), self.output / "targets.json"]
        for path in paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        journal["status"] = "CLEANED"
        journal["phases"] = {phase: "PENDING" for phase in preparation.PHASES}
        self.state.save(journal)

    def _verify_admin(self, journal, phase):
        try:
            # A new administrator session must execute the trusted command.
            marker = ("VPN_ORBIT_ADMIN_" + secrets.token_hex(16) + "\n").encode("ascii")
            script = 'test "$(/usr/bin/id -u)" = 0 && printf %s ' + shlex.quote(marker.decode("ascii"))
            self.run_remote(script, expected_stdout=marker)
        except (OSError, ValueError, subprocess.SubprocessError):
            self._record(journal, phase, "IN_PROGRESS", error="SSH_ADMIN_ACCESS_UNCONFIRMED")
            raise ValueError(f"SSH_ADMIN_ACCESS_UNCONFIRMED during {phase}") from None

    def _probe_verified(self):
        try:
            observation = self.probe(self.key)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
            return False
        return isinstance(observation, dict) and observation.get("v") == PROBE_VERSION and observation.get("uid") == 0

    def _reconcile_phase(self, journal, phase, context):
        script = preparation.PHASE_SCRIPTS[phase](context, inspect=True)
        try:
            self._remote(f"# vpn-orbit-readback: {phase}\n" + script)
        except subprocess.CalledProcessError as error:
            if error.returncode == preparation.PHASE_INCOMPLETE:
                return False
            code = "READBACK_UNAVAILABLE" if error.returncode in (preparation.REMOTE_BUSY, 255) else "READBACK_CONFLICT"
        except (OSError, subprocess.SubprocessError):
            code = "READBACK_UNAVAILABLE"
        else:
            if phase != "sshd":
                return True
            if self._probe_verified():
                # The observation key only confirms its own live SSH settings.
                return not context["firewall"]
            code = "SSH_ACTIVATION_UNCONFIRMED"
        self._record(journal, phase, "IN_PROGRESS", error=code)
        raise ValueError(f"{code} during {phase}") from None

    def run(self):
        journal = self.state.load()
        now = int(time.time())
        if journal is None:
            journal = {"version": 1, "host": self.host, "port": self.port, "user": self.user,
                       "fingerprint": self.fingerprint, "phases": {phase: "PENDING" for phase in preparation.PHASES},
                       "status": "IN_PROGRESS", "attempts": 0, "created_at": now}
        else:
            cleanup_journal(journal, host=self.host, port=self.port, user=self.user, fingerprint=self.fingerprint)
        journal["attempts"] = journal.get("attempts", 0) + 1
        self.state.save(journal)

        try:
            context = self._context()
            if journal["phases"].get("preflight") != "DONE":
                self._verify_admin(journal, "preflight")
            for phase in preparation.PHASES:
                progress = journal["phases"].get(phase)
                if progress == "DONE":
                    continue
                if progress == "IN_PROGRESS" and self._reconcile_phase(journal, phase, context):
                    self._record(journal, phase, "DONE")
                    continue
                self._record(journal, phase, "IN_PROGRESS")
                script = preparation.PHASE_SCRIPTS[phase](context)
                script = f"# vpn-orbit-phase: {phase}\n" + script
                try:
                    self._remote(script, fault_phase=phase)
                except (OSError, subprocess.SubprocessError) as error:
                    if self.fault and self.fault["phase"] == phase and self.fault["kind"] == "crash":
                        raise
                    code = "PROVISION_PHASE_FAILED"
                    if isinstance(error, subprocess.TimeoutExpired):
                        code = "SSH_TIMEOUT"
                    elif isinstance(error, subprocess.CalledProcessError):
                        code = {255: "SSH_DISCONNECTED", preparation.REMOTE_BUSY: "VPS_PREPARATION_BUSY"}.get(error.returncode, code)
                    self._record(journal, phase, "IN_PROGRESS", error=code)
                    raise ValueError(f"{code} during {phase}") from None
                if self.fault and self.fault["phase"] == phase and self.fault["kind"] == "crash":
                    self._record(journal, phase, "IN_PROGRESS", error="WORKSTATION_INTERRUPTED")
                    raise ValueError("WORKSTATION_INTERRUPTED during " + phase)
                self._record(journal, phase, "DONE")

            self._record(journal, "verify", "IN_PROGRESS")
            self._verify_admin(journal, "verify")
            if (self.fault and self.fault["phase"] == "verify") or not self._probe_verified():
                self._record(journal, "verify", "FAILED", error="POSTCONDITION_FAILED")
                if self.cleanup_on_failure:
                    self._cleanup(journal)
                raise ValueError("Postcondition verification failed")
            journal["phases"]["verify"] = "DONE"
            journal["status"] = "VERIFIED"
            journal.pop("error", None)
            self.state.save(journal)
            return journal
        except ValueError:
            raise
        except Exception:
            journal["status"] = "FAILED"
            journal["error"] = "UNEXPECTED_FAILURE"
            self.state.save(journal)
            raise


def cleanup_journal(journal, *, host, port, user, fingerprint):
    if journal is None:
        raise ValueError("No provisioning state exists for cleanup")
    expected = (host, port, user, fingerprint)
    actual = tuple(journal.get(name) for name in ("host", "port", "user", "fingerprint"))
    if actual != expected:
        raise ValueError("Saved provisioning state belongs to a different VPS")


def _check_remote_reply(command, expected, timeout):
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, stdout=subprocess.PIPE) as process:
        reply = bytearray()
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired(command, timeout)
                chunk = os.read(process.stdout.fileno(), len(expected) + 1 - len(reply))
                if not chunk:
                    break
                reply.extend(chunk)
                if not expected.startswith(reply):
                    raise ValueError("Unexpected administrator verification reply")
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
            if status != 0:
                raise subprocess.CalledProcessError(status, command)
            if reply != expected:
                raise ValueError("Unexpected administrator verification reply")
        finally:
            if process.poll() is None:
                process.kill()


def build_transport(ip, port, identity, user, host_key):
    known = tempfile.NamedTemporaryFile(prefix="vpn-orbit-known-", delete=False)
    known.close()
    path = Path(known.name)
    host = ip if port == 22 else f"[{ip}]:{port}"
    path.write_text(f"{host} {host_key}\n")
    base = ["ssh", "-F", "/dev/null", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={path}",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=10"]
    if identity is None:
        auth = ["-o", "PreferredAuthentications=keyboard-interactive,password"]
    else:
        auth = ["-i", str(identity), "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"]

    def run_remote(script, *, expected_stdout=None):
        shell = ["/bin/sh", "-c", script, "vpn-orbit-provision"]
        remote = shlex.join(shell if user == "root" else ["sudo", "--", *shell]) + ' "${SSH_CONNECTION%% *}"'
        command = [*base, "-T", *auth, f"{user}@{ip}", remote]
        if expected_stdout is None:
            subprocess.run(command, check=True, timeout=SSH_PHASE_TIMEOUT)
        else:
            _check_remote_reply(command, expected_stdout, SSH_PHASE_TIMEOUT)

    def cleanup():
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    return run_remote, cleanup, base, auth


def make_probe(ip, port, key, known_hosts_path):
    def probe(key_path):
        host = ip if port == 22 else f"[{ip}]:{port}"
        # The caller already pinned the host key; a per-probe file avoids TOFU.
        result = subprocess.check_output(
            ["ssh", "-F", "/dev/null", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
             "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={known_hosts_path}",
             "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=10",
             "-T", "-i", str(key_path), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
             f"{preparation.PROBE_ACCOUNT}@{ip}", PROBE_COMMAND],
            input=PROBE_REQUEST.decode("ascii"), text=True, timeout=SSH_PROBE_TIMEOUT,
        )
        return json.loads(result)
    return probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=ipaddress.ip_address, help="Numeric VPS IP")
    parser.add_argument("--user", required=True, help="Existing SSH administrator (root or sudo)")
    parser.add_argument("--port", default=22, type=int)
    parser.add_argument("--fingerprint", required=True, help="Ed25519 SHA256 fingerprint from the VPS console")
    parser.add_argument("--identity", type=Path, help="Administrator's SSH private key. Omit for an interactive password.")
    parser.add_argument("--output", type=Path, help="Private directory for the managed key and Controller policy")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--check", action="store_true", help="Check host readiness without preparing it")
    operation.add_argument("--cleanup", action="store_true", help="Remove remote and local provisioning artifacts, then exit")
    parser.add_argument("--cleanup-on-failure", action="store_true", help="Roll back when postcondition verification fails")
    parser.add_argument("--firewall", action="store_true",
                        help="Also provision the dedicated typed firewall account, key and capability")
    args = parser.parse_args()
    if (not isinstance(args.host, ipaddress.IPv4Address) or args.host.is_loopback or args.host.is_link_local
            or args.host.is_unspecified or args.host.is_multicast or str(args.host) == "100.100.100.200"
            or not 1 <= args.port <= 65535 or not re.fullmatch(r"[a-z_][a-z0-9_-]*", args.user)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", args.fingerprint)):
        parser.error("Provide a non-loopback IPv4 address, SSH port, administrator and Ed25519 fingerprint")
    if args.identity is not None and not args.identity.is_file():
        parser.error("Administrator identity file does not exist")
    if args.check and (args.output is not None or args.cleanup_on_failure):
        parser.error("--check does not use --output or --cleanup-on-failure")
    if not args.check and args.output is None:
        parser.error("--output is required for preparation or cleanup")
    ip = str(args.host)
    os.umask(0o077)
    lock = None
    original_directory = None
    try:
        if args.check:
            host_key = identify_host(ip, args.port, args.fingerprint)
            run_remote, cleanup_transport, _, _ = build_transport(ip, args.port, args.identity, args.user, host_key)
            try:
                run_remote(preparation.check_remote(firewall=args.firewall) + preparation.inspect_host_readiness() + """
printf 'Default route: IPv4 %s, IPv6 %s\\nDocker CLI: %s\\nSystem Compose plugin: %s\\n' \\
    "$orbit_ipv4" "$orbit_ipv6" "$orbit_docker" "$orbit_compose"
""")
            finally:
                cleanup_transport()
            print("VPS passed the OS, package, SSH configuration and account checks for preparation.")
            return
        fault = fault_spec()
        if not args.output.exists():
            if args.cleanup:
                raise ValueError("Provisioning state directory does not exist")
            args.output.mkdir(mode=0o700, exist_ok=True)
        lock = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(lock)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Output directory must be private and owned by the current user")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another preparation is using this output directory") from None
        if args.identity is not None:
            args.identity = args.identity.absolute()
        original_directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        os.fchdir(lock)
        output = Path(".")
        state = State(output / STATE_FILE)
        cleanup_state = None
        if args.cleanup:
            cleanup_state = state.load()
            cleanup_journal(cleanup_state, host=ip, port=args.port, user=args.user, fingerprint=args.fingerprint)
            if cleanup_state["status"] == "CLEANED":
                print("Provisioning artifacts removed.")
                return
            public_key = output / "probe.pub"
            if not Provisioner._managed_file(public_key):
                raise ValueError("The saved public observation key is required for cleanup")
            cleanup = preparation.cleanup_script(public_key.read_bytes())
        host_key = identify_host(ip, args.port, args.fingerprint)
        run_remote, cleanup_transport, _, _ = build_transport(ip, args.port, args.identity, args.user, host_key)
        host = ip if args.port == 22 else f"[{ip}]:{args.port}"
        known_hosts = Path(tempfile.mkdtemp(prefix="vpn-orbit-ssh-")) / "known_hosts"
        known_hosts.write_text(f"{host} {host_key}\n")
        try:
            if args.cleanup:
                run_remote(cleanup)
                for path in (output / "probe", output / "probe.pub",
                             output / "firewall", output / "firewall.pub",
                             output / "targets.json"):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                cleanup_state["status"] = "CLEANED"
                cleanup_state["phases"] = {phase: "PENDING" for phase in preparation.PHASES}
                state.save(cleanup_state)
                print("Provisioning artifacts removed.")
                return

            key = output / "probe"
            firewall_key = output / "firewall"
            policy = output / "targets.json"
            if key.is_symlink() or key.with_suffix(".pub").is_symlink():
                raise ValueError("The saved observation key pair contains a symlink")
            if not key.exists():
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            if args.firewall and (firewall_key.is_symlink() or firewall_key.with_suffix(".pub").is_symlink()):
                raise ValueError("The saved firewall key pair contains a symlink")
            if args.firewall and not firewall_key.exists():
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(firewall_key)], check=True)
            capabilities = ["host.probe"] + (["firewall.apply"] if args.firewall else [])
            scope = {"ip": ip, "port": args.port, "allowed_cidrs": [ip + "/32"], "host_key": host_key,
                     "policy_revision": 1, "dependencies": [], "capabilities": capabilities}
            if policy.is_symlink():
                raise ValueError("The saved policy is a symlink")
            if policy.exists():
                value = json.loads(policy.read_text())
                target, = value["targets"]
                if any(target.get(name) != value for name, value in scope.items()):
                    raise ValueError("The saved policy belongs to a different VPS or capability set")
                if ("firewall_secret_ref" in target) != args.firewall:
                    raise ValueError("The saved policy belongs to a different capability set")
                if any(not Provisioner._managed_file(path) for path in (key, key.with_suffix(".pub"))):
                    raise ValueError("The saved observation key pair is missing")
                if args.firewall and any(not Provisioner._managed_file(path)
                                         for path in (firewall_key, firewall_key.with_suffix(".pub"))):
                    raise ValueError("The saved firewall key pair is missing")
            else:
                target = {**scope, "id": identifier(), "secret_ref": identifier() + ":v1"}
                if args.firewall:
                    target["firewall_secret_ref"] = identifier() + ":v1"
                policy.write_text(json.dumps({"v": 1, "targets": [target]}, indent=2) + "\n")
            provisioner = Provisioner(
                host=ip, port=args.port, user=args.user, identity=args.identity, output=output,
                run_remote=run_remote, probe=make_probe(ip, args.port, key, known_hosts),
                fingerprint=args.fingerprint, state=state, fault=fault,
                cleanup_on_failure=args.cleanup_on_failure, firewall=args.firewall,
            )
            provisioner.run()
            saved_output = Path.cwd()
        finally:
            cleanup_transport()
            try:
                known_hosts.parent.rmdir()
            except OSError:
                pass
    except subprocess.TimeoutExpired:
        parser.exit(1, "VPS preparation failed: SSH command timed out.\n")
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"VPS preparation failed: {exc}\n" if not isinstance(exc, subprocess.CalledProcessError)
                    else f"VPS preparation failed (command exited with status {exc.returncode}).\n")
    finally:
        if original_directory is not None:
            os.fchdir(original_directory)
            os.close(original_directory)
        if lock is not None:
            os.close(lock)
    print(f"SSH observation verified. Controller policy: {saved_output / 'targets.json'}")
    print(f"Resource ID: {target['id']} · Secret Reference: {target['secret_ref']}")
    print(f"Managed key for Broker import: {saved_output / 'probe'}")
    if args.firewall:
        print(f"Managed firewall key for Broker import: {saved_output / 'firewall'}")


if __name__ == "__main__":
    main()
