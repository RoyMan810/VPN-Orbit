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
import shlex
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
PROBE_ACCOUNT = "vpn-orbit-svc"
PROBE_HOME = "/var/lib/vpn-orbit-ssh/vpn-orbit-svc"
FIREWALL_ACCOUNT = "vpn-orbit-firewall"
FIREWALL_HOME = "/var/lib/vpn-orbit-ssh/vpn-orbit-firewall"
LIBEXEC = "/usr/local/libexec/vpn-orbit"
SSH_CONFIG = "/etc/ssh/sshd_config.d/60-vpn-orbit-probe.conf"
SUDOERS = "/etc/sudoers.d/vpn-orbit-probe"
AUTHORIZED = "/etc/ssh/vpn-orbit-keys/vpn-orbit-svc"
FIREWALL_AUTHORIZED = "/etc/ssh/vpn-orbit-keys/vpn-orbit-firewall"
FIREWALL_SUDOERS = "/etc/sudoers.d/vpn-orbit-firewall"
FIREWALL_POLICY = "/etc/vpn-orbit/firewall-policy.json"
REMOTE_STATE = "/var/lib/vpn-orbit-provision"
STATE_FILE = ".provision-state.json"
PHASES = ("preflight", "account", "helpers", "keys", "sudoers", "sshd")
FAULT_PHASES = PHASES + ("verify",)
FAULT_ENV = "VPN_ORBIT_PROVISION_FAULT"
REMOTE_BUSY = 75
PHASE_INCOMPLETE = 76
SSH_PHASE_TIMEOUT = 60
SSH_PROBE_TIMEOUT = 15
SSH_PROFILE = f"""Match User {PROBE_ACCOUNT}
    AuthorizedKeysFile {AUTHORIZED}
    ForceCommand {LIBEXEC}/ssh-gateway
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no

Match all
"""

FIREWALL_SSH_PROFILE = SSH_PROFILE.removesuffix("Match all\n") + f"""Match User {FIREWALL_ACCOUNT}
    AuthorizedKeysFile {FIREWALL_AUTHORIZED}
    ForceCommand {LIBEXEC}/firewall-gateway
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    PermitUserRC no

Match all
"""

HELPER_FILES = ("ssh-gateway", "typed-helper", "firewall-gateway", "firewall-apply", "firewall-rollback")


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


def _protected_ancestors(path):
    if not Path(path).is_absolute():
        raise ValueError("Provisioning paths must be absolute")
    return f"""(
    orbit_directory={shlex.quote(str(Path(path).parent))}
    while [ "$orbit_directory" != / ]; do
        if [ -e "$orbit_directory" ] || [ -L "$orbit_directory" ]; then
            if [ ! -d "$orbit_directory" ] || [ -L "$orbit_directory" ] ||
               [ "$(stat -c '%u:%g' "$orbit_directory")" != 0:0 ]; then
                printf 'Unexpected provisioning directory: %s\\n' "$orbit_directory" >&2
                exit 1
            fi
            orbit_mode=$(stat -c '%a' "$orbit_directory") || exit 1
            if [ "$((0$orbit_mode & 022))" -ne 0 ]; then
                printf 'Writable provisioning directory: %s\\n' "$orbit_directory" >&2
                exit 1
            fi
        fi
        orbit_directory=${{orbit_directory%/*}}
        orbit_directory=${{orbit_directory:-/}}
    done
) || exit 1
"""


def _marker_check(name, expected=None):
    path = f'"$STATE/{name}"'
    if expected is None:
        return f"""if [ -e {path} ] || [ -L {path} ]; then
    printf '%s\\n' 'Provisioning artifact is missing: {name}' >&2
    exit 1
fi"""
    return f"""if [ -e {path} ] || [ -L {path} ]; then
    if [ ! -f {path} ] || [ -L {path} ] || [ "$(stat -c '%u:%g:%a:%h' {path})" != 0:0:600:1 ] ||
       [ "$(cat {path})" != {expected} ]; then
        printf '%s\\n' 'Unexpected provisioning marker: {name}' >&2
        exit 1
    fi
fi"""


def install_file(path, contents, mode, marker, *, inspect=False):
    filename = shlex.quote(str(path))
    expected_hash = hashlib.sha256(contents).hexdigest()
    file_mode = mode.lstrip("0")
    sudoers = path in (SUDOERS, FIREWALL_SUDOERS)
    validate_existing = f"\n    /usr/sbin/visudo -cf {filename}" if sudoers else ""
    create = "orbit_missing=1"
    if not inspect:
        encoded = base64.b64encode(contents).decode()
        validate = '    /usr/sbin/visudo -cf "$work/file"\n' if sudoers else ""
        create = f"""printf %s {shlex.quote(encoded)} | base64 -d > "$work/file"
{validate}    printf '%s\\n' {file_mode}:{expected_hash} > "$STATE/created-{marker}"
    install -o root -g root -m {mode} "$work/file" {filename}"""
    check_marker = _marker_check(f"created-{marker}", f"{file_mode}:{expected_hash}")
    return _protected_ancestors(path) + f"""{check_marker}
if [ -e {filename} ] || [ -L {filename} ]; then
    if [ ! -f {filename} ] || [ -L {filename} ] ||
       [ "$(stat -c '%u:%g:%a:%h' {filename})" != 0:0:{file_mode}:1 ]; then
        printf 'Existing provisioning file has unexpected contents or metadata: %s\\n' {filename} >&2
        exit 1
    fi
    orbit_hash=$(sha256sum {filename})
    if [ "${{orbit_hash%% *}}" != {expected_hash} ]; then
        printf 'Existing provisioning file has unexpected contents or metadata: %s\\n' {filename} >&2
        exit 1
    fi{validate_existing}
else
    {create}
fi"""


def _platform_guard():
    detect = (ROOT / "vpn_orbit" / "runtime" / "vps-platform.sh").read_text(encoding="ascii")
    return "set -eu\numask 077\n" + detect + """if [ "$orbit_platform" = UNSUPPORTED ]; then
    printf '%s\\n' 'Use Ubuntu 24.04/26.04 or Debian 13 on amd64.' >&2
    exit 1
fi
"""


def _state_directory(probe_public_key, *, create=False, inspect=False):
    binding = hashlib.sha256(probe_public_key).hexdigest()
    missing = 'mkdir -m 0700 "$STATE" || test -d "$STATE"' if create else f"exit {PHASE_INCOMPLETE if inspect else 1}"
    claim_action = (f'(set -C; printf \'%s\\n\' {binding} > "$owner_key") || exit 1'
                    if create else f"exit {PHASE_INCOMPLETE}")
    claim = f"""if [ ! -e "$owner_key" ] && [ ! -L "$owner_key" ] && [ -z "$(ls -A -- "$STATE")" ]; then
    {claim_action}
fi
""" if create or inspect else ""
    return _protected_ancestors(REMOTE_STATE) + f"""\
STATE={REMOTE_STATE}
if [ ! -e "$STATE" ] && [ ! -L "$STATE" ]; then
    {missing}
fi
if [ ! -d "$STATE" ] || [ -L "$STATE" ] || [ "$(stat -c '%u:%g:%a' "$STATE")" != 0:0:700 ]; then
    printf '%s\\n' 'Unexpected provisioning state directory metadata.' >&2
    exit 1
fi
exec 9<"$STATE"
flock -n -E {REMOTE_BUSY} 9
# Cleanup can remove the directory while another command still holds its old descriptor.
test "$STATE" -ef /proc/$$/fd/9 || exit {REMOTE_BUSY}
owner_key="$STATE/probe-key.sha256"
{claim}if [ ! -f "$owner_key" ] || [ -L "$owner_key" ] || [ "$(stat -c '%u:%g:%a:%h' "$owner_key")" != 0:0:600:1 ] ||
   [ "$(cat "$owner_key")" != {binding} ]; then
    printf '%s\\n' 'Provisioning state belongs to another preparation or has no key binding.' >&2
    exit 1
fi
"""


def _preamble(ctx):
    return _platform_guard() + _state_directory(ctx["probe_public_key"])


def _accounts(ctx):
    values = [(PROBE_ACCOUNT, PROBE_HOME)]
    if ctx["firewall"]:
        values.append((FIREWALL_ACCOUNT, FIREWALL_HOME))
    return values


def _account_checks(account, home):
    return f'''test "$(getent passwd "{account}" | cut -d: -f6,7)" = "{home}:/bin/sh"
test "$(passwd -S "{account}" | cut -d' ' -f2)" = L
test "$(id -Gn "{account}")" = "{account}"'''


def _check_remote(ctx):
    checks = []
    for account, home in _accounts(ctx):
        checks.append(f"""if getent passwd {account} >/dev/null 2>&1; then
{_account_checks(account, home)}
fi""")
    return _platform_guard() + f"""test -d /etc/ssh/sshd_config.d
test -x /usr/sbin/sshd
test -x /usr/bin/sudo
test -x /usr/sbin/visudo
command -v flock >/dev/null
/usr/sbin/sshd -t
{chr(10).join(checks)}
"""


def _phase_preflight(ctx, *, inspect=False):
    return _check_remote(ctx) + _state_directory(ctx["probe_public_key"], create=not inspect, inspect=inspect)


def _phase_account(ctx, *, inspect=False):
    steps = []
    for account, home in _accounts(ctx):
        marker = f"account-created-{account}"
        create = "orbit_missing=1" if inspect else f"""useradd --system --user-group --no-create-home --home-dir {home} --shell /bin/sh {account}
    id -u {account} > "$STATE/{marker}"
    {_account_checks(account, home)}"""
        steps.append(f"""if ! id {account} >/dev/null 2>&1; then
    {_marker_check(marker)}
    {create}
else
    {_account_checks(account, home)}
    {_marker_check(marker, f'"$(id -u {account})"')}
fi""")
    directories = [(home, "dir-" + account + "-home") for account, home in _accounts(ctx)]
    directories.extend(((LIBEXEC, "dir-libexec"), ("/etc/ssh/vpn-orbit-keys", "dir-authorized"),
                        ("/etc/vpn-orbit", "dir-config")))
    ensure = []
    for path, marker in directories:
        create = "orbit_missing=1" if inspect else f'''install -d -o root -g root -m 0755 {path}
    stat -c '%d:%i' {path} > "$STATE/created-{marker}"'''
        ensure.append(_protected_ancestors(Path(path) / "entry") + f"""if [ ! -d {path} ]; then
    {_marker_check(f"created-{marker}")}
    {create}
else
    {_marker_check(f"created-{marker}", f'''"$(stat -c '%d:%i' {path})"''')}
fi""")
    checks = "\n".join(ensure + steps)
    return _inspect_phase(ctx, checks) if inspect else _preamble(ctx) + checks + "\n"


def _inspect_phase(ctx, checks):
    return _preamble(ctx) + f"orbit_missing=0\n{checks}\nif [ \"$orbit_missing\" = 1 ]; then exit {PHASE_INCOMPLETE}; fi\n"


def _file_phase(ctx, files, *, inspect):
    commands = "\n".join(install_file(*item, inspect=inspect) for item in files)
    if inspect:
        return _inspect_phase(ctx, commands)
    return _preamble(ctx) + f"""work=$(mktemp -d)
trap 'rm -f "$work/file"; rmdir "$work"' EXIT
{commands}
"""


def _phase_helpers(ctx, *, inspect=False):
    helper_names = HELPER_FILES if ctx["firewall"] else ("ssh-gateway", "typed-helper")
    files = [(f"{LIBEXEC}/{name}", (ROOT / "remote" / name).read_bytes(), "0755", f"helper-{name}")
             for name in helper_names]
    if ctx["firewall"]:
        policy = json.dumps({"v": 1, "ssh_port": ctx["ssh_port"], "max_rules": 32,
                             "rollback_seconds": 60}, sort_keys=True, separators=(",", ":")) + "\n"
        files.append((FIREWALL_POLICY, policy.encode(), "0600", "firewall-policy"))
    return _file_phase(ctx, files, inspect=inspect)


def _phase_keys(ctx, *, inspect=False):
    probe = f'restrict,command="{LIBEXEC}/ssh-gateway" '.encode() + ctx["probe_public_key"]
    files = [(AUTHORIZED, probe, "0644", "probe-authorized")]
    if ctx["firewall"]:
        firewall = f'restrict,command="{LIBEXEC}/firewall-gateway" '.encode() + ctx["firewall_public_key"]
        files.append((FIREWALL_AUTHORIZED, firewall, "0644", "firewall-authorized"))
    return _file_phase(ctx, files, inspect=inspect)


def _phase_sudoers(ctx, *, inspect=False):
    lines = [f'{PROBE_ACCOUNT} ALL=(root) NOPASSWD: {LIBEXEC}/typed-helper ""']
    if ctx["firewall"]:
        lines.append(f'{FIREWALL_ACCOUNT} ALL=(root) NOPASSWD: {LIBEXEC}/firewall-apply ""')
    contents = ("\n".join(lines) + "\n").encode()
    return _file_phase(ctx, [(SUDOERS, contents, "0440", "probe-sudoers")], inspect=inspect)


CHECK_OWNED_FILE = """owned_file() {
    file=$1
    marker=$STATE/created-$2
    if [ ! -f "$marker" ] || { [ ! -e "$file" ] && [ ! -L "$file" ]; }; then
        return 0
    fi
    if [ -L "$marker" ] || [ ! -f "$file" ] || [ -L "$file" ] ||
       [ "$(stat -c '%u:%g:%h' "$file")" != 0:0:1 ]; then
        return 1
    fi
    file_mode=$(stat -c '%a' "$file")
    file_digest=$(sha256sum "$file")
    if [ "$(cat "$marker")" != "$file_mode:${file_digest%% *}" ]; then
        printf 'Provisioning file has changed: %s\\n' "$file" >&2
        return 1
    fi
    if [ "$3" = remove ]; then rm -- "$file"; fi
}
"""


def _phase_sshd(ctx, *, inspect=False):
    accounts = [(PROBE_ACCOUNT, "ssh-gateway")]
    if ctx["firewall"]:
        accounts.append((FIREWALL_ACCOUNT, "firewall-gateway"))
    checks = [f'''(effective=$(/usr/sbin/sshd -T -C "user={account},addr=$1,host=localhost") &&
    printf '%s\\n' "$effective" | grep -Fxq 'forcecommand {LIBEXEC}/{gateway}')'''
              for account, gateway in accounts]
    condition = " ||\n   ".join(["! /usr/sbin/sshd -t", *(f"! {check}" for check in checks), "! systemctl reload ssh.service"])
    profile = FIREWALL_SSH_PROFILE if ctx["firewall"] else SSH_PROFILE
    file = (SSH_CONFIG, profile.encode(), "0644", "sshd-config")
    if inspect:
        checked_file = _inspect_phase(ctx, "/usr/sbin/sshd -t\n" + install_file(*file, inspect=True))
        return checked_file + "\n".join(checks) + "\n"
    script = _file_phase(ctx, [file], inspect=False)
    return script + f"""\
if {condition}; then
    {CHECK_OWNED_FILE}    owned_file {SSH_CONFIG} sshd-config remove
    /usr/sbin/sshd -t && systemctl reload ssh.service || true
    exit 1
fi
"""


PHASE_SCRIPTS = {
    "preflight": _phase_preflight,
    "account": _phase_account,
    "helpers": _phase_helpers,
    "keys": _phase_keys,
    "sudoers": _phase_sudoers,
    "sshd": _phase_sshd,
}


def provision(probe_public_key, firewall_public_key=None, *, ssh_port=22):
    """Return one combined, shell-valid provisioning script (diagnostics only)."""
    ctx = {"probe_public_key": probe_public_key, "firewall_public_key": firewall_public_key,
           "firewall": firewall_public_key is not None, "ssh_port": ssh_port}
    return "set -eu\n" + "\n".join(PHASE_SCRIPTS[phase](ctx) for phase in PHASES)


REMOVE_ACCOUNT = """remove_account() {
    account=$1
    pkill -TERM -u "$account" 2>/dev/null || true
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if userdel "$account" 2>/dev/null; then break; fi
        sleep 0.2
    done
    if id "$account" >/dev/null 2>&1; then
        printf 'Provisioning account still exists: %s\\n' "$account" >&2
        return 1
    fi
}
"""


def cleanup_script(probe_public_key):
    files = [(AUTHORIZED, "probe-authorized"), (SUDOERS, "probe-sudoers"),
             (FIREWALL_AUTHORIZED, "firewall-authorized"), (FIREWALL_POLICY, "firewall-policy"),
             (SSH_CONFIG, "sshd-config")]
    files.extend((f"{LIBEXEC}/{name}", f"helper-{name}") for name in HELPER_FILES)
    directories = [(LIBEXEC, "dir-libexec"), ("/etc/ssh/vpn-orbit-keys", "dir-authorized"),
                   ("/etc/vpn-orbit", "dir-config"), (PROBE_HOME, f"dir-{PROBE_ACCOUNT}-home"),
                   (FIREWALL_HOME, f"dir-{FIREWALL_ACCOUNT}-home")]
    allowed_markers = [f"created-{marker}" for _, marker in files + directories]
    allowed_markers.extend((f"account-created-{PROBE_ACCOUNT}", f"account-created-{FIREWALL_ACCOUNT}", "probe-key.sha256"))
    parents = "".join(_protected_ancestors(path) for path in dict.fromkeys(path for path, _ in files + directories))
    return f"""set -eu
{_state_directory(probe_public_key)}{parents}{CHECK_OWNED_FILE}{REMOVE_ACCOUNT}for state_file in "$STATE"/* "$STATE"/.[!.]* "$STATE"/..?*; do
    if [ ! -e "$state_file" ] && [ ! -L "$state_file" ]; then continue; fi
    case "${{state_file##*/}}" in
        {'|'.join(allowed_markers)}) test -f "$state_file" && test ! -L "$state_file" || exit 1 ;;
        *) printf 'Unexpected provisioning state file: %s\\n' "$state_file" >&2; exit 1 ;;
    esac
done
for account_home in '{PROBE_ACCOUNT}|{PROBE_HOME}' '{FIREWALL_ACCOUNT}|{FIREWALL_HOME}'; do
    account="${{account_home%%|*}}"
    home="${{account_home#*|}}"
    marker="$STATE/account-created-$account"
    if [ -f "$marker" ] && id "$account" >/dev/null 2>&1; then
        test "$(id -u "$account")" = "$(cat "$marker")" || exit 1
{_account_checks('$account', '$home')}
    fi
done
for operation in check remove; do
    for path_marker in {' '.join(f'"{path}|{marker}"' for path, marker in files)}; do
        owned_file "${{path_marker%%|*}}" "${{path_marker##*|}}" "$operation" || exit 1
    done
done
if [ -f "$STATE/created-sshd-config" ]; then
    /usr/sbin/sshd -t
    systemctl reload ssh.service
fi
for account in {PROBE_ACCOUNT} {FIREWALL_ACCOUNT}; do
    if [ -f "$STATE/account-created-$account" ] && id "$account" >/dev/null 2>&1; then
        remove_account "$account" || exit 1
    fi
done
for path_marker in \
    {' '.join(f'"{path}|{marker}"' for path, marker in directories)}; do
    path="${{path_marker%%|*}}"
    marker="${{path_marker##*|}}"
    if [ -f "$STATE/created-$marker" ] && [ -d "$path" ] && [ ! -L "$path" ] &&
       [ "$(stat -c '%d:%i' "$path")" = "$(cat "$STATE/created-$marker")" ]; then
        rmdir -- "$path" 2>/dev/null || true
    fi
done
for name in {' '.join(allowed_markers)}; do rm -f -- "$STATE/$name"; done
rmdir -- "$STATE"
"""


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
            self._remote("# vpn-orbit-phase: cleanup\n" + cleanup_script(public_key.read_bytes()))
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
        journal["phases"] = {phase: "PENDING" for phase in PHASES}
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
        return isinstance(observation, dict) and observation.get("v") == 8 and observation.get("uid") == 0

    def _reconcile_phase(self, journal, phase, context):
        script = PHASE_SCRIPTS[phase](context, inspect=True)
        try:
            self._remote(f"# vpn-orbit-readback: {phase}\n" + script)
        except subprocess.CalledProcessError as error:
            if error.returncode == PHASE_INCOMPLETE:
                return False
            code = "READBACK_UNAVAILABLE" if error.returncode in (REMOTE_BUSY, 255) else "READBACK_CONFLICT"
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
                       "fingerprint": self.fingerprint, "phases": {phase: "PENDING" for phase in PHASES},
                       "status": "IN_PROGRESS", "attempts": 0, "created_at": now}
        else:
            cleanup_journal(journal, host=self.host, port=self.port, user=self.user, fingerprint=self.fingerprint)
        journal["attempts"] = journal.get("attempts", 0) + 1
        self.state.save(journal)

        try:
            context = self._context()
            if journal["phases"].get("preflight") != "DONE":
                self._verify_admin(journal, "preflight")
            for phase in PHASES:
                progress = journal["phases"].get(phase)
                if progress == "DONE":
                    continue
                if progress == "IN_PROGRESS" and self._reconcile_phase(journal, phase, context):
                    self._record(journal, phase, "DONE")
                    continue
                self._record(journal, phase, "IN_PROGRESS")
                script = PHASE_SCRIPTS[phase](context)
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
                        code = {255: "SSH_DISCONNECTED", REMOTE_BUSY: "VPS_PREPARATION_BUSY"}.get(error.returncode, code)
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
        result = subprocess.run(
            [*base, "-T", *auth, f"{user}@{ip}", remote], check=True, timeout=SSH_PHASE_TIMEOUT,
            stdout=subprocess.PIPE if expected_stdout is not None else None,
        )
        if expected_stdout is not None and result.stdout != expected_stdout:
            raise ValueError("Unexpected administrator verification reply")

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
             f"{PROBE_ACCOUNT}@{ip}", "vpn-orbit.v8.probe"],
            input='{"operation":"probe","version":8}\n', text=True, timeout=SSH_PROBE_TIMEOUT,
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
                run_remote(_check_remote({"firewall": args.firewall}))
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
            cleanup = cleanup_script(public_key.read_bytes())
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
                cleanup_state["phases"] = {phase: "PENDING" for phase in PHASES}
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
