"""Shared, fixed scripts for scoped VPS preparation and readback."""

import base64
import hashlib
import json
from pathlib import Path
import shlex


ASSETS = Path(__file__).resolve().parent
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
PHASES = ("preflight", "account", "helpers", "keys", "sudoers", "sshd")
REMOTE_BUSY = 75
PHASE_INCOMPLETE = 76
ACCOUNT_CONFLICT = 77
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
    detect = (ASSETS / "vps-platform.sh").read_text(encoding="ascii")
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
    return f'''(
    uid=$(id -u "{account}") &&
    test "$uid" -gt 0 &&
    test "$(getent passwd "{account}" | cut -d: -f6,7)" = "{home}:/bin/sh" &&
    test "$(passwd -S "{account}" | cut -d' ' -f2)" = L &&
    test "$(id -Gn "{account}")" = "{account}"
) || exit {ACCOUNT_CONFLICT}'''


def check_account_conflicts(*, firewall=False):
    checks = []
    for account, home in _accounts({"firewall": firewall}):
        checks.append(f"""if getent passwd {account} >/dev/null 2>&1; then
    if ! (
{_account_checks(account, home)}
    ); then
        printf '%s\\n' 'Conflicting provisioning account: {account}' >&2
        exit {ACCOUNT_CONFLICT}
    fi
elif [ "$?" -ne 2 ]; then
    printf '%s\\n' 'Could not look up provisioning account: {account}' >&2
    exit 1
fi
""")
    return "".join(checks)


def check_remote(*, firewall=False):
    return _platform_guard() + """test -d /etc/ssh/sshd_config.d
test -x /usr/sbin/sshd
test -x /usr/bin/sudo
test -x /usr/sbin/visudo
command -v flock >/dev/null
/usr/sbin/sshd -t
""" + check_account_conflicts(firewall=firewall)


def _phase_preflight(ctx, *, inspect=False):
    return check_remote(firewall=ctx["firewall"]) + _state_directory(ctx["probe_public_key"], create=not inspect, inspect=inspect)


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
    files = [(f"{LIBEXEC}/{name}", (ASSETS / "vps_helpers" / name).read_bytes(), "0755", f"helper-{name}")
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
