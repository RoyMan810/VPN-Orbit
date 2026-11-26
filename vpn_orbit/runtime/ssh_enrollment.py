"""One credential check against an already approved SSH endpoint."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import secrets
import shlex

import asyncssh

from ..errors import Denied
from .ssh import bounded_read
from .vps_preparation import ACCOUNT_CONFLICT, check_account_conflicts, inspect_host_readiness


CHECK_SSHD = """exec </dev/null
PATH=/usr/sbin:/usr/bin:/sbin:/bin
test "$(/usr/bin/id -u)" = 0 || exit 1
/usr/sbin/sshd -t >/dev/null 2>&1 || exit 1
""" + check_account_conflicts()
SUDO_COMMAND = ("/usr/bin/sudo", "-k")
SUDO_VERIFY = shlex.join(SUDO_COMMAND + ("-n", "--", "/bin/sh", "-c", CHECK_SSHD))
ROOT_VERIFY = shlex.join(("/bin/sh", "-c", CHECK_SSHD))
SUDO_MARKER = b"VPN_ORBIT_SUDO_V1\n"
PREFLIGHT_SUDO_COMMAND = "exec " + shlex.join(SUDO_COMMAND + (
    "-S", "-p", "", "--", "/bin/sh", "-c", CHECK_SSHD + "printf %s " + shlex.quote(SUDO_MARKER.decode("ascii")),
))
PREFLIGHT_COMMAND = shlex.join(("/bin/sh", "-c", "set -eu\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n" +
    Path(__file__).with_name("vps-platform.sh").read_text(encoding="ascii") + f"""
if [ ! -d /etc/ssh/sshd_config.d ] || [ ! -x /usr/sbin/sshd ] ||
   [ ! -x /usr/bin/sudo ] || [ ! -x /usr/sbin/visudo ] || ! command -v flock >/dev/null; then
    orbit_ssh=DEPENDENCIES_MISSING
elif [ "$(id -u)" != 0 ]; then
    orbit_ssh=SUDO_OR_SSHD_UNVERIFIED
    if {SUDO_VERIFY} >/dev/null 2>&1; then
        orbit_ssh=VERIFIED
    elif [ "$?" = {ACCOUNT_CONFLICT} ]; then
        orbit_ssh=OBSERVATION_ACCOUNT_CONFLICT
    fi
else
    orbit_ssh=SSHD_INVALID
    if {ROOT_VERIFY} >/dev/null 2>&1; then
        orbit_ssh=VERIFIED
    elif [ "$?" = {ACCOUNT_CONFLICT} ]; then
        orbit_ssh=OBSERVATION_ACCOUNT_CONFLICT
    fi
fi
""" + inspect_host_readiness() + """
printf 'VPN_ORBIT_PREFLIGHT_V2 %s %s %s %s %s %s\\n' "$orbit_platform" "$orbit_ssh" \\
    "$orbit_ipv4" "$orbit_ipv6" "$orbit_docker" "$orbit_compose"
"""))


async def _read_reply(connection, command, *, input_data=b""):
    try:
        process = await connection.create_process(command, encoding=None, request_pty=False, window=4096)
        if input_data:
            process.stdin.write(input_data)
        process.stdin.write_eof()
        output, _, _ = await asyncio.gather(bounded_read(process.stdout, 128), bounded_read(process.stderr, 1024),
                                             process.wait_closed())
    except (asyncssh.ChannelOpenError, Denied):
        raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502) from None
    return process.exit_status, output


async def inspect_readiness(connection):
    status, output = await _read_reply(connection, PREFLIGHT_COMMAND)
    try:
        marker, platform, ssh, ipv4, ipv6, docker, compose = output.decode("ascii").removesuffix("\n").split(" ")
    except (UnicodeError, ValueError):
        raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502) from None
    if (status != 0 or marker != "VPN_ORBIT_PREFLIGHT_V2" or not output.endswith(b"\n")
            or platform not in ("UBUNTU_24_04", "UBUNTU_26_04", "DEBIAN_13", "UNSUPPORTED")
            or ssh not in ("VERIFIED", "DEPENDENCIES_MISSING", "SSHD_INVALID", "SUDO_OR_SSHD_UNVERIFIED",
                           "OBSERVATION_ACCOUNT_CONFLICT")
            or any(route not in ("PRESENT", "ABSENT", "UNKNOWN") for route in (ipv4, ipv6))
            or any(tool not in ("PRESENT", "NOT_DETECTED") for tool in (docker, compose))):
        raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502)
    return {"platform": platform, "ssh": ssh, "network": {"ipv4_default": ipv4, "ipv6_default": ipv6},
            "docker": docker, "compose": compose}


class EnrollmentClient(asyncssh.SSHClient):
    def __init__(self, fingerprint, password, key):
        self.fingerprint = fingerprint
        self.password, self.key = password, key
        self.offered = False

    def validate_host_public_key(self, host, addr, port, key):
        return secrets.compare_digest(key.get_fingerprint("sha256"), self.fingerprint)

    def password_auth_requested(self):
        password, self.password = self.password, None
        self.offered |= password is not None
        return password

    def public_key_auth_requested(self):
        key, self.key = self.key, None
        self.offered |= key is not None
        return [key] if key is not None else None


@asynccontextmanager
async def administrator_connection(ip, port, fingerprint, username, *, password, private_key):
    try:
        key = asyncssh.import_private_key(private_key) if private_key is not None else None
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED", 422) from None

    client = EnrollmentClient(fingerprint, password, key)
    connection = await asyncssh.connect(
        ip, port=port, username=username, client_factory=lambda: client,
        config=None, known_hosts=([], [], []), server_host_key_algs=["ssh-ed25519"],
        client_keys=None, agent_path=None, agent_forwarding=False,
        preferred_auth=["publickey" if key is not None else "password"],
        public_key_auth=key is not None, password_auth=password is not None,
        kbdint_auth=False, gss_auth=False, gss_kex=False, host_based_auth=False,
        x509_trusted_certs=None, x509_trusted_cert_paths=[], connect_timeout=4, login_timeout=5,
    )
    try:
        # Servers may permit login without any authentication.
        if not client.offered:
            raise Denied("SSH_AUTHENTICATION_FAILED", 424)
        yield connection
    finally:
        connection.abort()


def verify_credentials(target, username, *, password, private_key, preflight=False):
    async def check():
        async with administrator_connection(
            target["ip"], target["port"], target["fingerprint"], username, password=password, private_key=private_key,
        ) as connection:
            if preflight:
                try:
                    async with asyncio.timeout(5):
                        readiness = await inspect_readiness(connection)
                        if (readiness["platform"] != "UNSUPPORTED" and readiness["ssh"] == "SUDO_OR_SSHD_UNVERIFIED"
                                and password and not any(character in password for character in "\n\r\0")):
                            status, reply = await _read_reply(
                                connection, PREFLIGHT_SUDO_COMMAND, input_data=password.encode("utf-8") + b"\n",
                            )
                            if status == 0 and reply == SUDO_MARKER:
                                readiness["ssh"] = "VERIFIED"
                            elif status == ACCOUNT_CONFLICT and not reply:
                                readiness["ssh"] = "OBSERVATION_ACCOUNT_CONFLICT"
                            elif status != 1 or reply:
                                raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502)
                        return readiness
                except TimeoutError:
                    raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502) from None

    async def bounded():
        return await asyncio.wait_for(check(), 8 if not preflight else 13)

    try:
        return asyncio.run(bounded())
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("HOST_FINGERPRINT_MISMATCH", 412) from None
    except asyncssh.PermissionDenied:
        raise Denied("SSH_AUTHENTICATION_FAILED", 424) from None
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied("SSH_CONNECTION_FAILED", 502) from None
