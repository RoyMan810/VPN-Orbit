"""One credential check against an already approved SSH endpoint."""

import asyncio
from pathlib import Path
import secrets
import shlex

import asyncssh

from ..errors import Denied
from .ssh import bounded_read


PREFLIGHT_COMMAND = shlex.join(("/bin/sh", "-c", "set -eu\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n" +
    Path(__file__).with_name("vps-platform.sh").read_text(encoding="ascii") + """
if [ ! -d /etc/ssh/sshd_config.d ] || [ ! -x /usr/sbin/sshd ] ||
   [ ! -x /usr/bin/sudo ] || [ ! -x /usr/sbin/visudo ]; then
    orbit_ssh=DEPENDENCIES_MISSING
elif [ "$(id -u)" = 0 ]; then
    orbit_ssh=SSHD_INVALID
    if /usr/sbin/sshd -t >/dev/null 2>&1; then orbit_ssh=VERIFIED; fi
else
    orbit_ssh=SUDO_OR_SSHD_UNVERIFIED
    if /usr/bin/sudo -n -- /bin/sh -c 'test "$(id -u)" = 0 && /usr/sbin/sshd -t' >/dev/null 2>&1; then
        orbit_ssh=VERIFIED
    fi
fi
printf 'VPN_ORBIT_PREFLIGHT_V1 %s %s\\n' "$orbit_platform" "$orbit_ssh"
"""))


async def inspect_readiness(connection):
    try:
        process = await connection.create_process(PREFLIGHT_COMMAND, encoding=None, request_pty=False, window=4096)
        process.stdin.write_eof()
        output, _, _ = await asyncio.gather(bounded_read(process.stdout, 128), bounded_read(process.stderr, 1024),
                                             process.wait_closed())
        marker, platform, ssh = output.decode("ascii").removesuffix("\n").split(" ")
    except (asyncssh.ChannelOpenError, UnicodeError, ValueError, Denied):
        raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502) from None
    if (process.exit_status != 0 or marker != "VPN_ORBIT_PREFLIGHT_V1" or not output.endswith(b"\n")
            or platform not in ("UBUNTU_24_04", "UBUNTU_26_04", "DEBIAN_13", "UNSUPPORTED")
            or ssh not in ("VERIFIED", "DEPENDENCIES_MISSING", "SSHD_INVALID", "SUDO_OR_SSHD_UNVERIFIED")):
        raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502)
    return {"platform": platform, "ssh": ssh}


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


def verify_credentials(target, username, *, password, private_key, preflight=False):
    try:
        key = asyncssh.import_private_key(private_key) if private_key is not None else None
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED", 422) from None

    client = EnrollmentClient(target["fingerprint"], password, key)

    async def check():
        async with asyncssh.connect(
            target["ip"], port=target["port"], username=username, client_factory=lambda: client,
            config=None, known_hosts=([], [], []), server_host_key_algs=["ssh-ed25519"],
            client_keys=None, agent_path=None, agent_forwarding=False,
            preferred_auth=["publickey" if key is not None else "password"],
            public_key_auth=key is not None, password_auth=password is not None,
            kbdint_auth=False, gss_auth=False, gss_kex=False, host_based_auth=False,
            x509_trusted_certs=None, x509_trusted_cert_paths=[], connect_timeout=4, login_timeout=5,
        ) as connection:
            # Servers may permit login without any authentication.
            if not client.offered:
                raise Denied("SSH_AUTHENTICATION_FAILED", 424)
            if preflight:
                try:
                    return await asyncio.wait_for(inspect_readiness(connection), 3)
                except TimeoutError:
                    raise Denied("SSH_PREFLIGHT_UNAVAILABLE", 502) from None

    async def bounded():
        return await asyncio.wait_for(check(), 8 if not preflight else 11)

    try:
        return asyncio.run(bounded())
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("HOST_FINGERPRINT_MISMATCH", 412) from None
    except asyncssh.PermissionDenied:
        raise Denied("SSH_AUTHENTICATION_FAILED", 424) from None
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied("SSH_CONNECTION_FAILED", 502) from None
