"""Pinned, typed SSH transport for restricted observation access preparation."""

import asyncio
import re
import secrets
import shlex
import time
from typing import Literal

import asyncssh

from ..errors import Denied
from .ssh import bounded_read, exchange, parse_probe, validate_private_key
from .ssh_enrollment import administrator_connection
from .vps_preparation import ACCOUNT_CONFLICT, PHASE_INCOMPLETE, PHASE_SCRIPTS, REMOTE_BUSY


class PreparationSSH:
    """Keep one attempt's administrator credentials in memory.

    The caller owns durable phase state and admission. It must persist dispatch
    before applying a phase and request readback before repeating unknown work.
    """

    def __init__(self, target, username, *, password, private_key, observation_key):
        if ("host.probe" not in target.value["capabilities"]
                or not isinstance(username, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", username)):
            raise Denied("VPS_PREPARATION_TARGET_INVALID")
        if ((password is None) == (private_key is None)
                or (password is not None and (not isinstance(password, str) or not 1 <= len(password) <= 1024
                                               or any(character in password for character in "\n\r\0")))
                or (private_key is not None and (not isinstance(private_key, str) or not 1 <= len(private_key) <= 8192))):
            raise Denied("SSH_CREDENTIAL_REQUIRED", 422)
        self.target, self.username = target, username
        self._known_hosts = f'vpn-orbit-{target.id} {target.value["host_key"]}\n'.encode("ascii")
        self._password, self._private_key = password, private_key
        self._observation_key = validate_private_key(observation_key)

    async def _command(self, script):
        nonce = "VPN_ORBIT_PHASE_" + secrets.token_hex(16)
        shell = (
            "exec </dev/null\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n"
            'test "$(/usr/bin/id -u)" = 0 || exit 1\n'
            + shlex.join(("/bin/sh", "-c", script, "vpn-orbit-phase"))
            + ' "$1" >/dev/null 2>&1\n'
            + f'printf "{nonce} %s\\n" "$?"\n'
        )
        arguments = ("/bin/sh", "-c", shell, "vpn-orbit-preparation")
        input_data = b""
        if self.username != "root":
            options = ("-n",) if self._password is None else ("-S", "-p", "")
            arguments = ("/usr/bin/sudo", "-k", *options, "--", *arguments)
            if self._password is not None:
                input_data = self._password.encode("utf-8") + b"\n"
        command = "exec " + shlex.join(arguments) + ' "${SSH_CONNECTION%% *}"'
        async with asyncio.timeout(60):
            async with administrator_connection(
                self.target.value["ip"], self.target.value["port"], self.target.fingerprint, self.username,
                password=self._password, private_key=self._private_key,
            ) as connection:
                process = await connection.create_process(command, encoding=None, request_pty=False, window=4096)
                if input_data:
                    process.stdin.write(input_data)
                process.stdin.write_eof()
                output, _, _ = await asyncio.gather(
                    bounded_read(process.stdout, 64), bounded_read(process.stderr, 1024), process.wait_closed(),
                )
        matched = re.fullmatch(re.escape(nonce.encode()) + rb" (0|[1-9][0-9]{0,2})\n", output)
        if process.exit_status != 0 or matched is None or int(matched[1]) > 255:
            raise Denied("VPS_PREPARATION_REPLY_UNCONFIRMED", 502)
        return int(matched[1])

    async def _verify_observation(self):
        version, output = await asyncio.wait_for(exchange(self.target, self._observation_key, self._known_hosts), 12)
        if version != 9:
            raise Denied("VPS_PREPARATION_OBSERVATION_UNCONFIRMED", 502)
        parse_probe(output, version, now=int(time.time()))

    async def phase(self, name, *, inspect: bool) -> Literal["APPLIED", "VERIFIED", "INCOMPLETE", "CONFLICT", "BUSY"]:
        if not isinstance(name, str) or name not in PHASE_SCRIPTS or type(inspect) is not bool:
            raise Denied("VPS_PREPARATION_PHASE_INVALID")
        context = {
            "probe_public_key": self._observation_key.export_public_key("openssh"),
            "firewall": False,
            "ssh_port": self.target.value["port"],
        }
        try:
            status = await self._command(PHASE_SCRIPTS[name](context, inspect=inspect))
            if status == 0:
                if not inspect:
                    return "APPLIED"
                if name == "sshd":
                    await self._verify_observation()
                return "VERIFIED"
        except (asyncssh.Error, OSError, TimeoutError):
            raise Denied("VPS_PREPARATION_SSH_UNCONFIRMED", 502) from None
        if inspect:
            if status == REMOTE_BUSY:
                return "BUSY"
            if status == PHASE_INCOMPLETE:
                return "INCOMPLETE"
            if status in (1, ACCOUNT_CONFLICT):
                return "CONFLICT"
        # A failing apply may have performed part of its work.
        raise Denied("VPS_PREPARATION_PHASE_UNCONFIRMED", 502)

    async def verify_access(self):
        """Verify the administrator and observation paths on separate fresh sessions."""
        try:
            if await self._command(":") != 0:
                raise Denied("SSH_ADMIN_ACCESS_UNCONFIRMED", 502)
        except (Denied, asyncssh.Error, OSError, TimeoutError):
            raise Denied("SSH_ADMIN_ACCESS_UNCONFIRMED", 502) from None
        try:
            await self._verify_observation()
        except (Denied, asyncssh.Error, OSError, TimeoutError):
            raise Denied("VPS_PREPARATION_OBSERVATION_UNCONFIRMED", 502) from None
