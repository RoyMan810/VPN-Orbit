import asyncio
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import asyncssh

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.protocol import PROBE_VERSION, canonical, software_summary
from vpn_orbit.runtime.ssh import exchange, exchange_restart, parse_probe


BOOT = '12345678-1234-1234-1234-123456789abc'
SOFTWARE = {'docker': 'PRESENT', 'nginx': 'NOT_DETECTED', 'nginx_service': 'NOT_FOUND'}


class DiscoveryPayloadTests(unittest.TestCase):
    def test_current_probe_requires_complete_scoped_observation(self):
        value = {"v": PROBE_VERSION, "uid": 0, "boot_id": BOOT, "observed_at": 1000, "software": SOFTWARE,
                 "docker": {"status": "NOT_CONFIGURED", "containers": []},
                 "compose": {"status": "NOT_CONFIGURED", "containers": []}}
        self.assertEqual(parse_probe(canonical(value), now=1000)["software"], SOFTWARE)
        for invalid in (
            {**value, "software": {**SOFTWARE, "docker": "/private/key"}},
            {**value, "software": {**SOFTWARE, "nginx_service": "unexpected"}},
            {**value, "software": {"docker": "PRESENT", "nginx": "PRESENT"}},
            {**value, "docker": {"status": "OBSERVED", "containers": [
                {"id": "a" * 64, "project": "fixture", "service": "web", "state": "RUNNING"}]}},
            {**value, "v": 10},
            {k: v for k, v in value.items() if k != "compose"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                parse_probe(canonical(invalid), now=1000)

    def test_nginx_service_state_is_bounded_and_historical_software_still_validates(self):
        previous = {"docker": "PRESENT", "nginx": "NOT_DETECTED"}
        self.assertEqual(software_summary(previous), previous)
        helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'remote/typed-helper'))
        observe = helper["nginx_service_state"]
        for code, output, state in (
            (0, b"LoadState=loaded\nActiveState=active\n", "ACTIVE"),
            (0, b"ActiveState=inactive\nLoadState=loaded\n", "INACTIVE"),
            (0, b"LoadState=loaded\nActiveState=failed\n", "FAILED"),
            (0, b"LoadState=loaded\nActiveState=reloading\n", "TRANSITIONING"),
            (0, b"LoadState=not-found\nActiveState=inactive\n", "NOT_FOUND"),
            (1, b"LoadState=loaded\nActiveState=active\n", "UNKNOWN"),
            (0, b"LoadState=masked\nActiveState=inactive\n", "UNKNOWN"),
            (0, b"LoadState=loaded\nActiveState=inactive\nPrivate=canary\n", "UNKNOWN"),
        ):
            result = subprocess.CompletedProcess([], code, stdout=output)
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=result) as run:
                self.assertEqual(observe(), state)
                args, kwargs = run.call_args
                self.assertEqual(args[0], ["/usr/bin/systemctl", "--no-pager", "show",
                                           "--property=LoadState,ActiveState", "--", "nginx.service"])
                self.assertEqual(kwargs["timeout"], 1)
        for error in (FileNotFoundError(), subprocess.TimeoutExpired([], 1)):
            with patch.object(subprocess, "run", side_effect=error):
                self.assertEqual(observe(), "UNKNOWN")

    def test_remote_helper_only_checks_fixed_file_metadata(self):
        helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'remote/typed-helper'))
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'docker'
            executable.touch(mode=0o700)
            # Container builds may remap system file owners. Model the root-owned installation.
            metadata = SimpleNamespace(st_mode=executable.stat().st_mode, st_uid=0)
            with patch.object(Path, 'stat', return_value=metadata):
                self.assertEqual(helper['tool_status'](executable), 'PRESENT')
                metadata.st_uid = 65534
                self.assertEqual(helper['tool_status'](executable), 'UNKNOWN')
            self.assertEqual(helper['tool_status'](Path(directory) / 'missing'), 'NOT_DETECTED')
            self.assertEqual(helper['tool_status'](directory), 'UNKNOWN')


class ProbeNegotiationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.reply = lambda command: (0, b'probe')
        key = asyncssh.generate_private_key('ssh-ed25519')
        self.client_key = asyncssh.generate_private_key('ssh-ed25519')
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.known_hosts = directory / 'known_hosts'
        self.known_hosts.write_bytes(b'vpn-orbit-discovery ' + key.export_public_key())

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return False

        async def command(process):
            self.requests.append((process.command, await process.stdin.read()))
            status, output = self.reply(process.command)
            process.stdout.write(output)
            process.exit(status)

        server = await asyncssh.listen('127.0.0.1', 0, server_factory=Server,
                                      server_host_keys=[key], process_factory=command, encoding=None)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        self.target = SimpleNamespace(id='discovery', value={'ip': '127.0.0.1', 'port': server.get_port()})

    async def probe(self):
        return await asyncio.wait_for(exchange(self.target, self.client_key, self.known_hosts), 5)

    async def test_v11_uses_one_fixed_request(self):
        self.assertEqual(await self.probe(), b'probe')
        self.assertEqual(self.requests, [('vpn-orbit.v11.probe', b'{"operation":"probe","version":11}\n')])

    async def test_failed_or_noisy_probe_does_not_fall_back(self):
        for status, data in ((65, b''), (65, b'canary'), (1, b'')):
            with self.subTest(status=status):
                self.requests.clear()
                self.reply = lambda command: (status, data)
                with self.assertRaisesRegex(Denied, 'SSH_REMOTE_PROBE_FAILED'):
                    await self.probe()
                self.assertEqual(len(self.requests), 1)


    async def test_restart_is_one_fixed_command_with_a_typed_reply(self):
        request = {"operation_id": "0" * 26, "container_id": "a" * 64, "boot_id": BOOT,
                   "started_at": "2026-11-18T01:02:03.123456789Z"}
        result = {"outcome": "SUCCEEDED", "code": "DOCKER_RESTART_VERIFIED"}
        self.reply = lambda _: (0, canonical(result))
        output = await exchange_restart(self.target, self.client_key, self.known_hosts, request)
        self.assertEqual(output, result)
        self.assertEqual(self.requests, [("vpn-orbit.v1.docker-restart", canonical(request) + b"\n")])
        self.requests.clear()
        self.reply = lambda _: (70, canonical(result))
        with self.assertRaisesRegex(Denied, "SSH_RESTART_REPLY_INVALID"):
            await exchange_restart(self.target, self.client_key, self.known_hosts, request)
        self.assertEqual(len(self.requests), 1)
