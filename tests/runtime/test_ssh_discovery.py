import asyncio
import io
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import asyncssh

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.protocol import PROBE_VERSION, app_links_summary, canonical, firewall_summary, software_summary
from vpn_orbit.runtime.ssh import exchange, exchange_restart, parse_probe


BOOT = '12345678-1234-1234-1234-123456789abc'
SOFTWARE = {'docker': 'PRESENT', 'nginx': 'NOT_DETECTED', 'nginx_service': 'NOT_FOUND'}


class DiscoveryPayloadTests(unittest.TestCase):
    def test_current_probe_requires_complete_scoped_observation(self):
        value = {"v": PROBE_VERSION, "uid": 0, "boot_id": BOOT, "observed_at": 1000, "software": SOFTWARE,
                 "docker": {"status": "NOT_CONFIGURED", "containers": []},
                 "app_links": {"status": "NOT_CONFIGURED", "links": []},
                 "firewall": {"status": "NOT_CONFIGURED", "chains": []},
                 "nginx": {"status": "NOT_CONFIGURED", "names": [], "partial": False},
                 "local_https": {"status": "NOT_CONFIGURED", "sites": []},
                 "compose": {"status": "NOT_CONFIGURED", "containers": []}}
        self.assertEqual(parse_probe(canonical(value), now=1000)["software"], SOFTWARE)
        for invalid in (
            {**value, "software": {**SOFTWARE, "docker": "/private/key"}},
            {**value, "software": {**SOFTWARE, "nginx_service": "unexpected"}},
            {**value, "software": {"docker": "PRESENT", "nginx": "PRESENT"}},
            {**value, "docker": {"status": "OBSERVED", "containers": [
                {"id": "a" * 64, "project": "fixture", "service": "web", "state": "RUNNING"}]}},
            {**value, "v": 13},
            {k: v for k, v in value.items() if k != "compose"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                parse_probe(canonical(invalid), now=1000)

    def test_nginx_service_state_is_bounded(self):
        previous = {"docker": "PRESENT", "nginx": "NOT_DETECTED"}
        with self.assertRaises(Denied):
            software_summary(previous)
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


    def test_nftables_snapshot_only_exports_base_filter_chain_metadata(self):
        helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote/typed-helper"))
        observe = helper["observe_firewall"]
        chain = {"family": "inet", "table": "filter", "name": "incoming", "hook": "input", "policy": "drop", "prio": -10}
        raw = canonical({"nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"chain": {**chain, "type": "filter", "comment": "private-canary"}},
            {"chain": {**chain, "name": "nat", "type": "nat", "comment": "private-canary"}},
            {"chain": {"family": "inet", "table": "filter", "name": "regular"}},
        ]})
        with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"enabled\n",
                                              "tool_status": lambda _: "PRESENT"}), patch.object(subprocess, "Popen") as popen:
            process = popen.return_value.__enter__.return_value
            process.stdout = io.BytesIO(raw)
            process.wait.return_value = process.poll.return_value = 0
            self.assertEqual(firewall_summary(observe()), {"status": "OBSERVED", "chains": [chain]})
            self.assertEqual(popen.call_args.args[0], ["/usr/sbin/nft", "-j", "-nn", "list", "chains"])
            process.stdout = io.BytesIO(b"x" * (128 * 1024 + 1))
            self.assertEqual(observe(), {"status": "LIMIT_EXCEEDED", "chains": []})
        for invalid in ([{**chain, "comment": "private-canary"}], [{**chain, "prio": True}], [chain, chain]):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                firewall_summary({"status": "OBSERVED", "chains": invalid})


    def test_application_links_are_explicit_sorted_and_reject_credentials(self):
        helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote/typed-helper"))
        observe = helper["observe_app_links"]
        with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"node xray panel.example 443\nbot api panel.example 443\n"}):
            snapshot = observe()
        self.assertEqual(app_links_summary(snapshot), {"status": "DECLARED", "links": [
            {"project": "bot", "service": "api", "host": "panel.example", "port": 443},
            {"project": "node", "service": "xray", "host": "panel.example", "port": 443},
        ]})
        for invalid in (b"bot api https://user:password@panel.example 443\n",
                        b"bot api panel.example 65536\n", b"bot api panel.example 443\n" * 2):
            with self.subTest(value=invalid), patch.dict(observe.__globals__, {"read_root_config": lambda *_: invalid}):
                self.assertEqual(observe(), {"status": "POLICY_INVALID", "links": []})


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

    async def test_v18_uses_one_fixed_request(self):
        self.assertEqual(await self.probe(), b'probe')
        self.assertEqual(self.requests, [('vpn-orbit.v18.probe', b'{"operation":"probe","version":18}\n')])

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
