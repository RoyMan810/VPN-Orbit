import asyncio
import re
import unittest
from unittest.mock import patch

import asyncssh
from fastapi.testclient import TestClient

from vpn_orbit.api import create_app
from vpn_orbit.config import Settings
from vpn_orbit.database import identifier
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.policy import Policy
from vpn_orbit.runtime.ssh_enrollment import PREFLIGHT_COMMAND, PREFLIGHT_SUDO_COMMAND, SUDO_MARKER
from vpn_orbit.runtime.ssh_preparation import PreparationSSH
from vpn_orbit.runtime.vps_preparation import ACCOUNT_CONFLICT
from .test_auth_api import Fixture, ORIGIN, OTHER, SCOPE


PASSWORD = "ssh-enrollment-password-canary"
IP, OTHER_IP = "192.0.2.8", "192.0.2.9"


class SSHEnrollmentTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        host = asyncssh.generate_private_key("ssh-ed25519")
        different_host = asyncssh.generate_private_key("ssh-ed25519")
        client = asyncssh.generate_private_key("ssh-ed25519")
        self.private_key = client.export_private_key().decode()
        self.host_pin = host.get_fingerprint()
        self.other_pin = different_host.get_fingerprint()
        self.dials, self.auth_methods, self.sessions = [], [], []
        self.output = b"VPN_ORBIT_PREFLIGHT_V1 DEBIAN_13 VERIFIED\n"
        self.sudo_output = None
        self.sudo_status = 0
        self.stderr = b""
        self.phase_reply = None
        fixture = self

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return username != "anonymous"

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                fixture.auth_methods.append("password")
                return username == "ubuntu" and password == PASSWORD

            def public_key_auth_supported(self):
                return True

            def validate_public_key(self, username, key):
                fixture.auth_methods.append("publickey")
                return username == "ubuntu" and key.public_data == client.public_data

        async def process_factory(process):
            fixture.sessions.append((process.command, await process.stdin.read()))
            marker = re.search(r"VPN_ORBIT_PHASE_[a-f0-9]{32}", process.command)
            if marker and fixture.phase_reply is not None:
                status, response = fixture.phase_reply
                process.stdout.write(response.replace(b"NONCE", marker[0].encode()))
                process.exit(status)
                return
            output = fixture.sudo_output if process.command == PREFLIGHT_SUDO_COMMAND else fixture.output
            if output is None:
                await process.wait_closed()
                return
            process.stdout.write(output)
            process.stderr.write(fixture.stderr)
            process.exit(fixture.sudo_status if process.command == PREFLIGHT_SUDO_COMMAND else 0)

        server = await asyncssh.listen("127.0.0.1", 0, server_factory=Server, server_host_keys=[host],
                                       process_factory=process_factory, encoding=None)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        self.port = server.get_port()
        targets = [{"id": identity, "ip": ip, "port": self.port, "allowed_cidrs": [ip + "/32"],
                    "host_key": key.export_public_key().decode().strip(), "secret_ref": identifier() + ":v1",
                    "policy_revision": 1, "dependencies": [], "capabilities": ["host.probe"]}
                   for identity, ip, key in ((SCOPE, IP, host), (OTHER, OTHER_IP, different_host))]
        self.policy = Policy(targets)
        self.managed_key = client.export_private_key()
        catalog = self.policy.enrollment_catalog(ssh_endpoints=True)
        self.client = self.enterContext(TestClient(create_app(Settings(self.store.path, ORIGIN), auth=self.auth,
                                                               enrollment_catalog=catalog), base_url=ORIGIN))
        self.csrf = self.login()

        connect = asyncssh.connect

        def loopback_connect(host, *, port, **options):
            # Keep all test traffic local while asserting the address selected by production policy.
            self.dials.append((host, port))
            self.assertIn(host, (IP, OTHER_IP))
            self.assertEqual(port, self.port)
            return connect("127.0.0.1", port=port, **options)

        self.enterContext(patch("vpn_orbit.runtime.ssh_enrollment.asyncssh.connect", loopback_connect))

    async def enroll(self, *, client=None, headers=None, preflight=False, **values):
        body = {"ip": IP, "port": self.port, "username": "ubuntu", "fingerprint": self.host_pin, **values}
        endpoint = "/api/v1/enrollment/ssh/preflight" if preflight else "/api/v1/enrollment/ssh"
        return await asyncio.to_thread((client or self.client).post, endpoint,
                                       json=body, headers=self.headers() if headers is None else headers)

    async def test_password_login_failures_and_retry_never_open_a_session(self):
        mismatch = await self.enroll(fingerprint=self.other_pin, password=PASSWORD)
        self.assertEqual(mismatch.status_code, 412)
        blocked = await self.enroll(ip="192.0.2.99", password=PASSWORD)
        self.assertEqual(blocked.status_code, 404)
        self.assertEqual(self.dials, [])

        # A correct console fingerprint does not authorize a different key presented by SSH.
        replaced_host = await self.enroll(ip=OTHER_IP, fingerprint=self.other_pin, password=PASSWORD)
        self.assertEqual(replaced_host.status_code, 412)
        self.assertEqual(self.auth_methods, [])

        wrong_password = await self.enroll(password="wrong-" + PASSWORD)
        no_auth = await self.enroll(username="anonymous", password=PASSWORD)
        self.assertEqual(wrong_password.status_code, 424)
        self.assertEqual(no_auth.status_code, 424)
        self.assertEqual(self.auth_methods, ["password"])
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

        success = await self.enroll(password=PASSWORD)
        self.assertEqual(success.status_code, 201, success.text)
        repeat = await self.enroll(password=PASSWORD)
        self.assertEqual(repeat.status_code, 409)
        self.assertEqual(self.auth_methods, ["password", "password"])
        self.assertEqual(self.dials, [(OTHER_IP, self.port)] + [(IP, self.port)] * 3)
        self.assertEqual(self.sessions, [])
        self.assertEqual(self.client.get(success.headers["location"]).json()["id"], SCOPE)

        for response in (mismatch, blocked, replaced_host, wrong_password, no_auth, success, repeat):
            self.assertNotIn(PASSWORD, response.text)
        self.assertNotIn(PASSWORD, str(self.store.events_after(0)))

    async def test_private_key_and_owner_boundary(self):
        self.create_user(grants=[{"permission": "vps:read", "resource_id": SCOPE}])
        other = self.enterContext(TestClient(self.client.app, base_url=ORIGIN))
        headers = {"Origin": ORIGIN, "X-CSRF-Token": self.login(client=other, user="operator")}
        forbidden = await self.enroll(client=other, headers=headers, private_key=self.private_key)
        csrf_missing = await self.enroll(headers={"Origin": ORIGIN}, private_key=self.private_key)
        ambiguous = await self.enroll(password=PASSWORD, private_key=self.private_key)
        malformed = await self.enroll(private_key="invalid-ssh-key-canary")
        self.assertEqual([reply.status_code for reply in (forbidden, csrf_missing, ambiguous, malformed)], [403, 403, 422, 422])
        self.assertEqual(self.dials, [])

        success = await self.enroll(private_key=self.private_key)
        self.assertEqual(success.status_code, 201, success.text)
        self.assertEqual(set(self.auth_methods), {"publickey"})
        self.assertEqual(self.sessions, [])
        self.assertNotIn("invalid-ssh-key-canary", malformed.text)
        self.assertNotIn("PRIVATE KEY", success.text)
        self.assertNotIn("PRIVATE KEY", str(self.store.events_after(0)))

    async def test_preflight_runs_a_fixed_command_without_registering_or_sending_credentials_to_stdin(self):
        wrong = await self.enroll(preflight=True, ip=OTHER_IP, fingerprint=self.other_pin, password=PASSWORD)
        self.assertEqual(wrong.status_code, 412)
        self.assertEqual(self.auth_methods, [])
        self.assertEqual(self.sessions, [])
        no_csrf = await self.enroll(preflight=True, headers={"Origin": ORIGIN}, password=PASSWORD)
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(self.dials, [(OTHER_IP, self.port)])

        self.stderr = b"private-remote-diagnostic"
        result = await self.enroll(preflight=True, password=PASSWORD)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json(), {"platform": "DEBIAN_13", "ssh": "VERIFIED"})
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertEqual(self.sessions, [(PREFLIGHT_COMMAND, b"")])
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])
        self.assertNotIn(SCOPE, str(self.store.events_after(0)))
        self.assertNotIn(PASSWORD, str(self.store.events_after(0)))

    async def test_preflight_checks_password_protected_sudo_only_with_password_authentication(self):
        self.output = b"VPN_ORBIT_PREFLIGHT_V1 DEBIAN_13 SUDO_OR_SSHD_UNVERIFIED\n"
        self.sudo_output = SUDO_MARKER
        self.stderr = PASSWORD.encode()
        key_only = await self.enroll(preflight=True, private_key=self.private_key)
        self.assertEqual(key_only.json(), {"platform": "DEBIAN_13", "ssh": "SUDO_OR_SSHD_UNVERIFIED"})
        result = await self.enroll(preflight=True, password=PASSWORD)
        self.assertEqual(result.json(), {"platform": "DEBIAN_13", "ssh": "VERIFIED"})
        self.assertEqual(self.sessions, [(PREFLIGHT_COMMAND, b""), (PREFLIGHT_COMMAND, b""),
                                         (PREFLIGHT_SUDO_COMMAND, PASSWORD.encode() + b"\n")])
        self.assertNotIn(PASSWORD, PREFLIGHT_SUDO_COMMAND)
        self.assertNotIn(PASSWORD, result.text + str(self.store.events_after(0)))
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

    async def test_preflight_rejects_nonprotocol_output_without_exposing_it(self):
        for output in (b"VPN_ORBIT_PREFLIGHT_V1 DEBIAN_13 VERIFIED\nremote-canary\n", b"x" * 129):
            with self.subTest(output=output[:17]):
                self.output = output
                result = await self.enroll(preflight=True, private_key=self.private_key)
                self.assertEqual(result.status_code, 502, result.text)
                self.assertEqual(result.json()["code"], "SSH_PREFLIGHT_UNAVAILABLE")
                self.assertNotIn("remote-canary", result.text)
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

    async def test_preflight_reports_a_conflicting_observation_account_without_registration(self):
        self.output = b"VPN_ORBIT_PREFLIGHT_V1 DEBIAN_13 OBSERVATION_ACCOUNT_CONFLICT\n"
        direct = await self.enroll(preflight=True, password=PASSWORD)
        self.assertEqual(direct.json(), {"platform": "DEBIAN_13", "ssh": "OBSERVATION_ACCOUNT_CONFLICT"})
        self.assertEqual(self.sessions, [(PREFLIGHT_COMMAND, b"")])

        self.output = b"VPN_ORBIT_PREFLIGHT_V1 DEBIAN_13 SUDO_OR_SSHD_UNVERIFIED\n"
        self.sudo_output = b""
        self.sudo_status = ACCOUNT_CONFLICT
        elevated = await self.enroll(preflight=True, password=PASSWORD)
        self.assertEqual(elevated.json(), direct.json())
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

    async def test_preflight_times_out_a_session_that_never_replies(self):
        self.output = None
        result = await self.enroll(preflight=True, password=PASSWORD)
        self.assertEqual(result.json()["code"], "SSH_PREFLIGHT_UNAVAILABLE")
        self.assertEqual(result.status_code, 502)
        self.assertEqual(self.sessions, [(PREFLIGHT_COMMAND, b"")])
        self.assertEqual(self.client.get("/api/v1/resources").json()["items"], [])

    async def test_preparation_readback_requires_a_bounded_phase_reply_on_the_pinned_target(self):
        target = self.policy.targets[SCOPE]
        transport = PreparationSSH(target, "ubuntu", password=PASSWORD, private_key=None,
                                   observation_key=self.managed_key)
        for status, output in ((76, b""), (0, b"false 76\n"), (0, b"NONCE 76\n" + b"x" * 128),
                               (76, b"NONCE 76\n")):
            self.phase_reply = (status, output)
            with self.subTest(status=status, output=output[:15]), self.assertRaises(Denied):
                await transport.phase("preflight", inspect=True)
        self.phase_reply = (0, b"NONCE 76\n")
        self.assertEqual(await transport.phase("preflight", inspect=True), "INCOMPLETE")
        for command, stdin in self.sessions:
            self.assertTrue(command.startswith("exec /usr/bin/sudo"))
            self.assertNotIn(PASSWORD, command)
            self.assertEqual(stdin, PASSWORD.encode() + b"\n")
        sessions = self.sessions.copy()
        wrong = PreparationSSH(self.policy.targets[OTHER], "ubuntu", password=PASSWORD, private_key=None,
                               observation_key=self.managed_key)
        with self.assertRaisesRegex(Denied, "VPS_PREPARATION_SSH_UNCONFIRMED"):
            await wrong.phase("preflight", inspect=True)
        with self.assertRaisesRegex(Denied, "VPS_PREPARATION_PHASE_INVALID"):
            await transport.phase("cleanup", inspect=False)
        self.assertEqual(sessions, self.sessions)
