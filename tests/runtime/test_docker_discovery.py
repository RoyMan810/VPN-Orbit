from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.protocol import MAX_FRAME, canonical, compose_summary
from vpn_orbit.runtime.ssh import parse_probe


TARGET = "a" * 64
FOREIGN = "b" * 64
SCOPE = [{"id": TARGET, "project": "fixture", "service": "web"}]
ROW = {**SCOPE[0], "state": "RUNNING"}
SUMMARY = {"status": "OBSERVED", "containers": [ROW]}
BINDING = {"address": "127.0.0.1", "host_port": 49152, "container_port": 8080, "protocol": "tcp"}
IPV6_BINDING = {"address": "::", "host_port": 49152, "container_port": 8080, "protocol": "udp"}
DAEMON_PORTS = [
    {"IP": "127.0.0.1", "PublicPort": 49152, "PrivatePort": 8080, "Type": "tcp"},
    {"IP": "0:0:0:0:0:0:0:0", "PublicPort": 49152, "PrivatePort": 8080, "Type": "udp"},
    {"PrivatePort": 8443, "Type": "tcp"},
    {"IP": "::", "PrivatePort": 8080, "Type": "tcp"},
]
HELPER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote/typed-helper"))


class DockerPayloadTests(unittest.TestCase):
    def parse(self, docker, version=3):
        value = {"v": version, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
                 "docker": docker}
        return parse_probe(canonical(value), version, now=1000)

    def test_v8_start_time_is_strict_and_preserves_nanoseconds(self):
        started = "2026-11-18T01:02:03.123456789Z"
        row = {**ROW, "published_ports": [], "mount_status": "NONE", "network_status": "ISOLATED",
               "dependency_status": "ISOLATED", "started_at": started}
        self.assertEqual(self.parse({"status": "OBSERVED", "containers": [row]}, version=8)["docker"]["containers"][0], row)
        self.assertEqual(HELPER["docker_started_at"]({"State": {"StartedAt": started}}), started)
        for bad in ("0001-01-01T00:00:00Z", "2026-02-30T01:02:03Z", "canary"):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                self.assertIsNone(HELPER["docker_started_at"]({"State": {"StartedAt": bad}}))
                self.parse({"status": "OBSERVED", "containers": [{**row, "started_at": bad}]}, version=8)
        with self.assertRaises(Denied):
            self.parse({"status": "OBSERVED", "containers": [row]}, version=7)

    def test_v9_keeps_compose_discovery_separate_from_approved_scope(self):
        scoped = {"status": "NOT_CONFIGURED", "containers": []}
        compose = {"status": "OBSERVED", "containers": [{**ROW, "image_id": "sha256:" + FOREIGN}]}
        value = {"v": 9, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
                 "docker": scoped, "compose": compose}
        result = parse_probe(canonical(value), 9, now=1000)
        self.assertEqual(result["docker"], scoped)
        self.assertEqual(result["compose"], compose)
        for bad in ({"status": "LIMIT_EXCEEDED", "containers": compose["containers"]},
                    {"status": "OBSERVED", "containers": compose["containers"] * 2},
                    {"status": "OBSERVED", "containers": [{**compose["containers"][0], "env": "secret"}]},
                    {"status": "OBSERVED", "containers": [{**compose["containers"][0], "image_id": "/local/path"}]}):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                compose_summary(bad)

    def test_v10_requires_typed_complete_attachment_fields(self):
        base = {**ROW, "image_id": "sha256:" + FOREIGN}
        row = {**base, "networks": ["backend", "frontend"], "volumes": None}
        scoped = {"status": "NOT_CONFIGURED", "containers": []}
        value = {"v": 10, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
                 "docker": scoped, "compose": {"status": "OBSERVED", "containers": [row]}}
        self.assertEqual(parse_probe(canonical(value), 10, now=1000)["compose"], value["compose"])
        with self.assertRaises(Denied):
            parse_probe(canonical({**value, "v": 9}), 9, now=1000)
        for rows in ([{**base, "networks": []}], [row, {**base, "id": FOREIGN}],
                     [{**row, "volumes": ["/host/private"]}], [{**row, "volumes": ["x" * 65]}],
                     [{**row, "volumes": ["data", "data"]}], [{**row, "volumes": ["web", "data"]}],
                     [{**row, "volumes": [str(i) for i in range(9)]}],
                     [{**row, "networks": {"frontend": "192.0.2.1"}}]):
            with self.subTest(rows=rows), self.assertRaises(Denied):
                compose_summary({"status": "OBSERVED", "containers": rows})

    def test_largest_supported_compose_and_scoped_inventory_fit_the_frame(self):
        row = {"project": "p" * 63, "service": "s" * 63, "state": "RESTARTING"}
        address = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        ports = [{"address": address, "host_port": p, "container_port": p, "protocol": "sctp"}
                 for p in range(65528, 65536)]
        scoped = [{**row, "id": f"{i:064x}", "state": "RUNNING", "published_ports": ports,
                   "mount_status": "PRESENT", "network_status": "OTHER", "dependency_status": "UNKNOWN",
                   "started_at": "2026-11-18T01:02:03.123456789Z"} for i in range(8)]
        compose = [{**row, "id": f"{i:064x}", "image_id": "sha256:" + FOREIGN} for i in range(12)]
        value = {"v": 9, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc", "observed_at": 1000,
                 "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED"},
                 "docker": {"status": "OBSERVED", "containers": scoped},
                 "compose": {"status": "OBSERVED", "containers": compose}}
        result = parse_probe(canonical(value), 9, now=1000)
        self.assertLess(len(canonical(value)) + 1, 15360)
        self.assertLess(len(canonical(result)) + 1024, MAX_FRAME)
        value["v"] = 10
        names = [f"{i:064x}" for i in range(8)]
        for item in compose:
            item.update(networks=names, volumes=names)
        compose[0]["volumes"] = []
        self.assertGreater(len(canonical(value)), 15360)
        wire = HELPER["probe_reply"](value).encode() + b"\n"
        self.assertLessEqual(len(wire), 15360)
        result = parse_probe(wire, 10, now=1000)
        self.assertEqual(result["docker"], value["docker"])
        self.assertEqual(len(result["compose"]["containers"]), 12)
        self.assertEqual(result["compose"]["containers"][0]["volumes"], [])
        self.assertIsNone(result["compose"]["containers"][1]["volumes"])
        self.assertIsNone(result["compose"]["containers"][1]["networks"])
        self.assertLess(len(canonical(result)) + 1024, MAX_FRAME)

    def test_v3_accepts_only_the_bounded_typed_summary(self):
        self.assertEqual(self.parse(SUMMARY)["docker"], SUMMARY)
        for payload in ({"status": "OBSERVED", "containers": []},
                        {"status": "NOT_CONFIGURED", "containers": [ROW]},
                        {"status": "OBSERVED", "containers": [ROW, ROW]},
                        {"status": "OBSERVED", "containers": [{**ROW, "env": ["canary"]}]},
                        {"status": "OBSERVED", "containers": [{**ROW, "state": "HEALTHY"}]},
                        {"status": "OBSERVED", "containers": [{**ROW, "project": "../private"}]}):
            with self.subTest(payload=payload), self.assertRaises(Denied):
                self.parse(payload)

    def test_v4_requires_typed_and_bounded_bindings(self):
        def summary(ports, *, state="RUNNING"):
            return {"status": "OBSERVED", "containers": [{**ROW, "state": state, "published_ports": ports}]}

        for ports in (None, [], [BINDING, IPV6_BINDING]):
            with self.subTest(ports=ports):
                payload = summary(ports)
                self.assertEqual(self.parse(payload, version=4)["docker"], payload)
                with self.assertRaises(Denied):
                    self.parse(payload, version=3)
        for payload in (
            SUMMARY,
            summary([BINDING], state="NOT_FOUND"),
            summary([], state="UNKNOWN"),
            summary([BINDING, BINDING]),
            summary([{**BINDING, "host_port": port} for port in range(1, 10)]),
            summary([{**BINDING, "address": "fe80::1%eth0"}]),
            summary([{**BINDING, "address": "0:0:0:0:0:0:0:0"}]),
            summary([{**BINDING, "host_port": True}]),
            summary([{**BINDING, "container_port": 65536}]),
            summary([{**BINDING, "protocol": "icmp"}]),
            summary([{**BINDING, "label": "secret"}]),
        ):
            with self.subTest(payload=payload), self.assertRaises(Denied):
                self.parse(payload, version=4)

    def test_v5_requires_a_mount_status_and_keeps_older_payloads_strict(self):
        for status in ("NONE", "PRESENT", "UNKNOWN"):
            payload = {"status": "OBSERVED", "containers": [
                {**ROW, "published_ports": [], "mount_status": status},
            ]}
            self.assertEqual(self.parse(payload, version=5)["docker"], payload)
            with self.assertRaises(Denied):
                self.parse(payload, version=4)
        for row in ({**ROW, "published_ports": []},
                    {**ROW, "published_ports": [], "mount_status": []},
                    {**ROW, "state": "NOT_FOUND", "published_ports": None, "mount_status": "NONE"}):
            with self.subTest(row=row), self.assertRaises(Denied):
                self.parse({"status": "OBSERVED", "containers": [row]}, version=5)

    def test_v6_requires_typed_network_status_without_changing_v5(self):
        row = {**ROW, "published_ports": [], "mount_status": "NONE"}
        for status in ("ISOLATED", "OTHER", "UNKNOWN"):
            summary = {"status": "OBSERVED", "containers": [{**row, "network_status": status}]}
            self.assertEqual(self.parse(summary, version=6)["docker"], summary)
            with self.assertRaises(Denied):
                self.parse(summary, version=5)
        for invalid in (row, {**row, "network_status": "bridge"},
                        {**row, "state": "CREATED", "mount_status": "UNKNOWN", "network_status": "ISOLATED"}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                self.parse({"status": "OBSERVED", "containers": [invalid]}, version=6)

    def test_v7_requires_dependency_scope_and_consistent_observations(self):
        row = {**ROW, "published_ports": [], "mount_status": "NONE", "network_status": "ISOLATED"}
        for status in ("ISOLATED", "OTHER", "UNKNOWN"):
            payload = {"status": "OBSERVED", "containers": [{**row, "dependency_status": status}]}
            self.assertEqual(self.parse(payload, version=7)["docker"], payload)
            with self.assertRaises(Denied):
                self.parse(payload, version=6)
        for invalid in (row, {**row, "dependency_status": "SAFE"},
                        {**row, "network_status": "OTHER", "dependency_status": "ISOLATED"},
                        {**row, "mount_status": "PRESENT", "dependency_status": "ISOLATED"}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                self.parse({"status": "OBSERVED", "containers": [invalid]}, version=7)

    def test_protected_registry_requires_full_unique_ids_and_exact_fields(self):
        parse = HELPER["parse_docker_scope"]
        self.assertEqual(parse(canonical({"v": 1, "containers": SCOPE})), SCOPE)
        for scope in ([{**SCOPE[0], "id": TARGET[:12]}], SCOPE * 2,
                      [{**SCOPE[0], "service": "/etc/passwd"}],
                      [{**SCOPE[0], "mount": "secret"}],
                      [{"id": format(i, "064x"), "project": "p", "service": "s"} for i in range(9)]):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                parse(canonical({"v": 1, "containers": scope}))
        with self.assertRaises(ValueError):
            parse(b'{"v":1,"v":1,"containers":[]}')


class DockerTransportTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.response = [{"Id": TARGET, "State": "running",
                          "Labels": {"com.docker.compose.project": "fixture",
                                     "com.docker.compose.service": "web", "secret": "label-canary"},
                          "Command": "command-canary", "Mounts": [{"Source": "/private/path"}]}]
        self.inspect = {"Id": TARGET, "Config": {"Labels": self.response[0]["Labels"], "Env": ["secret-canary"]},
                        "State": {"Status": "running"}, "HostConfig": {}, "Mounts": []}
        self.peers = [{"Id": TARGET, "State": "running"}]
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append(self.path)
                if self.path == "/v1.44/containers/json?all=1&limit=2":
                    value = fixture.peers
                elif self.path == f"/v1.44/containers/{TARGET}/json":
                    value = fixture.inspect
                else:
                    value = fixture.response
                if value is None:
                    self.send_error(404)
                    return
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        # The local sandbox denies AF_UNIX creation. CI exercises the real daemon socket.
        self.enterContext(patch.dict(HELPER["list_docker"].__globals__, {
            "DockerConnection": lambda _: HTTPConnection("127.0.0.1", server.server_port, timeout=2),
        }))

    def observe(self, **options):
        return HELPER["list_docker"](Path("/unused.sock"), SCOPE, **options)

    def test_compose_discovery_is_opt_in_and_returns_only_an_allowlist(self):
        observe = HELPER["observe_compose"]
        with patch.dict(observe.__globals__, {"require_docker_socket": lambda _: None}):
            self.assertEqual(observe(switch=Path("/nonexistent/switch")),
                             {"status": "NOT_CONFIGURED", "containers": []})
            self.assertEqual(self.requests, [])
            self.response[0]["ImageID"] = "sha256:" + FOREIGN
            with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"enabled\n"}):
                self.assertEqual(observe(), {"status": "OBSERVED", "containers": [{**ROW, "image_id": "sha256:" + FOREIGN}]})
                self.assertEqual(len(self.requests), 1)
                route = urlsplit(self.requests[0])
                query = parse_qs(route.query)
                self.assertEqual(route.path, "/v1.44/containers/json")
                self.assertEqual(query["all"], ["1"])
                self.assertEqual(query["limit"], ["13"])
                self.assertEqual(json.loads(query["filters"][0]), {"label": ["com.docker.compose.project"]})
                self.response *= 2
                self.assertEqual(observe(), {"status": "UNAVAILABLE", "containers": []})
                self.response *= 7
                self.assertEqual(observe(), {"status": "LIMIT_EXCEEDED", "containers": []})
                self.response = []
                self.assertEqual(observe(), {"status": "OBSERVED", "containers": []})
            with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"invalid"}):
                self.assertEqual(observe(), {"status": "POLICY_INVALID", "containers": []})

    def test_compose_attachments_require_extended_scope_and_use_one_read(self):
        row = self.response[0]
        row.update(ImageID="sha256:" + FOREIGN,
                   NetworkSettings={"Networks": {"bridge": {"IPAddress": "192.0.2.1", "Aliases": ["alias-canary"]}}},
                   Mounts=[{"Type": "volume", "Name": "named-data", "Source": "/private/path"},
                           {"Type": "volume", "Name": "named-data", "Destination": "/private/destination"},
                           {"Type": "bind", "Name": "bind-canary", "Source": "/private/bind"}])
        observe = HELPER["observe_compose"]
        base = {**ROW, "image_id": "sha256:" + FOREIGN}
        with patch.dict(observe.__globals__, {"require_docker_socket": lambda _: None}):
            for switch, extended, expected in (
                (b"enabled\n", True, base),
                (b"enabled-with-resources\n", False, base),
                (b"enabled-with-resources\n", True, {**base, "networks": ["bridge"], "volumes": ["named-data"]}),
            ):
                self.requests.clear()
                with patch.dict(observe.__globals__, {"read_root_config": lambda *_: switch}):
                    self.assertEqual(observe(include_attachments=extended), {"status": "OBSERVED", "containers": [expected]})
                self.assertEqual(len(self.requests), 1)
            row.update(NetworkSettings={"Networks": {}}, Mounts=[{"Type": "volume"}])
            with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"enabled-with-resources\n"}):
                result = observe(include_attachments=True)["containers"][0]
                self.assertEqual(result, {**base, "networks": [], "volumes": None})

    def test_reads_only_approved_ids_and_projects_fixed_fields(self):
        self.assertEqual(self.observe(), [ROW])
        self.assertEqual(len(self.requests), 1)
        route = urlsplit(self.requests[0])
        self.assertEqual(route.path, "/v1.44/containers/json")
        query = parse_qs(route.query)
        self.assertEqual(query["all"], ["1"])
        self.assertEqual(json.loads(query["filters"][0]), {"id": [TARGET]})

    def test_foreign_or_duplicate_daemon_results_fail_closed(self):
        first = self.response[0]
        for response in ([first, {**first, "Id": FOREIGN}], [first, first]):
            self.response = response
            with self.assertRaises(ValueError):
                self.observe()

    def test_missing_id_and_changed_compose_identity_are_distinct(self):
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong-project"
        self.assertEqual(self.observe(), [{**SCOPE[0], "state": "UNKNOWN"}])
        self.response = []
        self.assertEqual(self.observe(), [{**SCOPE[0], "state": "NOT_FOUND"}])

    def test_published_ports_are_filtered_and_normalized_in_one_scoped_request(self):
        self.response[0]["Ports"] = [*DAEMON_PORTS, DAEMON_PORTS[0]]
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "published_ports": [BINDING, IPV6_BINDING]},
        ])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.observe(), [ROW])

    def test_unpublished_ports_and_incomplete_ports_are_distinct(self):
        for ports, expected in (
            (DAEMON_PORTS[2:], []),
            (None, None),
            ([{"PrivatePort": True, "Type": "tcp"}], None),
            ([{**DAEMON_PORTS[3], "IP": "invalid"}], None),
            ([DAEMON_PORTS[0], {**DAEMON_PORTS[1], "IP": "invalid"}], None),
            ([{**DAEMON_PORTS[0], "PublicPort": port} for port in range(1, 10)], None),
        ):
            with self.subTest(ports=ports):
                self.response[0]["Ports"] = ports
                self.assertEqual(self.observe(include_ports=True), [{**ROW, "published_ports": expected}])

    def test_ports_are_hidden_when_compose_identity_is_unverified(self):
        self.response[0]["Ports"] = DAEMON_PORTS
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong-project"
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "state": "UNKNOWN", "published_ports": None},
        ])
        self.response = []
        self.assertEqual(self.observe(include_ports=True), [
            {**ROW, "state": "NOT_FOUND", "published_ports": None},
        ])


    def test_inspects_only_the_matched_running_container_and_projects_mount_status(self):
        for mounts, config, expected in (
            ([], {}, "NONE"),
            ([{"Type": "volume", "Source": "/private/path"}], {}, "PRESENT"),
            ([], {"Binds": ["/private/path:/data"]}, "PRESENT"),
            ([], {"Tmpfs": {"/data": "size=1m"}}, "PRESENT"),
            (None, {}, "UNKNOWN"),
            ([], {"Binds": ""}, "UNKNOWN"),
        ):
            with self.subTest(mounts=mounts, config=config):
                self.requests.clear()
                self.inspect.update(Mounts=mounts, HostConfig=config)
                self.assertEqual(self.observe(include_ports=True, include_mounts=True), [
                    {**ROW, "published_ports": None, "mount_status": expected},
                ])
                self.assertEqual(len(self.requests), 2)
                self.assertEqual(self.requests[1], f"/v1.44/containers/{TARGET}/json")
        self.inspect = None
        self.assertEqual(self.observe(include_ports=True, include_mounts=True)[0]["mount_status"], "UNKNOWN")
        self.requests.clear()
        self.response[0]["Labels"]["com.docker.compose.project"] = "wrong"
        self.assertEqual(self.observe(include_ports=True, include_mounts=True)[0]["mount_status"], "UNKNOWN")
        self.assertEqual(len(self.requests), 1)

    def test_inspects_network_without_publishing_network_details_or_requesting_a_second_inspect(self):
        for mode, networks, expected in (
            ("none", {"none": {}}, "ISOLATED"),
            ("bridge", {"private-network": {"IPAddress": "192.0.2.10"}}, "OTHER"),
            ("host", {"host": {}}, "OTHER"),
            ("container:peer", {}, "OTHER"),
            ("none", {"none": {}, "private-network": {}}, "OTHER"),
            ("none", {}, "UNKNOWN"),
            ("none", None, "UNKNOWN"),
        ):
            with self.subTest(mode=mode, networks=networks):
                self.requests.clear()
                self.inspect["HostConfig"]["NetworkMode"] = mode
                self.inspect["NetworkSettings"] = {"Networks": networks}
                self.assertEqual(self.observe(include_ports=True, include_mounts=True, include_network=True), [
                    {**ROW, "published_ports": None, "mount_status": "NONE", "network_status": expected},
                ])
                self.assertEqual(len(self.requests), 2)
        self.inspect["Id"] = FOREIGN
        self.assertEqual(self.observe(include_ports=True, include_mounts=True, include_network=True)[0]["network_status"],
                         "UNKNOWN")

    def test_dependency_scope_requires_private_host_config_and_exclusive_daemon(self):
        self.inspect["NetworkSettings"] = {"Networks": {"none": {}}}
        options = dict(include_ports=True, include_mounts=True, include_network=True, include_dependencies=True)
        profile = {"NetworkMode": "none", "PidMode": "", "IpcMode": "private", "UTSMode": "",
                   "CgroupnsMode": "private", "Privileged": False, "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                   "Runtime": "runc", "LogConfig": {"Type": "local", "Config": {}}}
        for config, peers, expected in (
            (profile, [{"Id": TARGET, "State": "running"}], "ISOLATED"),
            (profile, [{"Id": TARGET, "State": "running"}, {"Id": FOREIGN, "State": "exited"}], "OTHER"),
            (profile, [{"Id": TARGET, "State": "paused"}], "UNKNOWN"),
            (profile, [{"Id": FOREIGN, "State": "running"}], "UNKNOWN"),
            (profile, None, "UNKNOWN"),
            ({**profile, "PidMode": "host"}, [], "OTHER"),
            ({**profile, "IpcMode": "shareable"}, [], "OTHER"),
            ({**profile, "Devices": [{"PathOnHost": "/secret-device"}]}, [], "OTHER"),
            ({**profile, "Privileged": True}, [], "OTHER"),
            ({**profile, "CapAdd": ["SYS_ADMIN"]}, [], "OTHER"),
            ({**profile, "LogConfig": {"Type": "syslog", "Config": {"syslog-address": "tcp://192.0.2.10:514"}}},
             [], "OTHER"),
            ({**profile, "LogConfig": {"Type": "local", "Config": "bad"}}, [], "UNKNOWN"),
            ({**profile, "LogConfig": None}, [], "UNKNOWN"),
            ({**profile, "Runtime": "custom-runtime"}, [], "OTHER"),
            ({**profile, "Runtime": ""}, [], "UNKNOWN"),
            ({**profile, "CgroupnsMode": None}, [], "UNKNOWN"),
        ):
            with self.subTest(config=config, peers=peers):
                self.inspect["HostConfig"] = config
                self.peers = peers
                self.requests.clear()
                self.assertEqual(self.observe(**options), [
                    {**ROW, "published_ports": None, "mount_status": "NONE", "network_status": "ISOLATED",
                     "dependency_status": expected},
                ])
                if config == profile:
                    self.assertEqual(self.requests[-1], "/v1.44/containers/json?all=1&limit=2")
                else:
                    self.assertEqual(len(self.requests), 2)
