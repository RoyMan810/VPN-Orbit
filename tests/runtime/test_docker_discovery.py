import hashlib
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
from vpn_orbit.runtime.protocol import MAX_FRAME, MAX_PROBE_REPLY, PROBE_VERSION, canonical, compose_summary, docker_summary
from vpn_orbit.runtime.ssh import parse_probe


TARGET = "a" * 64
FOREIGN = "b" * 64
SCOPE = [{"id": TARGET, "project": "fixture", "service": "web"}]
ROW = {**SCOPE[0], "state": "RUNNING"}
SCOPED_ROW = {**ROW, "published_ports": None, "mount_status": "UNKNOWN", "network_status": "UNKNOWN",
              "dependency_status": "UNKNOWN", "started_at": None}
SUMMARY = {"status": "OBSERVED", "containers": [SCOPED_ROW]}
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
    def test_start_time_is_strict_and_preserves_nanoseconds(self):
        started = "2026-11-18T01:02:03.123456789Z"
        row = {**ROW, "published_ports": [], "mount_status": "NONE", "network_status": "ISOLATED",
               "dependency_status": "ISOLATED", "started_at": started}
        self.assertEqual(docker_summary({"status": "OBSERVED", "containers": [row]})["containers"][0], row)
        self.assertEqual(HELPER["docker_started_at"]({"State": {"StartedAt": started}}), started)
        for bad in ("0001-01-01T00:00:00Z", "2026-02-30T01:02:03Z", "canary"):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                self.assertIsNone(HELPER["docker_started_at"]({"State": {"StartedAt": bad}}))
                docker_summary({"status": "OBSERVED", "containers": [{**row, "started_at": bad}]})

    def test_probe_keeps_compose_discovery_separate_from_approved_scope(self):
        scoped = {"status": "NOT_CONFIGURED", "containers": []}
        compose = {"status": "OBSERVED", "containers": [{**ROW, "image_id": "sha256:" + FOREIGN}]}
        value = {"v": PROBE_VERSION, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED", "nginx_service": "NOT_FOUND"},
                 "docker": scoped, "app_links": {"status": "NOT_CONFIGURED", "links": []}, "firewall": {"status": "NOT_CONFIGURED", "chains": []}, "nginx": {"status": "NOT_CONFIGURED", "names": [], "partial": False}, "local_https": {"status": "NOT_CONFIGURED", "sites": []}, "compose": compose}
        result = parse_probe(canonical(value), now=1000)
        self.assertEqual(result["docker"], scoped)
        self.assertEqual(result["compose"], compose)
        for bad in ({"status": "LIMIT_EXCEEDED", "containers": compose["containers"]},
                    {"status": "OBSERVED", "containers": compose["containers"] * 2},
                    {"status": "OBSERVED", "containers": [{**compose["containers"][0], "env": "secret"}]},
                    {"status": "OBSERVED", "containers": [{**compose["containers"][0], "image_id": "/local/path"}]}):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                compose_summary(bad)

    def test_probe_requires_typed_complete_attachment_fields(self):
        base = {**ROW, "image_id": "sha256:" + FOREIGN}
        row = {**base, "networks": ["backend", "frontend"], "volumes": None}
        scoped = {"status": "NOT_CONFIGURED", "containers": []}
        value = {"v": PROBE_VERSION, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc",
                 "observed_at": 1000, "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED", "nginx_service": "NOT_FOUND"},
                 "docker": scoped, "app_links": {"status": "NOT_CONFIGURED", "links": []}, "firewall": {"status": "NOT_CONFIGURED", "chains": []}, "nginx": {"status": "NOT_CONFIGURED", "names": [], "partial": False}, "local_https": {"status": "NOT_CONFIGURED", "sites": []}, "compose": {"status": "OBSERVED", "containers": [row]}}
        self.assertEqual(parse_probe(canonical(value), now=1000)["compose"], value["compose"])
        with self.assertRaises(Denied):
            parse_probe(canonical({**value, "v": PROBE_VERSION - 1}), now=1000)
        for rows in ([{**base, "networks": []}], [row, {**base, "id": FOREIGN}],
                     [{**row, "volumes": ["/host/private"]}], [{**row, "volumes": ["x" * 65]}],
                     [{**row, "volumes": ["data", "data"]}], [{**row, "volumes": ["web", "data"]}],
                     [{**row, "volumes": [str(i) for i in range(9)]}],
                     [{**row, "networks": {"frontend": "192.0.2.1"}}]):
            with self.subTest(rows=rows), self.assertRaises(Denied):
                compose_summary({"status": "OBSERVED", "containers": rows})

    def test_adoption_evidence_is_bounded_and_belongs_to_observed_resources(self):
        image = "sha256:" + FOREIGN
        row = {**ROW, "image_id": image, "networks": ["backend"], "volumes": ["data"]}
        fingerprint = "c" * 64 + ":" + "d" * 64
        evidence = {"images": {image: [fingerprint]}, "networks": {"backend": "fixture"}, "volumes": {"data": None}}
        compose = {"status": "OBSERVED", "containers": [row], "adoption_evidence": evidence}
        self.assertEqual(compose_summary(compose), compose)
        for invalid in ({"images": {"sha256:" + TARGET: [fingerprint]}},
                        {"images": {image: ["remnawave/node@sha256:" + FOREIGN]}},
                        {"images": {image: [fingerprint] * 5}},
                        {"networks": {"alien": "fixture"}}, {"volumes": {"data": "/host/project"}}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                compose_summary({**compose, "adoption_evidence": {**evidence, **invalid}})

    def test_largest_supported_compose_and_scoped_inventory_fit_the_frame(self):
        row = {"project": "p" * 63, "service": "s" * 63, "state": "RESTARTING"}
        address = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        ports = [{"address": address, "host_port": p, "container_port": p, "protocol": "sctp"}
                 for p in range(65528, 65536)]
        scoped = [{**row, "id": f"{i:064x}", "state": "RUNNING", "published_ports": ports,
                   "mount_status": "PRESENT", "network_status": "OTHER", "dependency_status": "UNKNOWN",
                   "started_at": "2026-11-18T01:02:03.123456789Z"} for i in range(8)]
        compose = [{**row, "id": f"{i:064x}", "image_id": "sha256:" + FOREIGN} for i in range(12)]
        value = {"v": PROBE_VERSION, "uid": 0, "boot_id": "12345678-1234-1234-1234-123456789abc", "observed_at": 1000,
                 "software": {"docker": "PRESENT", "nginx": "NOT_DETECTED", "nginx_service": "NOT_FOUND"},
                 "docker": {"status": "OBSERVED", "containers": scoped},
                 "app_links": {"status": "NOT_CONFIGURED", "links": []},
                 "firewall": {"status": "NOT_CONFIGURED", "chains": []},
                 "nginx": {"status": "NOT_CONFIGURED", "names": [], "partial": False},
                 "local_https": {"status": "OBSERVED", "sites": [
                     {"name": chr(97 + i) + "a" * 62 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 5,
                      "state": "VERIFIED", "expires_at": 253402300799} for i in range(2)
                 ]},
                 "compose": {"status": "OBSERVED", "containers": compose}}
        result = parse_probe(canonical(value), now=1000)
        self.assertLess(len(canonical(value)) + 1, MAX_PROBE_REPLY)
        self.assertLessEqual(len(canonical(result)) + 1024, MAX_FRAME)
        names = [f"{i:064x}" for i in range(8)]
        for item in compose:
            item.update(networks=names, volumes=names)
        value["compose"]["adoption_evidence"] = {
            "images": {"sha256:" + FOREIGN: [FOREIGN + ":" + TARGET]},
            "networks": {}, "volumes": {},
        }
        compose[0]["volumes"] = []
        self.assertGreater(len(canonical(value)), MAX_PROBE_REPLY)
        wire = HELPER["probe_reply"](value).encode() + b"\n"
        self.assertLessEqual(len(wire), MAX_PROBE_REPLY)
        result = parse_probe(wire, now=1000)
        self.assertEqual(result["docker"], value["docker"])
        self.assertEqual(len(result["compose"]["containers"]), 12)
        self.assertEqual(result["compose"]["containers"][0]["volumes"], [])
        self.assertIsNone(result["compose"]["containers"][1]["volumes"])
        self.assertIsNone(result["compose"]["containers"][1]["networks"])
        self.assertNotIn("adoption_evidence", result["compose"])
        self.assertLessEqual(len(canonical(result)) + 1024, MAX_FRAME)
        self.assertEqual(result["local_https"], value["local_https"])

        value["nginx"] = {"status": "OBSERVED", "partial": True, "names": ["panel.example"]}
        reply = HELPER["probe_reply"]
        with patch.dict(reply.__globals__, {"MAX_PROBE_REPLY": len(canonical(value)) - 1}):
            wire = reply(value).encode() + b"\n"
        nginx_limited = parse_probe(wire, now=1000)
        self.assertEqual(nginx_limited["nginx"], {"status": "LIMIT_EXCEEDED", "names": [], "partial": False})
        self.assertEqual(nginx_limited["local_https"], result["local_https"])

        value["local_https"]["sites"] += [
            {**site, "name": chr(99 + i) + site["name"][1:]} for i, site in enumerate(value["local_https"]["sites"])
        ]
        with patch.dict(reply.__globals__, {"MAX_PROBE_REPLY": len(canonical(value)) - 1}):
            wire = reply(value).encode() + b"\n"
        self.assertLessEqual(len(wire), MAX_PROBE_REPLY)
        result = parse_probe(wire, now=1000)
        self.assertEqual(result["local_https"], {"status": "UNAVAILABLE", "sites": []})
        self.assertEqual(result["docker"], value["docker"])

    def test_saved_summary_remains_bounded_and_typed(self):
        self.assertEqual(docker_summary(SUMMARY), SUMMARY)
        for payload in ({"status": "OBSERVED", "containers": []},
                        {"status": "OBSERVED", "containers": [ROW]},
                        {"status": "NOT_CONFIGURED", "containers": [ROW]},
                        {"status": "OBSERVED", "containers": [SCOPED_ROW, SCOPED_ROW]},
                        {"status": "OBSERVED", "containers": [{**SCOPED_ROW, "env": ["canary"]}]},
                        {"status": "OBSERVED", "containers": [{**SCOPED_ROW, "state": "HEALTHY"}]},
                        {"status": "OBSERVED", "containers": [{**SCOPED_ROW, "project": "../private"}]}):
            with self.subTest(payload=payload), self.assertRaises(Denied):
                docker_summary(payload)

    def test_bindings_are_typed_and_bounded(self):
        def summary(ports, *, state="RUNNING"):
            return {"status": "OBSERVED", "containers": [{**SCOPED_ROW, "state": state, "published_ports": ports}]}

        for ports in (None, [], [BINDING, IPV6_BINDING]):
            with self.subTest(ports=ports):
                payload = summary(ports)
                self.assertEqual(docker_summary(payload), payload)
        for payload in (
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
                docker_summary(payload)

    def test_mount_status_is_typed_and_consistent(self):
        for status in ("NONE", "PRESENT", "UNKNOWN"):
            payload = {"status": "OBSERVED", "containers": [
                {**SCOPED_ROW, "published_ports": [], "mount_status": status},
            ]}
            self.assertEqual(docker_summary(payload), payload)
        for row in ({k: v for k, v in SCOPED_ROW.items() if k != "published_ports"},
                    {**SCOPED_ROW, "published_ports": [], "mount_status": []},
                    {**SCOPED_ROW, "state": "NOT_FOUND", "published_ports": None, "mount_status": "NONE"}):
            with self.subTest(row=row), self.assertRaises(Denied):
                docker_summary({"status": "OBSERVED", "containers": [row]})

    def test_network_status_is_typed_and_consistent(self):
        row = {**SCOPED_ROW, "published_ports": [], "mount_status": "NONE"}
        for status in ("ISOLATED", "OTHER", "UNKNOWN"):
            summary = {"status": "OBSERVED", "containers": [{**row, "network_status": status}]}
            self.assertEqual(docker_summary(summary), summary)
        for invalid in ({**row, "network_status": "bridge"},
                        {**row, "state": "CREATED", "mount_status": "UNKNOWN", "network_status": "ISOLATED"}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                docker_summary({"status": "OBSERVED", "containers": [invalid]})

    def test_dependency_scope_is_consistent(self):
        row = {**SCOPED_ROW, "published_ports": [], "mount_status": "NONE", "network_status": "ISOLATED"}
        for status in ("ISOLATED", "OTHER", "UNKNOWN"):
            payload = {"status": "OBSERVED", "containers": [{**row, "dependency_status": status}]}
            self.assertEqual(docker_summary(payload), payload)
        for invalid in ({**row, "dependency_status": "SAFE"},
                        {**row, "network_status": "OTHER", "dependency_status": "ISOLATED"},
                        {**row, "mount_status": "PRESENT", "dependency_status": "ISOLATED"}):
            with self.subTest(invalid=invalid), self.assertRaises(Denied):
                docker_summary({"status": "OBSERVED", "containers": [invalid]})

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
                elif self.path in getattr(fixture, "listings", {}):
                    value = fixture.listings[self.path]
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
            for switch, expected in (
                (b"enabled\n", base),
                (b"enabled-with-resources\n", {**base, "networks": ["bridge"], "volumes": ["named-data"]}),
            ):
                self.requests.clear()

                def read_switch(_path, limit):
                    if len(switch) > limit:
                        raise ValueError("Docker configuration too large")
                    return switch

                with patch.dict(observe.__globals__, {"read_root_config": read_switch}):
                    self.assertEqual(observe(), {"status": "OBSERVED", "containers": [expected]})
                self.assertEqual(len(self.requests), 1)
            row.update(NetworkSettings={"Networks": {}}, Mounts=[{"Type": "volume"}])
            with patch.dict(observe.__globals__, {"read_root_config": lambda *_: b"enabled-with-resources\n"}):
                result = observe()["containers"][0]
                self.assertEqual(result, {**base, "networks": [], "volumes": None})

    def test_adoption_scope_collects_only_matching_image_digests_and_resource_labels(self):
        image = "sha256:" + FOREIGN
        row = self.response[0]
        row.update(ImageID=image, NetworkSettings={"Networks": {
            "backend": {"NetworkID": TARGET}, "drifted": {"NetworkID": TARGET},
        }}, Mounts=[{"Type": "volume", "Name": "data"}])
        self.listings = {
            "/v1.44/images/json?all=1": [
                {"Id": image, "RepoDigests": ["remnawave/node@sha256:" + FOREIGN], "RepoTags": ["tag-canary"]},
                {"Id": "sha256:" + TARGET, "RepoDigests": ["private.site/repo@sha256:" + TARGET]},
            ],
            "/v1.44/networks": [
                {"Name": "backend", "Id": TARGET, "Labels": {"com.docker.compose.project": "fixture", "env": "label-canary"}},
                {"Name": "drifted", "Id": FOREIGN, "Labels": {"com.docker.compose.project": "fixture"}},
            ],
            "/v1.44/volumes": {"Volumes": [{"Name": "data", "Labels": None, "Mountpoint": "/volume-canary"}]},
        }
        observe = HELPER["observe_compose"]
        with patch.dict(observe.__globals__, {"require_docker_socket": lambda _: None,
                                             "read_root_config": lambda *_: b"enabled-with-adoption\n"}):
            result = compose_summary(observe())
            digest = hashlib.sha256(b"docker.io/remnawave/node").hexdigest()
            self.assertEqual(result["adoption_evidence"], {
                "images": {image: [digest + ":" + FOREIGN]}, "networks": {"backend": "fixture"},
                "volumes": {"data": None},
            })
            self.assertEqual(self.requests[1:], list(self.listings))
            self.assertNotIn("canary", json.dumps(result))
            self.listings["/v1.44/networks"].append(self.listings["/v1.44/networks"][0])
            self.assertEqual(observe()["adoption_evidence"]["networks"], {})
            get = observe.__globals__["docker_get"]

            def timeout(path, endpoint):
                if endpoint == "/v1.44/images/json?all=1":
                    raise TimeoutError
                return get(path, endpoint)

            with patch.dict(observe.__globals__, {"docker_get": timeout}):
                unavailable = observe()
            self.assertEqual(unavailable["containers"], result["containers"])
            self.assertNotIn("adoption_evidence", unavailable)

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
