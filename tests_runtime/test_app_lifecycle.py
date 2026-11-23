import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_app_profiles import specification
from vpn_orbit.app_lifecycle import Lifecycle, managed_contents
from vpn_orbit.app_profiles import PANEL_CA_FILE, digest
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.storage import Journal


ID = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
INSTALL = ID[:-1] + "B"
REMOVE = ID[:-1] + "C"


class FixtureDocker:
    """Stateful Docker model. Lifecycle and journal operations remain real."""

    def __init__(self):
        self.containers = {}
        self.volumes = {}
        self.networks = {}
        self.calls = []
        self.lost_start_reply = False
        self.images = {}

    def __call__(self, kind, verb, *rest, **options):
        self.calls.append((kind, verb, *rest))
        if kind == "pull":
            return ""
        if kind == "compose":
            document = json.loads(Path(rest[rest.index("--file") + 1]).read_bytes())
            network = document["networks"]["apps"]
            self.networks[network["name"]] = {"Id": "4" * 64, "Name": network["name"], "Driver": "bridge",
                                                "Labels": network["labels"], "Containers": {}}
            for value in document["volumes"].values():
                self.volumes[value["name"]] = {"Name": value["name"], "Driver": "local", "Labels": value["labels"]}
            for index, (name, value) in enumerate(document["services"].items()):
                identity = f"{index + 1:064x}"
                self.containers[identity] = {"Id": identity, "Image": "sha256:" + "5" * 64,
                    "Config": {"Image": value["image"], "Labels": {**value["labels"],
                               "com.docker.compose.service": name, "com.docker.compose.project": document["name"]}},
                    "State": {"Running": False}, "HostConfig": {"Privileged": False, "OomKillDisable": False},
                    "NetworkSettings": {"Networks": {("host" if value.get("network_mode") == "host"
                                                      else network["name"]): {"NetworkID": ""}}}}
            return ""
        entries = {"container": self.containers, "volume": self.volumes, "network": self.networks}
        if verb == "inspect":
            if kind == "image":
                return json.dumps([{"Id": "sha256:" + "5" * 64, **self.images.get(rest[0], {})}])
            return json.dumps([entries[kind][rest[0]]])
        if verb == "ls":
            if kind == "container" and "--filter" in rest:
                selector = rest[rest.index("--filter") + 1]
                if selector.startswith("volume="):
                    return ""
                project = selector.split("=")[-1]
                return "\n".join(key for key, item in self.containers.items()
                                 if item["Config"]["Labels"]["com.docker.compose.project"] == project)
            return "\n".join(entries[kind])
        if verb == "start":
            for entry in rest:
                self.containers[entry]["State"] = {"Running": True, "Health": {"Status": "healthy"}}
                self.containers[entry]["HostConfig"]["OomKillDisable"] = None
                for network in self.containers[entry]["NetworkSettings"]["Networks"].values():
                    network["NetworkID"] = "4" * 64
            if self.lost_start_reply:
                self.lost_start_reply = False
                raise Denied("APP_DOCKER_UNAVAILABLE")
        elif verb == "stop":
            self.containers[rest[-1]]["State"]["Running"] = False
        elif verb == "rm":
            del self.containers[rest[0]]
        return ""


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        docker = self.docker = FixtureDocker()
        spec = self.spec = specification()
        self.binding = digest(spec)
        # Configure as the developer in a private synthetic parent. The host
        # parent check is separate from the actual files, process lock and journal.
        self.state = self.directory / ID
        self.state.mkdir(mode=0o700)
        from vpn_orbit.app_profiles import canonical, managed_files, render
        (self.state / "spec.json").write_bytes(canonical(spec))
        for name, value in managed_files(spec).items():
            (self.state / name).write_text(value)
        (self.state / "compose.json").write_bytes(canonical(render(spec, "a" * 64)))
        for path in self.state.iterdir():
            path.chmod(0o600)
        from vpn_orbit.app_lifecycle import SCHEMA
        journal = Journal.initialize(self.state / "lifecycle.sqlite3", SCHEMA)
        with journal.write() as db:
            db.execute("INSERT INTO installation(id,spec_digest,owner) VALUES(1,?,?)", (self.binding, "a" * 64))
        self.app = Lifecycle(ID, root=self.directory, docker=docker, owner=os.geteuid())

    def test_install_replay_and_remove_uses_only_recorded_ids(self):
        self.assertEqual(self.app.execute(INSTALL, "install", self.binding)["outcome"], "SUCCEEDED")
        count = len(self.docker.calls)
        self.assertEqual(self.app.execute(INSTALL, "install", self.binding)["outcome"], "SUCCEEDED")
        self.assertEqual(len(self.docker.calls), count)
        volumes, networks = copy.deepcopy(self.docker.volumes), copy.deepcopy(self.docker.networks)
        owned = set(self.docker.containers)
        self.assertEqual(self.app.execute(REMOVE, "remove", self.binding)["outcome"], "SUCCEEDED")
        self.assertEqual(self.docker.volumes, volumes)
        self.assertEqual(self.docker.networks, networks)
        self.assertEqual({call[-1] for call in self.docker.calls if call[:2] == ("container", "rm")}, owned)
        self.assertEqual(self.app.status()["state"], "REMOVED")

    def test_drift_and_shared_network_refuse_mutation(self):
        self.app.execute(INSTALL, "install", self.binding)
        network = next(iter(self.docker.networks.values()))
        network["Containers"] = {"f" * 64: {"Name": "foreign"}}
        with self.assertRaisesRegex(Denied, "APP_NETWORK_SHARED"):
            self.app.execute(REMOVE, "remove", self.binding)
        network["Containers"] = {}
        next(iter(self.docker.containers.values()))["HostConfig"]["Privileged"] = True
        with self.assertRaisesRegex(Denied, "APP_CONTAINER_DRIFT"):
            self.app.execute(REMOVE, "remove", self.binding)
        self.assertFalse(any(call[:2] == ("container", "stop") for call in self.docker.calls))

    def test_lost_start_reply_is_quarantined_until_verified_readback(self):
        self.app.execute(INSTALL, "install", self.binding)
        self.docker.lost_start_reply = True
        self.assertEqual(self.app.execute(REMOVE, "start", self.binding)["outcome"], "UNKNOWN_OUTCOME")
        with self.assertRaisesRegex(Denied, "APP_RECONCILIATION_REQUIRED"):
            self.app.execute(ID[:-1] + "D", "remove", self.binding)
        before = len([call for call in self.docker.calls if call[:2] == ("container", "start")])
        self.assertEqual(self.app.reconcile(REMOVE)["outcome"], "RECONCILED_SUCCEEDED")
        self.assertEqual(len([call for call in self.docker.calls if call[:2] == ("container", "start")]), before)

    def test_config_drift_cannot_reach_docker(self):
        with patch.object(self.docker, "lost_start_reply", False):
            (self.state / "compose.json").write_text("{}")
            with self.assertRaisesRegex(Denied, "APP_CONFIG_DRIFT"):
                self.app.execute(INSTALL, "install", self.binding)
        self.assertEqual(self.docker.calls, [])

    def test_image_pull_failure_reports_phase_and_stays_quarantined(self):
        def fail_pull(kind, *args, **options):
            if kind == "pull":
                raise Denied("APP_DOCKER_FAILED")
            return self.docker(kind, *args, **options)

        self.app.docker = fail_pull
        receipt = self.app.execute(INSTALL, "install", self.binding)
        self.assertEqual((receipt["outcome"], receipt["code"]), ("UNKNOWN_OUTCOME", "APP_IMAGE_PULL_UNVERIFIED"))
        self.app.docker = self.docker
        self.assertEqual(self.app.execute(INSTALL, "install", self.binding), receipt)
        self.assertEqual(self.app.reconcile(INSTALL)["code"], "APP_QUARANTINED")
        self.assertFalse(any(call[0] == "compose" for call in self.docker.calls))

    def test_install_health_timeout_keeps_quarantine_until_readback_verifies_health(self):
        def start_unhealthy(kind, verb, *args, **options):
            result = self.docker(kind, verb, *args, **options)
            if (kind, verb) == ("container", "start"):
                for identity in args:
                    self.docker.containers[identity]["State"]["Health"]["Status"] = "starting"
            return result

        self.app.docker = start_unhealthy
        with patch("vpn_orbit.app_lifecycle.time.monotonic", side_effect=[0, 151]):
            receipt = self.app.execute(INSTALL, "install", self.binding)
        self.assertEqual((receipt["outcome"], receipt["code"]), ("UNKNOWN_OUTCOME", "APP_HEALTH_UNVERIFIED"))

        mutations = tuple(call for call in self.docker.calls if call[1] in {"start", "stop", "rm"})
        self.assertEqual(self.app.reconcile(INSTALL)["code"], "APP_QUARANTINED")
        self.assertEqual(self.app.status()["state"], "UNKNOWN_OUTCOME")
        with self.assertRaisesRegex(Denied, "APP_RECONCILIATION_REQUIRED"):
            self.app.execute(REMOVE, "remove", self.binding)

        # Complete the dependency startup out of band and observe the same IDs.
        for container in self.docker.containers.values():
            container["State"] = {"Running": True, "Health": {"Status": "healthy"}}
        self.assertEqual(self.app.reconcile(INSTALL)["outcome"], "RECONCILED_SUCCEEDED")
        self.assertEqual(self.app.status()["state"], "HEALTHY")
        self.assertEqual(tuple(call for call in self.docker.calls if call[1] in {"start", "stop", "rm"}), mutations)

    def test_dns_defaults_after_docker_restart_keep_existing_inventory_valid(self):
        self.assertEqual(self.app.execute(INSTALL, "install", self.binding)["outcome"], "SUCCEEDED")
        _, document, initial = self.app.configuration()
        legacy = json.loads(initial["inventory"])
        fields = ("Dns", "DnsOptions", "DnsSearch")
        for index, item in enumerate(legacy["containers"].values()):
            container = self.docker.containers[item["Id"]]
            host = {**container["HostConfig"], "OomKillDisable": False}
            host.update({key: ([] if index % 2 else None) for key in fields})
            item["configuration"] = digest({
                "Image": container["Image"], "Config": container["Config"], "HostConfig": host, "Mounts": [],
            })
            container["HostConfig"].update({key: (None if index % 2 else []) for key in fields})
        initial["inventory"] = json.dumps(legacy)
        self.assertEqual(self.app.verify_inventory(document, initial), legacy)

        container["HostConfig"]["Dns"] = ["192.0.2.53"]
        with self.assertRaisesRegex(Denied, "APP_CONTAINER_DRIFT"):
            self.app.verify_inventory(document, initial)

    def test_only_the_exact_pinned_platform_image_can_skip_pull(self):
        reference = self.spec["images"]["postgres"]
        short = reference.removeprefix("docker.io/library/")
        cases = (
            ({"Os": "linux", "Architecture": "amd64", "RepoDigests": [short]}, False),
            ({"Os": "linux", "Architecture": "arm64", "RepoDigests": [short]}, True),
            ({"Os": "linux", "Architecture": "amd64", "RepoDigests": [short[:-64] + "f" * 64]}, True),
            ({"Os": "linux", "Architecture": "amd64"}, True),
        )
        for image, pull in cases:
            with self.subTest(image=image):
                self.docker.images[reference] = image
                self.docker.calls.clear()
                self.app.acquire_image(reference)
                self.assertEqual(any(call[0] == "pull" for call in self.docker.calls), pull)

    def test_private_panel_ca_preserves_public_trust_roots(self):
        system = b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
        private = "-----BEGIN CERTIFICATE-----\nprivate\n-----END CERTIFICATE-----\n"
        with patch("vpn_orbit.app_lifecycle.protected_bytes", return_value=system) as read:
            self.assertEqual(managed_contents(PANEL_CA_FILE, private), system + private.encode())
            self.assertEqual(read.call_args.kwargs["owner"], 0)
