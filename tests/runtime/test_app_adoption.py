import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpn_orbit.app_adoption import ExternalLifecycle, checked_dependencies
from vpn_orbit.app_lifecycle import SCHEMA, atomic_write
from vpn_orbit.app_profiles import canonical, digest
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.storage import Journal


INSTALLATION = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"
ADOPT = INSTALLATION[:-1] + "B"
DETACH = INSTALLATION[:-1] + "C"
OTHER = INSTALLATION[:-1] + "D"
CONTAINER = "c" * 64
SOURCE = "/var/lib/fixture/compose.yaml"
PROJECT = "fixture"
PIN = json.loads((Path(__file__).resolve().parents[2] / "vpn_orbit/application-images.json").read_text())["images"]["remnawave-node"]


class NodeDocker:
    def __init__(self):
        self.container = {
            "Id": CONTAINER, "Image": "sha256:" + "d" * 64,
            "Config": {"Labels": {"com.docker.compose.service": "node", "com.docker.compose.project": PROJECT,
                                  "com.docker.compose.project.config_files": SOURCE,
                                  "com.docker.compose.config-hash": "e" * 64},
                       "Env": ["SECRET_KEY=adoption-secret-canary"]},
            "HostConfig": {"NetworkMode": "host"},
            "State": {"Running": True, "Status": "running", "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Networks": {"host": {"NetworkID": "4" * 64}}}, "Mounts": [],
        }

    def __call__(self, kind, verb, *args, **options):
        if (kind, verb) == ("container", "ls"):
            assert args[-1] == f"label=com.docker.compose.project={PROJECT}"
            return CONTAINER
        if (kind, verb) == ("container", "inspect"):
            assert args == (CONTAINER,)
            return json.dumps([self.container])
        if (kind, verb) == ("image", "inspect"):
            assert args == (self.container["Image"],)
            return json.dumps([{"Id": self.container["Image"], "RepoDigests": [PIN]}])
        raise AssertionError("unexpected Docker operation")


class ExternalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.docker = NodeDocker()
        self.source = self.enterContext(patch("vpn_orbit.app_adoption.source_digest", return_value="1" * 64))
        self.app, self.binding, self.review = self.staged(INSTALLATION)

    def staged(self, identity):
        # Use an isolated journal and the production capture, without requiring
        # a root-owned ancestor for this test process's temporary root.
        directory = self.root / identity
        directory.mkdir(mode=0o700)
        app = ExternalLifecycle(identity, root=self.root, owner=os.geteuid(), docker=self.docker)
        layout = {"version": 1, "id": identity, "project": PROJECT, "compose_files": [SOURCE], "extra_files": [],
                  "service_hashes": {"node": "e" * 64}}
        baseline = app.capture(layout)
        definition = {"layout": layout, "baseline": baseline, "nonce": "a" * 64}
        binding = digest(definition)
        atomic_write(directory / "external.json", canonical(definition))
        journal = Journal.initialize(directory / "lifecycle.sqlite3", SCHEMA)
        with journal.write() as db:
            db.execute("INSERT INTO installation(id,spec_digest,owner) VALUES(1,?,?)", (binding, definition["nonce"]))
        return app, binding, baseline["identity"]

    def test_register_reconcile_detach_and_idempotent_retry_preserve_docker(self):
        before = canonical(self.docker.container)
        adopted = self.app.execute(ADOPT, "adopt", self.binding, self.review)
        self.assertEqual(adopted["code"], "APP_ADOPTION_REGISTERED")
        self.assertEqual(self.app.status()["state"], "ADOPTED")
        self.assertEqual(self.app.reconcile(ADOPT, action="adopt", binding=self.binding, review=self.review), adopted)
        self.assertEqual(self.app.execute(ADOPT, "adopt", self.binding, self.review), adopted)
        second, binding, review = self.staged(OTHER)
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_ALREADY_REGISTERED"):
            second.execute(OTHER, "adopt", binding, review)
        detached = self.app.execute(DETACH, "detach", self.binding)
        self.assertEqual(detached["code"], "APP_ADOPTION_DETACHED")
        self.assertEqual(self.app.status()["state"], "STAGED")
        self.assertEqual(self.app.reconcile(DETACH, action="detach", binding=self.binding), detached)
        self.assertEqual(canonical(self.docker.container), before)
        for action in ("install", "remove", "start"):
            with self.subTest(action=action), self.assertRaisesRegex(Denied, "APP_ACTION_INVALID"):
                self.app.execute(OTHER, action, self.binding)
        self.assertNotIn(b"adoption-secret-canary", (self.app.directory / "external.json").read_bytes())

    def test_rejects_changed_runtime_configuration_and_missing_receipt(self):
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            self.app.execute(ADOPT, "adopt", self.binding, "f" * 64)
        self.docker.container["Config"]["Env"] = ["SECRET_KEY=changed"]
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            self.app.execute(ADOPT, "adopt", self.binding, self.review)
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_RECEIPT_UNVERIFIED"):
            self.app.reconcile(ADOPT, action="adopt", binding=self.binding, review=self.review)
        self.assertEqual(self.app.status()["state"], "STAGED")

    def test_rejects_node_without_a_healthcheck(self):
        del self.docker.container["State"]["Health"]
        with self.assertRaisesRegex(Denied, "APP_HEALTH_UNVERIFIED"):
            self.app.execute(ADOPT, "adopt", self.binding, self.review)

    def test_rejects_changed_source_and_writable_or_unknown_binds(self):
        self.source.return_value = "2" * 64
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            self.app.execute(ADOPT, "adopt", self.binding, self.review)
        self.source.return_value = "1" * 64
        self.docker.container["Mounts"] = [{"Type": "bind", "Source": SOURCE, "RW": True}]
        with self.assertRaisesRegex(Denied, "APP_BIND_UNVERIFIED"):
            self.app.execute(ADOPT, "adopt", self.binding, self.review)


class ConfiguredDependencyTests(unittest.TestCase):
    def test_checks_runtime_postgres_and_redis_addresses_against_network_aliases(self):
        network = "a" * 64
        def container(alias, env=(), *, identity=network):
            return {"Config": {"Env": list(env)}, "NetworkSettings": {
                "Networks": {"fixture": {"NetworkID": identity, "Aliases": [alias]}}}}

        containers = {
            "panel": container("panel", ("DATABASE_URL=postgresql://user:secret@database:5432/db", "REDIS_HOST=cache")),
            "postgres": container("database"),
            "redis": container("cache"),
        }
        roles = {"panel": "remnawave-panel", "postgres": "postgres", "redis": "redis"}
        self.assertEqual(checked_dependencies(containers, roles), {
            "panel": ["postgres", "redis"], "postgres": [], "redis": [],
        })
        containers["panel"]["HostConfig"] = {"ExtraHosts": ["database:192.0.2.2"]}
        with self.assertRaisesRegex(Denied, "APP_DEPENDENCY_UNVERIFIED"):
            checked_dependencies(containers, roles)
        containers["panel"]["HostConfig"] = {}
        containers["panel"]["Mounts"] = [{"Type": "bind", "Destination": "/etc"}]
        with self.assertRaisesRegex(Denied, "APP_DEPENDENCY_UNVERIFIED"):
            checked_dependencies(containers, roles)
        containers["panel"]["Mounts"] = []
        containers["panel"]["NetworkSettings"]["Networks"]["fixture"]["Aliases"].append("database")
        with self.assertRaisesRegex(Denied, "APP_DEPENDENCY_UNVERIFIED"):
            checked_dependencies(containers, roles)
        containers["panel"]["NetworkSettings"]["Networks"]["fixture"]["Aliases"].remove("database")
        containers["redis"] = container("cache", identity="b" * 64)
        with self.assertRaisesRegex(Denied, "APP_DEPENDENCY_UNVERIFIED"):
            checked_dependencies(containers, roles)
