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
START = INSTALLATION[:-1] + "E"
NEXT = INSTALLATION[:-1] + "F"
STARTED_AT = "2026-11-27T10:00:00.12345678Z"
LATER = "2026-11-27T10:00:00.123456781Z"
FINISHED_AT = "2026-11-27T10:00:00.12345679Z"
ZERO_TIME = "0001-01-01T00:00:00Z"
CONTAINER = "c" * 64
SOURCE = "/var/lib/fixture/compose.yaml"
PROJECT = "fixture"
PIN = json.loads((Path(__file__).resolve().parents[2] / "vpn_orbit/application-images.json").read_text())["images"]["remnawave-node"]


class NodeDocker:
    def __init__(self):
        self.starts = []
        self.stops = []
        self.lose_reply = False
        self.lose_stop_reply = False
        self.container = {
            "Id": CONTAINER, "Image": "sha256:" + "d" * 64,
            "Config": {"Labels": {"com.docker.compose.service": "node", "com.docker.compose.project": PROJECT,
                                  "com.docker.compose.project.config_files": SOURCE,
                                  "com.docker.compose.config-hash": "e" * 64},
                       "Env": ["SECRET_KEY=adoption-secret-canary"]},
            "HostConfig": {"NetworkMode": "host", "ReadonlyRootfs": True, "RestartPolicy": {"Name": "no"}},
            "State": {"Running": True, "Status": "running", "Health": {"Status": "healthy"},
                      "StartedAt": STARTED_AT, "FinishedAt": ZERO_TIME},
            "RestartCount": 0,
            "NetworkSettings": {"Networks": {"host": {"NetworkID": "4" * 64}}}, "Mounts": [],
        }

    def stop(self):
        self.container["State"].update(Running=False, Status="exited", FinishedAt=FINISHED_AT)
        self.container["NetworkSettings"]["Networks"] = {}

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
        if (kind, verb) == ("container", "start"):
            assert args == (CONTAINER,)
            assert self.container["State"]["Status"] == "exited"
            self.starts.append(args)
            self.container["NetworkSettings"]["Networks"] = {"host": {"NetworkID": "4" * 64, "EndpointID": "5" * 64}}
            self.container["State"].update(Running=True, Status="running", StartedAt=LATER, FinishedAt=ZERO_TIME,
                                           Health={"Status": "healthy"})
            if self.lose_reply:
                raise Denied("APP_DOCKER_FAILED")
            return CONTAINER
        if (kind, verb) == ("container", "stop"):
            assert args == ("--timeout", "30", CONTAINER)
            assert self.container["State"]["Status"] == "running"
            self.stops.append(args[-1])
            self.stop()
            if self.lose_stop_reply:
                raise Denied("APP_DOCKER_FAILED")
            return CONTAINER
        raise AssertionError("unexpected Docker operation")


class ExternalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.docker = NodeDocker()
        self.source = self.enterContext(patch("vpn_orbit.app_adoption.source_digest", return_value="1" * 64))
        self.app, self.binding, self.review = self.staged(INSTALLATION)

    def staged(self, identity, *, allow_start=False, allow_stop=False):
        # Use an isolated journal and the production capture, without requiring
        # a root-owned ancestor for this test process's temporary root.
        directory = self.root / identity
        directory.mkdir(mode=0o700)
        app = ExternalLifecycle(identity, root=self.root, owner=os.geteuid(), docker=self.docker)
        layout = {"version": 1, "id": identity, "project": PROJECT, "compose_files": [SOURCE], "extra_files": [],
                  "service_hashes": {"node": "e" * 64}}
        if allow_start:
            layout["allow_start"] = True
        if allow_stop:
            layout["allow_stop"] = True
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

    def startable(self, *, allow_stop=False):
        app, binding, review = self.staged(OTHER, allow_start=True, allow_stop=allow_stop)
        app.execute(ADOPT, "adopt", binding, review)
        return app, binding

    def test_start_requires_an_opted_in_registered_stopped_container(self):
        self.app.execute(ADOPT, "adopt", self.binding, self.review)
        self.docker.stop()
        with self.assertRaisesRegex(Denied, "APP_ADOPTED_START_UNSUPPORTED"):
            self.app.execute(START, "start-adopted", self.binding, registration_id=ADOPT)
        self.assertEqual(self.docker.starts, [])
        with patch.dict(self.docker.container["HostConfig"], IpcMode="shareable"):
            self.docker.container["State"].update(Running=True, Status="running")
            self.docker.container["NetworkSettings"]["Networks"] = {"host": {"NetworkID": "4" * 64}}
            with self.assertRaisesRegex(Denied, "APP_ADOPTED_START_UNSUPPORTED"):
                self.staged(OTHER, allow_start=True)

    def test_detach_revokes_the_old_registration_even_after_readoption(self):
        app, binding = self.startable()
        app.execute(DETACH, "detach", binding)
        app.execute(NEXT, "adopt", binding, app.definition()["baseline"]["identity"])
        self.docker.stop()
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_STATE_INVALID"):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(self.docker.starts, [])
        self.assertEqual(app.execute(START, "start-adopted", binding, registration_id=NEXT)["outcome"], "SUCCEEDED")

    def test_start_validates_full_scope_and_records_the_next_baseline(self):
        app, binding = self.startable()
        with self.assertRaisesRegex(Denied, "APP_ADOPTED_NOT_STOPPED"):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.docker.stop()
        with patch.dict(self.docker.container["State"], StartedAt=LATER), self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.source.return_value = "2" * 64
        with self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(self.docker.starts, [])
        self.source.return_value = "1" * 64
        started = app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(started["code"], "APP_ADOPTED_START_VERIFIED")
        self.assertEqual(app.execute(START, "start-adopted", binding, registration_id=ADOPT), started)
        with app.journal.connect() as db:
            inventory = json.loads(db.execute("SELECT inventory FROM installation").fetchone()["inventory"])
        self.assertEqual(inventory["containers"]["node"]["started_at"], LATER)
        self.assertEqual(self.docker.starts, [(CONTAINER,)])

    def test_uncertain_start_is_never_dispatched_again_and_requires_new_healthy_state(self):
        app, binding = self.startable()
        self.docker.stop()
        self.docker.lose_reply = True
        result = app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(result["outcome"], "UNKNOWN_OUTCOME")
        self.assertEqual(app.status()["operations"], [START])
        self.assertEqual(app.execute(START, "start-adopted", binding, registration_id=ADOPT), result)
        for operation, action in ((NEXT, "start-adopted"), (DETACH, "detach")):
            with self.subTest(action=action), self.assertRaisesRegex(Denied, "APP_RECONCILIATION_REQUIRED"):
                app.execute(operation, action, binding, registration_id=ADOPT if action == "start-adopted" else None)
        for field, value in (("StartedAt", STARTED_AT), ("Health", {"Status": "unhealthy"})):
            state = self.docker.container["State"]
            with self.subTest(field=field), patch.dict(state, {field: value}):
                self.assertEqual(app.reconcile(START, action="start-adopted", binding=binding, registration_id=ADOPT), result)
        self.assertEqual(app.reconcile(START, action="start-adopted", binding=binding, registration_id=ADOPT)["outcome"], "SUCCEEDED")
        self.assertEqual(self.docker.starts, [(CONTAINER,)])
        self.assertEqual(app.execute(DETACH, "detach", binding)["code"], "APP_ADOPTION_DETACHED")

    def test_interruption_after_docker_start_is_read_back_from_dispatching(self):
        app, binding = self.startable()
        self.docker.stop()
        with patch.object(app, "record_node_outcome", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(app.execute(START, "start-adopted", binding, registration_id=ADOPT)["outcome"], "UNKNOWN_OUTCOME")
        self.assertEqual(app.reconcile(START, action="start-adopted", binding=binding, registration_id=ADOPT)["outcome"], "SUCCEEDED")
        self.assertEqual(self.docker.starts, [(CONTAINER,)])

    def test_stop_requires_separate_permission_and_the_approved_running_generation(self):
        app, binding = self.startable()
        options = {"registration_id": ADOPT, "running_receipt_id": ADOPT}
        with self.assertRaisesRegex(Denied, "APP_ADOPTED_STOP_UNSUPPORTED"):
            app.execute(START, "stop-adopted", binding, **options)
        self.assertEqual(self.docker.stops, [])

    def test_stop_only_permission_does_not_allow_start(self):
        app, binding, review = self.staged(OTHER, allow_stop=True)
        app.execute(ADOPT, "adopt", binding, review)
        self.assertEqual(app.execute(DETACH, "stop-adopted", binding, registration_id=ADOPT,
                                     running_receipt_id=ADOPT)["outcome"], "SUCCEEDED")
        with self.assertRaisesRegex(Denied, "APP_ADOPTED_START_UNSUPPORTED"):
            app.execute(START, "start-adopted", binding, registration_id=ADOPT)
        self.assertEqual(self.docker.stops, [CONTAINER])
        self.assertEqual(self.docker.starts, [])

    def test_stop_and_start_keep_the_same_container_and_reject_stale_stop_approvals(self):
        app, binding = self.startable(allow_stop=True)
        options = {"registration_id": ADOPT, "running_receipt_id": ADOPT}
        with patch.dict(self.docker.container["State"], StartedAt=LATER), self.assertRaisesRegex(Denied, "APP_ADOPTION_DRIFT"):
            app.execute(DETACH, "stop-adopted", binding, **options)
        self.assertEqual(self.docker.stops, [])
        self.docker.container["State"]["Health"] = {"Status": "unhealthy"}
        result = app.execute(DETACH, "stop-adopted", binding, **options)
        self.assertEqual(result["code"], "APP_ADOPTED_STOP_VERIFIED")
        self.assertEqual(app.reconcile(DETACH, action="stop-adopted", binding=binding, **options), result)
        self.assertEqual(self.docker.stops, [CONTAINER])
        self.assertEqual(app.execute(START, "start-adopted", binding, registration_id=ADOPT)["outcome"], "SUCCEEDED")
        with self.assertRaisesRegex(Denied, "APP_ADOPTED_RUN_CHANGED"):
            app.execute(NEXT, "stop-adopted", binding, **options)
        self.assertEqual(self.docker.stops, [CONTAINER])
        self.assertEqual(app.execute(DETACH, "stop-adopted", binding, **options), result)
        self.assertEqual(app.execute(NEXT, "stop-adopted", binding, registration_id=ADOPT,
                                     running_receipt_id=START)["outcome"], "SUCCEEDED")
        self.assertEqual(self.docker.stops, [CONTAINER, CONTAINER])

    def test_uncertain_stop_requires_a_confirmed_exit_and_never_repeats_the_command(self):
        app, binding = self.startable(allow_stop=True)
        options = {"registration_id": ADOPT, "running_receipt_id": ADOPT}
        self.docker.lose_stop_reply = True
        result = app.execute(START, "stop-adopted", binding, **options)
        self.assertEqual(result["outcome"], "UNKNOWN_OUTCOME")
        self.assertEqual(app.execute(START, "stop-adopted", binding, **options), result)
        with self.assertRaisesRegex(Denied, "APP_RECONCILIATION_REQUIRED"):
            app.execute(NEXT, "start-adopted", binding, registration_id=ADOPT)
        with self.assertRaisesRegex(Denied, "APP_RECONCILIATION_REQUIRED"):
            app.execute(DETACH, "detach", binding)
        for change in ({"FinishedAt": ZERO_TIME}, {"StartedAt": LATER}, {"Dead": True}):
            with self.subTest(change=change), patch.dict(self.docker.container["State"], change):
                self.assertEqual(app.reconcile(START, action="stop-adopted", binding=binding, **options), result)
        self.assertEqual(app.reconcile(START, action="stop-adopted", binding=binding, **options)["outcome"], "SUCCEEDED")
        self.assertEqual(self.docker.stops, [CONTAINER])

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
