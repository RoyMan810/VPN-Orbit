from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from vpn_orbit.api import create_app
from vpn_orbit.config import Settings
from vpn_orbit.database import identifier
from vpn_orbit.errors import Denied
from vpn_orbit.runtime.policy import Policy
from tests.runtime.fixtures import public_key
from .test_auth_api import Fixture, ORIGIN, SCOPE, OTHER


URL = "/api/v1/enrollment/preparation"
KEY = "prepare-test-key-123"
SECRET = "web-preparation-credential-canary"


class WebPreparationTests(Fixture):
    def setUp(self):
        super().setUp()
        self.policy = Policy([
            {"id": identity, "ip": ip, "port": 22, "allowed_cidrs": [ip + "/32"], "host_key": public_key(),
             "secret_ref": identifier() + ":v1", "policy_revision": 1, "dependencies": [], "capabilities": capabilities}
            for identity, ip, capabilities in ((SCOPE, "192.0.2.8", ["host.probe", "host.prepare"]),
                                                (OTHER, "192.0.2.9", ["host.probe"]))
        ])
        self.broker = Mock(call=Mock(side_effect=lambda operation, payload: {"job_id": payload["job_id"]}))
        self.client = self.enterContext(TestClient(create_app(
            Settings(self.store.path, ORIGIN), auth=self.auth, enrollment_catalog=self.policy.enrollment_catalog(ssh_endpoints=True),
            preparation_catalog=self.policy.enrollment_catalog(ssh_endpoints=True, preparation=True), preparation_broker=self.broker,
        ), base_url=ORIGIN))
        self.csrf = self.login()
        self.body = {"ip": "192.0.2.8", "username": "ubuntu", "fingerprint": self.policy.targets[SCOPE].fingerprint,
                     "password": SECRET}

    def post(self, *, key=KEY, **body):
        return self.client.post(URL, headers=self.headers(**{"Idempotency-Key": key}), json={**self.body, **body})

    def test_owner_enqueues_once_and_can_restore_status_without_credentials(self):
        self.assertEqual(self.client.get(URL).json(), {"available": True, "job": None})
        queued = self.post()
        self.assertEqual(queued.status_code, 202, queued.text)
        job = queued.json()
        self.assertEqual((job["status"], job["resource_id"], job["action"]), ("QUEUED", SCOPE, "host.prepare"))
        self.assertEqual(self.client.get(URL).json()["job"], job)
        self.assertEqual(self.client.get(queued.headers["location"]).json(), job)
        self.assertFalse(self.client.get(f"/api/v1/resources/{SCOPE}").json()["enabled"])
        self.assertEqual(self.post(password="different-retry-input").json(), job)
        self.assertEqual(self.post(username="root").json()["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(self.post(key="new-prepare-test-key").json()["code"], "VPS_PREPARATION_ALREADY_PENDING")
        self.broker.call.assert_called_once_with("prepare.credentials", {
            "job_id": job["id"], "actor_id": self.owner, "target": SCOPE, "scope_digest": self.policy.targets[SCOPE].scope_digest,
            "username": "ubuntu", "password": SECRET, "private_key": None,
        })
        for path in self.directory.glob("controller.sqlite3*"):
            self.assertNotIn(SECRET.encode(), path.read_bytes())

    def test_separates_owner_csrf_and_pin_checks_from_existing_enrollment(self):
        self.assertEqual(self.client.get("/api/v1/enrollment/candidates").json(), {"items": [OTHER]})
        self.assertEqual(self.client.post("/api/v1/enrollment/ssh", headers=self.headers(), json=self.body).status_code, 404)
        self.assertEqual(self.client.post("/api/v1/resources", headers=self.headers(),
                                         json={"resource_id": SCOPE, "fingerprint": self.body["fingerprint"]}).status_code, 404)
        with patch("vpn_orbit.api.verify_credentials", return_value={"platform": "DEBIAN_13", "ssh": "VERIFIED"}) as check:
            ready = self.client.post("/api/v1/enrollment/ssh/preflight", headers=self.headers(), json=self.body)
            self.assertEqual(ready.status_code, 200)
            check.assert_called_once()
            self.assertTrue(check.call_args.kwargs["preflight"])
        self.assertEqual(self.post(ip="192.0.2.9").status_code, 404)
        self.assertEqual(self.post(fingerprint="SHA256:" + "A" * 43).status_code, 412)
        self.assertEqual(self.post(key="bad").status_code, 400)
        self.assertEqual(self.client.post(URL, headers={"Origin": ORIGIN, "Idempotency-Key": KEY}, json=self.body).status_code, 403)
        self.create_user(role="Admin")
        other = self.enterContext(TestClient(self.client.app, base_url=ORIGIN))
        csrf = self.login(client=other, user="operator")
        self.assertEqual(other.post(URL, headers={**self.headers(), "X-CSRF-Token": csrf, "Idempotency-Key": KEY},
                                    json=self.body).status_code, 403)
        self.assertEqual(other.get(URL).status_code, 403)
        self.assertEqual(self.client.get(URL).json()["job"], None)
        self.broker.call.assert_not_called()

    def test_revalidates_session_after_deposit_and_lost_receipt_never_publishes_job(self):
        self.broker.call.side_effect = Denied("RPC_UNAVAILABLE")
        self.assertEqual(self.post().status_code, 503)
        self.assertIsNone(self.client.get(URL).json()["job"])

        def revoke(operation, payload):
            with self.store.write() as db:
                db.execute("DELETE FROM sessions")
            return {"job_id": payload["job_id"]}

        self.broker.call.side_effect = revoke
        self.assertEqual(self.post().status_code, 401)
        with self.store.read() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM resources").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM request_keys").fetchone())

    def test_concurrent_retries_publish_only_one_job(self):
        waiting = Barrier(2)

        def supply(operation, payload):
            waiting.wait(timeout=5)
            return {"job_id": payload["job_id"]}

        self.broker.call.side_effect = supply
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.post) for _ in range(2)]
            replies = [future.result(timeout=10) for future in futures]
        self.assertEqual([reply.status_code for reply in replies], [202, 202])
        self.assertEqual(replies[0].json(), replies[1].json())
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
