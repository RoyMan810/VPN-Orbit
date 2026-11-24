from vpn_orbit.queue import JobQueue
from .test_auth_api import Fixture, PASSWORD, SCOPE


class ApplicationApiTests(Fixture):
    def setUp(self):
        super().setUp()
        JobQueue(self.store, clock=self.auth.clock).register_resource(SCOPE, "a" * 64, 1)
        self.route = f"/api/v1/resources/{SCOPE}/application-drafts"
        self.body = {"installation_id": SCOPE, "spec_digest": "b" * 64, "action": "install"}

    def test_reauth_approval_and_replayed_enqueue_keep_one_audited_job(self):
        draft = self.client.post(self.route, json=self.body, headers=self.headers())
        self.assertEqual(draft.status_code, 201, draft.text)
        plan = draft.headers["location"]
        headers = self.headers(**{"If-Match": draft.headers["etag"]})
        grant = self.client.post("/api/v1/auth/reauth", headers=self.headers(),
                                 json={"password": PASSWORD, "plan_hash": draft.json()["plan_hash"]})
        approved = self.client.post(plan + "/application-approval", headers=headers,
                                    json={"reauth_id": grant.json()["id"]})
        self.assertEqual(approved.status_code, 200, approved.text)
        queued = self.client.post(plan + "/application-execution-requests", headers=headers,
                                  json={"approval_id": approved.json()["approval_id"]})
        self.assertEqual(queued.status_code, 202, queued.text)
        again = self.client.post(plan + "/application-execution-requests", headers=headers,
                                 json={"approval_id": approved.json()["approval_id"]})
        self.assertEqual(again.json(), queued.json())
        timeline = f"/api/v1/jobs/{queued.json()['id']}/application-timeline"
        response = self.client.get(timeline)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"items": []})
        self.create_user(name="operator", role="Admin", grants=[
            {"permission": "vps:apps", "resource_id": SCOPE},
            {"permission": "vps:read", "resource_id": SCOPE},
        ])
        response = self.other_client("operator").get(timeline)
        self.assertEqual(response.status_code, 403, response.text)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT action FROM jobs").fetchone()[0], "apps.lifecycle")
        self.store.verify_audit()

    def test_generic_commands_secrets_and_nonowner_are_refused(self):
        for extra in ({"command": "id"}, {"environment": {"TOKEN": "secret"}}, {"action": "shell"}):
            response = self.client.post(self.route, json={**self.body, **extra}, headers=self.headers())
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.client.post(self.route, json=self.body, headers={"Origin": self.headers()["Origin"]}).status_code, 403)
        self.create_user(name="limited", role="Admin", grants=[{"permission": "vps:apps", "resource_id": SCOPE}])
        other = self.other_client("limited")
        csrf = other.get("/api/v1/auth/session").json()["csrf_token"]
        response = other.post(self.route, json=self.body, headers={**self.headers(), "X-CSRF-Token": csrf})
        self.assertEqual(response.status_code, 403, response.text)
