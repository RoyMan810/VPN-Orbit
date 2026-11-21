from vpn_orbit.queue import JobQueue

from test_auth_api import Fixture, PASSWORD, SCOPE


RULES = [{"action": "allow", "direction": "in", "protocol": "tcp", "port": 2222, "cidr": "0.0.0.0/0"}]


class FirewallApiTests(Fixture):
    def setUp(self):
        super().setUp()
        JobQueue(self.store, clock=self.auth.clock).register_resource(SCOPE, "a" * 64, 1)
        self.route = f"/api/v1/resources/{SCOPE}/firewall-drafts"

    def test_owner_preview_reauthentication_approval_and_enqueue_are_separate(self):
        body = {"rules": RULES, "ssh_port": 2222}
        refused = self.client.post(self.route, json=body, headers={"Origin": self.headers()["Origin"]})
        self.assertEqual(refused.status_code, 403)
        draft = self.client.post(self.route, json=body, headers=self.headers())
        self.assertEqual(draft.status_code, 201, draft.text)
        plan = draft.headers["location"]
        headers = self.headers(**{"If-Match": draft.headers["etag"]})
        self.assertEqual(self.client.get(plan + "/firewall-preview").status_code, 428)
        preview = self.client.get(plan + "/firewall-preview", headers=headers)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["diff"]["added"], RULES)
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
        grant = self.client.post("/api/v1/auth/reauth", headers=self.headers(),
                                 json={"password": PASSWORD, "plan_hash": draft.json()["plan_hash"]})
        self.assertEqual(grant.status_code, 200, grant.text)
        approved = self.client.post(plan + "/firewall-approval", headers=headers,
                                    json={"reauth_id": grant.json()["id"]})
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["approval"], "OWNER_CONFIRMED")
        execution = {"approval_id": approved.json()["approval_id"]}
        queued = self.client.post(plan + "/firewall-execution-requests", headers=headers, json=execution)
        self.assertEqual(queued.status_code, 202, queued.text)
        retry = self.client.post(plan + "/firewall-execution-requests", headers=headers, json=execution)
        self.assertEqual(retry.json(), queued.json())
        with self.store.read() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
        self.store.verify_audit()

    def test_commands_wrong_types_missing_ssh_and_nonowner_cannot_create_plan(self):
        for body in ({"rules": RULES, "ssh_port": 2222, "command": "nft flush ruleset"},
                     {"rules": RULES, "ssh_port": "2222"}):
            result = self.client.post(self.route, json=body, headers=self.headers())
            self.assertEqual(result.status_code, 422, result.text)
        missing_ssh = self.client.post(self.route, json={"rules": RULES, "ssh_port": 22}, headers=self.headers())
        self.assertEqual(missing_ssh.status_code, 409)
        self.create_user(name="limited", role="Admin", grants=[
            {"permission": "vps:read", "resource_id": SCOPE},
            {"permission": "vps:firewall", "resource_id": SCOPE},
        ])
        other = self.other_client("limited")
        csrf = other.get("/api/v1/auth/session").json()["csrf_token"]
        result = other.post(self.route, json={"rules": RULES, "ssh_port": 2222},
                            headers={**self.headers(), "X-CSRF-Token": csrf})
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.json()["code"], "FIREWALL_OWNER_CONFIRMATION_REQUIRED")
