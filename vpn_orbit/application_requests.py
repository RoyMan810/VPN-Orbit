"""Owner-approved application operations in the existing durable queue."""

import json

from .auth import AuthService, Role, check_etag
from .change_drafts import _latest, _public, _stored
from .database import Store, identifier
from .errors import Denied
from .inventory import Inventory
from .runtime.protocol import ULID, application_payload, canonical, checksum, text


REQUESTED = "change_plan.application_requested"


def application_value(identity, revision, baseline):
    return {"version": 1, "id": identity, "revision": revision, "action": "apps.lifecycle", "state": "DRAFT",
            "baseline": baseline, "diff": {"operation": baseline["action"], "installation_id": baseline["installation_id"],
                                           **{key: baseline[key] for key in ("project", "observation_id", "registration_id")
                                              if key in baseline}},
            "risk": ("MANAGEMENT_REGISTRATION_ONLY" if baseline["action"] in ("adopt", "detach")
                     else "HOST_NETWORK_AND_APPLICATION_DATA"), "execution": "OWNER_APPROVAL_REQUIRED",
            "data_policy": "PRESERVE_VOLUMES_AND_NETWORKS"}


def owner(db, auth, token, csrf=None, mutating=False):
    actor = auth._session(db, token, csrf=csrf, mutating=mutating)
    if actor["role"] != Role.OWNER:
        raise Denied("APP_OWNER_REQUIRED", 403)
    return actor


def checked(db, auth, token, identity, tag, *, csrf=None, mutating=False):
    actor = owner(db, auth, token, csrf, mutating)
    row = _latest(db, identity)
    if row["action"] != "apps.lifecycle":
        raise Denied("RESOURCE_NOT_FOUND", 404)
    AuthService.require(db, actor, "vps:apps", row["resource_id"])
    draft = _stored(row)
    check_etag(tag, _public(draft, row["plan_hash"])[1])
    resource = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (row["resource_id"],)).fetchone()
    baseline = draft["baseline"]
    if (resource is None or resource["scope_digest"] != baseline["scope_digest"]
            or resource["revision"] != baseline["resource_revision"] or resource["policy_revision"] != baseline["policy_revision"]):
        raise Denied("STALE_BASELINE", 409)
    return actor, row, draft


def active_registration(db, baseline):
    return next((item for item in registered_applications(db, baseline["resource_id"])
                 if (item["installation_id"], item["spec_digest"]) == (baseline["installation_id"], baseline["spec_digest"])),
                None)


def reviewed_snapshot(db, inventory, actor, baseline):
    if baseline["action"] == "adopt":
        preview, _ = inventory.adoption_preview_in(db, actor, baseline["resource_id"], baseline["project"],
                                                    if_match=baseline["preview_tag"])
        if not preview["adoption_ready"] or preview["daemon_digest"] != baseline["review"]:
            raise Denied("APP_ADOPTION_EVIDENCE_INCOMPLETE", 409)
    if baseline["action"] == "start-adopted":
        registered = active_registration(db, baseline)
        if registered is None or registered["job_id"] != baseline["registration_id"]:
            raise Denied("APP_ADOPTION_STATE_INVALID", 409)


def application_intent(baseline, operation):
    payload = {"operation_id": operation, **{key: baseline[key] for key in ("installation_id", "spec_digest", "action")}}
    if baseline["action"] == "adopt":
        payload["review"] = baseline["review"]
    elif baseline["action"] == "start-adopted":
        payload["registration_id"] = baseline["registration_id"]
    return application_payload(payload)


def save(db, auth, token, csrf, resource, installation, binding, action, *, project=None, preview_tag=None):
    actor = owner(db, auth, token, csrf, True)
    text(resource, ULID)
    AuthService.require(db, actor, "vps:apps", resource)
    row = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (resource,)).fetchone()
    if row is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    identity = identifier()
    baseline = {"installation_id": installation, "spec_digest": binding, "action": action,
                "resource_id": resource, "resource_revision": row["revision"],
                "scope_digest": row["scope_digest"], "policy_revision": row["policy_revision"]}
    if action == "adopt":
        if project is None or preview_tag is None:
            raise Denied("IF_MATCH_REQUIRED", 428)
        preview, _ = Inventory(auth.store, clock=auth.clock).adoption_preview_in(db, actor, resource, project,
                                                                                if_match=preview_tag)
        if not preview["adoption_ready"]:
            raise Denied("APP_ADOPTION_EVIDENCE_INCOMPLETE", 409)
        baseline.update(project=project, preview_tag=preview_tag, observation_id=preview["observation_id"],
                        preview_digest=preview["preview_digest"], review=preview["daemon_digest"])
    elif project is not None:
        raise Denied("APP_ACTION_INVALID", 422)
    if action == "start-adopted":
        registered = active_registration(db, baseline)
        if registered is None:
            raise Denied("APP_ADOPTION_STATE_INVALID", 409)
        baseline.update(project=registered["project"], registration_id=registered["job_id"])
    application_intent(baseline, resource)
    value = application_value(identity, 1, baseline)
    binding = checksum(value)
    db.execute("""INSERT INTO change_plan_drafts VALUES(?,1,?,?,'apps.lifecycle',?,?,?)""",
               (identity, actor["id"], resource, canonical(baseline).decode(), binding, int(auth.clock())))
    Store.event(db, at=int(auth.clock()), actor=actor["id"], kind="change_plan.draft_saved", target=resource,
                outcome="SUCCEEDED", correlation=identity, details={"revision": 1, "plan_hash": binding})
    return _public(value, binding)


def approve(db, auth, token, csrf, identity, tag, reauth):
    actor, row, draft = checked(db, auth, token, identity, tag, csrf=csrf, mutating=True)
    reviewed_snapshot(db, Inventory(auth.store, clock=auth.clock), actor, draft["baseline"])
    auth.consume_reauthentication(db, token, reauth, row["plan_hash"])
    previous = db.execute("""SELECT 1 FROM audit WHERE correlation_id=? AND event='change_plan.application_approved'""",
                          (identity,)).fetchone()
    if previous:
        raise Denied("CHANGE_PLAN_ALREADY_APPROVED", 409)
    approval = identifier()
    Store.event(db, at=int(auth.clock()), actor=actor["id"], target=row["resource_id"], correlation=identity,
                kind="change_plan.application_approved", outcome="SUCCEEDED",
                details={"approval_id": approval, "plan_hash": row["plan_hash"]})
    return {"approval_id": approval, "plan_hash": row["plan_hash"]}


def enqueue(db, queue, auth, token, csrf, identity, tag, approval_id):
    actor, row, draft = checked(db, auth, token, identity, tag, csrf=csrf, mutating=True)
    details = {"approval_id": approval_id, "plan_hash": row["plan_hash"]}
    approval = db.execute("""SELECT * FROM audit WHERE correlation_id=? AND actor_id=?
        AND target_id=? AND event='change_plan.application_approved' AND details=?""",
                          (identity, actor["id"], row["resource_id"], canonical(details).decode())).fetchone()
    if approval is None:
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    existing = db.execute("SELECT * FROM jobs WHERE id=?", (approval["id"],)).fetchone()
    if existing:
        return queue._public(existing)
    if not 0 <= int(auth.clock()) - approval["at"] <= 300:
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    if db.execute("SELECT 1 FROM job_incidents").fetchone():
        raise Denied("OPEN_INCIDENT", 409)
    baseline = draft["baseline"]
    reviewed_snapshot(db, Inventory(auth.store, clock=auth.clock), actor, baseline)
    details = {**details, "operation_id": approval["id"], "actor_id": actor["id"], "revision": row["revision"],
               "scope_digest": baseline["scope_digest"], "application": application_intent(baseline, approval["id"])}
    Store.event(db, at=int(auth.clock()), actor=actor["id"], target=row["resource_id"], correlation=identity,
                kind=REQUESTED, outcome="QUEUED", details=details)
    queue._enqueue_mutation(db, approval["id"], actor["id"], row["resource_id"], baseline["scope_digest"],
                            baseline["policy_revision"], row["plan_hash"], "apps.lifecycle")
    return queue._public(db.execute("SELECT * FROM jobs WHERE id=?", (approval["id"],)).fetchone())


class ApplicationOperations:
    def __init__(self, queue, gate, broker, refs):
        self.queue, self.gate, self.broker, self.refs = queue, gate, broker, refs

    def prepare(self, job):
        def validate(db):
            row = db.execute("""SELECT * FROM audit WHERE event=? AND json_extract(details,'$.operation_id')=?""",
                             (REQUESTED, job["id"])).fetchone()
            if row is None:
                raise Denied("APP_REQUEST_NOT_FOUND")
            details = json.loads(row["details"])
            draft = _latest(db, row["correlation_id"])
            if (row["actor_id"] != job["actor_id"] or row["target_id"] != job["resource_id"]
                    or draft["plan_hash"] != job["payload_hash"] or draft["revision"] != details["revision"]
                    or details["scope_digest"] != job["scope_digest"]):
                raise Denied("APP_REQUEST_DRIFT")
            value = _stored(draft)
            baseline = value["baseline"]
            actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (job["actor_id"],)).fetchone()
            if actor is None or actor["role"] != Role.OWNER:
                raise Denied("ACTOR_REVOKED")
            AuthService.require(db, actor, "vps:apps", job["resource_id"])
            approval = db.execute("SELECT * FROM audit WHERE id=?", (job["id"],)).fetchone()
            expected = {"approval_id": details["approval_id"], "plan_hash": job["payload_hash"]}
            if (approval is None or approval["event"] != "change_plan.application_approved"
                    or approval["actor_id"] != job["actor_id"] or approval["correlation_id"] != row["correlation_id"]
                    or json.loads(approval["details"]) != expected
                    or not 0 <= int(self.queue.clock()) - approval["at"] <= 300):
                raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED")
            reviewed_snapshot(db, Inventory(self.queue.store, clock=self.queue.clock), actor, baseline)
            payload = application_intent(baseline, job["id"])
            if payload != details["application"]:
                raise Denied("APP_REQUEST_DRIFT")
            return row, payload, details

        with self.queue.store.read() as db:
            row, payload, details = validate(db)
        ref = self.refs.get(job["resource_id"])
        if ref is None:
            raise Denied("CAPABILITY_DISABLED")
        anchor = self.gate.call("time.anchor", {"plan_id": row["correlation_id"], "revision": details["revision"]})
        binding = {"job_id": job["id"], "plan_id": row["correlation_id"], "revision": details["revision"],
                   "plan_digest": job["payload_hash"], "approval_id": details["approval_id"], "actor_id": job["actor_id"],
                   "target": job["resource_id"], "capability": "apps.lifecycle", "scope_digest": job["scope_digest"],
                   "time_anchor": anchor, "application": payload}
        return binding, ref, validate


def registrations(db, auth, token, resource):
    actor = owner(db, auth, token)
    AuthService.require(db, actor, "vps:apps", resource)
    if not db.execute("SELECT 1 FROM resources WHERE id=?", (resource,)).fetchone():
        raise Denied("RESOURCE_NOT_FOUND", 404)
    return {"items": registered_applications(db, resource)}


def registered_applications(db, resource):
    rows = db.execute("""
        WITH completed AS (
            SELECT json_extract(d.baseline, '$.installation_id') AS installation_id,
                   json_extract(d.baseline, '$.project') AS project,
                   json_extract(d.baseline, '$.action') AS action,
                   json_extract(d.baseline, '$.spec_digest') AS spec_digest, j.id AS job_id,
                   row_number() OVER (
                       PARTITION BY json_extract(d.baseline, '$.installation_id') ORDER BY completion.seq DESC
                   ) AS newest
            FROM audit req
            JOIN jobs j ON j.id=json_extract(req.details,'$.operation_id') AND j.resource_id=req.target_id
            JOIN change_plan_drafts d ON d.id=req.correlation_id AND d.revision=json_extract(req.details,'$.revision')
            JOIN audit completion ON completion.correlation_id=j.id AND completion.target_id=j.resource_id
                AND ((completion.event='job.finished' AND completion.outcome='SUCCEEDED')
                     OR (completion.event='application.reconciled' AND completion.outcome='RECONCILED_SUCCEEDED'))
            WHERE req.event=? AND req.target_id=? AND j.action='apps.lifecycle'
                AND json_extract(d.baseline,'$.action') IN ('adopt','detach')
        )
        SELECT installation_id, project, spec_digest, job_id FROM completed
        WHERE newest=1 AND action='adopt' ORDER BY project, installation_id
        """, (REQUESTED, resource)).fetchall()
    return [dict(row) for row in rows]


def timeline(db, queue, auth, token, identity):
    actor = owner(db, auth, token)
    job = queue._read_job(db, auth, token, identity)
    if job["action"] != "apps.lifecycle":
        raise Denied("RESOURCE_NOT_FOUND", 404)
    AuthService.require(db, actor, "vps:apps", job["resource_id"])
    items = db.execute("""SELECT seq,event,outcome,details FROM audit WHERE correlation_id=?
        AND event IN ('application.reconciliation_requested','application.reconciled') ORDER BY seq""",
                       (identity,)).fetchall()
    return {"items": [{"seq": row["seq"], "event": row["event"], "outcome": row["outcome"],
                       **{key: value for key, value in json.loads(row["details"]).items()
                          if key in ("attempt", "code")}} for row in items]}


def reconcile(db, queue, auth, token, csrf, identity, attempt):
    actor = owner(db, auth, token, csrf, True)
    if type(attempt) is not int or not 1 <= attempt <= 3:
        raise Denied("APP_RECONCILIATION_LIMIT", 409)
    job = db.execute("SELECT * FROM jobs WHERE id=? AND action='apps.lifecycle'", (identity,)).fetchone()
    if job is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    AuthService.require(db, actor, "vps:apps", job["resource_id"])
    previous = db.execute("""SELECT * FROM audit WHERE correlation_id=? AND event='application.reconciliation_requested'
                          AND json_extract(details,'$.attempt')=?""", (identity, attempt)).fetchone()
    if previous:
        return {"operation_id": identity, "attempt": attempt, "status": "RECONCILIATION_REQUESTED"}
    if job["status"] != "UNKNOWN_OUTCOME":
        raise Denied("APP_RECONCILIATION_NOT_REQUIRED", 409)
    if attempt > 1 and not db.execute("""SELECT 1 FROM audit WHERE correlation_id=?
        AND event='application.reconciled' AND outcome='QUARANTINED'
        AND json_extract(details,'$.attempt')=?""", (identity, attempt - 1)).fetchone():
        raise Denied("APP_RECONCILIATION_PENDING", 409)
    Store.event(db, at=int(auth.clock()), actor=actor["id"], target=job["resource_id"], correlation=identity,
                kind="application.reconciliation_requested", outcome="QUEUED", details={"attempt": attempt})
    return {"operation_id": identity, "attempt": attempt, "status": "RECONCILIATION_REQUESTED"}


def reconcile_pending(operations):
    store, queue = operations.queue.store, operations.queue
    with store.read() as db:
        row = db.execute("""SELECT r.* FROM audit r WHERE r.event='application.reconciliation_requested'
            AND NOT EXISTS (SELECT 1 FROM audit s WHERE s.event='application.reconciled'
                AND s.correlation_id=r.correlation_id
                AND json_extract(s.details,'$.request_seq')=r.seq) ORDER BY r.seq LIMIT 1""").fetchone()
    if row is None:
        return False
    outcome, code = "QUARANTINED", "APP_RECONCILIATION_UNVERIFIED"
    try:
        with store.read() as db:
            actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0 AND role='Owner'", (row["actor_id"],)).fetchone()
            if actor is None:
                raise Denied("ACTOR_REVOKED")
            AuthService.require(db, actor, "vps:apps", row["target_id"])
        remote = operations.broker.call("apps.reconcile", {"job_id": row["correlation_id"]})
        if remote.get("outcome") not in ("SUCCEEDED", "RECONCILED_SUCCEEDED"):
            raise Denied("APP_RECONCILIATION_UNVERIFIED")
        outcome, code = "RECONCILED_SUCCEEDED", "APP_READBACK_VERIFIED"
    except Denied as error:
        code = error.code
    with store.write(kind="control") as db:
        if outcome == "RECONCILED_SUCCEEDED":
            db.execute("DELETE FROM job_incidents WHERE job_id=?", (row["correlation_id"],))
        Store.event(db, at=int(queue.clock()), actor=row["actor_id"], target=row["target_id"],
                    correlation=row["correlation_id"], kind="application.reconciled", outcome=outcome,
                    details={**json.loads(row["details"]), "request_seq": row["seq"], "code": code})
    return True
