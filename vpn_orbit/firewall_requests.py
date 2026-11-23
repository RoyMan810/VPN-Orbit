"""Owner-confirmed, typed firewall change plans with host-local rollback.

The flow is deliberately the same shape as the isolated Docker restart flow:
preview/diff -> Owner re-authentication -> durable execution request -> typed
helper -> fresh SSH verification -> confirm or rollback.  An UNKNOWN_OUTCOME
opens an incident and blocks every further mutation until it is reconciled.
"""

import json
import re
import secrets

from .auth import AuthService, Role, check_etag
from .change_drafts import _latest, _public, _stored
from .database import Store, identifier
from .errors import Denied
from .runtime.protocol import ULID, canonical, checksum, firewall_payload, firewall_rules, integer, text

REQUESTED = "change_plan.firewall_requested"
EVENTS = (REQUESTED, "change_plan.firewall_prepared", "change_plan.firewall_finished")
RECONCILIATION_EVENTS = ("change_plan.firewall_reconciliation_requested", "change_plan.firewall_reconciled")
RESOLVED = ("RECONCILED_SUCCEEDED", "RECONCILED_FAILED")
MAX_AGE = 300
SUCCESS_CODES = ("FIREWALL_CONFIRMED", "FIREWALL_ALREADY_CONFIRMED")


def _rule_key(rule):
    return canonical(rule).decode()


def firewall_diff(previous, rules):
    before = {_rule_key(rule) for rule in previous}
    after = {_rule_key(rule) for rule in rules}
    return {"operation": "FIREWALL_APPLY",
            "added": [rule for rule in rules if _rule_key(rule) not in before],
            "removed": [rule for rule in previous if _rule_key(rule) not in after],
            "order_changed": [rule for rule in previous if _rule_key(rule) in after]
                             != [rule for rule in rules if _rule_key(rule) in before],
            "unchanged": len(rules) - sum(1 for rule in rules if _rule_key(rule) not in before)}


def firewall_value(draft_id, revision, baseline):
    return {"version": 1, "id": draft_id, "revision": revision, "action": "firewall.apply", "state": "DRAFT",
            "baseline": baseline, "diff": firewall_diff(baseline["previous_rules"], baseline["rules"]),
            "risk": "SSH_ACCESS_INTERRUPTION", "preflight": "OWNER_CONFIRMATION_WITH_ROLLBACK",
            "backup_gate": "NOT_REQUIRED", "execution": "BLOCKED"}


def _schema(db):
    if not db.in_transaction or db.execute("PRAGMA user_version").fetchone()[0] != 6:
        raise Denied("DATABASE_SCHEMA_UNSUPPORTED", 503)


def _require(db, actor, resource_id):
    try:
        AuthService.require(db, actor, "vps:read", resource_id)
    except Denied:
        raise Denied("RESOURCE_NOT_FOUND", 404) from None
    AuthService.require(db, actor, "vps:firewall", resource_id)


def _checked(db, auth, token, draft_id, if_match, *, csrf=None, mutating=False):
    _schema(db)
    actor = auth._session(db, token, csrf=csrf, mutating=mutating)
    row = _latest(db, draft_id)
    if row["action"] != "firewall.apply":
        raise Denied("RESOURCE_NOT_FOUND", 404)
    _require(db, actor, row["resource_id"])
    draft = _stored(row)
    check_etag(if_match, _public(draft, row["plan_hash"])[1])
    return row, draft, actor


def _owner(actor):
    if actor["role"] != Role.OWNER:
        raise Denied("FIREWALL_OWNER_CONFIRMATION_REQUIRED", 403)


def _last_confirmed_rules(db, resource_id):
    row = db.execute("""SELECT r.details FROM audit r WHERE r.target_id=?
        AND ((r.event='change_plan.firewall_finished' AND r.outcome='SUCCEEDED')
          OR (r.event='change_plan.firewall_reconciled' AND r.outcome='RECONCILED_SUCCEEDED'))
        ORDER BY r.seq DESC LIMIT 1""", (resource_id,)).fetchone()
    if row is None:
        return []
    operation = json.loads(row["details"])["operation_id"]
    event = db.execute("""SELECT details FROM audit WHERE target_id=? AND event=?
                          AND json_extract(details,'$.operation_id')=? ORDER BY seq DESC LIMIT 1""",
                       (resource_id, REQUESTED, operation)).fetchone()
    if event is None:
        raise Denied("FIREWALL_HISTORY_INVALID", 503)
    return firewall_rules(json.loads(event["details"])["rules"])


def _baseline_check(db, row, draft):
    baseline = draft["baseline"]
    resource = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (row["resource_id"],)).fetchone()
    if (resource is None or resource["scope_digest"] != baseline["scope_digest"]
            or resource["revision"] != baseline["resource_revision"]
            or resource["policy_revision"] != baseline["policy_revision"]
            or _last_confirmed_rules(db, row["resource_id"]) != baseline["previous_rules"]):
        raise Denied("STALE_BASELINE", 409)
    return resource


def save_firewall_draft(db, auth, token, csrf, resource_id, rules, ssh_port, *, draft_id=None, if_match=None):
    """Create or revise a typed firewall draft inside BEGIN IMMEDIATE."""
    _schema(db)
    actor = auth._session(db, token, csrf=csrf, mutating=True)
    if not isinstance(resource_id, str) or re.fullmatch(ULID, resource_id) is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    _require(db, actor, resource_id)
    _owner(actor)
    integer(ssh_port, 1, 65535)
    rules = firewall_rules(rules)
    if not any(rule["action"] == "allow" and rule["direction"] == "in" and rule["protocol"] == "tcp"
               and rule["port"] == ssh_port for rule in rules):
        raise Denied("FIREWALL_SSH_RULE_REQUIRED", 409)
    resource = db.execute("SELECT * FROM resources WHERE id=? AND enabled=1", (resource_id,)).fetchone()
    if resource is None:
        raise Denied("RESOURCE_NOT_FOUND", 404)
    revision = 1
    if draft_id is not None:
        row = _latest(db, draft_id)
        if row["resource_id"] != resource_id or row["action"] != "firewall.apply":
            raise Denied("RESOURCE_NOT_FOUND", 404)
        check_etag(if_match, _public(_stored(row), row["plan_hash"])[1])
        revision = row["revision"] + 1
    else:
        draft_id = identifier()
    baseline = {"resource_id": resource_id, "rules": rules, "previous_rules": _last_confirmed_rules(db, resource_id),
                "ssh_port": ssh_port, "scope_digest": resource["scope_digest"], "resource_revision": resource["revision"],
                "policy_revision": resource["policy_revision"], "probe_nonce": secrets.token_hex(32)}
    value = firewall_value(draft_id, revision, baseline)
    plan_hash = checksum(value)
    now = int(auth.clock())
    db.execute("""INSERT INTO change_plan_drafts(id,revision,actor_id,resource_id,action,baseline,plan_hash,created_at)
                  VALUES(?,?,?,?,?,?,?,?)""",
               (draft_id, revision, actor["id"], resource_id, "firewall.apply", canonical(baseline).decode(), plan_hash, now))
    Store.event(db, at=now, actor=actor["id"], kind="change_plan.draft_saved", target=resource_id,
                outcome="SUCCEEDED", correlation=draft_id, details={"revision": revision, "plan_hash": plan_hash})
    return _public(value, plan_hash)


def check_firewall_draft(db, auth, token, draft_id, *, if_match):
    row, draft, _ = _checked(db, auth, token, draft_id, if_match)
    _baseline_check(db, row, draft)
    baseline = draft["baseline"]
    return {"draft_id": row["id"], "revision": row["revision"], "plan_hash": row["plan_hash"],
            "diff": draft["diff"], "rules": baseline["rules"], "ssh_port": baseline["ssh_port"],
            "checked_at": int(auth.clock()), "baseline_check": "MATCHED", "execution": "BLOCKED",
            "rollback": "HOST_LOCAL_TIMER"}


def _approval_details(row, draft):
    baseline = draft["baseline"]
    return {"revision": row["revision"], "plan_hash": row["plan_hash"], "rules_digest": checksum(baseline["rules"]),
            "ssh_port": baseline["ssh_port"], "confirmation": "OWNER_CONFIRMED_SSH_ACCESS"}


def record_firewall_approval(db, auth, token, csrf, draft_id, *, if_match, reauth_id):
    row, draft, actor = _checked(db, auth, token, draft_id, if_match, csrf=csrf, mutating=True)
    _owner(actor)
    _baseline_check(db, row, draft)
    if db.execute("""SELECT 1 FROM audit WHERE target_id=? AND correlation_id=?
                      AND event='change_plan.approval_recorded' AND outcome='SUCCEEDED'
                      AND json_extract(details,'$.plan_hash')=? LIMIT 1""",
                  (row["resource_id"], draft_id, row["plan_hash"])).fetchone():
        raise Denied("CHANGE_PLAN_ALREADY_APPROVED", 409)
    now = int(auth.clock())
    auth.consume_reauthentication(db, token, reauth_id, row["plan_hash"])
    approval_id = identifier()
    details = {**_approval_details(row, draft), "approval_id": approval_id}
    seq = Store.event(db, at=now, actor=actor["id"], kind="change_plan.approval_recorded", target=row["resource_id"],
                      outcome="SUCCEEDED", correlation=draft_id, details=details)
    return {"approval": "OWNER_CONFIRMED", "approval_id": approval_id, "audit_seq": seq,
            "revision": row["revision"], "plan_hash": row["plan_hash"], "checked_at": now}


def _approved(db, row, draft, actor, approval_id, now):
    details = {**_approval_details(row, draft), "approval_id": approval_id}
    approval = db.execute("""SELECT seq,id,at FROM audit WHERE target_id=? AND correlation_id=? AND actor_id=?
        AND event='change_plan.approval_recorded' AND outcome='SUCCEEDED' AND details=? ORDER BY seq DESC LIMIT 1""",
                          (row["resource_id"], row["id"], actor["id"], canonical(details).decode())).fetchone()
    if approval is None or not 0 <= now - approval["at"] <= MAX_AGE:
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    return approval


def request_firewall_apply(db, queue, auth, token, csrf, draft_id, *, if_match, approval_id):
    row, draft, actor = _checked(db, auth, token, draft_id, if_match, csrf=csrf, mutating=True)
    _owner(actor)
    previous = db.execute("""SELECT details FROM audit WHERE target_id=? AND correlation_id=? AND event=?
                            AND json_extract(details,'$.approval_id')=? ORDER BY seq DESC LIMIT 1""",
                          (row["resource_id"], draft_id, REQUESTED, approval_id)).fetchone()
    if previous is not None:
        details = json.loads(previous["details"])
        if details["actor_id"] != actor["id"] or details["revision"] != row["revision"] or details["plan_hash"] != row["plan_hash"]:
            raise Denied("FIREWALL_REQUEST_CONFLICT", 409)
        latest = db.execute("""SELECT outcome FROM audit WHERE target_id=? AND correlation_id=?
            AND event IN (?,?,?) AND json_extract(details,'$.operation_id')=? ORDER BY seq DESC LIMIT 1""",
                            (row["resource_id"], draft_id, *EVENTS, details["operation_id"])).fetchone()
        return {"id": details["operation_id"], "revision": row["revision"], "status": latest["outcome"]}
    now = int(auth.clock())
    approval = _approved(db, row, draft, actor, approval_id, now)
    _baseline_check(db, row, draft)
    baseline = draft["baseline"]
    operation = {"operation_id": approval["id"], "actor_id": actor["id"], "revision": row["revision"],
                 "plan_hash": row["plan_hash"], "approval_id": approval_id, "approval_seq": approval["seq"],
                 "scope_digest": baseline["scope_digest"], "rules": baseline["rules"],
                 "previous_rules_digest": checksum(baseline["previous_rules"]),
                 "rules_digest": checksum(baseline["rules"]), "ssh_port": baseline["ssh_port"]}
    Store.event(db, at=now, actor=actor["id"], target=row["resource_id"], correlation=draft_id,
                kind=REQUESTED, outcome="QUEUED", details=operation)
    queue.enqueue_firewall(db, operation["operation_id"], actor["id"], row["resource_id"], baseline["scope_digest"],
                           baseline["policy_revision"], row["plan_hash"])
    return {"id": operation["operation_id"], "revision": row["revision"], "status": "QUEUED"}


def validate_firewall_request(db, event, now):
    """Recheck the Owner approval and immutable baseline before any dispatch."""
    operation = json.loads(event["details"])
    if db.execute("""SELECT 1 FROM audit u WHERE u.event=? AND u.outcome='UNKNOWN_OUTCOME'
        AND NOT EXISTS (SELECT 1 FROM audit r WHERE r.event=? AND r.outcome IN (?,?)
            AND r.target_id=u.target_id AND r.correlation_id=u.correlation_id
            AND json_extract(r.details,'$.operation_id')=json_extract(u.details,'$.operation_id')) LIMIT 1""",
                  (EVENTS[2], RECONCILIATION_EVENTS[1], *RESOLVED)).fetchone():
        raise Denied("FIREWALL_INCIDENT_OPEN", 409)
    row = _latest(db, event["correlation_id"])
    draft = _stored(row)
    if (row["revision"] != operation["revision"] or row["plan_hash"] != operation["plan_hash"]
            or row["resource_id"] != event["target_id"] or event["actor_id"] != operation["actor_id"]):
        raise Denied("STALE_REVISION", 409)
    actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (event["actor_id"],)).fetchone()
    if actor is None:
        raise Denied("ACTOR_REVOKED")
    _owner(actor)
    _require(db, actor, row["resource_id"])
    approval = db.execute("SELECT * FROM audit WHERE seq=?", (operation["approval_seq"],)).fetchone()
    if (approval is None or approval["id"] != operation["operation_id"] or approval["actor_id"] != actor["id"]
            or approval["target_id"] != row["resource_id"] or approval["correlation_id"] != row["id"]
            or approval["event"] != "change_plan.approval_recorded" or approval["outcome"] != "SUCCEEDED"
            or not 0 <= now - approval["at"] <= MAX_AGE):
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    expected = {**_approval_details(row, draft), "approval_id": operation["approval_id"]}
    if (json.loads(approval["details"]) != expected or operation["rules"] != draft["baseline"]["rules"]
            or operation["rules_digest"] != checksum(operation["rules"])
            or operation["ssh_port"] != draft["baseline"]["ssh_port"]):
        raise Denied("CHANGE_PLAN_APPROVAL_REQUIRED", 409)
    resource = _baseline_check(db, row, draft)
    if operation["scope_digest"] != resource["scope_digest"]:
        raise Denied("STALE_BASELINE", 409)
    if operation["previous_rules_digest"] != checksum(draft["baseline"]["previous_rules"]):
        raise Denied("STALE_BASELINE", 409)
    firewall_payload({key: operation[key] for key in ("operation_id", "rules_digest", "previous_rules_digest", "rules", "ssh_port")})
    return operation


def request_firewall_reconciliation(db, auth, token, csrf, draft_id, operation_id, attempt):
    _schema(db)
    actor = auth._session(db, token, csrf=csrf, mutating=True)
    target = _latest(db, draft_id)["resource_id"]
    _require(db, actor, target)
    _owner(actor)
    binding = (target, draft_id, operation_id)
    incident = db.execute("""SELECT details FROM audit WHERE target_id=? AND correlation_id=?
        AND json_extract(details,'$.operation_id')=? AND event=? AND outcome='UNKNOWN_OUTCOME'""",
                          (*binding, EVENTS[2])).fetchone()
    if incident is None:
        raise Denied("FIREWALL_INCIDENT_NOT_FOUND", 404)
    rows = db.execute("""SELECT outcome, json_extract(details,'$.attempt') AS attempt FROM audit
        WHERE target_id=? AND correlation_id=? AND json_extract(details,'$.operation_id')=?
        AND event IN (?,?) ORDER BY seq DESC""", (*binding, *RECONCILIATION_EVENTS)).fetchall()
    previous = next((row for row in rows if row["attempt"] == attempt), None)
    if previous is not None:
        return {"attempt": attempt, "status": previous["outcome"]}
    if not 1 <= attempt <= 3 or attempt != (rows[0]["attempt"] + 1 if rows else 1) or (rows and rows[0]["outcome"] != "QUARANTINED"):
        raise Denied("FIREWALL_RECONCILIATION_UNAVAILABLE", 409)
    Store.event(db, at=int(auth.clock()), actor=actor["id"], target=target, correlation=draft_id,
                kind=RECONCILIATION_EVENTS[0], outcome="RECONCILIATION_REQUESTED",
                details={"operation_id": operation_id, "revision": json.loads(incident["details"])["revision"], "attempt": attempt})
    return {"attempt": attempt, "status": "RECONCILIATION_REQUESTED"}


def firewall_timeline(db, auth, token, draft_id):
    _schema(db)
    actor = auth._session(db, token)
    row = _latest(db, draft_id)
    _require(db, actor, row["resource_id"])
    events = db.execute("""SELECT seq,at,event,outcome,details FROM audit WHERE target_id=? AND correlation_id=?
                          AND event IN (?,?,?,?,?) ORDER BY seq DESC LIMIT 100""",
                        (row["resource_id"], draft_id, *EVENTS, *RECONCILIATION_EVENTS)).fetchall()
    return {"items": [{"seq": event["seq"], "at": event["at"], "event": event["event"],
                       "status": event["outcome"], "operation_id": (details := json.loads(event["details"]))["operation_id"],
                       "revision": details["revision"], "reason": details.get("reason"), "attempt": details.get("attempt")}
                      for event in reversed(events)]}


class FirewallOperations:
    def __init__(self, queue, gate, broker, secret_refs):
        self.queue, self.store, self.clock = queue, queue.store, queue.clock
        self.gate, self.broker, self.secret_refs = gate, broker, secret_refs


    @staticmethod
    def pending_reconciliation(db):
        return db.execute("""SELECT a.* FROM audit a WHERE a.event=? AND NOT EXISTS
            (SELECT 1 FROM audit r WHERE r.event=? AND r.correlation_id=a.correlation_id
             AND json_extract(r.details,'$.request_seq')=a.seq) ORDER BY a.seq LIMIT 1""", RECONCILIATION_EVENTS).fetchone()

    def reconcile_one(self, row):
        from .runtime.protocol import SHA256, fields

        details = json.loads(row["details"])
        job_id = details["operation_id"]
        outcome, digest, reason = "QUARANTINED", None, "FIREWALL_RECONCILIATION_PENDING"
        try:
            saved = self.broker.call("receipt.get", {"job_id": job_id})
            fields(saved, ("outcome", "code", "observation", "authority_receipt"))
            receipt = self.gate.call("attempt.status", {"job_id": job_id})
            fields(receipt, ("job_id", "nonce", "state", "result_digest", "result_code"))
            result = {key: saved[key] for key in ("outcome", "code", "observation")}
            text(receipt["nonce"], SHA256)
            original = saved["authority_receipt"]
            reconciled = receipt["state"] in RESOLVED and saved["outcome"] == "UNKNOWN_OUTCOME"
            if (({**receipt, "state": original["state"]} if reconciled else receipt) != original or receipt["job_id"] != job_id
                    or original["state"] != saved["outcome"] or receipt["result_code"] != saved["code"]
                    or receipt["result_digest"] != checksum(result) or saved["observation"] is not None):
                raise Denied("BROKER_RECEIPT_INVALID")
            digest = receipt["result_digest"]
            policy_ref = self.secret_refs.get(row["target_id"])
            if policy_ref is None:
                raise Denied("CAPABILITY_DISABLED")
            remote = self.broker.call("firewall.status", {"policy_ref": policy_ref, "target": row["target_id"],
                                                         "operation_id": job_id})
            with self.store.read() as db:
                request = self.queue.firewall_request(db, job_id)
                expected = json.loads(request["details"])["rules_digest"] if request else None
            if not isinstance(remote, dict) or remote.get("outcome") != "SUCCEEDED" or remote.get("rules_digest") != expected:
                raise Denied("FIREWALL_RECONCILIATION_UNVERIFIED")
            state = remote["state"]
            if state == "CONFIRMED":
                outcome, reason = "RECONCILED_SUCCEEDED", "FIREWALL_REMOTE_CONFIRMED"
            elif state == "ROLLED_BACK":
                outcome, reason = "RECONCILED_FAILED", "FIREWALL_REMOTE_" + state
        except Denied as error:
            reason = error.code
        with self.store.write(kind="control") as db:
            try:
                actor = db.execute("SELECT * FROM users WHERE id=? AND disabled=0", (row["actor_id"],)).fetchone()
                if actor is None:
                    raise Denied("ACTOR_REVOKED")
                _owner(actor)
                _require(db, actor, row["target_id"])
            except Denied as error:
                outcome, reason = "QUARANTINED", error.code
            if outcome in RESOLVED:
                db.execute("DELETE FROM job_incidents WHERE job_id=?", (job_id,))
            Store.event(db, at=int(self.clock()), actor=row["actor_id"], target=row["target_id"],
                        correlation=row["correlation_id"], kind=RECONCILIATION_EVENTS[1], outcome=outcome,
                        details={**details, "request_seq": row["seq"], "reason": reason, "receipt_digest": digest})
        return True

    def reconcile_pending(self):
        with self.store.write(kind="dispatch") as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 6:
                return False
            row = self.pending_reconciliation(db)
        return self.reconcile_one(row) if row is not None else False

    def prepare(self, job):
        with self.store.read() as db:
            _schema(db)
            row = self.queue.firewall_request(db, job["id"])
            if row is None:
                raise Denied("FIREWALL_REQUEST_NOT_FOUND")
            operation = validate_firewall_request(db, row, int(self.clock()))
        secret_ref = self.secret_refs.get(job["resource_id"])
        if secret_ref is None:
            raise Denied("CAPABILITY_DISABLED")
        if (job["resource_id"] != row["target_id"] or job["actor_id"] != row["actor_id"]
                or job["payload_hash"] != operation["plan_hash"] or job["scope_digest"] != operation["scope_digest"]):
            raise Denied("STALE_SCOPE")
        payload = firewall_payload({key: operation[key] for key in ("operation_id", "rules_digest", "previous_rules_digest", "rules", "ssh_port")})

        def revalidate(db):
            if validate_firewall_request(db, row, int(self.clock())) != operation:
                raise Denied("STALE_BASELINE")

        anchor = self.gate.call("time.anchor", {"plan_id": row["correlation_id"], "revision": operation["revision"]})
        binding = {"job_id": job["id"], "plan_id": row["correlation_id"], "revision": operation["revision"],
                   "plan_digest": job["payload_hash"], "approval_id": operation["approval_id"], "actor_id": job["actor_id"],
                   "target": job["resource_id"], "capability": job["action"], "scope_digest": job["scope_digest"],
                   "time_anchor": anchor, "firewall": payload}
        return binding, secret_ref, revalidate
