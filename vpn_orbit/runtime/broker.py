"""Scoped SSH-use with durable receipts, gate consumption and protected Vault policy."""

import asyncio
from pathlib import Path
import sqlite3
from threading import Lock, Timer
import time

from ..errors import Denied
from .authority import verify_permit
from .protocol import SHA256, ULID, canonical, checksum, decode, fields, text
from .ssh import application, apply_firewall, firewall_status, probe, provision_known_hosts, restart, verify_known_hosts
from .ssh_preparation import PreparationSSH, validate_administrator
from .storage import Journal
from .vps_preparation import PHASES


_SCHEMA = """
CREATE TABLE receipts(job_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
    permit TEXT NOT NULL, response TEXT);
"""
_PREPARATION_PHASES = """CREATE TABLE IF NOT EXISTS preparation_phases (
    job_id TEXT PRIMARY KEY REFERENCES receipts(job_id), phase TEXT NOT NULL,
    stage TEXT NOT NULL CHECK(stage IN ('DISPATCHING','VERIFIED')))"""
_PREPARATION_TIMEOUT = 115
_CREDENTIAL_TTL = 180


class Broker:
    def __init__(self, directory, policy, vault, gate, verify_key, *, worker_uid, execute=probe, execute_restart=restart,
                 execute_firewall=apply_firewall, execute_application=application, clock=time.time, writers=None):
        self.directory, self.policy = Path(directory), policy
        self.vault, self.gate, self.verify_key = vault, gate, verify_key
        self.worker_uid, self.execute, self.clock = worker_uid, execute, clock
        self.execute_restart = execute_restart
        self.execute_firewall = execute_firewall
        self.execute_application = execute_application
        self.firewall_status = firewall_status
        self._preparation_credentials = {}
        self._credentials_lock = Lock()
        self.journal = Journal(self.directory / "receipts.sqlite3", writers=writers)
        verify_known_hosts(self.directory / "known_hosts", policy)

    @classmethod
    def initialize(cls, directory, policy):
        Journal.initialize(Path(directory) / "receipts.sqlite3", _SCHEMA)
        provision_known_hosts(Path(directory) / "known_hosts", policy)

    def recover(self):
        # A restarted Broker never repeats a possibly sent request.
        with self.journal.connect() as db:
            rows = db.execute("SELECT * FROM receipts WHERE state IN ('PREPARED','DISPATCHING')").fetchall()
        for row in rows:
            permit = decode(row["permit"].encode())
            current = self.gate.call("attempt.status", {"job_id": row["job_id"]})
            if current["state"] == "DISPATCHING":
                self._complete(permit, "UNKNOWN_OUTCOME", "BROKER_RESTART", None)
            elif current["state"] == "ISSUED" or (current["state"] == "CANCELLED_SAFE"
                    and permit["claims"]["capability"] == "host.prepare"):
                receipt = current
                if current["state"] == "ISSUED":
                    receipt = self.gate.call("permit.cancel", {"job_id": row["job_id"], "nonce": row["nonce"]})
                self._persist(row["job_id"], "FAILED", {
                    "outcome": "FAILED", "code": "BROKER_RESTART_BEFORE_DISPATCH",
                    "observation": None, "authority_receipt": receipt,
                })
            else:
                self._persist(row["job_id"], "UNKNOWN_OUTCOME", {
                    "outcome": "UNKNOWN_OUTCOME", "code": "BROKER_RESTART",
                    "observation": None, "authority_receipt": current,
                })

    def _persist(self, job_id, state, response):
        with self.journal.write() as db:
            db.execute("UPDATE receipts SET state=?,response=? WHERE job_id=?", (state, canonical(response).decode(), job_id))

    def _complete(self, permit, outcome, code, observation):
        result = {"outcome": outcome, "code": code, "observation": observation}
        claims = permit["claims"]
        receipt = self.gate.call("attempt.complete", {"job_id": claims["job_id"], "nonce": claims["nonce"],
                                 "outcome": outcome, "result_code": code, "result_digest": checksum(result)})
        response = {**result, "authority_receipt": receipt}
        self._persist(claims["job_id"], outcome, response)
        return response

    def use(self, request, peer):
        by_policy = isinstance(request, dict) and "policy_ref" in request
        ref_field = "policy_ref" if by_policy else "secret_ref"
        fields(request, ("permit", ref_field))
        claims = verify_permit(request["permit"], self.verify_key, now=int(self.clock()))
        target = self.policy.target(claims["target"], claims["capability"], claims["scope_digest"])
        capability = claims["capability"]
        if capability == "host.prepare" and claims["mutating"]:
            if not by_policy or request[ref_field] != target.value["secret_ref"]:
                raise Denied("BROKER_SCOPE_DENIED")
            return self._dispatch_key(request, claims, target, None)
        if capability == "host.probe" and not claims["mutating"]:
            anchor = target.value["secret_ref"]
        elif capability == "docker.restart" and claims["mutating"]:
            anchor = target.value["restart_secret_ref"]
        elif capability == "firewall.apply" and claims["mutating"]:
            anchor = target.value["firewall_secret_ref"]
        elif capability == "apps.lifecycle" and claims["mutating"]:
            anchor = target.value["application_secret_ref"]
            app = claims["application"]
            if target.value["applications"].get(app["installation_id"]) != app["spec_digest"]:
                raise Denied("APP_POLICY_MISMATCH")
        else:
            raise Denied("BROKER_SCOPE_DENIED")
        text(request[ref_field], ULID + r":v[1-9][0-9]{0,8}")
        if by_policy and request[ref_field] != anchor:
            raise Denied("BROKER_SCOPE_DENIED")
        # Key bytes stay in this Broker process and never enter RPC responses.
        with self.vault.key_lock(anchor, shared=True):
            key = self.vault.use_policy_key(anchor, consumer_uid=peer.uid, target=target.id, purpose=capability,
                                            scope_digest=target.scope_digest, policy_revision=target.revision,
                                            exact_ref=None if by_policy else request[ref_field])
            return self._dispatch_key(request, claims, target, key)

    def _dispatch_key(self, request, claims, target, key):
        with self.journal.write() as db:
            if db.execute("SELECT 1 FROM receipts WHERE job_id=? OR nonce=?", (claims["job_id"], claims["nonce"])).fetchone():
                raise Denied("PERMIT_REPLAY")
            db.execute("INSERT INTO receipts VALUES(?,?,'PREPARED',?,NULL)", (claims["job_id"], claims["nonce"], canonical(request["permit"]).decode()))
        self.gate.call("permit.consume", request["permit"])
        with self.journal.write() as db:
            db.execute("UPDATE receipts SET state='DISPATCHING' WHERE job_id=?", (claims["job_id"],))
        if claims["capability"] == "host.prepare":
            return self._dispatch_preparation(request["permit"], target)
        if claims["capability"] in ("docker.restart", "firewall.apply", "apps.lifecycle"):
            execute, payload_key = {
                "docker.restart": (self.execute_restart, "restart"),
                "firewall.apply": (self.execute_firewall, "firewall"),
                "apps.lifecycle": (self.execute_application, "application"),
            }[claims["capability"]]
            payload = claims[payload_key]
            try:
                result = execute(target, key, self.directory / "known_hosts", payload)
            except Denied as error:
                return self._complete(request["permit"], "UNKNOWN_OUTCOME", error.code, None)
            outcome = "FAILED" if result["outcome"] == "DENIED" else result["outcome"]
            return self._complete(request["permit"], outcome, result["code"], None)
        try:
            observation = self.execute(target, key, self.directory / "known_hosts")
            return self._complete(request["permit"], "SUCCEEDED", "PROBE_VERIFIED", observation)
        except Denied as error:
            # The only installed operation is read-only, with no delegated effects.
            return self._complete(request["permit"], "FAILED", error.code, None)

    def _expire_credentials(self, job_id):
        with self._credentials_lock:
            self._preparation_credentials.pop(job_id, None)

    def _preparation_request(self, payload):
        fields(payload, ("job_id", "actor_id", "target", "scope_digest", "username", "password", "private_key"))
        for name in ("job_id", "actor_id", "target"):
            text(payload[name], ULID)
        text(payload["scope_digest"], SHA256)
        target = self.policy.target(payload["target"], "host.prepare", payload["scope_digest"])
        username, password, private_key = (payload[name] for name in ("username", "password", "private_key"))
        validate_administrator(username, password, private_key)
        return target, (username, password, private_key)

    def _supply_preparation(self, payload):
        target, credentials = self._preparation_request(payload)
        job_id = payload["job_id"]
        with self._credentials_lock:
            if job_id in self._preparation_credentials or len(self._preparation_credentials) >= 8:
                raise Denied("VPS_PREPARATION_CREDENTIALS_BUSY")
            timer = Timer(_CREDENTIAL_TTL, self._expire_credentials, (job_id,))
            timer.daemon = True
            self._preparation_credentials[job_id] = (
                payload["actor_id"], target.id, target.scope_digest, time.monotonic() + _CREDENTIAL_TTL, credentials, timer,
            )
            timer.start()
        return {"job_id": job_id}

    def _take_credentials(self, claims):
        with self._credentials_lock:
            entry = self._preparation_credentials.pop(claims["job_id"], None)
        if entry is None:
            raise Denied("VPS_PREPARATION_CREDENTIALS_EXPIRED")
        actor, target, scope, expiry, credentials, timer = entry
        timer.cancel()
        if (actor, target, scope) != (claims["actor_id"], claims["target"], claims["scope_digest"]) or time.monotonic() >= expiry:
            raise Denied("VPS_PREPARATION_CREDENTIALS_EXPIRED")
        return credentials

    def _preparation_key(self, target):
        ref = target.value["secret_ref"]
        return self.vault.use_policy_key(ref, consumer_uid=self.worker_uid, target=target.id, purpose="host.probe",
                                         scope_digest=target.scope_digest, policy_revision=target.revision, exact_ref=ref)

    def _checkpoint(self, job_id, phase, stage):
        with self.journal.write(kind="dispatch") as db:
            db.execute(_PREPARATION_PHASES)
            db.execute("""INSERT INTO preparation_phases VALUES(?,?,?)
                          ON CONFLICT(job_id) DO UPDATE SET phase=excluded.phase,stage=excluded.stage""",
                       (job_id, phase, stage))

    def _dispatch_preparation(self, permit, target):
        claims = permit["claims"]
        dispatched = False

        async def execute(transport):
            nonlocal dispatched
            async with asyncio.timeout(_PREPARATION_TIMEOUT):
                for phase in PHASES:
                    status = await transport.phase(phase, inspect=True)
                    if status == "INCOMPLETE":
                        self._checkpoint(claims["job_id"], phase, "DISPATCHING")
                        dispatched = True
                        await transport.phase(phase, inspect=False)
                        status = await transport.phase(phase, inspect=True)
                    if status != "VERIFIED":
                        raise Denied({"CONFLICT": "VPS_PREPARATION_CONFLICT", "BUSY": "VPS_PREPARATION_BUSY"}.get(
                            status, "VPS_PREPARATION_PHASE_UNCONFIRMED"))
                    self._checkpoint(claims["job_id"], phase, "VERIFIED")
                await transport.verify_access()

        try:
            with self.vault.key_lock(target.value["secret_ref"], shared=True):
                username, password, private_key = self._take_credentials(claims)
                transport = PreparationSSH(target, username, password=password, private_key=private_key,
                                           observation_key=self._preparation_key(target))
                asyncio.run(execute(transport))
        except (Denied, OSError, TimeoutError, sqlite3.Error) as error:
            code = error.code if isinstance(error, Denied) else "VPS_PREPARATION_UNCONFIRMED"
            return self._complete(permit, "UNKNOWN_OUTCOME" if dispatched else "FAILED", code, None)
        return self._complete(permit, "SUCCEEDED", "VPS_PREPARATION_VERIFIED", None)

    def _reconcile_preparation(self, payload):
        target, (username, password, private_key) = self._preparation_request(payload)
        with self.journal.connect() as db:
            row = db.execute("SELECT permit FROM receipts WHERE job_id=?", (payload["job_id"],)).fetchone()
        if row is None:
            raise Denied("VPS_PREPARATION_RECONCILIATION_UNVERIFIED")
        claims = decode(row["permit"].encode())["claims"]
        if (claims["capability"] != "host.prepare" or claims["target"] != target.id
                or claims["scope_digest"] != target.scope_digest or claims["actor_id"] != payload["actor_id"]):
            raise Denied("VPS_PREPARATION_RECONCILIATION_UNVERIFIED")
        request = {"job_id": claims["job_id"], "nonce": claims["nonce"]}

        async def inspect(transport):
            async with asyncio.timeout(_PREPARATION_TIMEOUT):
                for phase in PHASES:
                    if await transport.phase(phase, inspect=True) != "VERIFIED":
                        raise Denied("VPS_PREPARATION_RECONCILIATION_UNVERIFIED")
                await transport.verify_access()

        receipt = self.gate.call("prepare.readback", request)
        if receipt["state"] in ("FAILED", "CANCELLED_SAFE"):
            return receipt
        with self.vault.key_lock(target.value["secret_ref"], shared=True):
            transport = PreparationSSH(target, username, password=password, private_key=private_key,
                                       observation_key=self._preparation_key(target))
            try:
                asyncio.run(inspect(transport))
            except TimeoutError:
                raise Denied("VPS_PREPARATION_RECONCILIATION_UNVERIFIED") from None
            receipt = self.gate.call("prepare.reconcile", request)
            self._persist(claims["job_id"], receipt["state"], {
                "outcome": "SUCCEEDED", "code": receipt["result_code"], "observation": None, "authority_receipt": receipt,
            })
            return receipt

    def remote_firewall_status(self, payload, peer):
        fields(payload, ("policy_ref", "target", "operation_id"))
        text(payload["policy_ref"], ULID + r":v[1-9][0-9]{0,8}")
        text(payload["target"], ULID)
        text(payload["operation_id"], ULID)
        target = self.policy.targets.get(payload["target"])
        if target is None or "firewall.apply" not in target.value["capabilities"]:
            raise Denied("CAPABILITY_DISABLED")
        if payload["policy_ref"] != target.value["firewall_secret_ref"]:
            raise Denied("BROKER_SCOPE_DENIED")
        with self.journal.connect() as db:
            row = db.execute("SELECT permit FROM receipts WHERE job_id=?", (payload["operation_id"],)).fetchone()
        if row is None:
            raise Denied("RECEIPT_NOT_TERMINAL")
        claims = decode(row["permit"].encode())["claims"]
        if (claims["target"] != target.id or claims["capability"] != "firewall.apply"
                or claims["scope_digest"] != target.scope_digest):
            raise Denied("BROKER_SCOPE_DENIED")
        # A read-only reconciliation query. It can never issue a permit or mutate.
        with self.vault.key_lock(payload["policy_ref"], shared=True):
            key = self.vault.use_policy_key(payload["policy_ref"], consumer_uid=peer.uid, target=target.id,
                                            purpose="firewall.apply", scope_digest=target.scope_digest,
                                            policy_revision=target.revision)
            remote = self.firewall_status(target, key, self.directory / "known_hosts", payload["operation_id"])
        if (remote.get("outcome") != "SUCCEEDED" or remote.get("rules_digest") != claims["firewall"]["rules_digest"]):
            raise Denied("FIREWALL_RECONCILIATION_UNVERIFIED")
        receipt = self.gate.call("attempt.status", {"job_id": payload["operation_id"]})
        if remote.get("state") in ("CONFIRMED", "ROLLED_BACK") and receipt["state"] in (
                "UNKNOWN_OUTCOME", "RECONCILED_SUCCEEDED", "RECONCILED_FAILED"):
            self.gate.call("firewall.reconcile", {"job_id": claims["job_id"], "nonce": claims["nonce"],
                                                "rules_digest": claims["firewall"]["rules_digest"],
                                                "state": remote["state"]})
        return remote

    def dispatch(self, role, peer, operation, payload):
        if role == "local-root" and (peer.uid, peer.gid) == (0, 0):
            if operation == "prepare.credentials":
                return self._supply_preparation(payload)
            if operation == "prepare.reconcile":
                return self._reconcile_preparation(payload)
        if role != "worker" or peer.uid != self.worker_uid:
            raise Denied("RPC_PEER_DENIED")
        if operation == "use_for_scoped_ssh":
            return self.use(payload, peer)
        if operation == "firewall.status":
            return self.remote_firewall_status(payload, peer)
        if operation == "apps.reconcile":
            fields(payload, ("job_id",))
            text(payload["job_id"], ULID)
            with self.journal.connect() as db:
                row = db.execute("SELECT permit FROM receipts WHERE job_id=?", (payload["job_id"],)).fetchone()
            if row is None:
                raise Denied("APP_RECONCILIATION_UNVERIFIED")
            claims = decode(row["permit"].encode())["claims"]
            if claims["capability"] != "apps.lifecycle":
                raise Denied("BROKER_SCOPE_DENIED")
            target = self.policy.target(claims["target"], claims["capability"], claims["scope_digest"])
            request = claims["application"]
            if target.value["applications"].get(request["installation_id"]) != request["spec_digest"]:
                raise Denied("APP_POLICY_MISMATCH")
            anchor = target.value["application_secret_ref"]
            with self.vault.key_lock(anchor, shared=True):
                key = self.vault.use_policy_key(anchor, consumer_uid=peer.uid, target=target.id, purpose="apps.lifecycle",
                                                scope_digest=target.scope_digest, policy_revision=target.revision)
                remote = self.execute_application(target, key, self.directory / "known_hosts", request, operation="reconcile")
            if (remote.get("outcome") not in ("SUCCEEDED", "RECONCILED_SUCCEEDED")
                    or remote.get("code") not in ("APP_READBACK_VERIFIED", "APP_HEALTH_VERIFIED", "APP_REMOVED_DATA_PRESERVED")):
                raise Denied("APP_RECONCILIATION_UNVERIFIED")
            receipt = self.gate.call("attempt.status", {"job_id": claims["job_id"]})
            if receipt["state"] in ("UNKNOWN_OUTCOME", "RECONCILED_SUCCEEDED"):
                self.gate.call("apps.reconcile", {"job_id": claims["job_id"], "nonce": claims["nonce"],
                                                 "spec_digest": request["spec_digest"]})
            elif receipt["state"] != "SUCCEEDED":
                raise Denied("APP_RECONCILIATION_UNVERIFIED")
            return remote
        if operation == "receipt.get":
            fields(payload, ("job_id",))
            text(payload["job_id"], ULID)
            with self.journal.connect() as db:
                row = db.execute("SELECT response FROM receipts WHERE job_id=?", (payload["job_id"],)).fetchone()
                if row is None or row["response"] is None:
                    raise Denied("RECEIPT_NOT_TERMINAL")
                return decode(row["response"].encode())
        raise Denied("RPC_OPERATION_DENIED")
