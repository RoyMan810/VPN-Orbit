"""One process owns a durable queue claim. All SSH use goes through protected local IPC."""

from threading import Event

from .database import identifier
from .application_requests import ApplicationOperations, reconcile_pending as reconcile_applications
from .errors import Denied
from .firewall_requests import FirewallOperations
from .queue import JobQueue
from .restart_requests import RestartOperations
from .runtime.protocol import checksum, docker_summary, fields, firewall_rules, integer, software_summary, text
from .runtime.storage import process_lock


class Worker:
    def __init__(self, queue: JobQueue, gate, broker, *, secret_refs, observe=None, restart_refs=None, firewall_refs=None,
                 application_refs=None):
        self.queue, self.gate, self.broker = queue, gate, broker
        self.secret_refs = secret_refs
        self.restart = RestartOperations(queue, gate, broker, restart_refs if restart_refs is not None else {})
        self.firewall = FirewallOperations(queue, gate, broker, firewall_refs if firewall_refs is not None else {})
        self.applications = ApplicationOperations(queue, gate, broker, application_refs or {})
        self.id = identifier()
        self.observe = observe or (lambda _: None)

    def _recover_result(self, row):
        if row["status"] not in ("QUEUED", "INTENT_PREPARED"):
            return "UNKNOWN_OUTCOME"
        try:
            status = self.gate.call("attempt.status", {"job_id": row["id"]})
            if status["state"] == "ISSUED":
                self.gate.call("permit.cancel", {"job_id": row["id"], "nonce": status["nonce"]})
                return "CANCELLED_SAFE"
            if status["state"] == "CANCELLED_SAFE":
                return "CANCELLED_SAFE"
        except Denied as error:
            if error.code == "ATTEMPT_NOT_FOUND":
                return "CANCELLED_SAFE"
        return "UNKNOWN_OUTCOME"

    def run_one(self):
        try:
            if self.restart.reconcile_pending():
                return True
            if self.firewall.reconcile_pending():
                return True
            if reconcile_applications(self.applications):
                return True
            claimed = self.queue.claim(self.id)
        except Denied as error:
            if error.code in {"WRITER_ADMISSION_CLOSED", "WRITER_BARRIER_TIMEOUT"}:
                return False
            raise
        if claimed is None:
            return False
        claim, row = claimed
        sent = False
        permit = None
        try:
            restart = row["action"] == "docker.restart"
            firewall = row["action"] == "firewall.apply"
            application = row["action"] == "apps.lifecycle"
            if restart:
                binding, secret_ref, revalidate = self.restart.prepare(row)
            elif firewall:
                binding, secret_ref, revalidate = self.firewall.prepare(row)
            elif application:
                binding, secret_ref, revalidate = self.applications.prepare(row)
            else:
                binding, secret_ref, revalidate = self.queue.binding(row), self.secret_refs[row["resource_id"]], None
            permit = self.gate.call("permit.admit", binding)
            self.queue.advance(claim, "INTENT_PREPARED", permit=permit, binding=binding)
            self.observe("INTENT_PREPARED")
            # This commit must precede even entering the Broker dispatch path.
            self.queue.advance(claim, "DISPATCHING", validate=revalidate)
            sent = True
            self.observe("DISPATCHING")
            response = self.broker.call("use_for_scoped_ssh", {"permit": permit, "policy_ref": secret_ref})
            self.queue.advance(claim, "EXECUTING")
            self.queue.advance(claim, "VERIFYING")
            self.observe("VERIFYING")
            fields(response, ("outcome", "code", "observation", "authority_receipt"))
            result = {k: response[k] for k in ("outcome", "code", "observation")}
            receipt = self.gate.call("attempt.status", {"job_id": row["id"]})
            if (receipt != response["authority_receipt"] or receipt["state"] != response["outcome"]
                    or receipt["result_digest"] != checksum(result)):
                raise Denied("BROKER_RECEIPT_INVALID")
            text(response["code"], r"[A-Z][A-Z0-9_]{1,63}")
            if restart or application:
                if response["outcome"] not in ("SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME") or response["observation"] is not None:
                    raise Denied("BROKER_RECEIPT_INVALID")
                if application and response["outcome"] == "SUCCEEDED" and response["code"] not in (
                        "APP_HEALTH_VERIFIED", "APP_REMOVED_DATA_PRESERVED", "APP_READBACK_VERIFIED"):
                    raise Denied("BROKER_RECEIPT_INVALID")
                self.queue.finish(claim, response["outcome"], response["code"])
            elif firewall:
                if response["outcome"] not in ("SUCCEEDED", "FAILED", "UNKNOWN_OUTCOME") or response["observation"] is not None:
                    raise Denied("BROKER_RECEIPT_INVALID")
                result = None
                if response["outcome"] == "SUCCEEDED":
                    if response["code"] not in ("FIREWALL_CONFIRMED", "FIREWALL_ALREADY_CONFIRMED"):
                        raise Denied("BROKER_RECEIPT_INVALID")
                    result = {"rules": firewall_rules(binding["firewall"]["rules"]),
                              "rules_digest": binding["firewall"]["rules_digest"],
                              "ssh_port": binding["firewall"]["ssh_port"]}
                self.queue.finish(claim, response["outcome"], response["code"], result=result)
            elif response["outcome"] == "SUCCEEDED":
                value = response["observation"]
                names = ("status", "source", "observed_at", "boot_id")
                if isinstance(value, dict) and "docker" in value:
                    fields(value, names + ("software", "docker"))
                    software_summary(value["software"])
                    docker_summary(value["docker"])
                elif isinstance(value, dict) and "software" in value:
                    fields(value, names + ("software",))
                    software_summary(value["software"])
                else:
                    fields(value, names)
                if value["status"] != "REACHABLE" or value["source"] != "restricted_helper":
                    raise Denied("BROKER_OBSERVATION_INVALID")
                integer(value["observed_at"], int(self.queue.clock()) - 300, int(self.queue.clock()) + 2)
                text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                self.queue.finish(claim, "SUCCEEDED", response["code"], result=value)
            elif response["outcome"] in ("FAILED", "UNKNOWN_OUTCOME") and response["observation"] is None:
                self.queue.finish(claim, response["outcome"], response["code"])
            else:
                raise Denied("BROKER_OBSERVATION_INVALID")
        except Denied as error:
            if not sent and permit is not None:
                try:
                    self.gate.call("permit.cancel", {"job_id": row["id"], "nonce": permit["claims"]["nonce"]})
                except Denied:
                    self.queue.finish(claim, "UNKNOWN_OUTCOME", error.code)
                    return True
            # A lost reply after dispatch never becomes success and never causes an automatic retry.
            self.queue.finish(claim, "UNKNOWN_OUTCOME" if sent else "CANCELLED_SAFE", error.code)
        return True

    def run(self, *, once=False, stop=None):
        stop = stop if stop is not None else Event()
        path = self.queue.store.path.with_suffix(".worker.lock")
        with process_lock(path, shared_gid=self.queue.store.access.shared_gid):
            self.queue.recover(self._recover_result)
            while not stop.is_set():
                found = self.run_one()
                if once:
                    return found
                if not found:
                    stop.wait(0.5)
            return False
