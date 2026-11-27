"""Canonical bounded frames shared by local IPC and signed capabilities."""

from datetime import datetime
import hashlib
from ipaddress import ip_address, ip_network
import json
import re

from ..errors import Denied


MAX_FRAME = 16384
PROBE_VERSION = 12
PROBE_COMMAND = f"vpn-orbit.v{PROBE_VERSION}.probe"
PROBE_REQUEST = b'{"operation":"probe","version":%d}\n' % PROBE_VERSION
MAX_PROBE_REPLY = 15360
PARTIAL_PREPARATION = "VPS_PREPARATION_PARTIAL_VERIFIED"
ULID = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
SHA256 = r"[0-9a-f]{64}"
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
BOOT_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
DOCKER_STARTED_AT = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z"


MAX_FIREWALL_RULES = 32


def application_payload(value):
    fields(value, ("operation_id", "installation_id", "spec_digest", "action"))
    text(value["operation_id"], ULID)
    text(value["installation_id"], ULID)
    text(value["spec_digest"], SHA256)
    if value["action"] not in ("install", "start", "remove"):
        raise Denied("APP_ACTION_INVALID")
    return value


def firewall_rules(value):
    """Validate the complete typed rule set. No free-form nftables is accepted."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FIREWALL_RULES:
        raise Denied("FIREWALL_RULES_INVALID")
    seen = set()
    for rule in value:
        fields(rule, ("action", "direction", "protocol", "port", "cidr"))
        if rule["action"] not in ("allow", "deny") or rule["direction"] not in ("in", "out"):
            raise Denied("FIREWALL_RULES_INVALID")
        if rule["protocol"] not in ("tcp", "udp"):
            raise Denied("FIREWALL_RULES_INVALID")
        integer(rule["port"], 1, 65535)
        cidr = rule["cidr"]
        if not isinstance(cidr, str) or "%" in cidr:
            raise Denied("FIREWALL_RULES_INVALID")
        try:
            parsed = ip_network(cidr, strict=True)
        except ValueError:
            raise Denied("FIREWALL_RULES_INVALID") from None
        if str(parsed) != cidr:
            raise Denied("FIREWALL_RULES_INVALID")
        identity = (rule["action"], rule["direction"], rule["protocol"], rule["port"], cidr)
        if identity in seen:
            raise Denied("FIREWALL_RULES_INVALID")
        seen.add(identity)
    return value


def firewall_payload(value):
    fields(value, ("operation_id", "rules_digest", "previous_rules_digest", "rules", "ssh_port"))
    text(value["operation_id"], ULID)
    text(value["rules_digest"], SHA256)
    text(value["previous_rules_digest"], SHA256)
    rules = firewall_rules(value["rules"])
    if checksum(rules) != value["rules_digest"]:
        raise Denied("FIREWALL_RULES_INVALID")
    integer(value["ssh_port"], 1, 65535)
    if not any(rule["action"] == "allow" and rule["direction"] == "in" and rule["protocol"] == "tcp"
               and rule["port"] == value["ssh_port"] for rule in rules):
        raise Denied("FIREWALL_SSH_RULE_REQUIRED")
    return value


def restart_payload(value):
    fields(value, ("operation_id", "container_id", "boot_id", "started_at"))
    for key, pattern in (("operation_id", ULID), ("container_id", SHA256),
                         ("boot_id", BOOT_ID), ("started_at", DOCKER_STARTED_AT)):
        text(value[key], pattern)
    try:
        datetime.fromisoformat(value["started_at"])
    except ValueError:
        raise Denied("RPC_INVALID_REQUEST") from None
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def checksum(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def preparation_digest(job_id, actor_id, target, scope_digest):
    return checksum({"job_id": job_id, "actor_id": actor_id, "target": target,
                     "scope_digest": scope_digest, "action": "host.prepare"})

def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field")
        obj[key] = value
    return obj


def decode(data, *, canonical_required=True):
    def depth(value, level=0):
        if level > 12:
            raise ValueError("nested frame")
        if isinstance(value, dict):
            for v in value.values():
                depth(v, level + 1)
        elif isinstance(value, list):
            for v in value:
                depth(v, level + 1)
    try:
        if not data or len(data) > MAX_FRAME:
            raise ValueError("frame length")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))
        depth(value)
        if canonical_required and canonical(value) != data:
            raise ValueError("non-canonical frame")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise Denied("RPC_INVALID_REQUEST") from None


def fields(value, names):
    if not isinstance(value, dict) or value.keys() != set(names):
        raise Denied("RPC_INVALID_REQUEST")
    return value


def text(value, pattern, code="RPC_INVALID_REQUEST"):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise Denied(code)
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Denied("RPC_INVALID_REQUEST")
    return value


def software_summary(value):
    names = ("docker", "nginx")
    fields(value, (*names, "nginx_service"))
    if any(value[name] not in ("PRESENT", "NOT_DETECTED", "UNKNOWN") for name in names):
        raise Denied("PROBE_SOFTWARE_INVALID")
    if value["nginx_service"] not in (
        "ACTIVE", "INACTIVE", "FAILED", "TRANSITIONING", "NOT_FOUND", "UNKNOWN",
    ):
        raise Denied("PROBE_SOFTWARE_INVALID")
    return value


def _validate_published_ports(ports, state):
    if ports is None:
        return
    if state in ("UNKNOWN", "NOT_FOUND") or not isinstance(ports, list) or len(ports) > 8:
        raise Denied("PROBE_DOCKER_INVALID")
    seen = set()
    for port in ports:
        fields(port, ("address", "host_port", "container_port", "protocol"))
        address = text(port["address"], r"[0-9a-f:.]{2,45}")
        try:
            if str(ip_address(address)) != address:
                raise ValueError("noncanonical address")
        except ValueError:
            raise Denied("PROBE_DOCKER_INVALID") from None
        host = integer(port["host_port"], 1, 65535)
        private = integer(port["container_port"], 1, 65535)
        protocol = port["protocol"]
        if protocol not in ("tcp", "udp", "sctp") or (address, host, private, protocol) in seen:
            raise Denied("PROBE_DOCKER_INVALID")
        seen.add((address, host, private, protocol))


def compose_summary(value):
    fields(value, ("status", "containers"))
    status, rows = value["status"], value["containers"]
    if (status not in ("OBSERVED", "NOT_CONFIGURED", "POLICY_INVALID", "UNAVAILABLE", "LIMIT_EXCEEDED")
            or not isinstance(rows, list) or len(rows) > 12 or rows and status != "OBSERVED"):
        raise Denied("PROBE_COMPOSE_INVALID")
    seen = set()
    attachments = ("networks", "volumes")
    # Attachment discovery is opt-in for the entire Compose scope.
    include = any(isinstance(row, dict) and ("networks" in row or "volumes" in row) for row in rows)
    names = ("id", "image_id", "project", "service", "state") + (attachments if include else ())
    for row in rows:
        fields(row, names)
        if include:
            for key in attachments:
                items = row[key]
                if items is None:
                    continue
                if not isinstance(items, list) or len(items) > 8:
                    raise Denied("PROBE_COMPOSE_INVALID")
                for name in items:
                    text(name, r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", "PROBE_COMPOSE_INVALID")
                if items != sorted(set(items)):
                    raise Denied("PROBE_COMPOSE_INVALID")
        identity = text(row["id"], SHA256)
        text(row["image_id"], "sha256:" + SHA256)
        text(row["project"], r"[a-z0-9][a-z0-9_-]{0,62}")
        text(row["service"], r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
        if identity in seen or row["state"] not in ("CREATED", "RESTARTING", "RUNNING", "REMOVING", "PAUSED", "EXITED", "DEAD"):
            raise Denied("PROBE_COMPOSE_INVALID")
        seen.add(identity)
    return value


def docker_summary(value):
    fields(value, ("status", "containers"))
    status, rows = value["status"], value["containers"]
    if (status not in ("OBSERVED", "NOT_CONFIGURED", "POLICY_INVALID", "UNAVAILABLE")
            or not isinstance(rows, list) or len(rows) > 8 or bool(rows) != (status == "OBSERVED")):
        raise Denied("PROBE_DOCKER_INVALID")
    names = ("id", "project", "service", "state", "published_ports", "mount_status", "network_status",
             "dependency_status", "started_at")
    seen = set()
    for item in rows:
        fields(item, names)
        identity = text(item["id"], r"[0-9a-f]{64}")
        text(item["project"], r"[a-z0-9][a-z0-9_-]{0,62}")
        text(item["service"], r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
        if identity in seen or item["state"] not in (
            "CREATED", "RESTARTING", "RUNNING", "REMOVING", "PAUSED", "EXITED", "DEAD", "UNKNOWN", "NOT_FOUND",
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        seen.add(identity)
        _validate_published_ports(item["published_ports"], item["state"])
        if (
            item["mount_status"] not in ("NONE", "PRESENT", "UNKNOWN")
            or item["state"] != "RUNNING" and item["mount_status"] != "UNKNOWN"
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        if (
            item["network_status"] not in ("ISOLATED", "OTHER", "UNKNOWN")
            or item["state"] != "RUNNING" and item["network_status"] != "UNKNOWN"
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        if (
            item["dependency_status"] not in ("ISOLATED", "OTHER", "UNKNOWN")
            or (item["mount_status"] != "NONE" or item["network_status"] != "ISOLATED")
            and item["dependency_status"] != "UNKNOWN"
        ):
            raise Denied("PROBE_DOCKER_INVALID")
        if item["started_at"] is not None:
            started_at = item["started_at"]
            if (item["state"] != "RUNNING" or not isinstance(started_at, str)
                    or started_at.startswith("0001-01-01T00:00:00")
                    or not re.fullmatch(DOCKER_STARTED_AT, started_at)):
                raise Denied("PROBE_DOCKER_INVALID")
            try:
                datetime.fromisoformat(started_at)
            except ValueError:
                raise Denied("PROBE_DOCKER_INVALID") from None
    return value


def local_https_summary(value):
    fields(value, ("status", "sites"))
    status, sites = value["status"], value["sites"]
    if (status not in ("OBSERVED", "NOT_CONFIGURED", "POLICY_INVALID", "UNAVAILABLE")
            or not isinstance(sites, list) or len(sites) > 4 or bool(sites) != (status == "OBSERVED")):
        raise Denied("PROBE_LOCAL_HTTPS_INVALID")
    previous = ""
    for site in sites:
        fields(site, ("name", "state", "expires_at"))
        name = site["name"]
        if (not isinstance(name, str) or len(name) > 253 or name <= previous or name.rsplit(".", 1)[-1].isdigit()
                or not re.fullmatch(rf"{DNS_LABEL}(?:\.{DNS_LABEL})+", name)):
            raise Denied("PROBE_LOCAL_HTTPS_INVALID")
        previous = name
        if site["state"] == "VERIFIED":
            integer(site["expires_at"], 0, 253402300799)
        elif site["state"] not in ("CERTIFICATE_INVALID", "UNAVAILABLE") or site["expires_at"] is not None:
            raise Denied("PROBE_LOCAL_HTTPS_INVALID")
    return value


def observation_summary(value):
    fields(value, ("status", "source", "observed_at", "boot_id", "software", "docker", "compose", "local_https"))
    if value["status"] != "REACHABLE" or value["source"] != "restricted_helper":
        raise Denied("BROKER_OBSERVATION_INVALID")
    integer(value["observed_at"], 0, 2**63 - 1)
    text(value["boot_id"], BOOT_ID)
    software_summary(value["software"])
    docker_summary(value["docker"])
    compose_summary(value["compose"])
    local_https_summary(value["local_https"])
    return value
