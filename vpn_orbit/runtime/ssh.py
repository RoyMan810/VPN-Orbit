"""One fixed SSH operation with in-process keys, pinned host identity and bounded streams."""

import asyncio
import errno
import os
import time

import asyncssh

from ..errors import Denied
from .protocol import MAX_PROBE_REPLY, PROBE_COMMAND, PROBE_REQUEST, PROBE_VERSION, SHA256, ULID, application_payload, canonical, compose_summary, decode, docker_summary, fields, firewall_payload, integer, restart_payload, software_summary, text
from .storage import new_private_file, protected_bytes


def validate_private_key(key):
    try:
        imported = asyncssh.import_private_key(key)
        if imported.get_algorithm() != "ssh-ed25519":
            raise ValueError
        return imported
    except (asyncssh.KeyImportError, ValueError, TypeError):
        raise Denied("SSH_KEY_FORMAT_UNSUPPORTED") from None


async def bounded_read(stream, limit=2048):
    result = bytearray()
    while True:
        chunk = await stream.read(1024)
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > limit:
            raise Denied("SSH_UNSUPPORTED_OUTPUT")


async def connect(target, key, known_hosts, username):
    return await asyncssh.connect(
        target.value["ip"], port=target.value["port"], username=username,
        client_keys=[key], agent_path=None, config=None,
        known_hosts=os.fspath(known_hosts), host_key_alias=f"vpn-orbit-{target.id}",
        x509_trusted_certs=None, x509_trusted_cert_paths=[],
        preferred_auth=["publickey"], password_auth=False, kbdint_auth=False,
        gss_auth=False, gss_kex=False, host_based_auth=False, server_host_key_algs=["ssh-ed25519"],
        agent_forwarding=False, connect_timeout=4, login_timeout=5,
    )


async def exchange(target, key, known_hosts):
    connection = await connect(target, key, known_hosts, "vpn-orbit-svc")
    try:
        process = await connection.create_process(PROBE_COMMAND, input=PROBE_REQUEST, encoding=None, request_pty=False)
        output, _, _ = await asyncio.gather(
            bounded_read(process.stdout, MAX_PROBE_REPLY),
            bounded_read(process.stderr), process.wait_closed())
        if process.exit_status != 0:
            raise Denied("SSH_REMOTE_PROBE_FAILED")
        return output
    finally:
        connection.close()
        try:
            await asyncio.wait_for(connection.wait_closed(), 1)
        except asyncio.TimeoutError:
            connection.abort()


def probe(target, private_key, known_hosts):
    key = validate_private_key(private_key)
    async def bounded():
        return await asyncio.wait_for(exchange(target, key, known_hosts), 12)
    try:
        output = asyncio.run(bounded())
    except asyncssh.HostKeyNotVerifiable:
        raise Denied("SSH_HOST_KEY_MISMATCH") from None
    except asyncssh.PermissionDenied:
        raise Denied("SSH_AUTHENTICATION_FAILED") from None
    except asyncssh.KeyExchangeFailed:
        raise Denied("SSH_KEY_EXCHANGE_FAILED") from None
    except asyncssh.ConnectionLost:
        raise Denied("SSH_CONNECTION_LOST") from None
    except asyncssh.ProtocolError:
        raise Denied("SSH_PROTOCOL_ERROR") from None
    except (asyncio.TimeoutError, TimeoutError):
        raise Denied("SSH_TIMEOUT") from None
    except OSError as error:
        code = {errno.EACCES: "SSH_LOCAL_ACCESS_DENIED", errno.ENOENT: "SSH_LOCAL_FILE_MISSING",
                errno.ECONNREFUSED: "SSH_CONNECTION_REFUSED", errno.ENETUNREACH: "SSH_NETWORK_UNREACHABLE"}.get(error.errno, "SSH_NETWORK_UNAVAILABLE")
        raise Denied(code) from None
    except asyncssh.Error:
        raise Denied("SSH_CONNECTION_FAILED") from None
    return parse_probe(output, now=int(time.time()))


async def exchange_restart(target, key, known_hosts, request):
    connection = await connect(target, key, known_hosts, "vpn-orbit-restart")
    try:
        process = await connection.create_process("vpn-orbit.v1.docker-restart", input=canonical(request) + b"\n",
                                                  encoding=None, request_pty=False)
        output, error, _ = await asyncio.gather(
            bounded_read(process.stdout, 512), bounded_read(process.stderr, 512), process.wait_closed())
        if error:
            raise Denied("SSH_RESTART_REPLY_INVALID")
        value = fields(decode(output.rstrip(b"\n"), canonical_required=False), ("outcome", "code"))
        valid = {"SUCCEEDED": 0, "DENIED": 65, "UNKNOWN_OUTCOME": 70}
        if not isinstance(value["outcome"], str) or valid.get(value["outcome"]) != process.exit_status:
            raise Denied("SSH_RESTART_REPLY_INVALID")
        text(value["code"], r"[A-Z][A-Z0-9_]{1,63}")
        if value["outcome"] == "SUCCEEDED" and value["code"] not in ("DOCKER_RESTART_VERIFIED", "RESTART_ALREADY_VERIFIED"):
            raise Denied("SSH_RESTART_REPLY_INVALID")
        return value
    finally:
        connection.abort()


def restart(target, private_key, known_hosts, request):
    restart_payload(request)
    try:
        return asyncio.run(asyncio.wait_for(exchange_restart(target, validate_private_key(private_key), known_hosts, request), 32))
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied("SSH_RESTART_UNCONFIRMED") from None


async def exchange_application(target, key, known_hosts, request, *, operation="execute"):
    connection = await connect(target, key, known_hosts, "vpn-orbit-apps")
    try:
        process = await connection.create_process(
            "vpn-orbit.v1.apps", input=canonical({"operation": operation, "application": request}) + b"\n",
            encoding=None, request_pty=False)
        output, error, _ = await asyncio.gather(
            bounded_read(process.stdout, 512), bounded_read(process.stderr, 512), process.wait_closed())
        if error:
            if b"sudo:" in error:
                raise Denied("SSH_APP_SUDO_FAILED")
            if b"Traceback" in error:
                raise Denied("SSH_APP_HELPER_FAILED")
            if b"lecture" in error or b"lecture" in error.lower() or b"privacy" in error.lower():
                raise Denied("SSH_APP_SUDO_LECTURE")
            raise Denied("SSH_APP_REMOTE_STDERR")
        value = fields(decode(output.rstrip(b"\n"), canonical_required=False), ("outcome", "code"))
        valid = {"SUCCEEDED": 0, "RECONCILED_SUCCEEDED": 0, "DENIED": 65, "UNKNOWN_OUTCOME": 70}
        if not isinstance(value["outcome"], str) or valid.get(value["outcome"]) != process.exit_status:
            raise Denied("SSH_APP_REPLY_STATUS_INVALID")
        text(value["code"], r"APP_[A-Z_]{1,59}")
        return value
    finally:
        connection.abort()


def application(target, private_key, known_hosts, request, *, operation="execute"):
    application_payload(request)
    if (target.value.get("applications", {}).get(request["installation_id"]) != request["spec_digest"]
            or operation not in ("execute", "reconcile")):
        raise Denied("APP_POLICY_MISMATCH")
    try:
        return asyncio.run(asyncio.wait_for(
            exchange_application(target, validate_private_key(private_key), known_hosts, request, operation=operation), 920))
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied("SSH_APP_UNCONFIRMED") from None

FIREWALL_USER = "vpn-orbit-firewall"
FIREWALL_OUTCOMES = {"SUCCEEDED": 0, "DENIED": 65, "UNKNOWN_OUTCOME": 70}
FIREWALL_STATES = ("ARMED", "CONFIRMED", "ROLLED_BACK", "ROLLBACK_FAILED", "ABSENT")


def firewall_reply(value, exit_status):
    if not isinstance(value, dict) or not {"outcome", "code"} <= value.keys():
        raise Denied("SSH_FIREWALL_REPLY_INVALID")
    allowed = {"outcome", "code", "state", "rules_digest"}
    if not value.keys() <= allowed:
        raise Denied("SSH_FIREWALL_REPLY_INVALID")
    if not isinstance(value["outcome"], str) or FIREWALL_OUTCOMES.get(value["outcome"]) != exit_status:
        raise Denied("SSH_FIREWALL_REPLY_INVALID")
    text(value["code"], r"[A-Z][A-Z0-9_]{1,63}")
    if "state" in value and value["state"] not in FIREWALL_STATES:
        raise Denied("SSH_FIREWALL_REPLY_INVALID")
    if "rules_digest" in value:
        text(value["rules_digest"], r"[0-9a-f]{64}")
    if value["outcome"] == "SUCCEEDED":
        requirements = {
            "FIREWALL_APPLIED": ("ARMED", True),
            "FIREWALL_ALREADY_APPLIED": (("ARMED", "CONFIRMED"), True),
            "FIREWALL_CONFIRMED": ("CONFIRMED", False),
            "FIREWALL_ALREADY_CONFIRMED": ("CONFIRMED", False),
            "FIREWALL_ROLLED_BACK": ("ROLLED_BACK", False),
            "FIREWALL_ALREADY_ROLLED_BACK": ("ROLLED_BACK", False),
            "FIREWALL_STATUS": (FIREWALL_STATES, False),
        }
        requirement = requirements.get(value["code"])
        if requirement is None:
            raise Denied("SSH_FIREWALL_REPLY_INVALID")
        expected_state, digest_required = requirement
        if "state" not in value or (value["state"] not in expected_state
                                     if isinstance(expected_state, tuple)
                                     else value["state"] != expected_state):
            raise Denied("SSH_FIREWALL_REPLY_INVALID")
        if digest_required and "rules_digest" not in value:
            raise Denied("SSH_FIREWALL_REPLY_INVALID")
    return value


async def exchange_firewall(target, key, known_hosts, request):
    connection = await connect(target, key, known_hosts, FIREWALL_USER)
    try:
        process = await connection.create_process("vpn-orbit.v1.firewall", input=canonical(request) + b"\n",
                                                  encoding=None, request_pty=False)
        output, error, _ = await asyncio.gather(
            bounded_read(process.stdout, 8192), bounded_read(process.stderr, 2048), process.wait_closed())
        if error:
            raise Denied("SSH_FIREWALL_REPLY_INVALID")
        value = decode(output.rstrip(b"\n"), canonical_required=False)
        return firewall_reply(value, process.exit_status)
    finally:
        connection.abort()


def _firewall_request(operation, payload):
    if operation == "apply":
        firewall_payload(payload)
        return {"operation": "apply", **payload}
    if operation == "confirm":
        fields(payload, ("operation_id", "rules_digest"))
        text(payload["operation_id"], ULID)
        text(payload["rules_digest"], SHA256)
        return {"operation": "confirm", **payload}
    if operation in ("rollback", "status"):
        fields(payload, ("operation_id",))
        text(payload["operation_id"], ULID)
        return {"operation": operation, **payload}
    raise Denied("RPC_INVALID_REQUEST")


def _firewall_call(target, private_key, known_hosts, request, *, timeout, code):
    try:
        return asyncio.run(asyncio.wait_for(
            exchange_firewall(target, validate_private_key(private_key), known_hosts, request), timeout))
    except (asyncssh.Error, OSError, TimeoutError):
        raise Denied(code) from None


def firewall(target, private_key, known_hosts, payload):
    return _firewall_call(target, private_key, known_hosts, _firewall_request("apply", payload),
                          timeout=90, code="SSH_FIREWALL_UNCONFIRMED")


def firewall_control(target, private_key, known_hosts, operation, payload):
    return _firewall_call(target, private_key, known_hosts, _firewall_request(operation, payload),
                          timeout=30, code="SSH_FIREWALL_CONTROL_UNCONFIRMED")


def firewall_status(target, private_key, known_hosts, operation_id):
    return firewall_control(target, private_key, known_hosts, "status", {"operation_id": operation_id})


def apply_firewall(target, private_key, known_hosts, payload):
    """Apply, prove a fresh SSH connection, then confirm or roll back.

    Confirmation and rollback are separate SSH connections. The remote helper
    also arms an independent host-local timer, so a lost Controller reply can
    never leave an unconfirmed ruleset installed.
    """
    reply = firewall(target, private_key, known_hosts, payload)
    if reply["outcome"] != "SUCCEEDED":
        return reply
    if reply.get("rules_digest") != payload["rules_digest"]:
        return {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_REPLY_DIGEST_MISMATCH"}
    operation = payload["operation_id"]
    if reply.get("state") == "CONFIRMED":
        return {"outcome": "SUCCEEDED", "code": "FIREWALL_ALREADY_CONFIRMED"}
    try:
        status = firewall_status(target, private_key, known_hosts, operation)
    except Denied:
        status = None
    if status is not None and status.get("rules_digest") != payload["rules_digest"]:
        status = None
    if status is not None and status.get("outcome") == "SUCCEEDED" and status.get("state") == "CONFIRMED":
        return {"outcome": "SUCCEEDED", "code": "FIREWALL_ALREADY_CONFIRMED"}
    if status is None or status.get("outcome") != "SUCCEEDED" or status.get("state") != "ARMED":
        try:
            rolled = firewall_control(target, private_key, known_hosts, "rollback", {"operation_id": operation})
        except Denied:
            rolled = None
        if rolled is not None and rolled.get("outcome") == "SUCCEEDED" and rolled.get("state") == "ROLLED_BACK":
            return {"outcome": "FAILED", "code": "FIREWALL_SSH_UNCONFIRMED_ROLLED_BACK"}
        return {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_SSH_UNCONFIRMED"}
    try:
        confirmed = firewall_control(target, private_key, known_hosts, "confirm",
                                     {"operation_id": operation, "rules_digest": payload["rules_digest"]})
    except Denied:
        return {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_CONFIRM_UNCONFIRMED"}
    if confirmed.get("outcome") != "SUCCEEDED" or confirmed.get("state") != "CONFIRMED":
        return {"outcome": "UNKNOWN_OUTCOME", "code": "FIREWALL_CONFIRM_UNCONFIRMED"}
    return {"outcome": "SUCCEEDED", "code": confirmed["code"]}


def parse_probe(output, *, now):
    # Arbitrary third-party stdout/stderr is never a public result, log payload or exception message.
    try:
        value = decode(output.rstrip(b"\n"))
    except Denied:
        raise Denied("SSH_UNSUPPORTED_OUTPUT") from None
    fields(value, ("v", "uid", "boot_id", "observed_at", "software", "docker", "compose"))
    if type(value["v"]) is not int or value["v"] != PROBE_VERSION or type(value["uid"]) is not int or value["uid"] != 0:
        raise Denied("SSH_PROBE_INVALID")
    text(value["boot_id"], r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    integer(value["observed_at"], now - 300, now + 2)
    return {"status": "REACHABLE", "source": "restricted_helper", "observed_at": value["observed_at"],
            "boot_id": value["boot_id"], "software": software_summary(value["software"]),
            "docker": docker_summary(value["docker"], complete=True), "compose": compose_summary(value["compose"])}


def provision_known_hosts(path, policy):
    new_private_file(path, "".join(f"vpn-orbit-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode())


def verify_known_hosts(path, policy):
    expected = "".join(f"vpn-orbit-{t.id} {t.value['host_key']}\n" for t in policy.targets.values()).encode()
    if protected_bytes(path, owner=os.geteuid(), exact_mode=0o600) != expected:
        raise Denied("SSH_PINNED_KEYS_INVALID")
