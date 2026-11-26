"""Host-installed service entry points driven by root-owned configuration."""

import argparse
from contextlib import contextmanager
from getpass import GetPassWarning, getpass
import os
import json
from pathlib import Path
import resource
import signal
import sqlite3
import sys
from threading import Event
import warnings

from ..admission import Admission
from ..config import Settings
from ..database import DataAccess, Store, identifier
from ..errors import Denied
from ..queue import JobQueue
from ..worker import Worker
from .authority import Authority, verify_host_time
from .ipc import Client, activated_socket, serve
from .policy import Policy
from .protocol import ULID, checksum, fields, integer, text, decode
from .storage import new_private_file, process_lock, protected_bytes
from .vault import Vault
from .timehealth import TimeHealth
from .credentials import initialize_credential


@contextmanager
def worker_shutdown():
    """PID 1 must handle TERM explicitly; release its lock only after the job."""
    stop, previous = Event(), {}
    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, lambda *_: stop.set())
        yield stop
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def configuration(path):
    value = decode(protected_bytes(path, owner=0, maximum=16384), canonical_required=False)
    fields(value, ("v", "database", "app_uid", "app_gid", "worker_uid", "worker_gid", "broker_uid", "broker_gid",
                   "broker_rpc_gid", "gate_rpc_gid", "public_origin", "trusted_proxies", "api_port", "targets",
                   "supervisor_directory", "broker_directory", "vault_directory", "vault_credential", "public_verify_key",
                   "gate_socket", "broker_socket", *(name for name in ("api_bind", "writer_directory", "enrollment_catalog",
                                                                       "preparation_catalog") if name in value)))
    if type(value["v"]) is not int or value["v"] != 1:
        raise Denied("RUNTIME_CONFIG_INVALID")
    for key in ("app_uid", "app_gid", "worker_uid", "worker_gid", "broker_uid", "broker_gid", "broker_rpc_gid", "gate_rpc_gid"):
        integer(value[key], 1, 2**31 - 1)
    if len({value[k] for k in ("app_uid", "worker_uid", "broker_uid")}) != 3 or len({value[k] for k in ("app_gid", "broker_rpc_gid", "gate_rpc_gid")}) != 3:
        raise Denied("RUNTIME_IDENTITIES_OVERLAP")
    for key in ("database", "targets", "supervisor_directory", "broker_directory", "vault_directory", "vault_credential", "public_verify_key", "gate_socket", "broker_socket"):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute() or ".." in Path(value[key]).parts:
            raise Denied("RUNTIME_PATH_INVALID")
    if "writer_directory" in value:
        path = value["writer_directory"]
        if not isinstance(path, str) or not Path(path).is_absolute() or ".." in Path(path).parts:
            raise Denied("RUNTIME_PATH_INVALID")
    integer(value["api_port"], 1024, 65535)
    if value.get("api_bind", "127.0.0.1") not in ("127.0.0.1", "0.0.0.0"):
        raise Denied("API_BIND_INVALID")
    Settings(Path(value["database"]), value["public_origin"], tuple(value["trusted_proxies"]), value["app_uid"], value["app_gid"])
    return value


def run(config, command, *, once=False, listener=None, import_args=None):
    expected = {"supervisor": 0, "initialize-supervisor": 0, "api": config["app_uid"], "worker": config["worker_uid"],
                "broker": config["broker_uid"], "initialize-broker": config["broker_uid"], "import-key": config["broker_uid"],
                "rotate-key": config["broker_uid"], "revoke-key": config["broker_uid"],
                "import-restart-key": config["broker_uid"],
                 "import-firewall-key": config["broker_uid"],
                 "import-application-key": config["broker_uid"],
                "enrollment-catalog": 0, "register-observations": 0, "initialize-time-health": 0, "time-health": 0,
                "initialize-credential": 0, "initialize-writers": 0,
                "prepare-observation": 0, "reconcile-preparation": 0}[command]
    if os.geteuid() != expected:
        raise Denied("LOCAL_SERVICE_IDENTITY_INVALID")
    access = DataAccess(config["app_uid"], config["app_gid"])
    writers = Admission(config["writer_directory"]) if "writer_directory" in config else None
    if command == "initialize-writers":
        if writers is None:
            raise Denied("WRITER_CONFIGURATION_REQUIRED")
        writers = Admission.initialize(config["writer_directory"])
        writers.publish("OPEN")
        return
    if command == "initialize-credential":
        initialize_credential(config)
        return
    if command == "time-health":
        envelope = Client(config["gate_socket"], server_uids={0}).call("time.health", {})
        report = verify_host_time(envelope, protected_bytes(config["public_verify_key"], owner=0, maximum=32))
        print(json.dumps(report))
        return
    if command == "api":
        from ..api import create_app
        import uvicorn
        with Store(config["database"], access=access, writers=writers).connect():
            pass
        settings = Settings(Path(config["database"]), config["public_origin"], tuple(config["trusted_proxies"]), access.owner_uid,
                            access.shared_gid, Path(config["writer_directory"]) if writers else None)
        preparation = config.get("preparation_catalog")
        client = Client(config["broker_socket"], server_uids={0, config["broker_uid"]}, timeout=5) if preparation else None
        uvicorn.run(create_app(settings, enrollment_catalog=config.get("enrollment_catalog"),
                               preparation_catalog=preparation, preparation_broker=client), host=config.get("api_bind", "127.0.0.1"),
                    port=config["api_port"], proxy_headers=False, access_log=False)
        return
    policy = Policy.load(config["targets"], owner=0)
    if command == "enrollment-catalog":
        print(json.dumps(policy.enrollment_catalog(ssh_endpoints=getattr(import_args, "ssh_endpoints", False),
                                                   preparation=getattr(import_args, "preparation", False))))
        return
    if command == "initialize-time-health":
        with Authority(config["supervisor_directory"], policy).journal.connect():
            pass
        health = TimeHealth.initialize(Path(config["supervisor_directory"]) / "time-health")
        health.close()
        return
    if command == "initialize-supervisor":
        authority = Authority.initialize(config["supervisor_directory"], policy)
        new_private_file(config["public_verify_key"], bytes(authority.key.verify_key))
        Path(config["public_verify_key"]).chmod(0o644)
        return
    if command == "supervisor":
        authority = Authority(config["supervisor_directory"], policy, writers=writers)
        def dispatch(*args):
            return authority.dispatch(*args)

        def poll():
            authority.poll_time()

        identities = {(config["worker_uid"], config["worker_gid"]): "worker", (config["broker_uid"], config["broker_gid"]): "broker", (0, 0): "updater"}
        with process_lock(Path(config["supervisor_directory"]) / "authority.lock"):
            try:
                authority.recover()
                serve(listener or activated_socket(config["gate_socket"]), dispatch, identities, poll=poll)
            finally:
                authority.close()
        return
    if command == "register-observations":
        queue = JobQueue(Store(config["database"], access=access, writers=writers))
        for target in policy.targets.values():
            if "host.prepare" not in target.value["capabilities"]:
                queue.register_resource(target.id, target.scope_digest, target.revision)
        return
    if command in ("prepare-observation", "reconcile-preparation"):
        queue = JobQueue(Store(config["database"], access=access, writers=writers))
        prepare_observation(config, policy, queue, command, import_args)
        return
    if command == "worker":
        worker = Worker(JobQueue(Store(config["database"], access=access, writers=writers)), Client(config["gate_socket"], server_uids={0}),
                        Client(config["broker_socket"], server_uids={0, config["broker_uid"]},
                               timeout=940 if any("apps.lifecycle" in t.value["capabilities"] for t in policy.targets.values()) else 160),
                        secret_refs={t.id: t.value["secret_ref"] for t in policy.targets.values()},
                        restart_refs={t.id: t.value["restart_secret_ref"] for t in policy.targets.values()
                                      if "docker.restart" in t.value["capabilities"]},
                        firewall_refs={t.id: t.value["firewall_secret_ref"] for t in policy.targets.values()
                                       if "firewall.apply" in t.value["capabilities"]},
                        application_refs={t.id: t.value["application_secret_ref"] for t in policy.targets.values()
                                          if "apps.lifecycle" in t.value["capabilities"]})
        with worker_shutdown() as stop:
            return worker.run(once=once, stop=stop)
    managed_credential = "CREDENTIALS_DIRECTORY" in os.environ
    credential = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "broker-dek" if managed_credential else Path(config["vault_credential"])
    if command == "initialize-broker":
        from .broker import Broker
        Vault.initialize(config["vault_directory"], credential, systemd_credential=managed_credential)
        Broker.initialize(config["broker_directory"], policy)
        return
    vault = Vault(config["vault_directory"], credential, systemd_credential=managed_credential, writers=writers)
    if command in {"rotate-key", "revoke-key"}:
        if writers is None:
            raise Denied("WRITER_CONFIGURATION_REQUIRED")
        purpose = import_args.purpose
        target = policy.targets.get(import_args.target)
        scope = target.value if target and purpose in target.value["capabilities"] else {}
        consumer = config["worker_uid"]
        ref_field = {"docker.restart": "restart_secret_ref", "firewall.apply": "firewall_secret_ref",
                     "apps.lifecycle": "application_secret_ref"}.get(purpose, "secret_ref")
        if (scope.get("id") != import_args.target
                or scope.get("policy_revision") != import_args.policy_revision):
            raise Denied("SECRET_SCOPE_DENIED")
        key = (protected_bytes(import_args.key_file, owner=config["broker_uid"], maximum=8192, private=True)
               if command == "rotate-key" else None)
        replacement = vault.change_key(import_args.reference, anchor=scope[ref_field], scope_digest=checksum(scope),
                                       purpose=purpose, target=import_args.target,
                                       consumer_uid=consumer, policy_revision=import_args.policy_revision, key=key)
        print(replacement or "REVOKED")
        return
    if command in {"import-key", "import-restart-key", "import-firewall-key", "import-application-key"}:
        key = protected_bytes(import_args.key_file, owner=config["broker_uid"], maximum=8192, private=True)
        if command == "import-key":
            reference = vault.import_ssh(import_args.secret_id, import_args.version, key, owner_id=import_args.owner_id,
                                         worker_uid=config["worker_uid"], target=import_args.target, policy_revision=import_args.policy_revision)
        else:
            field, import_key = {
                "import-restart-key": ("restart_secret_ref", vault.import_restart_ssh),
                "import-firewall-key": ("firewall_secret_ref", vault.import_firewall_ssh),
                "import-application-key": ("application_secret_ref", vault.import_application_ssh),
            }[command]
            target = policy.targets.get(import_args.target)
            if (target is None or target.value.get(field) != f"{import_args.secret_id}:v{import_args.version}"
                    or target.revision != import_args.policy_revision):
                raise Denied("CAPABILITY_DISABLED")
            reference = import_key(import_args.secret_id, import_args.version, key, owner_id=import_args.owner_id,
                                   worker_uid=config["worker_uid"], target=import_args.target,
                                   policy_revision=import_args.policy_revision)
        print(reference)
        return
    from .broker import Broker
    gate = Client(config["gate_socket"], server_uids={0})
    verify_key = protected_bytes(config["public_verify_key"], owner=0, maximum=32)
    identities = {(config["worker_uid"], config["worker_gid"]): "worker", (0, 0): "local-root"}
    preparation = config.get("preparation_catalog") or {}
    if preparation:
        identities[config["app_uid"], config["app_gid"]] = "preparation-api"
    broker = Broker(config["broker_directory"], policy, vault, gate, verify_key, worker_uid=config["worker_uid"], writers=writers,
                    web_preparation_targets=preparation.keys())
    with process_lock(Path(config["broker_directory"]) / "broker.lock"):
        broker.recover()
        serve(listener or activated_socket(config["broker_socket"]), broker.dispatch, identities)


def prepare_observation(config, policy, queue, command, args):
    target = policy.targets.get(text(args.target, ULID))
    if target is None or "host.prepare" not in target.value["capabilities"]:
        raise Denied("CAPABILITY_DISABLED")
    if command == "prepare-observation":
        job_id, actor = identifier(), queue.preparation_owner()
    else:
        job_id = args.job
        actor = queue.preparation_incident(job_id, target)["actor_id"]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    password = private_key = None
    if args.admin_key_file:
        private_key = protected_bytes(args.admin_key_file, owner=0, maximum=8192, private=True).decode("utf-8")
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            try:
                password = getpass("VPS SSH password: ")
            except (GetPassWarning, EOFError):
                raise Denied("SSH_INTERACTIVE_CREDENTIAL_REQUIRED") from None
    payload = {"job_id": job_id, "target": target.id, "actor_id": actor, "scope_digest": target.scope_digest,
               "username": args.user, "password": password, "private_key": private_key}
    broker = Client(config["broker_socket"], server_uids={0, config["broker_uid"]}, timeout=135)
    if command == "prepare-observation":
        broker.call("prepare.credentials", payload)
        result = queue.enqueue_preparation(job_id, actor, target)
    else:
        receipt = broker.call("prepare.reconcile", payload)
        result = queue.reconcile_preparation(job_id, target, receipt)
    print(json.dumps(result))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vpn-orbit-runtime")
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize-supervisor", "initialize-broker", "initialize-credential", "initialize-writers", "initialize-time-health", "time-health",
                 "register-observations", "supervisor", "broker", "api"):
        commands.add_parser(name)
    catalog = commands.add_parser("enrollment-catalog")
    catalog.add_argument("--ssh-endpoints", action="store_true")
    catalog.add_argument("--preparation", action="store_true")
    worker = commands.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    for name in ("prepare-observation", "reconcile-preparation"):
        preparation = commands.add_parser(name)
        preparation.add_argument("--target", required=True)
        preparation.add_argument("--user", required=True)
        preparation.add_argument("--admin-key-file", type=Path)
        if name == "reconcile-preparation":
            preparation.add_argument("--job", required=True)
    key = commands.add_parser("import-key")
    key.add_argument("--key-file", type=Path, required=True)
    key.add_argument("--secret-id", required=True)
    key.add_argument("--owner-id", required=True)
    key.add_argument("--target", required=True)
    key.add_argument("--version", type=int, default=1)
    key.add_argument("--policy-revision", type=int, default=1)
    commands.add_parser("import-restart-key", parents=[key], add_help=False,
                                      help="Provision a dedicated Docker restart credential")
    commands.add_parser("import-firewall-key", parents=[key], add_help=False,
                                      help="Provision a dedicated typed firewall credential")
    commands.add_parser("import-application-key", parents=[key], add_help=False,
                                      help="Provision a dedicated typed application credential")
    for name in ("rotate-key", "revoke-key"):
        lifecycle = commands.add_parser(name, help="Retire the exact credential selected by the protected target policy")
        lifecycle.add_argument("--purpose", choices=("host.probe", "docker.restart", "firewall.apply", "apps.lifecycle"), required=True)
        lifecycle.add_argument("--target", required=True)
        lifecycle.add_argument("--reference", required=True)
        lifecycle.add_argument("--policy-revision", type=int, required=True)
        if name == "rotate-key":
            lifecycle.add_argument("--key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        run(configuration(args.config), args.command, once=getattr(args, "once", False), import_args=args)
    except (Denied, OSError, RuntimeError, ValueError, sqlite3.Error, TypeError, KeyError) as error:
        print(error.code if isinstance(error, Denied) else "RUNTIME_UNAVAILABLE", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
