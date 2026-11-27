"""Durable, local-root execution of fixed Compose application operations.

No request contains shell commands, Compose fragments, image overrides or
filesystem paths. Configuration and receipts live in an administrator-owned
directory, outside the API and Worker.
"""

from contextlib import contextmanager
import argparse
from itertools import product
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time

from .app_profiles import PANEL_CA_FILE, canonical, digest, managed_files, render, validate
from .errors import Denied
from .runtime.storage import Journal, directory_sync, process_lock, protected_bytes


ROOT = Path("/var/lib/vpn-orbit-apps")
SYSTEM_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
SCHEMA = """
CREATE TABLE installation(id INTEGER PRIMARY KEY CHECK(id=1), spec_digest TEXT NOT NULL,
    owner TEXT NOT NULL, inventory TEXT, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE operations(id TEXT PRIMARY KEY, action TEXT NOT NULL, binding TEXT NOT NULL,
    state TEXT NOT NULL, code TEXT NOT NULL, resolution TEXT);
"""
ULID = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
ID = r"[0-9a-f]{64}"
DNS_LIST_FIELDS = ("Dns", "DnsOptions", "DnsSearch")


def refuse(code):
    raise Denied(code)


def private_directory(path, owner):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        refuse("APP_DIRECTORY_UNPROTECTED")


def atomic_write(path, data, *, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".app-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_sync(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def managed_contents(name, pem):
    if name != PANEL_CA_FILE:
        return pem.encode()
    # SSL_CERT_FILE replaces the default bundle. Keep the packaged public
    # trust roots so the same process can still verify Telegram HTTPS.
    system = protected_bytes(SYSTEM_CA_BUNDLE, owner=0, maximum=1024**2)
    if b"-----BEGIN CERTIFICATE-----" not in system:
        refuse("APP_SYSTEM_CA_UNAVAILABLE")
    return system.rstrip(b"\n") + b"\n" + pem.encode()


class Docker:
    def __call__(self, *args, timeout=120):
        try:
            result = subprocess.run(
                ["/usr/bin/docker", "--host", "unix:///run/docker.sock", *args],
                capture_output=True, timeout=timeout,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent",
                     "LANG": "C.UTF-8", "DOCKER_CONFIG": "/var/empty/vpn-orbit-apps"},
            )
        except (OSError, subprocess.SubprocessError):
            refuse("APP_DOCKER_UNAVAILABLE")
        if result.returncode or len(result.stdout) > 4 * 1024**2:
            # Docker stdout/stderr can contain environment values and credentials.
            refuse("APP_DOCKER_FAILED")
        return result.stdout.decode()


class Lifecycle:
    def __init__(self, identity, *, root=ROOT, docker=None, owner=0):
        if not isinstance(identity, str) or re.fullmatch(ULID, identity) is None:
            refuse("APP_ID_INVALID")
        self.root, self.identity, self.owner = Path(root), identity, owner
        private_directory(self.root, owner)
        self.directory = self.root / identity
        private_directory(self.directory, owner)
        self.journal = Journal(self.directory / "lifecycle.sqlite3")
        self.docker = docker or Docker()

    @classmethod
    def configure(cls, spec, *, root=ROOT, owner=0):
        validate(spec)
        root = Path(root)
        # Parent directories must be real, trusted directories. Never adopt or
        # chmod an existing installation or foreign system path.
        for parent in (root.parent, *root.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
                refuse("APP_PARENT_UNPROTECTED")
        root.mkdir(mode=0o700, exist_ok=True)
        private_directory(root, owner)
        directory = root / spec["id"]
        directory.mkdir(mode=0o700, exist_ok=False)
        private_directory(directory, owner)
        atomic_write(directory / "spec.json", canonical(spec))
        journal = Journal.initialize(directory / "lifecycle.sqlite3", SCHEMA)
        token = secrets.token_hex(32)
        with journal.write() as db:
            db.execute("INSERT INTO installation(id,spec_digest,owner) VALUES(1,?,?)", (digest(spec), token))
        for name, contents in managed_files(spec).items():
            # The Bot reads its public CA certificate as an unprivileged user.
            mode = 0o644 if name == PANEL_CA_FILE else 0o600
            atomic_write(directory / name, managed_contents(name, contents), mode=mode)
        atomic_write(directory / "compose.json", canonical(render(spec, token)))
        directory_sync(root)
        return spec["id"]

    @contextmanager
    def locked(self):
        with process_lock(self.root / "lifecycle.lock"):
            yield

    def configuration(self):
        spec = json.loads(protected_bytes(self.directory / "spec.json", owner=self.owner,
                                         private=True, maximum=65536))
        validate(spec)
        with self.journal.connect() as db:
            row = db.execute("SELECT * FROM installation WHERE id=1").fetchone()
        if row is None or spec["id"] != self.identity or row["spec_digest"] != digest(spec):
            refuse("APP_CONFIG_DRIFT")
        expected = render(spec, row["owner"])
        if protected_bytes(self.directory / "compose.json", owner=self.owner, private=True, maximum=131072) != canonical(expected):
            refuse("APP_CONFIG_DRIFT")
        for name, value in managed_files(spec).items():
            public_ca = name == PANEL_CA_FILE
            if protected_bytes(self.directory / name, owner=self.owner, private=not public_ca,
                               maximum=2 * 1024**2 if public_ca else 16384,
                               exact_mode=0o644 if public_ca else None) != managed_contents(name, value):
                refuse("APP_CONFIG_DRIFT")
        return spec, expected, dict(row)

    def compose(self, document, *args, timeout=180):
        return self.docker("compose", "--project-name", document["name"], "--project-directory", str(self.directory),
                           "--file", str(self.directory / "compose.json"), *args, timeout=timeout)

    def inspect(self, kind, identity):
        if kind == "container" and re.fullmatch(ID, identity) is None:
            refuse("APP_CONTAINER_ID_INVALID")
        values = json.loads(self.docker(kind, "inspect", identity))
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            refuse("APP_INSPECT_INVALID")
        return values[0]

    def acquire_image(self, reference):
        repository, pin = reference.split("@", 1)
        # Docker may omit the canonical Docker Hub prefix in RepoDigests.
        aliases = {reference}
        if repository.startswith("docker.io/"):
            short = repository.removeprefix("docker.io/")
            aliases.add(short + "@" + pin)
            if short.startswith("library/"):
                aliases.add(short.removeprefix("library/") + "@" + pin)
        try:
            image = self.inspect("image", reference)
        except Denied as error:
            if error.code != "APP_DOCKER_FAILED":
                raise
        else:
            if (image.get("Os") == "linux" and image.get("Architecture") == "amd64"
                    and aliases.intersection(image.get("RepoDigests") or ())):
                return
        self.docker("pull", "--platform", "linux/amd64", reference, timeout=600)

    @staticmethod
    def stable(container, *, expected=None):
        # Runtime counters, PIDs and health transitions are intentionally excluded.
        # Security configuration, exact image identity and mounts are included.
        host = dict(container["HostConfig"])
        # Engine 29 can normalize the default false pointer to null on start.
        if host.get("OomKillDisable") is None:
            host["OomKillDisable"] = False
        # Engine 29 can replace null DNS lists with empty lists on daemon
        # restart. Neither sets an override. Preserve all nonempty values.
        unset_dns = [key for key in DNS_LIST_FIELDS if key in host and host[key] in (None, [])]
        for key in unset_dns:
            host[key] = None
        configuration = {"Image": container["Image"], "Config": container["Config"],
                         "HostConfig": host, "Mounts": sorted(container.get("Mounts", []), key=canonical)}
        current = digest(configuration)
        if unset_dns and expected is not None and current != expected:
            # Older journals can contain hashes of either representation.
            for defaults in product((None, []), repeat=len(unset_dns)):
                host.update(zip(unset_dns, defaults, strict=True))
                if digest(configuration) == expected:
                    return {"Id": container["Id"], "configuration": expected}
        return {"Id": container["Id"], "configuration": current}

    def inventory(self, document, *, complete=True, expected_containers=None):
        containers, volumes, networks = {}, {}, {}
        expected_containers = expected_containers or {}
        selector = "label=com.docker.compose.project=" + document["name"]
        found = self.docker("container", "ls", "--all", "--quiet", "--no-trunc", "--filter", selector).split()
        for identity in found:
            value = self.inspect("container", identity)
            labels = value["Config"].get("Labels", {})
            name = labels.get("com.vpn-orbit.service")
            service = document["services"].get(name)
            if service is None or name in containers or any(labels.get(k) != v for k, v in service["labels"].items()):
                refuse("APP_OWNERSHIP_UNVERIFIED")
            if labels.get("com.docker.compose.project") != document["name"] or labels.get("com.docker.compose.service") != name:
                refuse("APP_OWNERSHIP_UNVERIFIED")
            # Image identity is resolved from the exact repository digest.
            image = self.inspect("image", service["image"])
            if value.get("Image") != image.get("Id") or value["Config"].get("Image") != service["image"]:
                refuse("APP_IMAGE_DRIFT")
            attached = value.get("NetworkSettings", {}).get("Networks", {})
            expected_networks = ({"host"} if service.get("network_mode") == "host"
                                 else {document["networks"][key]["name"] for key in service["networks"]})
            if set(attached) - expected_networks or (value["State"]["Running"] and set(attached) != expected_networks):
                refuse("APP_NETWORK_DRIFT")
            stored = expected_containers.get(name, {})
            match = stored.get("configuration") if stored.get("Id") == identity else None
            containers[name] = self.stable(value, expected=match)
        if complete and set(containers) != set(document["services"]):
            refuse("APP_SERVICE_SET_DRIFT")
        for name, requested in document["volumes"].items():
            value = self.inspect("volume", requested["name"])
            if value.get("Driver") != "local" or value.get("Options") not in (None, {}):
                refuse("APP_VOLUME_DRIFT")
            labels = value.get("Labels") or {}
            if any(labels.get(k) != v for k, v in requested["labels"].items()):
                refuse("APP_OWNERSHIP_UNVERIFIED")
            volumes[name] = {key: value.get(key) for key in ("Name", "Driver", "Mountpoint", "Labels", "Options")}
        for name, requested in document["networks"].items():
            value = self.inspect("network", requested["name"])
            labels = value.get("Labels") or {}
            if value.get("Driver") != "bridge" or any(labels.get(k) != v for k, v in requested["labels"].items()):
                refuse("APP_OWNERSHIP_UNVERIFIED")
            if set(value.get("Containers") or {}) - {entry["Id"] for entry in containers.values()}:
                refuse("APP_NETWORK_SHARED")
            networks[name] = {key: value.get(key) for key in ("Id", "Name", "Driver", "Internal", "Labels", "Options", "IPAM")}
        return {"containers": containers, "volumes": volumes, "networks": networks}

    def verify_inventory(self, document, installation, *, allow_missing=False):
        if installation["inventory"] is None:
            refuse("APP_OWNERSHIP_UNVERIFIED")
        saved = json.loads(installation["inventory"])
        current = self.inventory(document, complete=not allow_missing, expected_containers=saved["containers"])
        if current["volumes"] != saved["volumes"] or current["networks"] != saved["networks"]:
            refuse("APP_RESOURCE_DRIFT")
        for name, container in current["containers"].items():
            if container != saved["containers"].get(name):
                refuse("APP_CONTAINER_DRIFT")
        if allow_missing and set(current["containers"]) != set(saved["containers"]):
            all_ids = set(self.docker("container", "ls", "--all", "--quiet", "--no-trunc").split())
            if any(saved["containers"][name]["Id"] in all_ids
                   for name in set(saved["containers"]) - set(current["containers"])):
                refuse("APP_CONTAINER_DRIFT")
        owned = {value["Id"] for value in current["containers"].values()}
        for volume in current["volumes"].values():
            users = self.docker("container", "ls", "--all", "--quiet", "--no-trunc",
                                "--filter", "volume=" + volume["Name"]).split()
            if set(users) - owned:
                refuse("APP_VOLUME_SHARED")
        return current

    def healthy(self, inventory):
        for container in inventory["containers"].values():
            state = self.inspect("container", container["Id"]).get("State", {})
            if state.get("Running") is not True or state.get("Health", {}).get("Status") != "healthy":
                return False
        return bool(inventory["containers"])

    @staticmethod
    def batches(document):
        remaining = set(document["services"])
        finished = set()
        while remaining:
            ready = sorted(name for name in remaining
                           if set(document["services"][name].get("depends_on", {})) <= finished)
            if not ready:
                refuse("APP_DEPENDENCY_CYCLE")
            yield ready
            finished.update(ready)
            remaining.difference_update(ready)

    def start(self, document, inventory):
        deadline = time.monotonic() + 150
        for ready in self.batches(document):
            batch = {name: inventory["containers"][name] for name in ready}
            self.docker("container", "start", *(value["Id"] for value in batch.values()), timeout=45)
            while not self.healthy({"containers": batch}):
                if time.monotonic() >= deadline:
                    refuse("APP_HEALTH_UNVERIFIED")
                time.sleep(1)

    def finish(self, operation, state, code):
        with self.journal.write() as db:
            db.execute("UPDATE operations SET state=?,code=? WHERE id=?", (state, code, operation))
        return {"operation_id": operation, "outcome": state, "code": code}

    def status(self):
        with self.locked():
            if os.path.lexists(self.directory / "restore.pending"):
                return {"state": "UNKNOWN_OUTCOME", "code": "APP_RESTORE_INCOMPLETE"}
            _, document, installation = self.configuration()
            with self.journal.connect() as db:
                unknown = db.execute("""SELECT id FROM operations WHERE resolution IS NULL
                                     AND state IN ('DISPATCHING','UNKNOWN_OUTCOME')""").fetchall()
            if unknown:
                return {"state": "UNKNOWN_OUTCOME", "operations": [row["id"] for row in unknown]}
            if installation["inventory"] is None:
                return {"state": "CONFIGURED", "spec_digest": installation["spec_digest"]}
            current = self.verify_inventory(document, installation, allow_missing=bool(installation["removed"]))
            return {"state": "REMOVED" if installation["removed"] else ("HEALTHY" if self.healthy(current) else "UNHEALTHY"),
                    "spec_digest": installation["spec_digest"]}

    def execute(self, operation, action, binding):
        if not isinstance(operation, str) or re.fullmatch(ULID, operation) is None:
            refuse("APP_OPERATION_INVALID")
        if action not in ("install", "start", "remove"):
            refuse("APP_ACTION_INVALID")
        with self.locked():
            if os.path.lexists(self.directory / "restore.pending"):
                refuse("APP_RESTORE_INCOMPLETE")
            spec, document, installation = self.configuration()
            if binding != digest(spec):
                refuse("APP_CONFIG_DRIFT")
            with self.journal.connect() as db:
                old = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
                unknown = db.execute("""SELECT id FROM operations WHERE resolution IS NULL
                                     AND state IN ('DISPATCHING','UNKNOWN_OUTCOME')""").fetchone()
            if old:
                if (old["action"], old["binding"]) != (action, binding):
                    refuse("APP_IDEMPOTENCY_CONFLICT")
                if old["resolution"]:
                    return {"operation_id": operation, "outcome": old["resolution"], "code": "APP_READBACK_VERIFIED"}
                if old["state"] == "DISPATCHING":
                    return self.finish(operation, "UNKNOWN_OUTCOME", "APP_INTERRUPTED")
                return {"operation_id": operation, "outcome": old["state"], "code": old["code"]}
            if unknown:
                refuse("APP_RECONCILIATION_REQUIRED")
            if installation["removed"]:
                refuse("APP_INSTALLATION_REMOVED")
            if installation["inventory"] is not None:
                current = self.verify_inventory(document, installation)
            else:
                if action != "install":
                    refuse("APP_NOT_INSTALLED")
                # Prevent adoption of pre-existing project names and volume/network names.
                existing = self.docker("container", "ls", "--all", "--quiet", "--filter",
                                       "label=com.docker.compose.project=" + document["name"])
                for kind, key in (("volume", "volumes"), ("network", "networks")):
                    names = set(self.docker(kind, "ls", "--format", "{{.Name}}").splitlines())
                    if any(item["name"] in names for item in document[key].values()):
                        refuse("APP_FOREIGN_RESOURCE")
                if existing.strip():
                    refuse("APP_FOREIGN_RESOURCE")
                current = None
            with self.journal.write() as db:
                db.execute("""INSERT INTO operations(id,action,binding,state,code)
                              VALUES(?,?,?,'DISPATCHING','APP_PENDING')""", (operation, action, binding))
            unverified = "APP_EFFECT_UNVERIFIED"
            try:
                if current is None:
                    unverified = "APP_IMAGE_PULL_UNVERIFIED"
                    for image in sorted(set(spec["images"].values())):
                        self.acquire_image(image)
                    unverified = "APP_COMPOSE_CREATE_UNVERIFIED"
                    self.compose(document, "create", "--no-build", "--pull", "never")
                    unverified = "APP_INVENTORY_UNVERIFIED"
                    current = self.inventory(document)
                    with self.journal.write() as db:
                        db.execute("UPDATE installation SET inventory=? WHERE id=1", (canonical(current).decode(),))
                    installation["inventory"] = canonical(current).decode()
                    unverified = "APP_EFFECT_UNVERIFIED"
                if action == "remove":
                    # Stop and remove only recorded full container IDs. Never execute
                    # compose down, delete volumes, or delete a shared network.
                    for batch in reversed(list(self.batches(document))):
                        for name in batch:
                            identity = current["containers"][name]["Id"]
                            self.verify_inventory(document, installation, allow_missing=True)
                            self.docker("container", "stop", "--time", "30", identity, timeout=45)
                            self.verify_inventory(document, installation, allow_missing=True)
                            self.docker("container", "rm", identity)
                    if self.verify_inventory(document, installation, allow_missing=True)["containers"]:
                        refuse("APP_REMOVAL_UNVERIFIED")
                    with self.journal.write() as db:
                        db.execute("UPDATE installation SET removed=1 WHERE id=1")
                else:
                    self.start(document, current)
                    current = self.verify_inventory(document, installation)
                    if not self.healthy(current):
                        refuse("APP_HEALTH_UNVERIFIED")
                return self.finish(operation, "SUCCEEDED", "APP_REMOVED_DATA_PRESERVED" if action == "remove" else "APP_HEALTH_VERIFIED")
            except Exception as error:
                if isinstance(error, Denied) and error.code == "APP_HEALTH_UNVERIFIED":
                    unverified = error.code
                return self.finish(operation, "UNKNOWN_OUTCOME", unverified)

    def reconcile(self, operation):
        if not isinstance(operation, str) or re.fullmatch(ULID, operation) is None:
            refuse("APP_OPERATION_INVALID")
        with self.locked():
            _, document, installation = self.configuration()
            with self.journal.connect() as db:
                row = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
            if row is None:
                refuse("APP_OPERATION_NOT_FOUND")
            if row["resolution"]:
                return {"operation_id": operation, "outcome": row["resolution"], "code": "APP_READBACK_VERIFIED"}
            if row["state"] not in ("DISPATCHING", "UNKNOWN_OUTCOME"):
                return {"operation_id": operation, "outcome": row["state"], "code": row["code"]}
            # Readback only. Incomplete create inventory cannot be adopted from labels.
            try:
                current = self.verify_inventory(document, installation, allow_missing=row["action"] == "remove")
            except Denied:
                return {"operation_id": operation, "outcome": "UNKNOWN_OUTCOME", "code": "APP_QUARANTINED"}
            succeeded = not current["containers"] if row["action"] == "remove" else self.healthy(current)
            if not succeeded:
                return {"operation_id": operation, "outcome": "UNKNOWN_OUTCOME", "code": "APP_QUARANTINED"}
            with self.journal.write() as db:
                if row["action"] == "remove":
                    db.execute("UPDATE installation SET removed=1 WHERE id=1")
                db.execute("""UPDATE operations SET state='UNKNOWN_OUTCOME',resolution='RECONCILED_SUCCEEDED'
                              WHERE id=?""", (operation,))
            return {"operation_id": operation, "outcome": "RECONCILED_SUCCEEDED", "code": "APP_READBACK_VERIFIED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("configure", "stage-adoption", "install", "start", "status", "remove", "reconcile"))
    parser.add_argument("--id")
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--operation")
    parser.add_argument("--digest")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            refuse("LOCAL_ROOT_REQUIRED")
        if args.action in ("configure", "stage-adoption"):
            if args.spec is None:
                refuse("APP_SPEC_REQUIRED")
            value = json.loads(protected_bytes(args.spec, owner=0, private=True, maximum=65536))
            if args.action == "stage-adoption":
                from .app_adoption import ExternalLifecycle
                result = ExternalLifecycle.stage(value)
            else:
                result = {"installation_id": Lifecycle.configure(value)}
        else:
            runtime = Lifecycle(args.id)
            if args.action == "status" and (runtime.directory / "external.json").exists():
                from .app_adoption import ExternalLifecycle
                runtime = ExternalLifecycle(args.id)
            if args.action == "status":
                result = runtime.status()
            elif args.action == "reconcile":
                result = runtime.reconcile(args.operation)
            else:
                result = runtime.execute(args.operation, args.action, args.digest)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Denied as error:
        # All Denied codes originate in protected storage and lifecycle checks.
        print(json.dumps({"outcome": "DENIED", "code": error.code}))
        return 1
    except (OSError, ValueError, KeyError):
        # Never forward input values, subprocess output or configuration contents.
        print(json.dumps({"outcome": "DENIED", "code": "APP_REQUEST_REFUSED"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
