"""Protected lifecycle operations for an existing Docker Compose project."""

from contextlib import ExitStack
from datetime import datetime
from hashlib import sha256
from importlib.resources import files
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import tempfile
import time
from urllib.parse import urlsplit

from .adoption import daemon_identity
from .app_lifecycle import Lifecycle, ROOT, SCHEMA, atomic_write, private_directory, refuse
from .app_profiles import CABINET_CONFIG, canonical, digest, panel_origin
from .errors import Denied
from .runtime.protocol import (
    ADOPTED_NODE_ACTIONS, APPLICATION_SUCCESS, COMPOSE_PROJECT, COMPOSE_SERVICE, DOCKER_RESOURCE,
    DOCKER_STARTED_AT, NEW_RUN_ADOPTED_ACTIONS, RESTART_ADOPTED, RUN_BOUND_ADOPTED_ACTIONS,
    SHA256, START_ADOPTED, STOP_ADOPTED, ULID,
)
from .runtime.storage import Journal, directory_sync, process_lock, protected_bytes


EXTERNAL_ACTIONS = {action: APPLICATION_SUCCESS[action][0] for action in ("adopt", "detach", *ADOPTED_NODE_ACTIONS)}
NODE_PERMISSION = {START_ADOPTED: "allow_start", STOP_ADOPTED: "allow_stop", RESTART_ADOPTED: "allow_restart"}
NODE_UNSUPPORTED = {
    START_ADOPTED: "APP_ADOPTED_START_UNSUPPORTED",
    STOP_ADOPTED: "APP_ADOPTED_STOP_UNSUPPORTED",
    RESTART_ADOPTED: "APP_ADOPTED_RESTART_UNSUPPORTED",
}
NODE_UNVERIFIED = {
    START_ADOPTED: "APP_ADOPTED_START_UNVERIFIED",
    STOP_ADOPTED: "APP_ADOPTED_STOP_UNVERIFIED",
    RESTART_ADOPTED: "APP_ADOPTED_RESTART_UNVERIFIED",
}
BUILTIN_NETWORKS = {"bridge", "host", "none"}
LAYOUT_FIELDS = {"version", "id", "project", "compose_files", "extra_files", "service_hashes"}


def source_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value.encode()) > 256
            or "," in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        refuse("APP_SOURCE_UNVERIFIED")
    parts = value[1:].split("/")
    if len(parts) > 12 or any(part in ("", ".", "..") for part in parts):
        refuse("APP_SOURCE_UNVERIFIED")
    return parts


def source_digest(path):
    """Hash a protected file through directory descriptors without following links."""
    parts = source_path(path)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with ExitStack() as stack:
            parent = os.open("/", directory_flags)
            stack.callback(os.close, parent)
            for component in parts[:-1]:
                parent = os.open(component, directory_flags, dir_fd=parent)
                stack.callback(os.close, parent)
                info = os.fstat(parent)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    refuse("APP_SOURCE_UNVERIFIED")
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            with os.fdopen(fd, "rb") as source:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                        or before.st_nlink != 1):
                    refuse("APP_SOURCE_UNVERIFIED")
                content = source.read(1024 * 1024 + 1)
                after = os.fstat(fd)
                if (len(content) > 1024 * 1024 or before.st_size != len(content)
                        or before.st_ctime_ns != after.st_ctime_ns):
                    refuse("APP_SOURCE_UNVERIFIED")
                return sha256(content).hexdigest()
    except OSError:
        refuse("APP_SOURCE_UNVERIFIED")


def validate_layout(layout):
    if (not isinstance(layout, dict) or not LAYOUT_FIELDS <= layout.keys() <= (LAYOUT_FIELDS | set(NODE_PERMISSION.values()))
            or any(type(layout.get(key, False)) is not bool for key in NODE_PERMISSION.values())
            or type(layout["version"]) is not int
            or layout["version"] != 1 or not isinstance(layout["id"], str) or not re.fullmatch(ULID, layout["id"])
            or not isinstance(layout["project"], str) or not re.fullmatch(COMPOSE_PROJECT, layout["project"])
            or layout["project"].startswith("vo-app-")
            or not isinstance(layout["compose_files"], list) or not 1 <= len(layout["compose_files"]) <= 4
            or not isinstance(layout["extra_files"], list) or len(layout["extra_files"]) > 12
            or not isinstance(layout["service_hashes"], dict) or not 1 <= len(layout["service_hashes"]) <= 12
            or any(not re.fullmatch(COMPOSE_SERVICE, name) or not isinstance(value, str) or not re.fullmatch(SHA256, value)
                   for name, value in layout["service_hashes"].items())):
        refuse("APP_ADOPTION_SPEC_INVALID")
    paths = layout["compose_files"] + layout["extra_files"]
    for path in paths:
        source_path(path)
    if len(set(paths)) != len(paths):
        refuse("APP_ADOPTION_SPEC_INVALID")


def repo_reference(reference):
    return reference.removeprefix("index.docker.io/").removeprefix("docker.io/").removeprefix("library/")


def image_roles(docker, containers):
    known = json.loads(files("vpn_orbit").joinpath("application-images.json").read_text(encoding="utf-8"))["images"]
    roles = {}
    for name, container in containers.items():
        inspected = docker.inspect("image", container["Image"])
        refs = inspected.get("RepoDigests")
        if inspected.get("Id") != container["Image"] or not isinstance(refs, list):
            refuse("APP_IMAGE_DRIFT")
        refs = {repo_reference(ref) for ref in refs if isinstance(ref, str)}
        matches = [role for role, reference in known.items() if repo_reference(reference) in refs]
        if len(matches) != 1:
            refuse("APP_IMAGE_DRIFT")
        roles[name] = matches[0]
    return roles


def checked_dependencies(containers, roles, sources=None):
    """Verify the materialized addresses of the supported local dependencies."""
    edges = {}
    required = {"remnawave-panel": ("postgres", "redis"), "bedolaga-bot": ("postgres", "redis"),
                "bedolaga-cabinet": ("bedolaga-bot",)}
    for name, container in containers.items():
        configuration = container["Config"]
        mapping = {}
        for entry in configuration.get("Env") or []:
            key, sep, value = entry.partition("=") if isinstance(entry, str) else ("", "", "")
            if not sep or key in mapping:
                refuse("APP_DEPENDENCY_UNVERIFIED")
            mapping[key] = value

        def host(keys, schemes, port, port_var):
            candidates = set()
            for key in keys:
                if key not in mapping:
                    continue
                value = mapping[key]
                if key.endswith("_URL"):
                    try:
                        uri = urlsplit(value)
                        if uri.scheme not in schemes or (uri.port is not None and uri.port != port):
                            refuse("APP_DEPENDENCY_UNVERIFIED")
                        value = uri.hostname
                    except ValueError:
                        refuse("APP_DEPENDENCY_UNVERIFIED")
                if not isinstance(value, str) or not re.fullmatch(COMPOSE_SERVICE, value):
                    refuse("APP_DEPENDENCY_UNVERIFIED")
                candidates.add(value)
            if len(candidates) != 1 or (port_var in mapping and mapping[port_var] != str(port)):
                refuse("APP_DEPENDENCY_UNVERIFIED")
            return candidates.pop()

        if roles[name] == "bedolaga-bot":
            try:
                panel_origin(mapping.get("REMNAWAVE_API_URL"))
            except ValueError:
                refuse("APP_DEPENDENCY_UNVERIFIED")
        endpoints = {"postgres": (("DATABASE_URL", "POSTGRES_HOST"), ("postgres", "postgresql"), 5432, "POSTGRES_PORT"),
                     "redis": (("REDIS_URL", "REDIS_HOST"), ("redis", "rediss"), 6379, "REDIS_PORT")}
        dependencies = required.get(roles[name], ())
        if dependencies:
            require_docker_resolution(container)
        source_nets = attached_networks(container)
        selected = []
        for dependency in dependencies:
            if dependency == "bedolaga-bot":
                alias = cabinet_target(container, sources or {}, containers, roles)
            else:
                alias = host(*endpoints[dependency])
            if alias in (configuration.get("Hostname"), configuration.get("Domainname")):
                refuse("APP_DEPENDENCY_UNVERIFIED")
            matches = set()
            for peer, candidate in containers.items():
                for network, endpoint in attached_networks(candidate).items():
                    if network in BUILTIN_NETWORKS or network not in source_nets:
                        continue
                    if endpoint.get("NetworkID") != source_nets[network].get("NetworkID"):
                        continue
                    if alias in (endpoint.get("Aliases") or []):
                        matches.add(peer)
            if len(matches) != 1:
                refuse("APP_DEPENDENCY_UNVERIFIED")
            target = matches.pop()
            if roles[target] != dependency or target == name:
                refuse("APP_DEPENDENCY_UNVERIFIED")
            selected.append(target)
        edges[name] = sorted(selected)
    applications = [role for role in roles.values() if role not in ("postgres", "redis")]
    if not applications or len(applications) != len(set(applications)):
        refuse("APP_PROFILE_UNVERIFIED")
    for auxiliary in ("postgres", "redis"):
        hosted = {name for name, role in roles.items() if role == auxiliary}
        paired = [name for peers in edges.values() for name in peers if roles[name] == auxiliary]
        if set(paired) != hosted or len(paired) != len(hosted):
            refuse("APP_DEPENDENCY_UNVERIFIED")
    return edges


def require_docker_resolution(container):
    host = container.get("HostConfig") or {}
    if any(host.get(key) for key in ("ExtraHosts", "Dns", "DnsOptions", "DnsSearch")):
        refuse("APP_DEPENDENCY_UNVERIFIED")
    files = [PurePosixPath(name) for name in ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hostname")]
    for mount in container.get("Mounts") or ():
        destination = PurePosixPath(mount["Destination"])
        if any(destination == file or destination in file.parents for file in files):
            refuse("APP_DEPENDENCY_UNVERIFIED")


def cabinet_target(container, sources, containers, roles):
    files = [mount["Source"] for mount in container["Mounts"]
             if mount.get("Type") == "bind" and mount.get("RW") is False
             and mount.get("Destination") == "/etc/nginx/conf.d/default.conf"]
    if len(files) != 1 or files[0] not in sources:
        refuse("APP_DEPENDENCY_UNVERIFIED")
    options = set()
    for service, candidate in containers.items():
        if roles[service] != "bedolaga-bot":
            continue
        for endpoint in attached_networks(candidate).values():
            for alias in endpoint.get("Aliases") or []:
                if not isinstance(alias, str) or not re.fullmatch(COMPOSE_SERVICE, alias):
                    continue
                config = CABINET_CONFIG.replace("http://bedolaga-bot:8080/", f"http://{alias}:8080/")
                if sha256(config.encode()).hexdigest() == sources[files[0]]:
                    options.add(alias)
    if len(options) != 1:
        refuse("APP_DEPENDENCY_UNVERIFIED")
    return options.pop()


def attached_networks(container):
    networks = container.get("NetworkSettings", {}).get("Networks")
    if not isinstance(networks, dict) or any(not isinstance(endpoint, dict) for endpoint in networks.values()):
        refuse("APP_NETWORK_DRIFT")
    return networks


def timestamp(value, *, code="APP_ADOPTED_START_UNVERIFIED"):
    if not isinstance(value, str) or not re.fullmatch(DOCKER_STARTED_AT, value):
        refuse(code)
    seconds, _, fraction = value[:-1].partition(".")
    try:
        return datetime.fromisoformat(seconds), fraction.ljust(9, "0")
    except ValueError:
        refuse(code)


def node_runtime(container, attached, *, stopped):
    host, state = container["HostConfig"], container["State"]
    host_network = attached.get("host", {}).get("NetworkID") or None
    if (host.get("NetworkMode") != "host" or set(attached) - {"host"}
            or ((not stopped or host_network is not None) and
                (not isinstance(host_network, str) or not re.fullmatch(SHA256, host_network)))
            or host.get("ReadonlyRootfs") is not True or host.get("AutoRemove") or host.get("Privileged")
            or (host.get("RestartPolicy") or {}).get("Name") not in ("", "no", None)
            or any(host.get(key) for key in ("Devices", "DeviceRequests", "DeviceCgroupRules", "VolumesFrom",
                                             "PidMode", "UTSMode"))
            or host.get("IpcMode") not in (None, "", "private")
            or any(mount.get("Type") == "volume" for mount in container["Mounts"])):
        refuse("APP_ADOPTED_START_UNSUPPORTED")
    if state.get("Running") is not (not stopped) or any(state.get(key) for key in ("Paused", "Restarting", "Dead")):
        refuse("APP_ADOPTED_START_UNVERIFIED")
    timestamp(state.get("StartedAt"))
    restarts = container.get("RestartCount")
    if type(restarts) is not int or restarts < 0:
        refuse("APP_ADOPTED_START_UNVERIFIED")
    return {"restart_count": restarts, "host_network": host_network}


class ExternalLifecycle(Lifecycle):
    @classmethod
    def stage(cls, layout, *, root=ROOT, docker=None, owner=0):
        validate_layout(layout)
        root = Path(root)
        for parent in (root.parent, *root.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
                refuse("APP_PARENT_UNPROTECTED")
        root.mkdir(mode=0o700, exist_ok=True)
        private_directory(root, owner)
        directory = root / layout["id"]
        with process_lock(root / "lifecycle.lock"):
            if os.path.lexists(directory):
                refuse("APP_ADOPTION_ALREADY_STAGED")
            with tempfile.TemporaryDirectory(prefix=".adoption-", dir=root) as staging:
                (Path(staging) / layout["id"]).mkdir(mode=0o700)
                runtime = cls(layout["id"], root=staging, docker=docker, owner=owner)
                baseline = runtime.capture(layout)
                definition = {"layout": layout, "baseline": baseline, "nonce": secrets.token_hex(32)}
                binding = digest(definition)
                journal = Journal.initialize(runtime.journal.path, SCHEMA)
                with journal.write() as db:
                    db.execute("INSERT INTO installation(id,spec_digest,owner) VALUES(1,?,?)",
                               (binding, definition["nonce"]))
                atomic_write(runtime.directory / "external.json", canonical(definition))
                os.rename(runtime.directory, directory)
                directory_sync(root)
        return {"installation_id": layout["id"], "spec_digest": binding, "project": layout["project"]}

    def require_unique_registration(self, project):
        for directory in self.root.iterdir():
            if (directory == self.directory or not re.fullmatch(ULID, directory.name)
                    or not (directory / "external.json").exists()):
                continue
            other = ExternalLifecycle(directory.name, root=self.root, owner=self.owner)
            if other.definition()["layout"]["project"] == project:
                with other.journal.connect() as db:
                    active = db.execute("SELECT inventory FROM installation WHERE id=1").fetchone()
                if active is None or active["inventory"] is not None:
                    refuse("APP_ADOPTION_ALREADY_REGISTERED")

    def list_ids(self, selector):
        ids = self.docker("container", "ls", "--all", "--quiet", "--no-trunc", "--filter", selector).split()
        if len(ids) > 32 or len(ids) != len(set(ids)) or any(not re.fullmatch(SHA256, identity) for identity in ids):
            refuse("APP_ADOPTION_SCOPE_UNVERIFIED")
        return set(ids)

    def capture(self, layout, *, stopped=False, expected=None, require_health=True):
        node_management_enabled = any(layout.get(permission) for permission in NODE_PERMISSION.values())
        if stopped and not node_management_enabled:
            refuse("APP_ADOPTED_START_UNSUPPORTED")
        running_state = "exited" if stopped else "running"
        project = layout["project"]
        ids = self.list_ids("label=com.docker.compose.project=" + project)
        if not 1 <= len(ids) <= 12:
            refuse("APP_ADOPTION_SCOPE_UNVERIFIED")
        paths = layout["compose_files"] + layout["extra_files"]
        sources = {path: source_digest(path) for path in paths}
        containers, networks, volumes, observations = {}, {}, {}, []
        stable = {}
        for identity in sorted(ids):
            container = self.inspect("container", identity)
            config = container["Config"]
            labels = config.get("Labels") or {}
            service = labels.get("com.docker.compose.service")
            state = container["State"]["Status"]
            if (container.get("Id") != identity or labels.get("com.docker.compose.project") != project
                    or not isinstance(service, str) or not re.fullmatch(COMPOSE_SERVICE, service)
                    or service in containers or labels.get("com.vpn-orbit.installation") is not None
                    or labels.get("com.docker.compose.project.config_files") != ",".join(layout["compose_files"])
                    or service not in layout["service_hashes"]
                    or labels.get("com.docker.compose.config-hash") != layout["service_hashes"][service]
                    or not isinstance(container["Image"], str)
                    or re.fullmatch("sha256:" + SHA256, container["Image"]) is None):
                refuse("APP_OWNERSHIP_UNVERIFIED")
            if state != running_state:
                refuse("APP_ADOPTED_NOT_STOPPED" if stopped else "APP_OWNERSHIP_UNVERIFIED")
            attached = attached_networks(container)
            attached_volumes = set()
            for mount in container["Mounts"]:
                kind = mount.get("Type")
                if kind == "bind":
                    # Existing bind inputs are pinned as protected files.
                    if mount.get("RW") is not False or mount.get("Source") not in sources:
                        refuse("APP_BIND_UNVERIFIED")
                elif kind == "volume":
                    name = mount.get("Name")
                    if not isinstance(name, str) or not re.fullmatch(DOCKER_RESOURCE, name):
                        refuse("APP_OWNERSHIP_UNVERIFIED")
                    attached_volumes.add(name)
                elif kind != "tmpfs":
                    refuse("APP_MOUNT_UNVERIFIED")
            for name, endpoint in attached.items():
                if name in BUILTIN_NETWORKS:
                    continue
                network = endpoint.get("NetworkID")
                if not isinstance(network, str) or not re.fullmatch(SHA256, network):
                    refuse("APP_NETWORK_DRIFT")
                if name in networks and networks[name] != network:
                    refuse("APP_NETWORK_DRIFT")
                networks[name] = network
            for name in attached_volumes:
                volumes.setdefault(name, set()).add(identity)
            containers[service] = container
            pinned = expected["containers"].get(service, {}) if expected else {}
            stable[service] = {**self.stable(container, expected=pinned.get("configuration")),
                               "started_at": container["State"].get("StartedAt"),
                               "network_bindings": digest(attached)}
            observations.append({"id": identity, "service": service, "image_id": container["Image"],
                                 "state": state.upper(), "networks": sorted(attached), "volumes": sorted(attached_volumes)})

        if set(containers) != layout["service_hashes"].keys():
            refuse("APP_SERVICE_SET_DRIFT")
        records = {"networks": {}, "volumes": {}}
        for name, identity in networks.items():
            network = self.inspect("network", identity)
            if (network.get("Id") != identity or network.get("Name") != name or network.get("Scope") != "local"
                    or network.get("Driver") != "bridge"
                    or (network.get("Labels") or {}).get("com.docker.compose.project") != project
                    or set(network.get("Containers") or {}) - ids
                    or self.list_ids("network=" + identity) - ids):
                refuse("APP_NETWORK_SHARED")
            records["networks"][name] = digest({key: value for key, value in network.items()
                                                if key not in ("Containers", "Services")})
        for name, users in volumes.items():
            volume = self.inspect("volume", name)
            if (volume.get("Name") != name or volume.get("Driver") != "local" or volume.get("Options") not in (None, {})
                    or (volume.get("Labels") or {}).get("com.docker.compose.project") != project
                    or self.list_ids("volume=" + name) != users):
                refuse("APP_VOLUME_SHARED")
            records["volumes"][name] = digest(volume)
        roles = image_roles(self, containers)
        if node_management_enabled and list(roles.values()) != ["remnawave-node"]:
            refuse("APP_ADOPTED_START_UNSUPPORTED")
        for service, container in containers.items():
            if node_management_enabled:
                stable[service].update(node_runtime(container, attached_networks(container), stopped=stopped))
            if layout.get("allow_stop"):
                finished = container["State"].get("FinishedAt")
                timestamp(finished, code=NODE_UNVERIFIED[STOP_ADOPTED])
                stable[service]["finished_at"] = finished
            if stopped or not require_health:
                continue
            health = container["State"].get("Health")
            if (health is not None or roles[service] == "remnawave-node") and (
                    not isinstance(health, dict) or health.get("Status") != "healthy"):
                refuse("APP_HEALTH_UNVERIFIED")
            if roles[service] == "remnawave-node" and container["HostConfig"].get("NetworkMode") != "host":
                refuse("APP_NETWORK_DRIFT")
        dependencies = checked_dependencies(containers, roles, sources)
        if self.list_ids("label=com.docker.compose.project=" + project) != ids:
            refuse("APP_ADOPTION_DRIFT")
        return {"identity": daemon_identity(project, observations), "sources": sources,
                "containers": stable, "roles": roles, "dependencies": dependencies, **records}

    def definition(self):
        definition = json.loads(protected_bytes(self.directory / "external.json", owner=self.owner,
                                                private=True, maximum=65536))
        validate_layout(definition["layout"])
        if definition["layout"]["id"] != self.identity:
            refuse("APP_ADOPTION_DRIFT")
        return definition

    def status(self):
        with self.locked(), self.journal.connect() as db:
            definition = self.definition()
            row = db.execute("SELECT * FROM installation WHERE id=1").fetchone()
            if row is None or row["spec_digest"] != digest(definition):
                refuse("APP_ADOPTION_DRIFT")
            pending = db.execute("SELECT id FROM operations WHERE state IN ('DISPATCHING','UNKNOWN_OUTCOME')").fetchone()
            state = "ADOPTED" if row["inventory"] is not None else "STAGED"
            result = {"state": state, "project": definition["layout"]["project"], "spec_digest": row["spec_digest"]}
            if pending:
                result.update(state="UNKNOWN_OUTCOME", operations=[pending["id"]])
            return result

    @staticmethod
    def operation_binding(action, binding, registration_id, running_receipt_id):
        if action not in RUN_BOUND_ADOPTED_ACTIONS and running_receipt_id is not None:
            refuse("APP_ACTION_INVALID")
        if action in ADOPTED_NODE_ACTIONS:
            if not isinstance(registration_id, str) or not re.fullmatch(ULID, registration_id):
                refuse("APP_ADOPTION_STATE_INVALID")
            intent = {"spec_digest": binding, "registration_id": registration_id}
            if action in RUN_BOUND_ADOPTED_ACTIONS:
                if not isinstance(running_receipt_id, str) or not re.fullmatch(ULID, running_receipt_id):
                    refuse("APP_ADOPTED_RUN_CHANGED")
                intent["running_receipt_id"] = running_receipt_id
            return digest(intent)
        if registration_id is not None:
            refuse("APP_ACTION_INVALID")
        return binding

    def execute(self, operation, action, binding, review=None, *, registration_id=None, running_receipt_id=None):
        if action not in EXTERNAL_ACTIONS:
            refuse("APP_ACTION_INVALID")
        if not isinstance(operation, str) or not re.fullmatch(ULID, operation):
            refuse("APP_OPERATION_INVALID")
        with self.locked():
            definition = self.definition()
            baseline = definition["baseline"]
            if digest(definition) != binding or (action == "adopt" and review != baseline["identity"]):
                refuse("APP_ADOPTION_DRIFT")
            if action != "adopt" and review is not None:
                refuse("APP_ACTION_INVALID")
            receipt_binding = self.operation_binding(action, binding, registration_id, running_receipt_id)
            with self.journal.connect() as db:
                old = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
                pending = db.execute("SELECT 1 FROM operations WHERE state IN ('DISPATCHING','UNKNOWN_OUTCOME')").fetchone()
                installation = db.execute("SELECT * FROM installation WHERE id=1").fetchone()
            if installation is None or installation["spec_digest"] != binding:
                refuse("APP_ADOPTION_DRIFT")
            if old is not None:
                return self.receipt(old, action, receipt_binding)
            if pending:
                refuse("APP_RECONCILIATION_REQUIRED")
            if action in ADOPTED_NODE_ACTIONS:
                return self.change_node(operation, action, receipt_binding, definition["layout"],
                                        installation["inventory"], registration_id, running_receipt_id)
            if action == "adopt":
                self.require_unique_registration(definition["layout"]["project"])
                if self.capture(definition["layout"]) != baseline:
                    refuse("APP_ADOPTION_DRIFT")
            with self.journal.write() as db:
                if (installation["inventory"] is not None) == (action == "adopt"):
                    refuse("APP_ADOPTION_STATE_INVALID")
                inventory = canonical(baseline).decode() if action == "adopt" else None
                db.execute("UPDATE installation SET inventory=? WHERE id=1", (inventory,))
                db.execute("INSERT INTO operations(id,action,binding,state,code) VALUES(?,?,?,'SUCCEEDED',?)",
                           (operation, action, binding, EXTERNAL_ACTIONS[action]))
            return {"operation_id": operation, "outcome": "SUCCEEDED", "code": EXTERNAL_ACTIONS[action]}

    def verify_node(self, layout, inventory, action, *, after, running_since=None):
        stopped = action == STOP_ADOPTED if after else action == START_ADOPTED
        new_run = after and action in NEW_RUN_ADOPTED_ACTIONS
        current = self.capture(layout, stopped=stopped, expected=inventory, require_health=new_run)
        service, old = next(iter(inventory["containers"].items()))
        node = current["containers"].get(service, {})
        unchanged = all(current[key] == inventory[key] for key in
                        ("sources", "roles", "dependencies", "networks", "volumes"))
        # Docker's explicit restart resets the daemon restart counter.
        expected_restarts = 0 if after and action == RESTART_ADOPTED else old["restart_count"]
        if (not unchanged or any(node.get(key) != old[key] for key in ("Id", "configuration"))
                or node.get("restart_count") != expected_restarts):
            refuse("APP_ADOPTION_DRIFT")
        previous, observed = timestamp(old["started_at"]), timestamp(node["started_at"])
        networks = (None, old["host_network"]) if stopped else (old["host_network"],)
        if node["host_network"] not in networks or (not new_run and observed != previous):
            refuse("APP_ADOPTION_DRIFT")
        if new_run and (observed <= previous or (running_since is not None and observed != timestamp(running_since))):
            refuse(NODE_UNVERIFIED[action])
        if not after and action in RUN_BOUND_ADOPTED_ACTIONS and node["network_bindings"] != old["network_bindings"]:
            refuse("APP_ADOPTION_DRIFT")
        if action == STOP_ADOPTED:
            prior_finish = timestamp(old["finished_at"], code=NODE_UNVERIFIED[action])
            finished = timestamp(node["finished_at"], code=NODE_UNVERIFIED[action])
            if after and finished <= max(previous, prior_finish):
                refuse(NODE_UNVERIFIED[action])
            if not after and finished != prior_finish:
                refuse("APP_ADOPTION_DRIFT")
        return current

    def change_node(self, operation, action, binding, layout, inventory, registration_id, running_receipt_id):
        if not layout.get(NODE_PERMISSION[action]):
            refuse(NODE_UNSUPPORTED[action])
        if inventory is None:
            refuse("APP_ADOPTION_STATE_INVALID")
        with self.journal.connect() as db:
            registration = db.execute("""SELECT id FROM operations WHERE action='adopt' AND state='SUCCEEDED'
                                         ORDER BY rowid DESC LIMIT 1""").fetchone()
            running = db.execute("""SELECT id FROM operations WHERE action IN ('adopt',?,?) AND state='SUCCEEDED'
                                    ORDER BY rowid DESC LIMIT 1""", NEW_RUN_ADOPTED_ACTIONS).fetchone()
        if registration is None or registration["id"] != registration_id:
            refuse("APP_ADOPTION_STATE_INVALID")
        if action in RUN_BOUND_ADOPTED_ACTIONS and (running is None or running["id"] != running_receipt_id):
            refuse("APP_ADOPTED_RUN_CHANGED")
        inventory = json.loads(inventory)
        self.verify_node(layout, inventory, action, after=False)
        node = next(iter(inventory["containers"].values()))
        # The inventory pins the exact running generation through dispatch and readback.
        with self.journal.write() as db:
            db.execute("INSERT INTO operations(id,action,binding,state,code) VALUES(?,?,?,'DISPATCHING','APP_PENDING')",
                       (operation, action, binding))
            if action == RESTART_ADOPTED:
                db.execute("""CREATE TABLE IF NOT EXISTS restart_observations(
                    operation_id TEXT PRIMARY KEY REFERENCES operations(id), started_at TEXT NOT NULL)""")
        try:
            if action == START_ADOPTED:
                self.docker("container", "start", node["Id"], timeout=45)
            elif action == STOP_ADOPTED:
                self.docker("container", "stop", "--timeout", "30", node["Id"], timeout=45)
            else:
                self.docker("container", "restart", "--timeout", "30", node["Id"], timeout=60)
            running_since = None
            if action in NEW_RUN_ADOPTED_ACTIONS:
                running_since = self.wait_for_node_health(operation, action, node)
            current = self.verify_node(layout, inventory, action, after=True, running_since=running_since)
        except Exception:
            return self.finish(operation, "UNKNOWN_OUTCOME", NODE_UNVERIFIED[action])
        return self.record_node_outcome(operation, action, current)

    def pin_restart_generation(self, operation, node, value):
        code = NODE_UNVERIFIED[RESTART_ADOPTED]
        state = value["State"]
        if (value["Id"] != node["Id"] or state["Status"] != "running" or state.get("Running") is not True
                or any(state.get(key) for key in ("Paused", "Restarting", "Dead"))):
            refuse(code)
        observed_at = state["StartedAt"]
        observed = timestamp(observed_at, code=code)
        if observed <= timestamp(node["started_at"], code=code):
            refuse(code)
        # Keep the first observed run through a lost reply or subsequent manual restart.
        with self.journal.write() as db:
            db.execute("INSERT OR IGNORE INTO restart_observations VALUES(?,?)", (operation, observed_at))
            row = db.execute("SELECT started_at FROM restart_observations WHERE operation_id=?", (operation,)).fetchone()
        if observed != timestamp(row["started_at"], code=code):
            refuse(code)
        return row["started_at"]

    def wait_for_node_health(self, operation, action, node):
        deadline = time.monotonic() + 90
        started_at = None
        while True:
            value = self.inspect("container", node["Id"])
            state = value["State"]
            if value["Id"] != node["Id"] or state["Status"] != "running":
                refuse(NODE_UNVERIFIED[action])
            if action == RESTART_ADOPTED and started_at is None:
                started_at = self.pin_restart_generation(operation, node, value)
            if started_at is not None and state["StartedAt"] != started_at:
                refuse(NODE_UNVERIFIED[action])
            if (state.get("Health") or {}).get("Status") == "healthy":
                return started_at
            if time.monotonic() >= deadline:
                refuse("APP_HEALTH_UNVERIFIED")
            time.sleep(1)

    def record_node_outcome(self, operation, action, inventory):
        code = EXTERNAL_ACTIONS[action]
        with self.journal.write() as db:
            if action in NEW_RUN_ADOPTED_ACTIONS:
                db.execute("UPDATE installation SET inventory=? WHERE id=1", (canonical(inventory).decode(),))
            db.execute("UPDATE operations SET state='SUCCEEDED',code=? WHERE id=?", (code, operation))
        return {"operation_id": operation, "outcome": "SUCCEEDED", "code": code}

    @staticmethod
    def receipt(row, action, binding):
        if row is None or row["action"] != action or row["binding"] != binding:
            refuse("APP_ADOPTION_RECEIPT_UNVERIFIED")
        if row["state"] == "SUCCEEDED" and row["code"] == EXTERNAL_ACTIONS.get(action):
            return {"operation_id": row["id"], "outcome": "SUCCEEDED", "code": row["code"]}
        if action in ADOPTED_NODE_ACTIONS and row["state"] in ("DISPATCHING", "UNKNOWN_OUTCOME"):
            return {"operation_id": row["id"], "outcome": "UNKNOWN_OUTCOME", "code": NODE_UNVERIFIED[action]}
        refuse("APP_ADOPTION_RECEIPT_UNVERIFIED")

    def reconcile(self, operation, *, action, binding, review=None, registration_id=None, running_receipt_id=None):
        with self.locked():
            definition = self.definition()
            if digest(definition) != binding or (action == "adopt" and review != definition["baseline"]["identity"]):
                refuse("APP_ADOPTION_DRIFT")
            if action != "adopt" and review is not None:
                refuse("APP_ACTION_INVALID")
            with self.journal.connect() as db:
                saved = db.execute("SELECT * FROM operations WHERE id=?", (operation,)).fetchone()
                installation = db.execute("SELECT * FROM installation WHERE id=1").fetchone()
            result = self.receipt(saved, action, self.operation_binding(action, binding, registration_id, running_receipt_id))
            if action not in ADOPTED_NODE_ACTIONS or result["outcome"] == "SUCCEEDED":
                return result
            if installation is None or installation["spec_digest"] != binding or installation["inventory"] is None:
                refuse("APP_ADOPTION_DRIFT")
            inventory = json.loads(installation["inventory"])
            try:
                running_since = None
                if action == RESTART_ADOPTED:
                    node = next(iter(inventory["containers"].values()))
                    value = self.inspect("container", node["Id"])
                    running_since = self.pin_restart_generation(operation, node, value)
                current = self.verify_node(definition["layout"], inventory, action, after=True, running_since=running_since)
            except Denied:
                return result
            return self.record_node_outcome(operation, action, current)
