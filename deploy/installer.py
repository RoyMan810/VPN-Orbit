#!/usr/bin/env python3
"""Fresh Ubuntu installation from a verified development bundle."""

import argparse
import getpass
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import traceback
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, urlopen

from artifact import AGE_FILE, ArtifactError, bundle_channel, canonical, snapshot, trusted_key


APP = Path("/opt/vpn-orbit")
CONFIG = Path("/etc/vpn-orbit")
DATA = Path("/var/lib/vpn-orbit")
RUN = Path("/run/vpn-orbit")
UNITS = Path("/etc/systemd/system")
HOST_UNITS = ("vpn-orbit-supervisor.socket", "vpn-orbit-supervisor.service",
              "vpn-orbit-broker.socket", "vpn-orbit-broker.service")
COMPOSE_UNIT = "vpn-orbit-compose.service"
DOCKER = "/usr/bin/docker"


def command(*args, timeout=60, env=None):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, timeout=timeout,
                            env=env or {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})
    if result.returncode:
        # Child stderr, env and command output are never forwarded as application logs.
        raise ArtifactError("INSTALL_COMMAND_FAILED_" + Path(str(args[0])).name.upper().replace("-", "_"))
    return result.stdout.decode("utf-8").strip()


def write(path, data, *, mode=0o644, uid=0, gid=0, replace=False):
    path = Path(path)
    if not replace:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    else:
        fd, temporary = tempfile.mkstemp(prefix=".vpn-orbit-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    if replace:
        os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def folder(path, mode, uid=0, gid=0):
    path.mkdir(mode=mode, exist_ok=False)
    os.chown(path, uid, gid)
    path.chmod(mode)


def system_config_directory(path):
    """Minimal Ubuntu images may omit optional /etc/*.d directories."""
    try:
        folder(path, 0o755)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ArtifactError("SYSTEM_CONFIG_DIRECTORY_UNTRUSTED") from None


def origin(value):
    p = urlsplit(value)
    try:
        valid = (p.scheme == "https" and p.hostname and not p.username and not p.password
                 and not p.path and not p.query and not p.fragment and p.port != 443
                 and p.netloc == p.netloc.lower() and len(value) <= 300)
        if valid:
            try:
                ipaddress.ip_address(p.hostname)
            except ValueError:
                valid = p.hostname.isascii() and len(p.hostname) <= 253 and all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in p.hostname.split("."))
    except ValueError:
        valid = False
    if not valid:
        raise ArtifactError("PUBLIC_ORIGIN_INVALID")
    return value


def daemon(value):
    if not isinstance(value, str) or re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", value) is None or ".." in Path(value[7:]).parts:
        raise ArtifactError("LOCAL_DOCKER_SOCKET_REQUIRED")
    if not stat.S_ISSOCK(Path(value[7:]).stat().st_mode):
        raise ArtifactError("LOCAL_DOCKER_SOCKET_REQUIRED")
    return value


def docker(host, *args, timeout=60):
    return command(DOCKER, "--host", host, *args, timeout=timeout)


def check_buildx(host):
    try:
        docker(host, "buildx", "version")
    except ArtifactError as error:
        raise ArtifactError("DOCKER_BUILDX_REQUIRED") from error


def supported_ubuntu(release):
    version = re.fullmatch(r"([0-9]{2,})\.(04|10)", release.get("VERSION_ID", ""))
    return release.get("ID") == "ubuntu" and version is not None and tuple(map(int, version.groups())) >= (24, 4)


def supported_compose(version):
    return re.fullmatch(r"v?(?:2|5)\.[0-9]+\.[0-9]+(?:\+ds[0-9]+-[0-9]+ubuntu[0-9]+(?:\.[0-9]+)*(?:~[0-9]+(?:\.[0-9]+)*)?)?", version) is not None


def advise_capacity(cpus, memory, disk):
    # A 2 GiB VPS exposes less MemTotal after kernel and hardware reservations.
    if (cpus or 0) < 1 or memory < 1792 * 1024**2 or disk.free < 2 * 1024**3:
        print("VPN-Orbit: recommended 1 vCPU, 2 GiB RAM and 2 GiB free in /var/lib.", file=sys.stderr)


def preflight(args):
    if os.geteuid() != 0:
        raise ArtifactError("LOCAL_ROOT_REQUIRED")
    release = platform.freedesktop_os_release()
    if not supported_ubuntu(release) or platform.machine() != "x86_64":
        raise ArtifactError("PLATFORM_UNSUPPORTED")
    if sys.version_info[:2] not in ((3, 13), (3, 15)) or sqlite3.sqlite_version_info < (3, 45):
        raise ArtifactError("HOST_PYTHON_SQLITE_UNSUPPORTED")
    # A root-owned child can still be replaced when its permanent parent is
    # writable by another account. Refuse; never chmod/chown foreign host dirs.
    for base in (APP.parent, CONFIG.parent, DATA.parent, RUN.parent):
        for parent in (base, *base.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ArtifactError("INSTALLATION_PARENT_UNTRUSTED")
    memory = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
    disk = shutil.disk_usage("/var/lib")
    advise_capacity(os.cpu_count(), memory, disk)
    origin(args.origin)
    daemon(args.docker_host)
    if not 1024 <= args.port <= 65535:
        raise ArtifactError("LOOPBACK_HIGH_PORT_REQUIRED")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", args.port))
        except OSError:
            raise ArtifactError("LISTENER_OCCUPIED") from None
    for path in (APP, CONFIG, DATA, RUN, Path("/etc/tmpfiles.d/vpn-orbit.conf"), Path("/etc/sysusers.d/vpn-orbit.conf"),
                 *(UNITS / unit for unit in (*HOST_UNITS, COMPOSE_UNIT,
                                                                 "vpn-orbit-api.service", "vpn-orbit-worker.service"))):
        if path.exists() or path.is_symlink():
            raise ArtifactError("EXISTING_INSTALLATION_REQUIRES_MAINTENANCE")
    for name in ("vpn-orbit-api", "vpn-orbit-worker", "vpn-orbit-broker"):
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise ArtifactError("SERVICE_IDENTITY_ALREADY_EXISTS")
    for name in ("vpn-orbit-api", "vpn-orbit-worker", "vpn-orbit-broker", "vpn-orbit-app-db", "vpn-orbit-broker-rpc", "vpn-orbit-gate-rpc"):
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise ArtifactError("SERVICE_IDENTITY_ALREADY_EXISTS")
    if not docker(args.docker_host, "version", "--format", "{{.Server.Version}}").startswith("29."):
        raise ArtifactError("DOCKER_VERSION_UNSUPPORTED")
    compose = docker(args.docker_host, "compose", "version", "--short")
    if not supported_compose(compose):
        raise ArtifactError("COMPOSE_VERSION_UNSUPPORTED")
    check_buildx(args.docker_host)
    info = json.loads(docker(args.docker_host, "info", "--format", "{{json .SecurityOptions}}"))
    if any("rootless" in option or "userns" in option for option in info):
        # Numeric host/container identities must be the ones authenticated by SO_PEERCRED.
        raise ArtifactError("EXPLICIT_ROOTFUL_UID_MAPPING_REQUIRED")
    if docker(args.docker_host, "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=vpn-orbit"):
        raise ArtifactError("COMPOSE_PROJECT_ALREADY_EXISTS")
    if docker(args.docker_host, "network", "ls", "--quiet", "--filter", "name=^vpn-orbit_api$"):
        raise ArtifactError("COMPOSE_NETWORK_ALREADY_EXISTS")
    # A host-native interpreter remains outside the replaceable API/Worker image.
    interpreter = Path(sys.executable).resolve()
    if re.fullmatch(r"/[A-Za-z0-9_./-]+", str(interpreter)) is None:
        raise ArtifactError("HOST_INTERPRETER_PATH_INVALID")
    if not Path("/run/systemd/system").is_dir():
        raise ArtifactError("SYSTEMD_HOST_REQUIRED")
    for unit in (*HOST_UNITS, COMPOSE_UNIT, "vpn-orbit-api.service", "vpn-orbit-worker.service"):
        result = subprocess.run(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit],
                                capture_output=True, timeout=10)
        if result.stdout.strip() != b"not-found":
            raise ArtifactError("EXISTING_VPN_ORBIT_UNIT")
    return interpreter


def bind(source, target, *, read_only=True):
    return {"type": "bind", "source": str(source), "target": str(target), "read_only": read_only,
            "bind": {"create_host_path": False}}


def compose_document(config, image, port):
    common = {"image": image, "pull_policy": "never", "read_only": True,
              "cap_drop": ["ALL"], "security_opt": ["no-new-privileges=true"], "userns_mode": "host",
              "restart": "unless-stopped", "stop_grace_period": "60s", "pids_limit": 128, "mem_limit": "512m", "cpus": 1,
              "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777"],
              "environment": {"HOME": "/nonexistent", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
              "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "2"}}}
    mounts = [bind(CONFIG / "runtime.json", CONFIG / "runtime.json"),
              bind(config["writer_directory"], config["writer_directory"]),
              bind(DATA / "app", DATA / "app", read_only=False)]
    return {"name": "vpn-orbit", "services": {
        "api": {**common, "user": f"{config['app_uid']}:{config['app_gid']}", "command": ["api"],
                "networks": ["api"], "ports": [{"target": 8000, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"}],
                "volumes": mounts,
                "healthcheck": {"test": ["CMD", "python", "-c", "from urllib.request import urlopen; assert urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200"],
                                "interval": "10s", "timeout": "3s", "retries": 6, "start_period": "10s"}},
        "worker": {**common, "user": f"{config['worker_uid']}:{config['worker_gid']}", "command": ["worker"],
                   "network_mode": "none", "group_add": [str(config[key]) for key in ("app_gid", "broker_rpc_gid", "gate_rpc_gid")],
                   "volumes": [*mounts, bind(CONFIG / "targets.json", CONFIG / "targets.json"),
                               bind(CONFIG / "gate.pub", CONFIG / "gate.pub"),
                               bind(RUN / "broker", RUN / "broker"), bind(RUN / "supervisor", RUN / "supervisor")]},
    }, "networks": {"api": {"driver": "bridge", "internal": False,
                              "driver_opts": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"}}}}


def controller_image(channel, digest):
    prefix = "dev" if channel == "development" else "release"
    return f"vpn-orbit/controller:{prefix}-{digest[:24]}"


def load_installation():
    path = APP / "installation.json"
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ArtifactError("INSTALLATION_METADATA_INVALID")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("v") != 1 or value.get("project") != "vpn-orbit":
        raise ArtifactError("INSTALLATION_METADATA_INVALID")
    channel = bundle_channel(value.get("version"))
    digest = value.get("manifest_sha256")
    image_id = value.get("image_id")
    if (channel is None or value.get("channel") != channel
            or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or value.get("image") != controller_image(channel, digest)
            or not isinstance(image_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None):
        raise ArtifactError("INSTALLATION_METADATA_INVALID")
    daemon(value["docker_host"])
    return value


def verify_image():
    value = load_installation()
    if docker(value["docker_host"], "image", "inspect", "--format", "{{.Id}}", value["image"]) != value["image_id"]:
        raise ArtifactError("INSTALLED_IMAGE_ID_CHANGED")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def stable_version(version):
    if bundle_channel(version) != "release":
        raise ArtifactError("UPDATE_STABLE_VERSION_REQUIRED")
    return tuple(int(part) for part in version.split("."))


def discover_release(installed):
    from vpn_orbit.errors import Denied
    from vpn_orbit.release_info import discover
    try:
        return discover(installed)
    except Denied as error:
        raise ArtifactError(error.code) from None


def check_update_bundle(args, installed):
    """Authenticate a release and compare local compatibility without applying it."""
    from vpn_orbit.runtime.cli import configuration
    from vpn_orbit.runtime.data_contract import inspect

    expected = stable_version(args.version)
    if expected <= stable_version(installed["version"]):
        raise ArtifactError("UPDATE_VERSION_NOT_NEWER")
    path = CONFIG / "release-trust.pub"
    if os.path.lexists(path):
        key = trusted_key(path)
        if args.trust_key is not None and trusted_key(args.trust_key) != key:
            raise ArtifactError("UPDATE_TRUST_KEY_MISMATCH")
    else:
        if args.trust_key is None:
            raise ArtifactError("INDEPENDENT_TRUST_KEY_REQUIRED")
        if args.trust_key.resolve().is_relative_to(args.bundle.resolve()):
            raise ArtifactError("INDEPENDENT_TRUST_KEY_REQUIRED")
        key = trusted_key(args.trust_key)
    if shutil.disk_usage(APP).free < 2 * 1024**3 or shutil.disk_usage("/var/tmp").free < 512 * 1024**2:
        raise ArtifactError("UPDATE_DISK_SPACE_INSUFFICIENT")
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-update-check-", dir="/var/tmp") as directory:
        stage = Path(directory) / "bundle"
        release, digest = snapshot(args.bundle, stage, key)
        if release["version"] != args.version:
            raise ArtifactError("UPDATE_BUNDLE_VERSION_MISMATCH")
        if release["python"] != f"{sys.version_info.major}.{sys.version_info.minor}":
            raise ArtifactError("HOST_BUNDLE_PYTHON_MISMATCH")
        if not (stage / AGE_FILE).is_file():
            raise ArtifactError("PINNED_AGE_TOOL_REQUIRED")
        selected = installed["docker_host"]
        if not docker(selected, "version", "--format", "{{.Server.Version}}").startswith("29."):
            raise ArtifactError("DOCKER_VERSION_UNSUPPORTED")
        if not supported_compose(docker(selected, "compose", "version", "--short")):
            raise ArtifactError("DOCKER_COMPOSE_UNSUPPORTED")
        check_buildx(selected)
        cfg = configuration(CONFIG / "runtime.json")
        compatible = inspect(cfg, target_schema=release["sqlite_schema"])
        if compatible["writer_phase"] != "OPEN":
            raise ArtifactError("UPDATE_ADMISSION_NOT_OPEN")
    return {"status": "VERIFIED_COMPATIBLE", "installed_version": installed["version"], "candidate_version": release["version"],
            "manifest_sha256": digest, "migration": compatible["migration"], "applied": False}


def create_owner(username):
    # This command runs with the host venv, never inside the public API.
    from vpn_orbit.auth import AuthService
    from vpn_orbit.database import DataAccess, Store
    from vpn_orbit.runtime.cli import configuration
    cfg = configuration(CONFIG / "runtime.json")
    password = getpass.getpass("Owner password: ")
    if password != getpass.getpass("Confirm password: "):
        raise ArtifactError("PASSWORD_CONFIRMATION_MISMATCH")
    from vpn_orbit.admission import Admission
    service = AuthService(Store(cfg["database"], access=DataAccess(cfg["app_uid"], cfg["app_gid"]),
                                writers=Admission(cfg["writer_directory"])))
    token = service.issue_bootstrap()
    user_id = service.create_owner(token, username, password)
    print("Owner created " + user_id)


def install(args):
    os.umask(0o077)
    interpreter = preflight(args)
    key = None
    if args.trust_key is not None:
        trust = Path(args.trust_key).resolve()
        if trust.is_relative_to(args.bundle.resolve()):
            raise ArtifactError("INDEPENDENT_TRUST_KEY_REQUIRED")
        key = trusted_key(args.trust_key)
    # A copied/authenticated staging tree is the only source used below. No
    # network package index or mutable input directory is executed by root.
    with tempfile.TemporaryDirectory(prefix="vpn-orbit-install-", dir="/var/tmp") as temporary:
        stage = Path(temporary) / "bundle"
        manifest, digest = snapshot(args.bundle, stage, key, expected_sha256=args.manifest_sha256,
                                    allow_development=args.development)
        if manifest["python"] != f"{sys.version_info.major}.{sys.version_info.minor}":
            raise ArtifactError("HOST_BUNDLE_PYTHON_MISMATCH")
        if not (stage / AGE_FILE).is_file():
            raise ArtifactError("PINNED_AGE_TOOL_REQUIRED")
        if args.web_enrollment and not args.targets:
            raise ArtifactError("WEB_ENROLLMENT_REQUIRES_TARGETS")
        channel = manifest["channel"]
        if args.check:
            print(json.dumps({"preflight": "PASS", "manifest_sha256": digest, "channel": channel,
                              "authentication": "signature" if key is not None else "sha256",
                              "recovery": "NOT_READY"}))
            return
        image = controller_image(channel, digest)
        try:
            docker(args.docker_host, "pull", "--platform", "linux/amd64", manifest["python_image"], timeout=600)
        except subprocess.TimeoutExpired:
            raise ArtifactError("INSTALL_BASE_IMAGE_PULL_TIMED_OUT") from None
        docker(args.docker_host, "build", "--network=none", "--pull=false", "--build-arg", "PYTHON_IMAGE=" + manifest["python_image"],
               "--tag", image, "--file", str(stage / "deploy/Controller.Dockerfile"), str(stage), timeout=240)
        image_id = docker(args.docker_host, "image", "inspect", "--format", "{{.Id}}", image)
        folder(APP, 0o755)
        (APP / "bundle").mkdir(mode=0o700)
        for path in stage.iterdir():
            shutil.move(str(path), APP / "bundle" / path.name)
        bundle = APP / "bundle"
        folder(APP / "tools", 0o755)
        write(APP / AGE_FILE, (bundle / AGE_FILE).read_bytes(), mode=0o755)
        write(APP / "install-state.json", canonical({"v": 1, "phase": "INITIALIZING", "manifest_sha256": digest}), mode=0o600)
        command(interpreter, "-m", "venv", APP / "venv")
        python = APP / "venv/bin/python"
        command(python, "-m", "pip", "install", "--no-index", "--find-links", bundle / "wheelhouse",
                "--require-hashes", "-r", bundle / "requirements-install.txt", timeout=180)
        # Only root can write code; the isolated service UIDs need traversal/read
        # access to their shared host interpreter and installed distributions.
        for path in (APP / "venv").rglob("*"):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        (APP / "venv").chmod(0o755)
        command(python, "-c", "from vpn_orbit.runtime.policy import CAPABILITIES; from vpn_orbit.database import SCHEMA_VERSION; import sys; assert SCHEMA_VERSION == int(sys.argv[1]); assert set(CAPABILITIES)=={'host.probe','docker.restart','firewall.apply','apps.lifecycle'}", manifest["sqlite_schema"])
        command("/usr/bin/systemd-sysusers", bundle / "deploy/sysusers.d/vpn-orbit.conf")
        cfg = {"v": 1, "database": str(DATA / "app/controller.sqlite3"), "public_origin": args.origin,
               "trusted_proxies": ["127.0.0.1/32"], "api_port": 8000, "api_bind": "0.0.0.0",
               "targets": str(CONFIG / "targets.json"), "supervisor_directory": str(DATA / "control-gate"),
               "broker_directory": str(DATA / "broker"), "vault_directory": str(DATA / "vault"),
               "writer_directory": str(DATA / "writer-admission"),
               "vault_credential": str(CONFIG / "credentials/broker-dek.cred"), "public_verify_key": str(CONFIG / "gate.pub"),
               "gate_socket": str(RUN / "supervisor/gate.sock"), "broker_socket": str(RUN / "broker/broker.sock")}
        for role, name in (("app", "vpn-orbit-api"), ("worker", "vpn-orbit-worker"), ("broker", "vpn-orbit-broker")):
            user = pwd.getpwnam(name)
            cfg[role + "_uid"], cfg[role + "_gid"] = user.pw_uid, user.pw_gid
        for key_name, name in (("app_gid", "vpn-orbit-app-db"), ("broker_rpc_gid", "vpn-orbit-broker-rpc"), ("gate_rpc_gid", "vpn-orbit-gate-rpc")):
            cfg[key_name] = grp.getgrnam(name).gr_gid
        folder(CONFIG, 0o755)
        folder(CONFIG / "credentials", 0o700)
        folder(DATA, 0o755)
        folder(DATA / "app", 0o2770, cfg["app_uid"], cfg["app_gid"])
        for name in ("broker", "vault"):
            folder(DATA / name, 0o700, cfg["broker_uid"], cfg["broker_gid"])
        folder(DATA / "control-gate", 0o700)
        folder(RUN, 0o755)
        folder(RUN / "broker", 0o710, 0, cfg["broker_rpc_gid"])
        folder(RUN / "supervisor", 0o710, 0, cfg["gate_rpc_gid"])
        targets = args.targets.read_bytes() if args.targets else canonical({"v": 1, "targets": []})
        write(CONFIG / "targets.json", targets)
        write(CONFIG / "runtime.json", canonical(cfg))
        if key is not None:
            write(CONFIG / "release-trust.pub", key)
        else:
            write(CONFIG / "release-authentication.json",
                  canonical({"v": 1, "authentication": "sha256", "manifest_sha256": digest,
                             "source_commit": manifest["source_commit"]}))
        runtime = APP / "venv/bin/vpn-orbit-runtime"
        command(runtime, "--config", CONFIG / "runtime.json", "initialize-credential")
        command(runtime, "--config", CONFIG / "runtime.json", "initialize-writers")
        command(APP / "venv/bin/vpn-orbit", "--database", cfg["database"], "--database-owner", cfg["app_uid"],
                "--database-group", cfg["app_gid"], "init")
        command(runtime, "--config", CONFIG / "runtime.json", "initialize-supervisor")
        # systemd gives just this UID a private copy of the OS credential.
        command("/usr/bin/systemd-run", "--unit=vpn-orbit-vault-initialize", "--quiet", "--wait", "--collect", "--property=User=vpn-orbit-broker",
                "--property=Group=vpn-orbit-broker", "--property=SupplementaryGroups=vpn-orbit-gate-rpc",
                "--property=UMask=0077", "--property=LoadCredentialEncrypted=broker-dek:" + cfg["vault_credential"],
                runtime, "--config", CONFIG / "runtime.json", "initialize-broker")
        if args.web_enrollment:
            cfg["enrollment_catalog"] = json.loads(command(runtime, "--config", CONFIG / "runtime.json",
                                                           "enrollment-catalog", "--ssh-endpoints"))
        else:
            command(runtime, "--config", CONFIG / "runtime.json", "register-observations")
        compose = compose_document(cfg, image, args.port)
        write(CONFIG / "compose.json", canonical(compose))
        prefix = ("compose", "--project-name", "vpn-orbit", "--project-directory", str(APP), "--file", str(CONFIG / "compose.json"))
        docker(args.docker_host, *prefix, "create", "--no-build")
        network, = json.loads(docker(args.docker_host, "network", "inspect", "vpn-orbit_api"))
        if network["Labels"].get("com.docker.compose.project") != "vpn-orbit" or network["Internal"]:
            raise ArtifactError("COMPOSE_NETWORK_BINDING_INVALID")
        gateway = ipaddress.ip_address(network["IPAM"]["Config"][0]["Gateway"])
        if gateway.version != 4 or not gateway.is_private:
            raise ArtifactError("COMPOSE_GATEWAY_INVALID")
        cfg["trusted_proxies"].append(str(gateway) + "/32")
        write(CONFIG / "runtime.json", canonical(cfg), replace=True)
        metadata = {"v": 1, "project": "vpn-orbit", "image": image, "image_id": image_id, "docker_host": args.docker_host,
                    "manifest_sha256": digest, "source_commit": manifest["source_commit"], "version": manifest["version"],
                    "authentication": "signature" if key is not None else "sha256",
                    "channel": channel, "remote_mutation_enabled": False, "recovery": "NOT_READY", "port": args.port}
        write(APP / "installation.json", canonical(metadata), mode=0o600)
        for path in (UNITS, Path("/etc/sysusers.d"), Path("/etc/tmpfiles.d")):
            system_config_directory(path)
        for name in HOST_UNITS:
            write(UNITS / name, (bundle / "deploy/systemd" / name).read_bytes())
        write(Path("/etc/sysusers.d/vpn-orbit.conf"), (bundle / "deploy/sysusers.d/vpn-orbit.conf").read_bytes())
        # Recreate the narrowly owned socket directories after /run is cleared.
        tmpfiles = (f"d {RUN} 0755 root root -\nd {RUN}/broker 0710 root vpn-orbit-broker-rpc -\n"
                    f"d {RUN}/supervisor 0710 root vpn-orbit-gate-rpc -\n")
        write(Path("/etc/tmpfiles.d/vpn-orbit.conf"), tmpfiles.encode())
        cli = f"{DOCKER} --host {args.docker_host} compose --project-name vpn-orbit --project-directory {APP} --file {CONFIG}/compose.json"
        unit = ("[Unit]\nDescription=VPN-Orbit API and Worker containers\nRequires=vpn-orbit-broker.socket vpn-orbit-supervisor.socket\n"
                "ConditionPathExists=!/var/lib/vpn-orbit/restore.pending\n"
                "After=docker.service vpn-orbit-broker.socket vpn-orbit-supervisor.socket\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                f"ExecStartPre={python} {bundle}/deploy/installer.py verify-image\n"
                f"ExecStart={cli} up --detach --no-build --wait\nExecStop={cli} stop --timeout 60\n"
                "TimeoutStartSec=120\nTimeoutStopSec=75\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=true\n"
                "CapabilityBoundingSet=\nLimitCORE=0\n\n[Install]\nWantedBy=multi-user.target\n")
        write(UNITS / COMPOSE_UNIT, unit.encode())
        admin = f"#!/bin/sh\nexec {python} {bundle}/deploy/installer.py \"$@\"\n"
        write(APP / "admin", admin.encode(), mode=0o755)
        command("/usr/bin/systemctl", "daemon-reload")
        command("/usr/bin/systemctl", "enable", "--now", "vpn-orbit-supervisor.socket", "vpn-orbit-broker.socket")
        command("/usr/bin/systemctl", "start", "vpn-orbit-supervisor.service", "vpn-orbit-broker.service")
        command("/usr/bin/systemctl", "enable", "--now", COMPOSE_UNIT, timeout=150)
        with urlopen(f"http://127.0.0.1:{args.port}/healthz", timeout=5) as response:
            if json.load(response).get("status") != "alive":
                raise ArtifactError("INSTALLATION_SMOKE_FAILED")
        write(APP / "install-state.json", canonical({"v": 1, "phase": "COMPLETE", "manifest_sha256": digest}), mode=0o600, replace=True)
        print(json.dumps({"installed": True, "channel": channel, "endpoint": f"http://127.0.0.1:{args.port}",
                          "owner_setup": "/opt/vpn-orbit/admin create-owner --username <name>",
                          "recovery": "NOT_READY"}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("install", help="Install a fresh verified Controller bundle")
    new.add_argument("--bundle", type=Path, required=True)
    authentication = new.add_mutually_exclusive_group(required=True)
    authentication.add_argument("--trust-key", type=Path,
                                help="Independently delivered 32-byte Ed25519 public key for an external bundle")
    authentication.add_argument("--manifest-sha256",
                                help="SHA-256 of manifest.json for a bundle built locally by ./install")
    new.add_argument("--development", action="store_true", help="Select the development channel instead of the release channel")
    new.add_argument("--origin", required=True)
    new.add_argument("--port", type=int, default=18080)
    new.add_argument("--web-enrollment", action="store_true", help="Require Owner fingerprint confirmation for --targets")
    new.add_argument("--targets", type=Path, help="Optional locally approved protected target policy; otherwise empty")
    new.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    new.add_argument("--check", action="store_true", help="Validate preconditions and all bundle files without installing")
    commands.add_parser("verify-image", help="Internal systemd preflight for the installed image identity")
    owner = commands.add_parser("create-owner", help="Create the initial Owner locally using hidden password input")
    owner.add_argument("--username", required=True)
    # The bootstrap interpreter has no application wheel until install completes.
    if Path(sys.prefix) == APP / "venv":
        from vpn_orbit.runtime.backup import add_commands
        add_commands(commands)
        diagnostic = commands.add_parser("diagnose", help="Collect a local diagnostic report without secrets")
        diagnostic.add_argument("--output", type=Path, help="Write a new 0600 JSON report in a protected directory")
        diagnostic.add_argument("--backup-directory", default=Path("/var/backups/vpn-orbit"), type=Path)
        restore = commands.add_parser("restore-apply", help="Install staged state on this stopped controller in read-only recovery")
        restore.add_argument("--sha256", required=True)
        restore.add_argument("--resume", action="store_true", help="Resume an interrupted restore of this exact archive")
        restore.add_argument("--confirm-replace", action="store_true", required=True,
                             help="Confirm local replacement and retain the previous state for review")
        commands.add_parser("activation-review", help="Print the binding for independently verified fencing evidence")
        activate = commands.add_parser("activate", help="Activate a recovered controller after fencing and Owner confirmation")
        activate.add_argument("--report", type=Path, required=True)
        activate.add_argument("--owner", required=True)
        activate.add_argument("--confirm", action="store_true", required=True)
        schema = commands.add_parser("schema-check", help="Review all installed data contracts without modifying databases")
        schema.add_argument("--target-schema", type=int, help="Expected SQLite schema of the candidate release")
        commands.add_parser("release-check", help="Look up the latest stable public GitHub release without installing it")
        candidate = commands.add_parser("update-check", help="Verify a local signed update bundle without executing it")
        candidate.add_argument("--bundle", type=Path, required=True)
        candidate.add_argument("--version", required=True, help="Expected candidate version without v")
        candidate.add_argument("--trust-key", type=Path, help="Independently obtained public key for an installation without a pinned signer")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ArtifactError("LOCAL_ROOT_REQUIRED")
        if args.command == "install":
            install(args)
        elif args.command == "verify-image":
            verify_image()
        elif args.command == "create-owner":
            if (DATA / "restore.pending").exists():
                raise ArtifactError("RESTORE_RESUME_REQUIRED")
            create_owner(args.username)
        elif args.command == "diagnose":
            from vpn_orbit.runtime.diagnostics import report, write_report
            info = report(load_installation(), directory=args.backup_directory)
            if args.output:
                write_report(args.output, info)
            print(json.dumps(info))
        elif args.command == "restore-apply":
            os.umask(0o077)
            import resource
            from vpn_orbit.runtime.recovery import install as restore_install
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            print(json.dumps(restore_install(args.sha256, docker_host=load_installation()["docker_host"], resume=args.resume)))
        elif args.command in {"activation-review", "activate"}:
            import resource
            from vpn_orbit.runtime.activation import activate, review
            from vpn_orbit.runtime.backup import secure_directory
            from vpn_orbit.runtime.cli import configuration
            from vpn_orbit.runtime.storage import protected_bytes
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            cfg = configuration(CONFIG / "runtime.json")
            if args.command == "activation-review":
                print(json.dumps(review(cfg)))
            else:
                secure_directory(args.report.absolute().parent)
                report = json.loads(protected_bytes(args.report, owner=0, exact_mode=0o600, maximum=65536))
                print(json.dumps(activate(cfg, report, args.owner, getpass.getpass("Owner password: "))))
        elif args.command == "schema-check":
            from vpn_orbit.runtime.cli import configuration
            from vpn_orbit.runtime.data_contract import inspect
            options = {} if args.target_schema is None else {"target_schema": args.target_schema}
            print(json.dumps(inspect(configuration(CONFIG / "runtime.json"), **options)))
        elif args.command == "release-check":
            print(json.dumps(discover_release(load_installation()["version"])))
        elif args.command == "update-check":
            print(json.dumps(check_update_bundle(args, load_installation())))
        else:
            from vpn_orbit.runtime.backup import administer
            print(json.dumps(administer(args)))
    except Exception as error:
        # Keep arbitrary subprocess, filesystem, validation and secret values out of output.
        from_code = getattr(error, "code", None)
        category = {"backup": "BACKUP", "backup-verify": "BACKUP", "diagnose": "DIAGNOSTICS",
                    "release-check": "UPDATE", "update-check": "UPDATE",
                    "activation-review": "ACTIVATION", "activate": "ACTIVATION",
                    "restore-stage": "RESTORE", "restore-apply": "RESTORE"}.get(args.command, "INSTALLATION")
        code = str(error) if isinstance(error, ArtifactError) else from_code or category + "_UNAVAILABLE"
        print("VPN-Orbit: " + code, file=sys.stderr)
        if code == "INSTALLATION_UNAVAILABLE":
            # Code locations and exception classes help diagnose installation
            # failures without forwarding exception messages or local values.
            frames = traceback.extract_tb(error.__traceback__)
            sites = ",".join(str(frame.lineno) for frame in frames if frame.filename == __file__)
            print(f"failure_site=installer.py:{sites} error_type={type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
