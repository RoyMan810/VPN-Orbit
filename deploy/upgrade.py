#!/usr/bin/env python3
"""In-place 1.0.0 -> 1.1.0 upgrade from an independently trusted checkout."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import ssl
import stat
import sys
import time
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

import installer as base
from artifact import AGE_FILE, ArtifactError, WEB_INDEX, canonical, manifest, snapshot


SOURCE, TARGET = "1.0.0", "1.1.0"
SLOT = base.APP / "upgrade-1.1.0"
RECORD = SLOT / "transaction.json"
MARKER = base.DATA / "update.blocked"
RESTORE_MARKER = base.DATA / "restore.pending"
WEB = base.APP.parent / "vpn-orbit-bootstrap"
PROXY = "vpn-orbit-web.service"
UNIT_GROUP = (base.COMPOSE_UNIT, *base.HOST_UNITS, PROXY)
SYSTEMCTL = "/usr/bin/systemctl"
PHASES = ("PREPARED", "DRAINING", "QUIESCENT", "BACKED_UP", "SWITCHING", "TESTING", "COMMITTING",
          "ROLLING_BACK", "FAILED_SAFE", "ROLLED_BACK", "COMPLETE")


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def trusted_dir(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ArtifactError("UPDATE_DIRECTORY_UNTRUSTED")


def read_file(path, limit=1024**2):
    trusted_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ArtifactError("UPDATE_FILE_UNTRUSTED")
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise ArtifactError("UPDATE_FILE_TOO_LARGE")
        return value


@contextmanager
def maintenance_lock():
    for path in (base.RUN, base.DATA, base.CONFIG, base.APP, base.UNITS):
        trusted_dir(path)
    lock = base.RUN / "maintenance.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ArtifactError("UPDATE_LOCK_INVALID")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ArtifactError("MAINTENANCE_ALREADY_RUNNING") from None
        if os.path.lexists(RESTORE_MARKER):
            raise ArtifactError("RESTORE_IN_PROGRESS")
        yield
    finally:
        os.close(fd)


def runtime(*args, timeout=30):
    return json.loads(base.command(SLOT / "venv/bin/python", "-I", "-m", "vpn_orbit.runtime.upgrade",
                                   *args, timeout=timeout))


def save(state, phase, **extra):
    state.update(phase=phase, **extra)
    base.write(RECORD, canonical(state), mode=0o600, replace=True)


def load():
    state = json.loads(read_file(RECORD, 65536))
    if (state.get("v") != 1 or state.get("phase") not in PHASES or state.get("source") != SOURCE or state.get("target") != TARGET
            or not re.fullmatch(r"[0-9a-f]{64}", state["digest"])):
        raise ArtifactError("UPDATE_TRANSACTION_INVALID")
    base.daemon(state["docker_host"])
    return state


def compose(state, *args, timeout=120):
    return base.docker(state["docker_host"], "compose", "--project-name", "vpn-orbit",
                       "--project-directory", base.APP, "--file", base.CONFIG / "compose.json", *args, timeout=timeout)


def add_condition(raw):
    condition = b"ConditionPathExists=!/var/lib/vpn-orbit/restore.pending"
    if condition in raw.splitlines():
        return raw
    if not raw.startswith(b"[Unit]\n"):
        raise ArtifactError("UPDATE_SYSTEMD_CONTRACT_UNSUPPORTED")
    return raw.replace(b"[Unit]\n", b"[Unit]\n" + condition + b"\n", 1)


def installed_files(web):
    selected = {"installation": (base.APP / "installation.json", 0o600),
                "install_state": (base.APP / "install-state.json", 0o600),
                "compose": (base.CONFIG / "compose.json", 0o644)}
    for name in (*base.HOST_UNITS, base.COMPOSE_UNIT, *((PROXY,) if web else ())):
        selected[name] = (base.UNITS / name, 0o644)
    return selected


def install_guards():
    content = b"[Unit]\nConditionPathExists=!/var/lib/vpn-orbit/update.blocked\n"
    for unit in UNIT_GROUP:
        folder = base.UNITS / (unit + ".d")
        base.system_config_directory(folder)
        path = folder / "40-vpn-orbit-upgrade.conf"
        if os.path.lexists(path):
            if read_file(path) != content:
                raise ArtifactError("UPDATE_SYSTEMD_GUARD_CONFLICT")
        else:
            base.write(path, content)
    base.command(SYSTEMCTL, "daemon-reload")


def prepare(args):
    installed = base.load_installation()
    if installed["version"] != SOURCE or installed["channel"] != "release":
        raise ArtifactError("UPDATE_SOURCE_VERSION_UNSUPPORTED")
    initial = json.loads(read_file(base.APP / "install-state.json"))
    if initial != {"v": 1, "phase": "COMPLETE", "manifest_sha256": installed["manifest_sha256"]}:
        raise ArtifactError("UPDATE_SOURCE_INSTALLATION_INCOMPLETE")
    base.verify_image()
    if os.path.lexists(SLOT):
        raise ArtifactError("UPDATE_TRANSACTION_ALREADY_EXISTS")
    if min(shutil.disk_usage(path).free for path in (base.APP, base.DATA, base.CONFIG)) < 2 * 1024**3:
        raise ArtifactError("UPDATE_DISK_SPACE_INSUFFICIENT")
    pinned = base.CONFIG / "release-trust.pub"
    pinned_before = os.path.lexists(pinned)
    key_path = args.trust_key or pinned
    if key_path.resolve().is_relative_to(args.bundle.resolve()):
        raise ArtifactError("INDEPENDENT_TRUST_KEY_REQUIRED")
    key = base.trusted_key(key_path)
    if pinned_before and base.trusted_key(pinned) != key:
        raise ArtifactError("UPDATE_TRUST_KEY_MISMATCH")
    base.folder(SLOT, 0o755)
    try:
        stage = SLOT / "bundle"
        release, digest = snapshot(args.bundle, stage, key)
        if release["version"] != TARGET or release["python"] != f"{sys.version_info.major}.{sys.version_info.minor}":
            raise ArtifactError("UPDATE_BUNDLE_VERSION_MISMATCH")
        if not (stage / AGE_FILE).is_file():
            raise ArtifactError("PINNED_AGE_TOOL_REQUIRED")
        web = os.path.lexists(base.UNITS / PROXY)
        if web:
            trusted_dir(WEB / "web")
            if WEB.stat().st_dev != SLOT.stat().st_dev or not (stage / WEB_INDEX).is_file():
                raise ArtifactError("UPDATE_SIGNED_WEB_REQUIRED")
            shutil.copytree(stage / "web", SLOT / "web")
            for path in (SLOT / "web", *(SLOT / "web").rglob("*")):
                path.chmod(0o755 if path.is_dir() else 0o644)
        host = installed["docker_host"]
        if not base.docker(host, "version", "--format", "{{.Server.Version}}").startswith("29."):
            raise ArtifactError("DOCKER_VERSION_UNSUPPORTED")
        if not base.supported_compose(base.docker(host, "compose", "version", "--short")):
            raise ArtifactError("DOCKER_COMPOSE_UNSUPPORTED")
        base.check_buildx(host)
        image = base.controller_image("release", digest)
        base.docker(host, "pull", "--platform", "linux/amd64", release["python_image"], timeout=600)
        base.docker(host, "build", "--network=none", "--pull=false", "--build-arg", "PYTHON_IMAGE=" + release["python_image"],
                    "--tag", image, "--file", stage / "deploy/Controller.Dockerfile", stage, timeout=240)
        image_id = base.docker(host, "image", "inspect", "--format", "{{.Id}}", image)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ArtifactError("UPDATE_IMAGE_ID_INVALID")
        base.command(sys._base_executable, "-I", "-m", "venv", SLOT / "venv", timeout=120)
        python = SLOT / "venv/bin/python"
        base.command(python, "-I", "-m", "pip", "install", "--no-index", "--find-links", stage / "wheelhouse",
                     "--require-hashes", "-r", stage / "requirements-install.txt", timeout=180)
        for path in (SLOT / "venv", *(SLOT / "venv").rglob("*")):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        base.command(python, "-I", "-c", "import sys, vpn_orbit; assert vpn_orbit.__version__ == sys.argv[1]", TARGET)
        if runtime("inspect")["writer_phase"] != "OPEN":
            raise ArtifactError("UPDATE_ADMISSION_NOT_OPEN")

        old, new = SLOT / "old", SLOT / "new"
        old.mkdir(mode=0o700)
        new.mkdir(mode=0o700)
        for name, (path, mode) in installed_files(web).items():
            base.write(old / name, read_file(path), mode=mode)
        config = json.loads(read_file(base.CONFIG / "runtime.json"))
        profile = {**installed, "version": TARGET, "manifest_sha256": digest, "image": image, "image_id": image_id,
                   "source_commit": release["source_commit"], "authentication": "signature"}
        contents = {"installation": canonical(profile), "install_state": canonical({**initial, "manifest_sha256": digest}),
                    "compose": canonical(base.compose_document(config, image, installed["port"]))}
        for name in base.HOST_UNITS:
            contents[name] = (stage / "deploy/systemd" / name).read_bytes()
        for unit in (base.COMPOSE_UNIT, *((PROXY,) if web else ())):
            contents[unit] = add_condition(read_file(old / unit))
        for name, raw in contents.items():
            base.write(new / name, raw, mode=installed_files(web)[name][1])
        base.write(SLOT / "signer.pub", key, mode=0o600)
        install_guards()
        for current, _, files in os.walk(SLOT, topdown=False):
            for name in files:
                path = Path(current) / name
                if not path.is_symlink():
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
            fsync_dir(current)
        fsync_dir(SLOT.parent)
        state = {"v": 1, "source": SOURCE, "target": TARGET, "digest": digest, "docker_host": host, "pinned_before": pinned_before,
                 "web": web, "port": installed["port"], "origin": config["public_origin"]}
        save(state, "PREPARED")
        return state
    except Exception:
        if not RECORD.exists():  # This invocation created the slot; no data or executable switched.
            shutil.rmtree(SLOT)
        raise


def block():
    if not os.path.lexists(MARKER):
        base.write(MARKER, b"VPN_ORBIT_UPDATE\n", mode=0o600)
    elif read_file(MARKER) != b"VPN_ORBIT_UPDATE\n":
        raise ArtifactError("UPDATE_MARKER_INVALID")


def unblock():
    if os.path.lexists(MARKER):
        if read_file(MARKER) != b"VPN_ORBIT_UPDATE\n":
            raise ArtifactError("UPDATE_MARKER_INVALID")
        MARKER.unlink()
        fsync_dir(MARKER.parent)


def stop(state):
    services = [base.COMPOSE_UNIT, *base.HOST_UNITS] + ([PROXY] if state["web"] else [])
    base.command(SYSTEMCTL, "stop", *services, timeout=150)
    for unit in services:
        if base.command(SYSTEMCTL, "show", "--property=ActiveState", "--value", unit) != "inactive":
            raise ArtifactError("UPDATE_SERVICES_STILL_RUNNING")
    for unit in ("vpn-orbit-api.service", "vpn-orbit-worker.service"):
        if base.command(SYSTEMCTL, "show", "--property=ActiveState", "--value", unit) != "inactive":
            raise ArtifactError("UPDATE_SYSTEMD_CONTRACT_UNSUPPORTED")
    if base.docker(state["docker_host"], "ps", "--quiet", "--filter=label=com.docker.compose.project=vpn-orbit"):
        raise ArtifactError("UPDATE_CONTAINERS_STILL_RUNNING")


def drain():
    deadline = time.monotonic() + 120
    while runtime("busy")["busy"]:
        if time.monotonic() >= deadline:
            raise ArtifactError("UPDATE_ACTIVE_OPERATIONS")
        time.sleep(1)


def switch_directory(current, candidate, original, *, forward):
    if forward:
        if current.is_symlink():
            if Path(os.readlink(current)) != candidate or not original.is_dir():
                raise ArtifactError("UPDATE_DIRECTORY_CONFLICT")
            return
        if current.is_dir():
            if original.exists():
                raise ArtifactError("UPDATE_DIRECTORY_CONFLICT")
            os.rename(current, original)
            fsync_dir(current.parent)
            fsync_dir(original.parent)
        elif os.path.lexists(current) or not original.is_dir():
            raise ArtifactError("UPDATE_DIRECTORY_CONFLICT")
        os.symlink(candidate, current)
        fsync_dir(current.parent)
    elif original.is_dir():
        if current.is_symlink() and Path(os.readlink(current)) == candidate:
            current.unlink()
        if os.path.lexists(current):
            raise ArtifactError("UPDATE_DIRECTORY_CONFLICT")
        os.rename(original, current)
        fsync_dir(original.parent)
        fsync_dir(current.parent)
    elif current.is_symlink() or not current.is_dir():
        raise ArtifactError("UPDATE_DIRECTORY_CONFLICT")


def switch(state, *, forward):
    if not MARKER.exists():
        raise ArtifactError("UPDATE_NOT_FENCED")
    stop(state)
    compose(state, "rm", "--force")
    directories = [(base.APP / "venv", SLOT / "venv", SLOT / "old/venv"),
                   (base.APP / "bundle", SLOT / "bundle", SLOT / "old/bundle")]
    if state["web"]:
        directories.append((WEB / "web", SLOT / "web", SLOT / "old/web"))
    for current, candidate, original in directories:
        switch_directory(current, candidate, original, forward=forward)
    for name, (path, mode) in installed_files(state["web"]).items():
        base.write(path, read_file(SLOT / ("new" if forward else "old") / name), mode=mode, replace=True)
    pinned = base.CONFIG / "release-trust.pub"
    if not state["pinned_before"]:
        key = read_file(SLOT / "signer.pub", 32)
        if os.path.lexists(pinned):
            if read_file(pinned) != key:
                raise ArtifactError("UPDATE_TRUST_KEY_MISMATCH")
            if not forward:
                pinned.unlink()
                fsync_dir(pinned.parent)
        elif forward:
            base.write(pinned, key)
    base.command(SYSTEMCTL, "daemon-reload")


def check_staging(state):
    release, raw, _ = manifest(SLOT / "bundle", base.trusted_key(SLOT / "signer.pub"))
    if release["version"] != TARGET or hashlib.sha256(raw).hexdigest() != state["digest"]:
        raise ArtifactError("UPDATE_STAGE_INVALID")


def smoke(state, version):
    base.verify_image()
    base.command(SYSTEMCTL, "start", *base.HOST_UNITS, timeout=90)
    base.command(SYSTEMCTL, "start", base.COMPOSE_UNIT, timeout=155)
    if state["web"]:
        base.command(SYSTEMCTL, "start", PROXY, timeout=45)
    for unit in (base.COMPOSE_UNIT, *base.HOST_UNITS, *((PROXY,) if state["web"] else ())):
        if base.command(SYSTEMCTL, "is-active", unit).strip() != "active":
            raise ArtifactError("UPDATE_SERVICE_INACTIVE")
    local = f"http://127.0.0.1:{state['port']}"
    handlers = [ProxyHandler({}), base.NoRedirect()]
    addresses = [local]
    if state["web"]:
        origin = base.origin(state["origin"])
        ca = str(WEB / "web-ca.pem") if origin == "https://127.0.0.1:18443" else None
        handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
        addresses.append(origin)
    http = build_opener(*handlers)
    for address in addresses:
        with http.open(address + "/healthz", timeout=7) as response:
            if json.load(response) != {"status": "alive", "version": version}:
                raise ArtifactError("UPDATE_HEALTH_PROBE_FAILED")
    if state["web"]:
        with http.open(addresses[-1] + "/", timeout=7) as response:
            if response.read(2 * 1024**2) != read_file(WEB / "web/index.html" if version == SOURCE else SLOT / "web/index.html"):
                raise ArtifactError("UPDATE_WEB_PROBE_FAILED")
    image_id = base.load_installation()["image_id"]
    for service in ("api", "worker"):
        cid = compose(state, "ps", "--quiet", service, timeout=15)
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise ArtifactError("UPDATE_CONTAINER_NOT_RUNNING")
        info = base.docker(state["docker_host"], "inspect", "--format", "{{.State.Running}} {{.Image}}", cid)
        if info != "true " + image_id:
            raise ArtifactError("UPDATE_CONTAINER_NOT_RUNNING")


def rollback(state):
    if state["phase"] in ("COMMITTING", "COMPLETE"):
        raise ArtifactError("UPDATE_ALREADY_COMMITTED")
    save(state, "ROLLING_BACK")
    runtime("close")
    drain()
    block()
    # Only the explicitly compatible 1.0.0 contract may be reopened. Never
    # restore an older database over a potentially newer live database.
    info = runtime("inspect")
    if info["databases"] != {"app/controller.sqlite3": 6, "broker/receipts.sqlite3": 1,
                             "vault/vault.sqlite3": 1, "control-gate/gate.sqlite3": 1,
                             "control-gate/time-health/time.sqlite3": 1}:
        raise ArtifactError("UPDATE_ROLLBACK_DATA_INCOMPATIBLE")
    switch(state, forward=False)
    unblock()
    smoke(state, SOURCE)
    runtime("open")
    save(state, "ROLLED_BACK")


def apply(state, args):
    try:
        if state["phase"] == "PREPARED":
            save(state, "DRAINING")
        if state["phase"] == "DRAINING":
            runtime("close")
            drain()
            block()
            stop(state)
            save(state, "QUIESCENT")
        if state["phase"] == "QUIESCENT":
            if not (args.backup_directory and args.recipient and args.identity):
                raise ArtifactError("UPDATE_BACKUP_IDENTITY_REQUIRED")
            result = runtime("capture", args.backup_directory, args.recipient, args.identity, timeout=240)
            if result["decryption_verified"] is not True:
                raise ArtifactError("UPDATE_BACKUP_NOT_VERIFIED")
            save(state, "BACKED_UP", backup_sha256=result["sha256"], backup_file=result["archive"])
        if state["phase"] == "BACKED_UP":
            result = runtime("migrate", timeout=150)
            save(state, "SWITCHING", migrations=result["migrations"])
        if state["phase"] == "SWITCHING":
            switch(state, forward=True)
            save(state, "TESTING")
        if state["phase"] == "TESTING":
            unblock()
            smoke(state, TARGET)
            if runtime("inspect")["migration"] != "NOT_REQUIRED":
                raise ArtifactError("UPDATE_DATA_CONTRACT_NOT_READY")
            save(state, "COMMITTING")
        if state["phase"] == "COMMITTING":
            # Never rollback after the durable decision to allow live writes.
            smoke(state, TARGET)
            runtime("open")
            save(state, "COMPLETE")
        if state["phase"] not in ("COMPLETE", "ROLLED_BACK"):
            raise ArtifactError("UPDATE_RESUME_OR_ROLLBACK_REQUIRED")
    except Exception as exc:
        if state["phase"] not in ("COMMITTING", "COMPLETE", "ROLLED_BACK", "ROLLING_BACK", "FAILED_SAFE"):
            code = str(exc) if isinstance(exc, ArtifactError) else "UPDATE_APPLY_FAILED"
            save(state, state["phase"], failure=code)
            try:
                rollback(state)
            except Exception:
                block()
                save(state, "FAILED_SAFE")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--bundle", type=Path)
    mode.add_argument("--resume", action="store_true")
    mode.add_argument("--rollback", action="store_true")
    parser.add_argument("--trust-key", type=Path)
    parser.add_argument("--backup-directory", type=Path)
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path, help="Temporary readable private age identity for local backup verification")
    parser.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ArtifactError("LOCAL_ROOT_REQUIRED")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with maintenance_lock():
        state = prepare(args) if args.bundle else load()
        check_staging(state)
        if args.rollback or (args.resume and state["phase"] in ("ROLLING_BACK", "FAILED_SAFE")):
            rollback(state)
        else:
            apply(state, args)
        print(json.dumps({key: state[key] for key in ("phase", "source", "target", "digest", "backup_sha256", "migrations")
                          if key in state}))


if __name__ == "__main__":
    try:
        main()
    except (ArtifactError, OSError, RuntimeError, ValueError, KeyError) as error:
        print("VPN-Orbit: " + (str(error) if isinstance(error, ArtifactError) else "UPDATE_UNAVAILABLE"), file=sys.stderr)
        raise SystemExit(1) from None
