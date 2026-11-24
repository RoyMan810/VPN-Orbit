"""Encrypted offline volume and configuration backups of owned installations."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import subprocess
import tarfile
import tempfile

from .app_lifecycle import ROOT, ULID, Lifecycle, private_directory, refuse
from .app_postgres import docker, execute
from .app_profiles import canonical, digest, render, validate
from .errors import Denied
from .runtime import backup
from .runtime.storage import directory_sync, new_private_file, process_lock


LIMIT = 4 * 1024**3
ENTRY = re.compile(r"vol-[a-z0-9]{1,20}-[a-z0-9]{1,20}\.tar")


def read_index(raw):
    value = json.loads(raw)
    if (not isinstance(value, dict) or canonical(value) != raw or set(value) != {"v", "kind", "files", "spec_sha256"}
            or type(value["v"]) is not int or value["v"] != 1 or value["kind"] != "vpn-orbit-app"
            or not backup.SHA256.fullmatch(value["spec_sha256"])):
        refuse("APP_BACKUP_MANIFEST_INVALID")
    files = value["files"]
    if not isinstance(files, dict) or "spec.json" not in files or len(files) > 32:
        refuse("APP_BACKUP_MANIFEST_INVALID")
    for name, entry in files.items():
        if ((name != "spec.json" and not ENTRY.fullmatch(name)) or not isinstance(entry, dict)
                or set(entry) != {"sha256", "size"} or not backup.SHA256.fullmatch(entry["sha256"])
                or type(entry["size"]) is not int or not 0 < entry["size"] <= (65536 if name == "spec.json" else LIMIT)):
            refuse("APP_BACKUP_MANIFEST_INVALID")
    if sum(entry["size"] for entry in files.values()) > LIMIT:
        refuse("APP_BACKUP_SIZE_LIMIT")
    return value


def inspect_tar(path):
    names = set()
    if path.stat().st_size > LIMIT:
        refuse("APP_BACKUP_SIZE_LIMIT")
    with tarfile.open(path, "r:") as archive:
        for entry in archive:
            path = PurePosixPath(entry.name)
            if (path.is_absolute() or ".." in path.parts or path in names or len(names) >= 1_000_000
                    or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or entry.pax_headers
                    or entry.sparse is not None or entry.mode & 0o6000 or (entry.mode & 0o1000 and not entry.isdir())
                    or not 0 <= entry.uid <= 2**31 - 1
                    or not 0 <= entry.gid <= 2**31 - 1 or (not path.parts and not entry.isdir())):
                refuse("APP_BACKUP_VOLUME_ENTRY_UNSAFE")
            names.add(path)
    if PurePosixPath(".") not in names:
        refuse("APP_BACKUP_VOLUME_INVALID")
    return len(names)


def transfer(app, spec, volume, *, writing=False, data=None):
    image = spec["images"]["postgres"]  # Already-pinned image for volume helpers.
    name = volume["name"]
    if not re.fullmatch(r"vo-app-[a-z0-9]{26}-[a-z0-9-]{1,40}", name):
        refuse("APP_BACKUP_VOLUME_INVALID")
    image_id = app.inspect("image", image)["Id"]
    if not isinstance(image_id, str) or not image_id.startswith("sha256:") or not backup.SHA256.fullmatch(image_id[7:]):
        refuse("APP_IMAGE_DRIFT")
    read_only = "" if writing else ",readonly"
    argv = ("run", "--rm", "--network", "none", "--pull", "never", "--read-only", "--user", "0:0",
            "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges:true",
            "--mount", f"type=volume,source={name},target=/payload,volume-nocopy{read_only}", "--entrypoint", "tar")
    if writing:
        docker(*argv, "--cap-add", "CHOWN", "--cap-add", "FOWNER", "-i", image_id,
               "--extract", "--numeric-owner", "--same-owner", "-f", "-", "-C", "/payload", stdin=data)
    else:
        docker(*argv, image_id, "--create", "--format=ustar", "-f", "-", "-C", "/payload", ".", stdout=data)


def scratch():
    if execute("/usr/bin/stat", "-f", "-c", "%T", "/run").strip() != b"tmpfs":
        refuse("BACKUP_TMPFS_REQUIRED")
    return tempfile.TemporaryDirectory(prefix="orbit-app-state-", dir="/run")


def write_archive(root, recipient, output, spec, files):
    if not backup.RECIPIENT.fullmatch(recipient):
        refuse("BACKUP_RECIPIENT_UNSUPPORTED")
    path = backup.secure_directory(output.absolute().parent, private=True) / output.name
    if os.path.lexists(path):
        refuse("APP_BACKUP_ARCHIVE_EXISTS")
    index = {"v": 1, "kind": "vpn-orbit-app", "spec_sha256": digest(spec), "files": {}}
    for name, file in files.items():
        with file.open("rb") as stream:
            index["files"][name] = {"sha256": hashlib.file_digest(stream, "sha256").hexdigest(), "size": file.stat().st_size}
    raw = canonical(index)
    read_index(raw)
    if shutil.disk_usage(root).free < sum(entry["size"] for entry in index["files"].values()) + 1024**2:
        refuse("APP_BACKUP_STAGING_SPACE_INSUFFICIENT")
    archive = root / "plaintext.tar"
    with archive.open("xb") as stream:
        backup.write_archive(stream, raw, files)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".orbit-app-")
    try:
        with os.fdopen(fd, "w+b") as output, archive.open("rb") as source:
            execute(backup.AGE, "-e", "-r", recipient, stdin=source, stdout=output)
            os.fsync(output.fileno())
            output.seek(0)
            checksum = hashlib.file_digest(output, "sha256").hexdigest()
        os.link(tmp, path)
        directory_sync(path.parent)
    finally:
        Path(tmp).unlink(missing_ok=True)
    return {"status": "CAPTURED_OFFLINE", "sha256": checksum, "spec_sha256": index["spec_sha256"]}


def capture(identity, expected, recipient, archive):
    app = Lifecycle(identity)
    with app.locked(), scratch() as tmp:
        if os.path.lexists(app.directory / "restore.pending"):
            refuse("APP_RESTORE_INCOMPLETE")
        root = Path(tmp)
        spec, doc, state = app.configuration()
        if state["spec_digest"] != expected or state["removed"]:
            refuse("APP_BACKUP_SCOPE_MISMATCH")
        with app.journal.connect() as db:
            if db.execute("SELECT 1 FROM operations WHERE resolution IS NULL AND state IN ('DISPATCHING','UNKNOWN_OUTCOME')").fetchone():
                refuse("APP_RECONCILIATION_REQUIRED")
        inventory = app.verify_inventory(doc, state)
        for service, row in inventory["containers"].items():
            observed = app.inspect("container", row["Id"])["State"]
            if observed["Running"] or (service.endswith("-db") and (observed["ExitCode"] or observed["OOMKilled"])):
                refuse("APP_BACKUP_STOP_CLEANLY_FIRST")
        files = {"spec.json": root / "spec.json"}
        files["spec.json"].write_bytes(canonical(spec))
        for name, volume in doc["volumes"].items():
            label = f"vol-{name}.tar"
            if not ENTRY.fullmatch(label):
                refuse("APP_BACKUP_VOLUME_INVALID")
            files[label] = root / label
            with files[label].open("xb") as stream:
                transfer(app, spec, volume, data=stream)
            inspect_tar(files[label])
        if app.verify_inventory(doc, state) != inventory or any(app.inspect("container", c["Id"])["State"]["Running"]
                                                              for c in inventory["containers"].values()):
            refuse("APP_BACKUP_SCOPE_MISMATCH")
        return write_archive(root, recipient, archive, spec, files)


def restore(archive, identity, expected, requested_id=None):
    if not backup.SHA256.fullmatch(expected):
        refuse("BACKUP_CIPHERTEXT_DIGEST_MISMATCH")
    with scratch() as tmp:
        root = Path(tmp)

        def space(manifest):
            if shutil.disk_usage(root).free < sum(item["size"] for item in manifest["files"].values()) + 1024**2:
                refuse("APP_BACKUP_STAGING_SPACE_INSUFFICIENT")

        index = backup.decrypt_archive(archive, identity, age=backup.AGE, expected_sha256=expected,
                                       validator=read_index, start=space, sink=lambda name: (root / name).open("xb"))
        spec = json.loads((root / "spec.json").read_bytes())
        validate(spec)
        document = render(spec, "0" * 64)
        if digest(spec) != index["spec_sha256"] or set(index["files"]) != {"spec.json", *(
                f"vol-{name}.tar" for name in document["volumes"])}:
            refuse("APP_BACKUP_SCOPE_MISMATCH")
        for name in document["volumes"]:
            inspect_tar(root / f"vol-{name}.tar")
        if requested_id is not None:
            if not re.fullmatch(ULID, requested_id):
                refuse("APP_ID_INVALID")
            spec["id"] = requested_id
        backup.secure_directory(ROOT.parent)
        ROOT.mkdir(mode=0o700, exist_ok=True)
        private_directory(ROOT, 0)
        with process_lock(ROOT / "lifecycle.lock"):
            if os.path.lexists(ROOT / spec["id"]):
                refuse("APP_RESTORE_DESTINATION_EXISTS")
            app = Lifecycle(Lifecycle.configure(spec))
            marker = app.directory / "restore.pending"
            new_private_file(marker, canonical({"v": 1, "archive_sha256": expected}))
            _, document, binding = app.configuration()
            if app.docker("container", "ls", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + document["name"]).strip():
                refuse("APP_FOREIGN_RESOURCE")
            for kind, key in (("volume", "volumes"), ("network", "networks")):
                names = set(app.docker(kind, "ls", "--format", "{{.Name}}").splitlines())
                if names.intersection(item["name"] for item in document[key].values()):
                    refuse("APP_FOREIGN_RESOURCE")
            for image in sorted(set(spec["images"].values())):
                app.acquire_image(image)
            app.compose(document, "create", "--no-build", "--pull", "never")
            inventory = app.inventory(document)
            with app.journal.write() as db:
                db.execute("UPDATE installation SET inventory=? WHERE id=1", (canonical(inventory).decode(),))
            _, _, binding = app.configuration()
            for name, volume in document["volumes"].items():
                app.verify_inventory(document, binding)
                empty = root / "empty.tar"
                with empty.open("wb") as stream:
                    transfer(app, spec, volume, data=stream)
                if inspect_tar(empty) != 1:
                    refuse("APP_RESTORE_VOLUME_NOT_EMPTY")
                with (root / f"vol-{name}.tar").open("rb") as stream:
                    transfer(app, spec, volume, writing=True, data=stream)
            app.verify_inventory(document, binding)
            new_private_file(app.directory / "restore-evidence.json", canonical({"v": 1, "archive_sha256": expected,
                                                                                "spec_sha256": digest(spec)}))
            marker.unlink()
            directory_sync(marker.parent)
            return {"status": "RESTORED_STOPPED", "installation": app.identity, "spec_sha256": digest(spec)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "restore"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--id")
    parser.add_argument("--spec-sha256")
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            refuse("LOCAL_ROOT_REQUIRED")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        backup.secure_directory(backup.AGE.parent)
        if args.action == "capture":
            if not (args.id and args.spec_sha256 and args.recipient):
                refuse("APP_BACKUP_SCOPE_MISMATCH")
            value = capture(args.id, args.spec_sha256, args.recipient, args.archive)
        else:
            if not (args.identity and args.sha256):
                refuse("BACKUP_CIPHERTEXT_DIGEST_MISMATCH")
            value = restore(args.archive, args.identity, args.sha256, args.id)
        print(json.dumps(value))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(json.dumps({"status": "REFUSED", "code": error.code if isinstance(error, Denied) else "APP_BACKUP_UNAVAILABLE"}))
        return 1
