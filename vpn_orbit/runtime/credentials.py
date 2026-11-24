"""Host-bound OS wrapping; no plaintext credential file, argv or environment."""

import base64
import binascii
import os
from pathlib import Path
import stat
import subprocess

from ..errors import Denied
from .storage import new_private_file, protected_bytes


# systemd's CRED_AES256_GCM_BY_HOST. Allow only what seal_credential
# produces, including on systemd 255, which does not have --refuse-null.
_HOST_CREDENTIAL = bytes.fromhex("5a1c6a86df9d4096b1d5a65e0862f19a")


def unseal_credential(source):
    """Local root only. Return the DEK to the caller, not to a path or log."""
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    sealed = protected_bytes(source, owner=0, exact_mode=0o600)
    try:
        envelope = base64.b64decode(b"".join(sealed.split()), validate=True)
    except binascii.Error:
        raise Denied("OS_CREDENTIAL_UNSEAL_FAILED") from None
    if not envelope.startswith(_HOST_CREDENTIAL):
        raise Denied("OS_CREDENTIAL_UNSEAL_FAILED")
    try:
        result = subprocess.run(
            ["/usr/bin/systemd-creds", "decrypt", "--name=broker-dek", "-", "-"],
            input=sealed, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("OS_CREDENTIAL_UNSEAL_FAILED") from None
    if result.returncode or len(result.stdout) != 32:
        raise Denied("OS_CREDENTIAL_UNSEAL_FAILED")
    return result.stdout


def seal_credential(key, destination):
    if os.geteuid() != 0:
        raise Denied("LOCAL_ROOT_REQUIRED")
    if not isinstance(key, bytes) or len(key) != 32:
        raise Denied("VAULT_KEY_INVALID")
    destination = Path(destination).absolute()
    for parent in destination.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Denied("CREDENTIAL_PARENT_UNTRUSTED")
    parent = destination.parent.lstat()
    if stat.S_IMODE(parent.st_mode) != 0o700:
        raise Denied("CREDENTIAL_DIRECTORY_NOT_PRIVATE")
    if destination.exists() or destination.is_symlink():
        raise Denied("CREDENTIAL_ALREADY_EXISTS")
    try:
        result = subprocess.run(["/usr/bin/systemd-creds", "encrypt", "--with-key=host", "--name=broker-dek", "-", "-"],
            input=key, capture_output=True, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("OS_CREDENTIAL_SEAL_FAILED") from None
    if result.returncode or not 64 <= len(result.stdout) <= 16384:
        raise Denied("OS_CREDENTIAL_SEAL_FAILED")
    new_private_file(destination, result.stdout)


def initialize_credential(config):
    # Losing or changing an existing working DEK must never look like fresh init.
    directory = Path(config["vault_directory"])
    if not directory.is_dir() or any(directory.iterdir()):
        raise Denied("EXISTING_VAULT_MUST_NOT_REKEY")
    seal_credential(os.urandom(32), config["vault_credential"])
