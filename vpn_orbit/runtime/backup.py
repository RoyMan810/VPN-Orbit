"""Local-root, encrypted controller snapshots. No SSH, RPC, or restore side effects."""

from contextlib import ExitStack, closing, contextmanager, nullcontext
from datetime import UTC, datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time

from nacl.exceptions import CryptoError
from nacl.secret import Aead
from nacl.signing import SigningKey

from ..admission import Admission
from ..database import SCHEMA_VERSION, Store
from ..errors import Denied
from .credentials import unseal_credential
from .protocol import canonical
from .storage import directory_sync, process_lock, protected_bytes

APP = Path('/opt/vpn-orbit')
CONFIG = Path('/etc/vpn-orbit')
DATA = Path('/var/lib/vpn-orbit')
RUN = Path('/run/vpn-orbit')
WEB = Path('/opt/vpn-orbit-bootstrap')
UNITS = Path('/etc/systemd/system')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent'}
SHA256 = re.compile(r'[0-9a-f]{64}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:\.dev[0-9]+)?')
FILENAME = re.compile(r'controller-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.age')
RECIPIENT = re.compile(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}')
IDENTITY = re.compile(rb'AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}')
DBS = {'app/controller.sqlite3': SCHEMA_VERSION, 'broker/receipts.sqlite3': 1, 'vault/vault.sqlite3': 1,
       'control-gate/gate.sqlite3': 1, 'control-gate/time-health/time.sqlite3': 1}
REQUIRED = set(DBS) | {'config/runtime.json', 'config/targets.json', 'config/compose.json', 'config/gate.pub',
                       'installation.json', 'install-state.json', 'control-gate/signing.key',
                       'control-gate/verify.key', 'broker/known_hosts', 'vault/broker-dek', 'writers/state.json'}
EXTRAS = {'config/release-authentication.json', 'config/release-trust.pub', 'web/unit', 'web/nginx.conf',
          'web/web.key', 'web/web.pem', 'web/web-ca.pem'}
MANIFEST = 'manifest.json'
MANIFEST_LIMIT = 8 * 1024 * 1024
MAX_MEMBERS = 32768
MAX_BYTES = 64 * 1024**3
AGE = APP / "tools/age"


def secure_directory(path, *, private=False):
    """Never follow a symlink or publish into a directory another user can rename."""
    path = path.absolute()
    if '..' in path.parts:
        raise Denied('BACKUP_PATH_INVALID')
    for directory in (path, *path.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (directory == path and private and stat.S_IMODE(info.st_mode) != 0o700)):
            raise Denied('BACKUP_DIRECTORY_UNTRUSTED')
    return path


@contextmanager
def open_private(path, *, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
            raise Denied('BACKUP_FILE_UNTRUSTED')
        yield stream


def bound_layout(cfg):
    paths = {'database': DATA / 'app/controller.sqlite3', 'targets': CONFIG / 'targets.json',
             'broker_directory': DATA / 'broker', 'supervisor_directory': DATA / 'control-gate',
             'vault_directory': DATA / 'vault', 'public_verify_key': CONFIG / 'gate.pub',
             'writer_directory': DATA / 'writer-admission', 'vault_credential': CONFIG / 'credentials/broker-dek.cred'}
    if any(cfg.get(key) != str(path) for key, path in paths.items()):
        raise Denied('BACKUP_LAYOUT_UNSUPPORTED')


def installation_files(cfg):
    """All mutable configuration is local Root-owned; never archive arbitrary paths."""
    secure_directory(APP)
    secure_directory(CONFIG)
    secure_directory(CONFIG / 'credentials', private=True)
    secure_directory(DATA)
    files = {}
    for name in ('runtime.json', 'targets.json', 'compose.json', 'gate.pub'):
        files['config/' + name] = protected_bytes(CONFIG / name, owner=0, maximum=1024**2)
    for name in ('installation.json', 'install-state.json'):
        files[name] = protected_bytes(APP / name, owner=0, exact_mode=0o600)
    install = json.loads(files['installation.json'])
    status = json.loads(files['install-state.json'])
    if (install.get('v') != 1 or install.get('project') != 'vpn-orbit' or status.get('v') != 1
            or status.get('phase') != 'COMPLETE' or status.get('manifest_sha256') != install.get('manifest_sha256')
            or not VERSION.fullmatch(install['version']) or not SHA256.fullmatch(install['manifest_sha256'])
            or not re.fullmatch(r'[0-9a-f]{40}', install['source_commit'])):
        raise Denied('BACKUP_INSTALLATION_INVALID')
    trust = {'signature': 'release-trust.pub', 'sha256': 'release-authentication.json'}.get(install.get('authentication'))
    if trust is None:
        raise Denied('BACKUP_INSTALLATION_INVALID')
    files['config/' + trust] = protected_bytes(CONFIG / trust, owner=0)
    if os.path.lexists(UNITS / 'vpn-orbit-web.service'):
        secure_directory(WEB)
        files['web/unit'] = protected_bytes(UNITS / 'vpn-orbit-web.service', owner=0)
        files['web/nginx.conf'] = protected_bytes(WEB / 'nginx.conf', owner=0)
        if cfg['public_origin'] == 'https://127.0.0.1:18443':
            for name in ('web.key', 'web.pem', 'web-ca.pem'):
                files['web/' + name] = protected_bytes(WEB / name, owner=0, maximum=65536, private=name == 'web.key')
    return files, install


def pin_database(name, version, cfg, stack):
    path = DATA / name
    owner = cfg['app_uid'] if name.startswith('app/') else cfg['broker_uid'] if name.startswith(('broker/', 'vault/')) else 0
    group = cfg['app_gid'] if name.startswith('app/') else None
    for directory in (path.parent, *path.parent.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise Denied('BACKUP_LAYOUT_UNSUPPORTED')
    for suffix in ('', '-wal', '-shm'):
        try:
            info = Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            if suffix:
                continue
            raise
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o007
                or (not suffix and (info.st_uid != owner or stat.S_IMODE(info.st_mode) != (0o660 if group else 0o600)))
                or (group is not None and info.st_gid != group)):
            raise Denied('BACKUP_DATABASE_PERMISSIONS')
    # A SQLite read transaction starts at the first real read, not BEGIN.
    db = stack.enter_context(closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1, autocommit=True)))
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('BEGIN')
    db.execute('SELECT name FROM sqlite_schema LIMIT 1').fetchone()
    if db.execute('PRAGMA user_version').fetchone() != (version,) or db.execute('PRAGMA journal_mode').fetchone() != ('wal',):
        raise Denied('BACKUP_SCHEMA_UNSUPPORTED')
    return db


def snapshot_databases(root, cfg):
    admission = Admission(cfg['writer_directory'])
    with ExitStack() as reads:
        # No on-disk state transition: SIGKILL releases the flock and cannot
        # leave admission closed. Publication only occurs after all validation.
        with admission.exclusive(timeout=5):
            state = admission.state()
            if state['phase'] != 'OPEN':
                raise Denied('BACKUP_ADMISSION_NOT_OPEN')
            files, install = installation_files(cfg)
            files['vault/broker-dek'] = unseal_credential(cfg['vault_credential'])
            databases = {name: pin_database(name, version, cfg, reads) for name, version in DBS.items()}
            captured = datetime.now(UTC).isoformat(timespec='seconds')
            files['writers/state.json'] = canonical(state)
            files['control-gate/signing.key'] = protected_bytes(DATA / 'control-gate/signing.key', owner=0, exact_mode=0o600, maximum=32)
            files['control-gate/verify.key'] = protected_bytes(DATA / 'control-gate/verify.key', owner=0, exact_mode=0o600, maximum=32)
            files['broker/known_hosts'] = protected_bytes(DATA / 'broker/known_hosts', owner=cfg['broker_uid'], maximum=1024**2)
        # The five pinned readers now refer to a single instant. SQLite keeps
        # those WAL pages available while the controllers continue writing.
        required = sum(db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]
                       for db in databases.values())
        if required > MAX_BYTES or shutil.disk_usage(root).free < required + 8 * 1024**2:
            raise Denied("BACKUP_STAGING_SPACE_INSUFFICIENT")
        staged = {}
        deadline = time.monotonic() + 120

        def progress(*_):
            if time.monotonic() >= deadline:
                raise Denied("BACKUP_SNAPSHOT_TIMED_OUT")

        for number, (name, source) in enumerate(databases.items()):
            dest = root / f'{number}.sqlite3'
            with closing(sqlite3.connect(dest, autocommit=True)) as target:
                source.backup(target, pages=1024, sleep=0.05, progress=progress)
            source.close()
            staged[name] = dest
    return captured, files, install, staged


def checked_snapshot(files, staged, cfg, *, vault_directory=None, owner=None):
    if vault_directory is None:
        vault_directory = DATA / "vault"
    if owner is None:
        owner = cfg["broker_uid"]
    key = SigningKey(files['control-gate/signing.key'])
    if bytes(key.verify_key) != files['control-gate/verify.key'] or bytes(key.verify_key) != files['config/gate.pub']:
        raise Denied('BACKUP_AUTHORITY_KEYS_MISMATCH')
    for name, path in staged.items():
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            db.execute('PRAGMA trusted_schema=OFF')
            if db.execute('PRAGMA integrity_check(1)').fetchall() != [('ok',)] or db.execute('PRAGMA foreign_key_check').fetchone():
                raise Denied('BACKUP_DATABASE_CORRUPT')
            if name == 'app/controller.sqlite3':
                db.row_factory = sqlite3.Row
                Store.verify_audit_connection(db)
            if name == 'vault/vault.sqlite3':
                box = Aead(files['vault/broker-dek'])
                objects = vault_directory / "objects"
                info = objects.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                    raise Denied('BACKUP_VAULT_DIRECTORY_INVALID')
                for metadata, digest in db.execute('SELECT metadata,object_digest FROM secrets'):
                    if not SHA256.fullmatch(digest):
                        raise Denied('BACKUP_VAULT_OBJECT_INVALID')
                    if len(files) + len(staged) >= MAX_MEMBERS:
                        raise Denied("BACKUP_LIMIT_EXCEEDED")
                    data = protected_bytes(objects / digest, owner=owner, maximum=9000, exact_mode=0o600)
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise Denied('BACKUP_VAULT_OBJECT_INVALID')
                    try:
                        box.decrypt(data, canonical(json.loads(metadata)))
                    except CryptoError:
                        raise Denied('BACKUP_VAULT_KEY_MISMATCH') from None
                    files['vault/objects/' + digest] = data


@contextmanager
def read_payload(payload):
    with (io.BytesIO(payload) if isinstance(payload, bytes) else payload.open('rb')) as stream:
        yield stream


def archive_index(captured, files, installation):
    records = {}
    for name, payload in files.items():
        size = len(payload) if isinstance(payload, bytes) else payload.stat().st_size
        with read_payload(payload) as stream:
            records[name] = {'size': size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    manifest = {'v': 1, 'kind': 'vpn-orbit-controller', 'captured_at': captured, 'databases': DBS,
                'installation': {key: installation[key] for key in ('version', 'source_commit', 'manifest_sha256')},
                'files': records}
    payload = canonical(manifest)
    validate_manifest(payload)
    return payload


def validate_manifest(raw):
    if len(raw) > MANIFEST_LIMIT:
        raise Denied('BACKUP_MANIFEST_INVALID')
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical(value) != raw:
        raise Denied('BACKUP_MANIFEST_INVALID')
    if type(value.get('v')) is not int or value['v'] != 1 or value.get('kind') != 'vpn-orbit-controller' or value.get('databases') != DBS:
        raise Denied('BACKUP_FORMAT_UNSUPPORTED')
    if set(value) != {'v', 'kind', 'captured_at', 'databases', 'installation', 'files'}:
        raise Denied('BACKUP_MANIFEST_INVALID')
    stamp = value['captured_at']
    install = value['installation']
    if (not isinstance(stamp, str) or datetime.fromisoformat(stamp).astimezone(UTC).isoformat(timespec='seconds') != stamp
            or not isinstance(install, dict) or set(install) != {'version', 'source_commit', 'manifest_sha256'}
            or not VERSION.fullmatch(install['version']) or not SHA256.fullmatch(install['manifest_sha256'])
            or not re.fullmatch(r'[0-9a-f]{40}', install['source_commit'])):
        raise Denied('BACKUP_MANIFEST_INVALID')
    files = value['files']
    if not isinstance(files, dict):
        raise Denied('BACKUP_MANIFEST_INVALID')
    web = set(files) & {'web/unit', 'web/nginx.conf', 'web/web.key', 'web/web.pem', 'web/web-ca.pem'}
    if (not REQUIRED <= files.keys() or len(files) > MAX_MEMBERS
            or len({'config/release-trust.pub', 'config/release-authentication.json'} & files.keys()) != 1
            or web not in (set(), {'web/unit', 'web/nginx.conf'},
                           {'web/unit', 'web/nginx.conf', 'web/web.key', 'web/web.pem', 'web/web-ca.pem'})):
        raise Denied('BACKUP_MANIFEST_INVALID')
    total = 0
    for name, entry in files.items():
        obj = name.removeprefix('vault/objects/') if name.startswith('vault/objects/') else None
        if (name not in REQUIRED | EXTRAS and (obj is None or not SHA256.fullmatch(obj))
                or not isinstance(entry, dict) or set(entry) != {'size', 'sha256'}
                or type(entry['size']) is not int or not 0 <= entry['size'] <= (MAX_BYTES if name in DBS else 1024**2)
                or not SHA256.fullmatch(entry['sha256']) or (obj is not None and obj != entry['sha256'])
                or (name in {'config/gate.pub', 'control-gate/verify.key', 'control-gate/signing.key', 'vault/broker-dek'}
                    and entry['size'] != 32)):
            raise Denied('BACKUP_MANIFEST_INVALID')
        total += entry['size']
    if total > MAX_BYTES:
        raise Denied('BACKUP_LIMIT_EXCEEDED')
    return value


def write_archive(stream, index, files):
    with tarfile.open(fileobj=stream, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [(MANIFEST, index), *sorted(files.items())]:
            header = tarfile.TarInfo(name)
            header.size = len(data) if isinstance(data, bytes) else data.stat().st_size
            header.mode = 0o600
            with read_payload(data) as content:
                tar.addfile(header, content)


def read_archive(stream, *, start=None, sink=None):
    """No extract or PAX/GNU extensions; untrusted paths never reach the FS."""
    def exact(size):
        data = stream.read(size)
        if len(data) != size:
            raise Denied('BACKUP_ARCHIVE_TRUNCATED')
        return data

    def member():
        try:
            header = tarfile.TarInfo.frombuf(exact(512), 'ascii', 'strict')
        except (tarfile.HeaderError, UnicodeError):
            raise Denied("BACKUP_ARCHIVE_INVALID") from None
        if header.type != tarfile.REGTYPE or not 0 <= header.size <= MAX_BYTES or header.linkname:
            raise Denied('BACKUP_ARCHIVE_INVALID')
        return header

    def padding(size):
        if any(exact(-size % 512)):
            raise Denied('BACKUP_ARCHIVE_INVALID')

    first = member()
    if first.name != MANIFEST or not 0 < first.size <= MANIFEST_LIMIT:
        raise Denied('BACKUP_MANIFEST_INVALID')
    value = validate_manifest(exact(first.size))
    padding(first.size)
    if start is not None:
        start(value)
    for name, entry in sorted(value['files'].items()):
        header = member()
        if (header.name, header.size) != (name, entry['size']):
            raise Denied('BACKUP_ARCHIVE_INVALID')
        checksum = hashlib.sha256()
        remaining = header.size
        with (nullcontext() if sink is None else sink(name)) as destination:
            while remaining:
                data = exact(min(remaining, 1024**2))
                checksum.update(data)
                if destination is not None:
                    destination.write(data)
                remaining -= len(data)
        if checksum.hexdigest() != entry['sha256']:
            raise Denied('BACKUP_DIGEST_MISMATCH')
        padding(header.size)
    # Demand two end blocks and consume EOF to authenticate the final age chunk.
    if any(exact(1024)):
        raise Denied('BACKUP_ARCHIVE_INVALID')
    tail = stream.read(tarfile.RECORDSIZE + 1)
    if len(tail) >= tarfile.RECORDSIZE or any(tail):
        raise Denied('BACKUP_ARCHIVE_INVALID')
    return value


def create(directory, recipient, *, age, retain=None):
    from .cli import configuration

    if retain is not None and not 1 <= retain <= 365:
        raise Denied("BACKUP_RETENTION_INVALID")
    directory = secure_directory(directory, private=True)
    if not RECIPIENT.fullmatch(recipient):
        raise Denied('BACKUP_RECIPIENT_UNSUPPORTED')
    secure_directory(RUN)
    fs = subprocess.run(['/usr/bin/stat', '-f', '-c', '%T', RUN], env=ENV, capture_output=True, timeout=5)
    if fs.returncode or fs.stdout.strip() != b'tmpfs':
        raise Denied('BACKUP_TMPFS_REQUIRED')
    if sqlite3.sqlite_version_info < (3, 45):
        raise Denied('SQLITE_VERSION_UNSUPPORTED')
    with process_lock(RUN / 'maintenance.lock'), tempfile.TemporaryDirectory(prefix='backup-', dir=RUN) as work:
        cfg = configuration(CONFIG / 'runtime.json')
        bound_layout(cfg)
        captured, files, install, staged = snapshot_databases(Path(work), cfg)
        checked_snapshot(files, staged, cfg)
        all_files = files | staged
        index = archive_index(captured, all_files, install)
        estimate = len(index) + sum(len(x) if isinstance(x, bytes) else x.stat().st_size for x in all_files.values())
        if shutil.disk_usage(directory).free < estimate + 1024 * len(all_files) + 8 * 1024**2:
            raise Denied("BACKUP_DESTINATION_SPACE_INSUFFICIENT")
        stamp = datetime.fromisoformat(captured).strftime('%Y%m%dT%H%M%SZ')
        name = f'controller-{stamp}-{secrets.token_hex(8)}.age'
        fd, filename = tempfile.mkstemp(prefix=f'.{name}.', suffix='.partial', dir=directory)
        temporary = Path(filename)
        try:
            with os.fdopen(fd, 'w+b') as encrypted:
                with subprocess.Popen([age, '--encrypt', '--recipient', recipient], env=ENV, stdin=subprocess.PIPE,
                                      stdout=encrypted, stderr=subprocess.DEVNULL) as cipher:
                    try:
                        write_archive(cipher.stdin, index, all_files)
                        cipher.stdin.close()
                        if cipher.wait(timeout=30):
                            raise Denied('BACKUP_ENCRYPTION_FAILED')
                    except BaseException:
                        cipher.kill()
                        raise
                os.fsync(encrypted.fileno())
                encrypted.seek(0)
                digest = hashlib.file_digest(encrypted, "sha256").hexdigest()
            os.link(temporary, directory / name)
        finally:
            temporary.unlink(missing_ok=True)
        directory_sync(directory)
        if retain is not None:
            older = sorted((p for p in directory.iterdir() if p.name != name and FILENAME.fullmatch(p.name)
                            and p.name < name and stat.S_ISREG(p.lstat().st_mode) and p.stat().st_uid == 0), reverse=True)
            for path in older[retain - 1:]:
                path.unlink()
            directory_sync(directory)
    return {'status': 'CREATED', 'archive': name, 'sha256': digest, 'captured_at': captured, 'decryption_verified': False}


def decrypt_archive(archive, identity, *, age, expected_sha256=None, start=None, sink=None):
    secure_directory(archive.absolute().parent)
    secure_directory(identity.absolute().parent)
    with open_private(archive) as ciphertext, open_private(identity) as private:
        if expected_sha256 is not None:
            if not SHA256.fullmatch(expected_sha256) or hashlib.file_digest(ciphertext, "sha256").hexdigest() != expected_sha256:
                raise Denied("BACKUP_CIPHERTEXT_DIGEST_MISMATCH")
            ciphertext.seek(0)
        # Accept only a standard identity, not an age plugin executable.
        keys = [line for line in private.read(4097).splitlines() if line and not line.startswith(b'#')]
        if private.tell() > 4096 or len(keys) != 1 or not IDENTITY.fullmatch(keys[0]):
            raise Denied('BACKUP_IDENTITY_UNSUPPORTED')
        private.seek(0)
        with subprocess.Popen([age, '--decrypt', '--identity', f'/proc/self/fd/{private.fileno()}'], env=ENV,
                              stdin=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              pass_fds=(private.fileno(),)) as cipher:
            try:
                value = read_archive(cipher.stdout, start=start, sink=sink)
            except Denied as error:
                if error.code == "BACKUP_ARCHIVE_TRUNCATED" and cipher.wait(timeout=10):
                    raise Denied("BACKUP_DECRYPTION_FAILED") from None
                cipher.kill()
                raise
            except BaseException:
                cipher.kill()
                raise
            if cipher.wait(timeout=10):
                raise Denied('BACKUP_DECRYPTION_FAILED')
    return value


def verify(archive, identity, *, age, expected_sha256=None):
    value = decrypt_archive(archive, identity, age=age, expected_sha256=expected_sha256)
    return {'status': 'VERIFIED', 'format': value['v'], 'captured_at': value['captured_at'],
            'controller_version': value['installation']['version']}


def add_commands(commands):
    backup = commands.add_parser("backup", help="Write an encrypted snapshot of this controller")
    backup.add_argument("--directory", type=Path, required=True)
    backup.add_argument("--recipient", required=True, help="Offline age X25519 public recipient")
    backup.add_argument("--retain", type=int, help="Explicitly permit pruning in a dedicated local backup directory")
    check = commands.add_parser("backup-verify", help="Decrypt and verify a controller snapshot without extracting it")
    check.add_argument("--archive", type=Path, required=True)
    check.add_argument("--identity", type=Path, required=True)
    check.add_argument("--sha256", help="Expected ciphertext digest from the trusted capture record")
    stage = commands.add_parser("restore-stage", help="Rewrap and quarantine a recovery snapshot; do not replace installed data")
    stage.add_argument("--archive", type=Path, required=True)
    stage.add_argument("--identity", type=Path, required=True)
    stage.add_argument("--sha256", required=True, help="Expected ciphertext digest from the trusted capture record")


def administer(args):
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    secure_directory(AGE.parent)
    if args.command == "backup":
        return create(args.directory, args.recipient, age=AGE, retain=args.retain)
    if args.command == "restore-stage":
        from .recovery import stage
        return stage(args.archive, args.identity, args.sha256, age=AGE)
    return verify(args.archive, args.identity, age=AGE, expected_sha256=args.sha256)
