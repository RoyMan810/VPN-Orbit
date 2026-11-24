"""Validate and quarantine controller state without starting or replacing services."""

from contextlib import closing, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import sqlite3
import tempfile
import time

from .. import __version__
from ..admission import Admission
from ..database import Store, identifier
from ..errors import Denied
from ..queue import JobQueue
from nacl.secret import Aead
from . import backup
from .authority import host_binding
from .credentials import seal_credential, unseal_credential
from .policy import Policy
from .protocol import canonical, checksum
from .ssh import verify_known_hosts
from .storage import directory_sync, new_private_file, process_lock, protected_bytes


RECOVERY_ROOT = Path('/var/lib/vpn-orbit-recovery')
TERMINAL = ('SUCCEEDED', 'FAILED', 'UNKNOWN_OUTCOME', 'CANCELLED_SAFE')
DATA_DIRS = ('app', 'broker', 'vault', 'control-gate', 'writer-admission')
CONFIG_FILES = ('runtime.json', 'targets.json', 'gate.pub', 'credentials/broker-dek.cred')
SERVICES = ('vpn-orbit-compose.service', 'vpn-orbit-web.service', 'vpn-orbit-broker.service',
            'vpn-orbit-supervisor.service', 'vpn-orbit-broker.socket', 'vpn-orbit-supervisor.socket',
            'vpn-orbit-api.service', 'vpn-orbit-worker.service')
PENDING = 'restore.pending'


def check_compatibility(manifest, work):
    if manifest['installation']['version'] != __version__:
        raise Denied('RESTORE_VERSION_UNSUPPORTED')
    entries = manifest['files']
    # Allow room for the copies and for SQLite to journal quarantine changes.
    needed = (sum(entry['size'] for entry in entries.values())
              + sum(entries[name]['size'] for name in backup.DBS) + 8 * 1024**2)
    if shutil.disk_usage(work).free < needed:
        raise Denied('RESTORE_SPACE_INSUFFICIENT')


def check_contract(work, manifest, dek, signing_key):
    # Root-owned staged inputs only. Never import source units or execute SQL
    # supplied by the archive. Protected paths in runtime.json are evidence only.
    installation = json.loads((work / 'installation.json').read_bytes())
    if any(installation[key] != value for key, value in manifest['installation'].items()):
        raise Denied('RESTORE_INSTALLATION_MISMATCH')
    cfg = json.loads((work / 'config/runtime.json').read_bytes())
    backup.bound_layout(cfg)
    payloads = {'vault/broker-dek': dek, 'control-gate/signing.key': signing_key}
    for name in ('control-gate/verify.key', 'config/gate.pub'):
        payloads[name] = (work / name).read_bytes()
    staged = {name: work / name for name in backup.DBS}
    backup.checked_snapshot(payloads, staged, cfg, vault_directory=work / 'vault', owner=os.geteuid())
    if {name.removeprefix('vault/objects/') for name in payloads if name.startswith('vault/objects/')} != {
            p.name for p in (work / 'vault/objects').iterdir()}:
        raise Denied('RESTORE_VAULT_OBJECT_SET_MISMATCH')
    for name, version in backup.DBS.items():
        with closing(sqlite3.connect((work / name).as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            if db.execute('PRAGMA user_version').fetchone() != (version,):
                raise Denied('RESTORE_SCHEMA_UNSUPPORTED')
    policy = Policy.load(work / 'config/targets.json', owner=os.geteuid())
    verify_known_hosts(work / 'broker/known_hosts', policy)
    with closing(sqlite3.connect((work / 'control-gate/gate.sqlite3').as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        row = db.execute('SELECT policy_digest, instance_id FROM gate WHERE id=1').fetchone()
        if not row or row[0] != policy.digest:
            raise Denied('RESTORE_AUTHORITY_POLICY_MISMATCH')
        return policy, row[1]


@contextmanager
def edit_database(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, autocommit=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        if db.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
            raise Denied('RESTORE_DATABASE_MODE_INVALID')
        db.execute('BEGIN IMMEDIATE')
        yield db
        db.execute('COMMIT')


def quarantine_state(work, policy, source_id, digest):
    app = work / 'app/controller.sqlite3'
    now = int(time.time())
    import_id = identifier()
    queue = JobQueue(Store(app), clock=lambda: now)
    with edit_database(app) as db:
        for table in ('reauth', 'sessions', 'bootstrap'):
            db.execute(f'DELETE FROM {table}')
        # All pre-existing terminal records, incidents and request keys remain.
        # A QUEUED record with no claim has not begun. Every claimed or advanced
        # job is conservative UNKNOWN_OUTCOME; external state can have moved.
        queued = unknown = 0
        last = ''
        while rows := db.execute('SELECT * FROM jobs WHERE id>? AND status NOT IN (?,?,?,?) ORDER BY id LIMIT 128',
                                 (last, *TERMINAL)).fetchall():
            for row in rows:
                if row['status'] == 'QUEUED' and row['claimed_by'] is None:
                    outcome = 'CANCELLED_SAFE'
                    queued += 1
                else:
                    outcome = 'UNKNOWN_OUTCOME'
                    unknown += 1
                queue._finish(db, row, outcome, 'RESTORE_QUARANTINE')
            last = rows[-1]['id']
        Store.event(db, at=now, actor='local-root', kind='recovery.imported', target=source_id,
                    outcome='READ_ONLY_RECOVERY', correlation=import_id,
                    details={'archive_sha256': digest, 'cancelled_safe': queued, 'unknown_outcomes': unknown})
        Store.verify_audit_connection(db)
    with edit_database(work / 'control-gate/gate.sqlite3') as db:
        for row in db.execute("SELECT job_id,target,mutating FROM attempts WHERE state IN ('ISSUED','DISPATCHING')"):
            if row['mutating']:
                db.execute('INSERT OR IGNORE INTO incidents VALUES(?,?)', (row['job_id'], canonical(policy.closure(row['target'])).decode()))
        db.execute("UPDATE attempts SET state='UNKNOWN_OUTCOME',result_code='RESTORE_QUARANTINE' WHERE state IN ('ISSUED','DISPATCHING')")
        db.execute("UPDATE gate SET activated=0,state='RECOVERY_HOLD',epoch=epoch+1,update_ticket=NULL WHERE id=1")
    # Persist interrupted Broker attempts as ambiguous without RPC or replay.
    with edit_database(work / 'broker/receipts.sqlite3') as db:
        db.execute("UPDATE receipts SET state='UNKNOWN_OUTCOME' WHERE state IN ('PREPARED','DISPATCHING')")
    # Backed-up admission is evidence, never copied into the live profile.
    frozen = Admission.initialize(work / 'writer-admission', owner=os.geteuid())
    frozen.publish('READ_ONLY_RECOVERY')


def stage(archive, identity, digest, *, age):
    root = backup.secure_directory(RECOVERY_ROOT, private=True)
    if not backup.SHA256.fullmatch(digest):
        raise Denied('RESTORE_TRUSTED_DIGEST_REQUIRED')
    final = root / ('restore-' + digest[:24])
    with process_lock(root / 'restore.lock'), tempfile.TemporaryDirectory(prefix='.import-', dir=root) as temp:
        if os.path.lexists(final):
            raise Denied('RESTORE_STAGE_EXISTS')
        work = Path(temp) / 'state'
        work.mkdir(mode=0o700)
        (work / 'vault/objects').mkdir(mode=0o700, parents=True)
        # The raw DEK is never written to a staging file. Its destination is an
        # OS credential rewrapped under the current host key.
        with io.BytesIO() as dek, io.BytesIO() as signing_key:
            secrets = {'vault/broker-dek': dek, 'control-gate/signing.key': signing_key}

            @contextmanager
            def sink(name):
                if name in secrets:
                    yield secrets[name]
                    return
                path = work / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with path.open('xb') as out:
                    yield out
                    out.flush()
                    os.fsync(out.fileno())

            manifest = backup.decrypt_archive(archive, identity, age=age, expected_sha256=digest,
                                              start=lambda value: check_compatibility(value, work), sink=sink)
            policy, source_id = check_contract(work, manifest, dek.getvalue(), signing_key.getvalue())
            quarantine_state(work, policy, source_id, digest)
            (work / 'credentials').mkdir(mode=0o700)
            seal_credential(dek.getvalue(), work / 'credentials/broker-dek.cred')
            seal_credential(signing_key.getvalue(), work / 'credentials/authority.cred', name='restore-authority-key')
        value = {'status': 'STAGED_READ_ONLY', 'archive_sha256': digest, 'directory': final.name,
                 'controller_version': manifest['installation']['version'], 'services_started': False}
        new_private_file(work / 'recovery.json', canonical(value))
        for path in work.rglob('*'):
            if path.is_dir():
                directory_sync(path)
        directory_sync(work)
        os.rename(work, final)
        directory_sync(root)
        return value


def command(*args, timeout=10):
    result = subprocess.run(args, env=backup.ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode:
        raise Denied('RESTORE_SERVICE_STATE_UNAVAILABLE')
    return result.stdout.decode().strip()


def ensure_stopped(docker_host):
    for unit in SERVICES:
        state = command('/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', unit)
        if state != 'inactive':
            raise Denied('RESTORE_STOP_CONTROLLER_FIRST')
    prefix = ('/usr/bin/docker', '--host', docker_host)
    project = '--filter=label=com.docker.compose.project=vpn-orbit'
    if command(*prefix, 'ps', '--quiet', project):
        raise Denied('RESTORE_STOP_CONTROLLER_FIRST')
    # Old containers carry the original bind configuration. Require removal
    # by the operator, so the next start cannot reuse stale mount inodes.
    if command(*prefix, 'ps', '--all', '--quiet', project):
        raise Denied('RESTORE_REMOVE_STOPPED_CONTAINERS')


def ensure_start_guards():
    expected = b'ConditionPathExists=!/var/lib/vpn-orbit/restore.pending'
    installed = ('vpn-orbit-compose.service', 'vpn-orbit-broker.service', 'vpn-orbit-supervisor.service')
    for unit in (*installed, *(unit for unit in SERVICES if unit.endswith('.service') and unit not in installed
                               and os.path.lexists(backup.UNITS / unit))):
        path = backup.UNITS / unit
        if expected not in protected_bytes(path, owner=0, maximum=16384).splitlines():
            raise Denied('RESTORE_INSTALLATION_GUARD_MISSING')
        state = command('/usr/bin/systemctl', 'show', '--property=NeedDaemonReload', '--value', unit)
        if state != 'no':
            raise Denied('RESTORE_INSTALLATION_GUARD_MISSING')


def remap_vault(vault, dek, source, destination):
    mapping = {source[role + '_uid']: destination[role + '_uid'] for role in ('worker', 'broker')}
    box = Aead(dek)
    objects = vault / 'objects'
    with edit_database(vault / 'vault.sqlite3') as db:
        for row in db.execute('SELECT ref,metadata,object_digest FROM secrets ORDER BY ref').fetchall():
            old = json.loads(row['metadata'])
            try:
                updated = [mapping[uid] for uid in old['allowed_consumers']]
            except KeyError:
                raise Denied('RESTORE_VAULT_CONSUMER_UNSUPPORTED') from None
            if updated == old['allowed_consumers']:
                continue
            old_path = objects / row['object_digest']
            plaintext = box.decrypt(old_path.read_bytes(), canonical(old))
            metadata = {**old, 'allowed_consumers': updated, 'allowed_consumers_digest': checksum(updated)}
            ciphertext = bytes(box.encrypt(plaintext, canonical(metadata)))
            digest = hashlib.sha256(ciphertext).hexdigest()
            new_private_file(objects / digest, ciphertext)
            db.execute('UPDATE secrets SET metadata=?,object_digest=? WHERE ref=?',
                       (canonical(metadata).decode(), digest, row['ref']))
        used = {row[0] for row in db.execute('SELECT DISTINCT object_digest FROM secrets')}
    for path in objects.iterdir():
        if path.name not in used:
            path.unlink()


def prepare_destination(staged, next_data, next_config, live):
    from .cli import configuration

    source = configuration(staged / 'config/runtime.json')
    for name in DATA_DIRS:
        shutil.copytree(staged / name, next_data / name)
    gate = next_data / 'control-gate'
    with edit_database(gate / 'gate.sqlite3') as db:
        if db.execute("UPDATE gate SET host_binding=? WHERE id=1 AND activated=0 AND state='RECOVERY_HOLD'",
                      (host_binding(),)).rowcount != 1:
            raise Denied('RESTORE_QUARANTINE_REQUIRED')
    new_private_file(gate / 'signing.key',
                     unseal_credential(staged / 'credentials/authority.cred', name='restore-authority-key'))
    remap_vault(next_data / 'vault', unseal_credential(staged / 'credentials/broker-dek.cred'), source, live)
    if 'enrollment_catalog' in source:
        live['enrollment_catalog'] = source['enrollment_catalog']
    else:
        live.pop('enrollment_catalog', None)
    with (next_config / 'runtime.json').open('xb') as stream:
        stream.write(canonical(live))
    for name in ('targets.json', 'gate.pub'):
        shutil.copyfile(staged / 'config' / name, next_config / name)
    (next_config / 'credentials').mkdir(mode=0o700)
    shutil.copyfile(staged / 'credentials/broker-dek.cred', next_config / 'credentials/broker-dek.cred')
    for name in DATA_DIRS:
        directory = next_data / name
        if name == 'app':
            uid, gid, mode = live['app_uid'], live['app_gid'], 0o2770
        elif name in ('broker', 'vault'):
            uid, gid, mode = live['broker_uid'], live['broker_gid'], 0o700
        else:
            uid, gid, mode = 0, 0, 0o755 if name == 'writer-admission' else 0o700
        os.chown(directory, uid, gid)
        directory.chmod(mode)
        for path in directory.rglob('*'):
            os.chown(path, uid, gid)
            if name == 'app' and path.is_file():
                path.chmod(0o660)
    for name in CONFIG_FILES:
        path = next_config / name
        path.chmod(0o600 if name.startswith('credentials/') else 0o644)


def sync_tree(root):
    for current, _, files in os.walk(root, topdown=False):
        for name in files:
            fd = os.open(Path(current) / name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        directory_sync(current)


def swap_entries(live, work, names):
    """Each rename is durable and can be resumed with the same prepared tree."""
    previous, new = work / 'previous', work / 'next'
    for name in names:
        current, prior, incoming = live / name, previous / name, new / name
        if not prior.exists():
            if not incoming.exists() or not current.exists():
                raise Denied('RESTORE_TRANSITION_INVALID')
            os.rename(current, prior)
            directory_sync(current.parent)
            directory_sync(prior.parent)
        if incoming.exists():
            if current.exists():
                raise Denied('RESTORE_TRANSITION_INVALID')
            os.rename(incoming, current)
            directory_sync(incoming.parent)
            directory_sync(current.parent)
        elif not current.exists():
            raise Denied('RESTORE_TRANSITION_INVALID')


def install(staged_id, *, docker_host, resume=False):
    from .cli import configuration

    if not backup.SHA256.fullmatch(staged_id):
        raise Denied('RESTORE_TRUSTED_DIGEST_REQUIRED')
    staged = backup.secure_directory(RECOVERY_ROOT / ('restore-' + staged_id[:24]), private=True)
    evidence = json.loads(protected_bytes(staged / 'recovery.json', owner=0, exact_mode=0o600))
    if (evidence.get('status') != 'STAGED_READ_ONLY' or evidence.get('archive_sha256') != staged_id
            or evidence.get('controller_version') != __version__):
        raise Denied('RESTORE_STAGE_INVALID')
    for root in (backup.DATA, backup.CONFIG, backup.RUN):
        backup.secure_directory(root)
    flag = backup.DATA / PENDING
    with process_lock(backup.RUN / 'maintenance.lock'):
        ensure_start_guards()
        ensure_stopped(docker_host)
        if resume:
            current = json.loads(protected_bytes(flag, owner=0, exact_mode=0o600))
            if current.get('archive_sha256') != staged_id:
                raise Denied('RESTORE_STAGE_INVALID')
            token = current['transaction']
        else:
            if os.path.lexists(flag):
                raise Denied('RESTORE_RESUME_REQUIRED')
            token = identifier()
        transaction = '.restore-' + token
        if not re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{26}', token):
            raise Denied('RESTORE_STAGE_INVALID')
        data_tx, config_tx = backup.DATA / transaction, backup.CONFIG / transaction
        if not resume:
            cfg = configuration(backup.CONFIG / 'runtime.json')
            backup.bound_layout(cfg)
            estimate = sum(p.stat().st_size for p in staged.rglob("*") if p.is_file())
            if shutil.disk_usage(backup.DATA).free < 2 * estimate + 8 * 1024**2:
                raise Denied('RESTORE_SPACE_INSUFFICIENT')
            for tx in (data_tx, config_tx):
                tx.mkdir(mode=0o700)
                (tx / 'next').mkdir(mode=0o700)
                (tx / 'previous').mkdir(mode=0o700)
            (config_tx / 'previous/credentials').mkdir(mode=0o700)
            prepare_destination(staged, data_tx / 'next', config_tx / 'next', cfg)
            for tx in (data_tx, config_tx):
                sync_tree(tx)
                directory_sync(tx.parent)
            new_private_file(flag, canonical({'v': 1, 'archive_sha256': staged_id, 'transaction': token}))
        # Verify inactivity again after the persistent exclusion is published.
        ensure_stopped(docker_host)
        for tx in (data_tx, config_tx):
            backup.secure_directory(tx, private=True)
        swap_entries(backup.DATA, data_tx, DATA_DIRS)
        swap_entries(backup.CONFIG, config_tx, CONFIG_FILES)
        if Admission(backup.DATA / 'writer-admission').state()['phase'] != 'READ_ONLY_RECOVERY':
            raise Denied('RESTORE_QUARANTINE_REQUIRED')
        flag.unlink()
        directory_sync(flag.parent)
        return {'status': 'RESTORED_READ_ONLY', 'archive_sha256': staged_id,
                'previous_data': str(data_tx / 'previous'), 'previous_config': str(config_tx / 'previous'),
                'services_started': False, 'activation': 'FENCING_AND_RECONCILIATION_REQUIRED'}
