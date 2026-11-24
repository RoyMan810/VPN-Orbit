"""Allowlisted local health report. Never include command output or config values."""

from contextlib import ExitStack
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, build_opener

from ..admission import Admission
from ..database import DataAccess, Store
from ..errors import Denied
from . import backup
from .authority import verify_host_time
from .ipc import Client
from .storage import new_private_file, protected_bytes


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def probe_http(url, context=None):
    handlers = [ProxyHandler({}), NoRedirect()]
    if context is not None:
        handlers.append(HTTPSHandler(context=context))
    with build_opener(*handlers).open(url, timeout=4) as response:
        return json.loads(response.read(4096)).get('status') == 'alive'


def sys_state(unit):
    arguments = ('/usr/bin/systemctl', 'show', '--property=ActiveState,LoadState', unit)
    output = subprocess.run(arguments, env=backup.ENV, capture_output=True, timeout=4)
    if output.returncode:
        raise OSError
    state = dict(line.split('=', 1) for line in output.stdout.decode().splitlines() if '=' in line)
    if state.get('LoadState') == 'not-found':
        return 'NO_DATA', 'UNIT_NOT_INSTALLED'
    if state.get('ActiveState') == 'active':
        return 'OK', 'UNIT_ACTIVE'
    if state.get('ActiveState') == 'failed':
        return 'ERROR', 'UNIT_FAILED'
    return 'UNAVAILABLE', 'UNIT_NOT_ACTIVE'


def docker_status(installation):
    host = installation['docker_host']
    prefix = ('/usr/bin/docker', '--host', host)
    result = subprocess.run((*prefix, 'version', '--format', '{{.Server.Version}}'), env=backup.ENV,
                            capture_output=True, timeout=4)
    if result.returncode:
        return 'UNAVAILABLE', 'DOCKER_UNAVAILABLE'
    return 'OK', 'DOCKER_RESPONDED'


def worker_status(installation):
    prefix = ('/usr/bin/docker', '--host', installation['docker_host'])
    result = subprocess.run((*prefix, 'ps', '--no-trunc', '--format', '{{.ID}}',
                             '--filter=label=com.docker.compose.project=vpn-orbit',
                             '--filter=label=com.docker.compose.service=worker'), env=backup.ENV,
                            capture_output=True, timeout=5)
    if result.returncode:
        return 'UNAVAILABLE', 'DOCKER_UNAVAILABLE'
    ids = result.stdout.decode().split()
    if not ids:
        return 'UNAVAILABLE', 'WORKER_NOT_RUNNING'
    if len(ids) != 1 or not backup.SHA256.fullmatch(ids[0]):
        return 'ERROR', 'WORKER_IDENTITY_UNEXPECTED'
    result = subprocess.run((*prefix, 'inspect', '--format', '{{.Image}}', ids[0]), env=backup.ENV,
                            capture_output=True, timeout=5)
    if result.returncode:
        return 'UNAVAILABLE', 'WORKER_INSPECT_UNAVAILABLE'
    if result.stdout.decode().strip() != installation['image_id']:
        return 'ERROR', 'WORKER_IMAGE_MISMATCH'
    return 'OK', 'WORKER_RUNNING'


def classify_time(cfg):
    signed = Client(cfg['gate_socket'], server_uids={0}, timeout=4).call('time.health', {})
    public = protected_bytes(cfg['public_verify_key'], owner=0, maximum=32)
    claims = verify_host_time(signed, public)
    state = claims.get('state')
    if state == 'FRESH':
        return 'OK', 'TIME_FRESH'
    if state == 'HOLDOVER':
        return 'WARNING', 'TIME_HOLDOVER'
    if state == 'UNTRUSTED':
        return 'ERROR', 'TIME_UNTRUSTED'
    return 'ERROR', 'TIME_REPORT_INVALID'


def storage(cfg, checks):
    state = Admission(cfg['writer_directory']).state()
    checks['admission'] = {'status': 'OK' if state['phase'] == 'OPEN' else 'WARNING', 'code': state['phase']}
    store = Store(cfg['database'], access=DataAccess(cfg['app_uid'], cfg['app_gid']))
    with store.connect(readonly=True) as db:
        db.execute('BEGIN')
        pending = db.execute("SELECT count(*) FROM jobs WHERE status NOT IN ('SUCCEEDED','FAILED','UNKNOWN_OUTCOME','CANCELLED_SAFE')").fetchone()[0]
        unresolved = db.execute('SELECT count(*) FROM job_incidents').fetchone()[0]
        checks['queue'] = {'status': 'WARNING' if unresolved else 'OK', 'code': 'QUEUE_INSPECTED',
                           'pending': pending, 'unresolved': unresolved}
        checks['sqlite'] = {'status': 'OK' if db.execute('PRAGMA quick_check(1)').fetchone()[0] == 'ok' else 'ERROR',
                            'code': 'SQLITE_CHECKED'}
        try:
            Store.verify_audit_connection(db)
        except (RuntimeError, ValueError, sqlite3.Error, KeyError):
            checks['audit_outbox'] = {'status': 'ERROR', 'code': 'AUDIT_INTEGRITY_FAILED'}
        else:
            checks['audit_outbox'] = {'status': 'OK', 'code': 'AUDIT_INTEGRITY_VERIFIED'}


def vault_status(cfg):
    # No unsealing to diagnose. Deep verification of the credential and object
    # contents belongs to the encrypted backup/restore path.
    backup.secure_directory(Path(cfg['vault_credential']).parent, private=True)
    if not protected_bytes(cfg['vault_credential'], owner=0, exact_mode=0o600):
        return 'ERROR', 'VAULT_CREDENTIAL_MISSING'
    with ExitStack() as reads:
        db = backup.pin_database('vault/vault.sqlite3', 1, cfg, reads)
        if db.execute('PRAGMA quick_check(1)').fetchone() != ('ok',):
            return 'ERROR', 'VAULT_JOURNAL_INVALID'
        db.execute('SELECT 1 FROM secrets LIMIT 1').fetchone()
    return 'OK', 'VAULT_JOURNAL_CHECKED_WRAPPED_CREDENTIAL_PRESENT'


def backup_status(directory):
    try:
        backup.secure_directory(directory, private=True)
    except FileNotFoundError:
        return {'status': 'NO_DATA', 'code': 'BACKUP_DIRECTORY_NOT_FOUND'}
    candidates = sorted(p for p in directory.iterdir() if backup.FILENAME.fullmatch(p.name))
    if not candidates:
        return {'status': 'NO_DATA', 'code': 'BACKUP_NOT_FOUND'}
    with backup.open_private(candidates[-1]) as archive:
        info = os.fstat(archive.fileno())
        if not archive.read(128).startswith(b'age-encryption.org/v1\n'):
            return {'status': 'ERROR', 'code': 'BACKUP_HEADER_INVALID'}
    return {'status': 'WARNING', 'code': 'BACKUP_PRESENT_NOT_VERIFIED',
            'file_mtime': datetime.fromtimestamp(info.st_mtime, UTC).isoformat(timespec='seconds')}


def report(installation, *, directory=Path('/var/backups/vpn-orbit')):
    checks = {}

    def check(name, method, error):
        try:
            status, code = method()
        except (OSError, Denied, TypeError, ValueError, subprocess.SubprocessError, sqlite3.Error):
            status, code = error
        checks[name] = {'status': status, 'code': code}

    for name in ('systemd', 'compose', 'web', 'broker', 'supervisor', 'broker_socket', 'supervisor_socket'):
        unit = {'systemd': 'basic.target', 'broker_socket': 'vpn-orbit-broker.socket',
                'supervisor_socket': 'vpn-orbit-supervisor.socket'}.get(name, 'vpn-orbit-' + name + '.service')
        check(name, lambda: sys_state(unit), ('UNAVAILABLE', 'SYSTEMD_UNAVAILABLE'))
    check('docker', lambda: docker_status(installation), ('UNAVAILABLE', 'DOCKER_UNAVAILABLE'))
    check('worker', lambda: worker_status(installation), ('UNAVAILABLE', 'WORKER_INSPECT_UNAVAILABLE'))
    check('api', lambda: ('OK', 'API_RESPONDED') if probe_http(f"http://127.0.0.1:{installation['port']}/healthz")
          else ('ERROR', 'API_RESPONSE_INVALID'), ('UNAVAILABLE', 'API_UNAVAILABLE'))
    for name in ('admission', 'queue', 'sqlite', 'audit_outbox', 'time', 'https', 'vault'):
        checks[name] = {'status': 'NO_DATA', 'code': 'RUNTIME_CONFIGURATION_UNAVAILABLE'}
    from .cli import configuration
    try:
        cfg = configuration(backup.CONFIG / 'runtime.json')
        backup.bound_layout(cfg)
    except (OSError, Denied, ValueError, TypeError, KeyError):
        cfg = None
    if cfg is not None:
        try:
            storage(cfg, checks)
        except (OSError, Denied, RuntimeError, sqlite3.Error):
            checks['sqlite'] = {'status': 'ERROR', 'code': 'SQLITE_INSPECTION_FAILED'}
        check('time', lambda: classify_time(cfg), ('UNAVAILABLE', 'TIME_PROOF_UNAVAILABLE'))
        check('vault', lambda: vault_status(cfg), ('ERROR', 'VAULT_JOURNAL_OR_CREDENTIAL_INVALID'))
        if checks['web']['status'] != 'NO_DATA':
            def https():
                origin = cfg['public_origin']
                ca = str(backup.WEB / 'web-ca.pem') if origin == 'https://127.0.0.1:18443' else None
                return ('OK', 'HTTPS_CERTIFICATE_AND_API_VERIFIED') if probe_http(origin + '/healthz', ssl.create_default_context(cafile=ca)) else (
                    'ERROR', 'HTTPS_RESPONSE_INVALID')
            check('https', https, ('UNAVAILABLE', 'HTTPS_OR_CERTIFICATE_UNAVAILABLE'))
        else:
            checks['https'] = {'status': 'NO_DATA', 'code': 'WEB_UNIT_NOT_INSTALLED'}
    try:
        checks['backup'] = backup_status(directory)
    except (OSError, Denied, ValueError):
        checks['backup'] = {'status': 'UNAVAILABLE', 'code': 'BACKUP_DIRECTORY_UNAVAILABLE'}
    try:
        free = shutil.disk_usage(backup.DATA).free
        checks['disk'] = {'status': 'WARNING' if free < 512 * 1024**2 else 'OK', 'code': 'DATA_SPACE_CHECKED', 'free_bytes': free}
    except OSError:
        checks['disk'] = {'status': 'UNAVAILABLE', 'code': 'DATA_SPACE_UNAVAILABLE'}
    checks['restore'] = ({'status': 'WARNING', 'code': 'RESTORE_RESUME_REQUIRED'}
                         if (backup.DATA / 'restore.pending').exists() else
                         {'status': 'WARNING', 'code': 'RESTORE_QUARANTINE'}
                         if checks['admission']['code'] == 'READ_ONLY_RECOVERY' else {'status': 'NO_DATA', 'code': 'NO_RESTORE_REPORTED'})
    if checks['restore']['status'] == 'NO_DATA':
        try:
            restored = json.loads(protected_bytes(backup.DATA / 'restored.json', owner=0, exact_mode=0o600))
            if restored.get("v") != 1 or not backup.SHA256.fullmatch(restored["archive_sha256"]):
                raise ValueError
            checks['restore'] = ({'status': 'OK', 'code': 'RESTORE_ACTIVATED'}
                                 if checks['admission']['code'] == 'OPEN' else
                                 {'status': 'WARNING', 'code': 'RESTORE_APPLIED'})
        except FileNotFoundError:
            pass
        except (OSError, Denied, ValueError, KeyError, TypeError):
            checks['restore'] = {'status': 'UNAVAILABLE', 'code': 'RESTORE_STATE_UNAVAILABLE'}
    transaction = backup.APP / 'upgrade-1.1.0/transaction.json'
    try:
        update = json.loads(protected_bytes(transaction, owner=0, exact_mode=0o600))
        phase = update['phase']
        known = {'PREPARED', 'DRAINING', 'QUIESCENT', 'BACKED_UP', 'SWITCHING', 'TESTING',
                 'COMMITTING', 'ROLLING_BACK', 'FAILED_SAFE', 'ROLLED_BACK', 'COMPLETE'}
        if phase not in known:
            raise ValueError
        status = {'COMPLETE': 'OK', 'FAILED_SAFE': 'ERROR'}.get(phase, 'WARNING')
        checks['update'] = {'status': status, 'code': 'UPDATE_' + phase}
    except FileNotFoundError:
        checks['update'] = {'status': 'NO_DATA', 'code': 'NO_UPDATE_REPORTED'}
    except (OSError, Denied, ValueError, KeyError, TypeError):
        checks['update'] = {'status': 'UNAVAILABLE', 'code': 'UPDATE_STATE_UNAVAILABLE'}
    return {'v': 1, 'checked_at': datetime.now(UTC).isoformat(timespec='seconds'),
            'controller_version': installation['version'], 'checks': checks}


def write_report(path, value):
    folder = backup.secure_directory(path.absolute().parent, private=True)
    new_private_file(folder / path.name, json.dumps(value, sort_keys=True).encode() + b'\n')
