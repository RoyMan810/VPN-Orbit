import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, closing
from unittest.mock import patch

from vpn_orbit.admission import Admission
from vpn_orbit.errors import Denied
from vpn_orbit.runtime import backup
from vpn_orbit.runtime.storage import protected_bytes
from vpn_orbit.runtime import credentials
from vpn_orbit.runtime.protocol import canonical


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.files = {name: bytes(32) if name.endswith(('.key', '.pub', '-dek')) else b'state'
                      for name in backup.REQUIRED | {'config/release-trust.pub'}}
        self.installation = {'version': '1.0.0', 'source_commit': 'a' * 40, 'manifest_sha256': 'b' * 64}
        self.index = backup.archive_index('2026-11-24T12:00:00+00:00', self.files, self.installation)

    def archive(self, *, index=None, files=None):
        stream = io.BytesIO()
        backup.write_archive(stream, index or self.index, files or self.files)
        return stream.getvalue()

    def test_roundtrip_requires_all_members_and_eof(self):
        archive = self.archive()
        self.assertEqual(backup.read_archive(io.BytesIO(archive))['installation'], self.installation)
        for bad in [archive[:520], archive + b'extra', archive + bytes(10240)]:
            with self.assertRaises(Denied):
                backup.read_archive(io.BytesIO(bad))
        with self.assertRaisesRegex(Denied, 'BACKUP_DIGEST_MISMATCH'):
            backup.read_archive(io.BytesIO(self.archive(files={**self.files, 'config/runtime.json': b'other'})))

    def test_wrong_format_and_unexpected_paths_are_rejected_before_extraction(self):
        manifest = backup.validate_manifest(self.index)
        with self.assertRaisesRegex(Denied, 'BACKUP_FORMAT_UNSUPPORTED'):
            backup.read_archive(io.BytesIO(self.archive(index=canonical({**manifest, 'v': 2}))))
        entry = manifest['files']['config/runtime.json']
        for name in ('../etc/shadow', '/etc/shadow', 'vault/objects/not-a-sha256'):
            files = {**manifest['files'], name: entry}
            with self.subTest(name=name), self.assertRaises(Denied):
                backup.read_archive(io.BytesIO(self.archive(index=canonical({**manifest, 'files': files}))))

    @unittest.skipUnless(os.environ.get('VPN_ORBIT_TEST_AGE_DIR'), 'pinned age not configured')
    def test_real_age_requires_the_offline_identity_and_detects_ciphertext_corruption(self):
        age = Path(os.environ['VPN_ORBIT_TEST_AGE_DIR']) / 'age'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity = root / 'identity'
            wrong = root / 'wrong'
            for key in (identity, wrong):
                subprocess.run([age.with_name('age-keygen'), '-o', key], check=True, capture_output=True)
            recipient = subprocess.check_output([age.with_name('age-keygen'), '-y', identity]).decode().strip()
            self.assertIsNotNone(backup.RECIPIENT.fullmatch(recipient))
            ciphertext = subprocess.run([age, '-r', recipient], input=self.archive(), capture_output=True, check=True).stdout
            archive = root / 'copy.age'
            archive.write_bytes(ciphertext)
            archive.chmod(0o600)
            # Only host-root environment/path checks are substituted here.
            open_private = backup.open_private
            with patch.object(backup, 'secure_directory'), patch.object(
                    backup, 'open_private', side_effect=lambda p: open_private(p, owner=os.geteuid())):
                digest = hashlib.sha256(ciphertext).hexdigest()
                self.assertEqual(backup.verify(archive, identity, age=age, expected_sha256=digest)['status'], 'VERIFIED')
                with self.assertRaisesRegex(Denied, 'BACKUP_DECRYPTION_FAILED'):
                    backup.verify(archive, wrong, age=age)
                with self.assertRaises(FileNotFoundError):
                    backup.verify(archive, root / 'missing', age=age)
                archive.write_bytes(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
                with self.assertRaisesRegex(Denied, 'BACKUP_CIPHERTEXT_DIGEST_MISMATCH'):
                    backup.verify(archive, identity, age=age, expected_sha256=digest)
                with self.assertRaises(Denied):
                    backup.verify(archive, identity, age=age)


class SnapshotTests(unittest.TestCase):
    def test_untrusted_fifo_does_not_hold_the_maintenance_barrier(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "known_hosts"
            os.mkfifo(fifo, mode=0o600)
            result = subprocess.run([sys.executable, "-c",
                                     "import os,sys; from vpn_orbit.runtime.storage import protected_bytes;"
                                     "protected_bytes(sys.argv[1],owner=os.geteuid())", fifo],
                                    capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"PROTECTED_FILE_INVALID", result.stderr)

    def test_source_transaction_keeps_committed_wal_at_the_barrier(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            owner, group = os.getuid(), os.getgid()
            a = Admission.initialize(root / 'writers', owner=owner)
            a.publish('OPEN')
            name = 'app/controller.sqlite3'
            path = root / name
            path.parent.mkdir(mode=0o700)
            path.touch(mode=0o660)
            path.chmod(0o660)
            writer = stack.enter_context(closing(sqlite3.connect(path, autocommit=True)))
            writer.executescript('PRAGMA journal_mode=WAL; PRAGMA user_version=6; CREATE TABLE state(n); INSERT INTO state VALUES (1);')
            with patch.object(backup, 'DATA', root), a.exclusive(timeout=1):
                pinned = backup.pin_database(name, 6, {'app_uid': owner, 'app_gid': group}, stack)
            with a.writer():
                writer.execute('INSERT INTO state VALUES(2)')
            with closing(sqlite3.connect(':memory:')) as copy:
                pinned.backup(copy)
                self.assertEqual(copy.execute('SELECT n FROM state').fetchall(), [(1,)])
            self.assertEqual(writer.execute('SELECT n FROM state').fetchall(), [(1,), (2,)])
            self.assertEqual(a.state()['phase'], 'OPEN')

    def test_unseal_accepts_only_the_host_bound_systemd_envelope(self):
        import base64
        key = bytes(32)
        host_envelope = base64.b64encode(credentials._HOST_CREDENTIAL + b'fixture')
        with patch.object(credentials.os, 'geteuid', return_value=0), patch.object(
                credentials, 'protected_bytes', side_effect=[b'wrong', host_envelope]), patch.object(
                credentials.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, key)) as run:
            with self.assertRaisesRegex(Denied, 'OS_CREDENTIAL_UNSEAL_FAILED'):
                credentials.unseal_credential(Path('/unused'))
            run.assert_not_called()
            self.assertEqual(credentials.unseal_credential(Path('/unused')), key)
            self.assertEqual(run.call_args.kwargs['input'], host_envelope)
