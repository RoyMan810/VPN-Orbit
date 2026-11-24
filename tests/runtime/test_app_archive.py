import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from vpn_orbit.app_archive import inspect_tar, read_index
from vpn_orbit.app_profiles import canonical
from vpn_orbit.errors import Denied


class ApplicationArchiveTests(unittest.TestCase):
    def write_tar(self, directory, entry):
        path = directory / "volume.tar"
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as stream:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            stream.addfile(root)
            stream.addfile(entry, io.BytesIO(b"x" * entry.size) if entry.isfile() else None)
        return path

    def test_volume_validation_refuses_links_paths_devices_and_setuid(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            valid = tarfile.TarInfo("./fixture")
            valid.size = 1
            self.assertEqual(inspect_tar(self.write_tar(directory, valid)), 2)
            for kind, name, mode in (
                (tarfile.SYMTYPE, "link", 0o755),
                (tarfile.LNKTYPE, "hardlink", 0o755),
                (tarfile.CHRTYPE, "device", 0o600),
                (tarfile.REGTYPE, "../outside", 0o600),
                (tarfile.REGTYPE, "/absolute", 0o600),
                (tarfile.REGTYPE, "./program", 0o4755),
            ):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = kind, mode
                entry.linkname = "/outside" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                with self.subTest(kind=kind, name=name, mode=mode), self.assertRaisesRegex(
                        Denied, "APP_BACKUP_VOLUME_ENTRY_UNSAFE"):
                    inspect_tar(self.write_tar(directory, entry))

    def test_application_index_has_only_spec_and_fixed_volume_names(self):
        entry = {"sha256": "a" * 64, "size": 1}
        value = {"kind": "vpn-orbit-app", "v": 1, "spec_sha256": "b" * 64,
                 "files": {"spec.json": entry, "vol-bot-uploads.tar": entry}}
        self.assertEqual(read_index(canonical(value)), value)
        for file in ("../escape.tar", "nested/vol-bot-uploads.tar", "vol-bot-uploads.tar.gzip"):
            with self.subTest(file=file), self.assertRaisesRegex(Denied, "APP_BACKUP_MANIFEST_INVALID"):
                read_index(canonical({**value, "files": {**value["files"], file: entry}}))
