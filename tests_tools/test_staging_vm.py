from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import staging_vm as vm


ORIGINAL = f"""<domain><uuid>{vm.VM}</uuid><devices>
<disk device="disk"><source file="/var/lib/libvirt/images/ubuntu24.04.saved"/>
<target dev="vda"/><backingStore/></disk></devices></domain>"""
SNAPSHOT = f"""<domainsnapshot><domain><uuid>{vm.VM}</uuid><devices>
<disk><source file="{vm.BASE}"/></disk></devices></domain></domainsnapshot>"""


class StagingVMTests(unittest.TestCase):
    def test_disk_override_cannot_change_identity_and_does_not_mutate_restore_input(self):
        result = vm.overlay_xml(ORIGINAL, "/var/lib/libvirt/images/ubuntu24.04.test")
        self.assertEqual(vm.domain(result)[1].find("source").get("file"),
                         "/var/lib/libvirt/images/ubuntu24.04.test")
        self.assertIn("ubuntu24.04.saved", ORIGINAL)
        with self.assertRaisesRegex(ValueError, "IDENTITY"):
            vm.overlay_xml(ORIGINAL.replace(vm.VM, "another-vm"), "/test")

    def test_exception_after_switch_restores_exact_saved_xml(self):
        def virsh(*args):
            if args[0] == "dumpxml":
                return ORIGINAL
            if args[0] == "snapshot-dumpxml":
                return SNAPSHOT
            if args[0] == "domdisplay":
                return "spice://127.0.0.1:5900"
            return ""

        with (
            tempfile.TemporaryDirectory() as temp,
            patch.object(vm, "virsh", side_effect=virsh),
            patch.object(vm, "pinned_ssh", return_value=["ssh"]),
            patch.object(vm, "wait_ssh"),
            patch.object(vm, "capture"),
            patch.object(vm, "stop"),
            patch.object(vm, "define") as define,
        ):
            evidence = Path(temp) / "evidence"
            with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                with vm.disposable_disk(evidence):
                    raise RuntimeError("fixture failed")
            self.assertEqual(define.call_args_list[-1].args, (ORIGINAL,))
            self.assertEqual((evidence / "original.xml").read_text(), ORIGINAL)
            self.assertTrue((evidence / "restored").exists())

    def test_host_key_failure_cannot_switch_domain(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            patch.object(vm, "virsh") as virsh,
            patch.object(vm, "capture", return_value="192.168.122.244 ssh-ed25519 YWJj"),
        ):
            with self.assertRaisesRegex(ValueError, "HOST_KEY_MISMATCH"):
                vm.pinned_ssh(Path(temp))
            virsh.assert_not_called()
