import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_vps


class FakeRemote:
    """Models the durable remote effects without touching the workstation."""

    def __init__(self, *, fault=None, probe_result=None):
        self.fault = fault
        self.probe_result = probe_result if probe_result is not None else {"v": 8, "uid": 0}
        self.calls = []
        self.account = False
        self.state = False
        self.files = set()
        self.cleaned = False

    def phase(self, script):
        match = re.search(r"# vpn-orbit-phase: ([a-z]+)", script)
        return match.group(1) if match else "unknown"

    def __call__(self, script):
        phase = self.phase(script)
        self.calls.append(phase)
        if phase == "cleanup":
            self.account = self.state = False
            self.files.clear()
            self.cleaned = True
            return
        before = script.startswith("exit 255") or script.startswith("exit 1")
        after = script.rstrip().endswith("exit 255") or script.rstrip().endswith("exit 1")
        if before:
            raise subprocess.CalledProcessError(255 if "exit 255" in script.splitlines()[0] else 1, ["ssh"])
        if phase == "preflight":
            self.state = True
        elif phase == "account":
            self.account = True
        elif phase == "helpers":
            self.files.add("ssh-gateway")
        elif phase == "keys":
            self.files.add("authorized")
        elif phase == "sudoers":
            self.files.add("sudoers")
        elif phase == "sshd":
            self.files.add("sshd")
        if after:
            raise subprocess.CalledProcessError(255 if "exit 255" in script.splitlines()[-1] else 1, ["ssh"])


def make_provisioner(directory, remote, *, fault=None, cleanup_on_failure=False, probe=None, firewall=False):
    output = directory / "output"
    output.mkdir(mode=0o700)
    key = output / "probe"
    key.write_text("private")
    key.with_suffix(".pub").write_text("ssh-ed25519 test\n")
    if firewall:
        (output / "firewall").write_text("private")
        (output / "firewall.pub").write_text("ssh-ed25519 firewall\n")
    (output / "targets.json").write_text('{"v":1,"targets":[]}\n')
    return prepare_vps.Provisioner(
        host="192.0.2.20", port=2222, user="admin", identity=None, output=output,
        run_remote=remote, probe=probe or (lambda _: remote.probe_result),
        fingerprint="SHA256:" + "A" * 43, state=prepare_vps.State(output / prepare_vps.STATE_FILE),
        fault=fault, cleanup_on_failure=cleanup_on_failure, sleep=lambda _: None, firewall=firewall,
    ), output


class PrepareVpsTests(unittest.TestCase):
    def test_fingerprint_mismatch_stops_before_provisioning(self):
        with patch.object(prepare_vps.subprocess, "check_output", return_value="host ssh-ed25519 YWJj\n"):
            with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                prepare_vps.identify_host("192.0.2.20", 22, "SHA256:" + "A" * 43)

    def test_check_uses_pinned_root_ssh_without_provisioning(self):
        host_key = "ssh-ed25519 fixture"
        fingerprint = "SHA256:" + "A" * 43
        argv = ["prepare_vps.py", "--host", "192.0.2.20", "--user", "root", "--fingerprint", fingerprint, "--check"]

        def run(command, **kwargs):
            self.assertEqual(command[0], "ssh")
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("root@192.0.2.20", command)
            path = next(arg.split("=", 1)[1] for arg in command if arg.startswith("UserKnownHostsFile="))
            self.assertEqual(Path(path).read_text(), f"192.0.2.20 {host_key}\n")
            self.assertTrue(command[-1].startswith("/bin/sh -c "))
            self.assertIn("/usr/sbin/sshd -t", command[-1])
            self.assertNotIn(prepare_vps.REMOTE_STATE, command[-1])
            self.assertNotIn("useradd", command[-1])

        with (patch("sys.argv", argv), patch("builtins.print"),
              patch.object(prepare_vps, "identify_host", return_value=host_key) as identify,
              patch.object(prepare_vps.subprocess, "run", side_effect=run) as runner,
              patch.object(prepare_vps, "State") as state):
            prepare_vps.main()
        identify.assert_called_once_with("192.0.2.20", 22, fingerprint)
        runner.assert_called_once()
        state.assert_not_called()

    def test_platform_guard_requires_a_supported_release_on_amd64(self):
        guard = prepare_vps._platform_guard().replace(". /etc/os-release", '. "$1"')
        guard = 'test_arch=$2\ndpkg() { printf "%s\\n" "$test_arch"; }\n' + guard
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "os-release"
            for distro, version, arch, supported in (
                ("ubuntu", "24.04", "amd64", True), ("ubuntu", "26.04", "amd64", True),
                ("debian", "13", "amd64", True), ("debian", "12", "amd64", False),
                ("ubuntu", "24.04", "arm64", False), ("other", "13", "amd64", False),
            ):
                with self.subTest(distro=distro, version=version, arch=arch):
                    release.write_text(f"ID={distro}\nVERSION_ID={version}\n")
                    result = subprocess.run(["sh", "-c", guard, "platform", release, arch], capture_output=True)
                    self.assertEqual(result.returncode == 0, supported, result.stderr)

    def test_both_login_methods_use_the_pin_and_generate_a_separate_probe_key(self):
        blob = b"test host key"
        encoded = base64.b64encode(blob).decode()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        for use_key in (False, True):
            with self.subTest(use_key=use_key), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                admin_key = directory / "admin"
                admin_key.touch()
                output = directory / "target"
                argv = ["prepare_vps.py", "--host", "192.0.2.20", "--port", "2222",
                        "--user", "admin", "--fingerprint", fingerprint, "--output", str(output)]
                expected_auth = "PreferredAuthentications=keyboard-interactive,password"
                if use_key:
                    argv += ["--identity", str(admin_key)]
                    expected_auth = "PreferredAuthentications=publickey"

                def run(cmd, **kwargs):
                    if cmd[0] == "ssh-keygen":
                        Path(str(output / "probe")).write_bytes(b"private")
                        Path(str(output / "probe") + ".pub").write_bytes(b"ssh-ed25519 test\n")
                    else:
                        self.assertIn("StrictHostKeyChecking=yes", cmd)
                        self.assertIn(expected_auth, cmd)
                        self.assertEqual(str(admin_key) in cmd, use_key)
                        line = next(arg for arg in cmd if arg.startswith("UserKnownHostsFile="))
                        self.assertEqual(Path(line.split("=", 1)[1]).read_text(),
                                         f"[192.0.2.20]:2222 ssh-ed25519 {encoded}\n")

                with (patch("sys.argv", argv), patch("builtins.print"),
                      patch.object(prepare_vps.subprocess, "run", side_effect=run) as runner,
                      patch.object(prepare_vps.subprocess, "check_output", side_effect=[
                          f"[192.0.2.20]:2222 ssh-ed25519 {encoded}\n", '{"v":8,"uid":0}']) as reader):
                    prepare_vps.main()
                self.assertEqual(runner.call_count, 1 + len(prepare_vps.PHASES))
                probe = reader.call_args.args[0]
                self.assertIn(str(output / "probe"), probe)
                self.assertNotIn(str(admin_key), probe)
                policy = json.loads((output / "targets.json").read_text())["targets"][0]
                self.assertEqual(policy["capabilities"], ["host.probe"])
                self.assertEqual(policy["port"], 2222)
                state = json.loads((output / prepare_vps.STATE_FILE).read_text())
                self.assertEqual(state["status"], "VERIFIED")
                self.assertTrue(all(state["phases"][phase] == "DONE" for phase in prepare_vps.PHASES))

    def test_generated_profile_is_valid_shell(self):
        subprocess.run(["sh", "-n"], input=prepare_vps.provision(b"ssh-ed25519 test\n"),
                       text=True, check=True)

    def test_every_phase_is_idempotent_and_cleanup_removes_all_artifacts(self):
        context = {"probe_public_key": b"ssh-ed25519 test\n", "firewall_public_key": None,
                   "firewall": False, "ssh_port": 22}
        scripts = {phase: prepare_vps.PHASE_SCRIPTS[phase](context) for phase in prepare_vps.PHASES}
        for phase, script in scripts.items():
            with self.subTest(phase=phase):
                subprocess.run(["sh", "-n"], input=script, text=True, check=True)
        self.assertIn("if ! id vpn-orbit-svc", scripts["account"])
        self.assertIn("cmp -s", scripts["helpers"])
        self.assertNotIn("sshd-config.previous", scripts["sshd"])
        self.assertNotIn(prepare_vps.FIREWALL_POLICY, scripts["helpers"])
        self.assertNotIn(prepare_vps.FIREWALL_AUTHORIZED, scripts["keys"])
        self.assertNotIn(prepare_vps.FIREWALL_SUDOERS, scripts["sudoers"])
        self.assertNotIn(prepare_vps.FIREWALL_ACCOUNT, prepare_vps.SSH_PROFILE)
        cleanup = prepare_vps.cleanup_script(context["probe_public_key"])
        subprocess.run(["sh", "-n"], input=cleanup, text=True, check=True)
        for artifact in (prepare_vps.AUTHORIZED, prepare_vps.SUDOERS, prepare_vps.SSH_CONFIG,
                         prepare_vps.PROBE_HOME, prepare_vps.REMOTE_STATE,
                         prepare_vps.FIREWALL_AUTHORIZED,
                         prepare_vps.FIREWALL_POLICY, prepare_vps.FIREWALL_HOME):
            self.assertIn(artifact, cleanup)
        self.assertIn("account-created-$account", cleanup)
        self.assertIn("created-probe-authorized", prepare_vps.PHASE_SCRIPTS["keys"](context))
        self.assertIn("created-helper-ssh-gateway", prepare_vps.PHASE_SCRIPTS["helpers"](context))
        self.assertIn("created-probe-sudoers", prepare_vps.PHASE_SCRIPTS["sudoers"](context))
        self.assertIn("created-sshd-config", prepare_vps.PHASE_SCRIPTS["sshd"](context))

    def test_cleanup_journal_requires_exact_target_identity(self):
        journal = {
            "version": 1,
            "host": "192.0.2.20",
            "port": 2222,
            "user": "admin",
            "fingerprint": "SHA256:" + "A" * 43,
            "phases": {phase: "DONE" for phase in prepare_vps.PHASES},
        }
        prepare_vps.cleanup_journal(
            journal, host="192.0.2.20", port=2222, user="admin",
            fingerprint="SHA256:" + "A" * 43,
        )
        for field, value in (("host", "192.0.2.21"), ("port", 22), ("user", "other"),
                             ("fingerprint", "SHA256:" + "B" * 43)):
            with self.subTest(field=field):
                requested = {
                    "host": "192.0.2.20", "port": 2222, "user": "admin",
                    "fingerprint": "SHA256:" + "A" * 43,
                }
                requested[field] = value
                with self.assertRaisesRegex(ValueError, "different VPS"):
                    prepare_vps.cleanup_journal(journal, **requested)
        with self.assertRaisesRegex(ValueError, "No provisioning state"):
            prepare_vps.cleanup_journal(
                None, host="192.0.2.20", port=2222, user="admin",
                fingerprint="SHA256:" + "A" * 43,
            )

    def test_cleanup_script_removes_only_owned_files_and_directories(self):
        cleanup = prepare_vps.cleanup_script(b"ssh-ed25519 test\n")
        self.assertIn('for operation in check remove', cleanup)
        self.assertIn('probe-key.sha256', cleanup)
        self.assertIn("0:0:700", cleanup)
        self.assertNotIn("sshd-config.previous", cleanup)
        self.assertNotIn(prepare_vps.FIREWALL_SUDOERS, cleanup)
        self.assertNotIn('rm -rf -- "$STATE"', cleanup)
        self.assertNotIn(f"rm -f -- {prepare_vps.AUTHORIZED} {prepare_vps.SUDOERS}", cleanup)
        self.assertIn("dir-libexec", cleanup)

    def test_failed_userdel_leaves_cleanup_unconfirmed(self):
        script = "id() { return 0; }; pkill() { return 0; }; userdel() { return 1; }; sleep() { return 0; }\n"
        script += prepare_vps.REMOVE_ACCOUNT + 'remove_account fixture || exit 1\nprintf "cleanup completed\\n"\n'
        result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("Provisioning account still exists: fixture", result.stderr)

    def test_cli_cleanup_rejects_mismatched_state_before_host_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "managed"
            output.mkdir(mode=0o700)
            prepare_vps.State(output / prepare_vps.STATE_FILE).save({
                "version": 1,
                "host": "192.0.2.20",
                "port": 2222,
                "user": "admin",
                "fingerprint": "SHA256:" + "A" * 43,
                "phases": {phase: "DONE" for phase in prepare_vps.PHASES},
                "status": "VERIFIED",
                "attempts": 1,
                "created_at": 1,
            })
            argv = ["prepare_vps.py", "--host", "192.0.2.21", "--port", "2222",
                    "--user", "admin", "--fingerprint", "SHA256:" + "A" * 43,
                    "--output", str(output), "--cleanup"]
            with patch("sys.argv", argv), patch.object(prepare_vps, "identify_host") as identify:
                with self.assertRaises(SystemExit) as error:
                    prepare_vps.main()
            self.assertEqual(error.exception.code, 1)
            identify.assert_not_called()

    def test_retry_after_ssh_disconnect_during_account_repairs_without_duplicating(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            remote = FakeRemote()
            fault = {"phase": "account", "when": "after", "kind": "disconnect"}
            provisioner, output = make_provisioner(directory, remote, fault=fault)
            with self.assertRaisesRegex(ValueError, "SSH_DISCONNECTED during account"):
                provisioner.run()
            self.assertTrue(remote.account)
            self.assertTrue((output / "probe").is_file())
            state = json.loads((output / prepare_vps.STATE_FILE).read_text())
            self.assertEqual(state["phases"]["preflight"], "DONE")
            self.assertEqual(state["phases"]["account"], "IN_PROGRESS")
            self.assertEqual(state["status"], "FAILED")

            retry = prepare_vps.Provisioner(
                host="192.0.2.20", port=2222, user="admin", identity=None, output=output,
                run_remote=remote, probe=lambda _: remote.probe_result,
                fingerprint="SHA256:" + "A" * 43, state=prepare_vps.State(output / prepare_vps.STATE_FILE),
            )
            retry.run()
            self.assertEqual(remote.calls.count("preflight"), 1)
            self.assertEqual(remote.calls.count("account"), 2)
            state = json.loads((output / prepare_vps.STATE_FILE).read_text())
            self.assertEqual(state["status"], "VERIFIED")
            self.assertTrue(all(state["phases"][phase] == "DONE" for phase in prepare_vps.PHASES))

    def test_managed_key_pair_rejects_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            remote = FakeRemote()
            provisioner, output = make_provisioner(directory, remote)
            target = directory / "outside"
            target.write_text("outside")
            provisioner.key.unlink()
            provisioner.key.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "managed observation key pair is missing"):
                provisioner._context()

            provisioner.key.unlink()
            provisioner.key.write_text("private")
            linked = directory / "outside-hardlink"
            linked.hardlink_to(provisioner.key)
            self.assertFalse(provisioner._managed_file(provisioner.key))

    def test_state_rejects_hardlink_and_foreign_owner_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            state_path = directory / prepare_vps.STATE_FILE
            state = prepare_vps.State(state_path)
            state.save({"version": 1, "phases": {phase: "PENDING" for phase in prepare_vps.PHASES}})
            linked = directory / "state-hardlink"
            linked.hardlink_to(state_path)
            with self.assertRaisesRegex(ValueError, "not private"):
                prepare_vps.State(linked).load()

    def test_partial_helper_installation_is_reinstalled_on_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(
                Path(tmp), remote, fault={"phase": "helpers", "when": "after", "kind": "fail"})
            with self.assertRaisesRegex(ValueError, "PROVISION_PHASE_FAILED during helpers"):
                provisioner.run()
            self.assertIn("ssh-gateway", remote.files)
            self.assertEqual(json.loads((output / prepare_vps.STATE_FILE).read_text())["phases"]["helpers"], "IN_PROGRESS")
            provisioner.fault = None
            provisioner.run()
            self.assertEqual(remote.calls.count("helpers"), 2)
            self.assertEqual(json.loads((output / prepare_vps.STATE_FILE).read_text())["status"], "VERIFIED")

    def test_workstation_interruption_after_partial_effect_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(
                Path(tmp), remote, fault={"phase": "keys", "when": "after", "kind": "crash"})
            with self.assertRaisesRegex(ValueError, "WORKSTATION_INTERRUPTED during keys"):
                provisioner.run()
            self.assertIn("authorized", remote.files)
            state = json.loads((output / prepare_vps.STATE_FILE).read_text())
            self.assertEqual(state["phases"]["keys"], "IN_PROGRESS")
            self.assertEqual(state["error"], "WORKSTATION_INTERRUPTED")
            provisioner.fault = None
            provisioner.run()
            self.assertEqual(remote.calls.count("keys"), 2)
            self.assertEqual(json.loads((output / prepare_vps.STATE_FILE).read_text())["status"], "VERIFIED")

    def test_failed_postcondition_rolls_back_local_and_remote_keys_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote(probe_result={"v": 7, "uid": 0})
            provisioner, output = make_provisioner(Path(tmp), remote, cleanup_on_failure=True)
            with self.assertRaisesRegex(ValueError, "Postcondition verification failed"):
                provisioner.run()
            self.assertTrue(remote.cleaned)
            self.assertFalse(remote.account)
            self.assertFalse(remote.files)
            for name in ("probe", "probe.pub", "targets.json"):
                self.assertFalse((output / name).exists(), name)
            state = json.loads((output / prepare_vps.STATE_FILE).read_text())
            self.assertEqual(state["status"], "CLEANED")

    def test_failed_postcondition_without_cleanup_keeps_state_for_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote(probe_result={"v": 8, "uid": 1000})
            provisioner, output = make_provisioner(Path(tmp), remote)
            with self.assertRaisesRegex(ValueError, "Postcondition verification failed"):
                provisioner.run()
            self.assertFalse(remote.cleaned)
            self.assertTrue((output / "probe").is_file())
            state = json.loads((output / prepare_vps.STATE_FILE).read_text())
            self.assertEqual(state["status"], "FAILED")
            self.assertEqual(state["error"], "POSTCONDITION_FAILED")
            self.assertEqual(state["phases"]["verify"], "FAILED")
            provisioner.probe = lambda _: {"v": 8, "uid": 0}
            provisioner.run()
            self.assertEqual(json.loads((output / prepare_vps.STATE_FILE).read_text())["status"], "VERIFIED")

    def test_cleanup_removes_remaining_local_key_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(Path(tmp), remote)
            provisioner.run()
            remote.cleaned = False
            provisioner._cleanup(provisioner.state.load())
            self.assertTrue(remote.cleaned)
            self.assertFalse((output / "probe").exists())
            self.assertFalse((output / "probe.pub").exists())
            self.assertFalse((output / "targets.json").exists())

    def test_unconfirmed_cleanup_preserves_credentials_and_marks_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(Path(tmp), remote)
            provisioner.run()
            def fail_cleanup(script):
                raise subprocess.CalledProcessError(255, ["ssh"])
            provisioner.run_remote = fail_cleanup
            with self.assertRaisesRegex(ValueError, "cleanup is unconfirmed"):
                provisioner._cleanup(provisioner.state.load())
            self.assertTrue((output / "probe").exists())
            self.assertTrue((output / "targets.json").exists())
            self.assertEqual(provisioner.state.load()["status"], "CLEANUP_FAILED")

    def test_firewall_context_provisions_second_account_and_removes_its_keys(self):
        context = {"probe_public_key": b"ssh-ed25519 test\n", "firewall_public_key": b"ssh-ed25519 firewall\n",
                   "firewall": True, "ssh_port": 2222}
        account = prepare_vps.PHASE_SCRIPTS["account"](context)
        self.assertIn("id vpn-orbit-firewall", account)
        self.assertIn(prepare_vps.FIREWALL_HOME, account)
        keys = prepare_vps.PHASE_SCRIPTS["keys"](context)
        self.assertIn(prepare_vps.FIREWALL_AUTHORIZED, keys)
        payload = base64.b64decode(keys.split("printf %s ", 2)[2].split(" ", 1)[0])
        self.assertIn(b'command="/usr/local/libexec/vpn-orbit/firewall-gateway"', payload)
        self.assertIn(b"ssh-ed25519 firewall", payload)
        sudoers = prepare_vps.PHASE_SCRIPTS["sudoers"](context)
        rules = base64.b64decode(sudoers.split("printf %s ", 1)[1].split(" ", 1)[0]).decode()
        self.assertIn("vpn-orbit-firewall ALL=(root) NOPASSWD: /usr/local/libexec/vpn-orbit/firewall-apply", rules)
        sshd = prepare_vps.PHASE_SCRIPTS["sshd"](context)
        self.assertIn("firewall-gateway", sshd)
        self.assertIn("Match User vpn-orbit-firewall", prepare_vps.FIREWALL_SSH_PROFILE)
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(Path(tmp), remote, firewall=True)
            provisioner.run()
            provisioner._cleanup(provisioner.state.load())
            for name in ("probe", "probe.pub", "firewall", "firewall.pub", "targets.json"):
                self.assertFalse((output / name).exists(), name)

    def test_firewall_flag_records_a_second_secret_and_capability(self):
        blob = b"test host key"
        encoded = base64.b64encode(blob).decode()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            admin_key = directory / "admin"
            admin_key.touch()
            output = directory / "target"
            argv = ["prepare_vps.py", "--host", "192.0.2.20", "--port", "2222", "--user", "admin",
                    "--identity", str(admin_key), "--fingerprint", fingerprint, "--output", str(output),
                    "--firewall"]

            def run(cmd, **kwargs):
                if cmd[0] == "ssh-keygen":
                    path = Path(cmd[cmd.index("-f") + 1])
                    path.write_bytes(b"private")
                    Path(str(path) + ".pub").write_bytes(b"ssh-ed25519 test\n")

            with (patch("sys.argv", argv), patch("builtins.print"),
                  patch.object(prepare_vps.subprocess, "run", side_effect=run) as runner,
                  patch.object(prepare_vps.subprocess, "check_output", side_effect=[
                      f"[192.0.2.20]:2222 ssh-ed25519 {encoded}\n", '{"v":8,"uid":0}'])):
                prepare_vps.main()
            self.assertEqual(runner.call_count, 2 + len(prepare_vps.PHASES))
            policy = json.loads((output / "targets.json").read_text())["targets"][0]
            self.assertEqual(policy["capabilities"], ["host.probe", "firewall.apply"])
            self.assertRegex(policy["firewall_secret_ref"], r"^[0-7][0-9A-HJKMNP-TV-Z]{25}:v1$")
            self.assertNotEqual(policy["firewall_secret_ref"].split(":")[0], policy["secret_ref"].split(":")[0])
            self.assertTrue((output / "firewall").is_file())
            self.assertTrue((output / "firewall.pub").is_file())

    def test_state_from_another_host_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = FakeRemote()
            provisioner, output = make_provisioner(Path(tmp), remote)
            provisioner.run()
            other = prepare_vps.Provisioner(
                host="192.0.2.21", port=2222, user="admin", identity=None, output=output,
                run_remote=remote, probe=lambda _: remote.probe_result,
                fingerprint="SHA256:" + "A" * 43, state=prepare_vps.State(output / prepare_vps.STATE_FILE),
            )
            with self.assertRaisesRegex(ValueError, "different VPS"):
                other.run()

    def test_fault_specification_is_strict(self):
        with patch.dict(os.environ, {prepare_vps.FAULT_ENV: "phase=helpers,when=after,kind=disconnect"}):
            self.assertEqual(prepare_vps.fault_spec(),
                             {"phase": "helpers", "when": "after", "kind": "disconnect"})
        for value in ("phase=unknown", "phase=helpers,when=later", "phase=helpers,kind=explode"):
            with self.subTest(value=value), patch.dict(os.environ, {prepare_vps.FAULT_ENV: value}):
                with self.assertRaisesRegex(ValueError, "Invalid fault injection"):
                    prepare_vps.fault_spec()
        with patch.dict(os.environ, {prepare_vps.FAULT_ENV: ""}):
            self.assertIsNone(prepare_vps.fault_spec())


if __name__ == "__main__":
    unittest.main()
