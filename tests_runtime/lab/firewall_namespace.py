#!/usr/bin/env python3
"""Real nftables/SSH faults, guarded for a disposable GitHub-hosted VM only."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[2]
NS = "vo-firewall-lab"
LINK, PEER = "vo-fw-host", "vo-fw-peer"
ADDRESS = "10.232.0.2"
ACCOUNT = "vpn-orbit-firewall"
LIBEXEC = Path("/usr/local/libexec/vpn-orbit")
POLICY = Path("/etc/vpn-orbit/firewall-policy.json")
JOURNAL = Path("/var/lib/vpn-orbit-firewall")
OP = "01JCYQZ4T9V8MNVYEH3D2M7Q1"


def run(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, capture_output=True, timeout=30, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.parse_args()
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    for path in (LIBEXEC, POLICY.parent, JOURNAL):
        if path.exists() or path.is_symlink():
            raise SystemExit("Fixture path occupied: " + str(path))
    if subprocess.run(["getent", "passwd", ACCOUNT], capture_output=True).returncode == 0:
        raise SystemExit("Fixture account exists")
    processes, log, created_account = [], None, False
    root = Path(tempfile.mkdtemp(prefix="vo-firewall-", dir="/run"))
    try:
        root.chmod(0o755)
        run(["ip", "netns", "add", NS])
        run(["ip", "link", "add", LINK, "type", "veth", "peer", "name", PEER])
        run(["ip", "link", "set", PEER, "netns", NS])
        run(["ip", "addr", "add", "10.232.0.1/30", "dev", LINK])
        run(["ip", "link", "set", LINK, "up"])
        run(["ip", "-n", NS, "addr", "add", ADDRESS + "/30", "dev", PEER])
        run(["ip", "-n", NS, "link", "set", PEER, "up"])
        run(["ip", "-n", NS, "link", "set", "lo", "up"])
        LIBEXEC.mkdir(parents=True, mode=0o755)
        POLICY.parent.mkdir(mode=0o755)
        shutil.copyfile(REPO / "remote/firewall-apply", LIBEXEC / "firewall-implementation")
        # Root-only lab wrapper adds a *fixed* namespace to systemd's rollback
        # service. No production helper accepts namespace/path/command input.
        wrapper = f'''#!/usr/bin/python3 -I
import runpy, subprocess
helper = runpy.run_path({str(LIBEXEC / "firewall-implementation")!r})
original = subprocess.run
def run(args, **kwargs):
    if args[0] == "/usr/bin/systemd-run":
        args = [args[0], "--property=NetworkNamespacePath=/run/netns/{NS}", *args[1:]]
    return original(args, **kwargs)
subprocess.run = run
raise SystemExit(helper["main"]())
'''
        (LIBEXEC / "firewall-apply").write_text(wrapper)
        for name in ("firewall-gateway", "firewall-rollback"):
            shutil.copyfile(REPO / "remote" / name, LIBEXEC / name)
        for path in LIBEXEC.iterdir():
            path.chmod(0o755)
        POLICY.write_text(json.dumps({"v": 1, "ssh_port": 2222, "max_rules": 32, "rollback_seconds": 10}))
        POLICY.chmod(0o600)
        run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/bin/sh",
             "--password", "*", ACCOUNT])
        created_account = True
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", root / "key"])
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", root / "host"])
        (root / "authorized").write_bytes((root / "key.pub").read_bytes())
        (root / "authorized").chmod(0o644)
        sudo = Path("/etc/sudoers.d/vo-firewall-lab")
        sudo.write_text(f'{ACCOUNT} ALL=(root) NOPASSWD: {LIBEXEC}/firewall-apply ""\n')
        sudo.chmod(0o440)
        run(["visudo", "-cf", sudo])
        config = root / "sshd.conf"
        config.write_text(f"""Port 2222
ListenAddress {ADDRESS}
HostKey {root}/host
PidFile {root}/sshd.pid
UsePAM no
StrictModes yes
AllowUsers {ACCOUNT}
AuthorizedKeysFile {root}/authorized
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
DisableForwarding yes
PermitTTY no
PermitUserRC no
ForceCommand {LIBEXEC}/firewall-gateway
""")
        Path("/run/sshd").mkdir(exist_ok=True)
        log = (root / "sshd.log").open("wb")
        sshd = subprocess.Popen(["ip", "netns", "exec", NS, "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                stdout=log, stderr=log, start_new_session=True)
        processes.append(sshd)
        (root / "known_hosts").write_text(f"[{ADDRESS}]:2222 {(root / 'host.pub').read_text()}")
        ssh = ["ssh", "-F", "/dev/null", "-T", "-p", "2222", "-i", str(root / "key"),
               "-oBatchMode=yes", "-oIdentitiesOnly=yes", "-oStrictHostKeyChecking=yes",
               "-oGlobalKnownHostsFile=/dev/null", "-oUserKnownHostsFile=" + str(root / "known_hosts"),
               "-oConnectTimeout=3", f"{ACCOUNT}@{ADDRESS}", "vpn-orbit.v1.firewall"]

        def call(request, *, success=True):
            result = subprocess.run(ssh, input=json.dumps(request).encode(), capture_output=True, timeout=20)
            value = json.loads(result.stdout)
            if success and (result.returncode != 0 or value["outcome"] != "SUCCEEDED"):
                raise AssertionError(value)
            return value

        for _ in range(40):
            try:
                call({"operation": "status", "operation_id": OP + "A"})
                break
            except (ValueError, subprocess.SubprocessError):
                time.sleep(0.1)
        else:
            raise AssertionError("Fixture SSH not ready: " + (root / "sshd.log").read_text())

        previous_digest = None

        def payload(letter, rules):
            import hashlib
            digest = hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            return {"operation": "apply", "operation_id": OP + letter, "rules": rules,
                    "rules_digest": digest, "ssh_port": 2222,
                    "previous_rules_digest": previous_digest or hashlib.sha256(b"[]").hexdigest()}

        rules = [{"action": "allow", "direction": "in", "protocol": "tcp", "port": 2222, "cidr": "0.0.0.0/0"},
                 {"action": "deny", "direction": "in", "protocol": "tcp", "port": 2222, "cidr": "0.0.0.0/0"},
                 {"action": "deny", "direction": "in", "protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"}]
        first = payload("A", rules)
        call(first)
        # This is a different TCP+SSH connection from apply. A deny for SSH
        # cannot override the helper's fixed management rule.
        assert call({"operation": "status", "operation_id": first["operation_id"]})["state"] == "ARMED"
        call({"operation": "confirm", "operation_id": first["operation_id"], "rules_digest": first["rules_digest"]})
        previous_digest = first["rules_digest"]
        baseline = run(["ip", "netns", "exec", NS, "nft", "-nn", "list", "table", "inet", "vpn_orbit"]).stdout
        assert b"meta nfproto 2 tcp dport 443 drop" in baseline, baseline
        rejected = call({"operation": "exec", "command": "nft flush ruleset"}, success=False)
        assert rejected["outcome"] == "DENIED"

        def wait_rollback(operation):
            for _ in range(100):
                if json.loads((JOURNAL / (operation + ".json")).read_text())["state"] == "ROLLED_BACK":
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("Independent rollback did not fire")
            assert run(["ip", "netns", "exec", NS, "nft", "-nn", "list", "table", "inet", "vpn_orbit"]).stdout == baseline

        # Lose all Controller access after apply. systemd in the disposable VM
        # must roll back in the server namespace, without a second SSH request.
        second = payload("B", rules + [{**rules[-1], "port": 444}])
        call(second)
        os.killpg(sshd.pid, signal.SIGTERM)
        sshd.wait(timeout=5)
        wait_rollback(second["operation_id"])

        # SIGKILL the applying helper after a real nft transaction and before
        # durable postcondition/response. The timer must already exist.
        # A standalone root test driver uses the same production functions.
        driver = root / "crash.py"
        driver.write_text(f'''import os, runpy, signal, subprocess, json
h = runpy.run_path({str(LIBEXEC / "firewall-implementation")!r})
n = h["dispatch"].__globals__
original_run = subprocess.run
def run(args, **kw):
    if args[0] == "/usr/bin/systemd-run":
        args = [args[0], "--property=NetworkNamespacePath=/run/netns/{NS}", *args[1:]]
    return original_run(args, **kw)
subprocess.run = run
original_apply = n["apply_table"]
def apply(script):
    original_apply(script)
    os.kill(os.getpid(), signal.SIGKILL)
n["apply_table"] = apply
h["dispatch"](json.loads({json.dumps(payload("C", rules + [{**rules[-1], "port": 445}]))!r}))
''')
        crashed = subprocess.run(["ip", "netns", "exec", NS, sys.executable, str(driver)], timeout=20)
        assert crashed.returncode == -signal.SIGKILL
        wait_rollback(OP + "C")
        print(json.dumps({"status": "PASSED", "scenarios": ["typed-rejection", "fresh-SSH",
              "SSH-deny-preserves-access", "IPv4-scope", "controller-loss-rollback", "SIGKILL-rollback"]}))
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
        if log:
            log.close()
        for letter in ("A", "B", "C"):
            subprocess.run(["systemctl", "stop", f"vpn-orbit-firewall-{OP}{letter}.timer",
                            f"vpn-orbit-firewall-{OP}{letter}.service"], capture_output=True)
        subprocess.run(["ip", "netns", "del", NS], capture_output=True)
        subprocess.run(["ip", "link", "del", LINK], capture_output=True)
        Path("/etc/sudoers.d/vo-firewall-lab").unlink(missing_ok=True)
        if created_account:
            subprocess.run(["userdel", ACCOUNT], capture_output=True)
        for path in (root, LIBEXEC, POLICY.parent, JOURNAL):
            shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    main()
