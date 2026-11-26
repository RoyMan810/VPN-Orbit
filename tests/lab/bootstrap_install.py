"""Verify the one-command installation on a disposable Ubuntu or Debian host."""

from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener

import installation


def main():
    if os.geteuid() != 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("This fixture requires a disposable GitHub-hosted VM.")
    for name in ("vpn-orbit-compose.service", "vpn-orbit-broker.socket", "vpn-orbit-supervisor.socket",
                 "vpn-orbit-web.service"):
        subprocess.run(["systemctl", "is-active", "--quiet", name], check=True, timeout=10)

    installation.PASSWORD = secrets.token_urlsafe(32)
    installation.owner_create()

    origin = "https://127.0.0.1:18443"
    ca = "/opt/vpn-orbit-bootstrap/web-ca.pem"
    context = ssl.create_default_context(cafile=ca)
    browser = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(CookieJar()))
    with browser.open(origin, timeout=10) as response:
        assert b"/assets/" in response.read()
    with browser.open(origin + "/healthz", timeout=10) as response:
        assert json.load(response)["status"] == "alive"
    login = Request(origin + "/api/v1/auth/login",
                    data=json.dumps({"username": "roman", "password": installation.PASSWORD}).encode(),
                    headers={"Content-Type": "application/json", "Origin": origin})
    with browser.open(login, timeout=10) as response:
        user = json.load(response)["user"]
        assert user["role"] == "Owner"
        assert "Secure" in response.headers["Set-Cookie"]
    with browser.open(origin + "/api/v1/audit/integrity", timeout=10) as response:
        assert json.load(response)["status"] == "verified"

    subprocess.run(["systemctl", "restart", "vpn-orbit-compose.service"], check=True, timeout=195)
    # systemd may complete the Compose job before the HTTPS proxy accepts connections.
    subprocess.run([
        "curl", "--disable", "--fail", "--silent", "--show-error", "--noproxy", "*",
        "--retry", "8", "--retry-connrefused", "--retry-max-time", "30", "--max-time", "4",
        "--cacert", ca, "--output", "/dev/null", origin + "/healthz",
    ], check=True, timeout=40)
    with browser.open(origin + "/api/v1/auth/session", timeout=10) as response:
        assert json.load(response)["user"]["id"] == user["id"]
    with browser.open(origin + "/api/v1/audit/integrity", timeout=10) as response:
        assert json.load(response)["status"] == "verified"

    revision = subprocess.check_output(["git", "-c", f"safe.directory={Path.cwd()}",
                                        "rev-parse", "HEAD"], text=True).strip()
    installed = json.loads(Path("/opt/vpn-orbit/installation.json").read_bytes())
    assert installed["source_commit"] == revision
    assert installed["remote_mutation_enabled"] is False

    listeners = subprocess.check_output(["ss", "-Hltn", "sport = :18443"], text=True).splitlines()
    assert [line.split()[3] for line in listeners] == ["127.0.0.1:18443"]


if __name__ == "__main__":
    main()
