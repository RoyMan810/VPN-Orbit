"""Actual product lifecycle acceptance on an explicitly disposable host."""

import json
import os
from pathlib import Path
import secrets
import subprocess
from urllib.request import Request, urlopen

from vpn_orbit.app_lifecycle import Docker, Lifecycle, ROOT
from vpn_orbit.app_profiles import digest
from vpn_orbit.errors import Denied


IDENTITY = "01JCYQZ4T9V8MNVYEH3D2M7Q1A"


def panel_acceptance():
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError("Disposable app namespace must be absent")
    images = json.loads((Path(__file__).resolve().parents[2] / "deploy/application-images.json").read_text())["images"]
    spec = {"v": 1, "id": IDENTITY, "profiles": ["remnawave-panel"],
            "images": {name: images[name] for name in ("remnawave-panel", "postgres", "redis")},
            "settings": {"remnawave-panel": {
                "database_password": secrets.token_hex(32), "app_secret": secrets.token_hex(32),
                "metrics_password": secrets.token_hex(32),
                "domain": "panel.test.invalid", "subscription_domain": "sub.test.invalid",
            }}}
    Lifecycle.configure(spec)
    app = Lifecycle(IDENTITY)
    binding = digest(spec)
    receipt = app.execute(IDENTITY[:-1] + "B", "install", binding)
    assert receipt["outcome"] == "SUCCEEDED", receipt
    assert app.status()["state"] == "HEALTHY"
    # Upstream intentionally closes requests that lack trusted HTTPS-proxy headers.
    request = Request("http://127.0.0.1:3000/api/auth/status", headers={
        "Host": "panel.test.invalid", "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"})
    with urlopen(request, timeout=5) as response:
        assert response.status == 200 and isinstance(json.load(response), dict)
    assert app.execute(IDENTITY[:-1] + "B", "install", binding) == receipt
    _, document, installation = app.configuration()
    before = app.verify_inventory(document, installation)
    database = before["containers"]["panel-db"]["Id"]
    sql = "CREATE TABLE orbit_preservation(value text); INSERT INTO orbit_preservation VALUES('preserved');"
    app.docker("exec", database, "psql", "-U", "orbit", "-d", "orbit", "-c", sql)

    class LostReply(Docker):
        def __call__(self, *args, **kwargs):
            value = super().__call__(*args, **kwargs)
            if args[:2] == ("container", "start"):
                raise Denied("APP_REPLY_LOST")
            return value

    app.docker = LostReply()
    unknown = app.execute(IDENTITY[:-1] + "C", "start", binding)
    assert unknown["outcome"] == "UNKNOWN_OUTCOME"
    app.docker = Docker()
    app = Lifecycle(IDENTITY)  # Restart the executor with its original journal.
    assert app.reconcile(IDENTITY[:-1] + "C")["outcome"] == "RECONCILED_SUCCEEDED"
    with app.journal.connect() as db:
        assert db.execute("SELECT state FROM operations WHERE id=?", (IDENTITY[:-1] + "C",)).fetchone()["state"] == "UNKNOWN_OUTCOME"
    foreign = app.docker("run", "--detach", "--network", document["networks"]["apps"]["name"],
                         "--entrypoint", "sleep", spec["images"]["redis"], "60").strip()
    try:
        try:
            app.execute(IDENTITY[:-1] + "D", "remove", binding)
        except Denied as error:
            assert error.code == "APP_NETWORK_SHARED"
        else:
            raise AssertionError("Shared network was not protected")
    finally:
        app.docker("container", "rm", "--force", foreign)
    final = app.execute(IDENTITY[:-1] + "D", "remove", binding)
    assert final["outcome"] == "SUCCEEDED", final
    assert app.status()["state"] == "REMOVED"
    _, _, installation = app.configuration()
    after = app.verify_inventory(document, installation, allow_missing=True)
    assert not after["containers"]
    assert after["volumes"] == before["volumes"] and after["networks"] == before["networks"]
    print("PASS actual Panel HTTP, install, replay, lost reply, executor restart, readback, shared network refusal, removal.")
    print("PASS original data volume identities and networks preserved.")


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        panel_acceptance()
    except Exception:
        # No arbitrary product logs or exception messages: they may expose configuration.
        subprocess.run(["docker", "ps", "--all", "--format", "{{.Names}} {{.Status}}"], check=False)
        raise SystemExit("Product acceptance failed") from None


if __name__ == "__main__":
    main()
