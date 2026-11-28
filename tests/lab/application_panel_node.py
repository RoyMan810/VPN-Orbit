"""Acceptance of an existing Remnawave link on a disposable GitHub VM."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import traceback
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from vpn_orbit.app_adoption import ExternalLifecycle
from vpn_orbit.app_helper import dispatch
from vpn_orbit.app_lifecycle import Docker, ROOT
from vpn_orbit.app_profiles import render
from vpn_orbit.errors import Denied


PANEL_ID = "01JCYQZ4T9V8MNVYEH3D2M7Q1P"
NODE_ID = "01JCYQZ4T9V8MNVYEH3D2M7Q1N"
NODE_PORT = 2222
XRAY_PORT = 18444


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


PANEL_HTTP = build_opener(ProxyHandler({}), NoRedirect())


def panel_api(path, *, token=None, body=None):
    headers = {"Host": "panel.test.invalid", "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    request = Request("http://127.0.0.1:3000/api/" + path, headers=headers, data=data)
    try:
        with PANEL_HTTP.open(request, timeout=5) as response:
            return json.load(response)["response"]
    except HTTPError as error:
        error.close()
        raise RuntimeError(f"Panel API {path} returned HTTP {error.code}") from None


def identifier(value):
    return str(UUID(value["uuid"]))


def listening():
    try:
        with socket.create_connection(("127.0.0.1", XRAY_PORT), timeout=1):
            return True
    except OSError:
        return False


def await_link(read_node, *, connected):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = read_node()
        if (state["isConnected"] is connected and state["isConnecting"] is False
                and listening() is connected):
            return state
        time.sleep(1)
    raise RuntimeError("Panel link or Xray listener did not reach " + ("online" if connected else "offline"))


def start_external(stack, docker, directory, project, identity, role, images, settings, **permissions):
    """Use the pinned profiles in pre-existing projects with Compose's ownership labels."""
    spec = {"v": 1, "id": identity, "profiles": [role], "images": images, "settings": {role: settings}}
    document = render(spec, "a" * 64)
    document["name"] = project
    for service in document["services"].values():
        service.pop("labels")
    if permissions:
        document["services"][role]["restart"] = "no"
    for resource in (*document["networks"].values(), *document["volumes"].values()):
        resource.pop("labels")
        resource["name"] = project + resource["name"].removeprefix("vo-app-" + identity.lower())
    source = directory / (project + ".json")
    source.touch(mode=0o600)
    source.write_text(json.dumps(document))
    args = ("compose", "--project-name", project, "--file", str(source))
    stack.callback(docker, *args, "down", "--volumes")
    docker(*args, "up", "--wait", "--wait-timeout", "150", "--pull", "never", "--no-build", timeout=180)
    hashes = dict(row.split() for row in docker(*args, "config", "--hash=*").splitlines())
    return {"version": 1, "id": identity, "project": project, "compose_files": [str(source)],
            "extra_files": [], "service_hashes": hashes, **permissions}


def register(layout, runtime, staged):
    review = runtime.definition()["baseline"]["identity"]
    command = {"action": "adopt", "operation_id": layout["id"], "installation_id": layout["id"],
               "spec_digest": staged["spec_digest"], "review": review}
    result = dispatch({"operation": "execute", "application": command})
    assert result["code"] == "APP_ADOPTION_REGISTERED", result
    assert dispatch({"operation": "reconcile", "application": command}) == result
    assert runtime.status()["state"] == "ADOPTED"
    return command["spec_digest"]


def detach(runtime, layout, binding):
    command = {"action": "detach", "operation_id": layout["id"][:-1] + "D", "installation_id": layout["id"],
               "spec_digest": binding}
    result = dispatch({"operation": "execute", "application": command})
    assert result["code"] == "APP_ADOPTION_DETACHED", result
    assert runtime.status()["state"] == "STAGED"


def acceptance():
    if os.path.lexists(ROOT):
        raise RuntimeError("Disposable app namespace must be absent")
    images = json.loads((Path(__file__).resolve().parents[2] / "vpn_orbit/application-images.json")
                        .read_text(encoding="utf-8"))["images"]
    docker = Docker()
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vo-panel-node-", dir="/var/lib")))
        for role in ("remnawave-panel", "remnawave-node", "postgres", "redis"):
            docker("pull", "--platform", "linux/amd64", images[role], timeout=300)

        panel_settings = {"database_password": secrets.token_hex(32), "app_secret": secrets.token_hex(32),
                          "metrics_password": secrets.token_hex(32), "domain": "panel.test.invalid",
                          "subscription_domain": "sub.test.invalid"}
        panel = start_external(stack, docker, directory, "fixture-panel", PANEL_ID, "remnawave-panel",
                               {name: images[name] for name in ("remnawave-panel", "postgres", "redis")}, panel_settings)
        panel_container = docker("container", "ls", "--no-trunc", "--quiet",
                                 "--filter", "label=com.docker.compose.project=fixture-panel",
                                 "--filter", "label=com.docker.compose.service=remnawave-panel").strip()
        inspection = json.loads(docker("container", "inspect", panel_container))[0]
        address = inspection["NetworkSettings"]["Networks"]["fixture-panel-apps"]["Gateway"]
        assert address
        token = panel_api("auth/register", body={"username": "fixture-admin",
                                               "password": "Va9-" + secrets.token_urlsafe(32)})["accessToken"]
        secret = panel_api("keygen", token=token)["secretKey"]
        profile = panel_api("config-profiles", token=token, body={"name": "Orbit Link Fixture", "config": {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "fixture-inbound", "port": XRAY_PORT, "listen": "127.0.0.1", "protocol": "shadowsocks",
                          "settings": {"clients": [], "method": "chacha20-ietf-poly1305", "network": "tcp"}}],
            "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}],
        }})
        profile_id = identifier(profile)
        inbound_id = identifier(profile["inbounds"][0])

        node = start_external(stack, docker, directory, "fixture-node", NODE_ID, "remnawave-node",
                              {"remnawave-node": images["remnawave-node"]},
                              {"secret_key": secret, "port": NODE_PORT}, allow_start=True, allow_stop=True)
        created = panel_api("nodes", token=token, body={
            "name": "Orbit Link Node", "address": address, "port": NODE_PORT,
            "configProfile": {"activeConfigProfileUuid": profile_id, "activeInbounds": [inbound_id]},
        })
        node_uuid = identifier(created)

        def read_node():
            state = panel_api("nodes/" + node_uuid, token=token)
            assert identifier(state) == node_uuid
            assert (state["address"], state["port"]) == (address, NODE_PORT)
            assert state["configProfile"]["activeConfigProfileUuid"] == profile_id
            assert [identifier(inbound) for inbound in state["configProfile"]["activeInbounds"]] == [inbound_id]
            return state

        def assert_profile_unchanged():
            saved = panel_api("config-profiles/" + profile_id, token=token)
            assert identifier(saved) == profile_id
            assert saved["config"] == profile["config"]
            assert [identifier(inbound) for inbound in saved["inbounds"]] == [inbound_id]

        await_link(read_node, connected=True)

        panel_stage = ExternalLifecycle.stage(panel)
        node_stage = ExternalLifecycle.stage(node)
        panel_runtime, node_runtime = ExternalLifecycle(PANEL_ID), ExternalLifecycle(NODE_ID)
        panel_before, node_before = panel_runtime.capture(panel), node_runtime.capture(node)
        panel_binding = register(panel, panel_runtime, panel_stage)
        node_binding = register(node, node_runtime, node_stage)
        assert panel_runtime.capture(panel) == panel_before
        assert node_runtime.capture(node) == node_before
        await_link(read_node, connected=True)
        print("PASS external Panel and Node adopted with the existing Panel node/profile, Docker IDs, and volumes intact.")

        scope = {"installation_id": NODE_ID, "spec_digest": node_binding, "registration_id": NODE_ID}
        stop = {"action": "stop-adopted", "operation_id": NODE_ID[:-1] + "S", **scope, "running_receipt_id": NODE_ID}
        result = dispatch({"operation": "execute", "application": stop})
        assert result["code"] == "APP_ADOPTED_STOP_VERIFIED", result
        await_link(read_node, connected=False)
        start = {"action": "start-adopted", "operation_id": NODE_ID[:-1] + "T", **scope}
        result = dispatch({"operation": "execute", "application": start})
        assert result["code"] == "APP_ADOPTED_START_VERIFIED", result
        await_link(read_node, connected=True)
        current = node_runtime.capture(node)
        before, after = node_before["containers"]["remnawave-node"], current["containers"]["remnawave-node"]
        assert (after["Id"], after["configuration"]) == (before["Id"], before["configuration"])
        assert after["started_at"] != before["started_at"]
        assert panel_runtime.capture(panel) == panel_before
        print("PASS Panel detects the adopted Node offline and restores its existing Xray listener after exact-ID start.")

        detach(node_runtime, node, node_binding)
        detach(panel_runtime, panel, panel_binding)
        await_link(read_node, connected=True)
        assert_profile_unchanged()
        assert node_runtime.capture(node) == current
        assert panel_runtime.capture(panel) == panel_before
        print("PASS detaching both registrations preserves the live Panel link, profile, and Docker resources.")


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        acceptance()
    except Exception as error:
        subprocess.run(["docker", "ps", "--all", "--format", "{{.Names}} {{.Status}}"], check=False)
        frames = traceback.extract_tb(error.__traceback__)
        sites = ",".join(f"{Path(frame.filename).name}:{frame.lineno}" for frame in frames)
        code = error.code if isinstance(error, Denied) else type(error).__name__
        if isinstance(error, RuntimeError):
            code = str(error)
        print(f"Panel and Node acceptance diagnostic {code} at {sites}", flush=True)
        raise SystemExit("Panel and Node acceptance failed") from None


if __name__ == "__main__":
    main()
