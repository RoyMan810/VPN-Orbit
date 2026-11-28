"""Acceptance of an existing Remnawave link on a disposable GitHub VM."""

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
from threading import Thread
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
SOCKS_PORT = 18445


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


PANEL_HTTP = build_opener(ProxyHandler({}), NoRedirect())


def panel_api(path, *, token=None, body=None, admin=False):
    headers = {"Host": "panel.test.invalid", "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if admin:
        headers["X-Remnawave-Client-Type"] = "browser"
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


def listening(port=XRAY_PORT):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
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


def start_origin(stack, marker):
    """Serve one short response on loopback for the authenticated traffic check."""
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/acceptance":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            self.wfile.write(marker)

        def log_message(self, format, *args):
            pass

    server = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
    Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.shutdown)
    return server.server_port


def start_client(stack, docker, directory, image, user):
    """Run the Xray binary from the pinned Node image as a loopback-only client."""
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": XRAY_PORT,
            "users": [{"id": user, "encryption": "none"}],
        }]}}],
    }
    source = directory / "xray-client.json"
    source.touch(mode=0o600)
    source.write_text(json.dumps(config))
    client = docker("run", "--detach", "--pull", "never", "--network", "host", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--mount", f"type=bind,source={source},target=/probe.json,readonly",
                    "--entrypoint", "/usr/local/bin/xray", image, "run", "-config", "/probe.json").strip()
    stack.callback(docker, "container", "rm", "--force", client)
    return client


def request_through_node(port):
    return subprocess.run(
        ["curl", "--disable", "--noproxy", "", "--socks5", f"127.0.0.1:{SOCKS_PORT}",
         "--connect-timeout", "2", "--max-time", "4", "--silent", "--show-error", "--fail",
         "--url", f"http://127.0.0.1:{port}/acceptance"],
        capture_output=True, timeout=5, check=False,
    )


def await_traffic(port, marker, docker, client):
    deadline = time.monotonic() + 30
    status = None
    phase = ""
    while time.monotonic() < deadline:
        result = request_through_node(port)
        status = result.returncode
        failure = result.stderr.lower()
        phase = "SOCKS handshake" if b"socks" in failure else "transfer"
        if status == 0:
            if result.stdout != marker:
                raise RuntimeError("The VPN client received an unexpected HTTP body")
            return
        time.sleep(1)
    state = json.loads(docker("container", "inspect", client))[0]["State"]
    logs = docker("container", "logs", client)
    hints = ("failed to load config", "permission denied", "failed to listen", "configuration error",
             "failed to find", "failed to dial", "connection refused", "invalid", "rejected")
    matched = ", ".join(hint for hint in hints if hint in logs.lower())
    raise RuntimeError(f"VPN traffic failed ({phase}, curl exit {status}, client {state['Status']}:{state['ExitCode']}, "
                       f"SOCKS listening {listening(SOCKS_PORT)}, origin listening {listening(port)}, hints {matched})")


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
        admin = panel_api("auth/register", body={"username": "fixture-admin",
                                               "password": "Va9-" + secrets.token_urlsafe(32)})["accessToken"]
        token = panel_api("tokens", token=admin, admin=True, body={
            "name": "Orbit link acceptance", "expiresInDays": 1,
            "scopes": ["keygen:get", "config-profiles:create", "config-profiles:get",
                       "nodes:create", "nodes:get", "internal-squads:create", "users:create"],
        })["token"]
        secret = panel_api("keygen", token=token)["secretKey"]
        marker = secrets.token_hex(16).encode()
        origin = start_origin(stack, marker)
        profile = panel_api("config-profiles", token=token, body={"name": "Orbit Link Fixture", "config": {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "fixture-inbound", "port": XRAY_PORT, "listen": "127.0.0.1", "protocol": "vless",
                          "settings": {"clients": [], "decryption": "none"}}],
            "outbounds": [{"tag": "ORIGIN", "protocol": "freedom",
                           "settings": {"redirect": f"127.0.0.1:{origin}"}}],
        }})
        profile_id = identifier(profile)
        inbound_id = identifier(profile["inbounds"][0])
        squad = panel_api("internal-squads", token=token, body={"name": "Orbit Link Users", "inbounds": [inbound_id]})
        user = panel_api("users", token=token, body={
            "username": "orbit_fixture_user",
            "expireAt": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "activeInternalSquads": [identifier(squad)],
        })
        client = start_client(stack, docker, directory, images["remnawave-node"], str(UUID(user["vlessUuid"])))

        def verify_traffic():
            await_traffic(origin, marker, docker, client)

        node = start_external(stack, docker, directory, "fixture-node", NODE_ID, "remnawave-node",
                              {"remnawave-node": images["remnawave-node"]},
                              {"secret_key": secret, "port": NODE_PORT},
                              allow_start=True, allow_stop=True, allow_restart=True)
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
        verify_traffic()

        panel_stage = ExternalLifecycle.stage(panel)
        node_stage = ExternalLifecycle.stage(node)
        panel_runtime, node_runtime = ExternalLifecycle(PANEL_ID), ExternalLifecycle(NODE_ID)
        panel_before, node_before = panel_runtime.capture(panel), node_runtime.capture(node)
        panel_binding = register(panel, panel_runtime, panel_stage)
        node_binding = register(node, node_runtime, node_stage)
        assert panel_runtime.capture(panel) == panel_before
        assert node_runtime.capture(node) == node_before
        await_link(read_node, connected=True)
        verify_traffic()
        print("PASS adoption preserves authenticated VPN traffic, the existing Panel profile, Docker IDs, and volumes.")

        scope = {"installation_id": NODE_ID, "spec_digest": node_binding, "registration_id": NODE_ID}
        stop = {"action": "stop-adopted", "operation_id": NODE_ID[:-1] + "S", **scope, "running_receipt_id": NODE_ID}
        result = dispatch({"operation": "execute", "application": stop})
        assert result["code"] == "APP_ADOPTED_STOP_VERIFIED", result
        await_link(read_node, connected=False)
        if request_through_node(origin).returncode == 0:
            raise RuntimeError("The VPN client unexpectedly reached the origin with the Node stopped")
        start = {"action": "start-adopted", "operation_id": NODE_ID[:-1] + "T", **scope}
        result = dispatch({"operation": "execute", "application": start})
        assert result["code"] == "APP_ADOPTED_START_VERIFIED", result
        await_link(read_node, connected=True)
        verify_traffic()
        resumed = node_runtime.capture(node)["containers"]["remnawave-node"]
        print("PASS Panel detects the adopted Node offline and restores its existing Xray listener after exact-ID start.")

        restart = {"action": "restart-adopted", "operation_id": NODE_ID[:-1] + "R", **scope,
                   "running_receipt_id": start["operation_id"]}
        result = dispatch({"operation": "execute", "application": restart})
        assert result["code"] == "APP_ADOPTED_RESTART_VERIFIED", result
        await_link(read_node, connected=True)
        verify_traffic()
        current = node_runtime.capture(node)
        before, after = node_before["containers"]["remnawave-node"], current["containers"]["remnawave-node"]
        identity = before["Id"], before["configuration"]
        assert (resumed["Id"], resumed["configuration"]) == identity
        assert (after["Id"], after["configuration"]) == identity
        assert len({before["started_at"], resumed["started_at"], after["started_at"]}) == 3
        assert panel_runtime.capture(panel) == panel_before
        print("PASS authenticated VPN traffic resumes through the same Node after exact-ID stop/start and restart.")

        detach(node_runtime, node, node_binding)
        detach(panel_runtime, panel, panel_binding)
        await_link(read_node, connected=True)
        verify_traffic()
        assert_profile_unchanged()
        assert node_runtime.capture(node) == current
        assert panel_runtime.capture(panel) == panel_before
        print("PASS detaching both registrations preserves the Panel link, VPN traffic, profile, and Docker resources.")


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
