"""Adopt a running Bedolaga stack on an isolated GitHub-hosted VM."""

from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
from threading import Thread
import time
import traceback

from tests.lab.application_adopted_postgres import backup_key, capture_archive, query, require_unregistered, restore_isolated
from tests.lab.application_panel_node import detach, identifier, panel_api, register, start_external
from vpn_orbit.app_adoption import ExternalLifecycle
from vpn_orbit.app_lifecycle import Docker, ROOT
from vpn_orbit.app_profiles import CABINET_CONFIG, PANEL_CA_FILE, PANEL_CA_MOUNT, render
from vpn_orbit.errors import Denied


PANEL_ID = "01JCYQZ4T9V8MNVYEH3D2M7Q1P"
BEDOLAGA_ID = "01JCYQZ4T9V8MNVYEH3D2M7Q1B"
PROJECT = "fixture-bedolaga"
GATEWAY = "192.0.2.1"
BOT_DATABASE = "remnawave_bot"
BOT_DATABASE_ROLE = "remnawave_user"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Telegram(FixtureHandler):
    def do_POST(self):
        action = self.path.rsplit("/", 1)[-1].lower()
        if action == "getme":
            result = {"id": 123456, "is_bot": True, "first_name": "Fixture", "username": "orbit_fixture_bot"}
        elif action == "getupdates":
            time.sleep(1)
            result = []
        else:
            result = True
        self.reply(200, json.dumps({"ok": True, "result": result}).encode())


class PanelHTTPS(FixtureHandler):
    def do_GET(self):
        if self.path != "/api/internal-squads":
            self.reply(404, b"{}")
            return
        headers = {"Host": "panel.test.invalid", "X-Forwarded-Proto": "https", "X-Forwarded-For": "127.0.0.1",
                   "Authorization": self.headers.get("Authorization", "")}
        status, body = http("127.0.0.1", 3000, self.path, headers=headers)
        self.reply(status, body)


def http(address, port, path, *, headers=None):
    connection = HTTPConnection(address, port, timeout=3)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(1024 * 1024)
    finally:
        connection.close()


def serve(stack, address, port, handler, *, tls=None):
    server = stack.enter_context(ThreadingHTTPServer((address, port), handler))
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.shutdown)


def project_address(docker, service):
    identity = docker("container", "ls", "--no-trunc", "--quiet",
                      "--filter", f"label=com.docker.compose.project={PROJECT}",
                      "--filter", f"label=com.docker.compose.service={service}").strip()
    return json.loads(docker("container", "inspect", identity))[0]["NetworkSettings"]["Networks"][PROJECT]["IPAddress"]


def create_bedolaga(stack, docker, directory, images, panel_token):
    app_secret = {"database_password": secrets.token_hex(32), "bot_token": "123456:" + secrets.token_urlsafe(32),
                  "admin_ids": "123", "panel_url": f"https://{GATEWAY}", "panel_api_key": panel_token,
                  "api_token": secrets.token_hex(32), "jwt_secret": secrets.token_hex(32)}
    spec = {"v": 1, "id": BEDOLAGA_ID, "profiles": ["bedolaga-bot", "bedolaga-cabinet"],
            "images": {key: images[key] for key in ("bedolaga-bot", "bedolaga-cabinet", "postgres", "redis")},
            "settings": {"bedolaga-bot": app_secret, "bedolaga-cabinet": {}}}
    document = render(spec, "a" * 64)
    document["name"] = PROJECT
    postgres = document["services"]["bot-db"]
    postgres["environment"].update(POSTGRES_DB=BOT_DATABASE, POSTGRES_USER=BOT_DATABASE_ROLE)
    postgres["healthcheck"]["test"] = ["CMD", "pg_isready", "-U", BOT_DATABASE_ROLE, "-d", BOT_DATABASE]
    for service in document["services"].values():
        service.pop("labels")
        service.pop("ports", None)
    for key, volume in document["volumes"].items():
        volume.pop("labels")
        volume["name"] = f"{PROJECT}-{key}"
    document["networks"]["apps"] = {
        "name": PROJECT, "driver": "bridge", "internal": True,
        "ipam": {"config": [{"subnet": "192.0.2.0/24", "gateway": GATEWAY}]},
    }
    cabinet_config = directory / "cabinet.conf"
    cabinet_config.write_text(CABINET_CONFIG, encoding="utf-8")
    document["services"]["bedolaga-cabinet"]["volumes"][0]["source"] = str(cabinet_config)
    cert, key = directory / PANEL_CA_FILE, directory / "panel.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=Bedolaga fixture", "-addext", f"subjectAltName=IP:{GATEWAY}",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True, timeout=20)
    cert.chmod(0o644)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    bot = document["services"]["bedolaga-bot"]
    bot["environment"].update(TELEGRAM_API_URL=f"http://{GATEWAY}:18090", VERSION_CHECK_ENABLED="false",
                              SSL_CERT_FILE=PANEL_CA_MOUNT, DATABASE_MODE="auto",
                              POSTGRES_DB=BOT_DATABASE, POSTGRES_USER=BOT_DATABASE_ROLE)
    bot["volumes"].append({"type": "bind", "source": str(cert), "target": PANEL_CA_MOUNT, "read_only": True,
                           "bind": {"create_host_path": False}})
    source = directory / "bedolaga.json"
    source.touch(mode=0o600)
    source.write_text(json.dumps(document), encoding="utf-8")
    args = ("compose", "--project-name", PROJECT, "--file", str(source))
    stack.callback(docker, *args, "down", "--volumes")
    docker(*args, "create", "--pull", "never", "--no-build", timeout=90)
    serve(stack, GATEWAY, 443, PanelHTTPS, tls=tls)
    serve(stack, GATEWAY, 18090, Telegram)
    docker(*args, "up", "--wait", "--wait-timeout", "220", "--pull", "never", "--no-build", timeout=250)
    hashes = dict(row.split() for row in docker(*args, "config", "--hash=*").splitlines())
    return {"version": 1, "id": BEDOLAGA_ID, "project": PROJECT, "compose_files": [str(source)],
            "extra_files": [str(cabinet_config), str(cert)], "service_hashes": hashes}


def check_cabinet(bot_ip, cabinet_ip):
    home = http(cabinet_ip, 80, "/")
    assert home[0] == 200 and b"<html" in home[1].lower()
    status, body = http(cabinet_ip, 80, "/api/health")
    assert status == 200 and json.loads(body)["status"] == "ok"
    direct = http(bot_ip, 8080, "/cabinet/auth/me")
    via_cabinet = http(cabinet_ip, 80, "/api/cabinet/auth/me")
    assert direct[0] in (401, 403)
    assert via_cabinet[0] == direct[0] and json.loads(via_cabinet[1]) == json.loads(direct[1])


def squad_query(squad_id):
    return f"SELECT count(*) FROM server_squads WHERE squad_uuid = '{squad_id}'"


def check_squad(primary, squad_id):
    deadline = time.monotonic() + 15
    while query(primary, BOT_DATABASE, BOT_DATABASE_ROLE, squad_query(squad_id)) != "1":
        if time.monotonic() >= deadline:
            raise RuntimeError("Bedolaga did not retain the squad fetched from the authenticated Panel API")
        time.sleep(1)


def acceptance():
    if os.path.lexists(ROOT):
        raise RuntimeError("Disposable app namespace must be absent")
    images = json.loads((Path(__file__).resolve().parents[2] / "vpn_orbit/application-images.json").read_text())["images"]
    docker = Docker()
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vo-bedolaga-", dir="/var/lib")))
        private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="vo-bedolaga-backup-", dir="/run")))
        for role in ("remnawave-panel", "bedolaga-bot", "bedolaga-cabinet", "postgres", "redis"):
            docker("pull", "--platform", "linux/amd64", images[role], timeout=300)
        start_external(stack, docker, directory, "fixture-panel", PANEL_ID, "remnawave-panel",
                       {name: images[name] for name in ("remnawave-panel", "postgres", "redis")},
                       {"database_password": secrets.token_hex(32), "app_secret": secrets.token_hex(32),
                        "metrics_password": secrets.token_hex(32), "domain": "panel.test.invalid",
                        "subscription_domain": "sub.test.invalid"})
        admin = panel_api("auth/register", body={"username": "fixture-admin",
                                                 "password": "Va9-" + secrets.token_urlsafe(32)})["accessToken"]
        setup_token = panel_api("tokens", token=admin, admin=True, body={
            "name": "Fixture setup", "expiresInDays": 1, "scopes": ["internal-squads:create"],
        })["token"]
        panel_token = panel_api("tokens", token=admin, admin=True, body={
            "name": "Fixture Bedolaga", "expiresInDays": 1, "scopes": ["internal-squads:list"],
        })["token"]
        squad = identifier(panel_api("internal-squads", token=setup_token,
                                     body={"name": "Orbit Bedolaga Fixture", "inbounds": []}))
        layout = create_bedolaga(stack, docker, directory, images, panel_token)
        staged = ExternalLifecycle.stage(layout)
        runtime = ExternalLifecycle(BEDOLAGA_ID)
        before = runtime.capture(layout)
        assert before["dependencies"]["bedolaga-bot"] == ["bot-db", "bot-redis"]
        assert before["dependencies"]["bedolaga-cabinet"] == ["bedolaga-bot"]
        bot_ip = project_address(docker, "bedolaga-bot")
        cabinet_ip = project_address(docker, "bedolaga-cabinet")
        primary = before["containers"]["bot-db"]["Id"]
        check_squad(primary, squad)
        check_cabinet(bot_ip, cabinet_ip)
        print("PASS real Bedolaga imports a Panel squad via TLS and preserves the Cabinet API authentication boundary.", flush=True)

        identity, recipient = backup_key(private)
        archive = private / "bedolaga.age"
        require_unregistered(runtime, "bot-db", staged["spec_digest"], archive, recipient)
        binding = register(layout, runtime, staged)
        assert runtime.capture(layout) == before
        check_squad(primary, squad)
        check_cabinet(bot_ip, cabinet_ip)

        query(primary, BOT_DATABASE, BOT_DATABASE_ROLE,
              "CREATE TABLE orbit_backup_fixture(value text); INSERT INTO orbit_backup_fixture VALUES('captured')")
        sha256 = capture_archive(runtime, "bot-db", binding, archive, recipient)
        query(primary, BOT_DATABASE, BOT_DATABASE_ROLE, "UPDATE orbit_backup_fixture SET value='live'")
        recovery = restore_isolated(stack, docker, private, archive, identity, sha256, {
            "source": "adopted", "registration": BEDOLAGA_ID, "spec_sha256": binding, "service": "bot-db",
            "database": BOT_DATABASE, "role": BOT_DATABASE_ROLE, "image": images["postgres"],
        })
        assert query(recovery, "orbit", "postgres", squad_query(squad)) == "1"
        assert query(recovery, "orbit", "postgres", "SELECT value FROM orbit_backup_fixture") == "captured"
        assert query(primary, BOT_DATABASE, BOT_DATABASE_ROLE, "SELECT value FROM orbit_backup_fixture") == "live"
        print("PASS the encrypted backup restored the imported Panel squad and data in a separate PostgreSQL.", flush=True)

        detach(runtime, layout, binding)
        assert runtime.capture(layout) == before
        require_unregistered(runtime, "bot-db", binding, private / "detached.age", recipient)
        check_squad(primary, squad)
        check_cabinet(bot_ip, cabinet_ip)
        print("PASS adoption and detachment preserve the Bedolaga routes, squad data, containers, network, and volumes.",
              flush=True)


if __name__ == "__main__":
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        acceptance()
    except Exception as error:
        sites = ",".join(f"{Path(frame.filename).name}:{frame.lineno}" for frame in traceback.extract_tb(error.__traceback__))
        code = error.code if isinstance(error, Denied) else type(error).__name__
        print(f"Bedolaga acceptance diagnostic {code} at {sites}", flush=True)
        raise SystemExit("Bedolaga product acceptance failed") from None
