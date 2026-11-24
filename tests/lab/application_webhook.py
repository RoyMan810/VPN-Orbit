"""Exercise Bedolaga's actual webhook receiver in a networkless container."""

import json
import os
from pathlib import Path
import secrets
import subprocess


REPOSITORY = Path(__file__).resolve().parents[2]
SCENARIO = """
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.webserver.telegram import create_telegram_router

received = []


class Processor:
    async def enqueue(self, update):
        received.append(update.update_id)


app = FastAPI()
app.include_router(create_telegram_router(None, None, processor=Processor()))
with TestClient(app) as client:
    health = client.get("/health/telegram-webhook")
    assert health.status_code == 200 and health.json()["mode"] == "webhook"
    header = "X-Telegram-Bot-Api-Secret-Token"
    update = {"update_id": 123}
    assert client.post("/webhook", json=update).status_code == 401
    assert client.post("/webhook", json=update, headers={header: "wrong"}).status_code == 401
    headers = {header: os.environ["WEBHOOK_SECRET_TOKEN"]}
    assert client.post("/webhook", json={}, headers=headers).status_code == 400
    assert received == []
    assert client.post("/webhook", json=update, headers=headers).status_code == 200
    assert received == [123]
"""


def webhook_acceptance():
    pins = json.loads((REPOSITORY / "deploy/application-images.json").read_text())["images"]
    image = pins["bedolaga-bot"]
    subprocess.run(["/usr/bin/docker", "pull", "--platform", "linux/amd64", image],
                   check=True, timeout=240)
    env = {
        "BOT_TOKEN": "123456:" + "t" * 40,
        "BOT_RUN_MODE": "webhook",
        "WEBHOOK_URL": "https://bot.fixture.invalid",
        "WEBHOOK_PATH": "/webhook",
        "WEBHOOK_SECRET_TOKEN": secrets.token_hex(32),
        "DATABASE_MODE": "sqlite",
        "SQLITE_PATH": "/tmp/fixture.db",
        "LOG_FILE": "/tmp/fixture.log",
    }
    options = [arg for key, value in env.items() for arg in ("--env", f"{key}={value}")]
    subprocess.run(["/usr/bin/docker", "run", "--rm", "--pull=never", "--network=none",
                    "--read-only", "--tmpfs", "/tmp", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges:true", *options, "--entrypoint", "python",
                    image, "-c", SCENARIO], check=True, timeout=30)
    print("PASS pinned Bedolaga webhook receiver, secret checks and update handoff.")


if __name__ == "__main__":
    if os.geteuid() != 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    webhook_acceptance()
