"""Fixed product Compose profiles. Inputs are protected administrator configuration."""

import hashlib
import json
import re
from urllib.parse import urlsplit

from cryptography import x509


PROFILES = ("remnawave-panel", "remnawave-node", "bedolaga-bot", "bedolaga-cabinet")
REPOSITORIES = {
    "remnawave-panel": ("docker.io/remnawave/backend",),
    "remnawave-node": ("docker.io/remnawave/node",),
    "bedolaga-bot": ("ghcr.io/bedolaga-dev/remnawave-bedolaga-telegram-bot",
                     "docker.io/fr1ngg/remnawave-bedolaga-telegram-bot"),
    "bedolaga-cabinet": ("ghcr.io/bedolaga-dev/bedolaga-cabinet",),
    "postgres": ("docker.io/library/postgres",),
    "redis": ("docker.io/library/redis",),
}
DEPENDENCIES = {
    "remnawave-panel": ("panel-db", "panel-redis"),
    "remnawave-node": (),
    "bedolaga-bot": ("bot-db", "bot-redis"),
    "bedolaga-cabinet": ("bedolaga-bot",),
}
SETTING_KEYS = {
    "remnawave-panel": {"database_password", "app_secret", "metrics_password", "domain", "subscription_domain"},
    "remnawave-node": {"secret_key", "port"},
    "bedolaga-bot": {"database_password", "bot_token", "admin_ids", "panel_url", "panel_api_key", "api_token", "jwt_secret"},
    "bedolaga-cabinet": set(),
}
PANEL_CA_FILE = "panel-ca.pem"
PANEL_CA_MOUNT = "/app/vpn-orbit-panel-ca.pem"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def error(code):
    raise ValueError(code)


def secret(value, *, minimum=32, maximum=16384):
    if (not isinstance(value, str) or not minimum <= len(value) <= maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        error("APP_SECRET_INVALID")
    return value


def hostname(value):
    if (not isinstance(value, str) or len(value) > 253
            or re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9-]+)*", value) is None):
        error("APP_DOMAIN_INVALID")
    return value


def panel_origin(value):
    if not isinstance(value, str) or len(value) > 260 or re.fullmatch(r"https://[a-z0-9.-]+", value) is None:
        error("APP_PANEL_URL_INVALID")
    host = hostname(urlsplit(value).hostname)
    # These hosts put the pinned Bot's Remnawave client into a mode that
    # disables certificate verification even when the URL uses HTTPS.
    if ("." not in host or host == "127.0.0.1" or host.startswith(("10.", "172.", "192.168."))
            or host.endswith(".local")):
        error("APP_PANEL_TLS_REQUIRED")


def panel_ca(value):
    pattern = r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?"
    if not isinstance(value, str) or len(value) > 8192 or re.fullmatch(pattern, value) is None:
        error("APP_PANEL_CA_INVALID")
    try:
        certificate = x509.load_pem_x509_certificate(value.encode("ascii"))
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except (ValueError, x509.ExtensionNotFound):
        error("APP_PANEL_CA_INVALID")
    if not is_ca:
        error("APP_PANEL_CA_INVALID")


def validate(spec):
    if (not isinstance(spec, dict) or set(spec) != {"v", "id", "profiles", "images", "settings"}
            or type(spec["v"]) is not int or spec["v"] != 1
            or not isinstance(spec["id"], str) or re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", spec["id"]) is None):
        error("APP_SPEC_INVALID")
    profiles = spec["profiles"]
    if (not isinstance(profiles, list) or not profiles or any(not isinstance(name, str) or name not in PROFILES for name in profiles)
            or len(set(profiles)) != len(profiles)):
        error("APP_PROFILE_INVALID")
    if "bedolaga-cabinet" in profiles and "bedolaga-bot" not in profiles:
        error("APP_DEPENDENCY_MISSING")
    images, settings = spec["images"], spec["settings"]
    needed = set(profiles) | ({"postgres", "redis"} if set(profiles) & {"remnawave-panel", "bedolaga-bot"} else set())
    if not isinstance(images, dict) or set(images) != needed:
        error("APP_IMAGES_INVALID")
    for name, image in images.items():
        if (not isinstance(image, str) or not any(re.fullmatch(re.escape(repo) + r"@sha256:[0-9a-f]{64}", image)
                                                 for repo in REPOSITORIES[name])):
            error("APP_IMAGE_PIN_REQUIRED")
    if not isinstance(settings, dict) or set(settings) != set(profiles):
        error("APP_SETTINGS_INVALID")
    for name, values in settings.items():
        optional = {"panel_ca_pem"} if name == "bedolaga-bot" else set()
        if not isinstance(values, dict) or not SETTING_KEYS[name] <= values.keys() <= SETTING_KEYS[name] | optional:
            error("APP_SETTINGS_INVALID")
        for key, value in values.items():
            if key in ("domain", "subscription_domain"):
                hostname(value)
            elif key == "panel_url":
                panel_origin(value)
            elif key == "panel_ca_pem":
                panel_ca(value)
            elif key == "port":
                if type(value) is not int or not 1024 <= value <= 65535 or value in (18080, 18443):
                    error("APP_NODE_PORT_INVALID")
            elif key == "admin_ids":
                if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,19}(?:,[1-9][0-9]{0,19}){0,15}", value) is None:
                    error("APP_ADMIN_IDS_INVALID")
            elif key == "bot_token":
                if not isinstance(value, str) or re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,128}", value) is None:
                    error("APP_BOT_TOKEN_INVALID")
            else:
                secret(value)
        if "database_password" in values and re.fullmatch(r"[a-zA-Z0-9_-]{32,128}", values["database_password"]) is None:
            error("APP_DATABASE_PASSWORD_INVALID")
    return spec


def render(spec, owner):
    """Render only fixed services, commands, mount targets and capability bounds.

    The owner token is created by the durable executor before Docker effects.
    All values are literal; Compose variable expansion is escaped.
    """
    validate(spec)
    if not isinstance(owner, str) or re.fullmatch(r"[0-9a-f]{64}", owner) is None:
        error("APP_OWNER_INVALID")
    config_digest = digest(spec)
    project = "vo-app-" + spec["id"].lower()
    labels = {"com.vpn-orbit.installation": spec["id"], "com.vpn-orbit.owner": owner,
              "com.vpn-orbit.spec": config_digest}
    services, volumes = {}, {}

    def volume(name, destination):
        volumes[name] = {"name": project + "-" + name, "labels": labels, "driver": "local"}
        return {"type": "volume", "source": name, "target": destination}

    def health(command):
        return {"test": ["CMD", *command], "interval": "5s", "timeout": "4s", "retries": 24, "start_period": "30s"}

    def service(name, image, env=None):
        services[name] = {
            "image": spec["images"][image], "pull_policy": "never", "restart": "unless-stopped",
            "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "labels": {**labels, "com.vpn-orbit.service": name},
            "networks": ["apps"], "environment": env or {}, "tmpfs": ["/tmp", "/run"],
            "logging": {"driver": "local", "options": {"max-size": "10m", "max-file": "3"}},
        }
        return services[name]

    def database(prefix, password):
        db = service(prefix + "-db", "postgres",
                     {"POSTGRES_USER": "orbit", "POSTGRES_DB": "orbit", "POSTGRES_PASSWORD": password, "TZ": "UTC"})
        db["volumes"] = [volume(prefix + "-db", "/var/lib/postgresql")]
        db["cap_add"] = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]
        db["healthcheck"] = health(["pg_isready", "-U", "orbit", "-d", "orbit"])
        redis = service(prefix + "-redis", "redis")
        redis["user"] = "999:999"
        redis["command"] = ["redis-server", "--appendonly", "yes", "--maxmemory", "128mb", "--maxmemory-policy", "noeviction"]
        redis["volumes"] = [volume(prefix + "-redis", "/data")]
        redis["healthcheck"] = health(["redis-cli", "ping"])
        return {"DATABASE_URL": f"postgresql://orbit:{password}@{prefix}-db:5432/orbit",
                "REDIS_HOST": prefix + "-redis", "REDIS_PORT": "6379"}

    for name in spec["profiles"]:
        values = spec["settings"][name]
        if name == "remnawave-panel":
            env = database("panel", values["database_password"])
            env.update(APP_SECRET=values["app_secret"], PANEL_DOMAIN=values["domain"],
                       FRONT_END_DOMAIN="https://" + values["domain"], SUB_PUBLIC_DOMAIN=values["subscription_domain"],
                       APP_PORT="3000", METRICS_PORT="3001", API_INSTANCES="1",
                       METRICS_USER="orbit", METRICS_PASS=values["metrics_password"],
                       PM2_HOME="/tmp/pm2", IS_TELEGRAM_NOTIFICATIONS_ENABLED="false")
            panel = service(name, name, env)
            panel["ports"] = [{"target": 3000, "published": "3000", "host_ip": "127.0.0.1"}]
            panel["healthcheck"] = health(["curl", "--fail", "--silent", "http://127.0.0.1:3001/health"])
        elif name == "remnawave-node":
            node = service(name, name, {"NODE_PORT": str(values["port"]), "SECRET_KEY": values["secret_key"],
                                       "S6_READ_ONLY_ROOT": "1", "NFTABLES_TABLE_NAME": "vo_" + spec["id"].lower()})
            del node["networks"]
            node["network_mode"] = "host"
            node["cap_add"] = ["NET_ADMIN", "NET_BIND_SERVICE", "CHOWN", "SETGID", "SETUID", "KILL", "DAC_OVERRIDE", "FOWNER"]
            # s6-overlay executes its own pinned init binaries from this mount.
            node["tmpfs"] = ["/tmp", "/run:rw,exec,nosuid,nodev,mode=0755,size=64m", "/var/log/xray"]
            node["healthcheck"] = health(["node", "-e",
                f"const s=require('net').connect({values['port']},'127.0.0.1');s.on('connect',()=>{{s.end();process.exit(0)}});s.on('error',()=>process.exit(1))"])
        elif name == "bedolaga-bot":
            database("bot", values["database_password"])
            # Bedolaga builds its asyncpg URL from the PostgreSQL settings.
            env = dict(BOT_TOKEN=values["bot_token"], ADMIN_IDS=values["admin_ids"],
                       REMNAWAVE_API_URL=values["panel_url"], REMNAWAVE_API_KEY=values["panel_api_key"],
                       DATABASE_MODE="postgresql", POSTGRES_HOST="bot-db", POSTGRES_PORT="5432", POSTGRES_USER="orbit",
                       POSTGRES_DB="orbit", POSTGRES_PASSWORD=values["database_password"],
                       REDIS_URL="redis://bot-redis:6379/0", CABINET_ENABLED="true",
                       CABINET_JWT_SECRET=values["jwt_secret"], WEB_API_DEFAULT_TOKEN=values["api_token"],
                       WEB_API_ENABLED="true", WEB_API_HOST="0.0.0.0", WEB_API_PORT="8080",
                       DOCKER_ENV="true", PYTHONDONTWRITEBYTECODE="1")
            bot = service(name, name, env)
            bot["volumes"] = [volume("bot-data", "/app/data"), volume("bot-logs", "/app/logs"),
                              volume("bot-uploads", "/app/uploads")]
            if "panel_ca_pem" in values:
                env["SSL_CERT_FILE"] = PANEL_CA_MOUNT
                bot["volumes"].append({"type": "bind", "source": f"/var/lib/vpn-orbit-apps/{spec['id']}/{PANEL_CA_FILE}",
                                       "target": PANEL_CA_MOUNT, "read_only": True, "bind": {"create_host_path": False}})
            bot["ports"] = [{"target": 8080, "published": "8080", "host_ip": "127.0.0.1"}]
            bot["healthcheck"] = health(["python", "-c",
                "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)"])
        else:
            cabinet = service(name, name)
            # Upstream entrypoint brands index.html and prepares nginx config.
            # Its image filesystem is writable; no host filesystem is mounted.
            cabinet["read_only"] = False
            cabinet["cap_add"] = ["CHOWN", "SETGID", "SETUID", "NET_BIND_SERVICE"]
            cabinet["ports"] = [{"target": 80, "published": "3020", "host_ip": "127.0.0.1"}]
            cabinet["healthcheck"] = health(["wget", "--quiet", "-O", "/dev/null", "http://127.0.0.1:80/api/health"])
            cabinet["volumes"] = [{"type": "bind",
                                  "source": f"/var/lib/vpn-orbit-apps/{spec['id']}/cabinet.conf",
                                  "target": "/etc/nginx/conf.d/default.conf", "read_only": True,
                                  "bind": {"create_host_path": False}}]
        dependencies = DEPENDENCIES[name]
        if dependencies:
            services[name]["depends_on"] = {key: {"condition": "service_healthy"} for key in dependencies}
    # Separate product networks prevent the privileged host-network Node from
    # acquiring Docker socket access; no service receives a host bind mount.
    for item in services.values():
        item["environment"] = {key: value.replace("$", "$$") for key, value in item["environment"].items()}
    networks = {"apps": {"name": project + "-apps", "driver": "bridge", "labels": labels}}
    return {"name": project, "services": services, "volumes": volumes,
            "networks": networks if any("networks" in value for value in services.values()) else {}}


def managed_files(spec):
    validate(spec)
    files = {}
    if "panel_ca_pem" in spec["settings"].get("bedolaga-bot", {}):
        files[PANEL_CA_FILE] = spec["settings"]["bedolaga-bot"]["panel_ca_pem"]
    if "bedolaga-cabinet" not in spec["profiles"]:
        return files
    files["cabinet.conf"] = """server {
    listen 80;
    root /usr/share/nginx/html;
    location / { try_files $uri /index.html; }
    location /api/ {
        proxy_pass http://bedolaga-bot:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
"""
    return files
