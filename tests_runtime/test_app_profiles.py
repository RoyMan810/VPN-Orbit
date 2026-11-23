import copy
from datetime import UTC, datetime, timedelta
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vpn_orbit.app_profiles import PANEL_CA_FILE, PANEL_CA_MOUNT, PROFILES, REPOSITORIES, digest, managed_files, render


def specification():
    return {
        "v": 1, "id": "01JCYQZ4T9V8MNVYEH3D2M7Q1A", "profiles": list(PROFILES),
        "images": {name: repos[0] + "@sha256:" + "a" * 64 for name, repos in REPOSITORIES.items()},
        "settings": {
            "remnawave-panel": {"database_password": "b" * 40, "app_secret": "s" * 64, "metrics_password": "m" * 64,
                               "domain": "panel.test.invalid", "subscription_domain": "sub.test.invalid"},
            "remnawave-node": {"secret_key": "n" * 64, "port": 2222},
            "bedolaga-bot": {"database_password": "c" * 40, "bot_token": "123456:" + "t" * 40,
                             "admin_ids": "123456", "panel_api_key": "k" * 64,
                             "panel_url": "https://panel.test.invalid", "api_token": "a" * 64, "jwt_secret": "j" * 64},
            "bedolaga-cabinet": {},
        },
    }


class AppProfilesTests(unittest.TestCase):
    def test_node_only_profile_does_not_require_an_unused_bridge(self):
        spec = specification()
        spec["profiles"] = ["remnawave-node"]
        spec["images"] = {"remnawave-node": spec["images"]["remnawave-node"]}
        spec["settings"] = {"remnawave-node": spec["settings"]["remnawave-node"]}
        self.assertEqual(render(spec, "b" * 64)["networks"], {})

    def test_real_service_layout_and_dependencies_are_fixed(self):
        spec = specification()
        rendered = render(spec, "b" * 64)
        services = rendered["services"]
        self.assertEqual(len(services), 8)
        self.assertEqual(services["remnawave-node"]["network_mode"], "host")
        self.assertIn("NET_ADMIN", services["remnawave-node"]["cap_add"])
        self.assertNotIn("networks", services["remnawave-node"])
        self.assertEqual(set(services["bedolaga-bot"]["depends_on"]), {"bot-db", "bot-redis"})
        self.assertEqual(set(services["remnawave-panel"]["depends_on"]), {"panel-db", "panel-redis"})
        for name, service in services.items():
            self.assertEqual(service["labels"]["com.vpn-orbit.spec"], digest(spec))
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("privileged", service)
            self.assertNotIn("build", service)
            for port in service.get("ports", []):
                self.assertEqual(port["host_ip"], "127.0.0.1")
            for mount in service.get("volumes", []):
                if mount["type"] == "bind":
                    self.assertEqual(name, "bedolaga-cabinet")
                    self.assertEqual(mount["source"], f"/var/lib/vpn-orbit-apps/{spec['id']}/cabinet.conf")
                    self.assertTrue(mount["read_only"])
        self.assertIn("proxy_pass http://bedolaga-bot:8080/;", managed_files(spec)["cabinet.conf"])
        self.assertIn("http://127.0.0.1:80/api/health", services["bedolaga-cabinet"]["healthcheck"]["test"])

    def test_unknown_inputs_cannot_expand_commands_images_mounts_or_capabilities(self):
        for key, value in (("command", "id"), ("volumes", ["/:/host"]), ("cap_add", ["SYS_ADMIN"])):
            changed = specification()
            changed[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "APP_SPEC_INVALID"):
                render(changed, "b" * 64)
        for image in ("remnawave/node:latest", "docker.io/attacker/node@sha256:" + "a" * 64):
            changed = specification()
            changed["images"]["remnawave-node"] = image
            with self.subTest(image=image), self.assertRaisesRegex(ValueError, "APP_IMAGE_PIN_REQUIRED"):
                render(changed, "b" * 64)

    def test_secrets_are_literal_and_dependencies_cannot_be_omitted(self):
        changed = specification()
        changed["settings"]["remnawave-panel"]["app_secret"] = "$DOLLAR" * 10
        panel = render(changed, "b" * 64)["services"]["remnawave-panel"]
        self.assertEqual(panel["environment"]["APP_SECRET"], "$$DOLLAR" * 10)
        changed = copy.deepcopy(specification())
        changed["profiles"].remove("bedolaga-bot")
        with self.assertRaisesRegex(ValueError, "APP_DEPENDENCY_MISSING"):
            render(changed, "b" * 64)

    def test_bot_and_cabinet_can_use_a_separately_prepared_panel(self):
        spec = specification()
        for item in ("remnawave-panel", "remnawave-node"):
            spec["profiles"].remove(item)
            del spec["settings"][item], spec["images"][item]
        self.assertEqual(set(render(spec, "b" * 64)["services"]),
                         {"bot-db", "bot-redis", "bedolaga-bot", "bedolaga-cabinet"})

    def test_bot_refuses_panel_hosts_that_disable_upstream_certificate_verification(self):
        for host in ("api", "remnawave", "localhost", "127.0.0.1", "10.1.2.3", "172.16.1.1",
                     "192.168.1.1", "panel.local"):
            spec = specification()
            spec["settings"]["bedolaga-bot"]["panel_url"] = "https://" + host
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "APP_PANEL_TLS_REQUIRED"):
                render(spec, "b" * 64)

    def test_bot_mounts_only_a_ca_certificate_from_the_bound_spec(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "VPN-Orbit test CA")])
        now = datetime.now(UTC)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now)
                   .not_valid_after(now + timedelta(days=1)))
        spec = specification()
        for is_ca in (False, True):
            cert = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
            pem = cert.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
            spec["settings"]["bedolaga-bot"]["panel_ca_pem"] = pem
            if not is_ca:
                with self.assertRaisesRegex(ValueError, "APP_PANEL_CA_INVALID"):
                    render(spec, "b" * 64)
                continue
            bot = render(spec, "b" * 64)["services"]["bedolaga-bot"]
            self.assertEqual(bot["environment"]["SSL_CERT_FILE"], PANEL_CA_MOUNT)
            self.assertFalse(any(PANEL_CA_MOUNT.startswith(mount.split(":", 1)[0] + "/")
                                 for mount in bot["tmpfs"]))
            self.assertEqual(bot["volumes"][-1], {"type": "bind",
                "source": f"/var/lib/vpn-orbit-apps/{spec['id']}/{PANEL_CA_FILE}",
                "target": PANEL_CA_MOUNT, "read_only": True, "bind": {"create_host_path": False}})
            self.assertEqual(managed_files(spec)[PANEL_CA_FILE], pem)

    def test_bot_uses_upstream_async_database_settings(self):
        spec = specification()
        services = render(spec, "b" * 64)["services"]
        env = services["bedolaga-bot"]["environment"]
        self.assertNotIn("DATABASE_URL", env)
        self.assertEqual(env["DATABASE_MODE"], "postgresql")
        self.assertEqual(env["POSTGRES_HOST"], "bot-db")
        self.assertEqual(env["POSTGRES_PASSWORD"], services["bot-db"]["environment"]["POSTGRES_PASSWORD"])
        self.assertEqual(env["REDIS_URL"], "redis://bot-redis:6379/0")

    def test_invalid_settings_fail_without_echoing_the_value(self):
        for profile, key, value in (("remnawave-node", "port", 22),
                                    ("remnawave-panel", "database_password", "secret;$"),
                                    ("remnawave-panel", "domain", "host\ncommand"),
                                    ("bedolaga-bot", "bot_token", "invalid-token")):
            spec = specification()
            spec["settings"][profile][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "^APP_[A-Z_]+$"):
                render(spec, "b" * 64)
