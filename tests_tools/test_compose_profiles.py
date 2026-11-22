from pathlib import Path
import tempfile
import unittest

from tools.compose_profiles import load_catalog, load_selection, render


class ComposeProfileTests(unittest.TestCase):
    def test_catalog_is_typed_and_has_four_roles(self):
        catalog = load_catalog(Path(__file__).parents[1] / "deploy/compose-profiles.example.json")
        self.assertEqual(set(catalog["profiles"]), {"remnawave-panel", "remnawave-node", "bedolaga-bot", "bedolaga-cabinet"})

    def test_service_requires_digest_and_applies_security_defaults(self):
        profile = load_catalog(Path(__file__).parents[1] / "deploy/compose-profiles.example.json")["profiles"]["remnawave-panel"]
        image = "registry.example.invalid/remnawave/panel@sha256:" + "a" * 64
        result = render({"profiles": {"remnawave-panel": profile}}, {
            "remnawave-panel": {
                "image": image, "environment": {"PANEL_CONFIG": "/run/config"},
                "volumes": {"panel-data": "/var/lib/vpn-orbit/apps/remnawave-panel/panel-data"},
            },
        })
        service = result["services"]["remnawave-panel"]
        self.assertTrue(service["read_only"])
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertEqual(service["ports"][0]["host_ip"], "127.0.0.1")
        self.assertFalse(result["networks"]["vpn-orbit-remnawave"]["internal"])

    def test_networkless_node_and_explicit_service_dependencies(self):
        catalog = load_catalog(Path(__file__).parents[1] / "deploy/compose-profiles.example.json")
        image = "registry.example.invalid/remnawave/node@sha256:" + "b" * 64
        node = render(catalog, {"remnawave-node": {"image": image}})["services"]["remnawave-node"]
        self.assertEqual(node["network_mode"], "none")
        bot_image = "registry.example.invalid/bedolaga/bot@sha256:" + "c" * 64
        cabinet_image = "registry.example.invalid/bedolaga/cabinet@sha256:" + "d" * 64
        pair = render(catalog, {
            "bedolaga-bot": {"image": bot_image},
            "bedolaga-cabinet": {"image": cabinet_image},
        })
        self.assertEqual(pair["services"]["bedolaga-bot"]["depends_on"],
                         {"bedolaga-cabinet": {"condition": "service_healthy"}})
        self.assertEqual(pair["services"]["bedolaga-bot"]["networks"],
                         pair["services"]["bedolaga-cabinet"]["networks"])
        self.assertIn(pair["services"]["bedolaga-bot"]["networks"][0], pair["networks"])

    def test_selection_file_renders_all_declared_profiles(self):
        catalog_path = Path(__file__).parents[1] / "deploy/compose-profiles.example.json"
        selection_path = Path(__file__).parents[1] / "deploy/compose-profiles.selection.example.json"
        rendered = load_selection(selection_path, load_catalog(catalog_path))
        self.assertEqual(set(rendered["services"]), {"remnawave-panel", "remnawave-node", "bedolaga-bot", "bedolaga-cabinet"})
        self.assertEqual(rendered["services"]["remnawave-node"]["network_mode"], "none")

    def test_unknown_environment_volume_and_tagged_image_are_rejected(self):
        profile = load_catalog(Path(__file__).parents[1] / "deploy/compose-profiles.example.json")["profiles"]["remnawave-panel"]
        with self.assertRaisesRegex(ValueError, "COMPOSE_IMAGE_DIGEST_REQUIRED"):
            render({"profiles": {"remnawave-panel": profile}},
                   {"remnawave-panel": {"image": "registry.example.invalid/panel:latest"}})
        image = "registry.example.invalid/panel@sha256:" + "a" * 64
        with self.assertRaisesRegex(ValueError, "COMPOSE_ENV_NOT_ALLOWLISTED"):
            render({"profiles": {"remnawave-panel": profile}},
                   {"remnawave-panel": {"image": image, "environment": {"SECRET": "x"}}})
        with self.assertRaisesRegex(ValueError, "COMPOSE_VOLUME_PATH_INVALID"):
            render({"profiles": {"remnawave-panel": profile}},
                   {"remnawave-panel": {"image": image, "volumes": {"panel-data": "/"}}})
        with self.assertRaisesRegex(ValueError, "COMPOSE_VOLUME_PATH_INVALID"):
            render({"profiles": {"remnawave-panel": profile}},
                   {"remnawave-panel": {"image": image, "volumes": {"panel-data": "/etc"}}})
