import unittest

from vpn_orbit.runtime.nginx_inventory import inspect_config


class NginxInventoryTests(unittest.TestCase):
    def test_lists_only_literal_names_from_http_server_blocks(self):
        report = inspect_config(rb'''
            # server { server_name comment.example; }
            http {
                include /etc/nginx/sites-enabled/*;
                server {
                    listen 443 ssl;
                    server_name "Panel.Example." panel.example *.example '~^.*\.example$' $hostname;
                    proxy_set_header Authorization "private-canary; # {}";
                    location / { set $tag ${route}; }
                }
                server { server_name cabinet.example; }
            }
            stream { server { listen 443; server_name stream.example; } }
        ''')
        self.assertEqual(report, {"scope": "SUPPLIED_CONFIG", "includes_unread": True, "servers": [
            {"names": ["panel.example"], "other_names": True},
            {"names": ["cabinet.example"], "other_names": False},
        ]})

    def test_requires_explicit_http_context_for_standalone_fragment(self):
        fragment = b"server { server_name 192.0.2.4 site.example; include extra.conf; }"
        self.assertEqual(inspect_config(fragment)["servers"], [])
        self.assertEqual(inspect_config(fragment, http_fragment=True), {
            "scope": "SUPPLIED_CONFIG", "includes_unread": True,
            "servers": [{"names": ["site.example"], "other_names": True}],
        })

    def test_rejects_partial_and_oversized_inputs(self):
        for config in (b'http { server { server_name "unterminated;',
                       b"http { server { server_name site.example; }",
                       b"x" * (1024 * 1024 + 1)):
            with self.subTest(length=len(config)), self.assertRaises(ValueError):
                inspect_config(config)
