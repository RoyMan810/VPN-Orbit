import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.nginx_inventory import inspect_config
from vpn_orbit.runtime.protocol import nginx_summary


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


    def test_scoped_observation_reads_protected_files_and_excludes_raw_configuration(self):
        runtime = Path(__file__).resolve().parents[2] / "vpn_orbit/runtime"
        helper = runpy.run_path(str(runtime / "vps_helpers/typed-helper"))
        observe = helper["observe_nginx"]
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        nginx = root / "nginx"
        nginx.mkdir(mode=0o755)
        (nginx / "conf.d").mkdir(mode=0o755)
        (nginx / "nginx.conf").write_text("http { include conf.d/*.conf; }")
        fragment = nginx / "conf.d/site.conf"
        fragment.write_text("server { server_name panel.example; proxy_set_header Key private-canary; }")
        scope = root / "inventory.files"
        stat_fd = os.fstat

        def root_metadata(fd):
            metadata = stat_fd(fd)
            return SimpleNamespace(st_uid=0, st_mode=metadata.st_mode, st_nlink=metadata.st_nlink)

        with patch.object(os, "fstat", side_effect=root_metadata), patch.dict(
            observe.__globals__, {"__file__": str(runtime / "typed-helper")},
        ):
            self.assertEqual(observe(scope, nginx)["status"], "NOT_CONFIGURED")
            scope.write_text("nginx.conf\nconf.d/site.conf\n")
            scope.chmod(0o600)
            self.assertEqual(nginx_summary(observe(scope, nginx)), {
                "status": "OBSERVED", "names": ["panel.example"], "partial": True,
            })
            fragment.chmod(0o666)
            self.assertEqual(observe(scope, nginx)["status"], "UNAVAILABLE")
            fragment.unlink()
            fragment.symlink_to(nginx / "nginx.conf")
            self.assertEqual(observe(scope, nginx)["status"], "UNAVAILABLE")
            scope.write_text("conf.d/../nginx.conf\n")
            self.assertEqual(observe(scope, nginx)["status"], "POLICY_INVALID")

        with self.assertRaises(Denied):
            nginx_summary({"status": "OBSERVED", "names": ["secret://panel.example"], "partial": False})
