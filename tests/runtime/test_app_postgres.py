"""The adopted Panel's connection string cannot override the local dump target."""

import unittest
from unittest.mock import patch

from vpn_orbit.app_postgres import local_postgres, panel_database, postgres_identity
from vpn_orbit.errors import Denied


class AdoptedPostgresTests(unittest.TestCase):
    def test_extracts_endpoint_and_decodes_password_for_the_tcp_check(self):
        self.assertEqual(panel_database("postgresql://postgres:secret%40value@db:5432/postgres"),
                         ("postgres", "postgres", "db", "secret@value"))
        self.assertEqual(panel_database("postgres://backup@db/my_db"), ("my_db", "backup", "db", ""))

    def test_refuses_ambiguous_connection_strings(self):
        for url in (
            "postgresql://db/postgres",
            "postgresql://postgres@db:5433/postgres",
            "postgresql://postgres@db/postgres?host=elsewhere",
            "postgresql://postgres@db/postgres#fragment",
            "postgresql://post%67res@db/postgres",
            "postgresql://postgres:bad%0Avalue@db/postgres",
            "postgresql://postgres:bad%00value@db/postgres",
            "postgresql://postgres:bad%FFvalue@db/postgres",
            "postgresql://postgres@db/%70ostgres",
            "postgresql://postgres@db/postgres/other",
            "postgresql://postgres@db/other\n",
            "postgresql://postgres@db/not-supported",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(Denied, "APP_POSTGRES_SOURCE_UNVERIFIED"):
                panel_database(url)

    def test_postgres_command_uses_the_container_local_socket(self):
        command = local_postgres("pg_dump", "panel_data", "panel_role")
        self.assertEqual(command, (
            "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "PGPASSFILE=/dev/null", "pg_dump",
            "--host=/var/run/postgresql", "--port=5432", "--no-password",
            "--username=panel_role", "--dbname=panel_data",
        ))

    @patch("vpn_orbit.app_postgres.docker")
    def test_tcp_probe_authenticates_via_stdin_and_matches_the_socket(self, docker):
        docker.return_value = b"postgres|postgres|42|128\n"
        self.assertEqual(postgres_identity("container", "postgres", "postgres", "172.20.0.2", "secret"),
                         ["42", "128"])
        local, tcp = docker.call_args_list
        self.assertIn("--host=/var/run/postgresql", local.args)
        self.assertIn("--host=172.20.0.2", tcp.args)
        self.assertNotIn("secret", tcp.args)
        self.assertEqual(tcp.kwargs["input_data"], b"secret\n")

    @patch("vpn_orbit.app_postgres.docker", side_effect=(b"postgres|postgres|42|128\n",
                                                        b"postgres|postgres|42|129\n"))
    def test_rejects_a_tcp_endpoint_served_by_a_different_cluster(self, docker):
        with self.assertRaisesRegex(Denied, "APP_POSTGRES_SOURCE_UNVERIFIED"):
            postgres_identity("container", "postgres", "postgres", "172.20.0.2", "secret")
