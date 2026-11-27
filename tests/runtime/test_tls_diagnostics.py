from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import runpy
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.listener_diagnostics import main
from vpn_orbit.runtime.protocol import local_https_summary


class TlsDiagnosticsTests(unittest.TestCase):
    def test_checks_tls_identity_and_expiry_against_the_given_ip(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cert, key = directory / "server.pem", directory / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
             "-subj", "/CN=legacy.example", "-addext", "subjectAltName=DNS:site.example",
             "-out", cert, "-keyout", key], check=True, capture_output=True, timeout=10,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        names = []
        server_context.set_servername_callback(lambda _, name, __: names.append(name))

        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)

            def handshake(status):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(4)
                    try:
                        with server_context.wrap_socket(connection, server_side=True) as secured:
                            if status is not None:
                                with secured.makefile("rb") as request:
                                    self.assertEqual(request.readline(), b"HEAD /healthz HTTP/1.1\r\n")
                                    self.assertEqual(request.readline(), f"Host: site.example:{listener.getsockname()[1]}\r\n".encode())
                                    self.assertEqual(request.readline(), b"Connection: close\r\n")
                                    self.assertEqual(request.readline(), b"\r\n")
                                secured.sendall(f"HTTP/1.1 {status} Fixture\r\nLocation: https://other.example/\r\n\r\n".encode())
                            return True
                    except ssl.SSLError:
                        return False

            cases = (
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", None),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 204),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 302),
                ("site.example", {"SSL_CERT_FILE": str(cert)}, "VERIFIED", 503),
                ("legacy.example", {"SSL_CERT_FILE": str(cert)}, "CERTIFICATE_INVALID", 200),
                ("site.example", {}, "CERTIFICATE_INVALID", None),
            )
            for name, env, expected, status in cases:
                with self.subTest(name=name, state=expected, status=status):
                    future = executor.submit(handshake, status)
                    output = io.StringIO()
                    args = ["--connect", "127.0.0.1", "--port", str(listener.getsockname()[1]), "--tls-name", name]
                    if status is not None:
                        args.extend(["--https-path", "/healthz"])
                    with patch.dict(os.environ, env), redirect_stdout(output):
                        code = main(args)
                    report = json.loads(output.getvalue())
                    self.assertEqual(report["tcp_reachability"], "CONNECTED")
                    self.assertEqual(report["tls"]["state"], expected)
                    self.assertEqual(report["tls"]["server_name"], name)
                    self.assertEqual(future.result(timeout=5), expected == "VERIFIED")
                    self.assertEqual(code, int(expected != "VERIFIED" or status in (302, 503)))
                    if status is not None:
                        https = {"state": "RESPONDED", "status": status} if expected == "VERIFIED" else {"state": "NOT_TESTED"}
                        self.assertEqual(report["https"], https)
                    else:
                        self.assertNotIn("https", report)
                    if expected == "VERIFIED":
                        self.assertGreater(report["tls"]["expires_at"], time.time())
                    else:
                        self.assertNotIn("expires_at", report["tls"])
            future = executor.submit(handshake, None)
            output = io.StringIO()
            result = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))]
            with patch.object(socket, "getaddrinfo", return_value=result), patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}), \
                 redirect_stdout(output):
                code = main(["--check-site", "site.example", "--expect-ip", "127.0.0.1",
                             "--port", str(listener.getsockname()[1])])
            self.assertTrue(future.result(timeout=5))
            self.assertEqual(code, 0)
            site = json.loads(output.getvalue())
            self.assertEqual(site["dns"]["state"], "MATCH")
            self.assertEqual(site["endpoints"][0]["tls"]["state"], "VERIFIED")
            self.assertGreater(site["endpoints"][0]["tls"]["expires_at"], time.time())
        self.assertEqual(names, ["site.example"] * 4 + ["legacy.example", "site.example", "site.example"])

    def test_local_https_observation_requires_protected_names_and_checks_real_sni(self):
        helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote/typed-helper"))
        observe = helper["observe_local_https"]
        scope = observe.__globals__
        with patch.dict(scope, {"read_root_config": Mock(side_effect=FileNotFoundError)}):
            self.assertEqual(observe(), {"status": "NOT_CONFIGURED", "sites": []})
        for value in (b"127.0.0.1\n", b"https://site.example\n", b"site.example\nsite.example\n",
                      b"a.example\nb.example\nc.example\nd.example\ne.example\n"):
            with patch.dict(scope, {"read_root_config": lambda *_: value}), patch.object(socket, "socket") as transport:
                self.assertEqual(observe(), {"status": "POLICY_INVALID", "sites": []})
                transport.assert_not_called()

        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        cert, key = directory / "server.pem", directory / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
             "-subj", "/CN=legacy.example", "-addext", "subjectAltName=DNS:site.example",
             "-out", cert, "-keyout", key], check=True, capture_output=True, timeout=10,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)
            connect = socket.socket.connect
            def local_connect(sock, address):
                self.assertEqual(address, ("127.0.0.1", 443))
                return connect(sock, listener.getsockname())

            def serve():
                for _ in range(2):
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(4)
                        try:
                            with context.wrap_socket(connection, server_side=True) as secured:
                                self.assertEqual(secured.recv(1), b"")
                        except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
                            pass

            server = executor.submit(serve)
            with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}), patch.object(socket.socket, "connect", local_connect), \
                 patch.dict(scope, {"read_root_config": lambda *_: b"site.example\nlegacy.example\n"}):
                result = observe()
            server.result(timeout=5)
        self.assertEqual(local_https_summary(result), result)
        rejected, verified = result["sites"]
        self.assertEqual(rejected, {"name": "legacy.example", "state": "CERTIFICATE_INVALID", "expires_at": None})
        self.assertEqual((verified["name"], verified["state"]), ("site.example", "VERIFIED"))
        self.assertGreater(verified["expires_at"], time.time())
        for bad in ([verified, rejected], [verified, verified], [{**verified, "name": "127.0.0.1"}],
                    [{**verified, "expires_at": None}], [{**rejected, "expires_at": 1}]):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                local_https_summary({"status": "OBSERVED", "sites": bad})

    def test_tls_mode_keeps_tcp_refusal_separate(self):
        with socket.socket() as listener, redirect_stdout(io.StringIO()) as out:
            listener.bind(("127.0.0.1", 0))
            code = main(["--connect", "127.0.0.1", "--port", str(listener.getsockname()[1]),
                         "--tls-name", "site.example"])
        self.assertEqual(code, 1)
        report = json.loads(out.getvalue())
        self.assertEqual(report["tcp_reachability"], "REFUSED")
        self.assertEqual(report["tls"], {"state": "NOT_TESTED", "server_name": "site.example"})

    def test_invalid_tls_arguments_are_rejected_before_network_io(self):
        for args in (["--tls-name", "site.example"],
                     ["--connect", "127.0.0.1", "--tls-name", "https://site.example"],
                     ["--connect", "127.0.0.1", "--tls-name", "127.0.0.1"],
                     ["--connect", "127.0.0.1", "--https-path", "/healthz"],
                     ["--connect", "127.0.0.1", "--tls-name", "site.example", "--https-path", "//other.example/"],
                     ["--connect", "127.0.0.1", "--tls-name", "site.example", "--https-path", "/path\r\nHost: fake"]):
            with self.subTest(args=args), patch.object(socket, "socket") as transport:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    main(["--port", "443", *args])
                self.assertEqual(exc.exception.code, 2)
                transport.assert_not_called()
