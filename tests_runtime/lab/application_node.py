"""Actual Node host-network and mutual TLS acceptance on disposable hosts."""

import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import traceback

from vpn_orbit.app_lifecycle import Lifecycle, ROOT
from vpn_orbit.app_profiles import digest
from vpn_orbit.errors import Denied


IDENTITY = "01JCYQZ4T9V8MNVYEH3D2M7Q1N"


def node_acceptance():
    if ROOT.exists() or ROOT.is_symlink():
        raise RuntimeError("Disposable app namespace must be absent")
    images = json.loads((Path(__file__).resolve().parents[2] / "deploy/application-images.json").read_text())["images"]
    with tempfile.TemporaryDirectory(prefix="vo-node-pki-") as directory:
        directory = Path(directory)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=directory, check=True, capture_output=True, timeout=20)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Staging Node CA",
                "-days", "2", "-keyout", "ca.key", "-out", "ca.crt",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name in ("node", "client"):
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + ("localhost" if name == "node" else "staging"),
                    "-keyout", name + ".key", "-out", name + ".csr")
            (directory / "extensions").write_text("basicConstraints=critical,CA:FALSE\n"
                                                 "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                                 "authorityKeyIdentifier=keyid:always\n"
                                                 "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                                                 "extendedKeyUsage=serverAuth,clientAuth\n")
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                    "-CAcreateserial", "-days", "2", "-extfile", "extensions", "-out", name + ".crt")
        openssl("pkey", "-in", "client.key", "-pubout", "-out", "jwt.pub")
        payload = {key: (directory / name).read_text() for key, name in (
            ("caCertPem", "ca.crt"), ("jwtPublicKey", "jwt.pub"), ("nodeCertPem", "node.crt"), ("nodeKeyPem", "node.key"))}
        secret = base64.b64encode(json.dumps(payload).encode()).decode()
        spec = {"v": 1, "id": IDENTITY, "profiles": ["remnawave-node"],
                "images": {"remnawave-node": images["remnawave-node"]},
                "settings": {"remnawave-node": {"secret_key": secret, "port": 2222}}}
        Lifecycle.configure(spec)
        runtime = Lifecycle(IDENTITY)
        installed = runtime.execute(IDENTITY[:-1] + "P", "install", digest(spec))
        assert installed["outcome"] == "SUCCEEDED", installed
        assert runtime.status()["state"] == "HEALTHY"
        context = ssl.create_default_context(cafile=directory / "ca.crt")
        context.load_cert_chain(directory / "client.crt", directory / "client.key")
        with socket.create_connection(("127.0.0.1", 2222), timeout=4) as stream:
            with context.wrap_socket(stream, server_hostname="localhost") as tls:
                assert tls.version() == "TLSv1.3"
                tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                response = tls.recv(4096)
                assert response.startswith(b"HTTP/1.1 ")
        untrusted = ssl.create_default_context(cafile=directory / "ca.crt")
        try:
            with socket.create_connection(("127.0.0.1", 2222), timeout=4) as stream:
                with untrusted.wrap_socket(stream, server_hostname="localhost") as tls:
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    response = tls.recv(4096)
                    assert not response
        except ssl.SSLError:
            pass
        removed = runtime.execute(IDENTITY[:-1] + "Q", "remove", digest(spec))
        assert removed["outcome"] == "SUCCEEDED", removed
        print("PASS actual Node host networking, TLS 1.3, client certificate requirement and exact-ID removal.")


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Requires a disposable GitHub-hosted VM")
    try:
        node_acceptance()
    except Exception as error:
        subprocess.run(["docker", "ps", "--all", "--format", "{{.Names}} {{.Status}}"], check=False)
        frames = traceback.extract_tb(error.__traceback__)
        sites = ",".join(f"{Path(frame.filename).name}:{frame.lineno}" for frame in frames)
        code = error.code if isinstance(error, Denied) else type(error).__name__
        if isinstance(error, ssl.SSLCertVerificationError):
            code += f" ({error.verify_code})"
        print(f"Node acceptance diagnostic {code} at {sites}", flush=True)
        raise SystemExit("Node product acceptance failed") from None


if __name__ == "__main__":
    main()
