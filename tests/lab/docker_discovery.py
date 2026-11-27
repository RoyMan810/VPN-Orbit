"""Exercise the Docker and Compose read adapters on a disposable GitHub runner."""

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
from urllib.parse import urlsplit
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true")
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if (not args.isolated_vm or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or not re.fullmatch(r"docker\.io/library/python@sha256:[0-9a-f]{64}", args.image)):
        parser.error("a disposable GitHub-hosted VM and pinned lab image are required")
    host = os.environ["DOCKER_HOST"]
    address = urlsplit(host)
    if address.scheme != "unix" or address.netloc or not address.path.startswith("/") or address.query or address.fragment:
        parser.error("a local Docker daemon socket is required")
    socket_path = Path(address.path).resolve(strict=True)
    helper = runpy.run_path(str(Path(__file__).resolve().parents[2] / "remote" / "typed-helper"))
    observe = helper["observe_docker"]
    discover = helper["observe_compose"]
    prefix = "vpn-orbit-discovery-" + uuid4().hex[:10]
    ids = []
    network = volume = None
    config_hash = uuid4().hex * 2
    source_dir = tempfile.TemporaryDirectory(prefix="vpn-orbit-compose-", dir="/var/lib")
    source = Path(source_dir.name) / "compose.yaml"

    def docker(*values):
        return subprocess.check_output(["docker", "--host", host, *values], text=True, timeout=45).strip()

    def create(project, service, *network_args):
        dependency = "missing:service_started:false,worker:service_healthy:false" if service == "web" else ""
        compose_labels = ("--label", "com.docker.compose.project=" + project,
                          "--label", "com.docker.compose.service=" + service,
                          "--label", "com.docker.compose.config-hash=" + config_hash,
                          "--label", "com.docker.compose.project.config_files=" + str(source),
                          "--label", "com.docker.compose.depends_on=" + dependency) if project is not None else ()
        identity = docker("create", *network_args, "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges=true", "--user", "65534:65534",
                          *compose_labels,
                          "--label", "fixture.secret=label-canary",
                          "--entrypoint", "python", args.image, "-c", "import time; time.sleep(30)")
        assert re.fullmatch(r"[0-9a-f]{64}", identity)
        ids.append(identity)
        return identity

    try:
        source.write_text("source-content-canary\n")
        network = docker("network", "create", "--label", "com.docker.compose.project=" + prefix,
                         prefix + "-network")
        volume = docker("volume", "create", prefix + "-data")
        running = create(prefix, "web", "--network", prefix + "-network", "--network-alias", "alias-canary",
                         "--publish", "127.0.0.1::8080/tcp", "--expose", "8081/tcp")
        stopped = create(prefix, "worker", "--network", "none", "--ipc", "private", "--cgroupns", "private",
                         "--runtime", "runc", "--log-driver", "local")
        mount = f"type=volume,source={volume},target=/mount-canary"
        foreign = create(prefix + "-foreign", "private", "--network", "none", "--mount", mount)
        mounted = create(prefix, "mounted", "--network", "none", "--tmpfs", "/fixture-tmpfs", "--mount", mount,
                         "--mount", "type=bind,source=/etc/hosts,target=/bind-canary,readonly")
        outside = create(None, "standalone", "--network", "none", "--mount", mount)
        docker("start", running, mounted)
        scope = [{"id": running, "project": prefix, "service": "web"},
                 {"id": stopped, "project": prefix, "service": "worker"}]
        # The action's parent directory belongs to the runner. A hard link on
        # the same filesystem exposes the same socket in a root-owned directory.
        with tempfile.TemporaryDirectory(prefix="vpn-orbit-docker-", dir=socket_path.parent) as directory:
            registry = Path(directory) / "docker-discovery.json"
            switch = Path(directory) / "compose-discovery.enabled"
            protected_socket = Path(directory) / "docker.sock"
            os.link(socket_path, protected_socket)
            registry.write_text(json.dumps({"v": 1, "containers": scope}))
            registry.chmod(0o600)
            result = observe(registry, protected_socket)
            assert result == {"status": "OBSERVED", "containers": [
                {**scope[0], "state": "RUNNING"}, {**scope[1], "state": "CREATED"},
            ]}, result
            address, port = docker("port", running, "8080/tcp").rsplit(":", 1)
            assert address == "127.0.0.1"
            result = observe(registry, protected_socket, include_ports=True)
            assert result == {"status": "OBSERVED", "containers": [
                {**scope[0], "state": "RUNNING", "published_ports": [
                    {"address": "127.0.0.1", "host_port": int(port), "container_port": 8080, "protocol": "tcp"},
                ]},
                {**scope[1], "state": "CREATED", "published_ports": []},
            ]}, result
            assert foreign not in json.dumps(result) and "label-canary" not in json.dumps(result)
            assert discover(switch, protected_socket) == {"status": "NOT_CONFIGURED", "containers": []}
            switch.write_bytes(b"enabled\n")
            switch.chmod(0o644)
            assert discover(switch, protected_socket) == {"status": "POLICY_INVALID", "containers": []}
            switch.chmod(0o600)
            before = docker("inspect", "--format", "{{.Id}} {{.State.Status}} {{.State.StartedAt}}", *ids)
            projects = discover(switch, protected_socket)
            assert projects["status"] == "OBSERVED", projects
            assert {row["id"] for row in projects["containers"]} == set(ids) - {outside}, projects
            assert {row["project"] for row in projects["containers"]} == {prefix, prefix + "-foreign"}
            image = docker("inspect", "--format", "{{.Image}}", running)
            assert {row["image_id"] for row in projects["containers"]} == {image}
            assert {row["state"] for row in projects["containers"]} == {"RUNNING", "CREATED"}
            assert "label-canary" not in json.dumps(projects)
            switch.write_bytes(b"enabled-with-resources\n")
            attachments = discover(switch, protected_socket)
            assert attachments["status"] == "OBSERVED", attachments
            by_id = {row["id"]: row for row in attachments["containers"]}
            assert by_id[running]["networks"] == [prefix + "-network"] and by_id[running]["volumes"] == [], attachments
            assert by_id[foreign]["volumes"] == by_id[mounted]["volumes"] == [volume], attachments
            assert by_id[stopped]["volumes"] == [], attachments
            assert all(value not in json.dumps(attachments) for value in ("label-canary", "mount-canary", "alias-canary"))
            switch.write_bytes(b"enabled-with-adoption\n")
            sources = Path(directory) / "compose-sources.json"
            sources.write_text(json.dumps({prefix: [str(source)]}))
            sources.chmod(0o600)
            adoption = discover(switch, protected_socket, sources=sources)
            refs = json.loads(docker("image", "inspect", "--format", "{{json .RepoDigests}}", args.image))
            fingerprints = helper["digest_evidence"](refs)
            assert fingerprints, refs
            assert adoption["adoption_evidence"] == {
                "images": {image: fingerprints}, "networks": {prefix + "-network": prefix}, "volumes": {volume: None},
                "usage": {"networks": {prefix + "-network": "COMPOSE_ONLY"}, "volumes": {volume: "OUTSIDE_COMPOSE"}},
                "configuration": {
                    identity: {"service_config": "LABEL_PRESENT", "bind_mounts": "READ_ONLY" if identity == mounted else "NONE"}
                    for identity in set(ids) - {outside}
                },
                "definition": {
                    "sources": {prefix: "CONFIRMED", prefix + "-foreign": "NOT_CONFIGURED"},
                    "dependencies": {
                        running: [{"service": "missing", "status": "NOT_OBSERVED"},
                                  {"service": "worker", "status": "NETWORK_UNVERIFIED"}],
                        stopped: [], mounted: [], foreign: [],
                    },
                },
            }, adoption
            assert all(value not in json.dumps(adoption) for value in
                       ("label-canary", outside, config_hash, "/bind-canary", str(source), "source-content-canary"))
            original = source.rename(source.with_suffix(".bak"))
            source.symlink_to(original)
            source_check = discover(switch, protected_socket, sources=sources)
            assert source_check["adoption_evidence"]["definition"]["sources"][prefix] == "UNVERIFIED", source_check
            assert docker("inspect", "--format", "{{.Id}} {{.State.Status}} {{.State.StartedAt}}", *ids) == before
            mounted_scope = {"id": mounted, "project": prefix, "service": "mounted"}
            registry.write_text(json.dumps({"v": 1, "containers": [*scope, mounted_scope]}))
            result = observe(registry, protected_socket, include_ports=True, include_mounts=True)
            assert [row["mount_status"] for row in result["containers"]] == ["NONE", "UNKNOWN", "PRESENT"], result
            assert "/fixture-tmpfs" not in json.dumps(result) and foreign not in json.dumps(result)
            docker("start", stopped)
            result = observe(registry, protected_socket, include_ports=True, include_mounts=True, include_network=True)
            assert [row["network_status"] for row in result["containers"]] == ["OTHER", "ISOLATED", "ISOLATED"], result
            assert [row["mount_status"] for row in result["containers"]] == ["NONE", "NONE", "PRESENT"], result
            wrong = [{**scope[0], "project": prefix + "-wrong"}]
            registry.write_text(json.dumps({"v": 1, "containers": wrong}))
            assert observe(registry, protected_socket, include_ports=True) == {"status": "OBSERVED", "containers": [
                {**wrong[0], "state": "UNKNOWN", "published_ports": None},
            ]}
            registry.write_text(json.dumps({"v": 1, "containers": [scope[1]]}))
            options = dict(include_ports=True, include_mounts=True, include_network=True, include_dependencies=True)
            result = observe(registry, protected_socket, **options)
            assert result["containers"][0]["dependency_status"] == "OTHER", result
            docker("rm", "-f", running, foreign, mounted, outside)
            ids[:] = [stopped]
            result = observe(registry, protected_socket, **options)
            assert result == {"status": "OBSERVED", "containers": [
                {**scope[1], "state": "RUNNING", "published_ports": [], "mount_status": "NONE",
                 "network_status": "ISOLATED", "dependency_status": "ISOLATED"},
            ]}, result
            result = observe(registry, protected_socket, include_started_at=True, **options)
            started_at = docker("inspect", "--format", "{{.State.StartedAt}}", stopped)
            assert result["containers"][0]["started_at"] == started_at, result
            protected_socket.unlink()
            protected_socket.symlink_to(socket_path)
            assert observe(registry, protected_socket) == {"status": "UNAVAILABLE", "containers": []}
            registry.chmod(0o644)
            assert observe(registry, protected_socket) == {"status": "POLICY_INVALID", "containers": []}
            registry.unlink()
            assert observe(registry, protected_socket) == {"status": "NOT_CONFIGURED", "containers": []}
        print("Pinned Docker returned scoped containers and opt-in Compose inventory without changing any container.")
    finally:
        source_dir.cleanup()
        if ids:
            docker("rm", "-f", *ids)
        if volume:
            docker("volume", "rm", volume)
        if network:
            docker("network", "rm", network)


if __name__ == "__main__":
    main()
