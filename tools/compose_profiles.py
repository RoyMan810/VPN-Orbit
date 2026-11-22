"""Typed, non-deploying Compose profile catalog for optional applications."""

import json
import hashlib
import re
from pathlib import Path

IMAGE = re.compile(r"[a-z0-9][a-z0-9./_-]*@[A-Za-z0-9_-]+:[0-9a-f]{64}")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

PROFILE_NAMES = ("remnawave-panel", "remnawave-node", "bedolaga-bot", "bedolaga-cabinet")


def load_catalog(path: Path):
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or value.get("v") != 1 or set(value) != {"v", "profiles"}:
        raise ValueError("COMPOSE_PROFILE_CATALOG_INVALID")
    profiles = value["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILE_NAMES):
        raise ValueError("COMPOSE_PROFILE_CATALOG_INVALID")
    for name, profile in profiles.items():
        _validate_profile(name, profile)
    return value


def catalog_digest(catalog):
    raw = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _validate_profile(name, profile):
    if not isinstance(profile, dict) or set(profile) != {
        "kind", "network", "network_group", "ports", "env", "volumes", "depends_on"
    }:
        raise ValueError("COMPOSE_PROFILE_INVALID")
    group = profile["network_group"]
    if (not NAME.fullmatch(name) or profile["kind"] != name
            or profile["network"] not in ("bridge", "isolated")
            or (profile["network"] == "bridge" and (not isinstance(group, str) or not NAME.fullmatch(group)))
            or (profile["network"] == "isolated" and group is not None)):
        raise ValueError("COMPOSE_PROFILE_INVALID")
    if not isinstance(profile["ports"], list) or any(type(port) is not int or not 1 <= port <= 65535 for port in profile["ports"]):
        raise ValueError("COMPOSE_PROFILE_INVALID")
    if len(set(profile["ports"])) != len(profile["ports"]):
        raise ValueError("COMPOSE_PROFILE_INVALID")
    if not isinstance(profile["env"], list) or any(not isinstance(key, str) or not ENV_NAME.fullmatch(key) for key in profile["env"]):
        raise ValueError("COMPOSE_PROFILE_INVALID")
    if not isinstance(profile["volumes"], list) or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in profile["volumes"]):
        raise ValueError("COMPOSE_PROFILE_INVALID")
    if not isinstance(profile["depends_on"], list) or any(not isinstance(dep, str) or not NAME.fullmatch(dep) for dep in profile["depends_on"]):
        raise ValueError("COMPOSE_PROFILE_INVALID")


def _source_path(value, profile_name, volume_name):
    expected = f"/var/lib/vpn-orbit/apps/{profile_name}/{volume_name}"
    if value != expected:
        raise ValueError("COMPOSE_VOLUME_PATH_INVALID")
    return value


def render(catalog, selected):
    """Render only explicitly selected profile entries into a Compose fragment."""
    if not isinstance(selected, dict) or not selected:
        raise ValueError("COMPOSE_PROFILE_SELECTION_REQUIRED")
    profiles = catalog["profiles"]
    if set(selected) - set(profiles):
        raise ValueError("COMPOSE_PROFILE_UNKNOWN")
    services, networks = {}, {}
    for name, spec in selected.items():
        profile = profiles[name]
        if not isinstance(spec, dict) or set(spec) - {"image", "environment", "volumes"} or "image" not in spec:
            raise ValueError("COMPOSE_PROFILE_SELECTION_INVALID")
        image = spec["image"]
        environment = spec.get("environment", {})
        volume_paths = spec.get("volumes", {})
        if not isinstance(image, str) or not IMAGE.fullmatch(image):
            raise ValueError("COMPOSE_IMAGE_DIGEST_REQUIRED")
        if not isinstance(environment, dict) or set(environment) - set(profile["env"]):
            raise ValueError("COMPOSE_ENV_NOT_ALLOWLISTED")
        if any(not isinstance(key, str) or not isinstance(value, str) or len(value) > 4096
               for key, value in environment.items()):
            raise ValueError("COMPOSE_ENV_VALUE_INVALID")
        if not isinstance(volume_paths, dict) or set(volume_paths) - set(profile["volumes"]):
            raise ValueError("COMPOSE_VOLUME_NOT_ALLOWLISTED")
        service = {
            "image": image,
            "pull_policy": "never",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges=true"],
            "restart": "unless-stopped",
            "environment": environment,
            "volumes": [
                {"type": "bind", "source": _source_path(path, name, volume),
                 "target": f"/var/lib/vpn-orbit/{volume}", "bind": {"create_host_path": False}}
                for volume, path in sorted(volume_paths.items())
            ],
        }
        if profile["network"] == "isolated":
            service["network_mode"] = "none"
        else:
            network = f"vpn-orbit-{profile['network_group']}"
            service["networks"] = [network]
            networks[network] = {"driver": "bridge", "internal": False}
        if profile["ports"]:
            service["ports"] = [
                {"target": port, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"}
                for port in profile["ports"]
            ]
        if profile["depends_on"]:
            missing = set(profile["depends_on"]) - set(selected)
            if missing:
                raise ValueError("COMPOSE_PROFILE_DEPENDENCY_MISSING")
            service["depends_on"] = {
                dep: {"condition": "service_healthy"} for dep in profile["depends_on"]
            }
        services[name] = service
    return {"v": 1, "catalog_sha256": catalog_digest(catalog), "services": services, "networks": networks}


def audit(actual, expected):
    if not isinstance(actual, dict) or actual.get("v") != 1:
        raise ValueError("COMPOSE_METADATA_INVALID")
    if actual.get("catalog_sha256") != expected.get("catalog_sha256"):
        return {"status": "DRIFT", "reason": "CATALOG_DIGEST_MISMATCH"}
    if actual.get("services") != expected.get("services") or actual.get("networks") != expected.get("networks"):
        return {"status": "DRIFT", "reason": "COMPOSE_FRAGMENT_MISMATCH"}
    return {"status": "MATCHED", "catalog_sha256": actual["catalog_sha256"]}


def audit_docker_state(state, expected):
    """Audit read-only Docker state; never calls Docker or mutates host state."""
    if not isinstance(state, dict) or set(state) != {"containers", "networks", "volumes"}:
        raise ValueError("DOCKER_STATE_INVALID")
    expected_names = set(expected["services"])
    containers = state["containers"]
    if (not isinstance(containers, list)
            or any(not isinstance(item, dict) for item in containers)):
        raise ValueError("DOCKER_STATE_INVALID")
    managed = []
    for item in containers:
        labels = item.get("labels")
        if not isinstance(labels, dict):
            return {"status": "DRIFT", "reason": "CONTAINER_LABELS_MISSING"}
        if labels.get("com.vpn-orbit.managed") != "true":
            continue
        managed.append(item)
        if labels.get("com.vpn-orbit.catalog-sha256") != expected["catalog_sha256"]:
            return {"status": "DRIFT", "reason": "CONTAINER_CATALOG_DIGEST_MISMATCH"}
        if labels.get("com.vpn-orbit.profile") not in expected_names:
            return {"status": "DRIFT", "reason": "UNKNOWN_MANAGED_PROFILE"}
    profiles = {item["labels"]["com.vpn-orbit.profile"] for item in managed}
    if profiles != expected_names:
        return {"status": "DRIFT", "reason": "MANAGED_PROFILE_SET_MISMATCH"}
    for key in ("networks", "volumes"):
        if not isinstance(state[key], list) or any(not isinstance(item, dict) for item in state[key]):
            raise ValueError("DOCKER_STATE_INVALID")
    return {"status": "MATCHED", "catalog_sha256": expected["catalog_sha256"],
            "managed_profiles": sorted(profiles), "data_preserved": True}


def removal_plan(actual, expected, *, confirmed=False):
    """Return a non-destructive removal plan; never runs Compose or deletes data."""
    result = audit(actual, expected)
    if result["status"] != "MATCHED":
        raise ValueError("COMPOSE_REMOVAL_BLOCKED_DRIFT")
    services = sorted(expected["services"])
    networks = sorted(expected["networks"])
    volumes = sorted({
        volume["source"] for service in expected["services"].values()
        for volume in service.get("volumes", [])
    })
    if not confirmed:
        return {"status": "CONFIRMATION_REQUIRED", "services": services, "networks": networks,
                "volumes": volumes, "data_preserved": True}
    return {"status": "REMOVAL_AUTHORIZED", "services": services, "networks": networks,
            "volumes": volumes, "data_preserved": True, "compose_down": False}


def execute_removal(plan, runner):
    """Remove owned containers/networks only; never remove volumes or run compose down."""
    if not isinstance(plan, dict) or plan.get("status") != "REMOVAL_AUTHORIZED":
        raise ValueError("COMPOSE_REMOVAL_CONFIRMATION_REQUIRED")
    if plan.get("data_preserved") is not True or plan.get("compose_down") is not False:
        raise ValueError("COMPOSE_REMOVAL_PLAN_INVALID")
    for service in plan["services"]:
        runner(["docker", "compose", "--project-name", "vpn-orbit", "rm", "--stop", "--force", service])
    for network in plan["networks"]:
        runner(["docker", "network", "rm", network])
    return {"status": "REMOVAL_APPLIED", "services": plan["services"],
            "networks": plan["networks"], "volumes": plan["volumes"], "data_preserved": True}


def load_selection(path: Path, catalog):
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or value.get("v") != 1 or set(value) != {"v", "profiles"}:
        raise ValueError("COMPOSE_PROFILE_SELECTION_INVALID")
    return render(catalog, value["profiles"])


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--actual", type=Path, help="Existing rendered fragment to audit")
    parser.add_argument("--removal-plan", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args(argv)
    catalog = load_catalog(args.catalog)
    expected = load_selection(args.selection, catalog)
    if args.actual:
        actual = json.loads(args.actual.read_text())
        value = removal_plan(actual, expected, confirmed=args.confirm) if args.removal_plan else audit(actual, expected)
    else:
        value = expected
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
