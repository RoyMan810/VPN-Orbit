"""Read-only assessment of Compose inventory against the product catalog."""

from collections import Counter
from functools import cache
import hashlib
from importlib.resources import files
import json

from .app_profiles import DEPENDENCIES, PROFILES, REPOSITORIES
from .runtime.protocol import checksum


def repository_digest(repository):
    return hashlib.sha256(repository.encode("ascii")).hexdigest()


@cache
def image_catalog():
    pins = json.loads(files("vpn_orbit").joinpath("application-images.json").read_text(encoding="utf-8"))["images"]
    repositories = {repository_digest(repo): role for role, refs in REPOSITORIES.items() for repo in refs}
    fingerprints = {}
    for role, reference in pins.items():
        repo, digest = reference.split("@sha256:")
        fingerprints[role] = repository_digest(repo) + ":" + digest
    return repositories, fingerprints


def assess_profiles(containers, observed_images):
    repositories, pins = image_catalog()
    services = []
    for container in containers:
        refs = observed_images.get(container["image_id"], ())
        roles = {repositories[ref.split(":")[0]] for ref in refs if ref.split(":")[0] in repositories}
        role = next(iter(roles)) if len(roles) == 1 else None
        if role is not None:
            status = "PIN_MATCH" if pins[role] in refs else "PIN_NOT_VERIFIED"
        elif roles:
            status = "AMBIGUOUS"
        else:
            status = "OTHER_IMAGE" if refs else "UNKNOWN"
        services.append({"container_id": container["id"], "role": role, "status": status})

    counts = Counter(service["role"] for service in services)
    profiles = [role for role in PROFILES if counts[role]]
    dependencies = Counter(dep for profile in profiles for dep in DEPENDENCIES[profile])
    shape_matches = (bool(profiles) and all(counts[role] == 1 for role in profiles)
                     and counts["postgres"] == sum(n for dep, n in dependencies.items() if dep.endswith("-db"))
                     and counts["redis"] == sum(n for dep, n in dependencies.items() if dep.endswith("-redis"))
                     and all(counts[dep] for dep in dependencies if dep in PROFILES))

    if any(service["status"] == "OTHER_IMAGE" for service in services):
        status = "MISMATCH"
    elif counts[None]:
        status = "UNVERIFIED"
    elif not shape_matches:
        status = "MISMATCH"
    elif any(service["status"] != "PIN_MATCH" for service in services):
        status = "UNVERIFIED"
    else:
        status = "PROFILE_MATCH"
    return {"status": status, "profiles": profiles, "services": services}


def resource_claims(project, members, labels, usage):
    claims = []
    for name, projects in sorted(members.items()):
        if project not in projects:
            continue
        claimant = labels.get(name)
        if name not in labels:
            status = "UNKNOWN"
        elif claimant is None:
            status = "UNLABELED"
        else:
            status = "PROJECT_LABEL" if claimant == project else "OTHER_PROJECT_LABEL"
        consumer_status = usage.get(name, "UNKNOWN")
        if consumer_status == "COMPOSE_ONLY":
            consumer_status = "PROJECT_ONLY" if len(projects) == 1 else "OTHER_PROJECTS"
        claims.append({"name": name, "status": status, "project": claimant, "usage": consumer_status})
    return claims


def daemon_identity(project, containers):
    keys = ("id", "service", "image_id", "state", "networks", "volumes")
    return checksum({"project": project, "containers": [
        {key: row.get(key) for key in keys} for row in sorted(containers, key=lambda row: row["id"])
    ]})


def adoption_ready(preview):
    return not (preview["source"] != "CONFIRMED" or preview["compatibility"]["status"] != "PROFILE_MATCH"
            or any(row["state"] != "RUNNING" for row in preview["containers"])
            or any(value["service_config"] != "LABEL_PRESENT" or value["bind_mounts"] not in ("NONE", "READ_ONLY")
                   for value in preview["configuration"].values())
            or any(dependencies is None or any(edge["status"] != "SHARED_NETWORK" for edge in dependencies)
                   for dependencies in preview["dependencies"].values())
            or any(value["coverage"] != "OBSERVED_COMPOSE_ONLY"
                   or any(claim["status"] != "PROJECT_LABEL" or claim["usage"] != "PROJECT_ONLY"
                          for claim in value["claims"]) for value in preview["attachments"].values()))
