"""Read-only assessment of Compose inventory against the product catalog."""

from collections import Counter
from functools import cache
import hashlib
from importlib.resources import files
import json

from .app_profiles import DEPENDENCIES, PROFILES, REPOSITORIES


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


def resource_claims(project, names, labels):
    claims = []
    for name in sorted(names):
        claimant = labels.get(name)
        if name not in labels:
            status = "UNKNOWN"
        elif claimant is None:
            status = "UNLABELED"
        else:
            status = "PROJECT_LABEL" if claimant == project else "OTHER_PROJECT_LABEL"
        claims.append({"name": name, "status": status, "project": claimant})
    return claims
