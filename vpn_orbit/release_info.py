"""Fixed-origin, metadata-only release discovery."""

from datetime import UTC, datetime
import json
import re
from threading import Lock
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .errors import Denied


GITHUB_RELEASES = "https://api.github.com/repos/RoyMan810/VPN-Orbit/releases/latest"
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,9})(?:\.(?:0|[1-9][0-9]{0,9})){2}")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def stable_version(value):
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise Denied("UPDATE_STABLE_VERSION_REQUIRED")
    return tuple(map(int, value.split(".")))


def discover(installed):
    current = stable_version(installed)
    request = Request(GITHUB_RELEASES, headers={"Accept": "application/vnd.github+json", "User-Agent": "VPN-Orbit-maintenance"})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
            data = response.read(1024**2 + 1)
        if len(data) > 1024**2:
            raise ValueError
        release = json.loads(data)
        tag = release["tag_name"]
        if release["draft"] is not False or release["prerelease"] is not False or not tag.startswith("v"):
            raise ValueError
        latest = stable_version(tag[1:])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, Denied):
        raise Denied("UPDATE_RELEASE_DISCOVERY_UNAVAILABLE", 503) from None
    return {"installed_version": installed, "github_release_version": tag[1:],
            "status": "UPDATE_AVAILABLE" if latest > current else "NO_NEWER_RELEASE",
            "artifact_verified": False}


class ReleaseLookup:
    def __init__(self, version):
        self.version = version
        self._lock = Lock()
        self._cached = None
        self._until = 0

    def check(self):
        now = time.monotonic()
        if not self._lock.acquire(blocking=False):
            raise Denied("UPDATE_RELEASE_CHECK_IN_PROGRESS", 503, retry_after=5)
        try:
            if now < self._until:
                return self._cached
            try:
                value = discover(self.version)
                ttl = 300
            except Denied as exc:
                value = {"installed_version": self.version, "github_release_version": None, "status": "UNAVAILABLE",
                         "artifact_verified": False, "code": exc.code}
                ttl = 60
            self._cached = {**value, "checked_at": datetime.now(UTC).isoformat(timespec="seconds")}
            self._until = time.monotonic() + ttl
            return self._cached
        finally:
            self._lock.release()
