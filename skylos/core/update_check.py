"""Tell the user when a newer Skylos release is on PyPI.

The only request is an anonymous read of the public PyPI record for the
``skylos`` package. Nothing about the scanned project is sent. The answer is
kept for a day in the user cache so a scan never waits on the network: scans
read the cached answer and refresh it in the background.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

PYPI_RECORD_URL = "https://pypi.org/pypi/skylos/json"
CACHE_SECONDS = 24 * 60 * 60
REQUEST_SECONDS = 2.0
UPGRADE_COMMAND = "pip install -U skylos"
_RELEASE = re.compile(r"^\d+(\.\d+){1,3}$")
_CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "JENKINS_URL",
    "BUILD_NUMBER",
    "CIRCLECI",
    "GITLAB_CI",
    "BITBUCKET_PIPELINE_UUID",
    "AZURE_PIPELINES",
    "TF_BUILD",
)


def _cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "skylos" / "latest-version.json"


def _release_tuple(version: str) -> tuple[int, ...] | None:
    text = str(version).strip()
    if not _RELEASE.match(text):
        return None
    return tuple(int(part) for part in text.split("."))


def is_newer(latest: str, current: str) -> bool:
    """True only when both are plain release numbers and ``latest`` is higher.

    A development, local or pre-release install is never told to upgrade.
    """
    latest_parts = _release_tuple(latest)
    current_parts = _release_tuple(current)
    if latest_parts is None or current_parts is None:
        return False
    width = max(len(latest_parts), len(current_parts))
    latest_parts += (0,) * (width - len(latest_parts))
    current_parts += (0,) * (width - len(current_parts))
    return latest_parts > current_parts


def disabled() -> bool:
    if os.environ.get("SKYLOS_NO_TELEMETRY"):
        return True
    return any(os.environ.get(name) for name in _CI_VARIABLES)


def _read_cache() -> dict | None:
    try:
        record = json.loads(_cache_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    if _release_tuple(record.get("latest", "")) is None:
        return None
    if not isinstance(record.get("checked"), (int, float)):
        return None
    return record


def _write_cache(latest: str) -> None:
    path = _cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f".{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps({"latest": latest, "checked": time.time()}), encoding="utf-8"
        )
        os.replace(temporary, path)
    except OSError:
        return


def fetch_latest(timeout: float = REQUEST_SECONDS) -> str | None:
    """Ask PyPI for the newest release. None when it cannot be learned."""
    request = urllib.request.Request(
        PYPI_RECORD_URL,
        headers={"Accept": "application/json", "User-Agent": "skylos-update-check"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            record = json.loads(response.read(2_000_000))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    info = record.get("info")
    if not isinstance(info, dict):
        return None
    latest = info.get("version")
    if not isinstance(latest, str) or _release_tuple(latest) is None:
        return None
    return latest


def cached_latest() -> str | None:
    record = _read_cache()
    if record is None:
        return None
    return record["latest"]


def _cache_is_fresh() -> bool:
    record = _read_cache()
    return record is not None and time.time() - record["checked"] < CACHE_SECONDS


def latest_version(timeout: float = REQUEST_SECONDS) -> str | None:
    """The newest release, asking PyPI when the cached answer is a day old."""
    if disabled():
        return None
    if _cache_is_fresh():
        return cached_latest()
    latest = fetch_latest(timeout)
    if latest is None:
        return cached_latest()
    _write_cache(latest)
    return latest


def refresh_in_background() -> threading.Thread | None:
    """Refresh the cached answer without making the caller wait for it."""
    if disabled() or _cache_is_fresh():
        return None

    def refresh():
        latest = fetch_latest()
        if latest is not None:
            _write_cache(latest)

    thread = threading.Thread(target=refresh, name="skylos-update-check", daemon=True)
    thread.start()
    return thread


def upgrade_notice(current: str, latest: str | None = None) -> str | None:
    """One line telling the user to upgrade, or None when there is no need."""
    if latest is None:
        if disabled():
            return None
        latest = cached_latest()
    if latest is None or not is_newer(latest, str(current)):
        return None
    return (
        f"Skylos {latest} is available (you have {current}). Upgrade: {UPGRADE_COMMAND}"
    )
