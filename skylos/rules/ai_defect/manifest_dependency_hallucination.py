from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    parse_go_mod,
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)


RULE_ID_DEPENDENCY_HALLUCINATION = "SKY-D222"
RULE_ID_VERSION_HALLUCINATION = "SKY-D225"
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
VIBE_CATEGORY = "dependency_hallucination"
AI_LIKELIHOOD = "high"
STATUS_EXISTS = "exists"
STATUS_MISSING_PACKAGE = "missing_package"
STATUS_MISSING_VERSION = "missing_version"
STATUS_UNKNOWN = "unknown"
VERSION_CACHE_SCHEMA_VERSION = 1
VERSION_CACHE_PATH = Path(".skylos") / "cache" / "dependency_versions.json"
MAX_VERSION_CACHE_BYTES = 5_000_000
MAX_REGISTRY_RESPONSE_BYTES = 1_000_000
NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
GO_PROXY_ORIGIN = "https://proxy.golang.org"
PYPI_JSON_ORIGIN = "https://pypi.org/pypi"
ALLOWED_REGISTRY_HOSTS = {
    "pypi.org",
    "registry.npmjs.org",
    "proxy.golang.org",
}

StatusChecker = Callable[[str, str, str, dict[str, Any]], str]

logger = logging.getLogger(__name__)


def scan_manifest_dependency_hallucinations(
    repo_root: str | Path | None,
    *,
    status_checker: StatusChecker | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root = _repo_root(repo_root)
    if root is None:
        return findings

    dependencies = _collect_manifest_dependencies(root)
    if not dependencies:
        return findings

    cache = _load_version_cache(root)
    checker = _status_checker(status_checker)
    cache_changed = False

    for dependency in _unique_dependencies(dependencies):
        status = _cached_dependency_status(dependency, cache)
        if status is None:
            status = checker(
                str(dependency["ecosystem"]),
                str(dependency["name"]),
                str(dependency["version"]),
                cache,
            )
            _record_dependency_status(dependency, cache, status)
            cache_changed = True

        finding = _finding_for_status(dependency, status)
        if finding is not None:
            findings.append(finding)

    if cache_changed:
        _save_version_cache(root, cache)

    return findings


def check_dependency_version_status(
    ecosystem: str,
    name: str,
    version: str,
    cache: dict[str, Any],
) -> str:
    if ecosystem == ECOSYSTEM_PYPI:
        return _check_pypi_version(name, version)
    if ecosystem == ECOSYSTEM_NPM:
        return _check_npm_version(name, version)
    if ecosystem == ECOSYSTEM_GO:
        return _check_go_version(name, version)
    return STATUS_UNKNOWN


def _repo_root(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        return Path(value).resolve()
    except OSError:
        return Path(value)


def _status_checker(status_checker: StatusChecker | None) -> StatusChecker:
    if status_checker is not None:
        return status_checker
    return check_dependency_version_status


def _collect_manifest_dependencies(root: Path) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    parsers = {
        "requirements.txt": parse_requirements_txt,
        "pyproject.toml": parse_pyproject_toml,
        "package.json": parse_package_json,
        "go.mod": parse_go_mod,
    }

    for dirpath, dirnames, filenames in os.walk(root):
        _filter_manifest_dirs(dirnames)
        if _manifest_depth(root, dirpath) > 3:
            dirnames.clear()
            continue

        for filename in filenames:
            parser = parsers.get(filename)
            if parser is None:
                continue
            path = Path(dirpath) / filename
            try:
                dependencies.extend(parser(path))
            except Exception as exc:
                logger.debug("Failed to parse dependency manifest %s: %s", path, exc)

    return dependencies


def _filter_manifest_dirs(dirnames: list[str]) -> None:
    skipped = {
        ".git",
        ".skylos",
        "node_modules",
        "vendor",
        "dist",
        "build",
    }
    kept = []
    for dirname in dirnames:
        if dirname in skipped:
            continue
        kept.append(dirname)
    dirnames[:] = kept


def _manifest_depth(root: Path, dirpath: str) -> int:
    try:
        relative = Path(dirpath).resolve().relative_to(root)
    except (OSError, ValueError):
        return 0
    if not relative.parts:
        return 0
    return len(relative.parts)


def _unique_dependencies(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for dependency in dependencies:
        key = _dependency_key(dependency)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    return unique


def _dependency_key(dependency: dict[str, Any]) -> str:
    ecosystem = str(dependency.get("ecosystem", ""))
    name = str(dependency.get("name", ""))
    version = str(dependency.get("version", ""))
    return f"{ecosystem}:{name}:{version}"


def _load_version_cache(root: Path) -> dict[str, Any]:
    payload = load_project_json_cache(
        root,
        VERSION_CACHE_PATH,
        max_bytes=MAX_VERSION_CACHE_BYTES,
    )
    if payload.get("schema_version") != VERSION_CACHE_SCHEMA_VERSION:
        return _empty_version_cache()
    statuses = payload.get("statuses")
    if not isinstance(statuses, dict):
        payload["statuses"] = {}
    return payload


def _save_version_cache(root: Path, cache: dict[str, Any]) -> None:
    if not save_project_json_cache(root, VERSION_CACHE_PATH, cache):
        logger.debug("Failed to save dependency version cache")


def _empty_version_cache() -> dict[str, Any]:
    return {
        "schema_version": VERSION_CACHE_SCHEMA_VERSION,
        "statuses": {},
    }


def _cached_dependency_status(
    dependency: dict[str, Any],
    cache: dict[str, Any],
) -> str | None:
    statuses = cache.get("statuses")
    if not isinstance(statuses, dict):
        return None

    status = statuses.get(_dependency_key(dependency))
    if isinstance(status, str):
        return status
    return None


def _record_dependency_status(
    dependency: dict[str, Any],
    cache: dict[str, Any],
    status: str,
) -> None:
    statuses = cache.get("statuses")
    if not isinstance(statuses, dict):
        statuses = {}
        cache["statuses"] = statuses
    statuses[_dependency_key(dependency)] = status


def _finding_for_status(
    dependency: dict[str, Any],
    status: str,
) -> dict[str, Any] | None:
    if status == STATUS_MISSING_PACKAGE:
        return _missing_package_finding(dependency)
    if status == STATUS_MISSING_VERSION:
        return _missing_version_finding(dependency)
    return None


def _missing_package_finding(dependency: dict[str, Any]) -> dict[str, Any]:
    ecosystem = str(dependency["ecosystem"])
    name = str(dependency["name"])
    registry = _registry_label(ecosystem)
    message = (
        f"Hallucinated {ecosystem} dependency '{name}'. "
        f"Package does not exist in {registry}."
    )
    return _finding(
        dependency,
        rule_id=RULE_ID_DEPENDENCY_HALLUCINATION,
        severity=SEV_CRITICAL,
        message=message,
    )


def _missing_version_finding(dependency: dict[str, Any]) -> dict[str, Any]:
    ecosystem = str(dependency["ecosystem"])
    name = str(dependency["name"])
    version = str(dependency["version"])
    registry = _registry_label(ecosystem)
    message = (
        f"Hallucinated {ecosystem} dependency version '{name}@{version}'. "
        f"Version does not exist in {registry}."
    )
    return _finding(
        dependency,
        rule_id=RULE_ID_VERSION_HALLUCINATION,
        severity=SEV_HIGH,
        message=message,
    )


def _finding(
    dependency: dict[str, Any],
    *,
    rule_id: str,
    severity: str,
    message: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(dependency["file"]),
        "line": int(dependency["line"]),
        "col": 0,
        "symbol": f"{dependency['name']}@{dependency['version']}",
        "category": "ai_defect",
        "defect_type": VIBE_CATEGORY,
        "vibe_category": VIBE_CATEGORY,
        "ai_likelihood": AI_LIKELIHOOD,
        "confidence": 86,
        "metadata": {
            "ecosystem": dependency["ecosystem"],
            "package_name": dependency["name"],
            "package_version": dependency["version"],
        },
    }


def _registry_label(ecosystem: str) -> str:
    if ecosystem == ECOSYSTEM_PYPI:
        return "PyPI"
    if ecosystem == ECOSYSTEM_NPM:
        return "the npm registry"
    if ecosystem == ECOSYSTEM_GO:
        return "the Go module proxy"
    return "the package registry"


def _check_pypi_version(name: str, version: str) -> str:
    package_path = _safe_pypi_package_path(name)
    if package_path is None:
        return STATUS_UNKNOWN

    safe_version = quote(version.strip(), safe="")
    version_url = f"{PYPI_JSON_ORIGIN}/{package_path}/{safe_version}/json"
    try:
        _fetch_json(version_url, user_agent="skylos-pypi-dep-scanner/1.0")
        return STATUS_EXISTS
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    package_url = f"{PYPI_JSON_ORIGIN}/{package_path}/json"
    try:
        _fetch_json(package_url, user_agent="skylos-pypi-dep-scanner/1.0")
        return STATUS_MISSING_VERSION
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN


def _check_npm_version(name: str, version: str) -> str:
    package_path = _safe_npm_package_path(name)
    if package_path is None:
        return STATUS_UNKNOWN

    url = f"{NPM_REGISTRY_ORIGIN}/{package_path}"
    try:
        data = _fetch_json(url, user_agent="skylos-npm-dep-scanner/1.0")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    versions = data.get("versions")
    if not isinstance(versions, dict):
        return STATUS_UNKNOWN
    if version in versions:
        return STATUS_EXISTS
    return STATUS_MISSING_VERSION


def _check_go_version(name: str, version: str) -> str:
    module_path = _safe_go_module_path(name)
    if module_path is None:
        return STATUS_UNKNOWN

    go_version = _go_version(version)
    safe_go_version = quote(go_version, safe="")
    info_url = f"{GO_PROXY_ORIGIN}/{module_path}/@v/{safe_go_version}.info"
    try:
        _fetch_text(info_url, user_agent="skylos-go-dep-scanner/1.0")
        return STATUS_EXISTS
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    list_url = f"{GO_PROXY_ORIGIN}/{module_path}/@v/list"
    try:
        _fetch_text(list_url, user_agent="skylos-go-dep-scanner/1.0")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN
    return STATUS_MISSING_VERSION


def _go_version(version: str) -> str:
    if version.startswith("v"):
        return version
    return f"v{version}"


def _safe_pypi_package_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("."):
        return None
    if "/" in raw:
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    for char in raw:
        if char.isalnum():
            continue
        if char in ("-", "_", "."):
            continue
        return None
    return quote(raw, safe="")


def _safe_npm_package_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("."):
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    if raw.startswith("@"):
        parts = raw.split("/")
        if len(parts) != 2:
            return None
        if not _safe_npm_name_part(parts[0][1:]):
            return None
        if not _safe_npm_name_part(parts[1]):
            return None
    else:
        if "/" in raw:
            return None
        if not _safe_npm_name_part(raw):
            return None
    return quote(raw, safe="@")


def _safe_npm_name_part(value: str) -> bool:
    if not value:
        return False
    for char in value:
        if char.isalnum():
            continue
        if char in ("-", "_", "."):
            continue
        return False
    return True


def _safe_go_module_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("/"):
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    parts = raw.split("/")
    encoded_parts = []
    for part in parts:
        if not _safe_go_path_part(part):
            return None
        encoded_parts.append(quote(part, safe=""))
    return "/".join(encoded_parts)


def _safe_go_path_part(value: str) -> bool:
    if not value:
        return False
    for char in value:
        if char.isalnum():
            continue
        if char in ("-", "_", ".", "~"):
            continue
        return False
    return True


def _fetch_json(url: str, *, user_agent: str) -> dict[str, Any]:
    text = _fetch_text(url, user_agent=user_agent)
    data = json.loads(text)
    if isinstance(data, dict):
        return data
    return {}


def _fetch_text(url: str, *, user_agent: str) -> str:
    if not _allowed_registry_url(url):
        raise ValueError("Registry URL host is not allowed")

    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", user_agent)
    with urllib.request.urlopen(  # skylos: ignore[SKY-D216] URL is validated against fixed registry hosts above.
        request,
        timeout=5,
    ) as response:
        raw = response.read(MAX_REGISTRY_RESPONSE_BYTES + 1)
    if len(raw) > MAX_REGISTRY_RESPONSE_BYTES:
        raise ValueError("Registry response exceeds size limit")
    return raw.decode("utf-8", errors="replace")


def _allowed_registry_url(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return False
    if parsed.hostname not in ALLOWED_REGISTRY_HOSTS:
        return False
    if parsed.username:
        return False
    if parsed.password:
        return False
    if parsed.port is not None:
        return False
    return True
