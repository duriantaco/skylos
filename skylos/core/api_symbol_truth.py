from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache


API_SYMBOL_TRUTH_SCHEMA_VERSION = 1
API_SYMBOL_TRUTH_CACHE_PATH = Path(".skylos") / "cache" / "api_symbol_truth.json"
MAX_API_SYMBOL_TRUTH_BYTES = 10_000_000

SURFACE_KIND_PYTHON_MODULE = "python_module"
SURFACE_KIND_JS_MODULE = "js_module"
SURFACE_KIND_CLI = "cli"
SURFACE_KIND_CONFIG = "config"
SURFACE_KIND_ROUTE = "route"
SURFACE_KIND_SCHEMA = "schema"
SURFACE_KINDS = {
    SURFACE_KIND_PYTHON_MODULE,
    SURFACE_KIND_JS_MODULE,
    SURFACE_KIND_CLI,
    SURFACE_KIND_CONFIG,
    SURFACE_KIND_ROUTE,
    SURFACE_KIND_SCHEMA,
}

COLLECTION_FIELDS = {
    "members",
    "exports",
    "flags",
    "config_keys",
    "routes",
    "schema_fields",
}


def load_api_symbol_truth_cache(
    project_root: str | Path,
    *,
    cache_path: str | Path = API_SYMBOL_TRUTH_CACHE_PATH,
) -> dict[str, Any]:
    payload = load_project_json_cache(
        project_root,
        cache_path,
        max_bytes=MAX_API_SYMBOL_TRUTH_BYTES,
    )
    if not _valid_cache_payload(payload):
        return _empty_cache_payload()

    surfaces = payload.get("surfaces")
    if not isinstance(surfaces, dict):
        payload["surfaces"] = {}
    else:
        payload["surfaces"] = _valid_surfaces(surfaces)
    return payload


def save_api_symbol_truth_cache(
    project_root: str | Path,
    payload: dict[str, Any],
    *,
    cache_path: str | Path = API_SYMBOL_TRUTH_CACHE_PATH,
) -> bool:
    if not _valid_cache_payload(payload):
        return False
    payload = {
        "schema_version": API_SYMBOL_TRUTH_SCHEMA_VERSION,
        "surfaces": _valid_surfaces(payload.get("surfaces", {})),
    }
    return save_project_json_cache(project_root, cache_path, payload)


def cached_api_symbol_surface(
    project_root: str | Path,
    kind: str,
    name: str,
    *,
    environment_key: str | None = None,
    cache_path: str | Path = API_SYMBOL_TRUTH_CACHE_PATH,
) -> dict[str, Any] | None:
    key = api_symbol_surface_key(kind, name)
    if key is None:
        return None
    payload = load_api_symbol_truth_cache(project_root, cache_path=cache_path)
    surface = payload.get("surfaces", {}).get(key)
    if not isinstance(surface, dict):
        return None
    if surface.get("kind") == SURFACE_KIND_PYTHON_MODULE:
        if not isinstance(environment_key, str) or not environment_key:
            return None
        if surface.get("environment_key") != environment_key:
            return None
    return surface


def cache_api_symbol_surface(
    project_root: str | Path,
    surface: dict[str, Any],
    *,
    cache_path: str | Path = API_SYMBOL_TRUTH_CACHE_PATH,
) -> bool:
    normalized = normalize_api_symbol_surface(surface)
    if normalized is None:
        return False

    payload = load_api_symbol_truth_cache(project_root, cache_path=cache_path)
    surfaces = payload.get("surfaces")
    if not isinstance(surfaces, dict):
        surfaces = {}
    surfaces[api_symbol_surface_key(normalized["kind"], normalized["name"])] = normalized
    payload["surfaces"] = surfaces
    return save_api_symbol_truth_cache(project_root, payload, cache_path=cache_path)


def api_symbol_surface_key(kind: str, name: str) -> str | None:
    safe_kind = _safe_kind(kind)
    safe_name = _safe_name(name)
    if safe_kind is None or safe_name is None:
        return None
    return f"{safe_kind}:{safe_name}"


def python_module_api_symbol_surface(
    surface: dict[str, Any],
    *,
    environment_key: str,
) -> dict[str, Any] | None:
    module_name = surface.get("module")
    safe_name = _safe_name(module_name)
    safe_environment_key = _safe_name(environment_key)
    if safe_name is None or safe_environment_key is None:
        return None

    record = {
        "kind": SURFACE_KIND_PYTHON_MODULE,
        "name": safe_name,
        "source": "python_api_surface",
        "environment_key": safe_environment_key,
        "members": surface.get("members", {}),
    }
    origin = surface.get("origin")
    if isinstance(origin, str) and origin.strip():
        record["origin"] = origin
    captured_at = surface.get("captured_at")
    if isinstance(captured_at, str) and captured_at.strip():
        record["captured_at"] = captured_at
    return normalize_api_symbol_surface(record)


def normalize_api_symbol_surface(surface: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(surface, dict):
        return None

    normalized = _normalized_surface_identity(surface)
    if normalized is None:
        return None
    if not _copy_surface_collections(surface, normalized):
        return None

    for key in ("source", "origin", "version", "captured_at", "environment_key"):
        value = surface.get(key)
        if isinstance(value, str) and value.strip():
            normalized[key] = value.strip()

    metadata = surface.get("metadata")
    if isinstance(metadata, dict):
        normalized["metadata"] = _copy_json_dict(metadata)

    if not any(key in normalized for key in COLLECTION_FIELDS):
        return None
    return normalized


def _normalized_surface_identity(surface: dict[str, Any]) -> dict[str, Any] | None:
    safe_kind = _safe_kind(surface.get("kind"))
    safe_name = _safe_name(surface.get("name"))
    if safe_kind is None or safe_name is None:
        return None
    if safe_kind == SURFACE_KIND_PYTHON_MODULE and not isinstance(
        surface.get("members"),
        dict,
    ):
        return None
    return {"kind": safe_kind, "name": safe_name}


def _copy_surface_collections(
    surface: dict[str, Any],
    normalized: dict[str, Any],
) -> bool:
    safe_kind = str(normalized["kind"])
    for key in COLLECTION_FIELDS:
        value = surface.get(key)
        if safe_kind == SURFACE_KIND_PYTHON_MODULE and key == "members":
            members = _copy_python_members(value)
            if members is None:
                return False
            normalized[key] = members
            continue
        if isinstance(value, dict):
            normalized[key] = _copy_json_dict(value)
        elif isinstance(value, list):
            normalized[key] = _copy_string_list(value)
    return True


def _empty_cache_payload() -> dict[str, Any]:
    return {
        "schema_version": API_SYMBOL_TRUTH_SCHEMA_VERSION,
        "surfaces": {},
    }


def _valid_cache_payload(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    return payload.get("schema_version") == API_SYMBOL_TRUTH_SCHEMA_VERSION


def _valid_surfaces(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    surfaces: dict[str, Any] = {}
    for key, surface in value.items():
        normalized = normalize_api_symbol_surface(surface)
        if normalized is None:
            continue
        expected_key = api_symbol_surface_key(normalized["kind"], normalized["name"])
        if expected_key is None:
            continue
        if str(key) != expected_key:
            continue
        surfaces[expected_key] = normalized
    return surfaces


def _safe_kind(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw not in SURFACE_KINDS:
        return None
    return raw


def _safe_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if len(raw) > 300:
        return None
    if any(ch in raw for ch in "\x00\r\n"):
        return None
    return raw


def _copy_json_dict(value: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = _safe_name(key)
        if safe_key is None:
            continue
        if isinstance(item, dict):
            copied[safe_key] = _copy_json_dict(item)
        elif isinstance(item, list):
            copied[safe_key] = _copy_json_list(item)
        elif isinstance(item, (str, int, float, bool)) or item is None:
            copied[safe_key] = item
    return copied


def _copy_python_members(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    members: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = _safe_name(key)
        if safe_key is None or not isinstance(item, dict):
            return None
        copied = _copy_json_dict(item)
        for nested_key in ("methods", "properties"):
            if nested_key not in item:
                continue
            nested = _copy_python_members(item.get(nested_key))
            if nested is None:
                return None
            copied[nested_key] = nested
        if "parameters" in item:
            parameters = _copy_python_parameters(item.get("parameters"))
            if parameters is None:
                return None
            copied["parameters"] = parameters
        members[safe_key] = copied
    return members


def _copy_python_parameters(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None

    parameters: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        copied = _copy_json_dict(item)
        if _safe_name(copied.get("name")) is None:
            return None
        parameters.append(copied)
    return parameters


def _copy_json_list(value: list[Any]) -> list[Any]:
    copied: list[Any] = []
    for item in value:
        if isinstance(item, dict):
            copied.append(_copy_json_dict(item))
            continue
        safe_item = _safe_name(item)
        if safe_item is not None:
            copied.append(safe_item)
    return copied


def _copy_string_list(value: list[Any]) -> list[str]:
    copied: list[str] = []
    for item in value:
        safe_item = _safe_name(item)
        if safe_item is not None:
            copied.append(safe_item)
    return copied
