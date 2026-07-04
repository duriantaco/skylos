from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import re
import site
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from skylos.core.api_symbol_truth import (
    cache_api_symbol_surface,
    python_module_api_symbol_surface,
)
from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache


PYTHON_API_SURFACE_SCHEMA_VERSION = 1
PYTHON_API_SURFACE_CACHE_PATH = Path(".skylos") / "cache" / "python_api_surface.json"
MAX_PYTHON_API_SURFACE_BYTES = 10_000_000
MAX_MODULE_MEMBERS = 500
MAX_CLASS_MEMBERS = 200

Importer = Callable[[str], ModuleType]


def load_python_api_surface_cache(
    project_root: str | Path,
    *,
    cache_path: str | Path = PYTHON_API_SURFACE_CACHE_PATH,
) -> dict[str, Any]:
    payload = load_project_json_cache(
        project_root,
        cache_path,
        max_bytes=MAX_PYTHON_API_SURFACE_BYTES,
    )
    if not _valid_cache_payload(payload):
        return _empty_cache_payload()

    environment = payload.get("environment")
    if not isinstance(environment, dict):
        return _empty_cache_payload()
    if environment.get("key") != python_environment_key():
        return _empty_cache_payload()

    modules = payload.get("modules")
    if not isinstance(modules, dict):
        payload["modules"] = {}
    return payload


def save_python_api_surface_cache(
    project_root: str | Path,
    payload: dict[str, Any],
    *,
    cache_path: str | Path = PYTHON_API_SURFACE_CACHE_PATH,
) -> bool:
    if not _valid_cache_payload(payload):
        return False
    return save_project_json_cache(project_root, cache_path, payload)


def cached_python_api_surface(
    project_root: str | Path,
    module_name: str,
    *,
    cache_path: str | Path = PYTHON_API_SURFACE_CACHE_PATH,
) -> dict[str, Any] | None:
    safe_name = _safe_module_name(module_name)
    if safe_name is None:
        return None

    payload = load_python_api_surface_cache(project_root, cache_path=cache_path)
    modules = _modules_map(payload)
    surface = modules.get(safe_name)
    if not isinstance(surface, dict):
        return None
    return surface


def cache_python_api_surface(
    project_root: str | Path,
    module_name: str,
    *,
    cache_path: str | Path = PYTHON_API_SURFACE_CACHE_PATH,
    importer: Importer | None = None,
) -> dict[str, Any] | None:
    safe_name = _safe_module_name(module_name)
    if safe_name is None:
        return None

    surface = build_python_api_surface(safe_name, importer=importer)
    if surface is None:
        return None

    payload = load_python_api_surface_cache(project_root, cache_path=cache_path)
    modules = _modules_map(payload)
    modules[safe_name] = surface
    payload["modules"] = modules
    save_python_api_surface_cache(project_root, payload, cache_path=cache_path)
    shared_surface = python_module_api_symbol_surface(
        surface,
        environment_key=python_environment_key(),
    )
    if shared_surface is not None:
        cache_api_symbol_surface(project_root, shared_surface)
    return surface


def build_python_api_surface(
    module_name: str,
    *,
    importer: Importer | None = None,
) -> dict[str, Any] | None:
    safe_name = _safe_module_name(module_name)
    if safe_name is None:
        return None

    resolved_importer = _importer(importer)
    try:
        module = resolved_importer(safe_name)
    except (ImportError, AttributeError, TypeError, ValueError):
        return None

    if not isinstance(module, ModuleType):
        return None

    return {
        "module": safe_name,
        "origin": _module_origin(module),
        "captured_at": _utc_timestamp(),
        "members": _module_members(module),
    }


def python_environment_key() -> str:
    environment = _environment_info()
    key = environment.get("key")
    if isinstance(key, str):
        return key
    return ""


def _empty_cache_payload() -> dict[str, Any]:
    return {
        "schema_version": PYTHON_API_SURFACE_SCHEMA_VERSION,
        "environment": _environment_info(),
        "modules": {},
    }


def _valid_cache_payload(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("schema_version") != PYTHON_API_SURFACE_SCHEMA_VERSION:
        return False
    return True


def _modules_map(payload: dict[str, Any]) -> dict[str, Any]:
    modules = payload.get("modules")
    if not isinstance(modules, dict):
        return {}

    safe_modules: dict[str, Any] = {}
    for name, surface in modules.items():
        safe_name = _safe_module_name(str(name))
        if safe_name is None:
            continue
        if isinstance(surface, dict):
            safe_modules[safe_name] = surface
    return safe_modules


def _safe_module_name(value: str) -> str | None:
    raw = str(value).strip()
    if not raw:
        return None

    parts = raw.split(".")
    for part in parts:
        if not part:
            return None
        if not part.isidentifier():
            return None
    return raw


def _importer(importer: Importer | None) -> Importer:
    if importer is not None:
        return importer
    return importlib.import_module


def _module_origin(module: ModuleType) -> str:
    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str):
        return ""
    return origin


def _module_members(module: ModuleType) -> dict[str, Any]:
    members: dict[str, Any] = {}
    for name in _public_names(module, MAX_MODULE_MEMBERS):
        try:
            value = getattr(module, name)
        except Exception:
            continue

        entry = _member_entry(value)
        if entry is None:
            continue
        members[name] = entry
    return members


def _member_entry(value: Any) -> dict[str, Any] | None:
    if inspect.isclass(value):
        return _class_entry(value)
    if _callable_member(value):
        return _callable_entry(value)
    return None


def _class_entry(value: type) -> dict[str, Any]:
    return {
        "kind": "class",
        "signature": _signature_for(value),
        "parameters": _parameters_for(value),
        "methods": _class_methods(value),
        "properties": _class_properties(value),
    }


def _class_methods(value: type) -> dict[str, Any]:
    methods: dict[str, Any] = {}
    for name in _public_names(value, MAX_CLASS_MEMBERS):
        try:
            member = getattr(value, name)
        except Exception:
            continue

        if not _callable_member(member):
            continue

        methods[name] = {
            "kind": "method",
            "signature": _signature_for(member),
            "parameters": _parameters_for(member),
        }
    return methods


def _class_properties(value: type) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for name in _public_names(value, MAX_CLASS_MEMBERS):
        try:
            member = getattr(value, name)
        except Exception:
            continue

        resource_class = _property_resource_class(member, value)
        if resource_class is None:
            continue
        properties[name] = {
            "kind": "property",
            "class": resource_class.__name__,
            "methods": _class_methods(resource_class),
        }
    return properties


def _property_resource_class(member: Any, owner: type) -> type | None:
    getter = _property_getter(member)
    if getter is None:
        return None

    resource_class = _property_annotation_class(getter)
    if resource_class is not None:
        return resource_class
    return _property_source_import_class(getter, owner)


def _property_getter(member: Any) -> Any | None:
    getter = getattr(member, "fget", None)
    if getter is not None:
        return getter

    getter = getattr(member, "func", None)
    if getter is not None:
        return getter
    return None


def _property_annotation_class(getter: Any) -> type | None:
    annotations = getattr(getter, "__annotations__", {})
    if not isinstance(annotations, dict):
        return None

    return_value = annotations.get("return")
    if inspect.isclass(return_value):
        return return_value
    return None


def _property_source_import_class(getter: Any, owner: type) -> type | None:
    try:
        source = inspect.getsource(getter)
    except (OSError, TypeError):
        return None

    return_name = _return_annotation_name(getter)
    if return_name is None:
        return None

    import_module = _source_import_module(source, return_name, owner)
    if import_module is None:
        return None

    try:
        module = importlib.import_module(import_module)
        candidate = getattr(module, return_name)
    except (AttributeError, ImportError, ValueError):
        return None

    if inspect.isclass(candidate):
        return candidate
    return None


def _return_annotation_name(getter: Any) -> str | None:
    annotations = getattr(getter, "__annotations__", {})
    if not isinstance(annotations, dict):
        return None

    return_value = annotations.get("return")
    if not isinstance(return_value, str):
        return None
    if not return_value.isidentifier():
        return None
    return return_value


def _source_import_module(source: str, class_name: str, owner: type) -> str | None:
    pattern = re.compile(
        r"from\s+([.\w]+)\s+import\s+" + re.escape(class_name) + r"\b"
    )
    match = pattern.search(source)
    if match is None:
        return None

    module_name = match.group(1)
    if module_name.startswith("."):
        package = _owner_package(owner)
        try:
            return importlib.util.resolve_name(module_name, package)
        except (ImportError, ValueError):
            return None
    return module_name


def _owner_package(owner: type) -> str:
    module_name = getattr(owner, "__module__", "")
    if not isinstance(module_name, str):
        return ""
    if "." not in module_name:
        return module_name
    return module_name.rsplit(".", 1)[0]


def _callable_entry(value: Any) -> dict[str, Any]:
    return {
        "kind": "function",
        "signature": _signature_for(value),
        "parameters": _parameters_for(value),
    }


def _callable_member(value: Any) -> bool:
    if inspect.isfunction(value):
        return True
    if inspect.isbuiltin(value):
        return True
    if inspect.ismethod(value):
        return True
    return callable(value)


def _signature_for(value: Any) -> str:
    try:
        signature = inspect.signature(value)
    except Exception:
        return ""
    return str(signature)


def _parameters_for(value: Any) -> list[dict[str, Any]]:
    try:
        signature = inspect.signature(value)
    except Exception:
        return []

    parameters: list[dict[str, Any]] = []
    for name, parameter in signature.parameters.items():
        parameters.append(
            {
                "name": name,
                "kind": parameter.kind.name,
                "required": parameter.default is inspect._empty,
            }
        )
    return parameters


def _public_names(value: Any, limit: int) -> list[str]:
    names: list[str] = []
    try:
        raw_names = dir(value)
    except Exception:
        return names

    for name in raw_names:
        if len(names) >= limit:
            break
        if not isinstance(name, str):
            continue
        if name.startswith("_"):
            continue
        names.append(name)
    return names


def _environment_info() -> dict[str, Any]:
    info = {
        "key": "",
        "executable": sys.executable,
        "version": sys.version,
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "site_paths": _site_paths(),
    }
    raw = json.dumps(info, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    info["key"] = digest[:16]
    return info


def _site_paths() -> list[str]:
    paths: list[str] = []
    try:
        for path in site.getsitepackages():
            paths.append(str(path))
    except (AttributeError, OSError):
        pass

    try:
        user_site = site.getusersitepackages()
    except (AttributeError, OSError):
        user_site = ""

    if user_site:
        paths.append(str(user_site))
    return sorted(paths)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
