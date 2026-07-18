from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .schema import AgentBehaviorError


MAX_YAML_DEPTH = 32
MAX_YAML_NODES = 20_000
MAX_TEXT_LENGTH = 100_000
MAX_SCENARIOS = 1_000
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SAFE_TOOL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def resolve_project_file(path: str | Path, root: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise AgentBehaviorError(f"{label} must stay inside the project") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AgentBehaviorError(f"{label} must stay inside the project")
    current = root
    try:
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                if current == candidate:
                    raise AgentBehaviorError(f"{label} must not be a symlink")
                raise AgentBehaviorError(
                    f"{label} must not use symlink parent directories"
                )
    except OSError as exc:
        raise AgentBehaviorError(
            f"Could not inspect {label.lower()}: {candidate}"
        ) from exc
    return root.joinpath(*relative.parts)


def resolved_root(project_root: str | Path) -> Path:
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise AgentBehaviorError(f"Project root is invalid: {project_root}") from exc
    if not root.is_dir():
        raise AgentBehaviorError(f"Project root is not a directory: {root}")
    return root


def validate_loaded_shape(value: Any, label: str) -> None:
    seen: set[int] = set()
    active: set[int] = set()
    count = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal count
        if depth > MAX_YAML_DEPTH:
            raise AgentBehaviorError(f"{label} nesting exceeds {MAX_YAML_DEPTH}")
        count += 1
        if count > MAX_YAML_NODES:
            raise AgentBehaviorError(f"{label} exceeds {MAX_YAML_NODES} values")
        if isinstance(item, str) and len(item) > MAX_TEXT_LENGTH:
            raise AgentBehaviorError(f"{label} contains an oversized string")
        if not isinstance(item, dict | list):
            return
        identity = id(item)
        if identity in active:
            raise AgentBehaviorError(f"{label} contains a recursive YAML alias")
        if identity in seen:
            raise AgentBehaviorError(f"{label} contains a YAML alias")
        seen.add(identity)
        active.add(identity)
        values = item.items() if isinstance(item, dict) else enumerate(item)
        for key, child in values:
            visit(key, depth + 1)
            visit(child, depth + 1)
        active.remove(identity)

    visit(value, 0)


def load_unique_yaml(source: str, yaml_module: Any) -> Any:
    class UniqueKeyLoader(yaml_module.SafeLoader):
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml_module.events.AliasEvent):
                raise AgentBehaviorError("Contract contains a YAML alias")
            return super().compose_node(parent, index)

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise AgentBehaviorError(
                    "Contract mapping keys must be scalar"
                ) from exc
            if duplicate:
                raise AgentBehaviorError(f"Duplicate contract mapping key: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml_module.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    loader = UniqueKeyLoader(source)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentBehaviorError(f"Duplicate observation mapping key: {key!r}")
        result[key] = value
    return result


def mapping(value: Any, field: str, *, required: bool = False) -> dict[str, Any]:
    if value is None and not required:
        return {}
    if not isinstance(value, dict):
        raise AgentBehaviorError(f"{field} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        raise AgentBehaviorError(f"{field} keys must be strings")
    return value


def json_mapping(value: Any, field: str) -> dict[str, Any]:
    raw = mapping(value, field, required=True)
    try:
        json.dumps(raw, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise AgentBehaviorError(f"{field} must contain JSON values") from exc
    return dict(raw)


def list_value(value: Any, field: str, *, required: bool = False) -> list[Any]:
    if value is None and not required:
        return []
    if not isinstance(value, list):
        raise AgentBehaviorError(f"{field} must be a list")
    return value


def string_list(value: Any, field: str) -> list[str]:
    return [
        parse_text(item, f"{field}[{index}]")
        for index, item in enumerate(list_value(value, field))
    ]


def tool_name_list(value: Any, field: str) -> list[str]:
    return [
        tool_name(item, f"{field}[{index}]")
        for index, item in enumerate(list_value(value, field))
    ]


def required_text(raw: dict[str, Any], key: str, field: str) -> str:
    if key not in raw:
        raise AgentBehaviorError(f"{field} is required")
    return parse_text(raw.get(key), field)


def optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return parse_text(value, field)


def parse_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentBehaviorError(f"{field} must be a non-empty string")
    if len(value) > MAX_TEXT_LENGTH:
        raise AgentBehaviorError(f"{field} exceeds {MAX_TEXT_LENGTH} characters")
    return value.strip()


def safe_id(value: Any, field: str) -> str:
    identifier = parse_text(value, field)
    if not _SAFE_ID_RE.fullmatch(identifier):
        raise AgentBehaviorError(
            f"{field} must use 1-96 letters, numbers, dots, underscores, or hyphens"
        )
    return identifier


def tool_name(value: Any, field: str) -> str:
    name = parse_text(value, field)
    if not _SAFE_TOOL_RE.fullmatch(name):
        raise AgentBehaviorError(
            f"{field} must use 1-64 letters, numbers, underscores, or hyphens"
        )
    return name


def required_int(raw: dict[str, Any], key: str, field: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AgentBehaviorError(f"{field} must be an integer")
    return value


def number(value: Any, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise AgentBehaviorError(f"{field} must be a number")
    if not math.isfinite(value):
        raise AgentBehaviorError(f"{field} must be finite")
    return value


def boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AgentBehaviorError(f"{field} must be true or false")
    return value


def reject_unknown(raw: dict[str, Any], allowed: set[str], field: str) -> None:
    for key in raw:
        if key not in allowed:
            prefix = f"{field}." if field else ""
            raise AgentBehaviorError(f"Unknown behavior contract key: {prefix}{key}")


def reject_duplicates(values: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    if duplicates:
        raise AgentBehaviorError(f"Duplicate {label}: {sorted(duplicates)}")
