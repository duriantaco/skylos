from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any


DEFAULT_REASON = "configured dead-code entrypoint"


def configured_entrypoint_reason(
    def_obj: Any,
    analyzer: Any,
    cfg: dict | None,
) -> str | None:

    rules = _entrypoint_rules(cfg)
    if not rules:
        return None

    for rule in rules:
        if _has_specific_selector(rule) and _matches_rule(def_obj, analyzer, rule):
            reason = rule.get("reason")
            matched_reason = DEFAULT_REASON
            if isinstance(reason, str) and reason:
                matched_reason = reason
            return matched_reason
    return None


def _entrypoint_rules(cfg: dict | None) -> list[dict]:
    if not isinstance(cfg, dict):
        return []
    dead_code = cfg.get("dead_code")
    if not isinstance(dead_code, dict):
        return []
    rules = dead_code.get("entrypoints")
    if not isinstance(rules, list):
        return []
    entrypoint_rules: list[dict] = []
    for rule in rules:
        if isinstance(rule, dict):
            entrypoint_rules.append(rule)
    return entrypoint_rules


def _matches_rule(def_obj: Any, analyzer: Any, rule: dict) -> bool:
    if not _matches_values(rule.get("type"), [str(getattr(def_obj, "type", ""))]):
        return False
    if not _matches_values(
        rule.get("name"),
        [
            str(getattr(def_obj, "simple_name", "")),
            _display_name(def_obj),
        ],
    ):
        return False
    if not _matches_values(rule.get("full_name"), [str(getattr(def_obj, "name", ""))]):
        return False
    decorator_patterns = _combined_values(rule, "decorator", "decorators")
    if decorator_patterns and not _matches_values(
        decorator_patterns, _decorator_candidates(def_obj)
    ):
        return False
    base_patterns = _combined_values(rule, "base_class", "base_classes")
    if base_patterns and not _matches_values(
        base_patterns, _base_class_candidates(def_obj)
    ):
        return False

    parent = rule.get("parent")
    if isinstance(parent, dict) and not _matches_parent(def_obj, analyzer, parent):
        return False
    path_patterns = _as_list(rule.get("path"))
    if path_patterns and not _matches_values(
        path_patterns, _path_candidates(def_obj, analyzer)
    ):
        return False
    module_patterns = _as_list(rule.get("module"))
    if module_patterns and not _matches_values(
        module_patterns, _module_candidates(def_obj, analyzer)
    ):
        return False

    return True


def _has_specific_selector(rule: dict) -> bool:
    for key in (
        "name",
        "full_name",
        "decorator",
        "decorators",
        "base_class",
        "base_classes",
    ):
        if _as_list(rule.get(key)):
            return True
    has_parent_selector = isinstance(rule.get("parent"), dict)
    return has_parent_selector


def _display_name(def_obj: Any) -> str:
    name = str(getattr(def_obj, "name", ""))
    if getattr(def_obj, "type", None) == "method" and "." in name:
        parts = name.split(".")
        if len(parts) >= 2:
            display_name = ".".join(parts[-2:])
            return display_name
    display_name = str(getattr(def_obj, "simple_name", ""))
    return display_name


def _matches_parent(def_obj: Any, analyzer: Any, rule: dict) -> bool:
    parent = _parent_definition(def_obj, analyzer)
    if parent is None:
        return False

    if not _matches_values(
        rule.get("name"),
        [
            str(getattr(parent, "simple_name", "")),
            str(getattr(parent, "name", "")).rsplit(".", 1)[-1],
        ],
    ):
        return False
    if not _matches_values(rule.get("full_name"), [str(getattr(parent, "name", ""))]):
        return False
    base_patterns = _combined_values(rule, "base_class", "base_classes")
    if base_patterns and not _matches_values(
        base_patterns, _base_class_candidates(parent)
    ):
        return False
    path_patterns = _as_list(rule.get("path"))
    if path_patterns and not _matches_values(
        path_patterns, _path_candidates(parent, analyzer)
    ):
        return False
    module_patterns = _as_list(rule.get("module"))
    if module_patterns and not _matches_values(
        module_patterns, _module_candidates(parent, analyzer)
    ):
        return False
    return True


def _parent_definition(def_obj: Any, analyzer: Any) -> Any | None:
    name = str(getattr(def_obj, "name", ""))
    if "." not in name:
        return None

    parent_name = name.rsplit(".", 1)[0]
    defs = getattr(analyzer, "defs", {})
    if isinstance(defs, dict):
        direct = defs.get(parent_name)
        if direct is not None and getattr(direct, "type", None) == "class":
            return direct

        parent_simple = parent_name.rsplit(".", 1)[-1]
        filename = str(getattr(def_obj, "filename", ""))
        for candidate in defs.values():
            if getattr(candidate, "type", None) != "class":
                continue
            if str(getattr(candidate, "simple_name", "")) != parent_simple:
                continue
            if str(getattr(candidate, "filename", "")) == filename:
                return candidate
    return None


def _matches_values(patterns: Any, candidates: list[str]) -> bool:
    normalized_patterns = _as_list(patterns)
    if not normalized_patterns:
        return True

    normalized_candidates: list[str] = []
    for candidate in candidates:
        if candidate:
            normalized_candidates.append(candidate)
    if not normalized_candidates:
        return False

    for pattern in normalized_patterns:
        for candidate in normalized_candidates:
            if fnmatch.fnmatchcase(candidate, pattern):
                return True
    return False


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings: list[str] = []
        for item in value:
            if isinstance(item, str):
                strings.append(item)
        return strings
    return []


def _combined_values(rule: dict, singular: str, plural: str) -> list[str]:
    values: list[str] = []
    values.extend(_as_list(rule.get(singular)))
    values.extend(_as_list(rule.get(plural)))
    return values


def _decorator_candidates(def_obj: Any) -> list[str]:
    candidates: list[str] = []
    for decorator in _string_attribute_values(def_obj, "decorators"):
        text = str(decorator).lstrip("@")
        if not text:
            continue
        candidates.append(text)
        candidates.append(text.rsplit(".", 1)[-1])
    return candidates


def _base_class_candidates(def_obj: Any) -> list[str]:
    candidates: list[str] = []
    for base in _string_attribute_values(def_obj, "base_classes"):
        text = str(base)
        if not text:
            continue
        candidates.append(text)
        candidates.append(text.rsplit(".", 1)[-1])
    return candidates


def _string_attribute_values(def_obj: Any, name: str) -> list[str]:
    value = getattr(def_obj, name, [])
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        strings: list[str] = []
        for item in value:
            if isinstance(item, str):
                strings.append(item)
        return strings
    return []


def _path_candidates(def_obj: Any, analyzer: Any) -> list[str]:
    filename = str(getattr(def_obj, "filename", ""))
    if not filename:
        return []

    path = Path(filename)
    candidates = [filename.replace("\\", "/"), path.name]
    root = getattr(analyzer, "_project_root", None)
    if root:
        try:
            rel = path.resolve().relative_to(Path(root).resolve())
            candidates.append(str(rel).replace("\\", "/"))
        except (OSError, ValueError):
            pass
    return _dedupe(candidates)


def _module_candidates(def_obj: Any, analyzer: Any) -> list[str]:
    candidates: list[str] = []
    path_modules = _module_candidates_from_path(def_obj, analyzer)
    candidates.extend(path_modules)

    full_name = str(getattr(def_obj, "name", ""))
    for module in path_modules:
        if full_name == module or full_name.startswith(f"{module}."):
            candidates.append(module)
    return _dedupe(candidates)


def _module_candidates_from_path(def_obj: Any, analyzer: Any) -> list[str]:
    filename = str(getattr(def_obj, "filename", ""))
    if not filename:
        return []

    path = Path(filename)
    root = getattr(analyzer, "_project_root", None)
    if root:
        try:
            rel = path.resolve().relative_to(Path(root).resolve())
        except (OSError, ValueError):
            rel = path
    else:
        rel = path

    if rel.suffix not in {".py", ".pyi", ".pyw"}:
        return []

    rel_no_suffix = rel.with_suffix("")
    parts = list(rel_no_suffix.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    module = ".".join(part for part in parts if part and part != ".")
    modules: list[str] = []
    if module:
        modules.append(module)
    return modules


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
