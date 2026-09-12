from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import posixpath
import re
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink


REVIEW_CONTEXT_SCHEMA = "skylos.analysis-review-context-v2"
LLM_REVIEW_CONTEXT_SCHEMA = "skylos.llm-review-context-v1"

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})
_CATEGORIES = frozenset(
    {
        "AI_DEFECT",
        "CUSTOM",
        "DEAD_CODE",
        "DEPENDENCY",
        "QUALITY",
        "RELIABILITY",
        "SECRET",
        "SECURITY",
    }
)
_ENABLED_CATEGORIES = frozenset(
    {"ai_defects", "dependencies", "quality", "secrets", "security"}
)
_LLM_REVIEW_CATEGORIES = frozenset({"AI_DEFECT", "QUALITY", "RELIABILITY", "SECURITY"})
_LLM_REVIEW_MODES = frozenset({"agent_hybrid_llm", "agent_llm_only"})
_CONFIG_PROJECTIONS: dict[str, tuple[str, ...]] = {
    "dead_code": (
        "dead_code",
        "exclude",
        "ignore",
        "lower_confidence",
        "masking",
        "non_library_dirs",
        "overrides",
        "whitelist",
        "whitelist_documented",
        "whitelist_temporary",
    ),
    "security": (
        "exclude",
        "ignore",
        "masking",
        "security_contracts",
        "vibe",
    ),
    "ai_defect": (
        "api_signature_modules",
        "exclude",
        "ignore",
        "masking",
        "security_contracts",
        "vibe",
    ),
    "quality": (
        "architecture",
        "check_circular",
        "complexity",
        "duplicate_strings",
        "exclude",
        "god_file_max_definitions",
        "god_file_max_lines",
        "god_file_max_top_level_definitions",
        "ignore",
        "masking",
        "max_args",
        "max_circular_deps",
        "max_lines",
        "nesting",
        "nudges",
        "vibe",
    ),
    # Custom rule bodies carry their own content-derived rule revision.  The
    # effective custom-rules bundle is bound separately in analyzer options.
    "custom": ("exclude", "ignore", "masking"),
    # Secret and dependency analyzers do not currently read project config.
    "secret": (),
    "dependency": (),
}
_MAX_CONTEXT_BYTES = 128_000
_MAX_CONFIG_BYTES = 2_000_000
_MAX_PATHS = 20_000
_MAX_RULES = 2_000
_MAX_PATH_LENGTH = 2_000
_MAX_LLM_SOURCE_BYTES = 4_000_000
_MAX_LLM_SOURCE_TOTAL_BYTES = 32_000_000


class _InvalidContext(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _hash(value: Any, *, maximum_bytes: int = _MAX_CONTEXT_BYTES) -> str:
    encoded = _canonical_json(value).encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise _InvalidContext("review context exceeds its size limit")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded_json(value: Any, *, depth: int = 0, budget: list[int]) -> Any:
    if depth > 12:
        raise _InvalidContext("review context is nested too deeply")
    budget[0] -= 1
    if budget[0] < 0:
        raise _InvalidContext("review context has too many values")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _InvalidContext("review context contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value) > 100_000:
            raise _InvalidContext("review context contains an oversized string")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 20_000:
            raise _InvalidContext("review context contains an oversized list")
        return [_bounded_json(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, dict):
        if len(value) > 5_000:
            raise _InvalidContext("review context contains an oversized mapping")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 1_000:
                raise _InvalidContext("review context contains an invalid key")
            normalized[key] = _bounded_json(
                item,
                depth=depth + 1,
                budget=budget,
            )
        return normalized
    raise _InvalidContext("review context contains an unsupported value")


def _config_hash(config: Any) -> str:
    normalized = _bounded_json(config, budget=[100_000])
    return _hash(normalized, maximum_bytes=_MAX_CONFIG_BYTES)


def _category_config_hashes(config: Any) -> dict[str, str]:
    if not isinstance(config, dict):
        raise _InvalidContext("effective analyzer config is not a mapping")
    return {
        category: _config_hash(review_config_projection(config, category))
        for category in _CONFIG_PROJECTIONS
    }


def review_config_hash_for_category(config: Any, category: str) -> str | None:
    """Hash the effective config projection used by one finding category."""
    normalized_category = str(category).strip().upper()
    config_category = {
        "AI_DEFECT": "ai_defect",
        "CUSTOM": "custom",
        "DEAD_CODE": "dead_code",
        "DEPENDENCY": "dependency",
        "QUALITY": "quality",
        "RELIABILITY": "security",
        "SECRET": "secret",
        "SECURITY": "security",
    }.get(normalized_category)
    if config_category is None:
        return None
    try:
        return _config_hash(review_config_projection(config, config_category))
    except (MemoryError, RecursionError, TypeError, ValueError):
        return None


def review_config_projection(config: Any, category: str) -> dict[str, Any]:
    """Return only effective config keys read by one analyzer category."""
    if not isinstance(config, dict):
        raise _InvalidContext("effective analyzer config is not a mapping")
    keys = _CONFIG_PROJECTIONS.get(str(category).strip().lower())
    if keys is None:
        raise _InvalidContext("unknown analyzer config category")
    projected = {key: config[key] for key in keys if key in config}
    normalized = _bounded_json(projected, budget=[100_000])
    if not isinstance(normalized, dict):
        raise _InvalidContext("effective analyzer config projection is invalid")
    return normalized


def _resolved_root(project_root: str | Path) -> Path:
    return Path(project_root).expanduser().resolve(strict=False)


def _relative_target(value: Any, root: Path) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise _InvalidContext("scan selection contains a non-path value")
    raw = os.fspath(value)
    if not raw or "\x00" in raw or len(raw) > _MAX_PATH_LENGTH:
        raise _InvalidContext("scan selection contains an invalid path")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        relative = candidate.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _InvalidContext("scan selection escapes the project root") from exc
    normalized = relative.as_posix()
    return normalized if normalized else "."


def _relative_changed_file(value: Any, root: Path) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise _InvalidContext("changed-file selection contains a non-path value")
    raw = os.fspath(value)
    if not raw or "\x00" in raw or len(raw) > _MAX_PATH_LENGTH:
        raise _InvalidContext("changed-file selection contains an invalid path")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _InvalidContext(
            "changed-file selection escapes the project root"
        ) from exc
    normalized = relative.as_posix()
    if not normalized or normalized == ".":
        raise _InvalidContext("changed-file selection names the project root")
    return normalized


def _path_selection(values: Any, root: Path, *, changed: bool) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, (str, os.PathLike)):
        candidates = [values]
    else:
        try:
            candidates = list(values)
        except (MemoryError, TypeError) as exc:
            raise _InvalidContext("scan selection is not iterable") from exc
    if len(candidates) > _MAX_PATHS:
        raise _InvalidContext("scan selection contains too many paths")
    normalizer = _relative_changed_file if changed else _relative_target
    return sorted({normalizer(value, root) for value in candidates})


def _exclude_selection(values: Any, root: Path) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, os.PathLike)):
        candidates = [values]
    else:
        try:
            candidates = list(values)
        except (MemoryError, TypeError) as exc:
            raise _InvalidContext("exclude selection is not iterable") from exc
    if len(candidates) > _MAX_PATHS:
        raise _InvalidContext("exclude selection contains too many paths")

    normalized: set[str] = set()
    for value in candidates:
        if not isinstance(value, (str, os.PathLike)):
            raise _InvalidContext("exclude selection contains a non-path value")
        raw = os.fspath(value).strip()
        if not raw or "\x00" in raw or len(raw) > _MAX_PATH_LENGTH:
            raise _InvalidContext("exclude selection contains an invalid path")
        if Path(raw).is_absolute():
            normalized.add(_relative_target(raw, root))
            continue
        portable = posixpath.normpath(raw.replace("\\", "/"))
        if portable == ".." or portable.startswith("../") or portable.startswith("/"):
            raise _InvalidContext("exclude selection escapes the project root")
        normalized.add(portable.removeprefix("./"))
    return sorted(normalized)


def _rule_selection(required_rules: Any) -> list[str]:
    if required_rules is None:
        return []
    values = (
        [required_rules] if isinstance(required_rules, str) else list(required_rules)
    )
    if len(values) > _MAX_RULES:
        raise _InvalidContext("required-rule selection is too large")
    normalized = set()
    for value in values:
        if not isinstance(value, str):
            raise _InvalidContext("required-rule selection contains a non-string")
        rule_id = value.strip().upper()
        if not rule_id or len(rule_id) > 120:
            raise _InvalidContext("required-rule selection contains an invalid rule")
        normalized.add(rule_id)
    return sorted(normalized)


def _optional_text(value: Any, *, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = os.fspath(value) if isinstance(value, os.PathLike) else str(value)
    normalized = value.strip()
    if not normalized:
        return None
    if "\x00" in normalized or len(normalized) > maximum:
        raise _InvalidContext("review option contains invalid text")
    return normalized


def _custom_rules_hash(custom_rules_data: Any, environ: dict[str, str]) -> str | None:
    raw_environment = environ.get("SKYLOS_CUSTOM_RULES")
    if raw_environment:
        if len(raw_environment) > _MAX_CONFIG_BYTES:
            raise _InvalidContext("custom rules exceed their size limit")
        try:
            custom_rules_data = json.loads(raw_environment)
        except (MemoryError, RecursionError, TypeError, ValueError):
            raise _InvalidContext("custom rules are not valid JSON")
    if custom_rules_data in (None, [], {}):
        return None
    return _config_hash(custom_rules_data)


def _isolated_custom_hash(builder) -> tuple[str | None, bool]:
    """Keep incomplete custom extensions from poisoning built-in findings."""
    try:
        return builder(), True
    except (
        MemoryError,
        OSError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return None, False


def _visitor_hash(extra_visitors: Any) -> str | None:
    if extra_visitors is None:
        return None
    try:
        visitors = list(extra_visitors)
    except (MemoryError, TypeError) as exc:
        raise _InvalidContext("custom visitors are not iterable") from exc
    if not visitors:
        return None
    if len(visitors) > 1_000:
        raise _InvalidContext("too many custom visitors")
    records = []
    for visitor in visitors:
        module = getattr(visitor, "__module__", None)
        qualified_name = getattr(visitor, "__qualname__", None)
        if not isinstance(module, str) or not isinstance(qualified_name, str):
            raise _InvalidContext("custom visitor has no stable name")
        try:
            source = inspect.getsource(visitor).replace("\r\n", "\n")
        except (OSError, TypeError) as exc:
            raise _InvalidContext("custom visitor source is unavailable") from exc
        records.append(
            {
                "name": f"{module}.{qualified_name}",
                "source_hash": "sha256:"
                + hashlib.sha256(source.encode("utf-8")).hexdigest(),
            }
        )
    return _hash(sorted(records, key=lambda item: item["name"]))


def build_analysis_review_context(
    project_root: str | Path,
    scan_targets: Any,
    *,
    config: Any,
    threshold: int,
    exclude_folders: Any,
    requested_changed_files: Any,
    effective_changed_files: Any,
    enable_secrets: bool,
    enable_danger: bool,
    enable_quality: bool,
    enable_ai_defects: bool,
    enable_sca: bool,
    enable_dependency_hallucinations: bool,
    grep_verify: bool,
    trace_file: Any,
    required_config_rules: Any,
    dependency_bump_diff_base: Any,
    custom_rules_data: Any,
    extra_visitors: Any,
    analysis_scope: Any,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the checkout-independent analyzer inputs used by review identity."""
    try:
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise _InvalidContext("confidence threshold is not an integer")
        if not 0 <= threshold <= 100:
            raise _InvalidContext("confidence threshold is outside 0-100")
        root = _resolved_root(project_root)
        targets = (
            scan_targets if isinstance(scan_targets, (list, tuple)) else [scan_targets]
        )
        normalized_targets = _path_selection(targets, root, changed=False)
        if not normalized_targets:
            raise _InvalidContext("scan target selection is empty")

        scope_kind = "unknown"
        complete_repository = False
        if isinstance(analysis_scope, dict):
            raw_kind = analysis_scope.get("kind")
            if isinstance(raw_kind, str) and 0 < len(raw_kind) <= 120:
                scope_kind = raw_kind
            complete_repository = analysis_scope.get("complete_repository") is True

        enabled_categories = sorted(
            category
            for category, enabled in (
                ("ai_defects", enable_ai_defects),
                ("dependencies", enable_sca),
                ("quality", enable_quality),
                ("secrets", enable_secrets),
                ("security", enable_danger),
            )
            if enabled
        )
        environment = dict(os.environ if environ is None else environ)
        custom_rules_hash, custom_rules_complete = _isolated_custom_hash(
            lambda: _custom_rules_hash(custom_rules_data, environment)
        )
        custom_visitors_hash, custom_visitors_complete = _isolated_custom_hash(
            lambda: _visitor_hash(extra_visitors)
        )
        payload = {
            "config_hashes": _category_config_hashes(config),
            "scope": {
                "kind": scope_kind,
                "targets": normalized_targets,
                "complete_repository": complete_repository,
                "excluded_folders": _exclude_selection(exclude_folders, root),
                "requested_changed_files": _path_selection(
                    requested_changed_files,
                    root,
                    changed=True,
                ),
                "effective_changed_files": _path_selection(
                    effective_changed_files,
                    root,
                    changed=True,
                ),
            },
            "options": {
                "confidence_threshold": threshold,
                "enabled_categories": enabled_categories,
                "grep_verify": bool(grep_verify),
                "dead_code_liveness": str(
                    environment.get("SKYLOS_DEAD_CODE_LIVENESS", "1")
                ).lower()
                not in _DISABLED_VALUES,
                "trace_mode": (
                    "disabled"
                    if trace_file is False
                    else "default"
                    if trace_file is None
                    else "explicit"
                ),
                "dependency_hallucinations": bool(enable_dependency_hallucinations),
                "required_config_rules": _rule_selection(required_config_rules),
                "dependency_bump_diff_base": _optional_text(
                    dependency_bump_diff_base,
                    maximum=500,
                ),
                "custom_rules_hash": custom_rules_hash,
                "custom_rules_complete": custom_rules_complete,
                "custom_visitors_hash": custom_visitors_hash,
                "custom_visitors_complete": custom_visitors_complete,
            },
        }
        return {
            "schema": REVIEW_CONTEXT_SCHEMA,
            "context_hash": _hash(payload),
            **payload,
        }
    except (
        MemoryError,
        OSError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        # A present but incomplete context prevents identity creation.  It is
        # safer to ask for review again than to reuse a decision across inputs
        # the analyzer could not bind canonically.
        return {"schema": REVIEW_CONTEXT_SCHEMA, "complete": False}


def _selection_summary(values: Any, root: Path, *, allow_none: bool) -> Any:
    if values is None:
        if allow_none:
            return None
        values = []
    normalized = _path_selection(values, root, changed=True)
    if normalized is None:
        normalized = []
    return {
        "count": len(normalized),
        "paths_hash": _hash(normalized, maximum_bytes=_MAX_CONFIG_BYTES),
    }


def _repo_context_hash(value: Any, root: Path) -> str:
    if value is None:
        value = {}
    if not isinstance(value, dict) or len(value) > _MAX_PATHS:
        raise _InvalidContext("LLM repository context is not a bounded mapping")
    normalized = []
    for path, context in value.items():
        relative = _relative_changed_file(path, root)
        if not isinstance(context, str) or len(context) > 200_000:
            raise _InvalidContext("LLM repository context contains invalid text")
        normalized.append({"file": relative, "context": context})
    normalized.sort(key=lambda item: item["file"])
    return _hash(normalized, maximum_bytes=_MAX_CONFIG_BYTES)


def _source_selection_hash(values: Any, root: Path) -> str:
    normalized = _path_selection(values, root, changed=True) or []
    digest = hashlib.sha256(b"skylos-llm-source-selection-v1\0")
    total_bytes = 0
    for relative_path in normalized:
        source = read_project_text_no_symlink(
            root,
            relative_path,
            max_bytes=_MAX_LLM_SOURCE_BYTES,
            encoding="utf-8",
        )
        if source is None:
            raise _InvalidContext("LLM source selection could not be read safely")
        path_bytes = relative_path.encode("utf-8")
        source_bytes = source.encode("utf-8")
        total_bytes += len(source_bytes)
        if total_bytes > _MAX_LLM_SOURCE_TOTAL_BYTES:
            raise _InvalidContext("LLM source selection exceeds its size limit")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(source_bytes).to_bytes(8, "big"))
        digest.update(source_bytes)
    return "sha256:" + digest.hexdigest()


def _llm_definitions_hash(value: Any, root: Path) -> str:
    """Hash the static definition projection that can enter LLM prompts."""
    if value is None:
        value = {}
    if not isinstance(value, dict) or len(value) > _MAX_PATHS:
        raise _InvalidContext("LLM definitions are not a bounded mapping")

    normalized = []
    for key, raw_info in value.items():
        if not isinstance(key, str) or not _valid_llm_text(key, 1_000):
            raise _InvalidContext("LLM definitions contain an invalid name")
        if not isinstance(raw_info, dict):
            raise _InvalidContext("LLM definitions contain invalid metadata")

        name = _optional_text(raw_info.get("name", key), maximum=1_000)
        definition_type = _optional_text(raw_info.get("type", "unknown"), maximum=120)
        if name is None or definition_type is None:
            raise _InvalidContext("LLM definitions contain incomplete metadata")

        raw_file = raw_info.get("file")
        definition_file = None
        if raw_file not in (None, ""):
            definition_file = _relative_changed_file(raw_file, root)

        entry = {
            "key": key,
            "name": name,
            "type": definition_type,
            "file": definition_file,
        }
        for source_key in ("code", "source"):
            source = raw_info.get(source_key)
            if source is None:
                continue
            if not isinstance(source, str) or len(source) > _MAX_LLM_SOURCE_BYTES:
                raise _InvalidContext("LLM definitions contain invalid source text")
            entry[source_key] = source
        # Preserve insertion order: ContextBuilder walks this mapping in order
        # and caps dependency/project-index material included in prompts.
        normalized.append(entry)

    return _hash(normalized, maximum_bytes=_MAX_CONFIG_BYTES)


def build_llm_review_context(
    project_root: str | Path,
    scan_targets: Any,
    *,
    mode: str,
    config: Any,
    exclude_folders: Any,
    requested_changed_files: Any,
    effective_files: Any,
    repo_context_map: Any,
    force_full_file_paths: Any,
    definitions: Any,
    scan_kind: str,
    complete_target: bool,
    model: Any,
    provider: Any,
    base_url: Any,
    min_confidence: Any,
    prompt_revision: Any,
    enable_security: bool,
    enable_quality: bool,
    temperature: float,
    max_tokens: int,
    strict_validation: bool,
    stream: bool,
    smart_filter: bool,
    full_file_review: bool,
    parallel: bool,
    max_workers: int,
    max_chunk_tokens: int,
    batch_functions: bool,
    batch_size: int,
    complexity_threshold: int,
    agent_route: str,
) -> dict[str, Any]:
    """Bind an agent LLM pass to the inputs that shape its findings."""
    try:
        root = _resolved_root(project_root)
        targets = (
            scan_targets if isinstance(scan_targets, (list, tuple)) else [scan_targets]
        )
        normalized_targets = _path_selection(targets, root, changed=False)
        if not normalized_targets:
            raise _InvalidContext("LLM scan target selection is empty")
        if mode not in _LLM_REVIEW_MODES:
            raise _InvalidContext("LLM scan mode is invalid")
        if scan_kind not in {"file", "directory"}:
            raise _InvalidContext("LLM scan kind is invalid")
        if not isinstance(complete_target, bool):
            raise _InvalidContext("LLM scan completeness is invalid")

        model_name = _optional_text(model, maximum=300)
        provider_name = _optional_text(provider, maximum=120)
        if model_name is None or provider_name is None:
            raise _InvalidContext("LLM runtime identity is incomplete")
        if min_confidence not in {"low", "medium", "high"}:
            raise _InvalidContext("LLM confidence selection is invalid")
        if not isinstance(prompt_revision, str) or not _HASH_RE.fullmatch(
            prompt_revision
        ):
            raise _InvalidContext("LLM prompt revision is invalid")
        if agent_route not in {"full", "static_first", "static_only"}:
            raise _InvalidContext("LLM agent route is invalid")
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not math.isfinite(temperature)
            or not 0 <= temperature <= 10
        ):
            raise _InvalidContext("LLM temperature is invalid")
        for name, value, minimum in (
            ("max_tokens", max_tokens, 1),
            ("max_workers", max_workers, 1),
            ("max_chunk_tokens", max_chunk_tokens, 1),
            ("batch_size", batch_size, 1),
            ("complexity_threshold", complexity_threshold, 0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= 1_000_000
            ):
                raise _InvalidContext(f"LLM {name} is invalid")

        raw_base_url = _optional_text(base_url, maximum=2_000)
        payload = {
            "mode": mode,
            "scope": {
                "kind": scan_kind,
                "targets": normalized_targets,
                "complete_target": complete_target,
                "excluded_folders": _exclude_selection(exclude_folders, root),
                "requested_changed_files": _selection_summary(
                    requested_changed_files,
                    root,
                    allow_none=True,
                ),
                "effective_files": _selection_summary(
                    effective_files,
                    root,
                    allow_none=False,
                ),
                "force_full_file_paths": _selection_summary(
                    force_full_file_paths,
                    root,
                    allow_none=False,
                ),
            },
            "analyzer": {
                "config_hash": _config_hash(config),
                "model": model_name,
                "provider": provider_name,
                "endpoint_hash": _hash(raw_base_url) if raw_base_url else None,
                "min_confidence": min_confidence,
                "prompt_revision": prompt_revision,
                "enable_security": bool(enable_security),
                "enable_quality": bool(enable_quality),
                "temperature": temperature,
                "max_tokens": max_tokens,
                "strict_validation": bool(strict_validation),
                "stream": bool(stream),
                "smart_filter": bool(smart_filter),
                "full_file_review": bool(full_file_review),
                "parallel": bool(parallel),
                "max_workers": max_workers,
                "max_chunk_tokens": max_chunk_tokens,
                "batch_functions": bool(batch_functions),
                "batch_size": batch_size,
                "complexity_threshold": complexity_threshold,
                "agent_route": agent_route,
                "repo_context_hash": _repo_context_hash(repo_context_map, root),
                "definitions_hash": _llm_definitions_hash(definitions, root),
                "effective_source_hash": _source_selection_hash(
                    effective_files,
                    root,
                ),
            },
        }
        return {
            "schema": LLM_REVIEW_CONTEXT_SCHEMA,
            "context_hash": _hash(payload),
            **payload,
        }
    except (
        MemoryError,
        OSError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return {"schema": LLM_REVIEW_CONTEXT_SCHEMA, "complete": False}


def _valid_relative_paths(value: Any, *, allow_none: bool) -> bool:
    if value is None:
        return allow_none
    if not isinstance(value, list) or len(value) > _MAX_PATHS:
        return False
    if value != sorted(set(value)):
        return False
    for path in value:
        if not isinstance(path, str) or not path or len(path) > _MAX_PATH_LENGTH:
            return False
        if (
            any(ord(char) < 32 or ord(char) == 127 for char in path)
            or "\\" in path
            or path.startswith("/")
        ):
            return False
        if path == ".." or path.startswith("../"):
            return False
        if path != "." and posixpath.normpath(path) != path:
            return False
    return True


def _validated_payload(context: Any) -> dict[str, Any] | None:
    if not isinstance(context, dict):
        return None
    if set(context) != {
        "schema",
        "context_hash",
        "config_hashes",
        "scope",
        "options",
    }:
        return None
    if context.get("schema") != REVIEW_CONTEXT_SCHEMA:
        return None
    context_hash = context.get("context_hash")
    config_hashes = context.get("config_hashes")
    if not isinstance(context_hash, str) or not _HASH_RE.fullmatch(context_hash):
        return None
    if (
        not isinstance(config_hashes, dict)
        or set(config_hashes) != set(_CONFIG_PROJECTIONS)
        or any(
            not isinstance(value, str) or not _HASH_RE.fullmatch(value)
            for value in config_hashes.values()
        )
    ):
        return None
    scope = context.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "kind",
        "targets",
        "complete_repository",
        "excluded_folders",
        "requested_changed_files",
        "effective_changed_files",
    }:
        return None
    if not isinstance(scope.get("kind"), str) or not 0 < len(scope["kind"]) <= 120:
        return None
    if not isinstance(scope.get("complete_repository"), bool):
        return None
    if not _valid_relative_paths(scope.get("targets"), allow_none=False):
        return None
    if not scope["targets"]:
        return None
    if not _valid_relative_paths(scope.get("excluded_folders"), allow_none=False):
        return None
    if not _valid_relative_paths(scope.get("requested_changed_files"), allow_none=True):
        return None
    if not _valid_relative_paths(scope.get("effective_changed_files"), allow_none=True):
        return None

    options = context.get("options")
    if not isinstance(options, dict) or set(options) != {
        "confidence_threshold",
        "enabled_categories",
        "grep_verify",
        "dead_code_liveness",
        "trace_mode",
        "dependency_hallucinations",
        "required_config_rules",
        "dependency_bump_diff_base",
        "custom_rules_hash",
        "custom_rules_complete",
        "custom_visitors_hash",
        "custom_visitors_complete",
    }:
        return None
    threshold = options.get("confidence_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        return None
    if not 0 <= threshold <= 100:
        return None
    enabled = options.get("enabled_categories")
    if (
        not isinstance(enabled, list)
        or enabled != sorted(set(enabled))
        or any(item not in _ENABLED_CATEGORIES for item in enabled)
    ):
        return None
    for key in ("grep_verify", "dead_code_liveness", "dependency_hallucinations"):
        if not isinstance(options.get(key), bool):
            return None
    for key in ("custom_rules_complete", "custom_visitors_complete"):
        if not isinstance(options.get(key), bool):
            return None
    if options.get("trace_mode") not in {"default", "disabled", "explicit"}:
        return None
    rules = options.get("required_config_rules")
    if (
        not isinstance(rules, list)
        or len(rules) > _MAX_RULES
        or rules != sorted(set(rules))
        or any(
            not isinstance(rule, str) or not rule or len(rule) > 120 for rule in rules
        )
    ):
        return None
    diff_base = options.get("dependency_bump_diff_base")
    if diff_base is not None and (
        not isinstance(diff_base, str) or not diff_base or len(diff_base) > 500
    ):
        return None
    for key in ("custom_rules_hash", "custom_visitors_hash"):
        value = options.get(key)
        if value is not None and (
            not isinstance(value, str) or not _HASH_RE.fullmatch(value)
        ):
            return None

    payload = {
        "config_hashes": config_hashes,
        "scope": scope,
        "options": options,
    }
    try:
        if _hash(payload) != context_hash:
            return None
    except (MemoryError, RecursionError, TypeError, ValueError):
        return None
    return payload


def _valid_selection_summary(value: Any, *, allow_none: bool) -> bool:
    if value is None:
        return allow_none
    if not isinstance(value, dict) or set(value) != {"count", "paths_hash"}:
        return False
    count = value.get("count")
    paths_hash = value.get("paths_hash")
    return (
        isinstance(count, int)
        and not isinstance(count, bool)
        and 0 <= count <= _MAX_PATHS
        and isinstance(paths_hash, str)
        and bool(_HASH_RE.fullmatch(paths_hash))
    )


def _valid_llm_text(value: Any, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 0 < len(value) <= maximum
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _validated_llm_payload(context: Any) -> dict[str, Any] | None:
    if not isinstance(context, dict) or set(context) != {
        "schema",
        "context_hash",
        "mode",
        "scope",
        "analyzer",
    }:
        return None
    if (
        context.get("schema") != LLM_REVIEW_CONTEXT_SCHEMA
        or context.get("mode") not in _LLM_REVIEW_MODES
    ):
        return None
    context_hash = context.get("context_hash")
    if not isinstance(context_hash, str) or not _HASH_RE.fullmatch(context_hash):
        return None

    scope = context.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "kind",
        "targets",
        "complete_target",
        "excluded_folders",
        "requested_changed_files",
        "effective_files",
        "force_full_file_paths",
    }:
        return None
    if scope.get("kind") not in {"file", "directory"}:
        return None
    if not isinstance(scope.get("complete_target"), bool):
        return None
    if not _valid_relative_paths(scope.get("targets"), allow_none=False):
        return None
    if not scope["targets"]:
        return None
    if not _valid_relative_paths(scope.get("excluded_folders"), allow_none=False):
        return None
    if not _valid_selection_summary(
        scope.get("requested_changed_files"), allow_none=True
    ):
        return None
    if not _valid_selection_summary(scope.get("effective_files"), allow_none=False):
        return None
    if not _valid_selection_summary(
        scope.get("force_full_file_paths"), allow_none=False
    ):
        return None

    analyzer = context.get("analyzer")
    if not isinstance(analyzer, dict) or set(analyzer) != {
        "config_hash",
        "model",
        "provider",
        "endpoint_hash",
        "min_confidence",
        "prompt_revision",
        "enable_security",
        "enable_quality",
        "temperature",
        "max_tokens",
        "strict_validation",
        "stream",
        "smart_filter",
        "full_file_review",
        "parallel",
        "max_workers",
        "max_chunk_tokens",
        "batch_functions",
        "batch_size",
        "complexity_threshold",
        "agent_route",
        "repo_context_hash",
        "definitions_hash",
        "effective_source_hash",
    }:
        return None
    for key in (
        "config_hash",
        "prompt_revision",
        "repo_context_hash",
        "definitions_hash",
        "effective_source_hash",
    ):
        value = analyzer.get(key)
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            return None
    endpoint_hash = analyzer.get("endpoint_hash")
    if endpoint_hash is not None and (
        not isinstance(endpoint_hash, str) or not _HASH_RE.fullmatch(endpoint_hash)
    ):
        return None
    if not _valid_llm_text(analyzer.get("model"), 300):
        return None
    if not _valid_llm_text(analyzer.get("provider"), 120):
        return None
    if analyzer.get("min_confidence") not in {"low", "medium", "high"}:
        return None
    if analyzer.get("agent_route") not in {"full", "static_first", "static_only"}:
        return None
    for key in (
        "enable_security",
        "enable_quality",
        "strict_validation",
        "stream",
        "smart_filter",
        "full_file_review",
        "parallel",
        "batch_functions",
    ):
        if not isinstance(analyzer.get(key), bool):
            return None
    temperature = analyzer.get("temperature")
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(temperature)
        or not 0 <= temperature <= 10
    ):
        return None
    for key, minimum in (
        ("max_tokens", 1),
        ("max_workers", 1),
        ("max_chunk_tokens", 1),
        ("batch_size", 1),
        ("complexity_threshold", 0),
    ):
        value = analyzer.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= 1_000_000
        ):
            return None

    payload = {
        "mode": context["mode"],
        "scope": scope,
        "analyzer": analyzer,
    }
    try:
        if _hash(payload) != context_hash:
            return None
    except (MemoryError, RecursionError, TypeError, ValueError):
        return None
    return payload


def review_context_hash_for_category(
    context: Any,
    category: str,
    *,
    effective_config_hash: str | None = None,
) -> str | None:
    """Validate a context and return only inputs material to ``category``."""
    normalized_category = str(category).strip().upper()
    if isinstance(context, dict) and context.get("schema") == LLM_REVIEW_CONTEXT_SCHEMA:
        payload = _validated_llm_payload(context)
        if (
            payload is None
            or normalized_category not in _LLM_REVIEW_CATEGORIES
            or effective_config_hash is not None
        ):
            return None
        try:
            return _hash(
                {
                    "schema": LLM_REVIEW_CONTEXT_SCHEMA,
                    "category": normalized_category,
                    **payload,
                }
            )
        except (MemoryError, RecursionError, TypeError, ValueError):
            return None

    payload = _validated_payload(context)
    if payload is None or normalized_category not in _CATEGORIES:
        return None

    options = payload["options"]
    full_scope = payload["scope"]
    selected_scope = {
        "kind": full_scope["kind"],
        "targets": full_scope["targets"],
        "complete_repository": full_scope["complete_repository"],
        "excluded_folders": full_scope["excluded_folders"],
    }
    if normalized_category != "DEPENDENCY":
        selected_scope["requested_changed_files"] = full_scope[
            "requested_changed_files"
        ]
    if normalized_category in {
        "AI_DEFECT",
        "QUALITY",
        "RELIABILITY",
        "SECURITY",
    }:
        # These categories have repository/diff passes after the static worker
        # and can therefore consume Skylos's auto-detected Git selection.
        selected_scope["effective_changed_files"] = full_scope[
            "effective_changed_files"
        ]

    common = {
        "schema": REVIEW_CONTEXT_SCHEMA,
        "category": normalized_category,
        "scope": selected_scope,
    }
    if normalized_category == "DEAD_CODE":
        config_category = "dead_code"
        selected_options = {
            "confidence_threshold": options["confidence_threshold"],
            "grep_verify": options["grep_verify"],
            "dead_code_liveness": options["dead_code_liveness"],
            "trace_mode": options["trace_mode"],
        }
    elif normalized_category in {"SECURITY", "RELIABILITY"}:
        if not options["custom_visitors_complete"]:
            return None
        config_category = "security"
        selected_options = {
            "enabled": "security" in options["enabled_categories"],
            "required_config_rules": options["required_config_rules"],
            "custom_visitors_hash": options["custom_visitors_hash"],
        }
    elif normalized_category == "AI_DEFECT":
        if not options["custom_visitors_complete"]:
            return None
        config_category = "ai_defect"
        selected_options = {
            "enabled": "ai_defects" in options["enabled_categories"],
            "security_enabled": "security" in options["enabled_categories"],
            "dependency_hallucinations": options["dependency_hallucinations"],
            "dependency_bump_diff_base": options["dependency_bump_diff_base"],
            "custom_visitors_hash": options["custom_visitors_hash"],
        }
    elif normalized_category == "QUALITY":
        config_category = "quality"
        selected_options = {
            "enabled": "quality" in options["enabled_categories"],
        }
    elif normalized_category == "CUSTOM":
        if not options["custom_rules_complete"]:
            return None
        config_category = "custom"
        selected_options = {
            "custom_rules_hash": options["custom_rules_hash"],
        }
    elif normalized_category == "SECRET":
        config_category = "secret"
        selected_options = {
            "enabled": "secrets" in options["enabled_categories"],
        }
    else:
        config_category = "dependency"
        selected_options = {
            "enabled": "dependencies" in options["enabled_categories"],
        }
    config_hash = payload["config_hashes"][config_category]
    if effective_config_hash is not None:
        if not isinstance(effective_config_hash, str) or not _HASH_RE.fullmatch(
            effective_config_hash
        ):
            return None
        config_hash = _hash(
            {
                "root_config_hash": config_hash,
                "effective_file_config_hash": effective_config_hash,
            }
        )
    common["config_hash"] = config_hash
    common["options"] = selected_options
    try:
        return _hash(common)
    except (MemoryError, RecursionError, TypeError, ValueError):
        return None


def review_context_is_valid(context: Any) -> bool:
    if isinstance(context, dict) and context.get("schema") == LLM_REVIEW_CONTEXT_SCHEMA:
        return _validated_llm_payload(context) is not None
    return _validated_payload(context) is not None
