from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.core.reference_index import (
    INDEX_CACHE_PATH,
    build_empty_index,
    file_signature,
    validate_index_payload,
)
from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache


MAX_REFERENCE_INDEX_BYTES = 20_000_000


def load_reference_index(
    project_root: str | Path,
    *,
    cache_path: str | Path = INDEX_CACHE_PATH,
) -> dict[str, Any] | None:
    payload = load_project_json_cache(
        project_root,
        cache_path,
        max_bytes=MAX_REFERENCE_INDEX_BYTES,
    )
    if not payload:
        return None
    if not validate_index_payload(payload):
        return None
    if not _project_root_matches(payload, project_root):
        return None

    _ensure_content_graphs(payload)
    return payload


def save_reference_index(
    project_root: str | Path,
    payload: dict[str, Any],
    *,
    cache_path: str | Path = INDEX_CACHE_PATH,
) -> bool:
    if not validate_index_payload(payload):
        return False
    if not _project_root_matches(payload, project_root):
        return False

    _ensure_content_graphs(payload)
    return save_project_json_cache(project_root, cache_path, payload)


def record_file_graph(
    project_root: str | Path,
    payload: dict[str, Any] | None,
    file_path: str | Path,
    *,
    definitions: dict[str, Any] | None = None,
    references: list[dict[str, Any]] | None = None,
    imports: list[Any] | None = None,
) -> dict[str, Any] | None:
    signature = file_signature(project_root, file_path)
    if signature is None:
        return None

    if payload is None:
        updated = build_empty_index(project_root)
    else:
        updated = _copy_index_payload(payload)

    _ensure_content_graphs(updated)
    _record_signature(updated, signature)
    _record_content_graph(
        updated,
        signature,
        definitions=definitions,
        references=references,
        imports=imports,
    )
    return updated


def changed_index_paths(
    project_root: str | Path,
    payload: dict[str, Any],
    *,
    candidate_paths: list[str | Path] | None = None,
) -> list[str]:
    if not validate_index_payload(payload):
        return []

    changed = set()
    for relpath in _candidate_relpaths(project_root, payload, candidate_paths):
        if _signature_changed(project_root, payload, relpath):
            changed.add(relpath)
    return sorted(changed)


def invalidation_paths_for_changes(
    project_root: str | Path,
    payload: dict[str, Any],
    *,
    candidate_paths: list[str | Path] | None = None,
) -> list[str]:
    changed_paths = changed_index_paths(
        project_root,
        payload,
        candidate_paths=candidate_paths,
    )
    invalidated = set()
    for path in changed_paths:
        invalidated.add(path)
        for dependent in _direct_dependents(payload, path):
            invalidated.add(dependent)
    return sorted(invalidated)


def _record_signature(payload: dict[str, Any], signature: dict[str, Any]) -> None:
    files = _files_map(payload)
    path = str(signature["path"])
    files[path] = dict(signature)


def _record_content_graph(
    payload: dict[str, Any],
    signature: dict[str, Any],
    *,
    definitions: dict[str, Any] | None,
    references: list[dict[str, Any]] | None,
    imports: list[Any] | None,
) -> None:
    content_graphs = _content_graphs_map(payload)
    content_hash = str(signature["sha256"])
    existing = _existing_graph(content_graphs, content_hash)
    graph = _graph_payload(
        signature,
        existing,
        definitions=definitions,
        references=references,
        imports=imports,
    )
    content_graphs[content_hash] = graph


def _graph_payload(
    signature: dict[str, Any],
    existing: dict[str, Any],
    *,
    definitions: dict[str, Any] | None,
    references: list[dict[str, Any]] | None,
    imports: list[Any] | None,
) -> dict[str, Any]:
    path = str(signature["path"])
    return {
        "sha256": str(signature["sha256"]),
        "paths": _graph_paths(existing, path),
        "definitions": _dict_copy(definitions),
        "references": _list_copy(references),
        "imports": _list_copy(imports),
    }


def _graph_paths(existing: dict[str, Any], path: str) -> list[str]:
    paths = set()
    existing_paths = existing.get("paths")
    if isinstance(existing_paths, list):
        for existing_path in existing_paths:
            paths.add(str(existing_path))
    paths.add(path)
    return sorted(paths)


def _existing_graph(
    content_graphs: dict[str, dict[str, Any]],
    content_hash: str,
) -> dict[str, Any]:
    existing = content_graphs.get(content_hash)
    if isinstance(existing, dict):
        return existing
    return {}


def _candidate_relpaths(
    project_root: str | Path,
    payload: dict[str, Any],
    candidate_paths: list[str | Path] | None,
) -> list[str]:
    if candidate_paths is None:
        return sorted(_files_map(payload))

    relpaths = set()
    for candidate in candidate_paths:
        relpaths.add(_relative_candidate_path(project_root, candidate))
    return sorted(relpaths)


def _relative_candidate_path(project_root: str | Path, candidate: str | Path) -> str:
    root = Path(project_root).resolve()
    raw = Path(candidate)
    if raw.is_absolute():
        path = raw
    else:
        path = root / raw

    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return str(candidate).replace("\\", "/")


def _signature_changed(
    project_root: str | Path,
    payload: dict[str, Any],
    relpath: str,
) -> bool:
    stored = _stored_signature(payload, relpath)
    if stored is None:
        return True

    current = file_signature(project_root, relpath)
    if current is None:
        return True

    return not _same_content_signature(stored, current)


def _stored_signature(
    payload: dict[str, Any],
    relpath: str,
) -> dict[str, Any] | None:
    files = _files_map(payload)
    stored = files.get(relpath)
    if isinstance(stored, dict):
        return stored
    return None


def _same_content_signature(
    stored: dict[str, Any],
    current: dict[str, Any],
) -> bool:
    stored_hash = stored.get("sha256")
    current_hash = current.get("sha256")
    if not isinstance(stored_hash, str):
        return False
    if not isinstance(current_hash, str):
        return False
    return stored_hash == current_hash


def _direct_dependents(payload: dict[str, Any], relpath: str) -> list[str]:
    reverse_dependencies = payload.get("reverse_dependencies")
    if not isinstance(reverse_dependencies, dict):
        return []

    dependents = reverse_dependencies.get(relpath)
    if not isinstance(dependents, list):
        return []

    normalized = []
    for dependent in dependents:
        normalized.append(str(dependent))
    return normalized


def _copy_index_payload(payload: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key, value in payload.items():
        copied[key] = _copy_value(value)
    return copied


def _copy_value(value: Any) -> Any:
    if isinstance(value, dict):
        copied: dict[str, Any] = {}
        for child_key, child_value in value.items():
            copied[str(child_key)] = _copy_value(child_value)
        return copied
    if isinstance(value, list):
        copied_list = []
        for item in value:
            copied_list.append(_copy_value(item))
        return copied_list
    return value


def _files_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = payload.get("files")
    if isinstance(files, dict):
        return files

    payload["files"] = {}
    return payload["files"]


def _content_graphs_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    content_graphs = payload.get("content_graphs")
    if isinstance(content_graphs, dict):
        return content_graphs

    payload["content_graphs"] = {}
    return payload["content_graphs"]


def _ensure_content_graphs(payload: dict[str, Any]) -> None:
    content_graphs = payload.get("content_graphs")
    if isinstance(content_graphs, dict):
        return
    payload["content_graphs"] = {}


def _dict_copy(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return dict(value)


def _list_copy(value: list[Any] | None) -> list[Any]:
    if value is None:
        return []
    return list(value)


def _project_root_matches(payload: dict[str, Any], project_root: str | Path) -> bool:
    stored = payload.get("project_root")
    if not isinstance(stored, str):
        return False

    try:
        stored_root = Path(stored).resolve()
        current_root = Path(project_root).resolve()
    except OSError:
        return False
    return stored_root == current_root
