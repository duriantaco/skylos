"""Keep machine paths out of reported finding evidence.

Detectors resolve source with absolute paths. Reported and uploaded evidence
uses the ``security_trace`` convention instead: a POSIX path relative to the
scan's project root. A file outside that root is named only as
``<external>/<basename>``. Relative values are already in that convention and
are left unchanged. Nested evidence is copied before rewriting, preserving
detector-owned proof objects.
"""

from __future__ import annotations

import os
import re
from typing import Any

__all__ = [
    "EXTERNAL_PATH_PREFIX",
    "relativize_contract_traces",
    "relativize_definitions",
    "relativize_evidence_paths",
    "relativize_receiver_paths",
    "relativize_upload_finding",
    "scan_relative_location",
    "scan_relative_path",
]

EXTERNAL_PATH_PREFIX = "<external>"
_PATH_KEYS = frozenset({"file", "file_path"})
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_MAX_DEPTH = 64


def _looks_absolute(text: str) -> bool:
    return text.startswith(("/", "\\")) or bool(_DRIVE_RE.match(text))


def _relative_inside(path: str, root: str) -> str | None:
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return None
    rel = rel.replace("\\", "/")
    if rel == ".." or rel.startswith("../") or os.path.isabs(rel):
        return None
    return rel


def _inside_root(path: str, root: str) -> str | None:
    rel = _relative_inside(os.path.abspath(path), os.path.abspath(root))
    if rel is not None:
        return rel
    try:
        return _relative_inside(os.path.realpath(path), os.path.realpath(root))
    except (OSError, ValueError):
        return None


def _external(text: str) -> str:
    name = text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if not name or _DRIVE_RE.match(name + "/"):
        return EXTERNAL_PATH_PREFIX
    return f"{EXTERNAL_PATH_PREFIX}/{name}"


def scan_relative_path(value: Any, root: str | os.PathLike | None) -> Any:
    """``value`` relative to ``root``, or ``<external>/<basename>`` outside it.

    Non-strings and relative paths are returned unchanged.
    """
    if not isinstance(value, str) or not _looks_absolute(value):
        return value
    if root and os.path.isabs(value):
        rel = _inside_root(value, os.fspath(root))
        if rel is not None:
            return rel
    return _external(value)


def _relativize(node: Any, root, depth: int) -> tuple[Any, bool]:
    if depth > _MAX_DEPTH:
        return node, False
    if isinstance(node, dict):
        changed = False
        updated = {}
        for key, value in node.items():
            if key in _PATH_KEYS and isinstance(value, str):
                new_value = scan_relative_path(value, root)
            else:
                new_value, _ = _relativize(value, root, depth + 1)
            if new_value is not value:
                changed = True
            updated[key] = new_value
        if changed:
            return updated, True
        return node, False
    if isinstance(node, list):
        changed = False
        items = []
        for value in node:
            new_value, item_changed = _relativize(value, root, depth + 1)
            changed = changed or item_changed
            items.append(new_value)
        if changed:
            return items, True
        return node, False
    return node, False


def relativize_evidence_paths(node: Any, root: str | os.PathLike | None) -> Any:
    """Copy of ``node`` whose nested ``file``/``file_path`` values are relative.

    Only absolute string values under those keys change. Unchanged containers
    are returned as the same objects, so callers can detect a rewrite cheaply.
    """
    updated, _ = _relativize(node, root, 0)
    return updated


def relativize_receiver_paths(findings: Any, root: str | os.PathLike | None) -> None:
    """Give each finding a scan-relative copy of its ``receiver_resolution``.

    Detectors attach (and cache) the resolver's own absolute proof object; it
    is replaced on the finding, never mutated.
    """
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            continue
        proof = metadata.get("receiver_resolution")
        updated = relativize_evidence_paths(proof, root)
        if updated is not proof:
            finding["metadata"] = {**metadata, "receiver_resolution": updated}


def scan_relative_location(value: Any, root: str | os.PathLike | None) -> Any:
    """A ``path``, ``path:line`` or ``path:symbol`` string with a relative path."""
    if not isinstance(value, str) or not _looks_absolute(value):
        return value
    path, separator, suffix = value.rpartition(":")
    if (
        separator
        and suffix
        and "/" not in suffix
        and "\\" not in suffix
        and _looks_absolute(path)
    ):
        return f"{scan_relative_path(path, root)}:{suffix}"
    return scan_relative_path(value, root)


def relativize_contract_traces(contract: Any, root: str | os.PathLike | None) -> Any:
    """Copy of an evidence contract whose location traces use relative paths."""
    if not isinstance(contract, dict):
        return contract
    traces = contract.get("traces")
    if not isinstance(traces, list):
        return contract
    mapped = [scan_relative_location(trace, root) for trace in traces]
    if all(new is old for new, old in zip(mapped, traces)):
        return contract
    updated = []
    for trace in mapped:
        if trace not in updated:
            updated.append(trace)
    return {**contract, "traces": updated}


def relativize_upload_finding(finding: dict, root: str | os.PathLike | None) -> None:
    """Rewrite one upload copy's nested evidence paths; never its own location.

    The finding dict is an upload copy and is updated in place; nested
    containers it shares with the analyzer result are replaced, not mutated.
    """
    contract = finding.get("evidence_contract")
    updated_contract = relativize_contract_traces(contract, root)
    if updated_contract is not contract:
        finding["evidence_contract"] = updated_contract
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return
    updated = relativize_evidence_paths(metadata, root)
    nested = updated.get("evidence_contract")
    updated_nested = relativize_contract_traces(nested, root)
    if updated_nested is not nested:
        updated = {**updated, "evidence_contract": updated_nested}
    if updated is not metadata:
        finding["metadata"] = updated


def relativize_definitions(definitions: Any, root: str | os.PathLike | None) -> Any:
    """Copy of an analyzer ``definitions`` map without machine paths."""
    if not isinstance(definitions, dict):
        return definitions
    changed = False
    updated = {}
    for key, value in definitions.items():
        new_key = scan_relative_location(key, root)
        new_value = relativize_evidence_paths(value, root)
        if new_key is not key or new_value is not value:
            changed = True
        updated[new_key] = new_value
    if changed:
        return updated
    return definitions
