from __future__ import annotations

import re
from typing import Any


# Keep this exact: custom labels that merely resemble hosted labels are not proof.
# https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idruns-on
_HOSTED_LABELS = frozenset(
    {
        "ubuntu-latest",
        "ubuntu-slim",
        "ubuntu-22.04",
        "ubuntu-24.04",
        "ubuntu-26.04",
        "ubuntu-22.04-arm",
        "ubuntu-24.04-arm",
        "ubuntu-26.04-arm",
        "windows-latest",
        "windows-2022",
        "windows-2025",
        "windows-2025-vs2026",
        "windows-11-arm",
        "windows-11-vs2026-arm",
        "macos-latest",
        "macos-14",
        "macos-15",
        "macos-26",
        "macos-15-intel",
        "macos-26-intel",
        "xcode-27",
    }
)
_MATRIX_PROPERTY_RE = re.compile(
    r"\$\{\{\s*matrix\."
    r"(?P<path>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*)"
    r"\s*\}\}"
)
_MAX_MATRIX_ROWS = 256
_MAX_LITERAL_NODES = 4096
_MAX_LITERAL_DEPTH = 16


def _is_literal_matrix(matrix: dict[str, Any]) -> bool:
    pending = [(matrix, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_LITERAL_NODES or depth > _MAX_LITERAL_DEPTH:
            return False
        if isinstance(value, str):
            if "${{" in value:
                return False
        elif isinstance(value, dict):
            if len(value) > _MAX_MATRIX_ROWS or any(
                not isinstance(key, str) or "${{" in key for key in value
            ):
                return False
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            if len(value) > _MAX_MATRIX_ROWS:
                return False
            pending.extend((child, depth + 1) for child in value)
        elif value is not None and not isinstance(value, (bool, int, float)):
            return False
    return True


def _literal_matrix_rows(job: dict[str, Any]) -> list[dict[str, Any]] | None:
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return None
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict) or not _is_literal_matrix(matrix):
        return None
    if any(
        key.lower() in {"include", "exclude"} and key not in {"include", "exclude"}
        for key in matrix
    ):
        return None

    include = matrix.get("include", [])
    exclude = matrix.get("exclude", [])
    if not all(
        isinstance(entries, list) and all(isinstance(row, dict) for row in entries)
        for entries in (include, exclude)
    ):
        return None
    # Excludes alone only remove possibilities, so checking every base row is
    # conservative. With includes, they can turn an overlay into a new row; do
    # not prove safety without modelling that interaction.
    if include and exclude:
        return None

    axes = {
        key: values
        for key, values in matrix.items()
        if key not in {"include", "exclude"}
    }
    originals: list[dict[str, Any]] = [{}] if axes else []
    for key, values in axes.items():
        if not isinstance(values, list) or not values:
            return None
        if len(originals) * len(values) > _MAX_MATRIX_ROWS:
            return None
        originals = [dict(row, **{key: value}) for row in originals for value in values]

    rows = [dict(row) for row in originals]
    for addition in include:
        # Expression properties are case-insensitive. Do not guess when the
        # spelling used by an include differs from an original axis name.
        if any(
            key != axis and key.lower() == axis.lower()
            for key in addition
            for axis in axes
        ):
            return None
        # Nested object equality is outside this deliberately small proof.
        if any(
            key in axes
            and (
                isinstance(value, (dict, list))
                or any(isinstance(item, (dict, list)) for item in axes[key])
            )
            for key, value in addition.items()
        ):
            return None
        matched = False
        for index, original in enumerate(originals):
            if all(
                key not in original
                or (type(original[key]) is type(value) and original[key] == value)
                for key, value in addition.items()
            ):
                # Includes can overwrite earlier additions, never original axes.
                rows[index].update(addition)
                matched = True
        if not matched:
            rows.append(dict(addition))
        if len(rows) > _MAX_MATRIX_ROWS:
            return None
    return rows or None


def _is_hosted_label_value(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower() in _HOSTED_LABELS
    if isinstance(value, list) and value:
        return all(
            isinstance(label, str) and label.lower() in _HOSTED_LABELS
            for label in value
        )
    return False


def _matrix_property_is_hosted(expression: str, job: dict[str, Any]) -> bool:
    match = _MATRIX_PROPERTY_RE.fullmatch(expression.strip())
    if match is None:
        return False
    rows = _literal_matrix_rows(job)
    if rows is None:
        return False
    path = match.group("path").split(".")
    for row in rows:
        value: Any = row
        for key in path:
            if not isinstance(value, dict) or key not in value:
                return False
            if any(other != key and other.lower() == key.lower() for other in value):
                return False
            value = value[key]
        if not _is_hosted_label_value(value):
            return False
    return True


def runner_may_be_self_hosted(job: dict[str, Any]) -> bool:
    """Classify explicit or unresolved runner selection conservatively.

    Fixed custom labels keep their existing behavior: only the explicit
    self-hosted label establishes risk. Dynamic selections require a bounded
    literal matrix proof that every possible label is a known hosted label.
    """
    if "runs-on" not in job:
        return False
    runs_on = job["runs-on"]
    if isinstance(runs_on, dict):
        if "group" in runs_on or set(runs_on) != {"labels"}:
            return True
        runs_on = runs_on["labels"]
    labels = runs_on if isinstance(runs_on, list) else [runs_on]
    if not labels:
        return True
    for label in labels:
        if not isinstance(label, str) or not label.strip():
            return True
        if label.strip().lower() == "self-hosted":
            return True
        if "${{" in label and not _matrix_property_is_hosted(label, job):
            return True
    return False
