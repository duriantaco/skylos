from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from skylos.benchmarks._jev_dead_code_types import JevBenchmarkError


GOLDEN_SCHEMA = "skylos-golden-benchmark/v1"


def golden_manifest_metadata(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": GOLDEN_SCHEMA,
        "split": manifest.get("split"),
        "label_state": manifest.get("label_state"),
    }


def _required_string(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value:
        raise JevBenchmarkError(message)
    return value


def _required_object(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise JevBenchmarkError(message)
    return value


def _safe_relative_path(value: Any, field: str) -> str:
    raw = _required_string(value, f"{field} must be a non-empty relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        raise JevBenchmarkError(f"{field} must stay inside its benchmark root")
    return path.as_posix()


def _golden_kind(category: str) -> str:
    kinds = ("method", "function", "class", "variable", "parameter", "import", "file")
    for token in kinds:
        if token in category:
            return "function" if token == "method" else token
    return "function" if "entrypoint" in category else "symbol"


def _expected_label(value: Any, case_id: str) -> str:
    expected = {
        "should_report": "unused",
        "should_not_report": "used",
    }.get(value)
    if expected is None:
        raise JevBenchmarkError(f"golden case {case_id} has an unknown expectation")
    return expected


def _optional_line(match: dict[str, Any], case_id: str) -> int | None:
    if "line" not in match:
        return None
    line = match["line"]
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise JevBenchmarkError(f"golden case {case_id} label line is invalid")
    return line


def _golden_label(label: Any, case_id: str) -> tuple[str, dict[str, Any]]:
    label = _required_object(
        label, f"golden case {case_id} has a malformed label"
    )
    match = _required_object(
        label.get("match"), f"golden case {case_id} label has no match object"
    )
    symbol = _required_string(
        match.get("symbol"), f"golden case {case_id} label has no symbol"
    )
    category = _required_string(
        label.get("category"), f"golden case {case_id} label has no category"
    )
    label_id = _required_string(
        label.get("id"), f"golden case {case_id} label has no id"
    )
    item: dict[str, Any] = {
        "kind": _golden_kind(category),
        "file": _safe_relative_path(match.get("path"), "golden label path"),
        "symbol": symbol,
        "label_id": label_id,
        "_taxonomy": [category],
    }
    line = _optional_line(match, case_id)
    if line is not None:
        item["line"] = line
    return _expected_label(label.get("expectation"), case_id), item


def _case_labels(
    labels: Any, case_id: str
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    if not isinstance(labels, list) or not labels:
        raise JevBenchmarkError(f"golden case {case_id} has no labels")
    expect: dict[str, list[dict[str, Any]]] = {"unused": [], "used": []}
    label_ids: set[str] = set()
    for label in labels:
        expected, item = _golden_label(label, case_id)
        label_id = str(item["label_id"])
        if label_id in label_ids:
            raise JevBenchmarkError(f"duplicate golden label id: {label_id}")
        label_ids.add(label_id)
        expect[expected].append(item)
    return expect, label_ids


def _golden_case(
    raw_case: Any,
    source_root: Path,
) -> tuple[dict[str, Any], set[str]]:
    raw_case = _required_object(
        raw_case, "golden manifest contains a malformed case"
    )
    case_id = _required_string(
        raw_case.get("id"), "golden case ids must be unique non-empty strings"
    )
    if raw_case.get("label_coverage") != "closed":
        raise JevBenchmarkError(f"golden case {case_id} must have closed labels")
    source = _required_object(
        raw_case.get("source"), f"golden case {case_id} has no source object"
    )
    expect, label_ids = _case_labels(raw_case.get("labels"), case_id)
    case = {
        "id": case_id,
        "path": _safe_relative_path(
            source.get("local_path"), "golden source.local_path"
        ),
        "taxonomy": [str(value) for value in raw_case.get("languages", [])],
        "expect": expect,
        "_source_root": str(source_root),
    }
    return case, label_ids


def normalize_golden_cases(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    if manifest.get("suite") != "dead_code":
        raise JevBenchmarkError("golden manifest suite must be dead_code")
    if manifest.get("label_state") != "frozen":
        raise JevBenchmarkError("golden manifest labels must be frozen")
    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise JevBenchmarkError("golden manifest must contain cases")

    source_root = Path(manifest_path).expanduser().resolve().parent.parent
    cases = []
    case_ids: set[str] = set()
    label_ids: set[str] = set()
    for raw_case in raw_cases:
        case, current_label_ids = _golden_case(raw_case, source_root)
        if case["id"] in case_ids:
            raise JevBenchmarkError("golden case ids must be unique non-empty strings")
        duplicate_labels = label_ids.intersection(current_label_ids)
        if duplicate_labels:
            raise JevBenchmarkError(
                f"duplicate golden label id: {sorted(duplicate_labels)[0]}"
            )
        case_ids.add(case["id"])
        label_ids.update(current_label_ids)
        cases.append(case)
    return cases
