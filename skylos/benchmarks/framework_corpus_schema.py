from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEAD_CODE_CATEGORIES = (
    "unused_imports",
    "unused_functions",
    "unused_classes",
    "unused_variables",
    "unused_parameters",
    "unused_files",
)


@dataclass(frozen=True)
class FrameworkCorpusFailure:
    target_id: str
    failure_type: str
    mode: str
    expected: str
    found: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "failure_type": self.failure_type,
            "mode": self.mode,
            "expected": self.expected,
            "found": list(self.found),
        }


def load_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _validate_non_empty_string(
    target_id: str,
    target: dict[str, Any],
    field: str,
) -> str:
    value = target.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"framework corpus target {target_id} must declare {field}")
    return value.strip()


def _validate_scan_paths(target_id: str, target: dict[str, Any]) -> None:
    scan_paths = target.get("scan_paths")
    if scan_paths is None:
        return
    if not isinstance(scan_paths, list) or not scan_paths:
        raise ValueError(
            f"framework corpus target {target_id} scan_paths must be a non-empty list"
        )
    for scan_path in scan_paths:
        if not isinstance(scan_path, str) or not scan_path.strip():
            raise ValueError(
                f"framework corpus target {target_id} scan_paths must contain strings"
            )


def _validate_scan_config(target_id: str, target: dict[str, Any]) -> None:
    scan = target.get("scan", {})
    if not scan:
        return
    if not isinstance(scan, dict):
        raise ValueError(f"framework corpus target {target_id} scan must be an object")
    confidence = scan.get("confidence")
    if confidence is None:
        return
    if not isinstance(confidence, int) or confidence < 0 or confidence > 100:
        raise ValueError(
            f"framework corpus target {target_id} scan.confidence must be 0..100"
        )


def _validate_baseline(target_id: str, target: dict[str, Any]) -> None:
    baseline = target.get("baseline", {})
    if not baseline:
        return
    if not isinstance(baseline, dict):
        raise ValueError(
            f"framework corpus target {target_id} baseline must be an object"
        )

    counts = baseline.get("counts", {})
    if not isinstance(counts, dict) or not counts:
        raise ValueError(
            f"framework corpus target {target_id} baseline.counts must be non-empty"
        )
    for category, expected in counts.items():
        if category not in DEAD_CODE_CATEGORIES:
            allowed = ", ".join(DEAD_CODE_CATEGORIES)
            raise ValueError(
                f"framework corpus target {target_id} has unsupported category "
                f"{category}. Allowed: {allowed}"
            )
        if not isinstance(expected, int) or expected < 0:
            raise ValueError(
                f"framework corpus target {target_id} baseline count {category} "
                "must be a non-negative integer"
            )

    max_delta = baseline.get("max_delta", 0)
    if not isinstance(max_delta, int) or max_delta < 0:
        raise ValueError(
            f"framework corpus target {target_id} baseline.max_delta must be >= 0"
        )


def _validate_expectation(
    target_id: str,
    mode: str,
    item: Any,
) -> None:
    if not isinstance(item, dict):
        raise ValueError(
            f"framework corpus target {target_id} {mode} expectations must be objects"
        )

    category = item.get("category")
    if category not in DEAD_CODE_CATEGORIES:
        allowed = ", ".join(DEAD_CODE_CATEGORIES)
        raise ValueError(
            f"framework corpus target {target_id} has unsupported category "
            f"{category}. Allowed: {allowed}"
        )

    file_name = item.get("file")
    symbol = item.get("symbol")
    has_file = isinstance(file_name, str) and bool(file_name.strip())
    has_symbol = isinstance(symbol, str) and bool(symbol.strip())
    if not has_file and not has_symbol:
        raise ValueError(
            f"framework corpus target {target_id} {mode} expectations need file or symbol"
        )


def _validate_expectations(target_id: str, target: dict[str, Any]) -> None:
    expect = target.get("expect", {})
    if not expect:
        return
    if not isinstance(expect, dict):
        raise ValueError(
            f"framework corpus target {target_id} expect must be an object"
        )
    for mode in ("absent", "present"):
        items = expect.get(mode, [])
        if not isinstance(items, list):
            raise ValueError(
                f"framework corpus target {target_id} expect.{mode} must be a list"
            )
        for item in items:
            _validate_expectation(target_id, mode, item)


def validate_manifest(
    manifest: dict[str, Any],
    manifest_path: str | Path,
) -> list[dict[str, Any]]:
    if manifest.get("version") != 1:
        raise ValueError("framework corpus manifest version must be 1")

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("framework corpus manifest must define targets")

    seen_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("each framework corpus target must be an object")

        target_id = _validate_non_empty_string("<unknown>", target, "id")
        if target_id in seen_ids:
            raise ValueError(f"duplicate framework corpus target id: {target_id}")
        seen_ids.add(target_id)

        repo = _validate_non_empty_string(target_id, target, "repo")
        if not repo.startswith("https://"):
            raise ValueError(
                f"framework corpus target {target_id} repo must be an https URL"
            )
        _validate_non_empty_string(target_id, target, "ref")
        _validate_non_empty_string(target_id, target, "license")
        _validate_scan_paths(target_id, target)
        _validate_scan_config(target_id, target)
        _validate_baseline(target_id, target)
        _validate_expectations(target_id, target)

    return targets
