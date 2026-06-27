from __future__ import annotations

from pathlib import Path
from typing import Any


FINDING_SECTIONS = (
    ("ai_defects", "ai_defects"),
    ("danger", "security"),
    ("quality", "quality"),
    ("custom_rules", "quality"),
    ("secrets", "secrets"),
    ("dependency_vulnerabilities", "dependencies"),
    ("unused_functions", "dead_code"),
    ("unused_imports", "dead_code"),
    ("unused_classes", "dead_code"),
    ("unused_variables", "dead_code"),
    ("unused_parameters", "dead_code"),
    ("unused_files", "dead_code"),
    ("unused_fixtures", "dead_code"),
    ("unused_exports", "dead_code"),
)

_CATEGORY_KEYS = (
    "dead_code",
    "ai_defects",
    "quality",
    "security",
    "secrets",
    "dependencies",
)
_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "WARN": 3,
    "LOW": 4,
    "INFO": 5,
}


def build_directory_rollups(
    result: dict[str, Any],
    root_path: str | Path | None,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}

    for section, category in FINDING_SECTIONS:
        for finding in result.get(section, []) or []:
            if not isinstance(finding, dict):
                continue
            directory = _finding_directory(finding, root_path)
            bucket = buckets.setdefault(directory, _new_bucket(directory))
            bucket["total"] += 1
            bucket[category] += 1
            bucket["_files"].add(_finding_file_key(finding, root_path))

            rule_id = _rule_id(finding, section)
            bucket["rules"][rule_id] = bucket["rules"].get(rule_id, 0) + 1

            severity = _severity(finding, category)
            bucket["severities"][severity] = bucket["severities"].get(severity, 0) + 1

    rollups = []
    for bucket in buckets.values():
        out = {
            "path": bucket["path"],
            "total": bucket["total"],
            "files": len(bucket["_files"]),
        }
        for category in _CATEGORY_KEYS:
            if bucket[category]:
                out[category] = bucket[category]
        if bucket["rules"]:
            out["rules"] = dict(sorted(bucket["rules"].items()))
        if bucket["severities"]:
            out["severities"] = dict(
                sorted(
                    bucket["severities"].items(),
                    key=lambda item: (_SEVERITY_ORDER.get(item[0], 99), item[0]),
                )
            )
        rollups.append(out)

    rollups.sort(key=lambda item: (-item["total"], item["path"]))
    return rollups


def attach_directory_rollups(
    result: dict[str, Any],
    root_path: str | Path | None,
) -> dict[str, Any]:
    rollups = build_directory_rollups(result, root_path)
    if rollups:
        result.setdefault("analysis_summary", {})["by_directory"] = rollups
    return result


def _new_bucket(path: str) -> dict[str, Any]:
    bucket = {
        "path": path,
        "total": 0,
        "_files": set(),
        "rules": {},
        "severities": {},
    }
    for category in _CATEGORY_KEYS:
        bucket[category] = 0
    return bucket


def _finding_directory(finding: dict[str, Any], root_path: str | Path | None) -> str:
    file_key = _finding_file_key(finding, root_path)
    if file_key in {"", "unknown", "?"}:
        return "."
    parent = Path(file_key).parent
    text = str(parent).replace("\\", "/")
    return "." if text in {"", "."} else text


def _finding_file_key(finding: dict[str, Any], root_path: str | Path | None) -> str:
    raw_path = finding.get("file") or finding.get("file_path") or "unknown"
    text = str(raw_path).replace("\\", "/")
    if not text or text == "unknown":
        return "unknown"

    path = Path(text)
    if path.is_absolute() and root_path is not None:
        try:
            return str(path.resolve().relative_to(Path(root_path).resolve())).replace(
                "\\", "/"
            )
        except (OSError, ValueError):
            pass
    return text


def _rule_id(finding: dict[str, Any], section: str) -> str:
    value = (
        finding.get("rule_id")
        or finding.get("rule")
        or finding.get("code")
        or finding.get("id")
    )
    if value:
        return str(value)
    return section.replace("_", "-")


def _severity(finding: dict[str, Any], category: str) -> str:
    raw = finding.get("severity")
    if raw:
        label = str(raw).strip().upper()
        if label:
            return label
    if category in {"security", "secrets", "dependencies"}:
        return "HIGH"
    if category == "quality":
        return "MEDIUM"
    return "LOW"
