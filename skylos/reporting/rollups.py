from __future__ import annotations

from pathlib import Path
from typing import Any


FINDING_SECTIONS = (
    ("ai_defects", "ai_defects"),
    ("danger", "security"),
    ("reliability", "reliability"),
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
    "reliability",
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
_UNRESOLVED_ROOT = object()


def build_directory_rollups(
    result: dict[str, Any],
    root_path: str | Path | None,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    # Findings often share a file. Keep filesystem normalization local to this
    # build so subsequent reports still observe changed paths and symlinks.
    locations: dict[str, tuple[str, str]] = {}
    resolved_root = _UNRESOLVED_ROOT

    for section, category in FINDING_SECTIONS:
        for finding in result.get(section, []) or []:
            if not isinstance(finding, dict):
                continue
            raw_key = _finding_path_text(finding)
            location = locations.get(raw_key)
            if location is None:
                if (
                    resolved_root is _UNRESOLVED_ROOT
                    and root_path is not None
                    and Path(raw_key).is_absolute()
                ):
                    try:
                        resolved_root = Path(root_path).resolve()
                    except (OSError, ValueError):
                        resolved_root = None
                file_key = _finding_file_key(
                    finding, root_path, resolved_root=resolved_root
                )
                directory = _file_directory(file_key)
                location = locations[raw_key] = (file_key, directory)
            file_key, directory = location
            bucket = buckets.setdefault(directory, _new_bucket(directory))
            bucket["total"] += 1
            bucket[category] += 1
            bucket["_files"].add(file_key)

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
    return _file_directory(_finding_file_key(finding, root_path))


def _file_directory(file_key: str) -> str:
    if file_key in {"", "unknown", "?"}:
        return "."
    parent = Path(file_key).parent
    text = str(parent).replace("\\", "/")
    return "." if text in {"", "."} else text


def _finding_path_text(finding: dict[str, Any]) -> str:
    raw_path = finding.get("file") or finding.get("file_path") or "unknown"
    text = str(raw_path).replace("\\", "/")
    return text or "unknown"


def _finding_file_key(
    finding: dict[str, Any],
    root_path: str | Path | None,
    *,
    resolved_root=_UNRESOLVED_ROOT,
) -> str:
    text = _finding_path_text(finding)

    path = Path(text)
    if path.is_absolute() and root_path is not None:
        try:
            if resolved_root is _UNRESOLVED_ROOT:
                resolved_root = Path(root_path).resolve()
            if resolved_root is not None:
                return str(path.resolve().relative_to(resolved_root)).replace("\\", "/")
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
