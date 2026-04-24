from __future__ import annotations

import json
from pathlib import Path
from typing import Any


EXCLUSION_KEYS = (
    "sonar.exclusions",
    "sonar.coverage.exclusions",
    "sonar.test.exclusions",
    "sonar.cpd.exclusions",
)


def parse_sonar_properties(path: str | Path) -> dict[str, str]:
    props_path = Path(path)
    lines = props_path.read_text(encoding="utf-8").splitlines()
    logical_lines: list[str] = []
    pending = ""

    for raw in lines:
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#") or stripped.startswith("!")):
            continue

        continued = stripped.endswith("\\") and not stripped.endswith("\\\\")
        chunk = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending}{chunk}" if pending else chunk
        if continued:
            continue
        if pending:
            logical_lines.append(pending)
        pending = ""

    if pending:
        logical_lines.append(pending)

    properties: dict[str, str] = {}
    for line in logical_lines:
        parsed = _parse_property_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key:
            properties[key] = value
    return properties


def _parse_property_line(line: str) -> tuple[str, str] | None:
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"=", ":"}:
            return _clean_key_value(line[:idx], line[idx + 1 :])

    parts = line.split(None, 1)
    if len(parts) == 2:
        return _clean_key_value(parts[0], parts[1])
    return None


def _clean_key_value(key: str, value: str) -> tuple[str, str]:
    return key.strip(), _unescape_property(value.strip())


def _unescape_property(value: str) -> str:
    return (
        value.replace("\\:", ":")
        .replace("\\=", "=")
        .replace("\\,", ",")
        .replace("\\ ", " ")
        .replace("\\\\", "\\")
    )


def split_sonar_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def build_sonar_migration_plan(properties: dict[str, str]) -> dict[str, Any]:
    source_paths = split_sonar_list(properties.get("sonar.sources")) or ["."]
    test_paths = split_sonar_list(properties.get("sonar.tests"))
    exclusions: list[str] = []
    seen_exclusions: set[str] = set()

    for key in EXCLUSION_KEYS:
        for item in split_sonar_list(properties.get(key)):
            if item in seen_exclusions:
                continue
            seen_exclusions.add(item)
            exclusions.append(item)

    config: dict[str, Any] = {
        "exclude": exclusions,
        "gate": {
            "enabled": True,
            "mode": "zero-new",
        },
    }

    notes = [
        "Review Sonar quality profiles manually; Skylos does not import Sonar rule activation yet.",
        "Coverage thresholds are not imported into Skylos gates in this first migration slice.",
    ]
    if test_paths:
        notes.append("Sonar test paths are preserved in the report for review, not scanned as a separate Skylos family.")

    return {
        "sonar": {
            "project_key": properties.get("sonar.projectKey"),
            "project_name": properties.get("sonar.projectName"),
            "sources": source_paths,
            "tests": test_paths,
            "exclusions": exclusions,
        },
        "skylos": {
            "recommended_command": f"skylos {source_paths[0]} --danger --quality --upload",
            "suite_command": f"skylos suite {source_paths[0]} --upload",
            "config": config,
        },
        "manual_review": notes,
    }


def write_skylos_yaml_config(path: str | Path, config: dict[str, Any]) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Writing YAML requires PyYAML.") from exc

    output_path.write_text(
        yaml.safe_dump(config, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )
    return output_path


def format_migration_plan_json(plan: dict[str, Any]) -> str:
    return json.dumps(plan, indent=2)

