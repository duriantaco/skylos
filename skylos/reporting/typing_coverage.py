"""Annotation inventory is separate from required annotation findings."""

from collections.abc import Mapping


_COUNTS = (
    "definition_count",
    "definitions_with_complete_annotations",
    "definitions_missing_annotations",
    "missing_parameter_annotations",
    "missing_return_annotations",
    "definitions_with_supplied_contract",
    "unreported_missing_definitions",
)


def summarize_typing_coverage(files, *, measured_paths):
    selected = {
        row["file"]: row
        for row in files
        if isinstance(row, Mapping)
        and row.get("file") in measured_paths
        and row.get("version") == 1
        and row.get("scope") == "public_source_definitions"
        and all(type(row.get(key)) is int and row[key] >= 0 for key in _COUNTS)
    }
    if not selected:
        return None
    return {
        "version": 1,
        "scope": "public_source_definitions",
        "files_analyzed": len(selected),
        **{key: sum(row[key] for row in selected.values()) for key in _COUNTS},
        "enable_coverage_advice_with": "[tool.skylos] typing_coverage_advice = true",
    }


def typing_coverage_text(summary):
    coverage = summary.get("typing_coverage") if isinstance(summary, Mapping) else None
    if not isinstance(coverage, Mapping):
        return ""
    total = coverage.get("definition_count")
    complete = coverage.get("definitions_with_complete_annotations")
    missing = coverage.get("definitions_missing_annotations")
    if any(type(value) is not int or value < 0 for value in (total, complete, missing)):
        return ""
    if not total or complete + missing != total:
        return ""
    return (
        f"Public signature annotations: {complete}/{total} complete, "
        f"{missing} incomplete (coverage statistics; not type errors)."
    )
