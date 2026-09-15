from __future__ import annotations
import json
from pathlib import Path

from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    save_project_json_cache,
)
from skylos.core.sca_baseline import dependency_snapshot, filter_dependency_findings

BASELINE_DIR = ".skylos"
BASELINE_FILE = "baseline.json"
MAX_BASELINE_BYTES = 2_000_000

_FINDING_CATEGORIES = (
    "danger",
    "reliability",
    "ai_defects",
    "quality",
    "secrets",
    "unused_files",
)
_DEAD_CODE_CATEGORIES = (
    "unused_functions",
    "unused_imports",
    "unused_classes",
    "unused_variables",
)
_SUMMARY_COUNT_KEYS = {
    "unused_functions": "unused_functions_count",
    "unused_imports": "unused_imports_count",
    "unused_classes": "unused_classes_count",
    "unused_variables": "unused_variables_count",
    "unused_files": "unused_files_count",
    "danger": "danger_count",
    "reliability": "reliability_count",
    "ai_defects": "ai_defects_count",
    "quality": "quality_count",
    "secrets": "secrets_count",
    "dependency_vulnerabilities": "dependency_vulnerabilities_count",
}
_STALE_SUMMARY_AGGREGATES = (
    "by_directory",
    "dead_code_evidence",
    "grep_verify",
)
_STALE_RESULT_AGGREGATES = (
    "grade",
    "ai_security_stats",
    "provenance_summary",
)


def _baseline_path(project_root: str | Path) -> Path:
    return Path(project_root) / BASELINE_DIR / BASELINE_FILE


def save_baseline(project_root: str | Path, result: dict) -> Path:
    path = _baseline_path(project_root)

    counts = {
        "unused_functions": len(result.get("unused_functions", [])),
        "unused_imports": len(result.get("unused_imports", [])),
        "unused_classes": len(result.get("unused_classes", [])),
        "unused_variables": len(result.get("unused_variables", [])),
        "unused_files": len(result.get("unused_files", [])),
        "danger": len(result.get("danger", [])),
        "reliability": len(result.get("reliability", [])),
        "ai_defects": len(result.get("ai_defects", [])),
        "quality": len(result.get("quality", [])),
        "secrets": len(result.get("secrets", [])),
        "dependency_vulnerabilities": len(result.get("dependency_vulnerabilities", [])),
    }

    fingerprints = set()
    for category in _FINDING_CATEGORIES:
        for finding in result.get(category, []):
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            fingerprints.add(fp)

    for category in _DEAD_CODE_CATEGORIES:
        for item in result.get(category, []):
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fingerprints.add(f"dead:{category}:{name}")

    baseline = {
        "counts": counts,
        "fingerprints": sorted(fingerprints),
    }
    dependency_baseline = dependency_snapshot(result, project_root)
    if dependency_baseline is not None:
        baseline["dependency_baseline"] = dependency_baseline
    if (
        len((json.dumps(baseline, indent=2) + "\n").encode("utf-8"))
        > MAX_BASELINE_BYTES
    ):
        raise ValueError("baseline exceeds size limit")
    if not save_project_json_cache(
        project_root, Path(BASELINE_DIR) / BASELINE_FILE, baseline
    ):
        raise OSError("could not safely write baseline")
    return path


def load_baseline(project_root: str | Path) -> dict | None:
    text = read_project_text_no_symlink(
        project_root,
        Path(BASELINE_DIR) / BASELINE_FILE,
        max_bytes=MAX_BASELINE_BYTES,
    )
    if text is None:
        return None
    try:
        baseline = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return baseline if isinstance(baseline, dict) else None


def filter_new_findings(
    result: dict,
    baseline: dict,
    *,
    project_root: str | Path | None = None,
    dependency_baseline: dict | None = None,
    dependency_disabled_reason: str | None = None,
    dependency_source: dict | None = None,
) -> dict:
    raw_known = baseline.get("fingerprints", [])
    known = (
        {item for item in raw_known if isinstance(item, str)}
        if isinstance(raw_known, list)
        else set()
    )

    filtered = dict(result)

    for category in _FINDING_CATEGORIES:
        original = result.get(category, [])
        new_findings = []
        for finding in original:
            fp = f"{finding.get('rule_id', '')}:{finding.get('file', '')}:{finding.get('line', 0)}"
            if fp not in known:
                new_findings.append(finding)
        filtered[category] = new_findings

    for category in _DEAD_CODE_CATEGORIES:
        original = result.get(category, [])
        new_items = []
        for item in original:
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            fp = f"dead:{category}:{name}"
            if fp not in known:
                new_items.append(item)
        filtered[category] = new_items

    if "dependency_vulnerabilities" in result or "dependency_baseline" in baseline:
        filtered = filter_dependency_findings(
            filtered,
            dependency_baseline if dependency_baseline is not None else baseline,
            project_root=project_root,
            disabled_reason=dependency_disabled_reason,
            source=dependency_source,
        )

    if "analysis_summary" in filtered:
        summary = dict(filtered.get("analysis_summary") or {})
        grep_verify = summary.get("grep_verify")
        incomplete_grep_verify = (
            grep_verify
            if isinstance(grep_verify, dict) and grep_verify.get("complete") is False
            else None
        )
        for section, count_key in _SUMMARY_COUNT_KEYS.items():
            if section in result or count_key in summary:
                summary[count_key] = len(filtered.get(section) or [])
        for key in _STALE_SUMMARY_AGGREGATES:
            summary.pop(key, None)
        if incomplete_grep_verify is not None:
            summary["grep_verify"] = incomplete_grep_verify
        filtered["analysis_summary"] = summary

    for key in _STALE_RESULT_AGGREGATES:
        filtered.pop(key, None)

    return filtered
