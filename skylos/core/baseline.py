from __future__ import annotations
import json
from pathlib import Path

BASELINE_DIR = ".skylos"
BASELINE_FILE = "baseline.json"

_FINDING_CATEGORIES = (
    "danger",
    "reliability",
    "ai_defects",
    "quality",
    "secrets",
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
    "danger": "danger_count",
    "reliability": "reliability_count",
    "ai_defects": "ai_defects_count",
    "quality": "quality_count",
    "secrets": "secrets_count",
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
    path.parent.mkdir(parents=True, exist_ok=True)

    counts = {
        "unused_functions": len(result.get("unused_functions", [])),
        "unused_imports": len(result.get("unused_imports", [])),
        "unused_classes": len(result.get("unused_classes", [])),
        "unused_variables": len(result.get("unused_variables", [])),
        "danger": len(result.get("danger", [])),
        "reliability": len(result.get("reliability", [])),
        "ai_defects": len(result.get("ai_defects", [])),
        "quality": len(result.get("quality", [])),
        "secrets": len(result.get("secrets", [])),
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

    path.write_text(json.dumps(baseline, indent=2) + "\n")
    return path


def load_baseline(project_root: str | Path) -> dict | None:
    path = _baseline_path(project_root)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def filter_new_findings(result: dict, baseline: dict) -> dict:
    known = set(baseline.get("fingerprints", []))

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

    if "analysis_summary" in result:
        summary = dict(result.get("analysis_summary") or {})
        for section, count_key in _SUMMARY_COUNT_KEYS.items():
            if section in result or count_key in summary:
                summary[count_key] = len(filtered.get(section) or [])
        for key in _STALE_SUMMARY_AGGREGATES:
            summary.pop(key, None)
        filtered["analysis_summary"] = summary

    for key in _STALE_RESULT_AGGREGATES:
        filtered.pop(key, None)

    return filtered
