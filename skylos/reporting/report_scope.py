"""What a scan reports, after analysis: generated files and severity.

Two adjustments run before the grade and directory rollups are computed, so
counts, grades and gates describe exactly what is reported:

* findings located in files the scan treats as generated (Django migrations)
  are not reported, except security, reliability, secret and custom-rule
  findings (see ``skylos.core.generated_files``);
* CRITICAL is reserved for issues in shipped code: a CRITICAL finding in a
  test file is reported as HIGH, except secrets, which leak wherever they are
  committed.
"""

from __future__ import annotations

from pathlib import Path

from skylos.constants import get_non_library_dir_kind
from skylos.core.generated_files import (
    REPORT_ONLY_DROPPED_SECTIONS,
    finding_in_files,
)

_SUMMARY_COUNT_KEYS = {
    "quality": "quality_count",
    "ai_defects": "ai_defects_count",
    "danger": "danger_count",
    "reliability": "reliability_count",
    "custom_rules": "custom_rules_count",
    "unused_files": "unused_files_count",
    "unused_exports": "unused_exports_count",
}
TEST_FILE_CAPPED_SECTIONS = (
    "danger",
    "reliability",
    "quality",
    "ai_defects",
    "custom_rules",
)
TEST_FILE_SEVERITY_CAP = "HIGH"


def report_only_file_keys(analyzer) -> frozenset[str]:
    scope = getattr(analyzer, "_generated_file_scope", None)
    if scope is None:
        return frozenset()
    return scope.report_only_keys()


def without_report_only_files(items, file_keys: frozenset[str]) -> list:
    if not file_keys:
        return list(items or [])
    return [item for item in items or [] if not finding_in_files(item, file_keys)]


def apply_report_scope(result: dict, analyzer) -> None:
    summary = result.setdefault("analysis_summary", {})
    changed_sections: set[str] = set()

    scope = getattr(analyzer, "_generated_file_scope", None)
    if scope is not None:
        file_keys = scope.report_only_keys()
        not_reported = 0
        for section in REPORT_ONLY_DROPPED_SECTIONS:
            items = result.get(section)
            if not isinstance(items, list) or not items:
                continue
            kept = without_report_only_files(items, file_keys)
            if len(kept) != len(items):
                not_reported += len(items) - len(kept)
                result[section] = kept
                changed_sections.add(section)
        generated_summary = scope.summary()
        generated_summary["findings_not_reported"] = not_reported
        summary["generated_files"] = generated_summary

    capped = cap_test_file_severity(result, getattr(analyzer, "_project_root", None))
    if capped:
        summary["test_file_severity_capped"] = capped

    bare_noqa = count_bare_noqa_security_findings(result)
    if bare_noqa:
        summary["bare_noqa_security_findings"] = bare_noqa

    for section in changed_sections:
        count_key = _SUMMARY_COUNT_KEYS.get(section)
        if count_key and (count_key in summary or result.get(section)):
            summary[count_key] = len(result.get(section) or [])


_BARE_NOQA_SECTIONS = ("danger", "secrets", "ai_defects", "quality")


def count_bare_noqa_security_findings(result: dict) -> int:
    """HIGH/CRITICAL security findings that sit on a bare ``# noqa``, which
    no longer hides them (``skylos.analysis.finding_filter``)."""
    return sum(
        1
        for section in _BARE_NOQA_SECTIONS
        for finding in result.get(section) or []
        if isinstance(finding, dict) and finding.get("bare_noqa_ignored")
    )


def cap_test_file_severity(result: dict, project_root=None) -> int:
    """Report CRITICAL findings in test files as HIGH; return how many."""
    root = Path(project_root) if project_root is not None else None
    capped = 0
    for section in TEST_FILE_CAPPED_SECTIONS:
        for finding in result.get(section) or []:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("severity", "")).upper() != "CRITICAL":
                continue
            file_value = finding.get("file") or finding.get("file_path")
            if not file_value or not _is_test_file(file_value, root):
                continue
            finding["original_severity"] = finding.get("severity")
            finding["severity"] = TEST_FILE_SEVERITY_CAP
            finding["severity_reason"] = "test_file"
            capped += 1
    return capped


def _is_test_file(file_value, root: Path | None) -> bool:
    return get_non_library_dir_kind(str(file_value), root) == "test"
