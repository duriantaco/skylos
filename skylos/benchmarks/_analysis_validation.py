from __future__ import annotations

from collections.abc import Mapping

from skylos.analysis.errors import analysis_result_incomplete


def analysis_issues(result: object, *, scanner: str) -> list[str]:
    if not isinstance(result, Mapping):
        return ["scanner report is not an object"]

    issues = []
    if "analysis_errors" in result and not isinstance(result["analysis_errors"], list):
        issues.append("analysis_errors is not a list")
    if analysis_result_incomplete(result):
        issues.append("scanner reports incomplete analysis")

    summary = result.get("analysis_summary")
    if not isinstance(summary, Mapping):
        if scanner == "skylos" or "analysis_summary" in result:
            issues.append("analysis_summary is missing or is not an object")
        summary = {}
    if scanner == "skylos":
        count = summary.get("total_files")
        if type(count) is not int or count <= 0:
            issues.append("analysis_summary.total_files must be a positive integer")
    if "analysis_error_count" in summary:
        count = summary["analysis_error_count"]
        if type(count) is not int or count < 0:
            issues.append("analysis_error_count must be a nonnegative integer")
        elif count:
            issues.append(f"analysis_error_count is {count}")

    if "incomplete_languages" in summary and not isinstance(
        summary["incomplete_languages"], list
    ):
        issues.append("incomplete_languages is not a list")
    if "language_engines" in summary:
        engines = summary["language_engines"]
        if not isinstance(engines, Mapping) or any(
            not isinstance(engine, Mapping)
            or engine.get("status") != "available"
            or engine.get("complete") is False
            for engine in engines.values()
        ):
            issues.append("language engine analysis is unavailable or incomplete")
    if "grep_verify" in summary and not isinstance(summary["grep_verify"], Mapping):
        issues.append("grep_verify metadata is not an object")
    for metadata in (result, summary):
        if "analysis_status" in metadata:
            status = metadata["analysis_status"]
            if not isinstance(status, str) or status not in {"complete", "completed"}:
                issues.append("analysis_status is not complete")

    if "assessment" in result:
        assessment = result["assessment"]
        if not isinstance(assessment, Mapping):
            issues.append("assessment is not an object")
        else:
            coverage = assessment.get("coverage")
            if "coverage" in assessment and not isinstance(coverage, Mapping):
                issues.append("assessment.coverage is not an object")
            elif isinstance(coverage, Mapping):
                if coverage.get("status") == "incomplete":
                    issues.append("assessment coverage is incomplete")
                if "incomplete_checks" in coverage and (
                    not isinstance(coverage["incomplete_checks"], list)
                    or coverage["incomplete_checks"]
                ):
                    issues.append("assessment contains incomplete checks")
    return list(dict.fromkeys(issues))
