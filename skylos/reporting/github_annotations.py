import os
from pathlib import Path

_GITHUB_ANNOTATION_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "notice",
}
_GITHUB_ANNOTATION_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_GITHUB_ANNOTATION_THRESHOLDS = {
    "critical": {"CRITICAL"},
    "high": {"CRITICAL", "HIGH"},
    "medium": {"CRITICAL", "HIGH", "MEDIUM"},
    "low": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
}
_GITHUB_FINDING_CATEGORIES = (
    "danger",
    "reliability",
    "ai_defects",
    "quality",
    "secrets",
    "custom_rules",
    "unused_files",
)
_GITHUB_DEAD_CODE_CATEGORIES = (
    ("unused_functions", "Unused function"),
    ("unused_imports", "Unused import"),
    ("unused_classes", "Unused class"),
    ("unused_variables", "Unused variable"),
    ("unused_parameters", "Unused parameter"),
)


def _escape_github_command_data(value):
    """Escape a GitHub workflow-command data value."""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_github_command_property(value):
    """Escape a GitHub workflow-command property value."""
    return _escape_github_command_data(value).replace(":", "%3A").replace(",", "%2C")


def _emit_github_grade_annotation(result):
    assessment = result.get("assessment")
    if isinstance(assessment, dict) and assessment:
        from skylos.reporting.assessment_display import (
            assessment_notice,
            assessment_coverage_text,
        )

        message = (
            assessment_notice(assessment, gate=result.get("gate"))
            + " | "
            + assessment_coverage_text(assessment)
        )
        print(
            f"::notice title=Skylos Assessment::{_escape_github_command_data(message)}"
        )
        return
    grade_data = result.get("grade")
    if grade_data:
        overall = grade_data["overall"]
        grade = f"{overall['letter']} ({overall['score']}/100)"
        print(
            f"::notice title=Skylos Legacy Score::{_escape_github_command_data(grade)}"
        )


def _github_finding_annotation(finding):
    file = finding.get("file") or finding.get("file_path") or ""
    line = finding.get("line") or finding.get("line_number") or 1
    msg = (
        finding.get("message")
        or finding.get("msg")
        or finding.get("detail")
        or "Issue detected"
    )
    rule_id = finding.get("rule_id") or ""
    severity = finding.get("severity", "MEDIUM").upper()
    title = f"Skylos {rule_id}" if rule_id else "Skylos"
    return {
        "file": file,
        "line": line,
        "msg": msg,
        "title": title,
        "severity": severity,
    }


def _github_dead_code_annotation(item, label):
    name = item.get("name", "") if isinstance(item, dict) else str(item)
    file = item.get("file", "") if isinstance(item, dict) else ""
    line = item.get("line", 1) if isinstance(item, dict) else 1
    return {
        "file": file,
        "line": line,
        "msg": f"{label}: {name}",
        "title": "Skylos Dead Code",
        "severity": "MEDIUM",
    }


def _github_annotation_items(result):
    annotations = []
    for error in result.get("analysis_errors", []) or []:
        if not isinstance(error, dict):
            continue
        annotations.append(
            {
                "file": error.get("file") or "",
                "line": error.get("line") or 1,
                "msg": error.get("message") or "File analysis failed",
                "title": "Skylos Analysis Incomplete",
                "severity": "CRITICAL",
            }
        )

    for category in _GITHUB_FINDING_CATEGORIES:
        for finding in result.get(category, []) or []:
            annotations.append(_github_finding_annotation(finding))

    for category, label in _GITHUB_DEAD_CODE_CATEGORIES:
        for item in result.get(category, []) or []:
            annotations.append(_github_dead_code_annotation(item, label))
    return annotations


def _recorded_analysis_root(result):
    summary = result.get("analysis_summary") if isinstance(result, dict) else None
    if not isinstance(summary, dict):
        return None
    scope = summary.get("comparison_scope")
    if not isinstance(scope, dict):
        return None
    recorded = scope.get("repository_root")
    if isinstance(recorded, str) and recorded and Path(recorded).is_absolute():
        return Path(recorded)
    return None


def _github_annotation_roots(result, root_path):
    """The folder relative finding paths start from, and the repository root."""
    from skylos.core.file_discovery import find_git_root

    analysis_root = _recorded_analysis_root(result)
    if analysis_root is None and root_path is not None:
        from skylos.analyzer import _resolve_analysis_root

        scan_root = Path(root_path).resolve()
        if not scan_root.is_dir():
            scan_root = scan_root.parent
        analysis_root = _resolve_analysis_root(scan_root)
    if analysis_root is None:
        return None, None
    repo_root = find_git_root(analysis_root)
    if repo_root is None and root_path is not None:
        repo_root = find_git_root(root_path)
    if repo_root is None:
        repo_root = analysis_root
    return analysis_root, Path(repo_root).resolve()


def _github_repo_relative_path(file, analysis_root, repo_root):
    """GitHub places annotations by repository-relative path."""
    raw = str(file or "")
    if not raw or repo_root is None:
        return raw
    path = Path(raw)
    if not path.is_absolute():
        path = Path(analysis_root) / path
    candidates = [Path(os.path.abspath(path))]
    try:
        candidates.append(path.resolve())
    except (OSError, RuntimeError):
        pass
    for candidate in candidates:
        try:
            return candidate.relative_to(repo_root).as_posix()
        except ValueError:
            continue
    return raw


def _filter_github_annotations_by_severity(annotations, severity_filter):
    if severity_filter:
        allowed = _GITHUB_ANNOTATION_THRESHOLDS.get(severity_filter, set())
        return [a for a in annotations if a["severity"] in allowed]
    return annotations


def _github_annotation_sort_key(annotation):
    return _GITHUB_ANNOTATION_PRIORITY.get(annotation["severity"], 99)


def _emit_github_annotation(annotation):
    level = _GITHUB_ANNOTATION_LEVELS.get(annotation["severity"], "warning")
    file = _escape_github_command_property(annotation["file"])
    line = _escape_github_command_property(annotation["line"])
    title = _escape_github_command_property(annotation["title"])
    msg = _escape_github_command_data(annotation["msg"])
    print(f"::{level} file={file},line={line},title={title}::{msg}")


def _emit_github_annotations(
    result, *, max_annotations=50, severity_filter=None, root_path=None
):
    _emit_github_grade_annotation(result)
    from skylos.reporting.assessment_display import dependency_coverage_lines

    coverage = dependency_coverage_lines(result.get("analysis_summary"))
    if coverage:
        print(
            "::notice title=Skylos Dependency Coverage::"
            + _escape_github_command_data(" | ".join(coverage))
        )
    annotations = _github_annotation_items(result)
    annotations = _filter_github_annotations_by_severity(annotations, severity_filter)
    annotations.sort(key=_github_annotation_sort_key)
    analysis_root, repo_root = _github_annotation_roots(result, root_path)
    for annotation in annotations:
        annotation["file"] = _github_repo_relative_path(
            annotation["file"], analysis_root, repo_root
        )

    for annotation in annotations[:max_annotations]:
        _emit_github_annotation(annotation)
