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
    "ai_defects",
    "quality",
    "secrets",
    "custom_rules",
)
_GITHUB_DEAD_CODE_CATEGORIES = (
    ("unused_functions", "Unused function"),
    ("unused_imports", "Unused import"),
    ("unused_classes", "Unused class"),
    ("unused_variables", "Unused variable"),
    ("unused_parameters", "Unused parameter"),
)


def _emit_github_grade_annotation(result):
    grade_data = result.get("grade")
    if grade_data:
        overall = grade_data["overall"]
        print(
            f"::notice title=Skylos Grade::{overall['letter']} ({overall['score']}/100)"
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
    for category in _GITHUB_FINDING_CATEGORIES:
        for finding in result.get(category, []) or []:
            annotations.append(_github_finding_annotation(finding))

    for category, label in _GITHUB_DEAD_CODE_CATEGORIES:
        for item in result.get(category, []) or []:
            annotations.append(_github_dead_code_annotation(item, label))
    return annotations


def _filter_github_annotations_by_severity(annotations, severity_filter):
    if severity_filter:
        allowed = _GITHUB_ANNOTATION_THRESHOLDS.get(severity_filter, set())
        return [a for a in annotations if a["severity"] in allowed]
    return annotations


def _github_annotation_sort_key(annotation):
    return _GITHUB_ANNOTATION_PRIORITY.get(annotation["severity"], 99)


def _emit_github_annotation(annotation):
    level = _GITHUB_ANNOTATION_LEVELS.get(annotation["severity"], "warning")
    print(
        f"::{level} file={annotation['file']},line={annotation['line']},"
        f"title={annotation['title']}::{annotation['msg']}"
    )


def _emit_github_annotations(result, *, max_annotations=50, severity_filter=None):
    _emit_github_grade_annotation(result)
    annotations = _github_annotation_items(result)
    annotations = _filter_github_annotations_by_severity(annotations, severity_filter)
    annotations.sort(key=_github_annotation_sort_key)

    for annotation in annotations[:max_annotations]:
        _emit_github_annotation(annotation)
