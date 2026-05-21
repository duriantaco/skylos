import os

from skylos.api._snippets import extract_snippet


__all__ = [
    "UPLOAD_FINDING_SPECS",
    "VERIFY_FINDING_SPECS",
    "_normalize_findings",
    "_normalize_result_sections",
]


UPLOAD_FINDING_SPECS = (
    ("danger", "SECURITY", "SKY-D000"),
    ("quality", "QUALITY", "SKY-Q000"),
    ("secrets", "SECRET", "SKY-S000"),
    ("unused_functions", "DEAD_CODE", "SKY-U001"),
    ("unused_imports", "DEAD_CODE", "SKY-U002"),
    ("unused_variables", "DEAD_CODE", "SKY-U003"),
    ("unused_classes", "DEAD_CODE", "SKY-U004"),
    ("dependency_vulnerabilities", "DEPENDENCY", "SKY-SCA-000"),
)

VERIFY_FINDING_SPECS = (
    ("danger", "SECURITY", "SKY-D000"),
    ("secrets", "SECRET", "SKY-S000"),
)

_PRIVATE_METADATA_KEYS = (
    "_source",
    "_confidence",
    "_llm_verdict",
    "_llm_rationale",
    "_llm_challenged",
    "_needs_review",
    "_llm_uncertain",
    "_ci_blocking",
    "_security_evidence",
    "_review_verdict",
    "_review_reason",
)


def _normalize_findings(
    items,
    category,
    git_root,
    default_rule_id=None,
    default_severity=None,
    extract_metadata=False,
    generate_finding_id=False,
) -> list[dict]:
    """Unified finding normalization used by upload and verify paths."""
    _validate_category(category)
    return [
        _normalize_finding(
            dict(item),
            category,
            git_root,
            default_rule_id=default_rule_id,
            default_severity=default_severity,
            extract_metadata=extract_metadata,
            generate_finding_id=generate_finding_id,
        )
        for item in items or []
    ]


def _validate_category(category) -> None:
    if not isinstance(category, str):
        raise ValueError(f"category must be a string, got {type(category).__name__}")


def _normalize_finding(
    finding: dict,
    category: str,
    git_root,
    *,
    default_rule_id=None,
    default_severity=None,
    extract_metadata=False,
    generate_finding_id=False,
) -> dict:
    raw_path = finding.get("file_path") or finding.get("file") or ""
    file_abs = os.path.abspath(raw_path) if raw_path else ""
    line = _coerce_line_number(finding.get("line_number") or finding.get("line") or 1)

    finding["rule_id"] = _normalize_rule_id(finding, default_rule_id)
    finding["line_number"] = line
    finding["file_path"] = _normalize_file_path(raw_path, file_abs, git_root)
    finding["category"] = category
    _apply_default_severity(finding, default_severity)
    _apply_default_message(finding, category)
    _apply_snippet(finding, category, file_abs, line, git_root)

    if extract_metadata:
        _move_private_metadata(finding)
    if generate_finding_id:
        finding["finding_id"] = _finding_id(finding)
    return finding


def _normalize_rule_id(finding: dict, default_rule_id=None) -> str:
    rid = (
        finding.get("rule_id")
        or finding.get("rule")
        or finding.get("code")
        or finding.get("id")
        or default_rule_id
        or "UNKNOWN"
    )
    return str(rid)


def _coerce_line_number(value) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return 1
    return max(line, 1)


def _normalize_file_path(raw_path: str, file_abs: str, git_root) -> str:
    if not raw_path:
        return "unknown"
    if not (git_root and file_abs):
        return raw_path.replace("\\", "/")
    try:
        return os.path.relpath(file_abs, git_root).replace("\\", "/")
    except (ValueError, OSError):
        return raw_path.replace("\\", "/")


def _apply_default_severity(finding: dict, default_severity=None) -> None:
    if default_severity:
        finding["severity"] = finding.get("severity") or default_severity


def _apply_default_message(finding: dict, category: str) -> None:
    if finding.get("message"):
        return
    name = finding.get("name") or finding.get("symbol") or finding.get("function") or ""
    if category == "DEAD_CODE" and name:
        finding["message"] = f"Dead code: {name}"
        return
    finding["message"] = finding.get("detail") or finding.get("msg") or "Issue"


def _apply_snippet(
    finding: dict,
    category: str,
    file_abs: str,
    line: int,
    git_root,
) -> None:
    if category.upper() == "SECRET":
        finding.pop("snippet", None)
        return
    if file_abs and line:
        finding["snippet"] = (
            finding.get("snippet")
            or extract_snippet(file_abs, line, repo_root=git_root)
            or None
        )


def _move_private_metadata(finding: dict) -> None:
    existing_metadata = finding.get("metadata")
    metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    for meta_key in _PRIVATE_METADATA_KEYS:
        val = finding.pop(meta_key, None)
        if val is not None:
            metadata[meta_key.lstrip("_")] = val
    if metadata:
        finding["metadata"] = metadata


def _finding_id(finding: dict) -> str:
    return f"{finding['rule_id']}::{finding['file_path']}::{finding['line_number']}"


def _normalize_result_sections(
    result_json,
    section_specs,
    git_root,
    *,
    default_severity=None,
    extract_metadata=False,
    generate_finding_id=False,
) -> list[dict]:
    findings: list[dict] = []
    for section_name, category, default_rule_id in section_specs:
        findings.extend(
            _normalize_findings(
                result_json.get(section_name, []),
                category,
                git_root,
                default_rule_id=default_rule_id,
                default_severity=default_severity,
                extract_metadata=extract_metadata,
                generate_finding_id=generate_finding_id,
            )
        )
    return findings
