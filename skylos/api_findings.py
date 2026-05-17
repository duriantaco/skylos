import os

from skylos.api_snippets import extract_snippet


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
    if not isinstance(category, str):
        raise ValueError(f"category must be a string, got {type(category).__name__}")
    processed = []
    for item in items or []:
        finding = dict(item)
        category_upper = category.upper()

        rid = (
            finding.get("rule_id")
            or finding.get("rule")
            or finding.get("code")
            or finding.get("id")
            or default_rule_id
            or "UNKNOWN"
        )
        finding["rule_id"] = str(rid)

        raw_path = finding.get("file_path") or finding.get("file") or ""
        file_abs = os.path.abspath(raw_path) if raw_path else ""

        line_raw = finding.get("line_number") or finding.get("line") or 1
        try:
            line = int(line_raw)
        except (TypeError, ValueError):
            line = 1
        if line < 1:
            line = 1
        finding["line_number"] = line

        if git_root and file_abs:
            try:
                finding["file_path"] = os.path.relpath(file_abs, git_root).replace(
                    "\\", "/"
                )
            except (ValueError, OSError):
                finding["file_path"] = (
                    raw_path.replace("\\", "/") if raw_path else "unknown"
                )
        else:
            finding["file_path"] = (
                raw_path.replace("\\", "/") if raw_path else "unknown"
            )

        finding["category"] = category

        if default_severity:
            finding["severity"] = finding.get("severity") or default_severity

        if not finding.get("message"):
            name = (
                finding.get("name")
                or finding.get("symbol")
                or finding.get("function")
                or ""
            )
            if category == "DEAD_CODE" and name:
                finding["message"] = f"Dead code: {name}"
            else:
                finding["message"] = (
                    finding.get("detail") or finding.get("msg") or "Issue"
                )

        if category_upper == "SECRET":
            finding.pop("snippet", None)
        elif file_abs and line:
            finding["snippet"] = (
                finding.get("snippet")
                or extract_snippet(file_abs, line, repo_root=git_root)
                or None
            )

        if extract_metadata:
            existing_metadata = finding.get("metadata")
            metadata = (
                dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
            )
            for meta_key in (
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
            ):
                val = finding.pop(meta_key, None)
                if val is not None:
                    metadata[meta_key.lstrip("_")] = val
            if metadata:
                finding["metadata"] = metadata

        if generate_finding_id:
            finding_id = f"{finding['rule_id']}::{finding['file_path']}::{finding['line_number']}"
            finding["finding_id"] = finding_id

        processed.append(finding)

    return processed


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
