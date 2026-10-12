import logging
import pathlib
import json

from skylos.audit.redaction import SECRET_KEYWORDS, sanitize_for_audit
from skylos.reporting.finding_types import (
    annotate_finding_types,
    get_finding_type,
    group_advice,
    iter_result_findings,
    summarize_finding_types,
)


_LLM_REPORT_CATEGORIES = {
    "ai_defects": "AI Defects",
    "security": "Security",
    "reliability": "Reliability",
    "secrets": "Secrets",
    "quality": "Quality",
    "custom_rules": "Custom Rules",
    "dead_code": "Dead Code",
    "dependencies": "Dependencies",
}
_LLM_REPORT_DEAD_CODE_META = {
    "unused_functions": ("SKY-DC001", "MEDIUM", "Unused function"),
    "unused_imports": ("SKY-DC002", "LOW", "Unused import"),
    "unused_classes": ("SKY-DC003", "MEDIUM", "Unused class"),
    "unused_variables": ("SKY-DC004", "LOW", "Unused variable"),
    "unused_parameters": ("SKY-DC005", "LOW", "Unused parameter"),
    "unused_files": ("SKY-DC006", "LOW", "Empty file"),
}
_LLM_REPORT_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _default_dead_code_llm_fields(finding, rule_id, severity, human_label):
    if not finding.get("message"):
        name = finding.get("name") or finding.get("simple_name") or ""
        why = finding.get("why_unused")
        if why:
            finding["message"] = (
                f"{human_label} '{name}' is never used ({', '.join(why)})"
            )
        else:
            finding["message"] = f"{human_label} '{name}' is never used"
    if not finding.get("rule_id"):
        finding["rule_id"] = rule_id
    if not finding.get("severity"):
        finding["severity"] = severity


def _collect_llm_report_findings(result: dict):
    annotate_finding_types(result)
    all_findings = []
    for error in result.get("analysis_errors", []) or []:
        if not isinstance(error, dict):
            continue
        finding = dict(error)
        finding.setdefault("rule_id", "SKY-ANALYSIS-INCOMPLETE")
        finding.setdefault("severity", "CRITICAL")
        finding.setdefault("message", "File analysis failed")
        all_findings.append((finding, "Analysis Incomplete"))

    for category in _LLM_REPORT_DEAD_CODE_META:
        rule_id, severity, human_label = _LLM_REPORT_DEAD_CODE_META[category]
        for finding in result.get(category, []):
            _default_dead_code_llm_fields(finding, rule_id, severity, human_label)
    for category, finding in iter_result_findings(result):
        all_findings.append((finding, _LLM_REPORT_CATEGORIES.get(category, category)))

    return all_findings


def _llm_report_sort_key(finding_with_label):
    finding, _label = finding_with_label
    return _LLM_REPORT_SEVERITY_ORDER.get(finding.get("severity", "LOW"), 4)


def _llm_report_code_block(
    file_path: str, line: int, project_root: pathlib.Path, file_cache: dict
) -> str:
    if not file_path:
        return ""
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        return ""
    if line_number < 1:
        return ""

    abs_path = _resolve_report_context_path(file_path, project_root)
    if abs_path is None:
        return ""
    cache_key = str(abs_path)

    if cache_key not in file_cache:
        try:
            if abs_path.is_file():
                file_cache[cache_key] = abs_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            else:
                file_cache[cache_key] = None
        except (OSError, ValueError) as exc:
            logging.getLogger(__name__).debug(
                "Failed to read LLM report context from %s: %s", abs_path, exc
            )
            file_cache[cache_key] = None

    src_lines = file_cache[cache_key]
    if src_lines is not None:
        start = max(0, line_number - 3)
        end = min(len(src_lines), line_number + 4)
        context_lines = []
        for i in range(start, end):
            marker = ">>>" if i == line_number - 1 else "   "
            context_lines.append(f"{marker} {i + 1:4d} | {src_lines[i]}")
        if context_lines:
            return "\n```\n" + "\n".join(context_lines) + "\n```\n"
    return ""


def _resolve_report_context_path(
    file_path: str,
    project_root: pathlib.Path,
) -> pathlib.Path | None:
    root = pathlib.Path(project_root).resolve()
    candidate = pathlib.Path(file_path)
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved


def _llm_report_secret_block(finding: dict) -> str:
    preview = finding.get("preview") or "****"
    return f"\n```\n>>> secret preview | {preview}\n```\n"


def _format_llm_report_section(finding_num, finding, label, code_block):
    if label == "Secrets":
        finding = _redacted_secret_record(finding)
    rule_id = finding.get("rule_id", "")
    severity = finding.get("severity", "INFO")
    name = finding.get("name") or finding.get("simple_name", "")
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    message = finding.get("message", "")
    finding_type = (
        "Analysis incomplete"
        if label == "Analysis Incomplete"
        else _llm_finding_type(finding, label).title()
    )
    record = json.dumps(finding, ensure_ascii=False, indent=2, default=str)

    return (
        f"\n## {finding_num}. {rule_id} | {severity} | {label}\n"
        f"Type: {finding_type}\n"
        f"File: {file_path}:{line}\n"
        f"Name: {name}\n"
        f"{code_block}\n"
        f"Problem: {message}\n"
        f"Record:\n```json\n{record}\n```\n"
        f"\n---\n"
    )


def _generate_llm_report(
    result: dict, project_root: pathlib.Path, *, expand_advice: bool = False
) -> str:
    all_findings = _collect_llm_report_findings(result)
    from skylos.reporting.assessment_display import dependency_coverage_lines

    dependency_text = "\n".join(dependency_coverage_lines(result.get("analysis_summary")))
    if dependency_text:
        dependency_text += "\n\n"
    assessment_text = ""
    if isinstance(result.get("assessment"), dict):
        from skylos.reporting.assessment_display import (
            assessment_rows,
            assessment_coverage_text,
        )

        assessment_text = "\n".join(
            f"- {label}: {detail}"
            for label, detail in assessment_rows(
                result["assessment"], gate=result.get("gate")
            )
        )
        assessment_text += (
            "\n\n" + assessment_coverage_text(result["assessment"]) + "\n\n"
        )
    if not all_findings:
        return "# Skylos Report\n\n" + assessment_text + dependency_text + "No findings.\n"

    counts = summarize_finding_types(result)
    displayed = [
        (finding, label)
        for finding, label in all_findings
        if expand_advice
        or label == "Analysis Incomplete"
        or _llm_finding_type(finding, label) != "advice"
    ]
    displayed.sort(key=_llm_report_sort_key)

    groups = counts["advice_groups"]
    sections = [
        "# Skylos Report\n\n"
        f"{counts['defect']} defects · {counts['review']} review · "
        f"{counts['advice']} advice in {groups} {'group' if groups == 1 else 'groups'}.\n\n"
        "Severity is separate from finding type.\n"
        "Review the evidence before changing code.\n\n---\n"
    ]
    if assessment_text:
        sections.insert(1, assessment_text)
    if dependency_text:
        sections.insert(1, dependency_text)
    incomplete = sum(label == "Analysis Incomplete" for _finding, label in all_findings)
    if incomplete:
        sections.insert(
            1,
            f"\nAnalysis incomplete: {incomplete} {'error' if incomplete == 1 else 'errors'}.\n",
        )
    if counts["advice"] and not expand_advice:
        sections.append(_format_advice_groups(result))
    file_cache = {}

    for finding_num, (finding, label) in enumerate(displayed, 1):
        file_path = finding.get("file", "")
        line = finding.get("line", 0)
        code_block = (
            _llm_report_secret_block(finding)
            if label == "Secrets"
            else _llm_report_code_block(file_path, line, project_root, file_cache)
        )
        sections.append(
            _format_llm_report_section(finding_num, finding, label, code_block)
        )

    return "".join(sections)


def _format_advice_groups(result: dict) -> str:
    lines = [
        "\n## Advice groups\n\n",
        "Advice is grouped below. All Defect and Review records are included. "
        "Add --expand-advice to show every Advice record; JSON output retains "
        "the complete findings.\n\n",
    ]
    for group in group_advice(result):
        count = group["count"]
        files = len(group["files"])
        lines.append(
            f"- {group['rule_id']}: {count} {'finding' if count == 1 else 'findings'} "
            f"in {files} {'file' if files == 1 else 'files'} — {group['name']}\n"
        )
    return "".join(lines)


def _llm_finding_type(finding, label):
    return get_finding_type(
        finding, "custom_rules" if label == "Custom Rules" else None
    )


def _redacted_secret_record(finding):
    """Mask known values even when evidence echoes a generic credential."""
    secrets = set()
    stack = [(finding, False)]
    while stack:
        value, sensitive = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                key = str(key).lower()
                secret_key = "preview" not in key and any(
                    word in key for word in SECRET_KEYWORDS
                )
                stack.append((item, sensitive or secret_key))
        elif isinstance(value, (list, tuple)):
            stack.extend((item, sensitive) for item in value)
        elif sensitive and isinstance(value, str) and value:
            secrets.add(value)
    return _replace_secret_values(
        sanitize_for_audit(finding), sorted(secrets, key=len, reverse=True)
    )


def _replace_secret_values(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED_SECRET]")
        return value
    if isinstance(value, list):
        return [_replace_secret_values(item, secrets) for item in value]
    if isinstance(value, dict):
        return {
            key: _replace_secret_values(item, secrets) for key, item in value.items()
        }
    return value
