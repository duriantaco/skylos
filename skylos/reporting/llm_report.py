import logging
import pathlib
import json
from copy import deepcopy

from skylos.audit.redaction import SECRET_KEYWORDS, sanitize_for_audit
from skylos.reporting.advice_display import (
    ADVICE_PRIORITY_NOTE,
    advice_display_counts,
    advice_priority,
    combine_complexity_advice,
    complexity_display,
    group_advice_for_display,
)
from skylos.reporting.advice_policy import prepare_advice_view
from skylos.reporting.finding_types import (
    annotate_finding_types,
    get_finding_type,
    iter_result_findings,
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
    complexity = complexity_display(finding)
    rule_id = complexity.rule_label if complexity else finding.get("rule_id", "")
    severity = (
        advice_priority(finding, "quality" if label == "Quality" else label.lower())
        if _llm_finding_type(finding, label) == "advice"
        else finding.get("severity", "INFO")
    )
    name = finding.get("name") or finding.get("simple_name", "")
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    message = complexity.message if complexity else finding.get("message", "")
    finding_type = (
        "Analysis incomplete"
        if label == "Analysis Incomplete"
        else _llm_finding_type(finding, label).title()
    )
    original_findings = complexity.findings if complexity else (finding,)
    check = f"Check: {complexity.name}\n" if complexity else ""
    records = "\n".join(
        "Record:\n```json\n"
        + json.dumps(original, ensure_ascii=False, indent=2, default=str)
        + "\n```\n"
        for original in original_findings
    )

    return (
        f"\n## {finding_num}. {rule_id} | {severity} | {label}\n"
        f"Type: {finding_type}\n"
        f"File: {file_path}:{line}\n"
        f"Name: {name}\n"
        f"{check}"
        f"{code_block}\n"
        f"Problem: {message}\n"
        f"{records}"
        f"\n---\n"
    )


def _generate_llm_report(
    result: dict,
    project_root: pathlib.Path,
    *,
    expand_advice: bool = False,
    all_advice: bool = False,
) -> str:
    result, visibility = prepare_advice_view(
        result, project_root=project_root, all_advice=all_advice
    )
    # The collector supplies display defaults in place; keep those off raw data.
    result = deepcopy(result)
    all_findings = _collect_llm_report_findings(result)
    from skylos.reporting.assessment_display import dependency_coverage_lines

    dependency_text = "\n".join(
        dependency_coverage_lines(result.get("analysis_summary"))
    )
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
    summary = result.get("analysis_summary") or {}
    if summary.get("assessment_includes_filtered_findings") or summary.get(
        "grade_includes_filtered_findings"
    ):
        label = "Assessment" if result.get("assessment") else "Grade"
        assessment_text += f"{label} includes all analyzed findings, including those outside this display.\n\n"
    visibility_text = visibility.message + "\n\n" if visibility.message else ""
    if not all_findings:
        empty_text = (
            "No findings to display.\n" if visibility.message else "No findings.\n"
        )
        return (
            "# Skylos Report\n\n"
            + assessment_text
            + dependency_text
            + visibility_text
            + empty_text
        )

    counts = advice_display_counts(result)
    category_for_label = {
        label: category for category, label in _LLM_REPORT_CATEGORIES.items()
    }
    display_findings = combine_complexity_advice(
        (category_for_label.get(label, label), finding)
        for finding, label in all_findings
    )
    displayed = [
        (finding, _LLM_REPORT_CATEGORIES.get(category, category))
        for category, finding in display_findings
        if expand_advice
        or category == "Analysis Incomplete"
        or get_finding_type(finding, category) != "advice"
    ]
    displayed.sort(key=_llm_report_sort_key)

    groups = counts["advice_groups"]
    entry_label = "entry" if counts["advice"] == 1 else "entries"
    advice_count = (
        f"{counts['advice']} advice {entry_label} ({counts['raw_advice']} findings)"
        if counts["raw_advice"] != counts["advice"]
        else f"{counts['advice']} advice"
    )
    defect_label = "defect" if counts["defect"] == 1 else "defects"
    sections = [
        "# Skylos Report\n\n"
        f"{counts['defect']} {defect_label} · {counts['review']} review · "
        f"{advice_count} in {groups} {'group' if groups == 1 else 'groups'}.\n\n"
        "Severity is separate from finding type.\n"
        "Review the evidence before changing code.\n\n---\n"
    ]
    if assessment_text:
        sections.insert(1, assessment_text)
    if dependency_text:
        sections.insert(1, dependency_text)
    if visibility_text:
        sections.insert(1, visibility_text)
    if counts["advice"]:
        sections.insert(1, f"\n{ADVICE_PRIORITY_NOTE}\n")
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
        "Add --expand-advice to show every visible Advice entry, including each original "
        "record for grouped metric checks; JSON output holds the same findings "
        "with their full records.\n\n",
    ]
    for group in group_advice_for_display(result):
        count = group["count"]
        files = len(group["files"])
        priority = ", ".join(
            sorted(
                {
                    advice_priority(finding, "quality")
                    for finding in group["findings"]
                }
            )
        )
        lines.append(
            f"- {group['rule_id']}: {count} advice {'entry' if count == 1 else 'entries'} "
            f"in {files} {'file' if files == 1 else 'files'} — {group['name']}; "
            f"Advice priority: {priority}\n"
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
