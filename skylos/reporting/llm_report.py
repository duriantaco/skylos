import logging
import pathlib


_LLM_REPORT_CATEGORIES = [
    ("ai_defects", "AI Defects"),
    ("danger", "Security"),
    ("secrets", "Secrets"),
    ("quality", "Quality"),
    ("custom_rules", "Custom Rules"),
]
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
    all_findings = []
    for category, label in _LLM_REPORT_CATEGORIES:
        for finding in result.get(category, []):
            all_findings.append((finding, label))

    for category in _LLM_REPORT_DEAD_CODE_META:
        rule_id, severity, human_label = _LLM_REPORT_DEAD_CODE_META[category]
        for finding in result.get(category, []):
            _default_dead_code_llm_fields(finding, rule_id, severity, human_label)
            all_findings.append((finding, "Dead Code"))

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
    rule_id = finding.get("rule_id", "")
    severity = finding.get("severity", "INFO")
    name = finding.get("name") or finding.get("simple_name", "")
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    message = finding.get("message", "")

    return (
        f"\n## {finding_num}. {rule_id} | {severity} | {label}\n"
        f"File: {file_path}:{line}\n"
        f"Name: {name}\n"
        f"{code_block}\n"
        f"Problem: {message}\n"
        f"\n---\n"
    )


def _generate_llm_report(result: dict, project_root: pathlib.Path) -> str:
    all_findings = _collect_llm_report_findings(result)
    if not all_findings:
        return "# Skylos Report\n\nNo findings.\n"

    all_findings.sort(key=_llm_report_sort_key)

    sections = [
        f"# Skylos Report — {len(all_findings)} findings\n\n"
        f"Fix each finding below. The code context shows the problematic lines.\n\n---\n"
    ]
    file_cache = {}

    for finding_num, (finding, label) in enumerate(all_findings, 1):
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
