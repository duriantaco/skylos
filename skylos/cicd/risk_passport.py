from __future__ import annotations

from typing import Any

from skylos.cicd.evidence import (
    build_evidence_cards,
    evidence_counts,
    redact_sensitive_text,
)

_SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def build_risk_passport(
    *,
    all_findings: list[dict[str, Any]],
    diff_findings: list[dict[str, Any]],
    provenance: dict[str, Any] | None = None,
    defense_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provenance_data = provenance if isinstance(provenance, dict) else {}
    ai_files = _agent_files(provenance_data)
    reasons: list[str] = []
    warning_reasons: list[str] = []
    high_risk_ai_files: set[str] = set()
    weakened_controls: set[str] = set()

    cards = build_evidence_cards(diff_findings)
    counts = evidence_counts(cards)

    for finding, card in zip(diff_findings, cards):
        severity_score = _severity_score(finding.get("severity"))
        is_ai = _is_ai_authored_finding(finding, provenance_data, ai_files)
        file_label = _display_file(finding.get("file"))

        if card.kind == "security_regression":
            control = str(finding.get("control_type") or "unknown")
            weakened_controls.add(control)
            reasons.append(f"Changed-line security regression: {control}")
            continue

        if card.kind == "secret":
            reasons.append(
                f"Changed-line secret exposure in {file_label or 'unknown file'}"
            )
            continue

        if (
            is_ai
            and card.kind == "security"
            and severity_score >= _SEVERITY_SCORE["HIGH"]
            and card.label in {"proven", "likely"}
        ):
            if file_label:
                high_risk_ai_files.add(file_label)
            severity = str(finding.get("severity") or "HIGH").upper()
            reasons.append(
                f"AI-authored {card.label} {severity} security finding"
            )
            continue

        if severity_score >= _SEVERITY_SCORE["HIGH"] and card.label == "speculative":
            warning_reasons.append(
                f"High-severity speculative finding in {file_label or 'unknown file'}"
            )
            continue

        if is_ai and severity_score > 0:
            warning_reasons.append(
                f"AI-authored changed-line finding in {file_label or 'unknown file'}"
            )

    missing_guardrails, defense_block_files, defense_warnings = _defense_risk(
        defense_report, ai_files
    )
    high_risk_ai_files.update(defense_block_files)
    reasons.extend(
        f"AI-authored LLM integration failed high-risk guardrail: {plugin_id}"
        for plugin_id in missing_guardrails["blocking"]
    )
    warning_reasons.extend(defense_warnings)

    if provenance_data.get("confidence") == "low" and ai_files:
        warning_reasons.append("AI provenance detected with low confidence")

    recommendation: str
    if reasons:
        recommendation = "BLOCK"
    elif warning_reasons:
        recommendation = "WARN"
    else:
        recommendation = "PASS"

    summary = provenance_data.get("summary") or {}
    agents = summary.get("agents_seen") or []

    return {
        "recommendation": recommendation,
        "ai_authored_files": len(ai_files),
        "ai_agents": sorted(str(agent) for agent in agents if str(agent).strip()),
        "provenance_confidence": provenance_data.get("confidence") or "unavailable",
        "changed_line_evidence": counts,
        "high_risk_ai_files": sorted(high_risk_ai_files),
        "security_controls_weakened": sorted(weakened_controls),
        "missing_llm_guardrails": sorted(
            set(missing_guardrails["blocking"] + missing_guardrails["warning"])
        ),
        "reasons": reasons,
        "warnings": warning_reasons,
    }


def format_risk_passport_markdown(passport: dict[str, Any] | None) -> list[str]:
    if not passport:
        return []

    counts = passport.get("changed_line_evidence") or {}
    evidence_text = (
        f"Proven {int(counts.get('proven') or 0)} / "
        f"Likely {int(counts.get('likely') or 0)} / "
        f"Speculative {int(counts.get('speculative') or 0)}"
    )

    lines = [
        "",
        "### AI PR Risk Passport",
        "",
        f"**Merge recommendation: {passport.get('recommendation', 'PASS')}**",
        "",
        "| Signal | Value |",
        "|--------|-------|",
        f"| AI-authored files | {int(passport.get('ai_authored_files') or 0)} |",
        f"| Agents | {_join_values(passport.get('ai_agents'))} |",
        "| Provenance confidence | "
        f"{passport.get('provenance_confidence') or 'unavailable'} |",
        f"| Changed-line evidence | {evidence_text} |",
        f"| High-risk AI files | {_join_values(passport.get('high_risk_ai_files'))} |",
        "| Security controls weakened | "
        f"{_join_values(passport.get('security_controls_weakened'))} |",
        "| Missing LLM guardrails | "
        f"{_join_values(passport.get('missing_llm_guardrails'))} |",
    ]

    reasons = list(passport.get("reasons") or [])
    warnings = list(passport.get("warnings") or [])
    if reasons or warnings:
        lines.extend(["", "**Reasons:**"])
        for reason in reasons[:5]:
            lines.append(f"- BLOCK: {redact_sensitive_text(reason)}")
        for warning in warnings[:5]:
            lines.append(f"- WARN: {redact_sensitive_text(warning)}")

    return lines


def _defense_risk(
    defense_report: dict[str, Any] | None, ai_files: set[str]
) -> tuple[dict[str, list[str]], set[str], list[str]]:
    missing = {"blocking": [], "warning": []}
    block_files: set[str] = set()
    warnings: list[str] = []

    if not isinstance(defense_report, dict):
        return missing, block_files, warnings

    for finding in defense_report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if finding.get("passed") is not False:
            continue
        if str(finding.get("category") or "defense") != "defense":
            continue

        plugin_id = str(finding.get("plugin_id") or "unknown_guardrail")
        severity_score = _severity_score(finding.get("severity"))
        location = _location_file(
            finding.get("location") or finding.get("integration_location")
        )
        matched_ai_file = _matched_ai_file(location, ai_files)

        if severity_score >= _SEVERITY_SCORE["HIGH"] and matched_ai_file:
            missing["blocking"].append(plugin_id)
            block_files.add(matched_ai_file)
        else:
            missing["warning"].append(plugin_id)
            warnings.append(f"LLM defense guardrail failed: {plugin_id}")

    missing["blocking"] = sorted(set(missing["blocking"]))
    missing["warning"] = sorted(set(missing["warning"]))
    return missing, block_files, warnings


def _is_ai_authored_finding(
    finding: dict[str, Any], provenance: dict[str, Any], ai_files: set[str]
) -> bool:
    if finding.get("ai_authored") is True:
        return True
    if finding.get("ai_authored") is False and not provenance:
        return False

    file_path = _location_file(finding.get("file") or finding.get("file_path"))
    if not file_path:
        return False

    file_prov = _file_provenance(file_path, provenance)
    if file_prov is not None:
        if not file_prov.get("agent_authored"):
            return False
        ranges = file_prov.get("agent_lines") or []
        line = _int_or_none(finding.get("line") or finding.get("line_number"))
        if ranges and line is not None:
            return _line_in_ranges(line, ranges)
        return True

    return _matched_ai_file(file_path, ai_files) is not None


def _file_provenance(
    file_path: str, provenance: dict[str, Any]
) -> dict[str, Any] | None:
    files = provenance.get("files") or {}
    if not isinstance(files, dict):
        return None
    if isinstance(files.get(file_path), dict):
        return files[file_path]
    for prov_path, data in files.items():
        if _paths_match(file_path, str(prov_path)) and isinstance(data, dict):
            return data
    return None


def _line_in_ranges(line: int, ranges: list[Any]) -> bool:
    for raw_range in ranges:
        if not isinstance(raw_range, (list, tuple)) or len(raw_range) < 2:
            continue
        start = _int_or_none(raw_range[0])
        end = _int_or_none(raw_range[1])
        if start is not None and end is not None and start <= line <= end:
            return True
    return False


def _agent_files(provenance: dict[str, Any]) -> set[str]:
    return {
        str(path).replace("\\", "/")
        for path in (provenance.get("agent_files") or [])
        if str(path).strip()
    }


def _matched_ai_file(location: str | None, ai_files: set[str]) -> str | None:
    if not location:
        return None
    for ai_file in ai_files:
        if _paths_match(location, ai_file):
            return ai_file
    return None


def _paths_match(left: str, right: str) -> bool:
    left_norm = left.replace("\\", "/").strip("/")
    right_norm = right.replace("\\", "/").strip("/")
    if not left_norm or not right_norm:
        return False
    return (
        left_norm == right_norm
        or left_norm.endswith("/" + right_norm)
        or right_norm.endswith("/" + left_norm)
    )


def _location_file(raw: Any) -> str:
    text = str(raw or "").strip().replace("\\", "/")
    if not text:
        return ""
    if ":" in text:
        path_part, maybe_line = text.rsplit(":", 1)
        if maybe_line.isdigit():
            return path_part
    return text


def _display_file(raw: Any) -> str:
    path = _location_file(raw)
    return path.rsplit("/", 1)[-1] if path else ""


def _severity_score(raw: Any) -> int:
    return _SEVERITY_SCORE.get(str(raw or "").upper(), 0)


def _int_or_none(raw: Any) -> int | None:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _join_values(raw: Any) -> str:
    values = [redact_sensitive_text(item) for item in raw or [] if str(item).strip()]
    return ", ".join(values[:5]) if values else "-"
