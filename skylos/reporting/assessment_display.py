"""Plain-language assessment summaries shared by CLI and integrations.

These functions format measured results. They do not compute scores, make
gate decisions, or turn an incomplete check into evidence of safety.
"""

from __future__ import annotations

from collections.abc import Mapping


def _mapping(value):
    return value if isinstance(value, Mapping) else {}


def assessment_rows(assessment, *, gate=None) -> list[tuple[str, str]]:
    assessment = _mapping(assessment)
    risk = _mapping(assessment.get("risk"))
    risk_status = str(risk.get("status") or "unknown")
    risk_count = risk.get("finding_count", 0)
    if risk_status in {"critical", "high", "medium", "low"}:
        noun = "finding" if risk_count == 1 else "findings"
        risk_text = f"{risk_status.upper()} · {risk_count} unresolved {noun}"
        unknown = _mapping(risk.get("severity_counts")).get("UNKNOWN", 0)
        if unknown:
            risk_text += f" · {unknown} with unknown severity"
    elif risk_status == "none":
        risk_text = "No risk findings in assessed checks"
    elif risk_status == "not_assessed":
        risk_text = "Not assessed"
    else:
        risk_text = "Unknown · checks are incomplete or coverage is unavailable"

    maintenance = _mapping(assessment.get("maintainability"))
    if maintenance.get("status") == "measured":
        rule_count = maintenance.get("rule_count", 0)
        affected_files = maintenance.get("affected_files", 0)
        check_noun = "check" if rule_count == 1 else "checks"
        file_noun = "file" if affected_files == 1 else "files"
        maintenance_text = (
            f"{maintenance.get('advice_count', 0)} advice · "
            f"{rule_count} {check_noun} · "
            f"{affected_files} affected {file_noun}"
        )
    else:
        maintenance_text = "Not assessed"

    dead_code = _mapping(assessment.get("dead_code"))
    if dead_code.get("status") == "review":
        count = dead_code.get("candidate_count", 0)
        noun = "candidate" if count == 1 else "candidates"
        dead_code_text = f"{count} {noun} to review before removal"
        confidence = dead_code.get("confidence_range")
        if isinstance(confidence, (list, tuple)) and len(confidence) == 2:
            dead_code_text += f" · confidence {confidence[0]}–{confidence[1]}%"
    elif dead_code.get("status") == "none":
        dead_code_text = "No candidates in assessed code"
    elif dead_code.get("status") == "unknown":
        dead_code_text = "Unknown · dead-code checks are incomplete"
    else:
        dead_code_text = "Not assessed"

    gate = _mapping(gate)
    passed = gate.get("passed")
    if gate.get("status") == "incomplete":
        gate_text = "INCOMPLETE · gate cannot assess this scan"
    elif passed is True:
        gate_text = "PASS · configured policy allowed this scan"
    elif passed is False and gate.get("forced") is True:
        gate_text = "FAIL · configured limits exceeded; --force allowed continuation"
    elif passed is False:
        gate_text = "FAIL · configured policy blocked this scan"
    else:
        gate_text = "Not evaluated · use --gate to check configured limits"
    return [
        ("Risk", risk_text),
        ("Maintainability", maintenance_text),
        ("Dead code", dead_code_text),
        ("Gate", gate_text),
    ]


def maintainability_rows(assessment) -> list[tuple[str, str, str]]:
    rows = []
    maintenance = _mapping(_mapping(assessment).get("maintainability"))
    for check in maintenance.get("checks", []) or []:
        if not isinstance(check, Mapping):
            continue
        affected = check.get("affected_units", 0)
        total = check.get("analyzed_units")
        unit = str(check.get("unit") or "finding")
        prevalence = f"{affected} {unit}{'' if affected == 1 else 's'}"
        if total == 0:
            prevalence = f"No eligible {unit}s checked"
        elif total is not None:
            prevalence = f"{affected}/{total} {unit}{'' if total == 1 else 's'}"
        percentage = check.get("affected_percent")
        if isinstance(percentage, (int, float)):
            prevalence += f" ({percentage:g}%)"
        elif total is None:
            prevalence += " · denominator unavailable"
        value, threshold = check.get("max_value"), check.get("max_threshold")
        magnitude = "Not measured"
        if isinstance(value, (int, float)) and isinstance(threshold, (int, float)):
            magnitude = f"max {value:g} · limit {threshold:g}"
            excess = check.get("max_excess_ratio")
            if isinstance(excess, (int, float)):
                magnitude += f" · {excess:g}× limit"
        label = str(check.get("rule_id") or "Advice")
        if check.get("language"):
            label += f" · {check['language']}"
        if check.get("name"):
            label += f" · {check['name']}"
        rows.append((label, prevalence, magnitude))
    return rows


def assessment_coverage_text(assessment) -> str:
    coverage = _mapping(_mapping(assessment).get("coverage"))
    status = str(coverage.get("status") or "unknown")
    parts = [f"Coverage: {status}"]
    missing = coverage.get("not_assessed") or []
    incomplete = coverage.get("incomplete_checks") or []
    if missing:
        parts.append("not assessed: " + ", ".join(map(str, missing)))
    if incomplete:
        parts.append("incomplete: " + ", ".join(map(str, incomplete)))
    if status != "complete":
        parts.append("absence of findings does not establish a clean repository")
    return "; ".join(parts)


def dependency_coverage_lines(analysis_summary) -> list[str]:
    """Explain the existing SCA receipt without resolving or querying packages."""
    sca = _mapping(_mapping(analysis_summary).get("sca_coverage"))
    if not sca:
        return []

    def count(key):
        value = sca.get(key)
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )

    facts = []
    for key, label in (
        ("queried_dependency_count", "packages queried"),
        ("supported_lockfile_count", "supported lockfiles read"),
        ("unresolved_dependency_count", "manifest versions unresolved"),
        ("unresolved_lockfile_dependency_count", "lockfile entries unresolved"),
        ("non_registry_lockfile_dependency_count", "non-registry entries not queried"),
        ("not_checked_lockfile_dependency_count", "lockfile entries not checked"),
        ("parse_error_count", "parse errors"),
        ("unsupported_lockfile_count", "unsupported lockfiles"),
    ):
        value = count(key)
        if value is not None:
            facts.append(f"{value} {label}")
    lines = ["Dependency inventory: " + " · ".join(facts)] if facts else []
    skipped = count("non_registry_lockfile_dependency_count")
    if skipped:
        lines.append(
            "Dependency coverage limitation: Git, path, URL and private-registry "
            "sources are not checked for vulnerabilities through OSV; their vulnerability status is unknown"
        )
        examples = _non_registry_examples(sca.get("lockfile_not_checked"))
        if examples:
            detail = "; ".join(examples[:5])
            remaining = max(0, skipped - min(5, len(examples)))
            if remaining:
                detail += f"; {remaining} more entries (see sca_coverage JSON)"
            lines.append("Dependency sources not checked: " + detail)
    next_steps = []
    if count("unresolved_dependency_count") or count("supported_lockfile_count") == 0:
        next_steps.append(
            "for unresolved public-package versions, provide a supported lockfile (e.g. uv.lock, poetry.lock or package-lock.json) or exact manifest versions; version ranges are not resolved"
        )
    if (
        count("unresolved_lockfile_dependency_count")
        or count("parse_error_count")
        or count("unsupported_lockfile_count")
    ):
        next_steps.append(
            "inspect sca_coverage in the JSON report for unsupported, unreadable or unresolved dependency entries"
        )
    query = _mapping(sca.get("query"))
    if query.get("complete") is False:
        next_steps.append(
            "inspect failure and limit reasons in sca_coverage.query; retry failed requests after advisory-service access is restored"
        )
    if next_steps:
        lines.append("Dependency next step: " + "; ".join(next_steps))
    if sca.get("category_complete") is False:
        lines.append(
            "Dependency scope: recorded versions only; installed environment, lockfile freshness and runtime reachability are not verified"
        )
    return lines


def _non_registry_examples(entries) -> list[str]:
    """Only bounded package labels, never source URLs or credentials."""
    import re

    if not isinstance(entries, list):
        return []
    labels = {"git": "Git", "path": "path", "url": "URL"}
    examples = []
    for entry in entries[:25]:
        if not isinstance(entry, dict):
            continue
        reason = entry.get("reason")
        if reason not in ("non_registry_source", "non_public_registry"):
            continue
        name = entry.get("name") or entry.get("package")
        if not isinstance(name, str):
            continue
        name = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", name).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", name):
            continue
        source_type = entry.get("source_type")
        kind = (
            "private registry"
            if reason == "non_public_registry"
            else labels.get(source_type)
            if isinstance(source_type, str)
            else None
        )
        if kind:
            example = f"{name} ({kind})"
            if example not in examples:
                examples.append(example)
        if len(examples) == 5:
            break
    return examples


def assessment_notice(assessment, *, gate=None) -> str:
    return " | ".join(
        f"{label}: {detail}" for label, detail in assessment_rows(assessment, gate=gate)
    )
