from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skylos.contracts import contract_finding_metadata


SCHEMA_VERSION = 1

AI_VIBE_CATEGORIES = {
    "hallucinated_reference",
    "incomplete_generation",
    "ghost_config",
    "stale_reference",
    "missing_resilience_control",
    "api_signature_hallucination",
    "assertion_weakening",
    "ci_permission_expansion",
    "dependency_hallucination",
    "disabled_security_control",
    "test_impact_gap",
    "missing_contract_guardrail",
    "public_api_surface_drift",
}

AI_RULE_DEFAULTS = {
    "SKY-A101": ("assertion_weakening", "medium"),
    "SKY-A102": ("test_impact_gap", "low"),
    "SKY-A103": ("ci_permission_expansion", "high"),
    "SKY-A104": ("public_api_surface_drift", "medium"),
    "SKY-A105": ("missing_contract_guardrail", "high"),
    "SKY-L012": ("hallucinated_reference", "high"),
    "SKY-L011": ("disabled_security_control", "medium"),
    "SKY-D222": ("dependency_hallucination", "high"),
    "SKY-D224": ("api_signature_hallucination", "high"),
    "SKY-D225": ("dependency_hallucination", "high"),
    "SKY-L023": ("hallucinated_reference", "high"),
}

FINDING_SECTIONS = (
    ("ai_defects", "ai_defect"),
    ("quality", "quality"),
    ("danger", "security"),
    ("custom_rules", "custom"),
)

SUGGESTED_FIX_BY_VIBE = {
    "hallucinated_reference": (
        "Define or import the referenced symbol, or replace it with an existing helper."
    ),
    "incomplete_generation": "Implement the stub or remove the unfinished code path.",
    "ghost_config": "Define the referenced config value or remove the stale flag check.",
    "stale_reference": "Update the reference to the renamed symbol or remove it.",
    "missing_resilience_control": "Add the missing timeout or resilience control.",
    "disabled_security_control": "Re-enable the security control or remove the bypass.",
    "dependency_hallucination": (
        "Remove the hallucinated dependency or replace it with a real package."
    ),
    "api_signature_hallucination": (
        "Update the call to match the installed package API surface."
    ),
    "assertion_weakening": (
        "Restore the specific assertion or explain why the weaker test still proves the behavior."
    ),
    "test_impact_gap": (
        "Add or update relevant tests, or document why behavior is unchanged."
    ),
    "ci_permission_expansion": (
        "Restore the narrower workflow permissions or document why the broader CI trust boundary is required."
    ),
    "public_api_surface_drift": (
        "Restore the public option or document the compatibility break."
    ),
    "missing_contract_guardrail": (
        "Add one of the guard decorators required by the Skylos contract."
    ),
}


def parse_line_range(value: str | None) -> tuple[int, int] | None:
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    separator = _line_range_separator(raw)
    if separator is None:
        start = int(raw)
        end = int(raw)
    else:
        left, right = raw.split(separator, 1)
        start = int(left.strip())
        end = int(right.strip())

    _validate_line_range(start, end)
    return start, end


def build_verify_change_response(
    analysis_result: dict[str, Any],
    *,
    project_root: str | Path,
    target_file: str | Path | None = None,
    line_range: str | tuple[int, int] | None = None,
    scan_target: str | Path | None = None,
    contract: Any | None = None,
) -> dict[str, Any]:
    root = _project_root(project_root)
    parsed_range = _coerce_line_range(line_range)
    findings: list[dict[str, Any]] = []

    for finding, category in _iter_ai_findings(analysis_result):
        if not _matches_target(finding, root, target_file):
            continue
        if not _matches_line_range(finding, parsed_range):
            continue

        normalized = _normalize_finding(finding, category, root, contract=contract)
        findings.append(normalized)

    findings.sort(
        key=lambda item: (
            _likelihood_sort(item["ai_likelihood"]),
            item["range"]["file"],
            item["range"]["start_line"],
            item["rule_id"],
        )
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "verify_change",
        "status": _status_for_findings(findings),
        "target": {
            "path": _target_path_for_payload(scan_target, target_file, project_root),
            "file": _target_file_for_payload(target_file, root),
            "range": _range_for_payload(parsed_range),
        },
        "findings": findings,
        "summary": _summary(findings),
    }


def _iter_ai_findings(
    analysis_result: dict[str, Any],
) -> Iterator[tuple[dict[str, Any], str]]:
    for section, category in FINDING_SECTIONS:
        for finding in _section_findings(analysis_result, section):
            if _is_ai_finding(finding):
                yield finding, category


def _is_ai_finding(finding: dict[str, Any]) -> bool:
    vibe = str(_finding_value(finding, ("vibe_category",), "")).strip()
    if vibe in AI_VIBE_CATEGORIES:
        return True

    rule_id = str(_finding_value(finding, ("rule_id", "rule"), ""))
    return rule_id in AI_RULE_DEFAULTS


def _normalize_finding(
    finding: dict[str, Any],
    category: str,
    root: Path,
    *,
    contract: Any | None = None,
) -> dict[str, Any]:
    rule_id = str(_finding_value(finding, ("rule_id", "rule"), "UNKNOWN"))
    default_vibe, default_likelihood = _rule_defaults(rule_id)
    vibe_category = str(_finding_value(finding, ("vibe_category",), default_vibe))
    ai_likelihood = str(
        _finding_value(finding, ("ai_likelihood",), default_likelihood)
    )
    confidence = _confidence(finding.get("confidence"), ai_likelihood)
    severity = str(_finding_value(finding, ("severity",), "MEDIUM")).upper()

    normalized = {
        "rule_id": rule_id,
        "vibe_category": vibe_category,
        "ai_likelihood": ai_likelihood,
        "range": _finding_range(finding, root),
        "message": _message(finding),
        "suggested_fix": _suggested_fix(finding, vibe_category),
        "confidence": confidence,
        "severity": severity,
        "category": category,
    }
    normalized.update(contract_finding_metadata(contract, finding))
    return normalized


def _finding_range(finding: dict[str, Any], root: Path) -> dict[str, Any]:
    line_value = _finding_value(finding, ("line", "line_number"), None)
    line = _positive_int(line_value, default=1)
    col_value = _finding_value(finding, ("col", "column"), None)
    col = _non_negative_int(col_value, default=0)
    end_line_value = _finding_value(finding, ("end_line", "endLine"), None)
    end_line = _positive_int(end_line_value, default=line)
    end_col_value = _finding_value(finding, ("end_col", "endCol"), None)
    file_value = _finding_value(finding, ("file", "file_path"), None)

    return {
        "file": _relative_file(file_value, root),
        "start_line": line,
        "start_col": col,
        "end_line": max(line, end_line),
        "end_col": _non_negative_int(end_col_value, default=col),
    }


def _matches_target(
    finding: dict[str, Any],
    root: Path,
    target_file: str | Path | None,
) -> bool:
    if target_file is None:
        return True

    finding_file = _finding_value(finding, ("file", "file_path"), None)
    if not finding_file:
        return False

    finding_keys = _file_keys(finding_file, root)
    target_keys = _file_keys(target_file, root)
    return finding_keys & target_keys != set()


def _matches_line_range(
    finding: dict[str, Any],
    line_range: tuple[int, int] | None,
) -> bool:
    if line_range is None:
        return True

    start, end = line_range
    line_value = _finding_value(finding, ("line", "line_number"), None)
    line = _positive_int(line_value, default=1)
    end_line_value = _finding_value(finding, ("end_line", "endLine"), None)
    finding_end = _positive_int(end_line_value, default=line)
    return not (finding_end < start or line > end)


def _file_keys(path: str | Path, root: Path) -> set[str]:
    raw = Path(path)
    keys = {str(raw).replace("\\", "/")}
    try:
        if raw.is_absolute():
            resolved = raw
        else:
            resolved = root / raw

        absolute = resolved.resolve()
        keys.add(str(absolute).replace("\\", "/"))
        keys.add(str(absolute.relative_to(root)).replace("\\", "/"))
    except (OSError, ValueError):
        pass
    return keys


def _relative_file(path: Any, root: Path) -> str:
    if not path:
        return "unknown"

    raw = Path(str(path))
    try:
        if raw.is_absolute():
            resolved = raw
        else:
            resolved = root / raw

        relative = resolved.resolve().relative_to(root)
        return str(relative).replace("\\", "/")
    except (OSError, ValueError):
        return str(raw).replace("\\", "/")


def _project_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_file():
        candidate = candidate.parent
    try:
        return candidate.resolve()
    except OSError:
        return candidate


def _coerce_line_range(
    value: str | tuple[int, int] | None,
) -> tuple[int, int] | None:
    if isinstance(value, tuple):
        start, end = value
        _validate_line_range(start, end)
        return start, end
    return parse_line_range(value)


def _target_file_for_payload(target_file: str | Path | None, root: Path) -> str | None:
    if target_file is None:
        return None
    return _relative_file(target_file, root)


def _range_for_payload(line_range: tuple[int, int] | None) -> dict[str, int] | None:
    if line_range is None:
        return None
    start, end = line_range
    return {"start_line": start, "end_line": end}


def _summary(findings: list[dict[str, Any]]) -> str:
    count = len(findings)
    if count == 0:
        return "No AI-code issues found"
    if count == 1:
        issue_word = "issue"
    else:
        issue_word = "issues"
    return f"{count} AI-code {issue_word} found"


def _message(finding: dict[str, Any]) -> str:
    message = _finding_value(finding, ("message", "detail", "msg"), None)
    if message:
        return str(message)

    rule_id = _finding_value(finding, ("rule_id",), "UNKNOWN")
    return f"{rule_id} finding"


def _suggested_fix(finding: dict[str, Any], vibe_category: str) -> str | None:
    fix = _finding_value(
        finding,
        ("suggested_fix", "fix", "recommendation"),
        None,
    )
    if fix:
        return str(fix)
    return SUGGESTED_FIX_BY_VIBE.get(vibe_category)


def _confidence(value: Any, ai_likelihood: str) -> int:
    coerced = _optional_int(value)
    if coerced is not None:
        return min(100, max(0, coerced))

    likelihood_scores = {"high": 90, "medium": 70, "low": 50}
    return likelihood_scores.get(ai_likelihood.lower(), 70)


def _likelihood_sort(value: str) -> int:
    likelihood_order = {"high": 0, "medium": 1, "low": 2}
    return likelihood_order.get(str(value).lower(), 3)


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_int(value: Any, *, default: int) -> int:
    parsed = _optional_int(value)
    if parsed is None:
        return default
    if parsed <= 0:
        return default
    return parsed


def _non_negative_int(value: Any, *, default: int) -> int:
    parsed = _optional_int(value)
    if parsed is None:
        return default
    if parsed < 0:
        return default
    return parsed


def _line_range_separator(raw: str) -> str | None:
    if ":" in raw:
        return ":"
    if "-" in raw:
        return "-"
    return None


def _validate_line_range(start: int, end: int) -> None:
    if start <= 0:
        raise ValueError("line range values must be positive")
    if end <= 0:
        raise ValueError("line range values must be positive")
    if end < start:
        raise ValueError("line range end must be greater than or equal to start")


def _status_for_findings(findings: list[dict[str, Any]]) -> str:
    if findings:
        return "fail"
    return "pass"


def _target_path_for_payload(
    scan_target: str | Path | None,
    target_file: str | Path | None,
    project_root: str | Path,
) -> str:
    for value in (scan_target, target_file, project_root):
        if value is not None:
            return str(value)
    return "."


def _finding_value(
    finding: dict[str, Any],
    keys: tuple[str, ...],
    default: Any,
) -> Any:
    for key in keys:
        value = finding.get(key)
        if _has_value(value):
            return value
    return default


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        if value.strip() == "":
            return False
    return True


def _section_findings(
    analysis_result: dict[str, Any],
    section: str,
) -> list[dict[str, Any]]:
    findings = analysis_result.get(section)
    if isinstance(findings, list):
        return findings
    return []


def _rule_defaults(rule_id: str) -> tuple[str, str]:
    defaults = AI_RULE_DEFAULTS.get(rule_id)
    if defaults is not None:
        return defaults
    return "", "medium"
