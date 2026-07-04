from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.core.evidence_contract import finding_evidence_contract
from skylos.core.safe_cache_io import read_text_no_symlink

from .ai_defect_challenge_models import AIDefectChallengeProbe

MAX_CHALLENGE_CONTEXT_BYTES = 1_000_000

HIGH_IMPACT_RULE_IDS = {
    "SKY-A103",
    "SKY-A105",
    "SKY-D222",
    "SKY-D224",
    "SKY-D225",
    "SKY-L012",
    "SKY-L023",
}
HIGH_IMPACT_CATEGORIES = {"ai_defect", "security", "danger"}
HIGH_IMPACT_SEVERITIES = {"HIGH", "CRITICAL"}
HIGH_IMPACT_LIKELIHOODS = {"high", "critical"}


class HighImpactFindingDetector:
    def select(
        self,
        findings: list[dict[str, Any]],
        *,
        project_root: str | Path,
        max_challenge: int | None = None,
    ) -> list[AIDefectChallengeProbe]:
        root = Path(project_root).resolve()
        probes = []
        for finding in findings:
            if not is_high_impact_ai_finding(finding):
                continue
            probe_id = len(probes) + 1
            probes.append(_build_probe(probe_id, finding, root))
            if max_challenge is not None and len(probes) >= max_challenge:
                break
        return probes


def is_high_impact_ai_finding(finding: dict[str, Any]) -> bool:
    rule_id = str(finding.get("rule_id") or finding.get("rule") or "").strip()
    if rule_id in HIGH_IMPACT_RULE_IDS:
        return True

    category = str(finding.get("category") or "").strip().lower()
    severity = str(finding.get("severity") or "").strip().upper()
    if category in HIGH_IMPACT_CATEGORIES and severity in HIGH_IMPACT_SEVERITIES:
        return True

    ai_likelihood = str(finding.get("ai_likelihood") or "").strip().lower()
    return category == "ai_defect" and ai_likelihood in HIGH_IMPACT_LIKELIHOODS


def _build_probe(
    probe_id: int,
    finding: dict[str, Any],
    project_root: Path,
) -> AIDefectChallengeProbe:
    file_path = _finding_file(finding)
    line = _finding_line(finding)
    evidence_contract = finding.get("evidence_contract")
    if not isinstance(evidence_contract, dict):
        evidence_contract = finding_evidence_contract(finding)
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    return AIDefectChallengeProbe(
        id=probe_id,
        rule_id=str(finding.get("rule_id") or finding.get("rule") or "UNKNOWN"),
        category=str(finding.get("category") or ""),
        severity=str(finding.get("severity") or ""),
        file=file_path,
        line=line,
        message=str(finding.get("message") or ""),
        symbol=str(finding.get("symbol") or metadata.get("symbol") or ""),
        evidence_contract=evidence_contract,
        code_context=_read_context(project_root, file_path, line),
        metadata=metadata,
    )


def _finding_file(finding: dict[str, Any]) -> str:
    finding_range = finding.get("range")
    if isinstance(finding_range, dict):
        value = finding_range.get("file")
        if value:
            return str(value)
    return str(finding.get("file") or finding.get("file_path") or "unknown")


def _finding_line(finding: dict[str, Any]) -> int:
    finding_range = finding.get("range")
    if isinstance(finding_range, dict):
        line = finding_range.get("start_line") or finding_range.get("line")
        return _positive_int(line, default=1)
    return _positive_int(finding.get("line") or finding.get("line_number"), default=1)


def _positive_int(value: Any, *, default: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return result if result >= 1 else default


def _read_context(project_root: str | Path, file_path: str, line: int) -> str:
    source_path = _resolve_finding_file(project_root, file_path)
    source_text = read_text_no_symlink(
        source_path,
        max_bytes=MAX_CHALLENGE_CONTEXT_BYTES,
        encoding="utf-8",
    )
    if source_text is None:
        return ""

    lines = source_text.splitlines()
    start = max(0, line - 6)
    end = min(len(lines), line + 5)
    return "\n".join(
        f"{index + 1:4d}{' >>> ' if index == line - 1 else '     '}{lines[index]}"
        for index in range(start, end)
    )


def _resolve_finding_file(project_root: str | Path, file_path: str) -> Path:
    path = Path(file_path)
    if path.is_absolute():
        return path
    return Path(project_root).resolve() / path
