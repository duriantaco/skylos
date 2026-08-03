from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def is_reliability_finding(finding: dict[str, Any]) -> bool:
    """Return whether a finding belongs to the reliability result bucket."""
    return str(finding.get("category") or "").strip().lower() == "reliability"


def split_security_reliability_findings(
    findings: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Partition findings produced by the shared danger/config scan phase."""
    security: list[dict[str, Any]] = []
    reliability: list[dict[str, Any]] = []
    for finding in findings:
        if is_reliability_finding(finding):
            reliability.append(finding)
        else:
            security.append(finding)
    return security, reliability
