from __future__ import annotations

from pathlib import Path
from typing import Any


def config_finding(
    *,
    rule_id: str,
    domain: str,
    provider: str,
    name: str,
    message: str,
    file: Path,
    line: int,
    severity: str,
    value: str,
    finding_type: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "kind": "config",
        "domain": domain,
        "provider": provider,
        "severity": severity,
        "type": finding_type,
        "name": name,
        "simple_name": name,
        "value": value,
        "threshold": 0,
        "message": message,
        "file": str(file),
        "basename": file.name,
        "line": max(1, line),
        "col": 0,
        "category": "SECURITY",
    }
