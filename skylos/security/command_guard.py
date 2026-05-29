from __future__ import annotations

from pathlib import Path

from skylos.security.command_guard_exfil import command_risks, pipeline_risks
from skylos.security.command_guard_parse import (
    dedupe_risks,
    shell_tokens,
    split_pipeline,
    split_shell_statements,
)
from skylos.security.command_guard_paths import is_external_url, is_sensitive_path
from skylos.security.command_guard_policy import command_policy_risks, token_policy_risks
from skylos.security.command_guard_types import CommandRisk


def scan_shell_command(command: str) -> list[CommandRisk]:
    risks: list[CommandRisk] = list(command_risks(command))
    risks.extend(command_policy_risks(command))
    for statement in split_shell_statements(command):
        pipeline = [shell_tokens(part) for part in split_pipeline(statement)]
        pipeline = [tokens for tokens in pipeline if tokens]
        if not pipeline:
            continue
        risks.extend(pipeline_risks(pipeline))
        for tokens in pipeline:
            risks.extend(token_policy_risks(tokens))
    return dedupe_risks(risks)


def findings_for_command(
    command: str,
    file_path: str | Path,
    line: int,
    *,
    col: int = 0,
) -> list[dict]:
    return [
        {
            "rule_id": risk.rule_id,
            "severity": risk.severity,
            "message": risk.message,
            "file": str(file_path),
            "line": line,
            "col": col,
            "category": "danger",
        }
        for risk in scan_shell_command(command)
    ]


__all__ = [
    "CommandRisk",
    "findings_for_command",
    "is_external_url",
    "is_sensitive_path",
    "scan_shell_command",
]
