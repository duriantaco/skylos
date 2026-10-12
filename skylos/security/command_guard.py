from __future__ import annotations

from pathlib import Path

from skylos.security.command_guard_exfil import command_risks, pipeline_risks
from skylos.security.command_guard_parse import (
    dedupe_risks,
    may_change_directory,
    redefines_home,
    shell_tokens,
    split_pipeline,
    split_shell_statements,
)
from skylos.security.command_guard_paths import is_external_url, is_sensitive_path
from skylos.security.command_guard_policy import command_policy_risks, token_policy_risks
from skylos.security.command_guard_types import CommandRisk


def scan_shell_command(
    command: str, *, cwd_in_project: bool = False, home_is_default: bool = False
) -> list[CommandRisk]:
    """Risks in a shell command or script.

    ``cwd_in_project`` is the caller's word that the script starts in the
    project directory (a bash/sh CI step without an outside working
    directory); only then, and only if nothing in the script may change
    directory, does a relative redirect target such as ``.env`` count as a
    project file. ``home_is_default`` is the caller's word that HOME is the
    runner's own (a GitHub Actions job whose env and steps never set it);
    only then, and only if the script does not assign HOME itself, is
    home-directory credential setup (``~/.ssh/known_hosts``) routine. Shell
    files, GitLab jobs and Dockerfiles can set HOME in a statement the scanner
    does not see with this command, so they leave both off.
    """
    risks: list[CommandRisk] = list(command_risks(command))
    risks.extend(command_policy_risks(command))
    scopes = frozenset(
        scope
        for scope, allowed in (
            ("home", home_is_default and not redefines_home(command)),
            ("project", cwd_in_project and not may_change_directory(command)),
        )
        if allowed
    )
    for statement in split_shell_statements(command):
        parts = [
            (part, tokens)
            for part in split_pipeline(statement)
            if (tokens := shell_tokens(part))
        ]
        if not parts:
            continue
        risks.extend(pipeline_risks([tokens for _part, tokens in parts]))
        for part, tokens in parts:
            risks.extend(token_policy_risks(tokens, part, routine_scopes=scopes))
    return dedupe_risks(risks)


def findings_for_command(
    command: str,
    file_path: str | Path,
    line: int,
    *,
    col: int = 0,
    cwd_in_project: bool = False,
    home_is_default: bool = False,
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
        for risk in scan_shell_command(
            command, cwd_in_project=cwd_in_project, home_is_default=home_is_default
        )
    ]


__all__ = [
    "CommandRisk",
    "findings_for_command",
    "is_external_url",
    "is_sensitive_path",
    "scan_shell_command",
]
