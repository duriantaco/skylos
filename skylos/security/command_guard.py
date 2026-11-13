from __future__ import annotations

from pathlib import Path

from skylos.security.command_guard_exfil import (
    _rm_executable_tokens,
    command_risks,
    pipeline_risks,
)
from skylos.security.command_guard_parse import (
    command_name,
    dedupe_risks,
    may_change_directory,
    parse_shell_script,
    redefines_home,
    shell_tokens,
    split_pipeline,
)
from skylos.security.command_guard_paths import is_external_url, is_sensitive_path
from skylos.security.command_guard_policy import command_policy_risks, token_policy_risks
from skylos.security.command_guard_types import CommandRisk


HEREDOC_SHELLS = {"ash", "bash", "dash", "ksh", "sh", "zsh"}
MAX_HEREDOC_DEPTH = 4


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
    risks.extend(
        risk
        for _offset, risk in _statement_risks(
            command, cwd_in_project=cwd_in_project, home_is_default=home_is_default
        )
    )
    return dedupe_risks(risks)


def shell_command_risks(
    command: str, *, cwd_in_project: bool = False, home_is_default: bool = False
) -> list[tuple[int | None, CommandRisk]]:
    located = _statement_risks(
        command, cwd_in_project=cwd_in_project, home_is_default=home_is_default
    )
    seen = {risk.rule_id for _offset, risk in located}
    unlocated = [
        (None, risk)
        for risk in dedupe_risks(
            [*command_risks(command), *command_policy_risks(command)]
        )
        if risk.rule_id not in seen
    ]
    return unlocated + located


def script_comment_ignores(command: str, offset: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    lines = command.split("\n")
    index = command.count("\n", 0, offset)
    for start, text in parse_shell_script(command).comments:
        if needle not in text:
            continue
        line = command.count("\n", 0, start)
        if line == index:
            return True
        line_start = command.rfind("\n", 0, start) + 1
        if line == index - 1 and not lines[line][: start - line_start].strip():
            return True
    return False


def _statement_risks(
    command: str, *, cwd_in_project: bool, home_is_default: bool
) -> list[tuple[int, CommandRisk]]:
    scopes = frozenset(
        scope
        for scope, allowed in (
            ("home", home_is_default and not redefines_home(command)),
            ("project", cwd_in_project and not may_change_directory(command)),
        )
        if allowed
    )
    located: list[tuple[int, CommandRisk]] = []
    for offset, statement in _executed_statements(command, 0):
        parts = [
            (part, tokens)
            for part in split_pipeline(statement)
            if (tokens := shell_tokens(part))
        ]
        if not parts:
            continue
        found = list(command_risks(statement))
        found.extend(command_policy_risks(statement))
        found.extend(pipeline_risks([tokens for _part, tokens in parts]))
        for part, tokens in parts:
            found.extend(token_policy_risks(tokens, part, routine_scopes=scopes))
        located.extend((offset, risk) for risk in dedupe_risks(found))
    return located


def _executed_statements(command: str, depth: int) -> list[tuple[int, str]]:
    script = parse_shell_script(command)
    statements = list(script.statements)
    if depth < MAX_HEREDOC_DEPTH:
        for owner, start, body in script.heredocs:
            if owner < len(script.statements) and _feeds_shell(
                script.statements[owner][1]
            ):
                statements.extend(
                    (start + inner, text)
                    for inner, text in _executed_statements(body, depth + 1)
                )
    return sorted(statements)


def _feeds_shell(statement: str) -> bool:
    for part in split_pipeline(statement):
        if "<<" in part:
            tokens = _rm_executable_tokens(shell_tokens(part))
            return command_name(tokens) in HEREDOC_SHELLS
    return False


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
    "script_comment_ignores",
    "shell_command_risks",
]
