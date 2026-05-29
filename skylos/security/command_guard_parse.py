from __future__ import annotations

import shlex

from skylos.security.command_guard_types import CommandRisk


COMMAND_PREFIXES = {"command", "nohup", "sudo", "time"}
OPTIONS_WITH_VALUES = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--method",
    "--output",
    "--post-data",
    "--post-file",
    "--request",
    "--upload-file",
    "-F",
    "-T",
    "-X",
    "-d",
    "-o",
}


def split_shell_statements(command: str) -> list[str]:
    return _split_shell_on(command, {";", "&&", "||"})


def split_pipeline(statement: str) -> list[str]:
    return _split_shell_on(statement, {"|"})


def shell_tokens(statement: str) -> list[str]:
    try:
        return shlex.split(statement, comments=False, posix=True)
    except ValueError:
        return statement.split()


def split_option(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        flag, value = token.split("=", 1)
        return flag, value
    return token, None


def tokens_start_with(tokens: list[str], prefix: tuple[str, ...]) -> bool:
    return tuple(token.lower() for token in tokens[: len(prefix)]) == prefix


def command_name(tokens: list[str]) -> str:
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        name = token.rsplit("/", 1)[-1].lower()
        if "=" in token and not token.startswith(("$", "./", "/")):
            idx += 1
            continue
        if name in COMMAND_PREFIXES:
            idx += 1
            continue
        return name
    return ""


def dedupe_risks(risks: list[CommandRisk]) -> list[CommandRisk]:
    seen: set[str] = set()
    deduped: list[CommandRisk] = []
    for risk in risks:
        if risk.rule_id in seen:
            continue
        seen.add(risk.rule_id)
        deduped.append(risk)
    return deduped


def _split_shell_on(text: str, separators: set[str]) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    idx = 0
    while idx < len(text):
        char = text[idx]
        if escaped:
            escaped = False
            idx += 1
            continue
        if char == "\\":
            escaped = True
            idx += 1
            continue
        if quote:
            if char == quote:
                quote = None
            idx += 1
            continue
        if char in {"'", '"'}:
            quote = char
            idx += 1
            continue

        matched = _matched_separator(text, idx, separators)
        if matched:
            part = text[start:idx].strip()
            if part:
                parts.append(part)
            idx += len(matched)
            start = idx
            continue
        idx += 1

    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _matched_separator(text: str, idx: int, separators: set[str]) -> str | None:
    for sep in sorted(separators, key=len, reverse=True):
        if text.startswith(sep, idx):
            if sep == "|" and text.startswith("||", idx):
                continue
            return sep
    return None
