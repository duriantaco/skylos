from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path


_POSITIONAL_RE = re.compile(r"\$(?:\d+|[@*])|\$\{(?:\d+|[@*])(?:[:?+\-][^}]*)?\}")
_VAR_REF_RE = re.compile(
    r"\$(?P<simple>[A-Za-z_][A-Za-z0-9_]*)|\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?:[:?+\-][^}]*)?\}"
)
_ASSIGN_RE = re.compile(
    r"^(?:(?:local|declare|typeset|readonly|export)\b(?:\s+-[A-Za-z]+\b)*)?\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=(?P<rhs>.+)$"
)
_READ_RE = re.compile(r"^(?:IFS=\\?[^\s]+\s+)?read(?:\s+|$)(?P<args>.*)$")
_SHELL_NAMES = {"bash", "dash", "ksh", "sh", "zsh"}
_URL_FETCHERS = {"curl", "wget"}
_PATH_SINKS = {
    "cat",
    "chmod",
    "chown",
    "cp",
    "head",
    "less",
    "ln",
    "mkdir",
    "more",
    "mv",
    "rm",
    "rmdir",
    "tail",
    "tar",
    "touch",
    "unzip",
}
_COMMAND_PREFIXES = {"command", "env", "nohup", "sudo", "time"}
_OPTIONS_WITH_VALUES = {
    "-C",
    "-H",
    "-I",
    "-O",
    "-X",
    "-b",
    "-c",
    "-d",
    "-e",
    "-f",
    "-g",
    "-h",
    "-i",
    "-k",
    "-o",
    "-p",
    "-u",
    "--config",
    "--connect-timeout",
    "--data",
    "--data-binary",
    "--directory-prefix",
    "--execute",
    "--header",
    "--method",
    "--output",
    "--post-data",
    "--post-file",
    "--user",
}
_PREFIX_OPTIONS_WITH_VALUES = {
    "env": {"-C", "-S", "-u"},
    "sudo": {"-C", "-g", "-h", "-p", "-T", "-u"},
}
_REDIRECT_RE = re.compile(
    r"(?:^|[^\d])(?:>>?|<)\s*(?P<target>(?:\"[^\"]+\"|'[^']+'|\S+))"
)

_COMMAND_FINDING = (
    "SKY-D212",
    "Shell command execution receives untrusted input; use fixed commands and strict allowlists.",
    "CRITICAL",
)
_PATH_FINDING = (
    "SKY-D215",
    "User-controlled shell path reaches a filesystem sink without basename or canonical path validation.",
    "HIGH",
)
_SSRF_FINDING = (
    "SKY-D216",
    "User-controlled URL reaches curl or wget; validate outbound destinations against an allowlist.",
    "CRITICAL",
)


@dataclass
class _ShellState:
    tainted_vars: set[str] = field(default_factory=set)
    path_sanitized_vars: set[str] = field(default_factory=set)


def scan_danger(file_path: str, source: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    state = _ShellState()

    for line_no, statement in _iter_statements(source):
        text = statement.strip()
        if not text:
            continue

        _handle_read(text, state)
        _handle_assignment(text, state)

        if _command_sink_is_tainted(text, state):
            _add_finding(findings, seen, _COMMAND_FINDING, file_path, line_no)
        if _url_sink_is_tainted(text, state):
            _add_finding(findings, seen, _SSRF_FINDING, file_path, line_no)
        if _path_sink_is_tainted(text, state):
            _add_finding(findings, seen, _PATH_FINDING, file_path, line_no)

    return findings


def _iter_statements(source: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    pending = ""
    pending_line = 1
    heredoc_end: str | None = None

    for line_no, raw in enumerate(source.splitlines(), 1):
        if heredoc_end is not None:
            if raw.strip() == heredoc_end:
                heredoc_end = None
            continue

        line = _strip_inline_comment(raw).rstrip()
        if not line:
            continue

        marker = _heredoc_marker(line)
        if marker is not None:
            heredoc_end = marker

        if pending:
            pending += line.lstrip()
        else:
            pending = line
            pending_line = line_no

        if pending.endswith("\\"):
            pending = pending[:-1]
            continue

        for statement in _split_shell_statements(pending):
            statements.append((pending_line, statement))
        pending = ""

    if pending:
        for statement in _split_shell_statements(pending):
            statements.append((pending_line, statement))

    return statements


def _strip_inline_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (idx == 0 or line[idx - 1].isspace()):
            return line[:idx]
    return line


def _heredoc_marker(line: str) -> str | None:
    match = re.search(r"<<-?\s*['\"]?(?P<marker>[A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
    if match:
        return match.group("marker")
    return None


def _split_shell_statements(line: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    idx = 0

    while idx < len(line):
        char = line[idx]
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
        if char == ";" or line.startswith("&&", idx) or line.startswith("||", idx):
            part = line[start:idx].strip()
            if part:
                parts.append(part)
            idx += 2 if line.startswith(("&&", "||"), idx) else 1
            start = idx
            continue
        idx += 1

    tail = line[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _handle_read(statement: str, state: _ShellState) -> None:
    match = _READ_RE.match(statement)
    if not match:
        return

    tokens = _shell_tokens(match.group("args"))
    names: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {"-a", "-d", "-n", "-N", "-p", "-t", "-u"}:
            skip_next = True
            continue
        if token.startswith("-") or "=" in token:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            names.append(token)

    for name in names:
        state.tainted_vars.add(name)
        state.path_sanitized_vars.discard(name)


def _handle_assignment(statement: str, state: _ShellState) -> None:
    match = _ASSIGN_RE.match(statement)
    if not match:
        return

    name = match.group("name")
    rhs = match.group("rhs").strip()
    if _is_tainted(rhs, state):
        state.tainted_vars.add(name)
        if _path_expr_is_sanitized(rhs, state):
            state.path_sanitized_vars.add(name)
        else:
            state.path_sanitized_vars.discard(name)
    else:
        state.tainted_vars.discard(name)
        state.path_sanitized_vars.discard(name)


def _command_sink_is_tainted(statement: str, state: _ShellState) -> bool:
    tokens = _shell_tokens(statement)
    if not tokens:
        return False

    command_idx = _command_index(tokens)
    if command_idx is None:
        return False
    command = _command_name(tokens[command_idx])

    if command == "eval":
        return _is_tainted(" ".join(tokens[command_idx + 1 :]), state)
    if command == "source" or tokens[command_idx] == ".":
        return _is_tainted(" ".join(tokens[command_idx + 1 :]), state)
    if command in _SHELL_NAMES and "-c" in tokens[command_idx + 1 :]:
        idx = tokens.index("-c", command_idx + 1)
        return _is_tainted(" ".join(tokens[idx + 1 :]), state)

    return False


def _url_sink_is_tainted(statement: str, state: _ShellState) -> bool:
    tokens = _shell_tokens(statement)
    command_idx = _command_index(tokens)
    if command_idx is None or _command_name(tokens[command_idx]) not in _URL_FETCHERS:
        return False

    for arg in _url_arguments(tokens[command_idx:]):
        if _url_arg_controls_destination(arg, state):
            return True
    return False


def _path_sink_is_tainted(statement: str, state: _ShellState) -> bool:
    for target in _redirection_targets(statement):
        if _is_tainted(target, state) and not _path_expr_is_sanitized(target, state):
            return True

    tokens = _shell_tokens(statement)
    command_idx = _command_index(tokens)
    if command_idx is None or _command_name(tokens[command_idx]) not in _PATH_SINKS:
        return False

    for arg in _path_arguments(tokens[command_idx:]):
        if _is_tainted(arg, state) and not _path_expr_is_sanitized(arg, state):
            return True
    return False


def _shell_tokens(statement: str) -> list[str]:
    try:
        return shlex.split(statement, comments=False, posix=True)
    except ValueError:
        return statement.split()


def _command_index(tokens: list[str]) -> int | None:
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        name = _command_name(token)
        if "=" in token and not token.startswith(("$", "./", "/")):
            idx += 1
            continue
        if name in _COMMAND_PREFIXES:
            idx = _skip_command_prefix(tokens, idx, name)
            continue
        return idx
    return None


def _skip_command_prefix(tokens: list[str], idx: int, name: str) -> int:
    idx += 1
    options_with_values = _PREFIX_OPTIONS_WITH_VALUES.get(name, set())
    while idx < len(tokens):
        token = tokens[idx]
        if name == "env" and "=" in token and not token.startswith(("$", "./", "/")):
            idx += 1
            continue
        if token in options_with_values:
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        break
    return idx


def _command_name(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _url_arguments(command_tokens: list[str]) -> list[str]:
    args: list[str] = []
    idx = 1
    while idx < len(command_tokens):
        token = command_tokens[idx]
        if token == "--url" and idx + 1 < len(command_tokens):
            args.append(command_tokens[idx + 1])
            idx += 2
            continue
        if token in _OPTIONS_WITH_VALUES:
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        args.append(token)
        idx += 1
    return args


def _path_arguments(command_tokens: list[str]) -> list[str]:
    args: list[str] = []
    idx = 1
    while idx < len(command_tokens):
        token = command_tokens[idx]
        if token in _OPTIONS_WITH_VALUES:
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        args.append(token)
        idx += 1
    return args


def _redirection_targets(statement: str) -> list[str]:
    return [match.group("target") for match in _REDIRECT_RE.finditer(statement)]


def _url_arg_controls_destination(arg: str, state: _ShellState) -> bool:
    if not _is_tainted(arg, state):
        return False

    match = re.match(r"^https?://(?P<host>[^/?#]+)(?P<rest>.*)$", arg)
    if match:
        return _is_tainted(match.group("host"), state)
    return True


def _path_expr_is_sanitized(expr: str, state: _ShellState) -> bool:
    if _basename_call_is_tainted(expr, state):
        return True
    if _POSITIONAL_RE.search(expr):
        return False

    refs = _tainted_refs(expr, state)
    return bool(refs) and refs.issubset(state.path_sanitized_vars)


def _basename_call_is_tainted(expr: str, state: _ShellState) -> bool:
    if not re.search(r"(?:^|\$\()\s*basename\b", expr):
        return False
    return _is_tainted(expr, state)


def _is_tainted(expr: str, state: _ShellState) -> bool:
    if not expr:
        return False
    if _POSITIONAL_RE.search(expr):
        return True
    return bool(_tainted_refs(expr, state))


def _tainted_refs(expr: str, state: _ShellState) -> set[str]:
    refs: set[str] = set()
    for match in _VAR_REF_RE.finditer(expr):
        name = match.group("simple") or match.group("braced")
        if name in state.tainted_vars:
            refs.add(name)
    return refs


def _add_finding(
    findings: list[dict],
    seen: set[tuple[str, int, str]],
    spec: tuple[str, str, str],
    file_path: str,
    line: int,
) -> None:
    rule_id, message, severity = spec
    key = (rule_id, line, str(Path(file_path)))
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": str(Path(file_path)),
            "line": line,
            "col": 0,
            "category": "danger",
        }
    )
