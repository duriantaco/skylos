from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from skylos.security.command_guard import findings_for_command
from skylos.visitors.languages.shell.structure import ShellStructure, shell_structure


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
_SCRIPT_RUNNERS = _SHELL_NAMES | {"runuser", "su"}
_ROOT_IDENTITY_TEXT_RE = re.compile(r"\bE?UID\b|\bid\s+-u\b")
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
_COMMAND_PREFIXES = {"command", "env", "nohup", "time"}
_PRIVILEGE_WRAPPERS = {"doas", "runuser", "setpriv", "su", "sudo"}
_SU_VALUE_OPTIONS = {
    "-c",
    "--command",
    "-g",
    "--group",
    "-G",
    "--supp-group",
    "-s",
    "--shell",
    "-w",
    "--whitelist-environment",
    "--session-command",
}
_WRAPPER_VALUE_OPTIONS = {
    "doas": {"-C", "-u"},
    "runuser": _SU_VALUE_OPTIONS | {"-u", "--user"},
    "su": _SU_VALUE_OPTIONS,
    "setpriv": {
        "--ambient-caps",
        "--apparmor-profile",
        "--bounding-set",
        "--egid",
        "--euid",
        "--groups",
        "--inh-caps",
        "--landlock-access",
        "--landlock-rule",
        "--pdeathsig",
        "--regid",
        "--reuid",
        "--rgid",
        "--ruid",
        "--seccomp-filter",
        "--securebits",
        "--selinux-label",
    },
    "sudo": {
        "-C",
        "-D",
        "-R",
        "-T",
        "-U",
        "-g",
        "-h",
        "-p",
        "-r",
        "-t",
        "-u",
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--other-user",
        "--prompt",
        "--role",
        "--type",
        "--user",
    },
}
_USER_OPTIONS = {"-u", "--user", "--reuid"}
_SCRIPT_OPTIONS = {"-c", "--command"}
_ROOT_USERS = {"root", "0", "#0"}
_SHELL_COMMAND_FLAG_RE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
_SHELL_ARGUMENT_END_RE = re.compile(r"^(?:\|&?|&&?|\|\||;|\d*[<>]|&>)")
_ENV_ASSIGNMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$", re.S
)
_SUBSTITUTION_RE = re.compile(
    r"\$\(\s*(?!\()(?P<command>[^\s)`]*)(?P<rest>[^()`]*)|`\s*(?P<backtick>[^\s`]*)(?P<tail>[^`]*)"
)
_PATH_TRANSFORMS = {"basename", "dirname", "realpath"}
_CANONICAL_READLINK_RE = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[efm][A-Za-z]*|--canonicalize\S*)(?:\s|$)"
)
_SEVERITY_BELOW = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}
_MAX_INNER_SHELLS = 3
_CAPABILITY_OPTIONS = {"--ambient-caps", "--bounding-set", "--inh-caps"}
_GROUP_FLAGS = {"--clear-groups", "--init-groups"}
_ACCOUNT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*\$?")
_MAX_ACCOUNT_ID = 4294967295
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_PRIVILEGE_DROP_RULES = {"SKY-D212", "SKY-D215"}
_ROOT_ONLY_SUFFIX = (
    " The script exits unless it runs as root; the risk is a less-trusted "
    "user running it through sudo or another privileged wrapper."
)
_ROOT_ONLY_MESSAGES = {
    "SKY-D212": "Shell command execution receives the script's own command-line arguments."
    + _ROOT_ONLY_SUFFIX,
    "SKY-D215": "A path from the script's own command-line arguments reaches a filesystem sink without basename or canonical path validation."
    + _ROOT_ONLY_SUFFIX,
    "SKY-D216": "A URL from the script's own command-line arguments reaches curl or wget."
    + _ROOT_ONLY_SUFFIX,
}
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
}
_REDIRECT_RE = re.compile(
    # Bash <<< supplies a string, while << introduces a heredoc. Neither
    # operand is a filesystem path. The lookbehind also prevents matching
    # the final < inside either operator as a separate input redirection.
    r"(?<![\d<])(?:>>?|<(?!<))\s*(?P<target>(?:\"[^\"]+\"|'[^']+'|\S+))"
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


_FUNCTION_HEADER_RE = re.compile(
    r"^(?:function\s+(?P<kw>[A-Za-z_][\w:-]*)\s*(?:\(\s*\))?|(?P<name>[A-Za-z_][\w:-]*)\s*\(\s*\))\s*\{?$"
)


@dataclass
class _ShellState:
    tainted_vars: set[str] = field(default_factory=set)
    path_sanitized_vars: set[str] = field(default_factory=set)
    # Whether ``$1``/``$@`` are untrusted at the current statement: always at
    # script level (command-line arguments); inside a function only when some
    # call site passes untrusted data (``download "$CONST_URL"`` is not).
    positional_tainted: bool = True
    origins: dict[str, set[str]] = field(default_factory=dict)
    positional_origins: frozenset[str] = frozenset({"argv"})


@dataclass
class _Invocation:
    index: int | None = None
    privileged: bool = False
    wrapper: str | None = None
    user: str | None = None
    script: str | None = None
    script_index: int | None = None
    options: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)
    environment: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _SinkTaint:
    origins: frozenset[str]
    user: str | None = None
    wrapped: bool = False


def _function_scopes(statements: list[tuple[int, str]]) -> list[str | None]:
    """Enclosing shell function name for every statement (None at top level)."""
    scopes: list[str | None] = []
    stack: list[tuple[str | None, int]] = []  # (function name, brace depth)
    depth = 0
    pending_function: str | None = None
    for _line_no, statement in statements:
        text = statement.strip()
        header = _FUNCTION_HEADER_RE.match(text)
        current = next((name for name, _ in reversed(stack) if name), None)
        if header:
            name = header.group("kw") or header.group("name")
            scopes.append(current)
            if text.endswith("{"):
                depth += 1
                stack.append((name, depth))
            else:
                pending_function = name
            continue
        if pending_function is not None and text == "{":
            depth += 1
            stack.append((pending_function, depth))
            pending_function = None
            scopes.append(current)
            continue
        pending_function = None
        scopes.append(current)
        if text.endswith("{") and not text.endswith("${"):
            depth += 1
            stack.append((None, depth))
        elif text.startswith("}"):
            if stack and stack[-1][1] == depth:
                stack.pop()
            depth = max(depth - 1, 0)
    return scopes


def _tainted_functions(
    statements: list[tuple[int, str]], scopes: list[str | None]
) -> set[str]:
    """Functions whose positional parameters can carry untrusted data."""
    functions = {scope for scope in scopes if scope}
    called: set[str] = set()
    tainted: set[str] = set()
    for _ in range(4):
        state = _ShellState()
        before = set(tainted)
        for (_line_no, statement), scope in zip(statements, scopes):
            text = statement.strip()
            state.positional_tainted = scope is None or scope in tainted
            _handle_read(text, state)
            _handle_assignment(text, state)
            tokens = _shell_tokens(text)
            idx = _command_index(tokens)
            if idx is None or tokens[idx] not in functions:
                continue
            name = tokens[idx]
            called.add(name)
            if any(_is_tainted(arg, state) for arg in tokens[idx + 1 :]):
                tainted.add(name)
        if tainted == before:
            break
    # A function that is never called here is a library entry point: its
    # arguments come from whoever sources the script.
    return tainted | (functions - called)


def scan_danger(file_path: str, source: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    state = _ShellState()

    statements = _iter_statements(source)
    scopes = _function_scopes(statements)
    tainted_functions = _tainted_functions(statements, scopes)
    structure = None
    if _ROOT_IDENTITY_TEXT_RE.search(source):
        structure = shell_structure(source)

    for (line_no, statement), scope in zip(statements, scopes):
        text = statement.strip()
        if not text:
            continue

        state.positional_tainted = scope is None or scope in tainted_functions
        state.positional_origins = _positional_origins(scope, structure, line_no)
        _handle_read(text, state)
        _handle_assignment(text, state)

        for finding in findings_for_command(text, file_path, line_no):
            _add_existing_finding(findings, seen, finding)
        for spec, taint in _statement_sinks(text, state, 0):
            _add_finding(
                findings,
                seen,
                _assessed(spec, taint, structure, line_no),
                file_path,
                line_no,
            )

    return findings


def _positional_origins(
    scope: str | None,
    structure: ShellStructure | None,
    line_no: int,
) -> frozenset[str]:
    if scope is not None:
        return frozenset({"function"})
    if structure is None:
        return frozenset({"argv"})
    if structure.in_function(line_no):
        return frozenset({"function"})
    if structure.positionals_rebound:
        return frozenset({"rebound"})
    return frozenset({"argv"})


def _assessed(
    spec: tuple[str, str, str],
    taint: _SinkTaint,
    structure: ShellStructure | None,
    line_no: int,
) -> tuple[str, str, str, dict]:
    rule_id, message, severity = spec
    reasons = []
    lowered = severity
    if (
        structure is not None
        and structure.root_gate_covers(line_no)
        and taint.origins == {"argv"}
    ):
        reasons.append("root_only_script_arguments")
        message = _ROOT_ONLY_MESSAGES[rule_id]
        lowered = _SEVERITY_BELOW[lowered]
    if taint.user is not None and rule_id in _PRIVILEGE_DROP_RULES:
        reasons.append("privilege_drop")
        message = (
            f"{message} It runs as the non-root user '{taint.user}', "
            "which limits the impact."
        )
        lowered = _SEVERITY_BELOW[lowered]
    if not reasons:
        return rule_id, message, severity, {}
    return (
        rule_id,
        message,
        lowered,
        {"severity_reason": "_and_".join(reasons), "original_severity": severity},
    )


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
            # The newline ending a blank/comment-only physical line is not
            # escaped. It terminates any command continued onto that line.
            if pending:
                for statement in _split_shell_statements(pending):
                    statements.append((pending_line, statement))
                pending = ""
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
        state.origins[name] = {"read"}
        state.path_sanitized_vars.discard(name)


def _handle_assignment(statement: str, state: _ShellState) -> None:
    match = _ASSIGN_RE.match(statement)
    if not match:
        return

    name = match.group("name")
    rhs = match.group("rhs").strip()
    origins = _taint_origins(rhs, state)
    if origins:
        state.tainted_vars.add(name)
        state.origins[name] = origins
        if _path_expr_is_sanitized(rhs, state):
            state.path_sanitized_vars.add(name)
        else:
            state.path_sanitized_vars.discard(name)
    else:
        state.tainted_vars.discard(name)
        state.origins.pop(name, None)
        state.path_sanitized_vars.discard(name)


def _statement_sinks(
    statement: str, state: _ShellState, depth: int
) -> list[tuple[tuple[str, str, str], _SinkTaint]]:
    found = _command_sinks(statement, state, depth)
    url = _url_sink_taint(statement, state)
    if url is not None:
        found.append((_SSRF_FINDING, url))
    path = _path_sink_taint(statement, state)
    if path is not None:
        found.append((_PATH_FINDING, path))
    return found


def _command_sinks(
    statement: str, state: _ShellState, depth: int
) -> list[tuple[tuple[str, str, str], _SinkTaint]]:
    tokens = _shell_tokens(statement)
    if not tokens:
        return []
    expansions: list[str | None] = [None] * len(tokens)
    if any(_command_name(token) in _SCRIPT_RUNNERS for token in tokens):
        expansions = _outer_expansions(statement, tokens)
    found = []
    for segment in _pipeline_segments(list(zip(tokens, expansions))):
        found.extend(_segment_command_sinks(segment, state, depth))
    return found


def _pipeline_segments(words: list[tuple[str, str | None]]) -> list[list]:
    segments: list[list] = [[]]
    for word in words:
        if word[0] in {"|", "|&"}:
            segments.append([])
        else:
            segments[-1].append(word)
    return [segment for segment in segments if segment]


def _segment_command_sinks(
    words: list[tuple[str, str | None]], state: _ShellState, depth: int
) -> list[tuple[tuple[str, str, str], _SinkTaint]]:
    tokens = [token for token, _expansion in words]
    expansions = [expansion for _token, expansion in words]
    invocation = _invocation(tokens)
    if invocation.script is not None:
        expansion = None
        if invocation.script_index is not None:
            expansion = expansions[invocation.script_index]
        return _script_sinks(invocation.script, expansion, [], invocation, state, depth)
    command_idx = invocation.index
    if command_idx is None:
        return []
    command = _command_name(tokens[command_idx])
    if command in {"eval", "source"} or tokens[command_idx] == ".":
        origins = _taint_origins(" ".join(tokens[command_idx + 1 :]), state)
        if not origins:
            return []
        return [(_COMMAND_FINDING, _wrapped_taint(origins, invocation))]
    if command not in _SHELL_NAMES:
        return []
    flag_idx = _shell_command_flag(tokens, command_idx)
    if flag_idx is None:
        return []
    arguments = _shell_arguments(tokens[flag_idx + 1 :])
    if not arguments:
        return []
    return _script_sinks(
        arguments[0],
        expansions[flag_idx + 1],
        arguments[1:],
        invocation,
        state,
        depth,
    )


def _wrapped_taint(origins: set[str], invocation: _Invocation) -> _SinkTaint:
    return _SinkTaint(
        frozenset(origins), _dropped_user(invocation), invocation.privileged
    )


def _script_sinks(
    script: str,
    expansion: str | None,
    arguments: list[str],
    invocation: _Invocation,
    state: _ShellState,
    depth: int,
) -> list[tuple[tuple[str, str, str], _SinkTaint]]:
    environment = _environment_origins(invocation.environment, state)
    if expansion is None:
        expansion = script
    expanded = _taint_origins(expansion, state)
    if expanded or depth >= _MAX_INNER_SHELLS:
        origins = expanded | _taint_origins(
            " ".join([script, *arguments]), state, environment
        )
        if not origins:
            return []
        return [(_COMMAND_FINDING, _wrapped_taint(origins, invocation))]
    inner = _inner_state(invocation, environment, arguments, state)
    user = _dropped_user(invocation)
    found = []
    for _line_no, statement in _iter_statements(script):
        text = statement.strip()
        if not text:
            continue
        _handle_read(text, inner)
        _handle_assignment(text, inner)
        for spec, taint in _statement_sinks(text, inner, depth + 1):
            effective_user = user
            if taint.wrapped:
                effective_user = taint.user
            found.append(
                (
                    spec,
                    _SinkTaint(
                        taint.origins,
                        effective_user,
                        invocation.privileged or taint.wrapped,
                    ),
                )
            )
    return found


def _inner_state(
    invocation: _Invocation,
    environment: dict[str, set[str]],
    arguments: list[str],
    state: _ShellState,
) -> _ShellState:
    inner = _ShellState(
        tainted_vars=set(state.tainted_vars),
        path_sanitized_vars=set(state.path_sanitized_vars),
        origins={name: set(origins) for name, origins in state.origins.items()},
    )
    for name in invocation.environment:
        inner.tainted_vars.discard(name)
        inner.path_sanitized_vars.discard(name)
        inner.origins.pop(name, None)
    for name, origins in environment.items():
        inner.tainted_vars.add(name)
        inner.origins[name] = set(origins)
    positional: set[str] = set()
    for argument in arguments[1:]:
        positional |= _taint_origins(argument, state)
    inner.positional_tainted = bool(positional)
    inner.positional_origins = frozenset(positional)
    return inner


def _outer_expansions(statement: str, tokens: list[str]) -> list[str | None]:
    """For every token, the text the calling shell expands before running it.

    Single-quoted text reaches the command unexpanded. When the raw words do
    not line up with ``tokens``, every token counts as fully expanded.
    """
    raw = _raw_words(statement)
    unknown: list[str | None] = [None] * len(tokens)
    if raw is None or len(raw) != len(tokens):
        return unknown
    expansions: list[str | None] = []
    for word, token in zip(raw, tokens):
        try:
            decoded = shlex.split(word, comments=False, posix=True)
        except ValueError:
            return unknown
        if decoded != [token]:
            return unknown
        expansions.append(_expanded_text(word))
    return expansions


def _raw_words(statement: str) -> list[str] | None:
    words: list[str] = []
    start: int | None = None
    idx = 0
    while idx < len(statement):
        char = statement[idx]
        if char in " \t\n":
            if start is not None:
                words.append(statement[start:idx])
                start = None
            idx += 1
            continue
        if start is None:
            start = idx
        if char == "\\":
            idx += 2
        elif char == "'":
            end = statement.find("'", idx + 1)
            if end < 0:
                return None
            idx = end + 1
        elif char == '"':
            idx = _double_quote_end(statement, idx)
            if idx < 0:
                return None
        else:
            idx += 1
    if start is not None:
        words.append(statement[start:])
    return words


def _double_quote_end(text: str, idx: int) -> int:
    idx += 1
    while idx < len(text):
        if text[idx] == "\\":
            idx += 2
        elif text[idx] == '"':
            return idx + 1
        else:
            idx += 1
    return -1


def _expanded_text(word: str) -> str:
    parts: list[str] = []
    idx = 0
    quoted = False
    while idx < len(word):
        char = word[idx]
        if char == "\\":
            idx += 2
            continue
        if char == "'" and not quoted:
            end = word.find("'", idx + 1)
            if end < 0:
                return word
            idx = end + 1
            continue
        if char == '"':
            quoted = not quoted
            idx += 1
            continue
        parts.append(char)
        idx += 1
    return "".join(parts)


def _shell_command_flag(tokens: list[str], command_idx: int) -> int | None:
    skip = False
    for idx in range(command_idx + 1, len(tokens)):
        token = tokens[idx]
        if skip:
            skip = False
            continue
        if _SHELL_COMMAND_FLAG_RE.match(token):
            return idx
        if token in {"-o", "+o", "-O", "+O"}:
            skip = True
            continue
        if not token.startswith(("-", "+")) or token == "--":
            break
    if "-c" in tokens[command_idx + 1 :]:
        return tokens.index("-c", command_idx + 1)
    return None


def _url_sink_taint(statement: str, state: _ShellState) -> _SinkTaint | None:
    tokens = _shell_tokens(statement)
    command_idx = _command_index(tokens)
    if command_idx is None or _command_name(tokens[command_idx]) not in _URL_FETCHERS:
        return None

    origins: set[str] = set()
    for arg in _url_arguments(tokens[command_idx:]):
        if _url_arg_controls_destination(arg, state):
            origins |= _taint_origins(arg, state)
    if not origins:
        return None
    return _SinkTaint(frozenset(origins))


def _path_sink_taint(statement: str, state: _ShellState) -> _SinkTaint | None:
    redirected: set[str] = set()
    for target in _redirection_targets(statement):
        if _is_tainted(target, state) and not _path_expr_is_sanitized(target, state):
            redirected |= _taint_origins(target, state)

    tokens = _shell_tokens(statement)
    invocation = _invocation(tokens)
    command_idx = invocation.index
    arguments: set[str] = set()
    if command_idx is not None and _command_name(tokens[command_idx]) in _PATH_SINKS:
        for arg in _path_arguments(tokens[command_idx:]):
            if _is_tainted(arg, state) and not _path_expr_is_sanitized(arg, state):
                arguments |= _taint_origins(arg, state)

    if redirected:
        return _SinkTaint(frozenset(redirected | arguments))
    if arguments:
        return _wrapped_taint(arguments, invocation)
    return None


def _shell_tokens(statement: str) -> list[str]:
    try:
        return shlex.split(statement, comments=False, posix=True)
    except ValueError:
        return statement.split()


def _command_index(tokens: list[str]) -> int | None:
    return _invocation(tokens).index


def _invocation(tokens: list[str]) -> _Invocation:
    invocation = _Invocation()
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        name = _command_name(token)
        if "=" in token and not token.startswith(("$", "./", "/")):
            _record_assignment(invocation, token)
            idx += 1
            continue
        if name in _PRIVILEGE_WRAPPERS:
            idx = _skip_privilege_wrapper(tokens, idx, name, invocation)
            continue
        if name in _COMMAND_PREFIXES:
            idx = _skip_command_prefix(tokens, idx, name, invocation)
            continue
        invocation.index = idx
        return invocation
    return invocation


def _record_assignment(invocation: _Invocation, token: str) -> None:
    match = _ENV_ASSIGNMENT_RE.match(token)
    if match:
        invocation.environment[match.group("name")] = match.group("value")


def _skip_privilege_wrapper(
    tokens: list[str], idx: int, name: str, invocation: _Invocation
) -> int:
    invocation.privileged = True
    invocation.wrapper = name
    invocation.user = None
    invocation.script = None
    invocation.script_index = None
    invocation.options = {}
    invocation.flags = set()
    idx = _wrapper_options(tokens, idx + 1, name, invocation)
    if name in {"runuser", "su"} and invocation.user is None:
        if idx < len(tokens) and not tokens[idx].startswith("-"):
            invocation.user = tokens[idx]
            idx = _wrapper_options(tokens, idx + 1, name, invocation)
        if invocation.script is None:
            return len(tokens)
    if invocation.script is not None:
        return len(tokens)
    return idx


def _wrapper_options(
    tokens: list[str], idx: int, name: str, invocation: _Invocation
) -> int:
    options_with_values = _WRAPPER_VALUE_OPTIONS[name]
    while idx < len(tokens):
        token = tokens[idx]
        if token == "--":
            return idx + 1
        if token == "-" and name in {"runuser", "su"}:
            idx += 1
            continue
        if not token.startswith("-") or token == "-":
            return idx
        if not token.startswith("--") and len(token) > 2:
            idx = _short_option_cluster(tokens, idx, name, invocation)
            continue
        option, separator, inline = token.partition("=")
        if option in options_with_values:
            if separator:
                _wrapper_option(name, option, inline, None, invocation)
                idx += 1
            elif idx + 1 < len(tokens):
                _wrapper_option(name, option, tokens[idx + 1], idx + 1, invocation)
                idx += 2
            else:
                return len(tokens)
            continue
        invocation.flags.add(option)
        idx += 1
    return idx


def _short_option_cluster(
    tokens: list[str], idx: int, name: str, invocation: _Invocation
) -> int:
    token = tokens[idx]
    options_with_values = _WRAPPER_VALUE_OPTIONS[name]
    for position in range(1, len(token)):
        option = f"-{token[position]}"
        if option not in options_with_values:
            invocation.flags.add(option)
            continue
        rest = token[position + 1 :]
        if rest:
            _wrapper_option(name, option, rest, None, invocation)
            return idx + 1
        if idx + 1 < len(tokens):
            _wrapper_option(name, option, tokens[idx + 1], idx + 1, invocation)
            return idx + 2
        return len(tokens)
    return idx + 1


def _wrapper_option(
    name: str,
    option: str,
    value: str,
    value_index: int | None,
    invocation: _Invocation,
) -> None:
    invocation.options[option] = value
    if option in _USER_OPTIONS:
        invocation.user = value
    elif option in _SCRIPT_OPTIONS and name in {"runuser", "su"}:
        invocation.script = value
        invocation.script_index = value_index


def _dropped_user(invocation: _Invocation) -> str | None:
    if not invocation.privileged:
        return None
    if invocation.wrapper == "setpriv":
        return _setpriv_user(invocation)
    user = invocation.user
    if user is not None and user.startswith("#"):
        if _unprivileged_id(user[1:]):
            return user
        return None
    if _unprivileged_id(user):
        return user
    return None


def _setpriv_user(invocation: _Invocation) -> str | None:
    options = invocation.options
    uid = options.get("--reuid")
    if not _unprivileged_id(uid) or not _unprivileged_id(options.get("--regid")):
        return None
    if "--keep-groups" in invocation.flags:
        return None
    groups = options.get("--groups")
    if groups is not None:
        if not all(_unprivileged_id(group) for group in groups.split(",")):
            return None
    elif not invocation.flags & _GROUP_FLAGS:
        return None
    if any("+" in options.get(option, "") for option in _CAPABILITY_OPTIONS):
        return None
    return uid


def _unprivileged_id(value: str | None) -> bool:
    if not value or value in _ROOT_USERS:
        return False
    if value.isdigit():
        return 0 < int(value) < _MAX_ACCOUNT_ID
    return _ACCOUNT_NAME_RE.fullmatch(value) is not None


def _shell_arguments(tokens: list[str]) -> list[str]:
    arguments: list[str] = []
    for token in tokens:
        if _SHELL_ARGUMENT_END_RE.match(token):
            break
        arguments.append(token)
    return arguments


def _environment_origins(
    environment: dict[str, str], state: _ShellState
) -> dict[str, set[str]]:
    origins = {}
    for name, value in environment.items():
        value_origins = _taint_origins(value, state)
        if value_origins:
            origins[name] = value_origins
    return origins


def _skip_command_prefix(
    tokens: list[str], idx: int, name: str, invocation: _Invocation
) -> int:
    idx += 1
    options_with_values = _PREFIX_OPTIONS_WITH_VALUES.get(name, set())
    while idx < len(tokens):
        token = tokens[idx]
        if name == "env" and "=" in token and not token.startswith(("$", "./", "/")):
            _record_assignment(invocation, token)
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
    return bool(_taint_origins(expr, state))


def _taint_origins(
    expr: str,
    state: _ShellState,
    environment: dict[str, set[str]] | None = None,
) -> set[str]:
    if not expr:
        return set()
    origins: set[str] = set()
    if state.positional_tainted and _POSITIONAL_RE.search(expr):
        origins |= state.positional_origins
    for match in _VAR_REF_RE.finditer(expr):
        name = match.group("simple") or match.group("braced")
        if environment and name in environment:
            origins |= environment[name]
        if name in state.tainted_vars:
            origins |= state.origins.get(name, {"unknown"})
    if origins and _runs_untracked_command(expr):
        origins.add("derived")
    return origins


def _runs_untracked_command(expr: str) -> bool:
    for match in _SUBSTITUTION_RE.finditer(expr):
        command = match.group("command")
        rest = match.group("rest")
        if command is None:
            command = match.group("backtick")
            rest = match.group("tail")
        if not command or command[0] in "<>":
            return True
        name = _command_name(command)
        if name in _PATH_TRANSFORMS:
            continue
        if name == "readlink" and _CANONICAL_READLINK_RE.search(rest or ""):
            continue
        return True
    return False


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
    assessed: tuple[str, str, str, dict],
    file_path: str,
    line: int,
) -> None:
    rule_id, message, severity, evidence = assessed
    key = (rule_id, line, str(Path(file_path)))
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(Path(file_path)),
        "line": line,
        "col": 0,
        "category": "danger",
        **evidence,
    }
    if key in seen:
        for idx, existing in enumerate(findings):
            if (
                existing["rule_id"],
                existing["line"],
                str(Path(existing["file"])),
            ) == key and _SEVERITY_RANK.get(
                existing.get("severity"), 3
            ) < _SEVERITY_RANK[severity]:
                findings[idx] = finding
        return
    seen.add(key)
    findings.append(finding)


def _add_existing_finding(
    findings: list[dict],
    seen: set[tuple[str, int, str]],
    finding: dict,
) -> None:
    key = (finding["rule_id"], finding["line"], str(Path(finding["file"])))
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)
