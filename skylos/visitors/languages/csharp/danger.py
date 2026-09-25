from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from skylos.visitors.languages.csharp._lex import (
    _TOKEN_RE,
    _RawTokenMatch,
    mask_comments_and_strings,
    matching_brace,
)

_PARAM_RE = re.compile(
    r"(?:params\s+)?(?:this\s+)?(?:[\w.<>\[\],?]+\s+)+@?(?P<name>[A-Za-z_]\w*)$"
)
_ASSIGN_RE = re.compile(
    r"\b(?:(?P<decl_type>[\w.<>\[\],?]+)\s+)?"
    r"(?P<lhs>@?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*=(?!=)\s*(?P<rhs>.+?);?\s*$",
    re.DOTALL,
)
_METHOD_RE = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?:\[[^\]\n]+\]\s*)*"
    r"(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|partial|unsafe|new)\s+)*"
    r"(?:[A-Za-z_][\w.<>\[\],?]*\s+)+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*"
    r"(?:where\s+[^{=>]+)?(?P<opener>\{|=>)"
)
_CONSTRUCTOR_RE = re.compile(
    r"(?m)(?:^|(?<=[;{}]))\s*(?:\[[^\]\n]+\]\s*)*"
    r"(?:(?:public|private|protected|internal|static|extern|unsafe)\s+)*"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?P<opener>\{|=>)"
)
_TYPE_RE = re.compile(r"\b(?:class|record|struct)\s+(?P<name>[A-Za-z_]\w*)")
_SOURCE_HINTS = (
    "Request.Query",
    "Request.Form",
    "Request.Headers",
    "Request.Cookies",
    "Request.RouteValues",
    "Request.Path",
    "Request.Body",
    "HttpContext.Request",
    "Environment.GetEnvironmentVariable",
    "Console.ReadLine",
    "IFormFile.FileName",
    "args[",
)
_COMMAND_SINK_RE = re.compile(r"\b(?:Process\.Start|new\s+ProcessStartInfo)\s*\(")
_COMMAND_PROPERTY_RE = re.compile(
    r"\b(?P<owner>@?[A-Za-z_]\w*)\.(?:FileName|Arguments)\s*="
)
_PATH_SINK_RE = re.compile(
    r"\b(?:File|Directory)\.(?:Open|OpenRead|OpenWrite|ReadAllText|ReadAllBytes|"
    r"ReadLines|WriteAllText|WriteAllBytes|AppendAllText|Delete|Copy|Move|Exists|"
    r"GetFiles|GetDirectories)\s*\("
)
_PATH_COMBINE_RE = re.compile(r"\s*(?P<qualified>System\.IO\.)?Path\.Combine\s*\(")
_PATH_BASENAME_RE = re.compile(r"\s*(?P<qualified>System\.IO\.)?Path\.GetFileName\s*\(")
_FIXED_DIRECTORY_RE = re.compile(r'"(?P<path>[A-Za-z0-9_./-]+)"')
_PATH_SHADOW_RE = re.compile(
    r"\b(?:class|record|struct|interface)\s+Path\b"
    r"|\busing\s+Path\s*="
    r"|\b(?:var|[A-Za-z_]\w*)\s+Path\s*(?:=|[,;)])"
)
_SSRF_SINK_RE = re.compile(
    r"\b(?:GetAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync|"
    r"WebRequest\.Create|WebRequest\.CreateHttp)\s*\("
    r"|\bnew\s+HttpRequestMessage\s*\("
)
_SQL_SINK_RE = re.compile(
    r"\b(?:new\s+(?:SqlCommand|DbCommand|NpgsqlCommand|MySqlCommand|OleDbCommand)\s*\(|"
    r"FromSqlRaw\s*\(|ExecuteSqlRaw\s*\()"
)
_SQL_COMMAND_TYPE_RE = re.compile(
    r"\b(?:SqlCommand|DbCommand|NpgsqlCommand|MySqlCommand|OleDbCommand)\b"
)
_OBJECT_INIT_RE = re.compile(
    r"\bnew\s+(?P<type>ProcessStartInfo|SqlCommand|DbCommand|"
    r"NpgsqlCommand|MySqlCommand|OleDbCommand)\s*(?:\([^{};]*\))?\s*\{$"
)
_TARGET_TYPED_INIT_RE = re.compile(r"\bnew\s*\([^{};]*\)\s*\{$")
_COMMAND_TEXT_RE = re.compile(r"\b(?P<owner>@?[A-Za-z_]\w*)\.CommandText\s*=")
_REDIRECT_RE = re.compile(r"\b(?:Redirect|RedirectPermanent|LocalRedirect)\s*\(")

_COMMAND_FINDING = (
    "SKY-D212",
    "Process execution receives tainted input; validate or allowlist the command.",
)
_PATH_FINDING = (
    "SKY-D215",
    "User-controlled path reaches a filesystem sink without path validation.",
)
_SSRF_FINDING = ("SKY-D216", "User-controlled URL reaches an outbound request sink.")
_SQL_FINDING = (
    "SKY-D211",
    "SQL command text is built from tainted input; use parameters.",
)
_REDIRECT_FINDING = (
    "SKY-D230",
    "Redirect target is controlled by input; validate allowed destinations.",
)


@dataclass
class _ScopeState:
    tainted_vars: dict[str, set[str]]
    path_type_shadowed: bool = False
    basename_vars: set[str] = field(default_factory=set)
    assigned_vars: set[str] = field(default_factory=set)
    process_info_vars: set[str] = field(default_factory=set)
    sql_command_vars: set[str] = field(default_factory=set)


def scan_danger(file_path: str, source: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    path_type_shadowed = bool(_PATH_SHADOW_RE.search(mask_comments_and_strings(source)))

    for body, start_line, params in _iter_scopes(source):
        _scan_scope(
            body,
            start_line,
            params,
            path_type_shadowed=path_type_shadowed,
            file_path=file_path,
            findings=findings,
            seen=seen,
        )

    return findings


def _scan_scope(
    body: str,
    start_line: int,
    tainted_params: set[str],
    *,
    path_type_shadowed: bool,
    file_path: str,
    findings: list[dict],
    seen: set[tuple[str, int, str]],
) -> None:
    masked_body = mask_comments_and_strings(body)
    initializer_end = -1
    state = _ScopeState(
        tainted_vars={
            rule_id: set(tainted_params)
            for rule_id, _ in (
                _COMMAND_FINDING,
                _PATH_FINDING,
                _SSRF_FINDING,
                _SQL_FINDING,
                _REDIRECT_FINDING,
            )
        },
        path_type_shadowed=path_type_shadowed,
        assigned_vars=set(tainted_params),
    )
    for offset, statement in _iter_statements(body):
        text = statement.strip()
        if not text:
            continue
        opening_initializer = False
        line = start_line + body.count("\n", 0, offset)
        for spec in _findings_for_sinks(text, state):
            _add_finding(
                findings,
                seen,
                rule_id=spec[0],
                message=spec[1],
                file_path=file_path,
                line=line,
                statement=text,
            )
        if text.endswith("{"):
            open_brace = masked_body.find("{", offset)
            if open_brace >= 0:
                initializer_type = _object_initializer_type(text)
                if initializer_type:
                    close_brace = matching_brace(masked_body, open_brace)
                    if close_brace >= 0:
                        opening_initializer = True
                        initializer_end = close_brace
                        for spec, property_offset in _object_initializer_findings(
                            body,
                            masked_body,
                            open_brace,
                            close_brace,
                            initializer_type,
                            state,
                        ):
                            _add_finding(
                                findings,
                                seen,
                                rule_id=spec[0],
                                message=spec[1],
                                file_path=file_path,
                                line=start_line + body.count("\n", 0, property_offset),
                                statement=body[open_brace : close_brace + 1],
                            )
        if opening_initializer or offset >= initializer_end:
            _handle_assignment(text, state)


def _object_initializer_type(statement: str) -> str | None:
    code = _masked_code(statement)
    explicit = _OBJECT_INIT_RE.search(code)
    if explicit:
        return explicit.group("type")
    if _TARGET_TYPED_INIT_RE.search(code):
        assignment = _ASSIGN_RE.search(code)
        if assignment:
            declared = assignment.group("decl_type")
            if declared == "ProcessStartInfo" or (
                declared and _SQL_COMMAND_TYPE_RE.fullmatch(declared)
            ):
                return declared
    return None


def _object_initializer_findings(
    body: str,
    masked_body: str,
    open_brace: int,
    close_brace: int,
    initializer_type: str,
    state: _ScopeState,
) -> list[tuple[tuple[str, str], int]]:
    inner_start = open_brace + 1
    code = masked_body[inner_start:close_brace]
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    for index, char in enumerate(code):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
    spans.append((start, len(code)))

    is_process = initializer_type == "ProcessStartInfo"
    property_pattern = (
        r"\s*(?P<name>FileName|Arguments)\s*=(?!=)\s*"
        if is_process
        else r"\s*(?P<name>CommandText)\s*=(?!=)\s*"
    )
    spec = _COMMAND_FINDING if is_process else _SQL_FINDING
    matches: list[tuple[tuple[str, str], int]] = []
    for start, end in spans:
        match = re.match(property_pattern, code[start:end])
        if not match:
            continue
        rhs = body[inner_start + start + match.end() : inner_start + end]
        if _is_tainted(rhs, state.tainted_vars[spec[0]]):
            matches.append((spec, inner_start + start + match.start("name")))
    return matches


def _handle_assignment(statement: str, state: _ScopeState) -> None:
    code = _masked_code(statement)
    _invalidate_basename_writes(code, state.basename_vars)
    match = _ASSIGN_RE.search(code)
    if not match:
        return
    lhs = match.group("lhs").lstrip("@")
    if lhs.endswith((".CommandText", ".FileName", ".Arguments")):
        return

    name = lhs.rsplit(".", 1)[-1]
    rhs = match.group("rhs")
    if name not in state.assigned_vars and _is_basename_call(
        rhs, state.tainted_vars[_PATH_FINDING[0]], state.path_type_shadowed
    ):
        state.basename_vars.add(name)
    else:
        state.basename_vars.discard(name)
    state.assigned_vars.add(name)
    declared_type = match.group("decl_type")
    _track_typed_variable(
        name, rhs, "ProcessStartInfo", state.process_info_vars, declared_type
    )
    _track_typed_variable(
        name, rhs, _SQL_COMMAND_TYPE_RE, state.sql_command_vars, declared_type
    )
    for tainted_vars in state.tainted_vars.values():
        _track_taint(name, rhs, tainted_vars)


def _invalidate_basename_writes(code: str, basename_vars: set[str]) -> None:
    """A mutable local stops proving containment after any observed write."""
    for name in set(basename_vars):
        escaped = re.escape(name)
        if re.search(
            rf"\b@?{escaped}\s*(?:\+\+|--|\?\?=|[+*/%&|^-]=|=(?!=))"
            rf"|\b(?:ref|out)\s+@?{escaped}\b",
            code,
        ):
            basename_vars.discard(name)


def _track_typed_variable(
    name: str,
    rhs: str,
    type_hint: str | re.Pattern[str],
    tracked: set[str],
    declared_type: str | None,
) -> None:
    matched = (
        type_hint in rhs if isinstance(type_hint, str) else bool(type_hint.search(rhs))
    )
    if declared_type and re.match(r"\s*new\s*\(", rhs):
        matched |= (
            declared_type == type_hint
            if isinstance(type_hint, str)
            else bool(type_hint.fullmatch(declared_type))
        )
    if matched:
        tracked.add(name)
    else:
        tracked.discard(name)


def _track_taint(name: str, rhs: str, tainted_vars: set[str]) -> None:
    if _is_tainted(rhs, tainted_vars):
        tainted_vars.add(name)


def _findings_for_sinks(statement: str, state: _ScopeState) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    calls = (
        (_COMMAND_SINK_RE, _COMMAND_FINDING, True),
        (_PATH_SINK_RE, _PATH_FINDING, False),
        (_SSRF_SINK_RE, _SSRF_FINDING, False),
        (_SQL_SINK_RE, _SQL_FINDING, False),
        (_REDIRECT_RE, _REDIRECT_FINDING, False),
    )
    for regex, spec, all_arguments in calls:
        for match, args in _call_arguments(statement, regex):
            relevant = args if all_arguments else args[:1]
            if spec == _PATH_FINDING and re.search(
                r"\b(?:Copy|Move)\s*\($", match.group()
            ):
                relevant = args[:2]
            elif spec == _SSRF_FINDING and "HttpRequestMessage" in match.group():
                relevant = args[1:2]
            if any(
                _is_tainted(arg, state.tainted_vars[spec[0]])
                and not (
                    spec == _PATH_FINDING
                    and match.group().startswith("File.")
                    and _is_contained_basename_path(arg, state)
                )
                for arg in relevant
            ):
                findings.append(spec)

    properties = (
        (_COMMAND_PROPERTY_RE, state.process_info_vars, _COMMAND_FINDING),
        (_COMMAND_TEXT_RE, state.sql_command_vars, _SQL_FINDING),
    )
    for regex, owners, spec in properties:
        for match in regex.finditer(_masked_code(statement)):
            if match.group("owner").lstrip("@") in owners and _is_tainted(
                statement[match.end() :], state.tainted_vars[spec[0]]
            ):
                findings.append(spec)
    return findings


def _is_basename_call(
    expr: str, tainted_vars: set[str], path_type_shadowed: bool
) -> bool:
    """Recognize only a complete System.IO.Path.GetFileName expression."""
    code = _masked_code(expr)
    match = _PATH_BASENAME_RE.match(code)
    if not match or (path_type_shadowed and not match.group("qualified")):
        return False
    close = _matching_paren(code, match.end() - 1)
    if close < 0 or code[close + 1 :].strip():
        return False
    arguments = _split_arguments(expr, code, match.end(), close)
    return len(arguments) == 1 and _is_tainted(arguments[0], tainted_vars)


def _is_contained_basename_path(expr: str, state: _ScopeState) -> bool:
    """A basename is path-contained only when joined to a fixed directory.

    A bare basename can still select arbitrary local files. Directory APIs
    are deliberately excluded: GetFileName("..") remains ".." and may cause
    a directory operation to escape the base directory.
    """
    code = _masked_code(expr)
    match = _PATH_COMBINE_RE.match(code)
    if not match or (state.path_type_shadowed and not match.group("qualified")):
        return False
    close = _matching_paren(code, match.end() - 1)
    if close < 0 or code[close + 1 :].strip():
        return False
    arguments = _split_arguments(expr, code, match.end(), close)
    if len(arguments) != 2 or not _is_fixed_directory(arguments[0]):
        return False
    basename = _masked_code(arguments[1]).strip()
    if re.fullmatch(r"@?[A-Za-z_]\w*", basename):
        return basename.lstrip("@") in state.basename_vars
    return _is_basename_call(
        arguments[1],
        state.tainted_vars[_PATH_FINDING[0]],
        state.path_type_shadowed,
    )


def _is_fixed_directory(expr: str) -> bool:
    """Accept a simple non-root literal directory, never input-derived paths."""
    match = _FIXED_DIRECTORY_RE.fullmatch(expr.strip())
    if not match:
        return False
    components = [part for part in match.group("path").split("/") if part]
    return bool(components) and all(part not in {".", ".."} for part in components)


def _call_arguments(statement: str, regex: re.Pattern[str]):
    code = _masked_code(statement)
    for match in regex.finditer(code):
        open_paren = match.end() - 1
        close_paren = _matching_paren(code, open_paren)
        if close_paren < 0:
            continue
        yield match, _split_arguments(statement, code, open_paren + 1, close_paren)


def _matching_paren(code: str, open_paren: int) -> int:
    depth = 0
    for index in range(open_paren, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_arguments(statement: str, code: str, start: int, end: int) -> list[str]:
    args: list[str] = []
    depth = 0
    begin = start
    for index in range(start, end):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(statement[begin:index])
            begin = index + 1
    args.append(statement[begin:end])
    return args


def _is_tainted(expr: str, tainted_vars: set[str]) -> bool:
    if not expr:
        return False
    code = _masked_code(expr)
    if any(hint in code for hint in _SOURCE_HINTS):
        return True
    return any(re.search(rf"\b@?{re.escape(name)}\b", code) for name in tainted_vars)


def _masked_code(expr: str) -> str:
    """Mask literals, retaining only expressions inside interpolated strings."""
    chars = list(mask_comments_and_strings(expr))
    for match in _TOKEN_RE.finditer(expr):
        if isinstance(match, _RawTokenMatch):
            continue
        token = match.group()
        if not token.startswith(('$"', '$@"', '@$"')):
            continue
        index = token.find('"') + 1
        while index < len(token) - 1:
            if token[index : index + 2] in ("{{", "}}"):
                index += 2
                continue
            if token[index] != "{":
                index += 1
                continue
            start = index + 1
            depth = 1
            index = start
            while index < len(token) - 1 and depth:
                if token[index] == "{":
                    depth += 1
                elif token[index] == "}":
                    depth -= 1
                index += 1
            if depth == 0:
                hole = mask_comments_and_strings(token[start : index - 1])
                chars[match.start() + start : match.start() + index - 1] = hole
    return "".join(chars)


def _iter_scopes(source: str) -> list[tuple[str, int, set[str]]]:
    masked = mask_comments_and_strings(source)
    scopes: list[tuple[str, int, set[str]]] = []
    spans: list[tuple[int, int]] = []
    type_names = {match.group("name") for match in _TYPE_RE.finditer(masked)}
    declarations = list(_METHOD_RE.finditer(masked))
    declarations.extend(
        match
        for match in _CONSTRUCTOR_RE.finditer(masked)
        if match.group("name") in type_names
    )

    for match in sorted(declarations, key=lambda item: item.start()):
        if match.group("opener") == "{":
            open_brace = match.end() - 1
            close_brace = matching_brace(masked, open_brace)
            if close_brace == -1:
                continue
            scopes.append(
                _method_scope(source, open_brace, close_brace, match.group("params"))
            )
            spans.append((open_brace, close_brace + 1))
        else:
            expression_start = match.end()
            expression_end = masked.find(";", expression_start)
            if expression_end == -1:
                continue
            scopes.append(
                (
                    source[expression_start : expression_end + 1],
                    source.count("\n", 0, expression_start) + 1,
                    _tainted_params(match.group("params")),
                )
            )
            spans.append((expression_start, expression_end + 1))

    scopes.append((_blank_spans(source, spans), 1, {"args"}))
    return scopes


def _method_scope(
    source: str, open_brace: int, close_brace: int, params: str
) -> tuple[str, int, set[str]]:
    return (
        source[open_brace + 1 : close_brace],
        source.count("\n", 0, open_brace + 1) + 1,
        _tainted_params(params),
    )


def _blank_spans(source: str, spans: list[tuple[int, int]]) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if end <= cursor:
            continue
        start = max(start, cursor)
        pieces.append(source[cursor:start])
        pieces.append(_blank_non_newlines(source[start:end]))
        cursor = end
    pieces.append(source[cursor:])
    return "".join(pieces)


def _blank_non_newlines(text: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in text)


def _tainted_params(params: str) -> set[str]:
    tainted: set[str] = set()
    for raw in _split_params(params):
        cleaned = re.sub(r"\[[^\]]+\]", " ", raw).split("=", 1)[0].strip()
        match = _PARAM_RE.search(cleaned)
        if match:
            tainted.add(match.group("name"))
    return tainted


def _split_params(params: str) -> list[str]:
    masked = mask_comments_and_strings(params)
    pieces: list[str] = []
    begin = 0
    depth = 0
    for index, char in enumerate(masked):
        if char in "<([":
            depth += 1
        elif char in ">)]" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            pieces.append(params[begin:index])
            begin = index + 1
    pieces.append(params[begin:])
    return pieces


def _iter_statements(body: str):
    masked = mask_comments_and_strings(body)
    start = 0
    for match in re.finditer(r"[;{}]", masked):
        end = match.end()
        if chunk := body[start:end].strip():
            code_start = re.search(r"\S", masked[start:end])
            if code_start:
                yield start + code_start.start(), chunk
        start = end
    if tail := body[start:].strip():
        code_start = re.search(r"\S", masked[start:])
        if code_start:
            yield start + code_start.start(), tail


def _add_finding(
    findings: list[dict],
    seen: set[tuple[str, int, str]],
    *,
    rule_id: str,
    message: str,
    file_path: str,
    line: int,
    statement: str,
) -> None:
    key = (rule_id, line, statement)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "rule_id": rule_id,
            "severity": "HIGH",
            "message": message,
            "file": str(Path(file_path)),
            "line": line,
            "col": 0,
            "category": "danger",
        }
    )
