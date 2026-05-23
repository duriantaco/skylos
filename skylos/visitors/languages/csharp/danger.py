from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from skylos.visitors.languages.csharp._lex import mask_comments_and_strings, matching_brace

_TAINT_NAME_RE = re.compile(
    r"(arg|cmd|command|file|filename|id|input|name|path|payload|query|redirect|request|sql|target|url|uri|user)",
    re.I,
)
_PARAM_RE = re.compile(
    r"(?:params\s+)?(?:this\s+)?(?:[\w.<>\[\],?]+\s+)+@?(?P<name>[A-Za-z_]\w*)$"
)
_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:var|string|object|Uri|HttpRequestMessage|ProcessStartInfo|SqlCommand|[\w.<>\[\],?]+)\s+)?"
    r"(?P<lhs>@?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*=\s*(?P<rhs>.+?);?\s*$",
    re.DOTALL,
)
_METHOD_RE = re.compile(
    r"(?m)^\s*(?:\[[^\]\n]+\]\s*)*"
    r"(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|partial|unsafe|new)\s+)*"
    r"(?:[A-Za-z_][\w.<>\[\],?]*\s+)+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*"
    r"(?:where\s+[^{=>]+)?\{"
)

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
_SANITIZER_HINTS = (
    "Path.GetFileName(",
    "Path.GetRandomFileName(",
    "Uri.EscapeDataString(",
    "WebUtility.UrlEncode(",
    "HttpUtility.UrlEncode(",
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
_SQL_FINDING = ("SKY-D211", "SQL command text is built from tainted input; use parameters.")
_REDIRECT_FINDING = (
    "SKY-D230",
    "Redirect target is controlled by input; validate allowed destinations.",
)


@dataclass
class _ScopeState:
    tainted_vars: set[str]
    process_info_vars: set[str] = field(default_factory=set)
    sql_command_vars: set[str] = field(default_factory=set)


def scan_danger(file_path: str, source: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for body, start_line, params in _iter_scopes(source):
        _scan_scope(body, start_line, params, file_path=file_path, findings=findings, seen=seen)

    return findings


def _scan_scope(
    body: str,
    start_line: int,
    tainted_params: set[str],
    *,
    file_path: str,
    findings: list[dict],
    seen: set[tuple[str, int, str]],
) -> None:
    state = _ScopeState(tainted_vars=set(tainted_params))
    for offset, statement in _iter_statements(body):
        text = statement.strip()
        if not text:
            continue
        line = start_line + body.count("\n", 0, offset)
        _handle_assignment(text, state)
        if spec := _finding_for_sink(text, state):
            _add_finding(
                findings,
                seen,
                rule_id=spec[0],
                message=spec[1],
                file_path=file_path,
                line=line,
                statement=text,
            )


def _handle_assignment(statement: str, state: _ScopeState) -> None:
    match = _ASSIGN_RE.match(statement)
    if not match:
        return
    lhs = match.group("lhs").lstrip("@")
    if lhs.endswith((".CommandText", ".FileName", ".Arguments")):
        return

    name = lhs.rsplit(".", 1)[-1]
    rhs = match.group("rhs")
    _track_typed_variable(name, rhs, "ProcessStartInfo", state.process_info_vars)
    _track_typed_variable(name, rhs, _SQL_COMMAND_TYPE_RE, state.sql_command_vars)
    _track_taint(name, rhs, state.tainted_vars)


def _track_typed_variable(
    name: str, rhs: str, type_hint: str | re.Pattern[str], tracked: set[str]
) -> None:
    matched = type_hint in rhs if isinstance(type_hint, str) else bool(type_hint.search(rhs))
    if matched:
        tracked.add(name)
    else:
        tracked.discard(name)


def _track_taint(name: str, rhs: str, tainted_vars: set[str]) -> None:
    if _is_tainted(rhs, tainted_vars):
        tainted_vars.add(name)
    else:
        tainted_vars.discard(name)


def _finding_for_sink(statement: str, state: _ScopeState) -> tuple[str, str] | None:
    if not _is_tainted(statement, state.tainted_vars):
        return None
    checks = (
        (_is_command_sink(statement, state), _COMMAND_FINDING),
        (bool(_PATH_SINK_RE.search(statement)), _PATH_FINDING),
        (bool(_SSRF_SINK_RE.search(statement)), _SSRF_FINDING),
        (_is_sql_sink(statement, state), _SQL_FINDING),
        (bool(_REDIRECT_RE.search(statement)), _REDIRECT_FINDING),
    )
    for matched, spec in checks:
        if matched:
            return spec
    return None


def _is_command_sink(statement: str, state: _ScopeState) -> bool:
    return bool(_COMMAND_SINK_RE.search(statement)) or _tracked_property_sink(
        statement, _COMMAND_PROPERTY_RE, state.process_info_vars
    )


def _is_sql_sink(statement: str, state: _ScopeState) -> bool:
    return bool(_SQL_SINK_RE.search(statement)) or _tracked_property_sink(
        statement, _COMMAND_TEXT_RE, state.sql_command_vars
    )


def _tracked_property_sink(
    statement: str, regex: re.Pattern[str], tracked_names: set[str]
) -> bool:
    match = regex.search(statement)
    return bool(match and match.group("owner").lstrip("@") in tracked_names)


def _is_tainted(expr: str, tainted_vars: set[str]) -> bool:
    if not expr or any(hint in expr for hint in _SANITIZER_HINTS):
        return False
    if any(hint in expr for hint in _SOURCE_HINTS):
        return True
    return any(re.search(rf"\b@?{re.escape(name)}\b", expr) for name in tainted_vars)


def _iter_scopes(source: str) -> list[tuple[str, int, set[str]]]:
    masked = mask_comments_and_strings(source)
    scopes: list[tuple[str, int, set[str]]] = []
    spans: list[tuple[int, int]] = []

    for match in _METHOD_RE.finditer(masked):
        open_brace = masked.find("{", match.end() - 1)
        if open_brace == -1:
            continue
        close_brace = matching_brace(masked, open_brace)
        if close_brace == -1:
            continue
        scopes.append(_method_scope(source, open_brace, close_brace, match.group("params")))
        spans.append((open_brace, close_brace + 1))

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
    for start, end in spans:
        pieces.append(source[cursor:start])
        pieces.append(_blank_non_newlines(source[start:end]))
        cursor = end
    pieces.append(source[cursor:])
    return "".join(pieces)


def _blank_non_newlines(text: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in text)


def _tainted_params(params: str) -> set[str]:
    tainted: set[str] = set()
    for raw in params.split(","):
        cleaned = re.sub(r"\[[^\]]+\]", " ", raw).strip()
        match = _PARAM_RE.search(cleaned)
        if match and _TAINT_NAME_RE.search(match.group("name")):
            tainted.add(match.group("name"))
    return tainted


def _iter_statements(body: str):
    masked = mask_comments_and_strings(body)
    start = 0
    for match in re.finditer(r";", masked):
        end = match.end()
        if chunk := body[start:end].strip():
            yield start, chunk
        start = end
    if tail := body[start:].strip():
        yield start, tail


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
