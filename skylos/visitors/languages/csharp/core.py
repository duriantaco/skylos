from __future__ import annotations

import re
from dataclasses import dataclass, field

from skylos.visitors.base import Definition
from skylos.visitors.languages.csharp._lex import mask_comments_and_strings, matching_brace

_TYPE_RE = re.compile(
    r"(?m)^\s*(?P<mods>(?:(?:public|private|protected|internal|static|sealed|abstract|partial|readonly|unsafe)\s+)*)"
    r"(?P<kind>class|interface|struct|enum|record)\s+"
    r"(?P<name>[A-Za-z_]\w*)"
)
_METHOD_RE = re.compile(
    r"(?m)^\s*(?:\[[^\]\n]+\]\s*)*"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|abstract|extern|partial|unsafe|new)\s+)*)"
    r"(?P<rtype>[A-Za-z_][\w.<>\[\],?]*\s+)+"
    r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*"
    r"(?:where\s+[^{=>]+)?(?:\{|=>)"
)
_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
_NEW_TYPE_RE = re.compile(r"\bnew\s+(?P<name>[A-Za-z_][\w.]*)\s*[({]")

_CLASS_KIND = "class"
_KIND_MAP = dict.fromkeys(("class", "interface", "struct", "record", "enum"), _CLASS_KIND)
_NON_CALL_KEYWORDS = {
    "catch",
    "for",
    "foreach",
    "if",
    "lock",
    "return",
    "switch",
    "using",
    "while",
}
_LIFECYCLE_METHODS = {
    "Configure",
    "ConfigureServices",
    "Dispose",
    "Equals",
    "GetHashCode",
    "Main",
    "OnActionExecuted",
    "OnActionExecuting",
    "OnAuthorization",
    "OnDelete",
    "OnException",
    "OnGet",
    "OnPost",
    "OnPut",
    "Run",
    "StartAsync",
    "StopAsync",
    "ToString",
}


@dataclass
class _RefState:
    file_path: str
    refs: list[tuple[str, str]] = field(default_factory=list)
    seen: set[tuple[str, int]] = field(default_factory=set)


def scan_symbols(
    file_path: str, source: str
) -> tuple[list[Definition], list[tuple[str, str]], list[dict]]:
    masked = mask_comments_and_strings(source)
    type_ranges = _type_ranges(masked)
    defs = _type_defs(file_path, source, masked)
    methods, method_decl_offsets = _method_defs(file_path, source, masked, type_ranges)
    return defs + methods, _refs(file_path, masked, type_ranges, method_decl_offsets), []


def _type_defs(file_path: str, source: str, masked: str) -> list[Definition]:
    defs: list[Definition] = []
    for match in _TYPE_RE.finditer(masked):
        name = match.group("name")
        line = _line_for_offset(source, match.start("name"))
        definition = Definition(
            name, _KIND_MAP.get(match.group("kind"), _CLASS_KIND), file_path, line
        )
        definition.is_exported = _is_exported(match.group("mods"))
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs


def _method_defs(
    file_path: str,
    source: str,
    masked: str,
    type_ranges: list[tuple[int, int, str]],
) -> tuple[list[Definition], set[int]]:
    defs: list[Definition] = []
    method_decl_offsets: set[int] = set()
    for match in _METHOD_RE.finditer(masked):
        name = match.group("name")
        if name in _NON_CALL_KEYWORDS:
            continue
        method_decl_offsets.add(match.start("name"))
        line = _line_for_offset(source, match.start("name"))
        owner = _containing_type(type_ranges, match.start())
        definition = Definition(
            f"{owner}.{name}" if owner else name, "method", file_path, line
        )
        definition.is_exported = _is_exported(match.group("mods")) or name in _LIFECYCLE_METHODS
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs, method_decl_offsets


def _refs(
    file_path: str,
    masked: str,
    type_ranges: list[tuple[int, int, str]],
    method_decl_offsets: set[int],
) -> list[tuple[str, str]]:
    state = _RefState(file_path=file_path)
    type_names = {item[2] for item in type_ranges}
    _collect_call_refs(masked, method_decl_offsets, type_names, state)
    _collect_new_refs(masked, type_names, state)
    return state.refs


def _collect_call_refs(
    masked: str,
    method_decl_offsets: set[int],
    type_names: set[str],
    state: _RefState,
) -> None:
    for match in _CALL_RE.finditer(masked):
        name = match.group("name")
        if _skip_call_ref(name, match.start("name"), method_decl_offsets, type_names):
            continue
        _append_ref(name, match.start("name"), state)


def _collect_new_refs(
    masked: str,
    type_names: set[str],
    state: _RefState,
) -> None:
    for match in _NEW_TYPE_RE.finditer(masked):
        name = match.group("name").split(".")[-1]
        if name not in type_names:
            _append_ref(name, match.start("name"), state)


def _skip_call_ref(
    name: str,
    offset: int,
    method_decl_offsets: set[int],
    type_names: set[str],
) -> bool:
    return (
        offset in method_decl_offsets
        or name in _NON_CALL_KEYWORDS
        or name in type_names
    )


def _append_ref(
    name: str,
    offset: int,
    state: _RefState,
) -> None:
    key = (name, offset)
    if key not in state.seen:
        state.seen.add(key)
        state.refs.append((name, state.file_path))


def _type_ranges(masked: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for match in _TYPE_RE.finditer(masked):
        open_brace = masked.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = matching_brace(masked, open_brace)
        if close_brace != -1:
            ranges.append((open_brace, close_brace, match.group("name")))
    return ranges


def _containing_type(ranges: list[tuple[int, int, str]], offset: int) -> str | None:
    candidates = [
        (start, end, name) for start, end, name in ranges if start <= offset <= end
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[2]


def _is_exported(modifiers: str) -> bool:
    return bool(re.search(r"\b(public|protected)\b", modifiers or ""))


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1
