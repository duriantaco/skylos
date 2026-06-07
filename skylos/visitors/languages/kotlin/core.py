from __future__ import annotations

import re
from dataclasses import dataclass, field

from skylos.visitors.base import Definition
from skylos.visitors.languages.kotlin._lex import mask_comments_and_strings
from skylos.visitors.languages.kotlin._lex import matching_brace

_IDENT = r"(?:`[^`]+`|[A-Za-z_]\w*)"
_ANNOTATION_PREFIX = (
    r"(?P<annotations>"
    r"(?:(?:@[^\n]+\n\s*)|(?:@[A-Za-z_][\w.]*(?:\([^()\n]*\))?\s+))*"
    r")"
)
_MODIFIER = (
    "public|private|protected|internal|data|sealed|open|abstract|final|value|"
    "annotation|inner|companion|override|suspend|inline|tailrec|operator|infix|"
    "external|expect|actual"
)
_TYPE_RE = re.compile(
    rf"(?m)^\s*{_ANNOTATION_PREFIX}"
    rf"(?P<mods>(?:(?:{_MODIFIER})\s+)*)"
    rf"(?P<kind>enum\s+class|class|interface|object)\s+"
    rf"(?P<name>{_IDENT})"
)
_FUNCTION_RE = re.compile(
    rf"(?m)^\s*{_ANNOTATION_PREFIX}"
    rf"(?P<mods>(?:(?:{_MODIFIER})\s+)*)"
    rf"fun\s+(?:<[^>\n]+>\s*)?"
    rf"(?:(?:{_IDENT})(?:<[^>\n]+>)?\s*\.\s*)?"
    rf"(?P<name>{_IDENT})\s*\("
)
_IMPORT_RE = re.compile(
    rf"(?m)^\s*import\s+(?P<path>[A-Za-z_][\w.]*(?:\.\*)?|\*)"
    rf"(?:\s+as\s+(?P<alias>{_IDENT}))?"
)
_CALL_RE = re.compile(rf"\b(?P<name>{_IDENT})\s*\(")
_ANNOTATION_RE = re.compile(r"@(?:[A-Za-z_]\w*:)?(?P<name>[A-Za-z_][\w.]*)")

_CLASS_KIND = "class"
_NON_CALL_KEYWORDS = {
    "catch",
    "constructor",
    "else",
    "for",
    "if",
    "return",
    "super",
    "this",
    "throw",
    "try",
    "when",
    "while",
}
_ROOT_ANNOTATIONS = {
    "Bean",
    "Composable",
    "Controller",
    "GetMapping",
    "PostMapping",
    "RestController",
    "Test",
}
_LIFECYCLE_METHODS = {
    "main",
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onRestart",
    "onCreateView",
    "onViewCreated",
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
    type_defs = _type_defs(file_path, source, masked)
    function_defs, declaration_offsets = _function_defs(
        file_path,
        source,
        masked,
        type_ranges,
    )
    import_defs, raw_imports = _import_defs(file_path, source, masked)
    declaration_offsets.update(_type_declaration_offsets(masked))
    refs = _refs(file_path, masked, declaration_offsets)
    return type_defs + function_defs + import_defs, refs, raw_imports


def _type_defs(file_path: str, source: str, masked: str) -> list[Definition]:
    defs: list[Definition] = []
    for match in _TYPE_RE.finditer(masked):
        name = _clean_identifier(match.group("name"))
        line = _line_for_offset(source, match.start("name"))
        definition = Definition(name, _CLASS_KIND, file_path, line)
        definition.decorators = _decorators(match.group("annotations"))
        definition.is_exported = _is_visible_outside_file(match.group("mods"))
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs


def _function_defs(
    file_path: str,
    source: str,
    masked: str,
    type_ranges: list[tuple[int, int, str]],
) -> tuple[list[Definition], set[int]]:
    defs: list[Definition] = []
    declaration_offsets: set[int] = set()
    for match in _FUNCTION_RE.finditer(masked):
        name = _clean_identifier(match.group("name"))
        if name in _NON_CALL_KEYWORDS:
            continue

        declaration_offsets.add(match.start("name"))
        owner = _containing_type(type_ranges, match.start())
        kind = "method" if owner else "function"
        full_name = f"{owner}.{name}" if owner else name
        line = _line_for_offset(source, match.start("name"))
        definition = Definition(full_name, kind, file_path, line)
        definition.decorators = _decorators(match.group("annotations"))
        definition.is_exported = _is_function_exported(
            name,
            match.group("mods"),
            definition.decorators,
        )
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs, declaration_offsets


def _import_defs(
    file_path: str,
    source: str,
    masked: str,
) -> tuple[list[Definition], list[dict]]:
    defs: list[Definition] = []
    raw_imports: list[dict] = []
    for match in _IMPORT_RE.finditer(masked):
        import_path = match.group("path")
        alias = match.group("alias")
        names = _imported_names(import_path, alias)
        line = _line_for_offset(source, match.start())
        for name in names:
            defs.append(Definition(name, "import", file_path, line))
        raw_imports.append({"source": import_path, "names": names, "line": line})
    return defs, raw_imports


def _refs(
    file_path: str,
    masked: str,
    declaration_offsets: set[int],
) -> list[tuple[str, str]]:
    state = _RefState(file_path=file_path)
    for match in _CALL_RE.finditer(masked):
        name = _clean_identifier(match.group("name"))
        if _skip_call_ref(name, match.start("name"), declaration_offsets):
            continue
        _append_ref(name, match.start("name"), state)
    for match in _ANNOTATION_RE.finditer(masked):
        name = match.group("name").split(".")[-1]
        _append_ref(name, match.start("name"), state)
    return state.refs


def _type_declaration_offsets(masked: str) -> set[int]:
    offsets: set[int] = set()
    for match in _TYPE_RE.finditer(masked):
        offsets.add(match.start("name"))
    return offsets


def _type_ranges(masked: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for match in _TYPE_RE.finditer(masked):
        open_brace = masked.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = matching_brace(masked, open_brace)
        if close_brace == -1:
            continue
        ranges.append((open_brace, close_brace, _clean_identifier(match.group("name"))))
    return ranges


def _containing_type(ranges: list[tuple[int, int, str]], offset: int) -> str | None:
    candidates = []
    for start, end, name in ranges:
        if start <= offset <= end:
            candidates.append((start, end, name))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[2]


def _decorators(annotation_text: str | None) -> list[str]:
    if not annotation_text:
        return []
    names: list[str] = []
    for match in _ANNOTATION_RE.finditer(annotation_text):
        names.append("@" + match.group("name").split(".")[-1])
    return names


def _is_function_exported(
    name: str,
    modifiers: str | None,
    decorators: list[str],
) -> bool:
    decorator_names = {decorator.lstrip("@") for decorator in decorators}
    if decorator_names & _ROOT_ANNOTATIONS:
        return True
    if "Override" in decorator_names:
        return True
    if name in _LIFECYCLE_METHODS:
        return True
    return _is_visible_outside_file(modifiers)


def _is_visible_outside_file(modifiers: str | None) -> bool:
    modifier_set = set((modifiers or "").split())
    return "private" not in modifier_set


def _imported_names(import_path: str, alias: str | None) -> list[str]:
    if alias:
        return [_clean_identifier(alias)]
    if import_path.endswith(".*") or import_path == "*":
        return []
    leaf = import_path.rsplit(".", 1)[-1]
    if not leaf:
        return []
    return [_clean_identifier(leaf)]


def _skip_call_ref(
    name: str,
    offset: int,
    declaration_offsets: set[int],
) -> bool:
    return offset in declaration_offsets or name in _NON_CALL_KEYWORDS


def _append_ref(
    name: str,
    offset: int,
    state: _RefState,
) -> None:
    if not name:
        return
    key = (name, offset)
    if key in state.seen:
        return
    state.seen.add(key)
    state.refs.append((name, state.file_path))


def _clean_identifier(name: str) -> str:
    cleaned = name.strip()
    if cleaned.startswith("`") and cleaned.endswith("`"):
        return cleaned[1:-1]
    return cleaned


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1
