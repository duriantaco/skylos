from __future__ import annotations

import re
from dataclasses import dataclass, field

from skylos.visitors.base import Definition
from skylos.visitors.languages.java.core import (
    _CLASS_ENTRYPOINT_ANNOTATIONS,
    _METHOD_ENTRYPOINT_ANNOTATIONS,
)
from skylos.visitors.languages.kotlin._lex import KotlinSource, lex
from skylos.visitors.languages.kotlin._lex import matching_brace

_IDENT = r"(?:`[^`\n]+`|[A-Za-z_]\w*)"
_GENERIC = r"<(?:[^<>\n]|<(?:[^<>\n]|<[^<>\n]*>)*>)*>"
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
    rf"(?m)^[ \t]*{_ANNOTATION_PREFIX}"
    rf"(?P<mods>(?:(?:{_MODIFIER})\s+)*)"
    rf"(?P<kind>enum\s+class|class|interface|object)\s+"
    rf"(?P<name>{_IDENT})"
)
_FUNCTION_RE = re.compile(
    rf"(?m)^[ \t]*{_ANNOTATION_PREFIX}"
    rf"(?P<mods>(?:(?:{_MODIFIER})\s+)*)"
    rf"fun\s+(?:{_GENERIC}\s*)?"
    rf"(?:{_IDENT}(?:\s*\.\s*{_IDENT})*(?:{_GENERIC})?\??\s*\.\s*)?"
    rf"(?P<name>{_IDENT})\s*\("
)
_IMPORT_RE = re.compile(
    rf"(?m)^[ \t]*import\s+(?P<path>{_IDENT}(?:\s*\.\s*{_IDENT})*(?:\.\*)?|\*)"
    rf"(?:\s+as\s+(?P<alias>{_IDENT}))?"
)
_DIRECTIVE_RE = re.compile(r"(?m)^[ \t]*(?:package|import)\b[^\n;]*")
_IDENT_TOKEN_RE = re.compile(_IDENT)
_ANNOTATION_RE = re.compile(r"@(?:[A-Za-z_]\w*:)?(?P<name>[A-Za-z_][\w.]*)")
_LOCAL_DECL_RE = re.compile(
    rf"\b(?:val|var|typealias)\s+(?:{_GENERIC}\s*)?"
    rf"(?:{_IDENT}(?:{_GENERIC})?\??\s*\.\s*)?(?P<name>{_IDENT})"
)
_DESTRUCTURING_RE = re.compile(r"\b(?:val|var)\s*\((?P<names>[^()]*)\)")
_TYPED_NAME_RE = re.compile(rf"(?P<name>{_IDENT})[ \t]*:(?!:)")
_LABEL_ARG_RE = re.compile(rf"(?P<name>{_IDENT})\s*=(?![=>])")

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
_SKIPPED_WORDS = frozenset(
    {
        "as",
        "break",
        "class",
        "continue",
        "do",
        "else",
        "false",
        "for",
        "fun",
        "if",
        "import",
        "in",
        "interface",
        "is",
        "null",
        "object",
        "package",
        "return",
        "super",
        "this",
        "throw",
        "true",
        "try",
        "typealias",
        "val",
        "var",
        "when",
        "while",
        "private",
        "public",
        "internal",
        "protected",
        "override",
        "open",
        "abstract",
        "final",
        "sealed",
        "inline",
        "suspend",
        "companion",
        "lateinit",
        "const",
        "operator",
        "infix",
        "tailrec",
        "external",
        "inner",
        "vararg",
        "noinline",
        "crossinline",
        "reified",
    }
)
_ROOT_ANNOTATIONS = frozenset(
    {
        *_METHOD_ENTRYPOINT_ANNOTATIONS,
        "Binds",
        "BindingAdapter",
        "BindsInstance",
        "Composable",
        "Controller",
        "InverseBindingAdapter",
        "JavascriptInterface",
        "JvmStatic",
        "OnLifecycleEvent",
        "Preview",
        "Provides",
        "RestController",
        "Subscribe",
    }
)
_CLASS_ROOT_ANNOTATIONS = frozenset(
    {
        *_CLASS_ENTRYPOINT_ANNOTATIONS,
        "AndroidEntryPoint",
        "HiltViewModel",
        "Module",
        "Serializable",
    }
)
_OPERATOR_IMPORT_NAMES = frozenset(
    {
        "unaryPlus",
        "unaryMinus",
        "not",
        "inc",
        "dec",
        "plus",
        "minus",
        "times",
        "div",
        "rem",
        "mod",
        "rangeTo",
        "rangeUntil",
        "contains",
        "get",
        "set",
        "invoke",
        "assign",
        "plusAssign",
        "minusAssign",
        "timesAssign",
        "divAssign",
        "remAssign",
        "modAssign",
        "equals",
        "compareTo",
        "iterator",
        "getValue",
        "setValue",
        "provideDelegate",
    }
)
_COMPONENT_RE = re.compile(r"component\d+")
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
    file_path: str, source: str, *, lexed: KotlinSource | None = None
) -> tuple[list[Definition], list[tuple[str, str]], list[dict]]:
    if lexed is None:
        lexed = lex(source)
    masked = lexed.code
    type_ranges = _type_ranges(masked)
    type_defs = _type_defs(file_path, lexed)
    function_defs, declaration_offsets = _function_defs(
        file_path,
        lexed,
        type_ranges,
    )
    import_defs, raw_imports = _import_defs(file_path, lexed)
    declaration_offsets.update(_type_declaration_offsets(masked))
    refs = _refs(file_path, lexed, declaration_offsets, type_ranges, import_defs)
    return type_defs + function_defs + import_defs, refs, raw_imports


def _type_defs(file_path: str, lexed: KotlinSource) -> list[Definition]:
    defs: list[Definition] = []
    for match in _TYPE_RE.finditer(lexed.code):
        name = _clean_identifier(match.group("name"))
        line = lexed.line_for(match.start("name"))
        definition = Definition(name, _CLASS_KIND, file_path, line)
        definition.decorators = _decorators(match.group("annotations"))
        definition.is_exported = _is_type_exported(
            match.group("mods"), definition.decorators
        )
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs


def _function_defs(
    file_path: str,
    lexed: KotlinSource,
    type_ranges: list[tuple[int, int, str]],
) -> tuple[list[Definition], set[int]]:
    defs: list[Definition] = []
    declaration_offsets: set[int] = set()
    for match in _FUNCTION_RE.finditer(lexed.code):
        name = _clean_identifier(match.group("name"))
        if name in _NON_CALL_KEYWORDS:
            continue

        declaration_offsets.add(match.start("name"))
        owner = _containing_type(type_ranges, match.start("name"))
        kind = "method" if owner else "function"
        full_name = f"{owner}.{name}" if owner else name
        line = lexed.line_for(match.start("name"))
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
    lexed: KotlinSource,
) -> tuple[list[Definition], list[dict]]:
    defs: list[Definition] = []
    raw_imports: list[dict] = []
    for match in _IMPORT_RE.finditer(lexed.code):
        import_path = re.sub(r"\s*\.\s*", ".", match.group("path"))
        alias = match.group("alias")
        names = _imported_names(import_path, alias)
        line = lexed.line_for(match.start("path"))
        for name in names:
            definition = Definition(name, "import", file_path, line)
            if not alias and _is_operator_import(name):
                definition.references = 1
            defs.append(definition)
        raw_imports.append({"source": import_path, "names": names, "line": line})
    return defs, raw_imports


def _refs(
    file_path: str,
    lexed: KotlinSource,
    declaration_offsets: set[int],
    type_ranges: list[tuple[int, int, str]],
    import_defs: list[Definition],
) -> list[tuple[str, str]]:
    masked = lexed.code
    state = _RefState(file_path=file_path)
    skipped = set(declaration_offsets)
    skipped.update(_local_declaration_offsets(masked))
    skipped.update(_named_argument_offsets(masked))
    directives = [match.span() for match in _DIRECTIVE_RE.finditer(masked)]
    directive_index = 0
    for match in _IDENT_TOKEN_RE.finditer(masked):
        offset = match.start()
        while (
            directive_index < len(directives)
            and directives[directive_index][1] <= offset
        ):
            directive_index += 1
        if (
            directive_index < len(directives)
            and directives[directive_index][0]
            <= offset
            < directives[directive_index][1]
        ):
            continue
        token = match.group(0)
        if token in _SKIPPED_WORDS or offset in skipped:
            continue
        name = _clean_identifier(token)
        _append_ref(name, offset, state)
        if _is_unqualified_call(masked, offset, match.end()):
            owner = _containing_type(type_ranges, offset)
            if owner and owner != name:
                state.refs.append((f"{owner}.{name}", file_path))
    for match in _IMPORT_RE.finditer(masked):
        segments = re.sub(r"\s*\.\s*", ".", match.group("path")).split(".")
        for index, segment in enumerate(segments[:-1]):
            if index and segment[:1].isupper():
                qualified = ".".join(segments[:index] + [_clean_identifier(segment)])
                state.refs.append((qualified, file_path))
    imported = {definition.name for definition in import_defs}
    for kdoc_name in lexed.kdoc_names:
        parts = kdoc_name.split(".")
        for part in {parts[0], parts[-1]}:
            if part in imported:
                state.refs.append((part, file_path))
    return state.refs


def _local_declaration_offsets(masked: str) -> set[int]:
    offsets: set[int] = set()
    for match in _LOCAL_DECL_RE.finditer(masked):
        offsets.add(match.start("name"))
    for match in _DESTRUCTURING_RE.finditer(masked):
        base = match.start("names")
        for name_match in _IDENT_TOKEN_RE.finditer(match.group("names")):
            offsets.add(base + name_match.start())
    for match in _TYPED_NAME_RE.finditer(masked):
        if match.start() > 0 and masked[match.start() - 1] in "@.":
            continue
        offsets.add(match.start("name"))
    return offsets


def _named_argument_offsets(masked: str) -> set[int]:
    offsets: set[int] = set()
    for match in _LABEL_ARG_RE.finditer(masked):
        index = match.start() - 1
        while index >= 0 and masked[index] in " \t\r\n":
            index -= 1
        if index >= 0 and masked[index] in "(,":
            offsets.add(match.start("name"))
    return offsets


def _is_unqualified_call(masked: str, start: int, end: int) -> bool:
    index = start - 1
    while index >= 0 and masked[index] in " \t":
        index -= 1
    if index >= 1 and masked[index - 1 : index + 1] == "::":
        return True
    if index >= 0 and masked[index] in ".?@":
        return False
    following = end
    while following < len(masked) and masked[following] in " \t":
        following += 1
    return following < len(masked) and masked[following] in "({"


def _type_declaration_offsets(masked: str) -> set[int]:
    offsets: set[int] = set()
    for match in _TYPE_RE.finditer(masked):
        offsets.add(match.start("name"))
    return offsets


def _type_ranges(masked: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for match in _TYPE_RE.finditer(masked):
        open_brace = _body_open_brace(masked, match.end())
        if open_brace == -1:
            continue
        close_brace = matching_brace(masked, open_brace)
        if close_brace == -1:
            continue
        ranges.append((open_brace, close_brace, _clean_identifier(match.group("name"))))
    return ranges


def _body_open_brace(masked: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(masked):
        char = masked[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(depth - 1, 0)
        elif char == "{" and depth == 0:
            return index
        elif char == "\n" and depth == 0:
            rest = masked[index + 1 : index + 200].lstrip()
            if not rest.startswith(("{", ":", ",", "where", "(")) and not masked[
                start:index
            ].rstrip().endswith((",", ":", "(")):
                return -1
        index += 1
    return -1


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
    if "operator" in (modifiers or "").split():
        return True
    return _is_visible_outside_file(modifiers)


def _is_type_exported(modifiers: str | None, decorators: list[str]) -> bool:
    decorator_names = {decorator.lstrip("@") for decorator in decorators}
    if decorator_names & _CLASS_ROOT_ANNOTATIONS:
        return True
    if "companion" in (modifiers or "").split():
        return True
    return _is_visible_outside_file(modifiers)


def _is_visible_outside_file(modifiers: str | None) -> bool:
    modifier_set = set((modifiers or "").split())
    return "private" not in modifier_set


def _is_operator_import(name: str) -> bool:
    return name in _OPERATOR_IMPORT_NAMES or bool(_COMPONENT_RE.fullmatch(name))


def _imported_names(import_path: str, alias: str | None) -> list[str]:
    if alias:
        return [_clean_identifier(alias)]
    if import_path.endswith(".*") or import_path == "*":
        return []
    leaf = import_path.rsplit(".", 1)[-1]
    if not leaf:
        return []
    return [_clean_identifier(leaf)]


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
