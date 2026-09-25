from __future__ import annotations

import re
from dataclasses import dataclass, field

from skylos.visitors.base import Definition
from skylos.visitors.languages.csharp._lex import (
    mask_comments_and_strings,
    matching_brace,
)

_DECL_START = r"(?m)(?:^|(?<=[;{}]))\s*"
_ATTRIBUTES = r"(?:\[[^\]\n]*\]\s*)*"
_TYPE_RE = re.compile(
    _DECL_START
    + r"(?P<attrs>"
    + _ATTRIBUTES
    + r")"
    + r"(?P<mods>(?:(?:public|private|protected|internal|file|static|"
    r"sealed|abstract|partial|readonly|unsafe)\s+)*)"
    r"(?P<kind>record(?:\s+(?:class|struct))?|(?:ref\s+)?struct|class|interface|enum)\s+"
    r"(?P<name>[A-Za-z_]\w*)"
)
_METHOD_RE = re.compile(
    _DECL_START
    + r"(?P<attrs>"
    + _ATTRIBUTES
    + r")"
    + r"(?P<mods>(?:(?:public|private|protected|internal|static|async|virtual|"
    r"override|sealed|abstract|extern|partial|readonly|unsafe|new)\s+)*)"
    r"(?P<rtype>[A-Za-z_][\w.<>\[\],?]*\s+)+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<generic><[^;{}()]+>)?\s*"
    r"\((?P<params>[^;{}]*)\)\s*"
    r"(?:where\s+[^{=>]+)?(?:\{|=>)"
)
_FIELD_RE = re.compile(
    _DECL_START
    + r"(?P<attrs>"
    + _ATTRIBUTES
    + r")"
    + r"(?P<mods>(?:(?:public|private|protected|internal|static|readonly|"
    r"volatile|const|unsafe|new)\s+)*)"
    r"(?P<type>[A-Za-z_][\w.<>\[\],?]*)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?=[;,]|=(?!>))"
)
_PROPERTY_RE = re.compile(
    _DECL_START
    + _ATTRIBUTES
    + r"(?:(?:public|private|protected|internal|static|virtual|override|"
    r"abstract|sealed|new|required|readonly)\s+)*"
    r"(?P<type>[A-Za-z_][\w.<>\[\],?]*)\s+"
    r"[A-Za-z_]\w*\s*(?:\{|=>)"
)
_CONSTRUCTOR_RE = re.compile(
    _DECL_START
    + _ATTRIBUTES
    + r"(?:(?:public|private|protected|internal|static|extern|unsafe)\s+)*"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*"
    r"(?:\:[^{;]+)?\{"
)
_CALL_RE = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?:<[^;{}()]+>)?\s*\("
)
_NEW_TYPE_RE = re.compile(r"\bnew\s+(?P<name>[A-Za-z_][\w.]*)(?:<[^;{}()]+>)?\s*[({]")
_TYPE_BODY_START_RE = re.compile(r"[;{]")
_NAMESPACE_RE = re.compile(
    _DECL_START
    + r"namespace\s+(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?P<end>[;{])"
)
_TYPE_TOKEN_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_GENERIC_ARGS_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*<(?P<args>[^<>;{}]+)>"
)
_TypeRange = tuple[int, int, str, bool]
_NamespaceRange = tuple[int, int, str]

_CLASS_KIND = "class"
_KIND_MAP = dict.fromkeys(
    ("class", "interface", "struct", "record", "enum"), _CLASS_KIND
)
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
_NON_TYPE_STATEMENT_WORDS = {
    "await",
    "break",
    "case",
    "continue",
    "default",
    "goto",
    "return",
    "throw",
    "yield",
}


class CSharpDefinition(Definition):
    __slots__ = (
        "csharp_signature",
        "csharp_arity",
        "csharp_min_arity",
        "csharp_max_arity",
        "csharp_modifiers",
        "csharp_has_attributes",
        "csharp_type_kind",
        "csharp_base_types",
        "csharp_interface_methods",
        "csharp_is_extension",
    )

    def __init__(self, name: str, kind: str, file_path: str, line: int) -> None:
        super().__init__(name, kind, file_path, line)
        self.csharp_signature: str | None = None
        self.csharp_arity: int | None = None
        self.csharp_min_arity: int | None = None
        self.csharp_max_arity: int | None = None
        self.csharp_modifiers: frozenset[str] = frozenset()
        self.csharp_has_attributes = False
        self.csharp_type_kind: str | None = None
        self.csharp_base_types: tuple[str, ...] = ()
        self.csharp_interface_methods: frozenset[str] = frozenset()
        self.csharp_is_extension = False


@dataclass
class _RefState:
    file_path: str
    refs: list[tuple[str, str]] = field(default_factory=list)
    seen: set[tuple[str, int]] = field(default_factory=set)


def scan_symbols(
    file_path: str, source: str
) -> tuple[list[Definition], list[tuple[str, str]], list[dict]]:
    masked = mask_comments_and_strings(source)
    namespace_ranges = _namespace_ranges(masked)
    type_ranges = _type_ranges(masked, namespace_ranges)
    defs = _type_defs(file_path, source, masked, type_ranges, namespace_ranges)
    methods, method_decl_offsets = _method_defs(file_path, source, masked, type_ranges)
    fields = _field_defs(file_path, source, masked, type_ranges)
    refs = _refs(file_path, masked, type_ranges, namespace_ranges, method_decl_offsets)
    return defs + methods + fields, refs, []


def _type_defs(
    file_path: str,
    source: str,
    masked: str,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
) -> list[Definition]:
    defs: list[Definition] = []
    for match in _TYPE_RE.finditer(masked):
        name = _qualified_type_name(match, type_ranges, namespace_ranges)
        line = _line_for_offset(source, match.start("name"))
        definition = CSharpDefinition(
            name, _KIND_MAP.get(match.group("kind"), _CLASS_KIND), file_path, line
        )
        definition.csharp_modifiers = frozenset(match.group("mods").split())
        definition.csharp_has_attributes = bool(match.group("attrs").strip())
        definition.csharp_type_kind = match.group("kind").split()[0]
        definition.csharp_base_types = _base_type_names(masked, match)
        if definition.csharp_type_kind == "interface":
            definition.csharp_interface_methods = _interface_method_names(masked, match)
        definition.is_exported = _is_exported(match.group("mods"))
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs


def _method_defs(
    file_path: str,
    source: str,
    masked: str,
    type_ranges: list[_TypeRange],
) -> tuple[list[Definition], set[int]]:
    defs: list[Definition] = []
    method_decl_offsets: set[int] = set()
    for match in _METHOD_RE.finditer(masked):
        name = match.group("name")
        if name in _NON_CALL_KEYWORDS:
            continue
        owner_range = _containing_type_range(type_ranges, match.start())
        if owner_range and not _is_direct_member(masked, owner_range, match.start()):
            continue
        method_decl_offsets.add(match.start("name"))
        line = _line_for_offset(source, match.start("name"))
        owner = owner_range[2] if owner_range else None
        definition = CSharpDefinition(
            f"{owner}.{name}" if owner else name, "method", file_path, line
        )
        definition.csharp_modifiers = frozenset(match.group("mods").split())
        definition.csharp_has_attributes = bool(match.group("attrs").strip())
        definition.csharp_is_extension = bool(
            re.match(r"\s*(?:\[[^\]]*\]\s*)*this\s+", match.group("params"))
        )
        definition.csharp_signature = _parameter_signature(match.group("params"))
        definition.csharp_arity = _parameter_arity(match.group("params"))
        (
            definition.csharp_min_arity,
            definition.csharp_max_arity,
        ) = _parameter_arity_range(match.group("params"))
        definition.is_exported = _is_exported(match.group("mods")) or (
            name == "Main" and "static" in match.group("mods").split()
        )
        if definition.is_exported:
            definition.references = 1
        defs.append(definition)
    return defs, method_decl_offsets


def _field_defs(
    file_path: str,
    source: str,
    masked: str,
    type_ranges: list[_TypeRange],
) -> list[Definition]:
    defs: list[Definition] = []
    for match in _FIELD_RE.finditer(masked):
        owner_range = _containing_type_range(type_ranges, match.start())
        if (
            owner_range is None
            or owner_range[3]
            or match.group("attrs").strip()
            or not _is_direct_member(masked, owner_range, match.start())
        ):
            continue
        for name, offset in _field_declarators(masked, match):
            definition = CSharpDefinition(
                f"{owner_range[2]}.{name}",
                "variable",
                file_path,
                _line_for_offset(source, offset),
            )
            definition.is_exported = bool(
                re.search(r"\b(public|protected|internal)\b", match.group("mods"))
            )
            if definition.is_exported or _has_field_use(
                masked, owner_range, name, offset
            ):
                definition.references = 1
            defs.append(definition)
    return defs


def _has_field_use(
    masked: str,
    owner_range: _TypeRange,
    name: str,
    declaration_offset: int,
) -> bool:
    body_start = owner_range[0] + 1
    body = masked[body_start : owner_range[1]]
    parameter_shadows = _parameter_shadow_ranges(masked, owner_range, name)
    local_shadows = _local_shadow_ranges(masked, owner_range, name)
    for match in re.finditer(rf"\b{re.escape(name)}\b", body, re.ASCII):
        offset = body_start + match.start()
        if offset == declaration_offset:
            continue
        if any(
            parameter_start <= offset < parameter_end
            or (
                method_start <= offset < method_end
                and not _is_qualified_field_access(masked, offset)
            )
            for parameter_start, parameter_end, method_start, method_end in parameter_shadows
        ):
            continue
        if not _is_qualified_field_access(masked, offset) and any(
            start <= offset < end for start, end in local_shadows
        ):
            continue
        return True
    return False


def _is_qualified_field_access(masked: str, offset: int) -> bool:
    before = offset - 1
    while before >= 0 and masked[before].isspace():
        before -= 1
    return before >= 0 and masked[before] == "."


def _parameter_shadow_ranges(
    masked: str, owner_range: _TypeRange, name: str
) -> list[tuple[int, int, int, int]]:
    ranges: list[tuple[int, int, int, int]] = []
    for match in _METHOD_RE.finditer(masked, owner_range[0] + 1, owner_range[1]):
        if not _is_direct_member(masked, owner_range, match.start()):
            continue
        if name not in _parameter_names(match.group("params")):
            continue
        parameter_start, parameter_end = match.span("params")
        body_start = match.end() - 1
        if masked[body_start] == "{":
            body_end = matching_brace(masked, body_start)
        else:
            body_end = _declaration_semicolon(masked, body_start)
        if body_end is not None and body_end != -1:
            ranges.append((parameter_start, parameter_end, body_start, body_end))
    return ranges


def _local_shadow_ranges(
    masked: str, owner_range: _TypeRange, name: str
) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for method in _METHOD_RE.finditer(masked, owner_range[0] + 1, owner_range[1]):
        if not _is_direct_member(masked, owner_range, method.start()):
            continue
        body_open = method.end() - 1
        if masked[body_open] != "{":
            continue
        body_end = matching_brace(masked, body_open)
        if body_end == -1:
            continue
        for declaration in _FIELD_RE.finditer(masked, body_open + 1, body_end):
            if declaration.group("type") in _NON_TYPE_STATEMENT_WORDS:
                continue
            for local_name, offset in _field_declarators(masked, declaration):
                if local_name != name:
                    continue
                scope_end = _containing_block_end(masked, body_open, offset)
                if scope_end is not None:
                    ranges.append((offset, scope_end))
    return ranges


def _containing_block_end(masked: str, method_open: int, offset: int) -> int | None:
    stack = [method_open]
    for index in range(method_open + 1, offset):
        if masked[index] == "{":
            stack.append(index)
        elif masked[index] == "}" and stack:
            stack.pop()
    if not stack:
        return None
    close = matching_brace(masked, stack[-1])
    return close if close != -1 else None


def _parameter_names(params: str) -> set[str]:
    names: set[str] = set()
    for part, _ in _split_top_level(params, angle_brackets=True):
        declaration = part.split("=", 1)[0].strip()
        if declaration:
            match = re.search(r"(?P<name>[A-Za-z_]\w*)\s*$", declaration)
            if match:
                names.add(match.group("name"))
    return names


def _field_declarators(masked: str, match: re.Match[str]) -> list[tuple[str, int]]:
    start = match.start("name")
    end = _declaration_semicolon(masked, start)
    if end is None:
        return [(match.group("name"), start)]

    declarators: list[tuple[str, int]] = []
    for part, offset in _split_top_level(masked[start:end], start):
        identifier = re.match(r"\s*(?P<name>[A-Za-z_]\w*)\s*(?:=|$)", part)
        if identifier:
            declarators.append(
                (identifier.group("name"), offset + identifier.start("name"))
            )
    return declarators


def _declaration_semicolon(masked: str, start: int) -> int | None:
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    for offset in range(start, len(masked)):
        char = masked[offset]
        if char in depths:
            depths[char] += 1
        elif char in closing:
            opener = closing[char]
            if depths[opener] == 0:
                return None
            depths[opener] -= 1
        elif char == ";" and all(depth == 0 for depth in depths.values()):
            return offset
    return None


def _split_top_level(
    value: str, start: int = 0, *, angle_brackets: bool = False
) -> list[tuple[str, int]]:
    parts: list[tuple[str, int]] = []
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    closing = {")": "(", "]": "[", "}": "{", ">": "<"}
    part_start = 0
    for index, char in enumerate(value):
        if char == "<" and not angle_brackets:
            continue
        if char == ">" and not angle_brackets:
            continue
        if char in depths:
            depths[char] += 1
        elif char in closing:
            depths[closing[char]] = max(0, depths[closing[char]] - 1)
        elif char == "," and all(depth == 0 for depth in depths.values()):
            parts.append((value[part_start:index], start + part_start))
            part_start = index + 1
    parts.append((value[part_start:], start + part_start))
    return parts


def _parameter_signature(params: str) -> str:
    return ",".join(
        " ".join(part.split())
        for part, _ in _split_top_level(params, angle_brackets=True)
    )


def _parameter_arity(params: str) -> int:
    if not params.strip():
        return 0
    return len(_split_top_level(params, angle_brackets=True))


def _parameter_arity_range(params: str) -> tuple[int, int | None]:
    if not params.strip():
        return 0, 0
    parts = [part.strip() for part, _ in _split_top_level(params, angle_brackets=True)]
    required = 0
    variadic = False
    for part in parts:
        if re.match(r"(?:\[[^\]]*\]\s*)*params\s+", part):
            variadic = True
        elif "=" not in part:
            required += 1
    return required, None if variadic else len(parts)


def _argument_arity(args: str) -> int:
    if not args.strip():
        return 0
    return len(_split_top_level(args))


def _refs(
    file_path: str,
    masked: str,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
    method_decl_offsets: set[int],
) -> list[tuple[str, str]]:
    state = _RefState(file_path=file_path)
    type_names = {item[2].split(".")[-1] for item in type_ranges}
    _collect_call_refs(
        masked,
        type_ranges,
        namespace_ranges,
        method_decl_offsets,
        type_names,
        state,
    )
    _collect_new_refs(masked, namespace_ranges, state)
    _collect_type_refs(masked, type_ranges, namespace_ranges, state)
    return state.refs


def _collect_call_refs(
    masked: str,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
    method_decl_offsets: set[int],
    type_names: set[str],
    state: _RefState,
) -> None:
    for match in _CALL_RE.finditer(masked):
        name = match.group("name")
        leaf = name.rsplit(".", 1)[-1]
        if _skip_call_ref(leaf, match.start("name"), method_decl_offsets, type_names):
            continue
        owner = _containing_type_range(type_ranges, match.start())
        if "." not in name and owner:
            name = f"{owner[2]}.{name}"
        elif name.startswith("this.") and owner:
            name = f"{owner[2]}.{name[5:]}"
        elif "." in name:
            qualifier = name.split(".", 1)[0]
            if name.count(".") == 1:
                if qualifier in type_names or qualifier[:1].isupper():
                    namespace = _namespace_at(namespace_ranges, match.start())
                    if namespace:
                        name = f"{namespace}.{name}"
                else:
                    name = leaf
        else:
            namespace = _namespace_at(namespace_ranges, match.start())
            if namespace:
                name = f"{namespace}.{name}"
        close_paren = _matching_paren(masked, match.end() - 1)
        if close_paren is not None:
            params = masked[match.end() : close_paren]
            name = f"{name}#{_argument_arity(params)}"
        _append_ref(name, match.start("name"), state)


def _collect_new_refs(
    masked: str,
    namespace_ranges: list[_NamespaceRange],
    state: _RefState,
) -> None:
    for match in _NEW_TYPE_RE.finditer(masked):
        name = match.group("name")
        namespace = _namespace_at(namespace_ranges, match.start())
        if namespace and "." not in name:
            name = f"{namespace}.{name}"
        _append_ref(name, match.start("name"), state)


def _collect_type_refs(
    masked: str,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
    state: _RefState,
) -> None:
    for match in _METHOD_RE.finditer(masked):
        _append_type_tokens(
            match.group("rtype"),
            match.start("rtype"),
            type_ranges,
            namespace_ranges,
            state,
        )
        _append_parameter_type_refs(
            match.group("params"),
            match.start("params"),
            type_ranges,
            namespace_ranges,
            state,
        )

    for match in _CONSTRUCTOR_RE.finditer(masked):
        owner = _containing_type_range(type_ranges, match.start())
        if owner is None or match.group("name") != owner[2].rsplit(".", 1)[-1]:
            continue
        _append_parameter_type_refs(
            match.group("params"),
            match.start("params"),
            type_ranges,
            namespace_ranges,
            state,
        )

    for match in _FIELD_RE.finditer(masked):
        _append_type_tokens(
            match.group("type"),
            match.start("type"),
            type_ranges,
            namespace_ranges,
            state,
        )
    for match in _PROPERTY_RE.finditer(masked):
        _append_type_tokens(
            match.group("type"),
            match.start("type"),
            type_ranges,
            namespace_ranges,
            state,
        )

    for match in _TYPE_RE.finditer(masked):
        terminator = _TYPE_BODY_START_RE.search(masked, match.end())
        if terminator is None:
            continue
        trailer = masked[match.end() : terminator.start()]
        if trailer.startswith("("):
            close = _matching_paren(trailer, 0)
            if close is not None:
                _append_parameter_type_refs(
                    trailer[1:close],
                    match.end() + 1,
                    type_ranges,
                    namespace_ranges,
                    state,
                )
        base_list = trailer.split("where", 1)[0]
        if ":" in base_list:
            start = base_list.index(":") + 1
            _append_type_tokens(
                base_list[start:],
                match.end() + start,
                type_ranges,
                namespace_ranges,
                state,
            )

    for match in _GENERIC_ARGS_RE.finditer(masked):
        _append_type_tokens(
            match.group("args"),
            match.start("args"),
            type_ranges,
            namespace_ranges,
            state,
        )


def _append_parameter_type_refs(
    params: str,
    start: int,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
    state: _RefState,
) -> None:
    for part, offset in _split_top_level(params, start, angle_brackets=True):
        declaration = part.split("=", 1)[0]
        name = re.search(r"[A-Za-z_]\w*\s*$", declaration)
        if name is None:
            continue
        _append_type_tokens(
            declaration[: name.start()],
            offset,
            type_ranges,
            namespace_ranges,
            state,
        )


def _append_type_tokens(
    expression: str,
    start: int,
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
    state: _RefState,
) -> None:
    for match in _TYPE_TOKEN_RE.finditer(expression):
        name = match.group()
        offset = start + match.start()
        owner = _containing_type_range(type_ranges, offset)
        namespace = _namespace_at(namespace_ranges, offset)
        qualified = f"{namespace}.{name}" if namespace and "." not in name else name
        if owner is not None and (
            qualified == owner[2] or name == owner[2].rsplit(".", 1)[-1]
        ):
            continue
        _append_ref(f"@type:{qualified}", offset, state)


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


def _matching_paren(masked: str, open_paren: int) -> int | None:
    if open_paren >= len(masked) or masked[open_paren] != "(":
        return None
    depth = 0
    for offset in range(open_paren, len(masked)):
        if masked[offset] == "(":
            depth += 1
        elif masked[offset] == ")":
            depth -= 1
            if depth == 0:
                return offset
    return None


def _namespace_ranges(masked: str) -> list[_NamespaceRange]:
    ranges: list[_NamespaceRange] = []
    for match in _NAMESPACE_RE.finditer(masked):
        start = match.end()
        if match.group("end") == ";":
            ranges.append((start, len(masked), match.group("name")))
            continue
        close_brace = matching_brace(masked, match.end() - 1)
        if close_brace != -1:
            ranges.append((start, close_brace, match.group("name")))
    return ranges


def _namespace_at(ranges: list[_NamespaceRange], offset: int) -> str:
    active = [item for item in ranges if item[0] <= offset < item[1]]
    active.sort(key=lambda item: item[0])
    return ".".join(item[2] for item in active)


def _qualified_type_name(
    match: re.Match[str],
    type_ranges: list[_TypeRange],
    namespace_ranges: list[_NamespaceRange],
) -> str:
    parent = _containing_type_range(type_ranges, match.start())
    prefix = parent[2] if parent else _namespace_at(namespace_ranges, match.start())
    return f"{prefix}.{match.group('name')}" if prefix else match.group("name")


def _base_type_names(masked: str, match: re.Match[str]) -> tuple[str, ...]:
    terminator = _TYPE_BODY_START_RE.search(masked, match.end())
    if terminator is None:
        return ()
    trailer = masked[match.end() : terminator.start()].split("where", 1)[0]
    if ":" not in trailer:
        return ()
    return tuple(
        token.group() for token in _TYPE_TOKEN_RE.finditer(trailer.split(":", 1)[1])
    )


def _interface_method_names(masked: str, match: re.Match[str]) -> frozenset[str]:
    terminator = _TYPE_BODY_START_RE.search(masked, match.end())
    if terminator is None or terminator.group() != "{":
        return frozenset()
    close_brace = matching_brace(masked, terminator.start())
    if close_brace == -1:
        return frozenset()
    names: set[str] = set()
    body = (terminator.start(), close_brace, "", False)
    for call in _CALL_RE.finditer(masked, terminator.end(), close_brace):
        if not _is_direct_member(masked, body, call.start()):
            continue
        close_paren = _matching_paren(masked, call.end() - 1)
        if close_paren is None:
            continue
        following = masked[close_paren + 1 : close_brace].lstrip()
        if following.startswith((";", "{", "=>")):
            names.add(call.group("name").rsplit(".", 1)[-1])
    return frozenset(names)


def _type_ranges(
    masked: str, namespace_ranges: list[_NamespaceRange]
) -> list[_TypeRange]:
    ranges: list[_TypeRange] = []
    for match in _TYPE_RE.finditer(masked):
        terminator = _TYPE_BODY_START_RE.search(masked, match.end())
        if terminator is None or terminator.group() != "{":
            continue
        open_brace = terminator.start()
        close_brace = matching_brace(masked, open_brace)
        if close_brace != -1:
            ranges.append(
                (
                    open_brace,
                    close_brace,
                    _qualified_type_name(match, ranges, namespace_ranges),
                    "partial" in match.group("mods").split(),
                )
            )
    return ranges


def _containing_type_range(ranges: list[_TypeRange], offset: int) -> _TypeRange | None:
    candidates = [item for item in ranges if item[0] <= offset <= item[1]]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])


def _is_direct_member(masked: str, owner_range: _TypeRange, offset: int) -> bool:
    body_start = owner_range[0] + 1
    return masked.count("{", body_start, offset) == masked.count(
        "}", body_start, offset
    )


def _is_exported(modifiers: str) -> bool:
    return bool(re.search(r"\b(public|protected)\b", modifiers or ""))


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1
