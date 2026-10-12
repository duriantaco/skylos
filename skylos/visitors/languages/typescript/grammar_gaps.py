"""Position-preserving repairs for valid syntax tree-sitter cannot parse.

tree-sitter-typescript 0.23.2, the newest release, rejects valid TypeScript
and JavaScript that popular projects use:

* variance annotations on type parameters (TypeScript 4.7):
  ``interface Box<in out T>``, ``type Fn<in T> = ...``;
* a member of an interface or object type that starts a new line after a
  member without a separator, beginning with ``<`` (a generic call signature)
  or named ``in``. TypeScript never continues a type across that line break;
  the grammar does;
* ``export type * from "./types"`` (TypeScript 5.0);
* escape sequences such as ``\\n`` inside template literal types;
* ``using`` as an ordinary identifier (``function f(using) {}``);
* a raw ``&`` in a quoted JSX attribute value (``href="/?a=1&b=2"``).

Each one leaves an error in the syntax tree, which Skylos reports as
SKY-ANALYSIS-INCOMPLETE and which fails a full-repo gate; error recovery
often wraps the rest of the file in it. Only when the first parse has
errors, this module rewrites the offending bytes in a scratch copy of the
source and parses again:

* ``in``/``out`` modifiers, the ``type`` of ``export type *`` and template
  literal type escapes become spaces (line breaks are kept);
* one indentation byte before such a member becomes a ``;`` separator;
* the keyword-lexed identifier ``using`` becomes the identifier ``usin_``;
* the ``&`` in a JSX attribute value becomes ``x``.

Every byte offset and line number stays the same, and the TypeScript
analysis reads names and text from the original source by byte offset, so
the scratch bytes never reach a finding. A repaired tree is
used only when every rewrite lands where intended (checked on the reparsed
tree) and the repaired tree has fewer error nodes. Syntax errors without a
matching repair stay in the tree and are still reported. JavaScript files only
get the ``using`` and JSX repairs; the others are TypeScript-only syntax.
"""

from __future__ import annotations

import re
from typing import NamedTuple

_TYPESCRIPT_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")
_MAX_REPAIR_ROUNDS = 16

_IDENTIFIER_RE = re.compile(rb"[A-Za-z_$\x80-\xff][\w$\x80-\xff]*")
_IDENTIFIER_NODE_TYPES = frozenset(
    {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "statement_identifier",
        "type_identifier",
    }
)

_VARIANCE_MODIFIERS = frozenset({b"in", b"out"})
_TYPE_PARAMETER_LIST_OPENERS = frozenset({b"<", b","})
_TYPE_PARAMETER_FOLLOWERS = frozenset({b",", b">", b"=", b"extends"})
_TYPE_PARAMETER_NAME_EXCLUDED = frozenset(
    {b"in", b"out", b"const", b"extends", b"keyof", b"typeof", b"infer"}
)
# Declarations whose type parameters TypeScript accepts variance modifiers on.
_VARIANCE_OWNER_TYPES = frozenset(
    {
        "abstract_class_declaration",
        "class",
        "class_declaration",
        "interface_declaration",
        "type_alias_declaration",
    }
)

# Prefix operators after which a following line still continues the type.
_TYPE_CONTINUATION_KEYWORDS = frozenset(
    {
        b"as",
        b"asserts",
        b"extends",
        b"infer",
        b"is",
        b"keyof",
        b"new",
        b"readonly",
        b"satisfies",
        b"typeof",
        b"unique",
    }
)
_TYPE_END_PUNCTUATION = frozenset({b">", b")", b"]", b"}", b'"', b"'", b"`"})
_MEMBER_LIST_TYPES = frozenset({"interface_body", "object_type"})
# Tokens a template literal type can follow.
_TYPE_OPERAND_PRECEDERS = frozenset(
    {b"=", b"|", b"&", b"<", b",", b"(", b":", b"?", b"[", b"extends"}
)
_NAMED_MEMBER_TYPES = frozenset({"method_signature", "property_signature"})
_NAMED_MEMBER_FOLLOWERS = frozenset({b":", b"?", b"(", b"<"})

# Tokens after ``using`` that make it an identifier, not a declaration keyword.
_USING_DECLARATION_EXCLUDED_NAMES = frozenset(
    {b"as", b"in", b"instanceof", b"of", b"satisfies"}
)
_USING_REPLACEMENT = b"usin_"


class _Token(NamedTuple):
    start: int
    end: int
    text: bytes
    node: object


class _Rewrite(NamedTuple):
    kind: str
    start: int
    replacement: bytes
    # The byte where the repaired construct's anchor node must start.
    anchor: int

    @property
    def end(self) -> int:
        return self.start + len(self.replacement)


def is_typescript_path(file_path: str) -> bool:
    return str(file_path).lower().endswith(_TYPESCRIPT_SUFFIXES)


def repair_typescript_grammar_gaps(
    parser, source: bytes, tree, *, typescript: bool, jsx: bool
):
    """Return a tree for ``source`` with known grammar gaps repaired.

    ``tree`` is the first parse of ``source``. It is returned unchanged when it
    has no errors, or when no repair both lands where intended and removes
    errors.
    """
    if tree is None or not tree.root_node.has_error:
        return tree

    best_tree = tree
    best_errors = _error_node_count(tree.root_node)
    accepted: list[_Rewrite] = []
    for _ in range(_MAX_REPAIR_ROUNDS):
        candidates = _rewrite_candidates(
            tree.root_node, _apply(source, accepted), typescript=typescript, jsx=jsx
        )
        if not candidates:
            break
        trial = _verified_trial(parser, source, accepted, candidates)
        if trial is None:
            break
        # A repair can expose a later gap that error recovery had swallowed,
        # so one round may add error nodes; keep going and take the best tree.
        tree, kept = trial
        accepted.extend(kept)
        errors = _error_node_count(tree.root_node)
        if errors < best_errors:
            best_tree, best_errors = tree, errors
        if not errors:
            break
    return best_tree


def _verified_trial(parser, source, accepted, candidates):
    """Parse with ``candidates`` applied, keeping only those that verify."""
    for _ in range(2):
        trial_tree = parser.parse(_apply(source, accepted + candidates))
        root = trial_tree.root_node
        if not all(_rewrite_holds(root, rewrite) for rewrite in accepted):
            return None
        kept = [rewrite for rewrite in candidates if _rewrite_holds(root, rewrite)]
        if len(kept) == len(candidates):
            return (trial_tree, kept) if kept else None
        if not kept:
            return None
        candidates = kept
    return None


def _apply(source: bytes, rewrites: list[_Rewrite]) -> bytes:
    if not rewrites:
        return source
    buffer = bytearray(source)
    for rewrite in rewrites:
        buffer[rewrite.start : rewrite.end] = rewrite.replacement
    return bytes(buffer)


def _blank(text: bytes) -> bytes:
    """Same-length whitespace that keeps every line break."""
    return bytes(byte if byte in b"\r\n" else 0x20 for byte in text)


def _error_node_count(root_node) -> int:
    count = 0
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            count += 1
        stack.extend(child for child in node.children if child.has_error)
    return count


def _tokens(root_node, source: bytes) -> list[_Token]:
    """Non-comment leaf tokens in source order.

    Every leaf is scanned: error recovery can make the root itself an ERROR
    node whose error-free children still hold the misparsed construct.
    """
    tokens: list[_Token] = []
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.child_count:
            stack.extend(reversed(node.children))
            continue
        start, end = node.start_byte, node.end_byte
        if end > start and node.type != "comment":
            tokens.append(_Token(start, end, source[start:end], node))
    return tokens


def _rewrite_candidates(root_node, source: bytes, *, typescript: bool, jsx: bool):
    tokens = _tokens(root_node, source)
    candidates = _using_identifier_candidates(tokens, source)
    if jsx:
        candidates.extend(_jsx_attribute_ampersand_candidates(tokens, source))
    if typescript:
        candidates.extend(_variance_candidates(tokens))
        candidates.extend(_member_separator_candidates(tokens, source))
        candidates.extend(_type_star_export_candidates(tokens))
        candidates.extend(_template_literal_type_escape_candidates(tokens, source))
    # Nested literals can yield the same escape twice.
    return list(dict.fromkeys(candidates))


def _is_identifier(token: bytes) -> bool:
    return _IDENTIFIER_RE.fullmatch(token) is not None


def _variance_candidates(tokens: list[_Token]) -> list[_Rewrite]:
    """``<`` or ``,``, optional ``const``, ``in``/``out``, a name, a follower."""
    candidates: list[_Rewrite] = []
    for index, token in enumerate(tokens):
        if token.text not in _TYPE_PARAMETER_LIST_OPENERS:
            continue
        cursor = index + 1
        if cursor < len(tokens) and tokens[cursor].text == b"const":
            cursor += 1
        modifiers = []
        while (
            cursor < len(tokens)
            and len(modifiers) < 2
            and tokens[cursor].text in _VARIANCE_MODIFIERS
        ):
            modifiers.append(tokens[cursor])
            cursor += 1
        if not modifiers or cursor + 1 >= len(tokens):
            continue
        name = tokens[cursor]
        if not _is_identifier(name.text) or name.text in _TYPE_PARAMETER_NAME_EXCLUDED:
            continue
        if tokens[cursor + 1].text not in _TYPE_PARAMETER_FOLLOWERS:
            continue
        for modifier in modifiers:
            candidates.append(
                _Rewrite(
                    "variance",
                    modifier.start,
                    _blank(modifier.text),
                    name.start,
                )
            )
    return candidates


def _ends_a_type(token: bytes) -> bool:
    if token in _TYPE_END_PUNCTUATION or token.isdigit():
        return True
    return _is_identifier(token) and token not in _TYPE_CONTINUATION_KEYWORDS


def _member_separator_candidates(tokens: list[_Token], source: bytes):
    """A member starting an indented line right after a complete member type."""
    candidates: list[_Rewrite] = []
    for index in range(1, len(tokens) - 1):
        token = tokens[index]
        if token.text == b"in":
            if tokens[index + 1].text not in _NAMED_MEMBER_FOLLOWERS:
                continue
        elif token.text != b"<":
            continue
        if not _ends_a_type(tokens[index - 1].text):
            continue
        line_start = token.start
        while line_start > 0 and source[line_start - 1] in b" \t":
            line_start -= 1
        if line_start == token.start or line_start == 0:
            continue
        if source[line_start - 1] not in b"\r\n":
            continue
        candidates.append(_Rewrite("separator", token.start - 1, b";", token.start))
    return candidates


def _type_star_export_candidates(tokens: list[_Token]) -> list[_Rewrite]:
    """``export type * from`` / ``export type * as ns from``."""
    candidates: list[_Rewrite] = []
    for index in range(len(tokens) - 3):
        export, type_keyword, star, follower = tokens[index : index + 4]
        if (
            export.text == b"export"
            and type_keyword.text == b"type"
            and star.text == b"*"
            and follower.text in {b"from", b"as"}
        ):
            candidates.append(
                _Rewrite(
                    "type_star_export",
                    type_keyword.start,
                    _blank(type_keyword.text),
                    star.start,
                )
            )
    return candidates


def _template_literal_type_escape_candidates(tokens: list[_Token], source: bytes):
    """Every escape of a template literal type the grammar failed on.

    The grammar lexes no escapes inside template literal types, so a lone
    ``\\`` can close the literal early. Blanking only the escapes the error
    tree shows would let the next one break the literal, so the literal is
    scanned from its opening backtick and all of its escapes are blanked.
    """
    candidates: list[_Rewrite] = []
    for index, token in enumerate(tokens):
        if token.text != b"`" or token.node.parent is None:
            continue
        literal = token.node.parent
        opens_broken_literal = (
            literal.type == "template_literal_type"
            and literal.has_error
            and literal.start_byte == token.start
        )
        # Recovery may not have built the literal node at all; the reparse
        # still has to show the escapes inside a template literal type.
        opens_in_error = (
            literal.is_error
            and index > 0
            and tokens[index - 1].text in _TYPE_OPERAND_PRECEDERS
        )
        if not (opens_broken_literal or opens_in_error):
            continue
        escapes = _template_escapes(source, token.start)
        candidates.extend(
            _Rewrite(
                "template_literal_type_escape",
                start,
                _blank(source[start:end]),
                start,
            )
            for start, end in escapes
        )
    return candidates


def _template_escapes(source: bytes, opening: int) -> list[tuple[int, int]]:
    """Escape spans of the template literal opening at ``opening``.

    Returns no spans when the literal does not end before the source does.
    Substitutions are skipped, apart from escapes in nested literals.
    """
    escapes: list[tuple[int, int]] = []
    # Each frame is the brace depth of an open ``${``; a template frame is -1.
    frames = [-1]
    index = opening + 1
    length = len(source)
    while index < length:
        byte = source[index]
        if frames[-1] == -1:
            if byte == 0x5C:  # backslash
                if not _escape_is_valid(source, index):
                    # A genuine error; leave the literal as it is.
                    return []
                end = _escape_end(source, index)
                escapes.append((index, end))
                index = end
                continue
            if byte == 0x60:  # backtick
                frames.pop()
                if not frames:
                    return escapes
                index += 1
                continue
            if source.startswith(b"${", index):
                frames.append(1)
                index += 2
                continue
            index += 1
            continue
        if byte == 0x60:
            frames.append(-1)
        elif byte in b"\"'":
            index = _skip_quoted(source, index)
            continue
        elif byte == 0x7B:  # {
            frames[-1] += 1
        elif byte == 0x7D:  # }
            frames[-1] -= 1
            if frames[-1] == 0:
                frames.pop()
        index += 1
    return []


def _escape_is_valid(source: bytes, backslash: int) -> bool:
    """Whether the escape at ``backslash`` is valid in an untagged template."""
    kind = source[backslash + 1 : backslash + 2]
    if kind == b"x":
        return _all_hex(source[backslash + 2 : backslash + 4], 2)
    if kind == b"u":
        if source[backslash + 2 : backslash + 3] != b"{":
            return _all_hex(source[backslash + 2 : backslash + 6], 4)
        close = source.find(b"}", backslash + 3, backslash + 12)
        digits = source[backslash + 3 : close] if close >= 0 else b""
        return _all_hex(digits, len(digits)) and int(digits, 16) <= 0x10FFFF
    if kind == b"0":
        return not source[backslash + 2 : backslash + 3].isdigit()
    return kind != b"" and not kind.isdigit()


def _all_hex(digits: bytes, length: int) -> bool:
    return (
        length > 0
        and len(digits) == length
        and all(byte in b"0123456789abcdefABCDEF" for byte in digits)
    )


def _escape_end(source: bytes, backslash: int) -> int:
    following = backslash + 1
    if following >= len(source):
        return following
    if source.startswith(b"\r\n", following):
        return following + 2
    lead = source[following]
    width = 1
    if lead >= 0xF0:
        width = 4
    elif lead >= 0xE0:
        width = 3
    elif lead >= 0xC0:
        width = 2
    return min(following + width, len(source))


def _skip_quoted(source: bytes, quote_index: int) -> int:
    quote = source[quote_index]
    index = quote_index + 1
    while index < len(source):
        byte = source[index]
        if byte == 0x5C:
            index += 2
            continue
        if byte == quote or byte in b"\r\n":
            return index + 1
        index += 1
    return index


def _using_identifier_candidates(tokens: list[_Token], source: bytes):
    """``using`` the grammar rejected where it is not a ``using`` declaration."""
    candidates: list[_Rewrite] = []
    for index, token in enumerate(tokens):
        # The grammar lexed the keyword where it could not parse it.
        parent = token.node.parent
        if token.node.type != "using" or parent is None or not parent.has_error:
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if (
            following is not None
            and _is_identifier(following.text)
            and following.text not in _USING_DECLARATION_EXCLUDED_NAMES
            and b"\n" not in source[token.end : following.start]
            and b"\r" not in source[token.end : following.start]
        ):
            # ``using name`` on one line: a declaration, which the grammar
            # supports; leave it alone.
            continue
        candidates.append(
            _Rewrite("using_identifier", token.start, _USING_REPLACEMENT, token.start)
        )
    return candidates


def _jsx_attribute_ampersand_candidates(tokens: list[_Token], source: bytes):
    """Raw ``&`` in a quoted JSX attribute value, as in a URL query string."""
    candidates: list[_Rewrite] = []
    for token in tokens:
        if token.text != b"&" or token.node.parent is None:
            continue
        value = token.node.parent.parent
        if (
            not token.node.parent.is_error
            or value is None
            or value.type != "string"
            or value.parent is None
            or value.parent.type != "jsx_attribute"
        ):
            continue
        position = source.find(b"&", value.start_byte + 1, value.end_byte - 1)
        while position >= 0:
            candidates.append(
                _Rewrite("jsx_attribute_ampersand", position, b"x", value.start_byte)
            )
            position = source.find(b"&", position + 1, value.end_byte - 1)
    return candidates


def _rewrite_holds(root_node, rewrite: _Rewrite) -> bool:
    return _REWRITE_CHECKS[rewrite.kind](root_node, rewrite)


def _variance_holds(root_node, rewrite: _Rewrite) -> bool:
    name = root_node.named_descendant_for_byte_range(rewrite.anchor, rewrite.anchor)
    if name is None or name.start_byte != rewrite.anchor:
        return False
    parameter = name.parent
    if parameter is None or parameter.type != "type_parameter":
        return False
    field_name = parameter.child_by_field_name("name")
    if field_name is None or field_name.start_byte != rewrite.anchor:
        return False
    if parameter.has_error:
        return False
    opener = parameter.prev_sibling
    while opener is not None and opener.type == "comment":
        opener = opener.prev_sibling
    if opener is None or opener.type not in {"<", ","}:
        return False
    if not (opener.end_byte <= rewrite.start < rewrite.anchor):
        return False
    parameters = parameter.parent
    return (
        parameters is not None
        and parameters.type == "type_parameters"
        and parameters.parent is not None
        and parameters.parent.type in _VARIANCE_OWNER_TYPES
    )


def _separator_holds(root_node, rewrite: _Rewrite) -> bool:
    separator = root_node.descendant_for_byte_range(rewrite.start, rewrite.end)
    if (
        separator is None
        or separator.type != ";"
        or separator.start_byte != rewrite.start
        or separator.parent is None
        or separator.parent.type not in _MEMBER_LIST_TYPES
    ):
        return False
    member = separator.next_sibling
    if member is None or member.start_byte != rewrite.anchor or member.has_error:
        return False
    if member.type == "call_signature":
        return True
    if member.type not in _NAMED_MEMBER_TYPES:
        return False
    name = member.child_by_field_name("name")
    return (
        name is not None
        and name.start_byte == rewrite.anchor
        and name.end_byte == rewrite.anchor + len(b"in")
    )


def _type_star_export_holds(root_node, rewrite: _Rewrite) -> bool:
    star = root_node.descendant_for_byte_range(rewrite.anchor, rewrite.anchor + 1)
    if star is None or star.type != "*" or star.start_byte != rewrite.anchor:
        return False
    statement = star.parent
    if statement is not None and statement.type == "namespace_export":
        statement = statement.parent
    if (
        statement is None
        or statement.type != "export_statement"
        or statement.has_error
        or statement.child_by_field_name("source") is None
    ):
        return False
    export = statement.child(0)
    return (
        export is not None
        and export.type == "export"
        and export.end_byte <= rewrite.start
    )


def _template_literal_type_escape_holds(root_node, rewrite: _Rewrite) -> bool:
    node = root_node.descendant_for_byte_range(rewrite.start, rewrite.end)
    while node is not None and node.type == "string_fragment":
        node = node.parent
    return (
        node is not None and node.type == "template_literal_type" and not node.has_error
    )


def _using_identifier_holds(root_node, rewrite: _Rewrite) -> bool:
    node = root_node.named_descendant_for_byte_range(rewrite.start, rewrite.end)
    return (
        node is not None
        and node.type in _IDENTIFIER_NODE_TYPES
        and node.start_byte == rewrite.start
        and node.end_byte == rewrite.end
        and node.parent is not None
        and not node.parent.has_error
    )


def _jsx_attribute_ampersand_holds(root_node, rewrite: _Rewrite) -> bool:
    node = root_node.descendant_for_byte_range(rewrite.start, rewrite.end)
    if node is None or node.type != "string_fragment":
        return False
    value = node.parent
    return (
        value is not None
        and value.type == "string"
        and value.start_byte == rewrite.anchor
        and not value.has_error
        and value.parent is not None
        and value.parent.type == "jsx_attribute"
    )


_REWRITE_CHECKS = {
    "jsx_attribute_ampersand": _jsx_attribute_ampersand_holds,
    "separator": _separator_holds,
    "template_literal_type_escape": _template_literal_type_escape_holds,
    "type_star_export": _type_star_export_holds,
    "using_identifier": _using_identifier_holds,
    "variance": _variance_holds,
}
