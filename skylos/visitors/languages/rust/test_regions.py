"""Lines of a Rust file that only the test harness compiles.

rustc removes ``#[cfg(test)]`` code from every build except ``cargo test``,
and the libtest harness runs ``#[test]``/``#[bench]`` functions (also
``#[tokio::test]``, ``#[rstest]`` and other attributes whose path ends in
``test`` or ``bench``). Code there holds fixtures and test vectors, so the
secrets scan treats it like a file under ``tests/``: only provider-shaped
credentials count.

``#[cfg(test)]`` is not limited to items: rustc honours it on any node that
can carry an attribute, such as a struct field written in a value, a
statement, a match arm or an enum variant. A module file is also test-only
when its parent declares it with ``#[cfg(test)] mod name;``.
"""

from __future__ import annotations

from pathlib import Path

from .core import RUST_LANG, _get_parser

_TEST_ATTRIBUTES = frozenset({"test", "bench"})
# Test-harness attributes from common crates whose name does not end in
# ``test``: parameterised and property tests.
_TEST_ATTRIBUTE_NAMES = frozenset({"rstest", "test_case", "test_matrix", "quickcheck"})
_COMMENTS = frozenset({"line_comment", "block_comment"})
# Nodes whose children are a sequence of attributed entries. An outer
# attribute inside one of these applies to the next entry; inside any other
# node (a field initializer, a match arm, ...) it belongs to that node.
_SEQUENCE_NODES = frozenset(
    {
        "source_file",
        "declaration_list",
        "block",
        "field_declaration_list",
        "ordered_field_declaration_list",
        "enum_variant_list",
        "field_initializer_list",
        "match_block",
        "parameters",
        "arguments",
        "array_expression",
        "tuple_expression",
    }
)
_MAX_PARENT_MODULE_BYTES = 2_000_000


def _tokens(node, source):
    if node.type in _COMMENTS:
        return ()
    if not node.children or node.type in {"string_literal", "raw_string_literal"}:
        return (source[node.start_byte : node.end_byte].decode("utf-8", "replace"),)
    return tuple(token for child in node.children for token in _tokens(child, source))


def _test_only_cfg(tokens):
    """``cfg(test)`` or ``cfg(all(.., test, ..))``; ``any``/``not`` are not."""
    if tokens == ("(", "test", ")"):
        return True
    if len(tokens) < 4 or tokens[:3] != ("(", "all", "(") or tokens[-2:] != (")", ")"):
        return False
    depth = 0
    for index, token in enumerate(tokens[3:-2]):
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth == 0 and token == "test":
            previous = tokens[3 + index - 1]
            following = tokens[3 + index + 1] if 3 + index + 1 < len(tokens) else ""
            if previous in {"(", ","} and following in {")", ","}:
                return True
    return False


def _attribute_marks_test(attribute_item, source):
    tokens = _tokens(attribute_item, source)
    # ``#`` ``[`` path ... ``]`` (an inner attribute also has ``!``).
    body = tokens[3:-1] if tokens[1:2] == ("!",) else tokens[2:-1]
    if not body:
        return False
    if body[0] == "cfg":
        return _test_only_cfg(body[1:])
    path = []
    for token in body:
        if token == "(" or token == "=":
            break
        path.append(token)
    segments = [part for part in path if part != "::"]
    if not segments:
        return False
    last = segments[-1]
    return (
        last in _TEST_ATTRIBUTES
        or last in _TEST_ATTRIBUTE_NAMES
        or last.endswith(("_test", "_bench"))
    )


def _mark(lines, start_row, end_row):
    lines.update(range(start_row + 1, end_row + 2))


def _walk(root, source, lines):
    """Mark every node an attribute excludes from non-test builds."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "inner_attribute_item":
            if _attribute_marks_test(node, source):
                owner = node.parent
                start = owner.start_point[0] if owner.parent is not None else 0
                _mark(lines, start, owner.end_point[0])
            continue
        if node.type == "attribute_item":
            continue
        children = node.named_children
        if node.type in _SEQUENCE_NODES:
            pending_start = None
            marked = False
            for child in children:
                if child.type == "attribute_item":
                    if pending_start is None:
                        pending_start = child.start_point[0]
                    marked |= _attribute_marks_test(child, source)
                    continue
                if child.type in _COMMENTS:
                    continue
                if marked:
                    first = (
                        pending_start
                        if pending_start is not None
                        else child.start_point[0]
                    )
                    _mark(lines, first, child.end_point[0])
                else:
                    stack.append(child)
                pending_start = None
                marked = False
            for child in children:
                if child.type == "inner_attribute_item":
                    stack.append(child)
            continue
        # A node that holds its own outer attributes (``#[cfg(test)] name: v``
        # in a struct value, a match arm).
        if any(
            child.type == "attribute_item" and _attribute_marks_test(child, source)
            for child in children
        ):
            _mark(lines, node.start_point[0], node.end_point[0])
            continue
        stack.extend(children)


def test_line_numbers(source: bytes) -> frozenset[int]:
    """1-based lines inside test-only code. A file that does not parse
    cleanly has none, so nothing is excused on a guess."""
    if RUST_LANG is None or not source:
        return frozenset()
    root = _get_parser(RUST_LANG).parse(source).root_node
    if root.has_error:
        return frozenset()
    lines: set[int] = set()
    _walk(root, source, lines)
    return frozenset(lines)


def _parent_module_files(path: Path) -> tuple[str, list[Path]]:
    """The module name a file defines and the files that may declare it."""
    if path.stem == "mod":
        name = path.parent.name
        directory = path.parent.parent
    else:
        name = path.stem
        directory = path.parent
    candidates = [directory / "mod.rs", directory / "lib.rs", directory / "main.rs"]
    candidates.append(directory.parent / f"{directory.name}.rs")
    return name, [candidate for candidate in candidates if candidate != path]


def declared_test_module(path) -> bool:
    """Whether the parent module declares this file ``#[cfg(test)] mod name;``.

    Only a parent that parses cleanly and declares the module without a body
    and without a ``#[path]`` attribute counts.
    """
    if RUST_LANG is None or path is None:
        return False
    file_path = Path(path)
    if file_path.suffix != ".rs" or file_path.stem in {"lib", "main"}:
        return False
    name, candidates = _parent_module_files(file_path)
    parser = _get_parser(RUST_LANG)
    for candidate in candidates:
        try:
            if (
                not candidate.is_file()
                or candidate.stat().st_size > _MAX_PARENT_MODULE_BYTES
            ):
                continue
            source = candidate.read_bytes()
        except OSError:
            continue
        root = parser.parse(source).root_node
        if root.has_error:
            continue
        if _declares_test_module(root, source, name):
            return True
    return False


def _declares_test_module(root, source, name):
    stack = [root]
    while stack:
        node = stack.pop()
        children = node.named_children
        pending = []
        for child in children:
            if child.type == "attribute_item":
                pending.append(child)
                continue
            if child.type in _COMMENTS:
                continue
            if child.type == "mod_item":
                body = child.child_by_field_name("body")
                ident = child.child_by_field_name("name")
                declared = (
                    source[ident.start_byte : ident.end_byte].decode() if ident else ""
                )
                attributes = pending + [
                    item
                    for item in child.named_children
                    if item.type == "attribute_item"
                ]
                has_path = any(
                    _tokens(item, source)[2:3] == ("path",) for item in attributes
                )
                if (
                    body is None
                    and declared == name
                    and not has_path
                    and any(_attribute_marks_test(item, source) for item in attributes)
                ):
                    return True
                if body is not None:
                    stack.append(body)
            pending = []
    return False
