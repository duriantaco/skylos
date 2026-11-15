"""SKY-D215: read archive ``startsWith`` containment guards from the syntax tree.

A guard ``if (!out.startsWith(PREFIX)) return;`` proves containment only when
``PREFIX`` provably ends at a separator and is more than separators. The
prefix is resolved through the binding the guard actually sees, walking out
from the call through blocks, loops, catch clauses, function parameters and
imports. Anything that cannot be resolved to a value is not trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skylos.visitors.languages.typescript.express_taint import (
    _call_args,
    _string_value,
    _text,
    _unwrap,
)

_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
_BLOCK_TYPES = frozenset(
    {
        "program",
        "statement_block",
        "switch_case",
        "switch_default",
        "class_static_block",
    }
)
_DECLARATION_TYPES = frozenset({"lexical_declaration", "variable_declaration"})
_BINDING_IDENTIFIERS = frozenset(
    {"identifier", "shorthand_property_identifier_pattern"}
)
_EXIT_STATEMENTS = frozenset(
    {"return_statement", "throw_statement", "continue_statement", "break_statement"}
)
_PATH_MODULES = frozenset({"path", "node:path", "path/posix", "path/win32"})
# The scopes the archive check reads one at a time.
ARCHIVE_SCOPE_NODE_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    }
)
_MAX_DEPTH = 6

# A binding the guard cannot see through: a parameter, loop variable, import,
# destructured name or a reassigned ``let``.
_OPAQUE = object()
_PATH_SEP = object()


@dataclass(frozen=True)
class _Import:
    module: str | None


@dataclass(frozen=True)
class ArchiveGuard:
    """One ``if`` whose condition is a ``startsWith`` containment check."""

    negated: bool
    subjects: tuple[str, ...]
    separator_prefixes: bool
    exits: bool
    body_start_line: int
    body_end_line: int


def archive_scope_start(node) -> int:
    """The start byte of the archive scope that holds ``node``."""
    current = node.parent
    while current is not None:
        if current.type in ARCHIVE_SCOPE_NODE_TYPES:
            return current.start_byte
        if current.parent is None:
            return current.start_byte
        current = current.parent
    return node.start_byte


def archive_startswith_guards(
    root_node, source: bytes
) -> dict[tuple[int, int], ArchiveGuard]:
    """Map ``(line of the if keyword, scope start)`` to the guard it carries."""
    resolver = _Resolver(root_node, source)
    guards: dict[tuple[int, int], ArchiveGuard] = {}
    for node in _walk(root_node):
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            continue
        shape = _condition_shape(source, condition, resolver.value_text)
        if shape is None:
            continue
        negated, calls = shape
        subjects = []
        separator_prefixes = True
        for call in calls:
            callee = call.child_by_field_name("function")
            subject = callee.child_by_field_name("object") if callee else None
            subjects.append(_text(source, subject) if subject is not None else "")
            args = _call_args(call)
            if len(args) != 1 or not resolver.separator_prefix(args[0]):
                separator_prefixes = False
        guards[(node.start_point[0], archive_scope_start(node))] = ArchiveGuard(
            negated=negated,
            subjects=tuple(subjects),
            separator_prefixes=separator_prefixes,
            exits=_always_exits(consequence),
            body_start_line=consequence.start_point[0],
            body_end_line=consequence.end_point[0],
        )
    return guards


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _is_startswith_call(source: bytes, node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None or callee.type != "member_expression":
        return False
    prop = callee.child_by_field_name("property")
    return prop is not None and _text(source, prop) == "startsWith"


def _condition_shape(source: bytes, node, expand=None):
    """``(negated, calls)`` when the condition is decided by ``startsWith``.

    ``negated`` means the branch runs when the path is *outside* the prefix,
    so it must exit. A non-negated guard must hold the sink in its body. An
    operand that is not a ``startsWith`` check may only narrow the branch in
    the safe direction: ``!a.startsWith(p) || x`` still exits whenever the
    path escapes, ``a.startsWith(p) || x`` does not.
    """
    node = _unwrap(node)
    if node is None:
        return None
    if _is_startswith_call(source, node):
        return False, [node]
    if node.type == "unary_expression":
        operator = node.child_by_field_name("operator")
        if operator is not None and _text(source, operator) == "!":
            inner = _condition_shape(
                source, node.child_by_field_name("argument"), expand
            )
            return None if inner is None else (not inner[0], inner[1])
        return None
    if node.type != "binary_expression":
        return None
    operator = node.child_by_field_name("operator")
    op = _text(source, operator) if operator is not None else ""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if op in {"===", "==", "!==", "!="}:
        literal, other = (left, right) if _is_boolean(source, left) else (right, left)
        if not _is_boolean(source, literal):
            return None
        inner = _condition_shape(source, other, expand)
        if inner is None:
            return None
        flip = (_text(source, literal) == "false") != (op in {"!==", "!="})
        return (not inner[0], inner[1]) if flip else inner
    if op not in {"&&", "||"}:
        return None
    # `&&` keeps a non-negated guard: the body runs only inside the prefix.
    # `||` keeps a negated guard: the body runs whenever the path escapes.
    keeps_negated = op == "||"
    shapes = [
        _condition_shape(source, left, expand),
        _condition_shape(source, right, expand),
    ]
    if op == "&&":
        # `x !== root && !x.startsWith(root + sep)` only lets the root itself
        # through, which is still inside it.
        for guard, other in ((0, 1), (1, 0)):
            shape = shapes[guard]
            if (
                shape is not None
                and shape[0]
                and shapes[other] is None
                and _excludes_subject_equality(
                    source, (left, right)[other], shape[1], expand
                )
            ):
                return True, shape[1]
    calls = []
    for shape, side in zip(shapes, (left, right)):
        if shape is None:
            if _mentions_startswith(source, side):
                return None
            continue
        if shape[0] != keeps_negated:
            return None
        calls.extend(shape[1])
    if not calls:
        return None
    return keeps_negated, calls


def _excludes_subject_equality(source: bytes, node, calls, expand=None) -> bool:
    node = _unwrap(node)
    if node is None or node.type != "binary_expression":
        return False
    operator = node.child_by_field_name("operator")
    if operator is None or _text(source, operator) not in {"!==", "!="}:
        return False
    subjects = set()
    for call in calls:
        callee = call.child_by_field_name("function")
        subject = callee.child_by_field_name("object") if callee else None
        if subject is not None:
            subjects.add(_text(source, _unwrap(subject)))
    pieces = []
    for call in calls:
        for arg in _call_args(call):
            pieces.append(_text(source, arg))
            if (
                expand is not None
                and _unwrap(arg) is not None
                and _unwrap(arg).type == "identifier"
            ):
                pieces.append(expand(_unwrap(arg)))
    prefixes = " ".join(pieces)
    texts = [
        _text(source, _unwrap(operand))
        for operand in (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
        if operand is not None
    ]
    if len(texts) != 2:
        return False
    # One side is the checked path, the other the root its prefix is built
    # from: `out !== root && !out.startsWith(root + sep)`.
    for subject, other in (texts, texts[::-1]):
        if subject in subjects and re.search(
            rf"(?<![\w$.]){re.escape(other)}(?![\w$])", prefixes
        ):
            return True
    return False


def archive_parent_segment_guards(
    root_node, source: bytes
) -> dict[tuple[int, int], frozenset[str]]:
    """Map the line of each ``if`` that exits when a path has a ``..`` part to
    the names that check reads.

    ``if (rel.split(sep).includes("..")) throw``,
    ``if (parts.some((p) => p === "..")) return`` and
    ``if (relative.startsWith("..") || isAbsolute(relative)) throw`` all
    qualify. The check must decide the branch on its own: it may sit under
    ``||`` but not under ``&&`` or ``!``.
    """
    guards: dict[tuple[int, int], frozenset[str]] = {}
    for node in _walk(root_node):
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None or not _always_exits(consequence):
            continue
        names: set[str] = set()
        for leaf in _or_operands(source, condition):
            if _is_parent_segment_check(source, leaf):
                names.update(
                    _text(source, n) for n in _walk(leaf) if n.type == "identifier"
                )
        if names:
            guards[(node.start_point[0], archive_scope_start(node))] = frozenset(names)
    return guards


def _or_operands(source: bytes, node):
    node = _unwrap(node)
    if node is None:
        return
    if node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        if operator is not None and _text(source, operator) == "||":
            yield from _or_operands(source, node.child_by_field_name("left"))
            yield from _or_operands(source, node.child_by_field_name("right"))
            return
    yield node


def _is_dotdot(source: bytes, node) -> bool:
    return _string_value(source, node) in {"..", "../", "..\\"}


def _is_parent_segment_check(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        op = _text(source, operator) if operator is not None else ""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if op in {"===", "=="}:
            return _is_dotdot(source, left) or _is_dotdot(source, right)
        # `x.indexOf("..") !== -1` / `>= 0` / `> -1`
        if op in {"!==", "!=", ">=", ">"}:
            return _is_parent_segment_check(source, left)
        return False
    if node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None or callee.type != "member_expression":
        return False
    prop = callee.child_by_field_name("property")
    method = _text(source, prop) if prop is not None else ""
    args = _call_args(node)
    if method in {"includes", "indexOf", "startsWith"}:
        return len(args) == 1 and _is_dotdot(source, args[0])
    if method == "some" and len(args) == 1:
        callback = _unwrap(args[0])
        if callback is None or callback.type not in {
            "arrow_function",
            "function_expression",
            "function",
        }:
            return False
        body = callback.child_by_field_name("body")
        if body is None:
            return False
        if body.type == "statement_block":
            returns = [n for n in _walk(body) if n.type == "return_statement"]
            return any(
                any(
                    _is_parent_segment_check(source, leaf)
                    for leaf in _or_operands(source, r.named_children[0])
                )
                for r in returns
                if r.named_children
            )
        return any(
            _is_parent_segment_check(source, leaf)
            for leaf in _or_operands(source, body)
        )
    return False


def _is_boolean(source: bytes, node) -> bool:
    node = _unwrap(node)
    return node is not None and node.type in {"true", "false"}


def _mentions_startswith(source: bytes, node) -> bool:
    return node is not None and any(_is_startswith_call(source, n) for n in _walk(node))


def _always_exits(consequence) -> bool:
    if consequence.type in _EXIT_STATEMENTS:
        return True
    if consequence.type != "statement_block":
        return False
    return any(child.type in _EXIT_STATEMENTS for child in consequence.named_children)


class _Resolver:
    def __init__(self, root_node, source: bytes):
        self.source = source
        self.written = self._written_names(root_node)

    def _written_names(self, root_node) -> set[str]:
        """Every name an assignment, update or bare ``for`` head writes."""
        names: set[str] = set()
        for node in _walk(root_node):
            target = None
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                target = node.child_by_field_name("left")
            elif node.type == "update_expression":
                target = node.child_by_field_name("argument")
            elif node.type == "for_in_statement":
                target = node.child_by_field_name("left")
                kind = node.child_by_field_name("kind")
                if kind is not None:
                    target = None
            if target is None:
                continue
            target = _unwrap(target)
            if target.type == "identifier":
                names.add(_text(self.source, target))
                continue
            if target.type in {"object_pattern", "array_pattern"}:
                names.update(
                    _text(self.source, n)
                    for n in _walk(target)
                    if n.type in _BINDING_IDENTIFIERS
                )
        return names

    # -- binding resolution -------------------------------------------------

    def binding(self, identifier):
        """The value node the name is bound to, ``_OPAQUE``, or ``None`` when
        no declaration is visible (a global)."""
        name = _text(self.source, identifier)
        node = identifier
        while node.parent is not None:
            child, node = node, node.parent
            found = self._declared_in(node, child, name)
            if found is not None:
                return found
        return None

    def _declared_in(self, scope, came_from, name: str):
        if scope.type in _BLOCK_TYPES:
            matches = []
            for statement in scope.named_children:
                if statement.type in _DECLARATION_TYPES:
                    matches.extend(self._declarators(statement, name))
                elif statement.type == "export_statement":
                    for inner in statement.named_children:
                        if inner.type in _DECLARATION_TYPES:
                            matches.extend(self._declarators(inner, name))
                        elif self._declares_named(inner, name):
                            return _OPAQUE
                elif statement.type == "import_statement":
                    if self._import_binds(statement, name):
                        return self._import_value(statement, name)
                elif self._declares_named(statement, name):
                    return _OPAQUE
            if len(matches) > 1:
                return _OPAQUE
            if matches:
                return matches[0]
            return None
        if scope.type in _FUNCTION_TYPES:
            if self._parameters_bind(scope, name):
                return _OPAQUE
            if scope.type in {"function_expression", "function"}:
                own = scope.child_by_field_name("name")
                if own is not None and _text(self.source, own) == name:
                    return _OPAQUE
            if self._hoisted_var(scope, name):
                return _OPAQUE
            return None
        if scope.type in {"for_statement", "for_in_statement"}:
            head = scope.child_by_field_name(
                "initializer" if scope.type == "for_statement" else "left"
            )
            if head is not None and came_from is not head and self._binds(head, name):
                return _OPAQUE
            return None
        if scope.type == "catch_clause":
            parameter = scope.child_by_field_name("parameter")
            if parameter is not None and self._binds(parameter, name):
                return _OPAQUE
        return None

    def _declarators(self, declaration, name: str) -> list:
        is_const = _text(self.source, declaration).lstrip().startswith("const")
        found = []
        for declarator in declaration.named_children:
            if declarator.type != "variable_declarator":
                continue
            target = declarator.child_by_field_name("name")
            if target is None or not self._binds(target, name):
                continue
            value = declarator.child_by_field_name("value")
            if (
                target.type == "object_pattern"
                and name == "sep"
                and value is not None
                and self._is_require_of_path(value)
            ):
                found.append(_PATH_SEP)
            elif (
                target.type != "identifier"
                or value is None
                or (not is_const and name in self.written)
            ):
                found.append(_OPAQUE)
            else:
                found.append(value)
        return found

    def _binds(self, pattern, name: str) -> bool:
        if pattern.type in _BINDING_IDENTIFIERS:
            return _text(self.source, pattern) == name
        for node in _walk(pattern):
            if node.type not in _BINDING_IDENTIFIERS:
                continue
            parent = node.parent
            # The default value of `{ a = b }` reads `b`; it does not bind it.
            if (
                parent is not None
                and parent.type in {"assignment_pattern", "object_assignment_pattern"}
                and parent.child_by_field_name("right") is node
            ):
                continue
            if (
                parent is not None
                and parent.type == "pair_pattern"
                and parent.child_by_field_name("key") is node
            ):
                continue
            if _text(self.source, node) == name:
                return True
        return False

    def _parameters_bind(self, function, name: str) -> bool:
        single = function.child_by_field_name("parameter")
        if single is not None:
            return self._binds(single, name)
        parameters = function.child_by_field_name("parameters")
        if parameters is None:
            return False
        for parameter in parameters.named_children:
            pattern = parameter.child_by_field_name("pattern") or parameter
            if pattern.type == "assignment_pattern":
                pattern = pattern.child_by_field_name("left") or pattern
            if self._binds(pattern, name):
                return True
        return False

    def _hoisted_var(self, function, name: str) -> bool:
        """A ``var`` anywhere in the function body binds the name for all of it."""
        body = function.child_by_field_name("body")
        if body is None:
            return False
        stack = list(body.named_children)
        while stack:
            node = stack.pop()
            if node.type in _FUNCTION_TYPES:
                continue
            if node.type == "variable_declaration" and self._declarators(node, name):
                return True
            stack.extend(node.named_children)
        return False

    def _declares_named(self, node, name: str) -> bool:
        if node.type not in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "enum_declaration",
        }:
            return False
        own = node.child_by_field_name("name")
        return own is not None and _text(self.source, own) == name

    def _import_binds(self, statement, name: str) -> bool:
        for node in _walk(statement):
            if node.type != "identifier":
                continue
            parent = node.parent
            if parent is not None and parent.type == "import_specifier":
                alias = parent.child_by_field_name("alias")
                if alias is not None and alias is not node:
                    continue
            if _text(self.source, node) == name:
                return True
        return False

    def _import_value(self, statement, name: str):
        """``import { sep } from "path"`` is the separator; any other import is
        a value the file cannot see."""
        source_node = statement.child_by_field_name("source")
        module = _string_value(self.source, source_node) if source_node else None
        if module in _PATH_MODULES and name == "sep":
            return _PATH_SEP
        return _Import(module)

    # -- prefix values ------------------------------------------------------

    def value_text(self, identifier) -> str:
        """The source text a name is bound to, or ``""`` when unknown."""
        value = self._value(identifier, 0)
        if value is None or value is _PATH_SEP:
            return ""
        return _text(self.source, value)

    def _value(self, node, depth: int):
        """Follow identifiers to the expression they hold."""
        node = _unwrap(node)
        while node is not None and node.type == "identifier" and depth <= _MAX_DEPTH:
            bound = self.binding(node)
            if bound is None or bound is _OPAQUE or isinstance(bound, _Import):
                return None
            if bound is _PATH_SEP:
                return _PATH_SEP
            node = _unwrap(bound)
            depth += 1
        return node

    def _is_path_module(self, node) -> bool:
        node = _unwrap(node)
        if node is None or node.type != "identifier":
            return False
        bound = self.binding(node)
        if bound is None:
            # A global `path` (a CommonJS script without its own require).
            return _text(self.source, node) == "path"
        if isinstance(bound, _Import):
            return bound.module in _PATH_MODULES
        if bound is _OPAQUE or bound is _PATH_SEP:
            return False
        return self._is_require_of_path(bound)

    def _is_require_of_path(self, value) -> bool:
        value = _unwrap(value)
        if value is None or value.type != "call_expression":
            return False
        callee = value.child_by_field_name("function")
        args = _call_args(value)
        return (
            callee is not None
            and _text(self.source, callee) == "require"
            and len(args) == 1
            and _string_value(self.source, args[0]) in _PATH_MODULES
        )

    def _is_separator(self, node, depth: int) -> bool:
        node = self._value(node, depth)
        if node is _PATH_SEP:
            return True
        if node is None or node.type != "member_expression":
            return False
        prop = node.child_by_field_name("property")
        return (
            prop is not None
            and _text(self.source, prop) == "sep"
            and self._is_path_module(node.child_by_field_name("object"))
        )

    def _only_separators(self, node, depth: int) -> bool:
        """Nothing but separators (or empty pieces glued to them)."""
        if depth > _MAX_DEPTH:
            return False
        if self._is_separator(node, depth):
            return True
        value = self._value(node, depth)
        if value is None or value is _PATH_SEP:
            return False
        if value.type == "binary_expression":
            operator = value.child_by_field_name("operator")
            if operator is None or _text(self.source, operator) != "+":
                return False
            return self._only_separators(
                value.child_by_field_name("left"), depth + 1
            ) and self._only_separators(value.child_by_field_name("right"), depth + 1)
        text = _string_value(self.source, value)
        return text is not None and text.strip("/\\") == ""

    def _ends_with_separator(self, node, depth: int) -> bool:
        if depth > _MAX_DEPTH:
            return False
        if self._is_separator(node, depth):
            return True
        node = self._value(node, depth)
        if node is None or node is _PATH_SEP:
            return False
        text = _string_value(self.source, node)
        if text is not None:
            return text.endswith(("/", "\\"))
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is None or _text(self.source, operator) != "+":
                return False
            return self._ends_with_separator(
                node.child_by_field_name("right"), depth + 1
            )
        if node.type == "template_string":
            parts = [c for c in node.named_children if c.type != "comment"]
            if not parts:
                return False
            if parts[-1].type != "template_substitution":
                return _text(self.source, node).endswith(("/`", "\\\\`"))
            inner = [c for c in parts[-1].named_children if c.type != "comment"]
            return len(inner) == 1 and self._ends_with_separator(inner[0], depth + 1)
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            args = _call_args(node)
            if callee is None or callee.type != "member_expression" or not args:
                return False
            prop = callee.child_by_field_name("property")
            if prop is None or _text(self.source, prop) not in {"join", "normalize"}:
                return False
            if not self._is_path_module(callee.child_by_field_name("object")):
                return False
            return self._ends_with_separator(args[-1], depth + 1)
        return False

    def separator_prefix(self, node) -> bool:
        """The prefix ends at a separator and is more than separators:
        ``'/tmp/out2/x'.startsWith('/tmp/out')`` is true."""
        if self._only_separators(node, 0):
            return False
        return self._ends_with_separator(node, 0)


_NORMALIZING_TEXT = ("normalize(", "resolve(", "join(", "realpath")


_TERNARY_SEGMENT_CHECK = re.compile(
    r"""\.every\([^;]*!==?\s*(['"])\.\.\1"""
    r"""|!\s*[\w$.]+(?:\.split\([^)]*\))?\.includes\(\s*(['"])\.\.\2\s*\)""",
    re.DOTALL,
)


@dataclass(frozen=True)
class ArchiveValidators:
    """Functions in this file that refuse a path escaping its root.

    ``complete`` ones check on their own: what they return, and what they are
    handed as a bare assertion call, is safe. ``prefix_only`` ones compare a
    path the caller must already have normalized.
    """

    complete: frozenset[str]
    prefix_only: frozenset[str]


def archive_path_validators(
    root_node,
    source: bytes,
    guards: dict[tuple[int, int], ArchiveGuard],
    segment_guards: dict[tuple[int, int], frozenset[str]],
) -> ArchiveValidators:
    """A function qualifies when its own body exits on a ``..`` part, returns
    a name only when no part is ``..`` (``parts.every((p) => p !== "..") ?
    name : null``), or exits when a path fails a separator-terminated
    ``startsWith``."""
    by_scope: dict[int, list[str]] = {}
    functions: dict[int, object] = {}
    for node in _walk(root_node):
        name_node = None
        function = None
        if node.type in {"function_declaration", "generator_function_declaration"}:
            name_node, function = node.child_by_field_name("name"), node
        elif node.type == "variable_declarator":
            value = _unwrap(node.child_by_field_name("value"))
            if value is not None and value.type in ARCHIVE_SCOPE_NODE_TYPES:
                name_node, function = node.child_by_field_name("name"), value
        if name_node is None or function is None or name_node.type != "identifier":
            continue
        by_scope.setdefault(function.start_byte, []).append(_text(source, name_node))
        functions[function.start_byte] = function

    complete: set[str] = set()
    prefix_only: set[str] = set()
    for (_line, scope), names in segment_guards.items():
        if names and scope in by_scope:
            complete.update(by_scope[scope])
    for (_line, scope), guard in guards.items():
        if not (
            scope in by_scope
            and guard.negated
            and guard.exits
            and guard.separator_prefixes
        ):
            continue
        body = _text(source, functions[scope])
        if any(token in body for token in _NORMALIZING_TEXT):
            complete.update(by_scope[scope])
        else:
            prefix_only.update(by_scope[scope])
    for scope, function in functions.items():
        for node in _walk(function):
            if node.type in ARCHIVE_SCOPE_NODE_TYPES and node is not function:
                continue
            if node.type != "return_statement" or not node.named_children:
                continue
            value = _unwrap(node.named_children[0])
            if value is None or value.type != "ternary_expression":
                continue
            test = value.child_by_field_name("condition")
            if test is not None and _TERNARY_SEGMENT_CHECK.search(_text(source, test)):
                complete.update(by_scope[scope])
    return ArchiveValidators(frozenset(complete), frozenset(prefix_only - complete))
