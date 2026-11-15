"""SKY-D215: read archive ``startsWith`` containment guards from the syntax tree.

A guard ``if (!out.startsWith(PREFIX)) return;`` proves containment only when
``PREFIX`` provably ends at a separator and is more than separators. The
prefix is resolved through the binding the guard actually sees, walking out
from the call through blocks, loops, catch clauses, function parameters and
imports. Anything that cannot be resolved to a value is not trusted.
"""

from __future__ import annotations

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


def archive_startswith_guards(root_node, source: bytes) -> dict[int, ArchiveGuard]:
    """Map the 0-based line of each ``if`` keyword to the guard it carries."""
    resolver = _Resolver(root_node, source)
    guards: dict[int, ArchiveGuard] = {}
    for node in _walk(root_node):
        if node.type != "if_statement":
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            continue
        shape = _condition_shape(source, condition)
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
        guards[node.start_point[0]] = ArchiveGuard(
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


def _condition_shape(source: bytes, node):
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
            inner = _condition_shape(source, node.child_by_field_name("argument"))
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
        inner = _condition_shape(source, other)
        if inner is None:
            return None
        flip = (_text(source, literal) == "false") != (op in {"!==", "!="})
        return (not inner[0], inner[1]) if flip else inner
    if op not in {"&&", "||"}:
        return None
    # `&&` keeps a non-negated guard: the body runs only inside the prefix.
    # `||` keeps a negated guard: the body runs whenever the path escapes.
    keeps_negated = op == "||"
    shapes = [_condition_shape(source, left), _condition_shape(source, right)]
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
