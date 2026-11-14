"""Whether a string prefix provably ends at a path separator.

``"/srv/files2/x".startswith("/srv/files")`` is true, so a prefix check on a
resolved path proves containment only when the prefix ends with ``/`` or
``\\``. A prefix that is nothing but separators proves nothing.
"""

from __future__ import annotations

import ast

SEPARATORS = ("/", "\\")
SEPARATOR_NAMES = frozenset({"os.sep", "os.path.sep", "posixpath.sep", "ntpath.sep"})
JOIN_NAMES = frozenset({"os.path.join", "posixpath.join", "ntpath.join"})
_MAX_DEPTH = 8


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def ends_with_separator(node, resolve, canonical):
    """True when the prefix ``node`` provably ends with a separator.

    ``resolve(name)`` returns the one expression a name is bound to, or None.
    ``canonical(node)`` returns the standard-library name an expression
    refers to (``"os.sep"``), or None when it is not a trusted import.
    """
    if isinstance(node, ast.Tuple):
        return bool(node.elts) and all(
            ends_with_separator(item, resolve, canonical) for item in node.elts
        )
    value = _resolved(node, resolve, 0)
    if value is None or _only_separators(value, resolve, canonical, 0):
        return False
    return _terminal(value, resolve, canonical, 0)


def _resolved(node, resolve, depth):
    while isinstance(node, ast.Name) and depth <= _MAX_DEPTH:
        node = resolve(node.id)
        depth += 1
    if isinstance(node, ast.Name):
        return None
    return node


def _only_separators(node, resolve, canonical, depth):
    """The prefix is empty or nothing but separators, so it admits any
    absolute path."""
    if depth > _MAX_DEPTH or node is None:
        return False
    if isinstance(node, ast.Name):
        return _only_separators(resolve(node.id), resolve, canonical, depth + 1)
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and node.value.strip("/\\") == ""
    if isinstance(node, ast.Attribute):
        return canonical(node) in SEPARATOR_NAMES
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _only_separators(
            node.left, resolve, canonical, depth + 1
        ) and _only_separators(node.right, resolve, canonical, depth + 1)
    if isinstance(node, ast.JoinedStr):
        return all(
            _only_separators(part, resolve, canonical, depth + 1)
            for part in node.values
        )
    if isinstance(node, ast.FormattedValue):
        return (
            node.conversion == -1
            and node.format_spec is None
            and _only_separators(node.value, resolve, canonical, depth + 1)
        )
    return False


def _terminal(node, resolve, canonical, depth):
    if depth > _MAX_DEPTH or node is None:
        return False
    if isinstance(node, ast.Name):
        return _terminal(resolve(node.id), resolve, canonical, depth + 1)
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and node.value.endswith(SEPARATORS)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _terminal(node.right, resolve, canonical, depth + 1)
    if isinstance(node, ast.JoinedStr):
        if not node.values:
            return False
        return _terminal(node.values[-1], resolve, canonical, depth + 1)
    if isinstance(node, ast.FormattedValue):
        if node.conversion != -1 or node.format_spec is not None:
            return False
        return _terminal(node.value, resolve, canonical, depth + 1)
    if isinstance(node, ast.Attribute):
        return canonical(node) in SEPARATOR_NAMES
    if isinstance(node, ast.Call):
        return _join_ends_with_separator(node, resolve, canonical, depth)
    return False


def _join_ends_with_separator(call, resolve, canonical, depth):
    if canonical(call.func) not in JOIN_NAMES or call.keywords or len(call.args) < 2:
        return False
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return False
    last = call.args[-1]
    if isinstance(last, ast.Constant) and last.value == "":
        return True
    if _only_separators(last, resolve, canonical, depth + 1):
        return False
    return _terminal(last, resolve, canonical, depth + 1)


def bound_names(tree):
    """Names bound anywhere in ``tree`` by something other than an import."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.alias) and node.name == "*":
            names.add("*")
    return names


def scope_bindings(scope):
    """``name -> [value or None]`` for each binding in one function or module
    body, without nested definitions. ``None`` marks a binding whose value is
    not one plain expression (a parameter, loop target, ``with``, augmented
    assignment or unpacking)."""
    bindings = {}

    def add(name, value):
        bindings.setdefault(name, []).append(value)

    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]:
            if argument is not None:
                add(argument.arg, None)
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name, None)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                add(node.targets[0].id, node.value)
                pending.append(node.value)
                continue
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            add(node.target.id, node.value)
            if node.value is not None:
                pending.append(node.value)
            continue
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                add(name, None)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0], None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(node.name, None)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(node.name, None)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            add(node.id, None)
        pending.extend(ast.iter_child_nodes(node))
    return bindings
