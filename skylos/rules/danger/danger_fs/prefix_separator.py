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
AMBIGUOUS_BINDING = object()


def binding_value(values):
    """A single expression, no expression, or a known ambiguous assignment.

    Repeated imports have no expression here; their providers are checked by
    module_level_imports. An expression captured before another assignment
    must not be expanded as though an unknown later value proved its safety.
    """
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    if any(value is not None for value in values):
        return AMBIGUOUS_BINDING
    return None


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def module_level_imports(tree):
    """Unambiguous module imports, without bindings from another scope.

    An unconditional import establishes a provider only when every import
    of that name agrees. A conditional or relative import cannot replace it
    with another provider and still supply a safety proof.
    """
    providers = {}
    unconditional = set()
    pending = [(node, True) for node in ast.iter_child_nodes(tree)]
    while pending:
        node, direct = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        imported = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                target = alias.name if alias.asname else name
                imported.append((name, target))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    # A wildcard can replace any previously imported name.
                    return {}
                target = None
                if node.module and not node.level:
                    target = f"{node.module}.{alias.name}"
                imported.append((alias.asname or alias.name, target))
        for name, target in imported:
            providers.setdefault(name, set()).add(target)
            if direct:
                unconditional.add(name)
        pending.extend((child, False) for child in ast.iter_child_nodes(node))
    return {
        name: next(iter(targets))
        for name, targets in providers.items()
        if name in unconditional and len(targets) == 1 and None not in targets
    }


_MAX_WORK = 512


class _ProofLimit(Exception):
    pass


def ends_with_separator(
    node, resolve, canonical, module_resolve=None, module_canonical=None
):
    """Prove a non-vacuous string prefix, or one flat tuple of such strings.

    The callbacks read the checking scope. A binding whose AST expression is
    also returned by ``module_resolve`` belongs to the module, so its names
    and imports must be read there even when the checking scope shadows them.
    Inline and locally declared tuples retain the checking scope instead.

    A shared work budget covers alias expansion and every string operation;
    hitting a limit never supplies a partial safety proof.
    """
    proof = _PrefixProof(resolve, canonical, module_resolve, module_canonical)
    try:
        return proof.prefix(node, proof.local, 0)
    except _ProofLimit:
        return False


class _PrefixProof:
    def __init__(self, resolve, canonical, module_resolve, module_canonical):
        self.local = (resolve, canonical)
        self.module = (
            (module_resolve, module_canonical or canonical)
            if module_resolve is not None
            else None
        )
        self.work = 0

    def charge(self, depth):
        self.work += 1
        if self.work > _MAX_WORK or depth > _MAX_DEPTH:
            raise _ProofLimit

    def resolved(self, node, context, depth):
        while isinstance(node, ast.Name):
            self.charge(depth)
            value = context[0](node.id)
            if value is AMBIGUOUS_BINDING:
                raise _ProofLimit
            if value is None:
                break
            if self.module is not None and value is self.module[0](node.id):
                context = self.module
            node = value
            depth += 1
        return node, context, depth

    def prefix(self, node, context, depth, allow_tuple=True):
        self.charge(depth)
        node, context, depth = self.resolved(node, context, depth)
        if isinstance(node, ast.Tuple):
            # startswith accepts a tuple of strings, not nested tuples. Apart
            # from being invalid at runtime, expanding nested aliases can
            # multiply work exponentially even within a small depth limit.
            return allow_tuple and bool(node.elts) and all(
                self.prefix(item, context, depth + 1, allow_tuple=False)
                for item in node.elts
            )
        if self.only_separators(node, context, depth):
            return False
        return self.terminal(node, context, depth)

    def only_separators(self, node, context, depth):
        self.charge(depth)
        node, context, depth = self.resolved(node, context, depth)
        if isinstance(node, (ast.Name, ast.Attribute)):
            return context[1](node) in SEPARATOR_NAMES
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str) and node.value.strip("/\\") == ""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.only_separators(
                node.left, context, depth + 1
            ) and self.only_separators(node.right, context, depth + 1)
        if isinstance(node, ast.JoinedStr):
            return all(
                self.only_separators(part, context, depth + 1)
                for part in node.values
            )
        if isinstance(node, ast.FormattedValue):
            return (
                node.conversion == -1
                and node.format_spec is None
                and self.only_separators(node.value, context, depth + 1)
            )
        return False

    def terminal(self, node, context, depth):
        self.charge(depth)
        node, context, depth = self.resolved(node, context, depth)
        if isinstance(node, (ast.Name, ast.Attribute)):
            return context[1](node) in SEPARATOR_NAMES
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str) and node.value.endswith(SEPARATORS)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.terminal(node.right, context, depth + 1)
        if isinstance(node, ast.JoinedStr):
            return bool(node.values) and self.terminal(
                node.values[-1], context, depth + 1
            )
        if isinstance(node, ast.FormattedValue):
            return (
                node.conversion == -1
                and node.format_spec is None
                and self.terminal(node.value, context, depth + 1)
            )
        if isinstance(node, ast.Call):
            return self.join_ends_with_separator(node, context, depth)
        return False

    def join_ends_with_separator(self, call, context, depth):
        provider = context[1](call.func)
        if (
            provider not in JOIN_NAMES
            or call.keywords
            or len(call.args) < 2
            or any(isinstance(argument, ast.Starred) for argument in call.args)
        ):
            return False
        last = call.args[-1]
        if isinstance(last, ast.Constant) and last.value == "":
            parts = []
            for argument in call.args[:-1]:
                value, owner, level = self.resolved(argument, context, depth + 1)
                if self.root_only(value, owner, level, provider):
                    # An absolute component discards earlier components:
                    # join(BASE, '/', '') is '/', regardless of BASE.
                    parts.clear()
                parts.append(argument)
            return not all(
                self.only_separators(argument, context, depth + 1)
                for argument in parts
            )
        if self.only_separators(last, context, depth + 1):
            return False
        return self.terminal(last, context, depth + 1)

    def root_only(self, node, context, depth, provider):
        self.charge(depth)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            separators = "/" if provider == "posixpath.join" else "/\\"
            return bool(node.value) and not node.value.strip(separators)
        target = context[1](node)
        return target in SEPARATOR_NAMES and not (
            provider == "posixpath.join" and target == "ntpath.sep"
        )


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
