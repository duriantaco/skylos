"""Lexical bindings and mutation facts for source-only receiver evidence."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from skylos.rules.quality._provider_context import project_local_provider
from skylos.security.operation_contracts import _has_custom_import_provider

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BRANCHES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.ExceptHandler,
    ast.Match,
)


# os.open accepts integer bit flags. Passing those projected values cannot
# expose the os module itself: https://docs.python.org/3/library/os.html#os.open
_IMMUTABLE_OS_FLAGS = {
    "O_RDONLY",
    "O_WRONLY",
    "O_RDWR",
    "O_APPEND",
    "O_CREAT",
    "O_EXCL",
    "O_TRUNC",
    "O_NONBLOCK",
    "O_NDELAY",
    "O_CLOEXEC",
    "O_NOFOLLOW",
    "O_DIRECTORY",
    "O_SYNC",
    "O_DSYNC",
    "O_RSYNC",
    "O_NOCTTY",
    "O_BINARY",
    "O_TEXT",
    "O_TEMPORARY",
    "O_SHORT_LIVED",
    "O_SEQUENTIAL",
    "O_RANDOM",
    "O_DIRECT",
    "O_NOATIME",
    "O_PATH",
    "O_TMPFILE",
    "O_LARGEFILE",
}


def _escaped_object_names(value, immutable_projection=None):
    """Names passed as values, rather than names used to compute a result.

    Containers preserve references to their contents. A call's result does
    not, by itself, prove that its receiver or arguments have escaped; that
    call is inspected separately. This distinction matters for nested calls.
    """
    if immutable_projection is not None and immutable_projection(value):
        return set()
    if isinstance(value, ast.Name):
        return {value.id}
    if isinstance(value, (ast.Call, ast.Lambda)):
        return set()
    names = set()
    for child in ast.iter_child_nodes(value):
        names.update(_escaped_object_names(child, immutable_projection))
    return names


@dataclass
class _Reference:
    kind: str
    name: str
    module: "_Module | None" = None
    node: ast.AST | None = None
    receiver: "_Reference | None" = None
    model: str | None = None


class _Module:
    def __init__(self, tree, path, name, project_root=None):
        self.tree = tree
        self.path = path
        self.name = name
        self.project_root = project_root
        self.parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        self.binding_cache = {}
        self.mutated = set()
        self.dynamic_namespace = False
        self.custom_import_provider = _has_custom_import_provider(self)
        aliases = []
        alias_values = []
        object_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                object_names.add(node.name)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    object_names.add(alias.asname or alias.name.split(".")[0])
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = []
                if isinstance(node, ast.Assign):
                    assignments = node.targets
                else:
                    assignments = [node.target]
                for target in assignments:
                    if isinstance(target, ast.Name):
                        targets.append(target.id)
                value = node.value
                if isinstance(value, ast.Call):
                    object_names.update(targets)
                alias_values.append((targets, value))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                # A nested scope can replace the binding after its import or
                # initialization; outer-scope lookup alone cannot prove it.
                self.mutated.update(node.names)
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                root = node.value
                while isinstance(root, (ast.Attribute, ast.Subscript)):
                    root = root.value
                if isinstance(root, ast.Name) and root.id not in {"self", "cls"}:
                    self.mutated.add(root.id)
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        self.dynamic_namespace = True
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {
                    "exec",
                    "eval",
                    "globals",
                    "locals",
                    "vars",
                    "__import__",
                }:
                    self.dynamic_namespace = True
                if node.func.id in {"setattr", "delattr"} and node.args:
                    root = node.args[0]
                    if isinstance(root, ast.Name):
                        self.mutated.add(root.id)
        for targets, value in alias_values:
            if self._immutable_projection(value):
                continue
            while isinstance(value, ast.Attribute):
                value = value.value
            if isinstance(value, ast.Name):
                for target in targets:
                    aliases.append((target, value.id))
        changed = True
        while changed:
            changed = False
            for left, right in aliases:
                if left in object_names or right in object_names:
                    before = len(object_names)
                    object_names.update((left, right))
                    changed = changed or len(object_names) != before
        # Passing an owned object/class to an unresolved callable can replace
        # its dispatch, including qualified/aliased setattr and patch helpers.
        for node in ast.walk(tree):
            values = []
            if isinstance(node, ast.Call):
                values.extend(node.args)
                for keyword in node.keywords:
                    values.append(keyword.value)
            elif isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
                values.append(node.value)
            elif isinstance(node, (*_FUNCTIONS, ast.Lambda)):
                values.extend(node.args.defaults)
                for default in node.args.kw_defaults:
                    if default is not None:
                        values.append(default)
            elif isinstance(node, ast.NamedExpr):
                values.append(node.value)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is not None and not isinstance(
                    node.value, (ast.Name, ast.Attribute)
                ):
                    values.append(node.value)
                if (
                    isinstance(self.scope(node), ast.ClassDef)
                    and node.value is not None
                ):
                    values.append(node.value)
                if isinstance(node, ast.Assign):
                    targets = node.targets
                else:
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        if node.value is not None:
                            values.append(node.value)
            for value in values:
                self.mutated.update(
                    _escaped_object_names(value, self._immutable_projection)
                    & object_names
                )
        changed = True
        while changed:
            changed = False
            for left, right in aliases:
                if left in self.mutated or right in self.mutated:
                    before = len(self.mutated)
                    self.mutated.update((left, right))
                    changed = changed or len(self.mutated) != before

    def _immutable_projection(self, node, depth=0):
        """An integer flag value does not expose its owning module object.

        This is the documented os.open flag contract, not a name-casing rule.
        Local providers, rebinding, mutation and unknown projections retain
        the ordinary escape behavior.
        """
        if (
            node is None
            or depth > 16
            or self.dynamic_namespace
            or self.custom_import_provider
        ):
            return False
        attributes = []
        while isinstance(node, ast.Attribute):
            attributes.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id in self.mutated:
            return False
        scope = self.scope(node)
        while True:
            bindings = self.bindings(scope).get(node.id, [])
            if bindings:
                if len(bindings) != 1 or bindings[0][2]:
                    return False
                binding, value, _conditional = bindings[0]
                if isinstance(binding, ast.Import):
                    qualified = value.name
                    if not value.asname:
                        qualified = qualified.split(".")[0]
                elif isinstance(binding, ast.ImportFrom):
                    if binding.level or not binding.module:
                        return False
                    qualified = binding.module + "." + value.name
                elif (
                    isinstance(binding, (ast.Assign, ast.AnnAssign)) and not attributes
                ):
                    return self._immutable_projection(value, depth + 1)
                else:
                    return False
                attributes.reverse()
                parts = qualified.split(".") + attributes
                if (
                    len(parts) != 2
                    or parts[0] != "os"
                    or parts[1] not in _IMMUTABLE_OS_FLAGS
                ):
                    return False
                return not project_local_provider("os", self.path, self.project_root)
            if scope is self.tree:
                return False
            scope = self.scope(scope)
            if isinstance(scope, ast.ClassDef):
                scope = self.scope(scope)

    def scope(self, node):
        parent = self.parents.get(node)
        while parent is not None:
            if isinstance(parent, _SCOPES):
                return parent
            parent = self.parents.get(parent)
        return self.tree

    def bindings(self, scope):
        if scope in self.binding_cache:
            return self.binding_cache[scope]
        result = {}

        def add(name, node, value=None, conditional=False):
            result.setdefault(name, []).append((node, value, conditional))

        if isinstance(scope, (*_FUNCTIONS, ast.Lambda)):
            args = scope.args
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                add(arg.arg, arg)
            for arg in [args.vararg, args.kwarg]:
                if arg is not None:
                    add(arg.arg, arg)

        def visit(node, conditional=False):
            if isinstance(node, _SCOPES):
                if hasattr(node, "name"):
                    add(node.name, node, conditional=conditional)
                # Defaults, annotations, decorators and class bases execute
                # in the enclosing scope, and may contain binding expressions.
                body_ids = set()
                body = getattr(node, "body", [])
                if isinstance(body, list):
                    for statement in body:
                        body_ids.add(id(statement))
                for child in ast.iter_child_nodes(node):
                    if id(child) not in body_ids:
                        visit(child, conditional)
                return
            branch = conditional or isinstance(node, _BRANCHES)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    add(alias.asname or alias.name.split(".")[0], node, alias, branch)
                return
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    add(alias.asname or alias.name, node, alias, branch)
                return
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                else:
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        add(target.id, node, node.value, branch)
                    else:
                        for child in ast.walk(target):
                            if isinstance(child, ast.Name) and isinstance(
                                child.ctx, ast.Store
                            ):
                                add(child.id, node, conditional=True)
                if node.value is not None:
                    visit(node.value, branch)
                return
            if isinstance(node, ast.ExceptHandler) and node.name:
                add(node.name, node, conditional=True)
            if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                add(node.name, node, conditional=True)
            if isinstance(node, ast.MatchMapping) and node.rest:
                add(node.rest, node, conditional=True)
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                add(node.id, node, conditional=True)
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    add(name, node, conditional=True)
            for child in ast.iter_child_nodes(node):
                visit(child, branch)

        body = getattr(scope, "body", [])
        if isinstance(body, list):
            for node in body:
                visit(node)
        self.binding_cache[scope] = result
        return result
