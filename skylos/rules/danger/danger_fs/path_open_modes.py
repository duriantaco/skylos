"""Bounded source-only mode values for built-in and bound ``open`` calls."""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.security.receiver_bindings import _Module


class PathOpenModes:
    """Resolve explicit modes without confusing an unknown value with ``r``.

    Only literals, conditional expressions and single dominating assignments
    establish values. Parameters, mutation and unsupported syntax stay unknown.
    This class does not establish that the callee itself is a filesystem API.
    """

    MAX_DEPTH = 16
    MAX_EXPRESSIONS = 128
    MAX_MODES = 16

    def __init__(self, tree, resolver=None):
        self.tree = tree
        if resolver is not None and resolver.main.tree is tree:
            self.module = resolver.main
        else:
            self.module = _Module(tree, Path("<path-open-modes>"), "")
        self.changed_scopes = set()
        self.changed_names = {}
        for node in ast.walk(tree):
            scope = self.module.scope(node)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"exec", "eval", "globals", "locals", "vars"}:
                    self.changed_scopes.add(scope)
                    if node.func.id in {"exec", "eval", "globals"}:
                        self.changed_scopes.add(tree)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        self.changed_scopes.add(scope)
            elif isinstance(node, ast.Global):
                for name in node.names:
                    self.changed_names.setdefault(tree, set()).add(name)
            elif isinstance(node, ast.Nonlocal):
                for name in node.names:
                    outer = self.module.scope(scope)
                    while outer is not tree:
                        if self.module.bindings(outer).get(name):
                            self.changed_names.setdefault(outer, set()).add(name)
                            break
                        outer = self.module.scope(outer)

    def _namespace_changed(self, scope):
        while True:
            if scope in self.changed_scopes:
                return True
            if scope is self.tree:
                return False
            scope = self.module.scope(scope)

    def _binding(self, node):
        scope = self.module.scope(node)
        while True:
            if self._namespace_changed(scope):
                return None
            if node.id in self.changed_names.get(scope, set()):
                return None
            bindings = self.module.bindings(scope).get(node.id, [])
            if bindings:
                if len(bindings) != 1:
                    return None
                binding, value, _ = bindings[0]
                if not isinstance(binding, (ast.Assign, ast.AnnAssign)):
                    return None
                if not self._dominates(binding, node):
                    return None
                return value
            if scope is self.tree:
                return None
            scope = self.module.scope(scope)
            if isinstance(scope, ast.ClassDef):
                scope = self.module.scope(scope)

    def _dominates(self, binding, node):
        """The assignment precedes this use in the same containing suite.

        An assignment inside an if/loop/try can establish a value for later
        statements in that exact branch. It establishes nothing after the
        branch, in its alternative, or in an exception handler.
        """
        owner = self.module.parents.get(binding)
        if owner is None:
            return False
        child = node
        while self.module.parents.get(child) is not owner:
            child = self.module.parents.get(child)
            if child is None:
                return False
        for _, suite in ast.iter_fields(owner):
            if not isinstance(suite, list):
                continue
            if binding not in suite or child not in suite:
                continue
            return suite.index(binding) < suite.index(child)
        return False

    def _literal_mode(self, value):
        if not isinstance(value, str) or not value or len(value) > 4:
            return None
        counts = {}
        for char in value:
            if char not in "rwaxbt+":
                return None
            counts[char] = counts.get(char, 0) + 1
            if counts[char] > 1:
                return None
        primary_count = 0
        for char in "rwax":
            primary_count += counts.get(char, 0)
        if primary_count != 1 or ("b" in counts and "t" in counts):
            return None
        return frozenset({value})

    def _values(self, node, budget, depth=0, active=frozenset(), *, resolve_names=True):
        budget[0] += 1
        if depth > self.MAX_DEPTH or budget[0] > self.MAX_EXPRESSIONS:
            return None
        if node in active:
            return None
        active = active | {node}
        if isinstance(node, ast.Constant):
            return self._literal_mode(node.value)
        if isinstance(node, ast.Name):
            if not resolve_names:
                return None
            value = self._binding(node)
            if value is None:
                return None
            return self._values(
                value, budget, depth + 1, active, resolve_names=resolve_names
            )
        if isinstance(node, ast.IfExp):
            left = self._values(
                node.body, budget, depth + 1, active, resolve_names=resolve_names
            )
            right = self._values(
                node.orelse, budget, depth + 1, active, resolve_names=resolve_names
            )
            if left is None or right is None:
                return None
            combined = left | right
            if len(combined) > self.MAX_MODES:
                return None
            return combined
        return None

    def modes(self, call, bound_method=False):
        """Return possible literal modes, or ``None`` for an explicit unknown.

        A missing mode alone defaults to ``r``. Consumers must handle unknown
        explicit modes as both possible read and write, never silently as read.
        A ``+`` mode permits both operations.
        """
        if not isinstance(call, ast.Call):
            return None
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                return None
        position = 1
        if bound_method:
            position = 0
        value = None
        expansion_seen = False
        resolve_names = True
        if len(call.args) > position:
            value = call.args[position]
        for keyword in call.keywords:
            if keyword.arg is None:
                expansion_seen = True
                continue
            if keyword.arg != "mode":
                continue
            if value is not None:
                return None
            value = keyword.value
            # A preceding mapping expansion can execute custom code before
            # this expression. Its values cannot replace an explicit mode,
            # but a later name load no longer proves its earlier assignment.
            resolve_names = not expansion_seen
        if value is None:
            if expansion_seen:
                return None
            return frozenset({"r"})
        return self._values(value, [0], resolve_names=resolve_names)
