"""Observed reads of exact handles opened with an update-capable mode.

A '+' grants read capability but does not establish that data is consumed.
This only adds evidence for a read operation; it never proves a path safe or
changes the existing write, readonly, or unknown-mode security checks.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.security.receiver_bindings import _Module

_READS = {"read", "read1", "readinto", "readinto1", "readline", "readlines"}
_CONSUMERS = {"next", "list", "tuple", "set", "sorted", "sum", "any", "all"}


class UpdateHandleReads:
    MAX_NODES = 100_000
    MAX_DEPTH = 16

    def __init__(self, tree, resolver=None):
        if resolver is not None and resolver.main.tree is tree:
            self.module = resolver.main
        else:
            self.module = _Module(tree, Path("<open-read-evidence>"), "")
        self.reads = {}
        self.cache = {}
        count = 0
        for node in ast.walk(tree):
            count += 1
            if count > self.MAX_NODES:
                self.reads = {}
                return
            expression = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in _READS:
                    expression = node.func.value
                elif isinstance(node.func, ast.Name) and node.func.id in _CONSUMERS:
                    if node.args and self._builtin(node.func):
                        expression = node.args[0]
            elif isinstance(node, ast.For):
                expression = node.iter
            elif isinstance(node, ast.comprehension):
                if not node.is_async and not self._inside_generator(node):
                    expression = node.iter
            if expression is not None:
                scope = self.module.scope(expression)
                self.reads.setdefault(scope, []).append(expression)

    def _inside_generator(self, node):
        parent = self.module.parents.get(node)
        while parent is not None:
            if isinstance(parent, ast.GeneratorExp):
                return True
            if isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                return False
            parent = self.module.parents.get(parent)
        return False

    def _builtin(self, node):
        if self.module.dynamic_namespace:
            return False
        scope = self.module.scope(node)
        while True:
            if self.module.bindings(scope).get(node.id):
                return False
            if scope is self.module.tree:
                return True
            scope = self.module.scope(scope)
            if isinstance(scope, ast.ClassDef):
                scope = self.module.scope(scope)

    def _dominates(self, binding, node):
        owner = self.module.parents.get(binding)
        if owner is None:
            return False
        child = node
        while self.module.parents.get(child) is not owner:
            child = self.module.parents.get(child)
            if child is None:
                return False
        for _, suite in ast.iter_fields(owner):
            if isinstance(suite, list) and binding in suite and child in suite:
                return suite.index(binding) < suite.index(child)
        return False

    def _within_with(self, node, item):
        owner = self.module.parents.get(item)
        child = node
        while self.module.parents.get(child) is not owner:
            child = self.module.parents.get(child)
            if child is None:
                return False
        return child in owner.body

    def _handle(self, node, call, depth=0, seen=frozenset()):
        if node is call:
            return True
        if depth >= self.MAX_DEPTH or node in seen:
            return False
        following = seen | {node}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "iter" and self._builtin(node.func):
                if len(node.args) == 1 and not node.keywords:
                    return self._handle(node.args[0], call, depth + 1, following)
        if not isinstance(node, ast.Name) or self.module.dynamic_namespace:
            return False
        scope = self.module.scope(node)
        bindings = self.module.bindings(scope).get(node.id, [])
        if len(bindings) != 1:
            return False
        binding, _, conditional = bindings[0]
        if isinstance(binding, ast.Name):
            item = self.module.parents.get(binding)
            if isinstance(item, ast.withitem) and item.optional_vars is binding:
                if self._within_with(node, item):
                    return self._handle(item.context_expr, call, depth + 1, following)
            return False
        if conditional or not isinstance(binding, (ast.Assign, ast.AnnAssign)):
            return False
        if not self._dominates(binding, node):
            return False
        return self._handle(binding.value, call, depth + 1, following)

    def observed(self, call):
        """Whether the same lexical handle has a demonstrated read operation."""
        if call not in self.cache:
            result = False
            scope = self.module.scope(call)
            for expression in self.reads.get(scope, []):
                if self._handle(expression, call):
                    result = True
                    break
            self.cache[call] = result
        return self.cache[call]
