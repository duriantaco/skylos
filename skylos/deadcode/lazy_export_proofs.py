"""Bounded evaluation of source-owned PEP 562 return paths.

Only literal tables/guards, assignments and actual import/getattr operations
are interpreted. No scanned code, import hook or user function is executed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.python_proofs import (
    _has_fromlist,
    _lazy_tables,
    _literal_strings,
    _provider_available,
    qualified_name,
    scope_bindings,
)


_UNKNOWN = object()
_CONTINUE = object()


@dataclass(frozen=True)
class _Module:
    name: str


@dataclass(frozen=True)
class _Export:
    target: str


def _candidate_names(tree, getter, parameter, tables):
    result = {name for entries in tables.values() for name in entries}
    literal_globals = {}
    counts = bound_names(tree.body).counts
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if (
                isinstance(target, ast.Name)
                and target.id == "__all__"
                and counts[target.id] == 1
            ):
                values = _literal_strings(statement.value)
                if values is not None:
                    literal_globals[target.id] = values
                    result.update(values)
    for node in ast.walk(getter):
        if not (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == parameter
            and len(node.ops) == len(node.comparators) == 1
        ):
            continue
        other = node.comparators[0]
        if (
            isinstance(node.ops[0], ast.Eq)
            and isinstance(other, ast.Constant)
            and isinstance(other.value, str)
        ):
            result.add(other.value)
        elif isinstance(node.ops[0], ast.In):
            result.update(_literal_strings(other) or ())
    return result, literal_globals


class _Lookup:
    def __init__(self, bindings, filename):
        self.bindings = bindings
        self.filename = filename

    def value(self, node, environment, depth=0):
        if depth > 24:
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return environment.get(node.id, _UNKNOWN)
        if isinstance(node, ast.Constant) and isinstance(
            node.value, (str, int, bool, type(None))
        ):
            return node.value
        if isinstance(node, ast.Subscript):
            values = self.value(node.value, environment, depth + 1)
            key = self.value(node.slice, environment, depth + 1)
            if isinstance(values, dict) and isinstance(key, str):
                return values.get(key, _UNKNOWN)
            return _UNKNOWN
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1
        ):
            left = self.value(node.left, environment, depth + 1)
            right = self.value(node.comparators[0], environment, depth + 1)
            if left is _UNKNOWN or right is _UNKNOWN:
                return _UNKNOWN
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.In) and isinstance(
                right, (set, tuple, list, dict)
            ):
                return left in right
        if not isinstance(node, ast.Call) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            return _UNKNOWN
        provider = qualified_name(node.func, self.bindings)
        builtin_import = (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and "__import__" not in self.bindings
        )
        if provider == "importlib.import_module" or builtin_import:
            if not node.args:
                return _UNKNOWN
            module = self.value(node.args[0], environment, depth + 1)
            if not isinstance(module, str) or not module or module.startswith("."):
                return _UNKNOWN
            if not builtin_import and not _provider_available(provider, self.filename):
                return _UNKNOWN
            if builtin_import and "." in module and not _has_fromlist(node):
                return _UNKNOWN
            return _Module(module)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and "getattr" not in self.bindings
            and len(node.args) == 2
            and not node.keywords
        ):
            module = self.value(node.args[0], environment, depth + 1)
            attribute = self.value(node.args[1], environment, depth + 1)
            if isinstance(module, _Module) and isinstance(attribute, str):
                return _Export(module.name + "." + attribute)
        return _UNKNOWN

    def assign(self, target, value, environment):
        if isinstance(target, ast.Name):
            environment[target.id] = value
            return True
        if (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, tuple)
            and len(target.elts) == len(value)
        ):
            for part, item in zip(target.elts, value):
                if not self.assign(part, item, environment):
                    return False
            return True
        return False

    def guarded_lookup(self, statement):
        if statement.orelse or statement.finalbody or not statement.handlers:
            return False
        for handler in statement.handlers:
            if (
                not isinstance(handler.type, ast.Name)
                or handler.type.id != "KeyError"
                or "KeyError" in self.bindings
                or len(handler.body) != 1
            ):
                return False
            raised = handler.body[0]
            if (
                not isinstance(raised, ast.Raise)
                or not isinstance(raised.exc, ast.Call)
                or not isinstance(raised.exc.func, ast.Name)
                or raised.exc.func.id != "AttributeError"
                or "AttributeError" in self.bindings
            ):
                return False
        return True

    def body(self, statements, environment, depth=0):
        if depth > 24:
            return _UNKNOWN
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                value = self.value(statement.value, environment)
                if value is _UNKNOWN or not self.assign(
                    statement.targets[0], value, environment
                ):
                    return _UNKNOWN
            elif isinstance(statement, ast.If):
                condition = self.value(statement.test, environment)
                if not isinstance(condition, bool):
                    return _UNKNOWN
                selected = statement.body if condition else statement.orelse
                value = self.body(selected, environment, depth + 1)
                if value is not _CONTINUE:
                    return value
            elif isinstance(statement, ast.Try) and self.guarded_lookup(statement):
                value = self.body(statement.body, environment, depth + 1)
                if value is not _CONTINUE:
                    return value
            elif isinstance(statement, ast.Return):
                return self.value(statement.value, environment)
            else:
                return _UNKNOWN
        return _CONTINUE


def proven_lazy_exports(tree, filename):
    getters = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "__getattr__"
    ]
    if len(getters) != 1 or bound_names(tree.body).counts["__getattr__"] != 1:
        return {}
    getter = getters[0]
    positional = getter.args.posonlyargs + getter.args.args
    if (
        len(positional) != 1
        or getter.args.vararg
        or getter.args.kwarg
        or getter.args.kwonlyargs
    ):
        return {}
    name = positional[0].arg
    bindings = scope_bindings(getter.body, scope_bindings(tree.body), getter.args)
    tables = _lazy_tables(tree)
    candidates, literal_globals = _candidate_names(tree, getter, name, tables)
    proof = _Lookup(bindings, filename)
    result = {}
    for candidate in sorted(candidates)[:512]:
        environment = dict(tables)
        environment.update(literal_globals)
        environment[name] = candidate
        returned = proof.body(getter.body, environment)
        if isinstance(returned, _Export):
            result[candidate] = returned.target
    return result
