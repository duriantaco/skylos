"""Narrow proof for pickle bytes produced from built-in data in this scope.

Unknown objects may define reduction hooks, so dumps(anything) is not a safety
proof. Attributes, external bytes, cross-function state and mutable data aliases
remain review candidates. No target code or pickle bytecode is executed.
"""

from __future__ import annotations

import ast

from .module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from .untrusted_sources import UntrustedSourceIndex

_UNKNOWN = 0
_DATA = 1
_PICKLED = 2
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_TRY = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


class _RoundTrips:
    def __init__(self, tree, file_path):
        self.imports = UntrustedSourceIndex(tree)
        self.safe = set()
        self.scope = None
        self.env = {}
        writes, computed = attribute_write_names(tree)
        dynamic, _ = module_rebinding(tree, module_name_for(file_path))
        self.uncertain = (
            computed
            or dynamic
            or bool(writes & {"dumps", "loads"})
            or has_mock_api_patching(tree)
        )

    def imported(self, call, name):
        dotted = _dotted(call.func)
        return bool(
            not self.uncertain
            and dotted
            and self.imports.resolved_import(self.scope, dotted) == name
        )

    def value(self, node):
        if isinstance(node, ast.Constant):
            return (
                _DATA
                if type(node.value)
                in {str, bytes, int, float, complex, bool, type(None)}
                else _UNKNOWN
            )
        if isinstance(node, ast.Name):
            return self.env.get(node.id, _UNKNOWN)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return (
                _DATA
                if all(self.value(item) == _DATA for item in node.elts)
                else _UNKNOWN
            )
        if isinstance(node, ast.Dict):
            return (
                _DATA
                if all(
                    key is not None
                    and self.value(key) == _DATA
                    and self.value(value) == _DATA
                    for key, value in zip(node.keys, node.values)
                )
                else _UNKNOWN
            )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            return self.value(node.operand)
        if isinstance(node, ast.IfExp):
            left, right = self.value(node.body), self.value(node.orelse)
            return left if left == right else _UNKNOWN
        if isinstance(node, ast.Call):
            if (
                self.imported(node, "pickle.dumps")
                and node.args
                and self.value(node.args[0]) == _DATA
            ):
                # Callbacks and unknown options cannot support a proof.
                if all(isinstance(arg, ast.Constant) for arg in node.args[1:]) and all(
                    kw.arg in {"protocol", "fix_imports", "buffer_callback"}
                    and isinstance(kw.value, ast.Constant)
                    and (kw.arg != "buffer_callback" or kw.value.value is None)
                    for kw in node.keywords
                ):
                    return _PICKLED
        return _UNKNOWN

    def immutable_data(self, node):
        if isinstance(node, (ast.Constant, ast.Name)):
            return self.value(node) == _DATA
        if isinstance(node, ast.Tuple):
            return all(self.immutable_data(item) for item in node.elts)
        if isinstance(node, ast.UnaryOp):
            return self.immutable_data(node.operand)
        return False

    def expressions(self, node):
        if node is None or isinstance(node, _SCOPES):
            return
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            for part in ast.walk(node):
                if isinstance(part, ast.NamedExpr):
                    self.assign(part.target, _UNKNOWN)
            return
        if isinstance(node, ast.NamedExpr):
            self.expressions(node.value)
            self.assign(node.target, _UNKNOWN)
            return
        if isinstance(node, ast.Call) and self.imported(node, "pickle.loads"):
            if node.args and self.value(node.args[0]) == _PICKLED:
                # Unknown reducers / buffers passed to loads are not needed here.
                if not node.keywords and len(node.args) == 1:
                    self.safe.add(id(node))
        for child in ast.iter_child_nodes(node):
            self.expressions(child)

    def assign(self, target, kind):
        if isinstance(target, ast.Name):
            self.env[target.id] = kind
        elif isinstance(target, (ast.Tuple, ast.List)):
            for part in target.elts:
                self.assign(part, _UNKNOWN)

    def block(self, body):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for expression in [
                    *node.decorator_list,
                    *node.args.defaults,
                    *node.args.kw_defaults,
                ]:
                    self.expressions(expression)
                saved_scope, saved_env = self.scope, self.env
                self.scope, self.env = node, {}
                if not any(
                    isinstance(part, (ast.Global, ast.Nonlocal))
                    for part in ast.walk(node)
                ):
                    self.block(node.body)
                self.scope, self.env = saved_scope, saved_env
                self.env.pop(node.name, None)
            elif isinstance(node, ast.ClassDef):
                for expression in [*node.decorator_list, *node.bases, *node.keywords]:
                    self.expressions(expression)
                saved = self.env
                self.env = {}
                # Class namespace bindings are separate from lexical function
                # globals. Only methods have a supported import scope here.
                self.block([part for part in node.body if isinstance(part, _SCOPES)])
                self.env = saved
                self.env.pop(node.name, None)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self.expressions(node.value)
                kind = self.value(node.value)
                # Mutable data containers may change via aliases or arbitrary calls.
                # Their inline use is provable; only immutable local values persist.
                if kind == _DATA and not self.immutable_data(node.value):
                    kind = _UNKNOWN
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    self.assign(target, kind)
            elif isinstance(node, ast.If):
                self.expressions(node.test)
                before = self.env.copy()
                self.block(node.body)
                left = self.env.copy()
                self.env = before.copy()
                self.block(node.orelse)
                self.env = {
                    key: value
                    for key, value in left.items()
                    if self.env.get(key) == value
                }
            elif isinstance(
                node,
                (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Match)
                + _TRY,
            ):
                # Repeated/exceptional paths cannot establish a definite assignment.
                self.env = {}
                for field, value in ast.iter_fields(node):
                    if field in {"body", "orelse", "finalbody"}:
                        self.env = {}
                        self.block(value)
                    elif field == "handlers":
                        for handler in value:
                            self.env = {}
                            self.block(handler.body)
                    elif field == "cases":
                        for case in value:
                            self.env = {}
                            self.expressions(case.guard)
                            self.block(case.body)
                    elif isinstance(value, ast.AST):
                        self.expressions(value)
                self.env = {}
            else:
                self.expressions(node)
                if isinstance(node, (ast.AugAssign, ast.NamedExpr)):
                    self.assign(node.target, _UNKNOWN)
                elif isinstance(node, ast.Delete):
                    for target in node.targets:
                        self.assign(target, _UNKNOWN)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        self.env.pop(alias.asname or alias.name.split(".")[0], None)


def safe_pickle_loads(tree: ast.AST, file_path=None) -> set[int]:
    """Call ids whose input is a local built-in-data serialization round-trip."""
    if not any(
        (
            isinstance(node, ast.Import)
            and any(alias.name == "pickle" for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.module == "pickle"
            and not node.level
        )
        for node in ast.walk(tree)
    ):
        return set()
    checker = _RoundTrips(tree, file_path)
    checker.block(getattr(tree, "body", []))
    return checker.safe
