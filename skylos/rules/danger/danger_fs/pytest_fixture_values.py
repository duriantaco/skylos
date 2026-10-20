"""Straight-line values and effects for proven temporary fixture paths."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from skylos.analysis.ast_cache import run_memo
from skylos.rules.danger.danger_fs.pytest_paths import _relative_path, _resolved
from skylos.rules.danger.danger_fs.pytest_fixture_bindings import (
    binding_escapes,
    provider_namespace_stable,
)
from skylos.rules.danger.danger_fs.pytest_fixture_context import pytest_imports
from skylos.security.receiver_resolution import ReceiverResolver

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_PATH_METHODS = {
    "write_text",
    "write_bytes",
    "read_text",
    "read_bytes",
    "open",
    "stat",
    "exists",
    "is_file",
    "is_dir",
    "mkdir",
    "unlink",
    "rmdir",
}


@dataclass
class FixturePathEvidence:
    paths: set[ast.AST] = field(default_factory=set)
    unsafe: set[ast.AST] = field(default_factory=set)
    parameters: dict[ast.AST, set[str]] = field(default_factory=dict)


def _parameters(function):
    return [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]


def _imports(tree):
    result = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(statement, ast.ImportFrom) and not statement.level:
            for alias in statement.names:
                result[alias.asname or alias.name] = (
                    (statement.module or "") + "." + alias.name
                )
    # An imported constructor that is rebound anywhere is not evidence.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            result.pop(node.id, None)
        elif isinstance(node, ast.arg):
            result.pop(node.arg, None)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            result.pop(node.name, None)
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                result.pop(root.id, None)
    return result


class _FunctionPaths:
    """Small straight-line value model; unsupported control flow loses proof."""

    def __init__(
        self,
        tree,
        function,
        parameters,
        evidence,
        literals=(),
        *,
        file_path,
        project_root,
        preserve_opaque_calls=False,
    ):
        self.imports = run_memo(("fixture-imports", id(tree)), lambda: _imports(tree))
        self.tree = tree
        self.resolver = run_memo(
            ("fixture-receiver", id(tree), str(file_path), str(project_root)),
            lambda: ReceiverResolver(tree, file_path, project_root=project_root),
        )
        self.file_path = file_path
        self.project_root = project_root
        self.call_depth = 0
        self.preserve_opaque_calls = preserve_opaque_calls
        self.explicit_mutation = False
        self.mutating_helpers = set()
        self.helper_proofs = {}
        self.constructor_proofs = {}
        self.pytest_imports = run_memo(
            ("fixture-pytest-imports", id(tree)), lambda: pytest_imports(tree)
        )
        self.module_bindings = set()
        for statement in tree.body:
            if isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
                self.module_bindings.add(statement.name)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                else:
                    targets = [statement.target]
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name):
                            self.module_bindings.add(name.id)
        self.env = dict(parameters)
        self.function = function
        self.evidence = evidence
        self.literals = set(literals)
        self.lost_names = set()

    def value(self, node):
        if node is None:
            return None
        kind = None
        derived = False
        if isinstance(node, ast.Name):
            kind = self.env.get(node.id)
            if kind == "outside_path":
                derived = True
            if kind is None and node.id in self.lost_names:
                derived = True
            if node.id in self.literals:
                kind = "relative"
        elif isinstance(node, ast.Constant):
            if _relative_path(node):
                kind = "relative"
        elif isinstance(node, ast.Attribute):
            receiver = self.value(node.value)
            if receiver in {"path", "factory"} or node.value in self.evidence.unsafe:
                derived = True
                if receiver in {"path", "outside_path"} and node.attr == "parent":
                    kind = "outside_path"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self.value(node.left)
            right = self.value(node.right)
            if left == "path":
                derived = True
                if right == "relative":
                    kind = "path"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = self.imports.get(node.func.id, node.func.id)
                if (
                    name in {"str", "pathlib.Path", "pathlib.PosixPath"}
                    and len(node.args) == 1
                    and not node.keywords
                ):
                    if name == "str":
                        if self._bound_name("str") or not provider_namespace_stable(
                            self.tree, "builtins", "str"
                        ):
                            return None
                    if name != "str" and not self._path_constructor(node):
                        return None
                    argument = self.value(node.args[0])
                    if argument == "path":
                        kind = "path"
                else:
                    trusted_helper, returned = self._local_helper(node)
                    if trusted_helper:
                        kind = returned
                        if returned is None or returned == "outside_path":
                            derived = True
            elif isinstance(node.func, ast.Attribute):
                receiver = self.value(node.func.value)
                if receiver == "factory" and node.func.attr == "mktemp":
                    derived = True
                    if (
                        len(node.args) == 1
                        and not node.keywords
                        and _relative_path(node.args[0])
                    ):
                        kind = "path"
                elif receiver == "path" and node.func.attr == "joinpath":
                    derived = True
                    if node.args and not node.keywords:
                        kind = "path"
                        for argument in node.args:
                            if self.value(argument) != "relative":
                                kind = None
                elif receiver == "path":
                    derived = node.func.attr not in _PATH_METHODS
            # Inspect nested operands even when the enclosing call has no path result.
            for argument in node.args:
                self.value(argument)
            for keyword in node.keywords:
                self.value(keyword.value)
        elif isinstance(node, ast.expr):
            aggregate = isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict))
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    child_kind = self.value(child)
                    if (
                        child_kind in {"path", "factory", "aggregate"}
                        or child in self.evidence.unsafe
                    ):
                        derived = True
                        if aggregate:
                            kind = "aggregate"
        if kind == "path":
            self.evidence.paths.add(node)
        elif derived:
            self.evidence.unsafe.add(node)
        return kind

    def _bound_name(self, name):
        if name in self.imports or name in self.module_bindings:
            return True
        for node in ast.walk(self.function):
            if isinstance(node, ast.arg) and node.arg == name:
                return True
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id == name
            ):
                return True
        return False

    def _path_constructor(self, call):
        if call in self.constructor_proofs:
            return self.constructor_proofs[call]
        root = call.func
        while isinstance(root, ast.Attribute):
            root = root.value
        allowed = False
        if (
            isinstance(root, ast.Name)
            and not binding_escapes(self.tree, root.id)
            and provider_namespace_stable(self.tree, "pathlib", "Path")
        ):
            proof = self.resolver.resolve_call(call)
            if (
                proof.get("status") == "resolved"
                and proof.get("effects", {}).get("filesystem") == "path_receiver"
            ):
                allowed = True
        self.constructor_proofs[call] = allowed
        return allowed

    def _local_helper(self, call):
        if call in self.helper_proofs:
            return self.helper_proofs[call]
        self.helper_proofs[call] = False, None
        if self.call_depth >= 4 or not isinstance(call.func, ast.Name) or call.keywords:
            return False, None
        name = call.func.id
        if name == self.function.name or binding_escapes(self.tree, name):
            return False, None
        helper = None
        for statement in self.tree.body:
            if isinstance(statement, ast.FunctionDef) and statement.name == name:
                if helper is not None:
                    return False, None
                helper = statement
        if (
            helper is None
            or helper.decorator_list
            or helper.args.vararg
            or helper.args.kwarg
        ):
            return False, None
        arguments = _parameters(helper)
        if len(arguments) != len(call.args):
            return False, None
        proof = self.resolver.resolve_call(call)
        if (
            proof.get("status") != "resolved"
            or proof.get("file") != str(self.file_path)
            or proof.get("line") != helper.lineno
        ):
            return False, None
        parameters = {}
        has_owned_path = False
        for parameter, argument in zip(arguments, call.args):
            kind = self.value(argument)
            if kind is not None:
                parameters[parameter.arg] = kind
                if kind in {"path", "factory", "aggregate"}:
                    has_owned_path = True
        if not has_owned_path:
            return False, None
        model = _FunctionPaths(
            self.tree,
            helper,
            parameters,
            FixturePathEvidence(),
            file_path=self.file_path,
            project_root=self.project_root,
        )
        model.call_depth = self.call_depth + 1
        returned = model.run()
        if model.explicit_mutation:
            self.mutating_helpers.add(call)
        trusted = not model.lost_names
        self.helper_proofs[call] = trusted, returned
        return trusted, returned

    def _escapes(self, expression):
        for call in ast.walk(expression):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Attribute):
                receiver = self.value(call.func.value)
                if receiver == "path" and call.func.attr in _PATH_METHODS:
                    continue
                if receiver == "factory" and call.func.attr == "mktemp":
                    continue
                if receiver == "outside_path" and call.func.attr in {
                    "exists",
                    "stat",
                    "lstat",
                    "is_file",
                    "is_dir",
                    "is_symlink",
                    "readlink",
                    # Creating an ancestor does not remove, redirect or make
                    # an existing private temporary directory writable.
                    "mkdir",
                }:
                    continue
                if receiver in {"path", "factory", "outside_path"}:
                    self.explicit_mutation = True
                    return True
                if call.func.value in self.evidence.unsafe:
                    self.explicit_mutation = True
                    return True
            if isinstance(call.func, ast.Name):
                name = self.imports.get(call.func.id, call.func.id)
                if (
                    name in {"str", "open"}
                    and not self._bound_name(call.func.id)
                    and provider_namespace_stable(self.tree, "builtins", name)
                ):
                    continue
                if name in {
                    "pathlib.Path",
                    "pathlib.PosixPath",
                } and self._path_constructor(call):
                    continue
                trusted_helper, _returned = self._local_helper(call)
                if trusted_helper:
                    continue
                if call in self.mutating_helpers:
                    self.explicit_mutation = True
                    return True
            arguments = list(call.args)
            for keyword in call.keywords:
                arguments.append(keyword.value)
            for argument in arguments:
                if (
                    self.value(argument) in {"path", "factory", "aggregate"}
                    or argument in self.evidence.unsafe
                ):
                    if not self.preserve_opaque_calls:
                        return True
        return False

    def run(self, statements=None):
        returned = None
        if statements is None:
            statements = self.function.body
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                kind = self.value(value)
                escapes = self._escapes(value)
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                else:
                    targets = [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.env.pop(target.id, None)
                        if kind is not None:
                            self.env[target.id] = kind
                    elif kind in {"path", "factory", "aggregate"}:
                        escapes = True
                if escapes:
                    self._lose_paths()
            elif isinstance(statement, ast.Expr):
                self.value(statement.value)
                if self._escapes(statement.value):
                    self._lose_paths()
            elif isinstance(statement, ast.Return):
                returned = self.value(statement.value)
                if statement.value is not None and self._escapes(statement.value):
                    self._lose_paths()
                    returned = None
                break
            elif isinstance(statement, ast.Assert):
                self.value(statement.test)
                if self._escapes(statement.test):
                    self._lose_paths()
            elif isinstance(statement, ast.With):
                supported = True
                for item in statement.items:
                    self.value(item.context_expr)
                    call = item.context_expr
                    if not isinstance(call, ast.Call):
                        supported = False
                    elif isinstance(call.func, ast.Name):
                        if call.func.id != "open" or self._bound_name("open"):
                            supported = False
                    elif isinstance(call.func, ast.Attribute):
                        qualified = _resolved(call.func, self.pytest_imports)
                        if qualified in {
                            "pytest.raises",
                            "pytest.warns",
                            "pytest.deprecated_call",
                        }:
                            continue
                        if (
                            call.func.attr != "open"
                            or self.value(call.func.value) != "path"
                        ):
                            supported = False
                    else:
                        supported = False
                    if item.optional_vars is not None:
                        for target in ast.walk(item.optional_vars):
                            if isinstance(target, ast.Name):
                                self.env.pop(target.id, None)
                if not supported:
                    self._lose_paths()
                self.run(statement.body)
            else:
                # Branches, generators, context-manager binding and nested code
                # require another value model. Never assume the old bindings survive.
                self._lose_paths()
        return returned

    def _lose_paths(self):
        for name, kind in self.env.items():
            if kind in {"path", "factory", "aggregate", "outside_path"}:
                self.lost_names.add(name)
        self.env.clear()
