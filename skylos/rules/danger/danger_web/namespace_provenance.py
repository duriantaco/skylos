"""Receiver isolation for XSS API-write checks under the normal data-input model.

Unknown external inputs retain the analyzer's native-data/API assumptions.
Visible constructors, callbacks, protocol changes and capability escapes do not.
This is deliberately not a general Python object-effect interpreter.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ..builtin_bindings import builtin_references
from ..module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from ..project_source import project_source_snapshot
from ..untrusted_sources import UntrustedSourceIndex

_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_REFLECTION = {
    "__class__",
    "__dict__",
    "__globals__",
    "__closure__",
    "__code__",
    "__wrapped__",
    "__annotations__",
    "__annotate__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__getattribute__",
    "__getattr__",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_back",
    "gi_frame",
    "cr_frame",
    "ag_frame",
    "tb_frame",
}
_PROTOCOLS = _REFLECTION | {
    "__setattr__",
    "__delattr__",
    "__new__",
    "__init__",
    "__hash__",
    "__eq__",
}
_DYNAMIC = {
    "globals",
    "locals",
    "vars",
    "getattr",
    "exec",
    "eval",
    "compile",
    "__import__",
}
_LOADERS = {
    "importlib",
    "importlib.import_module",
    "importlib.util",
    "importlib.machinery",
}
_MAX_STEPS = 50_000


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        if prefix:
            return prefix + "." + node.attr
    return None


def _generator_function(function):
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            stack.extend(ast.iter_child_nodes(node))
    return False


class _Unit:
    def __init__(self, tree, nodes):
        self.tree = tree
        self.nodes = nodes
        self.parents = {
            id(child): node
            for node in self.nodes
            for child in ast.iter_child_nodes(node)
        }
        self.imports = UntrustedSourceIndex(tree)
        self.bindings = {}
        self.annotations = set()
        self.builtins = builtin_references(
            tree,
            {"setattr", "delattr", "staticmethod", "classmethod", "property", "type"}
            | _DYNAMIC,
        )
        self.definitions = {
            node.name: node
            for node in self.nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.unsupported_calls = {
            node.name
            for node in self.nodes
            if isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef))
            or isinstance(node, ast.FunctionDef)
            and _generator_function(node)
        }
        for node in self.nodes:
            bound = []
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                bound = [
                    alias.asname or alias.name.split(".")[0] for alias in node.names
                ]
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bound = [node.name]
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                bound = node.names
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bound = [node.name]
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                bound = [node.name]
            elif isinstance(node, ast.MatchMapping) and node.rest:
                bound = [node.rest]
            for name in bound:
                self.bindings.setdefault((id(self.scope(node)), name), []).append(None)
            if isinstance(node, ast.arg):
                self.bindings.setdefault((id(self.scope(node)), node.arg), []).append(
                    None
                )
                if isinstance(node.annotation, (ast.Name, ast.Attribute)):
                    self.annotations.update(
                        id(part) for part in ast.walk(node.annotation)
                    )
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and isinstance(node.returns, (ast.Name, ast.Attribute)):
                self.annotations.update(id(part) for part in ast.walk(node.returns))
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                parent = self.parents.get(id(node))
                value = (
                    parent.value
                    if isinstance(parent, (ast.Assign, ast.AnnAssign))
                    else None
                )
                self.bindings.setdefault((id(self.scope(node)), node.id), []).append(
                    value
                )

    def scope(self, node):
        current = self.parents.get(id(node))
        while current is not None and not isinstance(current, _SCOPES):
            current = self.parents.get(id(current))
        return current or self.tree

    def origin(self, node):
        name = _dotted(node)
        if not name:
            return None
        scope = self.scope(node)
        return self.imports.resolved_import(
            scope
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            else None,
            name,
        )

    def binding(self, node):
        scope = self.scope(node)
        inside_function = False
        while scope is not None:
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inside_function = True
            if inside_function and isinstance(scope, ast.ClassDef):
                scope = self.scope(scope)
                continue
            values = self.bindings.get((id(scope), node.id))
            if values is not None:
                return scope, values
            scope = self.scope(scope) if scope is not self.tree else None
        return None, []


def _barrier(unit, path):
    if (
        has_mock_api_patching(unit.tree)
        or module_rebinding(unit.tree, module_name_for(path))[0]
    ):
        return True
    for node in unit.nodes:
        if isinstance(node, ast.Call):
            if not isinstance(node.func, (ast.Name, ast.Attribute)) or _factory_result(
                unit, node.func
            ):
                return True
        if isinstance(node, ast.GeneratorExp):
            return True
        if isinstance(node, ast.Lambda):
            parent = unit.parents.get(id(node))
            if not isinstance(parent, ast.Call) or parent.func is not node:
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if any(
                not isinstance(decorator, ast.Name)
                or id(decorator) not in unit.builtins
                or decorator.id not in {"staticmethod", "classmethod", "property"}
                for decorator in node.decorator_list
            ):
                return True
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _PROTOCOLS
        ):
            return True
        if isinstance(node, ast.Attribute) and node.attr in _PROTOCOLS:
            return True
        if isinstance(node, ast.Name) and node.id in _PROTOCOLS:
            return True
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in _DYNAMIC
            and id(node) in unit.builtins
        ):
            return True
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        if (
            isinstance(node, ast.Name)
            and node.id == "type"
            and (id(node) in unit.builtins or unit.binding(node)[0] is None)
        ):
            parent = unit.parents.get(id(node))
            if (
                id(node) not in unit.builtins
                or not isinstance(parent, ast.Call)
                or parent.func is not node
                or len(parent.args) != 1
                or parent.keywords
                or isinstance(parent.args[0], ast.Starred)
            ):
                return True
        referenced = node.id if isinstance(node, ast.Name) else node.attr
        parent = unit.parents.get(id(node))
        if (
            referenced in unit.unsupported_calls
            and isinstance(parent, ast.Call)
            and parent.func is node
        ):
            return True
        if referenced in unit.definitions:
            parent = unit.parents.get(id(node))
            if not (isinstance(parent, ast.Call) and parent.func is node):
                if id(node) not in unit.annotations or not isinstance(
                    unit.definitions[referenced], ast.ClassDef
                ):
                    return True
        origin = unit.origin(node)
        if (
            origin in _LOADERS
            or origin
            and origin.startswith(
                ("importlib.", "sys.path", "sys.meta_path", "sys.modules", "builtins.")
            )
        ):
            return True
        if origin in {
            "operator.attrgetter",
            "operator.methodcaller",
            "types.new_class",
        }:
            return True
        if not origin or origin.split(".")[0] not in {
            "argparse",
            "html",
            "markupsafe",
            "bleach",
        }:
            continue
        parent = unit.parents.get(id(node))
        if (
            origin in {"argparse", "argparse.Namespace"}
            and id(node) in unit.annotations
        ):
            scope = unit.scope(node)
            if (
                isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                and scope.decorator_list
            ):
                return True
            continue
        if origin == "argparse.Namespace":
            if (
                isinstance(parent, ast.Call)
                and parent.func is node
                and not parent.args
                and not parent.keywords
            ):
                continue
            return True
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and isinstance(parent.ctx, ast.Load)
        ):
            if origin == "argparse" and parent.attr != "Namespace":
                return True
            continue
        if isinstance(parent, ast.Call) and parent.func is node:
            if origin == "argparse.Namespace" and (parent.args or parent.keywords):
                return True
            continue
        return True
    return False


def _factory_result(unit, node, seen=None):
    if isinstance(node, ast.Attribute):
        return _factory_result(unit, node.value, seen)
    if isinstance(node, ast.Call):
        return True
    if not isinstance(node, ast.Name):
        return False
    owner, values = unit.binding(node)
    marker = (id(owner), node.id)
    seen = set() if seen is None else set(seen)
    if marker in seen or len(seen) >= 16:
        return True
    if len(values) > 1:
        return True
    if not values or values[0] is None:
        return False
    seen.add(marker)
    return _factory_result(unit, values[0], seen)


def _helper_reference(unit, node, function):
    if not isinstance(node, ast.Name) or node.id != function.name:
        return False
    owner, values = unit.binding(node)
    return owner is unit.scope(function) and len(values) == 1 and values[0] is None


def _data(expr, unit, function, budget, seen=None):
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, str):
            return expr.value not in _PROTOCOLS
        return type(expr.value) in {bytes, int, float, complex, bool, type(None)}
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return all(_data(item, unit, function, budget, seen) for item in expr.elts)
    if isinstance(expr, ast.Dict):
        return all(
            key is not None
            and _data(key, unit, function, budget, seen)
            and _data(value, unit, function, budget, seen)
            for key, value in zip(expr.keys, expr.values)
        )
    if not isinstance(expr, ast.Name):
        return False
    owner, values = unit.binding(expr)
    marker = (id(owner), expr.id)
    seen = set() if seen is None else set(seen)
    if marker in seen or len(values) != 1 or values[0] is None:
        return False
    seen.add(marker)
    aliases = {expr.id}
    for _ in range(16):
        before = len(aliases)
        for node in unit.nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                parent = unit.parents.get(id(node))
                if (
                    unit.scope(node) is owner
                    and isinstance(parent, (ast.Assign, ast.AnnAssign))
                    and isinstance(parent.value, ast.Name)
                    and parent.value.id in aliases
                ):
                    aliases.add(node.id)
        if len(aliases) == before:
            break
    else:
        return False
    for node in unit.nodes:
        if (
            not isinstance(node, ast.Name)
            or node.id not in aliases
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        binding_owner, _values = unit.binding(node)
        if binding_owner is not owner:
            continue
        parent = unit.parents.get(id(node))
        if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
            targets = (
                parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            )
            if all(
                isinstance(target, ast.Name) and target.id in aliases
                for target in targets
            ):
                continue
        if (
            isinstance(parent, ast.Call)
            and _helper_reference(unit, parent.func, function)
            and node in parent.args
        ):
            continue
        return False
    return _data(values[0], unit, function, budget, seen)


def _callers_are_data(function, units, budget):
    names = {function.name}
    for unit in units:
        for node in unit.nodes:
            if isinstance(node, ast.ImportFrom):
                names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == function.name
                )
    for unit in units:
        for node in unit.nodes:
            budget[0] -= 1
            if budget[0] < 0:
                return False
            if not (
                (
                    isinstance(node, ast.Name)
                    and node.id in names
                    and isinstance(node.ctx, ast.Load)
                )
                or (isinstance(node, ast.Attribute) and node.attr == function.name)
            ):
                continue
            parent = unit.parents.get(id(node))
            if (
                unit is not units[0]
                or not _helper_reference(unit, node, function)
                or not isinstance(parent, ast.Call)
                or parent.func is not node
                or not isinstance(unit.parents.get(id(parent)), ast.Expr)
            ):
                return False
            if (
                len(parent.args) != 1
                or parent.keywords
                or not _data(parent.args[0], unit, function, budget)
            ):
                return False
    return True


def _function_writes(function, unit, units, budget):
    """Accept one native-data merge shape; other statements retain uncertainty."""
    if (
        function.decorator_list
        or function.args.defaults
        or any(default is not None for default in function.args.kw_defaults)
        or function.args.vararg
        or function.args.kwarg
        or function.args.kwonlyargs
        or isinstance(unit.scope(function), ast.ClassDef)
    ):
        return set()
    parameters = function.args.posonlyargs + function.args.args
    if len(parameters) != 1:
        return set()
    data_name = parameters[0].arg
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if len(body) < 3:
        return set()
    first = body.pop(0)
    if not isinstance(first, (ast.Assign, ast.AnnAssign)):
        return set()
    targets = first.targets if isinstance(first, ast.Assign) else [first.target]
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return set()
    constructor = first.value
    if (
        not isinstance(constructor, ast.Call)
        or constructor.args
        or constructor.keywords
        or unit.origin(constructor.func) != "argparse.Namespace"
    ):
        return set()
    names = {targets[0].id}
    while len(body) > 2:
        alias = body.pop(0)
        if (
            not isinstance(alias, ast.Assign)
            or len(alias.targets) != 1
            or not isinstance(alias.targets[0], ast.Name)
            or not isinstance(alias.value, ast.Name)
            or alias.value.id not in names
        ):
            return set()
        if alias.targets[0].id in names:
            return set()
        names.add(alias.targets[0].id)
    if data_name in names:
        return set()
    loop, returned = body
    if (
        not isinstance(returned, ast.Return)
        or not isinstance(returned.value, ast.Name)
        or returned.value.id not in names
    ):
        return set()
    if (
        not isinstance(loop, ast.For)
        or loop.orelse
        or not isinstance(loop.target, (ast.Tuple, ast.List))
        or len(loop.target.elts) != 2
        or not all(isinstance(item, ast.Name) for item in loop.target.elts)
    ):
        return set()
    key, value = (item.id for item in loop.target.elts)
    if key == value or {key, value} & (names | {data_name}):
        return set()
    iterable = loop.iter
    if (
        not isinstance(iterable, ast.Call)
        or iterable.args
        or iterable.keywords
        or not isinstance(iterable.func, ast.Attribute)
        or iterable.func.attr != "items"
        or not isinstance(iterable.func.value, ast.Name)
        or iterable.func.value.id != data_name
    ):
        return set()
    if len(loop.body) != 1 or not isinstance(loop.body[0], ast.Expr):
        return set()
    writer = loop.body[0].value
    if (
        not isinstance(writer, ast.Call)
        or not isinstance(writer.func, ast.Name)
        or writer.func.id != "setattr"
        or id(writer.func) not in unit.builtins
        or len(writer.args) != 3
        or writer.keywords
    ):
        return set()
    if (
        not all(isinstance(arg, ast.Name) for arg in writer.args)
        or writer.args[0].id not in names
        or writer.args[1].id != key
        or writer.args[2].id != value
    ):
        return set()
    if not _callers_are_data(function, units, budget):
        return set()
    return {id(writer)}


def isolated_namespace_writes(tree, file_path, project_root):
    """Return only source-proven writer-call IDs; incomplete context proves none."""
    if (
        not isinstance(project_root, (str, Path))
        or not project_root
        or not isinstance(tree, ast.Module)
    ):
        return frozenset()
    try:
        current_nodes = []
        for node in ast.walk(tree):
            current_nodes.append(node)
            if len(current_nodes) > _MAX_STEPS:
                return frozenset()
        current = _Unit(tree, current_nodes)
        constructors = [
            node
            for node in current.nodes
            if isinstance(node, ast.Call)
            and current.origin(node.func) == "argparse.Namespace"
        ]
        if not constructors:
            return frozenset()
        path = Path(file_path).resolve()
        trees, complete = project_source_snapshot(project_root)
        if not complete or path not in trees or ast.dump(trees[path]) != ast.dump(tree):
            return frozenset()
        if any(
            member.name in {"argparse.py", "html.py", "markupsafe.py", "bleach.py"}
            or member.name == "__init__.py"
            and member.parent.name in {"argparse", "html", "markupsafe", "bleach"}
            for member in trees
        ):
            return frozenset()
        protected = {"argparse", "html", "markupsafe", "bleach"}
        root = Path(project_root).resolve()
        directories = {root}
        for member in trees:
            directories.update(
                parent
                for parent in member.parents
                if parent == root or root in parent.parents
            )
        metadata_steps = 0
        for directory in directories:
            for entry in directory.iterdir():
                metadata_steps += 1
                if (
                    metadata_steps > _MAX_STEPS
                    or entry.name.split(".", 1)[0].casefold() in protected
                ):
                    return frozenset()
        units = [current]
        count = len(current.nodes)
        for member, source in trees.items():
            if member == path:
                continue
            nodes = []
            for node in ast.walk(source):
                count += 1
                if count > _MAX_STEPS:
                    return frozenset()
                nodes.append(node)
            units.append(_Unit(source, nodes))
        definitions = {}
        unsupported_calls = set()
        for unit in units:
            definitions.update(unit.definitions)
            unsupported_calls.update(unit.unsupported_calls)
        for _ in range(16):
            before = (len(definitions), len(unsupported_calls))
            for unit in units:
                for node in unit.nodes:
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            if alias.name in definitions:
                                definitions[alias.asname or alias.name] = definitions[
                                    alias.name
                                ]
                            if alias.name in unsupported_calls:
                                unsupported_calls.add(alias.asname or alias.name)
            if (len(definitions), len(unsupported_calls)) == before:
                break
        else:
            return frozenset()
        for unit in units:
            unit.definitions = definitions
            unit.unsupported_calls = unsupported_calls
        if any(
            _barrier(unit, member)
            for unit, member in zip(
                units, [path] + [member for member in trees if member != path]
            )
        ):
            return frozenset()
        budget = [_MAX_STEPS]
        ignored = set()
        audited_functions = set()
        for node in current.nodes:
            if isinstance(node, ast.FunctionDef):
                writes = _function_writes(node, current, units, budget)
                if writes:
                    audited_functions.add(id(node))
                    ignored.update(writes)
        for unit in units:
            for node in unit.nodes:
                if (
                    isinstance(node, ast.Call)
                    and unit.origin(node.func) == "argparse.Namespace"
                ):
                    parent = unit.parents.get(id(node))
                    owner = unit.scope(node)
                    if (
                        unit is not current
                        or id(owner) not in audited_functions
                        or not isinstance(parent, (ast.Assign, ast.AnnAssign))
                        or unit.parents.get(id(parent)) is not owner
                    ):
                        return frozenset()
        for unit in units:
            names, computed = attribute_write_names(
                unit.tree,
                isolated_writes=frozenset(ignored) if unit is current else frozenset(),
            )
            if computed or names & {"escape", "clean", "Namespace"}:
                return frozenset()
        return frozenset(ignored)
    except (OSError, TypeError, ValueError, RecursionError, RuntimeError):
        return frozenset()
