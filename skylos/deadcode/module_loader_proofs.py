"""Finite module execution effects from reachable source-owned loaders.

Import metadata alone does not execute a module. A file-loader contract must
join the path, spec, created module and the very same loader's exec_module.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.python_project_sources import (
    Function,
    ProjectSourceIndex,
    Symbol,
    alternatives,
    merge,
)
from skylos.deadcode.python_proofs import (
    _provider_available,
    qualified_name,
    scope_bindings,
)


@dataclass(frozen=True)
class LoadedModule:
    path: Path


_INVALID_CALL = object()
_NO_VALUE = object()


def _supplied_arguments(function, arguments, keywords):
    signature = function.node.args
    positional = [*signature.posonlyargs, *signature.args]
    if positional and positional[0].arg == "self" and "self" in function.closure:
        positional = positional[1:]
    declared = {argument.arg for argument in [*positional, *signature.kwonlyargs]}
    if len(arguments) > len(positional) and signature.vararg is None:
        return None
    if set(keywords) - declared and signature.kwarg is None:
        return None
    if any(argument.arg in keywords for argument in signature.posonlyargs):
        return None
    supplied = dict(zip((argument.arg for argument in positional), arguments))
    if set(supplied).intersection(keywords):
        return None
    supplied.update(keywords)
    defaulted = (
        {argument.arg for argument in positional[-len(signature.defaults) :]}
        if signature.defaults
        else set()
    )
    defaulted.update(
        argument.arg
        for argument, default in zip(signature.kwonlyargs, signature.kw_defaults)
        if default is not None
    )
    if declared - set(supplied) - defaulted:
        return None
    return supplied


def _loader_contract(function, tree):
    node = function.node
    if node.decorator_list or node.args.vararg or node.args.kwarg:
        return None
    parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    parameter_names = {parameter.arg for parameter in parameters}
    bindings = scope_bindings(node.body, scope_bindings(tree.body), node.args)
    counts = bound_names(node.body).counts
    specs = {}
    modules = {}
    for statement in node.body:
        if isinstance(statement, (ast.Return, ast.Raise)):
            break
        if isinstance(
            statement, (ast.If, ast.Try, ast.For, ast.While, ast.With, ast.AsyncWith)
        ):
            return None
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target = statement.targets[0].id
            value = statement.value
            if counts[target] != 1 or not isinstance(value, ast.Call):
                continue
            provider = qualified_name(value.func, bindings)
            if (
                provider == "importlib.util.spec_from_file_location"
                and len(value.args) == 2
                and not value.keywords
            ):
                path = value.args[1]
                if (
                    isinstance(path, ast.Name)
                    and path.id in parameter_names
                    and counts[path.id] == 0
                    and _provider_available("importlib", str(function.path))
                ):
                    specs[target] = path.id
            elif (
                provider == "importlib.util.module_from_spec"
                and len(value.args) == 1
                and not value.keywords
            ):
                spec = value.args[0]
                if isinstance(spec, ast.Name) and spec.id in specs:
                    modules[target] = spec.id
        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, ast.Call
        ):
            continue
        call = statement.value
        if not (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "exec_module"
            and len(call.args) == 1
            and not call.keywords
        ):
            continue
        loader = call.func.value
        module = call.args[0]
        if not (
            isinstance(loader, ast.Attribute)
            and loader.attr == "loader"
            and isinstance(loader.value, ast.Name)
            and isinstance(module, ast.Name)
        ):
            continue
        spec_name = loader.value.id
        if modules.get(module.id) != spec_name:
            continue
        protected = {spec_name, module.id}
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                base = child.value
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name) and base.id in protected:
                    return None
            if isinstance(child, ast.Call) and child is not call:
                if (
                    qualified_name(child.func, bindings)
                    == "importlib.util.module_from_spec"
                ):
                    continue
                passed = [*child.args, *(keyword.value for keyword in child.keywords)]
                if any(
                    isinstance(value, ast.Name) and value.id in protected
                    for argument in passed
                    for value in ast.walk(argument)
                ):
                    return None
                if child.lineno < statement.lineno and any(
                    (qualified_name(value, bindings) or "") == "importlib"
                    or (qualified_name(value, bindings) or "").startswith("importlib.")
                    for argument in passed
                    for value in ast.walk(argument)
                    if isinstance(value, (ast.Name, ast.Attribute))
                ):
                    return None
        returned = False
        for following in node.body:
            if following.lineno <= statement.lineno:
                continue
            if isinstance(following, ast.Return):
                returned = (
                    isinstance(following.value, ast.Name)
                    and following.value.id == module.id
                )
                break
            if isinstance(following, (ast.Raise, ast.If, ast.Try, ast.For, ast.While)):
                break
        return specs[spec_name], returned
    return None


def _providers_intact(index, function, tree):
    expected = {
        "importlib.util.spec_from_file_location",
        "importlib.util.module_from_spec",
    }
    bindings = scope_bindings(
        function.node.body, scope_bindings(tree.body), function.node.args
    )
    local = dict(function.closure)
    found = set()
    for statement in function.node.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            local.update(index.import_bindings(statement, function.path))
        if not isinstance(statement, ast.Assign) or not isinstance(
            statement.value, ast.Call
        ):
            continue
        provider = qualified_name(statement.value.func, bindings)
        if provider not in expected:
            continue
        value = index.evaluate(statement.value.func, function.path, local)
        if not isinstance(value, Symbol) or value.name != provider or value.invalid:
            return False
        found.add(provider)
    return found == expected


class ModuleExecutionProof:
    def __init__(self, report):
        self.report = report
        self.index = ProjectSourceIndex(report.project_root, report.index.modules)
        self.index.observer = self.observe
        self.loaded = set()
        self.effects = {}
        self.call_stack = []
        self.receivers = {}
        self.source_called = set()
        self.contracts = {}
        self.owners = {}
        self.keys = {}
        for path, module in report.index.modules.items():
            functions = [
                node
                for node in ast.walk(module.tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            self.owners[path] = sorted(
                functions, key=lambda node: node.end_lineno - node.lineno
            )
            for node in functions:
                key = report.index.by_location.get((path, node.lineno))
                if key is None:
                    names = list(module.names)
                    if len(names) == 1:
                        owner = names[0]
                        parents = [
                            parent
                            for parent in functions
                            if parent is not node
                            and parent.lineno < node.lineno <= parent.end_lineno
                        ]
                        owner += (
                            "."
                            + ".".join(
                                parent.name
                                for parent in sorted(
                                    parents, key=lambda item: item.lineno
                                )
                            )
                            if parents
                            else ""
                        )
                        key = owner + "." + node.name
                self.keys[path, node.lineno] = key

    def owner(self, path, line):
        for node in self.owners.get(path, ()):
            if node.lineno <= line <= node.end_lineno:
                return self.keys.get((path, node.lineno))
        return None

    def _paths(self, value):
        paths = set()
        for item in alternatives(value):
            if not isinstance(item, (str, Path)):
                continue
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = self.report.project_root / candidate
            try:
                if any(
                    part.is_symlink()
                    for part in [candidate, *candidate.parents]
                    if part != self.report.project_root
                ):
                    continue
                candidate = candidate.resolve()
                candidate.relative_to(self.report.project_root)
            except (OSError, ValueError):
                continue
            if candidate in self.report.index.modules:
                paths.add(candidate)
        return paths

    def observe(self, node, path, bindings, callee, arguments, keywords):
        owner = self.owner(path, node.lineno)
        if (
            owner
            and owner not in self.report.proven_reachable_keys
            and owner not in self.source_called
        ):
            return None
        if isinstance(callee, Function):
            self.index.initialize_module(callee.path)
            supplied = _supplied_arguments(callee, arguments, keywords)
            if supplied is None:
                return _INVALID_CALL
            key = self.keys.get((callee.path, callee.node.lineno))
            if key:
                self.source_called.add(key)
                for name, value in supplied.items():
                    if name in bound_names(callee.node.body).counts:
                        continue
                    for item in alternatives(value):
                        if isinstance(item, LoadedModule):
                            self.receivers.setdefault((key, name), set()).add(item.path)
            identity = (callee.path, callee.node.lineno)
            if identity not in self.contracts:
                tree = self.index.trees.get(callee.path)
                contract = _loader_contract(callee, tree) if tree is not None else None
                if contract is not None and not _providers_intact(
                    self.index, callee, tree
                ):
                    contract = None
                self.contracts[identity] = contract
            contract = self.contracts[identity]
            if contract is not None:
                parameter, returns_module = contract
                files = self._paths(supplied.get(parameter))
                self._loaded_at(files, path, owner, node.lineno)
                if returns_module:
                    modules = []
                    for candidate in files:
                        modules.append(LoadedModule(candidate))
                    return merge(modules)
            self.call_stack.append((path, owner or "", node.lineno))
            try:
                value = self.index.call(callee, arguments, keywords)
            finally:
                self.call_stack.pop()
            if value is None:
                return _NO_VALUE
            return value
        if (
            isinstance(callee, Symbol)
            and callee.name == "importlib.import_module"
            and arguments
            and _provider_available("importlib", str(path))
        ):
            loaded = set()
            for name in alternatives(arguments[0]):
                if isinstance(name, str):
                    candidate = self.index.modules.get(name)
                    if candidate is not None:
                        loaded.add(candidate)
            self._loaded_at(loaded, path, owner, node.lineno)
            modules = []
            for candidate in loaded:
                modules.append(LoadedModule(candidate))
            return merge(modules)
        return None

    def _loaded_at(self, files, path, owner, line):
        self.loaded.update(files)
        for site in [*self.call_stack, (path, owner or "", line)]:
            self.effects.setdefault(site, set()).update(files)

    def loaded_before(self, path, owner, line):
        result = set()
        for (effect_path, effect_owner, effect_line), files in self.effects.items():
            if effect_path == path and effect_owner == owner and effect_line < line:
                result.update(files)
        return result

    def collect(self, discovery_owners=()):
        list(self.index.contexts())
        needed = set(discovery_owners)
        for path, functions in self.owners.items():
            for node in functions:
                key = self.keys.get((path, node.lineno))
                if key not in needed:
                    continue
                for parent in functions:
                    if parent.lineno < node.lineno <= parent.end_lineno:
                        needed.add(self.keys.get((path, parent.lineno)))
        graph = getattr(self.report, "graph", None)
        if graph is not None:
            for _ in range(32):
                parents = {
                    owner
                    for owner, callees in graph.edges.items()
                    if needed.intersection(callees)
                }
                if parents <= needed:
                    break
                needed.update(parents)
        # These owners have actual source callers and no input arguments.
        # A startup budget must not change the answer for a later such call.
        needed.discard(None)
        for key in sorted(needed):
            if key not in self.report.proven_reachable_keys:
                continue
            definition = self.report.index.candidates.get(key)
            node = getattr(definition, "node", None)
            if not isinstance(node, ast.FunctionDef):
                continue
            args = node.args
            if (
                args.posonlyargs
                or args.args
                or args.kwonlyargs
                or args.vararg
                or args.kwarg
            ):
                continue
            path = Path(definition.filename).resolve()
            source_node = next(
                (
                    function
                    for function in self.index.trees.get(
                        path, ast.Module(body=[], type_ignores=[])
                    ).body
                    if isinstance(function, ast.FunctionDef)
                    and function.lineno == node.lineno
                ),
                None,
            )
            if source_node is None:
                continue
            self.index.budget = 0
            self.index.total_steps = 0
            self.index.owner_steps = 0
            self.source_called.add(key)
            self.index.call(Function(path, source_node), [], {})
        return self


def executed_modules(report, discovery_owners=()):
    return ModuleExecutionProof(report).collect(discovery_owners)
