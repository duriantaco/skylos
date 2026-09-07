"""Caller-owned callback edges for small, documented external protocols.

m3u8.load's fifth argument / http_client keyword uses download:
https://github.com/globocom/m3u8/blob/master/m3u8/__init__.py

This is not general escape analysis. Ambiguous control flow, dynamic arguments,
definition headers, and re-exports are left unresolved. Explicit class imports
use unique stable declarations in already-parsed files, never runtime imports.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from skylos.deadcode.python_ast import ParsedPythonFile


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_DEFERRED = (*_FUNCTIONS, ast.ClassDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_SOURCE_ROOTS = {"src", "lib", "python"}
_OBJECT_BASE = object()
_LOAD_PARAMETERS = (
    "uri",
    "timeout",
    "headers",
    "custom_tags_parser",
    "http_client",
    "verify_ssl",
)


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


class _BoundNames(ast.NodeVisitor):
    """Lexical bindings, including unreachable binders but excluding child scopes."""

    def __init__(self):
        self.names = set()
        self.mutated = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(
            alias.asname or alias.name.split(".")[0] for alias in node.names
        )

    def visit_ImportFrom(self, node):
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_Global(self, node):
        self.names.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.mutated.add(_root_name(node))
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"}:
            if node.args:
                self.mutated.add(_root_name(node.args[0]))
        self.generic_visit(node)


def _bindings_in(nodes):
    collector = _BoundNames()
    for node in nodes:
        collector.visit(node)
    return collector


def _class_value(value):
    if isinstance(value, ast.ClassDef):
        return value
    if isinstance(value, tuple) and len(value) == 2 and value[0] == "instance":
        return value[1]
    return None


def _instance_masks_download(cls):
    if "__getattribute__" in _bindings_in(cls.body).names:
        return True
    for method in cls.body:
        if not isinstance(method, _FUNCTIONS) or method.name != "__init__":
            continue
        arguments = [*method.args.posonlyargs, *method.args.args]
        if not arguments:
            continue
        receiver = arguments[0].arg
        if any(
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.attr == "download"
            and isinstance(node.value, ast.Name)
            and node.value.id == receiver
            for node in ast.walk(method)
        ):
            return True
        if any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == receiver
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "download"
            for node in ast.walk(method)
        ):
            return True
    return False


class _ClassImports:
    def __init__(self):
        self.exports = {}
        self.modules = set()
        self.owners = {}
        self.invalid_classes = set()
        self.mro_cache = {}


def _module_identities(definitions, tree):
    variables = {
        (node.lineno, target.id)
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }
    names = {
        definition.name.rpartition(".")[0]
        for definition in definitions
        if (
            isinstance(getattr(definition, "node", None), (*_FUNCTIONS, ast.ClassDef))
            and definition.node.col_offset == 0
        )
        or (
            definition.type == "variable"
            and (definition.line, definition.simple_name) in variables
        )
    }
    return names


class _Collector:
    def __init__(self, definitions, imports, tree, is_package=False):
        self.locations = defaultdict(list)
        self.found = {}
        self.class_contexts = {}
        self.imports = imports
        self.module_names = _module_identities(definitions, tree)
        self.module_name = (
            next(iter(self.module_names)) if len(self.module_names) == 1 else None
        )
        self.is_package = is_package
        self.mro_cache = imports.mro_cache
        self.invalid_classes = imports.invalid_classes
        for definition in definitions:
            node = getattr(definition, "node", None)
            nodes = getattr(definition, "nodes", None)
            if isinstance(nodes, (list, tuple)) and len(nodes) > 1:
                continue
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                self.locations[node.lineno].append(definition)

    def _definition(self, node):
        candidates = self.locations.get(node.lineno, ())
        return candidates[0] if len(candidates) == 1 else None

    def _value(self, node, bindings):
        if isinstance(node, ast.Name):
            return bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self._value(node.value, bindings)
            if isinstance(base, str):
                name = f"{base}.{node.attr}"
                return self.imports.exports.get(name, name)
        if isinstance(node, ast.Call):
            cls = self._value(node.func, bindings)
            if isinstance(cls, ast.ClassDef):
                return ("instance", cls)
        return None

    def _import_value(self, node, alias):
        if isinstance(node, ast.Import):
            return alias.name if alias.asname else alias.name.split(".")[0]
        module = node.module or ""
        if node.level:
            package = (
                self.module_name
                if self.is_package
                else (self.module_name or "").rpartition(".")[0]
            )
            parts = package.split(".") if package else []
            if node.level > len(parts):
                return None
            module = ".".join(
                [*parts[: len(parts) - node.level + 1], *([module] if module else [])]
            )
        name = f"{module}.{alias.name}" if module else alias.name
        if name == "m3u8.load" or name in self.imports.modules:
            return name
        return self.imports.exports.get(name)

    @staticmethod
    def _bind(name, value, bindings, observed):
        bindings[name] = value
        if name in observed and observed[name] != value:
            observed[name] = None
        else:
            observed[name] = value

    def _invalidate(self, nodes, bindings, observed):
        collected = _bindings_in(nodes)
        for name in collected.mutated:
            value = bindings.get(name)
            cls = _class_value(value)
            if cls is not None:
                self.invalid_classes.add(cls)
                self.mro_cache.clear()
            elif isinstance(value, str):
                self.invalid_classes.update(
                    exported
                    for name, exported in self.imports.exports.items()
                    if name.startswith(value + ".")
                )
                self.mro_cache.clear()
            for alias, other in list(bindings.items()):
                same_module = isinstance(value, str) and isinstance(other, str)
                if alias == name or (cls is not None and _class_value(other) is cls):
                    self._bind(alias, None, bindings, observed)
                elif same_module and value.split(".")[0] == other.split(".")[0]:
                    self._bind(alias, None, bindings, observed)
        for name in collected.names:
            self._bind(name, None, bindings, observed)

    def _mro(self, cls, active=()):
        if cls is _OBJECT_BASE:
            return [_OBJECT_BASE]
        owner = self.imports.owners.get(cls)
        if owner is not None and owner is not self:
            return owner._mro(cls, active)
        if cls in self.mro_cache:
            return self.mro_cache[cls]
        if (
            cls in active
            or len(active) >= 64
            or cls in self.invalid_classes
            or cls.decorator_list
            or cls.keywords
            or cls not in self.class_contexts
        ):
            return None
        context = self.class_contexts[cls]
        bases = []
        for expression in cls.bases:
            if (
                isinstance(expression, ast.Name)
                and expression.id == "object"
                and "object" not in context
            ):
                base = _OBJECT_BASE
            else:
                base = self._value(expression, context)
            if base is not _OBJECT_BASE and not isinstance(base, ast.ClassDef):
                return None
            bases.append(base)
        if not bases:
            bases = [_OBJECT_BASE]
        sequences = []
        for base in bases:
            order = self._mro(base, (*active, cls))
            if order is None:
                return None
            sequences.append(list(order))
        sequences.append(list(bases))
        result = [cls]
        while any(sequences):
            sequences = [sequence for sequence in sequences if sequence]
            candidate = next(
                (
                    sequence[0]
                    for sequence in sequences
                    if all(sequence[0] not in other[1:] for other in sequences)
                ),
                None,
            )
            if candidate is None or len(result) >= 128:
                return None
            result.append(candidate)
            for sequence in sequences:
                if sequence[0] is candidate:
                    sequence.pop(0)
        self.mro_cache[cls] = result
        return result

    def _download_method(self, client, bindings):
        cls = _class_value(client)
        order = self._mro(cls) if cls is not None else None
        if order is None:
            return None
        if not isinstance(client, ast.ClassDef) and any(
            _instance_masks_download(owner)
            for owner in order
            if owner is not _OBJECT_BASE
        ):
            return None
        for owner in order:
            if owner is _OBJECT_BASE:
                continue
            methods = [
                item
                for item in owner.body
                if isinstance(item, _FUNCTIONS) and item.name == "download"
            ]
            other = _bindings_in(item for item in owner.body if item not in methods)
            if "download" in other.names:
                return None  # A non-method binding masks later MRO entries.
            if not methods:
                continue
            if len(methods) != 1:
                return None
            method = methods[0]
            provider = self.imports.owners[owner]
            if any(
                not isinstance(dec, ast.Name)
                or dec.id not in {"staticmethod", "classmethod"}
                or dec.id in other.names
                or dec.id in provider.class_contexts[owner]
                for dec in method.decorator_list
            ):
                return None
            if isinstance(client, ast.ClassDef) and not method.decorator_list:
                return None  # An ordinary method needs its instance binding.
            return provider._definition(method)
        return None

    def _callback(self, node, bindings, caller):
        if self._value(node.func, bindings) != "m3u8.load":
            return
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            return
        if any(keyword.arg is None for keyword in node.keywords):
            return
        keywords = [keyword.arg for keyword in node.keywords]
        if (
            len(node.args) > len(_LOAD_PARAMETERS)
            or len(set(keywords)) != len(keywords)
            or any(name not in _LOAD_PARAMETERS for name in keywords)
            or set(keywords).intersection(_LOAD_PARAMETERS[: len(node.args)])
            or not node.args
            and "uri" not in keywords
        ):
            return
        uri = (
            node.args[0]
            if node.args
            else next(
                keyword.value for keyword in node.keywords if keyword.arg == "uri"
            )
        )
        if isinstance(uri, ast.Constant):
            if not isinstance(uri.value, (str, bytes)):
                return
            try:
                parts = urlsplit(uri.value)
            except ValueError:
                return
            # m3u8 uses its file loader when either URL component is absent.
            if not parts.scheme or not parts.netloc:
                return
        clients = [kw.value for kw in node.keywords if kw.arg == "http_client"]
        if len(node.args) > 4:
            clients.append(node.args[4])
        if len(clients) != 1:
            return
        definition = self._download_method(self._value(clients[0], bindings), bindings)
        if definition is not None:
            client = _class_value(self._value(clients[0], bindings))
            self.found[(id(definition), id(caller))] = (definition, caller, client)

    def _expression(self, node, bindings, caller, observed, report):
        if node is None or isinstance(node, (*_DEFERRED, *_COMPREHENSIONS)):
            return
        # Do not invent an evaluation path through short-circuit expressions or
        # let an embedded assignment/mutation retain stale import identity.
        mutations = _bindings_in((node,))
        if mutations.names or mutations.mutated:
            self._invalidate((node,), bindings, observed)
            return
        if isinstance(node, (ast.BoolOp, ast.IfExp)):
            return
        for child in ast.iter_child_nodes(node):
            self._expression(child, bindings, caller, observed, report)
        if report and isinstance(node, ast.Call):
            self._callback(node, bindings, caller)

    def _suite(self, statements, bindings, caller, observed, stable, report):
        for node in statements:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name == "*":
                        for bound_name in list(bindings):
                            self._bind(bound_name, None, bindings, observed)
                        continue
                    name = alias.asname or alias.name.split(".")[0]
                    value = self._import_value(node, alias)
                    self._bind(name, value, bindings, observed)
            elif isinstance(node, _FUNCTIONS):
                self._bind(node.name, None, bindings, observed)
                if report:
                    self._function(node, stable)
            elif isinstance(node, ast.ClassDef):
                self.imports.owners[node] = self
                if self.class_contexts.get(node) != bindings:
                    self.class_contexts[node] = dict(bindings)
                    self.mro_cache.clear()
                self._bind(node.name, node, bindings, observed)
                if report:
                    # Methods close over the containing function/module, not
                    # their class namespace. Class-body execution is unsupported.
                    for item in node.body:
                        if isinstance(item, _FUNCTIONS):
                            self._function(item, stable)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._expression(node.value, bindings, caller, observed, report)
                value = self._value(node.value, bindings)
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        self._bind(target.id, value, bindings, observed)
                    else:
                        self._invalidate((target,), bindings, observed)
            elif isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
                selected = node.body if bool(node.test.value) else node.orelse
                if not self._suite(
                    selected, bindings, caller, observed, stable, report
                ):
                    return False
            elif isinstance(node, (ast.Return, ast.Raise)):
                for value in ast.iter_child_nodes(node):
                    self._expression(value, bindings, caller, observed, report)
                return False
            elif isinstance(node, ast.Expr):
                self._expression(node.value, bindings, caller, observed, report)
            else:
                self._invalidate((node,), bindings, observed)
        return True

    def _scope(self, statements, incoming, caller, local_names=()):
        bindings = dict(incoming)
        bindings.update((name, None) for name in local_names)
        observed = {}
        self._suite(statements, dict(bindings), caller, observed, {}, False)
        stable = dict(bindings)
        stable.update(observed)
        self._suite(statements, bindings, caller, {}, stable, True)

    def _function(self, node, incoming):
        caller = self._definition(node)
        if caller is None:
            return
        local_names = _bindings_in(node.body).names
        local_names.update(
            arg.arg
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        )
        for arg in (node.args.vararg, node.args.kwarg):
            if arg is not None:
                local_names.add(arg.arg)
        self._scope(node.body, incoming, caller, local_names)


def find_external_protocol_callbacks(
    definitions, parsed_files: Iterable[ParsedPythonFile], root
):
    """Return (method, caller) edges; None means actual module-level execution."""
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    parsed = list(parsed_files)
    modules = []
    for module in parsed:
        try:
            parts = module.path.resolve().relative_to(root).parts
        except (OSError, ValueError):
            continue
        if not parts:
            continue
        if root.name == "m3u8" and parts[0] == "__init__.py":
            return []
        first = parts[1] if parts[0] in _SOURCE_ROOTS and len(parts) > 1 else parts[0]
        if first in {"m3u8", "m3u8.py", "m3u8.pyi"}:
            return []
        modules.append(module)
    active = [
        module
        for module in modules
        if any(
            isinstance(node, ast.Import)
            and any(alias.name == "m3u8" for alias in node.names)
            or isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "m3u8"
            for node in ast.walk(module.tree)
        )
    ]
    if not active:
        return []
    by_file = defaultdict(list)
    for definition in definitions.values():
        by_file[Path(definition.filename).resolve()].append(definition)
    imports = _ClassImports()
    collectors = {}
    packages = defaultdict(set)
    providers = defaultdict(list)
    for module in modules:
        path = module.path.resolve()
        collector = _Collector(
            by_file[path], imports, module.tree, path.name == "__init__.py"
        )
        collectors[path] = collector
        if collector.module_name:
            package, _, stem = collector.module_name.rpartition(".")
            if collector.is_package:
                packages[path.parent].add(collector.module_name)
            elif stem == path.stem:
                packages[path.parent].add(package)
    # An imports-only sibling has no own Definition. Reuse only an unambiguous
    # namespace established by definitions in that exact directory.
    for module in modules:
        path = module.path.resolve()
        collector = collectors[path]
        anchors = packages[path.parent]
        if not collector.module_names and len(anchors) == 1:
            package = next(iter(anchors))
            collector.module_name = (
                package
                if collector.is_package
                else ".".join(filter(None, (package, path.stem)))
            )
        if collector.module_name:
            providers[collector.module_name].append((module, collector))
    if any(name == "m3u8" or name.startswith("m3u8.") for name in providers):
        return []
    imports.modules.update(
        name for name, candidates in providers.items() if len(candidates) == 1
    )
    exports = {}
    prepared = []
    for name, candidates in providers.items():
        if len(candidates) != 1:
            continue
        module, collector = candidates[0]
        prepared.append((module, collector))
        stable = {}
        collector._suite(module.tree.body, {}, None, stable, {}, False)
        declarations = {
            node for node in module.tree.body if isinstance(node, ast.ClassDef)
        }
        for local, value in stable.items():
            if (
                isinstance(value, ast.ClassDef)
                and value in declarations
                and value.name == local
                and collector._definition(value) is not None
            ):
                exports[f"{name}.{local}"] = value
    imports.exports.update(exports)
    # Refresh owner contexts with the complete direct-export registry before
    # consumer analysis. No exports are discovered recursively in this pass.
    for module, collector in prepared:
        collector._suite(module.tree.body, {}, None, {}, {}, False)
    for module in active:
        collector = collectors[module.path.resolve()]
        collector._scope(module.tree.body, {}, None)
    found = {}
    for collector in collectors.values():
        for key, (method, caller, client) in collector.found.items():
            if collector._mro(client) is not None:
                found[key] = (method, caller)
    return list(found.values())
