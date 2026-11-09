"""Source-bound Django converter registrations, without importing project code."""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode.framework_liveness import (
    _DefinitionIndex,
    _bound_names,
    _eager_nodes,
    _qualified,
)
from skylos.deadcode.python_ast import parse_python_files
from skylos.deadcode.signature_contracts import _merge_c3_mro
from skylos.deadcode.web_framework_liveness import (
    _WebScanner,
    _executed_definitions,
    _function_bindings,
)


_REGISTER_CONVERTER = "django.urls.register_converter"
_CONVERTER_METHODS = {"to_python", "to_url"}


def _registration_converter(call, bindings):
    """Class passed to a proven register_converter(Class, name) call, if any.

    Accepts ``django.urls.register_converter`` and imported Name aliases whose
    binding ends with ``.register_converter`` (including local ``django_urls``
    shims). Rejects attribute calls on replaced providers
    (``routes.register_converter`` after ``routes = Registry()``).
    """
    if not isinstance(call, ast.Call) or not call.args:
        return None
    # The name can be computed; protocol evidence depends on the provider and
    # converter class, not on spelling the registration name as a literal.
    target = _qualified(call.func, bindings)
    if target == _REGISTER_CONVERTER:
        return _qualified(call.args[0], bindings)
    # Imported Name aliases only (``from django_urls import register_converter as x``).
    # Reject shadowed locals (``register_converter = noop``) and attribute calls on
    # replaced providers (``routes.register_converter``).
    if (
        isinstance(call.func, ast.Name)
        and target is not None
        and target.endswith(".register_converter")
    ):
        # Preserve the narrower legacy shim allowance; computed names gain
        # protocol evidence only through the actual Django provider above.
        if len(call.args) >= 2 and not (
            isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str)
        ):
            return None
        return _qualified(call.args[0], bindings)
    return None


_CORE_CONVERTERS = {
    "django.urls.converters.IntConverter": "builtins.object",
    "django.urls.converters.StringConverter": "builtins.object",
    "django.urls.converters.UUIDConverter": "builtins.object",
    "django.urls.converters.SlugConverter": "django.urls.converters.StringConverter",
    "django.urls.converters.PathConverter": "django.urls.converters.StringConverter",
}


def _definition_key(definition):
    return str(Path(definition.filename).resolve()), definition.name


class _ConverterScanner(_WebScanner):
    def __init__(self, index, module, registry):
        super().__init__(index, module, set())
        self.registry = registry
        self.bindings = {}
        self.functions = {}
        self.started = False
        self.finished = False
        self.active_functions = set()
        self.invoked = set()

    def collect(self):
        if not self.started:
            self.started = True
            self.suite(self.tree.body, self.bindings)
            self.finished = True
        return self.evidence

    def suite(self, statements, bindings, *, owner=None):
        for statement in statements:
            if not self._statement(statement, bindings, owner):
                return False
        return True

    def _statement(self, statement, bindings, owner):
        if isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
            selected = statement.orelse
            if statement.test.value:
                selected = statement.body
            return self.suite(selected, bindings, owner=owner)
        return super()._statement(statement, bindings, owner)

    def _scan_function(self, statement, bindings, _owner):
        definition = self.evidence.at(statement, "function")
        suspended = isinstance(statement, ast.AsyncFunctionDef) or any(
            isinstance(node, (ast.Yield, ast.YieldFrom))
            for child in statement.body
            for node in _eager_nodes(child)
        )
        if definition is None or statement.decorator_list or suspended:
            bindings[statement.name] = None
            return
        self.functions[definition.name] = statement, definition
        bindings[statement.name] = definition.name

    def _scan_class(self, statement, bindings, owner):
        if statement.decorator_list or statement.keywords:
            bindings[statement.name] = None
            return
        super()._scan_class(statement, bindings, owner)

    def _scan_import(self, statement, bindings, owner):
        super()._scan_import(statement, bindings, owner)
        for alias in statement.names:
            if alias.name == "*":
                continue
            if isinstance(statement, ast.Import):
                imported = self.registry.scanners.get(alias.name)
                if imported is not None:
                    imported.collect()
                continue
            local_name = alias.asname or alias.name
            qualified = bindings.get(local_name)
            if qualified is None:
                continue
            module_name, _, member = qualified.rpartition(".")
            imported = self.registry.scanners.get(module_name)
            if imported is not None:
                imported.collect()
                if member in imported.bindings:
                    bindings[local_name] = imported.bindings[member]
                    continue
            submodule = self.registry.scanners.get(qualified)
            if submodule is not None:
                submodule.collect()
            elif imported is not None:
                bindings[local_name] = None

    def _invalidate_provider_attribute(self, target, bindings):
        if not isinstance(target, ast.Attribute):
            return
        qualified = _qualified(target, bindings)
        if qualified is None or not qualified.startswith("django."):
            return
        root = target
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            bindings[root.id] = None

    def _scan_assignment(self, statement, bindings, owner):
        super()._scan_assignment(statement, bindings, owner)
        targets = []
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        for target in targets:
            self._invalidate_provider_attribute(target, bindings)

    def _invalidate(self, statement, bindings, owner):
        super()._invalidate(statement, bindings, owner)
        for node in _eager_nodes(statement):
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self._invalidate_provider_attribute(node, bindings)

    def _calls(self, expression, bindings, *, routes=False):
        for call in _eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            candidate = _registration_converter(call, bindings)
            if candidate is not None:
                self.registry.register(candidate)
            target = _qualified(call.func, bindings)
            scanner, function = self.registry.function(target)
            if scanner is not None:
                scanner.invoke(function, call, bindings)

    def invoke(self, function, call=None, caller_bindings=None):
        statement, definition = function
        if definition.name in self.active_functions or len(self.active_functions) >= 24:
            return
        self.active_functions.add(definition.name)
        self.invoked.add(id(definition))
        try:
            local = _function_bindings(statement, self.bindings)
            global_names = set()
            local_names = set()
            for item in statement.body:
                local_names.update(_bound_names(item))
                for node in _eager_nodes(item):
                    if isinstance(node, ast.Global):
                        global_names.update(node.names)
            for name in local_names - global_names:
                local[name] = None
            if call is not None:
                positional = [*statement.args.posonlyargs, *statement.args.args]
                for argument, value in zip(positional, call.args):
                    local[argument.arg] = _qualified(value, caller_bindings)
                for keyword in call.keywords:
                    if keyword.arg is not None:
                        local[keyword.arg] = _qualified(keyword.value, caller_bindings)
            self.suite(statement.body, local, owner=definition.name)
            for name in global_names:
                self.bindings[name] = local.get(name)
        finally:
            self.active_functions.remove(definition.name)


class _ConverterRegistry:
    def __init__(self, index, parsed):
        self.index = index
        self.scanners = {}
        self.registered = set()
        self.mro_cache = {}
        for module in parsed:
            scanner = _ConverterScanner(index, module, self)
            self.scanners[scanner.evidence.module] = scanner

    def function(self, qualified):
        if qualified is None:
            return None, None
        module_name, _, _ = qualified.rpartition(".")
        scanner = self.scanners.get(module_name)
        if scanner is None:
            return None, None
        scanner.collect()
        function = scanner.functions.get(qualified)
        if function is None:
            return None, None
        return scanner, function

    def class_info(self, qualified):
        if not isinstance(qualified, str) or not qualified:
            return None
        module_name, _, _ = qualified.rpartition(".")
        scanner = self.scanners.get(module_name)
        if scanner is None:
            return None
        scanner.collect()
        return scanner.evidence.classes.get(qualified)

    def linearization(self, qualified, active=()):
        if qualified in self.mro_cache:
            return self.mro_cache[qualified]
        if qualified in active or len(active) >= 24:
            return None
        if qualified == "builtins.object":
            return [qualified]
        if qualified in _CORE_CONVERTERS:
            parents = (_CORE_CONVERTERS[qualified],)
        else:
            info = self.class_info(qualified)
            if info is None:
                return None
            parents = info[1]
            if not parents:
                parents = ("builtins.object",)
        sequences = []
        for parent in parents:
            if parent is None:
                return None
            inherited = self.linearization(parent, (*active, qualified))
            if inherited is None:
                return None
            sequences.append(list(inherited))
        sequences.append(list(parents))
        merged = _merge_c3_mro(sequences)
        if merged is None:
            return None
        result = [qualified, *merged]
        self.mro_cache[qualified] = result
        return result

    def protocol_members(self, qualified):
        info = self.class_info(qualified)
        if info is None:
            return None
        order = self.linearization(qualified)
        if order is None:
            return None
        selected = {}
        for owner in order:
            if owner in _CORE_CONVERTERS:
                for name in {*_CONVERTER_METHODS, "regex"}:
                    selected.setdefault(name, None)
                continue
            parent = self.class_info(owner)
            if parent is None:
                continue
            definition, _, candidates, _ = parent
            for name in {*_CONVERTER_METHODS, "regex"}:
                if name not in selected and name in candidates:
                    node = candidates[name]
                    if name in _CONVERTER_METHODS:
                        if not isinstance(node, ast.FunctionDef):
                            return None
                        module_name, _, _ = owner.rpartition(".")
                        scanner = self.scanners[module_name]
                        if node not in scanner.evidence.protocol_methods:
                            return None
                    elif (
                        not isinstance(node, (ast.Assign, ast.AnnAssign))
                        or node.value is None
                    ):
                        return None
                    selected[name] = (
                        str(Path(definition.filename).resolve()),
                        owner + "." + name,
                    )
        if not {*_CONVERTER_METHODS, "regex"} <= selected.keys():
            return None
        return selected

    def register(self, qualified):
        if qualified is None:
            return
        module_name, _, member = qualified.rpartition(".")
        scanner = self.scanners.get(module_name)
        if scanner is None:
            return
        scanner.collect()
        if scanner.bindings.get(member) != qualified:
            return
        info = scanner.evidence.classes.get(qualified)
        if info is None:
            return
        selected = self.protocol_members(qualified)
        if selected is None:
            return
        self.registered.add(_definition_key(info[0]))
        for key in selected.values():
            if key is not None:
                self.registered.add(key)


def _converter_scan_paths(definitions, files, root):
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    paths = []
    for file in files:
        path = Path(file)
        if path.suffix not in {".py", ".pyi"}:
            continue
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        paths.append(path)
    return root, paths


def _project_may_register_converters(definitions, paths):
    if any(
        definition.type == "import" and definition.name.split(".", 1)[0] == "django"
        for definition in definitions.values()
    ):
        return True
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "register_converter" in text:
            return True
    return False


def _scan_django_converters(definitions, files, root):
    """Collect converter identities from registrations whose owners execute."""
    root, paths = _converter_scan_paths(definitions, files, root)
    if not paths or not _project_may_register_converters(definitions, paths):
        return frozenset(), []
    parsed = parse_python_files(paths)
    index = _DefinitionIndex(definitions, parsed, root)
    if "django" in index.shadowed:
        return frozenset(), []
    registry = _ConverterRegistry(index, parsed)
    for scanner in registry.scanners.values():
        scanner.collect()
    executed = _executed_definitions(index)
    for scanner in registry.scanners.values():
        for function in tuple(scanner.functions.values()):
            _, definition = function
            if id(definition) in executed and id(definition) not in scanner.invoked:
                scanner.invoke(function)
    return frozenset(registry.registered), []


def find_django_converter_classes(definitions, files, root):
    """Return exact registered class and selected protocol-member identities."""
    registered, _ = _scan_django_converters(definitions, files, root)
    return registered


def find_django_converter_method_targets(definitions, class_keys):
    """Only registered conversion methods become roots for helper reachability."""
    if not class_keys:
        return []
    targets = []
    paths = {}
    for definition in definitions.values():
        if definition.type == "class":
            filename = str(definition.filename)
            if filename not in paths:
                paths[filename] = str(Path(filename).resolve())
            key = paths[filename], definition.name
            if key in class_keys:
                targets.append((definition, "django_web_converter_method"))
            continue
        if (
            definition.type != "method"
            or definition.simple_name not in _CONVERTER_METHODS
        ):
            continue
        filename = str(definition.filename)
        if filename not in paths:
            paths[filename] = str(Path(filename).resolve())
        key = paths[filename], definition.name
        if key in class_keys:
            targets.append((definition, "django_web_converter_method"))
    return targets
