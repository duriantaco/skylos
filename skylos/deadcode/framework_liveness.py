"""Small, evidence-based contracts for statically registered framework callbacks."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.python_ast import ParsedPythonFile


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, ast.Lambda)
_SOURCE_ROOTS = {"src", "lib", "python"}
_RUNPYTHON = {
    "django.db.migrations.RunPython",
    "django.db.migrations.operations.RunPython",
}


def find_framework_entrypoint_targets(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    root: Path,
    *,
    exclude_folders=None,
) -> list[tuple[Any, str]]:
    """Return definitions used by proven imports, without executing target code."""
    parsed = []
    root = root.resolve()
    if root.is_file():
        root = root.parent
    for module in parsed_files:
        try:
            module.path.resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        parsed.append(module)
    index = _DefinitionIndex(definitions, parsed, root)
    found: dict[tuple[int, str], tuple[Any, str]] = {}
    for module in parsed:
        scanner = _FrameworkScanner(module, index)
        for definition, reason in scanner.collect():
            found[(id(definition), reason)] = (definition, reason)
    from skylos.deadcode.web_framework_liveness import find_web_framework_targets

    for definition, reason in find_web_framework_targets(
        index, parsed, root, exclude_folders=exclude_folders
    ):
        found[(id(definition), reason)] = (definition, reason)
    from skylos.deadcode.ros_launch_liveness import find_ros_launch_targets

    for definition, reason in find_ros_launch_targets(index, parsed, root):
        found[(id(definition), reason)] = (definition, reason)
    return list(found.values())


def _bound_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {alias.asname or alias.name.split(".", 1)[0] for alias in node.names}
    if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
        return {node.name}
    names = set()
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            names.add(child.id)
        elif not isinstance(child, ast.Lambda):
            names.update(_bound_names(child))
    return names


def _eager_nodes(node: ast.AST):
    if isinstance(node, _SCOPES):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _eager_nodes(child)


def _literal_nonempty(node):
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if any(not isinstance(item, ast.Starred) for item in node.elts):
            return True
        return None if node.elts else False
    if isinstance(node, ast.Dict):
        if any(key is not None for key in node.keys):
            return True
        return None if node.keys else False
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return bool(node.value)
    return None


def _literal_truth(node):
    inverted = False
    while isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inverted = not inverted
        node = node.operand
    result = (
        bool(node.value) if isinstance(node, ast.Constant) else _literal_nonempty(node)
    )
    return None if result is None else result != inverted


def _backend_access_nodes(node, definite=True, shadowed=frozenset()):
    if isinstance(node, _SCOPES):
        return
    yield node, definite, shadowed
    if isinstance(node, ast.GeneratorExp):
        # Creating a generator evaluates its outer iterator, not its body.
        yield from _backend_access_nodes(node.generators[0].iter, definite, shadowed)
    elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
        for generator in node.generators:
            yield from _backend_access_nodes(generator.iter, definite, shadowed)
            nonempty = _literal_nonempty(generator.iter)
            if nonempty is False:
                return
            if nonempty is None:
                definite = False
            target = generator.target
            names = (
                {target.id} if isinstance(target, ast.Name) else _bound_names(target)
            )
            shadowed = shadowed | names
            for condition in generator.ifs:
                yield from _backend_access_nodes(condition, definite, shadowed)
                truth = _literal_truth(condition)
                if truth is False:
                    return
                if truth is None:
                    definite = False
        values = (
            (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
        )
        for value in values:
            yield from _backend_access_nodes(value, definite, shadowed)
    elif isinstance(node, ast.BoolOp):
        for value in node.values:
            yield from _backend_access_nodes(value, definite, shadowed)
            truth = _literal_truth(value)
            if truth is None:
                definite = False
            elif truth == isinstance(node.op, ast.Or):
                break
    elif isinstance(node, ast.IfExp):
        yield from _backend_access_nodes(node.test, definite, shadowed)
        truth = _literal_truth(node.test)
        if truth is not None:
            chosen = node.body if truth else node.orelse
            yield from _backend_access_nodes(chosen, definite, shadowed)
        else:
            yield from _backend_access_nodes(node.body, False, shadowed)
            yield from _backend_access_nodes(node.orelse, False, shadowed)
    else:
        for child in ast.iter_child_nodes(node):
            yield from _backend_access_nodes(child, definite, shadowed)


def _qualified(node: ast.AST | None, bindings: dict[str, str | None]) -> str | None:
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, bindings)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        base = _qualified(node.value, bindings)
        if base and isinstance(node.slice.value, str):
            return f"{base}.{node.slice.value}"
    return None


def _module_name(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[0] in _SOURCE_ROOTS:
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class _DefinitionIndex:
    def __init__(self, definitions, parsed, root):
        self._resolved_paths: dict[Path, Path] = {}
        self.by_location = {}
        self.by_name = defaultdict(list)
        self.imports = defaultdict(list)
        self.parameters = defaultdict(dict)
        self.modules = {}
        self.shadowed = set()
        self.all_by_name = defaultdict(list)
        self.all_by_location = defaultdict(list)
        self._backend_modules = list(parsed)
        self._backend_exports = None
        for module in parsed:
            path = self._resolve_path(module.path)
            self.modules[path] = _module_name(path, root)
            relative = path.relative_to(root).parts
            first = (
                relative[1]
                if relative[0] in _SOURCE_ROOTS and len(relative) > 1
                else relative[0]
            )
            for framework in ("django", "celery", "flask"):
                if first in {framework, f"{framework}.py"} or (
                    root.name == framework and relative[0] == "__init__.py"
                ):
                    self.shadowed.add(framework)
        for definition in definitions.values():
            kind = getattr(definition, "type", "")
            path = self._resolve_path(Path(definition.filename))
            if path not in self.modules:
                continue
            if kind == "parameter":
                owner, _, name = definition.name.rpartition(".")
                self.parameters[owner][name] = definition
            elif kind == "import":
                self.imports[(path, definition.name)].append(definition)
            elif kind in {"function", "class"}:
                node = getattr(definition, "node", None)
                if node is not None and getattr(node, "col_offset", -1) == 0:
                    self.by_location[(path, node.lineno)] = definition
                    self.by_name[definition.name].append(definition)
                    self.modules[path] = definition.name.rsplit(".", 1)[0]
        # Always index definitions for location/name lookup. Gating on a
        # django/flask import left settings-only trees and local
        # ``register_converter`` shims unable to resolve classes/functions.
        for definition in definitions.values():
            path = self._resolve_path(Path(definition.filename))
            if path in self.modules:
                self.all_by_name[definition.name].append(definition)
                self.all_by_location[(path, definition.line)].append(definition)
        # A dotted setting names the module's final binding, not a stale function.
        for module in parsed:
            path = self._resolve_path(module.path)
            active = {}
            for statement in module.tree.body:
                for name in _bound_names(statement):
                    active.pop(name, None)
                if isinstance(statement, _FUNCTIONS):
                    definition = self.by_location.get((path, statement.lineno))
                    if definition is not None:
                        active[statement.name] = definition
            active_ids = {id(item) for item in active.values()}
            for statement in module.tree.body:
                if not isinstance(statement, _FUNCTIONS):
                    continue
                definition = self.by_location.get((path, statement.lineno))
                if definition is not None and id(definition) not in active_ids:
                    self.by_name[definition.name] = [
                        item
                        for item in self.by_name[definition.name]
                        if item is not definition
                    ]

    def _resolve_path(self, path: Path) -> Path:
        cached = self._resolved_paths.get(path)
        if cached is not None:
            return cached
        resolved = path.resolve()
        self._resolved_paths[path] = resolved
        return resolved

    def callable(self, name):
        candidates = self.by_name.get(name, ())
        if len(candidates) == 1 and getattr(candidates[0], "type", "") == "function":
            return candidates[0]
        return None

    def class_or_function(self, name):
        """Resolve a backend's current export, preserving captured local aliases."""
        if self._backend_exports is None:
            self._backend_exports = {}
            for module in self._backend_modules:
                self._backend_module_exports(module)
        seen = set()
        value = name
        while isinstance(value, str) and value not in seen:
            seen.add(value)
            value = self._backend_exports.get(value)
        return value if getattr(value, "type", "") in {"class", "function"} else None

    def _backend_module_exports(self, module):
        path = self._resolve_path(module.path)
        module_name = self.modules[path]
        bindings = {}

        def selected(node):
            if isinstance(node, ast.Name):
                return bindings.get(node.id)
            if isinstance(node, ast.Attribute):
                owner = selected(node.value)
                if isinstance(owner, str):
                    return f"{owner}.{node.attr}"
            return None

        pending = list(reversed(module.tree.body))
        while pending:
            statement = pending.pop()
            if isinstance(statement, ast.If) and isinstance(
                statement.test, ast.Constant
            ):
                body = statement.body if statement.test.value else statement.orelse
                pending.extend(reversed(body))
                continue
            if isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
                matches = [
                    definition
                    for definition in self.all_by_location.get(
                        (path, statement.lineno), ()
                    )
                    if getattr(definition, "type", "") in {"class", "function"}
                ]
                bindings[statement.name] = matches[0] if len(matches) == 1 else None
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    bindings[local] = alias.name if alias.asname else local
            elif isinstance(statement, ast.ImportFrom):
                source = statement.module or ""
                if statement.level:
                    package = module_name.split(".")
                    if path.name != "__init__.py":
                        package = package[:-1]
                    package = package[: len(package) - statement.level + 1]
                    source = ".".join([*package, *([source] if source else [])])
                for alias in statement.names:
                    if alias.name == "*":
                        bindings = dict.fromkeys(bindings)
                    else:
                        bindings[alias.asname or alias.name] = f"{source}.{alias.name}"
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                if statement.value is None:
                    continue
                value = selected(statement.value)
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    names = (
                        {target.id}
                        if isinstance(target, ast.Name)
                        else _bound_names(target)
                    )
                    for name in names:
                        bindings[name] = value if isinstance(target, ast.Name) else None
            else:
                for name in _bound_names(statement):
                    bindings[name] = None
        for name, value in bindings.items():
            self._backend_exports[f"{module_name}.{name}"] = value


class _FrameworkScanner:
    def __init__(self, parsed: ParsedPythonFile, index: _DefinitionIndex):
        self.parsed = parsed
        self.path = index._resolve_path(parsed.path)
        self.index = index
        self.targets = []
        self.routes: dict[str, tuple[ast.AST, dict[str, str | None]]] = {}
        self.backend_paths: dict[str, str] = {}
        self.loaded_backend_paths: dict[str, str | None] = {}
        self.possible_backend_paths: set[str] = set()
        self.bindings: dict[str, str | None] = {}

    def collect(self):
        self._suite(self.parsed.tree.body, self.bindings)
        for app, (value, bindings) in self.routes.items():
            if app not in self.bindings.values():
                continue
            for candidate in _router_candidates(value):
                name = (
                    candidate.value
                    if isinstance(candidate, ast.Constant)
                    else _qualified(candidate, bindings)
                )
                definition = self.index.callable(name)
                if definition is not None:
                    self.targets.append((definition, "celery_task_router"))
                    self._parameters(definition, 4, "celery_task_router", celery=True)
        paths = {path for path in self.loaded_backend_paths.values() if path} | {
            path
            for app, path in self.backend_paths.items()
            if app in self.bindings.values() and app not in self.loaded_backend_paths
        }
        for path in paths:
            definition = self.index.class_or_function(path)
            if definition is not None:
                self.targets.append((definition, "celery_result_backend"))
        for path in self.possible_backend_paths - paths:
            definition = self.index.class_or_function(path)
            if definition is not None:
                self.targets.append((definition, "possible_celery_result_backend"))
        return self.targets

    def _record_backend_path(self, app, value):
        self.backend_paths.pop(app, None)
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        path = value.value.strip().replace(":", ".")
        if path and len(path) <= 300 and "." in path:
            self.backend_paths[app] = path

    def _suite(self, statements, bindings, *, class_body=False):
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                break
            if isinstance(statement, ast.If) and isinstance(
                statement.test, ast.Constant
            ):
                body = statement.body if statement.test.value else statement.orelse
                self._suite(body, bindings, class_body=class_body)
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._imports(statement, bindings)
                continue
            if isinstance(statement, _FUNCTIONS):
                definition = self.index.by_location.get((self.path, statement.lineno))
                bindings[statement.name] = (
                    definition.name if definition and not class_body else None
                )
                continue
            if isinstance(statement, ast.ClassDef):
                if "django" not in self.index.shadowed and any(
                    _qualified(base, bindings) == "django.apps.AppConfig"
                    for base in statement.bases
                ):
                    ready = None
                    for method in statement.body:
                        if "ready" in _bound_names(method):
                            ready = (
                                method if isinstance(method, ast.FunctionDef) else None
                            )
                    if ready is not None:
                        self._ready_imports(ready.body)
                self._suite(statement.body, bindings.copy(), class_body=True)
                bindings[statement.name] = None
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if value is not None:
                    self._calls(value, bindings)
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                for target in targets:
                    self._assignment(target, value, bindings, class_body)
                continue
            if isinstance(statement, ast.Expr):
                self._calls(statement.value, bindings)
                if not class_body and isinstance(statement.value, ast.Call):
                    self._conf_update(statement.value, bindings)
                continue
            if isinstance(statement, ast.Delete) and not class_body:
                for target in statement.targets:
                    qualified = _qualified(target, bindings)
                    if qualified and qualified.startswith("@celery:"):
                        app, _, attribute = qualified.partition(".")
                        if attribute in {"conf", "conf.result_backend"}:
                            self.backend_paths.pop(app, None)
                        if attribute in {"conf", "conf.task_routes"}:
                            self.routes.pop(app, None)
                    elif isinstance(target, ast.Subscript):
                        container = _qualified(target.value, bindings)
                        if (
                            container
                            and container.startswith("@celery:")
                            and container.endswith(".conf")
                        ):
                            app = container.split(".", 1)[0]
                            self.backend_paths.pop(app, None)
                            self.routes.pop(app, None)
                    names = (
                        {target.id}
                        if isinstance(target, ast.Name)
                        else _bound_names(target)
                    )
                    for name in names:
                        self._invalidate(name, bindings)
                continue
            # Unknown control flow must not establish framework provenance.
            for name in _bound_names(statement):
                self._invalidate(name, bindings)
            for child in () if class_body else _eager_nodes(statement):
                if isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
                    child.ctx, (ast.Store, ast.Del)
                ):
                    qualified = _qualified(child, bindings)
                    if qualified and qualified.startswith("@celery:"):
                        app, _, attribute = qualified.partition(".")
                        if attribute in {"conf", "conf.result_backend"}:
                            self.backend_paths.pop(app, None)
                    elif isinstance(child, ast.Subscript):
                        container = _qualified(child.value, bindings)
                        if (
                            container
                            and container.startswith("@celery:")
                            and container.endswith(".conf")
                        ):
                            self.backend_paths.pop(container.split(".", 1)[0], None)
                elif isinstance(child, ast.Call):
                    qualified = _qualified(child.func, bindings)
                    if qualified and qualified.startswith("@celery:"):
                        app, _, attribute = qualified.partition(".")
                        updates_backend = any(
                            keyword.arg in {None, "result_backend"}
                            for keyword in child.keywords
                        ) or any(
                            not isinstance(argument, ast.Dict)
                            or any(
                                not isinstance(key, ast.Constant)
                                or key.value == "result_backend"
                                for key in argument.keys
                            )
                            for argument in child.args
                        )
                        if attribute.startswith("config_from_") or (
                            attribute == "conf.update" and updates_backend
                        ):
                            self.backend_paths.pop(app, None)
                if isinstance(child, (ast.Attribute, ast.Name)):
                    qualified = _qualified(child, bindings)
                    if qualified and qualified.startswith("@celery:"):
                        app = qualified.split(".", 1)[0]
                        self.routes.pop(app, None)

    def _imports(self, node, bindings):
        for alias in node.names:
            if isinstance(node, ast.Import):
                local = alias.asname or alias.name.split(".", 1)[0]
                target = alias.name if alias.asname else alias.name.split(".", 1)[0]
            else:
                local = alias.asname or alias.name
                module = node.module or ""
                if node.level:
                    package = self.index.modules.get(self.path, "").split(".")
                    if self.path.name != "__init__.py":
                        package = package[:-1]
                    package = package[: len(package) - node.level + 1]
                    module = ".".join([*package, *([module] if module else [])])
                target = f"{module}.{alias.name}" if module else alias.name
            self._invalidate(local, bindings)
            bindings[local] = target

    def _invalidate(self, name, bindings):
        previous = bindings.get(name)
        bindings[name] = None
        if (
            bindings is self.bindings
            and previous
            and previous.startswith("@celery:")
            and previous not in bindings.values()
        ):
            self.routes.pop(previous, None)
            self.backend_paths.pop(previous, None)

    def _assignment(self, target, value, bindings, class_body):
        qualified = _qualified(target, bindings)
        if qualified is None and isinstance(target, ast.Subscript) and not class_body:
            container = _qualified(target.value, bindings)
            if (
                container
                and container.startswith("@celery:")
                and container.endswith(".conf")
            ):
                self.routes.pop(container.split(".", 1)[0], None)
                self.backend_paths.pop(container.split(".", 1)[0], None)
        if qualified and qualified.startswith("@celery:") and not class_body:
            app, _, attribute = qualified.partition(".")
            if attribute == "conf.task_routes":
                self.routes[app] = (value, bindings.copy())
            elif attribute == "conf.result_backend":
                self._record_backend_path(app, value)
            elif attribute == "conf":
                self.routes.pop(app, None)
                self.backend_paths.pop(app, None)
                for name, binding in list(bindings.items()):
                    if binding == app:
                        bindings[name] = None
        if not isinstance(target, ast.Name):
            for name in _bound_names(target):
                self._invalidate(name, bindings)
            return
        resolved = _qualified(value, bindings)
        is_celery = (
            not class_body
            and "celery" not in self.index.shadowed
            and isinstance(value, ast.Call)
            and _qualified(value.func, bindings) == "celery.Celery"
        )
        self._invalidate(target.id, bindings)
        if is_celery:
            resolved = f"@celery:{value.lineno}:{value.col_offset}"
            for keyword in value.keywords:
                if keyword.arg == "task_routes":
                    self.routes[resolved] = (keyword.value, bindings.copy())
                elif keyword.arg in {"backend", "result_backend"}:
                    self._record_backend_path(resolved, keyword.value)
        bindings[target.id] = resolved

    def _conf_update(self, call, bindings):
        qualified = _qualified(call.func, bindings)
        if not qualified or not qualified.startswith("@celery:"):
            return
        app, _, attribute = qualified.partition(".")
        if attribute != "conf.update":
            if attribute.startswith("config_from_"):
                self.routes.pop(app, None)
                self.backend_paths.pop(app, None)
            return
        for argument in call.args:
            if not isinstance(argument, ast.Dict):
                self.routes.pop(app, None)
                self.backend_paths.pop(app, None)
                continue
            for key, value in zip(argument.keys, argument.values):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    self.routes.pop(app, None)
                    self.backend_paths.pop(app, None)
                elif key.value == "task_routes":
                    self.routes[app] = (value, bindings.copy())
                elif key.value == "result_backend":
                    self._record_backend_path(app, value)
        for keyword in call.keywords:
            if keyword.arg is None:
                self.routes.pop(app, None)
                self.backend_paths.pop(app, None)
            elif keyword.arg == "task_routes":
                self.routes[app] = (keyword.value, bindings.copy())
            elif keyword.arg == "result_backend":
                self._record_backend_path(app, keyword.value)

    def _calls(self, expression, bindings):
        for node, definite, shadowed in _backend_access_nodes(expression):
            if not isinstance(node, ast.Attribute) or node.attr != "backend":
                continue
            local = {
                name: value for name, value in bindings.items() if name not in shadowed
            }
            qualified = _qualified(node, local)
            if qualified and qualified.startswith("@celery:"):
                app, _, attribute = qualified.partition(".")
                if attribute == "backend":
                    path = self.backend_paths.get(app)
                    if definite:
                        # Only an eager load can exclude a later configured provider.
                        self.loaded_backend_paths.setdefault(app, path)
                    elif app not in self.loaded_backend_paths and path:
                        self.possible_backend_paths.add(path)
        if "django" in self.index.shadowed:
            return
        for call in _eager_nodes(expression):
            if (
                not isinstance(call, ast.Call)
                or _qualified(call.func, bindings) not in _RUNPYTHON
            ):
                continue
            callbacks = list(call.args[:2]) + [
                keyword.value
                for keyword in call.keywords
                if keyword.arg in {"code", "reverse_code"}
            ]
            for callback in callbacks:
                definition = self.index.callable(_qualified(callback, bindings))
                if definition is not None:
                    self._parameters(definition, 2, "django_migration_callback")

    def _parameters(self, definition, count, reason, *, celery=False):
        node = getattr(definition, "node", None)
        if not isinstance(node, ast.FunctionDef):
            return
        positional = [*node.args.posonlyargs, *node.args.args]
        supplied = positional[:count]
        if len(positional) < count and node.args.vararg is not None:
            supplied.append(node.args.vararg)
        if celery:
            supplied.extend(
                arg
                for arg in [*node.args.args, *node.args.kwonlyargs]
                if arg.arg == "task"
            )
            if node.args.kwarg is not None:
                supplied.append(node.args.kwarg)
        parameters = self.index.parameters.get(definition.name, {})
        for argument in supplied:
            if argument.arg in parameters:
                self.targets.append((parameters[argument.arg], reason))

    def _ready_imports(self, statements) -> bool:
        """Collect reachable imports; return whether this suite can continue."""
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                return False
            if isinstance(statement, ast.If) and isinstance(
                statement.test, ast.Constant
            ):
                if not self._ready_imports(
                    statement.body if statement.test.value else statement.orelse
                ):
                    return False
                continue
            for node in _eager_nodes(statement):
                if not isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue
                for alias in node.names:
                    if alias.name.rsplit(".", 1)[-1] != "signals":
                        continue
                    names = {}
                    self._imports(node, names)
                    local = alias.asname or (
                        alias.name.split(".", 1)[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    module = (
                        alias.name if isinstance(node, ast.Import) else names.get(local)
                    )
                    for definition in self.index.imports.get((self.path, module), ()):
                        # Import definitions aggregate aliases/lines for one symbol.
                        if definition.name in self.index.modules.values():
                            self.targets.append(
                                (definition, "django_appconfig_signal_import")
                            )
        return True


def _router_candidates(value):
    if isinstance(value, (ast.Name, ast.Attribute)):
        yield value
    elif isinstance(value, ast.Constant) and isinstance(value.value, str):
        yield value
    elif isinstance(value, (ast.Tuple, ast.List)):
        for candidate in value.elts:
            # A mapping (including ordered pattern/route pairs) is not a callback.
            if isinstance(candidate, (ast.Name, ast.Attribute, ast.Constant)):
                yield from _router_candidates(candidate)
