"""Bind proven Flask/Django registrations without executing project code."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.django_framework_liveness import find_django_targets
from skylos.deadcode.django_template_liveness import _path_expression
from skylos.deadcode.framework_liveness import (
    _FrameworkScanner,
    _bound_names,
    _eager_nodes,
    _qualified,
)
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode.web_framework_ast import _assigned, _literal, _main_guard

_FLASK_CALLBACKS = {
    "flask.Flask": {
        "before_request",
        "after_request",
        "teardown_request",
        "teardown_appcontext",
        "context_processor",
        "template_filter",
        "template_global",
        "errorhandler",
    },
    "flask.Blueprint": {
        "before_request",
        "after_request",
        "teardown_request",
        "before_app_request",
        "after_app_request",
        "teardown_app_request",
        "context_processor",
        "app_context_processor",
        "app_template_filter",
        "app_template_global",
        "errorhandler",
        "app_errorhandler",
    },
}
_DJANGO_LAUNCHERS = {
    "django.core.wsgi.get_wsgi_application",
    "django.core.asgi.get_asgi_application",
    "django.core.management.execute_from_command_line",
    "django.setup",
}
_DJANGO_APPLICATIONS = {
    "django.core.wsgi.get_wsgi_application",
    "django.core.asgi.get_asgi_application",
}
_EXECUTION_MARKERS = {
    "top_level_execution",
    "framework_root",
    "test_entrypoint",
    "package_entrypoint",
}
_HANDLERS = {
    ast.Import: "_scan_import",
    ast.ImportFrom: "_scan_import",
    ast.If: "_scan_if",
    ast.FunctionDef: "_scan_function",
    ast.AsyncFunctionDef: "_scan_function",
    ast.ClassDef: "_scan_class",
    ast.Assign: "_scan_assignment",
    ast.AnnAssign: "_scan_assignment",
    ast.Expr: "_scan_expression",
}


@dataclass
class _ModuleEvidence:
    index: Any
    path: Path
    module: str
    targets: list = field(default_factory=list)
    blueprints: set = field(default_factory=set)
    blueprint_callbacks: list = field(default_factory=list)
    classes: dict = field(default_factory=dict)
    settings: set = field(default_factory=set)
    values: dict = field(default_factory=dict)
    value_contexts: dict = field(default_factory=dict)
    routes: list = field(default_factory=list)
    view_overrides: set = field(default_factory=set)
    includes: set = field(default_factory=set)
    imported_modules: set = field(default_factory=set)
    admins: set = field(default_factory=set)

    def definition(self, name: str, *, line=None, kind=None):
        candidates = [
            item
            for item in self.index.all_by_name.get(name, ())
            if (line is None or item.line == line)
            and (kind is None or item.type == kind)
        ]
        return candidates[0] if len(candidates) == 1 else None

    def at(self, node: ast.AST, kind: str):
        candidates = [
            item
            for item in self.index.all_by_location.get((self.path, node.lineno), ())
            if item.type == kind and item.simple_name == node.name
        ]
        return candidates[0] if len(candidates) == 1 else None


@dataclass
class _Assignment:
    value: ast.AST
    qualified: str | None
    constructor: str | None
    owner: str | None


class _WebScanner:
    def __init__(self, index, module, executed_definitions):
        path = index._resolve_path(module.path)
        self.index = index
        self.evidence = _ModuleEvidence(index, path, index.modules[path])
        self.tree = module.tree
        self.path_values = {}
        self.settings_module = None
        self.executed_definitions = executed_definitions
        self._imports = _FrameworkScanner(module, index)._imports

    def collect(self):
        self.suite(self.tree.body, {})
        return self.evidence

    def suite(self, statements, bindings, *, owner=None):
        for statement in statements:
            if not self._statement(statement, bindings, owner):
                return

    def _statement(self, statement, bindings, owner):
        if isinstance(statement, (ast.Return, ast.Raise)):
            if isinstance(statement, ast.Return) and statement.value is not None:
                self._calls(statement.value, bindings)
            return False
        handler = getattr(self, _HANDLERS.get(type(statement), "_invalidate"))
        handler(statement, bindings, owner)
        return True

    def _invalidate(self, statement, bindings, _owner):
        for name in _bound_names(statement):
            bindings[name] = None

    def _scan_import(self, statement, bindings, _owner):
        self._imports(statement, bindings)
        for alias in statement.names:
            target = (
                alias.name
                if isinstance(statement, ast.Import)
                else bindings.get(alias.asname or alias.name)
            )
            if target:
                self.evidence.imported_modules.add(target)
                if isinstance(statement, ast.ImportFrom):
                    self.evidence.imported_modules.add(target.rpartition(".")[0])

    def _scan_if(self, statement, bindings, owner):
        if isinstance(statement.test, ast.Constant):
            selected = statement.body if statement.test.value else statement.orelse
            self.suite(selected, bindings, owner=owner)
        elif owner is None and _main_guard(statement.test):
            self.suite(statement.body, bindings, owner=owner)
        else:
            self._invalidate(statement, bindings, owner)

    def _scan_function(self, statement, bindings, _owner):
        definition = self.evidence.at(statement, "function")
        registered = self._flask_callback(statement, bindings, definition)
        if definition is not None:
            executes = registered is True or (
                registered is None and id(definition) in self.executed_definitions
            )
            if executes:
                self.suite(
                    statement.body,
                    _function_bindings(statement, bindings),
                    owner=definition.name,
                )
        bindings[statement.name] = definition.name if definition else None

    def _scan_class(self, statement, bindings, owner):
        definition = self.evidence.at(statement, "class")
        if definition is not None and owner is None:
            members, model_bindings = self._class_members(statement, bindings)
            bases = {_qualified(base, bindings) for base in statement.bases}
            self.evidence.classes[definition.name] = (
                definition,
                bases,
                members,
                model_bindings,
            )
            self._register_admin(statement, bindings, definition.name)
        bindings[statement.name] = definition.name if definition else None

    def _class_members(self, statement, bindings):
        members = {}
        class_bindings = bindings.copy()
        model_bindings = bindings.copy()
        for member in statement.body:
            names = _bound_names(member)
            if "model" in names:
                model_bindings = class_bindings.copy()
            if isinstance(member, (ast.Import, ast.ImportFrom)):
                self._imports(member, class_bindings)
            else:
                value = _qualified(_assigned(member)[1], class_bindings)
                class_bindings.update(dict.fromkeys(names, value))
            members.update(dict.fromkeys(names, member))
        return members, model_bindings

    def _register_admin(self, statement, bindings, name):
        if "django" in self.index.shadowed:
            return
        for decorator in statement.decorator_list:
            function = decorator.func if isinstance(decorator, ast.Call) else decorator
            if _qualified(function, bindings) == "django.contrib.admin.register":
                self.evidence.admins.add(name)

    def _scan_assignment(self, statement, bindings, owner):
        targets, value = _assigned(statement)
        if value is None:
            self._invalidate(statement, bindings, owner)
            return
        routes = owner is None and any(
            isinstance(target, ast.Name) and target.id == "urlpatterns"
            for target in targets
        )
        self._calls(value, bindings, routes=routes)
        assignment = _Assignment(
            value,
            _qualified(value, bindings),
            _qualified(value.func, bindings) if isinstance(value, ast.Call) else None,
            owner,
        )
        for target in targets:
            if isinstance(target, ast.Name):
                self._bind_name(target.id, bindings, assignment)
            elif _is_settings_key(target, bindings):
                self.settings_module = _literal(value)

    def _bind_name(self, name, bindings, assignment):
        qualified = assignment.qualified
        if (
            assignment.constructor in _FLASK_CALLBACKS
            and "flask" not in self.index.shadowed
        ):
            symbol = (assignment.owner or self.evidence.module) + "." + name
            qualified = "@" + assignment.constructor + ":" + symbol
        bindings[name] = qualified
        if assignment.owner is None:
            self.evidence.values[name] = assignment.value
            self.evidence.value_contexts[name] = (
                bindings.copy(),
                self.path_values.copy(),
            )
            self.path_values[name] = _path_expression(
                assignment.value,
                bindings,
                self.evidence.path,
                self.path_values,
            )
        self._mark_application(name, assignment)

    def _mark_application(self, name, assignment):
        if assignment.owner is not None or "django" in self.index.shadowed:
            return
        if (
            self.evidence.path.name not in {"wsgi.py", "asgi.py"}
            or name != "application"
        ):
            return
        if assignment.constructor in _DJANGO_APPLICATIONS:
            definition = self.evidence.definition(
                self.evidence.module + ".application",
                kind="variable",
            )
            if definition is not None:
                self.evidence.targets.append((definition, "django_web_application"))

    def _scan_expression(self, statement, bindings, _owner):
        self._calls(statement.value, bindings)

    def _flask_callback(self, node, bindings, definition):
        if definition is None or "flask" in self.index.shadowed:
            return None
        for decorator in node.decorator_list:
            function = decorator.func if isinstance(decorator, ast.Call) else decorator
            registered = _flask_decorator(_qualified(function, bindings))
            if registered is None:
                continue
            source, symbol = registered
            if source == "flask.Blueprint":
                self.evidence.blueprint_callbacks.append((definition, symbol))
                # Its body cannot prove that its own Blueprint is installed.
                return False
            self.evidence.targets.append((definition, "flask_web_callback"))
            return True
        return None

    def _calls(self, expression, bindings, *, routes=False):
        for call in _eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            function = _qualified(call.func, bindings)
            self._blueprint_call(call, function, bindings)
            if function == "os.environ.setdefault" and len(call.args) >= 2:
                if _literal(call.args[0]) == "DJANGO_SETTINGS_MODULE":
                    self.settings_module = _literal(call.args[1])
            if "django" not in self.index.shadowed:
                self._django_call(call, function, bindings, routes)

    def _blueprint_call(self, call, function, bindings):
        if not function or not function.startswith("@flask.Flask:"):
            return
        if not function.endswith(".register_blueprint") or not call.args:
            return
        blueprint = _qualified(call.args[0], bindings)
        if blueprint:
            symbol = (
                blueprint.partition(":")[2]
                if blueprint.startswith("@flask.Blueprint:")
                else blueprint
            )
            self.evidence.blueprints.add(symbol)

    def _django_call(self, call, function, bindings, routes):
        if function in _DJANGO_LAUNCHERS and isinstance(self.settings_module, str):
            self.evidence.settings.add(self.settings_module)
        if routes and function in {"django.urls.path", "django.urls.re_path"}:
            self._route_call(call, bindings)
        elif routes and function == "django.urls.include" and call.args:
            module = _literal(call.args[0])
            if isinstance(module, str):
                self.evidence.includes.add(module)
        elif function == "django.contrib.admin.site.register" and len(call.args) > 1:
            target = _qualified(call.args[1], bindings)
            if target:
                self.evidence.admins.add(target)

    def _route_call(self, call, bindings):
        view = (
            call.args[1]
            if len(call.args) > 1
            else next(
                (kw.value for kw in call.keywords if kw.arg == "view"),
                None,
            )
        )
        if not isinstance(view, ast.Call) or not isinstance(view.func, ast.Attribute):
            return
        if view.func.attr != "as_view":
            return
        target = _qualified(view.func.value, bindings)
        if target:
            self.evidence.routes.append(target)
            if view.args or view.keywords:
                self.evidence.view_overrides.add(target)


def _function_bindings(statement, bindings):
    local = bindings.copy()
    arguments = [
        *statement.args.posonlyargs,
        *statement.args.args,
        *statement.args.kwonlyargs,
    ]
    arguments.extend(
        arg for arg in (statement.args.vararg, statement.args.kwarg) if arg is not None
    )
    for argument in arguments:
        local[argument.arg] = None
    return local


def _is_settings_key(target, bindings):
    return (
        isinstance(target, ast.Subscript)
        and _qualified(target.value, bindings) == "os.environ"
        and _literal(target.slice) == "DJANGO_SETTINGS_MODULE"
    )


def _flask_decorator(qualified):
    if not qualified:
        return None
    factory, _, method = qualified.rpartition(".")
    source, _, symbol = factory.lstrip("@").partition(":")
    if factory.startswith("@") and method in _FLASK_CALLBACKS.get(source, ()):
        return source, symbol
    return None


def _execution_graph(index, definitions):
    children = defaultdict(set)
    for definition in definitions:
        for name in definition.called_by:
            callers = (
                item
                for item in index.all_by_name.get(name, ())
                if item.type in {"function", "method"}
            )
            for caller in callers:
                children[id(caller)].add(id(definition))
    return children


def _executed_definitions(index):
    """Follow existing execution evidence once, rather than per function."""
    definitions = [
        item
        for group in index.all_by_name.values()
        for item in group
        if item.type in {"function", "method"}
    ]
    roots = {
        id(item)
        for item in definitions
        if _EXECUTION_MARKERS.intersection(item.heuristic_refs)
    }
    children = _execution_graph(index, definitions)
    pending = list(roots)
    while pending:
        for child in children.get(pending.pop(), ()):
            if child not in roots:
                roots.add(child)
                pending.append(child)
    return roots


def _blueprint_targets(modules):
    registered = {name for module in modules for name in module.blueprints}
    return [
        (definition, "flask_web_callback")
        for module in modules
        for definition, symbol in module.blueprint_callbacks
        if symbol in registered
    ]


def find_web_framework_targets(
    index: Any,
    parsed: Iterable[ParsedPythonFile],
    root: Path,
    *,
    exclude_folders: Iterable[str] | None = None,
) -> list[tuple[Any, str]]:
    if not any(
        name.split(".", 1)[0] in {"django", "flask"} - index.shadowed
        for _, name in index.imports
    ):
        return []
    executed = _executed_definitions(index)
    modules = [_WebScanner(index, module, executed).collect() for module in parsed]
    scanners = {module.module: module for module in modules}
    classes = {
        name: info for module in modules for name, info in module.classes.items()
    }
    targets = [target for module in modules for target in module.targets]
    targets.extend(_blueprint_targets(modules))
    targets.extend(
        find_django_targets(
            index, scanners, classes, root, exclude_folders=exclude_folders
        )
    )
    return targets
