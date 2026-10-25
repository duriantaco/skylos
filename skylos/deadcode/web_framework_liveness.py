"""Bind proven Flask/Django registrations without executing project code."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.deadcode.django_framework_liveness import find_django_targets
from skylos.deadcode.django_setting_bindings import collect_setting_bindings
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
# Positional arguments Flask passes to each callback kind (None: all of them,
# for template filters/tests/globals that take the template's arguments).
_FLASK_CALLBACK_ARITY = {
    "teardown_appcontext": 1,
    "teardown_request": 1,
    "teardown_app_request": 1,
    "after_request": 1,
    "after_app_request": 1,
    "errorhandler": 1,
    "app_errorhandler": 1,
    "register_error_handler": 1,
    "url_value_preprocessor": 2,
    "app_url_value_preprocessor": 2,
    "url_defaults": 2,
    "app_url_defaults": 2,
    "template_filter": None,
    "app_template_filter": None,
    "add_template_filter": None,
    "app_template_test": None,
    "template_test": None,
    "add_template_test": None,
    "template_global": None,
    "app_template_global": None,
    "add_template_global": None,
}
# ``app.teardown_appcontext(close_db)``-style registration: the method name
# and the index of the callback argument.
_FLASK_REGISTRATION_CALLS = {
    "before_request": 0,
    "before_app_request": 0,
    "after_request": 0,
    "after_app_request": 0,
    "teardown_request": 0,
    "teardown_app_request": 0,
    "teardown_appcontext": 0,
    "context_processor": 0,
    "app_context_processor": 0,
    "url_value_preprocessor": 0,
    "url_defaults": 0,
    "register_error_handler": 1,
    "add_template_filter": 0,
    "add_template_test": 0,
    "add_template_global": 0,
}
# ``flask run`` / ``flask --app pkg`` calls a module-level factory with one of
# these names (Flask "Application Discovery"), so its body runs and the
# blueprints it registers are installed.
_FLASK_APP_FACTORY_NAMES = frozenset({"create_app", "make_app"})
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
    # ``from x import *`` targets anywhere at module level (also under
    # ``if``/``try``), so a settings package can reach ``settings.base``.
    star_imports: set = field(default_factory=set)
    # Final possible sources of named settings imports and aliases.
    setting_bindings: dict = field(default_factory=dict)
    # UPPER_CASE names assigned at module level, with their values.
    module_settings: dict = field(default_factory=dict)
    # Values added to those names in place (``MIDDLEWARE.append(path)``) at
    # import time, including inside functions the module calls while loading.
    setting_mutations: dict = field(default_factory=dict)
    # AST values may be defined inside an earlier function but applied later.
    setting_mutation_positions: dict = field(default_factory=dict)
    # Final source bindings distinguish a configured class from an earlier
    # declaration that the module has replaced.
    bindings: dict = field(default_factory=dict)
    class_member_overrides: dict = field(default_factory=dict)
    authentication_backend_assignments: list = field(default_factory=list)
    authentication_backend_mutations: list = field(default_factory=list)
    authentication_backend_invalidations: list = field(default_factory=list)
    protocol_methods: set = field(default_factory=set)

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
        self.authentication_calls = defaultdict(list)
        self._imports = _FrameworkScanner(module, index)._imports

    def collect(self):
        module_bindings = {}
        self.suite(self.tree.body, module_bindings)
        self.evidence.bindings = module_bindings.copy()
        self._collect_module_level()
        self._collect_callback_signatures(module_bindings)
        return self.evidence

    def _collect_callback_signatures(self, module_bindings):
        """Flask fixes the signature of any function registered as a callback,
        wherever the registration call is (``init_app(app)`` included)."""
        if "flask" in self.index.shadowed or not self._module_imports_flask():
            return
        for call in ast.walk(self.tree):
            if not isinstance(call, ast.Call) or not isinstance(
                call.func, ast.Attribute
            ):
                continue
            position = _FLASK_REGISTRATION_CALLS.get(call.func.attr)
            if position is None or len(call.args) <= position:
                continue
            argument = call.args[position]
            if not isinstance(argument, ast.Name):
                continue
            target = module_bindings.get(argument.id)
            definition = (
                self.evidence.definition(target, kind="function") if target else None
            )
            if definition is not None:
                self._flask_signature(definition, call.func.attr)

    def _collect_module_level(self):
        for statement in _possible_module_statements(self.tree.body):
            if _authentication_backend_invalidates(statement):
                self.evidence.authentication_backend_invalidations.append(
                    (statement.lineno, statement.col_offset)
                )
            for value in _authentication_backend_mutations(statement):
                self.evidence.authentication_backend_mutations.append(
                    (value, (statement.lineno, statement.col_offset))
                )
            targets, value = _assigned(statement)
            if value is not None and any(
                isinstance(target, ast.Name) and target.id == "AUTHENTICATION_BACKENDS"
                for target in targets
            ):
                self.evidence.authentication_backend_assignments.append(value)
        package = self.evidence.module
        if self.evidence.path.name != "__init__.py":
            package = package.rpartition(".")[0]
        for statement in _possible_module_statements(self.tree.body):
            if isinstance(statement, ast.ImportFrom):
                if any(alias.name == "*" for alias in statement.names):
                    target = _resolve_from_module(statement, package)
                    if target:
                        self.evidence.star_imports.add(target)
                    continue
                continue
            for name, value in _setting_mutations(statement):
                self.evidence.setting_mutations.setdefault(name, []).append(value)
                self.evidence.setting_mutation_positions.setdefault(
                    id(value), []
                ).append((statement.lineno, statement.col_offset))
            targets, value = _assigned(statement)
            if value is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    self.evidence.module_settings.setdefault(target.id, []).append(
                        value
                    )
        self.evidence.setting_bindings = collect_setting_bindings(
            self.tree.body, self.evidence.module, package, _resolve_from_module
        )
        self._collect_import_time_setting_mutations()

    def _collect_import_time_setting_mutations(self):
        """Mutations inside module functions the module calls while loading
        (``HEADER = _parse_remote_user_settings()``)."""
        for statement in self.tree.body:
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if statement.lineno in self.authentication_calls and _uses_global_setting(
                statement, "AUTHENTICATION_BACKENDS"
            ):
                for node in _possible_module_statements(statement.body):
                    if _authentication_backend_invalidates(node):
                        self.evidence.authentication_backend_invalidations.extend(
                            self.authentication_calls[statement.lineno]
                        )
                    for value in _authentication_backend_mutations(node):
                        for position in self.authentication_calls[statement.lineno]:
                            self.evidence.authentication_backend_mutations.append(
                                (value, position)
                            )
            positions = self.authentication_calls.get(statement.lineno, ())
            if not positions:
                continue
            module_names = set(self.evidence.module_settings) | {
                name
                for node in ast.walk(statement)
                if isinstance(node, ast.Global)
                for name in node.names
            }
            for node in _possible_module_statements(statement.body):
                for name, value in _setting_mutations(node):
                    if name in module_names and _uses_global_setting(statement, name):
                        self.evidence.setting_mutations.setdefault(name, []).append(
                            value
                        )
                        self.evidence.setting_mutation_positions.setdefault(
                            id(value), []
                        ).extend(positions)

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
        self._class_member_overrides(statement, bindings)
        for name in _bound_names(statement):
            bindings[name] = None

    def _class_member_overrides(self, statement, bindings):
        for node in _eager_nodes(statement):
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                name = _qualified(node, bindings)
                if name is not None:
                    self.evidence.class_member_overrides[name] = statement
            elif isinstance(node, ast.Call) and len(node.args) >= 2:
                function = _qualified(node.func, bindings)
                builtin = (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and node.func.id not in bindings
                )
                if not builtin and function not in {
                    "builtins.setattr",
                    "builtins.delattr",
                }:
                    continue
                if function in self.evidence.class_member_overrides:
                    continue
                owner = _qualified(node.args[0], bindings)
                if owner is None:
                    continue
                member = _literal(node.args[1])
                if isinstance(member, str):
                    self.evidence.class_member_overrides[owner + "." + member] = (
                        statement
                    )
                else:
                    self.evidence.class_member_overrides[owner] = statement

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
            bases = []
            for base in statement.bases:
                qualified = _qualified(base, bindings)
                if (
                    isinstance(base, ast.Name)
                    and base.id == "object"
                    and base.id not in bindings
                ):
                    qualified = "builtins.object"
                bases.append(qualified)
            self.evidence.classes[definition.name] = (
                definition,
                tuple(bases),
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
            if isinstance(member, ast.AnnAssign) and member.value is None:
                continue
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and all(
                _protocol_method_decorator(decorator, class_bindings)
                for decorator in member.decorator_list
            ):
                self.evidence.protocol_methods.add(member)
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
        self._class_member_overrides(statement, bindings)
        targets, value = _assigned(statement)
        if value is None:
            self._invalidate(statement, bindings, owner)
            return
        if owner is None:
            self._authentication_calls(value, bindings)
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

    def _scan_expression(self, statement, bindings, owner):
        self._class_member_overrides(statement, bindings)
        if owner is None:
            self._authentication_calls(statement.value, bindings)
        self._calls(statement.value, bindings)

    def _authentication_calls(self, expression, bindings):
        for call in _eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            definition = self.evidence.definition(
                _qualified(call.func, bindings), kind="function"
            )
            if (
                definition is not None
                and isinstance(getattr(definition, "node", None), ast.FunctionDef)
                and not any(
                    isinstance(node, (ast.Yield, ast.YieldFrom))
                    for statement in definition.node.body
                    for node in _eager_nodes(statement)
                )
                and self.index._resolve_path(Path(definition.filename))
                == self.evidence.path
            ):
                self.authentication_calls[definition.node.lineno].append(
                    (call.lineno, call.col_offset)
                )

    def _flask_callback(self, node, bindings, definition):
        if definition is None or "flask" in self.index.shadowed:
            return None
        for decorator in node.decorator_list:
            function = decorator.func if isinstance(decorator, ast.Call) else decorator
            registered = _flask_decorator(_qualified(function, bindings))
            if registered is None:
                continue
            source, symbol = registered
            self._flask_signature(definition, _qualified(function, bindings))
            if source == "flask.Blueprint":
                self.evidence.blueprint_callbacks.append((definition, symbol))
                # Its body cannot prove that its own Blueprint is installed.
                return False
            self.evidence.targets.append((definition, "flask_web_callback"))
            return True
        return None

    def _flask_signature(self, definition, registration):
        """Keep the parameters Flask passes to a callback (``close_db(e)``)."""
        method = (registration or "").rpartition(".")[2]
        if method not in _FLASK_CALLBACK_ARITY:
            return
        node = getattr(definition, "node", None)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        positional = [*node.args.posonlyargs, *node.args.args]
        count = _FLASK_CALLBACK_ARITY[method]
        supplied = positional if count is None else positional[:count]
        parameters = self.index.parameters.get(definition.name, {})
        for argument in supplied:
            parameter = parameters.get(argument.arg)
            if parameter is not None:
                self.evidence.targets.append((parameter, "flask_callback_signature"))

    def _flask_registration_call(self, call, bindings):
        """``app.teardown_appcontext(close_db)`` in a module importing Flask.

        Flask's extension pattern registers callbacks on an ``app`` parameter
        (``def init_app(app)``), so the receiver cannot be proven a Flask
        object; the module importing Flask and Flask's method name are the
        evidence.
        """
        if "flask" in self.index.shadowed or not self._module_imports_flask():
            return
        if not isinstance(call.func, ast.Attribute):
            return
        method = call.func.attr
        position = _FLASK_REGISTRATION_CALLS.get(method)
        if position is None or len(call.args) <= position:
            return
        argument = call.args[position]
        if not isinstance(argument, ast.Name):
            return
        target = bindings.get(argument.id)
        if not target:
            return
        definition = self.evidence.definition(target, kind="function")
        if definition is None:
            return
        self.evidence.targets.append((definition, "flask_web_callback"))
        self._flask_signature(definition, method)

    def _module_imports_flask(self):
        cached = getattr(self, "_imports_flask", None)
        if cached is None:
            cached = any(
                path == self.evidence.path and name.split(".", 1)[0] == "flask"
                for path, name in self.index.imports
            )
            self._imports_flask = cached
        return cached

    def _calls(self, expression, bindings, *, routes=False):
        for call in _eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            function = _qualified(call.func, bindings)
            self._blueprint_call(call, function, bindings)
            self._flask_registration_call(call, bindings)
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


_SETTING_MUTATORS = {"append", "extend", "insert", "add", "update", "setdefault"}
_SCOPES_FOR_SETTINGS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _protocol_method_decorator(decorator, bindings):
    if (
        isinstance(decorator, ast.Name)
        and decorator.id in {"classmethod", "staticmethod"}
        and decorator.id not in bindings
    ):
        return True
    return _qualified(decorator, bindings) in {
        "builtins.classmethod",
        "builtins.staticmethod",
    }


def _authentication_backend_invalidates(statement):
    """Destructive or escaped list state needs a later full assignment."""
    if isinstance(statement, ast.Delete):
        return any(
            _setting_root(target) == "AUTHENTICATION_BACKENDS"
            for target in statement.targets
        )
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets, expression = _assigned(statement)
        if any(
            isinstance(target, ast.Subscript)
            and _setting_root(target) == "AUTHENTICATION_BACKENDS"
            for target in targets
        ):
            return True
    elif isinstance(statement, ast.AugAssign):
        if _setting_root(
            statement.target
        ) == "AUTHENTICATION_BACKENDS" and not isinstance(statement.op, ast.Add):
            return True
        expression = statement.value
    elif isinstance(statement, ast.Expr):
        expression = statement.value
    elif isinstance(statement, (ast.If, ast.While)):
        expression = statement.test
    else:
        return False
    if expression is None:
        return False
    for node in _eager_nodes(expression):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and _setting_root(node.func.value) == "AUTHENTICATION_BACKENDS"
            and node.func.attr not in {"append", "extend", "insert"}
        ):
            return True
        if any(
            isinstance(argument, ast.Name) and argument.id == "AUTHENTICATION_BACKENDS"
            for argument in (*node.args, *(keyword.value for keyword in node.keywords))
        ):
            return True
    return False


def _authentication_backend_mutations(statement):
    """Only direct list operations can register an authentication backend."""
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        call = statement.value
        if not isinstance(call.func, ast.Attribute) or call.keywords:
            return
        receiver = call.func.value
        if (
            not isinstance(receiver, ast.Name)
            or receiver.id != "AUTHENTICATION_BACKENDS"
        ):
            return
        if call.func.attr == "append" and len(call.args) == 1:
            if isinstance(call.args[0], ast.Constant):
                yield call.args[0]
        elif call.func.attr == "extend" and len(call.args) == 1:
            if isinstance(call.args[0], (ast.List, ast.Tuple)):
                yield call.args[0]
        elif call.func.attr == "insert" and len(call.args) == 2:
            if isinstance(call.args[1], ast.Constant):
                yield call.args[1]
    elif (
        isinstance(statement, ast.AugAssign)
        and isinstance(statement.op, ast.Add)
        and isinstance(statement.target, ast.Name)
        and statement.target.id == "AUTHENTICATION_BACKENDS"
    ):
        if isinstance(statement.value, (ast.List, ast.Tuple)):
            yield statement.value
    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets, value = _assigned(statement)
        for target in targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "AUTHENTICATION_BACKENDS"
            ):
                if isinstance(target.slice, ast.Constant) and isinstance(
                    target.slice.value, int
                ):
                    if isinstance(value, ast.Constant):
                        yield value
                elif isinstance(target.slice, ast.Slice) and isinstance(
                    value, (ast.List, ast.Tuple)
                ):
                    yield value


def _uses_global_setting(function, name):
    statements = list(_module_level_statements(function.body))
    globals_ = {
        item
        for statement in statements
        if isinstance(statement, ast.Global)
        for item in statement.names
    }
    if name in globals_:
        return True
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
        function.args.vararg,
        function.args.kwarg,
    ]
    if any(argument is not None and argument.arg == name for argument in arguments):
        return False
    return not any(name in _bound_names(statement) for statement in function.body)


def _possible_module_statements(statements):
    """Import-time statements on possible paths, excluding literal dead arms."""
    for statement in statements:
        if isinstance(statement, _SCOPES_FOR_SETTINGS):
            continue
        yield statement
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if isinstance(statement, ast.If):
            if isinstance(statement.test, ast.Constant):
                if statement.test.value:
                    terminated = yield from _possible_module_statements(statement.body)
                else:
                    terminated = yield from _possible_module_statements(
                        statement.orelse
                    )
                if terminated:
                    return True
            else:
                body_terminated = yield from _possible_module_statements(statement.body)
                else_terminated = yield from _possible_module_statements(
                    statement.orelse
                )
                if body_terminated and else_terminated:
                    return True
            continue
        for name in ("body", "orelse", "finalbody"):
            children = getattr(statement, name, None)
            if isinstance(children, list):
                yield from _possible_module_statements(children)
        for handler in getattr(statement, "handlers", None) or ():
            yield from _possible_module_statements(handler.body)
        for case in getattr(statement, "cases", None) or ():
            yield from _possible_module_statements(case.body)
    return False


def _setting_root(node):
    while isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Name) and node.id.isupper():
        return node.id
    return None


def _setting_mutations(statement):
    """(UPPER_CASE name, added value) pairs for an in-place update."""
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        call = statement.value
        if isinstance(call.func, ast.Attribute) and call.func.attr in _SETTING_MUTATORS:
            name = _setting_root(call.func.value)
            if name:
                for value in (*call.args, *(kw.value for kw in call.keywords)):
                    yield name, value
    elif isinstance(statement, ast.AugAssign):
        name = _setting_root(statement.target)
        if name:
            yield name, statement.value
    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets, value = _assigned(statement)
        if value is None:
            return
        for target in targets:
            if isinstance(target, ast.Subscript):
                name = _setting_root(target)
                if name:
                    yield name, value


def _module_level_statements(statements):
    """Statements that run at import time, including nested blocks."""
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield statement
        for name in ("body", "orelse", "finalbody"):
            children = getattr(statement, name, None)
            if isinstance(children, list):
                yield from _module_level_statements(children)
        for handler in getattr(statement, "handlers", None) or ():
            yield from _module_level_statements(handler.body)
        for case in getattr(statement, "cases", None) or ():
            yield from _module_level_statements(case.body)


def _resolve_from_module(statement, package):
    if not statement.level:
        return statement.module
    parts = package.split(".") if package else []
    if statement.level - 1 > len(parts):
        return None
    base = parts[: len(parts) - (statement.level - 1)]
    if statement.module:
        base.append(statement.module)
    return ".".join(base) or None


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


def _flask_app_factories(index):
    """Module-level ``create_app``/``make_app`` in modules that import Flask."""
    if "flask" in index.shadowed:
        return []
    flask_modules = {
        path for path, name in index.imports if name.split(".", 1)[0] == "flask"
    }
    factories = []
    for name, group in index.by_name.items():
        if name.rpartition(".")[2] not in _FLASK_APP_FACTORY_NAMES:
            continue
        for definition in group:
            if definition.type != "function":
                continue
            path = index._resolve_path(Path(definition.filename))
            if path in flask_modules:
                factories.append(definition)
    return factories


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
    roots.update(id(item) for item in _flask_app_factories(index))
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
    from skylos.deadcode.django_framework_liveness import _looks_like_settings

    executed = _executed_definitions(index)
    modules = [_WebScanner(index, module, executed).collect() for module in parsed]
    scanners = {module.module: module for module in modules}
    has_framework_import = any(
        name.split(".", 1)[0] in {"django", "flask"} - index.shadowed
        for _, name in index.imports
    )
    has_settings = any(_looks_like_settings(scanner) for scanner in scanners.values())
    # Settings modules often configure Django without importing it
    # (``INSTALLED_APPS`` + ``SECRET_KEY`` / ``ROOT_URLCONF``).
    if not has_framework_import and not has_settings:
        return []
    classes = {
        name: info for module in modules for name, info in module.classes.items()
    }
    targets = [target for module in modules for target in module.targets]
    targets.extend(
        (definition, "flask_app_factory") for definition in _flask_app_factories(index)
    )
    targets.extend(_blueprint_targets(modules))
    if "django" not in index.shadowed:
        targets.extend(
            find_django_targets(
                index, scanners, classes, root, exclude_folders=exclude_folders
            )
        )
    return targets
