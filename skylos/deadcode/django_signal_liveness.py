"""Prove Django signal registrations while keeping unknown module loading uncertain."""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode.django_converter_liveness import (
    _ConverterRegistry,
    _ConverterScanner,
)
from skylos.deadcode.django_framework_liveness import (
    _loaded_modules,
    _member_names,
    _route_modules,
    _settings_activation,
)
from skylos.deadcode.framework_liveness import (
    _DefinitionIndex,
    _bound_names,
    _eager_nodes,
    _qualified,
)
from skylos.deadcode.signature_contracts import _mark_contract_parameter, _merge_c3_mro
from skylos.deadcode.web_framework_ast import _literal


_RECEIVERS = {"django.dispatch.receiver", "django.dispatch.dispatcher.receiver"}
_SIGNAL_CLASSES = {"django.dispatch.Signal", "django.dispatch.dispatcher.Signal"}
_BUILTIN_SIGNALS = {
    "django.core.signals": {
        "request_started",
        "request_finished",
        "got_request_exception",
        "setting_changed",
    },
    "django.db.models.signals": {
        "class_prepared",
        "pre_init",
        "post_init",
        "pre_save",
        "post_save",
        "pre_delete",
        "post_delete",
        "m2m_changed",
        "pre_migrate",
        "post_migrate",
    },
    "django.db.backends.signals": {"connection_created"},
    "django.contrib.auth.signals": {
        "user_logged_in",
        "user_logged_out",
        "user_login_failed",
    },
    "django.test.signals": {"setting_changed", "template_rendered"},
}
_APP_CONFIG = "django.apps.AppConfig"
_CALLBACK_INSTANCE = "@django.signal_callback_instance:"


def _signal_eager_nodes(node):
    if isinstance(
        node,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.Lambda,
            ast.GeneratorExp,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
        ),
    ):
        return
    yield node
    if isinstance(node, ast.IfExp):
        yield from _signal_eager_nodes(node.test)
        if isinstance(node.test, ast.Constant):
            selected = node.orelse
            if node.test.value:
                selected = node.body
            yield from _signal_eager_nodes(selected)
        else:
            yield from _signal_eager_nodes(node.body)
            yield from _signal_eager_nodes(node.orelse)
        return
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            yield from _signal_eager_nodes(value)
            if isinstance(value, ast.Constant):
                if isinstance(node.op, ast.And) and not value.value:
                    break
                if isinstance(node.op, ast.Or) and value.value:
                    break
        return
    for child in ast.iter_child_nodes(node):
        yield from _signal_eager_nodes(child)


def _function_body(function):
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _identity_return(function):
    arguments = [*function.args.posonlyargs, *function.args.args]
    if not arguments:
        return False
    body = function.body
    if isinstance(function, ast.Lambda):
        return isinstance(body, ast.Name) and body.id == arguments[0].arg
    body = _function_body(function)
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    return isinstance(body[0].value, ast.Name) and body[0].value.id == arguments[0].arg


def _identity_factory(function):
    if isinstance(function, ast.Lambda):
        return isinstance(function.body, ast.Lambda) and _identity_return(function.body)
    if not isinstance(function, ast.FunctionDef) or function.decorator_list:
        return False
    body = _function_body(function)
    if len(body) == 1 and isinstance(body[0], ast.Return):
        value = body[0].value
        return isinstance(value, ast.Lambda) and _identity_return(value)
    if len(body) != 2:
        return False
    inner, returned = body
    return (
        isinstance(inner, ast.FunctionDef)
        and not inner.decorator_list
        and _identity_return(inner)
        and isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == inner.name
    )


def _is_signal(qualified):
    if qualified is None:
        return False
    if qualified.startswith("@django.signal:"):
        return True
    module, _, member = qualified.rpartition(".")
    return member in _BUILTIN_SIGNALS.get(module, ())


class _SignalScanner(_ConverterScanner):
    def __init__(self, index, module, registry):
        super().__init__(index, module, registry)
        self.invocation_contexts = set()
        self.global_writes = {}
        self.unknown_registration_context = False

    def collect(self):
        evidence = super().collect()
        evidence.bindings = self.bindings.copy()
        return evidence

    def _scan_function(self, statement, bindings, owner):
        if bindings is self.bindings:
            self.registry.binding_epoch += 1
        definition = self.evidence.at(statement, "function")
        if definition is None:
            definition = self.evidence.at(statement, "method")
        registrations = [
            self._receiver_decorator(decorator, bindings)
            for decorator in statement.decorator_list
        ]
        if definition is not None:
            for registration in registrations:
                if registration is not None:
                    if self.unknown_registration_context:
                        registration = "unknown_control_flow"
                    elif not all(registrations):
                        registration = "unknown_decorator"
                    self.registry.connect(
                        definition, self.evidence.module, registration
                    )
        super()._scan_function(statement, bindings, owner)
        if definition is not None and isinstance(statement, ast.AsyncFunctionDef):
            # Django awaits async receivers; invoking an async registration
            # wrapper still must not execute that wrapper's body here.
            if not statement.decorator_list:
                bindings[statement.name] = definition.name
        if definition is not None and statement.decorator_list:
            # A receiver decorator returns the callback. Keep its source
            # binding available to later explicit connect() calls and imports.
            if all(registrations):
                bindings[statement.name] = definition.name

    def _receiver_decorator(self, decorator, bindings):
        if not isinstance(decorator, ast.Call):
            provider = _qualified(decorator, bindings)
            _, function = self.registry.function(provider)
            if function is not None and _identity_return(function[0]):
                return None
            leaf = None
            if isinstance(decorator, ast.Name):
                leaf = decorator.id
            elif isinstance(decorator, ast.Attribute):
                leaf = decorator.attr
            if isinstance(leaf, str) and "receiver" in leaf.lower():
                return "unknown_provider"
            return None
        provider = _qualified(decorator.func, bindings)
        if (
            isinstance(decorator.func, ast.Attribute)
            and provider in self.registry.changed_providers
        ):
            provider = None
        if provider not in _RECEIVERS:
            leaf = None
            if isinstance(decorator.func, ast.Name):
                leaf = decorator.func.id
            elif isinstance(decorator.func, ast.Attribute):
                leaf = decorator.func.attr
            scanner, function = self.registry.function(provider)
            if function is not None and _identity_factory(function[0]):
                return None
            if provider is not None and provider.startswith(
                "@skylos.identity_receiver:"
            ):
                return None
            if isinstance(leaf, str) and "receiver" in leaf.lower():
                return "unknown_provider"
            return None
        keywords = [item.arg for item in decorator.keywords]
        if (
            len(decorator.args) > 1
            or (decorator.args and "signal" in keywords)
            or any(
                name not in {"signal", "sender", "weak", "dispatch_uid"}
                for name in keywords
            )
        ):
            return "unknown_signal"
        signal = None
        if len(decorator.args) == 1:
            signal = decorator.args[0]
        for keyword in decorator.keywords:
            if keyword.arg == "signal":
                signal = keyword.value
        if signal is None:
            return "unknown_signal"
        signals = [signal]
        if isinstance(signal, (ast.Tuple, ast.List)):
            signals = signal.elts
        if not signals:
            return None
        if all(_is_signal(_qualified(item, bindings)) for item in signals):
            return "proven"
        return "unknown_signal"

    def _scan_import(self, statement, bindings, owner):
        if bindings is self.bindings:
            self.registry.binding_epoch += 1
        imported = self.evidence.imported_modules.copy()
        super()._scan_import(statement, bindings, owner)
        if self.unknown_registration_context:
            self.evidence.imported_modules = imported
        for alias in statement.names:
            name = alias.asname or alias.name
            if isinstance(statement, ast.Import) and not alias.asname:
                name = alias.name.split(".", 1)[0]
            provider = bindings.get(name)
            if provider in self.registry.changed_providers:
                bindings[name] = None

    def _scan_class(self, statement, bindings, owner):
        if bindings is self.bindings:
            self.registry.binding_epoch += 1
        class_bindings = bindings.copy()
        super()._scan_class(statement, bindings, owner)
        definition = self.evidence.at(statement, "class")
        if definition is None:
            return
        self._class_suite(statement.body, class_bindings, definition.name)

    def _class_suite(self, statements, bindings, owner):
        for member in statements:
            if isinstance(member, ast.If):
                if isinstance(member.test, ast.Constant):
                    selected = member.orelse
                    if member.test.value:
                        selected = member.body
                    self._class_suite(selected, bindings, owner)
                else:
                    previous = self.unknown_registration_context
                    self.unknown_registration_context = True
                    try:
                        self._class_suite(member.body, bindings.copy(), owner)
                        self._class_suite(member.orelse, bindings.copy(), owner)
                    finally:
                        self.unknown_registration_context = previous
                    for name in _bound_names(member):
                        bindings[name] = None
                continue
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_function(member, bindings, owner)
            elif isinstance(member, (ast.Import, ast.ImportFrom)):
                self._scan_import(member, bindings, owner)
            elif isinstance(member, (ast.Assign, ast.AnnAssign)):
                self._scan_assignment(member, bindings, owner)

    def _invalidate_provider_attribute(self, target, bindings):
        if isinstance(target, ast.Attribute):
            provider = _qualified(target, bindings)
            if provider is not None:
                self.registry.changed_providers.add(provider)
                self.registry.binding_epoch += 1
        super()._invalidate_provider_attribute(target, bindings)

    def _scan_assignment(self, statement, bindings, owner):
        if bindings is self.bindings:
            self.registry.binding_epoch += 1
        constructor = None
        if isinstance(statement.value, ast.Call):
            constructor = _qualified(statement.value.func, bindings)
        super()._scan_assignment(statement, bindings, owner)
        value = statement.value
        targets = []
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        for target in targets:
            if isinstance(target, ast.Name):
                if constructor in _SIGNAL_CLASSES or self.registry.signal_class(
                    constructor
                ):
                    bindings[target.id] = (
                        "@django.signal:" + self.evidence.module + "." + target.id
                    )
                elif isinstance(value, ast.Lambda) and _identity_factory(value):
                    bindings[target.id] = (
                        "@skylos.identity_receiver:"
                        + self.evidence.module
                        + "."
                        + target.id
                    )
                elif (
                    constructor is not None
                    and self.registry.class_info(constructor) is not None
                ):
                    bindings[target.id] = _CALLBACK_INSTANCE + constructor

    def _calls(self, expression, bindings, *, routes=False):
        for call in _signal_eager_nodes(expression):
            if not isinstance(call, ast.Call):
                continue
            self._provider_mutation(call, bindings)
            target = _qualified(call.func, bindings)
            if target is not None and target.endswith(".connect"):
                signal = target.removesuffix(".connect")
                if _is_signal(signal) and target not in self.registry.changed_providers:
                    callback = None
                    if call.args:
                        callback = call.args[0]
                    for keyword in call.keywords:
                        if keyword.arg == "receiver":
                            callback = keyword.value
                    target = _qualified(callback, bindings)
                    definition = self.registry.callback(target)
                    if definition is not None:
                        registration = "proven"
                        if self.unknown_registration_context:
                            registration = "unknown_control_flow"
                        elif definition.type == "method":
                            scanner = self.registry.scanners.get(
                                definition.name.rsplit(".", 2)[0]
                            )
                            info = self.registry.class_info(
                                definition.name.rpartition(".")[0]
                            )
                            member = None
                            if info is not None:
                                member = info[2].get(definition.simple_name)
                            if (
                                not isinstance(
                                    member, (ast.FunctionDef, ast.AsyncFunctionDef)
                                )
                                or member.lineno != definition.line
                            ):
                                registration = "unknown_callback"
                            elif member.decorator_list and (
                                scanner is None
                                or member not in scanner.evidence.protocol_methods
                            ):
                                registration = "unknown_callback"
                        self.registry.connect(
                            definition, self.evidence.module, registration
                        )
            target = _qualified(call.func, bindings)
            scanner, function = self.registry.function(target)
            if scanner is not None:
                scanner.invoke(function, call, bindings)

    def _provider_mutation(self, call, bindings):
        provider = _qualified(call.func, bindings)
        builtin = (
            isinstance(call.func, ast.Name)
            and call.func.id in {"setattr", "delattr"}
            and call.func.id not in bindings
        )
        if not builtin and provider not in {"builtins.setattr", "builtins.delattr"}:
            return
        if len(call.args) < 2:
            return
        owner = _qualified(call.args[0], bindings)
        member = _literal(call.args[1])
        if owner is None:
            return
        if isinstance(member, str):
            name = owner + "." + member
            self.evidence.class_member_overrides[name] = call
            self.registry.changed_providers.add(name)
            target = ast.Attribute(value=call.args[0], attr=member, ctx=ast.Store())
            self._invalidate_provider_attribute(target, bindings)

    def invoke(self, function, call=None, caller_bindings=None):
        statement, definition = function
        if definition.name in self.active_functions:
            return
        arguments = ()
        if call is not None:
            arguments = (
                tuple(_qualified(value, caller_bindings) for value in call.args),
                tuple(
                    (keyword.arg, _qualified(keyword.value, caller_bindings))
                    for keyword in call.keywords
                ),
            )
        context = (
            id(statement),
            arguments,
            self.registry.binding_epoch,
        )
        if context in self.invocation_contexts:
            return
        self.invocation_contexts.add(context)
        if id(statement) not in self.global_writes:
            self.global_writes[id(statement)] = {
                name
                for child in statement.body
                for node in _eager_nodes(child)
                if isinstance(node, ast.Global)
                for name in node.names
            }
        previous = {
            name: self.bindings.get(name) for name in self.global_writes[id(statement)]
        }
        super().invoke(function, call, caller_bindings)
        if any(self.bindings.get(name) != value for name, value in previous.items()):
            self.registry.binding_epoch += 1


class _SignalRegistry(_ConverterRegistry):
    def __init__(self, index, parsed):
        self.index = index
        self.scanners = {}
        self.connected = {}
        self.changed_providers = set()
        self.binding_epoch = 0
        self.mro_cache = {}
        for module in parsed:
            scanner = _SignalScanner(index, module, self)
            self.scanners[scanner.evidence.module] = scanner

    def connect(self, definition, module, registration):
        key = (str(definition.filename), definition.line, definition.name)
        self.connected.setdefault(key, (definition, set()))[1].add(
            (module, registration)
        )

    def callback(self, qualified):
        if qualified is None:
            return None
        if qualified in self.changed_providers:
            return None
        if qualified.startswith(_CALLBACK_INSTANCE):
            owner, _, method = qualified.removeprefix(_CALLBACK_INSTANCE).rpartition(
                "."
            )
            own = self.class_info(owner)
            if own is not None and method in own[2]:
                if owner + "." + method in self.changed_providers:
                    return None
                if isinstance(own[2][method], (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return self.callback(owner + "." + method)
                if isinstance(own[2][method], ast.If):
                    return self.callback(owner + "." + method)
                return None
            order = self.linearization(owner)
            if order is None:
                return None
            for name in order:
                info = self.class_info(name)
                if info is None or method not in info[2]:
                    continue
                if name + "." + method in self.changed_providers:
                    return None
                node = info[2][method]
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return None
                return self.callback(name + "." + method)
            return None
        candidates = self.index.all_by_name.get(qualified, ())
        functions = [item for item in candidates if item.type in {"function", "method"}]
        if len(functions) == 1:
            return functions[0]
        return None

    def linearization(self, qualified, active=()):
        # Unresolved bases are stored as None; treat them like the converter
        # registry so a single odd class cannot abort all signal proofs.
        if not isinstance(qualified, str) or not qualified:
            return None
        if qualified in self.mro_cache:
            return self.mro_cache[qualified]
        if qualified in active or len(active) >= 24:
            return None
        if qualified in {_APP_CONFIG, "builtins.object", *_SIGNAL_CLASSES}:
            return [qualified]
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
        order = [qualified, *merged]
        self.mro_cache[qualified] = order
        return order

    def signal_class(self, qualified):
        if qualified is None:
            return False
        order = self.linearization(qualified)
        if order is None or not _SIGNAL_CLASSES.intersection(order):
            return False
        for name in order:
            info = self.class_info(name)
            if info is not None and "connect" in info[2]:
                return False
            if name + ".connect" in self.changed_providers:
                return False
        return True

    def ready(self, qualified):
        order = self.linearization(qualified)
        if order is None or _APP_CONFIG not in order:
            return
        for name in order:
            info = self.class_info(name)
            if info is None or "ready" not in info[2]:
                continue
            method = info[2]["ready"]
            scanner = self.scanners[name.rpartition(".")[0]]
            changes = scanner.evidence.class_member_overrides
            if (
                name in changes
                or name + ".ready" in changes
                or name in self.changed_providers
                or name + ".ready" in self.changed_providers
            ):
                return
            if not isinstance(method, ast.FunctionDef) or method.decorator_list:
                return
            if any(
                isinstance(node, (ast.Yield, ast.YieldFrom))
                for statement in method.body
                for node in _eager_nodes(statement)
            ):
                return
            definition = scanner.evidence.definition(
                name + ".ready", line=method.lineno, kind="method"
            )
            if definition is not None:
                argument = ast.Name(id="_skylos_ready_instance", ctx=ast.Load())
                call = ast.Call(
                    func=ast.Name(id="ready", ctx=ast.Load()),
                    args=[argument],
                    keywords=[],
                )
                scanner.invoke(
                    (method, definition),
                    call,
                    {argument.id: _CALLBACK_INSTANCE + qualified},
                )
            return

    def configured_class(self, qualified):
        seen = set()
        while qualified not in seen and len(seen) < 24:
            seen.add(qualified)
            module, _, member = qualified.rpartition(".")
            scanner = self.scanners.get(module)
            if scanner is None:
                return None
            binding = scanner.bindings.get(member)
            if binding is None:
                return None
            if binding in scanner.evidence.classes:
                return binding
            qualified = binding
        return None

    def member_value(self, qualified, member):
        order = self.linearization(qualified)
        if order is None:
            return None
        for name in order:
            info = self.class_info(name)
            if info is None or member not in info[2]:
                continue
            node = info[2][member]
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                return node.value
            return None
        return None

    def app_configs(self, configured):
        selected = set()
        for entry in configured:
            explicit = self.configured_class(entry)
            if explicit is not None:
                order = self.linearization(explicit)
                if order is not None and _APP_CONFIG in order:
                    selected.add(explicit)
                continue
            scanner = self.scanners.get(entry + ".apps")
            if scanner is None:
                continue
            candidates = []
            defaults = []
            for name in scanner.evidence.classes:
                if self.configured_class(name) != name:
                    continue
                order = self.linearization(name)
                if order is None or _APP_CONFIG not in order:
                    continue
                default = self.member_value(name, "default")
                if default is not None:
                    if not isinstance(default, ast.Constant):
                        candidates.append((name, False))
                        continue
                    if not default.value:
                        continue
                    defaults.append(name)
                candidates.append((name, True))
            if len(candidates) == 1 and candidates[0][1]:
                selected.add(candidates[0][0])
            elif len(defaults) == 1 and all(valid for _, valid in candidates):
                selected.add(defaults[0])
        return selected


def find_django_signal_targets(definitions, parsed_files, root):
    """Return proven registrations with a separate unknown-loading reason.

    Django does not auto-import signals.py. A real registration in a module
    with no bounded loading proof remains possible external use, rather than
    a framework execution root or a definite unused-code finding.
    """
    signal_imports = {"django.dispatch", *_BUILTIN_SIGNALS}
    if not any(
        (
            item.type == "import"
            and any(
                item.name == provider or item.name.startswith(provider + ".")
                for provider in signal_imports
            )
        )
        or any(
            "receiver" in str(decorator).lower()
            for decorator in getattr(item, "decorators", ())
        )
        for item in definitions.values()
    ):
        return []
    parsed = list(parsed_files)
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    index = _DefinitionIndex(definitions, parsed, root)
    if "django" in index.shadowed:
        return []
    if not index.all_by_name:
        for definition in definitions.values():
            path = index._resolve_path(Path(definition.filename))
            if path in index.modules:
                index.all_by_name[definition.name].append(definition)
                index.all_by_location[(path, definition.line)].append(definition)
    registry = _SignalRegistry(index, parsed)
    for scanner in registry.scanners.values():
        scanner.collect()
    scanners = {name: scanner.evidence for name, scanner in registry.scanners.items()}
    classes = {
        name: info
        for scanner in scanners.values()
        for name, info in scanner.classes.items()
    }
    activation, _ = _settings_activation(scanners, classes)
    roots = set(activation.settings)
    roots.update(_route_modules(activation, scanners))
    roots.update(scanner.module for scanner in scanners.values() if scanner.settings)
    for app in activation.apps:
        roots.update({app, app + ".apps", app + ".models"})
    configured = set()
    for name in activation.settings:
        if name in scanners:
            configured.update(
                _member_names(scanners[name].values.get("INSTALLED_APPS"))
            )
    configs = registry.app_configs(configured)
    for name in configs:
        roots.add(name.rpartition(".")[0])
        app = _literal(registry.member_value(name, "name"))
        if isinstance(app, str):
            roots.update({app, app + ".models"})
        registry.ready(name)
    loaded = _loaded_modules(roots, scanners)
    targets = []
    for definition, registrations in registry.connected.values():
        # The dispatcher supplies callback keyword arguments. Keep the
        # existing external callback signature contract, including when
        # loading or an external signal provider remains unresolved.
        for parameter in index.parameters.get(definition.name, {}).values():
            _mark_contract_parameter(parameter)
        reason = "django_signal_registration_unknown_loading"
        if any(
            module in loaded and status == "proven" for module, status in registrations
        ):
            reason = "django_web_signal_receiver"
        elif not any(status == "proven" for _, status in registrations):
            reason = "signal_registration_unknown_provider"
        targets.append((definition, reason))
    return targets
