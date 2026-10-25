"""FastAPI callback contracts attached to source-proven app and router objects."""

from __future__ import annotations

import ast
from collections import defaultdict
from types import SimpleNamespace

from skylos.deadcode.framework_liveness import _eager_nodes


_BASE_HTTP_MIDDLEWARE = "starlette.middleware.base.BaseHTTPMiddleware"
_MIDDLEWARE = {"starlette.middleware.Middleware", "fastapi.middleware.Middleware"}
_CALLBACK_ARGUMENTS = {
    "lifespan": 1,
    "exception_handler": 2,
    "middleware": 2,
    "startup": 0,
    "shutdown": 0,
}


def _keyword(call, name):
    return next((item.value for item in call.keywords if item.arg == name), None)


def _argument(call, index, name):
    keyword = _keyword(call, name)
    if keyword is not None:
        return keyword
    if len(call.args) > index:
        return call.args[index]
    return None


def _node(project, expression, bindings, module):
    if expression is None:
        return None, bindings, module
    return project.resolve_node(expression, bindings, module)


def _literal(project, expression, bindings, module):
    node, _, _ = _node(project, expression, bindings, module)
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _sequence(project, expression, bindings, module):
    node, context, source = _node(project, expression, bindings, module)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [(item, context, source) for item in node.elts]
    return []


def _mapping_values(project, expression, bindings, module):
    node, context, source = _node(project, expression, bindings, module)
    if isinstance(node, ast.Dict):
        return [(item, context, source) for item in node.values]
    return []


def _external_provider(project, provider, allowed):
    return (
        provider in allowed
        and provider not in project.classes
        and provider not in project.functions
        and provider.split(".", 1)[0] not in project.shadowed
    )


def _callback(project, expression, bindings, module):
    value = project.resolve(expression, bindings, module)
    # Constructor callbacks need a separate factory contract. This collector
    # handles source functions and actual callable instances.
    if value in project.classes:
        return value, None
    return value, project.callable(value)


def _transparent_callback(project, function, role):
    generators = any(
        isinstance(node, (ast.Yield, ast.YieldFrom))
        for statement in function.node.body
        for node in _eager_nodes(statement)
    )
    if generators and role != "lifespan":
        return False
    if (
        role == "lifespan"
        and isinstance(function.node, ast.AsyncFunctionDef)
        and not generators
    ):
        return False
    if not function.node.decorator_list:
        return True
    if function.invocable:
        return True
    for decorator in function.node.decorator_list:
        plain = decorator.func if isinstance(decorator, ast.Call) else decorator
        provider = project.resolve(plain, function.bindings, function.module)
        if role == "lifespan" and provider == "contextlib.asynccontextmanager":
            continue
        registered = any(
            event.callback.key == function.key
            and event.proven
            and event.method in {"middleware", "exception_handler", "on_event"}
            and event.source_decorator.lineno == decorator.lineno
            and event.source_decorator.col_offset == decorator.col_offset
            for event in project.decorators
        )
        if registered:
            continue
        bound = project.bound_methods.get(provider)
        if (
            bound is not None
            and bound.proven
            and bound.method in {"middleware", "exception_handler", "on_event"}
        ):
            continue
        return False
    return True


def _parameter_keys(project, value, function, count):
    arguments = function.node.args
    positional = [*arguments.posonlyargs, *arguments.args]
    if project.is_bound(value) and positional:
        positional = positional[1:]
    selected = positional[:count]
    if len(positional) < count and arguments.vararg is not None:
        selected.append(arguments.vararg)
    return {(function.key[0], argument.lineno, argument.arg) for argument in selected}


class _Hooks:
    def __init__(self, project, report):
        self.project = project
        self.report = report
        self.registrations = defaultdict(list)
        self.custom_lifespans = set()
        self.uncertain_event = False

    def add(
        self, owner, expression, bindings, module, role, *, executed, decorator=False
    ):
        if expression is None:
            return
        value, callback = _callback(self.project, expression, bindings, module)
        if callback is None:
            return
        self.add_callable(
            owner, value, callback, role, executed=executed, decorator=decorator
        )

    def add_callable(self, owner, value, callback, role, *, executed, decorator=False):
        self.report.candidates.add(callback.key)
        if decorator:
            self.report.decorator_candidates.add(callback.key)
        instance = self.project.objects.get(owner)
        if not executed or instance is None or instance.kind not in {"app", "router"}:
            return
        if not _transparent_callback(self.project, callback, role):
            self.report.uncertain.add(callback.key)
            return
        self.registrations[owner].append((value, callback, role, self.uncertain_event))

    def constructor(self, event):
        self.uncertain_event = event.uncertain
        call = event.node
        owner = event.object_key
        lifespan = _keyword(call, "lifespan")
        if lifespan is not None:
            value, _, _ = _node(self.project, lifespan, event.bindings, event.module)
            if not isinstance(value, ast.Constant) or value.value is not None:
                self.custom_lifespans.add(owner)
            self.add(
                owner,
                lifespan,
                event.bindings,
                event.module,
                "lifespan",
                executed=event.executed and event.proven,
            )
        for keyword, role in (("on_startup", "startup"), ("on_shutdown", "shutdown")):
            for callback, bindings, module in _sequence(
                self.project, _keyword(call, keyword), event.bindings, event.module
            ):
                self.add(
                    owner,
                    callback,
                    bindings,
                    module,
                    role,
                    executed=event.executed and event.proven,
                )
        for callback, bindings, module in _mapping_values(
            self.project,
            _keyword(call, "exception_handlers"),
            event.bindings,
            event.module,
        ):
            self.add(
                owner,
                callback,
                bindings,
                module,
                "exception_handler",
                executed=event.executed and event.proven,
            )
        for middleware, bindings, module in _sequence(
            self.project, _keyword(call, "middleware"), event.bindings, event.module
        ):
            node, bindings, module = _node(self.project, middleware, bindings, module)
            if isinstance(node, ast.Call) and _external_provider(
                self.project,
                self.project.resolve(node.func, bindings, module),
                _MIDDLEWARE,
            ):
                self.middleware(
                    owner,
                    node,
                    bindings,
                    module,
                    executed=event.executed and event.proven,
                )

    def middleware(self, owner, call, bindings, module, *, executed):
        middleware = _argument(call, 0, "middleware_class")
        provider = self.project.resolve(middleware, bindings, module)
        dispatch = _keyword(call, "dispatch")
        # Only BaseHTTPMiddleware specifies that dispatch(request, call_next)
        # is consumed. Arbitrary middleware kwargs do not establish that role.
        self.add(
            owner,
            dispatch,
            bindings,
            module,
            "middleware",
            executed=executed
            and _external_provider(self.project, provider, {_BASE_HTTP_MIDDLEWARE}),
        )

    def unresolved_receiver(self, event):
        if not event.executed or event.proven or not event.module.mentions_fastapi:
            return False
        if not isinstance(event.node.func, ast.Attribute):
            return False
        receiver = self.project.resolve(
            event.node.func.value, event.bindings, event.module
        )
        instance = self.project.objects.get(receiver)
        if instance is not None:
            # A known local object or a replaced method on a real app is
            # contrary evidence, not an unresolved framework receiver.
            return instance.kind == "unknown"
        if receiver in self.project.classes or receiver in self.project.modules:
            return False
        if self.project.callable(event.target) is not None:
            return False
        if receiver is None:
            return True
        if receiver in self.project.values:
            value, _, _ = self.project.resolve_node(
                event.node.func.value, event.bindings, event.module
            )
            return isinstance(value, ast.Call)
        return False

    def uncertain_callback(self, event, expression, role):
        if expression is None:
            return
        value, callback = _callback(
            self.project, expression, event.bindings, event.module
        )
        if callback is None:
            return
        self.report.candidates.add(callback.key)
        self.report.uncertain.add(callback.key)
        if _transparent_callback(self.project, callback, role):
            self.report.callback_parameters.update(
                _parameter_keys(
                    self.project, value, callback, _CALLBACK_ARGUMENTS[role]
                )
            )

    def call(self, event):
        self.uncertain_event = event.uncertain
        call = event.node
        if event.method == "add_exception_handler":
            if self.unresolved_receiver(event):
                self.uncertain_callback(
                    event, _argument(call, 1, "handler"), "exception_handler"
                )
            self.add(
                event.receiver,
                _argument(call, 1, "handler"),
                event.bindings,
                event.module,
                "exception_handler",
                executed=event.executed and event.proven,
            )
        elif event.method == "add_middleware":
            self.middleware(
                event.receiver,
                call,
                event.bindings,
                event.module,
                executed=event.executed and event.proven,
            )
        elif event.method == "add_event_handler":
            event_type = _literal(
                self.project,
                _argument(call, 0, "event_type"),
                event.bindings,
                event.module,
            )
            role = "startup"
            if event_type == "shutdown":
                role = "shutdown"
            self.add(
                event.receiver,
                _argument(call, 1, "func"),
                event.bindings,
                event.module,
                role,
                executed=event.executed
                and event.proven
                and event_type in {"startup", "shutdown"},
            )

    def decorator(self, event):
        self.uncertain_event = event.uncertain
        role = None
        valid = True
        if event.method == "middleware":
            role = "middleware"
            valid = (
                _literal(
                    self.project,
                    _argument(event.node, 0, "middleware_type"),
                    event.bindings,
                    event.module,
                )
                == "http"
            )
        elif event.method == "exception_handler":
            role = "exception_handler"
        elif event.method == "on_event":
            role = _literal(
                self.project,
                _argument(event.node, 0, "event_type"),
                event.bindings,
                event.module,
            )
            valid = role in {"startup", "shutdown"}
            if not valid:
                role = "startup"
        if role is not None:
            self.decorator_site(event.callback, event.source_decorator)
            self.add_callable(
                event.receiver,
                event.callback.name,
                event.callback,
                role,
                executed=event.executed and event.proven and valid,
                decorator=True,
            )

    def decorator_site(self, callback, decorator):
        self.report.candidates.add(callback.key)
        self.report.decorator_candidates.add(callback.key)
        sites = self.report.decorator_sites
        if isinstance(sites, dict):
            sites.setdefault(callback.key, []).append(decorator)
        else:
            sites.add((*callback.key, decorator.lineno, decorator.col_offset))

    def syntactic_decorator_candidates(self):
        # A replaced or fake method can cease resolving as a registration,
        # while the visitor's old wildcard decorator hint still exists.
        for callback in self.project.functions.values():
            for decorator in callback.node.decorator_list:
                plain = decorator.func if isinstance(decorator, ast.Call) else decorator
                if not isinstance(plain, ast.Attribute) or plain.attr not in {
                    "middleware",
                    "exception_handler",
                    "on_event",
                }:
                    continue
                receiver = self.project.resolve(
                    plain.value, callback.bindings, callback.module
                )
                instance = self.project.objects.get(receiver)
                if instance is not None and instance.kind == "foreign":
                    continue
                if isinstance(receiver, str) and receiver.split(".", 1)[0] in {
                    "flask",
                    "starlette",
                    "aiohttp",
                    "sanic",
                    "django",
                }:
                    continue
                self.decorator_site(callback, decorator)

    def finish(self):
        for owner, callbacks in self.registrations.items():
            for value, callback, role, uncertain in callbacks:
                if role in {"startup", "shutdown"} and owner in self.custom_lifespans:
                    continue
                self.report.callback_parameters.update(
                    _parameter_keys(
                        self.project, value, callback, _CALLBACK_ARGUMENTS[role]
                    )
                )
                if owner in self.project.active_objects and not uncertain:
                    self.report.roots.add(callback.key)
                else:
                    # An actual standalone router can be included by a caller
                    # outside this project; its contract is not proof of startup.
                    self.report.uncertain.add(callback.key)


def _conditional_event(project, report, event):
    """Retain possible registrations without executing an uncalled owner."""
    if event.executed or not event.uncertain:
        return event
    caller = project.functions.get(event.owner)
    possible_owner = event.owner is None or (
        caller is not None and caller.key in project.executed_callables | report.roots
    )
    if possible_owner:
        return SimpleNamespace(**{**vars(event), "executed": True})
    return event


def collect_fastapi_hooks(project, report):
    """Add callback roots and exact injected-signature parameter identities."""
    hooks = _Hooks(project, report)
    for event in project.constructors:
        hooks.constructor(_conditional_event(project, report, event))
    for event in project.calls:
        hooks.call(_conditional_event(project, report, event))
    for event in project.decorators:
        hooks.decorator(_conditional_event(project, report, event))
    hooks.syntactic_decorator_candidates()
    hooks.finish()
