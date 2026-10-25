"""Source-bound FastAPI dependency and injected-parameter contracts."""

from __future__ import annotations

import ast
from dataclasses import dataclass


_DEPENDENCY_PROVIDERS = {
    "fastapi.Depends",
    "fastapi.Security",
    "fastapi.param_functions.Depends",
    "fastapi.param_functions.Security",
    "fastapi.params.Depends",
    "fastapi.params.Security",
}
_ANNOTATED_PROVIDERS = {"typing.Annotated", "typing_extensions.Annotated"}
_FIELD_NAMES = {"Query", "Path", "Body", "Header", "Cookie", "Form", "File"}


@dataclass(frozen=True)
class _Marker:
    dependency: ast.AST | None
    bindings: dict
    module: object


def _module(project, module):
    if isinstance(module, str):
        return project.modules[module]
    return module


def _expanded(project, node, bindings, module):
    if node is None:
        return node, bindings, module
    expanded = project.resolve_node(node, bindings, module)
    if expanded is None:
        return node, bindings, module
    return expanded


def _keyword(node, name):
    return next((item.value for item in node.keywords if item.arg == name), None)


def _provider(project, node, bindings, module):
    value = project.resolve(node, bindings, module)
    if not isinstance(value, str):
        return None
    if value.split(".", 1)[0] in project.shadowed:
        return None
    if value in project.functions or value in project.classes:
        return None
    return value


def _marker(project, node, bindings, module):
    node, bindings, module = _expanded(project, node, bindings, module)
    if not isinstance(node, ast.Call):
        return None
    if _provider(project, node.func, bindings, module) not in _DEPENDENCY_PROVIDERS:
        return None
    dependency = node.args[0] if node.args else _keyword(node, "dependency")
    if isinstance(dependency, ast.Constant) and dependency.value is None:
        dependency = None
    return _Marker(dependency, bindings, module)


def _annotation(project, node, bindings, module):
    node, bindings, module = _expanded(project, node, bindings, module)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            node = ast.parse(node.value, mode="eval").body
        except (SyntaxError, ValueError):
            return None, bindings, module, None
        node, bindings, module = _expanded(project, node, bindings, module)
    if not isinstance(node, ast.Subscript):
        return node, bindings, module, None
    if _provider(project, node.value, bindings, module) not in _ANNOTATED_PROVIDERS:
        return node, bindings, module, None
    parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
    marker = None
    for metadata in parts[1:]:
        selected = _marker(project, metadata, bindings, module)
        if selected is not None:
            marker = selected
            continue
        value, context, source = _expanded(project, metadata, bindings, module)
        if isinstance(value, ast.Call):
            provider = _provider(project, value.func, context, source)
            if provider in {
                prefix + name
                for prefix in (
                    "fastapi.",
                    "fastapi.param_functions.",
                    "fastapi.params.",
                )
                for name in _FIELD_NAMES
            }:
                marker = None
    return parts[0], bindings, module, marker


def _parameters(node):
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults))
    yield from zip(positional, [*defaults, *node.args.defaults])
    yield from zip(node.args.kwonlyargs, node.args.kw_defaults)


def _legacy_marker_candidates(project, report):
    """Identify old name-only hints to reconcile, without proving execution."""
    aliases = {}
    for module in project.modules.values():
        names = {"Depends", "Security"}
        for node in ast.walk(module.tree):
            if isinstance(node, ast.ImportFrom) and node.module == "fastapi":
                names.update(
                    item.asname or item.name
                    for item in node.names
                    if item.name in {"Depends", "Security"}
                )
        aliases[module.name] = names

    contexts = []
    for callback in project.functions.values():
        for argument, default in _parameters(callback.node):
            contexts.extend(
                (node, callback.bindings, callback.module, argument.annotation)
                for node in (default, argument.annotation)
                if node is not None
            )
        if callback.node.returns is not None:
            contexts.append(
                (callback.node.returns, callback.bindings, callback.module, None)
            )
    for value in project.values.values():
        contexts.append((value.node, value.bindings, value.module, None))
    for event in [*project.calls, *project.decorators, *project.constructors]:
        contexts.append((event.node, event.bindings, event.module, None))

    for expression, bindings, module, fallback in contexts:
        module = _module(project, module)
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call):
                continue
            spelling = getattr(node.func, "id", None)
            attribute = getattr(node.func, "attr", None)
            provider = project.resolve(node.func, bindings, module)
            if (
                spelling not in aliases[module.name]
                and attribute not in {"Depends", "Security"}
                and provider not in _DEPENDENCY_PROVIDERS
            ):
                continue
            dependency = node.args[0] if node.args else _keyword(node, "dependency")
            if dependency is None and fallback is not None:
                dependency = fallback
                if isinstance(fallback, ast.Subscript):
                    dependency = fallback.slice
                    if isinstance(dependency, ast.Tuple):
                        dependency = dependency.elts[0]
            if dependency is None:
                continue
            value = project.resolve(dependency, bindings, module)
            cls = project.classes.get(value)
            if cls is not None:
                report.candidates.add(cls.key)
                report.decorator_candidates.add(cls.key)
            callback = project.callable(value)
            if callback is not None:
                report.candidates.add(callback.key)
                report.decorator_candidates.add(callback.key)


def collect_fastapi_dependencies(project, report):
    """Attach dependencies to real registered consumers, retaining weak routers."""
    _legacy_marker_candidates(project, report)
    visited = set()

    def mark(key, strong):
        report.candidates.add(key)
        report.decorator_candidates.add(key)
        if strong:
            report.roots.add(key)
            report.uncertain.discard(key)
        elif key not in report.roots:
            report.uncertain.add(key)

    def dependency(node, bindings, module, strong):
        if node is None:
            return
        value = project.resolve(node, bindings, module)
        cls = project.classes.get(value)
        if cls is not None:
            mark(cls.key, strong)
        callback = project.callable(value)
        if callback is not None:
            consume(callback, strong)

    def consume(callback, strong):
        if not callback.invocable:
            mark(callback.key, False)
            return
        state = callback.key, strong
        if state in visited:
            return
        visited.add(state)
        mark(callback.key, strong)
        module = _module(project, callback.module)
        for argument, default in _parameters(callback.node):
            annotation, context, source, annotated = _annotation(
                project, argument.annotation, callback.bindings, module
            )
            marker = _marker(project, default, callback.bindings, module)
            if marker is None:
                marker = annotated
            if marker is None:
                continue
            report.injected_parameters.add(
                (str(module.path.resolve()), argument.lineno, argument.arg)
            )
            if marker.dependency is None:
                dependency(annotation, context, source, strong)
            else:
                dependency(marker.dependency, marker.bindings, marker.module, strong)

    def explicit(node, bindings, module, strong):
        node, bindings, module = _expanded(project, node, bindings, module)
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return
        for item in node.elts:
            marker = _marker(project, item, bindings, module)
            if marker is not None:
                dependency(marker.dependency, marker.bindings, marker.module, strong)

    children = {}
    for call in project.calls:
        if call.executed and call.proven and call.method == "include_router":
            child = _keyword(call.node, "router")
            if child is None and call.node.args:
                child = call.node.args[0]
            value = project.resolve(child, call.bindings, call.module)
            if value is not None:
                children.setdefault(call.receiver, set()).add(value)

    routed = {
        item.object_key
        for item in project.registrations
        if item.executed and item.proven
    }

    def has_routes(object_key):
        pending = [object_key]
        visited_objects = set()
        while pending:
            current = pending.pop()
            if current in visited_objects:
                continue
            if current in routed:
                return True
            visited_objects.add(current)
            pending.extend(children.get(current, ()))
        return False

    for registration in project.registrations:
        if not registration.proven:
            continue
        if (
            registration.callback.key not in report.roots
            and registration.callback.key not in report.uncertain
        ):
            continue
        if not registration.executed:
            owner = getattr(registration, "owner", None)
            caller = project.functions.get(owner)
            possible = owner is None or (
                caller is not None
                and caller.key in project.executed_callables | report.roots
            )
            if not registration.uncertain or not possible:
                continue
        strong = registration.callback.key in report.roots
        consume(registration.callback, strong)
        explicit(
            _keyword(registration.node, "dependencies"),
            registration.bindings,
            registration.module,
            strong,
        )
    for constructor in project.constructors:
        if (
            not constructor.executed
            or not constructor.proven
            or constructor.kind not in {"app", "router"}
        ):
            continue
        strong = constructor.object_key in project.active_objects and has_routes(
            constructor.object_key
        )
        explicit(
            _keyword(constructor.node, "dependencies"),
            constructor.bindings,
            constructor.module,
            strong,
        )
    for call in project.calls:
        receiver = project.objects.get(call.receiver)
        if (
            not call.executed
            or not call.proven
            or receiver is None
            or receiver.kind not in {"app", "router"}
            or call.method
            not in {"include_router", "add_api_route", "add_api_websocket_route"}
        ):
            continue
        strong = call.receiver in project.active_objects and has_routes(call.receiver)
        explicit(
            _keyword(call.node, "dependencies"), call.bindings, call.module, strong
        )
    return report
