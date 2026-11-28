"""Prove Starlette dispatch from route tables and application mounts."""

from __future__ import annotations

import ast
from collections import defaultdict
from functools import cached_property

from skylos.deadcode.fastapi_hook_proofs import _argument, _keyword

_ROUTE = "starlette.routing.Route"
_WEBSOCKET_ROUTE = "starlette.routing.WebSocketRoute"
_MOUNTS = {"starlette.routing.Mount", "starlette.routing.Host"}
_APP_KINDS = {"app", "router", "starlette_app", "starlette_router"}
_HTTP_ENDPOINT = "starlette.endpoints.HTTPEndpoint"
_WEBSOCKET_ENDPOINT = "starlette.endpoints.WebSocketEndpoint"
_HTTP_METHODS = (
    "get",
    "head",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "query",
)
_WEBSOCKET_METHODS = {
    "on_connect": 1,
    "on_receive": 2,
    "on_disconnect": 2,
    "decode": 2,
}
_MAX_SOURCE_USE_NODES = 200_000
_DYNAMIC_NAMES = {"eval", "exec", "globals", "locals", "vars"}


class _Routes:
    def __init__(self, project, closed_world):
        self.project = project
        self.report = project.report
        self.closed_world = closed_world
        self.route_events = [
            event
            for event in project.calls
            if event.executed
            and not event.uncertain
            and event.target in {_ROUTE, _WEBSOCKET_ROUTE}
        ]
        self.consumed = set()
        self.tables = defaultdict(list)
        self.constructors = defaultdict(set)
        self.visited_tables = set()
        self.pending_tables = []

    def collect(self):
        for event in self.project.constructors:
            if (
                event.executed
                and event.proven
                and not event.uncertain
                and event.kind in _APP_KINDS
            ):
                obj = self.project.objects[event.object_key]
                if self.project._class_member(obj.class_name, "__init__") is not None:
                    continue
                routes = _keyword(event.node, "routes")
                if routes is None and event.kind == "starlette_router":
                    routes = _argument(event.node, 0, "routes")
                self.tables[event.object_key].append(
                    (routes, event.bindings, event.module)
                )
                self.constructors[event.module.path, id(event.node)].add(
                    event.object_key
                )
        for owner in tuple(self.project.active_objects):
            self.visit_router(owner)
        while self.pending_tables:
            self.visit_table(*self.pending_tables.pop())
        if self.closed_world:
            self.discard_detached_tables()

    def visit_router(self, owner):
        if owner in self.visited_tables:
            return
        self.visited_tables.add(owner)
        self.pending_tables.extend(self.tables.get(owner, ()))

    def visit_table(self, node, bindings, module):
        sequence, bindings, module = self.project.resolve_node(node, bindings, module)
        if not isinstance(sequence, (ast.List, ast.Tuple)):
            return
        site = str(module.path), id(sequence), id(bindings)
        if site in self.visited_tables:
            return
        self.visited_tables.add(site)
        for route in sequence.elts:
            self.project._step()
            route, route_bindings, source = self.project.resolve_node(
                route, bindings, module
            )
            if not isinstance(route, ast.Call):
                continue
            provider = self.project.resolve(route.func, route_bindings, source)
            if provider in {_ROUTE, _WEBSOCKET_ROUTE}:
                endpoint = _argument(route, 1, "endpoint")
                target = self.project.resolve(endpoint, route_bindings, source)
                if self.activate(target, provider, route, route_bindings, source):
                    self.consumed.add((source.path, id(route)))
            elif provider in _MOUNTS:
                child = _argument(route, 1, "app")
                child_key = self.project.resolve(child, route_bindings, source)
                self.visit_router(child_key)
                value, _, child_module = self.project.resolve_node(
                    child, route_bindings, source
                )
                if isinstance(value, ast.Call):
                    for owner in self.constructors.get(
                        (child_module.path, id(value)), ()
                    ):
                        self.visit_router(owner)
                if provider == "starlette.routing.Mount" and (
                    child is None
                    or isinstance(value, ast.Constant)
                    and value.value is None
                ):
                    self.pending_tables.append(
                        (_argument(route, 2, "routes"), route_bindings, source)
                    )

    def activate(self, target, provider, route, bindings, module):
        cls = self.project.classes.get(target)
        if cls is None:
            callback = self.project.callable(target)
            if callback is None or not callback.invocable:
                return False
            self.add_callback(callback, 1)
            return True
        bases = self.project._mro(target) or ()
        if provider == _WEBSOCKET_ROUTE and _WEBSOCKET_ENDPOINT in bases:
            methods = _WEBSOCKET_METHODS
        elif provider == _ROUTE and _HTTP_ENDPOINT in bases:
            methods = self.http_methods(target, route, bindings, module)
        else:
            return False
        self.report.roots.add(cls.key)
        for name, count in methods.items():
            callback = self.project.callable(self.project._class_member(target, name))
            if callback is not None and callback.invocable:
                self.add_callback(callback, count, method=True)
        return True

    def http_methods(self, target, route, bindings, module):
        allowed = set(_HTTP_METHODS)
        value, _, _ = self.project.resolve_node(
            _keyword(route, "methods"), bindings, module
        )
        if (
            isinstance(value, (ast.List, ast.Tuple, ast.Set))
            and value.elts
            and all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in value.elts
            )
        ):
            allowed.intersection_update(item.value.lower() for item in value.elts)
            if "get" in allowed:
                allowed.add("head")
        if "head" in allowed and self.project._class_member(target, "head") is None:
            allowed.add("get")
        return dict.fromkeys(allowed, 1)

    def add_callback(self, callback, count, *, method=False):
        self.report.roots.add(callback.key)
        self.report.candidates.add(callback.key)
        parameters = [*callback.node.args.posonlyargs, *callback.node.args.args]
        offset = int(method or callback.bound)
        for parameter in parameters[offset : offset + count]:
            self.report.callback_parameters.add(
                (str(callback.module.path), parameter.lineno, parameter.arg)
            )

    @cached_property
    def source_uses(self):
        """Conservatively count name reads, imports, exports and attribute uses."""
        parents = {}
        used = set()
        visited = 0
        for module in self.project.modules.values():
            for node in ast.walk(module.tree):
                visited += 1
                if visited > _MAX_SOURCE_USE_NODES:
                    return None
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id in _DYNAMIC_NAMES:
                        return None
                    used.add(node.id)
                elif isinstance(node, ast.Attribute):
                    used.add(node.attr)
                elif isinstance(node, ast.ImportFrom):
                    used.update(alias.name for alias in node.names)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    used.add(node.value)
                for child in ast.iter_child_nodes(node):
                    parents[id(child)] = node
        return parents, used

    def detached(self, event):
        if self.source_uses is None:
            return False
        parents, used = self.source_uses
        if "*" in used:
            return False
        current = event.node
        parent = parents.get(id(current))
        while isinstance(parent, (ast.List, ast.Tuple)):
            current, parent = parent, parents.get(id(parent))
        if (
            not isinstance(parent, ast.Assign)
            or parent.value is not current
            or len(parent.targets) != 1
            or not isinstance(parent.targets[0], ast.Name)
            or not isinstance(parents.get(id(parent)), ast.Module)
        ):
            return False
        return parent.targets[0].id not in used

    def discard_detached_tables(self):
        for event in self.route_events:
            if (
                event.owner is not None
                or (event.module.path, id(event.node)) in self.consumed
            ):
                continue
            endpoint = _argument(event.node, 1, "endpoint")
            if not isinstance(endpoint, ast.Name) or not self.detached(event):
                continue
            value = self.project.resolve(endpoint, event.bindings, event.module)
            callback = self.project.callable(value)
            if (
                callback is None
                or not callback.invocable
                or callback.module is not event.module
                or endpoint.id != callback.node.name
            ):
                continue
            path = event.module.path
            self.report.candidates.add(callback.key)
            self.report.registration_argument_sites.add(
                (path, endpoint.lineno, endpoint.col_offset)
            )
            route_path = _argument(event.node, 0, "path")
            if isinstance(route_path, ast.Constant):
                self.report.registration_argument_sites.add(
                    (path, route_path.lineno, route_path.col_offset)
                )
            self.report.discarded_argument_refs.append((callback.name, str(path)))


def collect_starlette_liveness(project, *, closed_world=False):
    if "starlette" not in project.shadowed:
        routes = _Routes(project, closed_world)
        if routes.route_events or any(
            _keyword(event.node, "routes") is not None for event in project.constructors
        ):
            routes.collect()
