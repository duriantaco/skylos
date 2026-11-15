"""Functions a decorator hands to code outside the project.

``@factory(key)`` is ``f = factory(key)(f)``: a factory imported from a
third-party distribution receives the function object together with a key, so
it can keep the function and call it later. The standard library and the
wrapper libraries listed here only wrap. A project decorator that applies such
a registration to its argument, or to a closure over it, registers every
function it decorates; one that only wraps and returns registers nothing.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _decorator_reference,
    _first_param,
    _import_aliases,
    _own_body_nodes,
    _resolved,
)
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.visitors.framework_aware import (
    ROUTE_METHODS,
    WRAPPER_DECORATOR_MODULES,
    is_registration_decorator,
)
from skylos.visitors.registration_decorators import (
    _is_registration_decorator,
    _returned_local_function_names,
)

_MAX_ALIAS_HOPS = 8
_MAX_FORWARDING_ROUNDS = 4
_MAX_BASE_DEPTH = 16
_SOURCE_ROOTS = frozenset({"src", "lib", "python"})
_WRAPPER_LIBRARIES = WRAPPER_DECORATOR_MODULES | frozenset(
    {
        "aiocache",
        "asgiref",
        "async_lru",
        "backoff",
        "beartype",
        "cachetools",
        "cachier",
        "click",
        "cloup",
        "cupy",
        "cython",
        "datadog",
        "ddt",
        "ddtrace",
        "decorator",
        "deprecated",
        "deprecation",
        "django",
        "elasticapm",
        "flask_login",
        "freezegun",
        "func_timeout",
        "future",
        "hypothesis",
        "jax",
        "joblib",
        "langfuse",
        "langsmith",
        "line_profiler",
        "logfire",
        "loguru",
        "memoization",
        "memory_profiler",
        "methodtools",
        "mlflow",
        "mock",
        "moto",
        "newrelic",
        "nose",
        "numba",
        "numpy",
        "opentelemetry",
        "overrides",
        "parameterized",
        "prometheus_client",
        "pyinstrument",
        "ratelimit",
        "responses",
        "respx",
        "rest_framework",
        "retry",
        "retrying",
        "rich_click",
        "sentry_sdk",
        "six",
        "stamina",
        "statsd",
        "structlog",
        "tenacity",
        "tensorflow",
        "time_machine",
        "timeout_decorator",
        "torch",
        "typeguard",
        "vcr",
        "viztracer",
        "wandb",
        "weave",
        "wrapt",
    }
)


@dataclass
class _Scope:
    parsed: ParsedPythonFile
    file_key: str
    module: str
    names: dict[str, str]
    modules: dict[str, str]
    local_names: set[str]


@dataclass
class _ClassInfo:
    bases: list[str | None]
    members: set[str]


@dataclass
class _State:
    project_tops: set[str]
    forwarding: set[str] = field(default_factory=set)
    aliases: dict[str, str] = field(default_factory=dict)
    classes: dict[str, _ClassInfo] = field(default_factory=dict)

    def is_external(self, dotted: str | None) -> bool:
        if not dotted:
            return False
        top = dotted.split(".", 1)[0]
        if not top or top in self.project_tops:
            return False
        if top in sys.stdlib_module_names or top in _WRAPPER_LIBRARIES:
            return False
        return True

    def resolve(self, name: str | None, known) -> str | None:
        for _ in range(_MAX_ALIAS_HOPS):
            if name is None or name in known:
                return name
            name = self.aliases.get(name)
        return None


def _project_tops(module_names: dict[str, str], root: Path | None) -> set[str]:
    tops = set()
    for path, name in module_names.items():
        if name:
            tops.add(name.split(".", 1)[0])
        if root is None:
            continue
        try:
            parts = Path(path).resolve().relative_to(root).with_suffix("").parts
        except (OSError, ValueError):
            continue
        if not parts:
            continue
        tops.add(parts[0])
        if parts[0] in _SOURCE_ROOTS and len(parts) > 1:
            tops.add(parts[1])
    return tops


def _module_local_names(tree: ast.Module) -> set[str]:
    names = set()
    for stmt in tree.body:
        if isinstance(stmt, (*_FUNCTION_NODES, ast.ClassDef)):
            names.add(stmt.name)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        for node in ast.walk(stmt):
            if isinstance(node, _FUNCTION_NODES):
                break
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


def _attribute_chain(node: ast.AST) -> tuple[str | None, list[str]]:
    attrs = []
    current = node
    while isinstance(current, ast.Attribute):
        attrs.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        attrs.reverse()
        return current.id, attrs
    return None, []


def _import_origin(node: ast.AST, scope: _Scope) -> str | None:
    root, attrs = _attribute_chain(node)
    if root is None or root in scope.local_names:
        return None
    origin = scope.names.get(root) or scope.modules.get(root)
    if origin is None:
        return None
    return ".".join([origin, *attrs])


def _qualified_reference(node: ast.AST, scope: _Scope) -> str | None:
    root, attrs = _attribute_chain(node)
    if root is None:
        return None
    if root in scope.local_names:
        return ".".join([scope.module, root, *attrs])
    origin = scope.names.get(root) or scope.modules.get(root)
    if origin is None:
        return None
    return ".".join([origin, *attrs])


def _has_arguments(call: ast.Call) -> bool:
    return bool(call.args or call.keywords)


def _inherits_external_member(name: str, member: str, state: _State) -> bool:
    pending = [(name, 0)]
    seen = set()
    external = False
    while pending:
        current, depth = pending.pop()
        if current in seen or depth > _MAX_BASE_DEPTH:
            continue
        seen.add(current)
        info = state.classes.get(state.resolve(current, state.classes) or "")
        if info is None:
            if state.is_external(current):
                external = True
            continue
        if member in info.members:
            return False
        for base in info.bases:
            if base is None:
                return False
            pending.append((base, depth + 1))
    return external


def _is_external_factory(decorator: ast.AST, scope: _Scope, state: _State) -> bool:
    if not isinstance(decorator, ast.Call) or not _has_arguments(decorator):
        return False
    origin = _import_origin(decorator.func, scope)
    if state.is_external(origin):
        return True
    root, attrs = _attribute_chain(decorator.func)
    if root is None or len(attrs) != 1:
        return False
    owner = _qualified_reference(ast.Name(id=root, ctx=ast.Load()), scope)
    if owner is None or state.resolve(owner, state.classes) is None:
        return False
    return _inherits_external_member(owner, attrs[0], state)


def _dotted_text(node: ast.AST) -> str | None:
    root, attrs = _attribute_chain(node)
    if root is None:
        return None
    return ".".join([root, *attrs])


def _is_registration_expression(
    expression: ast.AST, scope: _Scope, state: _State, *, applied_bare: bool
) -> bool:
    target = expression
    if isinstance(expression, ast.Call):
        target = expression.func
    dotted = _dotted_text(target)
    if dotted is None:
        return False
    qualified = _qualified_reference(target, scope)
    if state.resolve(qualified, state.forwarding) is not None:
        return True
    if _is_external_factory(expression, scope, state):
        return True
    origin = _import_origin(target, scope)
    if isinstance(target, ast.Name):
        if origin is None or not state.is_external(origin):
            return False
        return is_registration_decorator(target.id, origin)
    if applied_bare and target.attr in ROUTE_METHODS:
        return False
    return is_registration_decorator(dotted, origin)


def _mentions(node: ast.AST, names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _registers_parameter(
    node: ast.FunctionDef | ast.AsyncFunctionDef, scope: _Scope, state: _State
) -> bool:
    param = _first_param(node)
    if param is None:
        return False
    carriers = {param}
    for stmt in node.body:
        if isinstance(stmt, _FUNCTION_NODES) and _mentions(stmt, {param}):
            carriers.add(stmt.name)
            for decorator in stmt.decorator_list:
                if _is_registration_expression(
                    decorator, scope, state, applied_bare=False
                ):
                    return True
    for child in _own_body_nodes(node):
        if not isinstance(child, ast.Call) or not child.args:
            continue
        first = child.args[0]
        if not isinstance(first, ast.Name) or first.id not in carriers:
            continue
        if _is_registration_expression(
            child.func,
            scope,
            state,
            applied_bare=not isinstance(child.func, ast.Call),
        ):
            return True
    return False


def _forwards_registration(
    node: ast.FunctionDef | ast.AsyncFunctionDef, scope: _Scope, state: _State
) -> bool:
    if _registers_parameter(node, scope, state):
        return True
    returned = _returned_local_function_names(node)
    for stmt in node.body:
        if isinstance(stmt, _FUNCTION_NODES) and stmt.name in returned:
            if _registers_parameter(stmt, scope, state):
                return True
    return False


def _collect_classes(scope: _Scope, state: _State) -> None:
    for stmt in scope.parsed.tree.body:
        if not isinstance(stmt, ast.ClassDef):
            continue
        bases = []
        for base in stmt.bases:
            expression = base
            if isinstance(expression, ast.Subscript):
                expression = expression.value
            bases.append(_qualified_reference(expression, scope))
        members = set()
        for child in stmt.body:
            if isinstance(child, (*_FUNCTION_NODES, ast.ClassDef)):
                members.add(child.name)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        members.add(target.id)
            elif isinstance(child, ast.AnnAssign) and isinstance(
                child.target, ast.Name
            ):
                members.add(child.target.id)
        state.classes[f"{scope.module}.{stmt.name}"] = _ClassInfo(bases, members)


def find_external_decorator_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
    module_names: dict[str, str] | None,
    root: Path | None = None,
) -> list[Any]:
    if not module_names:
        return []
    resolved_files: dict[Path, str] = {}
    modules_by_file = {}
    for path, name in module_names.items():
        modules_by_file[_resolved(Path(path), resolved_files)] = name
    state = _State(project_tops=_project_tops(module_names, root))

    scopes = []
    for parsed in parsed_files:
        file_key = _resolved(parsed.path, resolved_files)
        module = modules_by_file.get(file_key, "")
        if not module:
            continue
        names, modules = _import_aliases(parsed.tree, module, parsed.path)
        scope = _Scope(
            parsed, file_key, module, names, modules, _module_local_names(parsed.tree)
        )
        scopes.append(scope)
        for local, target in names.items():
            state.aliases[f"{module}.{local}"] = target
        _collect_classes(scope, state)

    for scope in scopes:
        for stmt in scope.parsed.tree.body:
            if isinstance(stmt, _FUNCTION_NODES) and _is_registration_decorator(stmt):
                state.forwarding.add(f"{scope.module}.{stmt.name}")
    seeded = set(state.forwarding)
    for _ in range(_MAX_FORWARDING_ROUNDS):
        added = False
        for scope in scopes:
            for stmt in scope.parsed.tree.body:
                if not isinstance(stmt, _FUNCTION_NODES):
                    continue
                qualified = f"{scope.module}.{stmt.name}"
                if qualified in state.forwarding:
                    continue
                if _forwards_registration(stmt, scope, state):
                    state.forwarding.add(qualified)
                    added = True
        if not added:
            break
    forwarding = state.forwarding - seeded

    defs_by_line: dict[tuple[str, int], Any] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        try:
            path = Path(getattr(defn, "filename", ""))
            line = int(getattr(defn, "line", 0) or 0)
        except (TypeError, ValueError):
            continue
        defs_by_line.setdefault((_resolved(path, resolved_files), line), defn)

    targets: list[Any] = []
    seen: set[int] = set()
    for scope in scopes:
        for node in ast.walk(scope.parsed.tree):
            if not isinstance(node, _FUNCTION_NODES) or not node.decorator_list:
                continue
            for decorator in node.decorator_list:
                registered = _is_external_factory(decorator, scope, state)
                if not registered and forwarding:
                    _leaf, qualified = _decorator_reference(
                        decorator, scope.names, scope.modules, scope.module
                    )
                    registered = state.resolve(qualified, forwarding) is not None
                if not registered:
                    continue
                defn = defs_by_line.get((scope.file_key, node.lineno))
                if defn is not None and id(defn) not in seen:
                    seen.add(id(defn))
                    targets.append(defn)
                break
    return targets
