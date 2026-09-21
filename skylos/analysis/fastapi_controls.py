"""Conservative static discovery of FastAPI route controls.

This module only reads and parses source. It never imports the scanned project,
evaluates decorators, or calls dependency factories.
"""

from __future__ import annotations

import ast
import hashlib
import re
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Sequence

from skylos.analysis.ast_cache import (
    MODE_SAFE_IGNORE_1MB,
    load_python_module,
    load_python_source,
    releases_python_ast_cache,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS, get_non_library_dir_kind
from skylos.core.file_discovery import discover_source_files


MAX_DISCOVERY_FILES = 5_000
MAX_DISCOVERED_CONTROLS = 1_000

_HTTP_DECORATORS = {
    "delete": "DELETE",
    "get": "GET",
    "head": "HEAD",
    "options": "OPTIONS",
    "patch": "PATCH",
    "post": "POST",
    "put": "PUT",
    "trace": "TRACE",
    "websocket": "WEBSOCKET",
    "websocket_route": "WEBSOCKET",
}
_ROUTE_DECORATORS = {*_HTTP_DECORATORS, "api_route"}
_CONTRACT_ROUTE_DECORATORS = {
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "websocket",
}
_IDENTIFIER_PARTS = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class _Guard:
    name: str
    kind: str
    line: int
    discovery_source: str
    is_factory: bool = False
    has_scopes: bool = False
    enforceable: bool = False


@dataclass(frozen=True)
class _RouteOwner:
    identity: int
    prefix: str | None
    guards: tuple[_Guard, ...]
    kind: str


@dataclass(frozen=True)
class _Route:
    owner: _RouteOwner
    methods: tuple[str | None, ...]
    path: str | None
    guards: tuple[_Guard, ...]
    line: int
    enforceable: bool


@dataclass
class _Bindings:
    fastapi_modules: set[str] = field(default_factory=set)
    fastapi_module_origins: dict[str, str] = field(default_factory=dict)
    setattr_names: set[str] = field(default_factory=lambda: {"setattr"})
    constructors: dict[str, str] = field(default_factory=dict)
    guard_wrappers: dict[str, str] = field(default_factory=dict)
    annotated_names: set[str] = field(default_factory=set)
    owners: dict[str, _RouteOwner] = field(default_factory=dict)
    dependency_lists: dict[str, tuple[_Guard, ...]] = field(default_factory=dict)
    annotated_aliases: dict[str, tuple[_Guard, ...]] = field(default_factory=dict)
    blocked_qualified: set[str] = field(default_factory=set)
    blocked_owners: set[int] = field(default_factory=set)

    def clone(self) -> _Bindings:
        return _Bindings(
            fastapi_modules=set(self.fastapi_modules),
            fastapi_module_origins=dict(self.fastapi_module_origins),
            setattr_names=set(self.setattr_names),
            constructors=dict(self.constructors),
            guard_wrappers=dict(self.guard_wrappers),
            annotated_names=set(self.annotated_names),
            owners=dict(self.owners),
            dependency_lists=dict(self.dependency_lists),
            annotated_aliases=dict(self.annotated_aliases),
            blocked_qualified=set(self.blocked_qualified),
            blocked_owners=set(self.blocked_owners),
        )

    def shadow(self, name: str) -> None:
        self.fastapi_modules.discard(name)
        self.fastapi_module_origins.pop(name, None)
        self.setattr_names = {
            value
            for value in self.setattr_names
            if value != name and not value.startswith(f"{name}.")
        }
        self.constructors.pop(name, None)
        self.guard_wrappers.pop(name, None)
        self.annotated_names = {
            value
            for value in self.annotated_names
            if value != name and not value.startswith(f"{name}.")
        }
        self.owners.pop(name, None)
        self.dependency_lists.pop(name, None)
        self.annotated_aliases.pop(name, None)
        self.blocked_qualified = {
            value
            for value in self.blocked_qualified
            if value != name and not value.startswith(f"{name}.")
        }


def _common_bindings(states: Sequence[_Bindings]) -> _Bindings:
    """Keep only positive bindings proven on every possible control path."""

    if not states:
        return _Bindings()

    def common_set(attribute: str) -> set[str]:
        values = [set(getattr(state, attribute)) for state in states]
        return set.intersection(*values)

    def common_dict(attribute: str) -> dict:
        first = getattr(states[0], attribute)
        return {
            key: value
            for key, value in first.items()
            if all(getattr(state, attribute).get(key) == value for state in states[1:])
        }

    return _Bindings(
        fastapi_modules=common_set("fastapi_modules"),
        fastapi_module_origins=common_dict("fastapi_module_origins"),
        setattr_names=common_set("setattr_names"),
        constructors=common_dict("constructors"),
        guard_wrappers=common_dict("guard_wrappers"),
        annotated_names=common_set("annotated_names"),
        owners=common_dict("owners"),
        dependency_lists=common_dict("dependency_lists"),
        annotated_aliases=common_dict("annotated_aliases"),
        blocked_qualified=set().union(*(state.blocked_qualified for state in states)),
        blocked_owners=set().union(*(state.blocked_owners for state in states)),
    )


def _expr_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expr_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _canonical_fastapi_name(name: str | None, bindings: _Bindings) -> str | None:
    if not name:
        return None
    for alias in sorted(bindings.fastapi_module_origins, key=len, reverse=True):
        if name != alias and not name.startswith(f"{alias}."):
            continue
        return f"{bindings.fastapi_module_origins[alias]}{name[len(alias) :]}"
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value[:500]
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
            return None
        return value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def _static_strings(node: ast.AST | None, *, limit: int = 16) -> tuple[str, ...]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return ()
    values = []
    for item in node.elts[:limit]:
        value = _literal_string(item)
        if value:
            values.append(value)
    return tuple(values)


def _join_route_path(prefix: str | None, path: str | None) -> str | None:
    if prefix is None:
        return None
    if path is None:
        return None
    if not prefix:
        return path
    if not path:
        return prefix
    joined = f"{prefix.rstrip('/')}/{path.lstrip('/')}"
    return joined or "/"


def _target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for item in node.elts for name in _target_names(item))
    return ()


def _match_capture_names(pattern: ast.pattern) -> tuple[str, ...]:
    """Return names bound by one match case without evaluating it."""

    names: list[str] = []

    def collect(node: ast.pattern) -> None:
        if isinstance(node, ast.MatchAs):
            if node.pattern is not None:
                collect(node.pattern)
            if node.name is not None:
                names.append(node.name)
        elif isinstance(node, ast.MatchStar):
            if node.name is not None:
                names.append(node.name)
        elif isinstance(node, ast.MatchMapping):
            for child in node.patterns:
                collect(child)
            if node.rest is not None:
                names.append(node.rest)
        elif isinstance(node, ast.MatchClass):
            for child in [*node.patterns, *node.kwd_patterns]:
                collect(child)
        elif isinstance(node, (ast.MatchSequence, ast.MatchOr)):
            for child in node.patterns:
                collect(child)

    collect(pattern)
    return tuple(dict.fromkeys(names))


def _callable_guard_name(node: ast.AST | None) -> tuple[str | None, bool]:
    direct = _expr_name(node)
    if direct:
        # Cloud policy stores exact guard identities with a 300-character
        # bound. Truncating here could create a different, apparently
        # protectable guard which the contract scanner can never match.
        return (direct, False) if len(direct) <= 300 else (None, False)
    if isinstance(node, ast.Call):
        factory = _expr_name(node.func)
        if factory:
            return (factory, True) if len(factory) <= 300 else (None, True)
    return None, False


def _has_static_scopes(call: ast.Call) -> bool:
    scopes = _keyword(call, "scopes")
    return bool(_static_strings(scopes))


def _resolve_guard_wrapper(call: ast.Call, bindings: _Bindings) -> str | None:
    name = _expr_name(call.func)
    if not name:
        return None
    canonical = _canonical_fastapi_name(name, bindings)
    if name in bindings.blocked_qualified or canonical in bindings.blocked_qualified:
        return None
    direct = bindings.guard_wrappers.get(name)
    if direct:
        return direct
    if canonical in {
        "fastapi.Depends",
        "fastapi.Security",
        "fastapi.params.Depends",
        "fastapi.params.Security",
    }:
        return "security" if canonical.endswith("Security") else "dependency"
    return None


def _guard_from_call(
    node: ast.AST | None,
    bindings: _Bindings,
    discovery_source: str,
) -> _Guard | None:
    if not isinstance(node, ast.Call):
        return None
    wrapper = _resolve_guard_wrapper(node, bindings)
    if wrapper is None:
        return None
    dependency = node.args[0] if node.args else _keyword(node, "dependency")
    guard_name, is_factory = _callable_guard_name(dependency)
    if not guard_name:
        return None
    wrapper_name = _expr_name(node.func) or ""
    # Security contracts currently inspect direct Depends(...) syntax only.
    # Aliased wrappers, Security(), factories, Annotated metadata, and
    # router-wide dependencies remain useful observations, but must not be
    # presented as controls that Skylos can enforce yet.
    enforceable = (
        wrapper == "dependency"
        and not is_factory
        and bool(node.args)
        and (wrapper_name == "Depends" or wrapper_name.endswith(".Depends"))
        and "." not in guard_name
        and discovery_source
        in {
            "fastapi.route.decorator.dependencies",
            "fastapi.route.parameter.default",
        }
    )
    return _Guard(
        name=guard_name,
        kind=("fastapi_security" if wrapper == "security" else "fastapi_dependency"),
        line=max(1, int(getattr(node, "lineno", 1) or 1)),
        discovery_source=discovery_source,
        is_factory=is_factory,
        has_scopes=wrapper == "security" and _has_static_scopes(node),
        enforceable=enforceable,
    )


def _guards_from_value(
    node: ast.AST | None,
    bindings: _Bindings,
    discovery_source: str,
) -> tuple[_Guard, ...]:
    if node is None:
        return ()
    if isinstance(node, ast.Name) and node.id in bindings.dependency_lists:
        return tuple(
            replace(
                guard,
                discovery_source=discovery_source,
                enforceable=False,
            )
            for guard in bindings.dependency_lists[node.id]
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        guards = []
        for item in node.elts:
            guard = _guard_from_call(item, bindings, discovery_source)
            if guard is not None:
                if isinstance(node, ast.Set):
                    guard = replace(guard, enforceable=False)
                guards.append(guard)
        return tuple(guards)
    guard = _guard_from_call(node, bindings, discovery_source)
    return (guard,) if guard is not None else ()


def _is_annotated(node: ast.AST, bindings: _Bindings) -> bool:
    name = _expr_name(node)
    return bool(name and name in bindings.annotated_names)


def _guards_from_annotation(
    node: ast.AST | None,
    bindings: _Bindings,
    discovery_source: str,
) -> tuple[_Guard, ...]:
    if isinstance(node, ast.Name) and node.id in bindings.annotated_aliases:
        return tuple(
            replace(
                guard,
                discovery_source=discovery_source,
                enforceable=False,
            )
            for guard in bindings.annotated_aliases[node.id]
        )
    if not isinstance(node, ast.Subscript) or not _is_annotated(node.value, bindings):
        return ()
    elements = node.slice.elts if isinstance(node.slice, ast.Tuple) else ()
    guards = []
    for item in elements[1:]:
        guard = _guard_from_call(item, bindings, discovery_source)
        if guard is not None:
            guards.append(replace(guard, enforceable=False))
    return tuple(guards)


def _route_methods(call: ast.Call, decorator_name: str) -> tuple[str | None, ...]:
    direct = _HTTP_DECORATORS.get(decorator_name)
    if direct:
        return (direct,)
    methods = tuple(
        value.upper()[:32] for value in _static_strings(_keyword(call, "methods"))
    )
    return tuple(dict.fromkeys(methods)) or (None,)


def _route_from_decorator(
    decorator: ast.AST,
    bindings: _Bindings,
) -> _Route | None:
    if not isinstance(decorator, ast.Call) or not isinstance(
        decorator.func, ast.Attribute
    ):
        return None
    decorator_name = decorator.func.attr
    if decorator_name not in _ROUTE_DECORATORS:
        return None
    decorator_qualified = _expr_name(decorator.func)
    if decorator_qualified in bindings.blocked_qualified:
        return None
    owner_name = _expr_name(decorator.func.value)
    owner = bindings.owners.get(owner_name or "")
    if owner is None or owner.identity in bindings.blocked_owners:
        return None
    path_node = decorator.args[0] if decorator.args else _keyword(decorator, "path")
    path = _join_route_path(owner.prefix, _literal_string(path_node))
    guards = _guards_from_value(
        _keyword(decorator, "dependencies"),
        bindings,
        "fastapi.route.decorator.dependencies",
    )
    return _Route(
        owner=owner,
        methods=_route_methods(decorator, decorator_name),
        path=path,
        guards=guards,
        line=max(1, int(getattr(decorator, "lineno", 1) or 1)),
        enforceable=decorator_name in _CONTRACT_ROUTE_DECORATORS,
    )


def _function_guards(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    bindings: _Bindings,
) -> tuple[_Guard, ...]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: dict[int, ast.AST] = {}
    first_default = len(positional) - len(node.args.defaults)
    for index, default in enumerate(node.args.defaults, start=first_default):
        defaults[index] = default

    guards = []
    for index, argument in enumerate(positional):
        default_guard = _guard_from_call(
            defaults.get(index),
            bindings,
            "fastapi.route.parameter.default",
        )
        if default_guard is not None:
            guards.append(default_guard)
        guards.extend(
            _guards_from_annotation(
                argument.annotation,
                bindings,
                "fastapi.route.parameter.annotated",
            )
        )

    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        default_guard = _guard_from_call(
            default,
            bindings,
            "fastapi.route.parameter.default",
        )
        if default_guard is not None:
            guards.append(default_guard)
        guards.extend(
            _guards_from_annotation(
                argument.annotation,
                bindings,
                "fastapi.route.parameter.annotated",
            )
        )
    return tuple(guards)


def _control_type(guard: _Guard) -> str:
    split_name = _CAMEL_BOUNDARY.sub("_", guard.name)
    words = set(filter(None, _IDENTIFIER_PARTS.split(split_name.lower())))
    normalized = guard.name.lower()
    if words.intersection({"tenant", "organization", "organisation", "workspace"}):
        return "tenant_isolation"
    if "rate_limit" in normalized or words.intersection({"throttle", "quota"}):
        return "rate_limit"
    if guard.has_scopes or words.intersection(
        {
            "access",
            "admin",
            "allow",
            "allowed",
            "authorize",
            "authorization",
            "manager",
            "owner",
            "permission",
            "permissions",
            "policy",
            "privilege",
            "privileged",
            "role",
            "roles",
            "scope",
            "scopes",
            "staff",
        }
    ):
        return "authorization"
    if normalized in {"get_current_user", "oauth2_scheme"} or (
        normalized.startswith("require_") and normalized.endswith("_user")
    ):
        return "auth"
    if (
        words.intersection(
            {
                "auth",
                "authenticate",
                "authentication",
                "credential",
                "credentials",
                "jwt",
                "login",
                "session",
                "token",
                "apikey",
            }
        )
        or "api_key" in normalized
    ):
        return "auth"
    if words.intersection(
        {"validate", "validation", "validator", "sanitize", "sanitise"}
    ):
        return "validation"
    if guard.kind == "fastapi_security":
        return "auth"
    return "unknown"


def _severity(control_type: str) -> str:
    if control_type in {"auth", "authorization", "tenant_isolation"}:
        return "HIGH"
    if control_type in {"rate_limit", "validation"}:
        return "MEDIUM"
    return "LOW"


def _confidence(route: _Route, guard: _Guard, control_type: str) -> str:
    if route.path is None or guard.is_factory or control_type == "unknown":
        return "medium"
    return "high"


def _confidence_reason(route: _Route, guard: _Guard, control_type: str) -> str:
    wrapper = "Security" if guard.kind == "fastapi_security" else "Depends"
    if route.path is None:
        return (
            f"Static FastAPI {wrapper} guard found; the dynamic route path was "
            "not evaluated."
        )
    if guard.is_factory:
        return (
            f"Static FastAPI {wrapper} guard factory found; Skylos did not call "
            "the factory."
        )
    if control_type == "unknown":
        return (
            f"Static FastAPI {wrapper} guard found; its control type remains "
            "unknown because the guard name is not specific."
        )
    return (
        f"Static FastAPI {wrapper} guard and literal route resolved without "
        "executing project code."
    )


def _fingerprint_parts(control: dict) -> tuple[str, ...]:
    route = control.get("route") or {}
    return (
        str(control.get("framework") or ""),
        str(control.get("control_type") or ""),
        str(control.get("file_path") or ""),
        str(control.get("handler") or ""),
        str(route.get("method") or ""),
        str(route.get("path") or ""),
        str(control.get("guard_kind") or ""),
        str(control.get("guard_name") or ""),
    )


def _control_id(control: dict) -> str:
    digest = hashlib.sha256("\0".join(_fingerprint_parts(control)).encode()).hexdigest()
    return f"fastapi:{digest[:32]}"


def _build_control(
    *,
    file_path: str,
    handler: str,
    route: _Route,
    method: str | None,
    guard: _Guard,
) -> dict | None:
    control_type = _control_type(guard)
    # Depends() is general dependency injection, not proof of a security
    # control. Keep only names that conservatively describe a known control;
    # Security() itself is an explicit security primitive and remains useful.
    if control_type == "unknown" and guard.kind == "fastapi_dependency":
        return None
    confidence = _confidence(route, guard, control_type)
    method_label = method or "dynamic method"
    path_label = route.path or "dynamic path"
    wrapper = "Security" if guard.kind == "fastapi_security" else "Depends"
    dependency = f"{guard.name}(...)" if guard.is_factory else guard.name
    guard_kind = (
        guard.kind
        if guard.enforceable or guard.kind != "fastapi_dependency"
        else "fastapi_dependency_observation"
    )
    control = {
        "control_type": control_type,
        "framework": "fastapi",
        "file_path": file_path[:800],
        "handler": handler[:300],
        "route": {"method": method, "path": route.path},
        "guard_name": guard.name[:300],
        "guard_kind": guard_kind,
        "severity": _severity(control_type),
        "confidence": confidence,
        "description": (
            f"{method_label} {path_label} syntactically declares {guard.name} "
            "through FastAPI."
        )[:1000],
        "evidence": {
            "line_number": guard.line,
            "snippet": f"{wrapper}({dependency})"[:400],
            "confidence_reason": _confidence_reason(route, guard, control_type)[:1000],
            "discovery_source": guard.discovery_source[:200],
            "source": "skylos-static-ast",
        },
    }
    control["control_id"] = _control_id(control)
    return control


class _FastAPIControlCollector(ast.NodeVisitor):
    def __init__(self, file_path: str, ambiguous_handlers: set[str]):
        self.file_path = file_path
        self.ambiguous_handlers = ambiguous_handlers
        self.bindings = _Bindings()
        self._binding_stack: list[_Bindings] = []
        self._symbol_stack: list[str] = []
        self.controls: list[dict] = []
        self._fingerprints: set[tuple[str, ...]] = set()
        self._next_owner_identity = 0

    def generic_visit(self, node: ast.AST) -> None:
        # Keep traversal independent of process-wide NodeVisitor patches.
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            bound = item.asname or item.name.split(".", 1)[0]
            self.bindings.shadow(bound)
            if item.name == "fastapi" or item.name.startswith("fastapi."):
                self.bindings.fastapi_modules.add(bound)
                self.bindings.fastapi_module_origins[bound] = (
                    item.name if item.asname else item.name.split(".", 1)[0]
                )
            if item.name == "builtins":
                self.bindings.setattr_names.add(f"{bound}.setattr")
            if item.name in {"typing", "typing_extensions"}:
                self.bindings.annotated_names.add(f"{bound}.Annotated")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for item in node.names:
            if item.name == "*":
                # A star import can rebind any currently positive name.  Its
                # exports cannot be resolved without importing scanned code,
                # so no FastAPI proof that predates it remains trustworthy.
                self._poison_positive_bindings()
                continue
            bound = item.asname or item.name
            self.bindings.shadow(bound)
            if module == "fastapi" and item.name in {"FastAPI", "APIRouter"}:
                self.bindings.constructors[bound] = item.name
            elif module in {"fastapi", "fastapi.params"} and item.name in {
                "Depends",
                "Security",
            }:
                self.bindings.guard_wrappers[bound] = (
                    "security" if item.name == "Security" else "dependency"
                )
            elif module == "fastapi" and item.name == "params":
                self.bindings.fastapi_modules.add(bound)
                self.bindings.fastapi_module_origins[bound] = "fastapi.params"
            elif module in {"typing", "typing_extensions"} and item.name == "Annotated":
                self.bindings.annotated_names.add(bound)
            elif module == "builtins" and item.name == "setattr":
                self.bindings.setattr_names.add(bound)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self._block_attribute_mutation(target)
        names = tuple(name for target in node.targets for name in _target_names(target))
        self._bind_names(names, node.value)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Attribute):
            self._block_attribute_mutation(node.target)
        names = _target_names(node.target)
        if node.value is not None:
            self._bind_names(names, node.value)
            self.generic_visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Attribute):
            self._block_attribute_mutation(node.target)
        for name in _target_names(node.target):
            self.bindings.shadow(name)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        names = _target_names(node.target)
        self._bind_names(names, node.value)
        self.visit(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self._block_attribute_mutation(target)
            for name in _target_names(target):
                self.bindings.shadow(name)

    def visit_Call(self, node: ast.Call) -> None:
        if _expr_name(node.func) in self.bindings.setattr_names and node.args:
            target_name = _expr_name(node.args[0])
            owner = self.bindings.owners.get(target_name or "")
            if owner is not None:
                attribute = (
                    _literal_string(node.args[1]) if len(node.args) > 1 else None
                )
                if attribute is None or attribute in _ROUTE_DECORATORS:
                    self.bindings.blocked_owners.add(owner.identity)

            module_origin = _canonical_fastapi_name(target_name, self.bindings)
            if module_origin in {"fastapi", "fastapi.params"}:
                attribute = (
                    _literal_string(node.args[1]) if len(node.args) > 1 else None
                )
                if attribute:
                    self.bindings.blocked_qualified.add(f"{module_origin}.{attribute}")
                else:
                    self.bindings.blocked_qualified.update(
                        {
                            f"{module_origin}.APIRouter",
                            f"{module_origin}.Depends",
                            f"{module_origin}.FastAPI",
                            f"{module_origin}.Security",
                        }
                    )
        self.generic_visit(node)

    def _visit_uncertain_blocks(
        self,
        blocks: Sequence[Sequence[ast.stmt]],
        *,
        include_unmodified_path: bool,
    ) -> None:
        incoming = self.bindings
        outcomes = [incoming.clone()] if include_unmodified_path else []
        for block in blocks:
            self.bindings = incoming.clone()
            for statement in block:
                self.visit(statement)
            outcomes.append(self.bindings)
        self.bindings = _common_bindings(outcomes)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        blocks = [node.body]
        if node.orelse:
            blocks.append(node.orelse)
        self._visit_uncertain_blocks(
            blocks,
            include_unmodified_path=not bool(node.orelse),
        )

    def _visit_loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.visit(node.iter)
            incoming = self.bindings
            self.bindings = incoming.clone()
            for name in _target_names(node.target):
                self.bindings.shadow(name)
            for statement in node.body:
                self.visit(statement)
            body_outcome = self.bindings
        else:
            self.visit(node.test)
            incoming = self.bindings
            self.bindings = incoming.clone()
            for statement in node.body:
                self.visit(statement)
            body_outcome = self.bindings

        loop_exit = _common_bindings([incoming.clone(), body_outcome])
        outcomes = [body_outcome]
        if node.orelse:
            self.bindings = loop_exit.clone()
            for statement in node.orelse:
                self.visit(statement)
            outcomes.append(self.bindings)
        else:
            outcomes.append(loop_exit)
        self.bindings = _common_bindings(outcomes)

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop(node)

    def visit_Try(self, node: ast.Try) -> None:
        incoming = self.bindings
        self.bindings = incoming.clone()
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        outcomes = [incoming.clone(), self.bindings]
        for handler in node.handlers:
            self.bindings = incoming.clone()
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self.bindings.shadow(handler.name)
            for statement in handler.body:
                self.visit(statement)
            outcomes.append(self.bindings)
        self.bindings = _common_bindings(outcomes)
        for statement in node.finalbody:
            self.visit(statement)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_Try(node)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        incoming = self.bindings
        outcomes = [incoming.clone()]
        for case in node.cases:
            self.bindings = incoming.clone()
            for name in _match_capture_names(case.pattern):
                self.bindings.shadow(name)
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
            outcomes.append(self.bindings)
        self.bindings = _common_bindings(outcomes)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                for name in _target_names(item.optional_vars):
                    self.bindings.shadow(name)
        for statement in node.body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def _bind_names(self, names: tuple[str, ...], value: ast.AST) -> None:
        if not names:
            return
        source_name = _expr_name(value)
        source_owner = self.bindings.owners.get(source_name or "")
        source_constructor = self.bindings.constructors.get(source_name or "")
        source_wrapper = self.bindings.guard_wrappers.get(source_name or "")
        source_dependencies = self.bindings.dependency_lists.get(source_name or "")
        source_annotation = self.bindings.annotated_aliases.get(source_name or "")
        source_setattr = source_name in self.bindings.setattr_names
        source_setattr_suffixes = (
            tuple(
                value[len(source_name) :]
                for value in self.bindings.setattr_names
                if source_name and value.startswith(f"{source_name}.")
            )
            if source_name
            else ()
        )
        canonical_source = _canonical_fastapi_name(source_name, self.bindings)
        source_module_origin = (
            canonical_source
            if canonical_source in {"fastapi", "fastapi.params"}
            else None
        )
        if (
            source_name
            and source_name not in self.bindings.blocked_qualified
            and canonical_source not in self.bindings.blocked_qualified
        ):
            if canonical_source in {"fastapi.FastAPI", "fastapi.APIRouter"}:
                source_constructor = canonical_source.rsplit(".", 1)[-1]
            elif canonical_source in {
                "fastapi.Depends",
                "fastapi.params.Depends",
            }:
                source_wrapper = "dependency"
            elif canonical_source in {
                "fastapi.Security",
                "fastapi.params.Security",
            }:
                source_wrapper = "security"

        owner = self._owner_from_value(value)
        dependency_list = _guards_from_value(
            value, self.bindings, "fastapi.static.dependencies"
        )
        annotation = _guards_from_annotation(
            value, self.bindings, "fastapi.annotated.alias"
        )

        for name in names:
            self.bindings.shadow(name)
            if owner is not None:
                self.bindings.owners[name] = owner
            elif source_owner is not None:
                self.bindings.owners[name] = source_owner
            if source_constructor:
                self.bindings.constructors[name] = source_constructor
            if source_wrapper:
                self.bindings.guard_wrappers[name] = source_wrapper
            if source_module_origin:
                self.bindings.fastapi_modules.add(name)
                self.bindings.fastapi_module_origins[name] = source_module_origin
            if source_setattr:
                self.bindings.setattr_names.add(name)
            for suffix in source_setattr_suffixes:
                self.bindings.setattr_names.add(f"{name}{suffix}")
            if dependency_list:
                self.bindings.dependency_lists[name] = dependency_list
            elif source_dependencies:
                self.bindings.dependency_lists[name] = source_dependencies
            if annotation:
                self.bindings.annotated_aliases[name] = annotation
            elif source_annotation:
                self.bindings.annotated_aliases[name] = source_annotation

    def _poison_positive_bindings(self) -> None:
        self.bindings.fastapi_modules.clear()
        self.bindings.fastapi_module_origins.clear()
        self.bindings.setattr_names.clear()
        self.bindings.constructors.clear()
        self.bindings.guard_wrappers.clear()
        self.bindings.annotated_names.clear()
        self.bindings.owners.clear()
        self.bindings.dependency_lists.clear()
        self.bindings.annotated_aliases.clear()

    def _block_owner_method(self, target: ast.Attribute) -> None:
        if target.attr not in _ROUTE_DECORATORS:
            return
        owner_name = _expr_name(target.value)
        owner = self.bindings.owners.get(owner_name or "")
        if owner is not None:
            self.bindings.blocked_owners.add(owner.identity)

    def _block_attribute_mutation(self, target: ast.Attribute) -> None:
        qualified = _expr_name(target)
        if qualified:
            self.bindings.blocked_qualified.add(qualified)
            canonical = _canonical_fastapi_name(qualified, self.bindings)
            if canonical:
                self.bindings.blocked_qualified.add(canonical)
        self._block_owner_method(target)

    def _owner_from_value(self, value: ast.AST) -> _RouteOwner | None:
        if not isinstance(value, ast.Call):
            return None
        name = _expr_name(value.func)
        constructor = self.bindings.constructors.get(name or "")
        if constructor is None and name:
            canonical = _canonical_fastapi_name(name, self.bindings)
            if (
                name in self.bindings.blocked_qualified
                or canonical in self.bindings.blocked_qualified
            ):
                return None
            if canonical in {"fastapi.FastAPI", "fastapi.APIRouter"}:
                constructor = canonical.rsplit(".", 1)[-1]
        if constructor is None:
            return None
        prefix_value = _keyword(value, "prefix")
        prefix = "" if prefix_value is None else _literal_string(prefix_value)
        guards = _guards_from_value(
            _keyword(value, "dependencies"),
            self.bindings,
            (
                "fastapi.router.dependencies"
                if constructor == "APIRouter"
                else "fastapi.application.dependencies"
            ),
        )
        guards = tuple(replace(guard, enforceable=False) for guard in guards)
        self._next_owner_identity += 1
        return _RouteOwner(
            identity=self._next_owner_identity,
            prefix=prefix,
            guards=guards,
            kind=constructor,
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        handler = ".".join([*self._symbol_stack, node.name])
        routes = [
            route
            for decorator in node.decorator_list
            if (route := _route_from_decorator(decorator, self.bindings)) is not None
        ]
        parameter_guards = _function_guards(node, self.bindings)
        contract_route_count = sum(
            1
            for decorator in node.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in _CONTRACT_ROUTE_DECORATORS
        )
        handler_is_unambiguous = (
            not self._symbol_stack
            and node.name not in self.ambiguous_handlers
            and contract_route_count == 1
        )
        for route in routes:
            guards = [*route.owner.guards, *route.guards, *parameter_guards]
            if not route.enforceable or not handler_is_unambiguous:
                guards = [replace(guard, enforceable=False) for guard in guards]
            for method in route.methods:
                for guard in guards:
                    control = _build_control(
                        file_path=self.file_path,
                        handler=handler,
                        route=route,
                        method=method,
                        guard=guard,
                    )
                    if control is None:
                        continue
                    fingerprint = _fingerprint_parts(control)
                    if fingerprint in self._fingerprints:
                        continue
                    self._fingerprints.add(fingerprint)
                    self.controls.append(control)

        child = self.bindings.clone()
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]:
            child.shadow(argument.arg)
        if node.args.vararg:
            child.shadow(node.args.vararg.arg)
        if node.args.kwarg:
            child.shadow(node.args.kwarg.arg)

        self._binding_stack.append(self.bindings)
        self.bindings = child
        self._symbol_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._symbol_stack.pop()
        self.bindings = self._binding_stack.pop()
        self.bindings.shadow(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        child = self.bindings.clone()
        self._binding_stack.append(self.bindings)
        self.bindings = child
        self._symbol_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._symbol_stack.pop()
        self.bindings = self._binding_stack.pop()
        self.bindings.shadow(node.name)


def _contained_scope(
    scan_path: str | Path,
    repository_root: str | Path,
) -> tuple[Path, Path] | None:
    raw_scan = Path(scan_path).expanduser()
    raw_root = Path(repository_root).expanduser()
    try:
        if raw_scan.is_symlink() or raw_root.is_symlink():
            return None
        root = raw_root.resolve(strict=True)
        target = raw_scan.resolve(strict=True)
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    return target, root


def _ambiguous_top_level_handlers(tree: ast.AST) -> set[str]:
    if not isinstance(tree, ast.Module):
        return set()
    counts: dict[str, int] = {}

    # The contract scanner currently selects a handler by its bare name while
    # walking the whole module AST. A nested function or class method with a
    # FastAPI-shaped decorator can therefore shadow a module-level route. Only
    # call a discovered route protectable when that bare route-handler name is
    # unique across the same AST surface the contract scanner searches.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in _CONTRACT_ROUTE_DECORATORS
            for decorator in node.decorator_list
        ):
            continue
        counts[node.name] = counts.get(node.name, 0) + 1
    return {name for name, count in counts.items() if count > 1}


def _clean_exclusions(exclude_folders: Sequence[str] | None) -> tuple[str, ...]:
    requested = (
        {str(value)[:500] for value in exclude_folders[:200] if value}
        if exclude_folders
        else set()
    )
    return tuple(sorted(DEFAULT_EXCLUDE_FOLDERS | requested))


def _has_custom_exclusions(exclude_folders: object) -> bool:
    if exclude_folders is None:
        return False
    if not isinstance(exclude_folders, list):
        return True
    return any(
        isinstance(folder, str) and folder not in DEFAULT_EXCLUDE_FOLDERS
        for folder in exclude_folders
    )


def _is_canonical_root_scope(scope: dict) -> bool:
    kind = scope.get("kind")
    if kind not in {
        "repository_root",
        "repository_root_with_exclusions",
    } or _has_custom_exclusions(scope.get("excluded_folders")):
        return False
    excluded = scope.get("excluded_folders")
    if not isinstance(excluded, list):
        return False
    if kind == "repository_root":
        if scope.get("complete_repository") is not True or excluded:
            return False
    elif scope.get("complete_repository") is not False or not excluded:
        return False
    scan_path = scope.get("scan_path")
    repository_root = scope.get("repository_root")
    if not isinstance(scan_path, str) or not isinstance(repository_root, str):
        return False
    contained = _contained_scope(scan_path, repository_root)
    return contained is not None and contained[0] == contained[1]


@releases_python_ast_cache
def discover_fastapi_controls(
    scan_path: str | Path,
    repository_root: str | Path,
    *,
    exclude_folders: Sequence[str] | None = None,
    max_files: int = MAX_DISCOVERY_FILES,
    max_controls: int = MAX_DISCOVERED_CONTROLS,
) -> dict:
    """Discover protected FastAPI routes inside a previously scanned scope."""

    scope = _contained_scope(scan_path, repository_root)
    if scope is None:
        return {
            "controls": [],
            "files_scanned": 0,
            "files_skipped": 0,
            "truncated": False,
            "complete": False,
            "reason": "invalid_scope",
        }
    target, root = scope
    paths = discover_source_files(
        target,
        (".py", ".pyw"),
        exclude_folders=_clean_exclusions(exclude_folders),
    )
    max_files = max(1, min(int(max_files), MAX_DISCOVERY_FILES))
    max_controls = max(1, min(int(max_controls), MAX_DISCOVERED_CONTROLS))
    selected_paths = paths[:max_files]
    truncated = len(paths) > len(selected_paths)
    files_skipped = 0
    files_scanned = 0
    controls: list[dict] = []

    for path in selected_paths:
        source = load_python_source(path, MODE_SAFE_IGNORE_1MB)
        if source is None:
            files_skipped += 1
            continue
        try:
            relative = path.resolve(strict=True).relative_to(root).as_posix()
        except (OSError, ValueError):
            files_skipped += 1
            continue
        if "fastapi" not in source:
            continue
        _, tree = load_python_module(path, MODE_SAFE_IGNORE_1MB)
        if tree is None:
            files_skipped += 1
            continue
        files_scanned += 1
        if get_non_library_dir_kind(path, root) is not None:
            continue
        collector = _FastAPIControlCollector(
            relative,
            _ambiguous_top_level_handlers(tree),
        )
        collector.visit(tree)
        controls.extend(collector.controls)
        if len(controls) > max_controls:
            truncated = True
            break

    controls.sort(
        key=lambda item: (
            item["file_path"],
            int((item.get("evidence") or {}).get("line_number") or 0),
            item["handler"],
            str((item.get("route") or {}).get("method") or ""),
            str((item.get("route") or {}).get("path") or ""),
            item["guard_kind"],
            item["guard_name"],
        )
    )
    if len(controls) > max_controls:
        controls = controls[:max_controls]

    return {
        "controls": controls,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "truncated": truncated,
        "complete": not truncated and files_skipped == 0,
    }


def discover_fastapi_controls_for_scan(result_json: object) -> dict:
    """Recover the analyzer's exact filesystem scope from a scan result."""

    if not isinstance(result_json, dict):
        return {"controls": [], "status": "skipped", "reason": "missing_scope"}
    summary = result_json.get("analysis_summary")
    scope = summary.get("comparison_scope") if isinstance(summary, dict) else None
    if not isinstance(scope, dict):
        return {"controls": [], "status": "skipped", "reason": "missing_scope"}
    if scope.get("kind") in {"multiple_paths", "symlink"} or scope.get(
        "changed_files_only"
    ):
        return {
            "controls": [],
            "status": "skipped",
            "reason": "unsupported_partial_scope",
        }
    scan_path = scope.get("scan_path")
    repository_root = scope.get("repository_root")
    if not isinstance(scan_path, str) or not isinstance(repository_root, str):
        return {"controls": [], "status": "skipped", "reason": "missing_scope"}
    report = discover_fastapi_controls(
        scan_path,
        repository_root,
        exclude_folders=(
            scope.get("excluded_folders")
            if isinstance(scope.get("excluded_folders"), list)
            else ()
        ),
    )
    if report.get("reason"):
        report["status"] = "skipped"
        return report
    report["complete"] = (
        bool(report.get("complete"))
        and not _has_custom_exclusions(scope.get("excluded_folders"))
        and (
            _is_canonical_root_scope(scope)
            or _covers_linked_project_scope(result_json, summary, scope)
        )
    )
    report["status"] = "discovered"
    return report


def _covers_linked_project_scope(
    result_json: dict,
    summary: dict,
    scope: dict,
) -> bool:
    """Return whether a full subdirectory scan covers its Cloud project.

    Monorepos bind a Cloud project to a repository subpath. The analyzer
    correctly calls that target a repository subdirectory, but it is still a
    complete snapshot for the linked Cloud project when the two paths match.
    """

    if (
        scope.get("kind") != "subdirectory"
        or scope.get("complete_repository") is not False
        or scope.get("changed_files_only")
        or _has_custom_exclusions(scope.get("excluded_folders"))
    ):
        return False
    raw_project_root = result_json.get("project_root")
    if raw_project_root is None:
        raw_project_root = summary.get("project_root")
    if not isinstance(raw_project_root, str):
        return False
    normalized = raw_project_root.strip().replace("\\", "/").strip("/")
    if not normalized or normalized in {".", ".."}:
        return False
    parts = normalized.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        return False
    contained = _contained_scope(scope.get("scan_path"), scope.get("repository_root"))
    if contained is None:
        return False
    target, root = contained
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError:
        return False
    return relative == normalized


__all__ = [
    "MAX_DISCOVERED_CONTROLS",
    "MAX_DISCOVERY_FILES",
    "discover_fastapi_controls",
    "discover_fastapi_controls_for_scan",
]
