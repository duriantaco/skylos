from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Callable, Iterable

from tree_sitter import Language


class Truth4(str, Enum):
    TRUE = "true"
    FALSE = "false"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    INCOMPLETE = "incomplete"


class ScopeKind(str, Enum):
    MODULE = "module"
    FUNCTION = "function"
    BLOCK = "block"


class RouteKind(str, Enum):
    NEXT_APP = "next_app"
    NEXT_PAGES = "next_pages"
    EXPRESS = "express"
    FASTIFY = "fastify"
    HONO = "hono"


class EventKind(str, Enum):
    BIND = "bind"
    ASSIGN = "assign"
    CALL = "call"
    BRANCH = "branch"
    RETURN = "return"
    THROW = "throw"
    NEW = "new"
    UPDATE = "update"
    UNKNOWN_CONTROL = "unknown_control"


class ImportKind(str, Enum):
    DEFAULT = "default"
    NAMED = "named"
    NAMESPACE = "namespace"
    REQUIRE = "require"


@dataclass(frozen=True, slots=True)
class Span:
    start_byte: int
    end_byte: int
    line: int
    col: int
    end_line: int
    end_col: int

    @classmethod
    def from_node(cls, node) -> Span:
        return cls(
            start_byte=node.start_byte,
            end_byte=node.end_byte,
            line=node.start_point[0] + 1,
            col=node.start_point[1],
            end_line=node.end_point[0] + 1,
            end_col=node.end_point[1],
        )


@dataclass(frozen=True, slots=True)
class SymbolId:
    scope_id: int
    name: str
    decl_byte: int


@dataclass(frozen=True, slots=True)
class ImportIdentity:
    module: str
    exported: str
    local: str
    kind: ImportKind


@dataclass(frozen=True, slots=True)
class CalleeIdentity:
    import_id: ImportIdentity | None
    member_path: tuple[str, ...]
    symbol: SymbolId | None = None


@dataclass(frozen=True, slots=True)
class EvidenceStep:
    kind: str
    span: Span
    message: str
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "line": self.span.line,
            "col": self.span.col,
            "message": self.message,
        }
        if self.subject:
            result["subject"] = self.subject
        return result


@dataclass(frozen=True, slots=True)
class FlowEvent:
    id: int
    ordinal: int
    kind: EventKind
    scope_id: int
    span: Span
    callee: CalleeIdentity | None
    arg_values: tuple[str, ...]
    node_type: str
    _node: Any = field(compare=False, hash=False, repr=False, default=None)


@dataclass(slots=True)
class LexicalScope:
    id: int
    kind: ScopeKind
    parent_id: int | None
    name: str
    body_span: Span
    params: tuple[SymbolId, ...]
    events: list[FlowEvent]
    complete: bool
    _node: Any = field(repr=False, default=None)
    _body: Any = field(repr=False, default=None)


@dataclass(frozen=True, slots=True)
class RouteScope:
    scope_id: int
    kind: RouteKind
    methods: frozenset[str]
    path: str | None
    request_symbols: tuple[SymbolId, ...]
    request_body_symbols: tuple[SymbolId, ...]
    request_raw_body_symbols: tuple[SymbolId, ...]
    request_header_symbols: tuple[SymbolId, ...]
    response_symbols: tuple[SymbolId, ...]
    registration: Span
    handler_index: int
    handler_count: int
    _region: Any = field(compare=False, hash=False, repr=False, default=None)


@dataclass(frozen=True, slots=True)
class OptionFact:
    state: Truth4
    evidence: tuple[EvidenceStep, ...] = ()


@dataclass(frozen=True, slots=True)
class CookieAssessment:
    http_only: OptionFact
    secure: OptionFact
    verdict: Verdict


@dataclass(frozen=True, slots=True)
class FlowLimits:
    max_nodes: int = 50_000
    max_scopes: int = 512
    max_events_per_scope: int = 4_096
    max_bindings_per_scope: int = 2_048
    max_routes: int = 512
    max_properties: int = 64
    max_expr_depth: int = 64
    max_work_items: int = 500_000


@dataclass(frozen=True, slots=True)
class _Binding:
    symbol: SymbolId
    value_node: Any
    declaration_node: Any


_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)
_EXPRESSION_WRAPPERS = frozenset(
    {
        "await_expression",
        "parenthesized_expression",
        "non_null_expression",
        "as_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ROUTE_RECEIVERS = {
    "app": RouteKind.EXPRESS,
    "express": RouteKind.EXPRESS,
    "router": RouteKind.EXPRESS,
    "server": RouteKind.FASTIFY,
    "fastify": RouteKind.FASTIFY,
    "hono": RouteKind.HONO,
}
_SECURITY_ROUTE_HINT_RE = re.compile(
    r"(?:webhooks?|stripe|github|clerk|svix|shopify|supabase|resend|twilio|"
    r"slack|discord|linear|vercel|netlify|paddle|lemon[_-]?squeezy)",
    re.IGNORECASE,
)
_MAX_OMITTED_SECURITY_ROUTES = 16


def _node_key(node) -> tuple[int, int, str]:
    return (node.start_byte, node.end_byte, node.type)


def _string_value(source: bytes, node) -> str | None:
    if node is None or node.type not in {"string", "template_string"}:
        return None
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    if len(text) < 2 or text[0] not in "'\"`" or text[-1] != text[0]:
        return None
    if node.type == "template_string" and any(
        child.type == "template_substitution" for child in node.children
    ):
        return None
    return text[1:-1]


def _identifier_text(source: bytes, node) -> str | None:
    if node is None or node.type not in {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "type_identifier",
    }:
        return None
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _named_children(node) -> list:
    return list(node.named_children) if node is not None else []


def _unwrap_expression(node):
    current = node
    for _ in range(16):
        if current is None or current.type not in _EXPRESSION_WRAPPERS:
            return current
        named = _named_children(current)
        if not named:
            return current
        expression_children = [
            child
            for child in named
            if not child.type.endswith("_type")
            and child.type
            not in {"type_identifier", "predefined_type", "type_annotation"}
        ]
        if not expression_children:
            return current
        current = expression_children[-1 if current.type == "as_expression" else 0]
    return current


def terminates(node) -> bool:
    """Return whether this branch definitely exits before its next sibling."""
    if node is None:
        return False
    if node.type in {"return_statement", "throw_statement"}:
        return True
    if node.type == "statement_block":
        statements = _named_children(node)
        return bool(statements and terminates(statements[-1]))
    if node.type == "if_statement":
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        return (
            consequence is not None
            and alternative is not None
            and (terminates(consequence) and terminates(alternative))
        )
    return False


def negative_guard_fallthrough(
    if_node,
    subject: str,
    source: bytes,
    *,
    allow_false: bool = False,
) -> bool:
    """Recognize a rejecting negative check whose fallthrough proves `subject`."""
    if if_node is None or if_node.type != "if_statement":
        return False
    condition = if_node.child_by_field_name("condition")
    consequence = if_node.child_by_field_name("consequence")
    if condition is None or not terminates(consequence):
        return False
    text = source[condition.start_byte : condition.end_byte].decode(
        "utf-8", errors="replace"
    )
    compact = "".join(text.split())
    while compact.startswith("(") and compact.endswith(")"):
        compact = compact[1:-1]
    path_segment = r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)"
    subject_expr = rf"{re.escape(subject)}(?:{path_segment})*"
    missing_values = "null|undefined|false" if allow_false else "null|undefined"
    return bool(
        re.fullmatch(rf"!\(?{subject_expr}\)?", compact)
        or re.fullmatch(rf"{subject_expr}(?:==|===)(?:{missing_values})", compact)
    )


class SecurityFlow:
    """Bounded, per-file TypeScript security facts.

    The object deliberately separates candidate discovery from positive proof.
    Rules may use names to find a candidate, but must use resolved bindings,
    route-local events and control-flow order before suppressing a finding.
    """

    def __init__(
        self,
        root_node,
        source: bytes,
        file_path: str,
        lang: Language,
        limits: FlowLimits,
    ) -> None:
        self.root_node = root_node
        self.source = source
        self.file_path = str(file_path)
        self.limits = limits
        self.analysis_complete = True
        self.diagnostics: list[str] = []
        self.scopes: tuple[LexicalScope, ...] = ()
        self.routes: tuple[RouteScope, ...] = ()
        self.omitted_security_routes: tuple[RouteScope, ...] = ()
        self.route_analysis_overflow = False
        self.calls: tuple[FlowEvent, ...] = ()
        self.imports: dict[str, ImportIdentity] = {}
        self._require_imports: dict[SymbolId, ImportIdentity] = {}
        self._scope_by_id: dict[int, LexicalScope] = {}
        self._scope_by_node: dict[tuple[int, int, str], int] = {}
        self._bindings: dict[str, list[_Binding]] = defaultdict(list)
        self._events_by_node: dict[tuple[int, int, str], FlowEvent] = {}
        self._binding_counts: dict[int, int] = defaultdict(int)
        self._scope_nodes_cache: dict[int, tuple[Any, ...]] = {}
        self._declarators_by_scope: dict[int, list[Any]] = defaultdict(list)
        self._assignments_by_scope: dict[int, list[Any]] = defaultdict(list)
        self._option_state_cache: dict[
            tuple[tuple[int, int, str], tuple[str, ...], int, int],
            dict[str, Truth4],
        ] = {}
        self._work_items = 0
        self._build()

    def node_text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def unwrap(self, node):
        return _unwrap_expression(node)

    def iter_nodes(self, node=None, *, skip_nested_functions: bool = False) -> Iterable:
        root = self.root_node if node is None else node
        stack = [root]
        seen = 0
        while stack:
            current = stack.pop()
            seen += 1
            if seen > self.limits.max_nodes:
                self._mark_incomplete("node budget exceeded")
                return
            if not self._consume_work():
                return
            self._observe_syntax_node(current)
            yield current
            children = list(reversed(current.named_children))
            for child in children:
                if (
                    skip_nested_functions
                    and child is not root
                    and child.type in _FUNCTION_TYPES
                ):
                    continue
                stack.append(child)

    def iter_scope_nodes(self, scope_or_region) -> Iterable:
        node = self.region_node(scope_or_region)
        if node is None:
            return ()

        scope_id: int | None = None
        if isinstance(scope_or_region, RouteScope):
            scope_id = scope_or_region.scope_id
        elif isinstance(scope_or_region, LexicalScope):
            scope_id = scope_or_region.id
        elif isinstance(scope_or_region, int):
            scope_id = scope_or_region

        if scope_id is None:
            return self.iter_nodes(node, skip_nested_functions=True)

        cached = self._scope_nodes_cache.get(scope_id)
        if cached is None:
            cached = tuple(self.iter_nodes(node, skip_nested_functions=True))
            self._scope_nodes_cache[scope_id] = cached
        if isinstance(scope_or_region, RouteScope):
            if not self._consume_work(len(cached)):
                return ()
            return tuple(
                item
                for item in cached
                if node.start_byte <= item.start_byte and item.end_byte <= node.end_byte
            )
        return cached

    def region_node(self, scope_or_route):
        if isinstance(scope_or_route, RouteScope):
            return scope_or_route._region
        if isinstance(scope_or_route, LexicalScope):
            return scope_or_route._body
        if isinstance(scope_or_route, int):
            return self._scope_by_id[scope_or_route]._body
        return scope_or_route

    def scope(self, scope_id: int) -> LexicalScope:
        return self._scope_by_id[scope_id]

    def scope_for_node(self, node) -> LexicalScope:
        current = node
        while current is not None:
            scope_id = self._scope_by_node.get(_node_key(current))
            if scope_id is not None:
                return self._scope_by_id[scope_id]
            current = current.parent
        return self._scope_by_id[0]

    def direct_statements(self, scope_or_region) -> list:
        node = self.region_node(scope_or_region)
        if node is None:
            return []
        if node.type == "statement_block":
            return list(node.named_children)
        if node.type in {"switch_case", "switch_default"}:
            return [
                child
                for child in node.named_children
                if child.type
                not in {
                    "string",
                    "number",
                    "identifier",
                    "member_expression",
                }
            ]
        return [node]

    def call_arguments(self, call_or_event) -> tuple:
        node = (
            call_or_event._node
            if isinstance(call_or_event, FlowEvent)
            else call_or_event
        )
        if node is None or node.type != "call_expression":
            return ()
        args = node.child_by_field_name("arguments")
        return tuple(args.named_children) if args is not None else ()

    def callee_path(self, call_node) -> tuple[str, ...]:
        if call_node is None or call_node.type != "call_expression":
            return ()
        return self._expression_path(call_node.child_by_field_name("function"))

    def calls_in(self, scope_or_region) -> tuple[FlowEvent, ...]:
        region = self.region_node(scope_or_region)
        if region is None:
            return ()
        scope_id = (
            scope_or_region.scope_id
            if isinstance(scope_or_region, RouteScope)
            else self.scope_for_node(region).id
        )
        return tuple(
            event
            for event in self._scope_by_id[scope_id].events
            if event.kind == EventKind.CALL
            and region.start_byte <= event.span.start_byte
            and event.span.end_byte <= region.end_byte
        )

    def calls_named(self, name: str, scope_or_region=None) -> tuple[FlowEvent, ...]:
        events = (
            self.calls if scope_or_region is None else self.calls_in(scope_or_region)
        )
        return tuple(
            event
            for event in events
            if event.callee is not None
            and event.callee.member_path
            and event.callee.member_path[-1] == name
        )

    def resolve_binding(
        self, name: str, before_byte: int, scope_id: int
    ) -> _Binding | None:
        candidates = self._visible_binding_candidates(name, before_byte, scope_id)
        if not candidates:
            return None
        candidates.sort(key=lambda binding: binding.symbol.decl_byte)
        return candidates[-1]

    def resolve_unique_binding(
        self, name: str, before_byte: int, scope_id: int
    ) -> _Binding | None:
        """Resolve only when collapsed block scopes leave one possible binding."""
        candidates = self._visible_binding_candidates(name, before_byte, scope_id)
        return candidates[0] if len(candidates) == 1 else None

    def has_visible_binding(self, name: str, before_byte: int, scope_id: int) -> bool:
        visible = set(self._visible_scope_ids(scope_id))
        return any(
            binding.symbol.scope_id in visible
            for binding in self._bindings.get(name, ())
        )

    def is_unshadowed_global_name(
        self, name: str, before_byte: int, scope_id: int
    ) -> bool:
        """Return whether a built-in name has no visible local replacement."""
        return self._is_unshadowed_global_name(name, before_byte, scope_id)

    def is_unshadowed_global_member(
        self,
        name: str,
        member: str,
        before_byte: int,
        scope_id: int,
    ) -> bool:
        """Return whether a built-in member has not been replaced locally."""
        if not self._is_unshadowed_global_name(name, before_byte, scope_id):
            return False
        visible = set(self._visible_scope_ids(scope_id))
        for candidate_scope_id in visible:
            cutoff = (
                before_byte
                if candidate_scope_id == scope_id
                else self._scope_by_id[candidate_scope_id].body_span.end_byte
            )
            for assignment in self._assignments_by_scope.get(candidate_scope_id, ()):
                if assignment.start_byte >= cutoff:
                    continue
                path = self._expression_path(assignment.child_by_field_name("left"))
                if path in {(name,), (name, member)}:
                    return False
        return True

    def _visible_binding_candidates(
        self, name: str, before_byte: int, scope_id: int
    ) -> list[_Binding]:
        visible_scope_ids = self._visible_scope_ids(scope_id)
        candidates = [
            binding
            for binding in self._bindings.get(name, ())
            if binding.symbol.scope_id in visible_scope_ids
            and (
                binding.symbol.scope_id != scope_id
                or binding.symbol.decl_byte < before_byte
            )
        ]
        if not candidates:
            return []
        for candidate_scope_id in visible_scope_ids:
            scoped = [
                binding
                for binding in candidates
                if binding.symbol.scope_id == candidate_scope_id
            ]
            if scoped:
                return scoped
        return []

    def dominant_guard(
        self,
        scope_or_region,
        before_byte: int,
        predicate: Callable[[Any], bool],
    ) -> Any | None:
        for statement in self.direct_statements(scope_or_region):
            if statement.start_byte >= before_byte:
                break
            if statement.type == "if_statement" and predicate(statement):
                return statement
        return None

    def cookie_assessment(self, call_event: FlowEvent) -> CookieAssessment:
        args = self.call_arguments(call_event)
        if len(args) < 3:
            states = {"httpOnly": Truth4.ABSENT, "secure": Truth4.ABSENT}
        else:
            states = self._object_option_states(
                args[2],
                names=("httpOnly", "secure"),
                before_byte=call_event.span.start_byte,
                scope_id=call_event.scope_id,
                depth=0,
                seen=frozenset(),
            )
        evidence = tuple(
            EvidenceStep(
                kind="option_fact",
                span=call_event.span,
                message=f"{name}={states[name].value}",
                subject=name,
            )
            for name in ("httpOnly", "secure")
        )
        verdict = (
            Verdict.PROTECTED
            if states["httpOnly"] == Truth4.TRUE and states["secure"] == Truth4.TRUE
            else Verdict.UNPROTECTED
        )
        if not self.analysis_complete:
            verdict = Verdict.INCOMPLETE
        return CookieAssessment(
            http_only=OptionFact(states["httpOnly"], evidence),
            secure=OptionFact(states["secure"], evidence),
            verdict=verdict,
        )

    def _mark_incomplete(self, diagnostic: str) -> None:
        self.analysis_complete = False
        if diagnostic not in self.diagnostics:
            self.diagnostics.append(diagnostic)

    def _consume_work(self, amount: int = 1) -> bool:
        if amount <= 0:
            return True
        self._work_items += amount
        if self._work_items > self.limits.max_work_items:
            self._mark_incomplete("security flow work budget exceeded")
            return False
        return True

    def _observe_syntax_node(self, node) -> None:
        if node is None:
            return
        if node.type == "ERROR" or bool(getattr(node, "is_missing", False)):
            self._mark_incomplete("TypeScript parse recovery intersects security flow")

    def _record_binding(self, binding: _Binding) -> bool:
        scope_id = binding.symbol.scope_id
        if not self._reserve_binding_slot(scope_id):
            return False
        self._bindings[binding.symbol.name].append(binding)
        return True

    def _reserve_binding_slot(self, scope_id: int, amount: int = 1) -> bool:
        if self._binding_counts[scope_id] + amount > self.limits.max_bindings_per_scope:
            self._mark_incomplete(f"binding budget exceeded in scope {scope_id}")
            return False
        self._binding_counts[scope_id] += amount
        return True

    def _build(self) -> None:
        if self.root_node is None:
            self._mark_incomplete("missing TypeScript syntax tree")
            return
        if bool(getattr(self.root_node, "has_error", False)):
            self._mark_incomplete("TypeScript syntax tree contains parse errors")
        self._collect_imports()
        self._collect_scopes_and_bindings()
        self._collect_require_imports()
        self._collect_events()
        self.calls = tuple(
            event
            for scope in self.scopes
            for event in scope.events
            if event.kind == EventKind.CALL
        )
        self.routes = tuple(self._bounded_unique_routes(self._collect_routes()))

    def import_identities(self) -> tuple[ImportIdentity, ...]:
        return tuple(self.imports.values()) + tuple(self._require_imports.values())

    def _bounded_unique_routes(self, routes: Iterable[RouteScope]) -> list[RouteScope]:
        unique: dict[tuple[Any, ...], RouteScope] = {}
        omitted_security_routes: list[RouteScope] = []
        for route in routes:
            region = route._region
            key = (
                route.scope_id,
                route.kind,
                route.methods,
                route.path,
                route.registration.start_byte,
                route.registration.end_byte,
                route.handler_index,
                region.start_byte if region is not None else -1,
                region.end_byte if region is not None else -1,
            )
            if key in unique:
                continue
            if len(unique) >= self.limits.max_routes:
                self._mark_incomplete("route budget exceeded")
                self.route_analysis_overflow = True
                if len(
                    omitted_security_routes
                ) < _MAX_OMITTED_SECURITY_ROUTES and self._route_has_security_hint(
                    route
                ):
                    omitted_security_routes.append(route)
                continue
            unique[key] = route
        self.omitted_security_routes = tuple(omitted_security_routes)
        return list(unique.values())

    def _route_has_security_hint(self, route: RouteScope) -> bool:
        if "POST" not in route.methods:
            return False
        route_hint = route.path
        if route_hint is None and route.kind in {
            RouteKind.NEXT_APP,
            RouteKind.NEXT_PAGES,
        }:
            route_hint = self.file_path.replace("\\", "/")
        return route_hint is None or bool(_SECURITY_ROUTE_HINT_RE.search(route_hint))

    def _collect_imports(self) -> None:
        for node in self.iter_nodes(self.root_node):
            if node.type != "import_statement":
                continue
            if any(child.type == "type" for child in node.children):
                continue
            source_node = node.child_by_field_name("source")
            module = _string_value(self.source, source_node)
            if not module:
                continue
            clause = next(
                (
                    child
                    for child in node.named_children
                    if child.type == "import_clause"
                ),
                None,
            )
            if clause is None:
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    local = self.node_text(child)
                    if not self._reserve_binding_slot(0):
                        continue
                    self.imports[local] = ImportIdentity(
                        module, "default", local, ImportKind.DEFAULT
                    )
                elif child.type == "namespace_import":
                    ident = next(
                        (c for c in child.named_children if c.type == "identifier"),
                        None,
                    )
                    if ident is not None:
                        local = self.node_text(ident)
                        if not self._reserve_binding_slot(0):
                            continue
                        self.imports[local] = ImportIdentity(
                            module, "*", local, ImportKind.NAMESPACE
                        )
                elif child.type == "named_imports":
                    for specifier in child.named_children:
                        if specifier.type != "import_specifier":
                            continue
                        if any(item.type == "type" for item in specifier.children):
                            continue
                        identifiers = [
                            c
                            for c in specifier.named_children
                            if c.type in {"identifier", "type_identifier"}
                        ]
                        if not identifiers:
                            continue
                        exported = self.node_text(identifiers[0])
                        local = self.node_text(identifiers[-1])
                        if not self._reserve_binding_slot(0):
                            continue
                        self.imports[local] = ImportIdentity(
                            module, exported, local, ImportKind.NAMED
                        )

    def _collect_require_imports(self) -> None:
        """Collect exact, unshadowed CommonJS module bindings."""
        for bindings in self._bindings.values():
            for binding in bindings:
                name_node = binding.declaration_node.child_by_field_name("name")
                if name_node is None or name_node.type != "identifier":
                    continue
                module = self._required_module(binding.value_node)
                if module is None:
                    continue
                scope_id = binding.symbol.scope_id
                if not self._is_unshadowed_global_name(
                    "require", binding.symbol.decl_byte, scope_id
                ):
                    continue
                local = self.node_text(name_node)
                self._require_imports[binding.symbol] = ImportIdentity(
                    module, "default", local, ImportKind.REQUIRE
                )

    def _required_module(self, node) -> str | None:
        node = self.unwrap(node)
        if node is None or node.type != "call_expression":
            return None
        function = self.unwrap(node.child_by_field_name("function"))
        require_call = node
        if function is not None and function.type == "call_expression":
            require_call = function
            function = self.unwrap(require_call.child_by_field_name("function"))
        if function is None or function.type != "identifier":
            return None
        if self.node_text(function) != "require":
            return None
        args = self.call_arguments(require_call)
        return _string_value(self.source, args[0]) if len(args) == 1 else None

    def _collect_scopes_and_bindings(self) -> None:
        module_scope = LexicalScope(
            id=0,
            kind=ScopeKind.MODULE,
            parent_id=None,
            name="<module>",
            body_span=Span.from_node(self.root_node),
            params=(),
            events=[],
            complete=True,
            _node=self.root_node,
            _body=self.root_node,
        )
        scopes = [module_scope]
        self._scope_by_id[0] = module_scope
        self._scope_by_node[_node_key(self.root_node)] = 0

        stack: list[tuple[Any, int]] = [(self.root_node, 0)]
        visited = 0
        while stack:
            node, owner_id = stack.pop()
            visited += 1
            if visited > self.limits.max_nodes:
                self._mark_incomplete("node budget exceeded while collecting scopes")
                break
            if not self._consume_work():
                break
            self._observe_syntax_node(node)
            current_owner = owner_id
            if node is not self.root_node and node.type in {
                "class_declaration",
                "enum_declaration",
                "function_declaration",
                "generator_function_declaration",
                "internal_module",
            }:
                declared_name = _identifier_text(
                    self.source, node.child_by_field_name("name")
                )
                if declared_name:
                    self._record_binding(
                        _Binding(
                            SymbolId(owner_id, declared_name, node.start_byte),
                            node,
                            node,
                        )
                    )
            elif node is not self.root_node and node.type == "import_require_clause":
                declared_name = next(
                    (
                        self.node_text(child)
                        for child in node.named_children
                        if child.type == "identifier"
                    ),
                    None,
                )
                if declared_name:
                    self._record_binding(
                        _Binding(
                            SymbolId(owner_id, declared_name, node.start_byte),
                            node,
                            node,
                        )
                    )
            elif node.type == "catch_clause":
                parameter = node.child_by_field_name("parameter")
                if parameter is not None:
                    for child in self.iter_nodes(parameter):
                        name = _identifier_text(self.source, child)
                        if name:
                            self._record_binding(
                                _Binding(
                                    SymbolId(owner_id, name, child.start_byte),
                                    None,
                                    node,
                                )
                            )
            if node is not self.root_node and node.type in _FUNCTION_TYPES:
                if len(scopes) >= self.limits.max_scopes:
                    self._mark_incomplete("scope budget exceeded")
                    continue
                body = node.child_by_field_name("body") or node
                name = self._function_name(node)
                scope_id = len(scopes)
                params = tuple(
                    SymbolId(scope_id, param, node.start_byte)
                    for param in self._parameter_names(node)
                )
                if params and not self._reserve_binding_slot(scope_id, len(params)):
                    self._mark_incomplete(
                        f"parameter binding budget exceeded in scope {scope_id}"
                    )
                scope = LexicalScope(
                    id=scope_id,
                    kind=ScopeKind.FUNCTION,
                    parent_id=owner_id,
                    name=name,
                    body_span=Span.from_node(body),
                    params=params,
                    events=[],
                    complete=True,
                    _node=node,
                    _body=body,
                )
                scopes.append(scope)
                self._scope_by_id[scope_id] = scope
                self._scope_by_node[_node_key(node)] = scope_id
                current_owner = scope_id

            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                name = _identifier_text(self.source, name_node)
                if name:
                    self._record_binding(
                        _Binding(
                            SymbolId(current_owner, name, node.start_byte),
                            value_node,
                            node,
                        )
                    )
            for child in reversed(node.named_children):
                stack.append((child, current_owner))

        self.scopes = tuple(scopes)

    def _collect_events(self) -> None:
        next_id = 0
        for scope in self.scopes:
            ordinal = 0
            scope_nodes: list[Any] = []
            for node in self._evaluation_nodes(scope._body, scope._node):
                scope_nodes.append(node)
                if node.type == "variable_declarator":
                    self._declarators_by_scope[scope.id].append(node)
                elif node.type in {
                    "assignment_expression",
                    "augmented_assignment_expression",
                }:
                    self._assignments_by_scope[scope.id].append(node)
                kind: EventKind | None = None
                callee = None
                args: tuple[str, ...] = ()
                if node.type == "call_expression":
                    kind = EventKind.CALL
                    callee = self._callee_identity(node, scope.id)
                    args = tuple(
                        self.node_text(arg) for arg in self.call_arguments(node)
                    )
                elif node.type == "new_expression":
                    kind = EventKind.NEW
                    callee = self._constructor_identity(node, scope.id)
                    args_node = node.child_by_field_name("arguments")
                    args = tuple(
                        self.node_text(arg)
                        for arg in (
                            args_node.named_children if args_node is not None else ()
                        )
                    )
                elif node.type == "update_expression":
                    kind = EventKind.UPDATE
                elif node.type == "unary_expression" and self.node_text(
                    node
                ).lstrip().startswith("delete"):
                    # `delete target.member` is an externally visible mutation just
                    # like an assignment or increment. Security rules must not let
                    # it occur before authentication/signature verification.
                    kind = EventKind.UPDATE
                elif node.type == "variable_declarator":
                    kind = EventKind.BIND
                elif node.type in {
                    "assignment_expression",
                    "augmented_assignment_expression",
                }:
                    kind = EventKind.ASSIGN
                elif node.type == "if_statement":
                    kind = EventKind.BRANCH
                elif node.type == "return_statement":
                    kind = EventKind.RETURN
                elif node.type == "throw_statement":
                    kind = EventKind.THROW
                elif node.type in {
                    "try_statement",
                    "for_statement",
                    "for_in_statement",
                    "while_statement",
                    "do_statement",
                    "switch_statement",
                }:
                    kind = EventKind.UNKNOWN_CONTROL
                if kind is None:
                    continue
                if len(scope.events) >= self.limits.max_events_per_scope:
                    scope.complete = False
                    self._mark_incomplete(
                        f"event budget exceeded in scope {scope.name}"
                    )
                    break
                event = FlowEvent(
                    id=next_id,
                    ordinal=ordinal,
                    kind=kind,
                    scope_id=scope.id,
                    span=Span.from_node(node),
                    callee=callee,
                    arg_values=args,
                    node_type=node.type,
                    _node=node,
                )
                scope.events.append(event)
                self._events_by_node[_node_key(node)] = event
                next_id += 1
                ordinal += 1
            self._scope_nodes_cache[scope.id] = tuple(
                sorted(scope_nodes, key=lambda item: (item.start_byte, item.end_byte))
            )

    def _evaluation_nodes(self, root, scope_node) -> Iterable:
        """Yield expressions in JS evaluation order; a call is emitted after args."""
        stack: list[tuple[Any, bool]] = [(root, False)]
        visited = 0
        while stack:
            node, expanded = stack.pop()
            if node is not root and node.type in _FUNCTION_TYPES:
                continue
            if expanded:
                yield node
                continue
            visited += 1
            if visited > self.limits.max_nodes:
                self._mark_incomplete("node budget exceeded while collecting events")
                return
            if not self._consume_work():
                return
            self._observe_syntax_node(node)
            stack.append((node, True))
            for child in reversed(node.named_children):
                stack.append((child, False))

    def _collect_routes(self) -> Iterable[RouteScope]:
        normalized_path = self.file_path.replace("\\", "/")
        is_app_route = "/app/" in normalized_path and normalized_path.endswith(
            ("route.ts", "route.tsx", "route.js", "route.jsx")
        )
        is_pages_route = "/pages/api/" in normalized_path and normalized_path.endswith(
            (".ts", ".tsx", ".js", ".jsx")
        )

        for child in self.root_node.named_children:
            if child.type != "export_statement":
                continue
            default_export = any(
                self.node_text(token) == "default" for token in child.children
            )
            declaration = next(
                (
                    item
                    for item in child.named_children
                    if item.type
                    in {
                        "function_declaration",
                        "lexical_declaration",
                    }
                ),
                None,
            )
            if declaration is None:
                if is_app_route:
                    yield from self._app_routes_from_export_clause(child)
                if is_pages_route and default_export:
                    expression = next(
                        (
                            item
                            for item in child.named_children
                            if item.type != "export_clause"
                        ),
                        None,
                    )
                    function_node = self._resolve_function_node(
                        expression, child.start_byte, 0
                    )
                    if function_node is not None:
                        yield from self._pages_routes(function_node)
                    else:
                        self._mark_incomplete(
                            "external or wrapped Next.js Pages handler is not resolved"
                        )
                continue
            if is_app_route and declaration.type == "function_declaration":
                name_node = declaration.child_by_field_name("name")
                method = _identifier_text(self.source, name_node)
                if method in _MUTATING_METHODS | {"GET"}:
                    yield self._route_for_function(
                        declaration,
                        RouteKind.NEXT_APP,
                        frozenset({method}),
                        None,
                        declaration,
                    )
            elif is_app_route and declaration.type == "lexical_declaration":
                for declarator in declaration.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    name_node = declarator.child_by_field_name("name")
                    value_node = declarator.child_by_field_name("value")
                    method = _identifier_text(self.source, name_node)
                    function_node = self._resolve_function_node(
                        value_node, declarator.start_byte, 0
                    )
                    if method in _MUTATING_METHODS | {"GET"} and function_node:
                        yield self._route_for_function(
                            function_node,
                            RouteKind.NEXT_APP,
                            frozenset({method}),
                            None,
                            declarator,
                        )
                    elif method in _MUTATING_METHODS:
                        self._mark_incomplete(
                            f"external or wrapped Next.js {method} route is not resolved"
                        )
            elif is_pages_route and default_export:
                function_node = declaration
                if declaration.type == "lexical_declaration":
                    declarator = next(
                        (
                            item
                            for item in declaration.named_children
                            if item.type == "variable_declarator"
                        ),
                        None,
                    )
                    function_node = (
                        self._resolve_function_node(
                            declarator.child_by_field_name("value"),
                            declarator.start_byte,
                            0,
                        )
                        if declarator is not None
                        else None
                    )
                if function_node is not None and function_node.type in _FUNCTION_TYPES:
                    yield from self._pages_routes(function_node)

        for event in self.calls:
            if event.callee is None or len(event.callee.member_path) < 2:
                continue
            receiver = event.callee.member_path[0]
            method = event.callee.member_path[-1].upper()
            route_kind = self._route_receiver_kind(
                receiver, event.span.start_byte, event.scope_id
            )
            if route_kind is None or method not in (_MUTATING_METHODS | {"GET"}):
                continue
            args = self.call_arguments(event)
            callbacks = [
                candidate
                for arg in args
                if (
                    candidate := self._resolve_function_node(
                        arg, event.span.start_byte, event.scope_id
                    )
                )
                is not None
            ]
            if not callbacks:
                continue
            path = self._route_path_for_call(event, args)
            # Express and compatible routers execute every callback from left to
            # right. Model each callback so an unsafe early middleware cannot be
            # hidden by a verifier in the final handler.
            for handler_index, callback in enumerate(callbacks):
                yield self._route_for_function(
                    callback,
                    route_kind,
                    frozenset({method}),
                    path,
                    event._node,
                    handler_index=handler_index,
                    handler_count=len(callbacks),
                )

    def _route_path_for_call(
        self, event: FlowEvent, args: tuple[Any, ...]
    ) -> str | None:
        if args:
            direct = self._static_route_path(
                args[0], event.span.start_byte, event.scope_id, frozenset()
            )
            if direct is not None:
                return direct

        # Express supports `router.route("/path").post(handler)`. The POST call's
        # own first argument is a handler, so recover the path from the chained
        # `route()` receiver instead.
        function = self.unwrap(event._node.child_by_field_name("function"))
        current = (
            self.unwrap(function.child_by_field_name("object"))
            if function is not None
            and function.type in {"member_expression", "subscript_expression"}
            else None
        )
        for _ in range(8):
            if current is None:
                break
            if current.type == "call_expression":
                if self.callee_path(current)[-1:] == ("route",):
                    route_args = self.call_arguments(current)
                    if route_args:
                        return self._static_route_path(
                            route_args[0],
                            event.span.start_byte,
                            event.scope_id,
                            frozenset(),
                        )
                current_function = self.unwrap(current.child_by_field_name("function"))
                current = (
                    self.unwrap(current_function.child_by_field_name("object"))
                    if current_function is not None
                    and current_function.type
                    in {"member_expression", "subscript_expression"}
                    else None
                )
                continue
            if current.type in {"member_expression", "subscript_expression"}:
                current = self.unwrap(current.child_by_field_name("object"))
                continue
            break
        return None

    def _static_route_path(
        self,
        node,
        before_byte: int,
        scope_id: int,
        seen: frozenset[str],
    ) -> str | None:
        node = self.unwrap(node)
        literal = _string_value(self.source, node)
        if literal is not None:
            return literal
        if node is None or node.type != "identifier":
            return None
        name = self.node_text(node)
        if name in seen:
            return None
        binding = self.resolve_unique_binding(name, before_byte, scope_id)
        if (
            binding is None
            or binding.value_node is None
            or not self._binding_is_stable_until(name, binding, before_byte, scope_id)
        ):
            return None
        return self._static_route_path(
            binding.value_node,
            binding.symbol.decl_byte,
            binding.symbol.scope_id,
            seen | {name},
        )

    def _app_routes_from_export_clause(self, export_node) -> list[RouteScope]:
        routes: list[RouteScope] = []
        clause = next(
            (
                child
                for child in export_node.named_children
                if child.type == "export_clause"
            ),
            None,
        )
        if clause is None:
            return routes
        for specifier in clause.named_children:
            if specifier.type != "export_specifier":
                continue
            local = specifier.child_by_field_name("name")
            exported = specifier.child_by_field_name("alias") or local
            method = _identifier_text(self.source, exported)
            local_name = _identifier_text(self.source, local)
            if method not in _MUTATING_METHODS | {"GET"} or not local_name:
                continue
            function_node = self._resolve_function_node(
                local, export_node.start_byte, 0
            )
            if function_node is None:
                self._mark_incomplete(
                    f"external Next.js {method} route re-export is not resolved"
                )
                continue
            routes.append(
                self._route_for_function(
                    function_node,
                    RouteKind.NEXT_APP,
                    frozenset({method}),
                    None,
                    specifier,
                )
            )
        return routes

    def _resolve_function_node(
        self,
        node,
        before_byte: int,
        scope_id: int,
        seen: frozenset[str] = frozenset(),
    ):
        node = self.unwrap(node)
        if node is None:
            return None
        if node.type in _FUNCTION_TYPES:
            return node
        if node.type == "identifier":
            name = self.node_text(node)
            if name in seen:
                return None
            binding = self.resolve_unique_binding(name, before_byte, scope_id)
            if binding is None:
                binding = self._hoisted_function_binding(name, scope_id)
            if binding is None:
                return None
            return self._resolve_function_node(
                binding.value_node,
                binding.symbol.decl_byte + 1,
                binding.symbol.scope_id,
                seen | {name},
            )
        # Arbitrary wrappers are not transparent: a wrapper can ignore the
        # supplied safe callback and return a different unsafe handler.
        return None

    def _hoisted_function_binding(self, name: str, scope_id: int) -> _Binding | None:
        for visible_scope_id in self._visible_scope_ids(scope_id):
            candidates = [
                binding
                for binding in self._bindings.get(name, ())
                if binding.symbol.scope_id == visible_scope_id
                and binding.value_node is not None
                and binding.value_node.type
                in {"function_declaration", "generator_function_declaration"}
            ]
            if candidates:
                return candidates[0] if len(candidates) == 1 else None
        return None

    def _route_for_function(
        self,
        function_node,
        kind: RouteKind,
        methods: frozenset[str],
        path: str | None,
        registration_node,
        *,
        region=None,
        handler_index: int = 0,
        handler_count: int = 1,
    ) -> RouteScope:
        scope = self.scope_for_node(function_node)
        parameter_groups = self._parameter_name_groups(function_node)
        destructured_request = self._destructured_request_parameters(function_node)
        request = tuple(
            SymbolId(scope.id, name, function_node.start_byte)
            for name in (parameter_groups[0] if parameter_groups else ())
        )
        request_body = tuple(
            SymbolId(scope.id, name, function_node.start_byte)
            for name in destructured_request.get("body", ())
        )
        request_raw_body = tuple(
            SymbolId(scope.id, name, function_node.start_byte)
            for name in destructured_request.get("rawBody", ())
        )
        request_headers = tuple(
            SymbolId(scope.id, name, function_node.start_byte)
            for name in destructured_request.get("headers", ())
        )
        response = tuple(
            SymbolId(scope.id, name, function_node.start_byte)
            for name in (parameter_groups[1] if len(parameter_groups) > 1 else ())
        )
        return RouteScope(
            scope_id=scope.id,
            kind=kind,
            methods=methods,
            path=path,
            request_symbols=request,
            request_body_symbols=request_body,
            request_raw_body_symbols=request_raw_body,
            request_header_symbols=request_headers,
            response_symbols=response,
            registration=Span.from_node(registration_node),
            handler_index=handler_index,
            handler_count=handler_count,
            _region=region or scope._body,
        )

    def _destructured_request_parameters(
        self, function_node
    ) -> dict[str, tuple[str, ...]]:
        params = function_node.child_by_field_name("parameters")
        if params is None:
            first = function_node.child_by_field_name("parameter")
        else:
            first = next(iter(params.named_children), None)
        if first is None:
            return {}
        if first.type in {"required_parameter", "optional_parameter"}:
            first = first.child_by_field_name("pattern") or next(
                iter(first.named_children), first
            )
        if first.type != "object_pattern":
            return {}

        result: dict[str, list[str]] = defaultdict(list)
        for child in first.named_children:
            if child.type in {
                "shorthand_property_identifier",
                "shorthand_property_identifier_pattern",
            }:
                source_name = self.node_text(child)
                if source_name in {"body", "rawBody", "headers"}:
                    result[source_name].append(source_name)
                continue
            if child.type not in {"pair_pattern", "object_assignment_pattern"}:
                continue
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            source_name = self._static_property_name(key)
            local_names = self._pattern_names(value)
            if source_name in {"body", "rawBody", "headers"} and len(local_names) == 1:
                result[source_name].append(local_names[0])
        return {name: tuple(dict.fromkeys(values)) for name, values in result.items()}

    def _pages_routes(self, function_node) -> list[RouteScope]:
        routes: list[RouteScope] = []
        scope = self.scope_for_node(function_node)
        for node in self.iter_scope_nodes(scope):
            if node.type == "if_statement":
                condition = node.child_by_field_name("condition")
                text = self.node_text(condition)
                methods = frozenset(
                    method
                    for method in _MUTATING_METHODS
                    if f"'{method}'" in text or f'"{method}"' in text
                )
                if methods and (".method" in text or "method" in text):
                    consequence = node.child_by_field_name("consequence")
                    condition_node = self.unwrap(condition)
                    operator = (
                        self.node_text(condition_node.child_by_field_name("operator"))
                        if condition_node is not None
                        and condition_node.type == "binary_expression"
                        else ""
                    )
                    if operator in {"!=", "!=="}:
                        # POST follows this rejecting branch (or lives in its
                        # else), so the consequence is not the POST route.
                        consequence = (
                            node.child_by_field_name("alternative") or scope._body
                        )
                    routes.append(
                        self._route_for_function(
                            function_node,
                            RouteKind.NEXT_PAGES,
                            methods,
                            None,
                            node,
                            region=consequence,
                        )
                    )
            elif node.type == "switch_case":
                value = node.child_by_field_name("value")
                text = self.node_text(value)
                methods = frozenset(
                    method
                    for method in _MUTATING_METHODS
                    if text.strip("'\"") == method
                )
                if methods:
                    routes.append(
                        self._route_for_function(
                            function_node,
                            RouteKind.NEXT_PAGES,
                            methods,
                            None,
                            node,
                            region=node,
                        )
                    )
        if not routes:
            body_text = self.node_text(scope._body)
            methods = frozenset(
                method
                for method in _MUTATING_METHODS
                if f"'{method}'" in body_text or f'"{method}"' in body_text
            )
            if methods:
                routes.append(
                    self._route_for_function(
                        function_node,
                        RouteKind.NEXT_PAGES,
                        methods,
                        None,
                        function_node,
                    )
                )
        return routes

    def _function_name(self, node) -> str:
        name_node = node.child_by_field_name("name")
        name = _identifier_text(self.source, name_node)
        if name:
            return name
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            return (
                _identifier_text(self.source, parent.child_by_field_name("name"))
                or "<anonymous>"
            )
        return "<anonymous>"

    def _parameter_names(self, node) -> list[str]:
        return [name for group in self._parameter_name_groups(node) for name in group]

    def _parameter_name_groups(self, node) -> list[list[str]]:
        params = node.child_by_field_name("parameters")
        if params is None:
            parameter = node.child_by_field_name("parameter")
            params_nodes = [parameter] if parameter is not None else []
        else:
            params_nodes = list(params.named_children)
        groups: list[list[str]] = []
        for param in params_nodes:
            current = param
            if current.type in {"required_parameter", "optional_parameter"}:
                pattern = current.child_by_field_name("pattern")
                current = pattern or next(
                    (
                        child
                        for child in current.named_children
                        if child.type == "identifier"
                    ),
                    current,
                )
            groups.append(self._pattern_names(current))
        return groups

    def _pattern_names(self, node) -> list[str]:
        if node is None:
            return []
        if node.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
        }:
            name = _identifier_text(self.source, node)
            return [name] if name else []
        if node.type in {"pair_pattern", "object_assignment_pattern"}:
            return self._pattern_names(node.child_by_field_name("value"))
        if node.type in {"assignment_pattern", "rest_pattern"}:
            child = node.child_by_field_name("left") or next(
                iter(node.named_children), None
            )
            return self._pattern_names(child)
        names: list[str] = []
        for child in node.named_children:
            names.extend(self._pattern_names(child))
        return list(dict.fromkeys(names))

    def _route_receiver_kind(
        self,
        name: str,
        before_byte: int,
        scope_id: int,
        seen: frozenset[str] = frozenset(),
    ) -> RouteKind | None:
        if not name or name in seen:
            return None
        binding = self.resolve_unique_binding(name, before_byte, scope_id)
        if binding is None:
            if self.has_visible_binding(name, before_byte, scope_id):
                return None
            identity = self.imports.get(name)
            if identity is not None:
                return self._route_kind_for_module(identity.module)
            return _ROUTE_RECEIVERS.get(name)

        value = self.unwrap(binding.value_node)
        if value is None:
            return None
        if value.type == "identifier":
            return self._route_receiver_kind(
                self.node_text(value),
                binding.symbol.decl_byte,
                binding.symbol.scope_id,
                seen | {name},
            )
        if value.type not in {"call_expression", "new_expression"}:
            return None
        target = value.child_by_field_name("function") or value.child_by_field_name(
            "constructor"
        )
        path = self._expression_path(target)
        if not path:
            return None
        identity = self._resolved_import_identity(
            path[0], binding.symbol.decl_byte, binding.symbol.scope_id
        )
        if identity is not None:
            return self._route_kind_for_module(identity.module)
        return self._route_receiver_kind(
            path[0],
            binding.symbol.decl_byte,
            binding.symbol.scope_id,
            seen | {name},
        )

    @staticmethod
    def _route_kind_for_module(module: str) -> RouteKind | None:
        if module in {"express", "@express/core"}:
            return RouteKind.EXPRESS
        if module == "fastify":
            return RouteKind.FASTIFY
        if module == "hono":
            return RouteKind.HONO
        return None

    def _expression_path(self, node) -> tuple[str, ...]:
        node = self.unwrap(node)
        if node is None:
            return ()
        if node.type in {"identifier", "property_identifier"}:
            name = _identifier_text(self.source, node)
            return (name,) if name else ()
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            prop_name = _identifier_text(self.source, prop) or self.node_text(prop)
            return self._expression_path(obj) + ((prop_name,) if prop_name else ())
        if node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            index_value = _string_value(self.source, index)
            return self._expression_path(obj) + ((index_value,) if index_value else ())
        if node.type in {"call_expression", "new_expression"}:
            target = node.child_by_field_name("function") or node.child_by_field_name(
                "constructor"
            )
            return self._expression_path(target)
        return ()

    def _callee_identity(self, call_node, scope_id: int) -> CalleeIdentity:
        path = self.callee_path(call_node)
        if not path:
            return CalleeIdentity(None, ())
        first = path[0]
        parameter = next(
            (
                symbol
                for symbol in self._scope_by_id[scope_id].params
                if symbol.name == first
            ),
            None,
        )
        if parameter is not None:
            return CalleeIdentity(None, path, parameter)
        binding = self.resolve_unique_binding(first, call_node.start_byte, scope_id)
        if binding is None:
            if self.has_visible_binding(first, call_node.start_byte, scope_id):
                return CalleeIdentity(None, path)
            return CalleeIdentity(self.imports.get(first), path)

        value = self.unwrap(binding.value_node)
        direct_import = self._require_imports.get(binding.symbol)
        if direct_import is not None:
            return CalleeIdentity(direct_import, path, binding.symbol)
        if value is not None and value.type == "new_expression":
            constructor = value.child_by_field_name("constructor")
            constructor_path = self._expression_path(constructor)
            if constructor_path:
                imported = self._resolved_import_identity(
                    constructor_path[0], value.start_byte, binding.symbol.scope_id
                )
                return CalleeIdentity(
                    imported,
                    constructor_path + path[1:],
                    binding.symbol,
                )
        return CalleeIdentity(None, path, binding.symbol)

    def _constructor_identity(self, new_node, scope_id: int) -> CalleeIdentity:
        constructor = new_node.child_by_field_name("constructor")
        path = self._expression_path(constructor)
        if not path:
            return CalleeIdentity(None, ())
        first = path[0]
        parameter = next(
            (
                symbol
                for symbol in self._scope_by_id[scope_id].params
                if symbol.name == first
            ),
            None,
        )
        if parameter is not None:
            return CalleeIdentity(None, path, parameter)
        binding = self.resolve_unique_binding(first, new_node.start_byte, scope_id)
        if binding is not None:
            identity = self._require_imports.get(binding.symbol)
            return CalleeIdentity(
                identity,
                path,
                binding.symbol,
            )
        if self.has_visible_binding(first, new_node.start_byte, scope_id):
            return CalleeIdentity(None, path)
        return CalleeIdentity(self.imports.get(first), path)

    def _resolved_import_identity(
        self, name: str, before_byte: int, scope_id: int
    ) -> ImportIdentity | None:
        binding = self.resolve_unique_binding(name, before_byte, scope_id)
        if binding is not None:
            return self._require_imports.get(binding.symbol)
        if self.has_visible_binding(name, before_byte, scope_id):
            return None
        return self.imports.get(name)

    def _object_option_states(
        self,
        node,
        *,
        names: tuple[str, ...],
        before_byte: int,
        scope_id: int,
        depth: int,
        seen: frozenset[tuple[int, int, str]],
    ) -> dict[str, Truth4]:
        unknown = {name: Truth4.UNKNOWN for name in names}
        if node is None or depth > self.limits.max_expr_depth:
            self._mark_incomplete("object expression depth exceeded")
            return unknown
        node = self.unwrap(node)
        if node is None:
            return unknown
        key = _node_key(node)
        if key in seen:
            return unknown
        seen = seen | {key}

        if node.type == "identifier":
            name = self.node_text(node)
            binding = self.resolve_unique_binding(name, before_byte, scope_id)
            if binding is None or binding.value_node is None:
                return unknown
            states = self._object_option_states(
                binding.value_node,
                names=names,
                before_byte=binding.symbol.decl_byte,
                scope_id=binding.symbol.scope_id,
                depth=depth + 1,
                seen=seen,
            )
            invalidated = self._apply_binding_effects(
                states,
                name,
                binding.symbol.decl_byte,
                before_byte,
                binding.symbol.scope_id,
                scope_id,
                names,
            )
            if invalidated:
                return unknown
            return states

        if node.type == "call_expression":
            path = self.callee_path(node)
            args = self.call_arguments(node)
            if (
                path == ("Object", "freeze")
                and args
                and self.is_unshadowed_global_member(
                    "Object", "freeze", node.start_byte, scope_id
                )
            ):
                return self._object_option_states(
                    args[0],
                    names=names,
                    before_byte=before_byte,
                    scope_id=scope_id,
                    depth=depth + 1,
                    seen=seen,
                )
            return unknown

        if node.type != "object":
            return unknown

        states = {name: Truth4.ABSENT for name in names}
        for child in node.named_children[: self.limits.max_properties]:
            if child.type == "spread_element":
                spread_expr = child.named_children[0] if child.named_children else None
                spread_states = self._object_option_states(
                    spread_expr,
                    names=names,
                    before_byte=before_byte,
                    scope_id=scope_id,
                    depth=depth + 1,
                    seen=seen,
                )
                for name in names:
                    if spread_states[name] != Truth4.ABSENT:
                        states[name] = spread_states[name]
                continue
            if child.type in {
                "shorthand_property_identifier",
                "shorthand_property_identifier_pattern",
            }:
                property_name = self.node_text(child)
                if property_name in states:
                    binding = self.resolve_unique_binding(
                        property_name, child.start_byte, scope_id
                    )
                    value_node = (
                        binding.value_node
                        if binding is not None
                        and self._binding_is_stable_until(
                            property_name, binding, before_byte, scope_id
                        )
                        else None
                    )
                    states[property_name] = self._truth_value(value_node)
                continue
            if child.type != "pair":
                continue
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            property_name = self._static_property_name(key_node)
            if property_name in states:
                states[property_name] = self._truth_value(value_node)
            elif property_name is None:
                for name in names:
                    states[name] = Truth4.UNKNOWN
        if len(node.named_children) > self.limits.max_properties:
            self._mark_incomplete("object property budget exceeded")
            return unknown
        return states

    def _binding_is_stable_until(
        self,
        name: str,
        binding: _Binding,
        before_byte: int,
        use_scope_id: int,
    ) -> bool:
        ranges = [
            (
                binding.symbol.scope_id,
                binding.symbol.decl_byte,
                before_byte,
            )
        ]
        if binding.symbol.scope_id != use_scope_id:
            ranges.append((use_scope_id, -1, before_byte))
        for candidate_scope_id, lower, upper in ranges:
            for node in self._scope_nodes_cache.get(candidate_scope_id, ()):
                if not (lower < node.start_byte < upper):
                    continue
                if node.type in {
                    "assignment_expression",
                    "augmented_assignment_expression",
                }:
                    path = self._expression_path(node.child_by_field_name("left"))
                    if path and path[0] == name:
                        return False
                elif node.type == "update_expression":
                    target = next(iter(node.named_children), None)
                    path = self._expression_path(target)
                    if path and path[0] == name:
                        return False
        return True

    def _truth_value(self, node) -> Truth4:
        node = self.unwrap(node)
        if node is None:
            return Truth4.UNKNOWN
        if node.type == "true":
            return Truth4.TRUE
        if node.type == "false":
            return Truth4.FALSE
        return Truth4.UNKNOWN

    def _static_property_name(self, node) -> str | None:
        if node is None:
            return None
        name = _identifier_text(self.source, node)
        if name:
            return name
        value = _string_value(self.source, node)
        if value is not None:
            return value
        if node.type == "computed_property_name" and len(node.named_children) == 1:
            return _string_value(self.source, node.named_children[0])
        return None

    def _visible_scope_ids(self, scope_id: int) -> tuple[int, ...]:
        visible: list[int] = []
        current: int | None = scope_id
        while current is not None and current not in visible:
            visible.append(current)
            scope = self._scope_by_id.get(current)
            current = scope.parent_id if scope is not None else None
        if 0 not in visible:
            visible.append(0)
        return tuple(visible)

    def _is_unshadowed_global_name(
        self, name: str, before_byte: int, scope_id: int
    ) -> bool:
        if name in self.imports:
            return False
        visible = set(self._visible_scope_ids(scope_id))
        for candidate_scope_id in visible:
            scope = self._scope_by_id.get(candidate_scope_id)
            if scope is not None and any(
                parameter.name == name for parameter in scope.params
            ):
                return False
            if scope is not None and self._scope_parameter_contains_name(scope, name):
                return False
        if any(
            binding.symbol.scope_id in visible
            for binding in self._bindings.get(name, ())
        ):
            return False
        for candidate_scope_id in visible:
            cutoff = (
                before_byte
                if candidate_scope_id == scope_id
                else self._scope_by_id[candidate_scope_id].body_span.end_byte
            )
            for assignment in self._assignments_by_scope.get(candidate_scope_id, ()):
                if assignment.start_byte >= cutoff:
                    continue
                left = assignment.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    if self.node_text(left) == name:
                        return False
        return True

    def _scope_parameter_contains_name(
        self, scope: LexicalScope, expected_name: str
    ) -> bool:
        if scope.kind != ScopeKind.FUNCTION or scope._node is None:
            return False
        params = scope._node.child_by_field_name("parameters")
        if params is None:
            params = scope._node.child_by_field_name("parameter")
        if params is None:
            return False
        stack = [params]
        depth = 0
        while stack:
            current = stack.pop()
            depth += 1
            if depth > self.limits.max_expr_depth * 4:
                self._mark_incomplete("parameter binding inspection exceeded budget")
                return True
            if not self._consume_work():
                return True
            if (
                current.type
                in {
                    "identifier",
                    "shorthand_property_identifier_pattern",
                }
                and self.node_text(current) == expected_name
            ):
                return True
            stack.extend(current.named_children)
        return False

    def _apply_binding_effects(
        self,
        states: dict[str, Truth4],
        object_name: str,
        start_byte: int,
        before_byte: int,
        binding_scope_id: int,
        use_scope_id: int,
        names: tuple[str, ...],
    ) -> bool:
        """Apply ordered writes to an object binding; return True if proof is lost."""
        phases: list[tuple[int, int, str, Any]] = []
        scope_ranges: list[tuple[int, int, int, int]] = []
        if binding_scope_id == use_scope_id:
            scope_ranges.append((0, binding_scope_id, start_byte, before_byte))
        else:
            # A module binding is initialized before an externally-invoked handler,
            # including module statements textually after the function declaration.
            binding_upper = len(self.source) if binding_scope_id == 0 else before_byte
            scope_ranges.append((0, binding_scope_id, start_byte, binding_upper))
            scope_ranges.append((1, use_scope_id, 0, before_byte))

        for phase, candidate_scope_id, lower, upper in scope_ranges:
            declarators = self._declarators_by_scope.get(candidate_scope_id, ())
            assignments = self._assignments_by_scope.get(candidate_scope_id, ())
            calls = (
                event
                for event in self._scope_by_id[candidate_scope_id].events
                if event.kind == EventKind.CALL
            )
            mutations = (
                node
                for node in self._scope_nodes_cache.get(candidate_scope_id, ())
                if node.type == "update_expression"
                or (
                    node.type == "unary_expression"
                    and self.node_text(node).lstrip().startswith("delete ")
                )
            )
            for declarator in declarators:
                if lower < declarator.start_byte < upper:
                    phases.append(
                        (phase, declarator.start_byte, "declaration", declarator)
                    )
            for assignment in assignments:
                if lower < assignment.start_byte < upper:
                    phases.append(
                        (phase, assignment.start_byte, "assignment", assignment)
                    )
            for event in calls:
                if lower < event.span.start_byte < upper:
                    phases.append((phase, event.span.start_byte, "call", event))
            for mutation in mutations:
                if lower < mutation.start_byte < upper:
                    phases.append((phase, mutation.start_byte, "mutation", mutation))

        if not self._consume_work(len(phases)):
            return True
        phases.sort(key=lambda item: (item[0], item[1], item[2]))
        aliases = {object_name}
        containers: set[str] = set()

        for _, _, kind, item in phases:
            if kind == "declaration":
                declared = item.child_by_field_name("name")
                value = self.unwrap(item.child_by_field_name("value"))
                declared_name = _identifier_text(self.source, declared)
                if declared_name is None or value is None:
                    continue
                if value.type == "identifier" and self.node_text(value) in aliases:
                    aliases.add(declared_name)
                elif self._expression_contains_alias(
                    value,
                    aliases | containers,
                    include_nested_functions=True,
                ):
                    containers.add(declared_name)
                elif declared_name in aliases and declared_name != object_name:
                    # Collapsed block scopes cannot prove which same-name alias is
                    # referenced later, so discard the positive object proof.
                    return True
                elif declared_name in containers:
                    containers.discard(declared_name)
                continue

            if kind == "assignment":
                left = item.child_by_field_name("left")
                right = self.unwrap(item.child_by_field_name("right"))
                path = self._expression_path(left)
                if len(path) == 1:
                    target = path[0]
                    if target == object_name:
                        # Whole-binding reassignment versions the value. Until the
                        # flow heap models versions, it cannot retain literal facts.
                        return True
                    if target in aliases:
                        if right is not None and right.type == "identifier":
                            if self.node_text(right) in aliases:
                                continue
                        aliases.discard(target)
                        continue
                    if target in containers:
                        containers.discard(target)
                    if right is not None and right.type == "identifier":
                        if self.node_text(right) in aliases:
                            aliases.add(target)
                        elif self.node_text(right) in containers:
                            containers.add(target)
                    elif self._expression_contains_alias(
                        right,
                        aliases | containers,
                        include_nested_functions=True,
                    ):
                        containers.add(target)
                    continue
                if len(path) >= 2 and path[0] in aliases:
                    if path[1] in names:
                        states[path[1]] = (
                            Truth4.UNKNOWN
                            if self._is_conditionally_executed(
                                item, self.scope_for_node(item).id
                            )
                            else self._truth_value(right)
                        )
                    else:
                        # A method/property mutation through an alias can affect
                        # tracked properties through setters or proxies.
                        return True
                    continue
                if len(path) >= 2 and path[0] in containers:
                    return True
                if self._expression_contains_alias(right, aliases | containers):
                    return True
                continue

            if kind == "mutation":
                target = next(iter(item.named_children), None)
                path = self._expression_path(target)
                if len(path) >= 2 and path[0] in aliases:
                    if path[1] in names:
                        states[path[1]] = (
                            Truth4.ABSENT
                            if item.type == "unary_expression"
                            else Truth4.UNKNOWN
                        )
                    else:
                        return True
                elif path and path[0] in containers:
                    return True
                continue

            event = item
            if event.callee is not None and event.callee.member_path == (
                "Object",
                "freeze",
            ):
                if self.is_unshadowed_global_member(
                    "Object",
                    "freeze",
                    event.span.start_byte,
                    event.scope_id,
                ):
                    continue
            if event.callee is not None and event.callee.member_path:
                if event.callee.member_path[0] in aliases | containers:
                    return True
                callee_root = event.callee.member_path[0]
                callee_binding = self.resolve_unique_binding(
                    callee_root, event.span.start_byte, event.scope_id
                )
                if (
                    callee_binding is not None
                    and callee_binding.value_node is not None
                    and callee_binding.value_node.type in _FUNCTION_TYPES
                    and self._expression_contains_alias(
                        callee_binding.value_node,
                        aliases | containers,
                        include_nested_functions=True,
                    )
                ):
                    return True
            for arg in self.call_arguments(event):
                if self._expression_contains_alias(arg, aliases | containers):
                    return True
            if self._expression_contains_alias(
                event._node,
                aliases | containers,
                include_nested_functions=True,
            ):
                return True
        return False

    def _is_conditionally_executed(self, node, scope_id: int) -> bool:
        scope = self._scope_by_id[scope_id]
        current = node.parent
        conditional_types = {
            "catch_clause",
            "do_statement",
            "else_clause",
            "finally_clause",
            "for_in_statement",
            "for_statement",
            "if_statement",
            "switch_case",
            "switch_default",
            "switch_statement",
            "ternary_expression",
            "try_statement",
            "while_statement",
        }
        while current is not None and _node_key(current) != _node_key(scope._body):
            if current.type in _FUNCTION_TYPES:
                return True
            if current.type in conditional_types:
                return True
            if current.type == "binary_expression":
                text = self.node_text(current)
                if any(operator in text for operator in ("&&", "||", "??")):
                    return True
            current = current.parent
        return False

    def _expression_contains_alias(
        self,
        node,
        aliases: set[str],
        *,
        include_nested_functions: bool = False,
    ) -> bool:
        if node is None or not aliases:
            return False
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if not self._consume_work():
                return True
            if depth > self.limits.max_expr_depth:
                self._mark_incomplete("alias expression depth exceeded")
                return True
            current = self.unwrap(current)
            if current is None:
                continue
            if (
                current.type
                in {
                    "identifier",
                    "shorthand_property_identifier",
                    "shorthand_property_identifier_pattern",
                }
                and self.node_text(current) in aliases
            ):
                return True
            if (
                not include_nested_functions
                and current is not node
                and current.type in _FUNCTION_TYPES
            ):
                continue
            stack.extend((child, depth + 1) for child in current.named_children)
        return False


def build_security_flow(
    root_node,
    source: bytes,
    file_path: str,
    lang: Language,
    limits: FlowLimits = FlowLimits(),
) -> SecurityFlow:
    return SecurityFlow(root_node, source, file_path, lang, limits)
