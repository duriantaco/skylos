from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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
    analyze_routes: bool = True


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
_GLOBAL_OBJECT_NAMES = ("global", "globalThis", "self", "window")
_PROPERTY_MUTATOR_CALLEES = frozenset(
    {
        ("Object", "defineProperty"),
        ("Reflect", "defineProperty"),
        ("Reflect", "deleteProperty"),
        ("Reflect", "set"),
    }
)
_BULK_MUTATOR_CALLEES = frozenset(
    {
        ("Object", "assign"),
        ("Object", "defineProperties"),
        ("Object", "setPrototypeOf"),
        ("Reflect", "setPrototypeOf"),
    }
)
_BUILTIN_MUTATOR_CALLEES = _PROPERTY_MUTATOR_CALLEES | _BULK_MUTATOR_CALLEES
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


def _builtin_mutator_callee(path: tuple[str, ...]) -> tuple[str, ...]:
    if len(path) >= 2 and path[0] in _GLOBAL_OBJECT_NAMES:
        return path[1:]
    return path


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
        self._child_scope_ids: dict[int, list[int]] = defaultdict(list)
        self._identifier_scope_ids_by_name: dict[str, set[int]] = defaultdict(set)
        self._identifier_nodes_by_name_scope: dict[tuple[str, int], list[Any]] = (
            defaultdict(list)
        )
        self._bindings: dict[str, list[_Binding]] = defaultdict(list)
        self._events_by_node: dict[tuple[int, int, str], FlowEvent] = {}
        self._expression_path_cache: dict[tuple[int, int, str], tuple[str, ...]] = {}
        self._binding_counts: dict[int, int] = defaultdict(int)
        self._scope_nodes_cache: dict[int, tuple[Any, ...]] = {}
        self._declarators_by_scope: dict[int, list[Any]] = defaultdict(list)
        self._assignments_by_scope: dict[int, list[Any]] = defaultdict(list)
        self._binding_phase_index_cache: dict[
            int,
            tuple[tuple[int, ...], tuple[tuple[int, str, Any], ...]] | None,
        ] = {}
        self._write_effects_by_name: (
            dict[
                str,
                tuple[tuple[int, int, tuple[str, ...], bool], ...],
            ]
            | None
        ) = None
        self._binding_write_effect_cache: dict[
            SymbolId,
            dict[int, tuple[int, ...]] | None,
        ] = {}
        self._binding_scope_relation_cache: dict[tuple[SymbolId, int], bool | None] = {}
        self._global_path_effect_cache: dict[
            tuple[frozenset[tuple[str, ...]], int], int | None
        ] = {}
        self._global_path_mutation_scopes_cache: dict[
            frozenset[tuple[str, ...]], frozenset[int] | None
        ] = {}
        self._binding_nested_member_effect_cache: dict[
            tuple[SymbolId, str], frozenset[int] | None
        ] = {}
        self._resolved_builtin_mutator_cache: dict[
            tuple[int, int, str], tuple[str, ...]
        ] = {}
        self._nested_member_call_guard: set[tuple[int, str, str]] = set()
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
        return self._invocation_arguments(node)

    def _invocation_arguments(self, call_or_event) -> tuple:
        node = (
            call_or_event._node
            if isinstance(call_or_event, FlowEvent)
            else call_or_event
        )
        if node is None or node.type not in {"call_expression", "new_expression"}:
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

    def resolve_unique_binding_with_hoisted_functions(
        self, name: str, before_byte: int, scope_id: int
    ) -> _Binding | None:
        """Resolve a value binding while honoring function-declaration hoisting.

        Future non-function declarations still block an outer binding: even before
        initialization, their lexical name is not the outer value. Collapsed block
        scopes or duplicate declarations remain ambiguous and fail closed.
        """
        for candidate_scope_id in self._visible_scope_ids(scope_id):
            scope = self._scope_by_id.get(candidate_scope_id)
            if scope is not None and (
                any(parameter.name == name for parameter in scope.params)
                or self._scope_parameter_contains_name(scope, name)
            ):
                return None
            scoped = [
                binding
                for binding in self._bindings.get(name, ())
                if binding.symbol.scope_id == candidate_scope_id
            ]
            if not scoped:
                continue
            if len(scoped) != 1:
                return None
            binding = scoped[0]
            declaration = binding.declaration_node
            is_hoisted_function = bool(
                declaration is not None
                and declaration.type
                in {"function_declaration", "generator_function_declaration"}
            )
            if binding.symbol.decl_byte >= before_byte and not is_hoisted_function:
                return None
            return binding
        return None

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
        return not self._has_prior_path_mutation(
            self._global_paths(name, member),
            before_byte,
            scope_id,
        )

    def is_stable_global_path(
        self,
        path: tuple[str, ...],
        before_byte: int,
        scope_id: int,
        *,
        include_nested_writes: bool = False,
    ) -> bool:
        """Return whether a global object path is unshadowed and unchanged."""
        if not path or not self._is_unshadowed_global_name(
            path[0], before_byte, scope_id
        ):
            return False
        protected = self._global_paths(*path)
        return not self._has_prior_path_mutation(
            protected,
            before_byte,
            scope_id,
        ) and not (
            include_nested_writes
            and self._has_nested_global_path_mutation(protected, scope_id)
        )

    def is_binding_member_stable(
        self,
        binding: _Binding,
        member: str,
        before_byte: int,
        use_scope_id: int,
        *,
        include_nested_writes: bool = False,
    ) -> bool:
        """Return whether a proven object member remains unchanged and unescaped."""
        if not self.analysis_complete or not member:
            return False
        if include_nested_writes and self._has_nested_binding_member_effect(
            binding, member, use_scope_id
        ):
            return False
        states = {member: Truth4.TRUE}
        proof_lost = self._apply_binding_effects(
            states,
            binding.symbol.name,
            binding.symbol.decl_byte,
            before_byte,
            binding.symbol.scope_id,
            use_scope_id,
            (member,),
        )
        return bool(
            not proof_lost and self.analysis_complete and states[member] == Truth4.TRUE
        )

    def is_binding_member_unmodified_allowing_escape(
        self,
        binding: _Binding,
        member: str,
        before_byte: int,
        use_scope_id: int,
        *,
        include_nested_writes: bool = False,
    ) -> bool:
        """Prove a member unchanged while allowing read-only aliases and escapes."""
        if not self.analysis_complete or not member:
            return False
        if include_nested_writes and self._has_nested_binding_member_effect(
            binding, member, use_scope_id
        ):
            return False
        states = {member: Truth4.TRUE}
        proof_lost = self._apply_binding_effects(
            states,
            binding.symbol.name,
            binding.symbol.decl_byte,
            before_byte,
            binding.symbol.scope_id,
            use_scope_id,
            (member,),
            allow_escapes=True,
        )
        return bool(
            not proof_lost and self.analysis_complete and states[member] == Truth4.TRUE
        )

    def is_binding_value_stable(
        self,
        binding: _Binding,
        before_byte: int,
        use_scope_id: int,
    ) -> bool:
        """Return whether a binding's value was not reassigned before use."""
        if not self.analysis_complete:
            return False
        declaration = binding.declaration_node
        is_hoisted_function = bool(
            declaration is not None
            and declaration.type
            in {"function_declaration", "generator_function_declaration"}
        )
        binding_scope = self._scope_by_id.get(binding.symbol.scope_id)
        lower = (
            binding_scope.body_span.start_byte - 1
            if is_hoisted_function and binding_scope is not None
            else binding.symbol.decl_byte
        )
        effects = self._binding_write_effects(binding)
        if effects is None or not self.analysis_complete:
            return False
        for candidate_scope_id, effect_bytes in effects.items():
            if candidate_scope_id == use_scope_id:
                scope_lower = (
                    lower if candidate_scope_id == binding.symbol.scope_id else -1
                )
                if any(
                    scope_lower < effect_byte < before_byte
                    for effect_byte in effect_bytes
                ):
                    return False
                continue
            if candidate_scope_id == binding.symbol.scope_id:
                if any(effect_byte > lower for effect_byte in effect_bytes):
                    return False
                continue
            # A closure that can see the binding may run before the checked use.
            # Inspect its whole body because source order between calls and closure
            # bodies does not describe runtime order.
            if effect_bytes:
                return False
        return self.analysis_complete

    def _binding_write_effects(
        self,
        binding: _Binding,
    ) -> dict[int, tuple[int, ...]] | None:
        cached = self._binding_write_effect_cache.get(binding.symbol)
        if cached is not None or binding.symbol in self._binding_write_effect_cache:
            return cached
        if not self._ensure_write_effect_index():
            self._binding_write_effect_cache[binding.symbol] = None
            return None

        bindings_by_scope: dict[int, list[_Binding]] = defaultdict(list)
        for candidate in self._bindings.get(binding.symbol.name, ()):
            bindings_by_scope[candidate.symbol.scope_id].append(candidate)

        effects: dict[int, list[int]] = defaultdict(list)
        assert self._write_effects_by_name is not None
        candidate_effects = self._write_effects_by_name.get(binding.symbol.name, ())
        if not self._consume_work(len(candidate_effects)):
            self._binding_write_effect_cache[binding.symbol] = None
            return None
        for (
            candidate_scope_id,
            effect_byte,
            path,
            dynamic,
        ) in candidate_effects:
            if dynamic or path != (binding.symbol.name,):
                continue
            relation = self._write_binding_relation(
                binding,
                candidate_scope_id,
                bindings_by_scope,
                effect_byte=effect_byte,
            )
            if relation is False:
                continue
            # Exact matches and unresolved collapsed-scope writes both invalidate
            # the proof. The latter is deliberately fail-closed.
            effects[candidate_scope_id].append(effect_byte)

        frozen = {
            scope_id: tuple(sorted(set(effect_bytes)))
            for scope_id, effect_bytes in effects.items()
        }
        self._binding_write_effect_cache[binding.symbol] = frozen
        return frozen

    def _write_binding_relation(
        self,
        binding: _Binding,
        write_scope_id: int,
        bindings_by_scope: dict[int, list[_Binding]],
        *,
        effect_byte: int | None = None,
    ) -> bool | None:
        """Return whether a write resolves to the binding, or None if ambiguous."""
        visible_scope_ids = self._visible_scope_ids(write_scope_id)
        if binding.symbol.scope_id not in visible_scope_ids:
            return False
        for candidate_scope_id in visible_scope_ids:
            scope = self._scope_by_id.get(candidate_scope_id)
            if scope is not None and any(
                parameter.name == binding.symbol.name for parameter in scope.params
            ):
                return False
            scoped = list(bindings_by_scope.get(candidate_scope_id, ()))
            if effect_byte is not None:
                visible_bindings: list[_Binding] = []
                uncertain = False
                for candidate in scoped:
                    visibility = self._binding_visible_at_byte(
                        candidate, candidate_scope_id, effect_byte
                    )
                    if visibility is None:
                        uncertain = True
                    elif visibility:
                        visible_bindings.append(candidate)
                if uncertain or len(visible_bindings) > 1:
                    return None
                if len(visible_bindings) == 1:
                    return visible_bindings[0].symbol == binding.symbol
                continue
            if any(candidate.symbol == binding.symbol for candidate in scoped):
                return True if len(scoped) == 1 else None
            if any(
                self._binding_covers_entire_scope(candidate, candidate_scope_id)
                for candidate in scoped
            ):
                return False
            if scoped:
                return None
        return None

    def _binding_visible_at_byte(
        self,
        binding: _Binding,
        scope_id: int,
        effect_byte: int,
    ) -> bool | None:
        declaration = binding.declaration_node
        scope = self._scope_by_id.get(scope_id)
        if declaration is None or scope is None:
            return None
        if declaration.type == "variable_declarator":
            declaration_statement = declaration.parent
            if (
                declaration_statement is not None
                and declaration_statement.type == "variable_declaration"
            ):
                # `var` is function-scoped even when its declaration is nested.
                return True
            current = declaration_statement or declaration
        elif declaration.type == "catch_clause":
            body = declaration.child_by_field_name("body") or declaration
            return body.start_byte <= effect_byte <= body.end_byte
        else:
            current = declaration

        lexical_boundaries = {
            "catch_clause",
            "class_body",
            "do_statement",
            "else_clause",
            "for_in_statement",
            "for_statement",
            "if_statement",
            "internal_module",
            "labeled_statement",
            "statement_block",
            "switch_body",
            "while_statement",
            "with_statement",
        }
        for _ in range(self.limits.max_expr_depth * 4 + 1):
            if current is None:
                return None
            parent = current.parent
            if parent is None:
                return None
            if _node_key(parent) == _node_key(scope._body):
                return True
            if parent.type in lexical_boundaries:
                return parent.start_byte <= effect_byte <= parent.end_byte
            if parent.type in _FUNCTION_TYPES:
                return None
            current = parent
        self._mark_incomplete("binding visibility depth exceeded")
        return None

    def _binding_covers_entire_scope(
        self,
        binding: _Binding,
        scope_id: int,
    ) -> bool:
        scope = self._scope_by_id.get(scope_id)
        if scope is None:
            return False
        visibility = self._binding_visible_at_byte(
            binding,
            scope_id,
            scope.body_span.start_byte,
        )
        return visibility is True

    def _scope_binding_relation(
        self,
        binding: _Binding,
        scope_id: int,
        bindings_by_scope: dict[int, list[_Binding]],
    ) -> bool | None:
        cache_key = (binding.symbol, scope_id)
        if cache_key in self._binding_scope_relation_cache:
            return self._binding_scope_relation_cache[cache_key]
        nodes = self._identifier_nodes_by_name_scope.get(
            (binding.symbol.name, scope_id), ()
        )
        if not self._consume_work(len(nodes)):
            self._binding_scope_relation_cache[cache_key] = None
            return None
        uncertain = False
        for node in nodes:
            relation = self._write_binding_relation(
                binding,
                scope_id,
                bindings_by_scope,
                effect_byte=node.start_byte,
            )
            if relation is True:
                self._binding_scope_relation_cache[cache_key] = True
                return True
            if relation is None:
                uncertain = True
        result = None if uncertain else False
        self._binding_scope_relation_cache[cache_key] = result
        return result

    def _ensure_write_effect_index(self) -> bool:
        if self._write_effects_by_name is not None:
            return self.analysis_complete
        effects: dict[
            str,
            list[tuple[int, int, tuple[str, ...], bool]],
        ] = defaultdict(list)
        for scope in self.scopes:
            nodes = self._scope_nodes_cache.get(scope.id, ())
            if not self._consume_work(len(nodes)):
                self._write_effects_by_name = {}
                return False
            for node in nodes:
                target = self._write_target_node(node)
                if target is None:
                    continue
                effect_byte = self._write_effect_byte(node)
                for path, dynamic in self._assignment_targets(target):
                    if path:
                        effects[path[0]].append((scope.id, effect_byte, path, dynamic))
                if not self.analysis_complete:
                    self._write_effects_by_name = {}
                    return False
        self._write_effects_by_name = {
            name: tuple(items) for name, items in effects.items()
        }
        return self.analysis_complete

    def _has_nested_binding_member_effect(
        self,
        binding: _Binding,
        member: str,
        use_scope_id: int,
    ) -> bool:
        cache_key = (binding.symbol, member)
        cached = self._binding_nested_member_effect_cache.get(cache_key)
        if cached is None and cache_key not in self._binding_nested_member_effect_cache:
            bindings_by_scope: dict[int, list[_Binding]] = defaultdict(list)
            for candidate in self._bindings.get(binding.symbol.name, ()):
                bindings_by_scope[candidate.symbol.scope_id].append(candidate)

            affected_scopes: set[int] = set()
            referenced_scopes = self._identifier_scope_ids_by_name.get(
                binding.symbol.name, set()
            )
            if not self._consume_work(len(referenced_scopes)):
                self._binding_nested_member_effect_cache[cache_key] = None
                return True
            for candidate_scope_id in referenced_scopes:
                if candidate_scope_id == binding.symbol.scope_id:
                    continue
                if binding.symbol.scope_id not in self._visible_scope_ids(
                    candidate_scope_id
                ):
                    continue
                scope = self._scope_by_id[candidate_scope_id]
                relation = self._scope_binding_relation(
                    binding,
                    scope.id,
                    bindings_by_scope,
                )
                if relation is False:
                    continue
                states = {member: Truth4.TRUE}
                proof_lost = self._apply_binding_effects(
                    states,
                    binding.symbol.name,
                    scope.body_span.start_byte - 1,
                    scope.body_span.end_byte + 1,
                    scope.id,
                    scope.id,
                    (member,),
                    allow_escapes=True,
                )
                if not self.analysis_complete:
                    self._binding_nested_member_effect_cache[cache_key] = None
                    return True
                if proof_lost or states[member] != Truth4.TRUE:
                    affected_scopes.add(scope.id)
            cached = frozenset(affected_scopes)
            self._binding_nested_member_effect_cache[cache_key] = cached
        if cached is None or not self.analysis_complete:
            return True
        return any(scope_id != use_scope_id for scope_id in cached)

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
        self.routes = (
            tuple(self._bounded_unique_routes(self._collect_routes()))
            if self.limits.analyze_routes
            else ()
        )

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
                self._child_scope_ids[owner_id].append(scope_id)
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
                elif name_node is not None:
                    # Destructured declarations still introduce lexical names.
                    # Their individual values are deliberately left unresolved,
                    # but they must shadow globals used by security proofs.
                    for pattern_name in self._pattern_names(name_node):
                        self._record_binding(
                            _Binding(
                                SymbolId(
                                    current_owner,
                                    pattern_name,
                                    node.start_byte,
                                ),
                                None,
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
                if node.type in {
                    "identifier",
                    "shorthand_property_identifier",
                    "shorthand_property_identifier_pattern",
                }:
                    name = _identifier_text(self.source, node)
                    if name:
                        self._identifier_scope_ids_by_name[name].add(scope.id)
                        self._identifier_nodes_by_name_scope[(name, scope.id)].append(
                            node
                        )
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
        names: list[str] = []
        stack: list[tuple[Any, int]] = [(node, 0)] if node is not None else []
        visited = 0
        while stack:
            current, depth = stack.pop()
            visited += 1
            if (
                depth > self.limits.max_expr_depth * 4
                or visited > self.limits.max_nodes
            ):
                self._mark_incomplete("binding pattern depth exceeded")
                return []
            if current.type in {
                "identifier",
                "shorthand_property_identifier_pattern",
            }:
                name = _identifier_text(self.source, current)
                if name:
                    names.append(name)
                continue
            if current.type == "pair_pattern":
                child = current.child_by_field_name("value")
                if child is not None:
                    stack.append((child, depth + 1))
                continue
            if current.type in {
                "assignment_pattern",
                "object_assignment_pattern",
                "rest_pattern",
            }:
                child = current.child_by_field_name("left") or next(
                    iter(current.named_children), None
                )
                if child is not None:
                    stack.append((child, depth + 1))
                continue
            stack.extend(
                (child, depth + 1) for child in reversed(current.named_children)
            )
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
        current = self.unwrap(node)
        trail: list[tuple[Any, str | None]] = []
        for _ in range(self.limits.max_expr_depth * 4 + 1):
            if not self._consume_work():
                for seen_node, _ in trail:
                    self._expression_path_cache[_node_key(seen_node)] = ()
                return ()
            if current is None:
                for seen_node, _ in trail:
                    self._expression_path_cache[_node_key(seen_node)] = ()
                return ()
            cached = self._expression_path_cache.get(_node_key(current))
            if cached is not None:
                path = cached
                break
            if current.type in {"identifier", "property_identifier"}:
                name = _identifier_text(self.source, current)
                path = (name,) if name else ()
                self._expression_path_cache[_node_key(current)] = path
                break
            if current.type == "member_expression":
                prop = current.child_by_field_name("property")
                prop_name = _identifier_text(self.source, prop)
                if prop_name is None and prop is not None:
                    prop_name = self.node_text(prop)
                trail.append((current, prop_name))
                current = self.unwrap(current.child_by_field_name("object"))
                continue
            if current.type == "subscript_expression":
                index_value = _string_value(
                    self.source, current.child_by_field_name("index")
                )
                trail.append((current, index_value))
                current = self.unwrap(current.child_by_field_name("object"))
                continue
            if current.type in {"call_expression", "new_expression"}:
                target = current.child_by_field_name(
                    "function"
                ) or current.child_by_field_name("constructor")
                trail.append((current, None))
                current = self.unwrap(target)
                continue
            path = ()
            self._expression_path_cache[_node_key(current)] = path
            break
        else:
            self._mark_incomplete("expression path depth exceeded")
            for seen_node, _ in trail:
                self._expression_path_cache[_node_key(seen_node)] = ()
            return ()

        for seen_node, segment in reversed(trail):
            if path and segment:
                path = (*path, segment)
            self._expression_path_cache[_node_key(seen_node)] = path
        return path

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
                target = self._write_target_node(node)
                if target is None:
                    continue
                effect_byte = self._write_effect_byte(node)
                if not (lower < effect_byte < upper):
                    continue
                targets = self._assignment_targets(target)
                if not self.analysis_complete:
                    return False
                if any(path and path[0] == name for path, _ in targets):
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
        return not self._has_prior_path_mutation(
            self._global_paths(name),
            before_byte,
            scope_id,
        )

    @staticmethod
    def _global_paths(*path: str) -> frozenset[tuple[str, ...]]:
        suffix = tuple(path)
        return frozenset(
            {suffix} | {(global_name, *suffix) for global_name in _GLOBAL_OBJECT_NAMES}
        )

    @staticmethod
    def _path_affects_any(
        target: tuple[str, ...], protected: frozenset[tuple[str, ...]]
    ) -> bool:
        return bool(
            target
            and any(
                len(target) <= len(path) and path[: len(target)] == target
                for path in protected
            )
        )

    @classmethod
    def _target_affects_any(
        cls,
        target: tuple[str, ...],
        has_dynamic_member: bool,
        protected: frozenset[tuple[str, ...]],
    ) -> bool:
        if cls._path_affects_any(target, protected):
            return True
        # Once a computed key is unknown, later static segments cannot restore
        # a precise path. A matching root may still reach any protected member.
        return bool(
            has_dynamic_member
            and target
            and any(path and path[0] == target[0] for path in protected)
        )

    def _has_prior_path_mutation(
        self,
        protected: frozenset[tuple[str, ...]],
        before_byte: int,
        scope_id: int,
    ) -> bool:
        for candidate_scope_id in self._visible_scope_ids(scope_id):
            scope = self._scope_by_id[candidate_scope_id]
            cutoff = (
                before_byte
                if candidate_scope_id == scope_id
                else scope.body_span.end_byte
            )
            effect_byte = self._first_path_effect_byte(protected, candidate_scope_id)
            if not self.analysis_complete:
                return True
            if effect_byte is not None and effect_byte < cutoff:
                return True
        return False

    def _has_nested_global_path_mutation(
        self,
        protected: frozenset[tuple[str, ...]],
        use_scope_id: int,
    ) -> bool:
        affected_scopes = self._global_path_mutation_scopes_cache.get(protected)
        if (
            affected_scopes is None
            and protected not in self._global_path_mutation_scopes_cache
        ):
            mutable_scopes: set[int] = set()
            relevant_scope_ids: set[int] = set()
            for root_name in {path[0] for path in protected if path}:
                relevant_scope_ids.update(
                    self._identifier_scope_ids_by_name.get(root_name, ())
                )
            for candidate_scope_id in relevant_scope_ids:
                scope = self._scope_by_id[candidate_scope_id]
                visible_paths = frozenset(
                    path
                    for path in protected
                    if path and self._name_is_lexically_global(path[0], scope.id)
                )
                if not visible_paths:
                    continue
                effect_byte = self._first_path_effect_byte(visible_paths, scope.id)
                if not self.analysis_complete:
                    self._global_path_mutation_scopes_cache[protected] = None
                    return True
                if effect_byte is not None:
                    mutable_scopes.add(scope.id)
            affected_scopes = frozenset(mutable_scopes)
            self._global_path_mutation_scopes_cache[protected] = affected_scopes
        if affected_scopes is None or not self.analysis_complete:
            return True
        visible_use_scopes = set(self._visible_scope_ids(use_scope_id))
        return any(scope_id not in visible_use_scopes for scope_id in affected_scopes)

    def _name_is_lexically_global(self, name: str, scope_id: int) -> bool:
        if name in self.imports:
            return False
        visible_scope_ids = self._visible_scope_ids(scope_id)
        bindings = self._bindings.get(name, ())
        for candidate_scope_id in visible_scope_ids:
            scope = self._scope_by_id.get(candidate_scope_id)
            if scope is not None and any(
                parameter.name == name for parameter in scope.params
            ):
                return False
            if any(
                binding.symbol.scope_id == candidate_scope_id
                and self._binding_covers_entire_scope(binding, candidate_scope_id)
                for binding in bindings
            ):
                return False
        # Block scopes are collapsed into their owning function. A same-name
        # declaration in one nested block does not prove that a write elsewhere
        # in the function is local, so keep the global mutation possibility.
        return True

    def _first_path_effect_byte(
        self,
        protected: frozenset[tuple[str, ...]],
        scope_id: int,
    ) -> int | None:
        cache_key = (protected, scope_id)
        if cache_key in self._global_path_effect_cache:
            return self._global_path_effect_cache[cache_key]

        nodes = self._scope_nodes_cache.get(scope_id, ())
        if not self._consume_work(len(nodes)):
            return None
        first: int | None = None
        for node in nodes:
            effect_byte = self._path_effect_byte(node, protected, scope_id)
            if not self.analysis_complete:
                return None
            if effect_byte is not None and (first is None or effect_byte < first):
                first = effect_byte
        self._global_path_effect_cache[cache_key] = first
        return first

    def _path_effect_byte(
        self,
        node,
        protected: frozenset[tuple[str, ...]],
        scope_id: int,
    ) -> int | None:
        if node.type not in {
            "assignment_expression",
            "augmented_assignment_expression",
            "call_expression",
            "for_in_statement",
            "new_expression",
            "unary_expression",
            "update_expression",
            "variable_declarator",
        }:
            return None
        protected = frozenset(
            path
            for path in protected
            if path and self._name_is_global_at_byte(path[0], scope_id, node.start_byte)
        )
        if not protected:
            return None
        if node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
        }:
            targets = self._assignment_targets(node.child_by_field_name("left"))
            if not self.analysis_complete:
                return None
            if any(
                self._target_affects_any(path, dynamic, protected)
                for path, dynamic in targets
            ):
                return node.start_byte
            right = node.child_by_field_name("right")
            if self._expression_exposes_protected_object(right, protected):
                return node.end_byte
            return None

        if node.type in {"update_expression", "unary_expression", "for_in_statement"}:
            target = self._write_target_node(node)
            if target is None:
                return None
            targets = self._assignment_targets(target)
            if not self.analysis_complete:
                return None
            if any(
                self._target_affects_any(path, dynamic, protected)
                for path, dynamic in targets
            ):
                return self._write_effect_byte(node)
            return None

        if node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if self._expression_exposes_protected_object(value, protected):
                return node.end_byte
            return None

        if node.type == "call_expression":
            if self._call_mutates_paths(node, protected):
                return node.start_byte
            if any(
                self._expression_exposes_protected_object(argument, protected)
                for argument in self.call_arguments(node)
            ):
                return node.start_byte
            return None

        if node.type == "new_expression" and any(
            self._expression_exposes_protected_object(argument, protected)
            for argument in self._invocation_arguments(node)
        ):
            return node.start_byte
        return None

    def _name_is_global_at_byte(
        self,
        name: str,
        scope_id: int,
        effect_byte: int,
    ) -> bool:
        if name in self.imports:
            return False
        bindings = self._bindings.get(name, ())
        for candidate_scope_id in self._visible_scope_ids(scope_id):
            scope = self._scope_by_id.get(candidate_scope_id)
            if scope is not None and any(
                parameter.name == name for parameter in scope.params
            ):
                return False
            if any(
                binding.symbol.scope_id == candidate_scope_id
                and self._binding_visible_at_byte(
                    binding, candidate_scope_id, effect_byte
                )
                is True
                for binding in bindings
            ):
                return False
        return True

    def _write_target_node(self, node):
        if node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
            "for_in_statement",
        }:
            return node.child_by_field_name("left")
        if node.type == "update_expression" or (
            node.type == "unary_expression"
            and self.node_text(node).lstrip().startswith("delete ")
        ):
            return next(iter(node.named_children), None)
        return None

    @staticmethod
    def _write_effect_byte(node) -> int:
        if node.type == "for_in_statement":
            body = node.child_by_field_name("body")
            if body is not None:
                # The loop target is assigned after the iterable is evaluated and
                # strictly before the body begins. A braceless body can start at
                # the same byte as its first call, so use the preceding byte as an
                # ordering sentinel rather than the body's own start byte.
                return max(node.start_byte, body.start_byte - 1)
        return node.start_byte

    def _assignment_targets(self, node) -> tuple[tuple[tuple[str, ...], bool], ...]:
        """Return lvalue paths and whether a computed member is unknown."""
        if node is None:
            return ()
        targets: list[tuple[tuple[str, ...], bool]] = []
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.limits.max_expr_depth * 4 or not self._consume_work():
                self._mark_incomplete("assignment target inspection exceeded budget")
                return ()
            if current.type in {
                "identifier",
                "shorthand_property_identifier_pattern",
            }:
                name = _identifier_text(self.source, current)
                if name:
                    targets.append(((name,), False))
                continue
            if current.type in {"member_expression", "subscript_expression"}:
                path, has_dynamic_member = self._lvalue_path(current)
                if path:
                    targets.append((path, has_dynamic_member))
                continue
            if current.type == "pair_pattern":
                value = current.child_by_field_name("value")
                if value is not None:
                    stack.append((value, depth + 1))
                continue
            if current.type in {
                "assignment_pattern",
                "object_assignment_pattern",
                "rest_pattern",
            }:
                left = current.child_by_field_name("left") or next(
                    iter(current.named_children), None
                )
                if left is not None:
                    stack.append((left, depth + 1))
                continue
            stack.extend((child, depth + 1) for child in current.named_children)
        return tuple(dict.fromkeys(targets))

    def _lvalue_path(self, node) -> tuple[tuple[str, ...], bool]:
        current = self.unwrap(node)
        suffix: list[str] = []
        has_dynamic_member = False
        for _ in range(self.limits.max_expr_depth * 4 + 1):
            if not self._consume_work():
                return (), True
            if current is None:
                return (), has_dynamic_member
            if current.type in {"identifier", "property_identifier"}:
                name = _identifier_text(self.source, current)
                if not name:
                    return (), has_dynamic_member
                return (name, *reversed(suffix)), has_dynamic_member
            if current.type == "member_expression":
                prop = current.child_by_field_name("property")
                prop_name = _identifier_text(self.source, prop)
                if prop_name is None:
                    has_dynamic_member = True
                else:
                    suffix.append(prop_name)
                current = self.unwrap(current.child_by_field_name("object"))
                continue
            if current.type == "subscript_expression":
                index = current.child_by_field_name("index")
                index_value = _string_value(self.source, index)
                if index_value is None:
                    has_dynamic_member = True
                else:
                    suffix.append(index_value)
                current = self.unwrap(current.child_by_field_name("object"))
                continue
            return (), has_dynamic_member
        self._mark_incomplete("lvalue path depth exceeded")
        return (), True

    def _expression_exposes_protected_object(
        self,
        node,
        protected: frozenset[tuple[str, ...]],
    ) -> bool:
        """Return whether an expression stores or passes a mutable path prefix."""
        if node is None:
            return False
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.limits.max_expr_depth * 4 or not self._consume_work():
                self._mark_incomplete("protected object inspection exceeded budget")
                return True
            current = self.unwrap(current)
            if current is None:
                continue
            path = ()
            if current.type in {
                "identifier",
                "member_expression",
                "property_identifier",
                "subscript_expression",
            }:
                path, _ = self._lvalue_path(current)
                if not self.analysis_complete:
                    return True
            if path and any(
                len(path) < len(candidate) and candidate[: len(path)] == path
                for candidate in protected
            ):
                return True
            if current.type in {"call_expression", "new_expression"} | _FUNCTION_TYPES:
                # A call result is not an alias of its receiver. Its arguments
                # are inspected separately as call events.
                continue
            stack.extend((child, depth + 1) for child in current.named_children)
        return False

    def _resolved_builtin_mutator_callee(self, call) -> tuple[str, ...]:
        if call is None or call.type != "call_expression":
            return ()
        cache_key = _node_key(call)
        cached = self._resolved_builtin_mutator_cache.get(cache_key)
        if cached is not None:
            return cached

        direct = _builtin_mutator_callee(self.callee_path(call))
        if direct in _BUILTIN_MUTATOR_CALLEES:
            self._resolved_builtin_mutator_cache[cache_key] = direct
            return direct

        function = self.unwrap(call.child_by_field_name("function"))
        result: tuple[str, ...] = ()
        if function is not None and function.type == "identifier":
            scope_id = self.scope_for_node(call).id
            result = self._resolved_builtin_mutator_binding(
                self.node_text(function),
                call.start_byte,
                scope_id,
                frozenset(),
                0,
            )
        self._resolved_builtin_mutator_cache[cache_key] = result
        return result

    def _resolved_builtin_mutator_binding(
        self,
        name: str,
        before_byte: int,
        scope_id: int,
        seen: frozenset[SymbolId],
        depth: int,
    ) -> tuple[str, ...]:
        if depth > self.limits.max_expr_depth or not self._consume_work():
            return ()
        binding = self.resolve_unique_binding(name, before_byte, scope_id)
        if binding is None or binding.symbol in seen:
            return ()
        if not self._binding_is_stable_until(name, binding, before_byte, scope_id):
            return ()

        value = self.unwrap(binding.value_node)
        if value is not None:
            path = _builtin_mutator_callee(self._expression_path(value))
            if path in _BUILTIN_MUTATOR_CALLEES:
                return path
            if value.type == "identifier":
                return self._resolved_builtin_mutator_binding(
                    self.node_text(value),
                    binding.symbol.decl_byte,
                    binding.symbol.scope_id,
                    seen | {binding.symbol},
                    depth + 1,
                )

        path = _builtin_mutator_callee(self._destructured_binding_value_path(binding))
        return path if path in _BUILTIN_MUTATOR_CALLEES else ()

    def _destructured_binding_value_path(
        self,
        binding: _Binding,
    ) -> tuple[str, ...]:
        declaration = binding.declaration_node
        if declaration is None or declaration.type != "variable_declarator":
            return ()
        pattern = declaration.child_by_field_name("name")
        source_value = self.unwrap(declaration.child_by_field_name("value"))
        if pattern is None or pattern.type != "object_pattern" or source_value is None:
            return ()
        source_path = self._expression_path(source_value)
        if not source_path:
            return ()
        for child in pattern.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                property_name = self.node_text(child)
                if property_name == binding.symbol.name:
                    return (*source_path, property_name)
                continue
            if child.type != "pair_pattern":
                continue
            target = child.child_by_field_name("value")
            if binding.symbol.name not in self._pattern_names(target):
                continue
            property_name = self._static_property_name(child.child_by_field_name("key"))
            if property_name:
                return (*source_path, property_name)
        return ()

    def _call_mutates_paths(
        self,
        call,
        protected: frozenset[tuple[str, ...]],
    ) -> bool:
        callee = self._resolved_builtin_mutator_callee(call)
        if callee not in _BUILTIN_MUTATOR_CALLEES:
            return False
        arguments = self.call_arguments(call)
        if not arguments:
            return False
        target, has_dynamic_member = self._lvalue_path(arguments[0])
        if not target:
            return False
        if has_dynamic_member and any(
            path and path[0] == target[0] for path in protected
        ):
            return True
        if callee in _BULK_MUTATOR_CALLEES:
            return self._path_affects_any(target, protected)
        if not any(
            len(target) < len(path) and path[: len(target)] == target
            for path in protected
        ):
            return False
        property_name = (
            _string_value(self.source, arguments[1]) if len(arguments) >= 2 else None
        )
        if property_name is None:
            return True
        return self._path_affects_any((*target, property_name), protected)

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

    def _local_function_has_binding_member_effect(
        self,
        event: FlowEvent,
        captured_names: set[str],
        names: tuple[str, ...],
    ) -> bool:
        if event.callee is None or not event.callee.member_path:
            return False
        callee_root = event.callee.member_path[0]
        callee_binding = self.resolve_unique_binding(
            callee_root, event.span.start_byte, event.scope_id
        )
        if callee_binding is None or callee_binding.value_node is None:
            return False
        value = self.unwrap(callee_binding.value_node)
        if value is None or value.type not in _FUNCTION_TYPES:
            return False
        function_scope_id = self.scope_for_node(value).id
        function_scope = self._scope_by_id[function_scope_id]

        for captured_name in captured_names:
            captured_binding = self.resolve_unique_binding(
                captured_name, event.span.start_byte, event.scope_id
            )
            if captured_binding is not None:
                bindings_by_scope: dict[int, list[_Binding]] = defaultdict(list)
                for candidate in self._bindings.get(captured_name, ()):
                    bindings_by_scope[candidate.symbol.scope_id].append(candidate)
                relation = self._scope_binding_relation(
                    captured_binding,
                    function_scope_id,
                    bindings_by_scope,
                )
                if relation is False:
                    continue
            elif any(
                parameter.name == captured_name for parameter in function_scope.params
            ):
                continue

            for name in names:
                guard_key = (function_scope_id, captured_name, name)
                if guard_key in self._nested_member_call_guard:
                    return True
                self._nested_member_call_guard.add(guard_key)
                try:
                    states = {name: Truth4.TRUE}
                    proof_lost = self._apply_binding_effects(
                        states,
                        captured_name,
                        function_scope.body_span.start_byte - 1,
                        function_scope.body_span.end_byte + 1,
                        function_scope_id,
                        function_scope_id,
                        (name,),
                        allow_escapes=True,
                    )
                finally:
                    self._nested_member_call_guard.discard(guard_key)
                if proof_lost or states[name] != Truth4.TRUE:
                    return True
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
        *,
        allow_escapes: bool = False,
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
            phase_index = self._binding_phase_index(candidate_scope_id)
            if phase_index is None:
                return True
            starts, indexed_items = phase_index
            first = bisect_right(starts, lower)
            last = bisect_left(starts, upper)
            phases.extend(
                (phase, effect_byte, kind, item)
                for effect_byte, kind, item in indexed_items[first:last]
            )

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
                if value is None:
                    continue
                if declared_name is None:
                    # Mapping a tracked object through a destructuring pattern
                    # creates aliases whose exact value path is not modeled.
                    if self._expression_contains_alias(
                        value,
                        aliases | containers,
                        include_nested_functions=True,
                    ):
                        return True
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
                targets = self._assignment_targets(left)
                if not self.analysis_complete:
                    return True
                if not targets and self._expression_contains_alias(
                    left, aliases | containers
                ):
                    # A call-derived lvalue such as
                    # `Object.getPrototypeOf(value).method` has no static root,
                    # but can still mutate the tracked object's method surface.
                    return True
                if (
                    left is not None
                    and left.type in {"array_pattern", "object_pattern"}
                    and self._expression_contains_alias(
                        right,
                        aliases | containers,
                        include_nested_functions=True,
                    )
                ):
                    return True
                right_name = (
                    self.node_text(right)
                    if right is not None and right.type == "identifier"
                    else None
                )
                simple_alias_assignment = False
                for path, has_dynamic_member in targets:
                    if has_dynamic_member and path and path[0] in aliases | containers:
                        return True
                    if len(path) == 1:
                        target = path[0]
                        if target == object_name:
                            # Whole-binding reassignment versions the value. Until the
                            # flow heap models versions, it cannot retain literal facts.
                            return True
                        if target in aliases:
                            if right_name in aliases:
                                simple_alias_assignment = True
                                continue
                            aliases.discard(target)
                            continue
                        if target in containers:
                            containers.discard(target)
                        if right_name in aliases:
                            aliases.add(target)
                            simple_alias_assignment = True
                        elif right_name in containers:
                            containers.add(target)
                            simple_alias_assignment = True
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
                if (
                    not allow_escapes
                    and not simple_alias_assignment
                    and self._expression_contains_alias(right, aliases | containers)
                ):
                    return True
                continue

            if kind == "mutation":
                target = self._write_target_node(item)
                targets = self._assignment_targets(target)
                if not self.analysis_complete:
                    return True
                if not targets and self._expression_contains_alias(
                    target, aliases | containers
                ):
                    return True
                for path, has_dynamic_member in targets:
                    if has_dynamic_member and path and path[0] in aliases | containers:
                        return True
                    if len(path) == 1:
                        target_name = path[0]
                        if target_name == object_name:
                            return True
                        if target_name in aliases:
                            aliases.discard(target_name)
                        elif target_name in containers:
                            containers.discard(target_name)
                    elif len(path) >= 2 and path[0] in aliases:
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
            if (
                event.callee is not None
                and event.callee.member_path == ("Object", "freeze")
                and self.is_unshadowed_global_member(
                    "Object",
                    "freeze",
                    event.span.start_byte,
                    event.scope_id,
                )
            ):
                continue
            if allow_escapes:
                callee_path = self._resolved_builtin_mutator_callee(event._node)
                if callee_path in _BUILTIN_MUTATOR_CALLEES:
                    arguments = self._invocation_arguments(event)
                    target, _ = (
                        self._lvalue_path(arguments[0]) if arguments else ((), False)
                    )
                    if (
                        target
                        and target[0] in aliases | containers
                        or arguments
                        and self._expression_contains_alias(
                            arguments[0], aliases | containers
                        )
                    ):
                        return True
                if self._local_function_has_binding_member_effect(
                    event,
                    aliases | containers,
                    names,
                ):
                    return True
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
            for arg in self._invocation_arguments(event):
                if self._expression_contains_alias(arg, aliases | containers):
                    return True
            if self._expression_contains_alias(
                event._node,
                aliases | containers,
                include_nested_functions=True,
            ):
                return True
        return False

    def _binding_phase_index(
        self, scope_id: int
    ) -> tuple[tuple[int, ...], tuple[tuple[int, str, Any], ...]] | None:
        """Index binding-relevant effects once for byte-bounded proof queries."""
        if scope_id in self._binding_phase_index_cache:
            return self._binding_phase_index_cache[scope_id]

        scope = self._scope_by_id.get(scope_id)
        if scope is None or not self._consume_work(len(scope.events)):
            self._binding_phase_index_cache[scope_id] = None
            return None

        items: list[tuple[int, str, Any]] = []
        for event in scope.events:
            if event.kind == EventKind.BIND:
                items.append((event.span.start_byte, "declaration", event._node))
            elif event.kind == EventKind.ASSIGN:
                items.append((event.span.start_byte, "assignment", event._node))
            elif event.kind in {EventKind.CALL, EventKind.NEW}:
                items.append((event.span.start_byte, "call", event))
            elif event.kind == EventKind.UPDATE or (
                event.kind == EventKind.UNKNOWN_CONTROL
                and event.node_type == "for_in_statement"
            ):
                items.append(
                    (self._write_effect_byte(event._node), "mutation", event._node)
                )

        items.sort(key=lambda item: (item[0], item[1]))
        indexed_items = tuple(items)
        result = (tuple(item[0] for item in indexed_items), indexed_items)
        self._binding_phase_index_cache[scope_id] = result
        return result

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
    limits: FlowLimits | None = None,
) -> SecurityFlow:
    return SecurityFlow(
        root_node,
        source,
        file_path,
        lang,
        FlowLimits() if limits is None else limits,
    )
