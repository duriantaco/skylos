from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from skylos.constants import get_non_library_dir_kind
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.visitors.languages.typescript.security_flow import (
    FlowEvent,
    EventKind,
    RouteKind,
    RouteScope,
    SecurityFlow,
    Verdict,
    negative_guard_fallthrough,
    terminates,
)


AUTH_GUARD_PROOF = "route-local rejecting authentication guard before mutation"
WEBHOOK_GUARD_PROOF = "provider signature verification of request payload before body trust or side effect"

_TRUSTED_AUTH_IMPORTS = frozenset(
    {
        ("next-auth", "getServerSession"),
        ("next-auth/next", "getServerSession"),
        ("next-auth/jwt", "getToken"),
        ("@clerk/nextjs", "auth"),
        ("@clerk/nextjs", "currentUser"),
        ("@clerk/nextjs/server", "auth"),
        ("@clerk/nextjs/server", "currentUser"),
    }
)

_AUTH_CANDIDATE_NAMES = frozenset(
    {
        "auth",
        "currentUser",
        "getServerSession",
        "getToken",
    }
)

_MUTATION_CALLEES = frozenset(
    {
        "add",
        "append",
        "bulkCreate",
        "create",
        "delete",
        "deleteMany",
        "destroy",
        "execute",
        "insert",
        "insertMany",
        "patch",
        "publish",
        "query",
        "remove",
        "save",
        "send",
        "set",
        "update",
        "updateMany",
        "upsert",
        "write",
        "writeFile",
        "writeFileSync",
    }
)

_CLERK_AUTH_MODULES = frozenset({"@clerk/nextjs", "@clerk/nextjs/server"})
_TRUSTED_WEBHOOK_MODULES = frozenset({"stripe", "svix", "@octokit/webhooks"})
_PUBLIC_ENV_PREFIXES = (
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
    "PUBLIC_",
)
_SERVER_SECRET_ENV_TERMS = frozenset(
    {"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PRIVATE", "SIGNING", "HMAC"}
)

_WEBHOOK_PROVIDERS = (
    "stripe",
    "github",
    "clerk",
    "svix",
    "shopify",
    "supabase",
    "resend",
    "twilio",
    "slack",
    "discord",
    "linear",
    "vercel",
    "netlify",
    "paddle",
    "lemon_squeezy",
    "lemonsqueezy",
)

_RAW_BODY_CALLS = frozenset({"text", "arrayBuffer"})
_PARSED_BODY_CALLS = frozenset({"json", "formData"})
_CONTROL_DEPENDENT_ANCESTORS = frozenset(
    {
        "do_statement",
        "for_in_statement",
        "for_statement",
        "if_statement",
        "switch_case",
        "switch_statement",
        "ternary_expression",
        "while_statement",
    }
)

_ASSIGNMENT_TYPES = frozenset(
    {"assignment_expression", "augmented_assignment_expression"}
)

_HTTP_COOKIE_RESPONSE_NAMES = frozenset({"reply", "res", "response"})
_WEBHOOK_ROUTE_KIND_RE = re.compile(
    r"(?:^|[/_-])(?:events?|hooks?|webhooks?)(?:[/_.-]|$)",
    re.IGNORECASE,
)


def check_cookie_security(flow: SecurityFlow, findings: list[dict]) -> None:
    cookie_events = tuple(flow.calls_named("cookie"))
    events = tuple(
        event for event in cookie_events if _is_http_cookie_sink(flow, event)
    )
    for event in events:
        assessment = flow.cookie_assessment(event)
        if assessment.verdict == Verdict.PROTECTED:
            continue

        option_states = {
            "httpOnly": assessment.http_only.state.value,
            "secure": assessment.secure.state.value,
        }
        _append_cookie_finding(
            flow,
            findings,
            line=event.span.line,
            col=event.span.col,
            sink=_event_callee(event) or "cookie",
            option_states=option_states,
        )

    # A bounded analysis must fail closed. If the candidate was beyond the event
    # budget, preserve the finding instead of silently losing the rule entirely.
    if not flow.analysis_complete:
        observed_starts = {event.span.start_byte for event in cookie_events}
        for line, col in _unobserved_http_cookie_candidates(
            flow,
            observed_starts,
        ):
            _append_cookie_finding(
                flow,
                findings,
                line=line,
                col=col,
                sink="cookie",
                option_states={"httpOnly": "unknown", "secure": "unknown"},
            )


def _is_http_cookie_sink(flow: SecurityFlow, event: FlowEvent) -> bool:
    """Require response provenance before treating `.cookie()` as an HTTP sink."""
    if event.callee is None or len(event.callee.member_path) < 2:
        return False
    path = event.callee.member_path
    if path[-1] != "cookie":
        return False

    response_names = {
        symbol.name
        for route in flow.routes
        if route._region is not None
        and route._region.start_byte <= event.span.start_byte
        and event.span.end_byte <= route._region.end_byte
        for symbol in route.response_symbols
    }

    return _identifier_may_be_http_response(
        flow,
        path[0],
        before_byte=event.span.start_byte,
        scope_id=event.scope_id,
        response_names=response_names,
        seen=frozenset(),
        depth=0,
    )


def _identifier_may_be_http_response(
    flow: SecurityFlow,
    name: str,
    *,
    before_byte: int,
    scope_id: int,
    response_names: set[str],
    seen: frozenset[tuple[str, int, int]],
    depth: int,
) -> bool:
    """Resolve the value held by an identifier at a cookie call.

    Declarations establish the initial provenance and ordered assignments can
    replace it. Conditional writes are joined because either value can reach
    the later call.
    """
    if depth >= 16:
        return True
    key = (name, before_byte, scope_id)
    if key in seen:
        return True
    seen |= {key}

    binding = flow.resolve_unique_binding(name, before_byte, scope_id)
    if binding is None:
        state = name in response_names or (
            name.lower() in _HTTP_COOKIE_RESPONSE_NAMES
            and not flow.has_visible_binding(name, before_byte, scope_id)
        )
        binding_scope_id = scope_id
        after_byte = flow.scope(scope_id).body_span.start_byte - 1
    else:
        state = _expression_may_be_http_response(
            flow,
            binding.value_node,
            before_byte=binding.symbol.decl_byte,
            scope_id=binding.symbol.scope_id,
            response_names=response_names,
            seen=seen,
            depth=depth + 1,
        )
        binding_scope_id = binding.symbol.scope_id
        after_byte = binding.symbol.decl_byte

    phases: list[tuple[int, int, FlowEvent]] = []
    current_scope_id: int | None = scope_id
    phase = 1
    while current_scope_id is not None:
        scope = flow.scope(current_scope_id)
        if current_scope_id == scope_id:
            cutoff = before_byte
        else:
            # Ancestor/module initialization completes before a route callback
            # is invoked, including statements after its declaration.
            cutoff = scope.body_span.end_byte
        lower = after_byte if current_scope_id == binding_scope_id else -1
        for candidate in scope.events:
            if candidate.kind != EventKind.ASSIGN:
                continue
            if not (lower < candidate.span.start_byte < cutoff):
                continue
            left = flow.unwrap(candidate._node.child_by_field_name("left"))
            if (
                left is None
                or left.type != "identifier"
                or flow.node_text(left) != name
            ):
                continue
            phases.append((phase, candidate.span.start_byte, candidate))
        if current_scope_id == binding_scope_id:
            break
        current_scope_id = scope.parent_id
        phase -= 1

    for _, _, assignment in sorted(phases):
        right = assignment._node.child_by_field_name("right")
        assigned_state = _expression_may_be_http_response(
            flow,
            right,
            before_byte=assignment.span.start_byte,
            scope_id=assignment.scope_id,
            response_names=response_names,
            seen=seen,
            depth=depth + 1,
        )
        if _plain_unconditional_assignment(flow, assignment):
            state = assigned_state
        else:
            state = state or assigned_state
    return state


def _expression_may_be_http_response(
    flow: SecurityFlow,
    node,
    *,
    before_byte: int,
    scope_id: int,
    response_names: set[str],
    seen: frozenset[tuple[str, int, int]],
    depth: int,
) -> bool:
    node = flow.unwrap(node)
    if node is None or depth >= 16:
        return False
    if node.type == "identifier":
        return _identifier_may_be_http_response(
            flow,
            flow.node_text(node),
            before_byte=before_byte,
            scope_id=scope_id,
            response_names=response_names,
            seen=seen,
            depth=depth + 1,
        )
    if node.type in _ASSIGNMENT_TYPES:
        return _expression_may_be_http_response(
            flow,
            node.child_by_field_name("right"),
            before_byte=before_byte,
            scope_id=scope_id,
            response_names=response_names,
            seen=seen,
            depth=depth + 1,
        )
    if node.type == "sequence_expression":
        child = next(reversed(node.named_children), None)
        return _expression_may_be_http_response(
            flow,
            child,
            before_byte=before_byte,
            scope_id=scope_id,
            response_names=response_names,
            seen=seen,
            depth=depth + 1,
        )
    if node.type in {"ternary_expression", "binary_expression"}:
        return any(
            _expression_may_be_http_response(
                flow,
                child,
                before_byte=before_byte,
                scope_id=scope_id,
                response_names=response_names,
                seen=seen,
                depth=depth + 1,
            )
            for child in node.named_children
        )
    return False


def _plain_unconditional_assignment(
    flow: SecurityFlow,
    event: FlowEvent,
) -> bool:
    node = event._node
    if node.type != "assignment_expression":
        return False
    if not any(not child.is_named and child.type == "=" for child in node.children):
        return False
    scope_body = flow.scope(event.scope_id)._body
    current = node
    while current is not None and not _same_node(current, scope_body):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in _CONTROL_DEPENDENT_ANCESTORS or parent.type in {
            "binary_expression",
            "catch_clause",
            "finally_clause",
            "try_statement",
        }:
            return False
        current = parent
    return current is not None and _same_node(current, scope_body)


def _unobserved_http_cookie_candidates(
    flow: SecurityFlow,
    observed_starts: set[int],
) -> tuple[tuple[int, int], ...]:
    """Recover response cookie calls omitted by a bounded event stream."""
    source_text = _source_text(flow)
    route_regions: dict[str, list[tuple[int, int]]] = {}
    for route in flow.routes:
        if route._region is None:
            continue
        for symbol in route.response_symbols:
            route_regions.setdefault(symbol.name, []).append(
                (route._region.start_byte, route._region.end_byte)
            )
    names = set(_HTTP_COOKIE_RESPONSE_NAMES) | set(route_regions)
    if not names:
        return ()
    alternatives = "|".join(
        re.escape(name) for name in sorted(names, key=len, reverse=True)
    )
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_$])(?P<name>{alternatives})(?![A-Za-z0-9_$])\s*"
        r"(?:\.\s*cookie|\[\s*['\"]cookie['\"]\s*\])\s*\("
    )
    recovered: list[tuple[int, int]] = []
    for candidate in pattern.finditer(source_text):
        start_byte = len(source_text[: candidate.start()].encode("utf-8"))
        if start_byte in observed_starts:
            continue
        name = candidate.group("name")
        if name not in _HTTP_COOKIE_RESPONSE_NAMES and not any(
            start <= start_byte < end for start, end in route_regions.get(name, ())
        ):
            continue
        recovered.append(_line_col(source_text, candidate.start()))
    return tuple(recovered)


def _append_cookie_finding(
    flow: SecurityFlow,
    findings: list[dict],
    *,
    line: int,
    col: int,
    sink: str,
    option_states: dict[str, str],
) -> None:
    unsafe = [name for name, state in option_states.items() if state != "true"]
    guards_seen = [
        f"{name}={state}" for name, state in option_states.items() if state == "true"
    ]
    guards_missing = [
        f"{name}=true" for name, state in option_states.items() if state != "true"
    ]
    state_summary = ", ".join(
        f"{name}={option_states[name]}" for name in ("httpOnly", "secure")
    )
    findings.append(
        {
            "rule_id": "SKY-D252",
            "severity": "MEDIUM",
            "message": (
                f"Cookie security flags are not proven enabled ({state_summary}). "
                f"Set {' and '.join(unsafe)} to literal true."
            ),
            "file": flow.file_path,
            "line": line,
            "col": col,
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "cookie_security_options",
                    "source": "cookie options at the response write",
                    "sink": sink,
                    "path": ["cookie options", state_summary, "Set-Cookie response"],
                    "guards_seen": guards_seen,
                    "guards_missing": guards_missing,
                    "options": option_states,
                    "confidence_reason": (
                        "The browser security flags are false, absent, or cannot "
                        "be proven true at this cookie write."
                    ),
                    "test_hint": (
                        "Assert the emitted Set-Cookie header has Secure and "
                        "HttpOnly attributes."
                    ),
                    "fix_shape": (
                        "set httpOnly and secure to literal true after all spreads"
                    ),
                    "analysis_complete": flow.analysis_complete,
                    "analysis_diagnostics": list(flow.diagnostics),
                }
            },
        }
    )


def check_nextjs_missing_auth(flow: SecurityFlow, findings: list[dict]) -> None:
    source_text = _source_text(flow)
    normalized_path = flow.file_path.replace(os.sep, "/").lower()
    route_path = _next_route_relative_path(normalized_path)
    has_provider_import = any(
        identity.module in _TRUSTED_WEBHOOK_MODULES
        for identity in flow.import_identities()
    )
    has_crypto_import = any(
        identity.module in {"crypto", "node:crypto"}
        for identity in flow.import_identities()
    )
    is_provider_webhook = _webhook_candidate_text(
        route_path,
        has_trusted_provider_import=has_provider_import,
        has_trusted_crypto_import=has_crypto_import,
    )
    routes = [
        route
        for route in flow.routes
        if route.kind in {RouteKind.NEXT_APP, RouteKind.NEXT_PAGES}
        and bool(route.methods & {"POST", "PUT", "PATCH", "DELETE"})
    ]
    for route in routes:
        if is_provider_webhook and "POST" in route.methods:
            # A real inbound body makes this a machine-to-machine webhook owned
            # by D282. A webhook-shaped name/import alone must not erase D280.
            if _assess_webhook_route(flow, route)["body_seen"]:
                continue
        assessment = _assess_auth_route(flow, route)
        if assessment["protected"]:
            continue
        _append_auth_finding(
            flow,
            findings,
            line=route.registration.line,
            col=route.registration.col,
            methods=route.methods,
            assessment=assessment,
        )

    if (
        not flow.analysis_complete
        and not routes
        and not (
            is_provider_webhook
            and _looks_like_webhook_body_candidate(route_path, source_text)
        )
        and _looks_like_mutating_next_route(normalized_path, source_text)
    ):
        match = re.search(r"\b(?:POST|PUT|PATCH|DELETE)\b", source_text)
        line, col = _line_col(source_text, match.start() if match else 0)
        _append_auth_finding(
            flow,
            findings,
            line=line,
            col=col,
            methods=frozenset({match.group(0) if match else "POST"}),
            assessment={
                "sink": "mutating route completion",
                "guards_seen": [],
                "reason": (
                    "Analysis was incomplete, so route-local authentication could "
                    "not be proven before the mutating handler."
                ),
            },
        )


def _append_auth_finding(
    flow: SecurityFlow,
    findings: list[dict],
    *,
    line: int,
    col: int,
    methods: frozenset[str],
    assessment: dict[str, Any],
) -> None:
    method_label = ",".join(sorted(methods))
    findings.append(
        {
            "rule_id": "SKY-D280",
            "severity": "HIGH",
            "message": (
                "Next.js mutating API route has no route-local authentication "
                "guard before mutation. Add and enforce an authentication check."
            ),
            "file": flow.file_path,
            "line": line,
            "col": col,
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "authorization_guard",
                    "source": f"Next.js {method_label} route entry",
                    "sink": assessment["sink"],
                    "path": [
                        f"mutating route {method_label}",
                        assessment["sink"],
                    ],
                    "guards_seen": assessment["guards_seen"],
                    "guards_missing": [AUTH_GUARD_PROOF],
                    "confidence_reason": assessment["reason"],
                    "test_hint": (
                        "Call a trusted server-side authentication API, reject "
                        "missing identity with return or throw, then mutate."
                    ),
                    "fix_shape": (
                        "add a route-local authentication call and an early "
                        "rejecting guard before the mutation"
                    ),
                    "analysis_complete": flow.analysis_complete,
                    "analysis_diagnostics": list(flow.diagnostics),
                }
            },
        }
    )


def check_unverified_webhooks(flow: SecurityFlow, findings: list[dict]) -> None:
    if _is_test_path(flow.file_path):
        return
    source_text = _source_text(flow)
    normalized_path = flow.file_path.replace(os.sep, "/")
    route_hint = _next_route_relative_path(normalized_path)
    post_routes = [route for route in flow.routes if "POST" in route.methods]
    has_trusted_provider_import = any(
        identity.module in _TRUSTED_WEBHOOK_MODULES
        for identity in flow.import_identities()
    )
    has_trusted_crypto_import = any(
        identity.module in {"crypto", "node:crypto"}
        for identity in flow.import_identities()
    )
    webhook_routes = [
        route
        for route in post_routes
        if _route_is_webhook_candidate(
            route,
            route_hint,
            has_trusted_provider_import=has_trusted_provider_import,
            has_trusted_crypto_import=has_trusted_crypto_import,
        )
    ]
    omitted_webhook_routes = [
        route
        for route in flow.omitted_security_routes
        if _route_is_webhook_candidate(
            route,
            route_hint,
            has_trusted_provider_import=has_trusted_provider_import,
            has_trusted_crypto_import=has_trusted_crypto_import,
        )
    ]

    if not webhook_routes and not omitted_webhook_routes:
        candidate_text = route_hint.lower()
        is_provider_endpoint = _webhook_candidate_text(
            candidate_text,
            has_trusted_provider_import=has_trusted_provider_import,
            has_trusted_crypto_import=has_trusted_crypto_import,
        )
        source_registration = _source_webhook_registration(
            source_text,
            has_trusted_provider_import=has_trusted_provider_import,
            has_trusted_crypto_import=has_trusted_crypto_import,
        )
        if (
            not flow.analysis_complete
            and (is_provider_endpoint or source_registration is not None)
            and _looks_like_webhook_body_candidate(
                (
                    candidate_text
                    if source_registration is None
                    else source_registration.group("path")
                ),
                source_text,
            )
        ):
            match = source_registration or re.search(r"\b(?:post|POST)\b", source_text)
            line, col = _line_col(source_text, match.start() if match else 0)
            _append_webhook_finding(
                flow,
                findings,
                line=line,
                col=col,
                assessment={
                    "source": "inbound webhook request",
                    "sink": "webhook handler",
                    "guards_seen": [],
                    "reason": (
                        "Analysis was incomplete, so request-signature verification "
                        "could not be proven before webhook processing."
                    ),
                },
            )
        return

    protected_registrations: set[tuple[Any, ...]] = set()
    for route in webhook_routes:
        registration_key = _route_registration_key(route)
        assessment = _assess_webhook_route(flow, route)
        if not assessment["body_seen"]:
            if flow.analysis_complete:
                continue
            assessment = {
                "body_seen": True,
                "protected": False,
                "source": "inbound webhook request",
                "sink": "webhook handler",
                "guards_seen": [],
                "reason": (
                    "Analysis was incomplete, so request-body use and signature "
                    "verification could not be proven safe."
                ),
            }
        if assessment["protected"]:
            protected_registrations.add(registration_key)
            continue
        if (
            registration_key in protected_registrations
            and route.handler_index > 0
            and _route_can_inherit_webhook_verification(flow, route)
        ):
            continue
        _append_webhook_finding(
            flow,
            findings,
            line=route.registration.line,
            col=route.registration.col,
            assessment=assessment,
        )

    if omitted_webhook_routes:
        route = omitted_webhook_routes[0]
        _append_webhook_finding(
            flow,
            findings,
            line=route.registration.line,
            col=route.registration.col,
            assessment={
                "source": "inbound webhook request",
                "sink": "webhook handler omitted by route budget",
                "guards_seen": [],
                "reason": (
                    "The route budget was exceeded, so provider signature "
                    "verification could not be proven for this webhook route."
                ),
            },
        )


def _route_is_webhook_candidate(
    route: RouteScope,
    route_hint: str,
    *,
    has_trusted_provider_import: bool,
    has_trusted_crypto_import: bool,
) -> bool:
    # Express/Fastify/Hono ownership comes from this registration's path. A
    # provider import elsewhere in the module must not taint unrelated POSTs.
    candidate_text = (
        route_hint
        if route.kind in {RouteKind.NEXT_APP, RouteKind.NEXT_PAGES}
        else (route.path or "")
    ).lower()
    return _webhook_candidate_text(
        candidate_text,
        has_trusted_provider_import=has_trusted_provider_import,
        has_trusted_crypto_import=has_trusted_crypto_import,
    )


def _route_registration_key(route: RouteScope) -> tuple[Any, ...]:
    return (
        route.kind,
        route.methods,
        route.path,
        route.registration.start_byte,
        route.registration.end_byte,
    )


def _webhook_candidate_text(
    candidate_text: str,
    *,
    has_trusted_provider_import: bool,
    has_trusted_crypto_import: bool,
) -> bool:
    has_provider_route_hint = any(
        provider in candidate_text for provider in _WEBHOOK_PROVIDERS
    )
    has_webhook_route_kind = bool(_WEBHOOK_ROUTE_KIND_RE.search(candidate_text))
    # Raw source is intentionally excluded so comments cannot activate D282.
    # Provider-specific event/hook paths are covered because production
    # endpoints are not always literally named webhook.
    return (
        "webhook" in candidate_text
        and (has_provider_route_hint or has_trusted_provider_import)
    ) or (
        has_provider_route_hint
        and has_webhook_route_kind
        and (has_trusted_provider_import or has_trusted_crypto_import)
    )


def _append_webhook_finding(
    flow: SecurityFlow,
    findings: list[dict],
    *,
    line: int,
    col: int,
    assessment: dict[str, Any],
) -> None:
    findings.append(
        {
            "rule_id": "SKY-D282",
            "severity": "HIGH",
            "message": (
                "Webhook handler processes an inbound request without proving "
                "provider signature verification before body trust or side effects."
            ),
            "file": flow.file_path,
            "line": line,
            "col": col,
            "metadata": {
                "security_evidence": {
                    "evidence_kind": "webhook_signature_guard",
                    "source": assessment["source"],
                    "sink": assessment["sink"],
                    "path": [assessment["source"], assessment["sink"]],
                    "guards_seen": assessment["guards_seen"],
                    "guards_missing": [WEBHOOK_GUARD_PROOF],
                    "confidence_reason": assessment["reason"],
                    "test_hint": (
                        "Verify the exact raw request body and signature, reject "
                        "failure, and only then parse or dispatch the event."
                    ),
                    "fix_shape": (
                        "verify the exact raw request payload before parsing or "
                        "performing side effects"
                    ),
                    "analysis_complete": flow.analysis_complete,
                    "analysis_diagnostics": list(flow.diagnostics),
                }
            },
        }
    )


def _assess_auth_route(flow: SecurityFlow, route: RouteScope) -> dict[str, Any]:
    route_events = _auth_route_events(flow, route)
    calls = tuple(event for event in route_events if event.kind == EventKind.CALL)
    mutations = tuple(
        event for event in route_events if _is_route_side_effect(flow, event, route)
    )
    targets: tuple[FlowEvent | None, ...] = mutations or (None,)
    protected_guards: list[str] = []

    for mutation in targets:
        assessment = _assess_auth_boundary(flow, route, calls, mutation)
        if not assessment["protected"]:
            return assessment
        protected_guards.extend(assessment["guards_seen"])

    return {
        "protected": True,
        "sink": "all mutating route effects",
        "guards_seen": _dedupe(protected_guards),
        "reason": (
            "Every reachable route mutation is dominated by a trusted, enforced "
            "authentication proof."
        ),
    }


def _assess_auth_boundary(
    flow: SecurityFlow,
    route: RouteScope,
    calls: tuple[FlowEvent, ...],
    mutation: FlowEvent | None,
) -> dict[str, Any]:
    boundary = (
        mutation.span.start_byte if mutation is not None else route._region.end_byte
    )
    sink = (
        _event_callee(mutation) if mutation is not None else "mutating route completion"
    )
    guards_seen: list[str] = []

    for event in calls:
        # A call is only complete after every argument has evaluated. This
        # prevents auth.protect(db.write()) from authenticating a prior write.
        if event.span.end_byte > boundary:
            continue
        if not _is_trusted_auth_call(flow, event):
            if _is_auth_candidate(event):
                identity = event.callee.import_id if event.callee else None
                if identity is not None:
                    guards_seen.append(
                        f"untrusted auth-shaped call from {identity.module}"
                    )
            continue

        if _is_clerk_protect_call(event):
            if (
                flow.analysis_complete
                and flow.scope(route.scope_id).complete
                and _async_call_is_enforced(event, route)
                and _event_executes_unconditionally(flow, event, route)
            ):
                return {
                    "protected": True,
                    "sink": sink,
                    "guards_seen": ["trusted Clerk `auth.protect()` enforcement"],
                    "reason": (
                        "Clerk auth.protect() rejects unauthenticated requests before "
                        "the mutation."
                    ),
                }
            guards_seen.append("Clerk auth.protect() is control-dependent")
            continue

        if not _call_is_awaited(event, route):
            guards_seen.append("authentication promise is not awaited")
            continue

        subjects = _assigned_auth_subjects(event, flow)
        if not subjects:
            guards_seen.append("trusted authentication call result is not enforced")
            continue

        for subject in subjects:
            guard = _dominant_auth_guard(
                flow,
                route,
                boundary,
                subject,
                boundary_node=mutation._node if mutation is not None else None,
            )
            declaration = _enclosing_declarator(event._node)
            declaration_byte = (
                declaration.start_byte
                if declaration is not None
                else event.span.start_byte
            )
            if (
                flow.analysis_complete
                and flow.scope(route.scope_id).complete
                and guard is not None
                and guard.start_byte > event.span.end_byte
                and _event_executes_unconditionally(flow, event, route)
                and _binding_is_stable(
                    flow,
                    route,
                    subject.split(".", 1)[0],
                    declaration_byte,
                    guard.start_byte,
                )
            ):
                return {
                    "protected": True,
                    "sink": sink,
                    "guards_seen": [
                        f"trusted authentication identity `{subject}`",
                        f"rejecting guard at line {guard.start_point[0] + 1}",
                    ],
                    "reason": (
                        "A trusted server authentication result is rejected on the "
                        "unauthenticated branch before the mutation."
                    ),
                }

            late_or_weak = _find_subject_guard(flow, route, subject)
            if late_or_weak is not None:
                if late_or_weak.start_byte >= boundary:
                    guards_seen.append("authentication guard occurs after mutation")
                elif not terminates(late_or_weak.child_by_field_name("consequence")):
                    guards_seen.append("authentication check does not exit on failure")
                else:
                    guards_seen.append(
                        "authentication result is conditional, mixed, or reassigned"
                    )
            else:
                guards_seen.append("authentication result has no rejecting guard")

    return {
        "protected": False,
        "sink": sink,
        "guards_seen": _dedupe(guards_seen),
        "reason": (
            "No trusted authentication result is enforced by a route-local "
            "terminating guard before this mutation."
        ),
    }


def _auth_route_events(flow: SecurityFlow, route: RouteScope) -> tuple[FlowEvent, ...]:
    scope_events = flow.scope(route.scope_id).events
    events = [
        event
        for event in scope_events
        if route._region.start_byte <= event.span.start_byte
        and event.span.end_byte <= route._region.end_byte
    ]
    if route.kind == RouteKind.NEXT_PAGES:
        events.extend(
            event
            for event in scope_events
            if event.span.end_byte <= route.registration.start_byte
        )
    return tuple(
        sorted({event.id: event for event in events}.values(), key=_event_byte)
    )


def _is_route_side_effect(
    flow: SecurityFlow, event: FlowEvent, route: RouteScope
) -> bool:
    if event.kind == EventKind.UPDATE:
        return True
    if event.kind == EventKind.NEW:
        if event.callee is None or not event.callee.member_path:
            return True
        path = event.callee.member_path
        identity = event.callee.import_id
        if identity is not None and identity.module in _TRUSTED_WEBHOOK_MODULES:
            return False
        if len(path) == 1 and path[0] in {
            "Date",
            "Headers",
            "Map",
            "Response",
            "Set",
            "URL",
            "URLSearchParams",
        }:
            return not flow.is_unshadowed_global_name(
                path[0], event.span.start_byte, event.scope_id
            )
        return True
    if event.kind in {EventKind.ASSIGN}:
        left = event._node.child_by_field_name("left")
        left = flow.unwrap(left)
        if left is None or left.type != "identifier":
            return True
        binding = flow.resolve_unique_binding(
            flow.node_text(left), event.span.start_byte, event.scope_id
        )
        return binding is None or binding.symbol.scope_id != event.scope_id
    if event.kind != EventKind.CALL:
        return False
    if event.callee is None or not event.callee.member_path:
        return False
    path = event.callee.member_path
    leaf = path[-1]
    if _is_trusted_auth_call(flow, event):
        return False
    request_names = _request_names(flow, route, event.span.start_byte)
    response_names = {symbol.name for symbol in route.response_symbols}
    if path[0] in response_names:
        return False
    if path[0] in {"Response", "NextResponse", "console"}:
        return not flow.is_unshadowed_global_name(
            path[0], event.span.start_byte, event.scope_id
        )
    if path[0] in request_names and leaf in {
        "arrayBuffer",
        "formData",
        "json",
        "text",
    }:
        return False
    identity = event.callee.import_id
    if (
        identity is not None
        and identity.module == "next/headers"
        and leaf
        in {
            "cookies",
            "get",
            "headers",
        }
    ):
        return False
    if path in {
        ("Array", "isArray"),
        ("JSON", "parse"),
        ("JSON", "stringify"),
        ("Object", "entries"),
        ("Object", "keys"),
        ("Object", "values"),
        ("Buffer", "from"),
        ("Boolean",),
        ("Number",),
        ("String",),
    }:
        return not flow.is_unshadowed_global_name(
            path[0], event.span.start_byte, event.scope_id
        )
    if leaf in _MUTATION_CALLEES:
        return True
    return True


def _dominant_auth_guard(
    flow: SecurityFlow,
    route: RouteScope,
    boundary: int,
    subject: str,
    *,
    boundary_node=None,
):
    guard = flow.dominant_guard(
        route,
        boundary,
        lambda node: negative_guard_fallthrough(
            node,
            subject,
            flow.source,
            allow_false=(
                subject == "isAuthenticated" or subject.endswith(".isAuthenticated")
            ),
        ),
    )
    if guard is None and route.kind == RouteKind.NEXT_PAGES:
        guard = flow.dominant_guard(
            flow.scope(route.scope_id),
            route.registration.start_byte,
            lambda node: negative_guard_fallthrough(
                node,
                subject,
                flow.source,
                allow_false=(
                    subject == "isAuthenticated" or subject.endswith(".isAuthenticated")
                ),
            ),
        )
    if guard is None:
        guard = flow.dominant_guard(
            route,
            boundary,
            lambda node: _positive_auth_fallthrough(flow, node, subject),
        )
    if guard is None and route.kind == RouteKind.NEXT_PAGES:
        guard = flow.dominant_guard(
            flow.scope(route.scope_id),
            route.registration.start_byte,
            lambda node: _positive_auth_fallthrough(flow, node, subject),
        )
    if guard is None and boundary_node is not None:
        guard = _positive_auth_guard(flow, route, boundary_node, subject)
    return guard


def _positive_auth_fallthrough(
    flow: SecurityFlow,
    if_node,
    subject: str,
) -> bool:
    """Prove fallthrough is authenticated when the rejecting `else` exits."""
    if if_node is None or if_node.type != "if_statement":
        return False
    condition = flow.unwrap(if_node.child_by_field_name("condition"))
    compact = _compact(flow.node_text(condition))
    if compact not in {subject, f"{subject}===true", f"{subject}==true"}:
        return False
    alternative = if_node.child_by_field_name("alternative")
    if alternative is None:
        return False
    if alternative.type == "else_clause":
        alternative = next(iter(alternative.named_children), None)
    return terminates(alternative)


def _positive_auth_guard(
    flow: SecurityFlow, route: RouteScope, boundary_node, subject: str
):
    current = boundary_node
    while current is not None and not _same_node(current, route._region):
        parent = current.parent
        if parent is None:
            return None
        if parent.type == "if_statement":
            consequence = parent.child_by_field_name("consequence")
            condition = flow.unwrap(parent.child_by_field_name("condition"))
            compact = _compact(flow.node_text(condition))
            if (
                consequence is not None
                and _node_within(current, consequence)
                and compact in {subject, f"{subject}===true", f"{subject}==true"}
            ):
                return parent
        current = parent
    return None


def _assigned_auth_subjects(event: FlowEvent, flow: SecurityFlow) -> tuple[str, ...]:
    declarator = _enclosing_declarator(event._node)
    if declarator is None:
        return ()
    value = flow.unwrap(declarator.child_by_field_name("value"))
    if value is None or (
        value.start_byte != event._node.start_byte
        or value.end_byte != event._node.end_byte
    ):
        return ()

    name_node = declarator.child_by_field_name("name")
    if name_node is None:
        return ()
    clerk_auth_object = _is_clerk_auth_object_call(event)
    if name_node.type == "identifier":
        name = flow.node_text(name_node)
        if clerk_auth_object:
            return (f"{name}.isAuthenticated", f"{name}.userId")
        return (name,)
    if not clerk_auth_object or name_node.type != "object_pattern":
        return ()

    subjects: list[str] = []
    for child in name_node.named_children:
        if child.type in {
            "shorthand_property_identifier",
            "shorthand_property_identifier_pattern",
        }:
            name = flow.node_text(child)
            if name in {"isAuthenticated", "userId"}:
                subjects.append(name)
            continue
        key = child.child_by_field_name("key")
        value_node = child.child_by_field_name("value")
        if key is None or value_node is None:
            continue
        if flow.node_text(key) not in {"isAuthenticated", "userId"}:
            continue
        value_node = flow.unwrap(value_node)
        if value_node is not None and value_node.type == "identifier":
            subjects.append(flow.node_text(value_node))
    return tuple(subjects)


def _event_executes_unconditionally(
    flow: SecurityFlow, event: FlowEvent, route: RouteScope
) -> bool:
    region = route._region
    if not (
        region.start_byte <= event.span.start_byte
        and event.span.end_byte <= region.end_byte
    ):
        if route.kind != RouteKind.NEXT_PAGES:
            return False
        region = flow.scope(route.scope_id)._body

    current = event._node
    while current is not None and not _same_node(current, region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in _CONTROL_DEPENDENT_ANCESTORS or parent.type in {
            "binary_expression",
            "catch_clause",
            "finally_clause",
            "try_statement",
        }:
            return False
        if parent.type == "call_expression" and not _same_node(parent, event._node):
            return False
        current = parent
    return current is not None and _same_node(current, region)


def _binding_is_stable(
    flow: SecurityFlow,
    route: RouteScope,
    name: str,
    after_byte: int,
    before_byte: int,
) -> bool:
    scope = flow.scope(route.scope_id)
    for node in flow.iter_scope_nodes(scope):
        if not (after_byte < node.start_byte < before_byte):
            continue
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            if name_node is not None and _pattern_binds_name(flow, name_node, name):
                return False
        elif node.type in _ASSIGNMENT_TYPES:
            left = flow.unwrap(node.child_by_field_name("left"))
            if _expression_root_name(flow, left) == name:
                return False
        elif node.type == "update_expression":
            target = next(iter(node.named_children), None)
            if _expression_root_name(flow, target) == name:
                return False
    return True


def _pattern_binds_name(flow: SecurityFlow, node, name: str) -> bool:
    return any(
        candidate.type == "identifier" and flow.node_text(candidate) == name
        for candidate in flow.iter_nodes(node, skip_nested_functions=True)
    )


def _expression_root_name(flow: SecurityFlow, node) -> str | None:
    path = flow._expression_path(node)
    return path[0] if path else None


def _event_byte(event: FlowEvent) -> int:
    return event.span.start_byte


def _same_node(left, right) -> bool:
    return bool(
        left is not None
        and right is not None
        and left.type == right.type
        and left.start_byte == right.start_byte
        and left.end_byte == right.end_byte
    )


def _is_trusted_auth_call(flow: SecurityFlow, event: FlowEvent) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    identity = event.callee.import_id
    if identity is None:
        return False
    path = event.callee.member_path
    if identity.exported == "*":
        if len(path) != 2 or path[0] != identity.local:
            return False
        exported = path[-1]
    else:
        exported = identity.exported
        direct_call = path == (identity.local,)
        clerk_protect = bool(
            identity.module in _CLERK_AUTH_MODULES
            and exported == "auth"
            and path == (identity.local, "protect")
        )
        if not (direct_call or clerk_protect):
            return False
    if (identity.module, exported) in _TRUSTED_AUTH_IMPORTS:
        return True
    return _is_proven_local_authjs_adapter(flow.file_path, identity.module, exported)


_MAX_LOCAL_AUTH_MODULE_BYTES = 256 * 1024
_MAX_PROJECT_PARENT_STEPS = 32
_LOCAL_AUTH_SOURCE_SUFFIXES = (
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
)


def _is_proven_local_authjs_adapter(
    importer: str,
    module: str,
    exported: str,
) -> bool:
    if exported != "auth" or not (module.startswith("@/") or module.startswith(".")):
        return False
    project_root = _nearest_ts_project_root(importer)
    if project_root is None:
        return False
    target = _resolve_local_auth_module(project_root, importer, module)
    if target is None:
        return False
    return _authjs_adapter_exports_auth(project_root, target)


def _nearest_ts_project_root(importer: str) -> str | None:
    current = Path(os.path.realpath(os.path.dirname(importer)))
    for _ in range(_MAX_PROJECT_PARENT_STEPS):
        if (current / "tsconfig.json").is_file() or (
            current / "package.json"
        ).is_file():
            return os.path.realpath(current)
        if current.parent == current:
            break
        current = current.parent
    return None


def _resolve_local_auth_module(
    project_root: str,
    importer: str,
    module: str,
) -> str | None:
    try:
        if module.startswith("."):
            from skylos.visitors.languages.typescript.analysis import resolve_ts_module

            resolved = resolve_ts_module(module, importer)
        else:
            from skylos.visitors.languages.typescript.resolve import MonorepoResolver

            resolved = MonorepoResolver(project_root).resolve(module, importer)
    except (OSError, RuntimeError, ValueError):
        return None
    if not resolved:
        return None

    target = os.path.realpath(resolved)
    try:
        if os.path.commonpath((project_root, target)) != project_root:
            return None
    except ValueError:
        return None
    if not target.lower().endswith(_LOCAL_AUTH_SOURCE_SUFFIXES):
        return None
    return target if os.path.isfile(target) else None


def _authjs_adapter_exports_auth(
    project_root: str,
    target: str,
) -> bool:
    try:
        source_text = read_project_text_no_symlink(
            project_root,
            target,
            max_bytes=_MAX_LOCAL_AUTH_MODULE_BYTES,
            errors="surrogateescape",
            newline="",
        )
        if source_text is None:
            return False
        source = source_text.encode("utf-8", errors="surrogateescape")
    except (OSError, UnicodeError):
        return False
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(target, source)
    root = core.root_node
    if root is None or bool(getattr(root, "has_error", False)):
        return False
    next_auth_names = _authjs_default_import_names(root, source)
    if not next_auth_names:
        return False
    return any(
        _is_authjs_export_declaration(node, source, next_auth_names)
        for node in root.named_children
        if node.type == "export_statement"
    )


def _authjs_default_import_names(root, source: bytes) -> set[str]:
    imported_names: set[str] = set()
    for statement in root.named_children:
        if statement.type != "import_statement":
            continue
        source_node = statement.child_by_field_name("source")
        if _string_literal(source, source_node) != "next-auth":
            continue
        clause = next(
            (
                child
                for child in statement.named_children
                if child.type == "import_clause"
            ),
            None,
        )
        if clause is None:
            continue
        default_name = next(
            (child for child in clause.named_children if child.type == "identifier"),
            None,
        )
        if default_name is not None:
            imported_names.add(_node_text(source, default_name))
    return imported_names


def _is_authjs_export_declaration(
    export_statement,
    source: bytes,
    next_auth_names: set[str],
) -> bool:
    declaration = export_statement.child_by_field_name("declaration") or next(
        (
            child
            for child in export_statement.named_children
            if child.type == "lexical_declaration"
        ),
        None,
    )
    if declaration is None or not _node_text(source, declaration).lstrip().startswith(
        "const "
    ):
        return False
    for declarator in declaration.named_children:
        if declarator.type != "variable_declarator":
            continue
        pattern = declarator.child_by_field_name("name")
        value = declarator.child_by_field_name("value")
        if not _object_pattern_exports_auth(pattern, source):
            continue
        if value is None or value.type != "call_expression":
            continue
        function = value.child_by_field_name("function")
        if (
            function is not None
            and function.type == "identifier"
            and _node_text(source, function) in next_auth_names
        ):
            return True
    return False


def _object_pattern_exports_auth(pattern, source: bytes) -> bool:
    if pattern is None or pattern.type != "object_pattern":
        return False
    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            if _node_text(source, child) == "auth":
                return True
        elif child.type == "pair_pattern":
            value = child.child_by_field_name("value")
            if value is not None and _node_text(source, value) == "auth":
                return True
    return False


def _string_literal(source: bytes, node) -> str | None:
    if node is None or node.type != "string":
        return None
    text = _node_text(source, node)
    if len(text) < 2 or text[0] not in {'"', "'"} or text[-1] != text[0]:
        return None
    return text[1:-1]


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _is_clerk_auth_object_call(event: FlowEvent) -> bool:
    if event.callee is None or event.callee.import_id is None:
        return False
    identity = event.callee.import_id
    return (
        identity.module in _CLERK_AUTH_MODULES
        and identity.exported == "auth"
        and event.callee.member_path[-1:] == ("auth",)
    )


def _is_clerk_protect_call(event: FlowEvent) -> bool:
    if event.callee is None or event.callee.import_id is None:
        return False
    identity = event.callee.import_id
    return (
        identity.module in _CLERK_AUTH_MODULES
        and identity.exported == "auth"
        and event.callee.member_path == (identity.local, "protect")
    )


def _is_auth_candidate(event: FlowEvent) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    identity = event.callee.import_id
    return event.callee.member_path[-1] in _AUTH_CANDIDATE_NAMES or bool(
        identity and identity.exported in _AUTH_CANDIDATE_NAMES
    )


def _find_subject_guard(flow: SecurityFlow, route: RouteScope, subject: str):
    regions = [route]
    if route.kind == RouteKind.NEXT_PAGES:
        regions.append(flow.scope(route.scope_id))
    for region in regions:
        for statement in flow.direct_statements(region):
            if statement.type != "if_statement":
                continue
            condition = statement.child_by_field_name("condition")
            if condition is not None and subject in flow.node_text(condition):
                return statement
    return None


def _assess_webhook_route(flow: SecurityFlow, route: RouteScope) -> dict[str, Any]:
    calls = tuple(sorted(flow.calls_in(route), key=_event_byte))
    request_names = _request_names(flow, route, route._region.end_byte)
    raw_names: set[str] = set()
    raw_expressions: set[str] = set()
    raw_events: list[FlowEvent] = []
    parsed_events: list[FlowEvent] = []
    body_bytes: list[int] = []

    for request_name in request_names:
        if request_name.lower() == "rawbody":
            raw_names.add(request_name)
            raw_expressions.add(request_name)
            body_bytes.append(route.registration.start_byte)

    for symbol in route.request_raw_body_symbols:
        raw_names.add(symbol.name)
        raw_expressions.add(symbol.name)
        body_bytes.append(route.registration.start_byte)
    for symbol in route.request_body_symbols:
        body_bytes.append(route.registration.start_byte)
        if _route_body_member_is_raw(flow, route, "body"):
            raw_names.add(symbol.name)
            raw_expressions.add(symbol.name)

    for event in calls:
        path = event.callee.member_path if event.callee else ()
        pages_reader = _is_next_pages_body_reader(flow, event, route)
        if pages_reader:
            body_bytes.append(event.span.start_byte)
            if _next_pages_body_parser_disabled(flow):
                raw_events.append(event)
                raw_expressions.add(_compact(flow.node_text(event._node)))
                assigned = _assigned_identifier(event._node, flow)
                if assigned:
                    raw_names.add(assigned)
            continue
        if len(path) < 2 or path[0] not in request_names:
            continue
        leaf = path[-1]
        if leaf in _RAW_BODY_CALLS:
            raw_events.append(event)
            raw_expressions.add(_compact(flow.node_text(event._node)))
            body_bytes.append(event.span.start_byte)
            assigned = _assigned_identifier(event._node, flow)
            if assigned:
                raw_names.add(assigned)
        elif leaf in _PARSED_BODY_CALLS:
            parsed_events.append(event)
            body_bytes.append(event.span.start_byte)

    for node in flow.iter_scope_nodes(route):
        if node.type not in {"member_expression", "subscript_expression"}:
            continue
        path = flow._expression_path(node)
        if (
            len(path) != 2
            or path[0] not in request_names
            or path[1] not in {"body", "rawBody"}
        ):
            continue
        body_bytes.append(node.start_byte)
        if _route_body_member_is_raw(flow, route, path[1]):
            raw_expressions.add(_compact(flow.node_text(node)))
        assigned = _assigned_identifier(node, flow)
        if assigned and _route_body_member_is_raw(flow, route, path[1]):
            raw_names.add(assigned)

    body_seen = bool(body_bytes or raw_events or raw_expressions or parsed_events)
    if not body_seen:
        return {
            "body_seen": False,
            "protected": False,
            "source": "inbound webhook request",
            "sink": "webhook handler",
            "guards_seen": [],
            "reason": "No request body use was found in the route scope.",
        }

    boundary_event = _first_webhook_use(
        flow,
        route,
        calls,
        raw_names,
        parsed_events,
    )
    boundary = (
        boundary_event.span.start_byte
        if boundary_event is not None
        else route._region.end_byte
    )
    stable_until = (
        boundary_event.span.end_byte
        if boundary_event is not None
        else route._region.end_byte
    )
    guards_seen: list[str] = []

    for event in calls:
        if not _is_provider_verifier_candidate(event):
            continue
        args = flow.call_arguments(event)
        provider = _trusted_provider_kind(event)
        payload_expression = _provider_payload_expression(flow, event, provider, args)
        matches = payload_expression is not None and _expression_is_raw_request_body(
            flow,
            payload_expression,
            event,
            route,
            raw_names,
            raw_expressions,
            stable_until=stable_until,
        )
        trusted = provider is not None and _provider_arguments_are_valid(
            flow, event, route, provider, args
        )
        # The verifier only exists after its arguments finish evaluating.
        # A nested database/network call in an optional argument therefore
        # remains a pre-verification side effect.
        before_use = event.span.end_byte <= boundary
        rejects_failure = False
        verifier_leaf = (
            event.callee.member_path[-1]
            if event.callee is not None and event.callee.member_path
            else ""
        )
        if provider in {"stripe", "svix"} or verifier_leaf == "verifyAndReceive":
            rejects_failure = _throwing_verifier_rejects_failure(flow, event, route)
        elif provider == "octokit":
            rejects_failure = _boolean_verifier_is_enforced(
                flow, event, route, boundary
            )
        if verifier_leaf in {"constructEventAsync", "verifyAndReceive"}:
            rejects_failure = rejects_failure and _async_call_is_enforced(event, route)
        if (
            flow.analysis_complete
            and flow.scope(route.scope_id).complete
            and trusted
            and matches
            and before_use
            and rejects_failure
        ):
            verified_names = _assigned_verifier_subjects(event, flow)
            if _route_uses_unverified_request_data_after(
                flow,
                route,
                event.span.end_byte,
                raw_names,
                raw_expressions,
                verified_names,
            ):
                guards_seen.append(
                    "post-verification processing uses request data that was not verified"
                )
                continue
            return {
                "body_seen": True,
                "protected": True,
                "source": _raw_source_label(raw_names, raw_expressions),
                "sink": _event_callee(boundary_event) or "webhook event use",
                "guards_seen": [
                    f"provider verifier `{_event_callee(event)}`",
                    "verifier receives the route raw body before use",
                    "verification failure cannot reach webhook processing",
                ],
                "reason": (
                    "A trusted provider verifier receives the exact route raw body "
                    "and rejects failure before the body is processed."
                ),
            }
        if not trusted:
            guards_seen.append(
                f"untrusted verifier-shaped call `{_event_callee(event)}`"
            )
        elif not matches:
            guards_seen.append("provider verifier receives an unrelated payload")
        elif not before_use:
            guards_seen.append("provider verification occurs after body use")
        elif not rejects_failure:
            guards_seen.append("provider verification failure is not enforced")

    hmac_guard = _find_hmac_guard(
        flow,
        route,
        calls,
        raw_names,
        raw_expressions,
        boundary,
        stable_until,
    )
    if (
        flow.analysis_complete
        and flow.scope(route.scope_id).complete
        and hmac_guard is not None
    ):
        if _route_uses_unverified_request_data_after(
            flow,
            route,
            hmac_guard.end_byte,
            raw_names,
            raw_expressions,
            frozenset(),
        ):
            guards_seen.append(
                "post-verification processing uses request data that was not verified"
            )
        else:
            return {
                "body_seen": True,
                "protected": True,
                "source": _raw_source_label(raw_names, raw_expressions),
                "sink": _event_callee(boundary_event) or "webhook event use",
                "guards_seen": [
                    "HMAC of the exact request body",
                    f"timing-safe rejecting guard at line {hmac_guard.start_point[0] + 1}",
                ],
                "reason": (
                    "A request-signature value is compared to an HMAC of the same raw "
                    "body and mismatch exits before event processing."
                ),
            }

    if any(
        event.callee
        and event.callee.member_path
        and event.callee.member_path[-1] == "timingSafeEqual"
        for event in calls
    ):
        guards_seen.append(
            "timing-safe comparison does not match signature to HMAC of request body"
        )

    return {
        "body_seen": True,
        "protected": False,
        "source": _raw_source_label(raw_names, raw_expressions),
        "sink": _event_callee(boundary_event) or "webhook event use",
        "guards_seen": _dedupe(guards_seen),
        "reason": (
            "No route-local proof verifies the same raw request body before its "
            "first parsed use or side effect."
        ),
    }


def _provider_payload_expression(
    flow: SecurityFlow,
    event: FlowEvent,
    provider: str | None,
    args: tuple,
):
    if not args:
        return None
    if (
        provider == "octokit"
        and event.callee is not None
        and event.callee.member_path[-1:] == ("verifyAndReceive",)
    ):
        return _object_property_value(flow, args[0], "payload")
    return args[0]


def _assigned_verifier_subjects(event: FlowEvent, flow: SecurityFlow) -> frozenset[str]:
    """Return local names that receive the trusted verifier's output."""
    assigned = _assigned_identifier(event._node, flow)
    if assigned:
        return frozenset({assigned})

    current = event._node
    while current is not None:
        parent = current.parent
        if parent is None:
            break
        if parent.type == "assignment_expression":
            right = flow.unwrap(parent.child_by_field_name("right"))
            if _same_node(right, event._node):
                left = flow.unwrap(parent.child_by_field_name("left"))
                if left is not None and left.type == "identifier":
                    return frozenset({flow.node_text(left)})
            break
        if parent.type in {
            "expression_statement",
            "return_statement",
            "statement_block",
        }:
            break
        current = parent
    return frozenset()


def _route_uses_unverified_request_data_after(
    flow: SecurityFlow,
    route: RouteScope,
    after_byte: int,
    raw_names: set[str],
    raw_expressions: set[str],
    verified_names: frozenset[str],
) -> bool:
    """Reject a proof when later processing consumes unsigned request input."""
    for candidate in flow.scope(route.scope_id).events:
        if candidate.span.start_byte < after_byte:
            continue
        if not (
            route._region.start_byte <= candidate.span.start_byte
            and candidate.span.end_byte <= route._region.end_byte
        ):
            continue
        if route.kind == RouteKind.NEXT_PAGES and _is_rejecting_non_post_branch(
            flow, candidate, route
        ):
            continue

        expressions: tuple[Any, ...] = ()
        if candidate.kind in {EventKind.CALL, EventKind.NEW}:
            expressions = flow.call_arguments(candidate)
            if candidate.kind == EventKind.CALL:
                function = candidate._node.child_by_field_name("function")
                path = flow._expression_path(function)
                request_roots = _request_names(
                    flow, route, candidate.span.start_byte
                ) | {symbol.name for symbol in route.request_header_symbols}
                if (
                    path
                    and path[0] in request_roots
                    and not _is_webhook_setup_call(
                        flow,
                        candidate,
                        route=route,
                        request_names=request_roots,
                        response_names={
                            symbol.name for symbol in route.response_symbols
                        },
                    )
                ):
                    return True
        elif candidate.kind == EventKind.ASSIGN:
            right = candidate._node.child_by_field_name("right")
            expressions = (right,) if right is not None else ()
        elif candidate.kind == EventKind.UPDATE:
            target = next(iter(candidate._node.named_children), None)
            expressions = (target,) if target is not None else ()

        if any(
            _expression_is_unverified_request_data(
                flow,
                expression,
                candidate,
                route,
                raw_names,
                raw_expressions,
                verified_names,
                after_byte=after_byte,
                seen=frozenset(),
            )
            for expression in expressions
        ):
            return True
    return False


def _expression_is_unverified_request_data(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    raw_names: set[str],
    raw_expressions: set[str],
    verified_names: frozenset[str],
    *,
    after_byte: int,
    seen: frozenset[str],
    depth: int = 0,
) -> bool:
    if node is None or depth > 16:
        return node is not None
    node = flow.unwrap(node)
    if node is None:
        return True

    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return True
        if name in verified_names:
            return not _name_is_stable_in_scope(
                flow,
                name,
                event.scope_id,
                after_byte,
                event.span.start_byte,
            )
        if name in raw_names:
            return not _expression_is_raw_request_body(
                flow,
                node,
                event,
                route,
                raw_names,
                raw_expressions,
                stable_until=event.span.end_byte,
            )
        if name in {symbol.name for symbol in route.request_symbols}:
            return True
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        if binding is None or binding.value_node is None:
            return False
        return _expression_is_unverified_request_data(
            flow,
            binding.value_node,
            event,
            route,
            raw_names,
            raw_expressions,
            verified_names,
            after_byte=after_byte,
            seen=seen | {name},
            depth=depth + 1,
        )

    if _expression_is_raw_request_body(
        flow,
        node,
        event,
        route,
        raw_names,
        raw_expressions,
        stable_until=event.span.end_byte,
    ):
        return False

    path = flow._expression_path(node)
    request_roots = _request_names(flow, route, event.span.start_byte) | {
        symbol.name for symbol in route.request_header_symbols
    }
    if path and path[0] in request_roots:
        return True

    return any(
        _expression_is_unverified_request_data(
            flow,
            child,
            event,
            route,
            raw_names,
            raw_expressions,
            verified_names,
            after_byte=after_byte,
            seen=seen,
            depth=depth + 1,
        )
        for child in node.named_children
    )


def _first_webhook_use(
    flow: SecurityFlow,
    route: RouteScope,
    calls: tuple[FlowEvent, ...],
    raw_names: set[str],
    parsed_events: list[FlowEvent],
) -> FlowEvent | None:
    candidates = list(parsed_events)
    request_names = _request_names(flow, route, route._region.end_byte)
    response_names = {symbol.name for symbol in route.response_symbols}
    for event in flow.scope(route.scope_id).events:
        if not (
            route._region.start_byte <= event.span.start_byte
            and event.span.end_byte <= route._region.end_byte
        ):
            continue
        if route.kind == RouteKind.NEXT_PAGES and _is_rejecting_non_post_branch(
            flow, event, route
        ):
            continue
        if event.kind == EventKind.NEW and _is_webhook_setup_call(
            flow,
            event,
            route=route,
            request_names=request_names,
            response_names=response_names,
        ):
            continue
        if event.kind in {EventKind.NEW, EventKind.UPDATE}:
            candidates.append(event)
            continue
        if event.kind != EventKind.ASSIGN:
            continue
        left = event._node.child_by_field_name("left")
        path = flow._expression_path(left)
        if (
            len(path) > 1
            or _expression_root_name(flow, left) in raw_names
            or (
                path
                and path[0] in request_names
                and (len(path) == 1 or path[-1] in {"body", "rawBody", "headers"})
            )
        ):
            candidates.append(event)
    for event in calls:
        if route.kind == RouteKind.NEXT_PAGES and _is_rejecting_non_post_branch(
            flow, event, route
        ):
            continue
        if _is_webhook_setup_call(
            flow,
            event,
            route=route,
            request_names=request_names,
            response_names=response_names,
        ):
            continue
        candidates.append(event)
    return (
        min(candidates, key=lambda event: event.span.start_byte) if candidates else None
    )


def _is_webhook_setup_call(
    flow: SecurityFlow,
    event: FlowEvent,
    *,
    route: RouteScope,
    request_names: set[str],
    response_names: set[str],
) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    path = event.callee.member_path
    leaf = path[-1]
    if path[0] in request_names and leaf in {
        "arrayBuffer",
        "get",
        "text",
    }:
        return True
    if path[0] in response_names:
        return route.kind == RouteKind.NEXT_PAGES and _is_rejecting_non_post_branch(
            flow, event, route
        )
    if path[0] in {"Response", "NextResponse"}:
        return flow.is_unshadowed_global_name(
            path[0], event.span.start_byte, event.scope_id
        )
    if path == ("Buffer", "from"):
        return flow.is_unshadowed_global_name(
            "Buffer", event.span.start_byte, event.scope_id
        )
    identity = event.callee.import_id
    if (
        event.kind == EventKind.NEW
        and identity is not None
        and identity.module in _TRUSTED_WEBHOOK_MODULES
    ):
        return True
    if (
        identity is not None
        and identity.module == "next/headers"
        and identity.exported == "headers"
        and leaf in {"headers", "get"}
    ):
        return True
    if leaf == "get" and _header_call_receiver_is_trusted(
        flow, event._node, event, route
    ):
        return True
    if _trusted_provider_kind(event) is not None:
        return True
    if _is_trusted_crypto_call(
        flow, event, {"createHmac", "digest", "timingSafeEqual", "update"}
    ):
        return True
    if _is_next_pages_body_reader(flow, event, route):
        return True
    # Calls chained from a trusted createHmac retain that import identity on the
    # flow event. This exact-source fallback is only for nested tree-sitter calls.
    return leaf in {"digest", "update"} and _contains_trusted_create_hmac(flow, event)


def _is_rejecting_non_post_branch(
    flow: SecurityFlow, event: FlowEvent, route: RouteScope
) -> bool:
    current = event._node
    while current is not None and not _same_node(current, route._region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type == "if_statement":
            consequence = parent.child_by_field_name("consequence")
            condition = parent.child_by_field_name("condition")
            compact = _compact(flow.node_text(condition)).lower()
            rejects_non_post = bool(
                re.search(r"\.method(?:!=|!==)['\"]post['\"]", compact)
            )
            selects_other_method = bool(
                re.search(
                    r"\.method(?:==|===)['\"]"
                    r"(?:get|put|patch|delete|options|head)['\"]",
                    compact,
                )
            )
            if (
                _node_within(event._node, consequence)
                and (rejects_non_post or selects_other_method)
                and terminates(consequence)
            ):
                return True
        current = parent
    return False


def _route_body_member_is_raw(
    flow: SecurityFlow, route: RouteScope, property_name: str
) -> bool:
    if property_name == "rawBody":
        return True
    return bool(
        property_name == "body"
        and route.kind == RouteKind.EXPRESS
        and _route_has_express_raw_middleware(flow, route)
    )


def _route_can_inherit_webhook_verification(
    flow: SecurityFlow, route: RouteScope
) -> bool:
    """Carry a proof only across callbacks in the same ordered registration.

    The previous callback already proved that failure cannot call `next()`. The
    later callback must still consume only the same stable raw body; any header,
    query, reassignment, or other unsigned request input invalidates the carry.
    """
    if route.handler_count <= 1:
        return False
    raw_names: set[str] = set()
    raw_expressions: set[str] = set()
    request_names = _request_names(flow, route, route._region.end_byte)

    for request_name in request_names:
        if request_name.lower() == "rawbody":
            raw_names.add(request_name)
            raw_expressions.add(request_name)
    for symbol in route.request_raw_body_symbols:
        raw_names.add(symbol.name)
        raw_expressions.add(symbol.name)
    if _route_body_member_is_raw(flow, route, "body"):
        for symbol in route.request_body_symbols:
            raw_names.add(symbol.name)
            raw_expressions.add(symbol.name)

    for event in flow.calls_in(route):
        path = event.callee.member_path if event.callee else ()
        if len(path) < 2 or path[0] not in request_names:
            continue
        if path[-1] not in _RAW_BODY_CALLS:
            continue
        raw_expressions.add(_compact(flow.node_text(event._node)))
        assigned = _assigned_identifier(event._node, flow)
        if assigned:
            raw_names.add(assigned)

    for node in flow.iter_scope_nodes(route):
        if node.type not in {"member_expression", "subscript_expression"}:
            continue
        path = flow._expression_path(node)
        if (
            len(path) != 2
            or path[0] not in request_names
            or not _route_body_member_is_raw(flow, route, path[1])
        ):
            continue
        raw_expressions.add(_compact(flow.node_text(node)))
        assigned = _assigned_identifier(node, flow)
        if assigned:
            raw_names.add(assigned)

    if not (raw_names or raw_expressions):
        return False
    return not _route_uses_unverified_request_data_after(
        flow,
        route,
        route._region.start_byte - 1,
        raw_names,
        raw_expressions,
        frozenset(),
    )


def _route_has_express_raw_middleware(flow: SecurityFlow, route: RouteScope) -> bool:
    if route.kind != RouteKind.EXPRESS:
        return False
    for event in flow.calls:
        if not (
            route.registration.start_byte <= event.span.start_byte
            and event.span.end_byte <= route.registration.end_byte
        ):
            continue
        if _node_within(event._node, route._region):
            continue
        identity = event.callee.import_id if event.callee is not None else None
        if (
            identity is not None
            and identity.module in {"express", "@express/core"}
            and event.callee is not None
            and event.callee.member_path[-1:] == ("raw",)
        ):
            return True
    return False


def _is_provider_verifier_candidate(event: FlowEvent) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    leaf = event.callee.member_path[-1]
    return leaf in {
        "constructEvent",
        "constructEventAsync",
        "construct_event",
        "verify",
        "verifyAndReceive",
    }


def _trusted_provider_kind(event: FlowEvent) -> str | None:
    if event.callee is None:
        return None
    path = event.callee.member_path
    identity = event.callee.import_id
    leaf = path[-1] if path else ""

    if leaf in {"constructEvent", "constructEventAsync", "construct_event"}:
        return (
            "stripe" if identity is not None and identity.module == "stripe" else None
        )

    if leaf in {"verify", "verifyAndReceive"}:
        if (
            identity is not None
            and identity.module == "svix"
            and identity.exported == "Webhook"
        ):
            return "svix"
        if (
            identity is not None
            and identity.module == "@octokit/webhooks"
            and identity.exported == "Webhooks"
        ):
            return "octokit"
    return None


def _provider_arguments_are_valid(
    flow: SecurityFlow,
    event: FlowEvent,
    route: RouteScope,
    provider: str,
    args: tuple,
) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    if not _provider_receiver_is_stable(flow, event):
        return False
    leaf = event.callee.member_path[-1]
    if provider == "stripe" and leaf in {
        "constructEvent",
        "constructEventAsync",
        "construct_event",
    }:
        return (
            len(args) >= 3
            and _expression_is_signature(flow, args[1], event, route)
            and _expression_is_server_secret(flow, args[2], event, route)
        )
    if provider == "svix" and leaf == "verify":
        return (
            len(args) >= 2
            and (
                _expression_is_signature(flow, args[1], event, route)
                or _expression_is_request_headers(flow, args[1], event, route)
                or _expression_is_svix_headers_object(flow, args[1], event, route)
            )
            and _provider_instance_has_server_secret(flow, event, route, provider)
        )
    if provider == "octokit" and leaf == "verify":
        return (
            len(args) >= 2
            and _expression_is_signature(flow, args[1], event, route)
            and _provider_instance_has_server_secret(flow, event, route, provider)
        )
    if provider == "octokit" and leaf == "verifyAndReceive":
        options = args[0] if len(args) == 1 else None
        payload = _object_property_value(flow, options, "payload")
        signature = _object_property_value(flow, options, "signature")
        return bool(
            payload is not None
            and signature is not None
            and _expression_is_signature(flow, signature, event, route)
            and _provider_instance_has_server_secret(flow, event, route, provider)
        )
    return False


def _provider_receiver_is_stable(flow: SecurityFlow, event: FlowEvent) -> bool:
    if event.callee is None or event.callee.symbol is None:
        return False
    symbol = event.callee.symbol
    binding = flow.resolve_unique_binding(
        symbol.name, event.span.start_byte, event.scope_id
    )
    return bool(
        binding is not None
        and binding.symbol == symbol
        and _resolved_name_is_stable(
            flow, symbol.name, binding, event, event.span.start_byte
        )
    )


def _provider_instance_has_server_secret(
    flow: SecurityFlow,
    event: FlowEvent,
    route: RouteScope,
    provider: str,
) -> bool:
    if not _provider_receiver_is_stable(flow, event):
        return False
    assert event.callee is not None and event.callee.symbol is not None
    symbol = event.callee.symbol
    binding = flow.resolve_unique_binding(
        symbol.name, event.span.start_byte, event.scope_id
    )
    if binding is None or binding.symbol != symbol:
        return False
    value = flow.unwrap(binding.value_node)
    if value is None or value.type != "new_expression":
        return False
    args_node = value.child_by_field_name("arguments")
    args = tuple(args_node.named_children) if args_node is not None else ()
    if provider == "svix":
        return bool(args and _expression_is_server_secret(flow, args[0], event, route))
    if provider == "octokit" and args:
        secret = _object_property_value(flow, args[0], "secret")
        return bool(
            secret is not None
            and _expression_is_server_secret(flow, secret, event, route)
        )
    return False


def _object_property_value(flow: SecurityFlow, node, property_name: str):
    node = flow.unwrap(node)
    if node is None or node.type != "object":
        return None
    for child in node.named_children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        if flow.node_text(key).strip("'\"") == property_name:
            return child.child_by_field_name("value")
    return None


def _throwing_verifier_rejects_failure(
    flow: SecurityFlow, event: FlowEvent, route: RouteScope
) -> bool:
    current = event._node
    region = route._region
    while current is not None and not _same_node(current, region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type == "try_statement":
            body = parent.child_by_field_name("body")
            if body is None or not _node_within(current, body):
                return False
            handler = parent.child_by_field_name("handler")
            finalizer = parent.child_by_field_name("finalizer")
            if finalizer is not None:
                return False
            if handler is None:
                return False
            else:
                catch_body = handler.child_by_field_name("body")
                if catch_body is None or not terminates(catch_body):
                    return False
            current = parent
            continue
        if parent.type in _CONTROL_DEPENDENT_ANCESTORS or parent.type in {
            "binary_expression",
            "catch_clause",
            "finally_clause",
        }:
            return False
        if parent.type == "call_expression" and not _same_node(parent, event._node):
            return False
        current = parent
    return current is not None and _same_node(current, region)


def _call_is_awaited(event: FlowEvent, route: RouteScope) -> bool:
    current = event._node
    while current is not None and not _same_node(current, route._region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type == "await_expression":
            return True
        if parent.type in {
            "expression_statement",
            "return_statement",
            "variable_declarator",
        }:
            return False
        current = parent
    return False


def _async_call_is_enforced(event: FlowEvent, route: RouteScope) -> bool:
    if _same_node(event._node, route._region):
        # Expression-bodied route callbacks implicitly return their promise.
        return True
    current = event._node
    while current is not None and not _same_node(current, route._region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in {"await_expression", "return_statement"}:
            return True
        if parent.type == "expression_statement":
            return False
        if parent.type == "call_expression" and not _same_node(parent, event._node):
            return False
        current = parent
    return False


def _boolean_verifier_is_enforced(
    flow: SecurityFlow,
    event: FlowEvent,
    route: RouteScope,
    boundary: int,
) -> bool:
    inline_guard = _enclosing_if(event._node, route._region)
    if (
        inline_guard is not None
        and inline_guard.start_byte < boundary
        and _condition_is_exact_negative_call(
            flow, inline_guard.child_by_field_name("condition"), event._node
        )
        and terminates(inline_guard.child_by_field_name("consequence"))
        and _statement_is_unconditional(flow, inline_guard, route)
    ):
        return True

    subject = _assigned_identifier(event._node, flow)
    if not subject or not _event_executes_unconditionally(flow, event, route):
        return False
    guard = flow.dominant_guard(
        route,
        boundary,
        lambda node: negative_guard_fallthrough(
            node, subject, flow.source, allow_false=True
        ),
    )
    declaration = _enclosing_declarator(event._node)
    return bool(
        guard is not None
        and guard.start_byte > event.span.end_byte
        and _statement_is_unconditional(flow, guard, route)
        and declaration is not None
        and _name_is_stable_in_scope(
            flow,
            subject,
            event.scope_id,
            declaration.start_byte,
            guard.start_byte,
        )
    )


def _statement_is_unconditional(
    flow: SecurityFlow, statement, route: RouteScope
) -> bool:
    current = statement
    region = route._region
    while current is not None and not _same_node(current, region):
        parent = current.parent
        if parent is None:
            return False
        if parent.type in _CONTROL_DEPENDENT_ANCESTORS or parent.type in {
            "binary_expression",
            "catch_clause",
            "finally_clause",
            "try_statement",
        }:
            return False
        current = parent
    return current is not None and _same_node(current, region)


def _node_within(node, region) -> bool:
    return bool(
        node is not None
        and region is not None
        and region.start_byte <= node.start_byte
        and node.end_byte <= region.end_byte
    )


def _find_hmac_guard(
    flow: SecurityFlow,
    route: RouteScope,
    calls: tuple[FlowEvent, ...],
    raw_names: set[str],
    raw_expressions: set[str],
    boundary: int,
    stable_until: int,
):
    for event in calls:
        if (
            event.span.start_byte >= boundary
            or event.callee is None
            or not event.callee.member_path
            or event.callee.member_path[-1] != "timingSafeEqual"
            or not _is_trusted_crypto_call(flow, event, {"timingSafeEqual"})
        ):
            continue
        args = flow.call_arguments(event)
        if len(args) != 2:
            continue
        left_signature = _expression_is_signature(flow, args[0], event, route)
        right_signature = _expression_is_signature(flow, args[1], event, route)
        left_hmac = _expression_is_hmac_of_raw(
            flow,
            args[0],
            event,
            route,
            raw_names,
            raw_expressions,
            stable_until=stable_until,
        )
        right_hmac = _expression_is_hmac_of_raw(
            flow,
            args[1],
            event,
            route,
            raw_names,
            raw_expressions,
            stable_until=stable_until,
        )
        if not ((left_signature and right_hmac) or (right_signature and left_hmac)):
            continue
        guard = _enclosing_if(event._node, route._region)
        if guard is None or guard.start_byte >= boundary:
            continue
        consequence = guard.child_by_field_name("consequence")
        if not _condition_is_exact_negative_call(
            flow, guard.child_by_field_name("condition"), event._node
        ):
            continue
        if terminates(consequence) and _statement_is_unconditional(flow, guard, route):
            return guard
    return None


def _expression_is_signature(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None:
        return False
    if node.type in {"member_expression", "subscript_expression"}:
        path = flow._expression_path(node)
        header_names = {symbol.name for symbol in route.request_header_symbols}
        return bool(
            path
            and (
                path[0] in _request_names(flow, route, event.span.start_byte)
                or path[0] in header_names
            )
            and _request_root_is_stable(
                flow,
                route,
                path[0],
                event,
                event.span.start_byte,
            )
            and ("headers" in path or path[0] in header_names)
            and _has_signature_marker(flow.node_text(node))
        )
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return False
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        return bool(
            binding
            and _resolved_name_is_stable(
                flow, name, binding, event, event.span.start_byte
            )
            and _expression_is_signature(
                flow,
                binding.value_node,
                event,
                route,
                depth + 1,
                seen | {name},
            )
        )
    if node.type == "call_expression":
        path = flow.callee_path(node)
        args = flow.call_arguments(node)
        if (
            path == ("Buffer", "from")
            and args
            and flow.is_unshadowed_global_name(
                "Buffer", node.start_byte, event.scope_id
            )
        ):
            return _expression_is_signature(
                flow, args[0], event, route, depth + 1, seen
            )
        if (
            path[-1:] == ("get",)
            and args
            and _header_call_receiver_is_trusted(flow, node, event, route)
        ):
            return _has_signature_marker(flow.node_text(args[0]))
    if node.type == "binary_expression" and len(node.named_children) == 2:
        left, right = node.named_children
        operator = flow.source[left.end_byte : right.start_byte].decode(
            "utf-8", errors="replace"
        )
        return (
            operator.strip() in {"??", "||"}
            and _is_empty_literal(flow, right)
            and _expression_is_signature(flow, left, event, route, depth + 1, seen)
        )
    return False


def _expression_is_server_secret(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None or node.type == "string":
        return False
    env_key = _server_environment_key(flow, node)
    if env_key is not None:
        compact = _compact(flow.node_text(node))
        if compact.startswith("process.env") and not flow.is_unshadowed_global_name(
            "process", node.start_byte, event.scope_id
        ):
            return False
        upper_key = env_key.upper()
        if upper_key.startswith(_PUBLIC_ENV_PREFIXES):
            return False
        return bool(
            set(upper_key.split("_")) & _SERVER_SECRET_ENV_TERMS
            and _environment_key_is_stable(flow, env_key, event)
        )
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return False
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        return bool(
            binding
            and _resolved_name_is_stable(
                flow, name, binding, event, event.span.start_byte
            )
            and _expression_is_server_secret(
                flow,
                binding.value_node,
                event,
                route,
                depth + 1,
                seen | {name},
            )
        )
    return False


def _environment_key_is_stable(
    flow: SecurityFlow, env_key: str, event: FlowEvent
) -> bool:
    scope_id: int | None = event.scope_id
    while scope_id is not None:
        scope = flow.scope(scope_id)
        cutoff = (
            event.span.start_byte
            if scope_id == event.scope_id
            else scope.body_span.end_byte
        )
        for node in flow.iter_scope_nodes(scope):
            if node.start_byte >= cutoff:
                continue
            target = None
            if node.type in _ASSIGNMENT_TYPES:
                target = node.child_by_field_name("left")
            elif node.type == "update_expression":
                target = next(iter(node.named_children), None)
            elif node.type == "unary_expression" and flow.node_text(
                node
            ).lstrip().startswith("delete"):
                target = next(iter(node.named_children), None)
            if target is None:
                continue
            path = flow._expression_path(target)
            if path in {
                ("process",),
                ("process", "env"),
                ("process", "env", env_key),
            }:
                return False
        scope_id = scope.parent_id
    return True


def _expression_is_hmac_of_raw(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    raw_names: set[str],
    raw_expressions: set[str],
    *,
    stable_until: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return False
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        return bool(
            binding
            and _resolved_name_is_stable(flow, name, binding, event, stable_until)
            and _expression_is_hmac_of_raw(
                flow,
                binding.value_node,
                event,
                route,
                raw_names,
                raw_expressions,
                stable_until=stable_until,
                depth=depth + 1,
                seen=seen | {name},
            )
        )
    if node.type != "call_expression":
        return False
    path = flow.callee_path(node)
    args = flow.call_arguments(node)
    if (
        path == ("Buffer", "from")
        and args
        and flow.is_unshadowed_global_name("Buffer", node.start_byte, event.scope_id)
    ):
        return _expression_is_hmac_of_raw(
            flow,
            args[0],
            event,
            route,
            raw_names,
            raw_expressions,
            stable_until=stable_until,
            depth=depth + 1,
            seen=seen,
        )

    function = node.child_by_field_name("function")
    if function is None or function.type != "member_expression":
        return False
    if flow.node_text(function.child_by_field_name("property")) != "digest":
        return False
    update_call = flow.unwrap(function.child_by_field_name("object"))
    if update_call is None or update_call.type != "call_expression":
        return False
    update_function = update_call.child_by_field_name("function")
    if update_function is None or update_function.type != "member_expression":
        return False
    if flow.node_text(update_function.child_by_field_name("property")) != "update":
        return False
    update_args = flow.call_arguments(update_call)
    if len(update_args) != 1 or not _expression_is_raw_request_body(
        flow,
        update_args[0],
        event,
        route,
        raw_names,
        raw_expressions,
        stable_until=stable_until,
    ):
        return False
    create_call = flow.unwrap(update_function.child_by_field_name("object"))
    if create_call is None or create_call.type != "call_expression":
        return False
    create_event = _event_for_call(flow, create_call, event.scope_id)
    create_args = flow.call_arguments(create_call)
    return bool(
        create_event
        and _is_trusted_crypto_call(flow, create_event, {"createHmac"})
        and len(create_args) >= 2
        and _expression_is_server_secret(flow, create_args[1], create_event, route)
    )


def _is_trusted_crypto_call(
    flow: SecurityFlow, event: FlowEvent, names: set[str]
) -> bool:
    if event.callee is None or not event.callee.member_path:
        return False
    identity = event.callee.import_id
    if identity is None or identity.module not in {"crypto", "node:crypto"}:
        return False
    path = event.callee.member_path
    if identity.exported == "*":
        if len(path) != 2 or path[0] != identity.local:
            return False
        called_name = path[-1]
    elif identity.exported == "default":
        if len(path) != 2 or path[0] != identity.local:
            return False
        called_name = path[-1]
    else:
        if path != (identity.local,):
            return False
        called_name = identity.exported
    if called_name not in names:
        return False
    return _import_receiver_is_stable(flow, event)


def _import_receiver_is_stable(flow: SecurityFlow, event: FlowEvent) -> bool:
    """Prove a trusted imported function/module was not replaced or escaped."""
    if event.callee is None or event.callee.import_id is None:
        return False
    identity = event.callee.import_id
    root_name = identity.local

    scope_id: int | None = event.scope_id
    while scope_id is not None:
        scope = flow.scope(scope_id)
        cutoff = (
            event.span.start_byte
            if scope_id == event.scope_id
            else scope.body_span.end_byte
        )
        for node in flow.iter_scope_nodes(scope):
            if node.start_byte >= cutoff:
                continue
            if node.type in _ASSIGNMENT_TYPES:
                path = flow._expression_path(node.child_by_field_name("left"))
                if path and path[0] == root_name:
                    return False
            elif node.type == "update_expression":
                target = next(iter(node.named_children), None)
                path = flow._expression_path(target)
                if path and path[0] == root_name:
                    return False
            elif node.type == "unary_expression" and flow.node_text(
                node
            ).lstrip().startswith("delete"):
                target = next(iter(node.named_children), None)
                path = flow._expression_path(target)
                if path and path[0] == root_name:
                    return False
        for call in flow.scope(scope_id).events:
            if call.kind != EventKind.CALL or call.span.start_byte >= cutoff:
                continue
            if _same_node(call._node, event._node):
                continue
            if any(
                _expression_root_name(flow, argument) == root_name
                for argument in flow.call_arguments(call)
            ):
                return False
        scope_id = scope.parent_id
    return True


def _expression_is_raw_request_body(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    raw_names: set[str],
    raw_expressions: set[str],
    *,
    stable_until: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return False
        if name in raw_names and name in {
            symbol.name for symbol in route.request_symbols
        }:
            return _request_root_is_stable(flow, route, name, event, stable_until)
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        if binding is None:
            return False
        if name in raw_names and not _resolved_name_is_stable(
            flow, name, binding, event, stable_until
        ):
            return False
        return _resolved_name_is_stable(
            flow, name, binding, event, stable_until
        ) and _expression_is_raw_request_body(
            flow,
            binding.value_node,
            event,
            route,
            raw_names,
            raw_expressions,
            stable_until=stable_until,
            depth=depth + 1,
            seen=seen | {name},
        )
    if node.type == "call_expression":
        call_event = _event_for_call(flow, node, event.scope_id)
        if call_event is not None and _is_next_pages_body_reader(
            flow, call_event, route
        ):
            return _next_pages_body_parser_disabled(flow)
    path = flow._expression_path(node)
    request_names = _request_names(flow, route, stable_until)
    return bool(
        path
        and path[0] in request_names
        and _request_root_is_stable(
            flow,
            route,
            path[0],
            event,
            stable_until,
        )
        and (
            (len(path) >= 2 and _route_body_member_is_raw(flow, route, path[-1]))
            or (
                node.type == "call_expression"
                and path[-1:] in {(name,) for name in _RAW_BODY_CALLS}
            )
        )
    )


def _is_next_pages_body_reader(
    flow: SecurityFlow,
    event: FlowEvent,
    route: RouteScope,
) -> bool:
    if route.kind != RouteKind.NEXT_PAGES or event.callee is None:
        return False
    identity = event.callee.import_id
    if identity is None or not event.callee.member_path:
        return False
    leaf = event.callee.member_path[-1]
    trusted_reader = (identity.module == "micro" and leaf == "buffer") or (
        identity.module == "raw-body"
        and (identity.exported == "default" or leaf == "getRawBody")
    )
    if not trusted_reader:
        return False
    args = flow.call_arguments(event)
    if not args:
        return False
    request_names = _request_names(flow, route, event.span.start_byte)
    request_path = flow._expression_path(args[0])
    return bool(
        len(request_path) == 1
        and request_path[0] in request_names
        and _request_root_is_stable(
            flow,
            route,
            request_path[0],
            event,
            event.span.start_byte,
        )
    )


def _next_pages_body_parser_disabled(flow: SecurityFlow) -> bool:
    for child in flow.root_node.named_children:
        if child.type != "export_statement":
            continue
        declaration = next(
            (
                item
                for item in child.named_children
                if item.type == "lexical_declaration"
            ),
            None,
        )
        if declaration is None:
            continue
        for declarator in declaration.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            if flow.node_text(name) != "config":
                continue
            config = flow.unwrap(declarator.child_by_field_name("value"))
            api = _exact_object_property_value(flow, config, "api")
            body_parser = _exact_object_property_value(flow, api, "bodyParser")
            if (
                flow.unwrap(body_parser) is not None
                and flow.unwrap(body_parser).type == "false"
            ):
                return _name_is_stable_in_scope(
                    flow,
                    "config",
                    0,
                    declarator.start_byte,
                    flow.root_node.end_byte,
                )
    return False


def _exact_object_property_value(flow: SecurityFlow, node, property_name: str):
    node = flow.unwrap(node)
    if node is None or node.type != "object":
        return None
    matches = []
    for child in node.named_children:
        if child.type != "pair":
            return None
        key = child.child_by_field_name("key")
        if flow.node_text(key).strip("'\"") == property_name:
            matches.append(child.child_by_field_name("value"))
    return matches[0] if len(matches) == 1 else None


def _expression_is_request_headers(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in {symbol.name for symbol in route.request_header_symbols}:
            return _request_root_is_stable(
                flow, route, name, event, event.span.start_byte
            )
        if name in seen:
            return False
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        return bool(
            binding
            and _resolved_name_is_stable(
                flow, name, binding, event, event.span.start_byte
            )
            and _expression_is_request_headers(
                flow,
                binding.value_node,
                event,
                route,
                depth + 1,
                seen | {name},
            )
        )
    if node.type == "call_expression":
        call_event = _event_for_call(flow, node, event.scope_id)
        identity = (
            call_event.callee.import_id if call_event and call_event.callee else None
        )
        return bool(
            identity is not None
            and identity.module == "next/headers"
            and identity.exported == "headers"
            and call_event.callee is not None
            and call_event.callee.member_path[-1:] == ("headers",)
        )
    path = flow._expression_path(node)
    return bool(
        path
        and path[0] in _request_names(flow, route, event.span.start_byte)
        and _request_root_is_stable(
            flow,
            route,
            path[0],
            event,
            event.span.start_byte,
        )
        and path[-1:] == ("headers",)
    )


def _header_call_receiver_is_trusted(
    flow: SecurityFlow,
    call_node,
    event: FlowEvent,
    route: RouteScope,
) -> bool:
    call_node = flow.unwrap(call_node)
    if call_node is None or call_node.type != "call_expression":
        return False
    function = flow.unwrap(call_node.child_by_field_name("function"))
    if function is None or function.type not in {
        "member_expression",
        "subscript_expression",
    }:
        return False
    property_node = function.child_by_field_name("property")
    if flow.node_text(property_node).strip("'\"") != "get":
        return False
    receiver = function.child_by_field_name("object")
    return _expression_is_request_headers(flow, receiver, event, route)


def _expression_is_svix_headers_object(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if node is None or depth > 12:
        return False
    node = flow.unwrap(node)
    if node is None:
        return False
    if node.type == "identifier":
        name = flow.node_text(node)
        if name in seen:
            return False
        binding = flow.resolve_unique_binding(
            name, event.span.start_byte, event.scope_id
        )
        return bool(
            binding
            and _resolved_name_is_stable(
                flow, name, binding, event, event.span.start_byte
            )
            and _expression_is_svix_headers_object(
                flow,
                binding.value_node,
                event,
                route,
                depth + 1,
                seen | {name},
            )
        )
    if node.type != "object" or any(
        child.type != "pair" for child in node.named_children
    ):
        return False
    required = ("svix-id", "svix-timestamp", "svix-signature")
    for header_name in required:
        value = _object_property_value(flow, node, header_name)
        if value is None or not _expression_reads_named_header(
            flow, value, event, route, header_name
        ):
            return False
    return True


def _expression_reads_named_header(
    flow: SecurityFlow,
    node,
    event: FlowEvent,
    route: RouteScope,
    header_name: str,
) -> bool:
    node = flow.unwrap(node)
    if node is None or node.type != "call_expression":
        return False
    args = flow.call_arguments(node)
    return bool(
        len(args) == 1
        and flow.node_text(args[0]).strip("'\"").lower() == header_name.lower()
        and _header_call_receiver_is_trusted(flow, node, event, route)
    )


def _request_names(flow: SecurityFlow, route: RouteScope, before_byte: int) -> set[str]:
    """Return route request bindings plus direct, route-local aliases."""
    names = {symbol.name for symbol in route.request_symbols}
    if not names:
        return names
    for node in flow.iter_scope_nodes(route):
        if node.start_byte >= before_byte or node.type != "variable_declarator":
            continue
        declared = node.child_by_field_name("name")
        value = flow.unwrap(node.child_by_field_name("value"))
        if (
            declared is None
            or declared.type != "identifier"
            or value is None
            or value.type != "identifier"
            or flow.node_text(value) not in names
        ):
            continue
        names.add(flow.node_text(declared))
    return names


def _request_root_is_stable(
    flow: SecurityFlow,
    route: RouteScope,
    name: str,
    event: FlowEvent,
    stable_until: int,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if name in seen:
        return False
    if name in {symbol.name for symbol in route.request_symbols}:
        return _name_is_stable_in_scope(
            flow,
            name,
            event.scope_id,
            route._region.start_byte - 1,
            stable_until,
        )
    binding = flow.resolve_unique_binding(name, event.span.start_byte, event.scope_id)
    if binding is None or not _resolved_name_is_stable(
        flow, name, binding, event, stable_until
    ):
        return False
    value = flow.unwrap(binding.value_node)
    return bool(
        value is not None
        and value.type == "identifier"
        and _request_root_is_stable(
            flow,
            route,
            flow.node_text(value),
            event,
            stable_until,
            seen | {name},
        )
    )


def _name_is_stable_in_scope(
    flow: SecurityFlow,
    name: str,
    scope_id: int,
    after_byte: int,
    before_byte: int,
) -> bool:
    for node in flow.iter_scope_nodes(flow.scope(scope_id)):
        if not (after_byte < node.start_byte < before_byte):
            continue
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            if name_node is not None and _pattern_binds_name(flow, name_node, name):
                return False
        elif node.type in _ASSIGNMENT_TYPES:
            if _expression_root_name(flow, node.child_by_field_name("left")) == name:
                return False
        elif node.type == "update_expression":
            target = next(iter(node.named_children), None)
            if _expression_root_name(flow, target) == name:
                return False
    return True


def _resolved_name_is_stable(
    flow: SecurityFlow,
    name: str,
    binding,
    event: FlowEvent,
    before_byte: int,
) -> bool:
    binding_before_byte = before_byte
    if binding.symbol.scope_id != event.scope_id:
        # Closures run after their ancestor scope has initialized. A module or
        # parent-function assignment textually after the callback declaration
        # therefore still replaces the captured provider before requests run.
        binding_before_byte = max(
            binding_before_byte,
            flow.scope(binding.symbol.scope_id).body_span.end_byte,
        )
    if not _name_is_stable_in_scope(
        flow,
        name,
        binding.symbol.scope_id,
        binding.symbol.decl_byte,
        binding_before_byte,
    ):
        return False
    if binding.symbol.scope_id == event.scope_id:
        return True
    event_scope = flow.scope(event.scope_id)
    return _name_is_stable_in_scope(
        flow,
        name,
        event.scope_id,
        event_scope.body_span.start_byte - 1,
        before_byte,
    )


def _server_environment_key(flow: SecurityFlow, node) -> str | None:
    compact = _compact(flow.node_text(node))
    match = re.fullmatch(
        r"(?:process\.env|import\.meta\.env)"
        r"(?:\.([A-Za-z_$][A-Za-z0-9_$]*)|\[['\"]([^'\"]+)['\"]\])",
        compact,
    )
    if match is None:
        return None
    return match.group(1) or match.group(2)


def _has_signature_marker(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ("signature", "x-hub-signature", "svix-"))


def _is_empty_literal(flow: SecurityFlow, node) -> bool:
    return _compact(flow.node_text(node)) in {'""', "''", "``"}


def _condition_is_exact_negative_call(flow: SecurityFlow, condition, call_node) -> bool:
    condition = flow.unwrap(condition)
    if condition is None:
        return False
    if condition.type == "unary_expression" and condition.named_children:
        argument = flow.unwrap(condition.named_children[-1])
        operator = flow.source[condition.start_byte : argument.start_byte].decode(
            "utf-8", errors="replace"
        )
        return operator.strip() == "!" and _same_node(argument, call_node)
    if condition.type == "binary_expression" and len(condition.named_children) == 2:
        left, right = condition.named_children
        operator = flow.source[left.end_byte : right.start_byte].decode(
            "utf-8", errors="replace"
        )
        return (
            operator.strip() in {"==", "==="}
            and _same_node(flow.unwrap(left), call_node)
            and right.type == "false"
        )
    return False


def _event_for_call(flow: SecurityFlow, call_node, scope_id: int) -> FlowEvent | None:
    return next(
        (
            event
            for event in flow.scope(scope_id).events
            if event.kind == EventKind.CALL and _same_node(event._node, call_node)
        ),
        None,
    )


def _contains_trusted_create_hmac(flow: SecurityFlow, event: FlowEvent) -> bool:
    return any(
        candidate.span.start_byte >= event.span.start_byte
        and candidate.span.end_byte <= event.span.end_byte
        and _is_trusted_crypto_call(flow, candidate, {"createHmac"})
        for candidate in flow.scope(event.scope_id).events
        if candidate.kind == EventKind.CALL
    )


def _assigned_identifier(call_node, flow: SecurityFlow) -> str | None:
    declarator = _enclosing_declarator(call_node)
    if declarator is None:
        return None
    value = flow.unwrap(declarator.child_by_field_name("value"))
    expression = flow.unwrap(call_node)
    if not _same_node(value, expression):
        return None
    name_node = declarator.child_by_field_name("name")
    if name_node is None or name_node.type != "identifier":
        return None
    return flow.node_text(name_node)


def _enclosing_declarator(node):
    current = node
    while current is not None:
        if current.type == "variable_declarator":
            value = current.child_by_field_name("value")
            if value is not None and (
                value.start_byte <= node.start_byte <= node.end_byte <= value.end_byte
            ):
                return current
            return None
        if current.type in {
            "expression_statement",
            "return_statement",
            "statement_block",
        }:
            return None
        current = current.parent
    return None


def _enclosing_if(node, region):
    current = node
    while current is not None and not _same_node(current, region):
        if current.type == "if_statement":
            return current
        current = current.parent
    return None


def _raw_source_label(raw_names: set[str], raw_expressions: set[str]) -> str:
    if raw_names:
        return f"raw request body `{sorted(raw_names)[0]}`"
    if raw_expressions:
        return f"raw request body `{sorted(raw_expressions)[0]}`"
    return "parsed inbound webhook body"


def _event_callee(event: FlowEvent | None) -> str:
    if event is None or event.callee is None:
        return ""
    return ".".join(event.callee.member_path)


def _compact(text: str) -> str:
    return "".join(text.split())


def _source_text(flow: SecurityFlow) -> str:
    return flow.source.decode("utf-8", errors="replace")


def _line_col(source: str, offset: int) -> tuple[int, int]:
    prefix = source[:offset]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    return line, offset if last_newline < 0 else offset - last_newline - 1


def _looks_like_mutating_next_route(path: str, source: str) -> bool:
    app_route = "/app/" in path and path.endswith(
        ("route.ts", "route.tsx", "route.js", "route.jsx")
    )
    pages_route = "/pages/api/" in path and path.endswith(
        (".ts", ".tsx", ".js", ".jsx")
    )
    if not (app_route or pages_route):
        return False
    if app_route:
        return bool(
            re.search(
                r"\bexport\s+(?:(?:(?:async\s+)?function\s+|const\s+)"
                r"(?:POST|PUT|PATCH|DELETE)\b|\{[^}]{0,300}\b(?:as\s+)?"
                r"(?:POST|PUT|PATCH|DELETE)\b[^}]*\}(?:\s+from\b)?)",
                source,
            )
        )
    return bool(
        re.search(
            r"\.method\s*(?:===?|!==?)\s*['\"](?:POST|PUT|PATCH|DELETE)",
            source,
        )
        or re.search(
            r"\bexport\s+default\s+(?:[A-Za-z_$][A-Za-z0-9_$]*\s*;?"
            r"|[A-Za-z_$][A-Za-z0-9_$]*\s*\()",
            source,
        )
    )


def _next_route_relative_path(path: str) -> str:
    indexes = [
        index
        for marker in ("/app/", "/pages/api/")
        if (index := path.rfind(marker)) >= 0
    ]
    return path[max(indexes) :] if indexes else path.rsplit("/", 1)[-1]


def _looks_like_webhook_body_candidate(combined: str, source: str) -> bool:
    lower = combined.lower()
    return (
        "webhook" in lower
        and any(provider in lower for provider in _WEBHOOK_PROVIDERS)
        and bool(re.search(r"\b(?:post|POST)\b", source))
        and bool(
            re.search(
                r"\b(?:req|request)\s*(?:\.|\?\.)\s*"
                r"(?:body|rawBody|text\s*\(|arrayBuffer\s*\(|json\s*\()",
                source,
            )
        )
    )


_SOURCE_POST_PATH_RE = re.compile(
    r"(?:\.\s*post\s*\(\s*|\.\s*route\s*\(\s*)"
    r"(?P<quote>['\"`])(?P<path>[^'\"`\r\n]{1,512})(?P=quote)",
    re.IGNORECASE,
)


def _source_webhook_registration(
    source: str,
    *,
    has_trusted_provider_import: bool,
    has_trusted_crypto_import: bool,
):
    """Recover a late literal route when bounded AST collection stopped early.

    This fallback is only used after the structured analysis is incomplete. It
    deliberately prefers a conservative finding over silently dropping a
    provider webhook that occurs after the node/work budget.
    """
    for match in _SOURCE_POST_PATH_RE.finditer(source):
        if _webhook_candidate_text(
            match.group("path").lower(),
            has_trusted_provider_import=has_trusted_provider_import,
            has_trusted_crypto_import=has_trusted_crypto_import,
        ):
            return match
    return None


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _is_test_path(file_path: str) -> bool:
    normalized = str(file_path).replace(os.sep, "/").lower()
    base = os.path.basename(normalized)
    # `app/api/test/.../route.ts` and `pages/api/test.ts` are deployable URLs,
    # not test fixtures merely because a route segment is named "test".
    if (
        "/app/" in normalized
        and base in {"route.ts", "route.tsx", "route.js", "route.jsx"}
    ) or "/pages/api/" in normalized:
        return False
    return (
        get_non_library_dir_kind(file_path) == "test"
        or "/test/" in normalized
        or "/tests/" in normalized
        or ".spec." in base
        or ".test." in base
    )
