from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from .models import InvestigationLimits
from .source_bounds import visible_initial_source


REVIEWER_PACK_REGISTRY_VERSION = "reviewer-packs-v1"
REVIEWER_GUIDANCE_MAX_PACKS = 4
REVIEWER_GUIDANCE_MAX_BYTES = 6_000


@dataclass(frozen=True)
class ReviewerPack:
    pack_id: str
    version: str
    guidance: tuple[str, ...]
    source_markers: tuple[str, ...] = ()
    path_markers: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    candidate_kinds: tuple[str, ...] = ()

    def prompt_value(self) -> dict[str, Any]:
        return {
            "id": self.pack_id,
            "version": self.version,
            "guidance": list(self.guidance),
        }


REVIEWER_PACKS = (
    ReviewerPack(
        pack_id="candidate.dataflow",
        version="1.0.0",
        candidate_kinds=("threat_trace",),
        rule_ids=("sky-audit-trace",),
        guidance=(
            "Treat the static trace as a hypothesis; inspect the exact source, sink, aliases, wrappers, and intervening call edges.",
            "Establish attacker control and runtime reachability before reporting impact.",
            "Verify that any sanitizer or allowlist is active on every relevant branch and correct for the sink context.",
            "Inspect configuration and framework wrappers that may strengthen or invalidate the proposed trace.",
        ),
    ),
    ReviewerPack(
        pack_id="candidate.entrypoint_invariants",
        version="1.0.0",
        candidate_kinds=("entrypoint",),
        rule_ids=("sky-audit-entrypoint",),
        guidance=(
            "Identify the externally reachable actor, action, resource, and trust boundary before assessing the entrypoint.",
            "Trace the actual middleware, decorator, dependency, and policy order into the handler.",
            "Verify tenant, role, status, price, amount, quota, and ownership values are server-authoritative at mutation time.",
            "Check transaction, conditional-update, uniqueness, idempotency, and side-effect ordering protections where relevant.",
        ),
    ),
    ReviewerPack(
        pack_id="candidate.path_surface",
        version="1.0.0",
        candidate_kinds=("path_signal",),
        rule_ids=("sky-audit-path",),
        guidance=(
            "A security-sensitive filename is triage evidence only; locate its actual registration, callers, and reachable operations.",
            "Determine which data crosses the boundary and which identity or service principal controls it.",
            "Inspect concrete authorization, validation, cryptographic, transaction, and replay protections before deciding.",
        ),
    ),
    ReviewerPack(
        pack_id="rule.dangerous_data_sinks",
        version="1.0.0",
        rule_ids=(
            "sky-d211",
            "sky-d212",
            "sky-d215",
            "sky-d216",
            "sky-d217",
            "sky-d226",
            "sky-d227",
            "sky-d228",
            "sky-d230",
            "sky-d260",
            "sky-d324",
            "sky-d325",
        ),
        guidance=(
            "Trace the exact untrusted value through transformations to the reported sink; similar names and nearby calls are not proof.",
            "Inspect the sanitizer, parameterization, allowlist, encoding, path containment, or protocol validation in its precise sink context.",
            "Check alternate branches, aliases, wrappers, defaults, and error paths for a concrete bypass.",
            "Report only a reachable payload and impact supported by inspected source ranges.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.next_node_web",
        version="1.0.0",
        source_markers=(
            "next/server",
            "nextrequest",
            "nextresponse",
            "from 'next",
            'from "next',
            "require('express')",
            'require("express")',
            "from 'express'",
            'from "express"',
            "@nestjs/",
        ),
        path_markers=(
            "next.config.",
            "pages/api/",
            "app/api/",
            "middleware.ts",
            "middleware.js",
        ),
        guidance=(
            "Resolve route, server-action, and middleware matching and execution order; a middleware file or wrapper name alone does not prove coverage.",
            "Verify session identity and tenant ownership are bound server-side before lookup, cache access, or mutation.",
            "For webhooks, inspect signature verification over the required raw bytes and durable replay handling before side effects.",
            "Check that caches, loaders, and revalidation keys cannot cross user or tenant boundaries and that API endpoints reauthorize independently.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.python_web",
        version="1.0.0",
        source_markers=(
            "from django",
            "import django",
            "from flask",
            "import flask",
            "from fastapi",
            "import fastapi",
            "from starlette",
            "import starlette",
        ),
        path_markers=("manage.py", "wsgi.py", "asgi.py"),
        guidance=(
            "Inspect active decorators, dependencies, middleware order, queryset scoping, and object-level policies rather than assuming framework defaults.",
            "Bind tenant and ownership constraints in the ORM lookup or mutation, including bulk and serializer-driven updates.",
            "Verify transaction, row-lock, conditional-update, constraint, and post-commit side-effect behavior for state changes.",
            "Treat CSRF, host, session, and proxy protections as present only when the exact route and active configuration prove them.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.jvm_web",
        version="1.0.0",
        source_markers=(
            "org.springframework",
            "@restcontroller",
            "jakarta.ws.rs",
            "javax.ws.rs",
            "jakarta.servlet",
            "javax.servlet",
        ),
        guidance=(
            "Trace the active security filter chain, path matchers, method security, and controller mapping in execution order.",
            "Verify repository queries and entity mutations bind the authenticated principal and tenant, and inspect DTO-to-entity field exposure.",
            "Check real transactional boundaries, affected-row conditions, uniqueness, and optimistic or pessimistic locking.",
            "Distinguish servlet and reactive behavior and inspect the concrete exception and rollback paths before relying on framework semantics.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.laravel_php",
        version="1.0.0",
        source_markers=(
            "illuminate\\",
            "route::",
            "extends controller",
            "formrequest",
            "authorize(",
        ),
        path_markers=("routes/web.php", "routes/api.php"),
        guidance=(
            "Resolve route groups, middleware order, model binding, policies, gates, and FormRequest authorization for the concrete action.",
            "Verify tenant scoping and ownership in the query and inspect fillable, guarded, casts, and mass-assignment behavior.",
            "Check DB transactions, lockForUpdate, conditional writes, uniqueness, and durable idempotency around external side effects.",
            "Inspect signed-route or webhook verification before state change; route naming and middleware aliases are not proof.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.go_web",
        version="1.0.0",
        source_markers=(
            '"net/http"',
            "gin-gonic/gin",
            "labstack/echo",
            "gofiber/fiber",
            "httprouter",
        ),
        guidance=(
            "Trace router groups and middleware registration order to the exact handler.",
            "Verify request-context identity and tenant scope are server-derived and bound into database lookups and mutations.",
            "Check transaction boundaries, affected-row conditions, uniqueness, and concurrency handling rather than assuming a prior read remains valid.",
            "Inspect body limits, URL and file sinks, raw-byte signature verification, replay handling, and error paths where relevant.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.rust_web",
        version="1.0.0",
        source_markers=("actix_web", "axum::", "rocket::", "warp::"),
        guidance=(
            "Resolve router nesting, layers, guards, and extractor order for the concrete endpoint.",
            "Trace authenticated claims or request extensions into resource and tenant-scoped persistence operations.",
            "Inspect shared-state synchronization, transaction boundaries, conditional writes, and error propagation around side effects.",
            "Typed extractors and wrapper types reduce classes of error but are not proof of authorization, validation, or invariant enforcement.",
        ),
    ),
    ReviewerPack(
        pack_id="framework.dart_shelf",
        version="1.0.0",
        source_markers=(
            "package:shelf/",
            "package:shelf_router/",
            "shelf_io",
            "pipeline().addmiddleware",
        ),
        guidance=(
            "Resolve Pipeline middleware and Router mount order for the exact handler.",
            "Verify identity in request.context is created by trusted middleware and bound to tenant-scoped resource operations.",
            "Inspect awaited persistence, transaction, idempotency, and error ordering before externally visible side effects.",
            "Check body limits and exact raw-byte signature and replay handling for untrusted requests and webhooks.",
        ),
    ),
)

REVIEWER_PACK_DEFINITION_HASH = hashlib.sha256(
    json.dumps(
        {
            "registry_version": REVIEWER_PACK_REGISTRY_VERSION,
            "max_packs": REVIEWER_GUIDANCE_MAX_PACKS,
            "max_bytes": REVIEWER_GUIDANCE_MAX_BYTES,
            "packs": [pack.__dict__ for pack in REVIEWER_PACKS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()


def select_trusted_reviewer_guidance(
    *,
    entry_file: str,
    source: str,
    candidates: Iterable[dict[str, Any]],
    catalog_paths: Iterable[str],
    max_source_chars: int = InvestigationLimits().max_initial_source_chars,
) -> dict[str, Any]:
    """Select built-in guidance without reflecting repository-controlled text."""

    source_text = visible_initial_source(source, max_source_chars).casefold()
    paths = tuple(
        sorted(
            {
                value.casefold()
                for raw_path in (entry_file, *catalog_paths)
                if (value := str(raw_path).strip())
            }
        )
    )
    rule_ids, candidate_kinds = _candidate_signals(candidates)
    ranked = _ranked_reviewer_packs(
        source=source_text,
        paths=paths,
        rule_ids=rule_ids,
        candidate_kinds=candidate_kinds,
    )
    return _bounded_guidance_payload(ranked)


def _candidate_signals(
    candidates: Iterable[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    rule_ids: set[str] = set()
    candidate_kinds: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rule_id = str(candidate.get("rule_id") or "").strip().casefold()
        kind = str(candidate.get("kind") or "").strip().casefold()
        if rule_id:
            rule_ids.add(rule_id)
        if kind:
            candidate_kinds.add(kind)
    return rule_ids, candidate_kinds


def _ranked_reviewer_packs(
    *,
    source: str,
    paths: tuple[str, ...],
    rule_ids: set[str],
    candidate_kinds: set[str],
) -> list[tuple[int, str, ReviewerPack]]:
    ranked: list[tuple[int, str, ReviewerPack]] = []
    for pack in REVIEWER_PACKS:
        score = _match_score(
            pack,
            source=source,
            paths=paths,
            rule_ids=rule_ids,
            candidate_kinds=candidate_kinds,
        )
        if score:
            ranked.append((-score, pack.pack_id, pack))
    ranked.sort()
    return ranked


def _bounded_guidance_payload(
    ranked: Iterable[tuple[int, str, ReviewerPack]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "registry_version": REVIEWER_PACK_REGISTRY_VERSION,
        "packs": [],
        "selection_truncated": False,
        "limits": {
            "max_packs": REVIEWER_GUIDANCE_MAX_PACKS,
            "max_bytes": REVIEWER_GUIDANCE_MAX_BYTES,
        },
    }
    selected = payload["packs"]
    for _score, _pack_id, pack in ranked:
        if len(selected) >= REVIEWER_GUIDANCE_MAX_PACKS:
            payload["selection_truncated"] = True
            break
        selected.append(pack.prompt_value())
        if _prompt_bytes(payload) > REVIEWER_GUIDANCE_MAX_BYTES:
            selected.pop()
            payload["selection_truncated"] = True
            break

    if _prompt_bytes(payload) > REVIEWER_GUIDANCE_MAX_BYTES:
        raise AssertionError("reviewer guidance envelope exceeds its byte budget")
    return payload


def reviewer_guidance_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    trusted_versions = {pack.pack_id: pack.version for pack in REVIEWER_PACKS}
    packs = payload.get("packs")
    selected = []
    if isinstance(packs, list):
        for pack in packs[:REVIEWER_GUIDANCE_MAX_PACKS]:
            if not isinstance(pack, dict):
                continue
            pack_id = str(pack.get("id") or "")
            version = str(pack.get("version") or "")
            if trusted_versions.get(pack_id) == version:
                selected.append({"id": pack_id, "version": version})
    return {
        "registry_version": REVIEWER_PACK_REGISTRY_VERSION,
        "definition_hash": REVIEWER_PACK_DEFINITION_HASH,
        "selected_packs": selected,
        "selection_truncated": bool(payload.get("selection_truncated", False)),
    }


def _match_score(
    pack: ReviewerPack,
    *,
    source: str,
    paths: tuple[str, ...],
    rule_ids: set[str],
    candidate_kinds: set[str],
) -> int:
    source_match = any(marker in source for marker in pack.source_markers)
    path_match = any(marker in path for marker in pack.path_markers for path in paths)
    rule_match = bool(rule_ids.intersection(pack.rule_ids))
    kind_match = bool(candidate_kinds.intersection(pack.candidate_kinds))
    return (
        (60 if source_match else 0)
        + (40 if path_match else 0)
        + (80 if rule_match else 0)
        + (70 if kind_match else 0)
    )


def _prompt_bytes(value: dict[str, Any]) -> int:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return len(encoded.encode("utf-8"))
