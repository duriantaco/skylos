"""Connect static process argument records to the rule-specific path tracer."""

from __future__ import annotations

import ast

from skylos.rules.danger.import_proof import provider_binding_is_stable

from .path_process import (
    python_argv_ambiguous_launches,
    python_argv_launches,
    python_argv_sources,
    python_process_context_launches,
)


def _launch_input_facts(tracer, launch, *, stdin=False):
    from .path_provenance import _Facts

    facts = _Facts()
    options = {
        None,
        "args",
        "argv",
        "path",
        "file",
        "env",
        "cwd",
        "executable",
        "shell",
    }
    if stdin:
        options.update({"stdin", "input"})
    for argument in launch.call.args:
        facts.add(tracer.trace(launch.unit, launch.scope, argument, None))
    for keyword in launch.call.keywords:
        if keyword.arg in options:
            facts.add(tracer.trace(launch.unit, launch.scope, keyword.value, None))
    return facts


def _uncertain_launch(tracer, launch, *, always=False, stdin=False):
    from .path_provenance import INCOMPLETE, UNKNOWN, UNTRUSTED, _extend, _Facts, _step

    parent = _launch_input_facts(tracer, launch, stdin=stdin)
    if parent.chains["operator"]:
        parent.add(operator_launch_gap(tracer, parent))
    uncertainty = _Facts()
    reason = (
        launch.uncertainty
        or "the launched command-line field is not mapped to one argv position"
    )
    step = _step(launch.unit, launch.call, reason)
    if (
        always
        or parent.chains[UNTRUSTED]
        or parent.chains[UNKNOWN]
        or parent.chains[INCOMPLETE]
    ):
        for kind in (UNTRUSTED, UNKNOWN, INCOMPLETE):
            target = INCOMPLETE if kind == INCOMPLETE else UNKNOWN
            for chain in parent.chains[kind]:
                uncertainty.chains[target].append(_extend(chain, step))
        if uncertainty.empty():
            uncertainty.add(_Facts.leaf(UNKNOWN, step))
    return uncertainty


def python_argv_facts(tracer, unit, scope, node, env):
    """Trace a fixed native ``sys.argv`` index in its launcher's own scope.

    Return None when this hook does not model the expression. A record is an
    additional possible edge, never evidence that every runtime launch is known.
    """
    from .path_provenance import UNKNOWN, UNTRUSTED, _Facts, _step

    if not isinstance(node, ast.Subscript):
        return None
    values = tracer.project.values(unit, scope, node.value)
    if not values or not all(
        value.kind == "ext" and value.name == "sys.argv" for value in values
    ):
        return None
    native_argv = provider_binding_is_stable(
        "sys.argv", unit.tree, unit.path, tracer.project.root
    )
    index = None
    if isinstance(node.slice, ast.Constant) and type(node.slice.value) is int:
        index = node.slice.value
    elif (
        isinstance(node.slice, ast.UnaryOp)
        and isinstance(node.slice.op, ast.USub)
        and isinstance(node.slice.operand, ast.Constant)
        and type(node.slice.operand.value) is int
    ):
        index = -node.slice.operand.value
    if index is None:
        return None
    active = getattr(tracer, "_python_argv_edges_active", None)
    if active is None:
        active = tracer._python_argv_edges_active = set()
    key = (id(unit), index)
    if key in active:
        return _Facts.leaf(
            UNKNOWN, _step(unit, node, "recursive process argument flow is unresolved")
        )
    active.add(key)
    try:
        facts = _Facts()
        if not native_argv:
            facts.add(
                _Facts.leaf(
                    UNKNOWN,
                    _step(
                        unit,
                        node,
                        "sys.argv may be reassigned or mutated; native argument binding is unverified",
                    ),
                )
            )
        matched = python_argv_launches(tracer.project, unit)
        sources = python_argv_sources(tracer.project, unit, index)
        for edge in sources:
            # A child helper's binding environment is not the parent's call
            # environment. Resolve the original parent expression afresh with
            # this tracer's current rule (a basename is not a symlink defense).
            parent = tracer.trace(edge.unit, edge.scope, edge.argument, None)
            parent = parent.then(
                _step(
                    edge.unit,
                    edge.call,
                    f"process launch binds child sys.argv[{index}] from command argument {edge.command_index}",
                )
            )
            parent = parent.then(
                _step(unit, node, f"child sys.argv[{index}] reaches this process")
            )
            facts.add(parent)
            if (not edge.exact_target or not native_argv) and not parent.chains[
                UNTRUSTED
            ]:
                facts.add(
                    _Facts.leaf(
                        UNKNOWN,
                        _step(
                            edge.unit,
                            edge.call,
                            "the relative child target depends on an unverified working directory",
                        ),
                    )
                )
        for launch in matched:
            if launch.uncertainty:
                facts.add(_uncertain_launch(tracer, launch, always=True))
        for launch in python_argv_ambiguous_launches(tracer.project):
            facts.add(_uncertain_launch(tracer, launch))
        if facts.empty():
            return None
        return facts
    finally:
        active.discard(key)


def _context_launch_gap(tracer, launch, kinds):
    from .path_provenance import INCOMPLETE, UNKNOWN, UNTRUSTED, _extend, _Facts, _step

    options = set()
    if "environment" in kinds or "env" in kinds:
        options.add("env")
    if "cwd" in kinds:
        options.add("cwd")
    if "stdin" in kinds:
        options.update({"stdin", "input"})
    parent = _Facts()
    unpacked = False
    if "environment" in kinds or "env" in kinds:
        providers = tracer.project.values(launch.unit, launch.scope, launch.call.func)
        if len(launch.call.args) > 2 and any(
            value.kind == "ext" and value.name in {"os.execve", "os.execvpe"}
            for value in providers or ()
        ):
            # These native exec transports pass env positionally. This is a
            # context gap, not a claim about which environment key is read.
            parent.add(
                tracer.trace(launch.unit, launch.scope, launch.call.args[2], None)
            )
    for keyword in launch.call.keywords:
        if keyword.arg in options or keyword.arg is None:
            unpacked |= keyword.arg is None
            parent.add(tracer.trace(launch.unit, launch.scope, keyword.value, None))
    if parent.chains["operator"]:
        parent.add(operator_launch_gap(tracer, parent))
    gaps = _Facts()
    reason = "the launched process context may supply this operator source"
    step = _step(launch.unit, launch.call, reason)
    for kind in (UNTRUSTED, UNKNOWN, INCOMPLETE):
        target = INCOMPLETE if kind == INCOMPLETE else UNKNOWN
        for chain in parent.chains[kind]:
            gaps.chains[target].append(_extend(chain, step))
    execution_unknown = launch.uncertainty and any(
        term in launch.uncertainty
        for term in (
            "provider",
            "shell",
            "overridden",
            "unpacked",
            "runtime import",
            "implicit startup",
        )
    )
    if (unpacked or execution_unknown) and gaps.empty():
        gaps.add(
            _Facts.leaf(
                UNKNOWN, _step(launch.unit, launch.call, launch.uncertainty or reason)
            )
        )
    return gaps


def _operator_launch_gap(tracer, facts):
    """Associate each operator source with relevant launch transports.

    Structured source records are independent of presentation text and its
    bounded explanation chains. Missing or truncated records cannot prove a
    source is operator-only. Known launches of unrelated scripts stay separate.
    """
    from .path_provenance import INCOMPLETE, OPERATOR, UNKNOWN, _Facts, _step

    gaps = _Facts()
    if not facts.chains[OPERATOR]:
        return gaps
    records = getattr(facts, "operator_origins", ())
    if not getattr(facts, "operator_origins_complete", False) or not records:
        return _Facts.leaf(
            INCOMPLETE,
            "operator source context is not fully associated with an indexed process",
        )
    origins = {}
    for origin, kind in sorted(records, key=lambda record: (record[0].rel, record[1])):
        if kind not in {"cli", "stdin", "environment", "env", "cwd"}:
            gaps.add(
                _Facts.leaf(
                    INCOMPLETE,
                    "operator source kind has no established process context",
                )
            )
            continue
        origins.setdefault(origin, set()).add(kind)
    active = getattr(tracer, "_operator_launch_gaps_active", None)
    if active is None:
        active = tracer._operator_launch_gaps_active = set()
    for origin, kinds in origins.items():
        if id(origin) in active:
            gaps.add(
                _Facts.leaf(
                    UNKNOWN,
                    _step(
                        origin,
                        origin.tree,
                        "recursive process launch context is unresolved",
                    ),
                )
            )
            continue
        active.add(id(origin))
        try:
            for launch in python_process_context_launches(tracer.project, origin):
                if "cli" in kinds:
                    gaps.add(
                        _uncertain_launch(
                            tracer,
                            launch,
                            always=bool(launch.uncertainty),
                            stdin="stdin" in kinds,
                        )
                    )
                gaps.add(_context_launch_gap(tracer, launch, kinds))
            for launch in python_argv_ambiguous_launches(tracer.project):
                if "cli" in kinds:
                    gaps.add(_uncertain_launch(tracer, launch, stdin="stdin" in kinds))
                gaps.add(_context_launch_gap(tracer, launch, kinds))
        finally:
            active.discard(id(origin))
    return gaps


def operator_launch_gap(tracer, facts):
    """Reuse completed source summaries under the exact active process context.

    Provisional caller fixpoints and limited results are never cached. Active
    process origins are part of the semantic key: a cycle in one launch context
    cannot become safety in another. Authority is independent of display chains.
    """
    from .path_provenance import INCOMPLETE, OPERATOR, _Facts

    records = getattr(facts, "operator_origins", ())
    if not facts.chains[OPERATOR] or not records or not getattr(facts, "operator_origins_complete", False):
        return _operator_launch_gap(tracer, facts)
    key = (
        tracer.rule,
        getattr(tracer, "_stdin_sink_scope", None),
        getattr(facts, "operator_origins_complete", False),
        tuple(sorted((id(unit), kind) for unit, kind in records)),
        tuple(sorted(getattr(tracer, "_operator_launch_gaps_active", ()))),
    )
    settled = not tracer.depth_of and not tracer.pending
    cache = getattr(tracer, "_operator_launch_gap_cache", None)
    if cache is None:
        cache = tracer._operator_launch_gap_cache = {}
    if settled and key in cache:
        return _Facts().add(cache[key])
    limited = tracer.limited
    result = _operator_launch_gap(tracer, facts)
    if (
        settled
        and tracer.limited == limited
        and not result.chains[INCOMPLETE]
        and not tracer.depth_of
        and not tracer.pending
        and len(cache) < 512
    ):
        cache[key] = _Facts().add(result)
    return result
