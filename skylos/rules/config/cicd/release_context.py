"""Prove release intent for a GitHub Actions publishing step."""

from __future__ import annotations

from typing import Any

from skylos.rules.config.cicd.actions_expressions import (
    Comparison,
    ExpressionError,
    Logical,
    Negation,
    Node,
    Reference,
    Value,
    parse_expression,
)
from skylos.rules.config.cicd.ai_agent_expressions import condition_source
from skylos.rules.config.cicd.yaml_source import YamlSource


_RELEASE_ACTIVITIES = frozenset(
    {
        "published",
        "unpublished",
        "created",
        "edited",
        "deleted",
        "prereleased",
        "released",
    }
)
_MAX_CONDITION_LENGTH = 4096
_MAX_PROOF_DEPTH = 50


def _release_trigger(trigger: Any) -> bool:
    if isinstance(trigger, str):
        return trigger == "release"
    if isinstance(trigger, list):
        return bool(trigger) and all(event == "release" for event in trigger)
    if not isinstance(trigger, dict) or set(trigger) != {"release"}:
        return False
    options = trigger["release"]
    if options is None:
        return True
    if not isinstance(options, dict) or set(options) - {"types"}:
        return False
    if "types" not in options:
        return True
    activities = options["types"]
    return (
        isinstance(activities, list)
        and bool(activities)
        and all(
            isinstance(activity, str) and activity in _RELEASE_ACTIVITIES
            for activity in activities
        )
    )


def _event_and_release(left: Node, right: Node) -> bool:
    return (
        isinstance(left, Reference)
        and left.is_exactly("github.event_name")
        and isinstance(right, Value)
        and isinstance(right.value, str)
        and right.value.lower() == "release"
    )


def _requires_release(node: Node, truthy: bool = True, depth: int = 0) -> bool:
    if depth >= _MAX_PROOF_DEPTH:
        return False
    if isinstance(node, Negation):
        return _requires_release(node.operand, not truthy, depth + 1)
    if isinstance(node, Comparison) and node.operator in {"==", "!="}:
        return (node.operator == "==") == truthy and (
            _event_and_release(node.left, node.right)
            or _event_and_release(node.right, node.left)
        )
    if isinstance(node, Logical) and node.operator in {"&&", "||"}:
        left = _requires_release(node.left, truthy, depth + 1)
        right = _requires_release(node.right, truthy, depth + 1)
        # A true conjunction needs both sides; a true disjunction can use either.
        # Unknown branches never supply proof, including under negation.
        if node.operator == "&&":
            return (left or right) if truthy else (left and right)
        return (left and right) if truthy else (left or right)
    return False


def _release_condition(value: Any) -> bool:
    if isinstance(value, str) and len(value) > _MAX_CONDITION_LENGTH:
        return False
    source = condition_source(value)
    if source is None or not source.strip():
        return False
    try:
        return _requires_release(parse_expression(source))
    except (ExpressionError, RecursionError):
        return False


def has_release_context(
    workflow: dict[str, Any],
    job: dict[str, Any] | None,
    step: dict[str, Any],
    source: YamlSource | None,
) -> bool:
    if (
        source is None
        or source.data is not workflow
        or source.has_ambiguous_mappings()
        or ("on" in workflow and True in workflow)
    ):
        return False
    # YAML 1.1 resolves an unquoted "on" key to True. Conflicting spellings
    # cannot establish a workflow-wide proof.
    trigger = workflow.get("on", workflow.get(True))
    return (
        (source.has_literal_root_key("on") and _release_trigger(trigger))
        or _release_condition(job.get("if") if job is not None else None)
        or _release_condition(step.get("if"))
    )
