"""Explain recorded comparison evidence without inventing runtime witnesses."""

from __future__ import annotations

import json


def _same(left, right):
    try:
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    except (TypeError, ValueError, RecursionError):
        return False


def _kind(value):
    return value[0] if isinstance(value, (list, tuple)) and value else None


def _short(value, limit=180):
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _value(value, calls, depth=0):
    if depth > 6:
        return "an earlier call result"
    kind = _kind(value)
    if kind in {"parameter", "external", "module"} and len(value) > 1:
        return _short(value[1])
    if kind == "constant" and len(value) > 2:
        return _short(value[2])
    if kind in {"result", "exception"} and len(value) > 1:
        index = value[1]
        if type(index) is int and 0 <= index < len(calls):
            call = _call(calls[index], calls, depth + 1)
            return call if kind == "result" else f"an exception from {call}"
        return "an earlier call result" if kind == "result" else "an exception"
    return "a modeled value"


def _call(call, calls, depth=0):
    if not isinstance(call, dict):
        return "an outgoing call"
    target = _value(call.get("target"), calls, depth)
    arguments = [_value(arg, calls, depth) for arg in call.get("args", [])[:5]]
    for keyword in call.get("kwargs", [])[:5]:
        if isinstance(keyword, (list, tuple)) and len(keyword) == 2:
            arguments.append(f"{keyword[0]}={_value(keyword[1], calls, depth)}")
    if len(call.get("args", [])) > 5 or len(call.get("kwargs", [])) > 5:
        arguments.append("...")
    return _short(f"{target}({', '.join(arguments)})")


def _terminal(trace, *, before=False):
    if not isinstance(trace, dict):
        return "No corresponding trace was selected for this side of the comparison."
    value = trace.get("value")
    calls = trace.get("calls", [])
    if trace.get("outcome") == "raise":
        verb = "Propagated" if before else "Propagates"
        return f"{verb} {_value(value, calls)}."
    verb = "Returned" if before else "Returns"
    if _kind(value) == "result":
        return f"{verb} the result of {_value(value, calls)}."
    return f"{verb} {_value(value, calls)}."


def _path(trace):
    if not isinstance(trace, dict):
        return "No corresponding trace was selected for this side of the comparison."
    calls = trace.get("calls", [])
    steps = [
        f"{_call(call, calls)} ({'raises' if call.get('outcome') == 'raise' else 'returns'})"
        for call in calls[:4]
        if isinstance(call, dict)
    ]
    if len(calls) > 4:
        steps.append(f"{len(calls) - 4} more calls")
    description = " -> ".join(steps) if steps else "No outgoing calls"
    return f"{description}. {_terminal(trace)}"


def _signature(value):
    if not isinstance(value, (list, tuple)):
        return "Signature details unavailable."
    parameters = [
        f"{name} ({str(kind).replace('_', ' ')})"
        for kind, name in value
        if isinstance(name, str)
    ]
    return "Parameters: " + (", ".join(parameters) if parameters else "none") + "."


def explain_difference(difference: dict) -> dict[str, str]:
    """Specific transitions require matching call histories and outcomes.

    The engine's first removed and first added traces are independently chosen.
    Otherwise describe separate model paths, not a same-input runtime witness.
    """
    before, after = difference.get("before"), difference.get("after")
    review = "Confirm whether this behavior change was intentional."
    if difference.get("kind") == "signature":
        return {
            "title": "Function signature changed",
            "before": _signature(before),
            "after": _signature(after),
            "impact": "Callers may need to change how they pass arguments.",
            "review": review,
        }

    explanation = {
        "title": "Behavior changed on compared paths",
        "before": _path(before),
        "after": _path(after),
        "impact": "These are different modeled paths; they are not an executed same-input example.",
        "review": review,
    }
    if not isinstance(before, dict) or not isinstance(after, dict):
        return explanation
    left_calls, right_calls = before.get("calls", []), after.get("calls", [])
    if not _same(left_calls, right_calls):
        explanation["title"] = "Call sequence changed"
        return explanation

    explanation["before"] = _terminal(before, before=True)
    explanation["after"] = _terminal(after)
    left, right = before.get("outcome"), after.get("outcome")
    if left == "raise" and right == "return":
        explanation.update(
            title="Exception no longer propagated",
            impact="Callers may continue without being told the operation failed.",
        )
    elif left == "return" and right == "raise":
        explanation.update(
            title="Exception now propagated",
            impact="Callers may now need to handle an exception instead of receiving a result.",
        )
    elif left == right == "return" and not _same(
        before.get("value"), after.get("value")
    ):
        explanation.update(
            title="Return value changed",
            impact="Callers that use the returned value may behave differently.",
        )
        if _kind(before.get("value")) == "result" and _same(
            after.get("value"), ("constant", "NoneType", "None")
        ):
            index = before["value"][1]
            callback = (
                type(index) is int
                and 0 <= index < len(left_calls)
                and _kind(left_calls[index].get("target")) == "parameter"
            )
            explanation.update(
                title="Callback result discarded"
                if callback
                else "Call result discarded",
                impact="Callers that use the returned value now receive None and may break.",
            )
    return explanation
