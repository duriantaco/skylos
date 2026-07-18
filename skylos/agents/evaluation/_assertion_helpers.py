from __future__ import annotations

from typing import Any

from .schema import BehaviorAssertion


def checked(
    assertion: str,
    kind: str,
    passed: bool,
    pass_message: str,
    fail_message: str,
    expected: Any,
    observed: Any,
) -> BehaviorAssertion:
    return BehaviorAssertion(
        assertion=assertion,
        kind=kind,
        status="pass" if passed else "fail",
        message=pass_message if passed else fail_message,
        expected=expected,
        observed=observed,
    )


def incomplete(
    assertion: str,
    kind: str,
    message: str,
    expected: Any,
    observed: Any = None,
) -> BehaviorAssertion:
    return BehaviorAssertion(
        assertion=assertion,
        kind=kind,
        status="incomplete",
        message=message,
        expected=expected,
        observed=observed,
    )
