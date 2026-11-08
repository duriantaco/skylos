"""Run the done checks for a base and head and decide the verdict."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path

from skylos.done.base import Comparison, open_comparison
from skylos.done.checks import CHECKS, RUN_ORDER, CheckContext, CheckResult, run_check
from skylos.done.config import (
    CHECK_IDS,
    TYPE_CHECKERS,
    DoneConfig,
    base_config_text,
    parse_done_config,
)

# Summary of a check that waits for the earlier required checks to pass.
WAITING_SUMMARY = "Earlier required checks failed or were incomplete"


@dataclass
class CheckOutcome:
    mode: str
    result: CheckResult

    @property
    def blocking(self) -> bool:
        return self.mode == "block" and self.result.status != "pass"


@dataclass
class DoneResult:
    comparison: Comparison
    config: DoneConfig
    checks: list[CheckOutcome]  # in CHECK_IDS order
    verdict: str  # "pass", "fail" or "incomplete"
    seconds: float


def run(
    path: str | Path,
    *,
    base_ref: str | None = None,
    run_tests: bool = True,
    session_id: str | None = None,
    type_check: bool | None = None,
    checker: str | None = None,
) -> DoneResult:
    started = time.monotonic()
    if session_id is not None:
        if base_ref is not None:
            from skylos.done.base import DoneError

            raise DoneError("choose either a session baseline or a PR base")
        from skylos.done.session import open_session_comparison

        comparison = open_session_comparison(path, session_id)
    else:
        comparison = open_comparison(path, base_ref)
    # The change under review never supplies its own settings: they come
    # from the base commit (the target branch's tip for a pull request).
    config = parse_done_config(base_config_text(comparison, sha=comparison.config_sha))
    config = _type_check_policy(config, type_check=type_check, checker=checker)
    ctx = CheckContext(comparison, config, run_tests=run_tests)
    results: dict[str, CheckOutcome] = {}
    for check_id in RUN_ORDER:
        mode = config.mode(check_id)
        if mode == "off":
            results[check_id] = CheckOutcome(
                mode,
                CheckResult(
                    id=check_id,
                    rule=CHECKS[check_id][1],
                    status="skipped",
                    summary="Off in [tool.skylos.done]",
                    evidence={"summary": "Off in [tool.skylos.done]"},
                ),
            )
            continue
        if check_id in {"tests_pass", "changed_lines_checked", "type_check"} and any(
            outcome.blocking for outcome in results.values()
        ):
            result = CheckResult(
                check_id,
                CHECKS[check_id][1],
                "incomplete",
                "Not run because an earlier required check needs attention",
                evidence={"summary": WAITING_SUMMARY},
            )
        elif (
            check_id == "tests_pass"
            and mode == "block"
            and not _has_test_evidence(config)
        ):
            result = CheckResult(
                check_id,
                CHECKS[check_id][1],
                "incomplete",
                "A non-pytest test command requires junit_xml; exit zero alone cannot verify tests",
                evidence={"summary": "Configure JUnit results for this test command"},
            )
        else:
            result = run_check(check_id, ctx)
        if mode == "block" and result.status == "skipped":
            result.status = "incomplete"
        results[check_id] = CheckOutcome(mode, result)
    checks = [results[check_id] for check_id in CHECK_IDS]
    if comparison._session_late:
        outcome = results["tests_pass"]
        outcome.mode = "block"
        if outcome.result.status != "fail":
            outcome.result.status = "incomplete"
        outcome.result.summary = "Session baseline was captured after edits; initial session coverage is unverified"
        outcome.result.evidence["session_base"] = "head_fallback"
    if session_id is not None:
        from skylos.done.session import assert_session_unchanged

        assert_session_unchanged(comparison)
    return DoneResult(
        comparison=comparison,
        config=config,
        checks=checks,
        verdict=decide_verdict(checks),
        seconds=round(time.monotonic() - started, 1),
    )


def _type_check_policy(
    config: DoneConfig, *, type_check: bool | None, checker: str | None
) -> DoneConfig:
    from skylos.done.base import DoneError

    if type_check is not None and not isinstance(type_check, bool):
        raise DoneError("type_check must be true or false")
    if checker is not None:
        if checker not in TYPE_CHECKERS:
            raise DoneError("type checker must be auto, mypy, pyright, pyrefly or tsc")
        if type_check is not True:
            raise DoneError("choosing a type checker requires --type-check")
        if config.mode("type_check") != "off" and checker != config.type_checker:
            raise DoneError("the type checker is fixed by the trusted Done policy")
    if type_check is not True:
        # A caller cannot disable a check enabled by the trusted baseline.
        return config
    return replace(
        config,
        modes={**config.modes, "type_check": "block"},
        type_checker=checker or config.type_checker,
    )


def _has_test_evidence(config: DoneConfig) -> bool:
    from skylos.done.runner import _is_pytest

    return bool(config.junit_xml) or _is_pytest(config.test_command or ("pytest",))


def decide_verdict(checks: list[CheckOutcome]) -> str:
    """Only blocking checks decide; advise and shadow checks are reported."""
    statuses = {c.result.status for c in checks if c.mode == "block"}
    if "fail" in statuses:
        return "fail"
    if statuses - {"pass"}:
        return "incomplete"
    return "pass"
