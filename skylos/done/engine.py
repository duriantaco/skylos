"""Run the done checks for a base and head and decide the verdict."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from skylos.done.base import Comparison, open_comparison
from skylos.done.checks import CHECKS, RUN_ORDER, CheckContext, CheckResult, run_check
from skylos.done.config import CHECK_IDS, DoneConfig, parse_done_config


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
) -> DoneResult:
    started = time.monotonic()
    comparison = open_comparison(path, base_ref)
    # The change under review never supplies its own settings: they come
    # from the base commit (the target branch's tip for a pull request).
    config = parse_done_config(
        comparison.base_text("pyproject.toml", sha=comparison.config_sha)
    )
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
        result = run_check(check_id, ctx)
        if mode == "block" and result.status == "skipped":
            result.status = "incomplete"
        results[check_id] = CheckOutcome(mode, result)
    checks = [results[check_id] for check_id in CHECK_IDS]
    return DoneResult(
        comparison=comparison,
        config=config,
        checks=checks,
        verdict=decide_verdict(checks),
        seconds=round(time.monotonic() - started, 1),
    )


def decide_verdict(checks: list[CheckOutcome]) -> str:
    """Only blocking checks decide; advise and shadow checks are reported."""
    statuses = {c.result.status for c in checks if c.mode == "block"}
    if "fail" in statuses:
        return "fail"
    if statuses - {"pass"}:
        return "incomplete"
    return "pass"
