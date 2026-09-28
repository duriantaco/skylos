"""Check that the release commit passed every required GitHub Actions job."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_CHECKS = (
    "test",
    "analyzer-speed",
    "corpus",
    "quality-benchmark",
    "scan",
)


def check_release_checks(payload: dict) -> tuple[list[str], list[str]]:
    """Return failed and pending required checks from a check-runs response."""
    runs = payload["check_runs"]
    if not isinstance(runs, list):
        raise ValueError("check_runs must be a list")

    failures: list[str] = []
    pending: list[str] = []
    for name in REQUIRED_CHECKS:
        matches = [
            run
            for run in runs
            if run.get("name") == name
            and (run.get("app") or {}).get("slug") == "github-actions"
        ]
        if not matches:
            pending.append(f"{name}: missing")
            continue

        # A rerun gets a new check-run ID. Never accept an older success while
        # the current run is pending or failed.
        latest = max(matches, key=lambda run: run["id"])
        if latest.get("status") != "completed":
            pending.append(f"{name}: {latest.get('status') or 'pending'}")
        elif latest.get("conclusion") != "success":
            failures.append(f"{name}: {latest.get('conclusion') or 'unknown'}")

    return failures, pending


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_release_checks.py CHECK_RUNS_JSON", file=sys.stderr)
        return 3

    try:
        payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        failures, pending = check_release_checks(payload)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"Invalid release check data: {exc}", file=sys.stderr)
        return 3

    if failures:
        print("Required release checks failed:")
        for item in failures:
            print(f"- {item}")
        return 1
    if pending:
        print("Required release checks are not complete yet:")
        for item in pending:
            print(f"- {item}")
        return 2

    print("Required release checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
