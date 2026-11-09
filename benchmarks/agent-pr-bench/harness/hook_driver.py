#!/usr/bin/env python3
"""Run the post-edit hook's own check on one file and print its findings as JSON.

The ``skylos-hook`` runner spawns this once per changed source file with the
Skylos interpreter, so the measured wall time is what an agent waits for after
an edit. Findings are the hook's, before same-line merging, so rule ids match
the scan's labels. Only findings on the given line ranges are kept, exactly as
the hook keeps only the lines the agent changed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

FIELDS = (
    "rule_id",
    "line",
    "severity",
    "message",
    "category",
    "vibe",
    "blocking",
    "why",
    "file_level",
)


def parse_ranges(spec: str) -> list[tuple[int, int]] | None:
    if spec == "all":
        return None
    ranges: list[tuple[int, int]] = []
    for part in spec.split(","):
        if not part:
            continue
        start, _, end = part.partition("-")
        ranges.append((int(start), int(end or start)))
    return ranges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="workspace root (the Git checkout)")
    parser.add_argument("--file", required=True, help="repo-relative file to check")
    parser.add_argument("--ranges", default="all", help="comma-separated L1-L2 ranges, or 'all'")
    args = parser.parse_args()

    started = time.perf_counter()
    from skylos.commands.hook_cmd import (
        AgentStandardsPolicyError,
        HookDeps,
        _check_file,
        finding_touches_ranges,
        load_agent_standards_policy,
    )

    root = Path(args.root).resolve()
    path = (root / args.file).resolve()
    deps = HookDeps()
    policy_error = None
    try:
        deps.standards_policy = load_agent_standards_policy(root)
    except AgentStandardsPolicyError as exc:
        policy_error = str(exc)

    result = {
        "file": args.file,
        "status": "skipped",
        "seconds": 0.0,
        "policy_error": policy_error,
        "findings": [],
    }
    checked = _check_file(path, root, deps)
    if checked is not None:
        findings, lines, _stat = checked
        ranges = parse_ranges(args.ranges)
        text = "\n".join(lines)
        result["status"] = "checked"
        for finding in findings:
            in_range = finding.get("file_level") or finding_touches_ranges(
                finding, ranges, path, text
            )
            if not in_range:
                continue
            result["findings"].append({key: finding.get(key) for key in FIELDS})
    result["seconds"] = round(time.perf_counter() - started, 3)
    json.dump(result, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
