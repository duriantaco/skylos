"""Grade submitted pytest tests against a reviewed regression task set."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

from skylos.done.regression_replay import replay


def grade(manifest: dict, submission: dict, repo: Path, timeout: int) -> dict:
    cases = manifest["cases"]
    tests = submission["tests"]
    ids = {case["id"] for case in cases}
    if not cases or len(ids) != len(cases) or tests.keys() - ids:
        raise ValueError("Use unique reviewed case IDs and no unknown submissions")

    results = []
    counts = {"passed": 0, "failed": 0, "inconclusive": 0, "missing": 0}
    for case in cases:
        case_id = case["id"]
        selection = tests.get(case_id)
        revisions = [case["fixed"], *case["buggy"], *case.get("correct", [])]
        if (
            not case["buggy"]
            or not case["source"]
            or any(
                re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is None
                for revision in revisions
            )
        ):
            raise ValueError(f"{case_id} requires pinned variants and source files")
        evidence = None
        if selection is None:
            status = "missing"
        else:
            node_id = selection if isinstance(selection, str) else selection["test"]
            args = argparse.Namespace(
                repo=repo,
                fixed=case["fixed"],
                buggy=case["buggy"],
                correct=case.get("correct", []),
                source=case["source"],
                baseline_test=case.get("baseline_test"),
                expect_assertion=case.get("expected_assertion"),
                test=node_id,
                test_revision=None
                if isinstance(selection, str)
                else selection["revision"],
                timeout=timeout,
            )
            try:
                evidence = replay(args)
            except (
                OSError,
                ValueError,
                tarfile.TarError,
                subprocess.TimeoutExpired,
            ) as exc:
                evidence = {"verdict": "INCONCLUSIVE", "detail": str(exc)}
            candidate = evidence.get("candidate", evidence)
            status = {
                "DETECTED": "passed",
                "INCONCLUSIVE": "inconclusive",
            }.get(candidate["verdict"], "failed")
        counts[status] += 1
        results.append(
            {
                "id": case_id,
                "title": case["title"],
                **({"context": case["context"]} if "context" in case else {}),
                "status": status,
                "evidence": evidence,
            }
        )

    return {
        "schema_version": 1,
        "benchmark": manifest["benchmark"],
        "manifest_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "submission": submission["label"],
        "total": len(cases),
        "counts": counts,
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--allow-local-execution", action="store_true", required=True)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("Timeout must be positive")
    try:
        report = grade(
            json.loads(args.manifest.read_bytes()),
            json.loads(args.submission.read_bytes()),
            args.repo,
            args.timeout,
        )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    if report["counts"]["inconclusive"]:
        return 2
    return int(report["counts"]["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
