"""Replay the supplemental PostgreSQL permission-change labels through the CLI."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from run import decide, fixture

FROZEN = {
    "transactions": "ff043f70fdfe21265656fa16ec193c78efa3049d0b2997f3935cef3f669fe993",
    "regroup": "d6079aea376fd551a103a0a1d27ebadba70490befc15dcaf878b8411aead20f2",
}
DEFAULTS = {
    "path": "db/prod/001.sql",
    "production_directory": "db/prod",
    "deny_public_writes": True,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--suite", choices=FROZEN, default="transactions")
    args = parser.parse_args()
    source = Path(__file__).with_name(args.suite + ".json").read_bytes()
    if hashlib.sha256(source).hexdigest() != FROZEN[args.suite]:
        parser.error("The labels differ from the frozen manifest")

    scanner = args.scanner_root.resolve()
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            filter(None, [str(scanner), os.getenv("PYTHONPATH")])
        ),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    results = []
    with tempfile.TemporaryDirectory() as temp:
        fingerprints = {}
        for label in json.loads(source):
            parent = Path(temp).resolve() / label["id"]
            case = {"before": label["base"], "after": label["head"]}
            exception = label.get("exception", {})
            statement = exception.get("statement")
            if statement and statement not in fingerprints:
                calibration = {"after": statement, "path": exception["path"]}
                repo, start, end = fixture(
                    parent / "calibrate", calibration, DEFAULTS, env
                )
                fingerprints[statement] = decide(repo, env, start, end)["violations"][
                    0
                ]["fingerprint"]
            project, base, head = fixture(
                parent,
                case,
                DEFAULTS,
                env,
                fingerprints.get(statement),
                exception_path=exception.get("path"),
            )
            decision = decide(project, env, base, head)
            count = len(decision["violations"])
            expected = label["violations"]
            expected_status = "fail" if expected else "pass"
            results.append(
                {
                    "id": label["id"],
                    "expected": expected,
                    "actual": count,
                    "matched": count == expected
                    and decision["status"] == expected_status
                    and decision["checked_files"] == 1
                    and not decision["unchecked_files"],
                }
            )
    modules = [
        "skylos/cicd/postgres_check.py",
        "skylos/visitors/languages/postgresql_grant_policy.py",
    ]
    matches = sum(case["matched"] for case in results)
    report = {
        "manifest_sha256": FROZEN[args.suite],
        "module_sha256": {
            name: hashlib.sha256((scanner / name).read_bytes()).hexdigest()
            for name in modules
        },
        "matches": matches,
        "total": len(results),
        "cases": results,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{matches}/{len(results)} {args.suite} cases matched")
    return int(matches != len(results))


if __name__ == "__main__":
    raise SystemExit(main())
