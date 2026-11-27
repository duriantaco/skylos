"""Replay the frozen security cases using an installed Skylos CLI. Sources are scan inputs only."""

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory


def score(cli, cases, *, no_grep_verify=False):
    with TemporaryDirectory() as scratch:
        work = Path(scratch).resolve()
        project = work / "fixtures"
        expected_paths = set()
        for case in cases:
            relative = Path(case["path"])
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or relative in expected_paths
            ):
                raise ValueError(f"Invalid fixture path {relative}")
            expected_paths.add(relative)
            source = case["source"].encode()
            if hashlib.sha256(source).hexdigest() != case["sha256"]:
                raise ValueError(f"Fixture digest mismatch for {relative}")
            dest = project / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(source)

        output = work / "report.json"
        subprocess.run(
            [
                cli,
                str(project),
                "--danger",
                *(["--no-grep-verify"] if no_grep_verify else []),
                "--no-cache",
                "--no-upload",
                "--no-provenance",
                "--no-clipboard",
                "--progress",
                "off",
                "--format",
                "json",
                "--output",
                str(output),
            ],
            cwd=work,
            env={**os.environ, "SKYLOS_CUSTOM_RULES": "[]", "SKYLOS_JOBS": "1"},
            check=True,
        )
        report = json.loads(output.read_bytes())
        summary = report["analysis_summary"]
        visited = {
            Path(row["file"]).relative_to(project)
            for row in report["definitions"].values()
        }
        if (
            report.get("analysis_errors")
            or summary["analysis_coverage"]["unchecked_file_count"]
            or expected_paths - visited
        ):
            raise ValueError("Incomplete scan. Cannot score uninspected cases.")
        findings = {}
        for row in report.get("danger", []):
            key = (Path(row["file"]).relative_to(project), row["rule_id"])
            findings.setdefault(key, set()).add(row["line"])
        decisions = {}
        for case in cases:
            lines = set().union(
                *(
                    findings.get((Path(case["path"]), rule), ())
                    for rule in case["rules"]
                )
            )
            hit = case["line"] in lines if "line" in case else bool(lines)
            if case["positive"]:
                decisions[case["path"]] = "TP" if hit else "FN"
            else:
                decisions[case["path"]] = "FP" if hit else "TN"
        return {"counts": dict(Counter(decisions.values())), "decisions": decisions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", help="Skylos executable to evaluate")
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path(__file__).with_name("cases.json"),
        help="Path to frozen case suites in the same format",
    )
    parser.add_argument(
        "--no-grep-verify",
        action="store_true",
        help="Disable dead-code grep verification during a security-only evaluation.",
    )
    args = parser.parse_args()
    cli = str(Path(args.cli).resolve()) if os.sep in args.cli else args.cli
    suites = json.loads(args.cases.read_bytes())
    print(
        json.dumps(
            {
                name: score(cli, suite["cases"], no_grep_verify=args.no_grep_verify)
                for name, suite in suites.items()
            },
            indent=2,
        )
    )
