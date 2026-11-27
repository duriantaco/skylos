"""Score PostgreSQL checks on the frozen, line-labeled generated examples."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

CASES_FILE = Path(__file__).with_name("cases.json")
FROZEN_SHA256 = "5ab9f1f3fb520cc4cc68f96c0b3910c93bb2aa4ebaa18a88b4175920ab05b87b"
RULES = {
    "skylos": {
        "SKY-Q503": "unused_cte",
        "SKY-Q504": "null_comparison",
        "SKY-D417": "definer_search_path",
    },
    "sqlfluff": {"ST03": "unused_cte", "CV05": "null_comparison"},
    "eslint": {
        "postgresql/no-security-definer-without-search-path": "definer_search_path"
    },
}


def load_cases():
    data = CASES_FILE.read_bytes()
    if hashlib.sha256(data).hexdigest() != FROZEN_SHA256:
        raise ValueError("PostgreSQL labels changed after the freeze")
    cases = json.loads(data)["cases"]
    return {f"{index:03d}.sql": case for index, case in enumerate(cases, 1)}


def parse_report(command, cwd):
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Tool exited {result.returncode}: {result.stderr or result.stdout}"
        )
    return json.loads(result.stdout)


def scan_external(tool, binary, workdir):
    names = sorted(path.name for path in workdir.glob("*.sql"))
    if tool == "sqlfluff":
        reports = parse_report(
            [
                str(binary),
                "lint",
                "--ignore-local-config",
                "--disable-noqa",
                "--templater",
                "raw",
                "--dialect",
                "postgres",
                "--rules",
                "ST03,CV05",
                "--format",
                "json",
                "--processes",
                "1",
                *names,
            ],
            workdir,
        )
        return {
            Path(row["filepath"]).name: (
                [
                    (v["code"], v["start_line_no"])
                    for v in row["violations"]
                    if v["code"] in RULES[tool]
                ],
                [
                    v["description"]
                    for v in row["violations"]
                    if v["code"] not in RULES[tool]
                ],
            )
            for row in reports
        }

    # Generate the config beside the synthetic files; resolve the pinned plugin
    # from the comparator's install directory rather than the scanned project.
    config = workdir / "eslint.config.mjs"
    module_root = binary.resolve().parents[2]
    (workdir / "node_modules").symlink_to(module_root, target_is_directory=True)
    config.write_text(
        "import pg from 'eslint-plugin-postgresql';\n"
        "export default [{ files: ['**/*.sql'], ...pg.configs.recommended, rules: {"
        "'postgresql/no-security-definer-without-search-path': 'error', "
        "'postgresql/no-syntax-error': 'error' } }];\n",
        encoding="utf8",
    )
    reports = parse_report(
        [
            str(binary),
            "--no-config-lookup",
            "--no-inline-config",
            "--config",
            str(config),
            "--format",
            "json",
            *names,
        ],
        workdir,
    )
    return {
        Path(row["filePath"]).name: (
            [
                (v["ruleId"], v["line"])
                for v in row["messages"]
                if v.get("ruleId") in RULES[tool]
            ],
            [
                v["message"]
                for v in row["messages"]
                if v.get("ruleId") not in RULES[tool]
            ],
        )
        for row in reports
    }


def scan_skylos(cases):
    from skylos.visitors.languages.postgresql import scan_postgresql

    rows = {}
    for filename, case in cases.items():
        findings, error = scan_postgresql(case["sql"] + "\n", filename)
        rows[filename] = (
            [(row["rule_id"], row["line"]) for row in findings],
            [str(error)] if error else [],
        )
    return rows


def score(tool, cases, observations):
    if set(observations) != set(cases):
        raise ValueError("Expected one tool report per input, including clean files")
    counts = {
        rule: {"tp": 0, "fp": 0, "fn": 0, "tn_files": 0}
        for rule in RULES[tool].values()
    }
    differences = []
    invalid = {}
    unparsed = []
    for filename, case in cases.items():
        findings, errors = observations[filename]
        if case.get("parse_error"):
            invalid[case["id"]] = "rejected" if errors else "accepted"
            continue
        if errors:
            unparsed.append({"case": case["id"], "errors": errors})
            continue
        actual = Counter((RULES[tool][rule], line) for rule, line in findings)
        for rule, tally in counts.items():
            expected = Counter(case["expected"].get(rule, []))
            observed = Counter(
                {line: count for (name, line), count in actual.items() if name == rule}
            )
            misses = expected - observed
            noise = observed - expected
            tally["tp"] += sum((expected & observed).values())
            tally["fp"] += sum(noise.values())
            tally["fn"] += sum(misses.values())
            tally["tn_files"] += int(not expected and not observed)
            if misses or noise:
                differences.append(
                    {
                        "case": case["id"],
                        "rule": rule,
                        "missed_lines": sorted(misses.elements()),
                        "unexpected_lines": sorted(noise.elements()),
                    }
                )
    return {
        "tool": tool,
        "label_sha256": FROZEN_SHA256,
        "cases": len(cases),
        "valid_scored": len(cases) - len(invalid) - len(unparsed),
        "invalid_controls": invalid,
        "valid_unparsed": unparsed,
        "rules": counts,
        "disagreements": differences,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=RULES)
    parser.add_argument(
        "--binary", type=Path, help="Installed SQLFluff or ESLint executable"
    )
    args = parser.parse_args()
    cases = load_cases()
    if args.tool == "skylos":
        sys.path.insert(0, str(CASES_FILE.resolve().parents[2]))
        observations = scan_skylos(cases)
    else:
        if not args.binary:
            parser.error("External comparators require --binary")
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            for filename, case in cases.items():
                (workdir / filename).write_text(case["sql"] + "\n", encoding="utf8")
            observations = scan_external(args.tool, args.binary.absolute(), workdir)
    print(json.dumps(score(args.tool, cases, observations), indent=2))


if __name__ == "__main__":
    main()
