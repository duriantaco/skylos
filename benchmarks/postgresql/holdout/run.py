"""Replay pre-labeled source files through Skylos, without executing any SQL."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = {"SKY-Q503", "SKY-Q504"}


def materialize(manifest, project, cache):
    sources = {}
    cache.mkdir(parents=True, exist_ok=True)
    for item in manifest["sources"]:
        name = item["name"]
        cached = cache / name
        if not cached.exists():
            url = f"https://raw.githubusercontent.com/{item['repo']}/{item['commit']}/{item['path']}"
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError(f"Upstream bytes differ for {name}")
            cached.write_bytes(data)
        data = cached.read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"Cached bytes differ for {name}")
        sources[name] = data
    for case in manifest["cases"]:
        target = project / case["name"]
        target.parent.mkdir(parents=True, exist_ok=True)
        dialect = case["dialect"]
        (target.parent / "skylos.toml").write_text(f'[sql]\ndialect = "{dialect}"\n')
        data = sources[case["source"]]
        if "lines" in case:
            first, last = case["lines"]
            data = b"".join(data.splitlines(keepends=True)[first - 1 : last])
        target.write_bytes(data)


def score(manifest, report, project):
    cases = {c["name"]: c for c in manifest["cases"]}
    coverage = report["analysis_summary"]["sql_analysis"]
    statuses = {
        Path(item["file"]).relative_to(project).as_posix(): item["status"]
        for item in coverage["files"]
    }
    if cases.keys() != statuses.keys():
        raise ValueError(f"Unexpected CLI coverage: {cases.keys() ^ statuses.keys()}")
    findings = []
    for finding in report.get("quality", []):
        if finding["rule_id"] not in RULES:
            continue
        name = Path(finding["file"]).relative_to(project).as_posix()
        first = cases[name].get("lines", [1])[0]
        findings.append((name, finding["rule_id"], first + finding["line"] - 1))
    counts = {
        rule: dict.fromkeys(("tp", "fp", "tn", "fn", "unscored"), 0)
        for rule in sorted(RULES)
    }
    unexpected = []
    unscored = []
    matched = set()
    for label in manifest["labels"]:
        name = label["name"]
        rule = label["rule"]
        start, end = label["original_lines"]
        if statuses[name] != "checked":
            counts[rule]["unscored"] += 1
            unscored.append([name, rule, start, end, statuses[name]])
            continue
        hits = {
            i
            for i, (f, r, line) in enumerate(findings)
            if f == name and r == rule and start <= line <= end
        }
        matched.update(hits)
        positive = label["expected"] == "positive"
        key = ("tp" if hits else "fn") if positive else ("fp" if hits else "tn")
        counts[rule][key] += 1
        if key in {"fp", "fn"}:
            unexpected.append([name, rule, start, end, key])
    mismatches = {}
    for name, case in cases.items():
        expected = case["coverage"]
        if expected == "psql_script":
            # A psql client directive is legal in the script but outside server SQL.
            continue
        if expected != statuses[name]:
            mismatches[name] = [expected, statuses[name]]
    return {
        "checks": counts,
        "unexpected_labeled_results": unexpected,
        "unscored_labels": unscored,
        "findings_outside_labels": [
            f for i, f in enumerate(findings) if i not in matched
        ],
        "coverage_counts": {
            s: sum(value == s for value in statuses.values())
            for s in sorted(set(statuses.values()))
        },
        "coverage_expectation_mismatches": mismatches,
        "coverage_by_case": dict(sorted(statuses.items())),
    }


def compare_sqlfluff(manifest, project, executable):
    """Compare the two matching rules on the exact PostgreSQL files with labeled sites."""
    names = {label["name"] for label in manifest["labels"]}
    selected = {
        **manifest,
        "cases": [c for c in manifest["cases"] if c["name"] in names],
    }
    paths = [str(project / name) for name in sorted(names)]
    rule_map = {"ST03": "SKY-Q503", "CV05": "SKY-Q504"}
    config = project.parent / "sqlfluff.cfg"
    config.write_text(
        "[sqlfluff]\nlarge_file_skip_byte_limit = 0\nlarge_file_skip_fail = true\n"
    )
    command = [
        executable,
        "lint",
        "--ignore-local-config",
        "--config",
        str(config),
        "--templater",
        "raw",
        "--dialect",
        "postgres",
        "--rules",
        "ST03,CV05",
        "--format",
        "json",
        *paths,
    ]
    result = subprocess.run(
        command, cwd=project.parent, check=False, capture_output=True, text=True
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"sqlfluff exited {result.returncode}: {result.stderr}")
    records = json.loads(result.stdout)
    statuses = {path: "skipped" for path in paths}
    findings = []
    for record in records:
        file = record["filepath"]
        violations = record["violations"]
        unparsed = any(v["code"] in {"PRS", "LXR", "TMP"} for v in violations)
        if unparsed:
            statuses[file] = "unparsed"
        elif record["statistics"]["source_chars"] and record["statistics"]["segments"]:
            statuses[file] = "checked"
        for violation in violations:
            code = violation["code"]
            if code in rule_map:
                findings.append(
                    {
                        "rule_id": rule_map[code],
                        "file": file,
                        "line": violation["start_line_no"],
                    }
                )
    report = {
        "analysis_summary": {
            "sql_analysis": {
                "files": [
                    {"file": name, "status": status}
                    for name, status in statuses.items()
                ]
            }
        },
        "quality": findings,
    }
    version = subprocess.check_output([executable, "--version"], text=True).strip()
    return {"tool": version, **score(selected, report, project)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skylos", default="skylos")
    parser.add_argument(
        "--sqlfluff", help="Also compare SQLFluff on the labeled PostgreSQL files"
    )
    parser.add_argument(
        "--cache",
        type=Path,
        required=True,
        help="Directory for pinned upstream SQL sources",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = (HERE / "manifest.json").read_bytes()
    manifest = json.loads(source)
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp).resolve() / "sources"
        materialize(manifest, project, args.cache)
        output = project.parent / "cli.json"
        command = [
            args.skylos,
            str(project),
            "--quality",
            "--format",
            "json",
            "--output",
            str(output),
            "--no-cache",
            "--no-upload",
            "--no-clipboard",
            "--no-provenance",
            "--progress",
            "off",
        ]
        subprocess.run(
            command, cwd=tmp, env={**os.environ, "SKYLOS_JOBS": "1"}, check=True
        )
        results = score(manifest, json.loads(output.read_text()), project)
        if args.sqlfluff:
            results["sqlfluff"] = compare_sqlfluff(manifest, project, args.sqlfluff)
    results = {"manifest_sha256": hashlib.sha256(source).hexdigest(), **results}
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: results[key]
                for key in (
                    "checks",
                    "coverage_counts",
                    "coverage_expectation_mismatches",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
