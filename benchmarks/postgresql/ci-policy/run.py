"""Replay frozen PostgreSQL policy labels through the local CLI and Git."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MANIFEST = Path(__file__).with_name("cases.json")
FROZEN = "803138622957edc65d756b46a2156a16169dc22ea70a075060d809a2aec08d2e"
CLI = [sys.executable, "-c", "from skylos.cli import main; main()"]

# Leave the CLI, Git diff, renderer, and serialized comment payloads intact.
# Only GitHub traffic is replaced. The target SQL is never executed.
FAKE_GH = """#!/usr/bin/env python3
import os, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version"]:
    print("gh version benchmark")
elif args[:1] == ["api"] and any("per_page=" in arg for arg in args):
    print("[]")
elif args[:2] == ["pr", "comment"]:
    Path(os.environ["CAPTURE_SUMMARY"]).write_text(args[args.index("--body") + 1])
elif args[:3] == ["api", "--method", "POST"] and any(a.endswith("/reviews") for a in args):
    Path(os.environ["CAPTURE_INLINE"]).write_text(sys.stdin.read())
else:
    sys.exit("unexpected gh call: " + repr(args))
"""


def command(args, cwd, env, codes=(0,)):
    result = subprocess.run(
        args, cwd=cwd, env=env, text=True, capture_output=True, check=False
    )
    if result.returncode not in codes:
        raise RuntimeError(
            f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result


def snapshot(project, env):
    command(["git", "add", "-A"], project, env)
    command(
        [
            "git",
            "-c",
            "user.name=Benchmark",
            "-c",
            "user.email=bench@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        project,
        env,
    )
    return command(["git", "rev-parse", "HEAD"], project, env).stdout.strip()


def fixture(parent, label, defaults, env, exception=None, *, exception_path=None):
    project = parent / "project"
    project.mkdir(parents=True)
    command(["git", "init", "-q"], project, env)
    path = label.get("path", defaults["path"])
    sql = project / path
    sql.parent.mkdir(parents=True, exist_ok=True)
    config = project / "pyproject.toml"
    forbid = label.get("deny_public_writes", defaults["deny_public_writes"])
    config.write_text(
        '[tool.skylos.sql]\ndialect = "postgresql"\n[tool.skylos.sql.production]\n'
        + f"directories = [{json.dumps(defaults['production_directory'])}]\n"
        + f"forbid_public_writes = {str(forbid).lower()}\n"
    )
    if exception is not None:
        with config.open("a") as f:
            f.write(
                f'allow_public_writes = [{{path = "{exception_path or path}", fingerprint = "{exception}"}}]\n'
            )
    if label.get("before") is not None:
        sql.write_text(label["before"] + "\n")
    base = snapshot(project, env)
    if label.get("after") is not None:
        sql.write_text(label["after"] + "\n")
    elif sql.exists():
        sql.unlink()
    if label.get("head_ignore"):
        config.write_text(
            '[tool.skylos]\nexclude = ["db/production"]\n' + config.read_text()
        )
    return project, base, snapshot(project, env)


def scan(project, env):
    output = project.parent / "report.json"
    command(
        [
            *CLI,
            ".",
            "--quality",
            "--danger",
            "--no-cache",
            "--no-upload",
            "--no-clipboard",
            "--no-provenance",
            "--progress",
            "off",
            "--format",
            "json",
            "--output",
            str(output),
        ],
        project,
        env,
    )
    return output


def annotation_lines(project, env, report):
    stdout = command(
        [*CLI, "cicd", "annotate", "--input", str(report)], project, env
    ).stdout
    return [
        line
        for line in stdout.splitlines()
        if line.startswith(("::notice", "::warning", "::error"))
    ]


def reporting_case(parent, case, defaults, env):
    sql = "\n".join(case["sql"].format(i=i) for i in range(case.get("repeat", 1)))
    project, base, _ = fixture(parent, {"after": sql}, defaults, env)
    report = scan(project, env)
    data = json.loads(report.read_text())
    lines = annotation_lines(project, env, report)
    summary, inline = parent / "summary.md", parent / "inline.json"
    command(
        [
            *CLI,
            "cicd",
            "review",
            "--diff-base",
            base,
            "--repo",
            "bench/fixture",
            "--pr",
            "1",
            "--input",
            str(report),
        ],
        project,
        {**env, "CAPTURE_SUMMARY": str(summary), "CAPTURE_INLINE": str(inline)},
    )
    if not summary.is_file():
        raise RuntimeError("GitHub summary payload was never produced")
    actual = {
        "quality": sum(
            Path(f["file"]).suffix == ".sql" for f in data.get("quality", [])
        ),
        "danger": sum(Path(f["file"]).suffix == ".sql" for f in data.get("danger", [])),
        "quality_annotations": sum("SKY-Q" in line for line in lines),
        "security_notices": sum(
            line.startswith("::notice") and "SKY-D" in line for line in lines
        ),
        "inline": len(json.loads(inline.read_text())["comments"])
        if inline.exists()
        else 0,
    }
    row = record(case, actual)
    row["summary_groups"] = [
        line.split(" · ")[0].removeprefix("- ").strip("`")
        for line in summary.read_text().splitlines()
        if line.startswith("- `SKY-D") and " · " in line
    ]
    return row


def decide(project, env, base, head):
    result = command(
        [
            *CLI,
            "cicd",
            "postgres-check",
            "--base",
            base,
            "--head",
            head,
            "--format",
            "json",
        ],
        project,
        env,
        codes=(0, 1),
    )
    data = json.loads(result.stdout)
    if data["status"] != ("fail" if result.returncode else "pass"):
        raise ValueError("Policy status disagrees with process exit code")
    return data


def record(case, actual):
    return {
        "id": case["id"],
        "actual": actual,
        "matched": all(value == case[key] for key, value in actual.items()),
    }


def run(args, tmp):
    source = MANIFEST.read_bytes()
    if hashlib.sha256(source).hexdigest() != FROZEN:
        raise ValueError("The manifest differs from the frozen labels")
    labels = json.loads(source)
    defaults = labels["defaults"]
    bindir = tmp / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(0o755)
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            filter(None, [str(args.scanner_root.resolve()), os.getenv("PYTHONPATH")])
        ),
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        "SKYLOS_JOBS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    missing = tmp / "missing-parser"
    missing.mkdir()
    (missing / "pglast.py").write_text(
        "raise ImportError('parser absent in this fixture')\n"
    )
    parser_version = command(
        [sys.executable, "-c", "import pglast; print(pglast.__version__)"], tmp, env
    ).stdout.strip()
    results = []
    for case in labels["reporting"]:
        results.append(reporting_case(tmp / case["id"], case, defaults, env))
    for case in labels["controls"]:
        report = tmp / (case["id"] + ".json")
        report.write_text(
            json.dumps(
                {
                    case["category"]: [
                        {
                            "file": "app.py",
                            "line": 1,
                            "rule_id": case["rule_id"],
                            "severity": case.get("severity", "MEDIUM"),
                            "message": "fixture",
                        }
                    ]
                }
            )
        )
        lines = annotation_lines(tmp, env, report)
        results.append(
            record(
                case,
                {"finding_annotations": sum(case["rule_id"] in line for line in lines)},
            )
        )
    # Discover the fingerprint for the independently specified exception using the
    # documented CLI. The policy being tested is committed to the base revision.
    fingerprints = {}
    for case in labels["policy"]:
        exception = case.get("exception")
        if exception and not args.legacy_advisory and exception not in fingerprints:
            project, base, head = fixture(
                tmp / ("calibrate-" + case["id"]), {"after": exception}, defaults, env
            )
            fingerprints[exception] = decide(project, env, base, head)["violations"][0][
                "fingerprint"
            ]
        project, base, head = fixture(
            tmp / case["id"], case, defaults, env, fingerprints.get(exception)
        )
        test_env = env
        if case.get("parser") is False:
            test_env = {
                **env,
                "PYTHONPATH": str(missing) + os.pathsep + env["PYTHONPATH"],
            }
        if args.legacy_advisory:
            report = scan(project, test_env)
            proc = command(
                [*CLI, "cicd", "gate", "--input", str(report), "--advisory"],
                project,
                test_env,
                codes=(0, 1),
            )
            outcome = "fail" if proc.returncode else "pass"
            results.append(record(case, {"outcome": outcome}))
        else:
            decision = decide(project, test_env, base, head)
            row = record(case, {"outcome": decision["status"]})
            row["checked_files"] = decision["checked_files"]
            row["violations"] = len(decision["violations"])
            row["unchecked_files"] = len(decision["unchecked_files"])
            results.append(row)
    return {
        "manifest_sha256": FROZEN,
        "pglast": parser_version,
        "policy_command": "gate --advisory"
        if args.legacy_advisory
        else "postgres-check",
        "matches": sum(row["matched"] for row in results),
        "total": len(results),
        "cases": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner-root", type=Path, required=True)
    parser.add_argument("--legacy-advisory", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        result = run(args, Path(tmp).resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['matches']}/{result['total']} matched")
    print(
        "Mismatches:",
        ", ".join(row["id"] for row in result["cases"] if not row["matched"]),
    )
    if not args.legacy_advisory and result["matches"] != result["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
