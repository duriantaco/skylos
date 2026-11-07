"""Explicit baseline/candidate evaluations of trusted Skylos source checkouts.

Reuses the existing static benchmark graders. No automatic cache, case selection,
model calls, or execution of fixture code is part of this interface.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

from skylos.benchmarks._analysis_validation import analysis_issues
from skylos.benchmarks.eval_identity import (
    environment_identity,
    source_identity,
    write_source_snapshot,
)
from skylos.benchmarks.eval_report import compare_receipts, format_comparison


ROOT = Path(__file__).resolve().parents[2]
SUITES = {"security": "security", "dead-code": "dead_code"}
WORKER_SETTINGS = {
    "SKYLOS_CUSTOM_RULES": "[]",
    "SKYLOS_NO_UPLOAD": "1",
    "SKYLOS_NO_TELEMETRY": "1",
    "PYTHONHASHSEED": "0",
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(_json(value))


def _tree(path: Path) -> dict[str, str]:
    """Fingerprint all fixture inputs; never follow links out of a fixture."""
    if path.is_symlink():
        raise ValueError(f"fixture symlinks are unsupported: {path}")
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    result = {}
    for item in files:
        if item.is_symlink():
            raise ValueError(f"fixture symlinks are unsupported: {item}")
        if item.is_dir():
            continue
        if not item.is_file():
            raise ValueError(f"fixture input is not a regular file: {item}")
        name = item.relative_to(path).as_posix() if path.is_dir() else item.name
        result[name] = hashlib.sha256(item.read_bytes()).hexdigest()
    if not result:
        raise ValueError(f"fixture has no files: {path}")
    return result


def _selected_dataset(manifest: Path, case_ids: list[str]) -> dict[str, Any]:
    if not case_ids or len(case_ids) != len(set(case_ids)):
        raise ValueError("select one or more unique --case IDs")
    document = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("expected a version 1 benchmark manifest")
    cases = document.get("cases")
    if not isinstance(cases, list) or any(not isinstance(c, dict) for c in cases):
        raise ValueError("manifest cases must be objects")
    ids = [case.get("id") for case in cases]
    if any(not isinstance(value, str) for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("manifest case IDs must be unique strings")
    unknown = set(case_ids) - set(ids)
    if unknown:
        raise ValueError("unknown case IDs: " + ", ".join(sorted(unknown)))
    selected = []
    for case in cases:
        if case["id"] not in case_ids:
            continue
        rel = case.get("path")
        if not isinstance(rel, str) or Path(rel).is_absolute():
            raise ValueError("eval fixtures must have manifest-relative paths")
        source = manifest.parent / rel
        if not source.resolve().is_relative_to(manifest.parent.resolve()):
            raise ValueError("eval fixture escapes its manifest directory")
        selected.append({"case": copy.deepcopy(case), "files": _tree(source)})
    return {"version": 1, "cases": selected}


def _freeze_dataset(manifest: Path, dataset: dict[str, Any], output: Path) -> Path:
    frozen_cases = []
    for number, entry in enumerate(dataset["cases"]):
        case = copy.deepcopy(entry["case"])
        source = manifest.parent / case["path"]
        dest = output / "fixtures" / str(number) / source.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, dest)
        else:
            shutil.copy2(source, dest)
        if _tree(source) != entry["files"] or _tree(dest) != entry["files"]:
            raise ValueError("fixture changed while taking its snapshot")
        case["path"] = dest.relative_to(output).as_posix()
        frozen_cases.append(case)
    target = output / "manifest.json"
    _write(target, {"version": 1, "cases": frozen_cases})
    _write(output / "identity.json", dataset)
    return target


def _harness_identity(repo: Path, suite: str) -> str:
    paths = [
        f"skylos/benchmarks/{SUITES[suite]}.py",
        "skylos/benchmarks/_analysis_validation.py",
        "skylos/analysis/errors.py",
        "skylos/benchmarks/eval_identity.py",
        "skylos/benchmarks/eval_report.py",
        "skylos/benchmarks/eval_workflow.py",
        "scripts/eval_check.py",
    ]
    return _digest(
        {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths}
    )


def _relative_file(value: str, fixture_files: dict[str, str]) -> str:
    name = value.replace("\\", "/")
    matches = [rel for rel in fixture_files if name == rel or name.endswith("/" + rel)]
    if matches:
        # Longest relative suffix preserves directories when basenames overlap.
        return max(matches, key=len)
    return name


def _findings(raw: object, suite: str, entry: dict[str, Any]) -> tuple[list, list]:
    if not isinstance(raw, dict):
        return [], ["raw analyzer result is not an object"]
    case = entry["case"]
    if suite == "security":
        scan = case.get("scan") or {}
        categories = {"danger"}
        if scan.get("enable_secrets"):
            categories.add("secrets")
        if scan.get("enable_quality"):
            categories.add("quality")
        for mode in ("present", "absent"):
            categories.update(case.get("expect", {}).get(mode, {}))
    else:
        categories = {
            "unused_functions",
            "unused_classes",
            "unused_variables",
            "unused_imports",
            "unused_parameters",
            "unused_files",
        }
    findings, issues = [], []
    for category in sorted(categories):
        if category not in raw:
            continue
        records = raw[category]
        if not isinstance(records, list):
            issues.append(f"{category} is not a list")
            continue
        for record in records:
            if not isinstance(record, dict):
                issues.append(f"{category} contains a non-object finding")
                continue
            if suite == "dead-code" and (
                not isinstance(record.get("file"), str)
                or not record["file"].strip()
                or (
                    category != "unused_files"
                    and not any(
                        isinstance(record.get(key), str) and record[key].strip()
                        for key in (
                            "full_name",
                            "name",
                            "simple_name",
                            "symbol",
                            "value",
                        )
                    )
                )
            ):
                issues.append(f"{category} finding has no file or symbol identity")
                continue
            finding = {"category": category}
            for key in (
                "rule_id",
                "file",
                "line",
                "col",
                "name",
                "simple_name",
                "full_name",
                "symbol",
                "value",
                "type",
                "severity",
                "confidence",
            ):
                if key in record:
                    finding[key] = (
                        _relative_file(str(record[key]), entry["files"])
                        if key == "file"
                        else record[key]
                    )
            if suite == "security" and not isinstance(finding.get("rule_id"), str):
                issues.append(f"{category} finding has no rule_id")
            findings.append(finding)
    # Deduplicate stable identities; full native records and evidence remain raw.
    findings = [json.loads(value) for value in sorted({_json(f) for f in findings})]
    return findings, issues


def _unresolved(suite: str, case: dict, findings: list, summary: dict) -> list:
    if suite == "dead-code":
        return [
            {"finding": found}
            for failure in summary.get("failures", [])
            if failure.get("failure_type") == "unlabeled"
            for found in failure.get("found", [])
        ]
    covered: dict[str, set[str]] = {}
    for mode in ("present", "absent"):
        for category, labels in case.get("expect", {}).get(mode, {}).items():
            covered.setdefault(category, set()).update(labels)
    unresolved = [
        finding
        for finding in findings
        if finding.get("rule_id") not in covered.get(finding["category"], set())
    ]
    # Presence labels do not adjudicate an arbitrary number of new locations.
    # Keep multiple distinct instances unresolved until finding-level review.
    for category, labels in case.get("expect", {}).get("present", {}).items():
        for label in labels:
            matches = [
                f
                for f in findings
                if f["category"] == category and f.get("rule_id") == label
            ]
            if len(matches) > 1:
                unresolved.extend(f for f in matches if f not in unresolved)
    return unresolved


def _worker_environment(repo: Path) -> dict[str, str]:
    # External config/rule files and injected engine paths are not frozen inputs.
    # Use built-in defaults plus the selected fixture's recorded configuration.
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("SKYLOS_")
    }
    env.update(WORKER_SETTINGS)
    env.update(PYTHONPATH=str(repo), PYTHONDONTWRITEBYTECODE="1")
    return env


def _worker(suite: str, manifest: Path, output: Path) -> int:
    # Only this subprocess imports the analyzer and executes the trusted graders.
    from importlib import import_module

    module = import_module("skylos.benchmarks." + SUITES[suite])
    manifest_cases = json.loads(manifest.read_text())["cases"]
    numbers = {case["id"]: i for i, case in enumerate(manifest_cases)}

    def capture(case_id: str, result: object) -> None:
        _write(output / "cases" / str(numbers[case_id]) / "actual.raw.json", result)

    options = {"capture_result": capture}
    if suite == "dead-code":
        options["strict_labels"] = True
    summary = module.run_manifest(manifest, **options)
    _write(output / "summary.json", summary)
    return 1 if summary["failure_count"] else 0


def _case_reports(dataset: dict, output: Path) -> tuple[list, list[str]]:
    try:
        summary = json.loads((output / "summary.json").read_text())
        summaries = summary["cases"]
        if not isinstance(summaries, list):
            raise ValueError("summary cases must be a list")
        by_id = {case["id"]: case for case in summaries}
        expected = {entry["case"]["id"] for entry in dataset["cases"]}
        if len(by_id) != len(summaries) or set(by_id) != expected:
            raise ValueError("executed case inventory differs from selected inventory")
        if summary.get("skipped_case_count", 0) or summary.get("skipped_cases"):
            raise ValueError("selected cases were skipped")
        if type(summary.get("case_count")) is not int or summary["case_count"] != len(
            expected
        ):
            raise ValueError("summary case_count differs from selected inventory")
        if any(
            not isinstance(case.get("failures"), list)
            or any(not isinstance(failure, dict) for failure in case["failures"])
            for case in summaries
        ):
            raise ValueError("summary failures must be lists of objects")
        if type(summary.get("failure_count")) is not int or summary[
            "failure_count"
        ] != sum(len(case["failures"]) for case in summaries):
            raise ValueError("summary failure_count does not match individual failures")
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [], [f"invalid or missing benchmark summary: {error}"]
    reports = []
    for number, entry in enumerate(dataset["cases"]):
        case_id = entry["case"]["id"]
        scored = by_id[case_id]
        declared_issues = scored.get("analysis_issues")
        issues = (
            list(declared_issues)
            if isinstance(declared_issues, list)
            and all(isinstance(issue, str) for issue in declared_issues)
            else ["case analysis_issues metadata is malformed"]
        )
        if (
            scored.get("scored") is not True
            or scored.get("analysis_status") != "complete"
        ):
            issues.append("case was not completely analyzed and scored")
        try:
            raw = json.loads(
                (output / "cases" / str(number) / "actual.raw.json").read_text()
            )
            issues.extend(analysis_issues(raw, scanner="skylos"))
            findings, finding_issues = _findings(raw, dataset["suite"], entry)
            issues.extend(finding_issues)
        except (OSError, ValueError) as error:
            findings = []
            issues.append(f"raw result unavailable: {error}")
        unresolved = _unresolved(dataset["suite"], entry["case"], findings, scored)
        report = {
            "id": case_id,
            "status": "incomplete"
            if issues
            else "failed"
            if scored["failures"]
            else "passed",
            "failures": scored["failures"],
            "analysis_issues": issues,
            "findings": findings,
            "unresolved_findings": unresolved,
        }
        _write(output / "cases" / str(number) / "actual.normalized.json", report)
        reports.append(report)
    return reports, []


def _artifact_hashes(output: Path) -> dict[str, str]:
    return {
        path.relative_to(output).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }


def load_receipt(path: Path) -> dict:
    if path.is_dir():
        path = path / "receipt.json"
    receipt_bytes = path.read_bytes()
    seal = path.with_suffix(".sha256")
    if (
        not seal.is_file()
        or seal.read_text().strip() != hashlib.sha256(receipt_bytes).hexdigest()
    ):
        raise ValueError("receipt checksum is missing or changed")
    report = json.loads(receipt_bytes)
    if not isinstance(report, dict):
        raise ValueError("receipt must be an object")
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("receipt has no artifact checksums")
    for name, expected in artifacts.items():
        target = path.parent / name
        if Path(name).is_absolute() or not target.resolve().is_relative_to(
            path.parent.resolve()
        ):
            raise ValueError("artifact path escapes the run directory")
        if (
            not target.is_file()
            or hashlib.sha256(target.read_bytes()).hexdigest() != expected
        ):
            raise ValueError(f"artifact missing or changed: {name}")
    return report


def _save_receipt(path: Path, report: dict) -> None:
    _write(path, report)
    with path.with_suffix(".sha256").open("x", encoding="utf-8") as output:
        output.write(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")


def run_evaluation(
    *,
    suite: str,
    manifest: Path,
    case_ids: list[str],
    output: Path,
    phase: str,
    timeout: float = 300.0,
    repo: Path = ROOT,
) -> dict:
    repo, manifest, output = repo.resolve(), manifest.resolve(), output.resolve()
    if output.is_relative_to(repo) and not output.is_relative_to(repo / ".skylos"):
        raise ValueError("local artifacts inside the checkout must be under .skylos")
    dataset = _selected_dataset(manifest, case_ids)
    dataset["suite"] = suite
    source_before = source_identity(repo)
    environment = environment_identity()
    inputs = {
        "dataset_sha256": _digest(dataset),
        "harness_sha256": _harness_identity(repo, suite),
        "environment_sha256": environment["sha256"],
        "options": {
            "scanner": "skylos",
            "strict_labels": suite == "dead-code",
            "worker_settings": WORKER_SETTINGS,
            "inherit_skylos_environment": False,
        },
    }
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    snapshot = _freeze_dataset(manifest, dataset, output / "dataset")
    write_source_snapshot(repo, output / "source.tar.gz", source_before)
    _write(output / "environment.json", environment)
    command = [
        sys.executable,
        "-B",
        str(repo / "scripts/eval_check.py"),
        "_worker",
        "--suite",
        suite,
        "--manifest",
        str(snapshot),
        "--output",
        str(output),
    ]
    errors = []
    env = _worker_environment(repo)
    exit_code = None
    with (
        (output / "stdout.txt").open("x") as stdout,
        (output / "stderr.txt").open("x") as stderr,
    ):
        try:
            process = subprocess.run(
                command,
                cwd=repo,
                env=env,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
            exit_code = process.returncode
            if exit_code not in (0, 1):
                errors.append(
                    f"benchmark worker exited {exit_code}; inspect stderr.txt"
                )
        except subprocess.TimeoutExpired:
            errors.append(f"benchmark worker exceeded {timeout:g}s")
        except OSError as error:
            errors.append(f"benchmark worker could not start: {error}")
    cases, summary_errors = _case_reports(dataset, output)
    errors.extend(summary_errors)
    if not summary_errors and exit_code in (0, 1):
        expected_exit = 1 if any(case["failures"] for case in cases) else 0
        if exit_code != expected_exit:
            errors.append("worker exit status disagrees with recorded grading failures")
    source_after = source_identity(repo)
    unchanged = source_before["snapshot_sha256"] == source_after["snapshot_sha256"]
    if not unchanged:
        errors.append("source changed during execution; rerun against stable inputs")
    try:
        if _selected_dataset(manifest, case_ids) != {
            k: v for k, v in dataset.items() if k != "suite"
        }:
            errors.append("fixture or expectation inputs changed during execution")
    except (ValueError, OSError) as error:
        errors.append(f"fixture or expectation inputs became unavailable: {error}")
    if environment_identity()["sha256"] != environment["sha256"]:
        errors.append("runtime environment changed during execution")
    report = {
        "schema_version": 1,
        "phase": phase,
        "suite": suite,
        "case_ids": [entry["case"]["id"] for entry in dataset["cases"]],
        "inputs": inputs,
        "selection": {
            "manifest": str(manifest),
            "manifest_relative": manifest.relative_to(repo).as_posix()
            if manifest.is_relative_to(repo)
            else None,
            "case_ids": case_ids,
        },
        "source": source_before,
        "source_after": source_after,
        "source_unchanged": unchanged,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "worker_exit_code": exit_code,
        "runtime_errors": errors,
        "cases": cases,
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "artifacts": _artifact_hashes(output),
    }
    _save_receipt(output / "receipt.json", report)
    return report


def _run_summary(report: dict, output: Path) -> tuple[str, int]:
    cases = report["cases"]
    counts = {
        status: sum(case["status"] == status for case in cases)
        for status in ("passed", "failed", "incomplete")
    }
    unresolved = sum(len(case["unresolved_findings"]) for case in cases)
    passed = (
        len(cases) == len(report["case_ids"])
        and not report["runtime_errors"]
        and not counts["failed"]
        and not counts["incomplete"]
        and not unresolved
    )
    lines = [
        f"{report['phase'].capitalize()} eval: {report['suite']} ({len(report['case_ids'])} selected cases)",
        f"Passed: {counts['passed']}; failed: {counts['failed']}; incomplete: {counts['incomplete']}",
        f"Unresolved findings: {unresolved}",
        f"Runtime errors: {len(report['runtime_errors'])}; elapsed: {report['elapsed_seconds']:.2f}s",
        f"Result: {'PASS (selected cases only)' if passed else 'FAIL / INCOMPLETE'}",
        f"Receipt: {output / 'receipt.json'}",
    ]
    return "\n".join(lines), 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("baseline", "candidate"):
        command = sub.add_parser(action)
        command.add_argument("--output", type=Path)
        command.add_argument("--timeout", type=float, default=300.0)
        if action == "baseline":
            command.add_argument("--suite", choices=SUITES, required=True)
            command.add_argument("--manifest", type=Path)
            command.add_argument("--case", action="append", required=True)
        else:
            command.add_argument("--baseline", type=Path, required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    worker = sub.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("--suite", choices=SUITES, required=True)
    worker.add_argument("--manifest", type=Path, required=True)
    worker.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "_worker":
            return _worker(args.suite, args.manifest, args.output)
        if args.action == "compare":
            comparison = compare_receipts(
                load_receipt(args.baseline), load_receipt(args.candidate)
            )
            print(format_comparison(comparison))
            return comparison["exit_code"]
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        before = load_receipt(args.baseline) if args.action == "candidate" else None
        if before is not None:
            if before.get("phase") != "baseline":
                raise ValueError("candidate requires a baseline receipt")
            suite = before["suite"]
            selection = before["selection"]
            manifest = (
                ROOT / selection["manifest_relative"]
                if selection.get("manifest_relative")
                else Path(selection["manifest"])
            )
            case_ids = selection["case_ids"]
        else:
            suite, case_ids = args.suite, args.case
            manifest = (
                args.manifest or ROOT / "benchmarks" / SUITES[suite] / "manifest.json"
            )
        output = (
            args.output
            or ROOT / ".skylos/evals/runs" / f"{time.time_ns()}-{args.action}"
        )
        report = run_evaluation(
            suite=suite,
            manifest=manifest,
            case_ids=case_ids,
            output=output,
            phase=args.action,
            timeout=args.timeout,
        )
        summary, code = _run_summary(report, output)
        print(summary)
        if before is not None:
            comparison = compare_receipts(before, report)
            _write(output / "comparison.json", comparison)
            print(format_comparison(comparison))
            print(f"Comparison details: {output / 'comparison.json'}")
            code = comparison["exit_code"]
        return code
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Eval check could not complete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
