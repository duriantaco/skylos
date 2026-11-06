"""Configuration corpus contracts. Unresolved inputs never earn safe credit."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping

from skylos.analyzer import analyze

STATUSES = {"unsafe", "safe", "unknown", "not_applicable"}
RULES = {"SKY-D400", "SKY-D401"}
RESOURCE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*\Z")


def load_manifest(path):
    path = Path(path).resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise ValueError("cloud manifest must declare version 1")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cloud manifest needs cases")
    ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("cloud case must be an object")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in ids:
            raise ValueError("cloud case ids must be unique nonempty strings")
        ids.add(case_id)
        target = case.get("path")
        if not isinstance(target, str) or not target:
            raise ValueError(f"{case_id}: missing fixture path")
        relative = Path(target)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"{case_id}: fixture must be inside manifest directory")
        current = path.parent
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"{case_id}: symlink fixture is not allowed")
        if not current.is_dir():
            raise ValueError(f"{case_id}: missing fixture directory")
        expect = case.get("expect")
        if not isinstance(expect, dict):
            raise ValueError(f"{case_id}: missing expectations")
        parse = expect.get("parse_status", "complete")
        checks = expect.get("checks")
        if parse not in {"complete", "incomplete"} or not isinstance(checks, list):
            raise ValueError(f"{case_id}: invalid parse/check expectations")
        if not checks and parse != "incomplete":
            raise ValueError(f"{case_id}: complete cases need policy expectations")
        seen = set()
        for check in checks:
            if not isinstance(check, dict):
                raise ValueError(f"{case_id}: check must be an object")
            rule, resource, status = (
                check.get(k) for k in ("rule_id", "resource", "status")
            )
            if (
                not isinstance(rule, str)
                or rule not in RULES
                or not isinstance(resource, str)
                or not RESOURCE.fullmatch(resource)
                or status not in STATUSES
            ):
                raise ValueError(f"{case_id}: invalid policy expectation")
            key = (rule, resource)
            if key in seen:
                raise ValueError(f"{case_id}: duplicate policy expectation")
            seen.add(key)
    return manifest


def scan_case(path):
    # Use an isolated snapshot: no enclosing Git/config or dummy app source.
    with tempfile.TemporaryDirectory(prefix="skylos-cloud-corpus-") as tmp:
        target = Path(tmp) / "project"
        shutil.copytree(path, target, symlinks=True)
        return json.loads(
            analyze(
                str(target),
                conf=0,
                enable_danger=True,
                enable_quality=False,
                enable_secrets=False,
                enable_ai_defects=False,
                enable_sca=False,
                enable_dependency_hallucinations=False,
                grep_verify=False,
                grep_cache=False,
                trace_file=False,
            )
        )


def evaluate_case(case, result):
    """Require parser receipts and check/finding agreement, not empty output."""
    failures = []
    expected = case["expect"]
    if not isinstance(result, Mapping):
        return {"id": case["id"], "failures": ["invalid analysis report"], "counts": {}}
    summary = result.get("analysis_summary", {})
    errors = result.get("analysis_errors", [])
    configuration = (
        summary.get("configuration_coverage") if isinstance(summary, Mapping) else None
    )
    coverage = (
        configuration.get("terraform") if isinstance(configuration, Mapping) else None
    )
    if not isinstance(coverage, Mapping):
        coverage = {}
    discovered = coverage.get("files_discovered")
    parsed = coverage.get("files_parsed")
    count_valid = (
        type(discovered) is int
        and discovered > 0
        and type(parsed) is int
        and 0 <= parsed <= discovered
    )
    if not count_valid:
        failures.append("missing or invalid Terraform file coverage")
    resources = coverage.get("resources")
    if type(resources) is not int or resources < len(
        {c["resource"] for c in expected["checks"]}
    ):
        failures.append("missing or invalid Terraform resource coverage")
    parse_status = expected.get("parse_status", "complete")
    if parse_status == "incomplete":
        if (
            coverage.get("status") != "incomplete"
            or not count_valid
            or parsed >= discovered
            or not isinstance(errors, list)
            or not any(
                isinstance(error, Mapping)
                and error.get("kind")
                in {
                    "terraform_parse_error",
                    "terraform_source_read_error",
                    "terraform_parser_unavailable",
                    "terraform_budget_exceeded",
                }
                for error in errors
            )
        ):
            failures.append(
                "malformed input must report incomplete parsing and a diagnostic"
            )
    elif (
        coverage.get("status") != "complete"
        or not count_valid
        or parsed != discovered
        or errors
    ):
        failures.append("Terraform parsing did not complete")
    checks = coverage.get("checks")
    if not isinstance(checks, list) or any(
        not isinstance(c, Mapping)
        or c.get("rule_id") not in RULES
        or c.get("status") not in STATUSES
        or not isinstance(c.get("resource"), str)
        for c in checks
    ):
        failures.append("missing or invalid resource policy checks")
        checks = []
    dangers = result.get("danger", [])
    if not isinstance(dangers, list) or any(
        not isinstance(f, Mapping) for f in dangers
    ):
        failures.append("invalid finding collection")
        dangers = []
    actual = {}
    for check in checks:
        key = (check["rule_id"], check["resource"])
        actual.setdefault(key, []).append(check["status"])
    counts = Counter()
    expected_keys = set()
    for check in expected["checks"]:
        key = (check["rule_id"], check["resource"])
        expected_keys.add(key)
        status = check["status"]
        if actual.get(key) != [status]:
            failures.append(f"{key}: expected {status}, got {actual.get(key, [])}")
            continue
        has_finding = any((f.get("rule_id"), f.get("resource")) == key for f in dangers)
        if has_finding != (status == "unsafe"):
            failures.append(f"{key}: finding disagrees with {status} check")
            continue
        counts[status] += 1
    for finding in dangers:
        key = (finding.get("rule_id"), finding.get("resource"))
        if key[0] in RULES and key not in expected_keys:
            failures.append(f"unexpected finding {key}")
    for key in actual.keys() - expected_keys:
        failures.append(f"unexpected policy check {key}")
    if failures:
        counts.clear()
    return {
        "id": case["id"],
        "failures": failures,
        "counts": dict(counts),
        "parse_status": coverage.get("status"),
        "configuration_coverage": coverage,
        "analysis_errors": errors,
        "findings": dangers,
    }


def run_manifest(path, *, selected_cases=None):
    path = Path(path).resolve()
    manifest = load_manifest(path)
    selected = set(selected_cases or ())
    unknown = selected - {c["id"] for c in manifest["cases"]}
    if unknown:
        raise ValueError(f"unknown cloud case ids: {sorted(unknown)}")
    results = []
    for case in manifest["cases"]:
        if selected and case["id"] not in selected:
            continue
        try:
            result = scan_case(path.parent / case["path"])
            results.append(evaluate_case(case, result))
        except Exception as exc:
            results.append(
                {
                    "id": case["id"],
                    "failures": [f"{type(exc).__name__}: {exc}"],
                    "counts": {},
                }
            )
    totals = Counter()
    for result in results:
        totals.update(result["counts"])
    return {
        "manifest": str(path),
        "case_count": len(results),
        "pass_count": sum(not r["failures"] for r in results),
        "failure_count": sum(len(r["failures"]) for r in results),
        "outcome_counts": {status: totals[status] for status in sorted(STATUSES)},
        "note": "Unknown and not-applicable checks are separate from safe outcomes; these are declaration policies, not deployed-state checks.",
        "cases": results,
    }


def format_summary(summary):
    return "\n".join(
        [
            f"Cloud corpus: {summary['pass_count']}/{summary['case_count']} contracts passed; {summary['failure_count']} failures",
            "Outcomes: "
            + ", ".join(
                f"{key}={value}" for key, value in summary["outcome_counts"].items()
            ),
            summary["note"],
            *[
                f"{case['id']}: {failure}"
                for case in summary["cases"]
                for failure in case["failures"]
            ],
        ]
    )
