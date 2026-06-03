from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from skylos.verify_change import verify_change_path


AI_CODE_DEFECT_TAXONOMY: dict[str, str] = {
    "hallucinated_reference": "Generated code references symbols that do not exist.",
    "incomplete_generation": "Generated code leaves stubs or unfinished bodies behind.",
    "dependency_hallucination": "Generated manifests cite packages or versions that do not exist.",
    "api_signature_hallucination": "Generated calls use real packages with invented APIs.",
    "precision_guard": "Clean generated code should remain free of AI-defect findings.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

VerifyFunc = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class AICodeDefectBenchmarkFailure:
    case_id: str
    failure_type: str
    mode: str
    expected: dict[str, Any]
    found: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "failure_type": self.failure_type,
            "mode": self.mode,
            "expected": dict(self.expected),
            "found": [dict(finding) for finding in self.found],
        }


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def validate_manifest(
    manifest: dict[str, Any],
    manifest_path: str | Path,
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("AI-code-defect benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("AI-code-defect benchmark manifest must define cases")
    if not cases:
        raise ValueError("AI-code-defect benchmark manifest must define cases")

    seen_ids: set[str] = set()
    for case in cases:
        _validate_case(case, manifest_file, seen_ids)
    return cases


def run_manifest(
    manifest_path: str | Path,
    *,
    selected_cases: set[str] | None = None,
    verify_func: VerifyFunc | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = load_manifest(manifest_file)
    cases = validate_manifest(manifest, manifest_file)
    selected = _selected_cases(selected_cases)
    runner = _verify_runner(verify_func)

    summary_cases = []
    total_weight = 0.0
    passed_weight = 0.0
    present_total = 0
    present_matched = 0
    absent_total = 0
    absent_violations = 0
    started = time.perf_counter()

    for case in cases:
        if selected is not None:
            if case["id"] not in selected:
                continue

        case_summary = _run_case(manifest_file.parent, case, runner)
        summary_cases.append(case_summary)
        weight = IMPORTANCE_WEIGHTS[case.get("importance", "high")]
        total_weight += weight
        if not case_summary["failures"]:
            passed_weight += weight

        present_total += case_summary["present_total"]
        present_matched += case_summary["present_matched"]
        absent_total += case_summary["absent_total"]
        absent_violations += case_summary["absent_violations"]

    elapsed = time.perf_counter() - started
    failure_count = 0
    for case_summary in summary_cases:
        if case_summary["failures"]:
            failure_count += 1

    return {
        "case_count": len(summary_cases),
        "pass_count": len(summary_cases) - failure_count,
        "failure_count": failure_count,
        "total_elapsed_seconds": elapsed,
        "scores": _scores(
            total_weight=total_weight,
            passed_weight=passed_weight,
            present_total=present_total,
            present_matched=present_matched,
            absent_total=absent_total,
            absent_violations=absent_violations,
        ),
        "cases": summary_cases,
    }


def format_summary(summary: dict[str, Any]) -> str:
    scores = summary.get("scores")
    if not isinstance(scores, dict):
        scores = {}

    lines = [
        "AI-code defect benchmark score: "
        f"{float(scores.get('overall_score', 0.0)):.1f}/100",
        (
            "AI-code defect benchmark cases: "
            f"{summary.get('pass_count', 0)} passed, "
            f"{summary.get('failure_count', 0)} failed"
        ),
        f"AI-code defect benchmark recall: {float(scores.get('recall', 0.0)):.2f}",
        (
            "AI-code defect benchmark absence guard: "
            f"{float(scores.get('absence_guard', 0.0)):.2f}"
        ),
    ]

    for case in summary.get("cases", []):
        if not isinstance(case, dict):
            continue
        status = "PASS"
        if case.get("failures"):
            status = "FAIL"
        lines.append(f"- {case.get('id', '<unknown>')}: {status}")
    return "\n".join(lines)


def _validate_case(
    case: Any,
    manifest_file: Path,
    seen_ids: set[str],
) -> None:
    if not isinstance(case, dict):
        raise ValueError("each AI-code-defect benchmark case must be an object")

    case_id = _required_string(case, "id", "case id")
    if case_id in seen_ids:
        raise ValueError(f"duplicate AI-code-defect benchmark case id: {case_id}")
    seen_ids.add(case_id)

    rel_path = _required_string(case, "path", f"case {case_id} path")
    case_path = (manifest_file.parent / rel_path).resolve()
    if not case_path.exists():
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} path does not exist: {case_path}"
        )

    _validate_taxonomy(case, case_id)
    _validate_importance(case, case_id)
    _validate_source(case, case_id)
    _validate_expectations(case, case_id)
    _validate_scan(case, case_id)


def _required_string(case: dict[str, Any], key: str, label: str) -> str:
    value = case.get(key)
    if not isinstance(value, str):
        raise ValueError(f"AI-code-defect benchmark {label} must be a string")
    if not value.strip():
        raise ValueError(f"AI-code-defect benchmark {label} must be non-empty")
    return value


def _validate_taxonomy(case: dict[str, Any], case_id: str) -> None:
    taxonomy = case.get("taxonomy")
    if not isinstance(taxonomy, list):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs taxonomy")
    if not taxonomy:
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs taxonomy")

    for label in taxonomy:
        if label not in AI_CODE_DEFECT_TAXONOMY:
            allowed = ", ".join(sorted(AI_CODE_DEFECT_TAXONOMY))
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} has unknown taxonomy "
                f"'{label}'. Allowed: {allowed}"
            )


def _validate_importance(case: dict[str, Any], case_id: str) -> None:
    importance = case.get("importance", "high")
    if importance in IMPORTANCE_WEIGHTS:
        return
    allowed = ", ".join(sorted(IMPORTANCE_WEIGHTS))
    raise ValueError(
        f"AI-code-defect benchmark case {case_id} importance must be one of: {allowed}"
    )


def _validate_source(case: dict[str, Any], case_id: str) -> None:
    source = case.get("source")
    if not isinstance(source, dict):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs source")

    repo = source.get("repo")
    if not isinstance(repo, str):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs source repo")
    if not repo.startswith("https://"):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs source repo")

    license_name = source.get("license")
    if not isinstance(license_name, str):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs license")
    if not license_name.strip():
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs license")


def _validate_expectations(case: dict[str, Any], case_id: str) -> None:
    expect = case.get("expect")
    if not isinstance(expect, dict):
        raise ValueError(f"AI-code-defect benchmark case {case_id} needs expectations")

    total = 0
    for mode in ("present", "absent"):
        expectations = expect.get(mode)
        if not isinstance(expectations, list):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} must be a list"
            )
        total += len(expectations)
        for expectation in expectations:
            _validate_expectation(expectation, case_id, mode)

    if total == 0:
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} must define expectations"
        )


def _validate_expectation(expectation: Any, case_id: str, mode: str) -> None:
    if not isinstance(expectation, dict):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} expect.{mode} entries must be objects"
        )
    rule_id = expectation.get("rule_id")
    if not isinstance(rule_id, str):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} expect.{mode} needs rule_id"
        )
    if not rule_id.strip():
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} expect.{mode} needs rule_id"
        )
    vibe = expectation.get("vibe_category")
    if vibe is not None:
        if not isinstance(vibe, str):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} vibe_category must be a string"
            )


def _validate_scan(case: dict[str, Any], case_id: str) -> None:
    scan = case.get("scan", {})
    if not isinstance(scan, dict):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan config must be an object"
        )


def _selected_cases(selected_cases: set[str] | None) -> set[str] | None:
    if selected_cases is None:
        return None
    selected = set()
    for case_id in selected_cases:
        selected.add(str(case_id))
    return selected


def _verify_runner(verify_func: VerifyFunc | None) -> VerifyFunc:
    if verify_func is not None:
        return verify_func
    return verify_change_path


def _run_case(
    manifest_root: Path,
    case: dict[str, Any],
    verify_func: VerifyFunc,
) -> dict[str, Any]:
    case_path = (manifest_root / case["path"]).resolve()
    scan = case.get("scan")
    if not isinstance(scan, dict):
        scan = {}

    started = time.perf_counter()
    result = verify_func(
        case_path,
        line_range=scan.get("range"),
        confidence=int(scan.get("confidence", 60)),
        project_context=bool(scan.get("project_context", True)),
        include_dependency_hallucinations=bool(
            scan.get("dependency_hallucinations", False)
        ),
    )
    elapsed = time.perf_counter() - started

    failures, counts = _evaluate_case(case, result)
    return {
        "id": case["id"],
        "path": case["path"],
        "taxonomy": list(case["taxonomy"]),
        "importance": case.get("importance", "high"),
        "elapsed_seconds": elapsed,
        "finding_count": len(_findings(result)),
        "failures": [failure.to_dict() for failure in failures],
        "present_total": counts["present_total"],
        "present_matched": counts["present_matched"],
        "absent_total": counts["absent_total"],
        "absent_violations": counts["absent_violations"],
    }


def _evaluate_case(
    case: dict[str, Any],
    result: dict[str, Any],
) -> tuple[list[AICodeDefectBenchmarkFailure], dict[str, int]]:
    findings = _findings(result)
    failures: list[AICodeDefectBenchmarkFailure] = []
    counts = {
        "present_total": 0,
        "present_matched": 0,
        "absent_total": 0,
        "absent_violations": 0,
    }

    expect = case["expect"]
    for expectation in expect["present"]:
        counts["present_total"] += 1
        matched = _matching_findings(expectation, findings)
        if matched:
            counts["present_matched"] += 1
            continue
        failures.append(
            AICodeDefectBenchmarkFailure(case["id"], "expectation", "present", expectation, [])
        )

    for expectation in expect["absent"]:
        counts["absent_total"] += 1
        matched = _matching_findings(expectation, findings)
        if not matched:
            continue
        counts["absent_violations"] += 1
        failures.append(
            AICodeDefectBenchmarkFailure(
                case["id"],
                "expectation",
                "absent",
                expectation,
                matched,
            )
        )

    return failures, counts


def _findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = result.get("findings")
    if not isinstance(findings, list):
        return []

    safe_findings = []
    for finding in findings:
        if isinstance(finding, dict):
            safe_findings.append(finding)
    return safe_findings


def _matching_findings(
    expectation: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matched = []
    for finding in findings:
        if not _finding_matches(expectation, finding):
            continue
        matched.append(finding)
    return matched


def _finding_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    if finding.get("rule_id") != expectation.get("rule_id"):
        return False

    vibe = expectation.get("vibe_category")
    if vibe is not None:
        if finding.get("vibe_category") != vibe:
            return False
    return True


def _scores(
    *,
    total_weight: float,
    passed_weight: float,
    present_total: int,
    present_matched: int,
    absent_total: int,
    absent_violations: int,
) -> dict[str, float]:
    weighted_pass_rate = _ratio(passed_weight, total_weight)
    recall = _ratio(float(present_matched), float(present_total))
    absence_guard = 1.0
    if absent_total:
        clean_absent = absent_total - absent_violations
        absence_guard = _ratio(float(clean_absent), float(absent_total))

    overall = (weighted_pass_rate * 0.6) + (recall * 0.3) + (absence_guard * 0.1)
    return {
        "overall_score": overall * 100.0,
        "weighted_pass_rate": weighted_pass_rate,
        "recall": recall,
        "absence_guard": absence_guard,
    }


def _ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 1.0
    return numerator / denominator
