from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze


QUALITY_TAXONOMY: dict[str, str] = {
    "api_design": "Parameter shape, call surface, and interface ergonomics.",
    "complexity": "Branching, nesting, and path explosion hotspots.",
    "control_flow": "Inconsistent returns, unreachable code, and path logic mistakes.",
    "exception_handling": "Swallowed errors, broad suppression, and silent failure.",
    "maintainability": "Long functions and patterns that become hard to review or change.",
    "precision_guard": "Clean cases that should stay free of noisy quality findings.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

DEFAULT_SCAN = {
    "enable_quality": True,
    "enable_danger": False,
    "enable_secrets": False,
    "grep_verify": False,
}


@dataclass(frozen=True)
class QualityBenchmarkFailure:
    case_id: str
    failure_type: str
    category: str
    mode: str
    expected: str
    found: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "failure_type": self.failure_type,
            "category": self.category,
            "mode": self.mode,
            "expected": self.expected,
            "found": list(self.found),
        }


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def validate_manifest(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("quality benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(
            "quality benchmark manifest must define a non-empty cases list"
        )

    seen_ids: set[str] = set()
    manifest_root = manifest_file.parent

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each quality benchmark case must be an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("each quality benchmark case must have a non-empty id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate quality benchmark case id: {case_id}")
        seen_ids.add(case_id)

        rel_path = case.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(f"quality benchmark case {case_id} must declare a path")
        case_path = (manifest_root / rel_path).resolve()
        if not case_path.exists():
            raise ValueError(
                f"quality benchmark case {case_id} path does not exist: {case_path}"
            )

        source = case.get("source")
        if not isinstance(source, dict):
            raise ValueError(
                f"quality benchmark case {case_id} must declare source metadata"
            )
        repo = source.get("repo")
        license_name = source.get("license")
        if not isinstance(repo, str) or not repo.startswith("https://"):
            raise ValueError(
                f"quality benchmark case {case_id} must declare an https repo URL"
            )
        if not isinstance(license_name, str) or not license_name.strip():
            raise ValueError(f"quality benchmark case {case_id} must declare a license")

        taxonomy = case.get("taxonomy")
        if not isinstance(taxonomy, list) or not taxonomy:
            raise ValueError(
                f"quality benchmark case {case_id} must declare a non-empty taxonomy list"
            )
        for label in taxonomy:
            if label not in QUALITY_TAXONOMY:
                allowed = ", ".join(sorted(QUALITY_TAXONOMY))
                raise ValueError(
                    f"quality benchmark case {case_id} has unknown taxonomy '{label}'. "
                    f"Allowed: {allowed}"
                )

        importance = case.get("importance", "high")
        if importance not in IMPORTANCE_WEIGHTS:
            allowed = ", ".join(sorted(IMPORTANCE_WEIGHTS))
            raise ValueError(
                f"quality benchmark case {case_id} importance must be one of: {allowed}"
            )

        expect = case.get("expect")
        if not isinstance(expect, dict):
            raise ValueError(
                f"quality benchmark case {case_id} must declare expectations"
            )

        absent = expect.get("absent", {})
        present = expect.get("present", {})
        if not isinstance(absent, dict) or not isinstance(present, dict):
            raise ValueError(
                f"quality benchmark case {case_id} expectations must use absent/present maps"
            )

        total_expectations = 0
        for mode_name, expectation_map in (("absent", absent), ("present", present)):
            for category, symbols in expectation_map.items():
                if not isinstance(category, str) or not category.strip():
                    raise ValueError(
                        f"quality benchmark case {case_id} {mode_name} expectations need string categories"
                    )
                if not isinstance(symbols, list) or not symbols:
                    raise ValueError(
                        f"quality benchmark case {case_id} {mode_name}.{category} must be a non-empty list"
                    )
                total_expectations += len(symbols)
                for symbol in symbols:
                    if not isinstance(symbol, str) or not symbol.strip():
                        raise ValueError(
                            f"quality benchmark case {case_id} {mode_name}.{category} has an invalid symbol"
                        )

        if total_expectations == 0:
            raise ValueError(
                f"quality benchmark case {case_id} must declare at least one expectation"
            )

        budget = case.get("budget", {})
        if budget:
            if not isinstance(budget, dict):
                raise ValueError(
                    f"quality benchmark case {case_id} budget must be an object"
                )
            max_seconds = budget.get("max_seconds")
            if max_seconds is not None:
                if not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
                    raise ValueError(
                        f"quality benchmark case {case_id} budget.max_seconds must be a positive number"
                    )

        scan = case.get("scan", {})
        if scan and not isinstance(scan, dict):
            raise ValueError(
                f"quality benchmark case {case_id} scan configuration must be an object"
            )

    return cases


def _finding_tokens(finding: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("full_name", "simple_name", "name", "rule_id", "type", "value"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            tokens.add(value)
    return tokens


def _scan_case(case_path: Path, scan: dict[str, Any] | None = None) -> dict[str, Any]:
    scan_cfg = dict(DEFAULT_SCAN)
    if scan:
        scan_cfg.update(scan)

    analyzer_logger = logging.getLogger("Skylos")
    prev_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.WARNING)
    try:
        raw = analyze(
            str(case_path),
            conf=0,
            enable_quality=bool(scan_cfg.get("enable_quality", False)),
            enable_danger=bool(scan_cfg.get("enable_danger", False)),
            enable_secrets=bool(scan_cfg.get("enable_secrets", False)),
            grep_verify=bool(scan_cfg.get("grep_verify", False)),
        )
    finally:
        analyzer_logger.setLevel(prev_level)
    return json.loads(raw)


def _count_expectations(expectations: dict[str, list[str]]) -> int:
    return sum(len(symbols) for symbols in expectations.values())


def _evaluate_expectations(
    case: dict[str, Any], result: dict[str, Any]
) -> tuple[list[QualityBenchmarkFailure], int, int, int, int]:
    expect = case.get("expect", {})
    present = expect.get("present", {}) or {}
    absent = expect.get("absent", {}) or {}

    failures: list[QualityBenchmarkFailure] = []
    present_total = _count_expectations(present)
    absent_total = _count_expectations(absent)
    present_matched = 0
    absent_violations = 0

    for mode, expectations in (("present", present), ("absent", absent)):
        for category, symbols in expectations.items():
            findings = result.get(category, []) or []
            finding_tokens = [_finding_tokens(finding) for finding in findings]

            for symbol in symbols:
                matched = sorted(
                    {
                        token
                        for tokens in finding_tokens
                        if symbol in tokens
                        for token in tokens
                    }
                )

                if mode == "present":
                    if matched:
                        present_matched += 1
                    else:
                        failures.append(
                            QualityBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                category=category,
                                mode=mode,
                                expected=symbol,
                                found=[],
                            )
                        )
                else:
                    if matched:
                        absent_violations += 1
                        failures.append(
                            QualityBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                category=category,
                                mode=mode,
                                expected=symbol,
                                found=matched,
                            )
                        )

    return failures, present_total, present_matched, absent_total, absent_violations


def _score_case(
    *,
    present_total: int,
    present_matched: int,
    absent_total: int,
    absent_violations: int,
    elapsed_seconds: float,
    max_seconds: float | None,
) -> dict[str, float]:
    presence_recall = 1.0
    if present_total:
        presence_recall = present_matched / present_total

    absence_guard = 1.0
    if absent_total:
        absence_guard = max(0.0, 1.0 - (absent_violations / absent_total))

    latency_score = 1.0
    if max_seconds is not None:
        latency_score = min(max_seconds / max(elapsed_seconds, 1e-9), 1.0)

    overall = (
        (presence_recall * 0.50) + (absence_guard * 0.35) + (latency_score * 0.15)
    ) * 100.0

    return {
        "presence_recall": round(presence_recall, 4),
        "absence_guard": round(absence_guard, 4),
        "latency_score": round(latency_score, 4),
        "overall_score": round(overall, 2),
    }


def run_case(case: dict[str, Any], manifest_path: str | Path) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = (manifest_root / case["path"]).resolve()

    start = time.perf_counter()
    result = _scan_case(case_path, scan=case.get("scan"))
    elapsed_seconds = time.perf_counter() - start

    (
        failures,
        present_total,
        present_matched,
        absent_total,
        absent_violations,
    ) = _evaluate_expectations(case, result)

    budget = case.get("budget", {}) or {}
    max_seconds = budget.get("max_seconds")
    if max_seconds is not None and elapsed_seconds > max_seconds:
        failures.append(
            QualityBenchmarkFailure(
                case_id=case["id"],
                failure_type="budget",
                category="runtime",
                mode="max_seconds",
                expected=f"{max_seconds:.3f}s",
                found=[f"{elapsed_seconds:.3f}s"],
            )
        )

    scores = _score_case(
        present_total=present_total,
        present_matched=present_matched,
        absent_total=absent_total,
        absent_violations=absent_violations,
        elapsed_seconds=elapsed_seconds,
        max_seconds=max_seconds,
    )

    findings_by_category = {
        key: len(value)
        for key, value in result.items()
        if isinstance(value, list) and value
    }

    return {
        "id": case["id"],
        "path": str(case_path),
        "description": case.get("description", ""),
        "taxonomy": list(case.get("taxonomy", [])),
        "importance": case.get("importance", "high"),
        "elapsed_seconds": round(elapsed_seconds, 4),
        "findings_by_category": findings_by_category,
        "present_total": present_total,
        "present_matched": present_matched,
        "absent_total": absent_total,
        "absent_violations": absent_violations,
        "scores": scores,
        "failures": [failure.to_dict() for failure in failures],
    }


def run_manifest(
    manifest_path: str | Path, selected_cases: set[str] | None = None
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())

    case_results = []
    weighted_scores = {
        "presence_recall": 0.0,
        "absence_guard": 0.0,
        "latency_score": 0.0,
        "overall_score": 0.0,
    }
    taxonomy_totals: dict[str, dict[str, float]] = {}
    total_weight = 0.0
    total_elapsed = 0.0

    for case in cases:
        if selected and case["id"] not in selected:
            continue

        result = run_case(case, manifest_path)
        case_results.append(result)

        weight = IMPORTANCE_WEIGHTS[result["importance"]]
        total_weight += weight
        total_elapsed += result["elapsed_seconds"]

        for score_name, score_value in result["scores"].items():
            weighted_scores[score_name] += score_value * weight

        for label in result["taxonomy"]:
            bucket = taxonomy_totals.setdefault(
                label,
                {
                    "case_count": 0.0,
                    "weight": 0.0,
                    "overall_score": 0.0,
                    "failures": 0.0,
                },
            )
            bucket["case_count"] += 1
            bucket["weight"] += weight
            bucket["overall_score"] += result["scores"]["overall_score"] * weight
            bucket["failures"] += len(result["failures"])

    failure_count = sum(len(case["failures"]) for case in case_results)

    if total_weight:
        aggregate_scores = {
            key: round(value / total_weight, 2)
            for key, value in weighted_scores.items()
        }
    else:
        aggregate_scores = {
            "presence_recall": 0.0,
            "absence_guard": 0.0,
            "latency_score": 0.0,
            "overall_score": 0.0,
        }

    taxonomy_summary = {}
    for label, bucket in sorted(taxonomy_totals.items()):
        weight = bucket["weight"] or 1.0
        taxonomy_summary[label] = {
            "description": QUALITY_TAXONOMY[label],
            "case_count": int(bucket["case_count"]),
            "weighted_score": round(bucket["overall_score"] / weight, 2),
            "failure_count": int(bucket["failures"]),
        }

    pass_count = sum(1 for case in case_results if not case["failures"])
    return {
        "manifest": str(Path(manifest_path).resolve()),
        "case_count": len(case_results),
        "pass_count": pass_count,
        "failure_count": failure_count,
        "total_elapsed_seconds": round(total_elapsed, 4),
        "scores": aggregate_scores,
        "taxonomy": taxonomy_summary,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    scores = summary["scores"]
    lines = [
        f"Quality benchmark cases: {summary['case_count']}",
        f"Quality benchmark failures: {summary['failure_count']}",
        f"Quality benchmark score: {scores['overall_score']}/100",
        (
            "Quality benchmark metrics: "
            f"recall={scores['presence_recall']}, "
            f"absence_guard={scores['absence_guard']}, "
            f"latency={scores['latency_score']}"
        ),
        f"Quality benchmark total time: {summary['total_elapsed_seconds']:.4f}s",
    ]

    if summary["taxonomy"]:
        lines.append("Taxonomy:")
        for label, bucket in sorted(summary["taxonomy"].items()):
            lines.append(
                f"  {label}: cases={bucket['case_count']} "
                f"score={bucket['weighted_score']} failures={bucket['failure_count']}"
            )

    for case in summary["cases"]:
        status = "PASS" if not case["failures"] else "FAIL"
        lines.append(
            f"{status} {case['id']} [{case['importance']}] "
            f"score={case['scores']['overall_score']} "
            f"time={case['elapsed_seconds']:.4f}s"
        )
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} "
                f"{failure['category']} -> {failure['expected']} (found: {found})"
            )

    return "\n".join(lines)
