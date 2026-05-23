from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze


SECURITY_TAXONOMY: dict[str, str] = {
    "sql_injection": "Untrusted data reaches SQL construction or execution.",
    "command_injection": "Untrusted or unsafe command execution reaches shell/process sinks.",
    "ssrf": "Untrusted data controls outbound request destinations.",
    "path_traversal": "Untrusted path segments reach filesystem sinks.",
    "deserialization": "Untrusted data reaches unsafe deserialization APIs.",
    "xss": "Untrusted data reaches HTML or script rendering sinks.",
    "open_redirect": "Untrusted URLs reach redirect/navigation sinks.",
    "auth_bypass": "Authentication or token verification is bypassed or disabled.",
    "cors": "CORS policy is overly permissive or credential unsafe.",
    "go": "Go security flow and sanitizer patterns.",
    "java": "Java security flow and sanitizer patterns.",
    "javascript": "JavaScript security flow and sanitizer patterns.",
    "rust": "Rust security flow and sanitizer patterns.",
    "typescript": "TypeScript security flow and sanitizer patterns.",
    "precision_guard": "Clean patterns that should stay free of noisy security findings.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

DEFAULT_SCAN = {
    "enable_quality": False,
    "enable_danger": True,
    "enable_secrets": False,
    "grep_verify": False,
}

SUPPORTED_SCANNERS = {"skylos", "bandit"}
SUPPORTED_LANGUAGES = {
    "python",
    "go",
    "java",
    "javascript",
    "typescript",
    "rust",
    "dart",
    "csharp",
}
SCANNER_LANGUAGE_SUPPORT = {
    "skylos": SUPPORTED_LANGUAGES,
    "bandit": {"python"},
}

_BANDIT_TO_SKYLOS_RULE = {
    "B301": "SKY-D204",
    "B302": "SKY-D205",
    "B403": "SKY-D204",
    "B506": "SKY-D206",
    "B602": "SKY-D209",
    "B604": "SKY-D209",
    "B605": "SKY-D209",
    "B606": "SKY-D209",
    "B607": "SKY-D209",
    "B608": "SKY-D211",
    "B310": "SKY-D216",
}


@dataclass(frozen=True)
class SecurityBenchmarkFailure:
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
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_manifest(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("security benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(
            "security benchmark manifest must define a non-empty cases list"
        )

    seen_ids: set[str] = set()
    root = manifest_file.parent
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each security benchmark case must be an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("each security benchmark case must have a non-empty id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate security benchmark case id: {case_id}")
        seen_ids.add(case_id)

        rel_path = case.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(f"security benchmark case {case_id} must declare a path")
        case_path = (root / rel_path).resolve()
        if not case_path.exists():
            raise ValueError(
                f"security benchmark case {case_id} path does not exist: {case_path}"
            )

        taxonomy = case.get("taxonomy")
        if not isinstance(taxonomy, list) or not taxonomy:
            raise ValueError(
                f"security benchmark case {case_id} must declare a non-empty taxonomy list"
            )
        for label in taxonomy:
            if label not in SECURITY_TAXONOMY:
                allowed = ", ".join(sorted(SECURITY_TAXONOMY))
                raise ValueError(
                    f"security benchmark case {case_id} has unknown taxonomy "
                    f"'{label}'. Allowed: {allowed}"
                )

        languages = _case_languages(case)
        for language in languages:
            if language not in SUPPORTED_LANGUAGES:
                allowed = ", ".join(sorted(SUPPORTED_LANGUAGES))
                raise ValueError(
                    f"security benchmark case {case_id} has unsupported language "
                    f"'{language}'. Allowed: {allowed}"
                )

        importance = case.get("importance", "high")
        if importance not in IMPORTANCE_WEIGHTS:
            allowed = ", ".join(sorted(IMPORTANCE_WEIGHTS))
            raise ValueError(
                f"security benchmark case {case_id} importance must be one of: {allowed}"
            )

        source = case.get("source")
        if not isinstance(source, dict):
            raise ValueError(
                f"security benchmark case {case_id} must declare source metadata"
            )
        repo = source.get("repo")
        license_name = source.get("license")
        if not isinstance(repo, str) or not repo.startswith("https://"):
            raise ValueError(
                f"security benchmark case {case_id} must declare an https repo URL"
            )
        if not isinstance(license_name, str) or not license_name.strip():
            raise ValueError(
                f"security benchmark case {case_id} must declare a license"
            )

        scan = case.get("scan", {})
        if scan and not isinstance(scan, dict):
            raise ValueError(
                f"security benchmark case {case_id} scan config must be an object"
            )

        expect = case.get("expect")
        if not isinstance(expect, dict):
            raise ValueError(
                f"security benchmark case {case_id} must declare expectations"
            )
        present = expect.get("present", {})
        absent = expect.get("absent", {})
        if not isinstance(present, dict) or not isinstance(absent, dict):
            raise ValueError(
                f"security benchmark case {case_id} expectations must use present/absent maps"
            )

        total_expectations = 0
        for mode_name, expectation_map in (("present", present), ("absent", absent)):
            for category, expected_values in expectation_map.items():
                if not isinstance(category, str) or not category.strip():
                    raise ValueError(
                        f"security benchmark case {case_id} {mode_name} expectations need string categories"
                    )
                if not isinstance(expected_values, list) or not expected_values:
                    raise ValueError(
                        f"security benchmark case {case_id} {mode_name}.{category} must be a non-empty list"
                    )
                total_expectations += len(expected_values)
                for expected in expected_values:
                    if not isinstance(expected, str) or not expected.strip():
                        raise ValueError(
                            f"security benchmark case {case_id} {mode_name}.{category} has an invalid expected value"
                        )

        if total_expectations == 0:
            raise ValueError(
                f"security benchmark case {case_id} must declare at least one expectation"
            )

        budget = case.get("budget", {})
        if budget:
            if not isinstance(budget, dict):
                raise ValueError(
                    f"security benchmark case {case_id} budget must be an object"
                )
            max_seconds = budget.get("max_seconds")
            if max_seconds is not None:
                if not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
                    raise ValueError(
                        f"security benchmark case {case_id} budget.max_seconds must be a positive number"
                    )

    return cases


def _case_languages(case: dict[str, Any]) -> list[str]:
    raw = case.get("languages")
    if raw is None:
        return ["python"]
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"security benchmark case {case.get('id', '<unknown>')} languages must be a non-empty list"
        )
    languages = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"security benchmark case {case.get('id', '<unknown>')} languages must contain strings"
            )
        languages.append(item.strip().lower())
    return languages


def _scanner_supports_case(scanner: str, case: dict[str, Any]) -> bool:
    supported = SCANNER_LANGUAGE_SUPPORT.get(scanner)
    if supported is None:
        allowed = ", ".join(sorted(SUPPORTED_SCANNERS))
        raise ValueError(
            f"unsupported security benchmark scanner '{scanner}': {allowed}"
        )
    return set(_case_languages(case)).issubset(supported)


def _finding_tokens(finding: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in (
        "rule_id",
        "full_name",
        "simple_name",
        "name",
        "symbol",
        "type",
        "value",
        "message",
        "file",
    ):
        value = finding.get(key)
        if isinstance(value, str) and value:
            tokens.add(value)
            if "/" in value:
                tokens.add(Path(value).name)
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
            enable_danger=bool(scan_cfg.get("enable_danger", True)),
            enable_secrets=bool(scan_cfg.get("enable_secrets", False)),
            grep_verify=bool(scan_cfg.get("grep_verify", False)),
        )
    finally:
        analyzer_logger.setLevel(prev_level)
    return json.loads(raw)


def _scan_bandit_case(
    case_path: Path, scan: dict[str, Any] | None = None
) -> dict[str, Any]:
    bandit = shutil.which("bandit")
    if not bandit:
        raise RuntimeError(
            "bandit scanner is not installed. Install it separately to run "
            "`python scripts/security_benchmark.py --scanner bandit`."
        )

    completed = subprocess.run(
        [bandit, "-r", ".", "-f", "json", "-q"],
        cwd=str(case_path),
        capture_output=True,
        text=True,
        timeout=30.0,
    )
    if completed.returncode not in (0, 1):
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"exit code {completed.returncode}"
        raise RuntimeError(f"bandit benchmark scan failed: {detail}")

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"bandit benchmark scan emitted invalid JSON: {exc}"
        ) from exc

    danger = []
    for finding in payload.get("results", []) or []:
        if not isinstance(finding, dict):
            continue
        test_id = finding.get("test_id")
        if not isinstance(test_id, str):
            continue
        danger.append(
            {
                "rule_id": _BANDIT_TO_SKYLOS_RULE.get(test_id, test_id),
                "bandit_rule_id": test_id,
                "message": finding.get("issue_text", ""),
                "file": finding.get("filename", ""),
                "line": finding.get("line_number", 0),
                "severity": finding.get("issue_severity", ""),
            }
        )
    return {"danger": danger}


def _scan_case_with_scanner(
    case_path: Path,
    scan: dict[str, Any] | None = None,
    *,
    scanner: str,
) -> dict[str, Any]:
    if scanner == "skylos":
        return _scan_case(case_path, scan=scan)
    if scanner == "bandit":
        return _scan_bandit_case(case_path, scan=scan)
    allowed = ", ".join(sorted(SUPPORTED_SCANNERS))
    raise ValueError(f"unsupported security benchmark scanner '{scanner}': {allowed}")


def _count_expectations(expectations: dict[str, list[str]]) -> int:
    return sum(len(items) for items in expectations.values())


def _evaluate_expectations(
    case: dict[str, Any], result: dict[str, Any]
) -> tuple[list[SecurityBenchmarkFailure], int, int, int, int]:
    expect = case.get("expect", {})
    present = expect.get("present", {}) or {}
    absent = expect.get("absent", {}) or {}

    failures: list[SecurityBenchmarkFailure] = []
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

    for mode, expectation_map in (("present", present), ("absent", absent)):
        for category, expected_values in expectation_map.items():
            findings = result.get(category, []) or []
            finding_tokens = [_finding_tokens(finding) for finding in findings]

            for expected in expected_values:
                matched = sorted(
                    {
                        token
                        for tokens in finding_tokens
                        if expected in tokens
                        for token in tokens
                    }
                )

                if mode == "present":
                    if matched:
                        true_positives += 1
                    else:
                        false_negatives += 1
                        failures.append(
                            SecurityBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                category=category,
                                mode=mode,
                                expected=expected,
                                found=[],
                            )
                        )
                else:
                    if matched:
                        false_positives += 1
                        failures.append(
                            SecurityBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                category=category,
                                mode=mode,
                                expected=expected,
                                found=matched,
                            )
                        )
                    else:
                        true_negatives += 1

    return failures, true_positives, false_positives, false_negatives, true_negatives


def _score_counts(
    *,
    true_positives: int,
    false_positives: int,
    false_negatives: int,
    true_negatives: int,
    elapsed_seconds: float,
    max_seconds: float | None,
) -> dict[str, float]:
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives

    precision = (
        1.0 if precision_denominator == 0 else true_positives / precision_denominator
    )
    recall = 1.0 if recall_denominator == 0 else true_positives / recall_denominator
    f1 = (
        1.0
        if precision + recall == 0
        else 2 * precision * recall / (precision + recall)
    )

    absence_denominator = true_negatives + false_positives
    absence_guard = (
        1.0 if absence_denominator == 0 else true_negatives / absence_denominator
    )
    latency_score = (
        1.0
        if max_seconds is None
        else min(max_seconds / max(elapsed_seconds, 1e-9), 1.0)
    )

    overall = (
        (recall * 0.40)
        + (precision * 0.30)
        + (absence_guard * 0.20)
        + (latency_score * 0.10)
    ) * 100.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "absence_guard": round(absence_guard, 4),
        "latency_score": round(latency_score, 4),
        "overall_score": round(overall, 2),
    }


def run_case(
    case: dict[str, Any],
    manifest_path: str | Path,
    *,
    scanner: str = "skylos",
) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = (manifest_root / case["path"]).resolve()

    start = time.perf_counter()
    result = _scan_case_with_scanner(
        case_path,
        scan=case.get("scan"),
        scanner=scanner,
    )
    elapsed_seconds = time.perf_counter() - start

    failures, tp, fp, fn, tn = _evaluate_expectations(case, result)

    max_seconds = (case.get("budget") or {}).get("max_seconds")
    if max_seconds is not None and elapsed_seconds > max_seconds:
        failures.append(
            SecurityBenchmarkFailure(
                case_id=case["id"],
                failure_type="budget",
                category="runtime",
                mode="max_seconds",
                expected=f"{max_seconds:.3f}s",
                found=[f"{elapsed_seconds:.3f}s"],
            )
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
        "languages": _case_languages(case),
        "taxonomy": list(case.get("taxonomy", [])),
        "importance": case.get("importance", "high"),
        "elapsed_seconds": round(elapsed_seconds, 4),
        "findings_by_category": findings_by_category,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "scores": _score_counts(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            elapsed_seconds=elapsed_seconds,
            max_seconds=max_seconds,
        ),
        "failures": [failure.to_dict() for failure in failures],
    }


def _aggregate_scores(
    case_results: list[dict[str, Any]],
) -> tuple[dict[str, float], dict[str, int]]:
    totals = {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
    }
    for result in case_results:
        for key in totals:
            totals[key] += int(result.get(key, 0))

    scores = _score_counts(
        true_positives=totals["true_positives"],
        false_positives=totals["false_positives"],
        false_negatives=totals["false_negatives"],
        true_negatives=totals["true_negatives"],
        elapsed_seconds=0.0,
        max_seconds=None,
    )
    return scores, totals


def run_manifest(
    manifest_path: str | Path,
    selected_cases: set[str] | None = None,
    *,
    scanner: str = "skylos",
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())

    case_results = []
    skipped_cases = []
    taxonomy_totals: dict[str, dict[str, float]] = {}
    total_elapsed = 0.0

    for case in cases:
        if selected and case["id"] not in selected:
            continue
        if not _scanner_supports_case(scanner, case):
            skipped_cases.append(
                {
                    "id": case["id"],
                    "languages": _case_languages(case),
                    "reason": f"{scanner} does not support this case language set",
                }
            )
            continue
        result = run_case(case, manifest_path, scanner=scanner)
        case_results.append(result)
        total_elapsed += result["elapsed_seconds"]

        weight = IMPORTANCE_WEIGHTS[result["importance"]]
        for label in result["taxonomy"]:
            bucket = taxonomy_totals.setdefault(
                label,
                {
                    "case_count": 0.0,
                    "weight": 0.0,
                    "overall_score": 0.0,
                    "failures": 0.0,
                    "true_positives": 0.0,
                    "false_positives": 0.0,
                    "false_negatives": 0.0,
                    "true_negatives": 0.0,
                },
            )
            bucket["case_count"] += 1
            bucket["weight"] += weight
            bucket["overall_score"] += result["scores"]["overall_score"] * weight
            bucket["failures"] += len(result["failures"])
            for count_key in (
                "true_positives",
                "false_positives",
                "false_negatives",
                "true_negatives",
            ):
                bucket[count_key] += result[count_key]

    scores, totals = _aggregate_scores(case_results)
    failure_count = sum(len(case["failures"]) for case in case_results)
    pass_count = sum(1 for case in case_results if not case["failures"])

    taxonomy_summary = {}
    for label, bucket in sorted(taxonomy_totals.items()):
        weight = bucket["weight"] or 1.0
        taxonomy_summary[label] = {
            "description": SECURITY_TAXONOMY[label],
            "case_count": int(bucket["case_count"]),
            "weighted_score": round(bucket["overall_score"] / weight, 2),
            "failure_count": int(bucket["failures"]),
            "true_positives": int(bucket["true_positives"]),
            "false_positives": int(bucket["false_positives"]),
            "false_negatives": int(bucket["false_negatives"]),
            "true_negatives": int(bucket["true_negatives"]),
        }

    return {
        "manifest": str(Path(manifest_path).resolve()),
        "scanner": scanner,
        "case_count": len(case_results),
        "skipped_case_count": len(skipped_cases),
        "skipped_cases": skipped_cases,
        "pass_count": pass_count,
        "failure_count": failure_count,
        "total_elapsed_seconds": round(total_elapsed, 4),
        "counts": totals,
        "scores": scores,
        "taxonomy": taxonomy_summary,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    scores = summary["scores"]
    lines = [
        f"Security benchmark scanner: {summary.get('scanner', 'skylos')}",
        f"Security benchmark cases: {summary['case_count']}",
        f"Security benchmark skipped cases: {summary.get('skipped_case_count', 0)}",
        f"Security benchmark failures: {summary['failure_count']}",
        (
            "Security benchmark counts: "
            f"TP={counts['true_positives']} "
            f"FP={counts['false_positives']} "
            f"FN={counts['false_negatives']} "
            f"TN={counts['true_negatives']}"
        ),
        (
            "Security benchmark metrics: "
            f"precision={scores['precision']} "
            f"recall={scores['recall']} "
            f"f1={scores['f1']} "
            f"absence_guard={scores['absence_guard']} "
            f"latency={scores['latency_score']}"
        ),
        f"Security benchmark score: {scores['overall_score']}/100",
        f"Security benchmark total time: {summary['total_elapsed_seconds']:.4f}s",
    ]

    if summary["taxonomy"]:
        lines.append("Taxonomy:")
        for label, bucket in sorted(summary["taxonomy"].items()):
            lines.append(
                f"  {label}: cases={bucket['case_count']} "
                f"score={bucket['weighted_score']} failures={bucket['failure_count']} "
                f"TP={bucket['true_positives']} FP={bucket['false_positives']} "
                f"FN={bucket['false_negatives']} TN={bucket['true_negatives']}"
            )

    for case in summary["cases"]:
        status = "PASS" if not case["failures"] else "FAIL"
        lines.append(
            f"{status} {case['id']} [{case['importance']}] "
            f"score={case['scores']['overall_score']} "
            f"TP={case['true_positives']} FP={case['false_positives']} "
            f"FN={case['false_negatives']} TN={case['true_negatives']} "
            f"time={case['elapsed_seconds']:.4f}s"
        )
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} "
                f"{failure['category']} -> {failure['expected']} (found: {found})"
            )

    for skipped in summary.get("skipped_cases", []):
        languages = ", ".join(skipped.get("languages", []))
        lines.append(f"SKIP {skipped['id']} [{languages}] {skipped['reason']}")

    return "\n".join(lines)
