from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from skylos.rules.ai_defect.manifest_dependency_hallucination import (
    VERSION_CACHE_PATH,
    VERSION_CACHE_SCHEMA_VERSION,
)
from skylos.verify_change import verify_change_path


AI_CODE_DEFECT_TAXONOMY: dict[str, str] = {
    "hallucinated_reference": "Generated code references symbols that do not exist.",
    "incomplete_generation": "Generated code leaves stubs or unfinished bodies behind.",
    "dependency_hallucination": "Generated manifests cite packages or versions that do not exist.",
    "api_signature_hallucination": "Generated calls use real packages with invented APIs.",
    "assertion_weakening": "Generated test edits weaken assertions instead of preserving behavior.",
    "contract_guardrail": "Generated code violates project-specific AI contract guardrails.",
    "precision_guard": "Clean generated code should remain free of AI-defect findings.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}
DEPENDENCY_STATUS_VALUES = {
    "exists",
    "missing_package",
    "missing_version",
    "unknown",
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

    _validate_expectation_finding_count(expect, case_id)

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


def _validate_expectation_finding_count(
    expect: dict[str, Any],
    case_id: str,
) -> None:
    finding_count = expect.get("finding_count")
    if finding_count is None:
        return
    if not isinstance(finding_count, int):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} expect.finding_count "
            "must be an integer"
        )
    if finding_count < 0:
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} expect.finding_count "
            "must not be negative"
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
                f"AI-code-defect benchmark case {case_id} expect.{mode} "
                "vibe_category must be a string"
            )

    min_count = expectation.get("min_count")
    if min_count is not None:
        if not isinstance(min_count, int):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} "
                "min_count must be an integer"
            )
        if min_count < 1:
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} "
                "min_count must be at least 1"
            )

    string_keys = (
        "message_contains",
        "file_contains",
        "category",
        "severity",
        "ai_likelihood",
        "contract_clause",
    )
    for key in string_keys:
        value = expectation.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} {key} must be a string"
            )
        if not value.strip():
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} {key} must be non-empty"
            )

    for key in ("start_line", "end_line"):
        value = expectation.get(key)
        if value is None:
            continue
        if not isinstance(value, int):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} {key} must be an integer"
            )
        if value < 1:
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} {key} must be positive"
            )


def _validate_scan(case: dict[str, Any], case_id: str) -> None:
    scan = case.get("scan", {})
    if not isinstance(scan, dict):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan config must be an object"
    )
    _validate_optional_scan_string(scan, case_id, "file")
    _validate_optional_scan_string(scan, case_id, "range")
    _validate_optional_scan_string(scan, case_id, "contract_path")
    if "danger" in scan:
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} uses legacy scan.danger; "
            "use scan.dependency_hallucinations instead"
        )
    _validate_dependency_statuses(scan, case_id)
    _validate_git_baseline(scan, case_id)


def _validate_optional_scan_string(
    scan: dict[str, Any],
    case_id: str,
    key: str,
) -> None:
    value = scan.get(key)
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.{key} must be a string"
        )
    if not value.strip():
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.{key} must be non-empty"
        )


def _validate_dependency_statuses(scan: dict[str, Any], case_id: str) -> None:
    dependency_statuses = scan.get("dependency_statuses")
    if dependency_statuses is None:
        return
    if not isinstance(dependency_statuses, list):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.dependency_statuses "
            "must be a list"
        )

    for entry in dependency_statuses:
        _validate_dependency_status_entry(entry, case_id)


def _validate_dependency_status_entry(entry: Any, case_id: str) -> None:
    if not isinstance(entry, dict):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} dependency status entries "
            "must be objects"
        )

    for key in ("ecosystem", "name", "version", "status"):
        value = entry.get(key)
        if not isinstance(value, str):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} dependency status "
                f"needs string {key}"
            )
        if not value.strip():
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} dependency status "
                f"needs non-empty {key}"
            )

    if entry["status"] in DEPENDENCY_STATUS_VALUES:
        return

    allowed = ", ".join(sorted(DEPENDENCY_STATUS_VALUES))
    raise ValueError(
        f"AI-code-defect benchmark case {case_id} dependency status must be "
        f"one of: {allowed}"
    )


def _validate_git_baseline(scan: dict[str, Any], case_id: str) -> None:
    baseline = scan.get("git_baseline")
    if baseline is None:
        return
    if not isinstance(baseline, dict):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.git_baseline must be an object"
        )
    if not baseline:
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.git_baseline must not be empty"
        )
    for rel_path, content in baseline.items():
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} git baseline paths must be non-empty strings"
            )
        if Path(rel_path).is_absolute() or ".." in Path(rel_path).parts:
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} git baseline paths must stay inside the fixture"
            )
        if not isinstance(content, str):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} git baseline content must be strings"
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

    run_case_path, temp_case = _prepared_case_path(case_path, scan)
    started = time.perf_counter()
    try:
        result = verify_func(
            run_case_path,
            file=scan.get("file"),
            line_range=scan.get("range"),
            confidence=int(scan.get("confidence", 60)),
            project_context=bool(scan.get("project_context", True)),
            include_dependency_hallucinations=_include_dependency_hallucination_scan(
                scan
            ),
            contract_path=_contract_path_scan(scan),
        )
        elapsed = time.perf_counter() - started
    finally:
        if temp_case is not None:
            temp_case.cleanup()

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


def _include_dependency_hallucination_scan(scan: dict[str, Any]) -> bool:
    return bool(scan.get("dependency_hallucinations", False))


def _contract_path_scan(scan: dict[str, Any]) -> str | None:
    contract_path = scan.get("contract_path")
    if isinstance(contract_path, str):
        return contract_path
    return None


def _prepared_case_path(
    case_path: Path,
    scan: dict[str, Any],
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    dependency_statuses = _dependency_status_entries(scan)
    git_baseline = _git_baseline_entries(scan)
    if (
        not dependency_statuses
        and not git_baseline
        and not _include_dependency_hallucination_scan(scan)
    ):
        return case_path, None

    temp_case = tempfile.TemporaryDirectory(prefix="skylos-ai-defect-")
    prepared_path = Path(temp_case.name) / case_path.name
    if case_path.is_dir():
        shutil.copytree(case_path, prepared_path)
    else:
        prepared_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(case_path, prepared_path)

    if dependency_statuses:
        _write_dependency_status_cache(prepared_path, dependency_statuses)
    if git_baseline:
        _prepare_git_baseline(prepared_path, git_baseline)
    return prepared_path, temp_case


def _dependency_status_entries(scan: dict[str, Any]) -> list[dict[str, Any]]:
    entries = scan.get("dependency_statuses")
    if not isinstance(entries, list):
        return []

    statuses: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            statuses.append(entry)
    return statuses


def _git_baseline_entries(scan: dict[str, Any]) -> dict[str, str]:
    baseline = scan.get("git_baseline")
    if not isinstance(baseline, dict):
        return {}
    entries: dict[str, str] = {}
    for rel_path, content in baseline.items():
        if isinstance(rel_path, str) and isinstance(content, str):
            entries[rel_path] = content
    return entries


def _prepare_git_baseline(case_path: Path, git_baseline: dict[str, str]) -> None:
    current_contents: dict[str, str | None] = {}
    for rel_path in git_baseline:
        target = case_path / rel_path
        if target.exists():
            current_contents[rel_path] = target.read_text(encoding="utf-8")
        else:
            current_contents[rel_path] = None

    for rel_path, content in git_baseline.items():
        target = case_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    _run_git(case_path, "init")
    _run_git(case_path, "config", "user.email", "benchmarks@skylos.dev")
    _run_git(case_path, "config", "user.name", "Skylos Benchmark")
    _run_git(case_path, "add", ".")
    _run_git(case_path, "commit", "-m", "baseline")

    for rel_path, content in current_contents.items():
        target = case_path / rel_path
        if content is None:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            continue
        target.write_text(content, encoding="utf-8")


def _run_git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )


def _write_dependency_status_cache(
    case_path: Path,
    dependency_statuses: list[dict[str, Any]],
) -> None:
    if case_path.is_file():
        cache_root = case_path.parent
    else:
        cache_root = case_path

    cache_path = cache_root / VERSION_CACHE_PATH
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, str] = {}
    for entry in dependency_statuses:
        key = _dependency_status_key(entry)
        statuses[key] = str(entry["status"])

    payload = {
        "schema_version": VERSION_CACHE_SCHEMA_VERSION,
        "statuses": statuses,
    }
    cache_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _dependency_status_key(entry: dict[str, Any]) -> str:
    ecosystem = str(entry["ecosystem"])
    name = str(entry["name"])
    version = str(entry["version"])
    return f"{ecosystem}:{name}:{version}"


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
    _evaluate_finding_count(case, findings, failures)

    for expectation in expect["present"]:
        counts["present_total"] += 1
        matched = _matching_findings(expectation, findings)
        min_count = _expectation_min_count(expectation)
        if len(matched) >= min_count:
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


def _evaluate_finding_count(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
    failures: list[AICodeDefectBenchmarkFailure],
) -> None:
    expect = case["expect"]
    expected_count = expect.get("finding_count")
    if expected_count is None:
        return
    if len(findings) == expected_count:
        return

    failures.append(
        AICodeDefectBenchmarkFailure(
            case["id"],
            "count",
            "finding_count",
            {"finding_count": expected_count},
            findings,
        )
    )


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

    for key in ("category", "severity", "ai_likelihood", "contract_clause"):
        value = expectation.get(key)
        if not isinstance(value, str):
            continue
        if str(finding.get(key, "")) != value:
            return False

    message_contains = expectation.get("message_contains")
    if isinstance(message_contains, str):
        message = str(finding.get("message", ""))
        if message_contains not in message:
            return False

    file_contains = expectation.get("file_contains")
    if isinstance(file_contains, str):
        finding_range = finding.get("range")
        if not isinstance(finding_range, dict):
            return False
        file_path = str(finding_range.get("file", ""))
        if file_contains not in file_path:
            return False

    if not _range_expectation_matches(expectation, finding):
        return False
    return True


def _expectation_min_count(expectation: dict[str, Any]) -> int:
    value = expectation.get("min_count")
    if isinstance(value, int):
        return value
    return 1


def _range_expectation_matches(
    expectation: dict[str, Any],
    finding: dict[str, Any],
) -> bool:
    finding_range = finding.get("range")
    if not isinstance(finding_range, dict):
        if "start_line" in expectation:
            return False
        if "end_line" in expectation:
            return False
        return True

    for key in ("start_line", "end_line"):
        expected_value = expectation.get(key)
        if expected_value is None:
            continue
        if finding_range.get(key) != expected_value:
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
