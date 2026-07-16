from __future__ import annotations

import json
import math
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from skylos.rules.ai_defect.dependency_truth import (
    LEGACY_STATUS_EXISTS,
    DependencyTruthState,
    dependency_truth_cache_key,
    normalize_dependency_truth_state,
)
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
    "security_regression": "Generated code introduces exploitable security flaws.",
    "precision_guard": "Clean generated code should remain free of AI-defect findings.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}
BENCHMARK_LANGUAGES = {
    "go",
    "javascript",
    "multi",
    "python",
    "typescript",
}
DEPENDENCY_STATUS_VALUES = {
    LEGACY_STATUS_EXISTS,
    *(state.value for state in DependencyTruthState),
}

VerifyFunc = Callable[..., dict[str, Any]]
ComparisonFunc = Callable[[str, Path, dict[str, Any]], dict[str, Any]]


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
    challenge_func: Callable[..., Any] | None = None,
    comparison_tools: list[str] | tuple[str, ...] | None = None,
    comparison_func: ComparisonFunc | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = load_manifest(manifest_file)
    cases = validate_manifest(manifest, manifest_file)
    selected = _selected_cases(selected_cases)
    runner = _verify_runner(verify_func)
    requested_comparison_tools = _comparison_tool_names(comparison_tools)

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

        case_summary = _run_case(
            manifest_file.parent,
            case,
            runner,
            challenge_func=challenge_func,
            comparison_tools=requested_comparison_tools,
            comparison_func=comparison_func,
        )
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

    summary = {
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
    metadata = _benchmark_metadata(summary_cases)
    if metadata:
        summary["metadata"] = metadata
    return summary


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
    metadata = summary.get("metadata")
    if isinstance(metadata, dict):
        evidence = metadata.get("evidence_contracts")
        if isinstance(evidence, dict):
            lines.append(
                "AI-code defect evidence-contract coverage: "
                f"{float(evidence.get('coverage_rate', 0.0)):.2f} "
                f"({int(evidence.get('with_contract', 0))}/"
                f"{int(evidence.get('finding_count', 0))})"
            )
        runtime = metadata.get("runtime")
        if isinstance(runtime, dict):
            lines.append(
                "AI-code defect benchmark runtime: "
                f"mean {float(runtime.get('mean_seconds', 0.0)):.2f}s, "
                f"p95 {float(runtime.get('p95_seconds', 0.0)):.2f}s"
            )
        challenge = metadata.get("challenge")
        if isinstance(challenge, dict):
            counts = challenge.get("outcome_counts")
            if isinstance(counts, dict):
                lines.append(
                    "AI-code defect challenge outcomes: "
                    f"accepted={int(counts.get('accepted', 0))}, "
                    f"refuted={int(counts.get('refuted', 0))}, "
                    f"uncertain={int(counts.get('uncertain', 0))}"
                )
        external_comparisons = metadata.get("external_comparisons")
        if isinstance(external_comparisons, dict):
            requested = external_comparisons.get("requested_tools")
            if isinstance(requested, list):
                requested_label = ", ".join(str(tool) for tool in requested)
            else:
                requested_label = "<none>"
            lines.append(
                "AI-code defect external comparisons: "
                f"{requested_label}, executed cases "
                f"{int(external_comparisons.get('executed_case_count', 0))}, "
                f"results {int(external_comparisons.get('result_count', 0))}"
            )

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
    _validate_language(case, case_id)
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


def _validate_language(case: dict[str, Any], case_id: str) -> None:
    language = case.get("language")
    if language is None:
        return
    if not isinstance(language, str) or language not in BENCHMARK_LANGUAGES:
        allowed = ", ".join(sorted(BENCHMARK_LANGUAGES))
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} language must be one of: {allowed}"
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

    metadata = expectation.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError(
                f"AI-code-defect benchmark case {case_id} expect.{mode} metadata "
                "must be an object"
            )
        for key, value in metadata.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(
                    f"AI-code-defect benchmark case {case_id} expect.{mode} "
                    "metadata keys must be non-empty strings"
                )
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"AI-code-defect benchmark case {case_id} expect.{mode} "
                    f"metadata.{key} must be a non-empty string"
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
    _validate_optional_scan_bool(scan, case_id, "dependency_hallucinations")
    _validate_optional_scan_bool(scan, case_id, "security_findings")
    if "danger" in scan:
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} uses legacy scan.danger; "
            "use scan.security_findings for static security benchmark cases"
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


def _validate_optional_scan_bool(
    scan: dict[str, Any],
    case_id: str,
    key: str,
) -> None:
    value = scan.get(key)
    if value is None:
        return
    if not isinstance(value, bool):
        raise ValueError(
            f"AI-code-defect benchmark case {case_id} scan.{key} must be a boolean"
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


def _comparison_tool_names(
    comparison_tools: list[str] | tuple[str, ...] | None,
) -> list[str]:
    if comparison_tools is None:
        return []

    names: list[str] = []
    seen: set[str] = set()
    for tool_name in comparison_tools:
        if not isinstance(tool_name, str):
            raise ValueError("external comparison tool names must be strings")
        name = tool_name.strip()
        if not name:
            raise ValueError("external comparison tool names must be non-empty")
        if name in seen:
            continue
        names.append(name)
        seen.add(name)
    return names


def _run_case(
    manifest_root: Path,
    case: dict[str, Any],
    verify_func: VerifyFunc,
    *,
    challenge_func: Callable[..., Any] | None = None,
    comparison_tools: list[str] | None = None,
    comparison_func: ComparisonFunc | None = None,
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
            include_security_findings=_include_security_findings_scan(scan),
            contract_path=_contract_path_scan(scan),
        )
        challenge_metadata = _challenge_metadata_for_case(
            result,
            run_case_path,
            challenge_func=challenge_func,
        )
        comparison_metadata = _comparison_metadata_for_case(
            case,
            run_case_path,
            comparison_tools=comparison_tools,
            comparison_func=comparison_func,
        )
        elapsed = time.perf_counter() - started
    finally:
        if temp_case is not None:
            temp_case.cleanup()

    findings = _findings(result)
    failures, counts = _evaluate_case(case, result)
    case_summary = {
        "id": case["id"],
        "path": case["path"],
        "language": case.get("language", "unlabelled"),
        "taxonomy": list(case["taxonomy"]),
        "importance": case.get("importance", "high"),
        "elapsed_seconds": elapsed,
        "finding_count": len(findings),
        "failures": [failure.to_dict() for failure in failures],
        "present_total": counts["present_total"],
        "present_matched": counts["present_matched"],
        "absent_total": counts["absent_total"],
        "absent_violations": counts["absent_violations"],
        "evidence_contracts": _case_evidence_contract_metadata(findings),
    }
    case_metadata = {}
    if challenge_metadata:
        case_metadata.update(challenge_metadata)
    if comparison_metadata:
        case_metadata["external_comparisons"] = comparison_metadata
    if case_metadata:
        case_summary["metadata"] = case_metadata
    return case_summary


def _include_dependency_hallucination_scan(scan: dict[str, Any]) -> bool:
    return bool(scan.get("dependency_hallucinations", False))


def _include_security_findings_scan(scan: dict[str, Any]) -> bool:
    return bool(scan.get("security_findings", False))


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
        and not _include_security_findings_scan(scan)
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
        statuses[key] = normalize_dependency_truth_state(entry["status"]).value

    payload = {
        "schema_version": VERSION_CACHE_SCHEMA_VERSION,
        "statuses": statuses,
    }
    cache_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _dependency_status_key(entry: dict[str, Any]) -> str:
    ecosystem = str(entry["ecosystem"])
    name = str(entry["name"])
    version = str(entry["version"])
    return dependency_truth_cache_key(ecosystem, name, version)


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


def _challenge_metadata_for_case(
    result: dict[str, Any],
    run_case_path: Path,
    *,
    challenge_func: Callable[..., Any] | None,
) -> dict[str, Any]:
    if challenge_func is None:
        return {}

    from skylos.llm.harness.ai_defect_challenge import (
        run_ai_defect_challenge_harness,
    )

    findings = _findings(result)
    project_root = run_case_path.parent if run_case_path.is_file() else run_case_path
    challenge = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=project_root,
        challenge_func=challenge_func,
        harness_run_id="ai-code-defect-benchmark",
        write_traces=False,
    )
    output = challenge.output
    if not isinstance(output, dict):
        return {}
    metadata = output.get("challenge")
    if not isinstance(metadata, dict):
        return {}
    return {"challenge": metadata}


def _comparison_metadata_for_case(
    case: dict[str, Any],
    run_case_path: Path,
    *,
    comparison_tools: list[str] | None,
    comparison_func: ComparisonFunc | None,
) -> dict[str, Any]:
    tools = comparison_tools or []
    if not tools:
        return {}

    metadata: dict[str, Any] = {
        "schema_version": 1,
        "requested_tools": list(tools),
        "executed": False,
        "results": [],
    }
    if comparison_func is None:
        metadata["reason"] = "no_comparison_runner"
        return metadata

    results = []
    for tool_name in tools:
        result = comparison_func(tool_name, run_case_path, case)
        if not isinstance(result, dict):
            raise ValueError("external comparison runner must return a dict")
        entry = dict(result)
        entry["tool"] = tool_name
        results.append(entry)

    metadata["executed"] = True
    metadata["results"] = results
    return metadata


def _benchmark_metadata(summary_cases: list[dict[str, Any]]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    challenge = _challenge_benchmark_metadata(summary_cases)
    if challenge:
        metadata["challenge"] = challenge
    comparisons = _external_comparison_benchmark_metadata(summary_cases)
    if comparisons:
        metadata["external_comparisons"] = comparisons
    metadata["evidence_contracts"] = _evidence_contract_metadata(summary_cases)
    metadata["runtime"] = _runtime_metadata(summary_cases)
    metadata["languages"] = _language_metadata(summary_cases)
    return metadata


def _language_metadata(summary_cases: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    labelled = 0
    for case in summary_cases:
        language = str(case.get("language") or "unlabelled")
        counts[language] = counts.get(language, 0) + 1
        if language != "unlabelled":
            labelled += 1
    total = len(summary_cases)
    return {
        "case_counts": dict(sorted(counts.items())),
        "labelled_cases": labelled,
        "total_cases": total,
        "coverage_rate": (labelled / total) if total else 1.0,
    }


def _challenge_benchmark_metadata(summary_cases: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    challenged_cases = 0
    for case in summary_cases:
        metadata = case.get("metadata")
        if not isinstance(metadata, dict):
            continue
        challenge = metadata.get("challenge")
        if not isinstance(challenge, dict):
            continue
        outcome_counts = challenge.get("outcome_counts")
        if not isinstance(outcome_counts, dict):
            continue
        challenged_cases += 1
        for key, value in outcome_counts.items():
            if isinstance(value, int):
                counts[key] = counts.get(key, 0) + value

    if not challenged_cases:
        return {}
    return {
        "schema_version": 1,
        "case_count": challenged_cases,
        "outcome_counts": counts,
        "refutation_accuracy": _ratio(
            float(counts.get("suppression_allowed", 0)),
            float(counts.get("refuted", 0)),
        ),
    }


def _external_comparison_benchmark_metadata(
    summary_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    requested_tools: list[str] = []
    seen_tools: set[str] = set()
    case_count = 0
    executed_case_count = 0
    skipped_case_count = 0
    result_count = 0
    reason_counts: dict[str, int] = {}
    tool_result_counts: dict[str, int] = {}

    for case in summary_cases:
        metadata = case.get("metadata")
        if not isinstance(metadata, dict):
            continue
        comparisons = metadata.get("external_comparisons")
        if not isinstance(comparisons, dict):
            continue

        case_count += 1
        tools = comparisons.get("requested_tools")
        if isinstance(tools, list):
            for tool_name in tools:
                tool = str(tool_name)
                if tool in seen_tools:
                    continue
                requested_tools.append(tool)
                seen_tools.add(tool)

        if comparisons.get("executed") is True:
            executed_case_count += 1
        else:
            skipped_case_count += 1
            reason = str(comparisons.get("reason") or "not_executed")
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

        results = comparisons.get("results")
        if not isinstance(results, list):
            continue
        result_count += len(results)
        for result in results:
            if not isinstance(result, dict):
                continue
            tool = result.get("tool")
            if not isinstance(tool, str) or not tool:
                continue
            tool_result_counts[tool] = tool_result_counts.get(tool, 0) + 1

    if not case_count:
        return {}
    return {
        "schema_version": 1,
        "case_count": case_count,
        "requested_tools": requested_tools,
        "executed_case_count": executed_case_count,
        "skipped_case_count": skipped_case_count,
        "result_count": result_count,
        "reason_counts": reason_counts,
        "tool_result_counts": tool_result_counts,
    }


def _evidence_contract_metadata(summary_cases: list[dict[str, Any]]) -> dict[str, Any]:
    finding_total = 0
    with_contract = 0
    proof_states: dict[str, int] = {}
    for case in summary_cases:
        evidence = case.get("evidence_contracts")
        if not isinstance(evidence, dict):
            continue
        finding_total += int(evidence.get("finding_count") or 0)
        with_contract += int(evidence.get("with_contract") or 0)
        states = evidence.get("proof_states")
        if not isinstance(states, dict):
            continue
        for state, count in states.items():
            if isinstance(count, int):
                proof_states[str(state)] = proof_states.get(str(state), 0) + count
    return {
        "finding_count": finding_total,
        "with_contract": with_contract,
        "coverage_rate": _ratio(float(with_contract), float(finding_total)),
        "proof_states": proof_states,
    }


def _case_evidence_contract_metadata(findings: list[dict[str, Any]]) -> dict[str, Any]:
    with_contract = 0
    proof_states: dict[str, int] = {}
    for finding in findings:
        contract = finding.get("evidence_contract")
        if not isinstance(contract, dict):
            continue
        with_contract += 1
        state = str(contract.get("proof_state") or "unknown")
        proof_states[state] = proof_states.get(state, 0) + 1
    return {
        "finding_count": len(findings),
        "with_contract": with_contract,
        "coverage_rate": _ratio(float(with_contract), float(len(findings))),
        "proof_states": proof_states,
    }


def _runtime_metadata(summary_cases: list[dict[str, Any]]) -> dict[str, Any]:
    elapsed = sorted(
        float(case.get("elapsed_seconds", 0.0))
        for case in summary_cases
        if isinstance(case.get("elapsed_seconds"), int | float)
    )
    if not elapsed:
        return {
            "case_count": 0,
            "min_seconds": 0.0,
            "mean_seconds": 0.0,
            "p95_seconds": 0.0,
            "max_seconds": 0.0,
        }
    return {
        "case_count": len(elapsed),
        "min_seconds": elapsed[0],
        "mean_seconds": sum(elapsed) / len(elapsed),
        "p95_seconds": _percentile(elapsed, 0.95),
        "max_seconds": elapsed[-1],
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = math.ceil(len(values) * fraction) - 1
    index = max(0, min(len(values) - 1, index))
    return values[index]


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
    if not _metadata_expectation_matches(expectation, finding):
        return False
    return True


def _metadata_expectation_matches(
    expectation: dict[str, Any],
    finding: dict[str, Any],
) -> bool:
    expected_metadata = expectation.get("metadata")
    if not isinstance(expected_metadata, dict):
        return True
    finding_metadata = finding.get("metadata")
    if not isinstance(finding_metadata, dict):
        return False
    for key, value in expected_metadata.items():
        if str(finding_metadata.get(key, "")) != value:
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
