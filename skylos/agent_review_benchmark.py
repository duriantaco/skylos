from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.file_discovery import discover_source_files
from skylos.llm.analyzer import AnalyzerConfig, SkylosLLM
from skylos.llm.repo_activation import build_repo_activation_index


AGENT_REVIEW_TAXONOMY: dict[str, str] = {
    "api_design": "Interface shape and review-worthy API ergonomics.",
    "complexity": "Branching and path-complexity review findings.",
    "concurrency": "Async and concurrency review findings.",
    "control_flow": "Logic and return-path review findings.",
    "exception_handling": "Silent failure and swallowed-exception review findings.",
    "maintainability": "Long or hard-to-review implementation patterns.",
    "precision_guard": "Clean cases that should stay quiet under review.",
    "resource_handling": "Resource lifetime and cleanup review findings.",
    "security": "Cross-file exploitability, trust boundaries, and dangerous sinks.",
    "state_management": "Mutable state and aliasing review findings.",
    "technical_debt": "Repo hotspots with high fan-in, wide APIs, and thin resilience.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

DEFAULT_SCAN_MAX_FILES = 8


@dataclass(frozen=True)
class AgentReviewBenchmarkFailure:
    case_id: str
    failure_type: str
    mode: str
    expected: str
    found: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "failure_type": self.failure_type,
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
        raise ValueError("agent review benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError(
            "agent review benchmark manifest must define a non-empty cases list"
        )

    seen_ids: set[str] = set()
    root = manifest_file.parent
    for case in cases:
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(
                "each agent review benchmark case must have a non-empty id"
            )
        if case_id in seen_ids:
            raise ValueError(f"duplicate agent review benchmark case id: {case_id}")
        seen_ids.add(case_id)

        rel_path = case.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(
                f"agent review benchmark case {case_id} must declare a path"
            )
        case_path = (root / rel_path).resolve()
        if not case_path.exists():
            raise ValueError(
                f"agent review benchmark case {case_id} path does not exist: {case_path}"
            )

        taxonomy = case.get("taxonomy")
        if not isinstance(taxonomy, list) or not taxonomy:
            raise ValueError(
                f"agent review benchmark case {case_id} must declare a taxonomy list"
            )
        for label in taxonomy:
            if label not in AGENT_REVIEW_TAXONOMY:
                allowed = ", ".join(sorted(AGENT_REVIEW_TAXONOMY))
                raise ValueError(
                    f"agent review benchmark case {case_id} has unknown taxonomy '{label}'. Allowed: {allowed}"
                )

        importance = case.get("importance", "high")
        if importance not in IMPORTANCE_WEIGHTS:
            allowed = ", ".join(sorted(IMPORTANCE_WEIGHTS))
            raise ValueError(
                f"agent review benchmark case {case_id} importance must be one of: {allowed}"
            )

        source = case.get("source")
        if not isinstance(source, dict):
            raise ValueError(
                f"agent review benchmark case {case_id} must declare source metadata"
            )

        scan_cfg = case.get("scan", {})
        if scan_cfg and not isinstance(scan_cfg, dict):
            raise ValueError(
                f"agent review benchmark case {case_id} scan config must be an object"
            )
        if isinstance(scan_cfg, dict) and "max_files" in scan_cfg:
            max_files = scan_cfg.get("max_files")
            if not isinstance(max_files, int) or max_files <= 0:
                raise ValueError(
                    f"agent review benchmark case {case_id} scan.max_files must be a positive integer"
                )

        expect = case.get("expect")
        if not isinstance(expect, dict):
            raise ValueError(
                f"agent review benchmark case {case_id} must declare expectations"
            )

        for mode_name in ("present", "absent"):
            expectation_map = expect.get(mode_name, {})
            if not isinstance(expectation_map, dict):
                raise ValueError(
                    f"agent review benchmark case {case_id} expectations must use absent/present maps"
                )
            for category, symbols in expectation_map.items():
                if not isinstance(category, str) or not category.strip():
                    raise ValueError(
                        f"agent review benchmark case {case_id} {mode_name} expectations need string categories"
                    )
                if not isinstance(symbols, list):
                    raise ValueError(
                        f"agent review benchmark case {case_id} {mode_name}.{category} must be a list"
                    )
                for symbol in symbols:
                    if not isinstance(symbol, str) or not symbol.strip():
                        raise ValueError(
                            f"agent review benchmark case {case_id} {mode_name}.{category} has invalid symbol"
                        )

    return cases


def _normalize_symbol(value: str | None) -> str:
    value = (value or "").strip()
    if "." in value and "/" not in value:
        value = value.split(".")[-1]
    return value


def prepare_case_scan(
    case_path: str | Path,
    *,
    max_files: int = DEFAULT_SCAN_MAX_FILES,
) -> dict[str, Any]:
    case_path = Path(case_path).resolve()

    if case_path.is_file():
        return {
            "project_root": case_path.parent,
            "files": [case_path],
            "repo_context_map": {},
            "full_file_review": True,
        }

    if not case_path.is_dir():
        raise ValueError(
            f"benchmark case path is neither file nor directory: {case_path}"
        )

    files = discover_source_files(
        case_path,
        [".py"],
        exclude_folders={"__pycache__", ".git", "venv", ".venv"},
    )
    if not files:
        raise ValueError(f"benchmark case directory has no Python files: {case_path}")

    review_index = build_repo_activation_index(
        files,
        project_root=case_path,
        static_findings={"security": [], "quality": [], "secrets": []},
    )
    selected = review_index.rank_files(max_files=max_files)
    if not selected:
        selected = [Path(path).resolve() for path in files[:max_files]]

    return {
        "project_root": case_path,
        "files": [Path(path).resolve() for path in selected],
        "repo_context_map": review_index.context_map_for(selected),
        "full_file_review": True,
    }


def _scan_case(
    case_path: Path,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
    *,
    case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_cfg = case.get("scan") if isinstance(case, dict) else {}
    max_files = int((scan_cfg or {}).get("max_files") or DEFAULT_SCAN_MAX_FILES)
    prepared = prepare_case_scan(case_path, max_files=max_files)

    config = AnalyzerConfig(
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        quiet=True,
        parallel=False,
        enable_security=True,
        enable_quality=True,
        full_file_review=prepared["full_file_review"],
        smart_filter=False,
        repo_context_map=prepared["repo_context_map"],
    )
    analyzer = SkylosLLM(config)
    result = analyzer.analyze_files(prepared["files"])

    symbols = {
        _normalize_symbol(getattr(finding, "symbol", None))
        for finding in result.findings
        if _normalize_symbol(getattr(finding, "symbol", None))
    }
    return {
        "finding_count": len(result.findings),
        "symbols": sorted(symbols),
        "summary": result.summary,
        "tokens_used": int(result.tokens_used or 0),
        "reviewed_files": [str(path) for path in prepared["files"]],
    }


def _count_expectations(expectations: dict[str, list[str]]) -> int:
    return sum(len(items) for items in expectations.values())


def _evaluate_expectations(case: dict[str, Any], symbols: set[str], finding_count: int):
    expect = case.get("expect", {})
    present = expect.get("present", {}) or {}
    absent = expect.get("absent", {}) or {}

    failures: list[AgentReviewBenchmarkFailure] = []
    present_total = _count_expectations(present)
    absent_total = _count_expectations(absent)
    present_matched = 0
    absent_violations = 0

    for mode, expectation_map in (("present", present), ("absent", absent)):
        for _category, names in expectation_map.items():
            for name in names:
                normalized = _normalize_symbol(name)
                matched = normalized in symbols
                if mode == "present":
                    if matched:
                        present_matched += 1
                    else:
                        failures.append(
                            AgentReviewBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                mode=mode,
                                expected=normalized,
                                found=[],
                            )
                        )
                else:
                    if matched:
                        absent_violations += 1
                        failures.append(
                            AgentReviewBenchmarkFailure(
                                case_id=case["id"],
                                failure_type="expectation",
                                mode=mode,
                                expected=normalized,
                                found=[normalized],
                            )
                        )

    if "precision_guard" in (case.get("taxonomy") or []) and finding_count > 0:
        absent_total += 1
        absent_violations += 1
        failures.append(
            AgentReviewBenchmarkFailure(
                case_id=case["id"],
                failure_type="expectation",
                mode="precision_guard",
                expected="no_findings",
                found=[str(finding_count)],
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
):
    recall = 1.0 if present_total == 0 else present_matched / present_total
    absence_guard = (
        1.0 if absent_total == 0 else max(0.0, 1.0 - (absent_violations / absent_total))
    )
    latency = (
        1.0
        if max_seconds is None
        else min(max_seconds / max(elapsed_seconds, 1e-9), 1.0)
    )
    overall = ((recall * 0.50) + (absence_guard * 0.35) + (latency * 0.15)) * 100.0
    return {
        "recall": round(recall, 4),
        "absence_guard": round(absence_guard, 4),
        "latency_score": round(latency, 4),
        "overall_score": round(overall, 2),
    }


def run_case(
    case: dict[str, Any],
    manifest_path: str | Path,
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = (manifest_root / case["path"]).resolve()

    start = time.perf_counter()
    scan_result = _scan_case(
        case_path,
        model,
        api_key,
        provider,
        base_url,
        case=case,
    )
    elapsed_seconds = time.perf_counter() - start

    failures, present_total, present_matched, absent_total, absent_violations = (
        _evaluate_expectations(
            case, set(scan_result["symbols"]), scan_result["finding_count"]
        )
    )

    max_seconds = (case.get("budget") or {}).get("max_seconds")
    if max_seconds is not None and elapsed_seconds > max_seconds:
        failures.append(
            AgentReviewBenchmarkFailure(
                case_id=case["id"],
                failure_type="budget",
                mode="max_seconds",
                expected=f"{max_seconds:.3f}s",
                found=[f"{elapsed_seconds:.3f}s"],
            )
        )

    return {
        "id": case["id"],
        "importance": case.get("importance", "high"),
        "taxonomy": list(case.get("taxonomy") or []),
        "elapsed_seconds": round(elapsed_seconds, 4),
        "finding_count": scan_result["finding_count"],
        "symbols": scan_result["symbols"],
        "summary": scan_result["summary"],
        "tokens_used": scan_result.get("tokens_used", 0),
        "reviewed_files": scan_result.get("reviewed_files", []),
        "scores": _score_case(
            present_total=present_total,
            present_matched=present_matched,
            absent_total=absent_total,
            absent_violations=absent_violations,
            elapsed_seconds=elapsed_seconds,
            max_seconds=max_seconds,
        ),
        "failures": [failure.to_dict() for failure in failures],
    }


def run_manifest(
    manifest_path: str | Path,
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    selected_cases: set[str] | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())

    case_results = []
    total_elapsed = 0.0
    total_tokens = 0
    total_weight = 0.0
    weighted_scores = {
        "recall": 0.0,
        "absence_guard": 0.0,
        "latency_score": 0.0,
        "overall_score": 0.0,
    }

    for case in cases:
        if selected and case["id"] not in selected:
            continue
        result = run_case(
            case,
            manifest_path,
            model=model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
        )
        case_results.append(result)
        weight = IMPORTANCE_WEIGHTS[result["importance"]]
        total_weight += weight
        total_elapsed += result["elapsed_seconds"]
        total_tokens += int(result.get("tokens_used", 0) or 0)
        for score_name, value in result["scores"].items():
            weighted_scores[score_name] += value * weight

    if total_weight:
        scores = {
            name: round(value / total_weight, 2)
            for name, value in weighted_scores.items()
        }
    else:
        scores = {
            "recall": 0.0,
            "absence_guard": 0.0,
            "latency_score": 0.0,
            "overall_score": 0.0,
        }

    return {
        "manifest": str(Path(manifest_path).resolve()),
        "model": model,
        "case_count": len(case_results),
        "failure_count": sum(len(case["failures"]) for case in case_results),
        "total_elapsed_seconds": round(total_elapsed, 4),
        "total_tokens_used": total_tokens,
        "avg_tokens_per_case": round(total_tokens / len(case_results), 2)
        if case_results
        else 0.0,
        "scores": scores,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Agent review benchmark cases: {summary['case_count']}",
        f"Agent review benchmark failures: {summary['failure_count']}",
        f"Agent review benchmark model: {summary['model']}",
        f"Agent review benchmark score: {summary['scores']['overall_score']}/100",
        (
            "Agent review benchmark metrics: "
            f"recall={summary['scores']['recall']}, "
            f"absence_guard={summary['scores']['absence_guard']}, "
            f"latency={summary['scores']['latency_score']}"
        ),
        f"Agent review benchmark total tokens: {summary.get('total_tokens_used', 0)}",
        f"Agent review benchmark avg tokens/case: {summary.get('avg_tokens_per_case', 0.0)}",
        f"Agent review benchmark total time: {summary['total_elapsed_seconds']:.4f}s",
    ]
    for case in summary["cases"]:
        status = "PASS" if not case["failures"] else "FAIL"
        lines.append(
            f"{status} {case['id']} [{case['importance']}] score={case['scores']['overall_score']} time={case['elapsed_seconds']:.4f}s"
        )
        lines.append(f"  tokens: {case.get('tokens_used', 0)}")
        if case["symbols"]:
            lines.append(f"  symbols: {', '.join(case['symbols'])}")
        if case.get("reviewed_files"):
            reviewed = ", ".join(Path(path).name for path in case["reviewed_files"])
            lines.append(f"  reviewed files: {reviewed}")
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} -> {failure['expected']} (found: {found})"
            )
    return "\n".join(lines)
