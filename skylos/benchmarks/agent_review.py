from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.core.file_discovery import discover_source_files
from skylos.llm.analyzer import AnalyzerConfig, SECURITY_AUDIT_ISSUE, SkylosLLM
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

SECURITY_BENCHMARK_CLASSES: dict[str, str] = {
    "sql_injection": "Tainted input reaches SQL/query construction or execution.",
    "command_injection": "Untrusted input reaches a shell or command-execution sink.",
    "ssrf": "Untrusted input reaches an outbound HTTP or network fetch sink.",
    "path_traversal": "Untrusted path segments reach filesystem read/write/delete sinks.",
    "file_upload": "User-controlled uploads or filenames reach unsafe storage/serving paths.",
    "auth_bypass": "Authentication or token verification is disabled or trivially bypassed.",
    "xss": "Untrusted content reaches HTML/JS rendering without contextual escaping.",
    "open_redirect": "Untrusted URL input reaches redirect/navigation sinks.",
    "deserialization": "Untrusted data reaches unsafe deserialize/load primitives.",
    "archive_extraction": "Archive extraction or unpack flows allow path escape or overwrite.",
    "secrets_exposure": "Secrets, credentials, or agent config are exposed or mishandled.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

DEFAULT_SCAN_MAX_FILES = 8
ALLOWED_SCAN_ISSUE_TYPES = {"quality", "security", "security_audit"}
ALLOWED_AGENT_ROUTES = {"full", "static_first", "static_only"}
SCAN_ISSUE_TYPES_FIELD = "issue_types"


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

        security_classes = case.get("security_classes", [])
        if security_classes not in (None, []) and not isinstance(
            security_classes, list
        ):
            raise ValueError(
                f"agent review benchmark case {case_id} security_classes must be a list when provided"
            )
        if isinstance(security_classes, list):
            invalid_security_classes = [
                label
                for label in security_classes
                if not isinstance(label, str)
                or not label.strip()
                or label not in SECURITY_BENCHMARK_CLASSES
            ]
            if invalid_security_classes:
                allowed = ", ".join(sorted(SECURITY_BENCHMARK_CLASSES))
                raise ValueError(
                    f"agent review benchmark case {case_id} has unknown security class "
                    f"'{invalid_security_classes[0]}'. Allowed: {allowed}"
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
        if isinstance(scan_cfg, dict) and "agent_route" in scan_cfg:
            route = scan_cfg.get("agent_route")
            if not isinstance(route, str) or route not in ALLOWED_AGENT_ROUTES:
                allowed = ", ".join(sorted(ALLOWED_AGENT_ROUTES))
                raise ValueError(
                    f"agent review benchmark case {case_id} scan.agent_route must be one of: {allowed}"
                )
        if isinstance(scan_cfg, dict) and SCAN_ISSUE_TYPES_FIELD in scan_cfg:
            issue_types = scan_cfg.get(SCAN_ISSUE_TYPES_FIELD)
            if not isinstance(issue_types, list) or not issue_types:
                raise ValueError(
                    f"agent review benchmark case {case_id} scan.issue_types must be a non-empty list"
                )
            invalid_issue_types = [
                issue_type
                for issue_type in issue_types
                if not isinstance(issue_type, str) or not issue_type.strip()
            ]
            if invalid_issue_types:
                raise ValueError(
                    f"agent review benchmark case {case_id} scan.issue_types must only contain strings"
                )
            unsupported_issue_types = sorted(
                {
                    issue_type
                    for issue_type in issue_types
                    if issue_type not in ALLOWED_SCAN_ISSUE_TYPES
                }
            )
            if unsupported_issue_types:
                allowed = ", ".join(sorted(ALLOWED_SCAN_ISSUE_TYPES))
                raise ValueError(
                    "agent review benchmark case "
                    f"{case_id} has unsupported scan.issue_types value "
                    f"'{unsupported_issue_types[0]}'. Allowed: {allowed}"
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

        security_present = (expect.get("present") or {}).get("security") or []
        if "security" in taxonomy and security_present and not security_classes:
            raise ValueError(
                f"agent review benchmark case {case_id} must declare security_classes when it expects present security findings"
            )

    return cases


def _normalize_symbol(value: str | None) -> str:
    value = (value or "").strip()
    if "." in value and "/" not in value:
        value = value.split(".")[-1]
    return value


def _is_test_file(path: str | Path) -> bool:
    path = Path(path)
    name = path.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in path.parts
    )


def _review_target_files(files: list[Path]) -> list[Path]:
    targets = [path for path in files if not _is_test_file(path)]
    return targets or files


def _case_agent_route(case: dict[str, Any] | None) -> str:
    if not isinstance(case, dict):
        return "full"
    route = str((case.get("scan") or {}).get("agent_route") or "static_first")
    return route if route in {"full", "static_first", "static_only"} else "full"


def _case_issue_types(case: dict[str, Any] | None) -> list[str]:
    if not isinstance(case, dict):
        return []

    scan_cfg = case.get("scan") or {}
    explicit = list(scan_cfg.get(SCAN_ISSUE_TYPES_FIELD) or [])
    if explicit:
        return explicit

    expect = case.get("expect", {}) or {}
    categories = set((expect.get("present", {}) or {}).keys())
    categories.update((expect.get("absent", {}) or {}).keys())

    issue_types: list[str] = []
    if "security" in categories:
        issue_types.append(SECURITY_AUDIT_ISSUE)
    if categories & {"quality", "bug", "performance", "style", "hallucination"}:
        issue_types.append("quality")
    return issue_types


def _static_route_target_files(
    files: list[Path],
    *,
    issue_types: list[str],
) -> list[Path]:
    analyzer = SkylosLLM(
        AnalyzerConfig(
            quiet=True,
            enable_security=True,
            enable_quality=True,
            agent_route="static_first",
        )
    )
    routed = []
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        static_findings = analyzer._collect_static_agent_findings(
            source,
            str(path),
            issue_types=issue_types or None,
        )
        if analyzer._static_route_complete(
            static_findings,
            issue_types=issue_types or None,
        ):
            routed.append(path)
    return routed


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
    issue_types = _case_issue_types(case)
    prepared = prepare_case_scan(case_path, max_files=max_files)
    reviewed_files = _review_target_files(list(prepared["files"]))
    route = _case_agent_route(case)
    if route == "static_only":
        static_targets = _static_route_target_files(
            reviewed_files,
            issue_types=issue_types,
        )
        if static_targets:
            reviewed_files = static_targets

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
        agent_route=route,
    )
    analyzer = SkylosLLM(config)
    result = analyzer.analyze_files(reviewed_files, issue_types=issue_types or None)

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
        "reviewed_files": [str(path) for path in reviewed_files],
        "context_files": [
            str(path) for path in prepared["files"] if path not in reviewed_files
        ],
        "route_counts": dict(getattr(result, "route_counts", {}) or {}),
    }


def _count_expectations(expectations: dict[str, list[str]]) -> int:
    return sum(len(items) for items in expectations.values())


def _dedupe_labels(labels: list[str] | None) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for label in labels or []:
        if label in seen:
            continue
        seen.add(label)
        ordered.append(label)
    return ordered


def _normalized_expectation_map(case: dict[str, Any], mode: str) -> dict[str, list[str]]:
    expect = case.get("expect", {}) or {}
    expectation_map = expect.get(mode, {}) or {}
    normalized: dict[str, list[str]] = {}
    for category, symbols in expectation_map.items():
        values = [
            _normalize_symbol(symbol)
            for symbol in symbols
            if _normalize_symbol(symbol)
        ]
        if values:
            normalized[category] = values
    return normalized


def _flatten_expectations(expectations: dict[str, list[str]]) -> set[str]:
    return {symbol for symbols in expectations.values() for symbol in symbols}


def _is_clean_precision_guard(case: dict[str, Any]) -> bool:
    present = case.get("expect", {}).get("present", {}) or {}
    return "precision_guard" in (case.get("taxonomy") or []) and not present


def _expectation_diagnostics(
    case: dict[str, Any],
    symbols: set[str],
    finding_count: int,
) -> dict[str, Any]:
    present_by_category = _normalized_expectation_map(case, "present")
    absent_by_category = _normalized_expectation_map(case, "absent")
    expected_present = _flatten_expectations(present_by_category)
    expected_absent = _flatten_expectations(absent_by_category)

    missed_by_category = {
        category: sorted(set(expected) - symbols)
        for category, expected in present_by_category.items()
        if set(expected) - symbols
    }
    absent_violations_by_category = {
        category: sorted(set(expected) & symbols)
        for category, expected in absent_by_category.items()
        if set(expected) & symbols
    }

    precision_guard_noise = (
        _is_clean_precision_guard(case) and int(finding_count or 0) > 0
    )

    return {
        "expected_present": sorted(expected_present),
        "expected_absent": sorted(expected_absent),
        "missed_present": sorted(expected_present - symbols),
        "absent_violations": sorted(expected_absent & symbols),
        "missed_by_category": missed_by_category,
        "absent_violations_by_category": absent_violations_by_category,
        "precision_guard_noise": precision_guard_noise,
        "finding_count": int(finding_count or 0),
        "reported_symbol_count": len(symbols),
    }


def _evaluate_expectations(case: dict[str, Any], symbols: set[str], finding_count: int):
    expect = case.get("expect", {})
    present = expect.get("present", {}) or {}
    absent = expect.get("absent", {}) or {}
    is_clean_precision_guard = _is_clean_precision_guard(case)

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

    if is_clean_precision_guard and finding_count > 0:
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
        "security_classes": _dedupe_labels(case.get("security_classes")),
        "scan_issue_types": list(
            (case.get("scan") or {}).get(SCAN_ISSUE_TYPES_FIELD) or []
        ),
        "elapsed_seconds": round(elapsed_seconds, 4),
        "finding_count": scan_result["finding_count"],
        "symbols": scan_result["symbols"],
        "summary": scan_result["summary"],
        "tokens_used": scan_result.get("tokens_used", 0),
        "reviewed_files": scan_result.get("reviewed_files", []),
        "context_files": scan_result.get("context_files", []),
        "route_counts": scan_result.get("route_counts", {}),
        "scores": _score_case(
            present_total=present_total,
            present_matched=present_matched,
            absent_total=absent_total,
            absent_violations=absent_violations,
            elapsed_seconds=elapsed_seconds,
            max_seconds=max_seconds,
        ),
        "diagnostics": _expectation_diagnostics(
            case,
            set(scan_result["symbols"]),
            scan_result["finding_count"],
        ),
        "failures": [failure.to_dict() for failure in failures],
    }


def _build_security_scorecard(
    case_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    totals: dict[str, dict[str, float]] = {}

    for case in case_results:
        labels = _dedupe_labels(case.get("security_classes"))
        if not labels:
            continue

        weight = IMPORTANCE_WEIGHTS[case["importance"]]
        case_failed = 1.0 if case.get("failures") else 0.0
        case_passed = 0.0 if case_failed else 1.0

        for label in labels:
            bucket = totals.setdefault(
                label,
                {
                    "case_count": 0.0,
                    "pass_count": 0.0,
                    "failed_case_count": 0.0,
                    "weight": 0.0,
                    "overall_score": 0.0,
                },
            )
            bucket["case_count"] += 1
            bucket["pass_count"] += case_passed
            bucket["failed_case_count"] += case_failed
            bucket["weight"] += weight
            bucket["overall_score"] += case["scores"]["overall_score"] * weight

    scorecard = {}
    for label, bucket in sorted(totals.items()):
        case_count = int(bucket["case_count"])
        pass_count = int(bucket["pass_count"])
        scorecard[label] = {
            "description": SECURITY_BENCHMARK_CLASSES[label],
            "case_count": case_count,
            "pass_count": pass_count,
            "failed_case_count": int(bucket["failed_case_count"]),
            "pass_rate": round(pass_count / case_count, 4) if case_count else 0.0,
            "weighted_score": round(
                bucket["overall_score"] / (bucket["weight"] or 1.0), 2
            ),
        }

    return scorecard


def _build_dimension_scorecard(
    case_results: list[dict[str, Any]],
    *,
    field: str,
    descriptions: dict[str, str],
) -> dict[str, dict[str, Any]]:
    totals: dict[str, dict[str, float]] = {}

    for case in case_results:
        labels = _dedupe_labels(case.get(field))
        if not labels:
            continue

        weight = IMPORTANCE_WEIGHTS[case["importance"]]
        diagnostics = case.get("diagnostics", {}) or {}
        missed_count = len(diagnostics.get("missed_present", []) or [])
        noise_count = len(diagnostics.get("absent_violations", []) or [])
        if diagnostics.get("precision_guard_noise"):
            noise_count += 1

        for label in labels:
            bucket = totals.setdefault(
                label,
                {
                    "case_count": 0.0,
                    "pass_count": 0.0,
                    "failed_case_count": 0.0,
                    "weight": 0.0,
                    "overall_score": 0.0,
                    "recall": 0.0,
                    "absence_guard": 0.0,
                    "latency_score": 0.0,
                    "tokens": 0.0,
                    "elapsed_seconds": 0.0,
                    "missed_present": 0.0,
                    "noise": 0.0,
                    "static_only_routes": 0.0,
                    "full_harness_routes": 0.0,
                },
            )
            failed = bool(case.get("failures"))
            bucket["case_count"] += 1
            bucket["pass_count"] += 0.0 if failed else 1.0
            bucket["failed_case_count"] += 1.0 if failed else 0.0
            bucket["weight"] += weight
            bucket["tokens"] += int(case.get("tokens_used", 0) or 0)
            bucket["elapsed_seconds"] += float(case.get("elapsed_seconds", 0.0) or 0.0)
            bucket["missed_present"] += missed_count
            bucket["noise"] += noise_count
            route_counts = case.get("route_counts", {}) or {}
            bucket["static_only_routes"] += int(route_counts.get("static_only", 0) or 0)
            bucket["full_harness_routes"] += int(
                route_counts.get("full_harness", 0) or 0
            ) + int(route_counts.get("static_first_escalated", 0) or 0)
            for score_name in (
                "overall_score",
                "recall",
                "absence_guard",
                "latency_score",
            ):
                bucket[score_name] += case["scores"][score_name] * weight

    scorecard = {}
    for label, bucket in sorted(totals.items()):
        case_count = int(bucket["case_count"])
        weight = bucket["weight"] or 1.0
        scorecard[label] = {
            "description": descriptions.get(label, ""),
            "case_count": case_count,
            "pass_count": int(bucket["pass_count"]),
            "failed_case_count": int(bucket["failed_case_count"]),
            "weighted_score": round(bucket["overall_score"] / weight, 2),
            "recall": round(bucket["recall"] / weight, 4),
            "absence_guard": round(bucket["absence_guard"] / weight, 4),
            "latency_score": round(bucket["latency_score"] / weight, 4),
            "total_tokens_used": int(bucket["tokens"]),
            "total_elapsed_seconds": round(bucket["elapsed_seconds"], 4),
            "missed_present": int(bucket["missed_present"]),
            "noise": int(bucket["noise"]),
            "static_only_routes": int(bucket["static_only_routes"]),
            "full_harness_routes": int(bucket["full_harness_routes"]),
        }

    return scorecard


def run_manifest(
    manifest_path: str | Path,
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    selected_cases: set[str] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
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
        if progress_callback is not None:
            progress_callback({"status": "completed", "case": result})
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

    pass_count = sum(1 for case in case_results if not case["failures"])
    route_counts: dict[str, int] = {}
    for case in case_results:
        for route, count in (case.get("route_counts", {}) or {}).items():
            route_counts[route] = route_counts.get(route, 0) + int(count or 0)
    return {
        "manifest": str(Path(manifest_path).resolve()),
        "model": model,
        "case_count": len(case_results),
        "pass_count": pass_count,
        "failure_count": sum(len(case["failures"]) for case in case_results),
        "total_elapsed_seconds": round(total_elapsed, 4),
        "total_tokens_used": total_tokens,
        "avg_tokens_per_case": round(total_tokens / len(case_results), 2)
        if case_results
        else 0.0,
        "route_counts": route_counts,
        "scores": scores,
        "security_scorecard": _build_security_scorecard(case_results),
        "taxonomy_scorecard": _build_dimension_scorecard(
            case_results,
            field="taxonomy",
            descriptions=AGENT_REVIEW_TAXONOMY,
        ),
        "security_diagnostics": _build_dimension_scorecard(
            case_results,
            field="security_classes",
            descriptions=SECURITY_BENCHMARK_CLASSES,
        ),
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
    if summary.get("route_counts"):
        rendered_routes = ", ".join(
            f"{name}={count}" for name, count in sorted(summary["route_counts"].items())
        )
        lines.append(f"Agent review benchmark routes: {rendered_routes}")
    if summary.get("security_scorecard"):
        lines.append("Security classes:")
        for label, bucket in sorted(summary["security_scorecard"].items()):
            lines.append(
                f"  {label}: cases={bucket['case_count']} pass={bucket['pass_count']} "
                f"fail={bucket['failed_case_count']} score={bucket['weighted_score']}"
            )
    if summary.get("taxonomy_scorecard"):
        lines.append("Taxonomy diagnostics:")
        for label, bucket in sorted(summary["taxonomy_scorecard"].items()):
            lines.append(
                f"  {label}: cases={bucket['case_count']} score={bucket['weighted_score']} "
                f"missed={bucket['missed_present']} noise={bucket['noise']} "
                f"tokens={bucket['total_tokens_used']} "
                f"routes=static:{bucket['static_only_routes']}/full:{bucket['full_harness_routes']}"
            )
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
        diagnostics = case.get("diagnostics") or {}
        if diagnostics.get("missed_present"):
            lines.append(
                f"  missed present: {', '.join(diagnostics['missed_present'])}"
            )
        if diagnostics.get("absent_violations"):
            lines.append(
                f"  absent violations: {', '.join(diagnostics['absent_violations'])}"
            )
        if diagnostics.get("precision_guard_noise"):
            lines.append("  precision guard noise: yes")
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} -> {failure['expected']} (found: {found})"
            )
    return "\n".join(lines)
