from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze


DEAD_CODE_TAXONOMY: dict[str, str] = {
    "basic_detection": "Core unused import, function, class, variable, and parameter detection.",
    "framework_precision": "Framework-owned symbols that should not be reported as dead code.",
    "fastapi": "FastAPI route and dependency injection liveness patterns.",
    "flask": "Flask route and registration liveness patterns.",
    "sqlalchemy": "SQLAlchemy declarative model and repository liveness patterns.",
    "cli_entrypoint": "CLI decorators and framework command entrypoints.",
    "multi_file": "Cross-file package and service-layer liveness patterns.",
    "service_layer": "Repository and service objects in industry-style application layers.",
    "dynamic_dispatch": "Registries, decorators, getattr, and runtime dispatch patterns.",
    "precision_guard": "Known-used symbols that should stay quiet.",
    "external_demo": "Larger external benchmark target.",
}

IMPORTANCE_WEIGHTS = {
    "low": 1.0,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}

KIND_TO_CATEGORY = {
    "import": "unused_imports",
    "function": "unused_functions",
    "class": "unused_classes",
    "variable": "unused_variables",
    "parameter": "unused_parameters",
    "file": "unused_files",
}

CATEGORY_TO_KIND = {category: kind for kind, category in KIND_TO_CATEGORY.items()}

DEFAULT_SCAN = {
    "confidence": 60,
    "grep_verify": True,
}

SUPPORTED_SCANNERS = {"skylos", "vulture"}

_VULTURE_OUTPUT_RE = re.compile(
    r"^(?P<file>.*?):(?P<line>\d+): unused (?P<label>[a-z_ ]+) "
    r"'(?P<symbol>[^']+)'"
)

_VULTURE_KIND_TO_CATEGORY = {
    "import": "unused_imports",
    "function": "unused_functions",
    "method": "unused_functions",
    "class": "unused_classes",
    "variable": "unused_variables",
    "attribute": "unused_variables",
    "property": "unused_variables",
}


@dataclass(frozen=True)
class DeadCodeKey:
    kind: str
    file: str
    symbol: str

    def label(self) -> str:
        return f"{self.kind}:{self.file}:{self.symbol}"


@dataclass(frozen=True)
class DeadCodeBenchmarkFailure:
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


def load_external_targets(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _case_path(root: Path, rel_path: str, *, allow_absolute: bool) -> Path:
    path = Path(rel_path).expanduser()
    if path.is_absolute():
        if not allow_absolute:
            raise ValueError(f"benchmark case path must be relative: {rel_path}")
        return path.resolve()
    return (root / path).resolve()


def _validate_expectation(
    case_id: str,
    mode: str,
    item: Any,
) -> None:
    if not isinstance(item, dict):
        raise ValueError(f"dead-code case {case_id} {mode} expectations must be objects")

    kind = item.get("kind")
    if kind not in KIND_TO_CATEGORY:
        allowed = ", ".join(sorted(KIND_TO_CATEGORY))
        raise ValueError(
            f"dead-code case {case_id} has unsupported kind '{kind}'. Allowed: {allowed}"
        )

    file_name = item.get("file")
    if not isinstance(file_name, str) or not file_name.strip():
        raise ValueError(
            f"dead-code case {case_id} {mode} expectation must declare a file"
        )

    symbol = item.get("symbol")
    if not isinstance(symbol, str) or not symbol.strip():
        raise ValueError(
            f"dead-code case {case_id} {mode} expectation must declare a symbol"
        )

    aliases = item.get("aliases", [])
    if aliases and not isinstance(aliases, list):
        raise ValueError(
            f"dead-code case {case_id} {mode} expectation aliases must be a list"
        )
    for alias in aliases:
        if not isinstance(alias, str) or not alias.strip():
            raise ValueError(
                f"dead-code case {case_id} {mode} expectation aliases must be strings"
            )


def _validate_case(
    case: dict[str, Any],
    root: Path,
    *,
    seen_ids: set[str],
    allow_absolute_path: bool,
    require_path_exists: bool = True,
) -> None:
    if not isinstance(case, dict):
        raise ValueError("each dead-code benchmark case must be an object")

    case_id = case.get("id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("each dead-code benchmark case must have a non-empty id")
    if case_id in seen_ids:
        raise ValueError(f"duplicate dead-code benchmark case id: {case_id}")
    seen_ids.add(case_id)

    rel_path = case.get("path")
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise ValueError(f"dead-code case {case_id} must declare a path")
    case_path = _case_path(root, rel_path, allow_absolute=allow_absolute_path)
    if require_path_exists and not case_path.exists():
        raise ValueError(f"dead-code case {case_id} path does not exist: {case_path}")

    scan_paths = case.get("scan_paths", [])
    if scan_paths and not isinstance(scan_paths, list):
        raise ValueError(f"dead-code case {case_id} scan_paths must be a list")
    for scan_path in scan_paths:
        if not isinstance(scan_path, str) or not scan_path.strip():
            raise ValueError(
                f"dead-code case {case_id} scan_paths must contain non-empty strings"
            )
        resolved = (case_path / scan_path).resolve()
        if require_path_exists and not resolved.exists():
            raise ValueError(
                f"dead-code case {case_id} scan path does not exist: {resolved}"
            )

    taxonomy = case.get("taxonomy")
    if not isinstance(taxonomy, list) or not taxonomy:
        raise ValueError(
            f"dead-code case {case_id} must declare a non-empty taxonomy list"
        )
    for label in taxonomy:
        if label not in DEAD_CODE_TAXONOMY:
            allowed = ", ".join(sorted(DEAD_CODE_TAXONOMY))
            raise ValueError(
                f"dead-code case {case_id} has unknown taxonomy '{label}'. Allowed: {allowed}"
            )

    importance = case.get("importance", "high")
    if importance not in IMPORTANCE_WEIGHTS:
        allowed = ", ".join(sorted(IMPORTANCE_WEIGHTS))
        raise ValueError(
            f"dead-code case {case_id} importance must be one of: {allowed}"
        )

    source = case.get("source")
    if not isinstance(source, dict):
        raise ValueError(f"dead-code case {case_id} must declare source metadata")
    repo = source.get("repo")
    license_name = source.get("license")
    if not isinstance(repo, str) or not repo.startswith("https://"):
        raise ValueError(f"dead-code case {case_id} must declare an https repo URL")
    if not isinstance(license_name, str) or not license_name.strip():
        raise ValueError(f"dead-code case {case_id} must declare a license")

    scan = case.get("scan", {})
    if scan and not isinstance(scan, dict):
        raise ValueError(f"dead-code case {case_id} scan config must be an object")
    confidence = (scan or {}).get("confidence")
    if confidence is not None and (
        not isinstance(confidence, int) or confidence < 0 or confidence > 100
    ):
        raise ValueError(
            f"dead-code case {case_id} scan.confidence must be an integer from 0 to 100"
        )

    expect = case.get("expect")
    if not isinstance(expect, dict):
        raise ValueError(f"dead-code case {case_id} must declare expectations")
    unused = expect.get("unused", [])
    used = expect.get("used", [])
    if not isinstance(unused, list) or not isinstance(used, list):
        raise ValueError(
            f"dead-code case {case_id} expectations must use unused/used lists"
        )
    if not unused and not used:
        raise ValueError(
            f"dead-code case {case_id} must declare at least one expectation"
        )
    for item in unused:
        _validate_expectation(case_id, "unused", item)
    for item in used:
        _validate_expectation(case_id, "used", item)

    budget = case.get("budget", {})
    if budget:
        if not isinstance(budget, dict):
            raise ValueError(f"dead-code case {case_id} budget must be an object")
        max_seconds = budget.get("max_seconds")
        if max_seconds is not None:
            if not isinstance(max_seconds, (int, float)) or max_seconds <= 0:
                raise ValueError(
                    f"dead-code case {case_id} budget.max_seconds must be a positive number"
                )


def validate_manifest(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("dead-code benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("dead-code benchmark manifest must define a non-empty cases list")

    seen_ids: set[str] = set()
    root = manifest_file.parent
    for case in cases:
        _validate_case(
            case,
            root,
            seen_ids=seen_ids,
            allow_absolute_path=False,
            require_path_exists=True,
        )
    return cases


def validate_external_targets(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("dead-code external target manifest version must be 1")

    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError(
            "dead-code external target manifest must define a non-empty targets list"
        )

    seen_ids: set[str] = set()
    root = manifest_file.parent
    for target in targets:
        _validate_case(
            target,
            root,
            seen_ids=seen_ids,
            allow_absolute_path=True,
            require_path_exists=False,
        )
    return targets


def _norm_rel_path(value: str, project_root: Path) -> str:
    text = (value or "").replace("\\", "/")
    if not text:
        return ""
    path = Path(text)
    try:
        if path.is_absolute():
            text = path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        pass
    if text.startswith("./"):
        text = text[2:]
    return text


def _norm_symbol(value: str, kind: str) -> str:
    symbol = str(value or "").strip()
    if not symbol:
        return ""
    if kind in {"function", "class", "variable", "parameter"}:
        if "." in symbol and "/" not in symbol:
            symbol = symbol.split(".")[-1]
    return symbol


def _expectation_keys(item: dict[str, Any]) -> set[DeadCodeKey]:
    kind = str(item["kind"])
    file_name = str(item["file"]).replace("\\", "/")
    symbols = [str(item["symbol"]), *[str(alias) for alias in item.get("aliases", [])]]
    return {
        DeadCodeKey(kind=kind, file=file_name, symbol=_norm_symbol(symbol, kind))
        for symbol in symbols
    }


def _primary_expectation_key(item: dict[str, Any]) -> DeadCodeKey:
    return next(iter(_expectation_keys(item)))


def _finding_symbol(finding: dict[str, Any], kind: str) -> str:
    for key in ("simple_name", "name", "symbol", "full_name", "value"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return _norm_symbol(value, kind)
    return ""


def _collect_dead_code_findings(
    result: dict[str, Any],
    *,
    project_root: Path,
) -> set[DeadCodeKey]:
    findings: set[DeadCodeKey] = set()
    for category, kind in CATEGORY_TO_KIND.items():
        for item in result.get(category, []) or []:
            if not isinstance(item, dict):
                continue
            file_name = _norm_rel_path(str(item.get("file", "")), project_root)
            symbol = _finding_symbol(item, kind)
            if kind == "file" and not symbol:
                symbol = file_name
            if not file_name or not symbol:
                continue
            findings.add(DeadCodeKey(kind=kind, file=file_name, symbol=symbol))
    return findings


def _scan_case(case_path: Path, case: dict[str, Any]) -> dict[str, Any]:
    scan_cfg = dict(DEFAULT_SCAN)
    scan_cfg.update(case.get("scan") or {})

    scan_paths = case.get("scan_paths") or []
    if scan_paths:
        scan_target: str | list[str] = [
            str((case_path / rel_path).resolve()) for rel_path in scan_paths
        ]
    else:
        scan_target = str(case_path)

    analyzer_logger = logging.getLogger("Skylos")
    prev_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.WARNING)
    try:
        raw = analyze(
            scan_target,
            conf=int(scan_cfg.get("confidence", DEFAULT_SCAN["confidence"])),
            enable_quality=False,
            enable_danger=False,
            enable_secrets=False,
            grep_verify=bool(scan_cfg.get("grep_verify", DEFAULT_SCAN["grep_verify"])),
        )
    finally:
        analyzer_logger.setLevel(prev_level)
    return json.loads(raw)


def _scan_vulture_case(case_path: Path, case: dict[str, Any]) -> dict[str, Any]:
    vulture = shutil.which("vulture")
    if not vulture:
        raise RuntimeError(
            "vulture scanner is not installed. Install it separately to run "
            "`python scripts/dead_code_benchmark.py --scanner vulture`."
        )

    scan_cfg = dict(DEFAULT_SCAN)
    scan_cfg.update(case.get("scan") or {})
    scan_paths = case.get("scan_paths") or []
    scan_args = list(scan_paths) if scan_paths else ["."]
    cmd = [
        vulture,
        *scan_args,
        "--min-confidence",
        str(int(scan_cfg.get("confidence", DEFAULT_SCAN["confidence"]))),
    ]
    completed = subprocess.run(
        cmd,
        cwd=str(case_path),
        capture_output=True,
        text=True,
        timeout=float((case.get("budget") or {}).get("max_seconds", 30.0)) + 5.0,
    )
    if completed.returncode not in (0, 3):
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"exit code {completed.returncode}"
        raise RuntimeError(f"vulture benchmark scan failed: {detail}")

    result = {category: [] for category in CATEGORY_TO_KIND}
    for line in completed.stdout.splitlines():
        match = _VULTURE_OUTPUT_RE.match(line.strip())
        if not match:
            continue
        label = match.group("label").strip()
        if label.startswith("import "):
            label = "import"
        category = _VULTURE_KIND_TO_CATEGORY.get(label)
        if not category:
            continue
        result[category].append(
            {
                "file": match.group("file"),
                "line": int(match.group("line")),
                "simple_name": match.group("symbol"),
            }
        )
    return result


def _scan_case_with_scanner(
    case_path: Path, case: dict[str, Any], *, scanner: str
) -> dict[str, Any]:
    if scanner == "skylos":
        return _scan_case(case_path, case)
    if scanner == "vulture":
        return _scan_vulture_case(case_path, case)
    allowed = ", ".join(sorted(SUPPORTED_SCANNERS))
    raise ValueError(f"unsupported dead-code benchmark scanner '{scanner}': {allowed}")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


@contextmanager
def _analysis_path(case_path: Path, manifest_root: Path):
    if not _is_relative_to(case_path, manifest_root):
        yield case_path
        return

    with tempfile.TemporaryDirectory(prefix="skylos_dead_code_bench_") as tmp_dir:
        staged = Path(tmp_dir) / case_path.name
        if case_path.is_dir():
            shutil.copytree(case_path, staged)  # skylos: ignore[SKY-D215]
        else:
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(case_path, staged)  # skylos: ignore[SKY-D215]
        yield staged


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
        0.0
        if precision + recall == 0.0
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
    case: dict[str, Any], manifest_path: str | Path, *, scanner: str = "skylos"
) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = _case_path(
        manifest_root,
        case["path"],
        allow_absolute=Path(str(case["path"])).is_absolute(),
    )
    if not case_path.exists():
        raise ValueError(
            f"dead-code benchmark case {case['id']} path does not exist: {case_path}"
        )

    start = time.perf_counter()
    with _analysis_path(case_path, manifest_root) as analysis_path:
        result = _scan_case_with_scanner(analysis_path, case, scanner=scanner)
        findings = _collect_dead_code_findings(result, project_root=analysis_path)
    elapsed_seconds = time.perf_counter() - start

    failures: list[DeadCodeBenchmarkFailure] = []
    true_positives = false_positives = false_negatives = true_negatives = 0

    unused_expectations = case.get("expect", {}).get("unused", []) or []
    used_expectations = case.get("expect", {}).get("used", []) or []

    expected_unused_keys = set()
    expected_used_keys = set()

    for item in unused_expectations:
        keys = _expectation_keys(item)
        expected_unused_keys.update(keys)
        matched = sorted(key.label() for key in keys if key in findings)
        expected = _primary_expectation_key(item).label()
        if matched:
            true_positives += 1
        else:
            false_negatives += 1
            failures.append(
                DeadCodeBenchmarkFailure(
                    case_id=case["id"],
                    failure_type="expectation",
                    mode="unused",
                    expected=expected,
                    found=[],
                )
            )

    for item in used_expectations:
        keys = _expectation_keys(item)
        expected_used_keys.update(keys)
        matched = sorted(key.label() for key in keys if key in findings)
        expected = _primary_expectation_key(item).label()
        if matched:
            false_positives += 1
            failures.append(
                DeadCodeBenchmarkFailure(
                    case_id=case["id"],
                    failure_type="expectation",
                    mode="used",
                    expected=expected,
                    found=matched,
                )
            )
        else:
            true_negatives += 1

    max_seconds = (case.get("budget") or {}).get("max_seconds")
    if max_seconds is not None and elapsed_seconds > max_seconds:
        failures.append(
            DeadCodeBenchmarkFailure(
                case_id=case["id"],
                failure_type="budget",
                mode="max_seconds",
                expected=f"{max_seconds:.3f}s",
                found=[f"{elapsed_seconds:.3f}s"],
            )
        )

    labeled_keys = expected_unused_keys | expected_used_keys
    unlabeled_findings = sorted(key.label() for key in findings - labeled_keys)
    findings_by_kind: dict[str, int] = {}
    for key in findings:
        findings_by_kind[key.kind] = findings_by_kind.get(key.kind, 0) + 1

    return {
        "id": case["id"],
        "path": str(case_path),
        "description": case.get("description", ""),
        "taxonomy": list(case.get("taxonomy", [])),
        "importance": case.get("importance", "high"),
        "elapsed_seconds": round(elapsed_seconds, 4),
        "findings_by_kind": findings_by_kind,
        "unlabeled_finding_count": len(unlabeled_findings),
        "unlabeled_findings": unlabeled_findings[:50],
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "scores": _score_counts(
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            elapsed_seconds=elapsed_seconds,
            max_seconds=max_seconds,
        ),
        "failures": [failure.to_dict() for failure in failures],
    }


def _aggregate_scores(
    case_results: list[dict[str, Any]]
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


def _taxonomy_summary(case_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    totals: dict[str, dict[str, float]] = {}
    for result in case_results:
        weight = IMPORTANCE_WEIGHTS[result["importance"]]
        for label in result["taxonomy"]:
            bucket = totals.setdefault(
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

    summary = {}
    for label, bucket in sorted(totals.items()):
        weight = bucket["weight"] or 1.0
        summary[label] = {
            "description": DEAD_CODE_TAXONOMY[label],
            "case_count": int(bucket["case_count"]),
            "weighted_score": round(bucket["overall_score"] / weight, 2),
            "failure_count": int(bucket["failures"]),
            "true_positives": int(bucket["true_positives"]),
            "false_positives": int(bucket["false_positives"]),
            "false_negatives": int(bucket["false_negatives"]),
            "true_negatives": int(bucket["true_negatives"]),
        }
    return summary


def _summary(
    case_results: list[dict[str, Any]], manifest_path: str | Path, *, scanner: str
) -> dict[str, Any]:
    scores, counts = _aggregate_scores(case_results)
    failure_count = sum(len(case["failures"]) for case in case_results)
    pass_count = sum(1 for case in case_results if not case["failures"])
    total_elapsed = sum(float(case["elapsed_seconds"]) for case in case_results)
    return {
        "manifest": str(Path(manifest_path).resolve()),
        "scanner": scanner,
        "case_count": len(case_results),
        "pass_count": pass_count,
        "failure_count": failure_count,
        "total_elapsed_seconds": round(total_elapsed, 4),
        "counts": counts,
        "scores": scores,
        "taxonomy": _taxonomy_summary(case_results),
        "cases": case_results,
    }


def run_manifest(
    manifest_path: str | Path,
    selected_cases: set[str] | None = None,
    *,
    scanner: str = "skylos",
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())

    case_results = [
        run_case(case, manifest_path, scanner=scanner)
        for case in cases
        if not selected or case["id"] in selected
    ]
    return _summary(case_results, manifest_path, scanner=scanner)


def _select_external_targets(
    external_targets_path: str | Path,
    selected_targets: set[str],
) -> list[dict[str, Any]]:
    manifest = load_external_targets(external_targets_path)
    targets = validate_external_targets(manifest, external_targets_path)
    if not selected_targets:
        return targets

    normalized_selections = {str(Path(item).expanduser().resolve()) for item in selected_targets}
    matched = []
    for target in targets:
        target_path = str(Path(target["path"]).expanduser().resolve())
        if target["id"] in selected_targets or target_path in normalized_selections:
            matched.append(target)

    if not matched:
        wanted = ", ".join(sorted(selected_targets))
        raise ValueError(f"no external dead-code benchmark target matched: {wanted}")
    return matched


def run_external_targets(
    external_targets_path: str | Path,
    selected_targets: set[str] | None = None,
    *,
    scanner: str = "skylos",
) -> dict[str, Any]:
    selected = set(selected_targets or set())
    targets = _select_external_targets(external_targets_path, selected)
    case_results = [
        run_case(target, external_targets_path, scanner=scanner) for target in targets
    ]
    return _summary(case_results, external_targets_path, scanner=scanner)


def format_summary(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    scores = summary["scores"]
    lines = [
        f"Dead-code benchmark cases: {summary['case_count']}",
        f"Dead-code benchmark failures: {summary['failure_count']}",
        (
            "Dead-code benchmark counts: "
            f"TP={counts['true_positives']} "
            f"FP={counts['false_positives']} "
            f"FN={counts['false_negatives']} "
            f"TN={counts['true_negatives']}"
        ),
        (
            "Dead-code benchmark metrics: "
            f"precision={scores['precision']} "
            f"recall={scores['recall']} "
            f"f1={scores['f1']} "
            f"absence_guard={scores['absence_guard']} "
            f"latency={scores['latency_score']}"
        ),
        f"Dead-code benchmark score: {scores['overall_score']}/100",
        f"Dead-code benchmark total time: {summary['total_elapsed_seconds']:.4f}s",
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
            f"unlabeled={case['unlabeled_finding_count']} "
            f"time={case['elapsed_seconds']:.4f}s"
        )
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} "
                f"-> {failure['expected']} (found: {found})"
            )
        if case["unlabeled_findings"]:
            preview = ", ".join(case["unlabeled_findings"][:5])
            suffix = " ..." if len(case["unlabeled_findings"]) > 5 else ""
            lines.append(f"  unlabeled preview: {preview}{suffix}")

    return "\n".join(lines)
