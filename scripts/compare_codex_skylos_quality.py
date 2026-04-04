#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.analyzer import analyze
from skylos.quality_benchmark import (
    DEFAULT_SCAN,
    IMPORTANCE_WEIGHTS,
    load_manifest,
    validate_manifest,
)


SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["findings"],
    "additionalProperties": False,
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "symbol", "category", "message"],
                "additionalProperties": False,
                "properties": {
                    "file": {"type": "string"},
                    "symbol": {"type": "string"},
                    "category": {"type": "string"},
                    "message": {"type": "string"},
                },
            },
        }
    },
}


def _is_symbol_expectation(value: str) -> bool:
    return isinstance(value, str) and value and not value.startswith("SKY-")


def _normalize_symbol(name: str) -> str:
    name = (name or "").strip()
    if "." in name and "/" not in name:
        name = name.split(".")[-1]
    return name


def _present_symbols(case: dict) -> set[str]:
    present = case.get("expect", {}).get("present", {}) or {}
    out: set[str] = set()
    for symbols in present.values():
        for symbol in symbols:
            if _is_symbol_expectation(symbol):
                out.add(_normalize_symbol(symbol))
    return out


def _absent_symbols(case: dict) -> set[str]:
    absent = case.get("expect", {}).get("absent", {}) or {}
    out: set[str] = set()
    for symbols in absent.values():
        for symbol in symbols:
            if _is_symbol_expectation(symbol):
                out.add(_normalize_symbol(symbol))
    return out


def _precision_guard(case: dict) -> bool:
    return "precision_guard" in (case.get("taxonomy") or [])


def _score(
    found_symbols: set[str], finding_count: int, case: dict, elapsed_seconds: float
):
    present = _present_symbols(case)
    absent = _absent_symbols(case)

    present_total = len(present)
    present_matched = len(found_symbols & present)

    absent_total = len(absent)
    absent_violations = len(found_symbols & absent)

    if _precision_guard(case):
        absent_total += 1
        if finding_count > 0:
            absent_violations += 1

    recall = 1.0 if present_total == 0 else present_matched / present_total
    absence_guard = (
        1.0 if absent_total == 0 else max(0.0, 1.0 - (absent_violations / absent_total))
    )

    max_seconds = (case.get("budget") or {}).get("max_seconds")
    latency = 1.0
    if max_seconds is not None:
        latency = min(max_seconds / max(elapsed_seconds, 1e-9), 1.0)

    overall = ((recall * 0.50) + (absence_guard * 0.35) + (latency * 0.15)) * 100.0

    return {
        "present_total": present_total,
        "present_matched": present_matched,
        "absent_total": absent_total,
        "absent_violations": absent_violations,
        "recall": round(recall, 4),
        "absence_guard": round(absence_guard, 4),
        "latency": round(latency, 4),
        "overall_score": round(overall, 2),
    }


def _finding_in_case(finding: dict, case_path: Path) -> bool:
    file_value = str(finding.get("file") or "").strip()
    if not file_value:
        return False

    fp = Path(file_value)
    if not fp.is_absolute():
        fp = (case_path / fp).resolve()
    else:
        fp = fp.resolve()

    try:
        fp.relative_to(case_path.resolve())
        return fp.suffix.lower() in {".py", ".pyi", ".pyw"}
    except Exception:
        return False


def _run_skylos(case_path: Path, scan_cfg: dict | None):
    scan = dict(DEFAULT_SCAN)
    if scan_cfg:
        scan.update(scan_cfg)

    start = time.perf_counter()
    analyzer_logger = logging.getLogger("Skylos")
    prev_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.WARNING)
    try:
        raw = analyze(
            str(case_path),
            conf=0,
            enable_quality=bool(scan.get("enable_quality", False)),
            enable_danger=bool(scan.get("enable_danger", False)),
            enable_secrets=bool(scan.get("enable_secrets", False)),
            grep_verify=bool(scan.get("grep_verify", False)),
        )
    finally:
        analyzer_logger.setLevel(prev_level)
    elapsed = time.perf_counter() - start
    data = json.loads(raw)

    findings = [
        finding
        for finding in (data.get("quality", []) or [])
        if _finding_in_case(finding, case_path)
    ]
    symbols = {
        _normalize_symbol(f.get("simple_name") or f.get("name") or "")
        for f in findings
        if (f.get("simple_name") or f.get("name"))
    }
    symbols.discard("")
    return {
        "elapsed_seconds": elapsed,
        "finding_count": len(findings),
        "symbols": sorted(symbols),
    }


def _codex_prompt(case: dict) -> str:
    tax = ", ".join(case.get("taxonomy") or [])
    return (
        "Review this tiny Python project for concrete code-quality issues only.\n"
        "Ignore security issues and style-only concerns.\n"
        "Return ONLY JSON matching the provided schema.\n"
        "Each finding must use the symbol name of the concrete function/class/variable at fault.\n"
        "Prefer correctness, control-flow, complexity, maintainability, exception-handling, and API-design issues.\n"
        f"Benchmark case: {case.get('id')}.\n"
        f"Taxonomy focus: {tax}.\n"
        'If there are no real quality findings, return {"findings": []}.'
    )


def _run_codex(case_path: Path, case: dict, model: str):
    with tempfile.TemporaryDirectory(prefix="codex-quality-") as td:
        td_path = Path(td)
        schema_path = td_path / "schema.json"
        output_path = td_path / "output.json"
        schema_path.write_text(json.dumps(SCHEMA), encoding="utf-8")

        cmd = [
            "codex",
            "exec",
            "-C",
            str(case_path),
            "--skip-git-repo-check",
            "--ephemeral",
            "--color",
            "never",
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
            "-m",
            model,
            _codex_prompt(case),
        ]

        start = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.perf_counter() - start

        if result.returncode != 0:
            raise RuntimeError(
                f"Codex failed for {case['id']} (exit={result.returncode}).\n"
                f"STDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
            )

        if not output_path.exists():
            raise RuntimeError(f"Codex produced no output file for {case['id']}")

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        findings = payload.get("findings", []) or []
        symbols = {
            _normalize_symbol(f.get("symbol") or "")
            for f in findings
            if isinstance(f, dict) and f.get("symbol")
        }
        symbols.discard("")
        return {
            "elapsed_seconds": elapsed,
            "finding_count": len(findings),
            "symbols": sorted(symbols),
        }


def _compare_case(case: dict, manifest_path: Path, model: str):
    case_path = (manifest_path.parent / case["path"]).resolve()

    skylos = _run_skylos(case_path, case.get("scan"))
    codex = _run_codex(case_path, case, model)

    skylos_score = _score(
        set(skylos["symbols"]), skylos["finding_count"], case, skylos["elapsed_seconds"]
    )
    codex_score = _score(
        set(codex["symbols"]), codex["finding_count"], case, codex["elapsed_seconds"]
    )

    return {
        "id": case["id"],
        "importance": case.get("importance", "high"),
        "taxonomy": list(case.get("taxonomy") or []),
        "expected_present_symbols": sorted(_present_symbols(case)),
        "expected_absent_symbols": sorted(_absent_symbols(case)),
        "skylos": {**skylos, "scores": skylos_score},
        "codex": {**codex, "scores": codex_score},
    }


def _aggregate(case_results: list[dict]):
    totals = {
        "skylos": {
            "score": 0.0,
            "recall": 0.0,
            "absence_guard": 0.0,
            "latency": 0.0,
            "time": 0.0,
        },
        "codex": {
            "score": 0.0,
            "recall": 0.0,
            "absence_guard": 0.0,
            "latency": 0.0,
            "time": 0.0,
        },
    }
    total_weight = 0.0

    for case in case_results:
        weight = IMPORTANCE_WEIGHTS.get(case["importance"], 1.0)
        total_weight += weight
        for tool_name in ("skylos", "codex"):
            scores = case[tool_name]["scores"]
            totals[tool_name]["score"] += scores["overall_score"] * weight
            totals[tool_name]["recall"] += scores["recall"] * weight
            totals[tool_name]["absence_guard"] += scores["absence_guard"] * weight
            totals[tool_name]["latency"] += scores["latency"] * weight
            totals[tool_name]["time"] += case[tool_name]["elapsed_seconds"]

    if total_weight == 0:
        total_weight = 1.0

    out = {}
    for tool_name, values in totals.items():
        out[tool_name] = {
            "overall_score": round(values["score"] / total_weight, 2),
            "recall": round(values["recall"] / total_weight, 4),
            "absence_guard": round(values["absence_guard"] / total_weight, 4),
            "latency": round(values["latency"] / total_weight, 4),
            "total_time_seconds": round(values["time"], 4),
        }
    return out


def _render(summary: dict) -> str:
    lines = [
        f"Cases: {summary['case_count']}",
        f"Model: {summary['model']}",
        (
            "Skylos: "
            f"score={summary['aggregate']['skylos']['overall_score']} "
            f"recall={summary['aggregate']['skylos']['recall']} "
            f"absence_guard={summary['aggregate']['skylos']['absence_guard']} "
            f"latency={summary['aggregate']['skylos']['latency']} "
            f"time={summary['aggregate']['skylos']['total_time_seconds']:.4f}s"
        ),
        (
            "Codex: "
            f"score={summary['aggregate']['codex']['overall_score']} "
            f"recall={summary['aggregate']['codex']['recall']} "
            f"absence_guard={summary['aggregate']['codex']['absence_guard']} "
            f"latency={summary['aggregate']['codex']['latency']} "
            f"time={summary['aggregate']['codex']['total_time_seconds']:.4f}s"
        ),
    ]

    for case in summary["cases"]:
        lines.append(
            f"{case['id']} [{case['importance']}] "
            f"Skylos={case['skylos']['scores']['overall_score']} "
            f"Codex={case['codex']['scores']['overall_score']}"
        )
        lines.append(
            f"  expected present={case['expected_present_symbols'] or ['<none>']} "
            f"absent={case['expected_absent_symbols'] or ['<none>']}"
        )
        lines.append(
            f"  skylos symbols={case['skylos']['symbols']} "
            f"time={case['skylos']['elapsed_seconds']:.4f}s"
        )
        lines.append(
            f"  codex symbols={case['codex']['symbols']} "
            f"time={case['codex']['elapsed_seconds']:.4f}s"
        )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Codex and Skylos on the quality benchmark suite."
    )
    parser.add_argument(
        "--manifest",
        default=str(Path("quality_benchmarks") / "manifest.json"),
        help="Path to the quality benchmark manifest.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only the specified case id. Repeat for multiple ids.",
    )
    parser.add_argument(
        "--model",
        default="gpt-5.4",
        help="Codex model to use.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a text summary.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(args.case)

    case_results = []
    for case in cases:
        if selected and case["id"] not in selected:
            continue
        case_results.append(_compare_case(case, manifest_path, args.model))

    summary = {
        "manifest": str(manifest_path),
        "model": args.model,
        "case_count": len(case_results),
        "aggregate": _aggregate(case_results),
        "cases": case_results,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(_render(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
