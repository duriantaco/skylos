#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.agent_review_benchmark import (
    IMPORTANCE_WEIGHTS,
    load_manifest,
    prepare_case_scan,
    validate_manifest,
)
from skylos.llm.analyzer import AnalyzerConfig, SkylosLLM
from skylos.llm.runtime import resolve_llm_runtime


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


def _normalize_symbol(value: str | None) -> str:
    value = (value or "").strip()
    if "." in value and "/" not in value:
        value = value.split(".")[-1]
    return value


def _expected_symbols(case: dict, mode: str) -> set[str]:
    expectation_map = (case.get("expect", {}) or {}).get(mode, {}) or {}
    return {
        _normalize_symbol(symbol)
        for symbols in expectation_map.values()
        for symbol in symbols
        if _normalize_symbol(symbol)
    }


def _score(
    found_symbols: set[str], finding_count: int, case: dict, elapsed_seconds: float
):
    present = _expected_symbols(case, "present")
    absent = _expected_symbols(case, "absent")

    present_total = len(present)
    present_matched = len(found_symbols & present)

    absent_total = len(absent)
    absent_violations = len(found_symbols & absent)

    if "precision_guard" in (case.get("taxonomy") or []):
        absent_total += 1
        if finding_count > 0:
            absent_violations += 1

    recall = 1.0 if present_total == 0 else present_matched / present_total
    absence_guard = (
        1.0 if absent_total == 0 else max(0.0, 1.0 - (absent_violations / absent_total))
    )
    max_seconds = (case.get("budget") or {}).get("max_seconds")
    latency = (
        1.0
        if max_seconds is None
        else min(max_seconds / max(elapsed_seconds, 1e-9), 1.0)
    )
    overall = ((recall * 0.50) + (absence_guard * 0.35) + (latency * 0.15)) * 100.0

    return {
        "recall": round(recall, 4),
        "absence_guard": round(absence_guard, 4),
        "latency": round(latency, 4),
        "overall_score": round(overall, 2),
    }


def _run_skylos_agent_review(
    case_path: Path,
    *,
    case: dict,
    model: str,
    api_key: str,
    provider: str | None,
    base_url: str | None,
):
    scan_cfg = case.get("scan") if isinstance(case, dict) else {}
    max_files = int((scan_cfg or {}).get("max_files") or 8)
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
    start = time.perf_counter()
    result = analyzer.analyze_files(prepared["files"])
    elapsed = time.perf_counter() - start

    symbols = {
        _normalize_symbol(getattr(finding, "symbol", None))
        for finding in result.findings
        if _normalize_symbol(getattr(finding, "symbol", None))
    }
    return {
        "elapsed_seconds": elapsed,
        "finding_count": len(result.findings),
        "symbols": sorted(symbols),
        "tokens_used": int(result.tokens_used or 0),
    }


def _codex_prompt(case: dict) -> str:
    tax = ", ".join(case.get("taxonomy") or [])
    return (
        "Review the Python code in the current working scope as if you were doing a strong code review.\n"
        "If the scope contains multiple files, inspect the relevant files before answering.\n"
        "Focus on concrete security, correctness, quality, and performance issues.\n"
        "Also surface technical-debt hotspots when repo evidence shows a central, hard-to-maintain module.\n"
        "Do not report style-only nits or dead code that needs whole-repo certainty.\n"
        "Return ONLY JSON matching the provided schema.\n"
        "Each finding must use the owning function/class/method/variable name in `symbol`.\n"
        "Never use syntax tokens like except/if/return as the symbol.\n"
        f"Benchmark case: {case.get('id')}.\n"
        f"Taxonomy focus: {tax}.\n"
        'If the file is clean, return {"findings": []}.'
    )


def _run_codex(case_path: Path, case: dict, model: str):
    with tempfile.TemporaryDirectory(prefix="codex-agent-review-") as td:
        td_path = Path(td)
        schema_path = td_path / "schema.json"
        output_path = td_path / "output.json"
        schema_path.write_text(json.dumps(SCHEMA), encoding="utf-8")

        cmd = [
            "codex",
            "exec",
            "--json",
            "-C",
            str(case_path.parent if case_path.is_file() else case_path),
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

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        findings = payload.get("findings", []) or []
        symbols = {
            _normalize_symbol(finding.get("symbol"))
            for finding in findings
            if isinstance(finding, dict) and _normalize_symbol(finding.get("symbol"))
        }
        usage = _extract_codex_usage(result.stdout)
        return {
            "elapsed_seconds": elapsed,
            "finding_count": len(findings),
            "symbols": sorted(symbols),
            "tokens_used": usage["input_tokens"] + usage["output_tokens"],
            "cached_input_tokens": usage["cached_input_tokens"],
        }


def _extract_codex_usage(stdout: str):
    usage = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
    }
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "turn.completed":
            continue
        event_usage = event.get("usage") or {}
        for key in usage:
            usage[key] = int(event_usage.get(key) or 0)
    return usage


def _aggregate(case_results: list[dict]):
    totals = {
        "skylos": {
            "score": 0.0,
            "recall": 0.0,
            "absence_guard": 0.0,
            "latency": 0.0,
            "time": 0.0,
            "tokens": 0,
        },
        "codex": {
            "score": 0.0,
            "recall": 0.0,
            "absence_guard": 0.0,
            "latency": 0.0,
            "time": 0.0,
            "tokens": 0,
            "cached_input_tokens": 0,
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
            totals[tool_name]["tokens"] += int(
                case[tool_name].get("tokens_used", 0) or 0
            )
            if tool_name == "codex":
                totals[tool_name]["cached_input_tokens"] += int(
                    case[tool_name].get("cached_input_tokens", 0) or 0
                )

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
            "total_tokens_used": int(values.get("tokens", 0) or 0),
            "total_cached_input_tokens": int(values.get("cached_input_tokens", 0) or 0),
        }
    return out


def _render(summary: dict) -> str:
    lines = [
        f"Cases: {summary['case_count']}",
        f"Codex model: {summary['codex_model']}",
        f"Skylos model: {summary['skylos_model']}",
        (
            "Skylos: "
            f"score={summary['aggregate']['skylos']['overall_score']} "
            f"recall={summary['aggregate']['skylos']['recall']} "
            f"absence_guard={summary['aggregate']['skylos']['absence_guard']} "
            f"latency={summary['aggregate']['skylos']['latency']} "
            f"time={summary['aggregate']['skylos']['total_time_seconds']:.4f}s "
            f"tokens={summary['aggregate']['skylos']['total_tokens_used']}"
        ),
        (
            "Codex: "
            f"score={summary['aggregate']['codex']['overall_score']} "
            f"recall={summary['aggregate']['codex']['recall']} "
            f"absence_guard={summary['aggregate']['codex']['absence_guard']} "
            f"latency={summary['aggregate']['codex']['latency']} "
            f"time={summary['aggregate']['codex']['total_time_seconds']:.4f}s "
            f"tokens={summary['aggregate']['codex']['total_tokens_used']} "
            f"cached_input_tokens={summary['aggregate']['codex']['total_cached_input_tokens']}"
        ),
    ]
    for case in summary["cases"]:
        lines.append(
            f"{case['id']} [{case['importance']}] Skylos={case['skylos']['scores']['overall_score']} Codex={case['codex']['scores']['overall_score']}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Codex vs Skylos on the agent review benchmark."
    )
    parser.add_argument(
        "--manifest", default=str(Path("agent_review_benchmarks") / "manifest.json")
    )
    parser.add_argument("--skylos-model", default="gpt-4.1")
    parser.add_argument("--codex-model", default="gpt-5.4")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    provider, api_key, base_url, is_local = resolve_llm_runtime(
        model=args.skylos_model,
        provider_override=args.provider,
        base_url_override=args.base_url,
        console=None,
        allow_prompt=False,
    )
    if args.api_key:
        api_key = args.api_key
    if not api_key and not is_local:
        raise SystemExit(
            "No API key configured for Skylos agent review. Pass --api-key, run `skylos key`, or use a local provider."
        )

    manifest = load_manifest(args.manifest)
    cases = validate_manifest(manifest, args.manifest)
    selected = set(args.case or [])
    manifest_root = Path(args.manifest).resolve().parent

    case_results = []
    for case in cases:
        if selected and case["id"] not in selected:
            continue
        case_path = (manifest_root / case["path"]).resolve()
        skylos = _run_skylos_agent_review(
            case_path,
            case=case,
            model=args.skylos_model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
        )
        codex = _run_codex(case_path, case, args.codex_model)
        case_results.append(
            {
                "id": case["id"],
                "importance": case.get("importance", "high"),
                "skylos": {
                    **skylos,
                    "scores": _score(
                        set(skylos["symbols"]),
                        skylos["finding_count"],
                        case,
                        skylos["elapsed_seconds"],
                    ),
                },
                "codex": {
                    **codex,
                    "scores": _score(
                        set(codex["symbols"]),
                        codex["finding_count"],
                        case,
                        codex["elapsed_seconds"],
                    ),
                },
            }
        )

    summary = {
        "manifest": str(Path(args.manifest).resolve()),
        "case_count": len(case_results),
        "skylos_model": args.skylos_model,
        "codex_model": args.codex_model,
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
