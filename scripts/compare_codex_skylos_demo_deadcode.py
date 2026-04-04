#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.analyzer import analyze
from skylos.dead_code import collect_dead_code_findings
from skylos.demo_deadcode_benchmark import (
    DEFAULT_DEMO_ROOT,
    hard_cases,
    hard_case_keys,
    normalize_skylos_symbol,
    score_case_predictions,
)
from skylos.llm.runtime import resolve_llm_runtime
from skylos.llm.verify_orchestrator import run_verification


SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["cases"],
    "additionalProperties": False,
    "properties": {
        "cases": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "verdict", "confidence", "reason"],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["DEAD", "ALIVE"]},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "reason": {"type": "string"},
                },
            },
        }
    },
}


def _hard_case_prompt(cases: list) -> str:
    lines = []
    for case in cases:
        lines.append(f"- {case.key}")
    case_block = "\n".join(lines)
    return (
        "You are auditing dead code in a Python repository.\n"
        "Classify each listed symbol as DEAD or ALIVE based only on evidence in this repo.\n"
        "Rules:\n"
        "- ALIVE means any real runtime or test usage in this repo.\n"
        "- Dynamic usage counts: getattr(), globals(), registry maps, decorators, event listeners, task registries.\n"
        "- Ignore benchmark files, README.md, CHANGELOG.md, AGENTS.md, .venv/, and venv/ as evidence.\n"
        "- Do not speculate about external consumers outside this repo.\n"
        "- Return exactly one result per listed symbol.\n"
        "- Keep reasons short and concrete.\n"
        "Symbols:\n"
        f"{case_block}\n"
        "Return only JSON matching the schema."
    )


def _extract_codex_usage(stdout: str) -> dict[str, int]:
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


def _run_skylos(demo_root: Path, model: str) -> dict:
    provider, api_key, base_url, _is_local = resolve_llm_runtime(
        model=model,
        provider_override=None,
        base_url_override=None,
        allow_prompt=False,
    )
    start = time.perf_counter()
    raw = analyze(str(demo_root), grep_verify=False)
    results = json.loads(raw) if isinstance(raw, str) else raw
    findings = collect_dead_code_findings(results)
    defs_map = results.get("definitions", {}) or {}
    hard_keys = hard_case_keys()
    candidates = []
    for finding in findings:
        key = normalize_skylos_symbol(finding, demo_root)
        if key in hard_keys:
            copied = dict(finding)
            file, symbol = key.split("::", 1)
            copied["file"] = file
            copied["symbol"] = symbol
            candidates.append(copied)

    verification = run_verification(
        candidates,
        defs_map,
        demo_root,
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        max_verify=len(candidates),
        max_challenge=0,
        batch_mode=True,
        parallel_grep=True,
        verification_mode="judge_all",
        enable_entry_discovery=False,
        quiet=True,
    )
    elapsed = time.perf_counter() - start
    predicted_dead = {
        normalize_skylos_symbol(finding, demo_root)
        for finding in verification["verified_findings"]
        if finding.get("_llm_verdict") == "TRUE_POSITIVE"
    }
    predicted_dead.update(
        {
            normalize_skylos_symbol(finding, demo_root)
            for finding in verification.get("new_dead_code", [])
        }
    )
    return {
        "elapsed_seconds": round(elapsed, 2),
        "predicted_dead": sorted(predicted_dead),
        "candidate_count": len(candidates),
        "new_dead_count": len(verification.get("new_dead_code", [])),
        "verification_stats": verification["stats"],
    }


def _run_codex(demo_root: Path, model: str, cases: list) -> dict:
    with tempfile.TemporaryDirectory(prefix="codex-demo-deadcode-") as td:
        td_path = Path(td)
        schema_path = td_path / "schema.json"
        output_path = td_path / "output.json"
        schema_path.write_text(json.dumps(SCHEMA), encoding="utf-8")

        cmd = [
            "codex",
            "exec",
            "--json",
            "-C",
            str(demo_root),
            "--skip-git-repo-check",
            "--ephemeral",
            "--color",
            "never",
            "-s",
            "read-only",
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
            "-m",
            model,
            _hard_case_prompt(cases),
        ]

        start = time.perf_counter()
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.perf_counter() - start
        if result.returncode != 0:
            raise RuntimeError(
                f"Codex failed (exit={result.returncode}).\n"
                f"STDOUT:\n{result.stdout[-2000:]}\nSTDERR:\n{result.stderr[-2000:]}"
            )

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        predictions = payload.get("cases", []) or []
        predicted_dead = {
            str(item.get("id", "")).strip()
            for item in predictions
            if str(item.get("verdict", "")).strip().upper() == "DEAD"
        }
        usage = _extract_codex_usage(result.stdout)
        return {
            "elapsed_seconds": round(elapsed, 2),
            "predicted_dead": sorted(predicted_dead),
            "tokens_used": usage["input_tokens"] + usage["output_tokens"],
            "cached_input_tokens": usage["cached_input_tokens"],
            "output_tokens": usage["output_tokens"],
            "input_tokens": usage["input_tokens"],
            "raw_predictions": predictions,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Codex vs Skylos on an audited hard dead-code subset from skylos-demo."
    )
    parser.add_argument(
        "--demo-root",
        default=str(DEFAULT_DEMO_ROOT),
        help="Path to the skylos-demo repository.",
    )
    parser.add_argument(
        "--skylos-model",
        default="gpt-4.1",
        help="Model to use for Skylos dead-code verification.",
    )
    parser.add_argument(
        "--codex-model",
        default="gpt-5.4",
        help="Model to use for Codex.",
    )
    parser.add_argument(
        "--tool",
        choices=("both", "skylos", "codex"),
        default="both",
        help="Which tool(s) to run.",
    )
    args = parser.parse_args()

    demo_root = Path(args.demo_root).resolve()
    cases = hard_cases()

    output: dict[str, object] = {
        "benchmark": "skylos-demo-deadcode-hard24",
        "demo_root": str(demo_root),
        "case_count": len(cases),
        "cases": [
            {
                "id": case.key,
                "expected": case.expected,
                "rationale": case.rationale,
            }
            for case in cases
        ],
    }

    if args.tool in ("both", "skylos"):
        skylos_result = _run_skylos(demo_root, args.skylos_model)
        skylos_result["metrics"] = score_case_predictions(
            set(skylos_result["predicted_dead"]), cases
        )
        output["skylos"] = skylos_result

    if args.tool in ("both", "codex"):
        codex_result = _run_codex(demo_root, args.codex_model, cases)
        codex_result["metrics"] = score_case_predictions(
            set(codex_result["predicted_dead"]), cases
        )
        output["codex"] = codex_result

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
