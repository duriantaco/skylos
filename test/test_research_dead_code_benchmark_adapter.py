from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from skylos.research.dead_code import (
    ScoreOutcome,
    evaluate_benchmark_manifest,
    write_benchmark_evaluation,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _benchmark_root(tmp_path: Path) -> Path:
    root = tmp_path / "benchmarks"
    _write(
        root / "corpora" / "seeded" / "dead_code" / "route_helper" / "app.py",
        """
        app = object()

        @app.get("/")
        def index():
            return render_dashboard()

        def render_dashboard():
            return "ok"

        def stale_helper():
            return "dead"

        class UnsupportedController:
            def action(self):
                return "unsupported class label"

        UNUSED_FLAG = True
        """,
    )
    _write(
        root / "manifests" / "dead_code.dev.json",
        """
        {
          "schema_version": "skylos-golden-benchmark/v1",
          "suite": "dead_code",
          "split": "dev",
          "label_state": "frozen",
          "cases": [
            {
              "id": "route-helper",
              "languages": ["python"],
              "label_coverage": "closed",
              "source": {
                "origin": "seeded",
                "local_path": "corpora/seeded/dead_code/route_helper",
                "license": "Apache-2.0",
                "provenance": "test fixture"
              },
              "labels": [
                {
                  "id": "route-root",
                  "expectation": "should_not_report",
                  "category": "framework_entrypoint",
                  "match": {"path": "app.py", "symbol": "index"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "route"}
                },
                {
                  "id": "live-helper",
                  "expectation": "should_not_report",
                  "category": "live_function",
                  "match": {"path": "app.py", "symbol": "render_dashboard"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "called"}
                },
                {
                  "id": "stale-helper",
                  "expectation": "should_report",
                  "category": "unused_function",
                  "match": {"path": "app.py", "symbol": "stale_helper"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "unused"}
                },
                {
                  "id": "unsupported-class",
                  "expectation": "should_report",
                  "category": "unused_class",
                  "match": {"path": "app.py", "symbol": "UnsupportedController"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "class"}
                },
                {
                  "id": "unused-variable",
                  "expectation": "should_report",
                  "category": "unused_variable",
                  "match": {"path": "app.py", "symbol": "UNUSED_FLAG"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "variable"}
                }
              ]
            },
            {
              "id": "ts-skip",
              "languages": ["typescript"],
              "label_coverage": "closed",
              "source": {
                "origin": "seeded",
                "local_path": "corpora/seeded/dead_code/ts_skip",
                "license": "Apache-2.0",
                "provenance": "test fixture"
              },
              "labels": [
                {
                  "id": "ts-label",
                  "expectation": "should_report",
                  "category": "unused_function",
                  "match": {"path": "src/app.ts", "symbol": "unused"},
                  "review": {"state": "frozen", "reviewer": "test", "reason": "skip"}
                }
              ]
            }
          ]
        }
        """,
    )
    return root


def test_benchmark_adapter_scores_python_class_function_method_subset(tmp_path: Path):
    root = _benchmark_root(tmp_path)

    evaluation = evaluate_benchmark_manifest(root, "manifests/dead_code.dev.json")

    assert len(evaluation.cases) == 1
    assert len(evaluation.skipped_cases) == 1
    case = evaluation.cases[0]
    assert case.manifest.name == "route-helper"
    assert len(case.manifest.cases) == 5
    assert case.skipped_labels == ()

    v1_cases = {
        item.qualified_name: item
        for item in case.scores["v1-roots-only"].cases
    }
    v2_cases = {
        item.qualified_name: item
        for item in case.scores["v2-roots-reachability"].cases
    }
    assert v1_cases["app.render_dashboard"].outcome == ScoreOutcome.FALSE_POSITIVE
    assert v2_cases["app.render_dashboard"].outcome == ScoreOutcome.TRUE_NEGATIVE

    aggregate = evaluation.aggregate_summary()
    assert aggregate["v1-roots-only"]["fp"] == 1
    assert aggregate["v2-roots-reachability"]["fp"] == 0
    assert aggregate["v3-top-level-execution"]["fp"] == 0
    assert aggregate["v4-factory-return-summaries"]["fp"] == 0
    closed_world = evaluation.closed_world_aggregate_summary()
    assert closed_world["v2-roots-reachability"]["fp"] == 2
    assert closed_world["v4-factory-return-summaries"]["fp"] == 1
    assert evaluation.to_dict()["scope"]["symbol_kinds"] == [
        "class",
        "function",
        "method",
        "variable",
    ]
    assert evaluation.to_dict()["runtime_seconds"]["v1-roots-only"] >= 0


def test_benchmark_adapter_retains_summary_raw_and_scores(tmp_path: Path):
    root = _benchmark_root(tmp_path)
    evaluation = evaluate_benchmark_manifest(root, "manifests/dead_code.dev.json")

    output_dir = write_benchmark_evaluation(evaluation, tmp_path / "results")

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["case_count"] == 1
    assert (output_dir / "research_subset_manifest.json").exists()
    assert (output_dir / "raw" / "route-helper" / "v1-roots-only.json").exists()
    assert (
        output_dir
        / "scores"
        / "route-helper"
        / "v2-roots-reachability.json"
    ).exists()


def test_benchmark_cli_writes_results(tmp_path: Path):
    root = _benchmark_root(tmp_path)
    output_path = tmp_path / "summary.json"
    results_dir = tmp_path / "retained"
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "research_dead_code_benchmark.py"
    )

    subprocess.run(
        [
            sys.executable,
            str(script),
            "--benchmark-root",
            str(root),
            "--manifest",
            "manifests/dead_code.dev.json",
            "--write-results",
            "--results-dir",
            str(results_dir),
            "--output",
            str(output_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["retained_result_dir"] == str(results_dir.resolve())
    assert payload["aggregate"]["v1-roots-only"]["fp"] == 1
    assert payload["aggregate"]["v2-roots-reachability"]["fp"] == 0
    assert payload["aggregate"]["v3-top-level-execution"]["fp"] == 0
    assert payload["aggregate"]["v4-factory-return-summaries"]["fp"] == 0
    assert payload["closed_world_aggregate"]["v4-factory-return-summaries"]["fp"] == 1
    assert (results_dir / "summary.json").exists()
