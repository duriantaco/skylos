from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from skylos.research.dead_code import (
    CandidateClassification,
    GroundTruthLabel,
    GroundTruthManifest,
    ResearchVariant,
    ScoreOutcome,
    load_manifest,
    run_ablation,
    score_ablation_result,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _route_fixture(tmp_path: Path) -> Path:
    _write(
        tmp_path / "app.py",
        """
        app = object()

        @app.get("/")
        def index():
            return render_dashboard()

        def render_dashboard():
            return "ok"

        def stale_helper():
            return "dead"
        """,
    )
    return tmp_path


def _manifest() -> GroundTruthManifest:
    return GroundTruthManifest.from_dict(
        {
            "name": "route-helper",
            "cases": [
                {"qualified_name": "app.index", "expected": "alive"},
                {"qualified_name": "app.render_dashboard", "expected": "alive"},
                {"qualified_name": "app.stale_helper", "expected": "dead"},
            ],
        }
    )


def test_score_v1_records_live_helper_false_positive(tmp_path: Path):
    root = _route_fixture(tmp_path)
    result = run_ablation(root, variant=ResearchVariant.ROOTS_ONLY)

    scored = score_ablation_result(result, _manifest())

    by_qname = {case.qualified_name: case for case in scored.cases}
    assert by_qname["app.index"].outcome == ScoreOutcome.TRUE_NEGATIVE
    assert by_qname["app.render_dashboard"].outcome == ScoreOutcome.FALSE_POSITIVE
    assert by_qname["app.render_dashboard"].predicted == (
        CandidateClassification.LIKELY_DEAD
    )
    assert by_qname["app.stale_helper"].outcome == ScoreOutcome.TRUE_POSITIVE
    assert scored.summary.to_dict() == {
        "positive_class": "dead",
        "tp": 1,
        "fp": 1,
        "fn": 0,
        "tn": 1,
        "abstain": 0,
        "missing": 0,
        "extra": 1,
        "precision": 0.5,
        "recall": 1.0,
        "f1": 0.666667,
        "accuracy": 0.666667,
    }


def test_score_v2_rescues_live_helper_and_keeps_stale_dead(tmp_path: Path):
    root = _route_fixture(tmp_path)
    result = run_ablation(root, variant=ResearchVariant.ROOTS_REACHABILITY)

    scored = score_ablation_result(result, _manifest())

    by_qname = {case.qualified_name: case for case in scored.cases}
    assert by_qname["app.index"].outcome == ScoreOutcome.TRUE_NEGATIVE
    assert by_qname["app.render_dashboard"].outcome == ScoreOutcome.TRUE_NEGATIVE
    assert by_qname["app.stale_helper"].outcome == ScoreOutcome.TRUE_POSITIVE
    assert scored.summary.precision == 1.0
    assert scored.summary.recall == 1.0
    assert scored.summary.f1 == 1.0
    assert scored.summary.accuracy == 1.0


def test_score_extra_predictions_include_only_unlabeled_dead_predictions(
    tmp_path: Path,
):
    root = _route_fixture(tmp_path)
    manifest = GroundTruthManifest.from_dict(
        {
            "name": "partial-route-helper",
            "cases": [
                {"qualified_name": "app.stale_helper", "expected": "dead"},
            ],
        }
    )
    result = run_ablation(root, variant=ResearchVariant.ROOTS_REACHABILITY)

    scored = score_ablation_result(result, manifest)

    assert scored.extra_predictions == ("app.app",)
    assert scored.summary.extra == 1
    assert scored.summary.false_positive == 0
    assert scored.summary.with_extra_as_false_positive().false_positive == 1

    payload = scored.to_dict()
    assert payload["summary"]["fp"] == 0
    assert payload["closed_world_summary"]["fp"] == 1
    assert payload["closed_world_summary"]["precision"] == 0.5


def test_binary_no_report_summary_counts_abstain_as_no_report(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        """
        from abc import ABC, abstractmethod

        class Base(ABC):
            @abstractmethod
            def process(self):
                pass

        class Removed:
            def run(self):
                return "dead"
        """,
    )
    manifest = GroundTruthManifest.from_dict(
        {
            "name": "abstain-binary",
            "cases": [
                {"qualified_name": "app.Base.process", "expected": "alive"},
                {"qualified_name": "app.Removed.run", "expected": "dead"},
            ],
        }
    )
    result = run_ablation(tmp_path, variant=ResearchVariant.GENERAL_ACTION_REPORTING)

    scored = score_ablation_result(result, manifest)

    assert scored.summary.abstain == 2
    assert scored.summary.false_negative == 0
    assert scored.summary.true_negative == 0
    assert scored.binary_no_report_summary.abstain == 2
    assert scored.binary_no_report_summary.false_negative == 1
    assert scored.binary_no_report_summary.true_negative == 1


def test_manifest_loader_accepts_aliases(tmp_path: Path):
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "name": "aliases",
                "cases": [
                    {"qname": "app.index", "expected": "live"},
                    {"qname": "app.stale_helper", "expected": "unused"},
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = load_manifest(path)

    assert manifest.cases[0].expected == GroundTruthLabel.ALIVE
    assert manifest.cases[1].expected == GroundTruthLabel.DEAD


def test_score_cli_outputs_all_variants(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    root = repo_root / "test" / "fixtures" / "research_dead_code" / "route_helper"
    manifest_path = root / "manifest.json"
    script = repo_root / "scripts" / "research_dead_code_score.py"

    completed = subprocess.run(
        [sys.executable, str(script), str(root), str(manifest_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    variants = {result["variant"]: result for result in payload["variants"]}
    assert variants["v1-roots-only"]["summary"]["fp"] == 1
    assert variants["v2-roots-reachability"]["summary"]["fp"] == 0
    assert variants["v3-top-level-execution"]["summary"]["fp"] == 0
    assert variants["v4-factory-return-summaries"]["summary"]["fp"] == 0
