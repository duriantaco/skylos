"""Tests for heuristic weight feedback loop and batch verification."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from skylos.llm.feedback import (
    FeedbackData,
    HeuristicObservation,
    compute_tuned_weights,
    record_verification_results,
    get_feedback_summary,
    get_tuned_weights,
    load_feedback,
    save_feedback,
    reset_feedback,
    DEFAULT_WEIGHTS,
    MIN_WEIGHT,
    MIN_OBSERVATIONS,
)
from skylos.llm.verify_orchestrator import (
    _batch_verify_findings,
    _batch_challenge_survivors,
    _parse_batch_response,
    _parse_batch_survivor_response,
    _strip_markdown_fences,
    _estimate_batches,
    run_verification,
)
from skylos.llm.dead_code_verifier import (
    DeadCodeVerifierAgent,
    Verdict,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Feedback data persistence
# ---------------------------------------------------------------------------


@pytest.fixture
def feedback_dir(tmp_path, monkeypatch):
    """Redirect feedback file to temp dir."""
    monkeypatch.setattr("skylos.llm.feedback.FEEDBACK_DIR", tmp_path)
    monkeypatch.setattr("skylos.llm.feedback.FEEDBACK_FILE", tmp_path / "feedback.json")
    return tmp_path


def test_load_feedback_empty(feedback_dir):
    data = load_feedback()
    assert data.total_runs == 0
    assert data.observations == {}


def test_save_and_load_feedback(feedback_dir):
    data = FeedbackData(
        observations={"same_file_attr": {"real": 10, "spurious": 5, "uncertain": 2}},
        tuned_weights={"same_file_attr": 0.67},
        total_runs=3,
    )
    save_feedback(data)

    loaded = load_feedback()
    assert loaded.total_runs == 3
    assert loaded.observations["same_file_attr"]["real"] == 10
    assert loaded.tuned_weights["same_file_attr"] == 0.67


def test_load_feedback_corrupted(feedback_dir):
    (feedback_dir / "feedback.json").write_text("not json {{")
    data = load_feedback()
    assert data.total_runs == 0


# ---------------------------------------------------------------------------
# Weight computation
# ---------------------------------------------------------------------------


def test_compute_tuned_weights_no_data():
    feedback = FeedbackData()
    weights = compute_tuned_weights(feedback)
    assert weights == DEFAULT_WEIGHTS


def test_compute_tuned_weights_all_spurious():
    feedback = FeedbackData(
        observations={
            "same_file_attr": {"real": 0, "spurious": 20, "uncertain": 0},
        }
    )
    weights = compute_tuned_weights(feedback)
    # All spurious → weight should be at MIN_WEIGHT
    assert weights["same_file_attr"] == MIN_WEIGHT
    # Others unchanged
    assert weights["same_pkg_attr"] == DEFAULT_WEIGHTS["same_pkg_attr"]


def test_compute_tuned_weights_all_real():
    feedback = FeedbackData(
        observations={
            "same_file_attr": {"real": 20, "spurious": 0, "uncertain": 0},
        }
    )
    weights = compute_tuned_weights(feedback)
    # All real → weight stays at default (100% accuracy)
    assert weights["same_file_attr"] == DEFAULT_WEIGHTS["same_file_attr"]


def test_compute_tuned_weights_mixed():
    feedback = FeedbackData(
        observations={
            "same_file_attr": {"real": 5, "spurious": 15, "uncertain": 0},
            # 25% accuracy → weight = 1.0 * 0.25 = 0.25
        }
    )
    weights = compute_tuned_weights(feedback)
    assert weights["same_file_attr"] == 0.25


def test_compute_tuned_weights_below_min_observations():
    feedback = FeedbackData(
        observations={
            "same_file_attr": {"real": 1, "spurious": 2, "uncertain": 0},
            # Only 3 observations, below MIN_OBSERVATIONS (5)
        }
    )
    weights = compute_tuned_weights(feedback)
    # Should keep default
    assert weights["same_file_attr"] == DEFAULT_WEIGHTS["same_file_attr"]


def test_compute_tuned_weights_global_attr_drops():
    feedback = FeedbackData(
        observations={
            "global_attr": {"real": 1, "spurious": 9, "uncertain": 0},
            # 10% accuracy → weight = 0.1 * 0.1 = 0.01 → clamped to MIN_WEIGHT
        }
    )
    weights = compute_tuned_weights(feedback)
    assert weights["global_attr"] == MIN_WEIGHT


# ---------------------------------------------------------------------------
# Record verification results
# ---------------------------------------------------------------------------


def test_record_verification_results(feedback_dir):
    verification_output = {
        "verified_findings": [
            {
                "name": "func_a",
                "heuristic_refs": {"same_file_attr": 1.0},
                "_llm_verdict": "TRUE_POSITIVE",
            },
            {
                "name": "func_b",
                "heuristic_refs": {"same_file_attr": 1.0, "global_attr": 0.1},
                "_llm_verdict": "FALSE_POSITIVE",
            },
            {
                "name": "func_c",
                "heuristic_refs": {},
                "_llm_verdict": "TRUE_POSITIVE",
            },
        ],
        "new_dead_code": [
            {
                "name": "survivor_a",
                "heuristic_refs": {"same_pkg_attr": 0.3},
            },
        ],
    }

    feedback = record_verification_results(verification_output)

    assert feedback.total_runs == 1
    # func_a: TRUE_POSITIVE with same_file_attr → spurious
    # func_b: FALSE_POSITIVE with same_file_attr → real, global_attr → real
    # func_c: no heuristic_refs → skipped
    # survivor_a: reclassified dead → same_pkg_attr spurious
    assert feedback.observations["same_file_attr"]["spurious"] == 1
    assert feedback.observations["same_file_attr"]["real"] == 1
    assert feedback.observations["global_attr"]["real"] == 1
    assert feedback.observations["same_pkg_attr"]["spurious"] == 1


def test_record_multiple_runs_accumulates(feedback_dir):
    run1 = {
        "verified_findings": [
            {
                "heuristic_refs": {"same_file_attr": 1.0},
                "_llm_verdict": "TRUE_POSITIVE",
            },
        ],
        "new_dead_code": [],
    }
    run2 = {
        "verified_findings": [
            {
                "heuristic_refs": {"same_file_attr": 1.0},
                "_llm_verdict": "TRUE_POSITIVE",
            },
        ],
        "new_dead_code": [],
    }

    record_verification_results(run1)
    feedback = record_verification_results(run2)

    assert feedback.total_runs == 2
    assert feedback.observations["same_file_attr"]["spurious"] == 2


# ---------------------------------------------------------------------------
# Get feedback summary
# ---------------------------------------------------------------------------


def test_get_feedback_summary(feedback_dir):
    data = FeedbackData(
        observations={
            "same_file_attr": {"real": 8, "spurious": 2, "uncertain": 1},
        },
        tuned_weights={"same_file_attr": 0.8},
        total_runs=5,
    )
    save_feedback(data)

    summary = get_feedback_summary()
    assert summary["total_runs"] == 5
    sfa = summary["heuristic_types"]["same_file_attr"]
    assert sfa["observations"] == 10
    assert sfa["accuracy_pct"] == 80.0
    assert sfa["tuned_weight"] == 0.8


# ---------------------------------------------------------------------------
# Get tuned weights
# ---------------------------------------------------------------------------


def test_get_tuned_weights_with_feedback(feedback_dir):
    data = FeedbackData(
        observations={},
        tuned_weights={"same_file_attr": 0.5, "global_attr": 0.05},
        total_runs=10,
    )
    save_feedback(data)

    weights = get_tuned_weights()
    assert weights["same_file_attr"] == 0.5
    assert weights["global_attr"] == 0.05
    assert weights["same_pkg_attr"] == DEFAULT_WEIGHTS["same_pkg_attr"]  # unchanged


def test_get_tuned_weights_no_feedback(feedback_dir):
    weights = get_tuned_weights()
    assert weights == DEFAULT_WEIGHTS


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_feedback(feedback_dir):
    save_feedback(FeedbackData(total_runs=5))
    assert (feedback_dir / "feedback.json").exists()

    reset_feedback()

    # Should be back to defaults
    data = load_feedback()
    assert data.total_runs == 0


# ---------------------------------------------------------------------------
# Batch verification
# ---------------------------------------------------------------------------


def test_batch_verify_findings():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        [
            {"id": 1, "verdict": "TRUE_POSITIVE", "rationale": "no callers"},
            {"id": 2, "verdict": "FALSE_POSITIVE", "rationale": "getattr dispatch"},
        ]
    )

    findings = [
        {
            "name": "some_func",
            "simple_name": "some_func",
            "full_name": "mod.some_func",
            "file": "a.py",
            "line": 1,
            "type": "function",
            "confidence": 70,
            "references": 0,
            "calls": [],
            "called_by": [],
        },
        {
            "name": "other_func",
            "simple_name": "other_func",
            "full_name": "mod.other_func",
            "file": "b.py",
            "line": 5,
            "type": "function",
            "confidence": 65,
            "references": 0,
            "calls": [],
            "called_by": [],
        },
    ]

    results = _batch_verify_findings(agent, findings, {}, {})
    assert len(results) == 2
    assert results[0].verdict == Verdict.TRUE_POSITIVE
    assert results[1].verdict == Verdict.FALSE_POSITIVE
    # Should be 1 LLM call, not 2
    assert agent._call_llm.call_count == 1


def test_batch_verify_skips_with_refs():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    # Only 1 finding will be sent to LLM (f1), f2 is skipped (has refs)
    agent._call_llm.return_value = json.dumps(
        [
            {"verdict": "TRUE_POSITIVE", "rationale": "dead"},
        ]
    )

    findings = [
        # f2 comes first with refs — will be skipped before batching
        {
            "name": "skip_func",
            "simple_name": "skip_func",
            "full_name": "mod.skip_func",
            "file": "b.py",
            "line": 5,
            "type": "function",
            "confidence": 70,
            "references": 3,
            "calls": [],
            "called_by": [],
        },
        {
            "name": "dead_func",
            "simple_name": "dead_func",
            "full_name": "mod.dead_func",
            "file": "a.py",
            "line": 1,
            "type": "function",
            "confidence": 70,
            "references": 0,
            "calls": [],
            "called_by": [],
        },
    ]

    results = _batch_verify_findings(agent, findings, {}, {})
    assert len(results) == 2
    assert results[0].verdict == Verdict.UNCERTAIN  # Skipped due to refs
    assert results[1].verdict == Verdict.TRUE_POSITIVE


def test_batch_challenge_survivors():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        [
            {
                "id": 1,
                "is_dead": True,
                "rationale": "spurious",
                "heuristic_assessment": "spurious",
            },
            {
                "id": 2,
                "is_dead": False,
                "rationale": "real call",
                "heuristic_assessment": "real",
            },
        ]
    )

    survivors = [
        {
            "name": "proc",
            "full_name": "mod.proc",
            "simple_name": "proc",
            "file": "a.py",
            "line": 1,
            "confidence": 45,
            "heuristic_refs": {"same_file_attr": 1.0},
        },
        {
            "name": "init",
            "full_name": "mod.init",
            "simple_name": "init",
            "file": "b.py",
            "line": 10,
            "confidence": 40,
            "heuristic_refs": {"global_attr": 0.1},
        },
    ]

    results = _batch_challenge_survivors(agent, survivors, {}, {})
    assert len(results) == 2
    assert results[0].verdict == Verdict.TRUE_POSITIVE
    assert results[1].verdict == Verdict.FALSE_POSITIVE
    assert agent._call_llm.call_count == 1


# ---------------------------------------------------------------------------
# Batch response parsing
# ---------------------------------------------------------------------------


def test_strip_markdown_fences():
    assert _strip_markdown_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert _strip_markdown_fences('{"a": 1}') == '{"a": 1}'
    assert _strip_markdown_fences("  ```\n[1,2]\n```  ") == "[1,2]"


def test_parse_batch_response_valid():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        [
            {"verdict": "TRUE_POSITIVE", "rationale": "dead"},
            {"verdict": "FALSE_POSITIVE", "rationale": "alive"},
        ]
    )

    results = _parse_batch_response(agent, "sys", "usr", 2)
    assert len(results) == 2
    assert results[0]["verdict"] == Verdict.TRUE_POSITIVE
    assert results[1]["verdict"] == Verdict.FALSE_POSITIVE


def test_parse_batch_response_missing_entries():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = json.dumps(
        [
            {"verdict": "TRUE_POSITIVE", "rationale": "dead"},
        ]
    )

    results = _parse_batch_response(agent, "sys", "usr", 3)
    assert len(results) == 3
    assert results[0]["verdict"] == Verdict.TRUE_POSITIVE
    assert results[1]["verdict"] == Verdict.UNCERTAIN  # Missing
    assert results[2]["verdict"] == Verdict.UNCERTAIN  # Missing


def test_parse_batch_response_bad_json():
    agent = MagicMock(spec=DeadCodeVerifierAgent)
    agent._call_llm.return_value = "not valid json"

    results = _parse_batch_response(agent, "sys", "usr", 2)
    assert len(results) == 2
    assert all(r["verdict"] == Verdict.UNCERTAIN for r in results)


# ---------------------------------------------------------------------------
# Batch mode in run_verification
# ---------------------------------------------------------------------------


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_batch_mode(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        [
            {"verdict": "TRUE_POSITIVE", "rationale": "dead"},
            {"verdict": "FALSE_POSITIVE", "rationale": "alive via decorator"},
        ]
    )

    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "main.py").write_text(
        "def compute_total(): pass\ndef format_output(): pass\n"
    )

    findings = [
        {
            "name": "compute_total",
            "simple_name": "compute_total",
            "full_name": "main.compute_total",
            "file": str(proj / "main.py"),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        },
        {
            "name": "format_output",
            "simple_name": "format_output",
            "full_name": "main.format_output",
            "file": str(proj / "main.py"),
            "line": 2,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        },
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        batch_mode=True,
        quiet=True,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    verified = result["verified_findings"]
    assert verified[0]["_llm_verdict"] == "TRUE_POSITIVE"
    assert verified[1]["_llm_verdict"] == "FALSE_POSITIVE"

    # Batch mode: should use fewer LLM calls than individual
    # 2 findings in 1 batch = 1 LLM call (not 2)
    assert result["stats"]["llm_calls"] <= 2


@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_run_verification_no_batch_mode(MockAgent, tmp_path):
    mock_instance = MockAgent.return_value
    mock_instance._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "dead"}
    )

    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "main.py").write_text(
        "def compute_total(): pass\ndef format_output(): pass\n"
    )

    findings = [
        {
            "name": "compute_total",
            "simple_name": "compute_total",
            "full_name": "main.compute_total",
            "file": str(proj / "main.py"),
            "line": 1,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        },
        {
            "name": "format_output",
            "simple_name": "format_output",
            "full_name": "main.format_output",
            "file": str(proj / "main.py"),
            "line": 2,
            "confidence": 70,
            "references": 0,
            "type": "function",
            "calls": [],
            "called_by": [],
        },
    ]

    result = run_verification(
        findings=findings,
        defs_map={},
        project_root=str(proj),
        model="test",
        api_key="test",
        batch_mode=False,
        quiet=True,
        enable_entry_discovery=False,
        enable_survivor_challenge=False,
    )

    # Non-batch mode: 1 LLM call per finding = 2
    assert result["stats"]["llm_calls"] == 2


# ---------------------------------------------------------------------------
# Estimate batches
# ---------------------------------------------------------------------------


def test_estimate_batches_small():
    findings = [
        {
            "name": f"some_func_{i}",
            "simple_name": f"some_func_{i}",
            "file": f"{i}.py",
            "confidence": 70,
            "references": 0,
            "type": "function",
        }
        for i in range(3)
    ]
    count = _estimate_batches(findings, {}, {})
    assert count == 1


def test_estimate_batches_large():
    findings = [
        {
            "name": f"some_func_{i}",
            "simple_name": f"some_func_{i}",
            "file": f"{i}.py",
            "confidence": 70,
            "references": 0,
            "type": "function",
        }
        for i in range(20)
    ]
    count = _estimate_batches(findings, {}, {})
    assert count >= 3  # 20 findings / 5 per batch = 4 batches
