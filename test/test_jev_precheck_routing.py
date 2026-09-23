"""Jev may route or judge static candidates, but never approve an LLM fix."""

from contextlib import ExitStack
import json
from unittest.mock import patch

import pytest

from skylos.llm.verify_orchestrator import run_verification
from skylos.commands.agent_verify_cmd import _confirmed_dead_findings


def _candidate(project):
    source = project / "module.py"
    source.write_text(  # skylos: ignore[SKY-D324] fixed fixture path under pytest tmp_path
        "def _spare():\n    return 1\n", encoding="utf-8"
    )
    return {
        "name": "_spare",
        "full_name": "module._spare",
        "file": str(source),
        "line": 1,
        "confidence": 75,
        "references": 0,
        "type": "function",
        "calls": [],
        "called_by": [],
    }


def _verify(project, finding):
    return run_verification(
        findings=[finding],
        defs_map={},
        project_root=project,
        model="test",
        api_key="test",
        batch_mode=False,
        quiet=True,
        jev_precheck=True,
        enable_entry_discovery=False,
        enable_suppression_challenge=False,
        enable_survivor_challenge=False,
    )


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_agreement_skips_broad_llm_but_retains_static_finding(
    triage, agent, _suppress, tmp_path
):
    triage.return_value = [
        {"status": "agreed", "choice": "unreferenced", "confidence": 0.96}
    ]
    finding = _candidate(tmp_path)

    result = _verify(tmp_path, finding)

    assert result["verified_findings"] == [finding]
    assert finding["_jev_agreed"] is True
    assert finding["_jev_status"] == "agreed"
    assert "_llm_verdict" not in finding
    assert "dead_code_disposition" not in finding
    assert result["stats"]["jev_agreed"] == 1
    assert result["stats"]["llm_calls"] == 0
    agent.return_value._call_llm.assert_not_called()


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [
        ({"status": "disagreed", "choice": "retained", "confidence": 0.9}, "disagreed"),
        (
            {
                "status": "uncertain",
                "choice": "insufficient_evidence",
                "confidence": 0.9,
            },
            "uncertain",
        ),
        (
            {"status": "uncertain", "choice": "unreferenced", "confidence": 0.79},
            "uncertain",
        ),
        ({"status": "unavailable", "choice": None, "confidence": None}, "unavailable"),
        (
            {"status": "agreed", "choice": "unreferenced", "confidence": 0.79},
            "unavailable",
        ),
    ],
)
@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_nonagreement_uses_broad_llm(
    triage, agent, _suppress, decision, expected_status, tmp_path
):
    triage.return_value = [decision]
    agent.return_value._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "no callers"}
    )
    finding = _candidate(tmp_path)

    result = _verify(tmp_path, finding)

    assert finding["_jev_status"] == expected_status
    assert not finding.get("_jev_agreed")
    assert finding["_llm_verdict"] == "TRUE_POSITIVE"
    assert result["stats"]["llm_calls"] == 1
    agent.return_value._call_llm.assert_called_once()


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings", side_effect=RuntimeError("failed"))
def test_adapter_exception_falls_back_to_broad_llm(_triage, agent, _suppress, tmp_path):
    agent.return_value._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "no callers"}
    )
    finding = _candidate(tmp_path)

    result = _verify(tmp_path, finding)

    assert finding["_jev_status"] == "unavailable"
    assert finding["_llm_verdict"] == "TRUE_POSITIVE"
    assert result["stats"]["jev_unavailable"] == 1


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_judge_retained_is_final_and_jev_sourced(triage, agent, _suppress, tmp_path):
    triage.return_value = [
        {
            "status": "disagreed",
            "choice": "retained",
            "confidence": 0.96,
            "choice_probability": 0.94,
        }
    ]
    finding = _candidate(tmp_path)

    with (
        patch(
            "skylos.llm.verify_orchestrator.run_entry_discovery_phase",
            side_effect=AssertionError("entry discovery ran before Jev"),
        ),
        patch(
            "skylos.llm.verify_orchestrator.run_survivor_challenge_phase",
            side_effect=AssertionError("survivor challenge ran after Jev"),
        ),
        patch(
            "skylos.llm.verify_orchestrator.run_haiku_prefilter_phase",
            side_effect=AssertionError("Haiku ran before fallback"),
        ),
    ):
        result = run_verification(
            findings=[finding],
            defs_map={},
            project_root=tmp_path,
            model="test",
            api_key="test",
            quiet=True,
            jev_judge=True,
        )

    assert finding["_jev_judged_retained"] is True
    assert finding["_llm_verdict"] == "FALSE_POSITIVE"
    assert finding["_verified_by_llm"] is False
    assert finding["_suppression_hard"] is True
    assert finding["_source"] == "jev_dead_code_verifier"
    assert finding["dead_code_evidence"][-1]["source"] == "jev_dead_code_verifier"
    assert result["stats"]["jev_judged_retained"] == 1
    assert result["stats"]["llm_calls"] == 0
    assert result["stats"]["suppression_challenged"] == 0
    assert result["stats"]["survivors_challenged"] == 0
    agent.return_value._call_llm.assert_not_called()
    triage.assert_called_once()
    assert triage.call_args.kwargs["min_confidence"] == 0.9


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_judge_unused_is_final_without_llm_or_fix_verdict(
    triage, agent, _suppress, tmp_path
):
    triage.return_value = [
        {
            "status": "agreed",
            "choice": "unreferenced",
            "confidence": 0.99,
            "choice_probability": 0.98,
        }
    ]
    finding = _candidate(tmp_path)
    finding["_llm_verdict"] = "TRUE_POSITIVE"  # A reused finding must be cleaned.

    result = run_verification(
        findings=[finding],
        defs_map={},
        project_root=tmp_path,
        model="test",
        api_key="test",
        quiet=True,
        jev_judge=True,
    )

    assert finding["_jev_agreed"] is True
    assert finding["_source"] == "jev_dead_code_verifier"
    assert finding["_verified_by_llm"] is False
    assert "_llm_verdict" not in finding
    assert result["stats"]["jev_agreed"] == 1
    assert result["stats"]["llm_calls"] == 0
    agent.return_value._call_llm.assert_not_called()


@pytest.mark.parametrize("choice", ["retained", "unreferenced"])
@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_judge_requires_both_confidence_and_probability(
    triage, agent, _suppress, choice, tmp_path
):
    triage.return_value = [
        {
            "status": "disagreed" if choice == "retained" else "agreed",
            "choice": choice,
            "confidence": 0.99,
            "choice_probability": 0.89,
        }
    ]
    agent.return_value._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "no callers"}
    )
    finding = _candidate(tmp_path)

    result = run_verification(
        findings=[finding],
        defs_map={},
        project_root=tmp_path,
        model="test",
        api_key="test",
        quiet=True,
        jev_judge=True,
        enable_suppression_challenge=False,
        batch_mode=False,
    )

    assert result["stats"]["llm_calls"] == 1
    assert not finding.get("_jev_judged_retained")
    assert not finding.get("_jev_agreed")
    assert finding["_llm_verdict"] == "TRUE_POSITIVE"


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
@patch("skylos.llm.jev_triage.triage_findings")
def test_judge_retained_does_not_propagate_alive_to_llm_dead_callee(
    triage, agent, _suppress, tmp_path
):
    source = tmp_path / "module.py"
    source.write_text(
        "def caller():\n    return callee()\n\ndef callee():\n    return 1\n",
        encoding="utf-8",
    )
    caller = {
        "name": "caller",
        "full_name": "module.caller",
        "file": str(source),
        "line": 1,
        "confidence": 75,
        "references": 0,
        "type": "function",
        "calls": ["module.callee"],
        "called_by": [],
    }
    callee = {
        "name": "callee",
        "full_name": "module.callee",
        "file": str(source),
        "line": 4,
        "confidence": 75,
        "references": 0,
        "type": "function",
        "calls": [],
        "called_by": ["module.caller"],
    }
    triage.return_value = [
        {
            "status": "disagreed",
            "choice": "retained",
            "confidence": 0.96,
            "choice_probability": 0.94,
        },
        {
            "status": "uncertain",
            "choice": "unreferenced",
            "confidence": 0.7,
            "choice_probability": 0.7,
        },
    ]
    agent.return_value._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "no live callers"}
    )

    result = run_verification(
        findings=[caller, callee],
        defs_map={},
        project_root=tmp_path,
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        jev_judge=True,
        enable_suppression_challenge=False,
    )

    assert caller["_jev_judged_retained"] is True
    assert caller["_llm_verdict"] == "FALSE_POSITIVE"
    assert callee["_llm_verdict"] == "TRUE_POSITIVE"
    assert not callee.get("_llm_challenged")
    assert result["stats"]["verified_true_positive"] == 1
    assert result["stats"]["llm_calls"] == 1


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
def test_judge_without_jev_key_uses_broad_candidate_verifier(
    agent, _suppress, tmp_path, monkeypatch
):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    agent.return_value._call_llm.return_value = json.dumps(
        {"verdict": "TRUE_POSITIVE", "rationale": "no callers"}
    )
    finding = _candidate(tmp_path)

    result = run_verification(
        findings=[finding],
        defs_map={},
        project_root=tmp_path,
        model="test",
        api_key="test",
        quiet=True,
        batch_mode=False,
        jev_judge=True,
        enable_suppression_challenge=False,
    )

    assert finding["_jev_status"] == "unavailable"
    assert not finding.get("_jev_judged_retained")
    assert finding["_llm_verdict"] == "TRUE_POSITIVE"
    assert result["stats"]["jev_unavailable"] == 1
    assert result["stats"]["llm_calls"] == 1


def _verify_jev_only_without_llm_phases(project, finding):
    """Keep default LLM phases enabled to catch accidental Jev-only calls."""
    phase_names = (
        "run_entry_discovery_phase",
        "run_haiku_prefilter_phase",
        "run_verify_findings_phase",
        "run_suppression_audit_phase",
        "run_survivor_challenge_phase",
    )
    with ExitStack() as stack:
        for name in phase_names:
            stack.enter_context(
                patch(
                    f"skylos.llm.verify_orchestrator.{name}",
                    side_effect=AssertionError(f"{name} ran in Jev-only mode"),
                )
            )
        agent = stack.enter_context(
            patch("skylos.llm.verify_orchestrator.DeadCodeVerifierAgent")
        )
        result = run_verification(
            findings=[finding],
            defs_map={},
            project_root=project,
            model="test",
            api_key=None,
            quiet=True,
            jev_judge=True,
            jev_only=True,
        )
    agent.return_value._call_llm.assert_not_called()
    return result


@pytest.mark.parametrize(
    ("decision", "expected_field"),
    [
        (
            {
                "status": "agreed",
                "choice": "unreferenced",
                "confidence": 0.96,
                "choice_probability": 0.95,
            },
            "_jev_agreed",
        ),
        (
            {
                "status": "disagreed",
                "choice": "retained",
                "confidence": 0.96,
                "choice_probability": 0.95,
            },
            "_jev_judged_retained",
        ),
    ],
)
@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.jev_triage.triage_findings")
def test_jev_only_accepts_confident_judgments_without_llm_or_fix(
    triage, _suppress, decision, expected_field, tmp_path
):
    triage.return_value = [decision]
    finding = _candidate(tmp_path)
    finding["_llm_verdict"] = "TRUE_POSITIVE"  # Reused input is not LLM proof.

    result = _verify_jev_only_without_llm_phases(tmp_path, finding)

    assert result["verified_findings"] == [finding]
    assert finding[expected_field] is True
    assert finding["_verified_by_llm"] is False
    assert finding["_source"] == "jev_dead_code_verifier"
    assert finding.get("_llm_verdict") != "TRUE_POSITIVE"
    assert _confirmed_dead_findings(
        result["verified_findings"], result["new_dead_code"]
    ) == []
    assert result["stats"]["llm_calls"] == 0
    assert result["new_dead_code"] == []


@pytest.mark.parametrize(
    "decision",
    [
        {
            "status": "uncertain",
            "choice": "insufficient_evidence",
            "confidence": 0.8,
            "choice_probability": 0.8,
        },
        {"status": "unavailable", "choice": None, "confidence": None},
        {
            "status": "agreed",
            "choice": "unreferenced",
            "confidence": 0.99,
            "choice_probability": 0.89,
        },
    ],
)
@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.jev_triage.triage_findings")
def test_jev_only_keeps_unresolved_static_findings_unverified(
    triage, _suppress, decision, tmp_path
):
    triage.return_value = [decision]
    finding = _candidate(tmp_path)
    finding["_llm_verdict"] = "TRUE_POSITIVE"  # Must not authorize a later fix.

    result = _verify_jev_only_without_llm_phases(tmp_path, finding)

    assert result["verified_findings"] == [finding]
    assert finding["_jev_status"] in {"uncertain", "unavailable"}
    assert finding["_jev_unverified"] is True
    assert not finding.get("_jev_agreed")
    assert not finding.get("_jev_judged_retained")
    assert finding["_verified_by_llm"] is False
    assert "_llm_verdict" not in finding
    assert _confirmed_dead_findings(
        result["verified_findings"], result["new_dead_code"]
    ) == []
    assert result["stats"]["llm_calls"] == 0
    assert result["new_dead_code"] == []


@patch("skylos.llm.verify_orchestrator._deterministic_suppress", return_value=None)
@patch("skylos.llm.jev_triage.triage_findings", side_effect=RuntimeError("offline"))
def test_jev_only_outage_does_not_call_llm_or_approve_fix(
    _triage, _suppress, tmp_path
):
    finding = _candidate(tmp_path)

    result = _verify_jev_only_without_llm_phases(tmp_path, finding)

    assert result["verified_findings"] == [finding]
    assert finding["_jev_status"] == "unavailable"
    assert finding["_jev_unverified"] is True
    assert "_llm_verdict" not in finding
    assert _confirmed_dead_findings(
        result["verified_findings"], result["new_dead_code"]
    ) == []
    assert result["stats"]["llm_calls"] == 0
