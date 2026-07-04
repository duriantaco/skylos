from __future__ import annotations

from pathlib import Path

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cache_api_symbol_surface,
)
from skylos.core.python_api_surface import python_environment_key
from skylos.llm.harness import (
    AIDefectChallengeDecision,
    HighImpactFindingDetector,
    build_ai_defect_challenge_prompt,
    normalize_ai_defect_challenge_decisions,
    run_ai_defect_challenge_harness,
)


def _finding(
    *,
    rule_id: str = "SKY-D224",
    severity: str = "HIGH",
    file_path: str = "app.py",
    line: int = 2,
    message: str = "Installed package 'requests' does not expose requests.fetch_json",
    symbol: str = "requests.fetch_json",
) -> dict:
    return {
        "rule_id": rule_id,
        "category": "ai_defect",
        "severity": severity,
        "ai_likelihood": "high" if severity == "HIGH" else "medium",
        "message": message,
        "range": {
            "file": file_path,
            "start_line": line,
            "end_line": line,
        },
        "metadata": {"symbol": symbol},
    }


def test_high_impact_detector_builds_probe_and_skips_medium_findings(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "requests.fetch_json('https://example.test')\n",
        encoding="utf-8",
    )
    findings = [
        _finding(rule_id="SKY-D224", severity="HIGH"),
        _finding(
            rule_id="SKY-A101",
            severity="MEDIUM",
            message="Specific assertion was replaced with a broad truthiness check",
        ),
    ]

    probes = HighImpactFindingDetector().select(findings, project_root=tmp_path)
    prompt = build_ai_defect_challenge_prompt(probes)

    assert [probe.rule_id for probe in probes] == ["SKY-D224"]
    assert "Use this Chain-of-Verification" in prompt
    assert "=== BEGIN UNTRUSTED CODE CONTEXT ===" in prompt
    assert "requests.fetch_json" in prompt


def test_refuted_without_static_proof_becomes_uncertain(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "requests.fetch_json('https://example.test')\n",
        encoding="utf-8",
    )
    findings = [_finding()]

    def challenge(_probes, _prompt):
        return {
            "decisions": [
                {
                    "id": 1,
                    "verdict": "REFUTED",
                    "reason": "looks okay",
                    "static_proof": "",
                    "proof_kind": "",
                    "proof_lines": [],
                }
            ]
        }

    result = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=tmp_path,
        challenge_func=challenge,
        harness_run_id="no-proof",
        harness_trace_root=tmp_path / "runs",
    )

    challenge_metadata = result.output["challenge"]
    assert challenge_metadata["deterministic_findings_retained"] is True
    assert challenge_metadata["outcome_counts"]["refuted"] == 0
    assert challenge_metadata["outcome_counts"]["uncertain"] == 1
    assert challenge_metadata["outcomes"][0]["suppression_allowed"] is False
    assert result.run.budget_used()["llm_calls"] == 1


def test_refuted_with_proof_shaped_response_without_deterministic_proof_is_uncertain(
    tmp_path: Path,
):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "requests.fetch_json('https://example.test')\n",
        encoding="utf-8",
    )
    findings = [_finding()]

    def challenge(_probes, _prompt):
        return {
            "decisions": [
                {
                    "id": 1,
                    "verdict": "REFUTED",
                    "reason": "not applicable",
                    "static_proof": "Line 2 proves this should be ignored.",
                    "proof_kind": "not_applicable",
                    "proof_lines": [2],
                }
            ]
        }

    result = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=tmp_path,
        challenge_func=challenge,
        harness_run_id="fake-proof",
        harness_trace_root=tmp_path / "runs",
    )

    counts = result.output["challenge"]["outcome_counts"]
    assert counts["refuted"] == 0
    assert counts["uncertain"] == 1
    assert counts["suppression_allowed"] == 0


def test_refuted_with_static_proof_exports_suppression_allowed_metadata(
    tmp_path: Path,
):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "requests.get('https://example.test')\n",
        encoding="utf-8",
    )
    assert cache_api_symbol_surface(
        tmp_path,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "requests",
            "environment_key": python_environment_key(),
            "members": {
                "get": {
                    "kind": "function",
                    "parameters": [],
                }
            },
        },
    )
    findings = [
        _finding(
            message="Installed package 'requests' does not expose requests.get",
            symbol="requests.get",
        )
    ]

    def challenge(_probes, _prompt):
        return {
            "decisions": [
                {
                    "id": 1,
                    "verdict": "REFUTED",
                    "reason": "requests.get is a real API in this source context",
                    "static_proof": "The call is to requests.get on line 2.",
                    "proof_kind": "api_signature_valid",
                    "proof_lines": [2],
                }
            ]
        }

    result = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=tmp_path,
        challenge_func=challenge,
        harness_run_id="with-proof",
        harness_trace_root=tmp_path / "runs",
    )

    counts = result.output["challenge"]["outcome_counts"]
    assert counts["refuted"] == 1
    assert counts["suppression_allowed"] == 1
    assert result.output["challenge"]["outcomes"][0]["proof_lines"] == [2]


def test_keyword_api_refutation_requires_keyword_in_cached_signature(
    tmp_path: Path,
):
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "requests.get('https://example.test', retry_policy=3)\n",
        encoding="utf-8",
    )
    assert cache_api_symbol_surface(
        tmp_path,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "requests",
            "environment_key": python_environment_key(),
            "members": {
                "get": {
                    "kind": "function",
                    "parameters": [
                        {
                            "name": "url",
                            "kind": "POSITIONAL_OR_KEYWORD",
                        }
                    ],
                }
            },
        },
    )
    findings = [
        _finding(
            message=(
                "Installed API 'requests.get' does not accept keyword "
                "argument 'retry_policy'."
            ),
            symbol="requests.get",
        )
    ]

    def challenge(_probes, _prompt):
        return {
            "decisions": [
                {
                    "id": 1,
                    "verdict": "REFUTED",
                    "reason": "requests.get exists",
                    "static_proof": "The call is to requests.get on line 2.",
                    "proof_kind": "api_signature_valid",
                    "proof_lines": [2],
                }
            ]
        }

    result = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=tmp_path,
        challenge_func=challenge,
        harness_run_id="keyword-proof",
        harness_trace_root=tmp_path / "runs",
    )

    counts = result.output["challenge"]["outcome_counts"]
    assert counts["refuted"] == 0
    assert counts["uncertain"] == 1
    assert counts["suppression_allowed"] == 0


def test_challenge_harness_skips_non_high_impact_findings_without_llm_call(
    tmp_path: Path,
):
    (tmp_path / "tests.py").write_text(
        "def test_ok():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    findings = [
        _finding(
            rule_id="SKY-A101",
            severity="MEDIUM",
            file_path="tests.py",
            line=2,
            message="Specific assertion was replaced with a broad truthiness check",
        )
    ]

    def challenge(_probes, _prompt):
        raise AssertionError("medium findings should not be challenged")

    result = run_ai_defect_challenge_harness(
        findings=findings,
        project_root=tmp_path,
        challenge_func=challenge,
        harness_run_id="skipped",
        harness_trace_root=tmp_path / "runs",
    )

    counts = result.output["challenge"]["outcome_counts"]
    assert counts["challenged"] == 0
    assert counts["skipped"] == 1
    assert result.run.budget_used()["llm_calls"] == 0


def test_normalize_challenge_decisions_fills_omitted_candidates():
    decisions = normalize_ai_defect_challenge_decisions(
        {"decisions": [{"id": 1, "verdict": "ACCEPTED"}]},
        expected_count=2,
    )

    assert decisions == [
        AIDefectChallengeDecision(id=1, verdict="ACCEPTED"),
        AIDefectChallengeDecision(
            id=2,
            verdict="UNCERTAIN",
            reason="Challenge response omitted this candidate.",
        ),
    ]
