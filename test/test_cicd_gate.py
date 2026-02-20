import os
import tempfile

import pytest

from skylos.gatekeeper import (
    check_gate,
    build_summary_markdown,
    write_github_summary,
    run_gate_interaction,
)


@pytest.fixture
def clean_results():
    return {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }


@pytest.fixture
def failing_results():
    return {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": "app.py",
                "line": 10,
                "severity": "CRITICAL",
                "message": "SQL injection",
            }
        ],
        "quality": [],
        "secrets": [],
    }


def test_gate_passes_clean_results(clean_results):
    passed, reasons = check_gate(clean_results, {})
    assert passed is True
    assert reasons == []


def test_gate_fails_on_critical(failing_results):
    passed, reasons = check_gate(failing_results, {})
    assert passed is False
    assert len(reasons) > 0


def test_gate_strict_mode(clean_results):
    clean_results["quality"] = [
        {
            "rule_id": "SKY-Q301",
            "file": "a.py",
            "line": 1,
            "severity": "LOW",
            "message": "complex",
        }
    ]
    passed, reasons = check_gate(clean_results, {}, strict=True)
    assert passed is False


def test_gate_interaction_with_summary(clean_results):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        summary_path = f.name

    try:
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        exit_code = run_gate_interaction(result=clean_results, config={}, summary=True)
        assert exit_code == 0
        content = open(summary_path).read()
        assert "Skylos Analysis Results" in content
        assert "PASSED" in content
    finally:
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        os.unlink(summary_path)


def test_summary_markdown_passed(clean_results):
    md = build_summary_markdown(clean_results, True, [])
    assert "PASSED" in md
    assert "| Security (critical) | 0 |" in md


def test_summary_markdown_failed(failing_results):
    md = build_summary_markdown(
        failing_results, False, ["1 critical security issue(s)"]
    )
    assert "FAILED" in md
    assert "Failure Reasons" in md
    assert "critical" in md
