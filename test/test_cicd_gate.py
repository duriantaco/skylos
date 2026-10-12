import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from skylos.core.gatekeeper import (
    build_summary_markdown,
    check_gate,
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
        "dependency_vulnerabilities": [],
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
        "dependency_vulnerabilities": [],
    }


def test_gate_passes_clean_results(clean_results):
    passed, reasons = check_gate(clean_results, {})
    assert passed is True
    assert reasons == []


def test_gate_fails_on_critical(failing_results):
    passed, reasons = check_gate(failing_results, {})
    assert passed is False
    assert len(reasons) > 0


def test_gate_fails_on_dependency_vulnerability(clean_results):
    clean_results["dependency_vulnerabilities"] = [
        {"rule_id": "SKY-SCA-GHSA-test", "severity": "HIGH"}
    ]

    passed, reasons = check_gate(clean_results, {})

    assert passed is False
    assert "1 dependency vulnerability (max: 0)" in reasons


def test_gate_fails_closed_on_incomplete_language_engine(clean_results):
    clean_results["analysis_errors"] = [
        {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "kind": "language_engine_unavailable",
            "message": "Go analysis incomplete",
        }
    ]
    clean_results["analysis_summary"] = {"incomplete_languages": ["go"]}

    passed, reasons = check_gate(clean_results, {})

    assert passed is False
    assert any("Analysis incomplete" in reason for reason in reasons)
    assert "Incomplete language engine coverage: go" in reasons


def test_gate_incomplete_analysis_is_not_advisory_or_force_bypass(clean_results):
    clean_results["analysis_errors"] = [
        {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "message": "Go analysis incomplete",
        }
    ]

    exit_code = run_gate_interaction(
        result=clean_results,
        config={},
        advisory=True,
        force=True,
    )

    assert exit_code == 2


@pytest.mark.parametrize("status", ["incomplete", "unavailable", "unknown"])
@pytest.mark.parametrize("strict", [False, True])
def test_gate_fails_on_sca_operational_failure(clean_results, status, strict):
    clean_results["analysis_summary"] = {
        "sca_coverage": {
            "status": status,
            "complete": False,
            "category_complete": False,
        }
    }

    passed, reasons = check_gate(clean_results, {}, strict=strict)

    assert passed is False
    assert reasons == [f"Dependency vulnerability scan incomplete (status: {status})"]
    assert (
        run_gate_interaction(
            result=clean_results,
            config={},
            strict=strict,
            advisory=True,
            force=True,
        )
        == 2
    )


@pytest.mark.parametrize(
    "receipt",
    [
        {"status": "no_supported_manifests", "complete": False},
        {"status": "complete", "complete": True},
        {
            "status": "complete_with_unresolved_versions",
            "complete": True,
            "unresolved_dependency_count": 3,
        },
        {},
    ],
)
def test_gate_allows_sca_coverage_limitations(clean_results, receipt):
    clean_results["analysis_summary"] = {
        "sca_coverage": {**receipt, "category_complete": False}
    }

    assert check_gate(clean_results, {}) == (True, [])
    assert check_gate(clean_results, {}, strict=True) == (True, [])
    assert run_gate_interaction(result=clean_results, config={}) == 0


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


def test_gate_interaction_advisory_returns_success(failing_results):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        summary_path = f.name

    try:
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        exit_code = run_gate_interaction(
            result=failing_results,
            config={},
            summary=True,
            advisory=True,
        )
        assert exit_code == 0
        content = open(summary_path).read()
        assert "ADVISORY - WOULD FAIL" in content
        assert "Advisory Reasons" in content
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


def test_summary_markdown_mixed_output_is_stable():
    results = {
        "unused_functions": [{"name": "f1"}, {"name": "f2"}],
        "unused_imports": [{"name": "i1"}],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "danger": [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
            {"severity": "LOW"},
            {"severity": "LOW"},
        ],
        "quality": [{"rule_id": f"Q{i}"} for i in range(11)],
        "secrets": [{"rule_id": "S1"}],
        "dependency_vulnerabilities": [{"rule_id": "SKY-SCA-GHSA-test"}],
    }

    md = build_summary_markdown(
        results,
        False,
        ["first failure", "second failure"],
    )

    assert md == (
        "## Skylos Analysis Results\n"
        "\n"
        "| Category | Count |\n"
        "|----------|-------|\n"
        "| Security (critical) | 1 |\n"
        "| Security (high) | 6 |\n"
        "| Security (total) | 11 |\n"
        "| Reliability | 0 |\n"
        "| AI defects | 0 |\n"
        "| Quality | 11 |\n"
        "| Secrets | 1 |\n"
        "| Dependency vulnerabilities | 1 |\n"
        "| Dead Code | 3 |\n"
        "\n"
        "**Result: ❌ FAILED**\n"
        "\n"
        "### Failure Reasons\n"
        "- first failure\n"
        "- second failure"
    )


def test_summary_markdown_keeps_reliability_count_and_overall_verdict():
    results = {
        "reliability": [
            {
                "rule_id": "SKY-GPU001",
                "severity": "HIGH",
                "file": "Dockerfile",
            }
        ]
    }

    md = build_summary_markdown(results, False, ["1 reliability issue(s)"])

    assert "| Reliability | 1 |" in md
    assert "**Result: ❌ FAILED**" in md


PHANTOM_CALL_APP = (
    "def handle(payload, signature):\n"
    "    if not verify_signature(payload, signature):\n"
    '        raise ValueError("bad signature")\n'
    "    return payload\n"
)
CLEAN_APP = "def handle(payload, signature):\n    return payload\n"
AI_GATE_OPT_OUT = "[tool.skylos.gate]\nblock_ai_defect_severities = []\n"
AI_GATE_REASON = "1 critical AI-code issue (SKY-L012 phantom symbol reference)"


def _cli_env():
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "LANG")
        if key in os.environ
    }
    env.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[1]),
        SKYLOS_NO_TELEMETRY="1",
        SKYLOS_JOBS="1",
    )
    return env


def _skylos(root, *args):
    return subprocess.run(
        [str(Path(sys.executable).with_name("skylos")), *args],
        cwd=root,
        env=_cli_env(),
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )


def _git(root, *args):
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("opt_out", [False, True])
def test_scan_gate_blocks_critical_ai_defect_unless_opted_out(tmp_path, opt_out):
    (tmp_path / "app.py").write_text(PHANTOM_CALL_APP)
    if opt_out:
        (tmp_path / "pyproject.toml").write_text(AI_GATE_OPT_OUT)

    result = _skylos(tmp_path, ".", "--ai-defects", "--gate")

    output = result.stdout + result.stderr
    if opt_out:
        assert result.returncode == 0, output
        assert "Quality Gate: PASSED" in result.stdout
    else:
        assert result.returncode == 1, output
        assert AI_GATE_REASON in result.stdout
        assert "block_ai_defect_severities = []" in result.stdout


def test_json_scan_gate_and_cicd_gate_block_critical_ai_defect(tmp_path):
    (tmp_path / "app.py").write_text(PHANTOM_CALL_APP)
    report = tmp_path / "report.json"

    scan = _skylos(
        tmp_path, ".", "--ai-defects", "--gate", "--format", "json", "-o", str(report)
    )

    assert scan.returncode == 1, scan.stdout + scan.stderr
    findings = json.loads(report.read_text())["ai_defects"]
    assert [item["rule_id"] for item in findings] == ["SKY-L012"]

    gate = _skylos(tmp_path, "cicd", "gate", "--input", str(report))
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert AI_GATE_REASON in gate.stdout

    (tmp_path / "pyproject.toml").write_text(AI_GATE_OPT_OUT)
    gate = _skylos(tmp_path, "cicd", "gate", "--input", str(report))
    assert gate.returncode == 0, gate.stdout + gate.stderr


def test_pr_gate_reads_the_ai_defect_policy_from_the_base_branch(tmp_path):
    (tmp_path / "app.py").write_text(CLEAN_APP)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "tag", "base")
    # The pull request adds the defect and tries to opt out in the same change.
    (tmp_path / "app.py").write_text(PHANTOM_CALL_APP)
    (tmp_path / "pyproject.toml").write_text(AI_GATE_OPT_OUT)
    _git(tmp_path, "add", "app.py", "pyproject.toml")
    _git(tmp_path, "commit", "-qm", "head")
    report = tmp_path / "report.json"

    scan = _skylos(
        tmp_path,
        ".",
        "--ai-defects",
        "--diff",
        "base",
        "--format",
        "json",
        "-o",
        str(report),
    )
    assert scan.returncode == 0, scan.stdout + scan.stderr

    gate = _skylos(
        tmp_path, "cicd", "gate", "--input", str(report), "--diff-base", "base"
    )

    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert AI_GATE_REASON in gate.stdout
