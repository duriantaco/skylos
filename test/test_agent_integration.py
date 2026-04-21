import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from skylos.llm.analyzer import AnalyzerConfig, SkylosLLM
from skylos.llm.schemas import (
    AnalysisResult,
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)
from skylos.llm.security_verifier import annotate_security_finding


def _security_scan_result(file_path: str) -> AnalysisResult:
    return AnalysisResult(
        findings=[
            Finding(
                rule_id="SKY-L001",
                issue_type=IssueType.SECURITY,
                severity=Severity.HIGH,
                message="Possible SQL injection",
                location=CodeLocation(file=file_path, line=1),
                confidence=Confidence.HIGH,
            ),
            Finding(
                rule_id="SKY-L002",
                issue_type=IssueType.SECURITY,
                severity=Severity.HIGH,
                message="Possible command injection",
                location=CodeLocation(file=file_path, line=2),
                confidence=Confidence.HIGH,
            ),
            Finding(
                rule_id="SKY-L003",
                issue_type=IssueType.SECURITY,
                severity=Severity.HIGH,
                message="Possible SSRF",
                location=CodeLocation(file=file_path, line=3),
                confidence=Confidence.HIGH,
            ),
        ],
        files_analyzed=1,
    )


def _make_security_scan_analyzer(result: AnalysisResult) -> SkylosLLM:
    analyzer = SkylosLLM(AnalyzerConfig(quiet=True))
    analyzer.analyze_files = MagicMock(return_value=result)
    return analyzer


class _DeterministicSecurityAuditAgent:
    def analyze(self, source, file_path, defs_map=None, context=None):
        findings = []
        for line_no, line in enumerate(source.splitlines(), start=1):
            if "SELECT * FROM users WHERE id = %s" in line and "%" in line:
                findings.append(
                    Finding(
                        rule_id="SKY-S001",
                        issue_type=IssueType.SECURITY,
                        severity=Severity.CRITICAL,
                        message="SQL injection vulnerability: user input is directly interpolated into SQL query string.",
                        location=CodeLocation(file=file_path, line=line_no),
                        confidence=Confidence.HIGH,
                    )
                )
            if (
                "subprocess.check_output" in line or "subprocess.run" in line
            ) and "shell=True" in line:
                findings.append(
                    Finding(
                        rule_id="SKY-C011",
                        issue_type=IssueType.SECURITY,
                        severity=Severity.CRITICAL,
                        message="Command injection vulnerability: untrusted user input passed to subprocess with shell=True.",
                        location=CodeLocation(file=file_path, line=line_no),
                        confidence=Confidence.HIGH,
                    )
                )
        return findings


def _supported_security_review(findings):
    for finding in findings:
        annotate_security_finding(
            finding,
            evidence="review_supported",
            review_verdict="SUPPORTED",
            review_reason="deterministic test review",
            needs_review=True,
            ci_blocking=False,
        )
    return {
        "supported": len(findings),
        "refuted": 0,
        "undecided": 0,
        "refuted_findings": [],
    }


def test_agent_review_passes_exclude_folders():
    with (
        patch("skylos.cli.run_pipeline") as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.get_git_changed_files", return_value=["fake.py"]),
        patch("skylos.cli.inquirer.confirm", return_value=True),
        patch("sys.argv", ["skylos", "agent", "scan", ".", "--changed"]),
    ):
        mock_pipeline.return_value = []

        from skylos.cli import main

        try:
            main()
        except SystemExit:
            pass

        call = mock_pipeline.call_args
        assert call is not None, "run_pipeline was not called"
        assert "exclude_folders" in call.kwargs
        assert "node_modules" in call.kwargs["exclude_folders"]


def test_agent_scan_disables_api_key_prompt_without_tty(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ) as mock_runtime,
        patch("skylos.cli._is_tty", return_value=False),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    assert mock_runtime.call_args.kwargs["allow_prompt"] is False


def test_agent_scan_without_api_key_non_tty_exits_with_message(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", None, None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "No OPENAI_API_KEY configured" in captured.out


def test_agent_analyze_exits_zero_by_default(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    findings = [
        {
            "file": str(sample),
            "line": 1,
            "message": "Issue found",
            "_category": "security",
            "_source": "llm",
        }
    ]

    with (
        patch("skylos.cli.run_pipeline", return_value=findings),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(tmp_path)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0


def test_agent_scan_defaults_to_fast_review_without_dead_code_verification(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]) as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    args = mock_pipeline.call_args.kwargs["agent_args"]
    assert args.skip_verification is True


def test_agent_scan_can_opt_into_dead_code_verification(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]) as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(sample), "--verify-dead-code"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    args = mock_pipeline.call_args.kwargs["agent_args"]
    assert args.skip_verification is False


def test_agent_analyze_strict_exits_one_when_findings_exist(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    findings = [
        {
            "file": str(sample),
            "line": 1,
            "message": "Issue found",
            "_category": "security",
            "_source": "llm",
        }
    ]

    with (
        patch("skylos.cli.run_pipeline", return_value=findings),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(tmp_path), "--strict"]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 1


def test_security_audit_skips_confirmation_without_tty(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    fake_llm = MagicMock()
    fake_llm.analyze_files.return_value = MagicMock(has_blockers=False)

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.inquirer.confirm") as mock_confirm,
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(tmp_path), "--security", "--interactive"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_confirm.assert_not_called()


def test_security_audit_uses_gitignore_aware_discovery(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    fake_llm = MagicMock()
    fake_llm.analyze_files.return_value = MagicMock(has_blockers=False)

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "skylos.cli.discover_source_files", return_value=[sample]
        ) as mock_discover,
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(tmp_path), "--security", "--interactive"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_discover.assert_called_once()
    fake_llm.analyze_files.assert_called_once_with(
        [sample], issue_types=["security_audit"]
    )


def test_security_audit_passes_provider_and_base_url_into_analyzer_config(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    fake_llm = MagicMock()
    fake_llm.analyze_files.return_value = MagicMock(has_blockers=False)
    sentinel_config = object()

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("anthropic", "fake-key", "https://custom.endpoint", False),
        ),
        patch(
            "skylos.cli._build_analyzer_config", return_value=sentinel_config
        ) as mock_build,
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--provider",
                "anthropic",
                "--base-url",
                "https://custom.endpoint",
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_build.assert_called_once()
    kwargs = mock_build.call_args.kwargs
    assert kwargs["provider"] == "anthropic"
    assert kwargs["base_url"] == "https://custom.endpoint"


def test_security_audit_json_output_handles_supported_refuted_and_hypothesis(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    output = tmp_path / "security.json"

    analyzer = _make_security_scan_analyzer(_security_scan_result(str(sample)))

    def _review(findings):
        findings[0].metadata["security_evidence"] = "review_supported"
        findings[0].metadata["review_verdict"] = "SUPPORTED"
        findings[0].metadata["review_reason"] = "source reaches string-built query"
        findings[1].metadata["security_evidence"] = "refuted"
        findings[1].metadata["review_verdict"] = "REFUTED"
        findings[1].metadata["review_reason"] = "input is constrained"
        findings[2].metadata["security_evidence"] = "hypothesis"
        findings[2].metadata["review_verdict"] = "UNCERTAIN"
        findings[2].metadata["review_reason"] = "not enough local context"
        return {
            "supported": 1,
            "refuted": 1,
            "undecided": 1,
            "refuted_findings": [findings[1]],
        }

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.cli.discover_source_files", return_value=[sample]),
        patch("skylos.cli.SkylosLLM", return_value=analyzer),
        patch(
            "skylos.llm.security_verifier.SecurityVerifier.review_findings",
            side_effect=_review,
        ),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    findings = payload["findings"]
    assert len(findings) == 2

    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert "SKY-L002" not in by_rule
    assert by_rule["SKY-L001"]["metadata"]["security_evidence"] == "review_supported"
    assert by_rule["SKY-L001"]["metadata"]["review_verdict"] == "SUPPORTED"
    assert by_rule["SKY-L001"]["metadata"]["ci_blocking"] is False
    assert by_rule["SKY-L003"]["metadata"]["security_evidence"] == "hypothesis"
    assert by_rule["SKY-L003"]["metadata"]["review_verdict"] == "UNCERTAIN"
    assert by_rule["SKY-L003"]["metadata"]["ci_blocking"] is False


def test_security_audit_sarif_output_handles_supported_refuted_and_hypothesis(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    output = tmp_path / "security.sarif"

    analyzer = _make_security_scan_analyzer(_security_scan_result(str(sample)))

    def _review(findings):
        findings[0].metadata["security_evidence"] = "review_supported"
        findings[0].metadata["review_verdict"] = "SUPPORTED"
        findings[0].metadata["review_reason"] = "source reaches string-built query"
        findings[1].metadata["security_evidence"] = "refuted"
        findings[1].metadata["review_verdict"] = "REFUTED"
        findings[1].metadata["review_reason"] = "input is constrained"
        findings[2].metadata["security_evidence"] = "hypothesis"
        findings[2].metadata["review_verdict"] = "UNCERTAIN"
        findings[2].metadata["review_reason"] = "not enough local context"
        return {
            "supported": 1,
            "refuted": 1,
            "undecided": 1,
            "refuted_findings": [findings[1]],
        }

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.cli.discover_source_files", return_value=[sample]),
        patch("skylos.cli.SkylosLLM", return_value=analyzer),
        patch(
            "skylos.llm.security_verifier.SecurityVerifier.review_findings",
            side_effect=_review,
        ),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--format",
                "sarif",
                "--output",
                str(output),
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    results = payload["runs"][0]["results"]
    assert len(results) == 2

    by_rule = {result["ruleId"]: result for result in results}
    assert "SKY-L002" not in by_rule
    assert by_rule["SKY-L001"]["properties"]["security_evidence"] == "review_supported"
    assert by_rule["SKY-L001"]["properties"]["review_verdict"] == "SUPPORTED"
    assert by_rule["SKY-L001"]["properties"]["ci_blocking"] is False
    assert by_rule["SKY-L003"]["properties"]["security_evidence"] == "hypothesis"
    assert by_rule["SKY-L003"]["properties"]["review_verdict"] == "UNCERTAIN"
    assert by_rule["SKY-L003"]["properties"]["ci_blocking"] is False


def test_security_audit_json_output_reports_vulnerable_repo_and_skips_safe_file(
    tmp_path,
):
    vuln = tmp_path / "vuln_app.py"
    vuln.write_text(
        "from flask import Flask, request\n"
        "import subprocess\n\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/user')\n"
        "def user():\n"
        "    user_id = request.args.get('id')\n"
        "    query = \"SELECT * FROM users WHERE id = %s\" % user_id\n"
        "    return query\n\n"
        "@app.get('/ls')\n"
        "def ls():\n"
        "    cmd = request.args['cmd']\n"
        "    return subprocess.check_output(cmd, shell=True)\n",
        encoding="utf-8",
    )
    safe = tmp_path / "safe_app.py"
    safe.write_text(
        "from flask import Flask, request\n"
        "import sqlite3\n\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/safe')\n"
        "def safe():\n"
        "    user_id = request.args.get('id')\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,)).fetchall()\n",
        encoding="utf-8",
    )
    output = tmp_path / "security.json"

    def _create_agent(agent_type, config=None):
        assert agent_type == "security_audit"
        return _DeterministicSecurityAuditAgent()

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.llm.analyzer.create_agent", side_effect=_create_agent),
        patch(
            "skylos.llm.security_verifier.SecurityVerifier.review_findings",
            side_effect=_supported_security_review,
        ),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    findings = payload["findings"]
    assert len(findings) == 2
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert set(by_rule) == {"SKY-S001", "SKY-C011"}
    assert all(Path(item["location"]["file"]).name == "vuln_app.py" for item in findings)
    assert all(item["metadata"]["security_evidence"] == "review_supported" for item in findings)
    assert all(item["metadata"]["review_verdict"] == "SUPPORTED" for item in findings)


def test_security_audit_json_output_reports_getter_based_command_injection(tmp_path):
    sample = tmp_path / "app.py"
    sample.write_text(
        "from flask import Flask, request\n"
        "import subprocess\n\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/run')\n"
        "def run_cmd():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    output = tmp_path / "security.json"

    def _create_agent(agent_type, config=None):
        assert agent_type == "security_audit"
        return _DeterministicSecurityAuditAgent()

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.llm.analyzer.create_agent", side_effect=_create_agent),
        patch(
            "skylos.llm.security_verifier.SecurityVerifier.review_findings",
            side_effect=_supported_security_review,
        ),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    findings = payload["findings"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-C011"
    assert findings[0]["metadata"]["security_evidence"] == "review_supported"
    assert findings[0]["metadata"]["review_verdict"] == "SUPPORTED"
