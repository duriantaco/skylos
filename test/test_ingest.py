import json
from unittest.mock import patch, MagicMock

from skylos.ingest import (
    is_claude_security_report,
    normalize_claude_security,
    ingest_claude_security,
    cross_reference,
)


SAMPLE_CCS_REPORT = {
    "tool": "claude-code-security",
    "scan_metadata": {"model": "claude-opus-4-6", "duration_ms": 12345},
    "findings": [
        {
            "id": "sql-injection",
            "severity": "critical",
            "file_path": "app/db.py",
            "line_number": 42,
            "message": "SQL injection via unsanitized user input",
            "confidence_score": 0.95,
            "exploit_scenario": "Attacker passes malicious SQL in query param",
            "fix": "Use parameterized queries",
            "cwe": "CWE-89",
            "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        },
        {
            "id": "xss-reflected",
            "severity": "high",
            "file_path": "app/views.py",
            "line_number": 18,
            "message": "Reflected XSS in template rendering",
            "confidence_score": 0.82,
            "exploit_scenario": "User-controlled input rendered without escaping",
            "cwe": "CWE-79",
        },
        {
            "id": "weak-crypto",
            "severity": "medium",
            "file": "utils/crypto.py",
            "line": 7,
            "description": "MD5 used for password hashing",
            "confidence_score": 0.70,
        },
        {
            "id": "debug-enabled",
            "severity": "low",
            "file_path": "settings.py",
            "line_number": 1,
            "message": "Debug mode enabled in production config",
            "confidence_score": 0.60,
        },
    ],
}

SAMPLE_CCS_ALTERNATIVE_FORMAT = {
    "scanner": "claude-code-security",
    "vulnerabilities": [
        {
            "type": "path-traversal",
            "severity": "high",
            "location": {"file": "api/files.py", "line": 33},
            "title": "Path traversal in file upload handler",
            "confidence": 0.88,
            "exploit": "Upload file with ../../../etc/passwd as filename",
            "remediation": "Sanitize file paths",
        },
    ],
}

NOT_CCS_REPORT = {
    "runs": [{"tool": {"driver": {"name": "eslint"}}}],
}


class TestIsClaudeSecurityReport:
    def test_detects_standard_format(self):
        assert is_claude_security_report(SAMPLE_CCS_REPORT) is True

    def test_detects_alternative_format(self):
        assert is_claude_security_report(SAMPLE_CCS_ALTERNATIVE_FORMAT) is True

    def test_rejects_sarif(self):
        assert is_claude_security_report(NOT_CCS_REPORT) is False

    def test_rejects_string(self):
        assert is_claude_security_report("not a dict") is False

    def test_rejects_none(self):
        assert is_claude_security_report(None) is False

    def test_rejects_empty_dict(self):
        assert is_claude_security_report({}) is False

    def test_detects_empty_findings_with_tool_key(self):
        assert (
            is_claude_security_report({"tool": "claude-code-security", "findings": []})
            is True
        )

    def test_rejects_empty_findings_without_tool_key(self):
        assert is_claude_security_report({"findings": []}) is False


class TestNormalizeClaudeSecurity:
    def test_finding_count(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert len(result["danger"]) == 4

    def test_rule_id_prefix(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        for f in result["danger"]:
            assert f["rule_id"].startswith("CCS:"), (
                f"rule_id {f['rule_id']} missing CCS: prefix"
            )

    def test_no_double_prefix(self):
        data = {
            "findings": [
                {
                    "id": "CCS:already-prefixed",
                    "severity": "high",
                    "file_path": "a.py",
                    "line_number": 1,
                    "message": "test",
                    "confidence_score": 0.9,
                },
            ],
        }
        result = normalize_claude_security(data)
        assert result["danger"][0]["rule_id"] == "CCS:already-prefixed"

    def test_severity_mapping(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        severities = [f["severity"] for f in result["danger"]]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_category_always_security(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        for f in result["danger"]:
            assert f["category"] == "SECURITY"

    def test_file_path_extraction(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["danger"][0]["file_path"] == "app/db.py"
        assert result["danger"][2]["file_path"] == "utils/crypto.py"

    def test_line_number_extraction(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["danger"][0]["line_number"] == 42
        assert result["danger"][2]["line_number"] == 7

    def test_message_extraction(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert (
            result["danger"][0]["message"] == "SQL injection via unsanitized user input"
        )
        assert result["danger"][2]["message"] == "MD5 used for password hashing"

    def test_snippet_preserved(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert "cursor.execute" in result["danger"][0]["snippet"]

    def test_confidence_in_metadata(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["danger"][0]["_confidence"] == 0.95

    def test_exploit_scenario_in_metadata(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert "malicious SQL" in result["danger"][0]["_exploit_scenario"]

    def test_cwe_in_metadata(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["danger"][0]["_cwe"] == "CWE-89"

    def test_suggested_fix_in_metadata(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["danger"][0]["_suggested_fix"] == "Use parameterized queries"

    def test_source_tag(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["_source"] == "claude-code-security"

    def test_scan_metadata_preserved(self):
        result = normalize_claude_security(SAMPLE_CCS_REPORT)
        assert result["_scan_metadata"]["model"] == "claude-opus-4-6"

    def test_alternative_format_location(self):
        result = normalize_claude_security(SAMPLE_CCS_ALTERNATIVE_FORMAT)
        f = result["danger"][0]
        assert f["file_path"] == "api/files.py"
        assert f["line_number"] == 33
        assert f["rule_id"] == "CCS:path-traversal"

    def test_alternative_format_title_as_message(self):
        result = normalize_claude_security(SAMPLE_CCS_ALTERNATIVE_FORMAT)
        assert result["danger"][0]["message"] == "Path traversal in file upload handler"

    def test_empty_findings(self):
        result = normalize_claude_security({"findings": []})
        assert result["danger"] == []

    def test_invalid_line_defaults_to_1(self):
        data = {
            "findings": [
                {
                    "id": "test",
                    "file_path": "a.py",
                    "line_number": "not-a-number",
                    "message": "test",
                    "confidence_score": 0.5,
                },
            ],
        }
        result = normalize_claude_security(data)
        assert result["danger"][0]["line_number"] == 1

    def test_negative_line_defaults_to_1(self):
        data = {
            "findings": [
                {
                    "id": "test",
                    "file_path": "a.py",
                    "line_number": -5,
                    "message": "test",
                    "confidence_score": 0.5,
                },
            ],
        }
        result = normalize_claude_security(data)
        assert result["danger"][0]["line_number"] == 1


class TestIngestClaudeSecurity:
    def test_file_not_found(self):
        result = ingest_claude_security("/nonexistent/file.json", upload=False)
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all")
        result = ingest_claude_security(str(bad_file), upload=False)
        assert result["success"] is False
        assert "json" in result["error"].lower()

    def test_not_ccs_format(self, tmp_path):
        sarif_file = tmp_path / "sarif.json"
        sarif_file.write_text(json.dumps(NOT_CCS_REPORT))
        result = ingest_claude_security(str(sarif_file), upload=False)
        assert result["success"] is False
        assert "does not appear" in result["error"].lower()

    def test_normalize_only(self, tmp_path):
        ccs_file = tmp_path / "ccs.json"
        ccs_file.write_text(json.dumps(SAMPLE_CCS_REPORT))
        result = ingest_claude_security(str(ccs_file), upload=False, quiet=True)
        assert result["success"] is True
        assert result["findings_count"] == 4
        assert "result" in result

    @patch("skylos.api.upload_report")
    def test_upload_called(self, mock_upload, tmp_path):
        mock_upload.return_value = {"success": True, "scan_id": "abc123"}
        ccs_file = tmp_path / "ccs.json"
        ccs_file.write_text(json.dumps(SAMPLE_CCS_REPORT))

        result = ingest_claude_security(str(ccs_file), upload=True, quiet=True)
        assert result["success"] is True
        assert result["findings_count"] == 4
        mock_upload.assert_called_once()

        call_args = mock_upload.call_args
        assert call_args.kwargs.get("analysis_mode") == "claude-security"

    @patch("skylos.api.upload_report")
    def test_upload_failure_propagates(self, mock_upload, tmp_path):
        mock_upload.return_value = {"success": False, "error": "No credits"}
        ccs_file = tmp_path / "ccs.json"
        ccs_file.write_text(json.dumps(SAMPLE_CCS_REPORT))

        result = ingest_claude_security(str(ccs_file), upload=True, quiet=True)
        assert result["success"] is False


class TestWorkflowClaudeSecurity:
    def test_without_flag(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow()
        assert "claude-security" not in yaml
        assert "upload-claude-findings" not in yaml

    def test_with_flag(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow(use_claude_security=True)
        assert "claude-security:" in yaml
        assert "upload-claude-findings:" in yaml
        assert "anthropics/claude-code-action@main" in yaml
        assert "skylos ingest claude-security" in yaml
        assert "SKYLOS_TOKEN" in yaml
        assert "ANTHROPIC_API_KEY" in yaml

    def test_parallel_jobs(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow(use_claude_security=True)
        assert "needs: [skylos, claude-security]" in yaml

    def test_security_events_permission(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow(use_claude_security=True)
        assert "security-events: write" in yaml

    def test_no_security_events_without_flag(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow(use_claude_security=False)
        assert "security-events" not in yaml

    def test_combined_with_llm(self):
        from skylos.cicd.workflow import generate_workflow

        yaml = generate_workflow(use_claude_security=True, use_llm=True)
        assert "claude-security:" in yaml
        assert "Skylos Agent Review (LLM)" in yaml


SAMPLE_SKYLOS_RESULT = {
    "unused_functions": [
        {"file_path": "app/views.py", "name": "old_handler", "line_number": 10},
        {"file_path": "utils/crypto.py", "name": "legacy_hash", "line_number": 1},
    ],
    "unused_imports": [
        {"file_path": "settings.py", "name": "os", "line_number": 1},
    ],
    "unused_variables": [],
    "unused_classes": [],
    "danger": [
        {
            "file_path": "app/db.py",
            "line_number": 42,
            "rule_id": "SKY-D211",
            "message": "SQL injection",
            "severity": "HIGH",
        },
    ],
}


class TestCrossReference:
    def _claude_findings(self):
        return normalize_claude_security(SAMPLE_CCS_REPORT)["danger"]

    def test_identifies_dead_code_findings(self):
        xref = cross_reference(self._claude_findings(), SAMPLE_SKYLOS_RESULT)
        assert xref["in_dead_code"] == 3

    def test_identifies_corroborated_findings(self):
        xref = cross_reference(self._claude_findings(), SAMPLE_SKYLOS_RESULT)
        assert xref["corroborated_by_skylos"] == 1

    def test_identifies_unique_findings(self):
        xref = cross_reference(self._claude_findings(), SAMPLE_SKYLOS_RESULT)
        assert xref["unique_to_claude"] == 0

    def test_attack_surface_reduction_percentage(self):
        xref = cross_reference(self._claude_findings(), SAMPLE_SKYLOS_RESULT)
        assert xref["attack_surface_reduction_pct"] == 75.0

    def test_totals_add_up(self):
        xref = cross_reference(self._claude_findings(), SAMPLE_SKYLOS_RESULT)
        assert (
            xref["in_dead_code"]
            + xref["corroborated_by_skylos"]
            + xref["unique_to_claude"]
            == xref["total_claude_findings"]
        )

    def test_no_dead_code(self):
        skylos_no_dead = {
            "unused_functions": [],
            "unused_imports": [],
            "unused_variables": [],
            "unused_classes": [],
            "danger": [],
        }
        xref = cross_reference(self._claude_findings(), skylos_no_dead)
        assert xref["in_dead_code"] == 0
        assert xref["attack_surface_reduction_pct"] == 0.0
        assert xref["unique_to_claude"] == 4

    def test_empty_claude_findings(self):
        xref = cross_reference([], SAMPLE_SKYLOS_RESULT)
        assert xref["total_claude_findings"] == 0
        assert xref["attack_surface_reduction_pct"] == 0.0

    def test_all_corroborated(self):
        claude = [
            {
                "file_path": "app/db.py",
                "line_number": 42,
                "message": "sqli",
                "severity": "HIGH",
            }
        ]
        skylos = {
            "unused_functions": [],
            "unused_imports": [],
            "unused_variables": [],
            "unused_classes": [],
            "danger": [{"file_path": "app/db.py", "line_number": 42}],
        }
        xref = cross_reference(claude, skylos)
        assert xref["corroborated_by_skylos"] == 1
        assert xref["unique_to_claude"] == 0

    def test_path_normalization(self):
        claude = [
            {
                "file_path": "./src/app.py",
                "line_number": 10,
                "message": "vuln",
                "severity": "HIGH",
            }
        ]
        skylos = {
            "unused_functions": [
                {"file_path": "src/app.py", "name": "dead_fn", "line_number": 1}
            ],
            "unused_imports": [],
            "unused_variables": [],
            "unused_classes": [],
            "danger": [],
        }
        xref = cross_reference(claude, skylos)
        assert xref["in_dead_code"] == 1

    def test_cross_reference_via_ingest(self, tmp_path):
        ccs_file = tmp_path / "ccs.json"
        ccs_file.write_text(json.dumps(SAMPLE_CCS_REPORT))
        skylos_file = tmp_path / "skylos.json"
        skylos_file.write_text(json.dumps(SAMPLE_SKYLOS_RESULT))

        result = ingest_claude_security(
            str(ccs_file),
            upload=False,
            quiet=True,
            cross_reference_path=str(skylos_file),
        )
        assert result["success"] is True
        assert "cross_reference" in result
        xref = result["cross_reference"]
        assert xref["total_claude_findings"] == 4
        assert xref["in_dead_code"] == 3

    def test_cross_reference_missing_file(self, tmp_path):
        ccs_file = tmp_path / "ccs.json"
        ccs_file.write_text(json.dumps(SAMPLE_CCS_REPORT))
        result = ingest_claude_security(
            str(ccs_file),
            upload=False,
            quiet=True,
            cross_reference_path="/nonexistent/skylos.json",
        )
        assert result["success"] is False
        assert "not found" in result["error"].lower()
