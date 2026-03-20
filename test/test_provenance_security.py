from skylos.provenance import (
    FileProvenance,
    ProvenanceReport,
    annotate_findings_with_provenance,
    compute_ai_security_stats,
)


def _make_report(files_dict=None):
    report = ProvenanceReport()
    for path, info in (files_dict or {}).items():
        fp = FileProvenance(
            file_path=path,
            agent_authored=info.get("agent_authored", False),
            agent_lines=info.get("agent_lines", []),
            indicators=info.get("indicators", []),
            agent_name=info.get("agent_name"),
        )
        report.files[path] = fp
        if fp.agent_authored:
            report.agent_files.append(path)
        else:
            report.human_files.append(path)
    return report


class TestAnnotateFindings:
    def test_finding_in_ai_file_gets_annotated(self):
        report = _make_report({
            "src/auth.py": {
                "agent_authored": True,
                "agent_name": "cursor",
            },
        })
        findings = [
            {"file": "src/auth.py", "line": 10, "severity": "HIGH", "message": "SQL injection"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "cursor"

    def test_finding_in_human_file_not_annotated(self):
        report = _make_report({
            "src/auth.py": {
                "agent_authored": False,
            },
        })
        findings = [
            {"file": "src/auth.py", "line": 10, "severity": "HIGH", "message": "SQL injection"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is False
        assert result[0]["ai_agent"] is None

    def test_finding_line_range_check_in_range(self):
        report = _make_report({
            "src/api.py": {
                "agent_authored": True,
                "agent_name": "copilot",
                "agent_lines": [(10, 30), (50, 60)],
            },
        })
        findings = [
            {"file": "src/api.py", "line": 25, "severity": "MEDIUM", "message": "Hardcoded secret"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "copilot"

    def test_finding_line_range_check_out_of_range(self):
        report = _make_report({
            "src/api.py": {
                "agent_authored": True,
                "agent_name": "copilot",
                "agent_lines": [(10, 30), (50, 60)],
            },
        })
        findings = [
            {"file": "src/api.py", "line": 40, "severity": "MEDIUM", "message": "Hardcoded secret"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is False
        assert result[0]["ai_agent"] is None

    def test_no_provenance_data(self):
        report = _make_report({})
        findings = [
            {"file": "src/models.py", "line": 5, "severity": "LOW", "message": "Unused import"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is False
        assert result[0]["ai_agent"] is None

    def test_file_level_attribution_no_line_ranges(self):
        """When agent_lines is empty, file-level attribution applies."""
        report = _make_report({
            "src/handler.py": {
                "agent_authored": True,
                "agent_name": "claude",
                "agent_lines": [],
            },
        })
        findings = [
            {"file": "src/handler.py", "line": 999, "severity": "HIGH", "message": "Eval usage"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "claude"

    def test_finding_no_file_key(self):
        report = _make_report({
            "src/x.py": {"agent_authored": True, "agent_name": "cursor"},
        })
        findings = [{"line": 5, "severity": "LOW", "message": "Something"}]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is False
        assert result[0]["ai_agent"] is None

    def test_finding_no_line_with_ranges(self):
        """File is AI-authored with line ranges, but finding has no line number.
        Should still attribute at file level."""
        report = _make_report({
            "src/x.py": {
                "agent_authored": True,
                "agent_name": "devin",
                "agent_lines": [(1, 10)],
            },
        })
        findings = [{"file": "src/x.py", "severity": "MEDIUM", "message": "Issue"}]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "devin"

    def test_multiple_findings_mixed(self):
        report = _make_report({
            "src/a.py": {"agent_authored": True, "agent_name": "copilot"},
            "src/b.py": {"agent_authored": False},
        })
        findings = [
            {"file": "src/a.py", "line": 5, "severity": "HIGH", "message": "Issue A"},
            {"file": "src/b.py", "line": 10, "severity": "LOW", "message": "Issue B"},
            {"file": "src/c.py", "line": 1, "severity": "MEDIUM", "message": "Issue C"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "copilot"
        assert result[1]["ai_authored"] is False
        assert result[2]["ai_authored"] is False

    def test_suffix_matching(self):
        """Provenance might use relative paths while findings use absolute paths."""
        report = _make_report({
            "src/auth.py": {"agent_authored": True, "agent_name": "cursor"},
        })
        findings = [
            {"file": "/home/user/project/src/auth.py", "line": 5, "severity": "HIGH", "message": "Issue"},
        ]
        result = annotate_findings_with_provenance(findings, report)
        assert result[0]["ai_authored"] is True
        assert result[0]["ai_agent"] == "cursor"

    def test_returns_same_list_object(self):
        report = _make_report({})
        findings = [{"file": "x.py", "line": 1}]
        result = annotate_findings_with_provenance(findings, report)
        assert result is findings


class TestAISecurityStats:
    def test_basic_stats(self):
        findings = [
            {"ai_authored": True, "ai_agent": "copilot", "severity": "HIGH", "category": "danger"},
            {"ai_authored": True, "ai_agent": "cursor", "severity": "MEDIUM", "category": "danger"},
            {"ai_authored": False, "ai_agent": None, "severity": "LOW", "category": "secrets"},
            {"ai_authored": False, "ai_agent": None, "severity": "HIGH", "category": "danger"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["total_findings"] == 4
        assert stats["ai_authored_findings"] == 2
        assert stats["ai_authored_pct"] == 50.0

    def test_by_agent_breakdown(self):
        findings = [
            {"ai_authored": True, "ai_agent": "copilot", "severity": "HIGH", "category": "danger"},
            {"ai_authored": True, "ai_agent": "copilot", "severity": "MEDIUM", "category": "danger"},
            {"ai_authored": True, "ai_agent": "cursor", "severity": "LOW", "category": "secrets"},
            {"ai_authored": False, "ai_agent": None, "severity": "HIGH", "category": "danger"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["by_agent"] == {"copilot": 2, "cursor": 1}

    def test_by_severity_breakdown(self):
        findings = [
            {"ai_authored": True, "ai_agent": "copilot", "severity": "HIGH", "category": "danger"},
            {"ai_authored": False, "ai_agent": None, "severity": "HIGH", "category": "danger"},
            {"ai_authored": True, "ai_agent": "cursor", "severity": "LOW", "category": "secrets"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["by_severity"]["HIGH"] == {"total": 2, "ai": 1}
        assert stats["by_severity"]["LOW"] == {"total": 1, "ai": 1}

    def test_by_category_breakdown(self):
        findings = [
            {"ai_authored": True, "ai_agent": "copilot", "severity": "HIGH", "category": "danger"},
            {"ai_authored": False, "ai_agent": None, "severity": "LOW", "category": "danger"},
            {"ai_authored": True, "ai_agent": "cursor", "severity": "MEDIUM", "category": "secrets"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["by_category"]["danger"] == {"total": 2, "ai": 1}
        assert stats["by_category"]["secrets"] == {"total": 1, "ai": 1}

    def test_empty_findings(self):
        stats = compute_ai_security_stats([])
        assert stats["total_findings"] == 0
        assert stats["ai_authored_findings"] == 0
        assert stats["ai_authored_pct"] == 0.0
        assert stats["by_agent"] == {}
        assert stats["by_severity"] == {}
        assert stats["by_category"] == {}

    def test_all_ai_authored(self):
        findings = [
            {"ai_authored": True, "ai_agent": "claude", "severity": "CRITICAL", "category": "danger"},
            {"ai_authored": True, "ai_agent": "claude", "severity": "CRITICAL", "category": "danger"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["ai_authored_pct"] == 100.0
        assert stats["by_agent"] == {"claude": 2}

    def test_no_ai_authored(self):
        findings = [
            {"ai_authored": False, "ai_agent": None, "severity": "HIGH", "category": "danger"},
            {"ai_authored": False, "ai_agent": None, "severity": "LOW", "category": "quality"},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["ai_authored_findings"] == 0
        assert stats["ai_authored_pct"] == 0.0
        assert stats["by_agent"] == {}

    def test_missing_severity_and_category(self):
        """Findings without severity/category should default gracefully."""
        findings = [
            {"ai_authored": True, "ai_agent": "copilot"},
            {"ai_authored": False},
        ]
        stats = compute_ai_security_stats(findings)
        assert stats["total_findings"] == 2
        assert stats["by_severity"]["UNKNOWN"]["total"] == 2
        assert stats["by_category"]["unknown"]["total"] == 2
