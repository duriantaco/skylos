"""Tests for the Skylos DevOps Agent (planner, executor, orchestrator)."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from skylos.llm.planner import (
    RemediationPlanner,
    RemediationPlan,
    FindingItem,
    FixBatch,
    SEVERITY_PRIORITY,
    AUTO_FIXABLE,
)
from skylos.llm.executor import RemediationExecutor, TestResult, VerifyResult
from skylos.llm.prompts import build_pr_description


# ====================================================================
# Planner tests
# ====================================================================
class TestRemediationPlanner:
    def _make_results(self, findings):
        return {"danger": findings, "quality": [], "secrets": []}

    def test_empty_results(self):
        planner = RemediationPlanner()
        plan = planner.create_plan({"danger": [], "quality": [], "secrets": []})
        assert plan.total_findings == 0
        assert len(plan.batches) == 0

    def test_sorts_critical_first(self):
        findings = [
            {
                "rule_id": "SKY-D211",
                "severity": "MEDIUM",
                "message": "sql",
                "file": "a.py",
                "line": 10,
            },
            {
                "rule_id": "SKY-D212",
                "severity": "CRITICAL",
                "message": "cmd",
                "file": "b.py",
                "line": 5,
            },
        ]
        planner = RemediationPlanner()
        plan = planner.create_plan(self._make_results(findings), max_fixes=10)
        # Critical should be in first batch
        assert plan.batches[0].top_severity == "CRITICAL"

    def test_groups_by_file(self):
        findings = [
            {
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "message": "eval",
                "file": "a.py",
                "line": 1,
            },
            {
                "rule_id": "SKY-D202",
                "severity": "HIGH",
                "message": "exec",
                "file": "a.py",
                "line": 5,
            },
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "message": "sql",
                "file": "b.py",
                "line": 3,
            },
        ]
        planner = RemediationPlanner()
        plan = planner.create_plan(self._make_results(findings), max_fixes=10)
        files = [b.file for b in plan.batches]
        assert len(plan.batches) == 2
        assert "a.py" in files
        assert "b.py" in files

    def test_max_fixes_caps(self):
        findings = [
            {
                "rule_id": f"SKY-D20{i}",
                "severity": "HIGH",
                "message": f"issue {i}",
                "file": f"f{i}.py",
                "line": 1,
            }
            for i in range(20)
        ]
        planner = RemediationPlanner()
        plan = planner.create_plan(self._make_results(findings), max_fixes=5)
        total_planned = sum(len(b.findings) for b in plan.batches)
        assert total_planned == 5
        assert plan.skipped_findings == 15

    def test_severity_filter(self):
        findings = [
            {
                "rule_id": "SKY-D211",
                "severity": "CRITICAL",
                "message": "sql",
                "file": "a.py",
                "line": 1,
            },
            {
                "rule_id": "SKY-D206",
                "severity": "MEDIUM",
                "message": "md5",
                "file": "b.py",
                "line": 1,
            },
            {
                "rule_id": "SKY-Q301",
                "severity": "LOW",
                "message": "complex",
                "file": "c.py",
                "line": 1,
            },
        ]
        planner = RemediationPlanner(severity_filter="high")
        plan = planner.create_plan(self._make_results(findings), max_fixes=10)
        # Only CRITICAL (priority 0) passes — HIGH (priority 1) also passes
        severities = {f.severity for b in plan.batches for f in b.findings}
        assert "LOW" not in severities
        assert "MEDIUM" not in severities

    def test_auto_fixable_sorted_first(self):
        findings = [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "message": "sql",
                "file": "a.py",
                "line": 1,
            },
            {
                "rule_id": "SKY-D206",
                "severity": "HIGH",
                "message": "md5",
                "file": "a.py",
                "line": 5,
            },
        ]
        planner = RemediationPlanner()
        plan = planner.create_plan(self._make_results(findings), max_fixes=10)
        batch = plan.batches[0]
        # D206 is auto-fixable, D211 is not — D206 should come first
        assert batch.findings[0].rule_id == "SKY-D206"

    def test_summary(self):
        plan = RemediationPlan(
            batches=[
                FixBatch(
                    file="a.py",
                    findings=[
                        FindingItem.from_dict(
                            {
                                "rule_id": "SKY-D206",
                                "severity": "HIGH",
                                "message": "md5",
                                "file": "a.py",
                                "line": 1,
                            }
                        )
                    ],
                    status="fixed",
                ),
                FixBatch(
                    file="b.py",
                    findings=[
                        FindingItem.from_dict(
                            {
                                "rule_id": "SKY-D211",
                                "severity": "CRITICAL",
                                "message": "sql",
                                "file": "b.py",
                                "line": 1,
                            }
                        )
                    ],
                    status="test_failed",
                ),
            ],
            total_findings=5,
            skipped_findings=3,
        )
        s = plan.summary()
        assert s["fixed"] == 1
        assert s["failed"] == 1
        assert s["skipped"] == 3 + 0  # skipped_findings + skipped batches
        assert s["total_findings"] == 5

    def test_finding_item_from_dict(self):
        raw = {
            "rule_id": "SKY-D206",
            "severity": "HIGH",
            "message": "md5",
            "file": "a.py",
            "line": 10,
            "col": 5,
        }
        item = FindingItem.from_dict(raw)
        assert item.rule_id == "SKY-D206"
        assert item.auto_fixable is True
        assert item.priority == SEVERITY_PRIORITY["HIGH"]

    def test_extracts_from_all_categories(self):
        results = {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "severity": "HIGH",
                    "message": "eval",
                    "file": "a.py",
                    "line": 1,
                }
            ],
            "quality": [
                {
                    "rule_id": "SKY-Q301",
                    "severity": "MEDIUM",
                    "message": "complex",
                    "file": "b.py",
                    "line": 1,
                }
            ],
            "secrets": [
                {
                    "rule_id": "SKY-S101",
                    "severity": "CRITICAL",
                    "message": "key",
                    "file": "c.py",
                    "line": 1,
                }
            ],
        }
        planner = RemediationPlanner()
        plan = planner.create_plan(results, max_fixes=10)
        assert plan.total_findings == 3


# ====================================================================
# Executor tests
# ====================================================================
class TestRemediationExecutor:
    def test_apply_and_revert(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("original content")

        executor = RemediationExecutor(project_root=tmp_path)
        assert executor.apply_fix(str(f), "fixed content")
        assert f.read_text() == "fixed content"

        assert executor.revert_fix(str(f))
        assert f.read_text() == "original content"

    def test_revert_nonexistent(self, tmp_path):
        executor = RemediationExecutor(project_root=tmp_path)
        assert executor.revert_fix("/nonexistent") is False

    def test_apply_nonexistent_file(self, tmp_path):
        executor = RemediationExecutor(project_root=tmp_path)
        assert executor.apply_fix("/nonexistent", "content") is False

    def test_revert_all(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("a original")
        f2.write_text("b original")

        executor = RemediationExecutor(project_root=tmp_path)
        executor.apply_fix(str(f1), "a fixed")
        executor.apply_fix(str(f2), "b fixed")

        executor.revert_all()
        assert f1.read_text() == "a original"
        assert f2.read_text() == "b original"

    def test_detect_test_command_pytest(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
        executor = RemediationExecutor(project_root=tmp_path)
        cmd = executor._detect_test_command()
        assert cmd is not None
        assert "pytest" in cmd

    def test_detect_test_command_makefile(self, tmp_path):
        (tmp_path / "Makefile").write_text("test:\n\tpytest\n")
        executor = RemediationExecutor(project_root=tmp_path)
        cmd = executor._detect_test_command()
        assert cmd == "make test"

    def test_detect_test_command_none(self, tmp_path):
        executor = RemediationExecutor(project_root=tmp_path)
        cmd = executor._detect_test_command()
        assert cmd is None

    def test_run_tests_no_suite(self, tmp_path):
        executor = RemediationExecutor(project_root=tmp_path)
        result = executor.run_tests()
        assert result.passed is True
        assert "No test suite" in result.output

    def test_run_tests_with_custom_cmd(self, tmp_path):
        executor = RemediationExecutor(test_cmd="echo ok", project_root=tmp_path)
        result = executor.run_tests()
        assert result.passed is True

    def test_run_tests_failure(self, tmp_path):
        executor = RemediationExecutor(test_cmd="exit 1", project_root=tmp_path)
        result = executor.run_tests()
        assert result.passed is False

    def test_verify_fix(self, tmp_path):
        # Write a file with a known dangerous call (eval)
        f = tmp_path / "test_verify.py"
        f.write_text("x = 1 + 2\n")

        executor = RemediationExecutor(project_root=tmp_path)
        result = executor.verify_fix(str(f), ["SKY-D201"])
        # No eval in file → finding resolved
        assert result.finding_resolved is True


# ====================================================================
# PR description tests
# ====================================================================
class TestPRDescription:
    def test_basic_description(self):
        summary = {
            "total_findings": 10,
            "fixed": 3,
            "failed": 1,
            "skipped": 6,
            "batches": [
                {
                    "file": "a.py",
                    "findings": 2,
                    "status": "fixed",
                    "top_severity": "CRITICAL",
                    "description": "Fixed eval",
                },
                {
                    "file": "b.py",
                    "findings": 1,
                    "status": "fixed",
                    "top_severity": "HIGH",
                    "description": "Fixed md5",
                },
                {
                    "file": "c.py",
                    "findings": 1,
                    "status": "test_failed",
                    "top_severity": "MEDIUM",
                    "description": "Tests failed",
                },
            ],
        }
        body = build_pr_description(summary)
        assert "3" in body  # fixed count
        assert "10" in body  # total
        assert "a.py" in body
        assert "Could Not Fix" in body
        assert "6" in body  # skipped

    def test_empty_plan(self):
        summary = {
            "total_findings": 0,
            "fixed": 0,
            "failed": 0,
            "skipped": 0,
            "batches": [],
        }
        body = build_pr_description(summary)
        assert "Skylos" in body


# ====================================================================
# Orchestrator integration tests (mocked)
# ====================================================================
class TestOrchestrator:
    def test_dry_run_no_changes(self, tmp_path):
        """Dry run should scan and plan but not modify any files."""
        test_file = tmp_path / "vuln.py"
        test_file.write_text("import hashlib\nhashlib.md5(b'data')\n")

        from skylos.llm.orchestrator import RemediationAgent

        agent = RemediationAgent(model="gpt-4.1")

        # Mock the scan to return a known finding
        mock_results = {
            "danger": [
                {
                    "rule_id": "SKY-D206",
                    "severity": "MEDIUM",
                    "message": "Weak hash: md5",
                    "file": str(test_file),
                    "line": 2,
                    "col": 0,
                }
            ],
            "quality": [],
            "secrets": [],
        }

        with patch.object(agent, "_scan", return_value=mock_results):
            summary = agent.run(str(tmp_path), dry_run=True, quiet=True)

        # File should be unchanged
        assert test_file.read_text() == "import hashlib\nhashlib.md5(b'data')\n"
        assert summary["total_findings"] == 1
        assert summary["planned"] == 1
        assert summary["fixed"] == 0  # dry run → nothing fixed

    def test_zero_findings(self, tmp_path):
        """No findings → clean exit."""
        from skylos.llm.orchestrator import RemediationAgent

        agent = RemediationAgent()

        with patch.object(
            agent, "_scan", return_value={"danger": [], "quality": [], "secrets": []}
        ):
            summary = agent.run(str(tmp_path), quiet=True)

        assert summary["total_findings"] == 0
        assert summary["fixed"] == 0
