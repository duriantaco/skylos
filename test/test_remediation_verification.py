from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from skylos.llm.cleanup_orchestrator import (
    CleanupItem,
    CleanupOrchestrator,
    CleanupResult,
)
from skylos.llm.executor import RemediationExecutor, TestResult as ExecutionTestResult
from skylos.llm.orchestrator import RemediationAgent
from skylos.llm.planner import FindingItem, FixBatch, RemediationPlan


def report(root, **sections):
    return {
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["security", "quality", "ai_defects", "secrets"],
            "comparison_scope": {"repository_root": str(root), "scan_path": str(root)},
            "ai_verification": {"state": "complete"},
        },
        "analysis_errors": [],
        "danger": [],
        "quality": [],
        "ai_defects": [],
        "secrets": [],
        **sections,
    }


def finding(path, rule="SKY-D201", line=1):
    return {
        "file": str(path),
        "rule_id": rule,
        "line": line,
        "severity": "HIGH",
        "message": rule,
    }


@pytest.mark.parametrize(
    "options,reason",
    [
        ({"test_cmd": "false"}, "execution_disabled"),
        ({"allow_test_execution": True}, "no_test_command"),
        ({"allow_test_execution": True, "auto_detect_tests": True}, "no_test_command"),
    ],
)
def test_absent_execution_never_counts_as_a_pass(tmp_path, options, reason):
    executor = RemediationExecutor(project_root=tmp_path, **options)
    with patch("skylos.llm.executor.subprocess.run") as run:
        result = executor.run_tests()
    assert result.passed is None
    assert result.to_receipt()["status"] == "skipped"
    assert result.reason == reason
    run.assert_not_called()


@pytest.mark.parametrize("returncode,status", [(0, "passed"), (1, "failed")])
def test_executed_tests_keep_actual_exit_status(tmp_path, returncode, status):
    executor = RemediationExecutor(
        project_root=tmp_path, test_cmd="trusted-tests", allow_test_execution=True
    )
    process = SimpleNamespace(returncode=returncode, stdout="out", stderr="err")
    with patch("skylos.llm.executor.subprocess.run", return_value=process) as run:
        result = executor.run_tests()
    assert result.status == status
    assert result.exit_code == returncode
    assert result.output == "outerr"
    assert run.call_args.kwargs["shell"] is False


def test_static_verification_disables_registry_and_target_execution(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    executor = RemediationExecutor(project_root=tmp_path)
    with patch("skylos.analyzer.analyze", return_value=report(tmp_path)) as analyze:
        assert executor.verify_fix(str(file), ["SKY-D201"]).finding_resolved is True
    options = analyze.call_args.kwargs
    assert options["enable_dependency_hallucinations"] is False
    assert options["enable_dead_code"] is False
    assert options["enable_sca"] is False
    assert options["grep_verify"] is False
    assert options["trace_file"] is False


@pytest.mark.parametrize(
    "broken",
    [
        {},
        {"analysis_errors": [{"kind": "syntax_error"}]},
        {"analysis_summary": {"total_files": 0}},
    ],
)
def test_incomplete_static_results_cannot_resolve_findings(tmp_path, broken):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    incomplete = report(tmp_path)
    incomplete.update(broken)
    if not broken:
        incomplete = {}
    executor = RemediationExecutor(project_root=tmp_path)
    with patch("skylos.analyzer.analyze", return_value=incomplete):
        result = executor.verify_fix(str(file), ["SKY-D201"])
    assert result.finding_resolved is False
    assert result.static_status == "skipped"
    assert result.verification_error


def test_ai_defect_still_present_is_not_a_successful_fix(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    executor = RemediationExecutor(project_root=tmp_path)
    after = report(tmp_path, ai_defects=[finding(file, "SKY-A113")])
    with patch("skylos.analyzer.analyze", return_value=after):
        result = executor.verify_fix(str(file), ["SKY-A113"])
    assert result.finding_resolved is False
    assert result.static_status == "failed"
    assert result.remaining_rule_ids == ["SKY-A113"]


def test_equal_finding_counts_cannot_hide_a_new_high_risk_finding(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    executor = RemediationExecutor(project_root=tmp_path)
    before = report(tmp_path, danger=[finding(file, "SKY-D201")])
    after = report(tmp_path, danger=[finding(file, "SKY-D211")])
    with patch("skylos.analyzer.analyze", return_value=after):
        result = executor.verify_fix(str(file), ["SKY-D201"], before_report=before)
    assert result.static_status == "failed"
    assert result.finding_resolved is False
    assert [row["rule_id"] for row in result.new_findings] == ["SKY-D211"]


@pytest.mark.parametrize("original", [[], ["SKY-D201"]])
def test_no_original_static_observation_remains_unverified(tmp_path, original):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    executor = RemediationExecutor(project_root=tmp_path)
    clean = report(tmp_path)
    with patch("skylos.analyzer.analyze", return_value=clean):
        result = executor.verify_fix(str(file), original, before_report=clean)
    assert result.static_status == "passed"
    assert result.finding_resolved is False
    assert result.to_receipt()["finding_resolution"]["status"] == "skipped"


def cleanup_case(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 42\n")
    item = CleanupItem(str(file), 1, "constants", "magic number", "extract")
    orchestrator = CleanupOrchestrator(model="test", api_key="test")
    orchestrator._adapter = MagicMock()
    orchestrator._adapter.complete.return_value = json.dumps(
        {
            "code_lines": ["ANSWER = 42", "x = ANSWER"],
            "confidence": "high",
            "change_description": "extract constant",
        }
    )
    return file, item, orchestrator


@pytest.mark.parametrize("tests_passed", [None, True])
def test_standards_patch_has_separate_static_test_and_resolution_receipts(
    tmp_path, tests_passed
):
    file, item, orchestrator = cleanup_case(tmp_path)
    executor = RemediationExecutor(project_root=tmp_path)
    clean = report(tmp_path)
    test_result = ExecutionTestResult(
        passed=tests_passed, reason="execution_disabled" if tests_passed is None else ""
    )
    with (
        patch("skylos.analyzer.analyze", return_value=clean) as analyze,
        patch.object(executor, "run_tests", return_value=test_result),
    ):
        orchestrator._apply_single_fix(item, executor, lambda *args: None)
    assert analyze.call_count == 2
    assert file.read_text() == "ANSWER = 42\nx = ANSWER\n"
    assert item.status == "applied_unverified"
    assert item.verification["static"]["status"] == "passed"
    assert item.verification["tests"]["status"] == (
        "skipped" if tests_passed is None else "passed"
    )
    assert item.verification["static"]["finding_resolution"]["status"] == "skipped"


@pytest.mark.parametrize("failure", ["new_finding", "incomplete", "test_failure"])
def test_standards_patch_reverts_failed_verification(tmp_path, failure):
    file, item, orchestrator = cleanup_case(tmp_path)
    executor = RemediationExecutor(project_root=tmp_path)
    before = report(tmp_path)
    after = deepcopy(before)
    if failure == "new_finding":
        after["danger"] = [finding(file)]
    elif failure == "incomplete":
        after["analysis_errors"] = [{"kind": "syntax_error"}]
    with (
        patch("skylos.analyzer.analyze", side_effect=[before, after]),
        patch.object(
            executor,
            "run_tests",
            return_value=ExecutionTestResult(passed=False, output="failure"),
        ) as tests,
    ):
        orchestrator._apply_single_fix(item, executor, lambda *args: None)
    assert file.read_text() == "x = 42\n"
    assert item.status == "reverted"
    if failure != "test_failure":
        tests.assert_not_called()


def test_general_remediation_requires_actual_tests_for_verified_status(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    old = finding(file)
    batch = FixBatch(str(file), findings=[FindingItem.from_dict(old)])
    executor = RemediationExecutor(project_root=tmp_path)
    fixer = MagicMock()
    fixer.fix.return_value = SimpleNamespace(
        fixed_code="x = 2\n",
        confidence=SimpleNamespace(value="high"),
        description="fix",
    )
    with (
        patch(
            "skylos.analyzer.analyze",
            side_effect=[report(tmp_path, danger=[old]), report(tmp_path)],
        ),
        patch.object(
            executor,
            "run_tests",
            return_value=ExecutionTestResult(passed=True, command="trusted-tests"),
        ),
    ):
        RemediationAgent()._process_batch(batch, fixer, executor, lambda *args: None)
    assert batch.status == "fixed"
    assert batch.verification["tests"]["status"] == "passed"
    assert batch.verification["static"]["finding_resolved"] is True


def test_summary_keeps_applied_totals_and_separates_verified_from_unverified():
    item = CleanupItem(
        "app.py",
        1,
        "constants",
        "description",
        "suggestion",
        status="applied_unverified",
    )
    assert CleanupResult(items=[item], applied=1).summary()["unverified"] == 1
    batch = FixBatch(
        "app.py",
        findings=[FindingItem("SKY-D201", "HIGH", "issue", "app.py", 1)],
        status="applied_unverified",
    )
    summary = RemediationPlan(batches=[batch], total_findings=1).summary()
    assert summary["fixed"] == 1
    assert summary["verified"] == 0
    assert summary["unverified"] == 1


def test_failed_rollback_retains_backup_for_retry(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("original\n")
    executor = RemediationExecutor(project_root=tmp_path)
    assert executor.apply_fix(str(file), "changed\n")
    with patch(
        "skylos.llm.executor.write_existing_text_no_symlink", return_value=False
    ):
        assert executor.revert_fix(str(file)) is False
    assert file.read_text() == "changed\n"
    assert executor.revert_fix(str(file)) is True
    assert file.read_text() == "original\n"


def test_cleanup_cannot_report_reverted_when_restore_failed(tmp_path):
    file, item, orchestrator = cleanup_case(tmp_path)
    executor = RemediationExecutor(project_root=tmp_path)
    with (
        patch("skylos.analyzer.analyze", return_value=report(tmp_path)),
        patch.object(
            executor, "run_tests", return_value=ExecutionTestResult(passed=False)
        ),
        patch.object(executor, "revert_fix", return_value=False),
    ):
        orchestrator._apply_single_fix(item, executor, lambda *args: None)
    assert item.status == "rollback_failed"
    assert item.verification["rollback"]["status"] == "failed"
    assert file.read_text() == "ANSWER = 42\nx = ANSWER\n"


@pytest.mark.parametrize(
    "after_source,after_line,status",
    [
        ("\neval('old')\n", 2, "passed"),
        ("eval('new')\n", 1, "failed"),
    ],
)
def test_static_identity_uses_captured_source_without_confusing_line_shifts(
    tmp_path, after_source, after_line, status
):
    file = tmp_path / "app.py"
    file.write_text("eval('old')\n")
    executor = RemediationExecutor(project_root=tmp_path)
    old = report(tmp_path, danger=[finding(file)])
    with patch("skylos.analyzer.analyze", return_value=old):
        before = executor.capture_static_report(str(file))
    assert "_verification_sources" not in old
    file.write_text(after_source)
    after = report(tmp_path, danger=[finding(file, line=after_line)])
    with patch("skylos.analyzer.analyze", return_value=after):
        result = executor.verify_fix(str(file), [], before_report=before)
    assert result.static_status == status
    assert bool(result.new_findings) is (status == "failed")


def test_changed_source_during_static_analysis_is_unverified(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("x = 1\n")
    executor = RemediationExecutor(project_root=tmp_path)

    def changed(*args, **kwargs):
        file.write_text("x = 2\n")
        return report(tmp_path)

    with patch("skylos.analyzer.analyze", side_effect=changed):
        result = executor.verify_fix(str(file), ["SKY-D201"])
    assert result.finding_resolved is False
    assert result.static_status == "skipped"
    assert "source changed" in result.verification_error
