from __future__ import annotations

import shlex
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from skylos.llm.executor import RemediationExecutor
from skylos.llm.orchestrator import RemediationAgent
from skylos.llm.planner import FindingItem, FixBatch, RemediationPlan
from skylos.llm.prompts import build_pr_description


def scan_result(findings=(), *, errors=()):
    return {
        "danger": list(findings),
        "quality": [],
        "secrets": [],
        "analysis_errors": list(errors),
        "analysis_summary": {"total_files": 1, "analysis_error_count": len(errors)},
    }


def finding(rule="SKY-D201", line=1, message="Unsafe eval"):
    return {"rule_id": rule, "line": line, "message": message, "col": 0}


def python_cmd(code):
    return shlex.join([sys.executable, "-c", code])


def make_batch(path):
    return FixBatch(
        file=str(path),
        findings=[
            FindingItem(
                rule_id="SKY-D201",
                severity="HIGH",
                message="Unsafe eval",
                file=str(path),
                line=1,
            )
        ],
    )


def make_fixer(code="value = 1\n"):
    fixer = MagicMock()
    fixer.fix.return_value = SimpleNamespace(
        fixed_code=code,
        confidence=SimpleNamespace(value="high"),
        description="Replace eval",
    )
    return fixer


def test_enabled_without_selected_suite_is_not_run(tmp_path):
    executor = RemediationExecutor(
        project_root=tmp_path, allow_test_execution=True, auto_detect_tests=True
    )
    with patch("skylos.llm.executor.subprocess.run") as run:
        result = executor.run_tests()
    assert (result.status, result.executed, result.passed) == ("not_run", False, False)
    assert result.returncode is None
    run.assert_not_called()


def test_disabled_custom_command_never_runs(tmp_path):
    executor = RemediationExecutor(
        project_root=tmp_path, test_cmd=python_cmd("raise SystemExit(0)")
    )
    with patch("skylos.llm.executor.subprocess.run") as run:
        result = executor.run_tests()
    assert result.status == "not_run"
    assert not result.passed
    run.assert_not_called()


def test_check_records_actual_exit_stderr_and_exact_source_digest(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd(
            "import sys\nprint('details', file=sys.stderr)\nraise SystemExit(3)"
        ),
    )
    result = executor.run_tests(source_files=[str(source)])
    assert result.status == "failed" and result.executed and not result.passed
    assert result.returncode == 3
    assert "details" in result.output
    assert set(result.source_digests) == {"app.py"}


def test_test_command_source_mutation_is_outdated_not_passed(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("before\n")
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd(
            "from pathlib import Path\nPath('app.py').write_text('changed\\n')"
        ),
    )
    result = executor.run_tests(source_files=[str(source)])
    assert result.returncode == 0
    assert result.status == "outdated" and not result.passed
    assert "changed during execution" in result.output


def test_timeout_is_executed_failure_not_pass(tmp_path):
    executor = RemediationExecutor(
        project_root=tmp_path, allow_test_execution=True, test_cmd="pytest -q"
    )
    with patch(
        "skylos.llm.executor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(["pytest"], 1),
    ):
        result = executor.run_tests(timeout=1)
    assert result.status == "failed" and result.executed and not result.passed
    assert result.returncode is None


def test_spawn_error_is_not_an_executed_pass(tmp_path):
    executor = RemediationExecutor(
        project_root=tmp_path, allow_test_execution=True, test_cmd="pytest -q"
    )
    with patch(
        "skylos.llm.executor.subprocess.run", side_effect=FileNotFoundError("missing")
    ):
        result = executor.run_tests()
    assert result.status == "failed" and not result.executed and not result.passed


def test_apply_fix_refuses_source_changed_after_model_context(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("user edit\n")
    executor = RemediationExecutor(project_root=tmp_path)
    assert not executor.apply_fix(
        str(source), "model fix\n", expected_source="old source\n"
    )
    assert source.read_text() == "user edit\n"


def test_revert_does_not_clobber_edit_made_after_fix(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("before\n")
    executor = RemediationExecutor(project_root=tmp_path)
    assert executor.apply_fix(str(source), "fix\n")
    source.write_text("later edit\n")
    assert not executor.revert_fix(str(source))
    assert source.read_text() == "later edit\n"


def test_new_rule_after_fix_is_rejected(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze",
        side_effect=[
            scan_result([finding()]),
            scan_result([finding("SKY-D212", message="Unsafe command")]),
        ],
    ):
        assert executor.capture_verification_baseline(str(source))
        assert executor.apply_fix(str(source), "os.system(value)\n")
        result = executor.verify_fix(str(source), ["SKY-D201"])
    assert not result.finding_resolved
    assert result.status == "failed"
    assert [row["rule_id"] for row in result.new_findings] == ["SKY-D212"]


def test_existing_unrelated_finding_survives_line_shift_without_new_false_alarm(
    tmp_path,
):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\nexisting_weak_hash()\n")
    unrelated = finding("SKY-D206", line=2, message="Weak hash")
    shifted = dict(unrelated, line=3)
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze",
        side_effect=[scan_result([finding(), unrelated]), scan_result([shifted])],
    ):
        assert executor.capture_verification_baseline(str(source))
        executor.apply_fix(str(source), "value = 1\n# shifted\nexisting_weak_hash()\n")
        result = executor.verify_fix(str(source), ["SKY-D201"])
    assert result.finding_resolved and result.status == "passed"
    assert result.new_findings == []


def test_another_instance_of_existing_rule_is_new_finding(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\nexisting_weak_hash()\n")
    unrelated = finding("SKY-D206", line=2, message="Weak hash")
    duplicate = dict(unrelated, line=3)
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze",
        side_effect=[
            scan_result([finding(), unrelated]),
            scan_result([unrelated, duplicate]),
        ],
    ):
        executor.capture_verification_baseline(str(source))
        executor.apply_fix(
            str(source), "value = 1\nexisting_weak_hash()\nanother_weak_hash()\n"
        )
        result = executor.verify_fix(str(source), ["SKY-D201"])
    assert not result.finding_resolved
    assert result.new_findings == [duplicate]


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"analysis_summary": {"total_files": 0}},
        scan_result(errors=[{"message": "parse failure"}]),
    ],
)
def test_incomplete_scan_cannot_verify_fix(tmp_path, result):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    with patch("skylos.analyzer.analyze", return_value=result):
        verification = RemediationExecutor(project_root=tmp_path).verify_fix(
            str(source), ["SKY-D201"]
        )
    assert not verification.finding_resolved
    assert verification.status == "incomplete"
    assert verification.verification_error


def test_orchestrator_keeps_disabled_tests_explicitly_incomplete_and_passes_graph_context(
    tmp_path,
):
    source = tmp_path / "app.py"
    source.write_text(
        "def run(value):\n    return eval(value)\n\ndef caller():\n    return run('1')\n"
    )
    batch = make_batch(source)
    batch.findings[0].line = 2
    fixer = make_fixer(
        "def run(value):\n    return int(value)\n\ndef caller():\n    return run('1')\n"
    )
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze",
        side_effect=[scan_result([finding(line=2)]), scan_result()],
    ):
        RemediationAgent()._process_batch(batch, fixer, executor, lambda _: None)
    assert batch.status == "fixed" and batch.fix_status == "incomplete", (
        batch.fix_description
    )
    assert batch.checks[0]["status"] == "not_run"
    context = fixer.fix.call_args.kwargs["context"]
    assert "caller" in context and "file_digests" in context
    assert "untrusted" in context.lower()
    assert batch.context_snapshot
    body = build_pr_description(
        RemediationPlan(batches=[batch], total_findings=1).summary()
    )
    assert "Not Run" in body
    assert "Incomplete" in body
    assert "Verification Proof" not in body


def test_orchestrator_executes_selected_test_and_reports_only_checks_passed(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    batch = make_batch(source)
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd("assert 2 + 2 == 4"),
    )
    with patch(
        "skylos.analyzer.analyze", side_effect=[scan_result([finding()]), scan_result()]
    ):
        RemediationAgent()._process_batch(batch, make_fixer(), executor, lambda _: None)
    assert batch.status == "fixed" and batch.fix_status == "checks_passed", (
        batch.fix_description
    )
    check = batch.checks[0]
    assert check["returncode"] == 0 and check["executed"]
    assert (
        check["source_digests"]["app.py"] == batch.static_verification["source_digest"]
    )
    assert "whole-project" in batch.static_verification["limitations"][0]


def test_orchestrator_reverts_new_finding_even_when_tests_pass(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    batch = make_batch(source)
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd("assert True"),
    )
    with patch(
        "skylos.analyzer.analyze",
        side_effect=[scan_result([finding()]), scan_result([finding("SKY-D212")])],
    ):
        RemediationAgent()._process_batch(
            batch, make_fixer("os.system(value)\n"), executor, lambda _: None
        )
    assert batch.status == "not_resolved" and batch.fix_status == "failed"
    assert source.read_text() == "eval(value)\n"
    assert "new static findings" in batch.fix_description


def test_orchestrator_reverts_on_failed_project_test(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    batch = make_batch(source)
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd("raise SystemExit(1)"),
    )
    with patch("skylos.analyzer.analyze", return_value=scan_result([finding()])):
        RemediationAgent()._process_batch(batch, make_fixer(), executor, lambda _: None)
    assert batch.status == "test_failed" and batch.fix_status == "failed"
    assert source.read_text() == "eval(value)\n"


def test_baseline_must_reproduce_planned_rule_before_paid_model_call(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    batch = make_batch(source)
    fixer = make_fixer()
    executor = RemediationExecutor(project_root=tmp_path)
    with patch("skylos.analyzer.analyze", return_value=scan_result()):
        RemediationAgent()._process_batch(batch, fixer, executor, lambda _: None)
    assert batch.fix_status == "incomplete"
    fixer.fix.assert_not_called()
    assert source.read_text() == "value = 1\n"


def test_failed_batch_cleanup_keeps_other_batches_generated_tests(tmp_path):
    from skylos.remediation.regression_tests import RegressionTestCandidate

    (tmp_path / "tests").mkdir()
    first = RegressionTestCandidate(
        "SKY-D211", "sql_injection", "a.py", "tests/first.py", "check", "assert True\n"
    )
    second = RegressionTestCandidate(
        "SKY-D211", "sql_injection", "b.py", "tests/second.py", "check", "assert True\n"
    )
    executor = RemediationExecutor(project_root=tmp_path)
    assert executor.write_regression_test(first)
    assert executor.write_regression_test(second)
    executor.revert_regression_tests([second])
    assert (tmp_path / first.test_file).exists()
    assert not (tmp_path / second.test_file).exists()


def test_checked_crlf_source_uses_exact_bytes_digest(tmp_path):
    import hashlib

    source = tmp_path / "app.py"
    original = b"value = 1\r\n"
    source.write_bytes(original)
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd("assert True"),
    )
    result = executor.run_tests(source_files=[str(source)])
    assert result.passed
    assert (
        result.source_digests["app.py"]
        == "sha256:" + hashlib.sha256(original).hexdigest()
    )


@pytest.mark.parametrize("section", ["ai_defects", "reliability"])
def test_new_separate_result_category_cannot_be_missed(tmp_path, section):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    after = scan_result()
    after[section] = [finding("SKY-A001", message="New separate-category defect")]
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze", side_effect=[scan_result([finding()]), after]
    ):
        executor.capture_verification_baseline(str(source), ["SKY-D201"])
        executor.apply_fix(str(source), "unknown_dependency()\n")
        verification = executor.verify_fix(str(source), ["SKY-D201"])
    assert not verification.finding_resolved
    assert verification.new_findings == after[section]


def test_inline_ignore_cannot_manufacture_fixed_status(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    after = scan_result()
    after["suppressed"] = [dict(finding(), reason="inline ignore comment")]
    executor = RemediationExecutor(project_root=tmp_path)
    with patch(
        "skylos.analyzer.analyze", side_effect=[scan_result([finding()]), after]
    ):
        executor.capture_verification_baseline(str(source), ["SKY-D201"])
        executor.apply_fix(str(source), "eval(value)  # skylos: ignore[SKY-D201]\n")
        verification = executor.verify_fix(str(source), ["SKY-D201"])
    assert not verification.finding_resolved
    assert verification.remaining_rule_ids == ["SKY-D201"]


@pytest.mark.parametrize("kind", ["language", "rule"])
def test_explicit_partial_static_coverage_is_incomplete(tmp_path, kind):
    source = tmp_path / "app.py"
    source.write_text("eval(value)\n")
    result = scan_result([finding()])
    if kind == "language":
        result["analysis_summary"]["language_engines"] = {
            "python": {"status": "available", "complete": False}
        }
    else:
        result["danger"][0]["metadata"] = {"analysis_complete": False}
    with patch("skylos.analyzer.analyze", return_value=result):
        verification = RemediationExecutor(project_root=tmp_path).verify_fix(
            str(source), ["SKY-D201"]
        )
    assert verification.status == "incomplete" and not verification.finding_resolved


def test_assessment_incomplete_checks_prevent_static_pass(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    result = scan_result()
    result["assessment"] = {
        "coverage": {"status": "incomplete", "incomplete_checks": ["ai_defects"]}
    }
    with patch("skylos.analyzer.analyze", return_value=result):
        verification = RemediationExecutor(project_root=tmp_path).verify_fix(
            str(source), ["SKY-D201"]
        )
    assert verification.status == "incomplete"
    assert not verification.finding_resolved


def _two_file_run(tmp_path, *, allow_test_execution=False, final_failure=False):
    paths = [tmp_path / "a.py", tmp_path / "b.py"]
    for path in paths:
        path.write_text("eval(value)\n")
    findings = [dict(finding(), file=str(path), severity="HIGH") for path in paths]
    # Two per-batch snapshots followed by both final edited-file rescans.
    results = [
        scan_result([finding()]),
        scan_result(),
        scan_result([finding()]),
        scan_result(),
        scan_result(),
        scan_result(),
    ]
    code = (
        "from pathlib import Path\n"
        "path = Path('check-count')\n"
        "count = int(path.read_text()) + 1 if path.exists() else 1\n"
        "path.write_text(str(count))\n"
        f"raise SystemExit(int(count == {3 if final_failure else 99}))"
    )
    agent = RemediationAgent(
        allow_test_execution=allow_test_execution, test_cmd=python_cmd(code)
    )
    with (
        patch.object(agent, "_scan", return_value={"danger": findings}),
        patch.object(agent, "_create_fixer", return_value=make_fixer()),
        patch("skylos.analyzer.analyze", side_effect=results),
    ):
        return agent.run(tmp_path, quiet=True), paths


def test_two_applied_fixes_get_one_final_shared_actual_check(tmp_path):
    summary, paths = _two_file_run(tmp_path, allow_test_execution=True)
    assert summary["checks_passed"] == 2
    assert (tmp_path / "check-count").read_text() == "3"
    for batch in summary["batches"]:
        assert batch["fix_status"] == "checks_passed"
        final = batch["checks"][-1]
        assert final["kind"] == "final_project_command"
        assert final["executed"] and final["returncode"] == 0
        assert set(final["source_digests"]) == {path.name for path in paths}
        assert batch["checks"][0]["current"] is False


def test_failed_final_shared_check_keeps_patches_and_reports_failed(tmp_path):
    summary, paths = _two_file_run(
        tmp_path, allow_test_execution=True, final_failure=True
    )
    assert summary["checks_passed"] == 0
    assert summary["failed"] == 0
    assert summary["checks_failed"] == 2
    assert summary["incomplete"] == 0
    assert all(batch["fix_status"] == "failed" for batch in summary["batches"])
    assert all(path.read_text() == "value = 1\n" for path in paths)
    assert all(
        "changes kept for review" in batch["description"]
        for batch in summary["batches"]
    )


def test_disabled_final_checks_mark_earlier_batch_outdated(tmp_path):
    summary, paths = _two_file_run(tmp_path)
    assert summary["checks_passed"] == 0
    assert [batch["fix_status"] for batch in summary["batches"]] == [
        "outdated",
        "incomplete",
    ]
    assert not (tmp_path / "check-count").exists()
    assert all(path.read_text() == "value = 1\n" for path in paths)


def test_generated_static_check_has_its_own_real_execution_receipt(tmp_path):
    from skylos.remediation.regression_tests import RegressionTestCandidate

    (tmp_path / "tests").mkdir()
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    candidate = RegressionTestCandidate(
        "SKY-D211",
        "sql_injection",
        "app.py",
        "tests/test_generated.py",
        "Static check",
        "def test_static_check():\n    assert True\n",
    )
    executor = RemediationExecutor(project_root=tmp_path, allow_test_execution=True)
    assert executor.write_regression_test(candidate)
    result = executor.run_regression_tests([candidate], source_files=[str(source)])
    assert result.passed and result.status == "passed" and result.executed
    assert result.returncode == 0
    assert set(result.source_digests) == {"app.py", "tests/test_generated.py"}
    assert "tests/test_generated.py" in result.command


def test_incomplete_auto_pr_is_draft_with_explicit_check_status(tmp_path):
    batch = make_batch(tmp_path / "app.py")
    batch.status = "fixed"
    batch.fix_status = "incomplete"
    plan = RemediationPlan(batches=[batch], total_findings=1)
    executor = MagicMock()
    executor.project_root = tmp_path
    executor.create_pr.return_value = "https://example.test/pull/1"
    executor.current_commit.return_value = "a" * 40
    RemediationAgent()._create_pr(executor, plan, "skylos/fix", lambda _: None)
    assert executor.create_pr.call_args.kwargs["draft"] is True
    body = executor.create_pr.call_args.args[2]
    assert "Incomplete" in body
    assert "Tests: **Not run**" in body


def test_all_skipped_generated_cases_cannot_claim_passed(tmp_path):
    from skylos.remediation.regression_tests import RegressionTestCandidate

    (tmp_path / "tests").mkdir()
    candidate = RegressionTestCandidate(
        "SKY-D211",
        "sql_injection",
        "app.py",
        "tests/test_skipped.py",
        "Static check",
        "import pytest\n\n@pytest.mark.skip(reason='not executed')\ndef test_static_check():\n    assert False\n",
    )
    executor = RemediationExecutor(project_root=tmp_path, allow_test_execution=True)
    executor.write_regression_test(candidate)
    result = executor.run_regression_tests([candidate])
    assert result.executed and result.returncode == 0
    assert not result.passed and result.status == "incomplete"
    assert result.case_counts["skipped"] == 1


def test_modified_generated_case_is_outdated_before_execution(tmp_path):
    from skylos.remediation.regression_tests import RegressionTestCandidate

    (tmp_path / "tests").mkdir()
    candidate = RegressionTestCandidate(
        "SKY-D211",
        "sql_injection",
        "app.py",
        "tests/test_changed.py",
        "Static check",
        "def test_static_check():\n    assert False\n",
    )
    executor = RemediationExecutor(project_root=tmp_path, allow_test_execution=True)
    executor.write_regression_test(candidate)
    (tmp_path / candidate.test_file).write_text(
        "def test_static_check():\n    assert True\n"
    )
    result = executor.run_regression_tests([candidate])
    assert not result.executed and not result.passed and result.status == "outdated"


def test_remediation_body_cannot_inject_evidence_headings_from_repo_or_model_text():
    batch = {
        "file": "evil`</details>\n## Proven.py",
        "findings": 1,
        "status": "fixed",
        "fix_status": "incomplete",
        "top_severity": "HIGH",
        "description": "</details>\r\n## VERIFIED | `fake`",
    }
    body = build_pr_description({"batches": [batch], "fixed": 1, "total_findings": 1})
    assert "</details>" not in body
    assert "\n## VERIFIED" not in body
    assert "&#96;" in body
    assert "&lt;/details&gt;" in body


def test_mixed_skipped_same_name_generated_cases_are_incomplete(tmp_path):
    from skylos.remediation.regression_tests import RegressionTestCandidate

    (tmp_path / "tests").mkdir()
    candidates = [
        RegressionTestCandidate(
            "SKY-D211",
            "sql_injection",
            "app.py",
            "tests/test_one.py",
            "Static check",
            "def test_static_check():\n    assert True\n",
        ),
        RegressionTestCandidate(
            "SKY-D211",
            "sql_injection",
            "app.py",
            "tests/test_two.py",
            "Static check",
            "import pytest\n\n@pytest.mark.skip(reason='not executed')\ndef test_static_check():\n    assert False\n",
        ),
    ]
    executor = RemediationExecutor(project_root=tmp_path, allow_test_execution=True)
    for candidate in candidates:
        executor.write_regression_test(candidate)
    result = executor.run_regression_tests(candidates)
    assert result.executed and result.returncode == 0
    assert not result.passed and result.status == "incomplete"
    assert result.case_counts["skipped"] == 1


def test_selected_pytest_all_skipped_is_incomplete(tmp_path):
    (tmp_path / "test_skipped.py").write_text(
        "import pytest\n\n@pytest.mark.skip(reason='not executed')\ndef test_body():\n    assert False\n"
    )
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=shlex.join([sys.executable, "-m", "pytest", "-q"]),
    )
    result = executor.run_tests()
    assert result.executed and result.returncode == 0
    assert not result.passed and result.status == "incomplete"
    assert result.case_counts == {"total": 1, "passed": 0, "skipped": 1}


def test_selected_pytest_records_passing_body(tmp_path):
    (tmp_path / "test_body.py").write_text("def test_body():\n    assert True\n")
    executor = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=shlex.join([sys.executable, "-m", "pytest", "-q"]),
    )
    result = executor.run_tests()
    assert result.passed and result.case_counts["passed"] == 1
    assert result.to_summary()["evidence_kind"] == "test_cases"


def test_selected_generic_command_is_not_called_test_case_proof(tmp_path):
    result = RemediationExecutor(
        project_root=tmp_path,
        allow_test_execution=True,
        test_cmd=python_cmd("assert True"),
    ).run_tests()
    assert result.passed and result.to_summary()["evidence_kind"] == "command_exit"
    body = build_pr_description(
        {
            "batches": [
                {
                    "file": "app.py",
                    "status": "fixed",
                    "fix_status": "checks_passed",
                    "findings": 1,
                    "top_severity": "HIGH",
                    "checks": [dict(result.to_summary(), kind="project_command")],
                }
            ]
        }
    )
    assert "Command succeeded" in body


def _publication_fixture(tmp_path, monkeypatch):
    import hashlib

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=tmp_path, check=True, text=True, capture_output=True
        )

    git("init", "-q")
    git("config", "user.name", "Skylos Test")
    git("config", "user.email", "skylos-test@example.invalid")
    git("config", "commit.gpgsign", "false")
    git("config", "core.hooksPath", str(tmp_path / ".git" / "hooks"))
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    batch = make_batch(source)
    batch.status = "fixed"
    batch.fix_status = "checks_passed"
    digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    batch.static_verification = {"status": "passed", "source_digest": digest}
    batch.checks = [
        {"status": "passed", "executed": True, "source_digests": {"app.py": digest}}
    ]
    executor = RemediationExecutor(project_root=tmp_path)
    push = MagicMock(return_value=True)
    create = MagicMock(return_value="https://example.test/pull/1")
    monkeypatch.setattr(executor, "push_branch", push)
    monkeypatch.setattr(executor, "create_pr", create)
    return source, batch, executor, push, create, git


def test_publication_refuses_source_drift_before_commit(tmp_path, monkeypatch):
    source, batch, executor, push, create, _git = _publication_fixture(
        tmp_path, monkeypatch
    )
    source.write_text("later user edit\n")
    commit = MagicMock(return_value=True)
    monkeypatch.setattr(executor, "commit_fixes", commit)
    result = RemediationAgent()._create_pr(
        executor,
        RemediationPlan(batches=[batch], total_findings=1),
        "skylos/fix",
        lambda _: None,
    )
    assert result is None
    assert batch.fix_status == "outdated"
    assert source.read_text() == "later user edit\n"
    commit.assert_not_called()
    push.assert_not_called()
    create.assert_not_called()


def test_publication_checks_committed_blob_after_hook_restages_bytes(
    tmp_path, monkeypatch
):
    source, batch, executor, push, create, git = _publication_fixture(
        tmp_path, monkeypatch
    )
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\nprintf 'value = 99\\n' > app.py\ngit add -- app.py\nprintf 'value = 1\\n' > app.py\n"
    )
    hook.chmod(0o755)
    result = RemediationAgent()._create_pr(
        executor,
        RemediationPlan(batches=[batch], total_findings=1),
        "skylos/fix",
        lambda _: None,
    )
    assert result is None
    assert batch.fix_status == "outdated"
    assert source.read_text() == "value = 1\n"
    assert git("show", "HEAD:app.py").stdout == "value = 99\n"
    push.assert_not_called()
    create.assert_not_called()


def test_publication_pushes_only_exact_checked_commit(tmp_path, monkeypatch):
    source, batch, executor, push, create, _git = _publication_fixture(
        tmp_path, monkeypatch
    )
    result = RemediationAgent()._create_pr(
        executor,
        RemediationPlan(batches=[batch], total_findings=1),
        "skylos/fix",
        lambda _: None,
    )
    assert result == "https://example.test/pull/1"
    checked_commit = executor.current_commit()
    push.assert_called_once_with("skylos/fix", expected_commit=checked_commit)
    assert batch.static_verification["commit"] == checked_commit
    assert create.call_args.kwargs["draft"] is False
    assert source.read_text() == "value = 1\n"


def test_push_command_binds_validated_oid_instead_of_mutable_branch(tmp_path):
    executor = RemediationExecutor(project_root=tmp_path)
    with patch("skylos.llm.executor.subprocess.run") as run:
        assert executor.push_branch("skylos/fix", expected_commit="a" * 40)
    assert run.call_args.args[0] == [
        "git",
        "push",
        "origin",
        "a" * 40 + ":refs/heads/skylos/fix",
    ]


def test_publication_preserves_unrelated_staged_work(tmp_path, monkeypatch):
    source, batch, executor, push, create, git = _publication_fixture(
        tmp_path, monkeypatch
    )
    other = tmp_path / "unrelated.py"
    other.write_text("user_change = True\n")
    git("add", "unrelated.py")
    result = RemediationAgent()._create_pr(
        executor,
        RemediationPlan(batches=[batch], total_findings=1),
        "skylos/fix",
        lambda _: None,
    )
    assert result is None and batch.fix_status == "outdated"
    assert other.read_text() == "user_change = True\n"
    assert git("diff", "--cached", "--name-only").stdout.strip() == "unrelated.py"
    push.assert_not_called()
    create.assert_not_called()


def test_publication_rejects_hook_added_unchecked_file(tmp_path, monkeypatch):
    source, batch, executor, push, create, git = _publication_fixture(
        tmp_path, monkeypatch
    )
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.write_text(
        "#!/bin/sh\nprintf 'unchecked = True\\n' > extra.py\ngit add -- extra.py\n"
    )
    hook.chmod(0o755)
    result = RemediationAgent()._create_pr(
        executor,
        RemediationPlan(batches=[batch], total_findings=1),
        "skylos/fix",
        lambda _: None,
    )
    assert result is None and batch.fix_status == "outdated"
    assert git("show", "HEAD:extra.py").stdout == "unchecked = True\n"
    assert source.read_text() == "value = 1\n"
    push.assert_not_called()
    create.assert_not_called()
