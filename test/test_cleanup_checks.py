import sys

import pytest

from skylos.cleanup_checks import (
    compare_cleanup_behavior,
    run_cleanup_tests,
    validate_junit_path,
)


def test_successful_non_test_command_has_no_observed_tests(tmp_path):
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "-c", "pass"],
        file="app.py",
        before="x = 1\n",
        after="x = 2\n",
    )
    assert result["status"] == "passed"
    assert result["evidence"] == "exit_code"
    assert result["observed"] is False
    assert result["count"] is None
    assert result["exercised_change"] is None


def test_pytest_records_test_count_and_whether_changed_code_ran(tmp_path):
    before = "def answer():\n    return 1 + 1\n"
    after = "def answer():\n    return 2\n"
    (tmp_path / "app.py").write_text(after)
    (tmp_path / "test_app.py").write_text(
        "from app import answer\n\ndef test_answer():\n    assert answer() == 2\n"
    )
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "-m", "pytest", "-q", "test_app.py"],
        file="app.py",
        before=before,
        after=after,
    )
    assert result["status"] == "passed"
    assert result["observed"] is True
    assert result["evidence"] == "pytest_junit"
    assert result["count"] == result["passed_count"] == 1
    assert result["exercised_change"] is True
    assert result["trace"]["test_nodes"] == ["test_app.py::test_answer"]


def test_unrelated_tests_are_counted_but_do_not_claim_to_exercise_the_change(tmp_path):
    (tmp_path / "app.py").write_text("def answer():\n    return 2\n")
    (tmp_path / "test_other.py").write_text(
        "def test_other():\n    assert 2 + 2 == 4\n"
    )
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "-m", "pytest", "-q", "test_other.py"],
        file="app.py",
        before="def answer():\n    return 1\n",
        after="def answer():\n    return 2\n",
    )
    assert result["observed"] is True
    assert result["exercised_change"] is False


def test_empty_or_skipped_test_suites_are_incomplete(tmp_path):
    (tmp_path / "test_skip.py").write_text(
        "import pytest\n\n@pytest.mark.skip\ndef test_later():\n    assert True\n"
    )
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "-m", "pytest", "-q", "test_skip.py"],
        file="app.py",
        before="x=1",
        after="x=2",
    )
    assert result["status"] == "incomplete"
    assert result["observed"] is False


def test_custom_junit_must_be_written_by_the_authorized_invocation(tmp_path):
    report = tmp_path / "junit.xml"
    report.write_text(
        '<testsuite><testcase classname="sample" name="test_ok" /></testsuite>'
    )
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "-c", "pass"],
        file="app.py",
        before="x=1",
        after="x=2",
        junit_xml="junit.xml",
    )
    assert result["status"] == "incomplete"
    assert result["observed"] is False


def test_fresh_custom_junit_records_tests_without_claiming_python_coverage(tmp_path):
    script = tmp_path / "check.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('junit.xml').write_text('<testsuite><testcase name=\"ok\" /></testsuite>')\n"
    )
    result = run_cleanup_tests(
        tmp_path,
        [sys.executable, "check.py"],
        file="app.ts",
        before="const x = 1;",
        after="const x = 2;",
        junit_xml="junit.xml",
    )
    assert result["status"] == "passed"
    assert result["observed"] is True
    assert result["count"] == 1
    assert result["evidence"] == "junit"
    assert result["exercised_change"] is None


@pytest.mark.parametrize(
    "path", ["../outside.xml", "/tmp/outside.xml", "C:\\outside.xml", "a\\b.xml", ""]
)
def test_junit_report_paths_are_scoped(path):
    with pytest.raises(ValueError):
        validate_junit_path(path)


def test_effect_model_records_equivalent_different_and_unsupported_separately():
    same = compare_cleanup_behavior(
        "app.py",
        "def f(x):\n    return x\n",
        "def f(x):\n    result = x\n    return result\n",
    )
    different = compare_cleanup_behavior(
        "app.py", "def f(x):\n    return x\n", "def f(x):\n    return 42\n"
    )
    deleted = compare_cleanup_behavior("app.py", "def f(x):\n    return x\n", "")
    assert same["status"] == "passed"
    assert different["status"] == "failed"
    assert different["functions"][0]["differences"][0]["runtime_witness"] is False
    assert deleted["status"] == "skipped"
