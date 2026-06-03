from __future__ import annotations

from skylos.llm.planner import FindingItem
from skylos.remediation.regression_tests import (
    SQL_INJECTION_RULE_ID,
    generate_regression_test_candidate,
)


def test_generates_sql_injection_regression_candidate(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    source = tmp_path / "app.py"
    source.write_text(
        "def get_user(cursor, user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    return cursor.execute(query)\n",
        encoding="utf-8",
    )
    finding = FindingItem(
        rule_id=SQL_INJECTION_RULE_ID,
        severity="CRITICAL",
        message="Possible SQL injection",
        file=str(source),
        line=3,
    )

    candidate = generate_regression_test_candidate(finding, tmp_path)

    assert candidate is not None
    assert candidate.rule_id == SQL_INJECTION_RULE_ID
    assert candidate.family == "sql_injection"
    assert candidate.source_file == "app.py"
    assert candidate.test_file.startswith("tests/test_skylos_sqli_app_py_")
    assert candidate.test_file.endswith(".py")
    assert "from skylos.analyzer import analyze" in candidate.content
    assert "SKY-D211" in candidate.content
    assert "SELECT * FROM users" not in candidate.content


def test_skips_non_sql_injection_findings(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    source = tmp_path / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")
    finding = {
        "rule_id": "SKY-D206",
        "severity": "MEDIUM",
        "message": "Weak hash",
        "file": str(source),
        "line": 1,
    }

    candidate = generate_regression_test_candidate(finding, tmp_path)

    assert candidate is None


def test_skips_when_project_has_no_existing_test_directory(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")
    finding = {
        "rule_id": SQL_INJECTION_RULE_ID,
        "severity": "CRITICAL",
        "message": "Possible SQL injection",
        "file": str(source),
        "line": 1,
    }

    candidate = generate_regression_test_candidate(finding, tmp_path)

    assert candidate is None


def test_skips_source_outside_project(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    outside_dir = tmp_path.parent / f"{tmp_path.name}-outside"
    outside_dir.mkdir()
    source = outside_dir / "app.py"
    source.write_text("x = 1\n", encoding="utf-8")
    finding = {
        "rule_id": SQL_INJECTION_RULE_ID,
        "severity": "CRITICAL",
        "message": "Possible SQL injection",
        "file": str(source),
        "line": 1,
    }

    candidate = generate_regression_test_candidate(finding, tmp_path)

    assert candidate is None
