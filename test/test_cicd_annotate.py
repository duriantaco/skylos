import pytest

from skylos.cli import _emit_github_annotations


@pytest.fixture
def sample_results():
    return {
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": "app.py",
                "line": 10,
                "severity": "CRITICAL",
                "message": "SQL injection via user input",
            },
            {
                "rule_id": "SKY-D202",
                "file": "api.py",
                "line": 20,
                "severity": "HIGH",
                "message": "Command injection risk",
            },
        ],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "file": "utils.py",
                "line": 5,
                "severity": "MEDIUM",
                "message": "Cyclomatic complexity too high",
            },
        ],
        "secrets": [],
        "unused_functions": [
            {"name": "old_func", "file": "lib.py", "line": 42},
        ],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
    }


def test_annotations_priority_order(sample_results, capsys):
    _emit_github_annotations(sample_results)
    output = capsys.readouterr().out
    lines = output.strip().splitlines()
    assert "::error" in lines[0]
    assert "SQL injection" in lines[0]


def test_annotations_capped(sample_results, capsys):
    sample_results["quality"] = [
        {
            "rule_id": f"SKY-Q{i}",
            "file": f"file{i}.py",
            "line": i,
            "severity": "LOW",
            "message": f"Issue {i}",
        }
        for i in range(60)
    ]
    _emit_github_annotations(sample_results, max_annotations=50)
    output = capsys.readouterr().out
    lines = output.strip().splitlines()
    assert len(lines) == 50


def test_severity_filter(sample_results, capsys):
    _emit_github_annotations(sample_results, severity_filter="high")
    output = capsys.readouterr().out
    lines = output.strip().splitlines()
    assert len(lines) == 2
    assert "::notice" not in output
    assert "::warning" not in output


def test_empty_results(capsys):
    _emit_github_annotations({})
    output = capsys.readouterr().out
    assert output.strip() == ""


def test_annotation_format(sample_results, capsys):
    _emit_github_annotations(sample_results)
    output = capsys.readouterr().out
    assert "::error file=app.py,line=10,title=Skylos SKY-D201::SQL injection" in output


def test_review_only_findings_share_a_notice_and_leave_error_slots_available(capsys):
    review = {
        "rule_id": "SKY-D324",
        "file": "helpers.py",
        "line": 8,
        "severity": "HIGH",
        "message": "Possible symlink-following write",
        "review_item": {"kind": "unproven_source", "blocking": False},
        "metadata": {"path_provenance": {"status": "incomplete"}},
    }
    traced = {
        **review,
        "file": "uploads.py",
        "metadata": {"path_provenance": {"status": "untrusted", "untrusted": True}},
    }
    result = {"danger": [review, {**review, "line": 18}, traced]}
    _emit_github_annotations(result)
    error, notice = capsys.readouterr().out.splitlines()
    assert error.startswith("::error file=uploads.py,line=8,title=Skylos SKY-D324::")
    assert notice.startswith(
        "::notice file=helpers.py,line=8,title=Skylos SKY-D324 (review only)::2 locations"
    )

    _emit_github_annotations(result, max_annotations=1)
    assert capsys.readouterr().out.splitlines() == [error]
    _emit_github_annotations(result, severity_filter="high")
    assert capsys.readouterr().out.splitlines() == [error]
