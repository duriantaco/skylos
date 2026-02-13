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
    # CRITICAL should come first
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
    # Should only have CRITICAL and HIGH (2 findings)
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
