import os
import pytest

from skylos.sarif_exporter import (
    SarifExporter,
    severity_to_sarif_level,
    normalize_file_path_for_sarif,
)


@pytest.mark.parametrize(
    "inp, expected",
    [
        ("CRITICAL", "error"),
        ("critical", "error"),
        ("HIGH", "error"),
        ("high", "error"),
        ("MEDIUM", "warning"),
        ("medium", "warning"),
        ("LOW", "note"),
        ("low", "note"),
        (None, "note"),
        ("", "note"),
        ("weird", "note"),
    ],
)
def test_severity_to_sarif_level(inp, expected):
    assert severity_to_sarif_level(inp) == expected


def test_normalize_file_path_removes_backslashes(monkeypatch):
    assert normalize_file_path_for_sarif(r"a\b\c.py") == "a/b/c.py"


def test_normalize_file_path_strips_file_scheme(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("file:///repo/app.py") == "app.py"


def test_normalize_file_path_makes_relative_to_repo_root(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("/repo/src/app.py") == "src/app.py"


def test_normalize_file_path_strips_leading_slashes(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("/var/tmp/x.py") == "var/tmp/x.py"


def test_normalize_file_path_unknown_when_empty(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")
    assert normalize_file_path_for_sarif("") == "unknown"
    assert normalize_file_path_for_sarif(None) == "unknown"


def test_generate_has_valid_top_level_structure():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": "Possible command injection",
            "file_path": "app.py",
            "line_number": 10,
            "col_number": 2,
            "category": "SECURITY",
        }
    ]
    s = SarifExporter(findings, tool_name="Skylos", version="9.9.9").generate()

    assert s["version"] == "2.1.0"
    assert "$schema" in s
    assert "runs" in s and isinstance(s["runs"], list) and len(s["runs"]) == 1

    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Skylos"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert isinstance(run["tool"]["driver"]["rules"], list)
    assert isinstance(run["results"], list)


def test_unique_rules_dedup_by_rule_id_and_sets_default_level_and_helpuri():
    findings = [
        {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": "msg A",
            "file_path": "a.py",
            "line_number": 1,
            "category": "SECURITY",
        },
        {
            "rule_id": "SKY-D212",
            "severity": "HIGH",
            "message": "msg B",
            "file_path": "b.py",
            "line_number": 2,
            "category": "SECURITY",
        },
    ]
    s = SarifExporter(findings).generate()
    rules = s["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    rule = rules[0]
    assert rule["id"] == "SKY-D212"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"].endswith("/SKY-D212")
    assert "properties" in rule and "tags" in rule["properties"]
    assert "security" in rule["properties"]["tags"]
    assert "security" in rule["properties"]["tags"]


def test_rule_title_truncates_to_120_chars():
    long_title = "A" * 200
    findings = [
        {
            "rule_id": "SKY-Q301",
            "severity": "MEDIUM",
            "title": long_title,
            "message": "whatever",
            "file_path": "x.py",
            "line_number": 1,
            "category": "QUALITY",
        }
    ]
    s = SarifExporter(findings).generate()
    rule = s["runs"][0]["tool"]["driver"]["rules"][0]
    title = rule["shortDescription"]["text"]
    assert len(title) <= 120
    assert title.endswith("...")


def test_results_include_location_region_and_snippet_when_present(monkeypatch):
    monkeypatch.setattr(os, "getcwd", lambda: "/repo")

    findings = [
        {
            "rule_id": "SKY-U002",
            "severity": "LOW",
            "message": "Unused import os",
            "file_path": "/repo/app.py",
            "line_number": 3,
            "col": 5,
            "snippet": "import os\n",
            "category": "DEAD_CODE",
        }
    ]
    s = SarifExporter(findings).generate()
    res = s["runs"][0]["results"][0]

    assert res["ruleId"] == "SKY-U002"
    assert res["level"] == "note"
    assert res["properties"]["category"] == "DEAD_CODE"

    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 3
    assert loc["region"]["startColumn"] == 5
    assert loc["region"]["snippet"]["text"] == "import os\n"
