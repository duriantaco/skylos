import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.config.deployment.spring import scan_spring_actuator

_RULE = "SKY-D432"
_YAML = """management:
  endpoints:
    web:
      exposure:
        include: "*"
"""


@pytest.mark.parametrize(
    ("filename", "text", "expected"),
    [
        ("application.yaml", _YAML, [5]),
        (
            "application-prod.yml",
            'management.endpoints.web.exposure.include: ["*"]\n',
            [1],
        ),
        (
            "application.properties",
            "management.endpoints.web.exposure.include=*\n",
            [1],
        ),
        ("application-prod.yaml", "server:\n  port: 8080\n---\n" + _YAML, [8]),
        ("application.yaml", _YAML.replace('"*"', "health,info"), []),
        ("application.yaml", _YAML + '        exclude: "*"\n', []),
        (
            "application.yaml",
            _YAML.replace("include:", "example:\n          include:"),
            [],
        ),
        (
            "application.yaml",
            _YAML.replace('"*"', '"' + chr(36) + '{ACTUATOR_EXPOSURE}"'),
            [],
        ),
        (
            "application.yaml",
            _YAML.replace('"*"', '"*" # skylos: ignore[SKY-D432]'),
            [],
        ),
        (
            "application.properties",
            "management.endpoints.web.exposure.include=*\nmanagement.endpoints.web.exposure.exclude=*\n",
            [],
        ),
        ("values.yaml", _YAML, []),
    ],
)
def test_spring_actuator_conventional_config(tmp_path, filename, text, expected):
    file = tmp_path / filename
    file.write_text(text)
    findings = scan_spring_actuator(tmp_path)
    assert [(row["rule_id"], row["file"], row["line"]) for row in findings] == [
        (_RULE, str(file), line) for line in expected
    ]


def test_spring_actuator_danger_entrypoint_and_change_scope(tmp_path):
    file = tmp_path / "application.yaml"
    file.write_text(_YAML)
    (tmp_path / "Example.java").write_text("final class Example {}\n")
    raw = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert [
        (row["file"], row["line"]) for row in raw["danger"] if row["rule_id"] == _RULE
    ] == [(str(file), 5)]
    assert not scan_spring_actuator(tmp_path, changed_files={"Example.java"})
    assert scan_spring_actuator(tmp_path, changed_files={"application.yaml"})
    assert not scan_spring_actuator(tmp_path, scan_paths=[tmp_path / "Example.java"])


def test_explicit_scope_uses_working_directory_paths_and_keeps_exclusions(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "apps"
    selected = root / "selected"
    excluded = selected / "fixture"
    other = root / "other"
    for folder in [selected, excluded, other]:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "application.yaml").write_text(_YAML)
    config = str(selected / "application.yaml")
    rows = scan_spring_actuator(root, scan_paths=["apps/selected/application.yaml"])
    assert [row["file"] for row in rows] == [config]
    rows = scan_spring_actuator(
        root, scan_paths=["apps/selected"], exclude_folders=["fixture"]
    )
    assert [row["file"] for row in rows] == [config]


def test_nonprintable_yaml_does_not_drop_other_spring_findings(tmp_path):
    invalid = tmp_path / "application-broken.yaml"
    invalid.write_text("message: " + chr(0))
    valid = tmp_path / "application-prod.yaml"
    valid.write_text(_YAML)
    rows = scan_spring_actuator(tmp_path)
    assert [(row["rule_id"], row["file"]) for row in rows] == [(_RULE, str(valid))]
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not any(
        issue.get("kind") == "config_scan_error"
        for issue in result.get("analysis_errors", [])
    )
    assert [row["file"] for row in result["danger"] if row["rule_id"] == _RULE] == [
        str(valid)
    ]
