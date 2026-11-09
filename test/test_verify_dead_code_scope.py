"""Verification retains detector results while omitting unused-code conclusions."""

import json

import pytest

import skylos.analyzer as analyzer_module
from skylos.analyzer import analyze
from skylos.core.verify_change_schema import build_verify_change_response
from skylos.verify_change import verify_change_path


def _analyze(target, **options):
    return json.loads(
        analyze(
            str(target),
            enable_secrets=True,
            enable_danger=True,
            enable_quality=True,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            changed_files=[str(target)],
            grep_verify=False,
            trace_file=False,
            **options,
        )
    )


def _project(tmp_path, source, *, suffix="py", config=""):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "verify-scope"\nversion = "0.1"\n' + config
    )
    target = tmp_path / f"app.{suffix}"
    target.write_text(source)
    helper = (
        "export function present() { return 1; }\n"
        if suffix == "ts"
        else "def present():\n    return 1\n"
    )
    (tmp_path / f"helper.{suffix}").write_text(helper)
    return target


def test_analysis_keeps_dead_code_enabled_by_default(tmp_path):
    target = _project(tmp_path, "def unused():\n    return 1\n")

    ordinary = _analyze(target)
    explicit = _analyze(target, enable_dead_code=True)

    assert ordinary == explicit
    assert any(f["name"].endswith("unused") for f in ordinary["unused_functions"])
    assert "dead_code" in ordinary["analysis_summary"]["grade_categories"]


def test_analysis_keeps_repo_policy_enabled_by_default(tmp_path):
    _project(tmp_path, "answer = 42\n")
    ordinary = json.loads(
        analyze(str(tmp_path), enable_quality=True, grep_verify=False)
    )
    explicit = json.loads(
        analyze(
            str(tmp_path),
            enable_quality=True,
            grep_verify=False,
            enable_repo_policy=True,
        )
    )

    assert ordinary == explicit
    assert {"SKY-R101", "SKY-R102", "SKY-R103", "SKY-R104"} <= {
        finding["rule_id"] for finding in ordinary["quality"]
    }


def test_owned_verify_runs_repo_policy_only_when_requested(tmp_path, monkeypatch):
    _project(tmp_path, "answer = 42\n")
    actual_scan = analyzer_module.analyze_repo_policy
    calls = []

    def observed(*args, **kwargs):
        calls.append((args, kwargs))
        return actual_scan(*args, **kwargs)

    monkeypatch.setattr(analyzer_module, "analyze_repo_policy", observed)
    default = verify_change_path(
        tmp_path,
        behavior_comparison=False,
        include_dependency_hallucinations=False,
        contract_enabled=False,
    )

    assert calls == []
    assert not any(f["rule_id"].startswith("SKY-R") for f in default["findings"])
    selected = verify_change_path(
        tmp_path,
        behavior_comparison=False,
        include_dependency_hallucinations=False,
        include_quality_rule_ids=frozenset({"SKY-R101"}),
        contract_enabled=False,
    )

    assert len(calls) == 1
    assert any(f["rule_id"] == "SKY-R101" for f in selected["findings"])


@pytest.mark.parametrize(
    "suffix,source,config,expected_rules,expected_status",
    [
        (
            "py",
            (
                "import os\nimport helper\n"
                'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7ABCDEFG"\n'
                "def unused():\n    os.system(input())\n    helper.absent()\n"
            ),
            "",
            {"SKY-D203", "SKY-L012", "SKY-S101"},
            "fail",
        ),
        ("py", "import helper\nhelper.present()\n", "", set(), "pass"),
        ("py", "def broken(\n", "", set(), "incomplete"),
        (
            "py",
            "import helper\nhelper.absent()\n",
            '\n[tool.skylos]\nignore = ["SKY-L012", "SKY-L023"]\n',
            set(),
            "incomplete",
        ),
        (
            "ts",
            '// @ts-nocheck\nimport { missing } from "./helper";\nmissing();\n',
            "",
            {"SKY-L012", "SKY-T104"},
            "fail",
        ),
    ],
    ids=["security-ai-secret", "safe", "parse-error", "ignored-ai", "typescript"],
)
def test_verification_without_dead_code_preserves_findings_and_coverage(
    tmp_path, suffix, source, config, expected_rules, expected_status
):
    target = _project(tmp_path, source, suffix=suffix, config=config)
    complete = _analyze(target)
    focused = _analyze(target, enable_dead_code=False)

    for section in (
        "danger",
        "reliability",
        "quality",
        "ai_defects",
        "secrets",
        "custom_rules",
        "analysis_errors",
    ):
        assert focused.get(section, []) == complete.get(section, [])
    assert (
        focused["analysis_summary"]["ai_verification"]
        == complete["analysis_summary"]["ai_verification"]
    )
    for section in (
        "unused_functions",
        "unused_imports",
        "unused_classes",
        "unused_variables",
        "unused_parameters",
        "unused_files",
        "unused_exports",
    ):
        assert focused.get(section, []) == []
    assert focused["analysis_summary"]["dead_code"] == {
        "enabled": False,
        "status": "not_enabled",
    }
    assert "dead_code" not in focused["analysis_summary"]["grade_categories"]
    selected_quality = frozenset({"SKY-T104"})
    expected = build_verify_change_response(
        complete,
        project_root=tmp_path,
        scan_target=target,
        include_security_findings=True,
        include_quality_rule_ids=selected_quality,
        analyzer_owned=True,
    )
    actual = verify_change_path(
        target,
        behavior_comparison=False,
        include_dependency_hallucinations=False,
        include_quality_rule_ids=selected_quality,
        contract_enabled=False,
    )

    assert actual == expected
    assert actual["status"] == expected_status
    assert {f["rule_id"] for f in actual["findings"]} >= expected_rules
