import json
import shutil
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.rules.ai_defect.api_surface_drift import detect_cli_surface_drift
from skylos.rules.ai_defect.ci_permission_expansion import (
    detect_ci_permission_expansion,
)


def _make_diff(removed_lines: list[str], added_lines: list[str]) -> str:
    parts = ["--- a/file", "+++ b/file", "@@ -1,8 +1,8 @@"]
    for line in removed_lines:
        parts.append(f"-{line}")
    for line in added_lines:
        parts.append(f"+{line}")
    return "\n".join(parts)


def test_detects_github_actions_write_all_added():
    diff = _make_diff([], ["permissions: write-all"])

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A103"
    assert findings[0]["metadata"]["expansion_type"] == "write_all_permissions"
    assert findings[0]["metadata"]["blocking_recommended"] is True


def test_detects_github_actions_privileged_trigger_added():
    diff = _make_diff([], ["on: pull_request_target"])

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert len(findings) == 1
    assert findings[0]["metadata"]["added_value"] == "pull_request_target"


def test_detects_all_privileged_triggers_on_same_line():
    # #774: both triggers on one line must BOTH be reported, deterministically.
    diff = _make_diff([], ["on: [pull_request_target, workflow_run]"])

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == [
        "pull_request_target",
        "workflow_run",
    ]


def test_reports_all_inline_write_permissions():
    diff = _make_diff([], ["permissions: {contents: write, issues: write}"])

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == [
        "contents: write",
        "issues: write",
    ]


def test_reports_only_new_privileged_trigger_on_changed_line():
    diff = _make_diff(
        ["on: [pull_request_target]"],
        ["on: [pull_request_target, workflow_run]"],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["workflow_run"]


def test_reports_only_new_inline_write_permission_on_changed_line():
    diff = _make_diff(
        ["permissions: {contents: write}"],
        ["permissions: {contents: write, issues: write}"],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["issues: write"]


@pytest.mark.parametrize(
    ("removed", "added"),
    [
        (
            "on: [workflow_run, pull_request_target]",
            "on: [pull_request_target, workflow_run]",
        ),
        (
            "permissions: {issues: write, contents: write}",
            "permissions: {contents: write, issues: write}",
        ),
    ],
)
def test_ci_permission_expansion_ignores_reordering(removed, added):
    findings = detect_ci_permission_expansion(
        _make_diff([removed], [added]),
        ".github/workflows/ci.yml",
    )

    assert findings == []


def test_adjacent_root_replacements_report_only_new_signals():
    diff = _make_diff(
        [
            "on: [pull_request_target]",
            "permissions: {contents: write}",
        ],
        [
            "on: [pull_request_target, workflow_run]",
            "permissions: {contents: write, issues: write}",
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == [
        "workflow_run",
        "issues: write",
    ]


def test_moving_root_permission_does_not_repeat_finding():
    diff = "\n".join(
        [
            "--- a/file",
            "+++ b/file",
            "@@ -1,3 +1,3 @@",
            "-permissions: write-all",
            " name: CI",
            "+permissions: write-all",
            " on: push",
        ]
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert findings == []


@pytest.mark.parametrize(
    ("removed", "added", "expected"),
    [
        (
            "permissions: {contents: write, contents: read}",
            "permissions: {contents: write}",
            ["contents: write"],
        ),
        (
            "{on: workflow_run, on: push}",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "{on: workflow_run, true: push}",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "permissions: !unsupported write-all",
            "permissions: write-all",
            ["permissions: write-all"],
        ),
        (
            "on: !!bool workflow_run",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "!!bool on: workflow_run",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "permissions: {contents: !!bool write}",
            "permissions: {contents: write}",
            ["contents: write"],
        ),
        (
            "permissions: !!python/object:os.system write-all",
            "permissions: write-all",
            ["permissions: write-all"],
        ),
        (
            "on: !!null workflow_run",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "permissions: {contents: !!null write}",
            "permissions: {contents: write}",
            ["contents: write"],
        ),
        (
            "permissions: {!!binary contents: write}",
            "permissions: {contents: write}",
            ["contents: write"],
        ),
        (
            "on: !!set {workflow_run: null}",
            "on: workflow_run",
            ["workflow_run"],
        ),
        (
            "on: &recursive [workflow_run, *recursive]",
            "on: workflow_run",
            ["workflow_run"],
        ),
    ],
)
def test_ambiguous_removed_yaml_cannot_suppress_finding(removed, added, expected):
    findings = detect_ci_permission_expansion(
        _make_diff([removed], [added]),
        ".github/workflows/ci.yml",
    )

    assert [f["metadata"]["added_value"] for f in findings] == expected


@pytest.mark.parametrize(
    ("added", "expected"),
    [
        (
            "on: workflow_run # pull_request_target is disabled",
            ["workflow_run"],
        ),
        (
            "permissions: {issues: write} # contents: write is disabled",
            ["issues: write"],
        ),
    ],
)
def test_ci_permission_expansion_ignores_signals_in_comments(added, expected):
    findings = detect_ci_permission_expansion(
        _make_diff([], [added]),
        ".github/workflows/ci.yml",
    )

    assert [f["metadata"]["added_value"] for f in findings] == expected


def test_added_comment_does_not_break_replacement_matching():
    diff = _make_diff(
        ["on: [pull_request_target]"],
        [
            "on: [pull_request_target, workflow_run]",
            "# workflow_run requires review",
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["workflow_run"]


def test_comment_only_change_does_not_repeat_permission_finding():
    diff = _make_diff(
        ["  contents: write # old explanation"],
        ["  contents: write # clearer explanation"],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert findings == []


def test_unrelated_removed_text_does_not_cancel_real_trigger():
    diff = _make_diff(
        ["name: workflow_run migration"],
        ["on: workflow_run"],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["workflow_run"]


def test_permission_removed_from_one_job_does_not_cancel_addition_to_another():
    diff = "\n".join(
        [
            "--- a/file",
            "+++ b/file",
            "@@ -1,5 +1,5 @@",
            " jobs:",
            "   build:",
            "-    permissions: {contents: write}",
            "+    permissions: {contents: read}",
            "   release:",
            "-    permissions: {contents: read}",
            "+    permissions: {contents: write}",
        ]
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [(f["line"], f["metadata"]["added_value"]) for f in findings] == [
        (5, "contents: write")
    ]


def test_ci_permission_expansion_supports_quoted_flow_values():
    diff = _make_diff(
        [],
        [
            'on: ["workflow_run", "pull_request_target"]',
            'permissions: {"issues": "write", "contents": "write"}',
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == [
        "pull_request_target",
        "workflow_run",
        "contents: write",
        "issues: write",
    ]


def test_ci_permission_expansion_supports_multiline_flow_values():
    diff = _make_diff(
        [],
        [
            "on: [",
            "  pull_request_target,",
            "  workflow_run",
            "]",
            "permissions: {",
            "  contents: write,",
            "  issues: write",
            "}",
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [(f["line"], f["metadata"]["added_value"]) for f in findings] == [
        (2, "pull_request_target"),
        (3, "workflow_run"),
        (6, "contents: write"),
        (7, "issues: write"),
    ]


def test_ci_permission_expansion_handles_split_single_permission_flow_map():
    diff = _make_diff(
        [],
        [
            "permissions: {contents: write",
            "}",
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["contents: write"]


@pytest.mark.parametrize(
    "added",
    [
        "name: workflow_run migration",
        "run: echo pull_request_target",
        "true: workflow_run",
        "yes: pull_request_target",
        "1: workflow_run",
        "ON: pull_request_target",
    ],
)
def test_ci_permission_expansion_ignores_triggers_outside_on(added):
    findings = detect_ci_permission_expansion(
        _make_diff([], [added]),
        ".github/workflows/ci.yml",
    )

    assert findings == []


def test_line_number_shift_does_not_break_one_line_replacement_matching():
    diff = "\n".join(
        [
            "--- a/file",
            "+++ b/file",
            "@@ -1,2 +1,3 @@",
            "+name: CI",
            " jobs: {}",
            "-on: [pull_request_target]",
            "+on: [pull_request_target, workflow_run]",
        ]
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [f["metadata"]["added_value"] for f in findings] == ["workflow_run"]


def test_no_newline_marker_does_not_shift_finding_line():
    diff = "\n".join(
        [
            "--- a/file",
            "+++ b/file",
            "@@ -1 +1 @@",
            "-on: pull_request",
            "\\ No newline at end of file",
            "+on: [pull_request, workflow_run]",
            "\\ No newline at end of file",
        ]
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [(f["line"], f["metadata"]["added_value"]) for f in findings] == [
        (1, "workflow_run")
    ]


def test_same_permission_added_to_two_jobs_reports_both_locations():
    diff = _make_diff(
        [],
        [
            "jobs:",
            "  build:",
            "    permissions:",
            "      contents: write",
            "  release:",
            "    permissions:",
            "      contents: write",
        ],
    )

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert [(f["line"], f["metadata"]["added_value"]) for f in findings] == [
        (4, "contents: write"),
        (7, "contents: write"),
    ]


def test_ci_permission_expansion_ignores_line_moves():
    diff = _make_diff(["permissions: write-all"], ["permissions: write-all"])

    findings = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")

    assert findings == []


def test_detects_removed_cli_flag():
    diff = _make_diff(
        ['parser.add_argument("--quality", action="store_true")'],
        [],
    )

    findings = detect_cli_surface_drift(diff, "src/app/cli.py")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-A104"
    assert findings[0]["metadata"]["removed_flag"] == "--quality"
    assert findings[0]["metadata"]["blocking_recommended"] is False


def test_cli_surface_drift_ignores_flag_line_moves():
    diff = _make_diff(
        ['parser.add_argument("--quality", action="store_true")'],
        ['parser.add_argument("--quality", action="store_true")'],
    )

    findings = detect_cli_surface_drift(diff, "src/app/cli.py")

    assert findings == []


def test_cli_surface_drift_ignores_non_cli_file_without_option_hints():
    diff = _make_diff(['message = "--quality removed"'], [])

    findings = detect_cli_surface_drift(diff, "src/app/messages.py")

    assert findings == []


def test_analyzer_reports_diff_backed_ai_pr_rules(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is required for this test")

    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows" / "ci.yml"
    cli_file = repo / "src" / "app" / "cli.py"
    workflow.parent.mkdir(parents=True)
    cli_file.parent.mkdir(parents=True)
    workflow.write_text(
        "\n".join(
            [
                "name: CI",
                "on: [pull_request]",
                "permissions:",
                "  contents: read",
                "",
            ]
        ),
        encoding="utf-8",
    )
    cli_file.write_text(
        "\n".join(
            [
                "import argparse",
                "parser = argparse.ArgumentParser()",
                'parser.add_argument("--quality", action="store_true")',
                "",
            ]
        ),
        encoding="utf-8",
    )

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)

    workflow.write_text(
        "\n".join(
            [
                "name: CI",
                "on: [pull_request_target]",
                "permissions: write-all",
                "",
            ]
        ),
        encoding="utf-8",
    )
    cli_file.write_text(
        "\n".join(
            [
                "import argparse",
                "parser = argparse.ArgumentParser()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(repo),
            conf=0,
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            changed_files={str(workflow), str(cli_file)},
        )
    )
    rule_ids = {finding.get("rule_id") for finding in result.get("ai_defects", [])}

    assert "SKY-A103" in rule_ids
    assert "SKY-A104" in rule_ids
