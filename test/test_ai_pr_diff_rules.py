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
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
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
    rule_ids = {
        finding.get("rule_id")
        for finding in result.get("ai_defects", [])
    }

    assert "SKY-A103" in rule_ids
    assert "SKY-A104" in rule_ids
