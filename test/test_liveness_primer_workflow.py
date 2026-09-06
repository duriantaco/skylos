import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from skylos.rules.config.cicd.github_actions import scan_github_actions_file


WORKFLOW_PATH = Path(".github/workflows/liveness-primer.yml")


def _workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _comparison_step(workflow):
    return next(
        step
        for step in workflow["jobs"]["blast-radius"]["steps"]
        if step.get("name") == "Compare base with the pull request merge result"
    )


def test_liveness_primer_workflow_covers_all_prs_read_only_and_advisory():
    workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))

    assert set(triggers) == {"pull_request"}
    pull_request = triggers["pull_request"]
    assert pull_request["types"] == [
        "opened",
        "synchronize",
        "reopened",
        "ready_for_review",
    ]
    # Docs-only, packaging, tests, and fork PRs all need the same check.
    assert set(pull_request) == {"types"}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "liveness-primer-${{ github.event.pull_request.number }}",
        "cancel-in-progress": True,
    }

    job = workflow["jobs"]["blast-radius"]
    assert "if" not in job  # Draft PRs get evidence too.
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 45

    comparison = _comparison_step(workflow)
    assert "--all" in comparison["run"]
    assert "--fail-on" not in comparison["run"]
    assert "continue-on-error" not in comparison
    assert "continue-on-error" not in job


def test_liveness_primer_workflow_pins_actions_and_toolchain():
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]
    action_steps = [step for step in steps if "uses" in step]

    assert {step["uses"] for step in action_steps} == {
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        "astral-sh/setup-uv@e4db8464a088ece1b920f60402e813ea4de65b8f",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    }
    for step in action_steps:
        action_ref = step["uses"].split("@", 1)[1]
        assert len(action_ref) == 40
        assert all(character in "0123456789abcdef" for character in action_ref)

    checkout = next(
        step for step in steps if step.get("name") == "Check out pinned liveness_primer"
    )
    assert checkout["with"] == {
        "repository": "mcdigman/liveness_primer",
        "ref": "d6f3118a2cfc465426500eab449005fe56845c58",
        "path": "_liveness_primer",
        "persist-credentials": False,
    }

    setup_uv = next(step for step in steps if step.get("name") == "Install uv")
    assert setup_uv["with"] == {
        "version": "0.12.5",
        "python-version": "3.13",
        "enable-cache": False,
    }


def test_liveness_primer_workflow_uses_locked_comparison_contract():
    workflow = _workflow()
    comparison = _comparison_step(workflow)
    assert comparison["env"] == {
        "SKYLOS_REPOSITORY": "https://github.com/duriantaco/skylos",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "MERGE_SHA": "${{ github.sha }}",
        "REPORT_JSON": "liveness-primer-report.json",
        "REPORT_MARKDOWN": "liveness-primer-report.md",
    }
    script = comparison["run"]
    assert "${{" not in script
    assert '[[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]' in script
    assert "uv run --project _liveness_primer --locked liveness-primer run" in script
    assert "--tool skylos" in script
    assert '--repo "$SKYLOS_REPOSITORY"' in script
    assert '--old "$BASE_SHA"' in script
    assert '--new "$MERGE_SHA"' in script
    assert "--output github" in script
    assert '--json-out "$REPORT_JSON"' in script
    assert "--jobs 2" in script
    assert "--timeout 300" in script
    assert "set -euo pipefail" in script
    assert '| tee "$REPORT_MARKDOWN" >> "$GITHUB_STEP_SUMMARY"' in script
    assert 'test -s "$REPORT_JSON"' in script


def test_liveness_primer_workflow_preserves_evidence_without_write_access():
    workflow_source = WORKFLOW_PATH.read_text(encoding="utf-8")
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]

    artifact = next(
        step for step in steps if step.get("name") == "Upload blast-radius evidence"
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["name"] == "liveness-primer-report"
    assert artifact["with"]["if-no-files-found"] == "error"
    assert artifact["with"]["retention-days"] == 14
    assert set(artifact["with"]["path"].splitlines()) == {
        "liveness-primer-report.md",
        "liveness-primer-report.json",
    }

    assert "pull_request_target" not in workflow_source
    assert "secrets." not in workflow_source
    assert "pull-requests: write" not in workflow_source
    assert "gh pr comment" not in workflow_source
    assert scan_github_actions_file(WORKFLOW_PATH, root=".") == []


def _run_comparison(
    tmp_path,
    *,
    exit_code=0,
    report_state="present",
    base_sha="a" * 40,
    merge_sha="b" * 40,
):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow shell checks require bash")

    # A shell function intercepts uv in the real workflow command. No primer,
    # detector revisions, network requests, or corpus code are executed, and
    # no executable fixture needs to be created on disk.
    stub = """uv() {
  "$PRIMER_STUB_PYTHON" - "$@" <<'PY'
import json, os, sys
with open('invocation.json', 'x', encoding='utf-8') as out:
    json.dump(sys.argv[1:], out)
if os.environ['PRIMER_STUB_REPORT'] != 'missing':
    with open(os.environ['REPORT_JSON'], 'x', encoding='utf-8') as out:
        if os.environ['PRIMER_STUB_REPORT'] == 'present':
            json.dump({'fixture': 'offline workflow test'}, out)
print('# Offline primer report')
sys.exit(int(os.environ['PRIMER_STUB_EXIT']))
PY
}
"""
    env = {
        "PATH": os.defpath,
        "SKYLOS_REPOSITORY": "https://github.com/duriantaco/skylos",
        "BASE_SHA": base_sha,
        "MERGE_SHA": merge_sha,
        # Spaces exercise quoting of the report destinations.
        "REPORT_JSON": str(tmp_path / "report data.json"),
        "REPORT_MARKDOWN": str(tmp_path / "report summary.md"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "step summary.md"),
        "PRIMER_STUB_EXIT": str(exit_code),
        "PRIMER_STUB_REPORT": report_state,
        "PRIMER_STUB_PYTHON": sys.executable,
    }
    return subprocess.run(
        [bash, "-c", stub + _comparison_step(_workflow())["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_comparison_shell_passes_exact_revisions_and_keeps_both_reports(tmp_path):
    result = _run_comparison(tmp_path)

    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / "invocation.json").read_text()) == [
        "run",
        "--project",
        "_liveness_primer",
        "--locked",
        "liveness-primer",
        "run",
        "--tool",
        "skylos",
        "--repo",
        "https://github.com/duriantaco/skylos",
        "--old",
        "a" * 40,
        "--new",
        "b" * 40,
        "--all",
        "--output",
        "github",
        "--json-out",
        str(tmp_path / "report data.json"),
        "--jobs",
        "2",
        "--timeout",
        "300",
    ]
    assert json.loads((tmp_path / "report data.json").read_text()) == {
        "fixture": "offline workflow test"
    }
    assert (tmp_path / "report summary.md").read_text() == "# Offline primer report\n"
    assert (tmp_path / "step summary.md").read_text() == "# Offline primer report\n"


@pytest.mark.parametrize("exit_code", [1, 2, 3])
def test_comparison_shell_does_not_hide_primer_failure_behind_tee(tmp_path, exit_code):
    result = _run_comparison(tmp_path, exit_code=exit_code)

    assert result.returncode == exit_code
    assert (tmp_path / "report data.json").is_file()
    assert (tmp_path / "report summary.md").read_text() == "# Offline primer report\n"


@pytest.mark.parametrize("report_state", ["missing", "empty"])
def test_comparison_shell_rejects_success_without_report_data(tmp_path, report_state):
    result = _run_comparison(tmp_path, report_state=report_state)

    assert result.returncode != 0
    assert (tmp_path / "invocation.json").is_file()


@pytest.mark.parametrize("revision", ["base_sha", "merge_sha"])
def test_comparison_shell_rejects_non_commit_refs_before_running(tmp_path, revision):
    result = _run_comparison(tmp_path, **{revision: "main"})

    assert result.returncode != 0
    assert "Invalid comparison revision" in result.stderr
    assert not (tmp_path / "invocation.json").exists()
