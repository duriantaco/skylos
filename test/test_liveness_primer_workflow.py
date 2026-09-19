import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

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
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
    }
    for step in action_steps:
        action_ref = step["uses"].split("@", 1)[1]
        assert len(action_ref) == 40
        assert all(character in "0123456789abcdef" for character in action_ref)

    assert workflow["env"] == {
        "LIVENESS_PRIMER_REF": "1438a928dd00cbb3b1098a9edc82480f43daabdb"
    }

    trusted_checkout = next(
        step for step in steps if step.get("name") == "Check out trusted Skylos base"
    )
    assert trusted_checkout["with"] == {
        "ref": "${{ github.event.pull_request.base.sha }}",
        "path": "_trusted_skylos",
        "persist-credentials": False,
    }

    primer_checkout = next(
        step for step in steps if step.get("name") == "Check out pinned liveness_primer"
    )
    assert primer_checkout["with"] == {
        "repository": "mcdigman/liveness_primer",
        "ref": "${{ env.LIVENESS_PRIMER_REF }}",
        "path": "_liveness_primer",
        "persist-credentials": False,
    }

    setup_go = next(step for step in steps if step.get("name") == "Install Go")
    assert setup_go["with"] == {"go-version": "1.22", "cache": False}

    setup_uv = next(step for step in steps if step.get("name") == "Install uv")
    assert setup_uv["with"] == {
        "version": "0.12.5",
        "python-version": "3.13",
        "enable-cache": False,
    }


def test_liveness_primer_workflow_builds_trusted_base_go_engine():
    workflow = _workflow()
    steps = workflow["jobs"]["blast-radius"]["steps"]
    build = next(
        step for step in steps if step.get("name") == "Build trusted base Go engine"
    )

    assert build["env"] == {
        "TRUSTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}"
    }
    assert build["shell"] == "bash"
    script = build["run"]
    assert '[[ ! "$TRUSTED_BASE_SHA" =~ ^[0-9a-f]{40}$ ]]' in script
    assert "git -C _trusted_skylos rev-parse HEAD" in script
    assert '[[ "$trusted_checkout_sha" != "$TRUSTED_BASE_SHA" ]]' in script
    assert "cd _trusted_skylos/skylos/engines/go" in script
    assert 'go build -trimpath -o "$engine_dir/skylos-go" ./cmd/skylos-go' in script
    assert 'engine_dir="$RUNNER_TEMP/skylos-go-engine"' in script
    assert '"$engine_dir/skylos-go" --version' in script
    # The comparison step must hand skylos the engine this step built.
    comparison = _comparison_step(workflow)
    assert comparison["env"]["SKYLOS_GO_BIN"] == (
        "${{ format('{0}/skylos-go-engine/skylos-go', runner.temp) }}"
    )


def test_liveness_primer_workflow_uses_locked_comparison_contract():
    workflow = _workflow()
    comparison = _comparison_step(workflow)
    assert comparison["env"] == {
        "SKYLOS_REPOSITORY": "${{ github.server_url }}/${{ github.repository }}",
        "SKYLOS_GO_BIN": (
            "${{ format('{0}/skylos-go-engine/skylos-go', runner.temp) }}"
        ),
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
    assert "--container" in script
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
        "--container",
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


_WORKFLOW_STUBS = r"""
record() {
  "$WORKFLOW_TEST_PYTHON" -c '
import json, os, sys
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
' "$@"
}
git() {
  record git "$@"
  printf '%s\n' "$CHECKOUT_SHA"
  return "$GIT_EXIT"
}
go() {
  record go "$@"
  if [[ "$GO_EXIT" != 0 ]]; then return "$GO_EXIT"; fi
  "$WORKFLOW_TEST_PYTHON" - "$RUNNER_TEMP/skylos-go-engine/skylos-go" <<'STUB'
import os, pathlib, sys
engine = pathlib.Path(sys.argv[1])
engine.write_text("#!/bin/sh\nprintf '%s\\n' 'engine-version-probed' > \"$VERSION_PROBE\"\nexit \"$ENGINE_EXIT\"\n")
engine.chmod(0o700)
STUB
}
"""


def _run_workflow_step(
    tmp_path: Path, name: str, overrides: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("workflow shell checks require bash")
    step = next(
        step
        for step in _workflow()["jobs"]["blast-radius"]["steps"]
        if step.get("name") == name
    )
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "WORKFLOW_TEST_PYTHON": sys.executable,
        "CALL_LOG": str(tmp_path / "calls.jsonl"),
        "RUNNER_TEMP": str(tmp_path / "runner temp"),
        "VERSION_PROBE": str(tmp_path / "version probe"),
        "TRUSTED_BASE_SHA": "a" * 40,
        "CHECKOUT_SHA": "a" * 40,
        "GIT_EXIT": "0",
        "GO_EXIT": "0",
        "ENGINE_EXIT": "0",
        **(overrides or {}),
    }
    (tmp_path / "_trusted_skylos/skylos/engines/go").mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [bash, "-c", _WORKFLOW_STUBS + step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _workflow_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_trusted_go_build_executes_and_probes_engine(tmp_path: Path) -> None:
    result = _run_workflow_step(tmp_path, "Build trusted base Go engine")
    assert result.returncode == 0, result.stderr
    assert _workflow_calls(tmp_path) == [
        ["git", "-C", "_trusted_skylos", "rev-parse", "HEAD"],
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            str(tmp_path / "runner temp/skylos-go-engine/skylos-go"),
            "./cmd/skylos-go",
        ],
    ]
    assert (tmp_path / "version probe").read_text() == "engine-version-probed\n"


@pytest.mark.parametrize(
    "overrides,expected_exit,expected_commands",
    [
        ({"TRUSTED_BASE_SHA": "main"}, 1, []),
        ({"CHECKOUT_SHA": "c" * 40}, 1, ["git"]),
        ({"GIT_EXIT": "7"}, 7, ["git"]),
        ({"GO_EXIT": "8"}, 8, ["git", "go"]),
        ({"ENGINE_EXIT": "9"}, 9, ["git", "go"]),
    ],
)
def test_trusted_go_build_stops_on_failure(
    tmp_path: Path,
    overrides: dict[str, str],
    expected_exit: int,
    expected_commands: list[str],
) -> None:
    result = _run_workflow_step(tmp_path, "Build trusted base Go engine", overrides)
    assert result.returncode == expected_exit, result.stderr
    assert [call[0] for call in _workflow_calls(tmp_path)] == expected_commands
    assert (tmp_path / "version probe").exists() == ("ENGINE_EXIT" in overrides)
