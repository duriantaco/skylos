"""Exercise the composite action's image path without running Trivy or Skylos."""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest
import yaml


ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"
TESTS_WORKFLOW_PATH = (
    Path(__file__).resolve().parents[1] / ".github/workflows/tests.yaml"
)
IMAGE = "ghcr.io/example/app@sha256:" + "a" * 64
PLATFORM = "linux/amd64"


@pytest.fixture
def action():
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


def _step(action, name):
    return next(step for step in action["runs"]["steps"] if step["name"] == name)


def _run_image_step(
    action,
    tmp_path,
    *,
    mode="gate",
    image=IMAGE,
    platform=PLATFORM,
    severity="high",
    scan_status=0,
    findings=(),
    write_report=True,
):
    step = _step(action, "Run Skylos Image Scan")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    calls = tmp_path / "cli-calls.jsonl"
    stub = tmp_path / "stub_python.py"
    stub.write_text(  # skylos: ignore[SKY-D324] fixed file in pytest tmp_path
        textwrap.dedent(
            """\
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with Path(os.environ["SKYLOS_TEST_CALLS"]).open("a") as stream:
                stream.write(json.dumps(args) + "\\n")
            if args[:5] != ["-I", "-m", "skylos.cli", "image", "scan"]:
                raise SystemExit("Unexpected Python invocation: " + repr(args))
            output_option = "--output" if "--output" in args else "-o"
            report = Path(args[args.index(output_option) + 1])
            if os.environ["SKYLOS_TEST_WRITE_REPORT"] == "true":
                report.write_text(os.environ["SKYLOS_TEST_REPORT"], encoding="utf-8")
            raise SystemExit(int(os.environ["SKYLOS_TEST_STATUS"]))
            """
        ),
        encoding="utf-8",
    )
    report_data = {
        "container_vulnerabilities": list(findings),
        "receipt": {
            "import_complete": scan_status != 2,
            "errors": [{"code": "example"}],
        },
        "image": {"repo_digests": [IMAGE]},
    }
    env = {
        **os.environ,
        "SKYLOS_IMAGE": image,
        "SKYLOS_IMAGE_PLATFORM": platform,
        "SKYLOS_IMAGE_FAIL_ON": severity,
        "SKYLOS_MODE": mode,
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "SKYLOS_TEST_PYTHON": sys.executable,
        "SKYLOS_TEST_STUB": str(stub),
        "SKYLOS_TEST_CALLS": str(calls),
        "SKYLOS_TEST_REPORT": json.dumps(report_data),
        "SKYLOS_TEST_STATUS": str(scan_status),
        "SKYLOS_TEST_WRITE_REPORT": "true" if write_report else "false",
    }
    script = """python() {
          if [ "${1:-}" = "-I" ] && [ "${2:-}" = "-m" ] && [ "${3:-}" = "skylos.cli" ]; then
            command "$SKYLOS_TEST_PYTHON" "$SKYLOS_TEST_STUB" "$@"
          else
            command "$SKYLOS_TEST_PYTHON" "$@"
          fi
        }
        """ + step["run"]
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=checkout,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    invocations = (
        [json.loads(line) for line in calls.read_text().splitlines()]
        if calls.exists()
        else []
    )
    outputs = {}
    output_path = tmp_path / "outputs"
    if output_path.exists():
        outputs = dict(
            line.split("=", 1) for line in output_path.read_text().splitlines()
        )
    return result, invocations, outputs, checkout, runner_temp


def test_image_inputs_are_opt_in_and_source_outputs_still_exist(action):
    assert action["inputs"]["image"]["default"] == ""
    assert action["inputs"]["image-platform"]["default"] == ""
    assert action["inputs"]["image-fail-on"]["default"] == "high"

    image_step = _step(action, "Run Skylos Image Scan")
    assert image_step["id"] == "image_scan"
    assert "inputs.image != ''" in image_step["if"]
    assert image_step["env"] == {
        "SKYLOS_IMAGE": "${{ inputs.image }}",
        "SKYLOS_IMAGE_PLATFORM": "${{ inputs.image-platform }}",
        "SKYLOS_IMAGE_FAIL_ON": "${{ inputs.image-fail-on }}",
        "SKYLOS_MODE": "${{ inputs.mode }}",
    }
    for output, source_step, image_output in (
        (
            "findings-count",
            "steps.scan.outputs.findings_count",
            "steps.image_scan.outputs.findings_count",
        ),
        ("gate-passed", "steps.gate.outputs.passed", "steps.image_scan.outputs.passed"),
        ("report-path", "steps.scan.outputs.report", "steps.image_scan.outputs.report"),
    ):
        value = action["outputs"][output]["value"]
        assert source_step in value
        assert image_output in value


def test_image_mode_does_not_enter_source_only_action_steps(action):
    for name in (
        "Detect Go sources",
        "Run Skylos Scan",
        "Upload to Skylos Dashboard",
        "Post GitHub Annotations",
        "Post PR Review Comments",
        "Quality Gate",
        "Upload Report Artifact",
    ):
        assert "inputs.image == ''" in _step(action, name)["if"]

    image_artifact = _step(action, "Upload Image Report Artifact")
    assert "always()" in image_artifact["if"]
    assert "inputs.image != ''" in image_artifact["if"]
    assert image_artifact["with"]["path"] == "${{ steps.image_scan.outputs.report }}"
    assert image_artifact["with"]["if-no-files-found"] == "error"


def test_image_step_quotes_inputs_and_does_not_install_or_upload(action):
    script = _step(action, "Run Skylos Image Scan")["run"]
    assert "${{" not in script
    assert 'ARGS=(image scan "$SKYLOS_IMAGE"' in script
    assert 'python -I -m skylos.cli "${ARGS[@]}"' in script
    assert '"$SKYLOS_IMAGE"' in script
    assert '"$SKYLOS_IMAGE_PLATFORM"' in script
    assert '"$SKYLOS_IMAGE_FAIL_ON"' in script
    assert "--upload" not in script
    assert "curl " not in script
    assert "wget " not in script


def test_gate_pass_reports_image_findings_only(action, tmp_path):
    findings = [{"id": "one"}, {"id": "two"}]
    result, calls, outputs, checkout, runner_temp = _run_image_step(
        action, tmp_path, findings=findings
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 1
    assert calls[0][:6] == ["-I", "-m", "skylos.cli", "image", "scan", IMAGE]
    assert calls[0][calls[0].index("--platform") + 1] == PLATFORM
    assert calls[0][calls[0].index("--fail-on") + 1] == "high"
    assert outputs["findings_count"] == "2"
    assert outputs["passed"] == "true"
    report = Path(outputs["report"])
    assert report.is_relative_to(runner_temp)
    assert not report.is_relative_to(checkout)
    assert json.loads(report.read_text())["container_vulnerabilities"] == findings


@pytest.mark.parametrize(
    ("scan_status", "expected_passed"),
    [(1, "false"), (2, "false")],
)
def test_gate_failure_and_incomplete_preserve_report_and_exit_code(
    action, tmp_path, scan_status, expected_passed
):
    finding = {"id": "partial"}
    result, calls, outputs, _, _ = _run_image_step(
        action, tmp_path, scan_status=scan_status, findings=[finding]
    )
    assert result.returncode == scan_status, result.stdout + result.stderr
    assert len(calls) == 1
    assert outputs["passed"] == expected_passed
    assert outputs["findings_count"] == "1"
    assert json.loads(Path(outputs["report"]).read_text())[
        "container_vulnerabilities"
    ] == [finding]


@pytest.mark.parametrize("scan_status", [0, 2])
def test_report_only_mode_never_sets_severity_gate(action, tmp_path, scan_status):
    result, calls, outputs, _, _ = _run_image_step(
        action, tmp_path, mode="scan", scan_status=scan_status
    )
    assert result.returncode == scan_status, result.stdout + result.stderr
    assert len(calls) == 1
    assert "--fail-on" not in calls[0]
    assert outputs["findings_count"] == "0"
    assert "passed" not in outputs


@pytest.mark.parametrize(
    ("mode", "platform"),
    [("review", PLATFORM), ("gate", "")],
)
def test_unsupported_review_and_missing_platform_fail_before_scan(
    action, tmp_path, mode, platform
):
    result, calls, _, _, _ = _run_image_step(
        action, tmp_path, mode=mode, platform=platform
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert calls == []


def test_invalid_gate_threshold_fails_before_scan(action, tmp_path):
    result, calls, outputs, _, _ = _run_image_step(
        action, tmp_path, severity="high; touch injected"
    )
    assert result.returncode == 2
    assert calls == []
    assert outputs["passed"] == "false"


def test_missing_report_fails_incomplete_not_as_severity_failure(action, tmp_path):
    result, calls, outputs, _, _ = _run_image_step(
        action, tmp_path, scan_status=1, write_report=False
    )
    assert result.returncode == 2
    assert len(calls) == 1
    assert outputs["passed"] == "false"
    assert "findings_count" not in outputs


def test_image_input_cannot_inject_shell_commands(action, tmp_path):
    marker = tmp_path / "injected"
    hostile_image = f'{IMAGE}"; touch {marker}; #'
    result, calls, _, _, _ = _run_image_step(action, tmp_path, image=hostile_image)
    assert result.returncode in {0, 2}, result.stdout + result.stderr
    assert not marker.exists()
    if calls:
        assert calls[0][5] == hostile_image


def test_manual_workflow_runs_pinned_image_scan_and_checks_receipt():
    workflow = yaml.safe_load(TESTS_WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["image_action_smoke"]
    assert job["if"] == "github.event_name == 'workflow_dispatch'"
    assert job["permissions"] == {"contents": "read"}
    install = next(
        step
        for step in job["steps"]
        if step.get("name") == "Install checksum-verified Trivy"
    )
    assert "v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz" in install["run"]
    assert (
        "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
        in install["run"]
    )
    assert "sha256sum --check" in install["run"]
    image_scan = next(step for step in job["steps"] if step.get("id") == "image_scan")
    assert image_scan["uses"] == "./"
    assert image_scan["with"] == {
        "image": "docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e",
        "image-platform": "linux/amd64",
        "mode": "scan",
    }
    receipt_check = job["steps"][-1]["run"]
    for assertion in (
        'receipt["execution"]["status"] == "completed"',
        'receipt["import_complete"] is True',
        'receipt["identity_verified"] is True',
        'receipt["platform_verified"] is True',
        'data["gate"]["scope"] == "direct_image_scan"',
    ):
        assert assertion in receipt_check
