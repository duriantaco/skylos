"""The action's optional SARIF upload to GitHub code scanning."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest
import yaml


ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"


@pytest.fixture
def action():
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


def _step(action, name):
    return next(step for step in action["runs"]["steps"] if step["name"] == name)


def _run_scan_step(action, tmp_path, upload_sarif):
    step = _step(action, "Run Skylos Scan")
    calls = tmp_path / "cli-calls.jsonl"
    stub = tmp_path / "stub_python.py"
    stub.write_text(  # skylos: ignore[SKY-D324] fixed filename under pytest tmp_path
        textwrap.dedent(
            """\
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            if args[:2] == ["-m", "skylos.cli"]:
                with Path(os.environ["SKYLOS_TEST_CALLS"]).open("a") as stream:
                    stream.write(json.dumps(args) + "\\n")
                print("{}")
            elif args[:1] == ["-c"]:
                print(0)
            else:
                raise SystemExit("Unexpected Python invocation: " + repr(args))
            """
        ),
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "SKYLOS_PATH": ".",
        "SKYLOS_ANALYSIS": "security",
        "SKYLOS_CONFIDENCE": "60",
        "SKYLOS_TOKEN": "",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "SKYLOS_TEST_PYTHON": sys.executable,
        "SKYLOS_TEST_STUB": str(stub),
        "SKYLOS_TEST_CALLS": str(calls),
    }
    if upload_sarif is not None:
        env["SKYLOS_UPLOAD_SARIF"] = upload_sarif
    script = (
        'python() { command "$SKYLOS_TEST_PYTHON" "$SKYLOS_TEST_STUB" "$@"; }\n'
        + step["run"]
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    invocations = [json.loads(line) for line in calls.read_text().splitlines()]
    outputs = (tmp_path / "outputs").read_text()
    return invocations[0], outputs


def test_upload_sarif_defaults_off(action):
    assert action["inputs"]["upload-sarif"]["default"] == "false"
    assert action["inputs"]["sarif-category"]["default"] == "skylos"


@pytest.mark.parametrize("value", [None, "false", "", "yes"])
def test_scan_step_does_not_write_sarif_unless_enabled(action, tmp_path, value):
    invocation, outputs = _run_scan_step(action, tmp_path, value)
    assert "--sarif" not in invocation
    assert invocation[-1] == "--json"
    assert "sarif=" not in outputs


def test_scan_step_writes_sarif_when_enabled(action, tmp_path):
    invocation, outputs = _run_scan_step(action, tmp_path, "true")
    idx = invocation.index("--sarif")
    assert invocation[idx + 1] == "skylos.sarif"
    assert invocation[-1] == "--json"
    assert "sarif=skylos.sarif" in outputs


def test_upload_step_is_gated_and_pinned(action):
    scan = _step(action, "Run Skylos Scan")
    assert scan["env"]["SKYLOS_UPLOAD_SARIF"] == "${{ inputs.upload-sarif }}"

    upload = _step(action, "Upload SARIF to GitHub Code Scanning")
    assert re.fullmatch(
        r"github/codeql-action/upload-sarif@[0-9a-f]{40}", upload["uses"]
    )
    condition = upload["if"]
    assert "inputs.upload-sarif == 'true'" in condition
    assert "inputs.image == ''" in condition
    assert "!cancelled()" in condition
    assert upload["with"]["sarif_file"] == "skylos.sarif"
    assert upload["with"]["category"] == "${{ inputs.sarif-category }}"

    names = [step["name"] for step in action["runs"]["steps"]]
    assert names.index("Upload SARIF to GitHub Code Scanning") < names.index(
        "Quality Gate"
    )
