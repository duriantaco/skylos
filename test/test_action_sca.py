"""Execute the action's shell flag mapping with an entirely local CLI stub."""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest
import yaml


ACTION_PATH = Path(__file__).resolve().parents[1] / "action.yml"


@pytest.fixture
def action():
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


def _run_step(action, step_name, analysis, tmp_path):
    step = next(step for step in action["runs"]["steps"] if step["name"] == step_name)
    calls = tmp_path / "cli-calls.jsonl"
    stub = tmp_path / "stub_python.py"
    stub.write_text(
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
                # The fixture report has no findings.
                print(0)
            else:
                raise SystemExit("Unexpected Python invocation: " + repr(args))
            """
        ),
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "SKYLOS_PATH": "project with spaces",
        "SKYLOS_ANALYSIS": analysis,
        "SKYLOS_CONFIDENCE": "73",
        "SKYLOS_TOKEN": "",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "SKYLOS_TEST_PYTHON": sys.executable,
        "SKYLOS_TEST_STUB": str(stub),
        "SKYLOS_TEST_CALLS": str(calls),
    }
    # Intercept every Python invocation: neither a scan nor an upload runs.
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
    assert len(invocations) == 1
    return invocations[0]


@pytest.mark.parametrize("step_name", ["Run Skylos Scan", "Upload to Skylos Dashboard"])
@pytest.mark.parametrize(
    ("analysis", "flags"),
    [
        ("sca", ["--sca"]),
        ("dependency", ["--sca"]),
        ("dependencies", ["--sca"]),
        ("sca dependency dependencies", ["--sca"]),
        ("  dead-code\tsecurity\nsca  ", ["--danger", "--sca"]),
        (
            "dead-code security quality ai-defects secrets dependencies",
            ["--danger", "--quality", "--ai-defects", "--secrets", "--sca"],
        ),
        ("", []),
        ("dead-code security", ["--danger"]),
        ("scala rescan dependencies-extra dependency-check", []),
    ],
)
def test_action_sca_flags(action, step_name, analysis, flags, tmp_path):
    invocation = _run_step(action, step_name, analysis, tmp_path)
    output_flag = "--json" if step_name == "Run Skylos Scan" else "--upload"
    assert invocation == [
        "-m",
        "skylos.cli",
        "project with spaces",
        "--confidence",
        "73",
        *flags,
        output_flag,
    ]


@pytest.mark.parametrize("step_name", ["Run Skylos Scan", "Upload to Skylos Dashboard"])
def test_action_default_does_not_enable_sca(action, step_name, tmp_path):
    analysis = action["inputs"]["analysis"]["default"]
    assert analysis == "dead-code security"
    invocation = _run_step(action, step_name, analysis, tmp_path)
    assert "--danger" in invocation
    assert "--sca" not in invocation
