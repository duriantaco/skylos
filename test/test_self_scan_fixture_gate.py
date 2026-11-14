import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def _gate(tmp_path, category, path):
    workflow = yaml.safe_load(Path(".github/workflows/skylos.yaml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["scan"]["steps"]
        if item.get("name") == "Block high-risk security findings"
    )
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                category: [
                    {
                        "rule_id": "SKY-D291",
                        "severity": "HIGH",
                        "file": path,
                        "line": 1,
                        "message": "test finding",
                    }
                ]
            }
        )
    )
    env = dict(os.environ)
    env.pop("GITHUB_STEP_SUMMARY", None)
    return subprocess.run(
        [sys.executable, "-", str(report)],
        input=script,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )


@pytest.mark.parametrize("absolute", [False, True])
def test_vulnerable_benchmark_fixture_dangers_are_outside_self_scan_gate(
    tmp_path, absolute
):
    path = "benchmarks/security/fixtures/demo/.github/workflows/release.yml"
    if absolute:
        path = str(tmp_path / path)
    result = _gate(tmp_path, "danger", path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fixture" in result.stdout


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/release.yml",
        ".vscode/tasks.json",
        "benchmarks/security/run.py",
        "benchmarks/security/fixtures-other/workflow.yml",
        "benchmarks/security/fixtures/../../../app.py",
        "../outside/benchmarks/security/fixtures/release.yml",
    ],
)
def test_production_and_lookalike_paths_still_block(tmp_path, path):
    assert _gate(tmp_path, "danger", path).returncode == 1


def test_real_secrets_still_block_inside_fixtures(tmp_path):
    assert (
        _gate(
            tmp_path, "secrets", "benchmarks/security/fixtures/demo/key.txt"
        ).returncode
        == 1
    )
