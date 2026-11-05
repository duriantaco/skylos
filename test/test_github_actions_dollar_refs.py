"""Same-commit reusable workflows are pinned without weakening action checks."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.rules.config.cicd.github_actions import scan_github_actions


SOURCE_ROOT = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"
DOCKER_DIGEST = "a" * 64
CALLED = """name: Called
on: workflow_call
permissions:
  contents: read
jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""


def _write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _caller(reference):
    return (
        "name: Caller\non: workflow_dispatch\npermissions:\n  contents: read\n"
        "jobs:\n  call:\n    uses: " + json.dumps(reference, ensure_ascii=False) + "\n"
    )


def _pair(root, reference="$/.github/workflows/called.yml"):
    _write(root, ".github/workflows/caller.yml", _caller(reference))
    if reference.startswith(("$/", "./")) and "@" not in reference:
        relative = reference[2:]
        if "/" not in relative.removeprefix(".github/workflows/"):
            _write(root, relative, CALLED)


def _pin_findings(root):
    return [f for f in scan_github_actions(root) if f["rule_id"] == "SKY-D292"]


def _identities(root):
    identities = []
    for finding in _pin_findings(root):
        file = Path(finding["file"])
        if file.is_absolute():
            file = file.relative_to(root)
        identities.append(
            (
                finding["rule_id"],
                finding["value"],
                finding["severity"],
                file.as_posix(),
                finding["line"],
            )
        )
    return sorted(identities)


def _mixed_workflow():
    jobs = {
        "same_commit": "$/.github/workflows/called.yml",
        "traditional": "./.github/workflows/called.yml",
        "external_branch": "thirdparty/project/.github/workflows/called.yml@main",
        "external_tag": "thirdparty/project/.github/workflows/called.yml@v1",
        "external_sha": "thirdparty/project/.github/workflows/called.yml@" + SHA,
    }
    steps = [
        "actions/checkout@v4",
        "actions/setup-python@main",
        "thirdparty/action@v1",
        "actions/checkout@${{ inputs.ref }}",
        "actions/cache/./@v4",
        "actions//checkout@v4",
        "thirdparty/action@" + SHA,
        "docker://alpine:3",
        "docker://alpine@sha256:" + DOCKER_DIGEST,
        "./.github/actions/local",
    ]
    text = "name: Mixed\non: workflow_dispatch\npermissions:\n  contents: read\njobs:\n"
    for name, value in jobs.items():
        text += f"  {name}:\n    uses: {value}\n"
    text += "  actions:\n    runs-on: ubuntu-latest\n    steps:\n"
    for value in steps:
        text += f"      - uses: {value}\n"
    return text


def test_reporter_two_workflow_reproduction_has_no_unpinned_reference(tmp_path):
    root = tmp_path.resolve()
    _pair(root)
    assert _identities(root) == []


@pytest.mark.parametrize(
    "filename", ["called.yml", "called.yaml", "build release.yml", "caf\u00e9.yml"]
)
def test_dollar_local_workflow_names_are_same_commit_references(tmp_path, filename):
    root = tmp_path.resolve()
    _pair(root, "$/.github/workflows/" + filename)
    assert _identities(root) == []


def test_traditional_relative_reusable_reference_remains_pinned(tmp_path):
    root = tmp_path.resolve()
    _pair(root, "./.github/workflows/called.yml")
    assert _identities(root) == []


@pytest.mark.parametrize(
    "reference",
    [
        "$/action.yml",
        "$/owner/repo/.github/workflows/called.yml",
        "$/.github/workflows/called.yml@main",
        "$/.github/workflows/called.yml@v1",
        "$/.github/workflows/sub/called.yml",
        "$/.github/workflows/../called.yml",
        "$/.github/workflows/",
        "$/.github/workflows/${{ inputs.workflow }}.yml",
        "$/.github/workflows/called.txt",
        "$\\.github\\workflows\\called.yml",
    ],
)
def test_dollar_lookalikes_do_not_gain_a_pinning_exemption(tmp_path, reference):
    root = tmp_path.resolve()
    _write(root, ".github/workflows/caller.yml", _caller(reference))
    findings = _pin_findings(root)
    assert [(f["rule_id"], f["value"], f["severity"]) for f in findings] == [
        ("SKY-D292", reference, "HIGH")
    ]


@pytest.mark.parametrize("composite", [False, True], ids=["step", "composite"])
def test_dollar_syntax_is_not_a_local_action_step_exemption(tmp_path, composite):
    root = tmp_path.resolve()
    reference = "$/.github/workflows/called.yml"
    if composite:
        relative = ".github/actions/example/action.yml"
        content = (
            "name: Composite\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {reference}\n"
        )
    else:
        relative = ".github/workflows/steps.yml"
        content = (
            "name: Steps\non: workflow_dispatch\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: {reference}\n"
        )
    _write(root, relative, content)
    findings = _pin_findings(root)
    assert [(f["value"], f["severity"]) for f in findings] == [(reference, "HIGH")]


def test_new_same_commit_reference_preserves_all_original_security_identities(tmp_path):
    root = tmp_path.resolve()
    content = _mixed_workflow()
    _write(root, ".github/workflows/mixed.yml", content)
    _write(root, ".github/workflows/called.yml", CALLED)
    expected = {
        "thirdparty/project/.github/workflows/called.yml@main": "HIGH",
        "thirdparty/project/.github/workflows/called.yml@v1": "HIGH",
        "actions/checkout@v4": "LOW",
        "actions/setup-python@main": "LOW",
        "thirdparty/action@v1": "HIGH",
        "actions/checkout@${{ inputs.ref }}": "HIGH",
        "actions/cache/./@v4": "HIGH",
        "actions//checkout@v4": "HIGH",
        "docker://alpine:3": "HIGH",
    }
    identities = [
        (
            "SKY-D292",
            value,
            severity,
            ".github/workflows/mixed.yml",
            next(
                i
                for i, line in enumerate(content.splitlines(), 1)
                if line.strip() in {"uses: " + value, "- uses: " + value}
            ),
        )
        for value, severity in expected.items()
    ]
    assert _identities(root) == sorted(identities)


def test_reporter_reproduction_is_clean_through_public_static_cli(tmp_path):
    root = (tmp_path / "reporter").resolve()
    root.mkdir()
    _pair(root)
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "LANG")
        if key in os.environ
    }
    env.update(PYTHONPATH=str(SOURCE_ROOT), SKYLOS_NO_TELEMETRY="1", SKYLOS_JOBS="1")
    scan = subprocess.run(
        [
            sys.executable,
            "-c",
            "from skylos.cli import main; main()",
            ".",
            "--danger",
            "--select",
            "SKY-D292",
            "--format",
            "json",
            "--strict",
            "--no-provenance",
            "--no-grep-verify",
        ],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
    )
    assert scan.returncode in (0, 1), scan.stdout + scan.stderr
    result = json.loads(scan.stdout)
    assert result.get("analysis_errors", []) == []
    assert [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D292"] == []
    assert scan.returncode == 0, scan.stderr
