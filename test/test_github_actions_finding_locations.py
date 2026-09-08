"""Location and comment-scope contracts using inert YAML and dummy findings."""

from pathlib import Path

import pytest

from skylos.rules.config.cicd import github_actions
from skylos.rules.config.cicd.github_actions import _is_inline_ignored
from skylos.rules.config.cicd.yaml_source import load_yaml_with_locations
from skylos.rules.catalog import get_rule_catalog


@pytest.mark.parametrize(
    ("text", "line", "expected"),
    [
        ("# skylos: ignore[TEST-LABEL]\nlabel: value\n", 2, True),
        ("label: value # skylos: ignore[TEST-LABEL]\n", 1, True),
        (
            "first: value # skylos: ignore[TEST-LABEL]\nsecond: value\n",
            2,
            False,
        ),
        ('label: "# skylos: ignore[TEST-LABEL]"\n', 1, False),
        ('label: "# skylos: ignore[TEST-LABEL]"\nnext: value\n', 2, False),
        ("label: |\n  # skylos: ignore[TEST-LABEL]\nnext: value\n", 3, False),
        ("# skylos: ignore[TEST-OTHER]\nlabel: value\n", 2, False),
        ("# skylos: ignore[TEST-LABEL]\n\nlabel: value\n", 3, False),
        ("# skylos: ignore[TEST-LABEL]\nlabel: value\n", 0, False),
    ],
    ids=[
        "preceding-standalone-comment",
        "same-line-comment",
        "previous-inline-comment-does-not-spill",
        "quoted-text-is-not-comment",
        "previous-quoted-text-is-not-comment",
        "block-scalar-text-is-not-comment",
        "other-rule-is-not-ignored",
        "blank-line-breaks-scope",
        "invalid-line-is-not-ignored",
    ],
)
def test_yaml_ignore_comment_scope(text, line, expected):
    assert _is_inline_ignored(text.splitlines(), line, "TEST-LABEL") is expected


@pytest.mark.parametrize(
    ("text", "name", "line"),
    [
        ("# alpha\nname: alpha\non:\n  alpha:\n", "alpha", 4),
        (
            "on:\n  beta:\n    branches: [alpha-example]\n  'alpha': {}\n",
            "alpha",
            4,
        ),
        ("on:\n  - alpha\n  - beta\n", "beta", 3),
        ('"on": [alpha, beta]\n', "beta", 1),
        ("on:\n  alpha\n", "alpha", 2),
        ("base: &events\n  alpha:\non:\n  <<: *events\n", "alpha", 4),
        ("base: &event alpha\non: *event\n", "alpha", 2),
        ("on: beta\non:\n  alpha:\n", "alpha", 3),
    ],
)
def test_trigger_location_uses_semantic_path(text, name, line):
    data, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    assert github_actions._line_for_trigger(data, lines, name) == line


def test_job_field_locations_stay_in_their_own_scope():
    text = (
        "# label: reference\n"
        "jobs:\n"
        "  first:\n"
        "    label: repeated\n"
        "  second:\n"
        "    'label': repeated\n"
    )
    _, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    assert github_actions._line_for_job_field(lines, "first", "label") == 4
    assert github_actions._line_for_job_field(lines, "second", "label") == 6


def test_dummy_finding_ignore_applies_only_to_intended_occurrence():
    text = "# skylos: ignore[TEST-LABEL]\nfirst: value\nsecond: value\n"
    _, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    findings = []
    for line in (2, 3):
        github_actions._add_finding(
            findings,
            lines,
            {"rule_id": "TEST-LABEL", "file": "labels.yml", "line": line},
            yaml_only=True,
        )
    assert findings == [{"rule_id": "TEST-LABEL", "file": "labels.yml", "line": 3}]


def test_runner_classifier_wiring_preserves_job_locations_and_catalog_severity(
    monkeypatch,
):
    # Force a diagnostic for benign hosted selections to check the wiring only.
    text = (
        "jobs:\n"
        "  first:\n"
        "    runs-on: ubuntu-latest\n"
        "  second:\n"
        "    runs-on: windows-latest\n"
    )
    data, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    visited = []

    def classify(job):
        visited.append(job)
        return True

    monkeypatch.setattr(github_actions, "runner_may_be_self_hosted", classify)
    findings = []
    github_actions._scan_self_hosted_runners(
        data, Path("labels.yml"), lines, findings, set()
    )
    assert visited == list(data["jobs"].values())
    assert [finding["line"] for finding in findings] == [3, 5]
    severity = get_rule_catalog("SKY-D295")[0]["severity"]
    assert severity == "HIGH"
    assert all(finding["severity"] == severity for finding in findings)


def test_scanner_reads_safe_workflow_once_and_accepts_hosted_matrix(monkeypatch):
    text = (
        "name: Preview\n"
        "on: workflow_dispatch\n"
        "permissions: {}\n"
        "jobs:\n"
        "  preview:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        os: [ubuntu-latest, windows-latest, macos-latest]\n"
        "    runs-on: ${{ matrix.os }}\n"
        "    steps: []\n"
    )
    path = Path(".github/workflows/preview.yml")
    reads = []

    def read(candidate, **kwargs):
        reads.append(candidate)
        return text

    monkeypatch.setattr(
        github_actions, "_resolve_github_actions_scan_path", lambda *a, **k: path
    )
    monkeypatch.setattr(github_actions, "read_text_no_symlink", read)
    assert github_actions.scan_github_actions_file(path) == []
    assert reads == [path]


@pytest.mark.parametrize("name", ["on", "off", "yes", "no", "true", "false"])
def test_job_field_lookup_preserves_yaml_boolean_keys(name):
    text = f"jobs:\n  {name}:\n    label: value\n"
    data, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    job_key, _ = next(github_actions._jobs(data))
    assert github_actions._line_for_job_field(lines, job_key, "label") == 3


def test_embedded_script_comments_keep_existing_ignore_behavior():
    text = "run: |\n  echo hello # skylos: ignore[TEST-SCRIPT]\n"
    _, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    assert not _is_inline_ignored(lines, 2, "TEST-SCRIPT", yaml_only=True)
    assert _is_inline_ignored(lines, 2, "TEST-SCRIPT", yaml_only=False)
    findings = []
    github_actions._add_finding(findings, lines, {"rule_id": "TEST-SCRIPT", "line": 2})
    assert findings == []
