"""D300 identifies its own risky run block without changing shell policy."""

import pytest

from skylos.rules.config.cicd.github_actions import scan_github_actions_file
from test.fixture_paths import write_fixture


WORKFLOW = ".github/workflows/mre.yml"
HEADER = """name: mre
on: push
permissions:
  contents: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
"""
SAFE = 'echo "SAFE=1" >> "$GITHUB_ENV"'


def _assert_env_lines(tmp_path, source, expected, *, relative=WORKFLOW):
    path = write_fixture(tmp_path, relative, source)
    errors = []
    findings = scan_github_actions_file(path, root=tmp_path, analysis_errors=errors)
    assert errors == []
    rows = [row for row in findings if row["rule_id"] == "SKY-D300"]
    assert [(row["rule_id"], row["line"], row["severity"]) for row in rows] == [
        ("SKY-D300", line, "MEDIUM") for line in expected
    ]
    assert all(row["file"] == str(path) for row in rows)


def test_issue_1213_reports_two_bad_steps_instead_of_first_safe_run(tmp_path):
    source = (
        HEADER
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      - name: Bad
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - name: Bad2
        run: echo "BAD2=$(date)" >> "$GITHUB_ENV"
"""
    )
    assert source.splitlines()[9] == "        run: " + SAFE
    _assert_env_lines(tmp_path, source, [12, 14])


def test_identical_dangerous_commands_in_separate_steps_are_distinct(tmp_path):
    source = (
        HEADER
        + """      - name: First
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - name: Second
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [10, 12])


def test_identical_dangerous_commands_in_separate_jobs_are_distinct(tmp_path):
    source = (
        HEADER
        + """      - name: First
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
  second:
    runs-on: ubuntu-latest
    steps:
      - name: Second
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [10, 15])


@pytest.mark.parametrize("style", ["|", "|-", "|+"])
def test_literal_block_uses_its_own_run_header(tmp_path, style):
    source = (
        HEADER
        + "      - name: Safe\n        run: "
        + SAFE
        + "\n      - name: Multiline\n        run: "
        + style
        + '\n          echo "SAFE=1" >> "$GITHUB_ENV"\n'
        '          echo "BAD=$(pwd)" >> "$GITHUB_ENV"\n'
    )
    _assert_env_lines(tmp_path, source, [12])


@pytest.mark.parametrize("style", [">", ">-"])
def test_folded_block_uses_physical_run_header_instead_of_decoded_offsets(
    tmp_path, style
):
    source = (
        HEADER
        + "      - name: Safe\n        run: "
        + SAFE
        + "\n      - name: Folded\n        run: "
        + style
        + '\n          echo "BAD=$(pwd)"\n          >> "$GITHUB_ENV"\n'
    )
    _assert_env_lines(tmp_path, source, [12])


@pytest.mark.parametrize("destination", ["GITHUB_ENV", "GITHUB_PATH"])
def test_each_environment_file_destination_keeps_its_actual_run_line(
    tmp_path, destination
):
    source = (
        HEADER
        + "      - name: Safe\n        run: "
        + SAFE
        + "\n      - name: Derived\n"
        + '        run: echo "BAD=$(pwd)" >> "$'
        + destination
        + '"\n'
    )
    _assert_env_lines(tmp_path, source, [12])


def test_literal_environment_assignment_remains_quiet(tmp_path):
    source = HEADER + "      - name: Safe\n        run: " + SAFE + "\n"
    _assert_env_lines(tmp_path, source, [])


@pytest.mark.parametrize("job_id", ["yes", "1", "'on'"])
def test_location_uses_the_original_yaml_job_key(tmp_path, job_id):
    source = (
        HEADER.replace("  j:\n", f"  {job_id}:\n")
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      - name: Bad
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [12])


def test_skipped_step_entries_do_not_shift_source_indices(tmp_path):
    source = (
        HEADER
        + """      - ignored
      - null
      - run: 42
      - name: Bad
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [13])


@pytest.mark.parametrize("last_is_unsafe", [False, True])
def test_duplicate_run_keys_follow_the_resolved_last_value(tmp_path, last_is_unsafe):
    bad = 'echo "BAD=$(pwd)" >> "$GITHUB_ENV"'
    first, last = (SAFE, bad) if last_is_unsafe else (bad, SAFE)
    source = (
        HEADER + f"      - name: Duplicate\n        run: {first}\n        run: {last}\n"
    )
    _assert_env_lines(tmp_path, source, [11] if last_is_unsafe else [])


def test_composite_action_uses_its_own_risky_run_line(tmp_path):
    source = """name: mre
runs:
  using: composite
  steps:
    - name: Safe
      shell: bash
      run: echo "SAFE=1" >> "$GITHUB_ENV"
    - name: Bad
      shell: bash
      run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    _assert_env_lines(tmp_path, source, [10], relative="action.yml")


def test_commented_run_and_quoted_run_key_do_not_steal_location(tmp_path):
    source = (
        HEADER
        + """      # run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      # A later quoted key owns the command below.
      - name: Bad
        'run': echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [14])


def test_scalar_alias_keeps_each_local_run_key(tmp_path):
    source = (
        HEADER
        + """      - name: First
        run: &unsafe echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - name: Second
        run: *unsafe
"""
    )
    _assert_env_lines(tmp_path, source, [10, 12])


def test_reused_step_mapping_uses_local_alias_reference_line(tmp_path):
    source = (
        HEADER
        + """      - &unsafe
        name: First
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - *unsafe
"""
    )
    _assert_env_lines(tmp_path, source, [11, 12])


def test_merged_run_uses_local_merge_reference_line(tmp_path):
    source = (
        HEADER
        + """      - &unsafe
        name: First
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - <<: *unsafe
        name: Second
"""
    )
    _assert_env_lines(tmp_path, source, [11, 12])


def test_two_unsafe_commands_in_one_block_remain_one_finding(tmp_path):
    source = (
        HEADER
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      - name: TwoCommands
        run: |
          echo "BAD=$(pwd)" >> "$GITHUB_ENV"
          echo "BAD2=$(date)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [12])


def test_ignore_on_safe_run_cannot_hide_a_later_risky_run(tmp_path):
    source = (
        HEADER
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV" # skylos: ignore[SKY-D300]
      - name: Bad
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [12])


def test_ignore_on_current_risky_header_does_not_hide_the_next_step(tmp_path):
    source = (
        HEADER
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      - name: Ignored
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV" # skylos: ignore[SKY-D300]
      - name: Bad2
        run: echo "BAD2=$(date)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [14])


def test_ignore_immediately_before_risky_header_stays_local(tmp_path):
    source = (
        HEADER
        + """      - name: Safe
        run: echo "SAFE=1" >> "$GITHUB_ENV"
      - name: Ignored
        # skylos: ignore[SKY-D300]
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
      - name: Bad2
        run: echo "BAD2=$(date)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [15])


def test_ignore_on_adjacent_safe_step_does_not_spill_to_risky_step(tmp_path):
    source = (
        HEADER
        + """      - run: echo "SAFE=1" >> "$GITHUB_ENV" # skylos: ignore[SKY-D300]
      - run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [10])


def test_ignore_text_inside_adjacent_run_string_is_not_a_comment(tmp_path):
    source = (
        HEADER
        + """      - run: 'echo "skylos: ignore[SKY-D300]"'
      - run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [10])


def test_ignore_text_inside_step_name_is_not_a_comment(tmp_path):
    source = (
        HEADER
        + """      - name: "skylos: ignore[SKY-D300]"
        run: echo "BAD=$(pwd)" >> "$GITHUB_ENV"
"""
    )
    _assert_env_lines(tmp_path, source, [10])
