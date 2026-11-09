"""Branch growth must preserve quoted arguments and later unsafe commands."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


def _source(count, left="a", right="b", *, suffix=False, unsafe_last=False):
    lines = [
        "import subprocess, shlex",
        "def run(value, flag):",
        '    command = "echo " + shlex.quote(value)',
    ]
    for _ in range(count):
        first = f"command + {left!r}" if suffix else f"{left!r} + command"
        second = f"command + {right!r}" if suffix else f"{right!r} + command"
        lines += [
            "    if flag:",
            f"        command = {first}",
            "    else:",
            f"        command = {second}",
        ]
    if unsafe_last:
        lines += ["    if flag:", "        command = value"]
    first_line = len(lines) + 1
    lines += [
        "    subprocess.run(command, shell=True)",
        "    subprocess.run(value, shell=True)",
    ]
    return "\n".join(lines) + "\n", first_line


def _assert_commands(tmp_path, monkeypatch, source, first_line, first_unsafe):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    path = write_fixture(root, "app.py", source)
    raw = [row for row in scan_ctx(root, [path]) if row["rule_id"] == "SKY-D212"]
    report = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not report.get("analysis_errors")
    assert report.get("analysis_summary", {}).get("analysis_error_count", 0) == 0
    listed = [row for row in report.get("danger", []) if row["rule_id"] == "SKY-D212"]
    expected = {first_line, first_line + 1} if first_unsafe else {first_line + 1}
    assert {row["line"] for row in raw} == expected
    assert {row["line"] for row in listed} == expected
    assert all(row["severity"] == "CRITICAL" for row in raw + listed)
    assert all(
        row["listing"]["listed"] and row["metadata"]["security_trace"] for row in listed
    )
    gate = {"gate": {"max_high": 1000, "max_security": 1000, "max_critical": 0}}
    assert check_gate(report, gate)[0] is False
    first_only = {
        **report,
        "danger": [row for row in listed if row["line"] == first_line],
    }
    assert check_gate(first_only, gate)[0] is (not first_unsafe)


@pytest.mark.parametrize("count", [100, 300, 500])
def test_neutral_prefix_branches_keep_quoted_command_quiet(
    tmp_path, monkeypatch, count
):
    source, line = _source(count)
    _assert_commands(tmp_path, monkeypatch, source, line, False)


@pytest.mark.parametrize("suffix", [False, True], ids=["prefix", "suffix"])
@pytest.mark.parametrize("fragments", [("a", "b"), ("valid_name", "other_name")])
def test_native_neutral_branch_fragments_keep_the_quote_context(
    tmp_path, monkeypatch, suffix, fragments
):
    source, line = _source(100, *fragments, suffix=suffix)
    _assert_commands(tmp_path, monkeypatch, source, line, False)


@pytest.mark.parametrize("suffix", [False, True], ids=["prefix", "suffix"])
def test_unquoted_branch_after_many_safe_branches_keeps_both_commands(
    tmp_path, monkeypatch, suffix
):
    source, line = _source(100, suffix=suffix, unsafe_last=True)
    _assert_commands(tmp_path, monkeypatch, source, line, True)


@pytest.mark.parametrize("unsafe_prefix", ["'", '"', "\\", "$(", "<<EOF\n"])
def test_context_changing_branch_cannot_be_merged_with_neutral_text(
    tmp_path, monkeypatch, unsafe_prefix
):
    source, line = _source(30, "a", unsafe_prefix)
    _assert_commands(tmp_path, monkeypatch, source, line, True)


@pytest.mark.parametrize(
    "transform",
    [
        "'eval ' + command",
        '"sh -c \'" + command + "\'"',
        "'sh -c \"' + command + '\"'",
        "'echo $(\"' + command + '\")'",
        "'\"' + command + '\"'",
        "command[105:]",
    ],
    ids=[
        "eval",
        "single-quoted-script",
        "double-quoted-script",
        "substitution",
        "quoted",
        "command-position",
    ],
)
def test_a_compacted_command_is_not_a_sanitizer_in_another_context(
    tmp_path, monkeypatch, transform
):
    source, line = _source(100)
    source = source.replace(
        "    subprocess.run(command, shell=True)",
        f"    command = {transform}\n    subprocess.run(command, shell=True)",
    )
    _assert_commands(tmp_path, monkeypatch, source, line + 1, True)


@pytest.mark.parametrize(
    "first,second,tail", [("e", "x", "val "), ("b", "d", "ash -c ")]
)
def test_literal_choice_that_forms_an_interpreter_is_not_normalized(
    tmp_path, monkeypatch, first, second, tail
):
    lines = [
        "import subprocess, shlex",
        "def run(value, flag):",
        "    if flag:",
        f"        prefix = {first!r}",
        "    else:",
        f"        prefix = {second!r}",
        f"    command = prefix + {tail!r} + shlex.quote(value)",
    ]
    for _ in range(100):
        lines += [
            "    if flag:",
            "        command = command + 'a'",
            "    else:",
            "        command = command + 'b'",
        ]
    line = len(lines) + 1
    lines += [
        "    subprocess.run(command, shell=True)",
        "    subprocess.run(value, shell=True)",
    ]
    _assert_commands(tmp_path, monkeypatch, "\n".join(lines) + "\n", line, True)


@pytest.mark.parametrize(
    "program,option", [("sh", "-c"), ("python3.11", "-c"), ("ruby3.3", "-e")]
)
def test_interpreter_commands_cannot_gain_a_whole_command_proof(
    tmp_path, monkeypatch, program, option
):
    source, line = _source(100, suffix=True)
    source = source.replace('"echo "', repr(f"{program} {option} "))
    _assert_commands(tmp_path, monkeypatch, source, line, True)


def test_leading_space_cannot_turn_a_neutral_prefix_into_eval(tmp_path, monkeypatch):
    source, line = _source(100, suffix=True)
    source = source.replace('"echo "', '" echo "').replace(
        "    subprocess.run(command, shell=True)",
        "    command = 'eval' + command\n    subprocess.run(command, shell=True)",
    )
    _assert_commands(tmp_path, monkeypatch, source, line + 1, True)
