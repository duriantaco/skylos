"""``skylos feedback``, the failure record it reads, and the crash hint.

Rows refer to build-B3.md (K1-K18). Every test uses its own HOME.
"""

from __future__ import annotations

import io
import json
import os
import socket
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from rich.console import Console

import skylos
from skylos import entry
from skylos.commands.feedback_cmd import run_feedback_command
from skylos.core import report_context as rc
from skylos.core.safe_cache_io import write_text_no_symlink

REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_FRAGMENTS = ("/Users/", "/home/", "/tmp/", "/var/", "/private/")


@pytest.fixture
def home(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.delenv(rc.DISABLE_ENV, raising=False)
    for name in rc._CI_MARKERS:
        monkeypatch.delenv(name, raising=False)
    return home_dir


def _record_file(home_dir: Path) -> Path:
    return Path(os.path.realpath(home_dir)) / ".skylos" / "last_error.json"


def _run(argv, **kwargs):
    out = io.StringIO()
    opened: list[str] = []

    def opener(url):
        opened.append(url)
        return True

    kwargs.setdefault("opener", opener)
    kwargs.setdefault("environ", {})
    kwargs.setdefault("interactive", True)
    code = run_feedback_command(argv, stdout=out, **kwargs)
    return code, out.getvalue(), opened


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


def _run_entry(argv, cli_main):
    """entry's wrapper around cli.main, as the console script runs it."""
    with pytest.raises(SystemExit) as raised:
        entry._run_recording_failures(cli_main, ["skylos", *argv])
    return raised.value.code


def _exit_with(code):
    def cli_main():
        raise SystemExit(code)

    return cli_main


# K1
def test_print_without_a_record_gives_the_plain_url(home):
    code, output, opened = _run(["--print"])

    assert code == 0
    assert opened == []
    lines = output.splitlines()
    assert len(lines) == 1
    url = lines[0]
    assert url.startswith("https://skylos.dev/feedback?src=cli&v=")
    query = _query(url)
    assert query["v"] == [skylos.__version__]
    assert set(query) == {"src", "v", "os", "py"}


# K2
def test_exit_two_is_recorded_masked_and_shown(home, tmp_path):
    project = tmp_path / "does-not-exist-b3"
    code = _run_entry([str(project), "--no-such-flag"], _exit_with(2))
    assert code == 2

    record_text = _record_file(home).read_text()
    record = json.loads(record_text)
    assert record["command"] == "skylos <path> --no-such-flag"
    assert record["exit_code"] == 2
    assert record["schema"] == 1

    code, output, opened = _run([])
    assert code == 0
    assert "Last error  skylos <path> --no-such-flag  ->  exit 2, just now" in output
    assert len(opened) == 1
    url = opened[0]
    assert "cmd=skylos+%3Cpath%3E+--no-such-flag&exit=2" in url
    for text in (url, output, record_text):
        assert "does-not-exist" not in text
        for fragment in PRIVATE_FRAGMENTS:
            assert fragment not in text


def test_real_cli_unknown_flag_exits_two_and_records(home, tmp_path):
    env = {**os.environ, "HOME": str(home)}
    env.pop(rc.DISABLE_ENV, None)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from skylos.entry import main; "
                "sys.argv = ['skylos', sys.argv[1], '--no-such-flag-b3']; main()"
            ),
            str(tmp_path / "does-not-exist-b3"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 2
    record = json.loads(_record_file(home).read_text())
    assert record["command"] == "skylos <path> --no-such-flag-b3"
    assert record["exit_code"] == 2


# K3
@pytest.mark.parametrize("code", [0, 1, None, "fatal", True, 130])
def test_non_failure_exits_are_not_recorded(home, code):
    _run_entry(["."], _exit_with(code))
    assert not _record_file(home).exists()


def test_exit_one_keeps_the_earlier_record(home):
    _run_entry(["--bad"], _exit_with(2))
    before = _record_file(home).read_text()
    _run_entry([".", "--gate"], _exit_with(1))
    assert _record_file(home).read_text() == before


def test_normal_return_restores_the_excepthook(home):
    previous = sys.excepthook
    entry._run_recording_failures(lambda: None, ["skylos", "."])
    assert sys.excepthook is previous
    _run_entry(["."], _exit_with(2))
    assert sys.excepthook is previous


# K4
def test_secret_flag_values_and_tokens_are_masked(home):
    argv = [
        "skylos",
        ".",
        "--api-key",
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    ]
    _run_entry(argv[1:], _exit_with(2))

    record_text = _record_file(home).read_text()
    assert json.loads(record_text)["command"] == (
        "skylos <path> --api-key <redacted> <redacted>"
    )
    _code, output, opened = _run([])
    for text in (record_text, output, opened[0]):
        assert "sk-ant-" not in text
        assert "ghp_" not in text


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--token=abc"], "skylos --token=<redacted>"),
        (
            ["--webhook-url", "https://hooks.example/x"],
            "skylos --webhook-url <redacted>",
        ),
        (["--api-key", "-starts-with-dash"], "skylos --api-key <redacted>"),
        (["https://user:pass@example.com/repo"], "skylos <url>"),
        (["-o/tmp/out.json"], "skylos -o<path>"),
        (["src/app/main.py"], "skylos <path>"),
        (["--format", "json"], "skylos --format json"),
        (["AKIAABCDEFGHIJKLMNOP"], "skylos <redacted>"),
        (["x" * 60], "skylos " + "x" * 39 + "\u2026"),
    ],
)
def test_redact_argv_rules(argv, expected, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert rc.redact_argv(["/usr/bin/skylos", *argv]) == expected


# K5
def test_git_refs_are_kept(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _run_entry([".", "--diff", "origin/main"], _exit_with(2))
    record = json.loads(_record_file(home).read_text())
    assert record["command"] == "skylos <path> --diff origin/main"


# K6, K7
CRASH_SCRIPT = textwrap.dedent(
    """
    import sys
    import skylos.cli

    def boom(_argv):
        raise RuntimeError("secret /Users/bob/private-repo token")

    skylos.cli._dispatch_early_command = boom
    sys.argv = ["skylos", ".", "--format", "json"]
    from skylos.entry import main
    main()
    """
)


def test_crash_prints_traceback_then_one_hint_line(home, tmp_path):
    env = {**os.environ, "HOME": str(home)}
    env.pop(rc.DISABLE_ENV, None)
    result = subprocess.run(
        [sys.executable, "-c", CRASH_SCRIPT],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    lines = result.stderr.rstrip("\n").splitlines()
    assert lines[0] == "Traceback (most recent call last):"
    assert lines[-2] == "RuntimeError: secret /Users/bob/private-repo token"
    hint = lines[-1]
    assert hint.startswith(
        "Skylos hit an internal error (RuntimeError in skylos/cli.py:"
    )
    assert hint.endswith(
        "). Report it: skylos feedback (opens a prefilled form to review before "
        "sending)"
    )
    assert sum("Skylos hit an internal error" in line for line in lines) == 1

    record_text = _record_file(home).read_text()
    record = json.loads(record_text)
    assert record["error_type"] == "RuntimeError"
    assert record["skylos_frame"].startswith("skylos/cli.py:")
    assert record["skylos_frame"].endswith(" in main")
    assert record["exit_code"] == 1
    assert record["command"] == "skylos <path> --format json"
    assert "secret" not in record_text
    assert "/Users/bob" not in record_text


def test_keyboard_interrupt_gets_no_hint(home):
    errors = io.StringIO()
    original = sys.stderr
    sys.stderr = errors
    try:
        entry._after_crash(["skylos", "."], KeyboardInterrupt, None)
    finally:
        sys.stderr = original
    assert errors.getvalue() == ""
    assert not _record_file(home).exists()


# K8
def test_hook_never_records(home, monkeypatch):
    from skylos.commands import hook_cmd

    monkeypatch.setattr(hook_cmd, "run_hook_command", lambda _argv: 2)
    monkeypatch.setattr(sys, "argv", ["skylos", "hook", "post-edit"])
    with pytest.raises(SystemExit) as raised:
        entry.main()
    assert raised.value.code == 2
    assert not _record_file(home).exists()

    # The help path goes through the full CLI but still never records.
    _run_entry(["hook", "--bogus"], _exit_with(2))
    _run_entry(["feedback", "--bogus"], _exit_with(2))
    assert not _record_file(home).exists()


# K9
def test_recording_can_be_switched_off(home, monkeypatch):
    monkeypatch.setenv(rc.DISABLE_ENV, "0")
    _run_entry(["--bad"], _exit_with(2))
    assert not _record_file(home).exists()

    _code, output, _opened = _run([], environ={rc.DISABLE_ENV: "0"})
    assert "Last error  recording off (SKYLOS_FEEDBACK_CONTEXT=0)" in output


# K10
@pytest.mark.parametrize(
    ("environ", "interactive"),
    [({"CI": "true"}, True), ({"GITHUB_ACTIONS": "true"}, True), ({}, False)],
)
def test_ci_or_pipe_prints_url_only(home, environ, interactive):
    code, output, opened = _run([], environ=environ, interactive=interactive)
    assert code == 0
    assert opened == []
    assert output.count("\n") == 1
    assert output.startswith("https://skylos.dev/feedback?src=cli&")


def test_ci_false_still_counts_as_interactive(home):
    _code, output, opened = _run([], environ={"CI": "false"})
    assert len(opened) == 1
    assert output.startswith("Skylos feedback\n")


# K11
@pytest.mark.parametrize("behaviour", ["false", "raise"])
def test_browser_failure_points_at_the_printed_url(home, behaviour):
    def opener(_url):
        if behaviour == "raise":
            raise RuntimeError("no display")
        return False

    code, output, _opened = _run([], opener=opener)
    assert code == 0
    assert (
        "If the browser doesn't open, visit:\n  https://skylos.dev/feedback?" in output
    )
    assert output.rstrip().endswith("Couldn't open a browser. Open the URL above.")


def test_interactive_output_names_what_is_and_is_not_attached(home):
    _code, output, opened = _run([])
    assert output.startswith(
        "Skylos feedback\n\nOpening a private feedback form on skylos.dev. "
        "Loading it shares the details below; your message is sent only when you "
        "press Send.\n"
    )
    assert f"  Skylos      {skylos.__version__}\n" in output
    assert "  Last error  none recorded\n" in output
    assert (
        "Not attached: your code, file paths, repository names, environment variables."
        in output
    )
    assert "Prefer a public GitHub issue? Run: skylos feedback --github" in output
    assert "Couldn't open a browser" not in output
    assert len(opened) == 1


# K12
def test_github_issue_form_url(home):
    _run_entry([".", "-a"], _exit_with(2))
    code, output, opened = _run(["--github"])
    assert code == 0
    url = opened[0]
    assert url.startswith(
        "https://github.com/duriantaco/skylos/issues/new?template=bug_report.yml&version="
    )
    query = _query(url)
    assert set(query) == {"template", "version", "os", "python", "command"}
    assert query["command"] == ["skylos <path> -a (exit 2)"]
    assert "labels=" not in url
    assert "assignees=" not in url
    assert len(url) <= rc.URL_MAX_CHARS
    assert "Opening a public GitHub issue form." in output
    assert "Prefer a private report? Run: skylos feedback" in output


@pytest.mark.parametrize(
    ("kind", "template", "keys"),
    [
        ("idea", "feature_request.yml", {"template"}),
        ("wrong-finding", "false_positive.yml", {"template", "version"}),
        ("question", "bug_report.yml", {"template", "version", "os", "python"}),
    ],
)
def test_github_type_picks_the_matching_form(home, kind, template, keys):
    _code, output, _opened = _run(["--github", "--type", kind, "--print"])
    query = _query(output.strip())
    assert query["template"] == [template]
    assert set(query) == keys


def test_private_form_type_parameter(home):
    _code, output, _opened = _run(["--type", "wrong-finding", "--print"])
    assert _query(output.strip())["type"] == ["wrong_finding"]
    _code, output, _opened = _run(["--print"])
    assert "type" not in _query(output.strip())


def test_issue_form_ids_match_the_prefill_keys():
    yaml = pytest.importorskip("yaml")
    forms = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"

    def ids(name):
        data = yaml.safe_load((forms / name).read_text())
        return {item["id"] for item in data["body"] if "id" in item}

    assert {"version", "os", "python", "command"} <= ids("bug_report.yml")
    assert {"version"} <= ids("false_positive.yml")
    for name in ("bug_report.yml", "false_positive.yml", "feature_request.yml"):
        assert yaml.safe_load((forms / name).read_text())["labels"]
    config = yaml.safe_load((forms / "config.yml").read_text())
    urls = {link["url"] for link in config["contact_links"]}
    assert "https://skylos.dev/feedback?src=github" in urls
    assert "https://github.com/duriantaco/skylos/security/advisories/new" in urls
    assert not list(forms.glob("*.md"))


# K13
def test_feedback_makes_no_network_request(home, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    for argv in ([], ["--github"], ["--print"]):
        code, _output, _opened = _run(argv)
        assert code == 0


# K14
def test_long_commands_are_capped(home):
    argv = ["skylos", *(f"--flag-{index:03d}" for index in range(60))]
    assert rc.record_failure(argv, 2)
    failure = rc.load_last_failure()
    assert len(failure["command"]) == rc.COMMAND_MAX_CHARS
    assert failure["command"].endswith("\u2026")

    url = rc.build_feedback_url(rc.environment_summary(), failure)
    assert len(url) <= rc.URL_MAX_CHARS
    assert _query(url)["cmd"][0].endswith("\u2026")


def test_url_is_cut_to_fit_even_for_an_oversized_command():
    failure = {"command": "skylos " + "a" * 3000, "exit_code": 2}
    env = {"version": "4.49.0", "os": "macOS 13 (arm64)", "python": "3.12.1"}
    for builder, key in (
        (rc.build_feedback_url, "cmd"),
        (rc.build_github_issue_url, "command"),
    ):
        url = builder(env, failure)
        assert len(url) <= rc.URL_MAX_CHARS
        assert _query(url)[key][0].endswith("\u2026")


# K15
@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        json.dumps({"schema": 2, "ts": 1, "command": "skylos", "exit_code": 2}),
        json.dumps({"schema": 1, "ts": "x", "command": "skylos", "exit_code": 2}),
        json.dumps(
            {"schema": 1, "ts": int(time.time()), "command": "rm -rf", "exit_code": 2}
        ),
        "[]",
    ],
)
def test_bad_records_are_treated_as_none(home, content):
    path = _record_file(home)
    path.parent.mkdir()
    assert write_text_no_symlink(path, content)
    assert rc.load_last_failure() is None
    _code, output, _opened = _run([])
    assert "Last error  none recorded" in output


def test_old_records_are_ignored_and_rewritten_private(home):
    assert rc.record_failure(["skylos", "--bad"], 2, now=time.time() - 25 * 3600)
    assert rc.load_last_failure() is None

    path = _record_file(home)
    os.chmod(path, 0o644)
    assert write_text_no_symlink(path, "{corrupt")
    assert rc.record_failure(["skylos", "--worse"], 3)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert rc.load_last_failure()["command"] == "skylos --worse"
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]


# K16
@pytest.mark.parametrize(
    "value", ["C:\\Users\\bob\\repo", "C:/Users/bob/repo", "repo\\sub", "D:"]
)
def test_windows_paths_are_masked(value):
    assert rc.redact_argv(["skylos.exe", value]) == "skylos <path>"


# K17
def test_help_lists_feedback_under_utility():
    from skylos.cli_core.dispatch import dispatch_early_command
    from skylos.ui.help import (
        COMMANDS,
        print_command_overview,
        print_flat_commands,
    )

    entries = [item for item in COMMANDS if item["name"].startswith("skylos feedback")]
    assert len(entries) == 1
    assert entries[0]["group"] == "Utility"

    console = Console(record=True, width=200)
    print_flat_commands(console)
    flat = console.export_text()
    assert "skylos feedback" in flat
    assert "Report a problem: skylos feedback" in flat

    console = Console(record=True, width=200)
    print_command_overview(console)
    assert "Report a problem: skylos feedback" in console.export_text()

    console = Console(record=True, width=200)
    namespace = {"_run_command_overview": lambda _argv: 0}
    assert (
        dispatch_early_command(
            ["feedback", "--help"], namespace, console_factory=lambda: console
        )
        == 0
    )
    text = console.export_text()
    assert "skylos feedback [--github] [--print]" in text
    assert "you review it before sending" in text


# K18
def test_symlinked_skylos_dir_is_not_followed(home, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (Path(os.path.realpath(home)) / ".skylos").symlink_to(target)

    assert rc.record_failure(["skylos", "--bad"], 2) is False
    assert list(target.iterdir()) == []
    assert rc.load_last_failure() is None


def test_symlinked_record_file_is_not_followed(home, tmp_path):
    target = tmp_path / "victim.txt"
    target.write_text("original")
    path = _record_file(home)
    path.parent.mkdir()
    path.symlink_to(target)

    assert rc.record_failure(["skylos", "--bad"], 2) is False
    assert target.read_text() == "original"
    assert path.is_symlink()
    assert rc.load_last_failure() is None


def test_recording_never_raises_without_a_home(monkeypatch):
    monkeypatch.setattr(rc, "record_path", lambda home=None: None)
    assert rc.record_failure(["skylos", "--bad"], 2) is False

    def explode(home=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(rc, "record_path", explode)
    assert rc.record_failure(["skylos", "--bad"], 2) is False


def test_frames_outside_the_package_are_not_described(tmp_path):
    assert entry._describe_frame(str(tmp_path / "x.py"), 3, "f") is None
    inside = os.path.join(os.path.dirname(skylos.__file__), "cli.py")
    assert entry._describe_frame(inside, 12, "main") == "skylos/cli.py:12 in main"
