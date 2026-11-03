"""Expanded command sinks preserve provider identity and shell context proofs."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


_SINKS = [
    pytest.param("native_os.popen(command)", id="popen-alias"),
    pytest.param("output(command)", id="getoutput-import-alias"),
    pytest.param("sp.getstatusoutput(command)", id="getstatusoutput-alias"),
    pytest.param("aio.create_subprocess_shell(command)", id="async-shell-alias"),
    pytest.param("sp.run(command, shell=flag)", id="dynamic-shell-alias"),
    pytest.param(
        "native_os.execv('/bin/sh', ['sh', '-c', command])", id="execv-shell-alias"
    ),
    pytest.param(
        "native_os.execl('/bin/sh', 'sh', '-c', command)", id="execl-shell-alias"
    ),
    pytest.param("pty.spawn(['/bin/sh', '-c', command])", id="pty-shell"),
    pytest.param(
        "aio.create_subprocess_exec('/bin/sh', '-c', command)",
        id="async-exec-shell-alias",
    ),
    pytest.param("sp.run(['/bin/sh', '-c', command])", id="subprocess-argv-shell"),
]


def _source(sink):
    lines = [
        "import os as native_os",
        "import subprocess as sp",
        "import asyncio as aio",
        "import pty",
        "from shlex import quote as q",
        "from subprocess import getoutput as output",
    ]
    sink_lines = {}
    for name, statements in {
        "quoted_argument": ["command = 'echo ' + q(value)"],
        "broken_quote_context": ["command = 'echo \"' + q(value) + '\"'"],
        "fixed_branches": [
            "if value:",
            "    command = 'echo yes'",
            "else:",
            "    command = 'echo no'",
        ],
        "unquoted_branch": [
            "if flag:",
            "    command = 'echo ' + q(value)",
            "else:",
            "    command = 'echo ' + value",
        ],
    }.items():
        lines.append(f"def {name}(value, flag):")
        lines.extend("    " + line for line in statements)
        lines.append("    " + sink)
        sink_lines[name] = len(lines)
    return "\n".join(lines) + "\n", sink_lines


@pytest.mark.parametrize("sink", _SINKS)
@pytest.mark.parametrize("project_provider", [False, True], ids=["native", "lookalike"])
def test_expanded_sinks_preserve_command_proofs(
    tmp_path, monkeypatch, sink, project_provider
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    source, sink_lines = _source(sink)
    path = write_fixture(root, "app.py", source)
    if project_provider:
        write_fixture(root, "shlex.py", "def quote(value):\n    return value\n")
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
    expected = {
        sink_lines["broken_quote_context"],
        sink_lines["unquoted_branch"],
    }
    if project_provider:
        expected.add(sink_lines["quoted_argument"])
    assert sorted(row["line"] for row in raw) == sorted(expected)
    assert sorted(row["line"] for row in listed) == sorted(expected)
    assert all(row["severity"] == "CRITICAL" for row in raw + listed)
    assert all(
        row["listing"]["listed"] and row["metadata"]["security_trace"] for row in listed
    )
    gate = {"gate": {"max_high": 1000, "max_security": 1000, "max_critical": 0}}
    command_report = {**report, "danger": listed}
    assert check_gate(command_report, gate)[0] is False
    quiet_report = {
        **report,
        "danger": [
            row for row in listed if row["line"] == sink_lines["fixed_branches"]
        ],
    }
    assert check_gate(quiet_report, gate)[0] is True
