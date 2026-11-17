"""Node preload flags identify exact consumers, not arbitrary path arguments."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.file_references import _shell_load_paths


@pytest.mark.parametrize("flag", ["--import", "--require"])
@pytest.mark.parametrize("runtime", ["node", "nodejs", "/usr/bin/node"])
def test_node_equals_preload_is_a_source_consumer(flag, runtime):
    command = f"{runtime} {flag}=./src/register.js src/worker.js src/data.js"
    assert list(_shell_load_paths(command)) == ["./src/register.js", "src/worker.js"]


@pytest.mark.parametrize(
    "command, expected",
    [
        ("echo node --import=./src/register.js src/worker.js", []),
        ("unknown --import=./src/register.js src/worker.js", []),
        ("node --title=./src/register.js src/worker.js", ["src/worker.js"]),
        ("node src/worker.js --import=./src/register.js", ["src/worker.js"]),
        ("node --import= src/worker.js", ["src/worker.js"]),
        ("deno --import=./src/register.js src/worker.js", ["src/worker.js"]),
        ("node -- --import=./src/register.js", ["--import=./src/register.js"]),
        ("node -- --require=./src/register.js", ["--require=./src/register.js"]),
        ("node -- src/worker.js src/data.js", ["src/worker.js"]),
        ("node --", []),
    ],
)
def test_preload_lookalikes_do_not_load_files(command, expected):
    assert list(_shell_load_paths(command)) == expected


@pytest.mark.parametrize("flag", ["--import", "--require"])
def test_shell_preload_keeps_loaded_file_and_reports_unused_siblings(tmp_path, flag):
    (tmp_path / "package.json").write_text('{"private": true}')
    (tmp_path / "launch.sh").write_text(
        f"node {flag}=./src/register.js src/worker.js src/data.js\n"
    )
    source = tmp_path / "src"
    source.mkdir()
    (source / "register.js").write_text("globalThis.registered = true;\n")
    (source / "worker.js").write_text("console.log('worker');\n")
    (source / "data.js").write_text("globalThis.data = true;\n")
    (source / "retired.js").write_text("globalThis.retired = true;\n")
    result = json.loads(
        analyze(str(tmp_path), conf=60, grep_verify=False, trace_file=False)
    )
    assert not result.get("analysis_errors")
    assert result["analysis_summary"]["total_files"] >= 4
    unused = {Path(row["file"]).name for row in result.get("unused_files", [])}
    assert "register.js" not in unused
    assert "worker.js" not in unused
    assert {"data.js", "retired.js"} <= unused


def test_options_after_terminator_do_not_rescue_preload_lookalike(tmp_path):
    (tmp_path / "package.json").write_text('{"private": true}')
    (tmp_path / "launch.sh").write_text("node -- --import=./src/register.js\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/register.js").write_text("globalThis.registered = true;\n")
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    assert not result.get("analysis_errors")
    assert "register.js" in {
        Path(row["file"]).name for row in result.get("unused_files", [])
    }
