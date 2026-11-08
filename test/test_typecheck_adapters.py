from __future__ import annotations

import json
import os
import shutil
import sys

import pytest

from skylos.typecheck import adapters


def _config(root, checker):
    name, source = {
        "mypy": ("mypy.ini", "[mypy]\nfiles = app.py\n"),
        "pyright": ("pyrightconfig.json", '{"include":["app.py"]}'),
        "tsc": ("tsconfig.json", '{"files":["app.ts"]}'),
        "pyrefly": ("pyrefly.toml", 'project-includes = ["app.py"]\n'),
    }[checker]
    (root / name).write_text(source)
    return name


def _executable(root, name, body="pass"):
    path = root / ".venv" / "bin" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(0o755)
    return path


def _run_result(tmp_path, monkeypatch, checker, stdout, code=0, stderr=""):
    _config(tmp_path, checker)
    _executable(tmp_path, checker)
    commands = []

    def run(command, root, timeout):
        commands.append(command)
        return {
            "stdout": stdout.encode(),
            "stderr": stderr.encode(),
            "returncode": code,
            "reason": "",
        }

    monkeypatch.setattr(adapters, "_run_bounded", run)
    return adapters.run_project_checker(tmp_path), commands


def test_discovery_never_guesses_from_source_files_or_executes_tools(
    tmp_path, monkeypatch
):
    (tmp_path / "app.py").write_text("x: int = 'wrong'\n")
    _executable(tmp_path, "mypy", 'raise AssertionError("discovery executed checker")')
    monkeypatch.setattr(adapters.shutil, "which", lambda name: None)
    plan = adapters.discover_checker(tmp_path)
    assert plan["status"] == "not_configured"
    assert plan["command"] == []


@pytest.mark.parametrize("checker", ["mypy", "pyright", "tsc", "pyrefly"])
def test_discovery_prefers_the_installed_project_tool_and_builds_project_command(
    tmp_path, monkeypatch, checker
):
    config = _config(tmp_path, checker)
    executable = _executable(tmp_path, checker)
    monkeypatch.setattr(adapters.shutil, "which", lambda name: "/unrelated/tool")
    plan = adapters.discover_checker(tmp_path)
    assert plan["status"] == "ready"
    assert plan["checker"] == checker
    assert plan["executable"] == str(executable.resolve())
    assert config in plan["config_files"]
    assert len(plan["config_fingerprints"][config]) == 64
    assert "app.py" not in plan["command"] and "app.ts" not in plan["command"]
    if checker == "tsc":
        assert plan["command"][1:] == [
            "--project",
            "tsconfig.json",
            "--noEmit",
            "--pretty",
            "false",
        ]
    if checker == "mypy":
        assert "." not in plan["command"]  # mypy.ini owns the selected files


def test_node_modules_checker_is_used_before_path(tmp_path, monkeypatch):
    _config(tmp_path, "tsc")
    executable = tmp_path / "node_modules/.bin/tsc"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setattr(adapters.shutil, "which", lambda name: "/unrelated/tsc")
    assert adapters.discover_checker(tmp_path)["executable"] == str(executable)


def test_multiple_declared_checkers_require_selection_and_pyproject_can_select(
    tmp_path,
):
    _config(tmp_path, "mypy")
    _config(tmp_path, "tsc")
    _executable(tmp_path, "mypy")
    assert adapters.discover_checker(tmp_path)["status"] == "incomplete"
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos.type_check]\nchecker = "mypy"\n'
    )
    plan = adapters.discover_checker(tmp_path)
    assert plan["status"] == "ready" and plan["checker"] == "mypy"
    assert "pyproject.toml" in plan["config_files"]


def test_missing_checker_does_not_pass_and_override_reuses_installed_binary(
    tmp_path, monkeypatch
):
    _config(tmp_path, "mypy")
    monkeypatch.setattr(adapters.shutil, "which", lambda name: None)
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "incomplete" and not result["complete"]
    assert result["reason"] == "checker_unavailable"
    installed = _executable(
        tmp_path / "tools", "mypy", 'print("Success: no issues found in 1 source file")'
    )
    monkeypatch.setattr(
        adapters,
        "_run_bounded",
        lambda *args: {
            "stdout": b"Success: no issues found in 1 source file\n",
            "stderr": b"",
            "returncode": 0,
            "reason": "",
        },
    )
    result = adapters.run_project_checker(tmp_path, executable_override=str(installed))
    assert result["status"] == "pass" and result["complete"]
    assert result["command"][0] == str(installed)


@pytest.mark.parametrize("checker", ["tsc", "pyright"])
def test_config_inheritance_is_fingerprinted_and_refreshed(tmp_path, checker):
    name = _config(tmp_path, checker)
    (tmp_path / name).write_text('{"extends":"./base.json"}')
    base = tmp_path / "base.json"
    base.write_text('{"compilerOptions":{"strict":true}}')
    first = adapters.discover_checker(tmp_path)
    assert set(first["config_files"]) == {name, "base.json"}
    base.write_text('{"compilerOptions":{"strict":false}}')
    second = adapters.discover_checker(tmp_path)
    assert (
        first["config_fingerprints"]["base.json"]
        != second["config_fingerprints"]["base.json"]
    )


def test_pyright_pyproject_inheritance_is_included(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.pyright]\nextends = "base.json"\n')
    (tmp_path / "base.json").write_text('{"include":["app.py"]}')
    plan = adapters.discover_checker(tmp_path)
    assert set(plan["config_files"]) == {"pyproject.toml", "base.json"}


def test_pyrefly_native_baseline_contents_are_checker_configuration(tmp_path):
    (tmp_path / "pyrefly.toml").write_text('baseline = "baseline.json"\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"errors":[]}')
    first = adapters.discover_checker(tmp_path)
    assert set(first["config_files"]) == {"pyrefly.toml", "baseline.json"}
    baseline.write_text('{"errors":[{"suppressed":true}]}')
    second = adapters.discover_checker(tmp_path)
    assert first["config_fingerprints"] != second["config_fingerprints"]


def test_unreadable_pyrefly_native_baseline_cannot_be_compared(tmp_path):
    (tmp_path / "pyrefly.toml").write_text('baseline = "missing.json"\n')
    _executable(tmp_path, "pyrefly")
    plan = adapters.discover_checker(tmp_path)
    assert plan["status"] == "ready" and plan["comparison_supported"] is False


def test_executable_fingerprint_refreshes_without_version_subprocess(tmp_path):
    _config(tmp_path, "mypy")
    executable = _executable(tmp_path, "mypy")
    first = adapters.discover_checker(tmp_path)
    executable.write_text(f'#!{sys.executable}\nprint("changed")\n')
    second = adapters.discover_checker(tmp_path)
    assert (
        first["executable_fingerprint"]["sha256"]
        != second["executable_fingerprint"]["sha256"]
    )


def test_checker_replacement_during_execution_is_incomplete(tmp_path, monkeypatch):
    _config(tmp_path, "mypy")
    executable = _executable(tmp_path, "mypy")

    def run(*args):
        executable.write_text(f'#!{sys.executable}\nprint("changed")\n')
        return {
            "stdout": b"Success: no issues found in 1 source file\n",
            "stderr": b"",
            "returncode": 0,
            "reason": "",
        }

    monkeypatch.setattr(adapters, "_run_bounded", run)
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "incomplete" and not result["complete"]


def test_config_replacement_during_execution_is_incomplete(tmp_path, monkeypatch):
    name = _config(tmp_path, "mypy")
    _executable(tmp_path, "mypy")

    def run(*args):
        (tmp_path / name).write_text("[mypy]\nignore_errors = true\n")
        return {
            "stdout": b"Success: no issues found in 1 source file\n",
            "stderr": b"",
            "returncode": 0,
            "reason": "",
        }

    monkeypatch.setattr(adapters, "_run_bounded", run)
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "incomplete" and not result["complete"]


@pytest.mark.parametrize(
    "source",
    [
        '{"extends":"./missing.json"}',
        '{"extends":"./tsconfig.json"}',
        '{"references":[{"path":"./child"}],"files":[]}',
        '{"extends":"@company/tsconfig","references":[{"path":"./child"}],"files":[]}',
    ],
)
def test_unresolved_cyclic_or_solution_config_is_incomplete(tmp_path, source):
    (tmp_path / "tsconfig.json").write_text(source)
    _executable(tmp_path, "tsc", 'raise AssertionError("invalid setup was executed")')
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "incomplete" and not result["complete"]


def test_package_config_can_run_current_check_but_disables_baseline_attribution(
    tmp_path, monkeypatch
):
    (tmp_path / "tsconfig.json").write_text('{"extends":"@company/tsconfig"}')
    _executable(tmp_path, "tsc")
    monkeypatch.setattr(
        adapters,
        "_run_bounded",
        lambda *args: {"stdout": b"", "stderr": b"", "returncode": 0, "reason": ""},
    )
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "pass" and result["complete"]
    assert result["comparison_supported"] is False
    assert result["config_files"] == ["tsconfig.json"]


@pytest.mark.skipif(
    os.name != "posix", reason="Node shebang integration fixture is POSIX"
)
def test_actual_installed_tsc_clean_project_if_available(tmp_path):
    executable = os.environ.get("SKYLOS_TEST_TSC") or shutil.which("tsc")
    if not executable:
        pytest.skip("tsc is not installed; no installation attempted")
    _config(tmp_path, "tsc")
    (tmp_path / "app.ts").write_text("const value: number = 42;\n")
    result = adapters.run_project_checker(
        tmp_path, checker="tsc", executable_override=executable
    )
    assert result["status"] == "pass" and result["complete"]
    assert not (tmp_path / "app.js").exists()


def test_config_json_comments_and_trailing_commas_are_supported(tmp_path):
    (tmp_path / "tsconfig.json").write_text(
        '{ // comment\n "compilerOptions":{"strict":true,},}'
    )
    _executable(tmp_path, "tsc")
    assert adapters.discover_checker(tmp_path)["status"] == "ready"


def test_mypy_preserves_errors_notes_codes_and_project_config(tmp_path, monkeypatch):
    output = 'app.py:2:7: error: Incompatible types in assignment  [assignment]\napp.py:2:7: note: Revealed type is "str"\nFound 1 error in 1 file (checked 1 source file)\n'
    result, commands = _run_result(tmp_path, monkeypatch, "mypy", output, 1)
    assert result["status"] == "fail" and result["complete"]
    assert result["error_count"] == 1
    assert result["diagnostics"][0] == {
        "file": "app.py",
        "line": 2,
        "column": 7,
        "code": "assignment",
        "message": "Incompatible types in assignment",
        "severity": "error",
    }
    assert result["diagnostics"][1]["severity"] == "note"
    assert commands[0][commands[0].index("--config-file") + 1] == "mypy.ini"


def test_tsc_preserves_multiline_type_diagnostic(tmp_path, monkeypatch):
    output = "src/app.ts(3,5): error TS2322: Type 'number' is not assignable.\n  Target requires 'string'.\n"
    result, _ = _run_result(tmp_path, monkeypatch, "tsc", output, 1)
    assert result["status"] == "fail" and result["complete"]
    assert result["diagnostics"][0]["code"] == "TS2322"
    assert "Target requires" in result["diagnostics"][0]["message"]


def test_tsc_exit_two_with_type_errors_is_a_complete_failure(tmp_path, monkeypatch):
    result, _ = _run_result(
        tmp_path,
        monkeypatch,
        "tsc",
        "app.ts(1,1): error TS2322: Incompatible assignment.\n",
        2,
    )
    assert result["status"] == "fail" and result["complete"]


def _pyright_output(file="app.py", *, errors=1, files=1):
    return json.dumps(
        {
            "generalDiagnostics": [
                {
                    "file": file,
                    "severity": "error",
                    "message": "Expected int, got str",
                    "range": {
                        "start": {"line": 1, "character": 2},
                        "end": {"line": 1, "character": 4},
                    },
                    "rule": "reportAssignmentType",
                }
            ],
            "summary": {
                "filesAnalyzed": files,
                "errorCount": errors,
                "warningCount": 0,
                "informationCount": 0,
            },
        }
    )


def test_pyright_machine_diagnostics_are_normalized_without_downgrading_errors(
    tmp_path, monkeypatch
):
    result, _ = _run_result(tmp_path, monkeypatch, "pyright", _pyright_output(), 1)
    assert result["status"] == "fail" and result["complete"]
    assert result["diagnostics"][0]["line"] == 2
    assert result["diagnostics"][0]["column"] == 3
    assert result["diagnostics"][0]["severity"] == "error"


def test_pyrefly_machine_diagnostics_are_preserved(tmp_path, monkeypatch):
    output = json.dumps(
        {
            "errors": [
                {
                    "path": "app.py",
                    "line": 2,
                    "column": 4,
                    "code": -2,
                    "name": "bad-assignment",
                    "description": "str is not assignable to int",
                    "severity": "error",
                }
            ]
        }
    )
    result, _ = _run_result(tmp_path, monkeypatch, "pyrefly", output, 1)
    assert result["status"] == "fail" and result["complete"]
    assert result["diagnostics"][0]["code"] == "bad-assignment"


def test_json_stderr_cannot_hide_a_checker_crash(tmp_path, monkeypatch):
    result, _ = _run_result(
        tmp_path,
        monkeypatch,
        "pyright",
        '{"generalDiagnostics":[],"summary":{"filesAnalyzed":1,"errorCount":0,"warningCount":0}}',
        0,
        "fatal: checker crashed",
    )
    assert result["status"] == "incomplete" and not result["complete"]


def test_project_configuration_cannot_turn_an_error_into_a_pass(tmp_path, monkeypatch):
    output = "app.py:1:1: error: Invalid value  [assignment]\nSuccess: no issues found in 1 source file\n"
    result, _ = _run_result(tmp_path, monkeypatch, "mypy", output, 0)
    assert result["status"] == "incomplete" and not result["complete"]


def test_located_tsc_configuration_error_is_not_a_preexisting_type_error(
    tmp_path, monkeypatch
):
    result, _ = _run_result(
        tmp_path,
        monkeypatch,
        "tsc",
        "tsconfig.json(1,10): error TS1005: '}' expected.\n",
        2,
    )
    assert result["status"] == "incomplete" and not result["complete"]


def test_explicit_skylos_mypy_selection_does_not_fake_a_mypy_config_section(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos.type_check]\nchecker = "mypy"\n'
    )
    _executable(tmp_path, "mypy")
    plan = adapters.discover_checker(tmp_path)
    assert plan["status"] == "ready"
    assert plan["command"][plan["command"].index("--config-file") + 1] == ""
    assert plan["command"][-1] == "."


@pytest.mark.parametrize(
    ("checker", "output", "code"),
    [
        ("mypy", "Success: no issues found in 1 source file\n", 0),
        ("tsc", "", 0),
        (
            "pyright",
            '{"generalDiagnostics":[],"summary":{"filesAnalyzed":1,"errorCount":0,"warningCount":0}}',
            0,
        ),
        ("pyrefly", '{"errors":[]}', 0),
    ],
)
def test_recognized_clean_project_report_passes(
    tmp_path, monkeypatch, checker, output, code
):
    result, _ = _run_result(tmp_path, monkeypatch, checker, output, code)
    assert result["status"] == "pass" and result["complete"]
    assert result["diagnostics"] == []


@pytest.mark.parametrize(
    ("checker", "output", "code"),
    [
        ("mypy", "", 0),
        ("mypy", "INTERNAL ERROR", 1),
        ("mypy", "Found 1 error in 1 file (checked 1 source file)", 0),
        ("mypy", "Success: no issues found in 0 source files", 0),
        ("mypy", "Success: no issues found in 1 source file\n", 2),
        ("tsc", "error TS5058: The specified path does not exist: tsconfig.json", 1),
        ("tsc", "some unexpected text", 0),
        ("pyright", "{}", 0),
        ("pyright", "not json", 0),
        ("pyright", _pyright_output(errors=0), 1),
        ("pyright", _pyright_output(files=0), 1),
        ("pyright", _pyright_output(file="../outside.py"), 1),
        ("pyrefly", '{"errors":[{"path":"app.py"}]}', 1),
        ("pyrefly", '{"errors":[]}', 1),
    ],
)
def test_crashes_malformed_reports_and_inconsistent_status_never_pass(
    tmp_path, monkeypatch, checker, output, code
):
    result, _ = _run_result(tmp_path, monkeypatch, checker, output, code)
    assert result["status"] == "incomplete" and not result["complete"]


@pytest.mark.skipif(os.name != "posix", reason="executable Python-script fixture")
def test_real_checker_process_uses_project_cwd_and_reports_a_failure(tmp_path):
    _config(tmp_path, "mypy")
    _executable(
        tmp_path,
        "mypy",
        "import os, sys\nassert os.path.isfile('mypy.ini')\nprint('app.py:1:1: error: bad assignment  [assignment]')\nprint('Found 1 error in 1 file (checked 1 source file)')\nsys.exit(1)",
    )
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "fail" and result["complete"]


@pytest.mark.skipif(os.name != "posix", reason="executable Python-script fixture")
def test_timeout_and_output_limit_are_incomplete(tmp_path, monkeypatch):
    _config(tmp_path, "mypy")
    executable = _executable(tmp_path, "mypy", "import time\ntime.sleep(10)")
    result = adapters.run_project_checker(tmp_path, timeout_seconds=0.05)
    assert result["status"] == "incomplete" and result["reason"] == "timeout"
    monkeypatch.setattr(adapters, "MAX_OUTPUT_BYTES", 1024)
    executable.write_text(
        f'#!{sys.executable}\nimport sys\nsys.stdout.write("x" * 100000)\n'
    )
    result = adapters.run_project_checker(tmp_path)
    assert result["status"] == "incomplete" and result["reason"] == "output_limit"


@pytest.mark.skipif(
    os.name != "posix", reason="Node shebang integration fixture is POSIX"
)
def test_actual_installed_tsc_if_available(tmp_path):
    executable = os.environ.get("SKYLOS_TEST_TSC") or shutil.which("tsc")
    if not executable:
        pytest.skip("tsc is not installed on PATH; no installation attempted")
    _config(tmp_path, "tsc")
    (tmp_path / "app.ts").write_text('const value: number = "bad";\n')
    result = adapters.run_project_checker(
        tmp_path, checker="tsc", executable_override=executable
    )
    assert result["status"] == "fail" and result["complete"]
    assert any(d["code"] == "TS2322" for d in result["diagnostics"])
