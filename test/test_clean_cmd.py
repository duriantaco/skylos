import json
from unittest.mock import Mock, patch

from skylos.commands import clean_cmd


def test_clean_command_remove_import_uses_source_and_line(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nimport sys\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {
                "name": "os",
                "file": str(target),
                "line": 1,
                "confidence": 100,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=["r", "y"]),
        patch(
            "skylos.commands.clean_cmd.remove_unused_import_cst",
            return_value=("import sys\n", True),
        ) as remove_import,
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path)])

    assert exit_code == 0
    remove_import.assert_called_once_with("import os\nimport sys\n", "os", 1)
    assert target.read_text(encoding="utf-8") == "import sys\n"


def test_clean_command_comment_out_function_uses_source_and_line(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(
        "def unused():\n    return 1\n\ndef used():\n    return 2\n",
        encoding="utf-8",
    )
    result = {
        "unused_functions": [
            {
                "name": "unused",
                "file": str(target),
                "line": 1,
                "confidence": 100,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=["c", "y"]),
        patch(
            "skylos.commands.clean_cmd.comment_out_unused_function_cst",
            return_value=("# SKYLOS DEADCODE\npass\n", True),
        ) as comment_out,
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path)])

    assert exit_code == 0
    comment_out.assert_called_once_with(
        "def unused():\n    return 1\n\ndef used():\n    return 2\n",
        "unused",
        1,
    )
    assert target.read_text(encoding="utf-8") == "# SKYLOS DEADCODE\npass\n"


def test_clean_command_refuses_symlink_outside_scan_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("def unused():\n    return 1\n", encoding="utf-8")
    link = repo / "link.py"
    link.symlink_to(outside)
    result = {
        "unused_functions": [
            {
                "name": "unused",
                "file": str(link),
                "line": 1,
                "confidence": 100,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=["c", "y"]),
        patch(
            "skylos.commands.clean_cmd.comment_out_unused_function_cst",
            return_value=("# SKYLOS DEADCODE\npass\n", True),
        ) as comment_out,
    ):
        exit_code = clean_cmd.run_clean_command([str(repo)])

    assert exit_code == 0
    comment_out.assert_not_called()
    assert outside.read_text(encoding="utf-8") == "def unused():\n    return 1\n"


def test_clean_command_skips_unsupported_findings_from_prompt(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(
        "def unused():\n    return 1\n\nvalue = 1\n",
        encoding="utf-8",
    )
    result = {
        "unused_functions": [
            {
                "name": "unused",
                "file": str(target),
                "line": 1,
                "confidence": 100,
            }
        ],
        "unused_variables": [
            {
                "name": "value",
                "file": str(target),
                "line": 4,
                "confidence": 90,
            }
        ],
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=["r", "y"]),
        patch(
            "skylos.commands.clean_cmd.remove_unused_function_cst",
            return_value=("value = 1\n", True),
        ) as remove_function,
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path)])

    assert exit_code == 0
    remove_function.assert_called_once_with(
        "def unused():\n    return 1\n\nvalue = 1\n",
        "unused",
        1,
    )
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Skipping 1 unsupported dead code item" in printed
    assert target.read_text(encoding="utf-8") == "value = 1\n"


def test_clean_command_dry_run_writes_nothing_and_uses_default_confidence(tmp_path):
    target = tmp_path / "sample.py"
    original = "import os\nimport sys\n"
    target.write_text(original, encoding="utf-8")
    result = {
        "unused_imports": [
            {
                "name": "os",
                "file": str(target),
                "line": 1,
                "confidence": 95,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)) as analyze,
        patch("skylos.commands.clean_cmd.remove_unused_import_cst") as remove_import,
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--dry-run"])

    assert exit_code == 0
    analyze.assert_called_once()
    assert analyze.call_args.args == (str(tmp_path),)
    assert analyze.call_args.kwargs["conf"] == 80
    assert ".git" in analyze.call_args.kwargs["exclude_folders"]
    remove_import.assert_not_called()
    assert target.read_text(encoding="utf-8") == original
    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Dry run" in printed
    assert "os" in printed


def test_clean_command_merges_config_and_cli_excludes(tmp_path):
    result = {
        "unused_imports": [],
        "unused_functions": [],
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch(
            "skylos.commands.clean_cmd.load_config",
            return_value={"exclude": ["generated", "vendor"]},
        ),
        patch(
            "skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)
        ) as analyze,
    ):
        exit_code = clean_cmd.run_clean_command(
            [
                str(tmp_path),
                "--dry-run",
                "--no-default-excludes",
                "--exclude",
                "build",
                "--exclude-folder",
                "legacy",
                "--include-folder",
                "vendor",
            ]
        )

    assert exit_code == 0
    assert set(analyze.call_args.kwargs["exclude_folders"]) == {
        "build",
        "generated",
        "legacy",
    }


def test_clean_command_apply_removes_without_prompt(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nimport sys\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {
                "name": "os",
                "file": str(target),
                "line": 1,
                "confidence": 95,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=AssertionError("should not prompt")),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--apply"])

    assert exit_code == 0
    assert target.read_text(encoding="utf-8") == "import sys\n"


def test_clean_command_apply_filters_by_confidence(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nimport sys\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {
                "name": "os",
                "file": str(target),
                "line": 1,
                "confidence": 70,
            },
            {
                "name": "sys",
                "file": str(target),
                "line": 2,
                "confidence": 95,
            },
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command(
            [str(tmp_path), "--apply", "--confidence", "80"]
        )

    assert exit_code == 0
    assert target.read_text(encoding="utf-8") == "import os\n"


def test_clean_command_apply_filters_by_type(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text(
        "import os\n\ndef unused():\n    return 1\n",
        encoding="utf-8",
    )
    result = {
        "unused_imports": [
            {
                "name": "os",
                "file": str(target),
                "line": 1,
                "confidence": 95,
            }
        ],
        "unused_functions": [
            {
                "name": "unused",
                "file": str(target),
                "line": 3,
                "confidence": 95,
            }
        ],
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command(
            [str(tmp_path), "--apply", "--types", "imports"]
        )

    assert exit_code == 0
    assert target.read_text(encoding="utf-8") == "\ndef unused():\n    return 1\n"


def test_clean_command_apply_comment_out_uses_comment_transform(tmp_path):
    target = tmp_path / "sample.py"
    original = "def unused():\n    return 1\n"
    target.write_text(original, encoding="utf-8")
    result = {
        "unused_functions": [
            {
                "name": "unused",
                "file": str(target),
                "line": 1,
                "confidence": 95,
            }
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch(
            "skylos.commands.clean_cmd.comment_out_unused_function_cst",
            return_value=("# SKYLOS DEADCODE\npass\n", True),
        ) as comment_out,
    ):
        exit_code = clean_cmd.run_clean_command(
            [str(tmp_path), "--apply", "--comment-out"]
        )

    assert exit_code == 0
    comment_out.assert_called_once_with(original, "unused", 1)
    assert target.read_text(encoding="utf-8") == "# SKYLOS DEADCODE\npass\n"


def test_clean_command_keeps_analyzer_progress_logs_off_the_screen(
    tmp_path, monkeypatch, caplog
):
    import logging

    analyzer_logger = logging.getLogger("Skylos")
    monkeypatch.setattr(analyzer_logger, "level", logging.NOTSET)
    levels = []

    def analyze(*_args, **_kwargs):
        levels.append(analyzer_logger.getEffectiveLevel())
        analyzer_logger.info("Analyzing 1 files...")
        return json.dumps({})

    with (
        caplog.at_level(logging.INFO),
        patch("skylos.commands.clean_cmd.Console", return_value=Mock()),
        patch("skylos.commands.clean_cmd.run_analyze", side_effect=analyze),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--dry-run"])

    assert exit_code == 0
    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert analyzer_logger.level == logging.NOTSET


def _printed(console):
    return "\n".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )


def _python_and_typescript_project(tmp_path):
    legacy = tmp_path / "legacy.py"
    legacy.write_text("import os\n\ndef old():\n    return 1\n", encoding="utf-8")
    checkout = tmp_path / "checkout.ts"
    checkout_source = (
        "export function renderTotal(total: number): string {\n"
        "  return `$${total}`;\n"
        "}\n\n"
        "function formatLegacyPrice(total: number): string {\n"
        '  return "USD " + total;\n'
        "}\n"
    )
    checkout.write_text(checkout_source, encoding="utf-8")
    result = {
        "unused_functions": [
            {"name": "old", "file": str(legacy), "line": 3, "confidence": 90},
            {
                "name": "formatLegacyPrice",
                "file": str(checkout),
                "line": 5,
                "confidence": 100,
            },
        ],
        "unused_imports": [
            {"name": "os", "file": str(legacy), "line": 1, "confidence": 100}
        ],
    }
    return legacy, checkout, checkout_source, result


def test_clean_command_dry_run_does_not_offer_non_python_files(tmp_path):
    legacy, checkout, checkout_source, result = _python_and_typescript_project(tmp_path)
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--dry-run"])

    assert exit_code == 0
    printed = _printed(console)
    assert "would remove 2 dead code items" in printed
    assert "L5 function formatLegacyPrice" not in printed
    assert "Not offering 1 dead code item in files skylos clean cannot edit" in printed
    assert "checkout.ts (1 dead code item): not a Python file" in printed
    assert checkout.read_text(encoding="utf-8") == checkout_source


def test_clean_command_apply_never_edits_non_python_files(tmp_path):
    legacy, checkout, checkout_source, result = _python_and_typescript_project(tmp_path)
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--apply"])

    assert exit_code == 0
    assert legacy.read_text(encoding="utf-8") == "\n"
    assert checkout.read_text(encoding="utf-8") == checkout_source
    printed = _printed(console)
    assert "Removed 2 item(s)" in printed
    assert "Failed" not in printed


def test_clean_command_does_not_offer_python_it_cannot_parse(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("import os\ndef old(:\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {"name": "os", "file": str(broken), "line": 1, "confidence": 100}
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--apply"])

    assert exit_code == 0
    assert broken.read_text(encoding="utf-8") == "import os\ndef old(:\n"
    printed = _printed(console)
    assert "the Python rewriter cannot parse it" in printed
    assert "No actionable dead code edits found." in printed


def test_clean_command_apply_reports_a_failed_edit_and_exits_nonzero(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nimport sys\n\ndef old():\n    return 1\n")
    result = {
        "unused_imports": [
            {"name": "os", "file": str(target), "line": 1, "confidence": 100}
        ],
        "unused_functions": [
            {"name": "old", "file": str(target), "line": 4, "confidence": 100}
        ],
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch(
            "skylos.commands.clean_cmd.remove_unused_function_cst",
            side_effect=RuntimeError("rewriter broke"),
        ),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--apply"])

    assert exit_code == 1
    assert target.read_text(encoding="utf-8") == (
        "import sys\n\ndef old():\n    return 1\n"
    )
    printed = _printed(console)
    assert "Failed to remove old: " in printed
    assert "sample.py:4: rewriter broke" in printed
    assert "Removed 1 item(s)" in printed
    assert "1 edit failed; see the error above." in printed


def test_clean_command_apply_reports_an_edit_that_found_nothing(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import sys\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {"name": "os", "file": str(target), "line": 1, "confidence": 100}
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path), "--apply"])

    assert exit_code == 1
    assert target.read_text(encoding="utf-8") == "import sys\n"
    printed = _printed(console)
    assert "Failed to remove os: no matching import at " in printed
    assert "sample.py:1; the file may have changed since the scan" in printed


def test_clean_command_interactive_failed_edit_exits_nonzero(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nimport sys\n", encoding="utf-8")
    result = {
        "unused_imports": [
            {"name": "os", "file": str(target), "line": 1, "confidence": 100}
        ]
    }
    console = Mock()

    with (
        patch("skylos.commands.clean_cmd.Console", return_value=console),
        patch("skylos.commands.clean_cmd.run_analyze", return_value=json.dumps(result)),
        patch("builtins.input", side_effect=["r", "y"]),
        patch(
            "skylos.commands.clean_cmd.remove_unused_import_cst",
            side_effect=RuntimeError("rewriter broke"),
        ),
    ):
        exit_code = clean_cmd.run_clean_command([str(tmp_path)])

    assert exit_code == 1
    assert target.read_text(encoding="utf-8") == "import os\nimport sys\n"
    assert "1 edit failed" in _printed(console)


def test_python_rewrite_blocker_explains_each_refusal(tmp_path):
    from skylos.remediation.safety import python_rewrite_blocker

    good = tmp_path / "good.py"
    good.write_text("x = 1\n", encoding="utf-8")
    stub = tmp_path / "types.pyi"
    stub.write_text("def f() -> int: ...\n", encoding="utf-8")
    script = tmp_path / "gui.pyw"
    script.write_text("print(1)\n", encoding="utf-8")
    ts = tmp_path / "app.ts"
    ts.write_text("const x = 1;\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(outside)

    assert python_rewrite_blocker(good, root_path=tmp_path) is None
    assert python_rewrite_blocker(stub, root_path=tmp_path) is None
    assert python_rewrite_blocker(script, root_path=tmp_path) is None
    assert python_rewrite_blocker(ts, root_path=tmp_path).startswith(
        "not a Python file"
    )
    assert "symlinked" in python_rewrite_blocker(link, root_path=tmp_path)
    assert python_rewrite_blocker(outside, root_path=tmp_path).startswith(
        "Refusing to modify path outside scan root"
    )
    assert python_rewrite_blocker(tmp_path / "missing.py", root_path=tmp_path)
