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
