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
