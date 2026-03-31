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
