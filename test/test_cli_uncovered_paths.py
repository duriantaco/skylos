import json
import sys
import pytest
from unittest.mock import Mock, patch
from rich.panel import Panel

import skylos.cli as cli


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_shorten_path_none():
    assert cli._shorten_path(None) == "?"


def test_shorten_path_relative_to_root(tmp_path):
    root = tmp_path / "proj"
    (root / "a").mkdir(parents=True)
    f = root / "a" / "b.py"
    f.write_text("x=1", encoding="utf-8")

    out = cli._shorten_path(str(f), root_path=str(root))
    assert out.replace("\\", "/") == "a/b.py"


def test_shorten_path_root_is_file(tmp_path):
    root_file = tmp_path / "pyproject.toml"
    root_file.write_text("x", encoding="utf-8")
    f = tmp_path / "src" / "m.py"
    f.parent.mkdir(parents=True)
    f.write_text("x=1", encoding="utf-8")

    out = cli._shorten_path(str(f), root_path=str(root_file))
    assert out.replace("\\", "/") == "src/m.py"


def test_run_init_creates_pyproject_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_console = Mock()

    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_init()

    p = tmp_path / "pyproject.toml"
    assert p.exists()
    content = p.read_text(encoding="utf-8")
    assert "[tool.skylos]" in content
    assert "[tool.skylos.gate]" in content
    assert mock_console.print.called


def test_run_init_resets_existing_tool_section(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text(
        """
[tool.skylos]
complexity = 999

[tool.other]
x = 1
""".strip(),
        encoding="utf-8",
    )

    mock_console = Mock()
    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_init()

    content = py.read_text(encoding="utf-8")
    assert "[tool.other]" in content
    assert "complexity = 10" in content


def test_run_whitelist_requires_pyproject(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_console = Mock()

    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_whitelist(pattern="x")

    assert not (tmp_path / "pyproject.toml").exists()
    assert mock_console.print.called


def test_run_whitelist_show_mode_prints(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.skylos]
exclude = []

[tool.skylos.whitelist]
names = ["a", "b"]

[tool.skylos.whitelist.documented]
"handle_*" = "called via getattr"

[tool.skylos.whitelist.temporary]
"legacy_*" = { reason = "old", expires = "2099-01-01" }
""".strip(),
        encoding="utf-8",
    )

    mock_console = Mock()
    with (
        patch("skylos.cli.Console", return_value=mock_console),
        patch(
            "skylos.cli.load_config",
            return_value={
                "whitelist": ["a", "b"],
                "whitelist_documented": {"handle_*": "called via getattr"},
                "whitelist_temporary": {
                    "legacy_*": {"reason": "old", "expires": "2099-01-01"}
                },
            },
        ),
    ):
        cli.run_whitelist(show=True)

    assert mock_console.print.called


def test_run_whitelist_no_pattern_prints_usage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")

    mock_console = Mock()
    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_whitelist(pattern=None)

    parts = []
    for call in mock_console.print.call_args_list:
        if not call.args:
            continue
        parts.append(str(call.args[0]))
    printed = " ".join(parts)

    assert ("Usage" in printed) or ("Examples" in printed)


def test_run_whitelist_adds_documented_reason(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text("[tool.skylos]\n", encoding="utf-8")

    mock_console = Mock()
    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_whitelist(pattern="handle_*", reason="Called via getattr")

    content = py.read_text(encoding="utf-8")
    assert "[tool.skylos.whitelist.documented]" in content
    assert '"handle_*" = "Called via getattr"' in content


def test_run_whitelist_adds_names_when_section_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text(
        """
[tool.skylos]
exclude = []

[tool.skylos.whitelist]
names = [
    "existing",
]
""".strip(),
        encoding="utf-8",
    )

    mock_console = Mock()
    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_whitelist(pattern="new_name")

    content = py.read_text(encoding="utf-8")
    assert '"new_name",' in content


def test_run_whitelist_creates_names_section_if_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    py = tmp_path / "pyproject.toml"
    py.write_text("[tool.skylos]\n", encoding="utf-8")

    mock_console = Mock()
    with patch("skylos.cli.Console", return_value=mock_console):
        cli.run_whitelist(pattern="dark_logic")

    content = py.read_text(encoding="utf-8")
    assert "[tool.skylos.whitelist]" in content
    assert "names = [" in content
    assert '"dark_logic"' in content


def test_get_git_changed_files_returns_only_existing_py(tmp_path):
    root = tmp_path
    (root / "a.py").write_text("x=1", encoding="utf-8")
    (root / "b.txt").write_text("no", encoding="utf-8")

    def fake_check_output(cmd, cwd=None, stderr=None):
        if cmd[:3] == ["git", "rev-parse", "--is-inside-work-tree"]:
            return b"true"
        if cmd[:3] == ["git", "diff", "--name-only"]:
            return b"a.py\nb.txt\nmissing.py\n"
        raise AssertionError("unexpected cmd")

    with patch("skylos.cli.subprocess.check_output", side_effect=fake_check_output):
        files = cli.get_git_changed_files(root)

    names = []
    for p in files:
        names.append(p.name)
    names.sort()

    assert names == ["a.py"]


def test_get_git_changed_files_on_error_returns_empty(tmp_path):
    with patch("skylos.cli.subprocess.check_output", side_effect=Exception("no git")):
        files = cli.get_git_changed_files(tmp_path)
    assert files == []


def test_estimate_cost_counts_chars(tmp_path):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("abcd", encoding="utf-8")
    f2.write_text("12345678", encoding="utf-8")  # 8 chars

    tokens, usd = cli.estimate_cost([f1, f2])
    assert tokens == pytest.approx((12 / 4), rel=1e-9)
    assert usd > 0


def test_estimate_cost_ignores_read_errors(tmp_path):
    f1 = tmp_path / "a.py"
    f1.write_text("abcd", encoding="utf-8")

    bad = Mock()
    bad.read_text.side_effect = OSError("boom")

    tokens, usd = cli.estimate_cost([f1, bad])
    assert tokens == pytest.approx((4 / 4), rel=1e-9)


def test_main_list_default_excludes_returns_without_analysis(monkeypatch):
    test_args = ["skylos", ".", "--list-default-excludes"]
    fake_logger = Mock()
    fake_logger.console = Mock()

    monkeypatch.setattr(sys, "argv", test_args)

    with patch("skylos.cli.setup_logger", return_value=fake_logger):
        cli.main()

    assert fake_logger.console.print.called


def test_main_writes_sarif_and_prints_json(tmp_path, monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "u", "file": "a.py", "line": 1}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }
    sarif_path = tmp_path / "out.sarif.json"
    test_args = ["skylos", ".", "--sarif", str(sarif_path), "--json"]
    monkeypatch.setattr(sys, "argv", test_args)

    with (
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.SarifExporter") as SarifExporter,
        patch("builtins.print") as p,
    ):
        exp = Mock()
        SarifExporter.return_value = exp

        cli.main()

        exp.write.assert_called_once_with(str(sarif_path))
        p.assert_called_once_with(json.dumps(result))


def test_main_coverage_runs_pytest_then_unittest_on_failure(tmp_path, monkeypatch):
    test_args = ["skylos", str(tmp_path), "--coverage", "--json"]
    monkeypatch.setattr(sys, "argv", test_args)

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    pytest_run = Mock(returncode=1)
    unittest_run = Mock(returncode=0)

    def run_side_effect(cmd, cwd=None, capture_output=None, text=None, **kwargs):
        if cmd[:4] == ["coverage", "run", "-m", "pytest"]:
            return pytest_run
        if cmd[:4] == ["coverage", "run", "-m", "unittest"]:
            return unittest_run
        return Mock(returncode=0)

    with (
        patch("skylos.cli.subprocess.run", side_effect=run_side_effect) as sprun,
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("builtins.print"),
    ):
        cli.main()

    calls = []
    for call in sprun.call_args_list:
        calls.append(call.args[0])

    found_pytest = False
    found_unittest = False

    for cmd in calls:
        if cmd == ["coverage", "run", "-m", "pytest", "-q"]:
            found_pytest = True
        if cmd == ["coverage", "run", "-m", "unittest", "discover"]:
            found_unittest = True

    assert found_pytest is True
    assert found_unittest is True


def test_main_trace_runs_python_c_script(tmp_path, monkeypatch):
    test_args = ["skylos", str(tmp_path), "--trace", "--json"]
    monkeypatch.setattr(sys, "argv", test_args)

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    with (
        patch("skylos.cli.subprocess.run", return_value=Mock(returncode=0)) as sprun,
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("builtins.print"),
    ):
        cli.main()

    called_cmds = []
    for call in sprun.call_args_list:
        called_cmds.append(call.args[0])

    found_python_c = False
    for cmd in called_cmds:
        if len(cmd) >= 2 and cmd[0] == sys.executable and cmd[1] == "-c":
            found_python_c = True
            break

    assert found_python_c is True


def test_remove_unused_import_returns_false_when_no_change():
    with (
        patch("pathlib.Path.read_text", return_value="import os\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch("skylos.cli.remove_unused_import_cst", return_value=("SAME", False)),
    ):
        ok = cli.remove_unused_import("x.py", "os", 1)

    assert ok is False
    mock_write.assert_not_called()


def test_remove_unused_function_returns_false_when_no_change():
    with (
        patch("pathlib.Path.read_text", return_value="def f():\n    pass\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch("skylos.cli.remove_unused_function_cst", return_value=("SAME", False)),
    ):
        ok = cli.remove_unused_function("x.py", "f", 1)

    assert ok is False
    mock_write.assert_not_called()


def test_comment_out_unused_import_returns_false_when_no_change():
    with (
        patch("pathlib.Path.read_text", return_value="import os\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch("skylos.cli.comment_out_unused_import_cst", return_value=("SAME", False)),
    ):
        ok = cli.comment_out_unused_import("x.py", "os", 1, marker="M")

    assert ok is False
    mock_write.assert_not_called()


def test_comment_out_unused_import_writes_when_changed():
    with (
        patch("pathlib.Path.read_text", return_value="import os\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch("skylos.cli.comment_out_unused_import_cst", return_value=("NEW", True)),
    ):
        ok = cli.comment_out_unused_import("x.py", "os", 1, marker="M")

    assert ok is True
    mock_write.assert_called_once_with("NEW", encoding="utf-8")


def test_comment_out_unused_function_returns_false_when_no_change():
    with (
        patch("pathlib.Path.read_text", return_value="def f():\n    pass\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch(
            "skylos.cli.comment_out_unused_function_cst", return_value=("SAME", False)
        ),
    ):
        ok = cli.comment_out_unused_function("x.py", "f", 1, marker="M")

    assert ok is False
    mock_write.assert_not_called()


def test_comment_out_unused_function_writes_when_changed():
    with (
        patch("pathlib.Path.read_text", return_value="def f():\n    pass\n"),
        patch("pathlib.Path.write_text") as mock_write,
        patch("skylos.cli.comment_out_unused_function_cst", return_value=("NEW", True)),
    ):
        ok = cli.comment_out_unused_function("x.py", "f", 1, marker="M")

    assert ok is True
    mock_write.assert_called_once_with("NEW", encoding="utf-8")


@pytest.fixture
def _sample_unused_items():
    functions = [
        {"name": "unused_func1", "file": "test1.py", "line": 10},
        {"name": "unused_func2", "file": "test2.py", "line": 20},
    ]
    imports = [
        {"name": "unused_import1", "file": "test1.py", "line": 1},
        {"name": "unused_import2", "file": "test2.py", "line": 2},
    ]
    return functions, imports


@patch("skylos.cli.inquirer")
def test_interactive_selection_with_selections_returns_expected(
    mock_inquirer, _sample_unused_items
):
    functions, imports = _sample_unused_items
    console = Mock()

    mock_inquirer.prompt.side_effect = [
        {"functions": [functions[0]]},
        {"imports": [imports[1]]},
    ]

    with patch("skylos.cli.INTERACTIVE_AVAILABLE", True):
        selected_functions, selected_imports = cli.interactive_selection(
            console, functions, imports
        )

    assert selected_functions == [functions[0]]
    assert selected_imports == [imports[1]]
    assert mock_inquirer.prompt.call_count == 2


def test_print_badge_includes_danger_and_quality_in_headline():
    logger = Mock()
    logger.console = Mock()

    cli.print_badge(
        3,
        logger,
        danger_enabled=True,
        danger_count=2,
        quality_enabled=True,
        quality_count=4,
    )

    printed = []
    for call in logger.console.print.call_args_list:
        if call.args:
            printed.append(call.args[0])

    panels = [x for x in printed if isinstance(x, Panel)]
    assert panels, "Expected a Panel to be printed"

    renderable = panels[0].renderable
    text = renderable.plain if hasattr(renderable, "plain") else str(renderable)

    assert "Found 3 dead-code items" in text
    assert "2 security issues" in text
    assert "4 quality issues" in text


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_main_gate_exits_with_run_gate_interaction_code(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    test_args = ["skylos", ".", "--gate"]
    monkeypatch.setattr(cli.sys, "argv", test_args)

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={"gate": {}}),
        patch("skylos.cli.run_gate_interaction", return_value=1) as gate,
        patch("builtins.print"),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    gate.assert_called_once()


def test_main_interactive_dry_run_does_not_modify(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "u", "file": "a.py", "line": 1}],
        "unused_imports": [{"name": "os", "file": "a.py", "line": 1}],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    test_args = ["skylos", ".", "--interactive", "--dry-run"]
    monkeypatch.setattr(cli.sys, "argv", test_args)

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch(
            "skylos.cli.interactive_selection",
            return_value=(result["unused_functions"], result["unused_imports"]),
        ),
        patch("skylos.cli.remove_unused_function") as rm_fn,
        patch("skylos.cli.remove_unused_import") as rm_imp,
        patch("skylos.cli.comment_out_unused_function") as c_fn,
        patch("skylos.cli.comment_out_unused_import") as c_imp,
        patch("builtins.print"),
    ):
        cli.main()

    rm_fn.assert_not_called()
    rm_imp.assert_not_called()
    c_fn.assert_not_called()
    c_imp.assert_not_called()


def test_main_interactive_comment_out_uses_comment_functions(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "u", "file": "a.py", "line": 1}],
        "unused_imports": [{"name": "os", "file": "a.py", "line": 1}],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    test_args = ["skylos", ".", "--interactive", "--comment-out"]
    monkeypatch.setattr(cli.sys, "argv", test_args)

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli.inquirer.prompt", return_value={"confirm": True}),
        patch(
            "skylos.cli.interactive_selection",
            return_value=(result["unused_functions"], result["unused_imports"]),
        ),
        patch("skylos.cli.remove_unused_function") as rm_fn,
        patch("skylos.cli.remove_unused_import") as rm_imp,
        patch("skylos.cli.comment_out_unused_function", return_value=True) as c_fn,
        patch("skylos.cli.comment_out_unused_import", return_value=True) as c_imp,
        patch("builtins.print"),
    ):
        cli.main()

    rm_fn.assert_not_called()
    rm_imp.assert_not_called()

    c_fn.assert_called_once()
    c_imp.assert_called_once()
