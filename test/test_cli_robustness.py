"""CLI flags and commands fail clearly instead of crashing or misreporting."""

import json
import logging
import subprocess
from argparse import Namespace
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

import skylos.cli as cli
from skylos.commands import scan_cmd


def _main_exit():
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


def _fail_if_called(*_args, **_kwargs):
    raise AssertionError("the scan must not start")


@pytest.mark.parametrize(
    ("value", "hint"),
    [
        ("secrets", "secrets (did you mean 'secret'?)"),
        ("security,deadcode", "deadcode (did you mean 'dead_code'?)"),
        ("ai_defect", "ai_defect (did you mean 'ai_defects'?)"),
        ("bogus", "bogus."),
    ],
)
def test_unknown_category_is_rejected_before_scanning(
    monkeypatch, capsys, tmp_path, value, hint
):
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", str(tmp_path), "-a", "--category", value, "--format", "concise"],
    )
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {})
    monkeypatch.setattr(cli, "run_analyze", _fail_if_called)

    assert _main_exit() == 2

    err = capsys.readouterr().err
    assert "Unknown --category value(s): " in err
    assert hint in err
    assert (
        "Valid categories: ai_defects, dead_code, dependency, publisher_change, "
        "quality, reliability, secret, security." in err
    )


@pytest.mark.parametrize(
    "value",
    [
        "secret",
        "Security,SECRET",
        "dead_code",
        "ai_defects,dependency,publisher_change,quality,reliability",
        "security,",
    ],
)
def test_documented_categories_are_accepted(value):
    cli._validate_display_category(Namespace(category=value))


def test_no_category_is_accepted():
    cli._validate_display_category(Namespace(category=None))
    cli._validate_display_category(Namespace())


def test_unnecessary_export_rule_is_selectable():
    args = Namespace(select=["sky-e004"])
    cli._apply_selected_rule_analysis_flags(args)
    assert args.select == ["SKY-E004"]

    result = {
        "unused_exports": [
            {"rule_id": "SKY-E004", "name": "helper", "file": "a.ts", "line": 1}
        ],
        "unused_functions": [{"name": "old", "file": "a.py", "line": 2}],
        "danger": [{"rule_id": "SKY-D211", "file": "b.py", "line": 3}],
    }
    selected = cli._apply_rule_selection(result, ["SKY-E004"])
    assert [item["name"] for item in selected["unused_exports"]] == ["helper"]
    assert selected["unused_functions"] == []
    assert selected["danger"] == []


def test_unknown_rule_is_still_rejected():
    with pytest.raises(cli.ConfigError, match="Unknown --select rule ID"):
        cli._apply_selected_rule_analysis_flags(Namespace(select=["SKY-E999"]))


def test_every_rule_id_the_analyzers_emit_is_selectable():
    from pathlib import Path
    import re

    from skylos.rules.catalog import get_rule_catalog

    known = (
        {entry["id"].upper() for entry in get_rule_catalog()}
        | set(cli._RULE_SELECTION_ANALYSIS_CATEGORY_OVERRIDES)
        | set(cli._RULE_SELECTION_DEFAULT_IDS.values())
    )
    emitted = set()
    pattern = re.compile(r"[\"']rule_id[\"']\s*:\s*[\"'](SKY-[A-Z]+[0-9]+)[\"']")
    package = Path(cli.__file__).resolve().parent
    for source in package.rglob("*.py"):
        emitted.update(pattern.findall(source.read_text(encoding="utf-8")))
    assert "SKY-E004" in emitted
    assert sorted(emitted - known) == []


def _dead_code_and_security_result(root):
    source = root / "app.py"
    source.write_text("def old():\n    return 1\n")
    return {
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["dead_code", "security"],
        },
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "file": str(source),
                "line": 2,
                "message": "Possible SQL injection",
            },
            {
                "rule_id": "SKY-D207",
                "severity": "MEDIUM",
                "file": str(source),
                "line": 1,
                "message": "Weak hash",
            },
        ],
        "unused_functions": [
            {"name": "old", "file": str(source), "line": 1, "confidence": 90}
        ],
        "unused_imports": [
            {"name": "os", "file": str(source), "line": 1, "confidence": 100}
        ],
    }


def test_severity_filter_hides_records_without_a_severity_by_their_shown_level(
    tmp_path,
):
    result = _dead_code_and_security_result(tmp_path)

    high = cli._apply_display_filters(result, severity="high")
    assert [item["rule_id"] for item in high["danger"]] == ["SKY-D211"]
    assert high["unused_functions"] == []
    assert high["unused_imports"] == []

    low = cli._apply_display_filters(result, severity="low")
    assert len(low["danger"]) == 2
    assert [item["name"] for item in low["unused_functions"]] == ["old"]
    assert [item["name"] for item in low["unused_imports"]] == ["os"]


def test_severity_filter_uses_the_level_the_report_prints():
    from skylos.ui.rich_report import _finding_severity

    record = {"name": "old", "file": "a.py", "line": 1}
    assert _finding_severity(record, "unused_functions") == "LOW"
    assert _finding_severity({"rule_id": "SKY-S101"}, "secrets") == "HIGH"
    assert _finding_severity({"rule_id": "SKY-X1"}, "custom_rules") == "MEDIUM"
    assert cli._display_filter_passes_severity(record, 1, "unused_functions")
    assert not cli._display_filter_passes_severity(record, 2, "unused_functions")
    assert cli._display_filter_passes_severity({}, 3, "secrets")
    assert not cli._display_filter_passes_severity({"severity": "LOW"}, 3, "secrets")


def test_severity_filter_footer_counts_only_listed_rows(monkeypatch, tmp_path):
    result = _dead_code_and_security_result(tmp_path)
    badge = {}
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", str(tmp_path), "--danger", "--severity", "high", "--no-upload"],
    )
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {})
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    monkeypatch.setattr(cli, "_is_tty", lambda: False)

    def record_badge(count, _logger, **kwargs):
        badge["count"] = count
        badge.update(kwargs)

    monkeypatch.setattr(cli, "print_badge", record_badge)
    _main_exit()

    assert badge["count"] == 0
    assert badge["danger_count"] == 1
    assert badge["summary"].startswith("Found 1 issue: security 1.")
    assert "dead code" not in badge["summary"]
    assert badge["show_badge"] is False


def test_unfiltered_footer_still_counts_every_listed_row(monkeypatch, tmp_path):
    result = _dead_code_and_security_result(tmp_path)
    badge = {}
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", str(tmp_path), "--danger", "--no-upload"]
    )
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {})
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    monkeypatch.setattr(cli, "_is_tty", lambda: False)

    def record_badge(count, _logger, **kwargs):
        badge["count"] = count
        badge.update(kwargs)

    monkeypatch.setattr(cli, "print_badge", record_badge)
    _main_exit()

    assert badge["count"] == 2
    assert badge["danger_count"] == 2
    assert badge["summary"].startswith("Found 4 issues: security 2, dead code 2.")


def test_interactive_scan_without_a_terminal_exits_before_scanning(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", str(tmp_path), "-i"])
    monkeypatch.setattr(cli, "_is_tty", lambda: False)
    monkeypatch.setattr(cli, "run_analyze", _fail_if_called)

    assert _main_exit() == 2

    err = capsys.readouterr().err
    assert "--interactive requires an interactive terminal" in err
    assert "skylos clean PATH --dry-run" in err
    assert "Traceback" not in err


def test_interactive_scan_offers_only_files_it_can_rewrite(tmp_path):
    python_file = tmp_path / "legacy.py"
    python_file.write_text("import os\n\ndef old():\n    return 1\n")
    ts_file = tmp_path / "checkout.ts"
    ts_file.write_text(
        "function formatLegacyPrice(total: number) {\n  return total;\n}\n"
    )
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n")
    items = [
        {"name": "old", "file": str(python_file), "line": 3},
        {"name": "formatLegacyPrice", "file": str(ts_file), "line": 1},
        {"name": "broken", "file": str(broken), "line": 1},
        {"name": "gone", "file": str(tmp_path / "missing.py"), "line": 1},
    ]

    rewritable, blocked = scan_cmd._rewritable_dead_code(items, tmp_path)

    assert [item["name"] for item in rewritable] == ["old"]
    reasons = {item["name"]: reason for item, reason in blocked}
    assert reasons["formatLegacyPrice"].startswith("not a Python file")
    assert reasons["broken"].startswith("the Python rewriter cannot parse it")
    assert set(reasons) == {"formatLegacyPrice", "broken", "gone"}

    console = Console(record=True, width=300)
    scan_cmd._print_blocked_dead_code(console, blocked)
    text = console.export_text()
    assert "Not offering 3 item(s) Skylos cannot edit safely" in text
    assert "checkout.ts: not a Python file" in text


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_interactive_scan_failed_edit_exits_nonzero(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("import os\n\ndef u():\n    return 1\n")
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "u", "file": "a.py", "line": 3}],
        "unused_imports": [{"name": "os", "file": "a.py", "line": 1}],
    }
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--interactive"])
    monkeypatch.setattr(cli, "_is_tty", lambda: True)
    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli.render_results") as render,
        patch("skylos.cli.print_badge"),
        patch("skylos.cli.inquirer.prompt", return_value={"confirm": True}),
        patch(
            "skylos.cli.interactive_selection",
            return_value=(result["unused_functions"], result["unused_imports"]),
        ),
        patch("skylos.cli.remove_unused_function", return_value=False),
        patch("skylos.cli.remove_unused_import", return_value=True) as remove_import,
        patch("skylos.api.get_project_token", return_value=None),
    ):
        assert _main_exit() == 1

    remove_import.assert_called_once()
    render.assert_not_called()
    printed = " ".join(
        str(call.args[0])
        for call in fake_logger.console.print.call_args_list
        if call.args
    )
    assert "Cleanup incomplete: 1 change(s) failed" in printed
    assert "Cleanup complete!" not in printed


def test_agent_file_selection_without_a_terminal_exits_cleanly(tmp_path):
    first = tmp_path / "one.py"
    second = tmp_path / "two.py"
    first.write_text("print(1)\n")
    second.write_text("print(2)\n")

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.discover_source_files", return_value=[first, second]),
        patch("skylos.cli.inquirer.prompt") as prompt,
        patch("skylos.cli.SkylosLLM") as llm,
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(tmp_path), "--security", "--interactive"],
        ),
    ):
        assert _main_exit() == 2

    prompt.assert_not_called()
    llm.assert_not_called()


def _analyzer_level_recorder(levels, value):
    def record(*_args, **_kwargs):
        levels.append(logging.getLogger("Skylos").getEffectiveLevel())
        logging.getLogger("Skylos").info("Analyzing 1 files...")
        return value

    return record


@pytest.fixture
def notset_analyzer_logger(monkeypatch):
    analyzer_logger = logging.getLogger("Skylos")
    monkeypatch.setattr(analyzer_logger, "level", logging.NOTSET)
    return analyzer_logger


def test_baseline_hides_analyzer_progress_logs(
    tmp_path, monkeypatch, caplog, notset_analyzer_logger
):
    from skylos.commands import baseline_cmd
    from skylos.core import review_decisions

    levels = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(baseline_cmd, "Console", lambda: Mock())
    monkeypatch.setattr(
        baseline_cmd,
        "run_analyze",
        _analyzer_level_recorder(levels, json.dumps({"analysis_summary": {}})),
    )
    monkeypatch.setattr(baseline_cmd, "load_config", lambda root, config_file=None: {})
    monkeypatch.setattr(baseline_cmd, "resolve_config_file_path", lambda: None)
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (False, False)
    )
    monkeypatch.setattr(
        review_decisions, "apply_trusted_review_decisions", lambda result, root: result
    )

    with caplog.at_level(logging.INFO):
        baseline_cmd.run_baseline_command([])

    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert notset_analyzer_logger.level == logging.NOTSET


def test_warm_cache_hides_analyzer_progress_logs(
    tmp_path, monkeypatch, caplog, notset_analyzer_logger
):
    from skylos.commands import hook_cmd
    from skylos.commands.warm_cache_cmd import run_warm_cache_command

    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("print(1)\n")
    levels = []
    monkeypatch.setattr(hook_cmd, "hook_verify", _analyzer_level_recorder(levels, {}))
    lines = []

    with caplog.at_level(logging.INFO):
        code = run_warm_cache_command(
            Namespace(path=str(tmp_path)), print_func=lines.append
        )

    assert code == 0
    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert "Indexed 1 Python file(s)" in lines[-1]
    assert notset_analyzer_logger.level == logging.NOTSET


def test_compare_scan_hides_analyzer_progress_logs(
    tmp_path, monkeypatch, caplog, notset_analyzer_logger
):
    import skylos.analyzer
    from skylos.commands import compare_cmd

    levels = []
    monkeypatch.setattr(
        skylos.analyzer, "analyze", _analyzer_level_recorder(levels, json.dumps({}))
    )
    monkeypatch.setattr(
        compare_cmd,
        "_git_context",
        lambda *_a, **_k: ("abc", False, str(tmp_path), "id"),
    )
    monkeypatch.setattr(
        compare_cmd, "_annotate_comparison_scan", lambda *_a, **_k: None
    )

    with caplog.at_level(logging.INFO):
        compare_cmd._run_local_scan(
            str(tmp_path), confidence=60, exclude_folders=[], enable_sca=False
        )

    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert notset_analyzer_logger.level == logging.NOTSET


def test_agent_refresh_hides_analyzer_progress_logs(
    tmp_path, monkeypatch, caplog, notset_analyzer_logger
):
    from skylos.agents import center
    from skylos.core import review_decisions

    levels = []
    monkeypatch.setattr(
        center, "run_analyze", _analyzer_level_recorder(levels, json.dumps({}))
    )
    monkeypatch.setattr(
        review_decisions, "review_scan_requirements", lambda root: (False, False)
    )
    monkeypatch.setattr(
        review_decisions, "apply_trusted_review_decisions", lambda result, root: result
    )

    with caplog.at_level(logging.INFO):
        center._run_refresh_analysis(
            tmp_path,
            conf=80,
            enable_secrets=True,
            enable_danger=True,
            enable_quality=True,
            enable_ai_defects=False,
            include_dead_code=True,
            use_baseline=False,
            changed_files=[],
        )

    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert notset_analyzer_logger.level == logging.NOTSET


def _git(root, *args):
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=t@example.invalid",
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("extra", [[], ["--format", "json"]])
def test_impact_comparison_hides_analyzer_progress_logs(
    tmp_path, monkeypatch, caplog, extra, notset_analyzer_logger
):
    import skylos.core.pr_impact as pr_impact

    (tmp_path / "app.py").write_text("print(1)\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-q", "-m", "base")
    levels = []
    monkeypatch.setattr(
        pr_impact, "annotate_dead_code_impact", _analyzer_level_recorder(levels, None)
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(
        "skylos.cloud.sync.load_custom_rules",
        lambda: {"rules": [], "status": "not_connected", "reason": "no_token"},
    )
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--diff",
            "HEAD",
            "--diff-mode",
            "impact",
            *extra,
        ],
    )

    with caplog.at_level(logging.INFO):
        _main_exit()

    assert levels == [logging.WARNING]
    assert "Analyzing" not in caplog.text
    assert notset_analyzer_logger.level == logging.NOTSET


def _annotation_files(capsys):
    files = []
    for line in capsys.readouterr().out.splitlines():
        if " file=" in line:
            files.append(line.split(" file=", 1)[1].split(",line=", 1)[0])
    return files


def test_github_annotations_use_repository_relative_paths(tmp_path, capsys):
    from skylos.reporting.github_annotations import _emit_github_annotations

    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    app = tmp_path / "app"
    app.mkdir()
    result = {
        "analysis_summary": {"comparison_scope": {"repository_root": str(tmp_path)}},
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "file": str(app / "db.py"),
                "line": 24,
                "message": "SQL",
            }
        ],
        "secrets": [
            {
                "rule_id": "SKY-S101",
                "severity": "CRITICAL",
                "file": "app/payments.py",
                "line": 3,
                "message": "secret",
            }
        ],
        "quality": [
            {
                "rule_id": "SKY-R104",
                "severity": "LOW",
                "file": str(tmp_path),
                "line": 1,
                "message": "no pre-commit",
            },
            {
                "rule_id": "SKY-R101",
                "severity": "MEDIUM",
                "file": "/elsewhere/outside.py",
                "line": 1,
                "message": "outside",
            },
        ],
        "unused_functions": [
            {"name": "old", "file": str(app / "legacy.py"), "line": 5}
        ],
    }

    _emit_github_annotations(result, root_path=tmp_path)

    assert sorted(_annotation_files(capsys)) == [
        ".",
        "/elsewhere/outside.py",
        "app/db.py",
        "app/legacy.py",
        "app/payments.py",
    ]


def test_github_annotations_resolve_relative_paths_from_the_analysis_root(
    tmp_path, capsys
):
    from skylos.reporting.github_annotations import _emit_github_annotations

    (tmp_path / ".git").mkdir()
    backend = tmp_path / "backend"
    (backend / "app").mkdir(parents=True)
    (backend / "pyproject.toml").write_text("[project]\nname='x'\n")
    result = {
        "secrets": [
            {
                "rule_id": "SKY-S101",
                "severity": "HIGH",
                "file": "app/keys.py",
                "line": 2,
            }
        ],
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "file": str(backend / "app" / "db.py"),
                "line": 4,
            }
        ],
    }

    _emit_github_annotations(result, root_path=backend / "app")

    assert sorted(_annotation_files(capsys)) == [
        "backend/app/db.py",
        "backend/app/keys.py",
    ]


def test_cicd_annotate_uses_the_report_root_from_another_directory(
    tmp_path, monkeypatch, capsys
):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    report = {
        "analysis_summary": {"comparison_scope": {"repository_root": str(repo)}},
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "file": str(repo / "app" / "db.py"),
                "line": 24,
            }
        ],
        "secrets": [
            {"rule_id": "SKY-S101", "severity": "HIGH", "file": "app/pay.py", "line": 3}
        ],
    }
    report_path = tmp_path / "r.json"
    report_path.write_text(json.dumps(report))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert cli.run_cicd_command(["annotate", "--input", str(report_path)]) == 0

    assert sorted(_annotation_files(capsys)) == ["app/db.py", "app/pay.py"]


def test_annotations_without_a_known_root_keep_their_paths(capsys):
    from skylos.reporting.github_annotations import _emit_github_annotations

    _emit_github_annotations(
        {
            "danger": [
                {
                    "rule_id": "SKY-D211",
                    "severity": "HIGH",
                    "file": "/abs/a.py",
                    "line": 1,
                }
            ],
            "secrets": [
                {"rule_id": "SKY-S101", "severity": "HIGH", "file": "b.py", "line": 1}
            ],
        }
    )

    assert sorted(_annotation_files(capsys)) == ["/abs/a.py", "b.py"]


def _advisory(name, version, vuln_id, severity):
    from skylos.rules.sca.vulnerability_scanner import _make_finding

    return _make_finding(
        {
            "name": name,
            "version": version,
            "ecosystem": "PyPI",
            "file": "requirements.txt",
            "line": 1,
            "dependency_dev": False,
        },
        {"vuln_id": vuln_id, "summary": "issue", "severity": severity},
    )


def _license_row(name, version):
    from skylos.rules.sca.licenses import _license_finding

    return _license_finding(
        {
            "name": name,
            "version": version,
            "ecosystem": "PyPI",
            "file": "requirements.txt",
            "line": 1,
        },
        {"license": "BSD-3-Clause", "source": "installed", "declared": "BSD-3-Clause"},
        [],
        ["MIT"],
        "HIGH",
    )


def test_license_violation_is_listed_apart_from_package_advisories():
    from skylos.reporting.advice_policy import apply_advice_policy
    from skylos.reporting.listing import is_listed

    rows = [
        _advisory("flask", "2.2.2", "GHSA-a", "LOW"),
        _advisory("flask", "2.2.2", "GHSA-b", "HIGH"),
        _license_row("flask", "2.2.2"),
    ]
    view = apply_advice_policy({"dependency_vulnerabilities": rows})
    listed = [
        row["rule_id"]
        for row in view["dependency_vulnerabilities"]
        if is_listed(row, "dependency_vulnerabilities")
    ]
    assert sorted(listed) == ["SKY-SCA-GHSA-b", "SKY-SCA-LIC001"]
    lead = next(
        row
        for row in view["dependency_vulnerabilities"]
        if row["rule_id"] == "SKY-SCA-GHSA-b"
    )
    assert [item["rule_id"].upper() for item in lead["listing"]["combines"]] == [
        "SKY-SCA-GHSA-A"
    ]


def test_license_violation_alone_is_still_listed_once():
    from skylos.reporting.advice_policy import apply_advice_policy
    from skylos.reporting.listing import is_listed

    view = apply_advice_policy(
        {"dependency_vulnerabilities": [_license_row("flask", "2.2.2")]}
    )
    assert [
        is_listed(row, "dependency_vulnerabilities")
        for row in view["dependency_vulnerabilities"]
    ] == [True]


def test_rich_report_prints_licenses_under_their_own_heading():
    from skylos.ui.rich_report import _render_sca

    console = Console(record=True, width=200)
    _render_sca(
        console,
        None,
        [
            _advisory("flask", "2.2.2", "GHSA-b", "HIGH"),
            _license_row("flask", "2.2.2"),
        ],
    )
    text = console.export_text()

    assert "Dependency Vulnerabilities (SCA), by package" in text
    assert "Dependency Licenses" in text
    licenses_at = text.index("Dependency Licenses")
    assert text.index("SKY-SCA-LIC001") > licenses_at
    assert "Dependency Vulnerabilities (SCA)\n" not in text.replace("─", "").replace(
        " ", ""
    )


def test_pretty_report_titles_a_license_row_by_its_message():
    from skylos.ui.terminal_report import _title

    row = _license_row("flask", "2.2.2")
    title = _title(row, "dependency_vulnerabilities", "dependency vulnerability")
    assert (
        title
        == "flask@2.2.2: license BSD-3-Clause is not in license_allow (BSD-3-Clause)."
    )
    advisory = _advisory("flask", "2.2.2", "GHSA-b", "HIGH")
    assert _title(advisory, "dependency_vulnerabilities", "x").startswith(
        "Vulnerable dependency: flask@2.2.2"
    )
