"""A failed input must not stop fallback AI checks for subsequent source files."""

import ast
import json
from collections import Counter
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


_PHANTOM = "@labelled\ndef present(value):\n    return format_label(value)\n"
_INVALID = "def incomplete(:\n    pass\n"
_NAMES = {"SKY-L012": "format_label", "SKY-L023": "labelled"}


@pytest.fixture(autouse=True)
def single_worker(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


def _write(path, source):
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _analyze(paths, *, ignored=(), progress_callback=None):
    return json.loads(
        analyze(
            [str(path) for path in paths],
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            progress_callback=progress_callback,
            project_config_overrides={
                "ignore": list(ignored),
                "vibe": {
                    "extra_phantom_names": ["format_label"],
                    "extra_phantom_decorators": ["labelled"],
                },
            },
        )
    )


def _phantom_keys(result, category="ai_defects"):
    return Counter(
        (finding["rule_id"], Path(finding["file"]).resolve(), finding["name"])
        for finding in result.get(category, [])
        if finding.get("rule_id") in _NAMES
    )


def _expected(paths, ignored=()):
    return Counter(
        (rule_id, path.resolve(), name)
        for path in paths
        for rule_id, name in _NAMES.items()
        if rule_id not in ignored
    )


def _assert_incomplete(result, failed, *, error_type, kind=None):
    errors = result.get("analysis_errors", [])
    assert len(errors) == 1, errors
    assert Path(errors[0]["file"]).resolve() == failed.resolve()
    assert errors[0]["error_type"] == error_type
    if kind is not None:
        assert errors[0]["kind"] == kind
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_summary"]["grade_unavailable_reason"] == (
        "analysis_incomplete"
    )
    assert "grade" not in result


@pytest.mark.parametrize("suffix", [".py", ".pyi", ".pyw"])
@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
def test_invalid_file_does_not_stop_later_fallback_checks(tmp_path, suffix, position):
    first = _write(tmp_path / f"first{suffix}", _PHANTOM)
    second = _write(tmp_path / f"second{suffix}", _PHANTOM)
    invalid = _write(tmp_path / f"broken{suffix}", _INVALID)
    ordered = [first, second]
    ordered.insert(position, invalid)

    result = _analyze(ordered)

    assert _phantom_keys(result) == _expected([first, second])
    _assert_incomplete(result, invalid, error_type="SyntaxError", kind="syntax_error")


def test_valid_files_report_each_fallback_finding_once(tmp_path):
    first = _write(tmp_path / "first.py", _PHANTOM)
    second = _write(tmp_path / "second.py", _PHANTOM)

    result = _analyze([first, second])

    assert _phantom_keys(result) == _expected([first, second])
    assert result.get("analysis_errors", []) == []


def test_defined_label_helpers_are_clean_after_invalid_file(tmp_path):
    invalid = _write(tmp_path / "broken.py", _INVALID)
    clean = _write(
        tmp_path / "clean.py",
        "def labelled(function):\n    return function\n\n"
        "def format_label(value):\n    return str(value)\n\n" + _PHANTOM,
    )

    result = _analyze([invalid, clean])

    assert _phantom_keys(result) == Counter()
    _assert_incomplete(result, invalid, error_type="SyntaxError", kind="syntax_error")


@pytest.mark.parametrize(
    "ignored", [("SKY-L012",), ("SKY-L023",), ("SKY-L012", "SKY-L023")]
)
def test_project_rule_ignores_survive_an_earlier_invalid_file(tmp_path, ignored):
    invalid = _write(tmp_path / "broken.py", _INVALID)
    first = _write(tmp_path / "first.py", _PHANTOM)
    second = _write(tmp_path / "second.py", _PHANTOM)

    result = _analyze([invalid, first, second], ignored=ignored)

    assert _phantom_keys(result) == _expected([first, second], ignored)
    _assert_incomplete(result, invalid, error_type="SyntaxError", kind="syntax_error")


def test_both_rules_ignored_skip_fallback_reads_and_visits(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import PhantomCallRule, PhantomDecoratorRule

    source = _write(tmp_path / "labels.py", _PHANTOM)
    original_read = Path.read_text
    active_ai_phase = False
    reached_ai_phase = False
    read_calls = []
    visit_calls = []

    def track_phase(completed, total, path):
        nonlocal active_ai_phase, reached_ai_phase
        phase = str(path)
        if phase.startswith("PHASE:"):
            active_ai_phase = phase == "PHASE: AI defect scan"
            reached_ai_phase = reached_ai_phase or active_ai_phase

    def reject_fallback_read(path, *args, **kwargs):
        if (
            active_ai_phase
            and path == source
            and kwargs == {"encoding": "utf-8", "errors": "ignore"}
        ):
            read_calls.append(path)
            raise PermissionError("an ignored fallback must not reread its source")
        return original_read(path, *args, **kwargs)

    def record_visits(original_visit):
        def reject_fallback_visit(rule, node, context):
            if active_ai_phase:
                visit_calls.append(rule.rule_id)
                raise AssertionError("an ignored fallback rule must not visit nodes")
            return original_visit(rule, node, context)

        return reject_fallback_visit

    monkeypatch.setattr(Path, "read_text", reject_fallback_read)
    for rule_class in (PhantomCallRule, PhantomDecoratorRule):
        monkeypatch.setattr(
            rule_class, "visit_node", record_visits(rule_class.visit_node)
        )

    result = _analyze([source], ignored=tuple(_NAMES), progress_callback=track_phase)

    assert reached_ai_phase
    assert read_calls == []
    assert visit_calls == []
    assert _phantom_keys(result) == Counter()
    assert result.get("analysis_errors", []) == []


def test_inline_rule_ignores_survive_an_earlier_invalid_file(tmp_path):
    invalid = _write(tmp_path / "broken.py", _INVALID)
    ignored = _write(
        tmp_path / "ignored.py",
        "@labelled  # skylos: ignore[SKY-L023]\n"
        "def present(value):\n"
        "    return format_label(value)  # skylos: ignore[SKY-L012]\n",
    )
    visible = _write(tmp_path / "visible.py", _PHANTOM)

    result = _analyze([invalid, ignored, visible])

    assert _phantom_keys(result) == _expected([visible])
    assert _phantom_keys(result, "suppressed") == _expected([ignored])
    _assert_incomplete(result, invalid, error_type="SyntaxError", kind="syntax_error")


def test_fallback_read_failure_keeps_later_findings_and_marks_incomplete(
    tmp_path, monkeypatch
):
    import skylos.rules.ai_defect.python_api_hallucination as python_api

    first = _write(tmp_path / "first.py", _PHANTOM)
    unreadable = _write(tmp_path / "unreadable.py", "label = 'example'\n")
    second = _write(tmp_path / "second.py", _PHANTOM)
    original_scan = python_api.scan_python_local_api_hallucinations
    original_read = Path.read_text
    read_failures = []

    def fail_selected_read(path, *args, **kwargs):
        if path == unreadable and kwargs.get("errors") == "ignore":
            read_failures.append(path)
            raise PermissionError("fixture became unreadable after initial analysis")
        return original_read(path, *args, **kwargs)

    def scan_then_restrict_read(*args, **kwargs):
        result = original_scan(*args, **kwargs)
        monkeypatch.setattr(Path, "read_text", fail_selected_read)
        return result

    monkeypatch.setattr(
        python_api, "scan_python_local_api_hallucinations", scan_then_restrict_read
    )

    result = _analyze([first, unreadable, second])

    assert read_failures
    assert _phantom_keys(result) == _expected([first, second])
    _assert_incomplete(result, unreadable, error_type="PermissionError")


def test_fallback_rule_failure_keeps_later_findings_and_marks_incomplete(
    tmp_path, monkeypatch
):
    from skylos.rules.ai_defect import PhantomCallRule

    first = _write(tmp_path / "first.py", _PHANTOM)
    failed = _write(
        tmp_path / "failed.py",
        "def format_label(value):\n    return value\n\n"
        "def labelled(function):\n    return function\n\n"
        "label = 'example'\n",
    )
    second = _write(tmp_path / "second.py", _PHANTOM)
    original_visit = PhantomCallRule.visit_node
    rule_failures = []

    def fail_selected_rule(rule, node, context):
        if isinstance(node, ast.Constant) and Path(context["filename"]) == failed:
            rule_failures.append(context["filename"])
            raise RuntimeError("controlled fallback rule failure")
        return original_visit(rule, node, context)

    monkeypatch.setattr(PhantomCallRule, "visit_node", fail_selected_rule)

    result = _analyze([first, failed, second])

    assert len(rule_failures) == 1
    assert _phantom_keys(result) == _expected([first, second])
    _assert_incomplete(result, failed, error_type="RuntimeError")


def test_cli_keeps_valid_findings_and_exits_two_after_invalid_file(
    tmp_path, monkeypatch, capsys
):
    import skylos.cli as cli

    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos.vibe]\nextra_phantom_names = ["format_label"]\n'
        'extra_phantom_decorators = ["labelled"]\n',
    )
    invalid = _write(tmp_path / "broken.py", _INVALID)
    first = _write(tmp_path / "first.py", _PHANTOM)
    second = _write(tmp_path / "second.py", _PHANTOM)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(invalid),
            str(first),
            str(second),
            "--select",
            "SKY-L012,SKY-L023",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
        ],
    )

    with pytest.raises(SystemExit) as exited:
        cli.main()

    assert exited.value.code == 2
    result = json.loads(capsys.readouterr().out)
    assert _phantom_keys(result) == _expected([first, second])
    _assert_incomplete(result, invalid, error_type="SyntaxError", kind="syntax_error")
