import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from skylos import analyze
from skylos.visitors.languages.rust import include_liveness

SOURCE = """include!("wiring.inc");
fn on_event() -> u8 { 7 }
fn idle() -> u8 { 9 }
fn main() { std::hint::black_box(connected()); }
"""


def _crate(root, source=SOURCE):
    src = root / "src"
    src.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\nedition="2024"\n'
    )
    (src / "main.rs").write_text(source)
    return src


def _scan(root, **kwargs):
    report = json.loads(analyze(str(root), conf=40, grep_cache=False, **kwargs))
    assert not report.get("analysis_errors")
    return report


def _unused(report):
    return {row["simple_name"] for row in report["unused_functions"]}


def _uncertain(report):
    return {
        row["simple_name"]
        for row in report["dead_code_abstentions"]
        if include_liveness.UNRESOLVED_INCLUDE in str(row)
    }


def test_cli_literal_include_keeps_actual_reference_and_reports_unused_sibling(
    tmp_path,
):
    src = _crate(tmp_path)
    (src / "wiring.inc").write_text(
        'fn connected() -> u8 { /* idle() */ let idle = "idle()"; std::hint::black_box(idle); on_event() }'
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "skylos.cli",
            ".",
            "--confidence",
            "40",
            "--format",
            "json",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert not report["analysis_errors"]
    assert _unused(report) == {"idle"}
    assert not _uncertain(report)


def test_nested_raw_literal_expression_and_qualified_path(tmp_path):
    src = _crate(
        tmp_path,
        """mod utils;
fn main() { std::hint::black_box(include!(r#"config/value.expr"#)); }
""",
    )
    (src / "utils.rs").write_text(
        "pub(crate) fn kept() -> u8 { 1 }\npub(crate) fn abandoned() {}"
    )
    nested = src / "config"
    nested.mkdir()
    (nested / "value.expr").write_text('include!("nested.inc")')
    (nested / "nested.inc").write_text("crate::utils::kept()")
    assert _unused(_scan(tmp_path)) == {"abandoned"}


@pytest.mark.parametrize(
    "argument",
    ['concat!(env!("OUT_DIR"), "/gen.rs")', '"missing.inc"', '"../../escape.inc"'],
)
def test_unknown_include_marks_its_crate_uncertain(tmp_path, argument):
    _crate(tmp_path / "first", SOURCE.replace('"wiring.inc"', argument))
    _crate(tmp_path / "other", "fn sibling_crate_orphan() {}\nfn main() {}")
    report = _scan(tmp_path)
    assert _uncertain(report) >= {"on_event", "idle"}
    assert _unused(report) == {"sibling_crate_orphan"}


@pytest.mark.parametrize("cause", ["excluded", "symlink", "oversize", "parse"])
def test_unreadable_include_does_not_silently_report_a_dead_caller(
    tmp_path, monkeypatch, cause
):
    src = _crate(tmp_path)
    path = src / "wiring.inc"
    text = "fn connected() -> u8 { on_event() }"
    excludes = []
    if cause == "excluded":
        excludes = ["src/wiring.inc"]
        path.write_text(text)
    elif cause == "symlink":
        outside = tmp_path.parent / "handler-outside.inc"
        outside.write_text(text)
        path.symlink_to(outside)
    elif cause == "oversize":
        monkeypatch.setattr(include_liveness, "_MAX_FILE_BYTES", 16)
        path.write_text(text)
    else:
        path.write_text("fn connected( ??? ")
    report = _scan(tmp_path, exclude_folders=excludes)
    assert "on_event" in _uncertain(report)
    assert not _unused(report)


def test_include_in_macro_tokens_and_source_data_macros_are_distinct(tmp_path):
    src = _crate(
        tmp_path,
        'fn on_event() -> bool { true }\nfn idle() {}\nfn main() { assert!(include!("check.inc")); include_str!("text"); }',
    )
    (src / "check.inc").write_text("on_event()")
    (src / "text").write_text("idle()")
    report = _scan(tmp_path)
    assert _unused(report) == {"idle"}
    assert not _uncertain(report)


def test_recursive_include_tree_marks_uncertainty(tmp_path):
    src = _crate(tmp_path)
    (src / "wiring.inc").write_text('include!("wiring.inc");')
    assert _uncertain(_scan(tmp_path)) >= {"on_event", "idle"}


def test_literal_fragment_counts_as_an_external_caller_of_a_cycle(tmp_path):
    src = _crate(
        tmp_path,
        'include!("entry.inc");\nfn a(){ b(); }\nfn b(){ a(); }\nfn idle() {}\nfn main(){ call(); }',
    )
    (src / "entry.inc").write_text("fn call(){ a(); }")
    assert _unused(_scan(tmp_path)) == {"idle"}


def test_include_method_call_uses_its_receiver(tmp_path):
    src = _crate(
        tmp_path,
        'include!("entry.inc");\nstruct Thing;\nimpl Thing { fn reached(&self) {} fn forgotten(&self) {} }\nfn main() { call(); }',
    )
    (src / "entry.inc").write_text("fn call() { Thing.reached(); }")
    report = _scan(tmp_path)
    assert "reached" not in _unused(report)
    assert "forgotten" in _unused(report)


@pytest.mark.parametrize("git_failure", [False, True])
def test_gitignored_source_is_never_opened(tmp_path, monkeypatch, git_failure):
    src = _crate(tmp_path)
    (src / "wiring.inc").write_text("fn connected() -> u8 { on_event() }")
    (tmp_path / ".gitignore").write_text("*.inc")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    if git_failure:
        monkeypatch.setattr(include_liveness, "list_git_visible_files", lambda _: None)
    read = include_liveness.read_project_text_no_symlink

    def guarded(root, path, **kwargs):
        assert path.name != "wiring.inc"
        return read(root, path, **kwargs)

    monkeypatch.setattr(include_liveness, "read_project_text_no_symlink", guarded)
    report = _scan(tmp_path)
    assert _uncertain(report) >= {"on_event", "idle"}


@pytest.mark.parametrize("limit", ["_MAX_DEPTH", "_MAX_TOTAL_BYTES", "_MAX_INCLUDES"])
def test_include_budget_does_not_silently_report_dead_code(
    tmp_path, monkeypatch, limit
):
    src = _crate(tmp_path)
    (src / "wiring.inc").write_text('include!("child.inc");')
    (src / "child.inc").write_text("fn connected() -> u8 { on_event() }")
    monkeypatch.setattr(include_liveness, limit, 1)
    assert _uncertain(_scan(tmp_path)) >= {"on_event", "idle"}


@pytest.mark.parametrize(
    "text",
    [
        "mod generated { pub fn connected() -> u8 { super::on_event() } }",
        "use crate::handlers::*; fn connected() -> u8 { on_event() }",
    ],
)
def test_unmodeled_pasted_scopes_do_not_prove_dead_callers(tmp_path, text):
    src = _crate(tmp_path)
    (src / "wiring.inc").write_text(text)
    assert "idle" in _uncertain(_scan(tmp_path))
