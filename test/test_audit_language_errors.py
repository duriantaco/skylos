import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.analysis.errors import analysis_result_incomplete
from skylos.analysis.language_errors import with_analysis_error
from skylos.analysis.file_worker import process_file
from skylos.analyzer import analyze
from skylos.cli import main
from skylos.core.safe_cache_io import read_bytes_no_symlink
from skylos.core import safe_cache_io


CASES = [
    ("php", ".php", "PhpCore", "<?php function broken( {\n", "<?php echo 1;\n"),
    ("rust", ".rs", "RustCore", "fn broken() { let x = ; }\n", "fn main() {}\n"),
    ("dart", ".dart", "DartCore", "void main() { print(; }\n", "void main() {}\n"),
]


def _write(root, name, source):
    root = root.resolve(strict=True)
    path = root / name
    path.resolve().relative_to(root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        handle.write(source.encode("utf-8") if isinstance(source, str) else source)
    return path


@pytest.mark.parametrize("language,suffix,core,bad,good", CASES)
def test_partial_language_parse_marks_actual_analysis_incomplete(
    tmp_path, monkeypatch, language, suffix, core, bad, good
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    broken = _write(tmp_path, "broken" + suffix, bad)
    _write(tmp_path, "good" + suffix, good)
    report = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert analysis_result_incomplete(report)
    error = next(
        item for item in report["analysis_errors"] if Path(item["file"]) == broken
    )
    assert error["language"] == language
    assert error["kind"] == "syntax_error"
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["line"] >= 1 and error["column"] >= 1
    assert (
        report["analysis_summary"]["grade_unavailable_reason"] == "analysis_incomplete"
    )


@pytest.mark.parametrize("language,suffix,core,bad,good", CASES)
def test_partial_language_parse_cannot_pass_the_cli(
    tmp_path, monkeypatch, capsys, language, suffix, core, bad, good
):
    path = _write(tmp_path, "broken" + suffix, bad)
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", str(path), "--format", "json", "--no-upload", "--no-provenance"],
    )
    with pytest.raises(SystemExit) as stopped:
        main()
    assert stopped.value.code == 2
    report = json.loads(capsys.readouterr().out)
    assert analysis_result_incomplete(report)
    assert report["analysis_errors"][0]["language"] == language


@pytest.mark.parametrize("language,suffix,core,bad,good", CASES)
def test_valid_language_parse_still_completes(
    tmp_path, language, suffix, core, bad, good
):
    path = _write(tmp_path, "good" + suffix, good)
    report = json.loads(analyze(str(path), enable_danger=True, grep_verify=False))
    assert not analysis_result_incomplete(report)
    assert not report.get("analysis_errors")


@pytest.mark.parametrize("language,suffix,core,bad,good", CASES)
def test_failed_source_read_is_explicit(
    tmp_path, monkeypatch, language, suffix, core, bad, good
):
    module = importlib.import_module("skylos.visitors.languages." + language)
    path = _write(tmp_path, "good" + suffix, good)
    monkeypatch.setattr(module, "read_bytes_no_symlink", lambda *args, **kwargs: None)
    scan = getattr(
        module, "scan_" + ("rust" if language == "rust" else language) + "_file"
    )
    result = scan(str(path))
    assert result[25]["kind"] == "source_read_error"
    assert result[25]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"


@pytest.mark.parametrize("language,suffix,core,bad,good", CASES)
def test_missing_parser_does_not_look_clean(
    tmp_path, monkeypatch, language, suffix, core, bad, good
):
    module = importlib.import_module("skylos.visitors.languages." + language)
    path = _write(tmp_path, "good" + suffix, good)
    unavailable = SimpleNamespace(
        root_node=None,
        defs=[],
        refs=[],
        raw_imports=[],
        is_test_file=False,
        test_decorated_lines=set(),
        scan=lambda: None,
    )
    monkeypatch.setattr(module, core, lambda *args: unavailable)
    scan = getattr(module, "scan_" + language + "_file")
    result = scan(str(path), enable_danger_rules=False)
    assert result[25]["kind"] == "language_parser_unavailable"
    assert result[25]["language"] == language


def test_bounded_binary_reader_preserves_bytes_and_rejects_oversize(tmp_path):
    path = _write(tmp_path, "source.bin", b"\xff\x00raw\r\n")
    assert read_bytes_no_symlink(path, max_bytes=7) == b"\xff\x00raw\r\n"
    assert read_bytes_no_symlink(path, max_bytes=6) is None


def test_bounded_binary_reader_rejects_symlinks_and_nonfiles(tmp_path):
    path = _write(tmp_path, "source.bin", b"data")
    link = tmp_path / "linked.bin"
    link.symlink_to(path)
    assert read_bytes_no_symlink(link, max_bytes=100) is None
    assert read_bytes_no_symlink(tmp_path, max_bytes=100) is None


def test_direct_binary_reader_normalizes_its_explicitly_trusted_parent(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    path = _write(real, "source.bin", b"data")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    assert read_bytes_no_symlink(alias / path.name, max_bytes=100) == b"data"
    assert (
        read_bytes_no_symlink(real / ".." / "real" / path.name, max_bytes=100)
        == b"data"
    )
    leaf_link = alias / "leaf.bin"
    leaf_link.symlink_to(path)
    assert read_bytes_no_symlink(leaf_link, max_bytes=100) is None


@pytest.mark.parametrize("fallback", [False, True])
def test_binary_reader_enforces_project_root_and_preserves_raw_bytes(
    tmp_path, monkeypatch, fallback
):
    if fallback:
        monkeypatch.setattr(safe_cache_io.os, "supports_dir_fd", set())
    project = tmp_path / "project"
    project.mkdir()
    child = project / "source"
    child.mkdir()
    path = _write(child, "source.bin", b"\xff\x00raw\r\n")
    outside = _write(tmp_path, "outside.bin", b"outside")
    link = project / "linked"
    link.symlink_to(tmp_path, target_is_directory=True)
    assert (
        read_bytes_no_symlink(path, project_root=project, max_bytes=7)
        == b"\xff\x00raw\r\n"
    )
    assert (
        read_bytes_no_symlink("source/source.bin", project_root=project, max_bytes=7)
        == b"\xff\x00raw\r\n"
    )
    assert read_bytes_no_symlink(path, project_root=project, max_bytes=6) is None
    assert read_bytes_no_symlink(outside, project_root=project, max_bytes=100) is None
    assert (
        read_bytes_no_symlink("../outside.bin", project_root=project, max_bytes=100)
        is None
    )
    assert (
        read_bytes_no_symlink(link / "outside.bin", project_root=project, max_bytes=100)
        is None
    )
    assert (
        read_bytes_no_symlink(
            child / "missing.bin", project_root=project, max_bytes=100
        )
        is None
    )


@pytest.mark.parametrize("fallback", [False, True])
def test_binary_reader_rejects_file_replaced_before_open(
    tmp_path, monkeypatch, fallback
):
    path = _write(tmp_path, "source.bin", b"original")
    replacement = _write(tmp_path, "replacement.bin", b"replacement")
    original_open = safe_cache_io.os.open
    replaced = False

    def racing_open(file, flags, *args, **kwargs):
        nonlocal replaced
        if not replaced and Path(file).name == path.name:
            replaced = True
            replacement.replace(path)
        return original_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(safe_cache_io.os, "open", racing_open)
    supported = set(safe_cache_io.os.supports_dir_fd)
    supported.add(racing_open)
    monkeypatch.setattr(
        safe_cache_io.os, "supports_dir_fd", set() if fallback else supported
    )
    assert read_bytes_no_symlink(path, project_root=tmp_path, max_bytes=100) is None
    assert replaced


WORKER_CASES = [
    (".java", "class Active {}\n"),
    (".go", "package main\nfunc main() { println(1) }\n"),
    (".php", "<?php echo 1;\n"),
    (".rs", "fn main() {}\n"),
    (".dart", "void main() {}\n"),
]


@pytest.mark.parametrize("suffix,source", WORKER_CASES)
def test_direct_language_scanner_accepts_an_explicit_parent_alias(
    tmp_path, suffix, source
):
    from skylos.analysis.file_processing import scan_non_python_file

    real = tmp_path / "real"
    real.mkdir()
    path = _write(real, "active" + suffix, source)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    result = scan_non_python_file(
        alias / path.name,
        {},
        enable_quality_rules=False,
        enable_danger_rules=False,
    )
    assert len(result) < 26 or result[25] is None


@pytest.mark.parametrize("suffix,source", WORKER_CASES)
@pytest.mark.parametrize("unsafe", ["outside", "parent_symlink"])
def test_actual_worker_rejects_source_outside_its_trusted_root(
    tmp_path, suffix, source, unsafe
):
    project = tmp_path / "project"
    project.mkdir()
    path = _write(tmp_path, "active" + suffix, source)
    if unsafe == "parent_symlink":
        link = project / "linked"
        link.symlink_to(tmp_path, target_is_directory=True)
        path = link / path.name
    result = process_file(
        path,
        project_root=project,
        enable_quality_rules=False,
        enable_danger_rules=False,
    )
    assert result[25]["kind"] == "source_read_error"
    assert result[25]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"


@pytest.mark.parametrize("suffix,source", WORKER_CASES)
def test_actual_worker_keeps_valid_in_root_source_complete(tmp_path, suffix, source):
    child = tmp_path / "source"
    child.mkdir()
    path = _write(child, "active" + suffix, source)
    result = process_file(
        path,
        project_root=tmp_path,
        enable_quality_rules=False,
        enable_danger_rules=False,
    )
    assert len(result) < 26 or result[25] is None


def test_language_error_metadata_preserves_existing_fields_and_error():
    header = tuple(range(13))
    error = {"kind": "syntax_error", "file": "sample.dart"}
    attached = with_analysis_error(header, error)
    assert attached[:13] == header
    assert attached[25] == error
    assert with_analysis_error(attached, {"kind": "source_read_error"}) == attached
    assert with_analysis_error(header, None) == header
