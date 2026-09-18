from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from skylos.analyzer import Skylos, analyze
from skylos.cli import main


def _write_source(path: Path, source: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)  # skylos: ignore[SKY-D215] pytest tmp_path
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(source)


def test_cpp_source_discovery_and_language_count(tmp_path: Path) -> None:
    supported = (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx")
    for suffix in supported:
        _write_source(tmp_path / f"sample{suffix}", "int value() { return 1; }\n")
    _write_source(tmp_path / "sample.h", "int ambiguous(void);\n")
    _write_source(tmp_path / "sample.c", "int c_only(void) { return 1; }\n")

    analyzer = Skylos()
    files, root = analyzer._get_python_files(tmp_path)

    assert root == tmp_path
    assert {path.suffix for path in files} == set(supported)
    assert analyzer._count_languages(files) == {"C++": len(supported)}


def test_cpp_same_named_static_functions_remain_separate(tmp_path: Path) -> None:
    first = tmp_path / "first.cpp"
    second = tmp_path / "second.cc"
    _write_source(
        first,
        "static int helper() { return 1; }\nint main() { return helper(); }\n",
    )
    _write_source(second, "static int helper() { return 2; }\n")

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert result["analysis_summary"]["languages"] == {"C++": 2}
    assert {Path(item["file"]) for item in result["unused_functions"]} == {second}
    assert {item["simple_name"] for item in result["unused_functions"]} == {"helper"}


def test_cpp_file_path_scans_as_source(tmp_path: Path) -> None:
    file_path = tmp_path / "helper.cxx"
    _write_source(file_path, "static int helper() { return 1; }\n")

    result = json.loads(analyze(str(file_path), conf=0, grep_verify=False))

    assert result["analysis_summary"]["total_files"] == 1
    assert result["analysis_summary"]["languages"] == {"C++": 1}
    assert {item["simple_name"] for item in result["unused_functions"]} == {"helper"}


def test_cpp_parse_failure_exits_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    source = tmp_path / "bad.cpp"
    _write_source(source, "static int unfinished() {\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", str(source), "--format", "json", "--no-provenance", "--no-upload"],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    report = json.loads(capsys.readouterr().out)
    assert exc.value.code == 2
    assert report["unused_functions"] == []
    assert report["analysis_errors"][0]["kind"] == "cpp_parse_error"
