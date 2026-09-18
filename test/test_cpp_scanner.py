from __future__ import annotations

import os
from pathlib import Path

import pytest

from skylos.visitors.languages.cpp import (
    CPP_HEADER_EXTS,
    CPP_SOURCE_EXTS,
    scan_cpp_file,
)
from skylos.visitors.languages.cpp import core


def _scan(tmp_path: Path, source: str, filename: str = "sample.cpp") -> tuple:
    path = tmp_path / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)  # skylos: ignore[SKY-D215] pytest tmp_path
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(source)
    return scan_cpp_file(str(path))


def test_cpp_static_used_and_unused_functions(tmp_path: Path) -> None:
    defs, refs, *rest = _scan(
        tmp_path,
        """
static int used() { return 1; }
static int unused() { return 2; }
int main() { return used(); }
""",
    )
    by_name = {definition.name: definition for definition in defs}
    assert set(by_name) == {"used", "unused", "main"}
    assert not by_name["used"].is_exported
    assert not by_name["unused"].is_exported
    assert by_name["main"].is_exported
    assert ("used", str(tmp_path / "sample.cpp")) in refs
    assert ("unused", str(tmp_path / "sample.cpp")) not in refs
    assert rest[4] == []  # quality findings
    assert rest[5] == []  # security findings


def test_cpp_comments_and_strings_do_not_keep_function_alive(tmp_path: Path) -> None:
    defs, refs, *_ = _scan(
        tmp_path,
        "static int ghost() { return 1; } // ghost()\n"
        'const char *message = "ghost()";\n',
    )
    assert defs[0].name == "ghost"
    assert not defs[0].is_exported
    assert "ghost" not in {name for name, _ in refs}


def test_cpp_address_taken_counts_as_reference(tmp_path: Path) -> None:
    _, refs, *_ = _scan(
        tmp_path,
        "static int callback() { return 1; } int (*handler)() = &callback;",
    )
    assert ("callback", str(tmp_path / "sample.cpp")) in refs


def test_cpp_anonymous_namespace_free_function_is_local(tmp_path: Path) -> None:
    defs, refs, *_ = _scan(
        tmp_path,
        "namespace { int hidden() { return 1; } } int main() { return hidden(); }",
    )
    assert {definition.name: definition.is_exported for definition in defs} == {
        "hidden": False,
        "main": True,
    }
    assert ("hidden", str(tmp_path / "sample.cpp")) in refs


@pytest.mark.parametrize("extension", CPP_SOURCE_EXTS)
def test_cpp_source_extensions_are_supported(tmp_path: Path, extension: str) -> None:
    defs, *_ = _scan(tmp_path, "static int dead() { return 1; }", f"sample{extension}")
    assert len(defs) == 1
    assert not defs[0].is_exported


@pytest.mark.parametrize("extension", CPP_HEADER_EXTS)
def test_cpp_header_functions_are_never_dead_candidates(
    tmp_path: Path, extension: str
) -> None:
    defs, *_ = _scan(
        tmp_path,
        "static int helper() { return 1; } namespace { int hidden() { return 2; } }",
        f"sample{extension}",
    )
    assert {definition.name for definition in defs} == {"helper", "hidden"}
    assert all(definition.is_exported for definition in defs)


def test_cpp_plain_h_is_not_assumed_to_be_cpp(tmp_path: Path) -> None:
    defs, refs, *_ = _scan(tmp_path, "static int maybe() { return 1; }", "maybe.h")
    assert defs == []
    assert refs == []


def test_cpp_external_and_member_functions_are_not_dead_candidates(
    tmp_path: Path,
) -> None:
    defs, *_ = _scan(
        tmp_path,
        "int public_api() { return 1; } class Widget { static int method() { return 2; } };",
    )
    assert {definition.name for definition in defs} == {"public_api"}
    assert all(definition.is_exported for definition in defs)


def test_cpp_templates_overloads_and_macros_are_protected(tmp_path: Path) -> None:
    defs, *_ = _scan(
        tmp_path,
        """
template <class T> static T templated(T value) { return value; }
static int overloaded() { return 1; }
static int overloaded(int value) { return value; }
#define CALL_MACRO macro_used()
static int macro_used() { return 3; }
""",
    )
    assert {definition.name for definition in defs} == {
        "templated",
        "overloaded",
        "macro_used",
    }
    assert all(definition.is_exported for definition in defs)


def test_cpp_token_pasting_protects_possible_generated_references(
    tmp_path: Path,
) -> None:
    defs, *_ = _scan(
        tmp_path,
        "#define JOIN(a,b) a ## b\nstatic int helper() { return 1; }\n",
    )
    assert defs[0].is_exported


def test_cpp_parse_errors_do_not_produce_dead_candidates(tmp_path: Path) -> None:
    result = _scan(tmp_path, "static int unfinished() {")
    defs, refs = result[:2]
    assert defs == []
    assert refs == []
    assert result[25]["kind"] == "cpp_parse_error"
    assert result[25]["line"] == 1


def test_cpp_missing_grammar_returns_empty_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(core, "CPP_LANG", None)
    result = _scan(tmp_path, "static int helper() { return 1; }")
    defs, refs = result[:2]
    assert defs == []
    assert refs == []
    assert result[25]["kind"] == "cpp_parser_unavailable"


def test_cpp_unreadable_path_reports_incomplete_scan(tmp_path: Path) -> None:
    missing = tmp_path / "missing.cpp"
    result = scan_cpp_file(str(missing))
    assert result[0] == []
    assert result[25]["kind"] == "source_read_error"
