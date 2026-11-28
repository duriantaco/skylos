from __future__ import annotations

import json
import sys

import pytest

from skylos.cli import main
from skylos.visitors.languages.cpp import core, scan_cpp_file

pytestmark = pytest.mark.skipif(core.CPP_LANG is None, reason="C++ grammar unavailable")


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            (
                "#include <cstring>\n"
                "#include <cstdio>\n"
                "void copy(char *dst, const char *src) {\n"
                "    std::strcpy(dst, src);\n"
                '    ::sprintf(dst, "%s", src);\n'
                '    std::snprintf(dst, 12, "%s", src);\n'
                "}\n"
            ),
            [("SKY-D435", 4), ("SKY-D435", 5)],
        ),
        (
            (
                "#include <cstring>\n"
                "namespace local { void strcpy(char *, const char *); }\n"
                "void copy(char *dst, const char *src) {\n"
                "    local::strcpy(dst, src);\n"
                "    std::strcpy(dst, src);\n"
                "}\n"
            ),
            [("SKY-D435", 5)],
        ),
        (
            (
                "#include <cstring>\n"
                "struct Store {\n"
                "    void strcpy(char *, const char *);\n"
                "    void copy(char *dst, const char *src) { strcpy(dst, src); }\n"
                "};\n"
                "void callback(char *dst, const char *src, void (*strcpy)(char *, const char *)) {\n"
                "    strcpy(dst, src);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstring>\n"
                "#define strcpy copy_text\n"
                "void copy(char *dst, const char *src) { strcpy(dst, src); }\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "void release() {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    auto *alias = ptr;\n"
                "    std::free(ptr);\n"
                "    int number = 3;\n"
                "    ::std::free(alias);\n"
                "}\n"
            ),
            [("SKY-D436", 7)],
        ),
        (
            (
                "#include <stdlib.h>\n"
                "int sample() {\n"
                "    char *ptr = (char *)calloc(1, 8);\n"
                "    ::free((ptr));\n"
                "    int result = ptr[0];\n"
                "    return *ptr;\n"
                "}\n"
            ),
            [("SKY-D437", 5), ("SKY-D437", 6)],
        ),
        (
            (
                "#include <cstdlib>\n"
                "struct Data { int count; };\n"
                "int sample() {\n"
                "    auto *ptr = static_cast<Data *>(std::malloc(sizeof(Data)));\n"
                "    std::free(ptr);\n"
                "    return ptr->count;\n"
                "}\n"
            ),
            [("SKY-D437", 6)],
        ),
        (
            (
                "#include <cstdlib>\n"
                "int sample() {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    std::free(ptr);\n"
                "    int capacity = sizeof(*ptr);\n"
                "    ptr = static_cast<char *>(std::malloc(8));\n"
                "    int value = ptr[0];\n"
                "    std::free(ptr);\n"
                "    ptr = nullptr;\n"
                "    std::free(ptr);\n"
                "    return value + capacity;\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "void sample(bool choose) {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    if (choose) { std::free(ptr); }\n"
                "    else { std::free(ptr); }\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "namespace local { void *malloc(int); void free(void *); }\n"
                "void sample() {\n"
                "    auto *ptr = local::malloc(8);\n"
                "    local::free(ptr);\n"
                "    local::free(ptr);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                '#include "project_cstdlib.h"\n'
                "void fake() {\n"
                "    auto *ptr = malloc(8);\n"
                "    free(ptr);\n"
                "    free(ptr);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstring>\n"
                "namespace tools { struct std { static void strcpy(char *, const char *); }; }\n"
                "using tools::std;\n"
                "void copy(char *dst, const char *src) {\n"
                "    std::strcpy(dst, src);\n"
                "    ::std::strcpy(dst, src);\n"
                "}\n"
            ),
            [("SKY-D435", 6)],
        ),
        (
            (
                "#include <cstring>\n"
                "void copy(char *dst, const char *src) {\n"
                "    using result = decltype(std::strcpy(dst, src));\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "void sample() {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    std::free(ptr);\n"
                "    ptr = nullptr;\n"
                "    std::free(ptr);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "void sample() {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    auto *&alias = ptr;\n"
                "    std::free(ptr);\n"
                "    alias = static_cast<char *>(std::malloc(8));\n"
                "    std::free(ptr);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <cstdlib>\n"
                "void sample() {\n"
                "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
                "    auto **slot = &ptr;\n"
                "    std::free(ptr);\n"
                "    *slot = static_cast<char *>(std::malloc(8));\n"
                "    std::free(ptr);\n"
                "}\n"
            ),
            [],
        ),
        (
            (
                "#include <string.h>\n"
                "struct Store {\n"
                "    void strcpy(char *, const char *) {}\n"
                "    void copy(char *dst, const char *src) { ::strcpy(dst, src); }\n"
                "};\n"
            ),
            [("SKY-D435", 4)],
        ),
    ],
)
def test_cpp_native_memory_findings(tmp_path, source, expected):
    path = tmp_path / "sample.cpp"
    path.write_text(source)
    findings = scan_cpp_file(path)[7]

    assert [(row["rule_id"], row["line"]) for row in findings] == expected
    assert all(row["file"] == str(path) for row in findings)
    assert not scan_cpp_file(path, enable_danger_rules=False)[7]


def test_cpp_cli_native_security_scope_and_directives(tmp_path, monkeypatch, capsys):
    path = tmp_path / "sample.cpp"
    path.write_text(
        "#include <cstring>\n"
        "#include <cstdlib>\n"
        "void sample(char *dst, const char *src) {\n"
        "    std::strcpy(dst, src); // skylos: ignore[SKY-D435]\n"
        "    auto *ptr = static_cast<char *>(std::malloc(8));\n"
        "    std::free(ptr);\n"
        "    std::free(ptr);\n"
        "    int result = ptr[0];\n"
        "}\n"
    )
    args = [
        "skylos",
        str(path),
        "--format",
        "json",
        "--no-provenance",
        "--no-upload",
    ]
    with monkeypatch.context() as active:
        active.setattr(sys, "argv", args)
        rc = main()
    report = json.loads(capsys.readouterr().out)
    assert rc in (None, 0)
    assert not report.get("danger")

    with monkeypatch.context() as active:
        active.setattr(sys, "argv", [*args, "--danger"])
        rc = main()
    report = json.loads(capsys.readouterr().out)
    assert rc in (None, 0)
    assert [
        (row["rule_id"], row["line"], row["file"]) for row in report.get("danger", [])
    ] == [
        ("SKY-D436", 7, str(path)),
        ("SKY-D437", 8, str(path)),
    ]
