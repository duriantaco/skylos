from __future__ import annotations

import ntpath
import posixpath
from types import SimpleNamespace

import pytest

from skylos.visitors.languages.typescript import analysis, esbuild_static


@pytest.fixture(params=[posixpath, ntpath], ids=["posix", "windows"])
def path_style(monkeypatch, request):
    path_module = request.param
    monkeypatch.setattr(
        esbuild_static, "os", SimpleNamespace(path=path_module, sep=path_module.sep)
    )
    return path_module


@pytest.mark.parametrize(
    ("segments", "posix", "windows"),
    [
        ([], ".", "."),
        (["", ""], ".", "."),
        (["", "/src/worker.js"], "/src/worker.js", r"\src\worker.js"),
        (["src", "worker.js"], "src/worker.js", r"src\worker.js"),
        (["a", "/b", "worker.js"], "a/b/worker.js", r"a\b\worker.js"),
        (["a", r"\b", "worker.js"], r"a/\b/worker.js", r"a\b\worker.js"),
        (["src", "./worker.js"], "src/worker.js", r"src\worker.js"),
        (["src", "../worker.js"], "worker.js", "worker.js"),
        (["src", "worker.js/"], "src/worker.js/", "src\\worker.js\\"),
        (["src", "../"], "./", ".\\"),
        (["src", "..", ""], ".", "."),
        (["/", ".."], "/", "\\"),
        (
            ["//server/share/project", "src", "worker.js"],
            "/server/share/project/src/worker.js",
            r"\\server\share\project\src\worker.js",
        ),
        (
            ["//", "server", "share", "worker.js"],
            "/server/share/worker.js",
            r"\server\share\worker.js",
        ),
        (["//server", "share"], "/server/share", "\\\\server\\share\\"),
        (["//server"], "/server", r"\server"),
        (["///server", "share"], "/server/share", r"\server\share"),
        (
            ["//server//share", "worker.js"],
            "/server/share/worker.js",
            r"\\server\share\worker.js",
        ),
        (
            ["C:/project", "/src", "worker.js"],
            "C:/project/src/worker.js",
            r"C:\project\src\worker.js",
        ),
        (["C:", "worker.js"], "C:/worker.js", r"C:\worker.js"),
        (["C:"], "C:", "C:."),
        (["//"], "/", "\\"),
    ],
)
def test_static_join_matches_node(path_style, segments, posix, windows):
    expected = posix if path_style is posixpath else windows
    assert esbuild_static.path_call(None, "path.join", segments) == expected


@pytest.mark.parametrize(
    ("value", "posix", "windows"),
    [
        ("", ".", "."),
        ("src", ".", "."),
        ("src/", ".", "."),
        ("src///", ".", "."),
        ("src/worker.js/", "src", "src"),
        ("src//worker.js/", "src/", "src/"),
        (".", ".", "."),
        ("..", ".", "."),
        ("/", "/", "/"),
        ("//", "/", "/"),
        ("///", "/", "/"),
        ("//src", "//", "/"),
        ("//src/file", "//src", "//src/file"),
        (
            "//server/share/project/file.js",
            "//server/share/project",
            "//server/share/project",
        ),
        ("//server/share/", "//server", "//server/share/"),
        ("C:", ".", "C:"),
        ("C:/", ".", "C:/"),
        ("C:/src/", "C:", "C:/"),
        ("C:/src/file//", "C:/src", "C:/src"),
        (r"C:\src\file.js", ".", "C:\\src"),
        (r"src\worker.js", ".", "src"),
    ],
)
def test_static_dirname_matches_node(path_style, value, posix, windows):
    expected = posix if path_style is posixpath else windows
    assert esbuild_static.path_call(None, "path.dirname", [value]) == expected


@pytest.mark.parametrize(
    "segments",
    [
        ["a", "C:b"],
        ["a", r"C:\b"],
        [r"C:\project", r"D:\src", "worker.js"],
        ["a", "alternate:stream"],
    ],
)
def test_static_windows_join_abstains_on_ambiguous_colons(monkeypatch, segments):
    monkeypatch.setattr(
        esbuild_static, "os", SimpleNamespace(path=ntpath, sep=ntpath.sep)
    )
    assert esbuild_static.path_call(None, "path.join", segments) is None


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        (
            "`${dirname('src')}/src/worker.js`",
            "./src/worker.js",
        ),
        ("join(dirname('src/'), 'worker.js')", "worker.js"),
        ("join(dirname('src/worker.js/'), 'worker.js')", "src/worker.js"),
    ],
)
def test_composed_path_helpers_keep_the_correct_entry_path(
    monkeypatch, expression, expected
):
    # Parse only: neither the build script nor any JavaScript is executed.
    source = (
        "import { dirname, join } from 'node:path';\n"
        "import { build } from 'esbuild';\n"
        f"const entry = {expression};\n"
        "build({ entryPoints: [entry] });\n"
    ).encode()
    parser = analysis._entry_parser_for_path("build.mjs")
    root = parser.parse(source).root_node
    context = esbuild_static.EsbuildStaticOptions(
        source, root, "/project/build.mjs", "/project", {"build"}, set()
    )
    monkeypatch.setattr(
        esbuild_static, "os", SimpleNamespace(path=posixpath, sep=posixpath.sep)
    )
    assert context.evaluate(context.constants["entry"]) == expected
