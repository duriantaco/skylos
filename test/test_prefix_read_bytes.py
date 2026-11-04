import pytest

from skylos.core import safe_cache_io


@pytest.mark.parametrize("reader", ["direct", "project", "fallback"])
@pytest.mark.parametrize(
    ("data", "budget", "errors", "newline", "expected"),
    [
        (b"\xff" * 32 + b"package hidden;\n", 8, "ignore", None, ""),
        (b"\r\n" * 8 + b"package hidden;\n", 16, None, None, "\n" * 8),
        (b"\r\n" * 8 + b"package hidden;\n", 16, None, "", "\r\n" * 8),
        (b"package " + b"\xff" * 32, 8, None, None, "package "),
        ("é".encode() * 16, 3, None, None, "é"),
        (b"\xffpackage hidden;\n", 8, None, None, None),
        (b"package app;\n", 0, None, None, ""),
    ],
)
def test_prefix_budget_is_applied_before_decoding(
    tmp_path, monkeypatch, reader, data, budget, errors, newline, expected
):
    path = tmp_path / "header.java"
    path.write_bytes(data)
    if reader == "fallback":
        monkeypatch.setattr(safe_cache_io.os, "supports_dir_fd", set())
    options = dict(max_bytes=budget, errors=errors, newline=newline, prefix=True)

    if reader == "direct":
        actual = safe_cache_io.read_text_no_symlink(path, **options)
    else:
        actual = safe_cache_io.read_project_text_no_symlink(tmp_path, path, **options)

    assert actual == expected
