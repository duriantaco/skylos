import pytest

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.deadcode.same_name_definitions import SameNameGroups, _PACKAGE_READ_LIMIT


def _source(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("extension", ["java", "kt"])
def test_header_without_scan_scope_does_not_read_arbitrary_files(tmp_path, extension):
    source = _source(
        tmp_path / f"Outside.{extension}", "package outside;\nimport outside.Util;\n"
    )
    groups = SameNameGroups({}, lambda _: "jvm")

    assert groups._header(source) == (None, set())


@pytest.mark.parametrize("extension", ["java", "kt"])
def test_scoped_header_retains_real_package_and_imports(tmp_path, extension):
    source = _source(
        tmp_path / f"Main.{extension}",
        "package app;\nimport live.Util;\n/*\nimport dead.Util;\n*/\n"
        'class Doc { String text = """\nimport quoted.Util;\n"""; }\n',
    )
    groups = SameNameGroups({}, lambda _: "jvm", scan_root=tmp_path)

    assert groups._header(source) == ("app", {"live.Util"})


@pytest.mark.parametrize(
    "reference", ["absolute", "traversal", "final-link", "directory-link"]
)
def test_scoped_header_refuses_external_or_symlinked_sources(tmp_path, reference):
    root = tmp_path / "scan"
    root.mkdir()
    outside = _source(
        tmp_path / "scan-sibling/Outside.kt", "package outside\nimport outside.Util\n"
    )
    if reference == "absolute":
        source = outside
    elif reference == "traversal":
        source = root / ".." / "scan-sibling" / "Outside.kt"
    elif reference == "final-link":
        source = root / "Outside.kt"
        source.symlink_to(outside)
    else:
        (root / "linked").symlink_to(outside.parent, target_is_directory=True)
        source = root / "linked/Outside.kt"
    groups = SameNameGroups({}, lambda _: "jvm", scan_root=root)

    assert groups._header(source) == (None, set())


def test_large_source_keeps_its_early_header_without_reading_the_tail(tmp_path):
    source = _source(
        tmp_path / "Large.java",
        "package app;\nimport live.Util;\n"
        + " " * (2 * _PACKAGE_READ_LIMIT)
        + "\nimport after_limit.Util;\n",
    )
    groups = SameNameGroups({}, lambda _: "jvm", scan_root=tmp_path)

    assert groups._header(source) == ("app", {"live.Util"})


def test_prefix_reader_preserves_strict_default_and_bounded_utf8(tmp_path):
    source = _source(tmp_path / "source.txt", "é" * 1000)

    assert read_project_text_no_symlink(tmp_path, source, max_bytes=31) is None
    prefix = read_project_text_no_symlink(tmp_path, source, max_bytes=31, prefix=True)
    assert prefix == "é" * 15
    assert len(prefix.encode("utf-8")) <= 31


def test_prefix_reader_rejects_symlinks_on_fallback_platforms(tmp_path, monkeypatch):
    import skylos.core.safe_cache_io as safe_io

    source = _source(tmp_path / "source.txt", "package app;\n")
    link = tmp_path / "link.txt"
    link.symlink_to(source)
    monkeypatch.setattr(safe_io.os, "supports_dir_fd", set())

    assert (
        read_project_text_no_symlink(tmp_path, link, max_bytes=4, prefix=True) is None
    )
    assert (
        read_project_text_no_symlink(tmp_path, source, max_bytes=4, prefix=True)
        == "pack"
    )


def test_negative_prefix_budget_cannot_become_an_unbounded_read(tmp_path, monkeypatch):
    import skylos.core.safe_cache_io as safe_io

    source = _source(tmp_path / "source.txt", "private text")

    def unexpected_open(*args, **kwargs):
        raise AssertionError("invalid byte budget must be rejected before opening")

    monkeypatch.setattr(safe_io.os, "open", unexpected_open)

    assert safe_io.read_text_no_symlink(source, max_bytes=-1, prefix=True) is None
    assert (
        read_project_text_no_symlink(tmp_path, source, max_bytes=-1, prefix=True)
        is None
    )
