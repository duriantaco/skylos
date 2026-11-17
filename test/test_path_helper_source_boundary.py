"""Containment proofs must read only bounded, regular project source files."""

import ast
import os
from pathlib import Path

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs import path_flow
from test.fixture_paths import write_fixture


@pytest.fixture(autouse=True)
def clear_helper_proofs():
    path_flow.reset_containment_proofs()
    yield
    path_flow.reset_containment_proofs()


@pytest.mark.parametrize("kind", ["absolute", "parent", "sibling"])
def test_helper_parser_rejects_paths_outside_project(tmp_path, monkeypatch, kind):
    root = tmp_path / "project"
    root.mkdir()
    if kind == "sibling":
        outside = write_fixture(tmp_path, "project_extra/helper.py", "value = 1\n")
        candidate = outside
    else:
        outside = write_fixture(tmp_path, "helper.py", "value = 1\n")
        candidate = outside if kind == "absolute" else Path("../helper.py")
        if kind == "parent":
            monkeypatch.chdir(root)

    assert path_flow._parsed_module(candidate, root) is None


@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
def test_helper_parser_rejects_symlink_escape(tmp_path, directory):
    root = tmp_path / "project"
    root.mkdir()
    outside = write_fixture(tmp_path, "external/helper.py", "value = 1\n")
    if directory:
        (root / "linked").symlink_to(outside.parent, target_is_directory=True)
        candidate = root / "linked" / "helper.py"
    else:
        candidate = root / "helper.py"
        candidate.symlink_to(outside)

    assert path_flow._parsed_module(candidate, root) is None


def test_helper_parser_rejects_symlink_even_when_target_is_inside_project(tmp_path):
    source = write_fixture(tmp_path, "actual.py", "value = 1\n")
    link = tmp_path / "helper.py"
    link.symlink_to(source)

    assert path_flow._parsed_module(link, tmp_path) is None


def test_helper_parser_requires_project_root(tmp_path):
    source = write_fixture(tmp_path, "helper.py", "value = 1\n")

    assert path_flow._parsed_module(source, None) is None


@pytest.mark.parametrize("relative", [False, True], ids=["absolute", "relative"])
def test_regular_project_helper_still_parses(tmp_path, monkeypatch, relative):
    source = write_fixture(tmp_path, "pkg/helper.py", "value = 1\n")
    candidate = source.relative_to(tmp_path) if relative else source
    if relative:
        monkeypatch.chdir(tmp_path)

    tree = path_flow._parsed_module(candidate, tmp_path)

    assert isinstance(tree, ast.Module)
    assert tree.body[0].value.value == 1


@pytest.mark.parametrize(
    "content",
    [b"#" + b"x" * 2_000_000, b"value = '\xff'\n", b"def broken(:\n"],
    ids=["oversize", "invalid-utf8", "invalid-python"],
)
def test_invalid_or_oversize_project_helper_cannot_supply_proof(tmp_path, content):
    source = tmp_path / "helper.py"
    source.write_bytes(content)

    assert path_flow._parsed_module(source, tmp_path) is None


def test_cached_helper_cannot_be_replaced_by_matching_stat_symlink(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = write_fixture(root, "helper.py", "value = 1\n")
    before = source.stat()
    assert path_flow._parsed_module(source, root) is not None
    outside = write_fixture(tmp_path, "outside.py", "value = 2\n")
    os.utime(outside, ns=(before.st_atime_ns, before.st_mtime_ns))
    source.unlink()
    source.symlink_to(outside)
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert source.stat().st_size == before.st_size

    assert path_flow._parsed_module(source, root) is None


def test_cached_helper_from_wider_root_cannot_escape_narrower_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = write_fixture(tmp_path, "helper.py", "value = 1\n")
    assert path_flow._parsed_module(outside, tmp_path) is not None

    assert path_flow._parsed_module(outside, root) is None


_SANITIZER = """import os

def contain(base, name):
    base = os.path.realpath(base)
    candidate = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, candidate]) != base:
        raise ValueError('outside')
    return candidate
"""


def test_containment_proof_cache_is_scoped_to_project_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    helper = write_fixture(tmp_path, "security.py", _SANITIZER)
    tainted = frozenset({"name"})
    assert path_flow._prove_containment(helper, "contain", tainted, tmp_path)

    assert not path_flow._prove_containment(helper, "contain", tainted, root)


@pytest.mark.parametrize("kind", ["internal", "file-symlink", "directory-symlink"])
def test_imported_helper_proof_requires_regular_project_source(tmp_path, kind):
    root = tmp_path / "project"
    root.mkdir()
    if kind == "internal":
        write_fixture(root, "helpers/security.py", _SANITIZER)
        write_fixture(root, "helpers/__init__.py", "")
    else:
        external = write_fixture(tmp_path, "external/security.py", _SANITIZER)
        if kind == "file-symlink":
            write_fixture(root, "helpers/__init__.py", "")
            (root / "helpers" / "security.py").symlink_to(external)
        else:
            write_fixture(tmp_path, "external/__init__.py", "")
            (root / "helpers").symlink_to(external.parent, target_is_directory=True)
    source = (
        "from fastapi import FastAPI\n"
        "from helpers.security import contain\n"
        "app = FastAPI()\n"
        "@app.get('/files/{name:path}')\n"
        "def read_file(name: str):\n"
        "    path = contain('/srv/files', name)\n"
        "    with open(path, 'rb') as handle:\n"
        "        return handle.read()\n"
    )
    app = write_fixture(root, "app.py", source)

    findings = scan_ctx(root, [app])
    traversal = [row for row in findings if row["rule_id"] == "SKY-D215"]

    assert bool(traversal) is (kind != "internal")
    assert all(row["line"] == 7 and row["symbol"] == "read_file" for row in traversal)
