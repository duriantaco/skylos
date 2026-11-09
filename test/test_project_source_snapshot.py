"""A partial or stale project snapshot must never supply a safety proof."""

import ast
import os
from pathlib import Path

import pytest

from skylos.rules.danger import project_source
from skylos.rules.danger.source_owned_code import source_owned_code_calls


def _source(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_snapshot_addition_exposes_a_new_reader_monkeypatch(tmp_path):
    core = _source(tmp_path, "package/core.py", "value = 1\n")
    before, complete = project_source.project_source_snapshot(tmp_path)
    assert complete
    assert core in before

    patcher = _source(
        tmp_path,
        "patcher.py",
        "from pathlib import Path\nPath.read_text = lambda self: external_input\n",
    )
    after, complete = project_source.project_source_snapshot(tmp_path)
    assert complete
    assert patcher in after
    assert any(
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Store)
        and node.attr == "read_text"
        for node in ast.walk(after[patcher])
    )


def test_same_size_rewrite_with_restored_mtime_invalidates_cached_ast(tmp_path):
    path = _source(tmp_path, "patcher.py", "reader = safe\n")
    before, complete = project_source.project_source_snapshot(tmp_path)
    assert complete
    stat = path.stat()

    path.write_text("reader = evil\n")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert path.stat().st_size == stat.st_size
    assert path.stat().st_mtime_ns == stat.st_mtime_ns

    after, complete = project_source.project_source_snapshot(tmp_path)
    assert complete
    assert before[path].body[0].value.id == "safe"
    assert after[path].body[0].value.id == "evil"


def test_invalid_new_module_does_not_reuse_an_earlier_complete_snapshot(tmp_path):
    _source(tmp_path, "runner.py", "value = 1\n")
    _, complete = project_source.project_source_snapshot(tmp_path)
    assert complete

    _source(tmp_path, "plugin.py", "def invalid(:\n")
    trees, complete = project_source.project_source_snapshot(tmp_path)
    assert not complete
    assert not trees


@pytest.mark.parametrize("extension", [".py", ".pyw", ".pyi"])
def test_every_python_source_extension_participates_in_the_snapshot(
    tmp_path, extension
):
    path = _source(
        tmp_path,
        "plugin" + extension,
        "from pathlib import Path\nPath.read_text = replacement\n",
    )
    trees, complete = project_source.project_source_snapshot(tmp_path)
    assert complete
    assert path in trees


@pytest.mark.parametrize("directory_link", [False, True])
def test_symlink_cannot_hide_project_code(tmp_path, directory_link):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = _source(outside, "patcher.py", "value = external_input\n")
    if directory_link:
        (root / "plugins").symlink_to(outside, target_is_directory=True)
    else:
        (root / "patcher.py").symlink_to(target)

    trees, complete = project_source.project_source_snapshot(root)
    assert not complete
    assert not trees


@pytest.mark.parametrize(
    "budget, maximum, files",
    [
        ("_MAX_FILES", 1, {"one.py": "pass\n", "two.py": "pass\n"}),
        ("_MAX_FILE_BYTES", 4, {"one.py": "value = 1\n"}),
        ("_MAX_TOTAL_BYTES", 9, {"one.py": "pass\n", "two.py": "pass\n"}),
        ("_MAX_NODES", 1, {"one.py": "value = 1\n"}),
    ],
)
def test_exhausted_source_budget_is_incomplete(
    tmp_path, monkeypatch, budget, maximum, files
):
    for relative, text in files.items():
        _source(tmp_path, relative, text)
    monkeypatch.setattr(project_source, budget, maximum)

    trees, complete = project_source.project_source_snapshot(tmp_path)
    assert not complete
    assert not trees


def test_unreadable_inventory_does_not_supply_a_partial_snapshot(tmp_path, monkeypatch):
    _source(tmp_path, "runner.py", "value = 1\n")
    real_walk = project_source.os.walk

    def interrupted_walk(root, onerror):
        yield from real_walk(root, onerror=onerror)
        onerror(PermissionError("plugin directory could not be enumerated"))

    monkeypatch.setattr(project_source.os, "walk", interrupted_walk)
    trees, complete = project_source.project_source_snapshot(tmp_path)
    assert not complete
    assert not trees


def test_snapshot_root_resolution_failure_is_not_a_safety_proof(tmp_path, monkeypatch):
    def denied(_path):
        raise OSError("project root cannot be resolved")

    monkeypatch.setattr(Path, "resolve", denied)
    trees, complete = project_source.project_source_snapshot(tmp_path)
    assert not complete
    assert not trees


def _owned_runner(root):
    _source(root, "package/core.py", "value = 1\n")
    path = _source(
        root,
        "runner.py",
        "import ast\nfrom pathlib import Path\n"
        "SOURCE = Path(__file__).parent / 'package' / 'core.py'\n"
        "def run():\n"
        "    tree = ast.parse(SOURCE.read_text())\n"
        "    exec(compile(tree, 'core.py', 'exec'), {})\n",
    )
    return path, ast.parse(path.read_text())


def test_adding_a_reader_monkeypatch_revokes_source_execution_proof(tmp_path):
    path, tree = _owned_runner(tmp_path)
    assert source_owned_code_calls(tree, path, tmp_path)

    _source(
        tmp_path,
        "patcher.py",
        "from pathlib import Path\nPath.read_text = replacement\n",
    )
    assert not source_owned_code_calls(tree, path, tmp_path)


def test_same_size_rewrite_revokes_source_execution_proof(tmp_path):
    path, tree = _owned_runner(tmp_path)
    benign = "from pathlib import Path\nreader = None\n"
    mutation = "from pathlib import Path\nPath.read_text = replacement\n"
    size = max(len(benign), len(mutation))
    patcher = _source(tmp_path, "patcher.py", benign.ljust(size))
    assert source_owned_code_calls(tree, path, tmp_path)
    stat = patcher.stat()

    patcher.write_text(mutation.ljust(size))
    os.utime(patcher, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert patcher.stat().st_size == stat.st_size
    assert patcher.stat().st_mtime_ns == stat.st_mtime_ns
    assert not source_owned_code_calls(tree, path, tmp_path)
