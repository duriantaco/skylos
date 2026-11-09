"""Trace path normalization is lexical and shared across repeated findings."""

import copy
import os
from pathlib import Path

import pytest

from skylos.security.static_trace import attach_security_traces
from skylos.security.static_trace_index import ProjectTraceIndex


class _PathLike:
    def __init__(self, value):
        self.value = value

    def __fspath__(self):
        return self.value


def test_repeated_trace_paths_normalize_once_per_input(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    index = ProjectTraceIndex(root, [])
    outside = str(tmp_path / "outside.py")
    absolute = str(root / "module.py")
    values = [
        ("module.py", "module.py"),
        (Path("module.py"), "module.py"),
        (_PathLike("module.py"), "module.py"),
        (absolute, "module.py"),
        (Path(absolute), "module.py"),
        (outside, None),
        (Path(outside), None),
        ("../outside.py", None),
    ]
    original = os.path.abspath
    normalizations = 0

    def counted(value):
        nonlocal normalizations
        normalizations += 1
        return original(value)

    monkeypatch.setattr(os.path, "abspath", counted)
    for _ in range(400):
        for value, expected in values:
            assert index.relative_path(value) == expected
    assert normalizations == len({os.fspath(value) for value, _ in values})


@pytest.mark.parametrize(
    "value, expected",
    [
        (".", "."),
        ("sub/../module.py", "module.py"),
        ("sub/../../outside.py", None),
        ("../project/module.py", "module.py"),
        ("../project-other/module.py", None),
        ("link/module.py", "link/module.py"),
        ("link/../module.py", "module.py"),
    ],
)
def test_trace_paths_keep_lexical_normalization(tmp_path, value, expected):
    root = tmp_path / "project"
    root.mkdir()
    index = ProjectTraceIndex(root, [])
    assert index.relative_path(value) == expected
    assert index.relative_path(value) == expected


def test_trace_paths_do_not_follow_symlinks(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")
    index = ProjectTraceIndex(root, [])

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata paths must not resolve or inspect symlinks")

    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "is_symlink", forbidden)
    for _ in range(2):
        assert index.relative_path(root / "link" / "module.py") == "link/module.py"
        assert index.relative_path(root / "link" / ".." / "module.py") == "module.py"


def test_trace_path_cache_is_local_to_its_root_and_index(tmp_path):
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = ProjectTraceIndex(first_root, [])
    second = ProjectTraceIndex(second_root, [])
    path = first_root / "module.py"
    assert first.relative_path(path) == "module.py"
    assert second.relative_path(path) is None
    first.root = second_root
    assert first.relative_path(path) is None
    first.root = first_root
    assert first.relative_path(path) == "module.py"


def test_trace_path_cache_preserves_the_input_case(tmp_path):
    index = ProjectTraceIndex(tmp_path, [])
    assert index.relative_path("Upper.py") == "Upper.py"
    assert index.relative_path("upper.py") == "upper.py"


@pytest.mark.parametrize("value", [None, b"module.py", _PathLike(123)])
def test_trace_path_cache_preserves_invalid_input_errors(tmp_path, value):
    index = ProjectTraceIndex(tmp_path, [])
    with pytest.raises(TypeError):
        index.relative_path(value)


def test_trace_path_cache_preserves_all_400_trace_documents(tmp_path, monkeypatch):
    path = tmp_path / "loads.py"
    path.write_text(
        "import yaml\ndata = input()\n"
        + "".join(f"yaml.load(data, Loader=missing_{i})\n" for i in range(400))
    )
    findings = [
        {
            "rule_id": "SKY-D206",
            "severity": "HIGH",
            "file": str(path),
            "line": i + 3,
            "col": 0,
            "message": "yaml.load without SafeLoader",
        }
        for i in range(400)
    ]
    cached = copy.deepcopy(findings)
    attach_security_traces(cached, project_root=tmp_path, files=[path])

    def uncached(self, value):
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        candidate = Path(os.path.abspath(candidate))
        try:
            return candidate.relative_to(self.root).as_posix()
        except ValueError:
            return None

    monkeypatch.setattr(ProjectTraceIndex, "relative_path", uncached)
    reference = copy.deepcopy(findings)
    attach_security_traces(reference, project_root=tmp_path, files=[path])
    assert len(cached) == 400
    assert cached == reference
    assert all("security_trace" in row["metadata"] for row in cached)
