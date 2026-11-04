from collections import Counter
from pathlib import Path

import pytest

from skylos.reporting.rollups import build_directory_rollups


def test_repeated_findings_normalize_each_file_and_root_once(tmp_path, monkeypatch):
    source = tmp_path / "loads.py"
    result = {
        "danger": [
            {"file": str(source), "rule_id": "SKY-D206", "severity": "HIGH"}
            for _ in range(400)
        ]
    }
    resolved = []
    original = Path.resolve

    def counted(path, *args, **kwargs):
        resolved.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counted)

    assert build_directory_rollups(result, tmp_path) == [
        {
            "path": ".",
            "total": 400,
            "files": 1,
            "security": 400,
            "rules": {"SKY-D206": 400},
            "severities": {"HIGH": 400},
        }
    ]
    assert Counter(resolved) == Counter({str(tmp_path): 1, str(source): 1})


def test_mixed_sections_share_path_work_and_preserve_all_totals(tmp_path, monkeypatch):
    source = tmp_path / "src" / "a.py"
    other = tmp_path / "src" / "b.py"
    outside = tmp_path.parent / "outside" / "secret.txt"
    result = {
        "quality": [
            {"file": str(source), "code": "SKY-Q301", "severity": " warn "},
            None,
        ],
        "danger": [{"file_path": str(source).replace("/", "\\"), "rule": "SKY-D206"}],
        "unused_functions": [{"file": str(other)}],
        "secrets": [{"file": str(outside), "id": "secret", "severity": ""}],
        "dependency_vulnerabilities": [{}],
    }
    calls = []
    original = Path.resolve

    def counted(path, *args, **kwargs):
        calls.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counted)
    assert build_directory_rollups(result, tmp_path) == [
        {
            "path": "src",
            "total": 3,
            "files": 2,
            "dead_code": 1,
            "quality": 1,
            "security": 1,
            "rules": {"SKY-D206": 1, "SKY-Q301": 1, "unused-functions": 1},
            "severities": {"HIGH": 1, "WARN": 1, "LOW": 1},
        },
        {
            "path": ".",
            "total": 1,
            "files": 1,
            "dependencies": 1,
            "rules": {"dependency-vulnerabilities": 1},
            "severities": {"HIGH": 1},
        },
        {
            "path": str(outside.parent),
            "total": 1,
            "files": 1,
            "secrets": 1,
            "rules": {"secret": 1},
            "severities": {"HIGH": 1},
        },
    ]
    assert Counter(calls) == Counter(
        {str(tmp_path): 1, str(source): 1, str(other): 1, str(outside): 1}
    )


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        ({"file": "src/a.py"}, "src"),
        ({"file": "src\\nested\\a.py"}, "src/nested"),
        ({"file": "", "file_path": "fallback/a.py"}, "fallback"),
        ({}, "."),
        ({"file": "?"}, "."),
    ],
)
def test_paths_without_root_keep_existing_fallbacks(finding, expected, monkeypatch):
    def unexpected_resolve(*args, **kwargs):
        pytest.fail("a path without a scan root needs no filesystem resolution")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    assert build_directory_rollups({"danger": [finding]}, None) == [
        {
            "path": expected,
            "total": 1,
            "files": 1,
            "security": 1,
            "rules": {"danger": 1},
            "severities": {"HIGH": 1},
        }
    ]


def test_absolute_path_without_root_is_not_resolved(tmp_path, monkeypatch):
    source = tmp_path / "src" / "a.py"

    def unexpected_resolve(*args, **kwargs):
        pytest.fail("an absolute path without a scan root needs no resolution")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    [row] = build_directory_rollups({"danger": [{"file": str(source)}]}, None)
    assert row["path"] == str(source.parent)
    assert row["files"] == row["total"] == row["security"] == 1


def test_relative_paths_do_not_resolve_unused_root(tmp_path, monkeypatch):
    def unexpected_resolve(*args, **kwargs):
        pytest.fail("relative file paths need no filesystem resolution")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    [row] = build_directory_rollups({"danger": [{"file": "src/a.py"}]}, tmp_path)
    assert row["path"] == "src"
    assert row["files"] == row["total"] == row["security"] == 1


def test_file_symlink_is_resolved_again_for_each_build(tmp_path):
    inside = tmp_path / "src" / "inside.py"
    inside.parent.mkdir()
    inside.touch()
    outside = tmp_path.parent / f"{tmp_path.name}-outside" / "outside.py"
    outside.parent.mkdir()
    outside.touch()
    link = tmp_path / "linked.py"
    link.symlink_to(inside)
    findings = {"danger": [{"file": str(link)}]}

    assert build_directory_rollups(findings, tmp_path)[0]["path"] == "src"
    link.unlink()
    link.symlink_to(outside)
    assert build_directory_rollups(findings, tmp_path)[0]["path"] == str(tmp_path)


def test_root_symlink_is_resolved_again_for_each_build(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    link = tmp_path / "root"
    link.symlink_to(first, target_is_directory=True)
    source = first / "src" / "a.py"
    findings = {"danger": [{"file": str(source)}]}

    assert build_directory_rollups(findings, link)[0]["path"] == "src"
    link.unlink()
    link.symlink_to(second, target_is_directory=True)
    assert build_directory_rollups(findings, link)[0]["path"] == str(source.parent)


@pytest.mark.parametrize("failed_path", ["root", "file"])
@pytest.mark.parametrize("error", [OSError, ValueError])
def test_resolution_failures_keep_original_absolute_path(
    tmp_path, monkeypatch, failed_path, error
):
    source = tmp_path / "src" / "a.py"
    original = Path.resolve

    def failed(path, *args, **kwargs):
        target = tmp_path if failed_path == "root" else source
        if path == target:
            raise error("cannot resolve")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failed)
    assert build_directory_rollups({"danger": [{"file": str(source)}]}, tmp_path) == [
        {
            "path": str(source.parent),
            "total": 1,
            "files": 1,
            "security": 1,
            "rules": {"danger": 1},
            "severities": {"HIGH": 1},
        }
    ]
