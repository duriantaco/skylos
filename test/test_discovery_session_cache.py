"""Discovery shares policy work inside a run, with fresh inputs next run."""

import json

import pytest

from skylos.analysis.ast_cache import python_ast_cache_session
from skylos.core import file_discovery
from skylos.visitors.languages.typescript import workspace


def test_exclusion_candidates_are_shared_across_discovery_callers(
    tmp_path, monkeypatch
):
    original = file_discovery._exclude_candidates
    calls = []

    def record(pattern, root):
        calls.append((pattern, root))
        return original(pattern, root)

    monkeypatch.setattr(file_discovery, "_exclude_candidates", record)
    patterns = ["vendor", "**/generated/**"]
    with python_ast_cache_session():
        for _ in range(4):
            assert file_discovery.should_exclude_path(
                tmp_path / "vendor" / "app.py", tmp_path, patterns
            )
            matcher = file_discovery.exclusion_matcher(tmp_path, patterns)
            assert matcher(tmp_path / "src" / "generated" / "app.py")
            assert not matcher(tmp_path / "src" / "app.py")
    assert calls == [(pattern, tmp_path) for pattern in patterns]
    with python_ast_cache_session():
        assert file_discovery.should_exclude_path(
            tmp_path / "vendor" / "app.py", tmp_path, patterns
        )
    assert calls == [(pattern, tmp_path) for pattern in patterns] * 2


def test_exclusion_cache_keeps_roots_and_policy_changes_separate(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    patterns = [str(first / "vendor")]
    with python_ast_cache_session():
        assert file_discovery.should_exclude_path(
            first / "vendor/a.py", first, patterns
        )
        assert not file_discovery.should_exclude_path(
            second / "vendor/a.py", second, patterns
        )
        patterns[:] = ["generated"]
        assert not file_discovery.should_exclude_path(
            first / "vendor/a.py", first, patterns
        )
        assert file_discovery.should_exclude_path(
            first / "generated/a.py", first, patterns
        )


def test_discovery_rechecks_symlinks_and_next_run_sees_added_deleted_files(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    first = root / "first.py"
    first.write_text("x = 1\n")
    outside = tmp_path / "outside.py"
    outside.write_text("x = 2\n")
    with python_ast_cache_session():
        assert file_discovery.discover_source_files(
            root, [".py"], respect_gitignore=False
        ) == [first]
        first.unlink()
        try:
            first.symlink_to(outside)
        except OSError:
            pytest.skip("filesystem does not allow symlink creation")
        assert (
            file_discovery.discover_source_files(root, [".py"], respect_gitignore=False)
            == []
        )
    first.unlink()
    second = root / "second.py"
    second.write_text("x = 3\n")
    with python_ast_cache_session():
        assert file_discovery.discover_source_files(
            root, [".py"], respect_gitignore=False
        ) == [second]


def test_workspace_inventory_is_shared_but_returned_values_are_independent(
    tmp_path, monkeypatch
):
    (tmp_path / "package.json").write_text(json.dumps({"name": "root"}))
    original = workspace._read_json_file
    reads = []

    def record(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(workspace, "_read_json_file", record)
    with python_ast_cache_session():
        first = workspace.discover_workspace_inventory(tmp_path)
        original_reads = list(reads)
        first.root_package.name = "modified by a caller"
        first.root_package.discovered_from.add("caller")
        first.declared_patterns.append("caller/*")
        second = workspace.discover_workspace_inventory(tmp_path)
        assert second.root_package.name == "root"
        assert second.root_package.discovered_from == {"root-package"}
        assert second.declared_patterns == []
        assert reads == original_reads


def test_workspace_inventory_refreshes_manifest_and_packages_between_runs(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"name": "before", "workspaces": ["packages/*"]}))
    pkg = tmp_path / "packages" / "one"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "one"}))
    with python_ast_cache_session():
        before = workspace.discover_workspace_inventory(tmp_path)
        assert before.root_package.name == "before"
        assert [p.name for p in before.packages] == ["one"]
    (pkg / "package.json").unlink()
    pkg.rmdir()
    added = tmp_path / "packages" / "two"
    added.mkdir()
    (added / "package.json").write_text(json.dumps({"name": "two"}))
    manifest.write_text(json.dumps({"name": "after", "workspaces": ["packages/*"]}))
    with python_ast_cache_session():
        after = workspace.discover_workspace_inventory(tmp_path)
        assert after.root_package.name == "after"
        assert [p.name for p in after.packages] == ["two"]
    manifest.write_text(json.dumps({"name": "outside", "workspaces": ["packages/*"]}))
    assert (
        workspace.discover_workspace_inventory(tmp_path).root_package.name == "outside"
    )


def test_workspace_inventory_keeps_roots_separate_and_is_uncached_outside_run(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    for root, name in [(first, "first"), (second, "second")]:
        root.mkdir()
        (root / "package.json").write_text(json.dumps({"name": name}))
    with python_ast_cache_session():
        assert (
            workspace.discover_workspace_inventory(first).root_package.name == "first"
        )
        assert (
            workspace.discover_workspace_inventory(second).root_package.name == "second"
        )
    manifest = first / "package.json"
    manifest.write_text(json.dumps({"name": "outside-one"}))
    assert (
        workspace.discover_workspace_inventory(first).root_package.name == "outside-one"
    )
    manifest.write_text(json.dumps({"name": "outside-two"}))
    assert (
        workspace.discover_workspace_inventory(first).root_package.name == "outside-two"
    )
