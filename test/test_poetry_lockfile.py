"""Trusted synthetic lockfile data; no Poetry, package installation, or network."""

import json
from pathlib import Path

import pytest

from skylos.rules.sca import poetry_lockfile
from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError
from skylos.rules.sca.poetry_lockfile import parse_poetry_lock


def _toml(value):
    if isinstance(value, dict):
        return (
            "{"
            + ", ".join(
                json.dumps(key) + " = " + _toml(item) for key, item in value.items()
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    return json.dumps(value)


def package(name="example", version="1.2.3", **metadata):
    return {
        "name": name,
        "version": version,
        "optional": False,
        "python-versions": ">=3.9",
        **metadata,
    }


def document(*packages, version="2.1", extras=None, python=">=3.10"):
    text = "" if packages else "package = []\n"
    for record in packages:
        text += "[[package]]\n"
        text += "".join(
            json.dumps(key) + " = " + _toml(value) + "\n"
            for key, value in record.items()
        )
    if extras is not None:
        text += "[extras]\n" + "".join(
            json.dumps(key) + " = " + _toml(value) + "\n"
            for key, value in extras.items()
        )
    return (
        text
        + "[metadata]\nlock-version = "
        + _toml(version)
        + "\npython-versions = "
        + _toml(python)
        + "\n"
    )


def parse(text, **kwargs):
    return parse_poetry_lock(Path("poetry.lock"), text=text, **kwargs)


@pytest.mark.parametrize("version", ["1.0", "1.1", "2.0", "2.1"])
def test_supported_formats_keep_transitives_and_multiple_versions(version):
    result = parse(
        document(
            package("Parent_Pkg", dependencies={"child": "==1.0.0"}),
            package("child", "1.0.0"),
            package("child", "2.0.0"),
            version=version,
        )
    )
    assert result.package_count == 3
    assert result.unresolved == []
    assert [(dep["name"], dep["version"]) for dep in result.dependencies] == [
        ("parent-pkg", "1.2.3"),
        ("child", "1.0.0"),
        ("child", "2.0.0"),
    ]
    parent = result.dependencies[0]
    assert parent["dependencies"][0]["package_path"] == "package[1]"
    assert parent["lockfile_version"] == int(version[0])
    assert parent["lockfile_revision"] == int(version[2])
    assert all(dep["dependency_kind"] == "unknown" for dep in result.dependencies)
    assert all(
        dep["source_type"] == "registry_unspecified" for dep in result.dependencies
    )


def test_groups_optional_markers_extras_and_python_context_preserved():
    result = parse(
        document(
            package(
                "parent",
                groups=["dev", "main"],
                optional=True,
                markers={
                    "main": 'sys_platform == "win32"',
                    "dev": 'python_version < "3.12"',
                },
                extras={"speed": ["child (>=2)"]},
                dependencies={
                    "child": {
                        "version": "2.0.0",
                        "optional": True,
                        "extras": ["fast"],
                        "markers": 'sys_platform == "win32"',
                    }
                },
            ),
            package("child", "2.0.0", groups=["dev"]),
            extras={"web": ["parent"]},
        )
    )
    parent, child = result.dependencies
    assert parent["dependency_groups"] == ["dev", "main"]
    assert parent["dependency_dev"] is False
    assert child["dependency_dev"] is True
    assert parent["dependency_optional"] is True
    assert parent["dependency_markers"]["groups"] == {
        "dev": 'python_version < "3.12"',
        "main": 'sys_platform == "win32"',
    }
    assert parent["requires_python"] == ">=3.9"
    assert parent["lockfile_requires_python"] == ">=3.10"
    assert parent["dependency_extras"] == ["web"]
    assert parent["dependency_extra_requirements"]["speed"] == [
        {"name": "child", "requirement": "child (>=2)"}
    ]
    assert parent["dependencies"][0]["optional"] is True
    assert parent["dependencies"][0]["extras"] == ["fast"]
    assert parent["environment_scope"] == "all_locked_environments"
    assert parent["marker_evaluation"] == "not_evaluated"


@pytest.mark.parametrize(
    "category,expected", [("main", False), ("dev", True), ("test", None)]
)
def test_legacy_categories_and_requirements(category, expected):
    result = parse(
        document(
            package(
                category=category,
                marker='sys_platform == "linux"',
                requirements={"python": ">=3.8", "platform": "linux"},
            ),
            version="1.0",
        )
    )
    record = result.dependencies[0]
    assert record["dependency_groups"] == [category]
    assert record["dependency_dev"] is expected
    assert record["dependency_markers"] == {
        "marker": 'sys_platform == "linux"',
        "requirements": {"python": ">=3.8", "platform": "linux"},
    }


def test_old_format_does_not_invent_missing_groups_or_development_context():
    record = parse(document(package(), version="2.0")).dependencies[0]
    assert record["dependency_groups"] == []
    assert record["dependency_dev"] is None


def test_custom_group_does_not_automatically_mean_development():
    record = parse(document(package(groups=["production"]))).dependencies[0]
    assert record["dependency_groups"] == ["production"]
    assert record["dependency_dev"] is None


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org/simple",
        "https://pypi.org/simple/",
        "https://pypi.python.org:443/simple",
    ],
)
def test_explicit_public_pypi_source(url):
    result = parse(
        document(package(source={"type": "legacy", "url": url, "reference": "pypi"}))
    )
    assert result.unresolved == []
    assert result.dependencies[0]["source_type"] == "registry"
    assert url not in repr(result.dependencies)


@pytest.mark.parametrize(
    "source,reason",
    [
        (
            {"type": "legacy", "url": "https://user:secret@private.example/simple"},
            "non_public_registry",
        ),
        (
            {"type": "legacy", "url": "https://pypi.org/simple?token=secret"},
            "non_public_registry",
        ),
        ({"type": "legacy", "url": "http://pypi.org/simple"}, "non_public_registry"),
        (
            {"type": "legacy", "url": "https://pypi.org:8443/simple"},
            "non_public_registry",
        ),
        (
            {
                "type": "git",
                "url": "https://user:secret@private.example/code",
                "reference": "secret",
            },
            "non_registry_source",
        ),
        (
            {"type": "url", "url": "https://private.example/archive?secret"},
            "non_registry_source",
        ),
        ({"type": "file", "url": "../secret.whl"}, "non_registry_source"),
        ({"type": "unknown", "url": "secret"}, "unsupported_package_source"),
        (
            {
                "type": "legacy",
                "url": "https://pypi.org/simple",
                "resolved_reference": "secret",
            },
            "invalid_package_source",
        ),
        ({}, "invalid_package_source"),
        ("secret", "invalid_package_source"),
    ],
)
def test_nonpublic_sources_remain_explicit_without_leaking_values(source, reason):
    result = parse(document(package("private", source=source), package("public")))
    assert [dep["name"] for dep in result.dependencies] == ["public"]
    assert result.unresolved[0]["reason"] == reason
    assert result.unresolved[0]["name"] == "private"
    assert result.non_registry_names == ["private"]
    assert "secret" not in repr(result)
    assert "secret" not in repr(result.unresolved)


@pytest.mark.parametrize(
    "source,path",
    [
        ("libs/app", "libs/app"),
        ("./libs/app", "libs/app"),
        (".", ""),
        ("../sibling", None),
        ("/outside", None),
    ],
)
def test_local_directories_are_counted_without_reading_target_paths(
    source, path, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("local source must not be read")

    monkeypatch.setattr(poetry_lockfile, "read_text_no_symlink", forbidden)
    result = parse(
        document(
            package("local", source={"type": "directory", "url": source}),
            package("public"),
        )
    )
    assert result.package_count == 2
    assert result.local_package_count == 1
    assert result.non_registry_names == ["local"]
    assert result.workspace_paths == ([] if path is None else [path])
    assert [dep["name"] for dep in result.dependencies] == ["public"]


def test_sources_in_dependency_edges_and_extra_requirements_are_redacted():
    result = parse(
        document(
            package(
                "parent",
                dependencies={
                    "child": {
                        "git": "https://user:secret@host.example/repo",
                        "branch": "secret",
                    }
                },
                extras={"feature": ["child @ https://user:secret@host.example/repo"]},
            ),
            package(
                "child",
                source={"type": "git", "url": "https://user:secret@host.example/repo"},
            ),
        )
    )
    assert "secret" not in repr(result.dependencies)
    assert "secret" not in repr(result.unresolved)
    parent = result.dependencies[0]
    assert parent["dependencies"][0]["source_type"] == "non_registry"
    assert parent["dependency_extra_requirements"]["feature"] == [
        {"name": "child", "source_type": "non_registry"}
    ]


def test_range_edges_are_not_misrepresented_as_evaluated_graph_relationships():
    result = parse(
        document(
            package("parent", dependencies={"child": ">=1"}), package("child", "2.0")
        )
    )
    edge = result.dependencies[0]["dependencies"][0]
    assert edge["version_spec"] == ">=1"
    assert edge["resolution"] == "version_constraint_not_evaluated"
    assert "package_path" not in edge
    assert result.dependencies[0]["dependency_graph_complete"] is False
    assert result.unresolved == []


def test_multiple_environment_edges_and_unrecorded_root_dependency():
    result = parse(
        document(
            package(
                "parent",
                dependencies={
                    "child": [
                        {"version": "1.0", "markers": 'python_version < "3.10"'},
                        {"version": "2.0", "markers": 'python_version >= "3.10"'},
                    ],
                    "absent": "*",
                },
            ),
            package("child", "1.0"),
            package("child", "2.0"),
        )
    )
    edges = result.dependencies[0]["dependencies"]
    assert [edge.get("package_path") for edge in edges] == [
        "package[1]",
        "package[2]",
        None,
    ]
    assert edges[2]["resolution"] == "dependency_not_recorded"
    assert result.dependencies[0]["dependency_graph_complete"] is False
    assert result.unresolved == []


def test_duplicate_name_and_version_context_does_not_choose_arbitrary_target():
    result = parse(
        document(
            package("parent", dependencies={"child": "1.0"}),
            package("child", "1.0", groups=["main"]),
            package("child", "1.0", groups=["dev"]),
        )
    )
    edge = result.dependencies[0]["dependencies"][0]
    assert "package_path" not in edge
    assert edge["resolution"] == "source_or_environment_not_resolved"
    assert len(result.dependencies) == 3


def test_equivalent_version_spellings_do_not_report_missing_package():
    result = parse(
        document(
            package("parent", dependencies={"child": "1.0"}), package("child", "1.0.0")
        )
    )
    edge = result.dependencies[0]["dependencies"][0]
    assert "package_path" not in edge
    assert edge["resolution"] == "version_constraint_not_evaluated"
    assert result.unresolved == []


@pytest.mark.parametrize(
    "version",
    [
        "1.0",
        "1!2.0",
        "1.0rc1",
        "1.0.post1",
        "1.0.dev1",
        "1.0+local.2",
        "1.0RC1",
        "v1.0",
        "1.0-1",
    ],
)
def test_exact_pep440_versions_remain_queryable(version):
    assert (
        parse(document(package(version=version))).dependencies[0]["version"] == version
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("name", "https://private.example/secret", "invalid_package_name"),
        ("version", "^1.0", "invalid_locked_version"),
        ("version", "https://secret", "invalid_locked_version"),
    ],
)
def test_invalid_package_identity_is_gap_not_silent_drop(field, value, reason):
    bad = package()
    bad[field] = value
    result = parse(document(bad, package("good")))
    assert len(result.dependencies) == 1
    assert result.unresolved[0]["reason"] == reason
    assert "secret" not in repr(result.unresolved)


def test_line_locations_ignore_multiline_descriptions_and_metadata_names():
    text = '''[[package]]
name = "first"
version = "1.0"
description = """
[[package]]
name = "not-a-package"
"""
[[package]]
name = "second"
version = "2.0"
[metadata]
lock-version = "2.1"
'''
    assert [dep["line"] for dep in parse(text).dependencies] == [2, 9]


@pytest.mark.parametrize("version", ["0.9", "1.2", "2.2", "3.0", 2, True, [], {}])
def test_unknown_formats_rejected(version):
    with pytest.raises(LockfileParseError):
        parse(document(package(), version=version))


@pytest.mark.parametrize(
    "metadata",
    [
        {"groups": "main"},
        {"optional": "true"},
        {"develop": "false"},
        {"markers": ["linux"]},
        {"groups": ["main"], "markers": {"dev": "*"}},
        {"python-versions": 3},
        {"dependencies": []},
        {"dependencies": {"child": []}},
        {"dependencies": {"child": {"optional": True}}},
        {"dependencies": {"child": {"version": "*", "unknown": "field"}}},
        {"dependencies": {"child": {"version": "*", "optional": "true"}}},
        {"extras": {"feature": "child"}},
        {"requirements": {"unknown": "value"}},
    ],
)
def test_malformed_context_does_not_silently_produce_complete_inventory(metadata):
    with pytest.raises(LockfileParseError):
        parse(document(package(**metadata)))


def test_empty_inventory_is_valid():
    result = parse(document())
    assert result.package_count == 0
    assert result.dependencies == []
    assert result.unresolved == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[broken",
        '[metadata]\nlock-version="2.1"',
        'package = {}\n[metadata]\nlock-version="2.1"',
    ],
)
def test_malformed_structure_is_explicit(text):
    with pytest.raises(LockfileParseError):
        parse(text)


def test_package_limit_counts_local_packages():
    with pytest.raises(LockfileLimitError):
        parse(
            document(
                package(source={"type": "directory", "url": "."}), package("child")
            ),
            max_packages=1,
        )


def test_byte_edge_and_tree_limits(monkeypatch):
    text = document(package("parent", dependencies={"child": "1", "other": "2"}))
    with monkeypatch.context() as scope:
        scope.setattr(poetry_lockfile, "MAX_POETRY_LOCK_BYTES", len(text.encode()) - 1)
        with pytest.raises(LockfileLimitError):
            parse(text)
    with monkeypatch.context() as scope:
        scope.setattr(poetry_lockfile, "MAX_DEPENDENCY_EDGES", 1)
        with pytest.raises(LockfileLimitError):
            parse(text)
    with monkeypatch.context() as scope:
        scope.setattr(poetry_lockfile, "MAX_TREE_NODES", 2)
        with pytest.raises(LockfileLimitError):
            parse(text)
    with monkeypatch.context() as scope:
        scope.setattr(poetry_lockfile, "MAX_TREE_DEPTH", 1)
        with pytest.raises(LockfileLimitError):
            parse(text)


def test_read_uses_bounded_no_symlink_helper(monkeypatch):
    calls = []

    def read(path, **kwargs):
        calls.append((path, kwargs))
        return document(package())

    monkeypatch.setattr(poetry_lockfile, "read_text_no_symlink", read)
    result = parse_poetry_lock(Path("poetry.lock"))
    assert len(result.dependencies) == 1
    assert calls == [
        (Path("poetry.lock"), {"max_bytes": 10_000_000, "encoding": "utf-8"})
    ]


def test_unreadable_file_does_not_return_empty_success(monkeypatch):
    monkeypatch.setattr(
        poetry_lockfile, "read_text_no_symlink", lambda *args, **kwargs: None
    )
    with pytest.raises(LockfileParseError, match="unreadable"):
        parse_poetry_lock(Path("not-present-poetry.lock"))
