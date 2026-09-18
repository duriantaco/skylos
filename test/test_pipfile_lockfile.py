"""Trusted synthetic Pipenv locks; no Pipenv installation or target execution."""

import json
from pathlib import Path

import pytest

from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError
from skylos.rules.sca.pipfile_lockfile import parse_pipfile_lock


PUBLIC = {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}
PRIVATE = {
    "name": "private",
    "url": "https://user:secret@private.example/simple",
    "verify_ssl": True,
}


def document(*, sources=None, default=None, develop=None, **groups):
    return {
        "_meta": {
            "pipfile-spec": 6,
            "sources": [PUBLIC] if sources is None else sources,
            "requires": {"python_version": "3.11"},
        },
        "default": default or {},
        "develop": develop or {},
        **groups,
    }


def parse(data, **kwargs):
    return parse_pipfile_lock(Path("Pipfile.lock"), text=json.dumps(data), **kwargs)


def test_all_categories_versions_and_markers_are_preserved_without_invented_edges():
    result = parse(
        document(
            default={
                "Parent_Pkg": {
                    "version": "==1.2.3",
                    "markers": 'sys_platform == "linux"',
                    "python_version": ">=3.10",
                },
                "child": {"version": "==1.0.0"},
            },
            develop={"child": {"version": "==2.0.0"}},
            docs={"sphinx": {"version": "==7.0.0"}},
        )
    )
    assert result.package_count == 4
    assert result.unresolved == []
    assert [(d["name"], d["version"]) for d in result.dependencies] == [
        ("parent-pkg", "1.2.3"),
        ("child", "1.0.0"),
        ("child", "2.0.0"),
        ("sphinx", "7.0.0"),
    ]
    parent, _, dev, docs = result.dependencies
    assert parent["dependency_groups"] == ["default"]
    assert parent["dependency_dev"] is False
    assert dev["dependency_dev"] is True
    assert docs["dependency_dev"] is None
    assert parent["dependency_kind"] == "unknown"
    assert all(d["dependency_graph_complete"] is False for d in result.dependencies)
    assert parent["dependency_markers"] == {
        "markers": 'sys_platform == "linux"',
        "python_version": ">=3.10",
    }
    assert parent["marker_evaluation"] == "not_evaluated"
    assert parent["lockfile_requires_python"] == "3.11"
    assert {d["package_path"] for d in result.dependencies} == {
        "default.parent-pkg",
        "default.child",
        "develop.child",
        "docs.sphinx",
    }


@pytest.mark.parametrize(
    "sources,entry,reason",
    [
        ([PRIVATE], {"version": "==1.0.0"}, "non_public_registry"),
        (
            [PUBLIC, PRIVATE],
            {"version": "==1.0.0", "index": "private"},
            "non_public_registry",
        ),
        (
            [PUBLIC],
            {"version": "==1.0.0", "index": "missing"},
            "invalid_package_source",
        ),
        (
            [PUBLIC],
            {"version": "==1.0.0", "git": "https://secret@example/repo"},
            "non_registry_source",
        ),
        (
            [PUBLIC],
            {"version": "==1.0.0", "file": "https://secret@example/pkg.whl"},
            "non_registry_source",
        ),
        ([PUBLIC], {"version": "==1.0.0", "editable": True}, "non_registry_source"),
        ([PUBLIC], {"path": "./pkg", "editable": "false"}, "invalid_package_source"),
    ],
)
def test_nonpublic_or_direct_sources_are_explicit_gaps(sources, entry, reason):
    result = parse(document(sources=sources, default={"private-pkg": entry}))
    assert result.dependencies == []
    assert result.unresolved[0]["reason"] == reason
    assert result.non_registry_names == ["private-pkg"]
    assert "secret" not in repr(result)


def test_unindexed_package_uses_public_first_source_not_private_second():
    result = parse(
        document(
            sources=[PUBLIC, PRIVATE],
            default={"public-pkg": {"version": "==1.0.0"}},
        )
    )
    assert result.unresolved == []
    assert result.dependencies[0]["source_type"] == "registry_unspecified"


def test_local_path_counted_but_not_queried_or_read():
    result = parse(
        document(
            default={
                "local-pkg": {"path": "./libs/local", "editable": True},
                "public-pkg": {"version": "==2.0.0"},
            }
        )
    )
    assert result.local_package_count == 1
    assert result.workspace_paths == ["libs/local"]
    assert result.non_registry_names == ["local-pkg"]
    assert [d["name"] for d in result.dependencies] == ["public-pkg"]


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        "{broken",
        '{"_meta":{"pipfile-spec":6,"sources":[]}}',
        '{"_meta":{"pipfile-spec":7,"sources":[]}}',
        '{"_meta":{"pipfile-spec":6,"pipfile-spec":6,"sources":[]}}',
        "NaN",
    ],
)
def test_malformed_and_future_locks_fail_explicitly(text):
    with pytest.raises(LockfileParseError):
        parse_pipfile_lock(Path("Pipfile.lock"), text=text)


def test_duplicate_source_names_are_rejected():
    with pytest.raises(LockfileParseError, match="duplicate source names"):
        parse(document(sources=[PUBLIC, {**PUBLIC, "url": PRIVATE["url"]}]))


def test_valid_packages_survive_bad_entries_and_invalid_versions():
    result = parse(
        document(
            default={
                "good": {"version": "==1.0.0"},
                "bad": {"version": ">=2"},
                "missing": {},
            }
        )
    )
    assert [d["name"] for d in result.dependencies] == ["good"]
    assert [issue["reason"] for issue in result.unresolved] == [
        "invalid_locked_version",
        "invalid_locked_version",
    ]


def test_package_limit_and_byte_limit():
    data = document(default={"one": {"version": "==1.0"}})
    with pytest.raises(LockfileLimitError):
        parse(data, max_packages=0)
    with pytest.raises(LockfileLimitError):
        parse_pipfile_lock(Path("Pipfile.lock"), text=" " * 10_000_001)


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "data.json"
    target.write_text(json.dumps(document()), encoding="utf-8")
    linked = tmp_path / "Pipfile.lock"
    linked.symlink_to(target)
    with pytest.raises(LockfileParseError, match="unreadable or unsafe"):
        parse_pipfile_lock(linked)


def test_line_is_structural_package_version_not_json_string_decoy():
    data = document(default={"real": {"version": "==1.2.3"}})
    data["_meta"]["hash"] = {"sha256": '\\"real\\": {\\"version\\": \\"==9.9.9\\"}'}
    text = json.dumps(data, indent=2)
    record = parse_pipfile_lock(Path("Pipfile.lock"), text=text).dependencies[0]
    assert record["line"] == next(
        index
        for index, line in enumerate(text.splitlines(), 1)
        if line.strip() == '"version": "==1.2.3"'
    )
