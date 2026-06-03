from __future__ import annotations

import hashlib

from skylos.core.reference_index import (
    INDEX_CACHE_PATH,
    build_empty_index,
    build_index_payload,
    file_signature,
    validate_index_payload,
)
from skylos.core.reference_index_store import (
    changed_index_paths,
    invalidation_paths_for_changes,
    load_reference_index,
    record_file_graph,
    save_reference_index,
)


def test_build_empty_index_has_stable_schema(tmp_path):
    payload = build_empty_index(tmp_path)

    assert payload["schema_version"] == 1
    assert payload["index_kind"] == "reference_graph"
    assert payload["project_root"] == str(tmp_path.resolve())
    assert payload["files"] == {}
    assert payload["definitions"] == {}
    assert payload["references"] == []
    assert payload["imports"] == {}
    assert payload["reverse_dependencies"] == {}
    assert payload["content_graphs"] == {}
    assert validate_index_payload(payload) is True
    assert INDEX_CACHE_PATH.as_posix() == ".skylos/index/v1/reference_graph.json"


def test_file_signature_uses_relative_path_and_content_hash(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    content = b"def handler():\n    pass\n"
    source.write_bytes(content)

    signature = file_signature(tmp_path, source)

    assert signature == {
        "path": "src/app.py",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "mtime_ns": signature["mtime_ns"],
    }
    assert isinstance(signature["mtime_ns"], int)


def test_file_signature_rejects_symlink(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def handler():\n    pass\n")
    link = tmp_path / "link.py"
    link.symlink_to(target)

    assert file_signature(tmp_path, link) is None


def test_file_signature_rejects_oversized_file(tmp_path):
    source = tmp_path / "big.py"
    source.write_text("abcdef")

    assert file_signature(tmp_path, source, max_bytes=5) is None


def test_build_index_payload_normalizes_reverse_dependencies(tmp_path):
    files = {"app.py": {"path": "app.py", "sha256": "abc", "size": 1, "mtime_ns": 1}}
    content_graphs = {
        "abc": {
            "paths": ["app.py"],
            "definitions": {"app.handler": {"line": 1}},
            "references": [],
            "imports": ["os"],
        }
    }
    payload = build_index_payload(
        tmp_path,
        files=files,
        definitions={"app.handler": {"file": "app.py", "line": 1}},
        references=[{"from": "app.main", "to": "app.handler"}],
        imports={"app.py": ["os"]},
        reverse_dependencies={"app.py": ["tests/test_app.py", "tests/test_app.py"]},
        content_graphs=content_graphs,
    )

    assert validate_index_payload(payload) is True
    assert payload["files"] == files
    assert payload["reverse_dependencies"] == {"app.py": ["tests/test_app.py"]}
    assert payload["content_graphs"] == content_graphs


def test_validate_index_payload_rejects_wrong_schema(tmp_path):
    payload = build_empty_index(tmp_path)
    payload["schema_version"] = 999

    assert validate_index_payload(payload) is False


def test_record_file_graph_keys_graph_by_content_hash(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    content = b"import os\n\ndef handler():\n    return os.getcwd()\n"
    source.write_bytes(content)

    payload = record_file_graph(
        tmp_path,
        build_empty_index(tmp_path),
        source,
        definitions={"app.handler": {"file": "src/app.py", "line": 3}},
        references=[{"from": "app.handler", "to": "os.getcwd"}],
        imports=["os"],
    )

    digest = hashlib.sha256(content).hexdigest()
    assert payload is not None
    assert payload["files"]["src/app.py"]["sha256"] == digest
    assert payload["content_graphs"][digest] == {
        "sha256": digest,
        "paths": ["src/app.py"],
        "definitions": {"app.handler": {"file": "src/app.py", "line": 3}},
        "references": [{"from": "app.handler", "to": "os.getcwd"}],
        "imports": ["os"],
    }


def test_record_file_graph_preserves_paths_for_same_content_hash(tmp_path):
    first = tmp_path / "src" / "first.py"
    second = tmp_path / "src" / "second.py"
    first.parent.mkdir()
    content = b"def shared():\n    return 1\n"
    first.write_bytes(content)
    second.write_bytes(content)

    payload = record_file_graph(
        tmp_path,
        None,
        first,
        definitions={"first.shared": {"file": "src/first.py", "line": 1}},
    )
    payload = record_file_graph(
        tmp_path,
        payload,
        second,
        definitions={"second.shared": {"file": "src/second.py", "line": 1}},
    )

    digest = hashlib.sha256(content).hexdigest()
    assert payload is not None
    assert payload["content_graphs"][digest]["paths"] == [
        "src/first.py",
        "src/second.py",
    ]
    assert payload["content_graphs"][digest]["definitions"] == {
        "second.shared": {"file": "src/second.py", "line": 1}
    }


def test_save_and_load_reference_index_round_trip(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def handler():\n    return 1\n")
    payload = record_file_graph(
        tmp_path,
        None,
        source,
        definitions={"app.handler": {"file": "app.py", "line": 1}},
        references=[],
        imports=[],
    )

    assert payload is not None
    assert save_reference_index(tmp_path, payload) is True

    loaded = load_reference_index(tmp_path)

    assert loaded == payload


def test_load_reference_index_rejects_wrong_project_root(tmp_path):
    project = tmp_path / "project"
    other = tmp_path / "other"
    project.mkdir()
    other.mkdir()
    payload = build_empty_index(other)

    assert save_reference_index(project, payload) is False
    assert load_reference_index(project) is None


def test_changed_index_paths_ignores_unchanged_content(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def handler():\n    return 1\n")
    payload = record_file_graph(tmp_path, None, source)

    assert payload is not None
    assert changed_index_paths(tmp_path, payload) == []


def test_invalidation_paths_include_changed_file_and_direct_dependents(tmp_path):
    source = tmp_path / "src" / "app.py"
    test_file = tmp_path / "tests" / "test_app.py"
    source.parent.mkdir()
    test_file.parent.mkdir()
    source.write_text("def handler():\n    return 1\n")
    test_file.write_text("from src.app import handler\n")
    payload = record_file_graph(tmp_path, None, source)

    assert payload is not None
    payload["reverse_dependencies"] = {"src/app.py": ["tests/test_app.py"]}
    source.write_text("def handler():\n    return 2\n")

    assert changed_index_paths(tmp_path, payload) == ["src/app.py"]
    assert invalidation_paths_for_changes(tmp_path, payload) == [
        "src/app.py",
        "tests/test_app.py",
    ]


def test_invalidation_paths_treat_deleted_indexed_file_as_changed(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("def handler():\n    return 1\n")
    payload = record_file_graph(tmp_path, None, source)

    assert payload is not None
    payload["reverse_dependencies"] = {"src/app.py": ["tests/test_app.py"]}
    source.unlink()

    assert invalidation_paths_for_changes(tmp_path, payload) == [
        "src/app.py",
        "tests/test_app.py",
    ]


def test_invalidation_paths_treat_new_candidate_as_changed(tmp_path):
    source = tmp_path / "src" / "new_file.py"
    source.parent.mkdir()
    source.write_text("def created():\n    return 1\n")
    payload = build_empty_index(tmp_path)

    assert invalidation_paths_for_changes(
        tmp_path,
        payload,
        candidate_paths=[source],
    ) == ["src/new_file.py"]
