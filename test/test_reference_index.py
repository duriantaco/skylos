from __future__ import annotations

import hashlib

from skylos.core.reference_index import (
    INDEX_CACHE_PATH,
    build_empty_index,
    build_index_payload,
    file_signature,
    validate_index_payload,
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
    payload = build_index_payload(
        tmp_path,
        files=files,
        definitions={"app.handler": {"file": "app.py", "line": 1}},
        references=[{"from": "app.main", "to": "app.handler"}],
        imports={"app.py": ["os"]},
        reverse_dependencies={"app.py": ["tests/test_app.py", "tests/test_app.py"]},
    )

    assert validate_index_payload(payload) is True
    assert payload["files"] == files
    assert payload["reverse_dependencies"] == {"app.py": ["tests/test_app.py"]}


def test_validate_index_payload_rejects_wrong_schema(tmp_path):
    payload = build_empty_index(tmp_path)
    payload["schema_version"] = 999

    assert validate_index_payload(payload) is False
