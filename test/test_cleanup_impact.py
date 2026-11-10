from hashlib import sha256

from skylos.cleanup_impact import build_cleanup_impact
from skylos.cleanup_context import build_cleanup_context


def _project(root):
    (root / "service.py").write_text("def calculate(value):\n    return value + 1\n")
    (root / "caller.py").write_text(
        "from service import calculate as compute\n\ndef run():\n    return compute(1)\n"
    )
    (root / "test_service.py").write_text(
        "from service import calculate as compute\n\ndef test_result():\n    assert compute(1) == 2\n"
    )
    (root / "unrelated.py").write_text(
        "class Foreign:\n    def calculate(self, value):\n        return value\n\ndef call_foreign():\n    return Foreign().calculate(1)\n"
    )
    source = (root / "service.py").read_bytes()
    return {
        "id": "task",
        "file": "service.py",
        "line": 1,
        "name": "calculate",
        "source_sha256": sha256(source).hexdigest(),
    }


def test_resolves_import_aliases_and_suggests_tests_without_name_confusion(tmp_path):
    task = _project(tmp_path)
    result = build_cleanup_impact([task], tmp_path)
    item = result["tasks"][0]
    assert item["resolution"] == "static_symbol"
    assert {row["file"] for row in item["callers"]} == {"caller.py"}
    assert {row["file"] for row in item["suggested_tests"]} == {"test_service.py"}
    assert result["status"] == "complete"
    assert not (tmp_path / ".skylos").exists()


def test_scope_exclusions_and_budget_are_explicit(tmp_path):
    task = _project(tmp_path)
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "another.py").write_text(
        "from service import calculate\n\ndef generated():\n    return calculate(1)\n"
    )
    result = build_cleanup_impact([task], tmp_path, exclude_folders=("generated",))
    assert all(
        row["file"] != "generated/another.py" for row in result["tasks"][0]["callers"]
    )
    bounded = build_cleanup_impact([task], tmp_path, max_files=1)
    assert bounded["status"] == "partial"
    assert bounded["parsed_files"] == 1
    assert bounded["limitations"]


def test_stale_task_does_not_get_current_source_impact(tmp_path):
    task = _project(tmp_path)
    (tmp_path / "service.py").write_text(
        "def calculate(value):\n    return value + 2\n"
    )
    item = build_cleanup_impact([task], tmp_path)["tasks"][0]
    assert item["resolution"] == "stale_source"
    assert item["callers"] == item["suggested_tests"] == []


def test_unparseable_or_unavailable_sources_do_not_claim_complete_context(tmp_path):
    task = _project(tmp_path)
    (tmp_path / "caller.py").write_text("def broken(\n")
    result = build_cleanup_impact([task], tmp_path)
    assert result["status"] == "partial"
    assert any("caller.py" in note for note in result["limitations"])


def test_context_includes_resolved_importer_and_reaching_test_source(tmp_path):
    task = _project(tmp_path)
    result = build_cleanup_context([task], tmp_path)
    assert {row["file"] for row in result["files"]} == {
        "service.py",
        "caller.py",
        "test_service.py",
        "unrelated.py",
    }
    # Legacy simple-name evidence remains explicitly separate from graph edges.
    assert {row["file"] for row in result["impact"]["tasks"][0]["callers"]} == {
        "caller.py"
    }
    assert result["suggested_tests"][0]["authorization"] == "suggestion_only"
    assert result["suggested_tests"][0]["selection"][-1] == "test_service.py"
