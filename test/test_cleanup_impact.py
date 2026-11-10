from hashlib import sha256

import pytest

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


def test_unchanged_crlf_sources_keep_resolved_callers_and_tests(tmp_path):
    task = _project(tmp_path)
    for file in tmp_path.glob("*.py"):
        file.write_bytes(file.read_bytes().replace(b"\n", b"\r\n"))
    task["source_sha256"] = sha256((tmp_path / "service.py").read_bytes()).hexdigest()
    result = build_cleanup_impact([task], tmp_path)
    item = result["tasks"][0]
    assert result["status"] == "complete" and result["limitations"] == []
    assert item["resolution"] == "static_symbol"
    assert {row["file"] for row in item["callers"]} == {"caller.py"}
    assert {row["file"] for row in item["suggested_tests"]} == {"test_service.py"}


@pytest.mark.parametrize(
    "file,source",
    [
        ("service.py", b"def calculate(value):\r\n    return value + 1\r\n"),
        (
            "service.ts",
            b"export function calculate(value: number) {\r\n    return value + 1;\r\n}\r\n",
        ),
    ],
)
def test_crlf_digest_matches_the_original_raw_source_snapshot(tmp_path, file, source):
    (tmp_path / file).write_bytes(source)
    task = {
        "id": "task",
        "file": file,
        "line": 1,
        "name": "calculate",
        "source_sha256": sha256(source).hexdigest(),
    }
    result = build_cleanup_impact([task], tmp_path)
    assert result["status"] == "complete" and result["limitations"] == []
    assert result["tasks"][0]["resolution"] == "static_symbol"
    assert (tmp_path / file).read_bytes() == source


@pytest.mark.parametrize("unavailable", [False, True])
def test_stale_or_missing_selected_source_never_claims_complete_impact(
    tmp_path, unavailable
):
    task = _project(tmp_path)
    if unavailable:
        (tmp_path / "service.py").unlink()
    else:
        (tmp_path / "service.py").write_text(
            "def calculate(value):\n    return value + 2\n"
        )
    result = build_cleanup_impact([task], tmp_path)
    assert result["status"] == "partial"
    assert any("service.py" in note for note in result["limitations"])
    item = result["tasks"][0]
    assert item["resolution"] == (
        "source_unavailable" if unavailable else "stale_source"
    )
    assert item["callers"] == item["possible_callers"] == item["suggested_tests"] == []


def test_source_becoming_unreadable_after_extraction_remains_partial(
    tmp_path, monkeypatch
):
    from skylos import cleanup_impact

    task = _project(tmp_path)
    original = cleanup_impact.read_project_text_no_symlink
    reads = 0

    def unavailable_on_recheck(root, file, **kwargs):
        nonlocal reads
        if file == "service.py":
            reads += 1
            if reads == 2:
                return None
        return original(root, file, **kwargs)

    monkeypatch.setattr(
        cleanup_impact, "read_project_text_no_symlink", unavailable_on_recheck
    )
    result = build_cleanup_impact([task], tmp_path)
    assert result["status"] == "partial"
    assert "Graph source changed during analysis" in result["limitations"]
    assert result["tasks"][0]["resolution"] == "stale_source"
    assert result["tasks"][0]["callers"] == result["tasks"][0]["suggested_tests"] == []
