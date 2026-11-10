"""Named plans retain evidence and never become edit or verification authority."""

from copy import deepcopy
from hashlib import sha256

import pytest

from skylos.cleanup import build_cleanup_plan
from skylos.cleanup_plans import (
    complete_cleanup_plan_task,
    create_cleanup_plan,
    move_cleanup_plan_task,
    view_cleanup_plans,
)
from skylos.cleanup_state import load_cleanup_state, update_cleanup_state


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "app.py").write_text("import math\nimport json\n")
    scope = {
        "target": str(tmp_path),
        "project_root": str(tmp_path),
        "scanner_version": "test",
        "config_digest": sha256(b"config").hexdigest(),
    }
    raw = {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
        },
        "unused_imports": [
            {
                "name": name,
                "file": str(tmp_path / "app.py"),
                "line": line,
                "confidence": 100,
            }
            for line, name in enumerate(("math", "json"), 1)
        ],
    }
    queue = build_cleanup_plan(raw, project_root=tmp_path, top=None)
    for task in queue["tasks"]:
        task["scope"] = deepcopy(scope)
    update_cleanup_state(tmp_path, scope, queue)
    return tmp_path, scope, queue


def create(workspace):
    root, scope, queue = workspace
    return create_cleanup_plan(
        root, scope, queue, "imports", [task["id"][:12] for task in queue["tasks"]]
    )


def test_plan_roundtrip_order_and_manual_completion_preserve_scanner_state(workspace):
    root, scope, queue = workspace
    original = deepcopy(queue)
    before = load_cleanup_state(root)
    plan = create(workspace)
    first, second = [step["id"] for step in plan["steps"]]
    moved = move_cleanup_plan_task(
        root, scope, queue, "imports", second[:12], before=first[:12]
    )
    assert [step["id"] for step in moved["steps"]] == [second, first]
    completed = complete_cleanup_plan_task(
        root, scope, queue, "imports", second, note="Reviewed manually"
    )
    assert completed["steps"][0]["completion"] == "completed"
    assert completed["steps"][0]["verification_status"] == "unverified"
    assert completed["execution_authorized"] is False
    view = view_cleanup_plans(root, scope, queue, "imports")
    assert view["completed_steps"] == 1 and view["status"] == "current"
    assert queue == original
    old = next(iter(before["scopes"].values()))["tasks"]
    assert next(iter(load_cleanup_state(root)["scopes"].values()))["tasks"] == old
    assert (root / "app.py").read_text() == "import math\nimport json\n"


def test_prerequisites_and_acceptance_checks_are_only_data(workspace):
    root, scope, queue = workspace
    marker = root / "must-not-run"
    command = f"touch {marker}"
    plan = create_cleanup_plan(
        root,
        scope,
        queue,
        "manual",
        [queue["tasks"][0]["id"]],
        prerequisites=["API owner review"],
        acceptance_checks=[command],
    )
    assert plan["acceptance_checks"] == [command]
    assert plan["prerequisites"] == ["API owner review"]
    assert plan["execution_authorized"] is False and not marker.exists()


@pytest.mark.parametrize("name", ["", "../escape", "a/b", ".hidden", "x" * 81])
def test_invalid_plan_names_cannot_mutate_history(workspace, name):
    root, scope, queue = workspace
    before = (root / ".skylos/cache/cleanup.json").read_bytes()
    with pytest.raises(ValueError, match="Plan names"):
        create_cleanup_plan(root, scope, queue, name, [queue["tasks"][0]["id"]])
    assert (root / ".skylos/cache/cleanup.json").read_bytes() == before


def test_unknown_ambiguous_duplicate_and_hidden_inventory_ids_are_rejected(workspace):
    root, scope, queue = workspace
    for ids in [["missing"], [queue["tasks"][0]["id"], queue["tasks"][0]["id"]]]:
        with pytest.raises(ValueError, match="unknown or ambiguous|duplicate"):
            create_cleanup_plan(root, scope, queue, "imports", ids)
    altered = deepcopy(queue)
    altered["tasks"][0]["id"] = "a" * 64
    altered["tasks"][1]["id"] = "a" * 63 + "b"
    with pytest.raises(ValueError, match="ambiguous"):
        create_cleanup_plan(root, scope, altered, "imports", ["a"])
    hidden = {**queue, "tasks": [], "_inventory": queue["tasks"]}
    with pytest.raises(ValueError, match="unknown"):
        create_cleanup_plan(root, scope, hidden, "imports", [queue["tasks"][0]["id"]])


def test_stale_source_needs_completion_note_and_reordering_never_refreshes_it(
    workspace,
):
    root, scope, queue = workspace
    plan = create(workspace)
    first, second = [step["id"] for step in plan["steps"]]
    (root / "app.py").write_text("import math\nimport json\nvalue = math.pi\n")
    view = view_cleanup_plans(root, scope, queue, "imports")
    assert view["status"] == "needs_refresh"
    assert all(step["refresh_status"] == "stale" for step in view["steps"])
    with pytest.raises(ValueError, match="requires a note"):
        complete_cleanup_plan_task(root, scope, queue, "imports", first)
    moved = move_cleanup_plan_task(root, scope, queue, "imports", first, before=second)
    assert moved["status"] == "needs_refresh"
    completed = complete_cleanup_plan_task(
        root, scope, queue, "imports", first, note="Replaced in a reviewed change"
    )
    step = next(step for step in completed["steps"] if step["id"] == first)
    assert (
        step["completion"] == "completed"
        and step["completed_with_evidence_status"] == "stale"
    )
    assert (
        step["refresh_status"] == "stale"
        and step["verification_status"] == "unverified"
    )


def test_absence_or_hidden_task_never_completes_a_step(workspace):
    root, scope, queue = workspace
    create(workspace)
    empty = {**queue, "status": "clear", "tasks": []}
    view = view_cleanup_plans(root, scope, empty, "imports")
    assert all(
        step["refresh_status"] == "not_reported_in_view" for step in view["steps"]
    )
    assert all(
        step["completion"] == "open" and step["verification_status"] == "unverified"
        for step in view["steps"]
    )
    with pytest.raises(ValueError, match="requires a note"):
        complete_cleanup_plan_task(
            root, scope, empty, "imports", view["steps"][0]["id"]
        )
    completed = complete_cleanup_plan_task(
        root,
        scope,
        empty,
        "imports",
        view["steps"][0]["id"],
        note="Manually reviewed; detector absence is not behavior proof",
    )
    assert completed["steps"][0]["completion"] == "completed"
    assert completed["steps"][0]["refresh_status"] == "not_reported_in_view"
    assert completed["steps"][0]["verification_status"] == "unverified"


@pytest.mark.parametrize(
    "change",
    [{"config_digest": "new"}, {"scanner_version": "other"}, {"target": "/elsewhere"}],
)
def test_scope_change_cannot_reuse_a_plan(workspace, change):
    root, scope, queue = workspace
    create(workspace)
    with pytest.raises(ValueError, match="unknown|outside|different"):
        view_cleanup_plans(root, {**scope, **change}, queue, "imports")
    with pytest.raises(ValueError, match="different|outside"):
        create_cleanup_plan(
            root, {**scope, **change}, queue, "other", [queue["tasks"][0]["id"]]
        )


def test_incomplete_queue_duplicate_name_and_noop_move_do_not_replace_state(workspace):
    root, scope, queue = workspace
    plan = create(workspace)
    before = (root / ".skylos/cache/cleanup.json").read_bytes()
    with pytest.raises(ValueError, match="complete"):
        view_cleanup_plans(root, scope, {**queue, "status": "incomplete"}, "imports")
    with pytest.raises(ValueError, match="already exists"):
        create(workspace)
    with pytest.raises(ValueError, match="itself"):
        move_cleanup_plan_task(
            root,
            scope,
            queue,
            "imports",
            plan["steps"][0]["id"],
            before=plan["steps"][0]["id"],
        )
    assert (root / ".skylos/cache/cleanup.json").read_bytes() == before


def test_symlinked_source_cannot_enter_a_plan(workspace, tmp_path):
    root, scope, queue = workspace
    file = root / "app.py"
    target = root / "other.py"
    target.write_text(file.read_text())
    file.unlink()
    file.symlink_to(target)
    with pytest.raises(ValueError, match="unavailable or stale"):
        create(workspace)


def test_source_change_before_transaction_cannot_store_a_current_plan(
    workspace, monkeypatch
):
    from skylos import cleanup_plans

    root, _scope, _queue = workspace
    mutate = cleanup_plans._mutate
    before = (root / ".skylos/cache/cleanup.json").read_bytes()

    def race(root, scope, callback):
        (root / "app.py").write_text("# changed during planning\n")
        return mutate(root, scope, callback)

    monkeypatch.setattr(cleanup_plans, "_mutate", race)
    with pytest.raises(ValueError, match="changed before"):
        create(workspace)
    assert (root / ".skylos/cache/cleanup.json").read_bytes() == before
