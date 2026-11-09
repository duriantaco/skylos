"""Display choices cannot turn observed cleanup work into detector absence."""

from copy import deepcopy
import io
import json

import pytest

from skylos.cleanup import build_cleanup_plan
from skylos.cleanup_state import update_cleanup_state
from skylos.commands.cleanup_cmd import run_cleanup_command


def _report(root, *, marked=True):
    (root / "app.py").write_text(
        'def render(value):\n    return f"{str(value)}"\n', encoding="utf-8"
    )
    finding = {
        "rule_id": "SKY-L038",
        "file": str(root / "app.py"),
        "line": 2,
        "name": "render",
        "severity": "LOW",
        "message": "Use an f-string conversion flag",
    }
    if marked:
        finding["listing"] = {
            "version": 1,
            "listed": False,
            "reason": "measurement",
        }
    report = {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
            "comparison_scope": {"scan_path": str(root)},
        },
        "quality": [finding],
        "ai_defects": [],
        "unused_imports": [],
    }
    if marked:
        report["listing_policy_version"] = 1
    return report


def _run(root, raw, *args):
    output = io.StringIO()
    code = run_cleanup_command(
        [str(root), "--format", "json", *args],
        stdout=output,
        analyze_func=lambda *_a, **_kw: deepcopy(raw),
    )
    return code, json.loads(output.getvalue())


@pytest.mark.parametrize("marked", [False, True])
def test_hiding_observed_optional_advice_keeps_same_open_history(tmp_path, marked):
    raw = _report(tmp_path, marked=marked)
    before = deepcopy(raw)
    code, expanded = _run(tmp_path, raw, "--all-advice")
    assert code == 0
    task_id = expanded["advisories"][0]["id"]
    scope_id = expanded["state"]["scope_id"]

    code, focused = _run(tmp_path, raw)
    assert code == 0 and focused["status"] == "clear"
    assert focused["advisories"] == []
    assert focused["counts"]["optional_advice"] == 1
    assert focused["state"]["scope_id"] == scope_id
    record = focused["state"]["tasks"][task_id]
    assert record["status"] == "open"
    assert record["history"] == []

    code, expanded_again = _run(tmp_path, raw, "--all-advice")
    assert code == 0
    assert expanded_again["advisories"][0]["id"] == task_id
    assert expanded_again["state"]["tasks"][task_id]["history"] == []
    assert raw == before


def test_hidden_advice_is_observed_even_before_expanding_the_queue(tmp_path):
    raw = _report(tmp_path)
    _, focused = _run(tmp_path, raw)
    assert focused["advisories"] == []
    assert len(focused["state"]["tasks"]) == 1
    task_id, record = next(iter(focused["state"]["tasks"].items()))
    assert record["status"] == "open"

    _, expanded = _run(tmp_path, raw, "--all-advice")
    assert expanded["advisories"][0]["id"] == task_id
    assert expanded["state"]["tasks"][task_id]["history"] == []


def test_deferred_advice_survives_hidden_and_expanded_views(tmp_path):
    raw = _report(tmp_path)
    _, expanded = _run(tmp_path, raw, "--all-advice")
    task_id = expanded["advisories"][0]["id"]
    code, deferred = _run(
        tmp_path, raw, "--all-advice", "--defer", task_id, "--reason", "Review later"
    )
    assert code == 0
    first_history = deferred["state"]["tasks"][task_id]["history"]
    for args in [(), ("--all-advice",)]:
        code, report = _run(tmp_path, raw, *args)
        assert code == 0 and report["advisories"] == []
        assert report["state"]["tasks"][task_id]["status"] == "deferred"
        assert report["state"]["tasks"][task_id]["history"] == first_history


@pytest.mark.parametrize("incomplete", [False, True])
def test_actual_absence_requires_complete_analysis_not_a_visibility_change(
    tmp_path, incomplete
):
    raw = _report(tmp_path)
    _, expanded = _run(tmp_path, raw, "--all-advice")
    task_id = expanded["advisories"][0]["id"]
    absent = deepcopy(raw)
    absent["quality"] = []
    if incomplete:
        absent["analysis_errors"] = [{"kind": "syntax_error", "file": "other.py"}]
    code, report = _run(tmp_path, absent)
    record = report["state"]["tasks"][task_id]
    assert code == (2 if incomplete else 0)
    assert record["status"] == ("open" if incomplete else "not_reported")
    if not incomplete:
        assert record["history"][-1]["status"] == "not_reported"
        assert "behavior is not verified" in record["history"][-1]["reason"]


def test_builder_inventory_protects_direct_state_callers_and_display_limits(tmp_path):
    raw = _report(tmp_path)
    scope = {"target": str(tmp_path), "config_digest": "same"}
    expanded = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)
    task_id = expanded["advisories"][0]["id"]
    update_cleanup_state(tmp_path, scope, expanded)
    focused = build_cleanup_plan(raw, project_root=tmp_path, top=1)
    assert focused["advisories"] == []

    state = update_cleanup_state(tmp_path, scope, focused)
    assert state["tasks"][task_id]["status"] == "open"
    assert state["tasks"][task_id]["history"] == []


def test_limited_builder_view_does_not_mark_other_observations_absent(tmp_path):
    raw = _report(tmp_path)
    for name in ("first.py", "second.py"):
        (tmp_path / name).write_text("1 + 1\n", encoding="utf-8")
        raw["quality"].append(
            {
                "rule_id": "SKY-L033",
                "file": str(tmp_path / name),
                "line": 1,
                "severity": "MEDIUM",
                "message": "Statement has no effect",
                "listing": {"version": 1, "listed": True, "reason": "finding"},
            }
        )
    scope = {"target": str(tmp_path), "config_digest": "same"}
    full = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)
    initial = update_cleanup_state(tmp_path, scope, full)
    limited = build_cleanup_plan(raw, project_root=tmp_path, top=1)
    assert len(limited["tasks"]) == 1 and limited["advisories"] == []

    state = update_cleanup_state(tmp_path, scope, limited)
    assert len(state["tasks"]) == len(initial["tasks"]) == 3
    assert {task["status"] for task in state["tasks"].values()} == {"open"}
    assert all(task["history"] == [] for task in state["tasks"].values())
    assert all(
        set(task) == {"id", "rule_id", "file", "name", "source_sha256"}
        for task in limited["_inventory"]
    )


def test_duplicate_identity_disambiguation_is_independent_of_visibility(tmp_path):
    raw = _report(tmp_path)
    listed = deepcopy(raw["quality"][0])
    listed["listing"] = {"version": 1, "listed": True, "reason": "evidence"}
    raw["quality"].append(listed)
    _, expanded = _run(tmp_path, raw, "--all-advice")
    initial_ids = set(expanded["state"]["tasks"])
    assert len(initial_ids) == 2

    _, focused = _run(tmp_path, raw)
    assert len(focused["advisories"]) == 1
    assert focused["advisories"][0]["id"] in initial_ids
    assert set(focused["state"]["tasks"]) == initial_ids
    assert all(
        task["status"] == "open" and task["history"] == []
        for task in focused["state"]["tasks"].values()
    )


@pytest.mark.parametrize("inventory", [{}, [None], [{"id": "task"}]])
def test_malformed_inventory_preserves_last_complete_history(tmp_path, inventory):
    raw = _report(tmp_path)
    scope = {"target": str(tmp_path), "config_digest": "same"}
    plan = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)
    original = update_cleanup_state(tmp_path, scope, plan)
    from skylos.cleanup_state import STATE_PATH, load_cleanup_state, scope_identity

    saved = (tmp_path / STATE_PATH).read_bytes()
    with pytest.raises(ValueError, match="inventory is malformed"):
        update_cleanup_state(tmp_path, scope, plan, inventory=inventory)
    assert (tmp_path / STATE_PATH).read_bytes() == saved
    assert load_cleanup_state(tmp_path)["scopes"][scope_identity(scope)] == original


def test_hidden_inventory_never_enters_context_patch_selection_or_public_json(
    tmp_path, monkeypatch
):
    raw = _report(tmp_path)
    (tmp_path / "other.py").write_text("1 + 1\n", encoding="utf-8")
    raw["quality"].append(
        {
            "rule_id": "SKY-L033",
            "file": str(tmp_path / "other.py"),
            "line": 1,
            "name": "other",
            "severity": "MEDIUM",
            "message": "Statement has no effect",
            "listing": {"version": 1, "listed": True, "reason": "finding"},
        }
    )
    captured = []

    def context(tasks, *_a, **_kw):
        captured.extend(tasks)
        return {"files": []}

    monkeypatch.setattr("skylos.cleanup_context.build_cleanup_context", context)
    code, report = _run(tmp_path, raw, "--context")
    assert code == 0
    assert [task["rule_id"] for task in captured] == ["SKY-L033"]
    assert "_inventory" not in report
    assert len(report["state"]["tasks"]) == 2
    hidden = next(
        task_id
        for task_id, task in report["state"]["tasks"].items()
        if task["rule_id"] == "SKY-L038"
    )
    original_source = (tmp_path / "app.py").read_bytes()
    code, preview = _run(tmp_path, raw, "--task", hidden)
    assert code == 2 and "edit" not in preview
    assert (tmp_path / "app.py").read_bytes() == original_source
