"""Review freshness covers supplied graph facts beyond the cited excerpts."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from skylos.cleanup_context import build_cleanup_context, review_cleanup_context
from skylos.cleanup_plans import (
    _context_is_current,
    create_cleanup_plan,
    view_cleanup_plans,
)
from skylos.cleanup_review_state import (
    promote_cleanup_review,
    store_cleanup_review,
    view_cleanup_reviews,
)
from skylos.cleanup_state import load_cleanup_state, mutate_cleanup_workspace


def _project(root, *, callers=20):
    source = "def calculate(value):\n    return value + 1\n"
    (root / "service.py").write_text(source)
    for number in range(callers):
        (root / f"caller{number:02}.py").write_text(
            f"from service import calculate\n\ndef caller{number}():\n    return calculate(1)\n"
        )
    scope = {
        "project_root": str(root),
        "target": str(root),
        "scanner_version": "fixture",
        "config_digest": sha256(b"config").hexdigest(),
    }
    task = {
        "id": "a" * 64,
        "file": "service.py",
        "line": 1,
        "name": "calculate",
        "rule_id": "SKY-U001",
        "source_sha256": sha256(source.encode()).hexdigest(),
        "source_anchor": "source-anchor",
        "scope": scope,
    }
    context = build_cleanup_context([task], root)
    review = {
        "status": "reviewed",
        "kind": "subjective_advice",
        "advice": [
            {
                "file": "service.py",
                "line": 1,
                "summary": "Review helper responsibility",
                "evidence": "The supplied helper adds one",
                "suggestion": "Review its supplied callers",
                "confidence": "medium",
            }
        ],
    }
    queue = {"status": "ready", "tasks": [task], "advisories": []}
    return scope, task, queue, context, review


def _store(root, scope, review, context):
    return store_cleanup_review(
        root, scope, review, context, model="fixture", provider="local"
    )[0]


def test_graph_sources_outside_twelve_excerpts_remain_review_and_plan_dependencies(
    tmp_path,
):
    scope, _task, queue, context, review = _project(tmp_path)
    excerpts = {row["file"] for row in context["files"]}
    callers = {row["file"] for row in context["impact"]["tasks"][0]["callers"]}
    assert len(excerpts) == 12 and len(callers) == 20
    omitted = sorted(callers - excerpts)[0]
    record = _store(tmp_path, scope, review, context)
    assert omitted not in record["context_source_hashes"]
    assert (
        record["context_dependency_hashes"][omitted]
        == sha256((tmp_path / omitted).read_bytes()).hexdigest()
    )
    create_cleanup_plan(tmp_path, scope, queue, "callers", [queue["tasks"][0]["id"]])
    promote_cleanup_review(tmp_path, scope, queue, record["id"], "callers")
    (tmp_path / omitted).write_text("def changed():\n    return 0\n")
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "stale"
    plan = view_cleanup_plans(tmp_path, scope, queue, "callers")
    assert plan["steps"][-1]["refresh_status"] == "stale"
    assert plan["steps"][-1]["verification_status"] == "unverified"
    with pytest.raises(ValueError, match="stale"):
        promote_cleanup_review(tmp_path, scope, queue, record["id"], "callers")


def test_legacy_name_candidate_sources_are_tracked_outside_the_graph_budget(
    tmp_path, monkeypatch
):
    from skylos import cleanup_impact

    original = cleanup_impact.build_cleanup_impact
    monkeypatch.setattr(
        cleanup_impact,
        "build_cleanup_impact",
        lambda *args, **kwargs: original(*args, **kwargs, max_files=1),
    )
    scope, _task, _queue, context, review = _project(tmp_path, callers=1)
    assert "caller00.py" not in context["impact"]["source_hashes"]
    assert any(row["file"] == "caller00.py" for row in context["candidate_callers"])
    record = _store(tmp_path, scope, review, context)
    assert "caller00.py" in record["context_dependency_hashes"]
    (tmp_path / "caller00.py").unlink()
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "stale"


def test_hash_manifests_are_persisted_without_sending_them_to_the_model(tmp_path):
    _scope, task, _queue, context, _review = _project(tmp_path, callers=1)
    original = deepcopy(context)

    class Model:
        payload = None

        def complete(self, _system, payload, **_kwargs):
            self.payload = json.loads(payload)
            return '{"advice":[]}'

    model = Model()
    result = review_cleanup_context(context, [task], model)
    assert result["status"] == "reviewed"
    assert "context_dependency_hashes" not in model.payload["context"]
    assert "source_hashes" not in model.payload["context"]["impact"]
    assert model.payload["context"]["impact"]["tasks"] == context["impact"]["tasks"]
    assert context == original


def test_crlf_graph_and_excerpt_snapshots_share_raw_source_hashes(tmp_path):
    scope, task, _queue, _context, review = _project(tmp_path, callers=1)
    for file in tmp_path.glob("*.py"):
        file.write_bytes(file.read_bytes().replace(b"\n", b"\r\n"))
    task["source_sha256"] = sha256((tmp_path / "service.py").read_bytes()).hexdigest()
    context = build_cleanup_context([task], tmp_path)
    record = _store(tmp_path, scope, review, context)
    assert record["source_sha256"] == task["source_sha256"]
    assert record["context_dependency_hashes"]["service.py"] == task["source_sha256"]
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "current"


def test_metadata_dependencies_over_sixty_four_do_not_relax_the_excerpt_limit(tmp_path):
    scope, _task, _queue, context, review = _project(tmp_path, callers=0)
    hashes = {}
    for number in range(65):
        file = f"proof{number}.py"
        source = f"value = {number}\n"
        (tmp_path / file).write_text(source)
        hashes[file] = sha256(source.encode()).hexdigest()
    with pytest.raises(ValueError, match="provenance"):
        _context_is_current(tmp_path, hashes)
    context["context_dependency_hashes"] = hashes
    record = _store(tmp_path, scope, review, context)
    assert len(record["context_dependency_hashes"]) == 65
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "current"
    (tmp_path / "proof64.py").write_text("value = -1\n")
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "stale"


@pytest.mark.parametrize(
    "dependencies",
    [
        None,
        {},
        [],
        "not-a-manifest",
        {f"file{number}.py": "a" * 64 for number in range(513)},
        {"../outside.py": "a" * 64},
    ],
)
def test_invalid_or_oversized_dependency_manifests_cannot_enter_state(
    tmp_path, dependencies
):
    scope, _task, _queue, context, review = _project(tmp_path, callers=0)
    _store(tmp_path, scope, review, context)
    before = (tmp_path / ".skylos/cache/cleanup.json").read_bytes()
    context["context_dependency_hashes"] = dependencies
    with pytest.raises(ValueError):
        _store(tmp_path, scope, review, context)
    assert (tmp_path / ".skylos/cache/cleanup.json").read_bytes() == before


def test_legacy_records_and_promoted_steps_without_dependency_manifest_still_load(
    tmp_path,
):
    scope, _task, queue, context, review = _project(tmp_path, callers=0)
    context.pop("context_dependency_hashes")
    record = _store(tmp_path, scope, review, context)
    assert "context_dependency_hashes" not in record
    assert view_cleanup_reviews(tmp_path, scope)[0]["refresh_status"] == "current"
    create_cleanup_plan(tmp_path, scope, queue, "legacy", [queue["tasks"][0]["id"]])
    plan = promote_cleanup_review(tmp_path, scope, queue, record["id"], "legacy")
    assert "context_dependency_hashes" not in plan["steps"][-1]
    assert (
        view_cleanup_plans(tmp_path, scope, queue, "legacy")["steps"][-1][
            "refresh_status"
        ]
        == "current"
    )


def test_source_changes_between_graph_and_excerpts_refuse_mixed_context(
    tmp_path, monkeypatch
):
    from skylos import cleanup_impact

    scope, task, _queue, _context, _review = _project(tmp_path, callers=1)
    original = cleanup_impact.build_cleanup_impact

    def racing_graph(*args, **kwargs):
        result = original(*args, **kwargs)
        (tmp_path / "caller00.py").write_text("def changed():\n    return 0\n")
        return result

    monkeypatch.setattr(cleanup_impact, "build_cleanup_impact", racing_graph)
    with pytest.raises(ValueError, match="Graph source changed"):
        build_cleanup_context([task], tmp_path)
    assert load_cleanup_state(tmp_path)["scopes"] == {}


def test_changed_metadata_dependency_before_transaction_preserves_old_state(
    tmp_path, monkeypatch
):
    from skylos import cleanup_review_state

    scope, _task, _queue, context, review = _project(tmp_path)
    _store(tmp_path, scope, review, context)
    before = (tmp_path / ".skylos/cache/cleanup.json").read_bytes()
    omitted = sorted(
        set(context["context_dependency_hashes"])
        - {row["file"] for row in context["files"]}
    )[0]
    original = cleanup_review_state._mutate

    def racing_store(root, scope, callback):
        (tmp_path / omitted).write_text("def changed():\n    return 0\n")
        return original(root, scope, callback)

    monkeypatch.setattr(cleanup_review_state, "_mutate", racing_store)
    with pytest.raises(ValueError, match="graph or caller evidence changed"):
        _store(tmp_path, scope, review, context)
    assert (tmp_path / ".skylos/cache/cleanup.json").read_bytes() == before


def test_malformed_persisted_dependency_manifest_does_not_gain_current_status(tmp_path):
    scope, _task, _queue, context, review = _project(tmp_path, callers=0)
    record = _store(tmp_path, scope, review, context)
    mutate_cleanup_workspace(
        tmp_path,
        scope,
        lambda bucket: bucket["reviews"][record["id"]].update(
            context_dependency_hashes=None
        ),
    )
    with pytest.raises(ValueError, match="provenance"):
        view_cleanup_reviews(tmp_path, scope)
