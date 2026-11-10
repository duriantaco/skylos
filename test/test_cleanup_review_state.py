"""Durable model advice stays cited, source-bound and separate from raw findings."""

from copy import deepcopy
from hashlib import sha256

import pytest

from skylos.cleanup_plans import create_cleanup_plan, view_cleanup_plans
from skylos.cleanup_review_state import (
    promote_cleanup_review,
    store_cleanup_review,
    view_cleanup_reviews,
)
from skylos.cleanup_state import load_cleanup_state, update_cleanup_state


@pytest.fixture
def workspace(tmp_path):
    source = "def transform(value):\n    return value\n"
    (tmp_path / "app.py").write_text(source)
    (tmp_path / "caller.py").write_text("result = transform(3)\n")
    scope = {
        "target": str(tmp_path),
        "project_root": str(tmp_path),
        "scanner_version": "test",
        "config_digest": sha256(b"config").hexdigest(),
    }
    task = {
        "id": "a" * 64,
        "rule_id": "SKY-U001",
        "file": "app.py",
        "source_sha256": sha256(source.encode()).hexdigest(),
        "source_anchor": "anchor",
        "scope": scope,
    }
    queue = {"status": "ready", "tasks": [task], "advisories": []}
    context = {
        "files": [
            {"file": "app.py", "start_line": 1, "source": source.rstrip()},
            {"file": "caller.py", "start_line": 1, "source": "result = transform(3)"},
        ],
        "limitations": ["Bounded caller candidates"],
    }
    review = {
        "status": "reviewed",
        "kind": "subjective_advice",
        "advice": [
            {
                "file": "app.py",
                "line": 1,
                "summary": "Review a pass-through helper",
                "evidence": "transform returns its input",
                "suggestion": "Review its callers before removing it",
                "confidence": "medium",
                "finding_type": "advice",
            }
        ],
    }
    update_cleanup_state(tmp_path, scope, queue)
    create_cleanup_plan(tmp_path, scope, queue, "boundaries", [task["id"]])
    return tmp_path, scope, queue, context, review


def store(workspace, **kwargs):
    root, scope, _queue, context, review = workspace
    return store_cleanup_review(
        root,
        scope,
        review,
        context,
        model="local-model",
        provider="local",
        revision="revision-1",
        **kwargs,
    )


def test_store_cited_advice_and_explicit_promotion_never_creates_scanner_findings(
    workspace,
):
    root, scope, queue, context, review = workspace
    original = deepcopy((queue, context, review))
    scanner_state = next(iter(load_cleanup_state(root)["scopes"].values()))["tasks"]
    records = store(workspace)
    record = records[0]
    assert record["finding_type"] == "advice" and record["refresh_status"] == "current"
    assert record["coverage"] == "bounded" and record["context_limitations"]
    assert record["citations"] == [
        {"file": "app.py", "line": 1, "text": "def transform(value):"}
    ]
    assert record["provenance"]["model"] == "local-model"
    assert record["provenance"]["revision"] == "revision-1"
    assert len(view_cleanup_plans(root, scope, queue, "boundaries")["steps"]) == 1
    plan = promote_cleanup_review(
        root, scope, queue, record["id"][:12], "boundaries", revision="revision-1"
    )
    step = plan["steps"][-1]
    assert step["kind"] == "review_advice" and "task_id" not in step
    assert (
        step["finding_type"] == "advice" and step["verification_status"] == "unverified"
    )
    assert view_cleanup_reviews(root, scope)[0]["promoted_plans"] == ["boundaries"]
    assert (
        next(iter(load_cleanup_state(root)["scopes"].values()))["tasks"]
        == scanner_state
    )
    assert (queue, context, review) == original
    with pytest.raises(ValueError, match="already"):
        promote_cleanup_review(root, scope, queue, record["id"], "boundaries")


def test_repeat_review_deduplicates_without_losing_promotion_history(workspace):
    root, scope, queue, _context, _review = workspace
    first = store(workspace)[0]
    promote_cleanup_review(root, scope, queue, first["id"], "boundaries")
    second = store(workspace)[0]
    assert second["id"] == first["id"] and second["created_at"] == first["created_at"]
    assert second["promoted_plans"] == ["boundaries"]
    assert len(view_cleanup_reviews(root, scope)) == 1


@pytest.mark.parametrize("file", ["app.py", "caller.py"])
def test_changed_citation_or_neighbor_source_makes_review_and_promoted_plan_stale(
    workspace, file
):
    root, scope, queue, _context, _review = workspace
    record = store(workspace)[0]
    promote_cleanup_review(root, scope, queue, record["id"], "boundaries")
    (root / file).write_text("# changed\n")
    assert view_cleanup_reviews(root, scope)[0]["refresh_status"] == "stale"
    assert (
        view_cleanup_plans(root, scope, queue, "boundaries")["steps"][-1][
            "refresh_status"
        ]
        == "stale"
    )
    with pytest.raises(ValueError, match="stale"):
        promote_cleanup_review(root, scope, queue, record["id"], "boundaries")


def test_changed_revision_does_not_silently_reuse_a_review(workspace):
    root, scope, queue, _context, _review = workspace
    record = store(workspace)[0]
    assert (
        view_cleanup_reviews(root, scope, revision="revision-2")[0]["refresh_status"]
        == "stale"
    )
    with pytest.raises(ValueError, match="stale"):
        promote_cleanup_review(
            root, scope, queue, record["id"], "boundaries", revision="revision-2"
        )


@pytest.mark.parametrize(
    "change",
    [
        {"file": "invented.py"},
        {"line": 99},
        {"line": True},
        {"confidence": "certain"},
        {"finding_type": "defect"},
        {"evidence": ""},
    ],
)
def test_invalid_model_evidence_cannot_enter_durable_state(workspace, change):
    root, _scope, _queue, _context, review = workspace
    before = (root / ".skylos/cache/cleanup.json").read_bytes()
    review["advice"][0].update(change)
    with pytest.raises(ValueError):
        store(workspace)
    assert (root / ".skylos/cache/cleanup.json").read_bytes() == before


def test_source_change_between_model_context_and_storage_is_rejected(workspace):
    root, _scope, _queue, _context, _review = workspace
    (root / "app.py").write_text("def transform(value):\n    return sanitize(value)\n")
    with pytest.raises(ValueError, match="context changed"):
        store(workspace)


def test_partial_or_failed_review_and_incomplete_queue_cannot_be_promoted(workspace):
    root, scope, queue, _context, review = workspace
    review["status"] = "incomplete"
    with pytest.raises(ValueError, match="completed advisory"):
        store(workspace)
    review["status"] = "reviewed"
    record = store(workspace)[0]
    with pytest.raises(ValueError, match="complete"):
        promote_cleanup_review(
            root, scope, {**queue, "status": "incomplete"}, record["id"], "boundaries"
        )


def test_other_scope_cannot_promote_advice_and_unknown_revision_is_disclosed(workspace):
    root, scope, queue, context, review = workspace
    record = store_cleanup_review(
        root, scope, review, context, model="model", provider="local"
    )[0]
    assert record["provenance"]["revision_known"] is False
    with pytest.raises(ValueError, match="unknown|different"):
        promote_cleanup_review(
            root,
            {**scope, "scanner_version": "other"},
            queue,
            record["id"],
            "boundaries",
        )
    assert view_cleanup_reviews(root, {**scope, "scanner_version": "other"}) == []


def test_foreign_queue_cannot_promote_current_advice(workspace):
    root, scope, queue, _context, _review = workspace
    record = store(workspace)[0]
    foreign = deepcopy(queue)
    foreign["tasks"][0]["scope"]["config_digest"] = "other-config"
    with pytest.raises(ValueError, match="different scan scope"):
        promote_cleanup_review(root, scope, foreign, record["id"], "boundaries")


def test_symlinked_context_is_refused_without_following_it(workspace):
    root, _scope, _queue, _context, _review = workspace
    file = root / "app.py"
    target = root / "other.py"
    target.write_text(file.read_text())
    file.unlink()
    file.symlink_to(target)
    with pytest.raises(ValueError, match="unavailable"):
        store(workspace)


def test_source_change_before_transaction_does_not_persist_stale_advice(
    workspace, monkeypatch
):
    from skylos import cleanup_review_state

    root, _scope, _queue, _context, _review = workspace
    mutate = cleanup_review_state._mutate
    before = (root / ".skylos/cache/cleanup.json").read_bytes()

    def race(root, scope, callback):
        (root / "caller.py").write_text("# changed during storage\n")
        return mutate(root, scope, callback)

    monkeypatch.setattr(cleanup_review_state, "_mutate", race)
    with pytest.raises(ValueError, match="changed before"):
        store(workspace)
    assert (root / ".skylos/cache/cleanup.json").read_bytes() == before
