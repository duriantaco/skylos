"""Public cleanup receipts keep observation limits and private local data separate."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest

from skylos.cleanup_receipts import (
    capture_cleanup_revision,
    cleanup_receipt_batch,
    load_cleanup_receipts,
    make_cleanup_receipt,
    parse_cleanup_receipt,
    store_cleanup_receipt,
)
from skylos.cleanup_state import STATE_PATH, mutate_cleanup_workspace


def _inputs(root):
    task = {"id": "1" * 64, "rule_id": "SKY-L038", "file": "app.py"}
    scope = {
        "target": str(root),
        "project_root": str(root),
        "scanner_version": "5.4.0",
        "config_digest": "4" * 64,
    }
    execution = {
        "task_id": task["id"],
        "rule_id": task["rule_id"],
        "file": "app.py",
        "source_sha256": "a" * 64,
        "applied_sha256": "b" * 64,
        "status": "verified",
        "applied": True,
        "rolled_back": False,
        "tests": {
            "status": "passed",
            "returncode": 0,
            "evidence": "pytest_junit",
            "count": 1,
            "observed": True,
            "exercised_change": True,
            "command": ["private", "secret-command"],
            "output": "secret-output",
        },
        "rescan": {
            "status": "passed",
            "new_findings": [],
            "original_present": False,
            "checked_categories": ["quality", "ai_defects", "dead_code"],
        },
        "behavior": {
            "status": "passed",
            "model": "python-source-effects-v1",
            "functions": [{"source": "secret-source"}],
        },
        "rollback": {"status": "skipped"},
        "limitations": ["secret-error"],
    }
    return task, scope, execution


def _make(root, *, status="verified"):
    task, scope, execution = _inputs(root)
    execution["status"] = status
    if status != "verified":
        execution["tests"].update(
            evidence="exit_code", count=None, observed=False, exercised_change=None
        )
    receipt = make_cleanup_receipt(
        task,
        scope,
        execution,
        project_root=root,
        source_revision={"head": "c" * 40, "dirty": False},
    )
    return scope, receipt


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def _repo(root):
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Receipt test")
    _git(root, "config", "user.email", "receipt@example.test")
    (root / ".gitignore").write_text(".skylos/\n", encoding="utf-8")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "source baseline")


def test_maker_keeps_pre_apply_revision_and_discards_private_execution_data(tmp_path):
    task, scope, execution = _inputs(tmp_path)
    before = deepcopy(execution)
    source = {"head": "c" * 40, "dirty": False, "source": "secret-revision-source"}
    receipt = make_cleanup_receipt(
        task, scope, execution, project_root=tmp_path, source_revision=source
    )
    assert receipt["source_revision"] == {"head": "c" * 40, "dirty": False}
    assert receipt["outcome_revision"] == {"head": None, "dirty": True}
    assert receipt["scope"] == {
        "target": ".",
        "scanner_version": "5.4.0",
        "config_digest": "sha256:" + "4" * 64,
    }
    assert receipt["checks"]["rescan"]["checked_categories"] == [
        "quality",
        "ai_defects",
        "dead_code",
    ]
    assert receipt["limitations"] == ["unbound_outcome", "security_not_checked"]
    assert "secret-" not in json.dumps(receipt)
    assert str(tmp_path) not in json.dumps(receipt)
    assert execution == before


@pytest.mark.parametrize("status", ["applied_unverified", "failed", "incomplete"])
def test_nonverified_outcomes_preserve_unknown_test_evidence(tmp_path, status):
    _, receipt = _make(tmp_path, status=status)
    assert receipt["status"] == status
    assert receipt["checks"]["tests"]["count"] is None
    assert "tests_not_observed" in receipt["limitations"]


def test_maker_refuses_verified_status_when_tests_were_not_observed(tmp_path):
    task, scope, execution = _inputs(tmp_path)
    execution["tests"]["observed"] = False
    with pytest.raises(ValueError, match="require observed test evidence"):
        make_cleanup_receipt(
            task,
            scope,
            execution,
            project_root=tmp_path,
            source_revision={"head": None, "dirty": None},
        )


@pytest.mark.parametrize(
    "path",
    [
        "/outside.py",
        "../app.py",
        "a/../../app.py",
        "a\\b.py",
        "C:/app.py",
        "./app.py",
        "a//b.py",
        "a\n.py",
    ],
)
def test_parser_rejects_unsafe_public_posix_paths(tmp_path, path):
    _, receipt = _make(tmp_path)
    receipt["file"] = path
    assert parse_cleanup_receipt(receipt) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (("schema_version",), True),
        (("attempt_id",), "a" * 64),
        (("task_id",), "a" * 63),
        (("source_sha256",), "A" * 64),
        (("source_revision", "head"), "c" * 7),
        (("source_revision", "dirty"), 0),
        (("scope", "target"), ".."),
        (("scope", "config_digest"), "4" * 64),
        (("scope", "scanner_version"), "v" * 41),
        (("recorded_at",), "2026-02-31T00:00:00Z"),
        (("status",), {}),
        (("checks", "tests", "status"), []),
        (("checks", "tests", "count"), True),
        (("checks", "tests", "returncode"), 2**32),
        (("checks", "tests", "evidence"), {}),
        (("checks", "tests", "exercised_change"), "yes"),
        (("checks", "rescan", "new_findings_count"), -1),
        (("checks", "rescan", "checked_categories"), ["unknown"]),
        (("checks", "rescan", "checked_categories"), ["quality"] * 6),
        (("limitations",), ["arbitrary private error"]),
        (("source_scan_id",), "not-a-uuid"),
    ],
)
def test_parser_rejects_malformed_fields_without_raising(tmp_path, field, value):
    _, receipt = _make(tmp_path)
    target = receipt
    for key in field[:-1]:
        target = target[key]
    target[field[-1]] = value
    assert parse_cleanup_receipt(receipt) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (("applied",), False),
        (("rolled_back",), True),
        (("checks", "tests", "count"), 0),
        (("checks", "tests", "evidence"), "exit_code"),
        (("checks", "tests", "returncode"), 1),
        (("checks", "rescan", "status"), "incomplete"),
        (("checks", "rescan", "new_findings_count"), 1),
        (("checks", "rescan", "original_present"), None),
        (("checks", "rollback", "status"), "failed"),
        (("checks", "behavior", "status"), "failed"),
    ],
)
def test_verified_receipt_cannot_contradict_recorded_checks(tmp_path, field, value):
    _, receipt = _make(tmp_path)
    target = receipt
    for key in field[:-1]:
        target = target[key]
    target[field[-1]] = value
    assert parse_cleanup_receipt(receipt) is None


def test_absent_checked_categories_stay_unknown_and_unknown_fields_are_dropped(
    tmp_path,
):
    _, receipt = _make(tmp_path)
    del receipt["checks"]["rescan"]["checked_categories"]
    receipt["limitations"] = []
    receipt["binding"] = {"status": "trusted"}
    receipt["command"] = "private-command"
    receipt["checks"]["tests"]["output"] = "private-output"
    parsed = parse_cleanup_receipt(receipt)
    assert parsed["checks"]["rescan"]["checked_categories"] == []
    assert "private-" not in json.dumps(parsed)
    assert "binding" not in parsed


@pytest.mark.parametrize(
    "field", ["task_id", "rule_id", "file", "source_sha256", "applied_sha256"]
)
def test_maker_rejects_cross_task_or_cross_edit_evidence(tmp_path, field):
    task, scope, execution = _inputs(tmp_path)
    edit = {
        "task_id": task["id"],
        "source_sha256": "a" * 64,
        "applied_sha256": "b" * 64,
    }
    execution[field] = (
        "other.py"
        if field == "file"
        else "SKY-L033"
        if field == "rule_id"
        else "f" * 64
    )
    with pytest.raises(ValueError):
        make_cleanup_receipt(
            task,
            scope,
            execution,
            project_root=tmp_path,
            source_revision={"head": None, "dirty": None},
            edit=edit,
        )


def test_store_is_idempotent_and_will_not_rebind_a_saved_attempt(tmp_path):
    scope, receipt = _make(tmp_path)
    assert store_cleanup_receipt(tmp_path, scope, receipt) == receipt
    assert store_cleanup_receipt(tmp_path, scope, receipt) == receipt
    path = tmp_path / STATE_PATH
    original = path.read_bytes()
    rebound = deepcopy(receipt)
    rebound["outcome_revision"] = {"head": "d" * 40, "dirty": False}
    with pytest.raises(ValueError, match="cannot be changed or rebound"):
        store_cleanup_receipt(tmp_path, scope, rebound)
    assert path.read_bytes() == original
    assert load_cleanup_receipts(tmp_path) == [receipt]


def test_load_selects_latest_twenty_valid_attempts_across_scopes(tmp_path):
    _, template = _make(tmp_path)
    expected = []
    for number in range(30):
        _, scope, _ = _inputs(tmp_path)
        scope["config_digest"] = ("4" if number % 2 else "5") * 64
        receipt = deepcopy(template)
        receipt["attempt_id"] = str(uuid4())
        receipt["scope"]["config_digest"] = "sha256:" + scope["config_digest"]
        receipt["recorded_at"] = (
            datetime(2026, 11, 10, tzinfo=timezone.utc) + timedelta(seconds=number)
        ).isoformat()
        expected.append(receipt)
        store_cleanup_receipt(tmp_path, scope, receipt)
    assert load_cleanup_receipts(tmp_path) == list(reversed(expected[-20:]))
    state = json.loads((tmp_path / STATE_PATH).read_text())
    assert all(
        len(bucket["cleanup_receipts"]) <= 20 for bucket in state["scopes"].values()
    )


def test_load_ignores_invalid_records_and_conflicting_duplicate_attempts(tmp_path):
    scope, receipt = _make(tmp_path)
    other = deepcopy(receipt)
    other["attempt_id"] = str(uuid4())
    conflicting = deepcopy(receipt)
    conflicting["outcome_revision"] = {"head": "d" * 40, "dirty": False}
    mutate_cleanup_workspace(
        tmp_path,
        scope,
        lambda bucket: bucket.update(
            cleanup_receipts=[{"command": "private"}, receipt, conflicting, other]
        ),
    )
    assert load_cleanup_receipts(tmp_path) == [other]


def test_loading_never_captures_current_revision(tmp_path, monkeypatch):
    scope, receipt = _make(tmp_path)
    store_cleanup_receipt(tmp_path, scope, receipt)
    monkeypatch.setattr(
        "skylos.cleanup_receipts.GitContext.from_path",
        lambda *_a, **_kw: pytest.fail("loading must not inspect current Git state"),
    )
    assert load_cleanup_receipts(tmp_path) == [receipt]


def test_capture_and_subdirectory_receipt_keep_original_commit_after_later_commit(
    tmp_path,
):
    _repo(tmp_path)
    source = capture_cleanup_revision(tmp_path)
    assert source == {"head": _git(tmp_path, "rev-parse", "HEAD"), "dirty": False}
    project = tmp_path / "services" / "tool"
    project.mkdir(parents=True)
    (project / "app.py").write_text("value = 2\n", encoding="utf-8")
    assert capture_cleanup_revision(project)["dirty"] is True
    task, scope, execution = _inputs(project)
    receipt = make_cleanup_receipt(
        task, scope, execution, project_root=project, source_revision=source
    )
    assert receipt["file"] == "services/tool/app.py"
    assert receipt["scope"]["target"] == "services/tool"
    store_cleanup_receipt(project, scope, receipt)
    _git(tmp_path, "add", "services/tool/app.py")
    _git(tmp_path, "commit", "-qm", "later committed outcome")
    assert _git(tmp_path, "rev-parse", "HEAD") != source["head"]
    loaded = load_cleanup_receipts(project)[0]
    assert loaded["source_revision"] == source
    assert loaded["outcome_revision"] == {"head": None, "dirty": True}


def test_root_alias_normalizes_metadata_without_following_source_links(tmp_path):
    alias = tmp_path.parent / (tmp_path.name + "-alias")
    alias.symlink_to(tmp_path, target_is_directory=True)
    task, scope, execution = _inputs(tmp_path)
    task["file"] = str(alias / "app.py")
    scope["target"] = str(alias)
    receipt = make_cleanup_receipt(
        task,
        scope,
        execution,
        project_root=tmp_path,
        source_revision={"head": None, "dirty": None},
    )
    assert receipt["scope"]["target"] == "."
    assert receipt["file"] == "app.py"


def test_revision_capture_non_git_is_unknown(tmp_path):
    assert capture_cleanup_revision(tmp_path) == {"head": None, "dirty": None}


def test_revision_capture_does_not_execute_repository_content_filters(tmp_path):
    _repo(tmp_path)
    marker = tmp_path / "filter-ran"
    _git(tmp_path, "config", "filter.receipt.clean", f"touch {marker}")
    (tmp_path / ".gitattributes").write_text("*.py filter=receipt\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("value = 2\n", encoding="utf-8")
    revision = capture_cleanup_revision(tmp_path)
    assert revision["head"] == _git(tmp_path, "rev-parse", "HEAD")
    assert revision["dirty"] is True
    assert not marker.exists()


def test_receipt_persistence_refuses_symlink_history(tmp_path):
    scope, receipt = _make(tmp_path)
    store_cleanup_receipt(tmp_path, scope, receipt)
    path = tmp_path / STATE_PATH
    outside = tmp_path / "outside.json"
    path.rename(outside)
    path.symlink_to(outside)
    original = outside.read_bytes()
    with pytest.raises((ValueError, OSError)):
        store_cleanup_receipt(tmp_path, scope, receipt)
    assert outside.read_bytes() == original


def test_contract_documents_receipt_limits_and_client_claim_boundary():
    path = Path(__file__).resolve().parents[1] / "skylos/api/upload_contract/v1.json"
    contract = json.loads(path.read_text())["scan_metadata"]["cleanup_receipts"]
    assert contract["schema_version"] == 1
    assert "at most 20" in contract["location"]
    assert "Never changes findings, quality gates" in contract["rule"]
    assert "old checks must not be rebound to a later commit" in contract["rule"]


def test_batch_preserves_valid_receipt_when_malformed_records_are_present(tmp_path):
    _, receipt = _make(tmp_path)
    assert cleanup_receipt_batch([None, [], {"status": []}, receipt]) == [receipt]
