from datetime import datetime, timedelta, timezone
import json
import subprocess
from types import SimpleNamespace

import pytest

import skylos.core.review_decisions as review_decisions
from skylos.config import DEFAULTS
from skylos.core.review_context import build_analysis_review_context
from skylos.core.review_decisions import (
    FINGERPRINT_VERSION,
    REVIEW_SCHEMA,
    active_decisions,
    annotate_result_identities,
    apply_review_decisions,
    apply_trusted_review_decisions,
    invalidate_trusted_bundle,
    load_trusted_bundle,
    list_local_decisions,
    record_local_decision,
    repository_scope,
    review_context_required,
    review_proofs_required,
    review_state_revision,
    revoke_local_decision,
    write_trusted_bundle,
)


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def _result(path, *, line=2, message="unsafe call"):
    review_context = build_analysis_review_context(
        path.parent,
        path,
        config=DEFAULTS,
        threshold=60,
        exclude_folders=(),
        requested_changed_files=None,
        effective_changed_files=None,
        enable_secrets=False,
        enable_danger=True,
        enable_quality=False,
        enable_ai_defects=False,
        enable_sca=False,
        enable_dependency_hallucinations=True,
        grep_verify=True,
        trace_file=None,
        required_config_rules=None,
        dependency_bump_diff_base=None,
        custom_rules_data=None,
        extra_visitors=None,
        analysis_scope={"kind": "file", "complete_repository": False},
        environ={},
    )
    return {
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(path),
                "line": line,
                "symbol": "write_report",
                "severity": "HIGH",
                "message": message,
            }
        ],
        "analysis_summary": {
            "danger_count": 1,
            "review_context": review_context,
        },
    }


def _v2_decision(identity, **overrides):
    decision = {
        "decision_id": "decision-1",
        "fingerprint_version": identity["fingerprint_version"],
        "stable_fingerprint": identity["stable_fingerprint"],
        "context_hash": identity["context_hash"],
        "rule_revision": identity["rule_revision"],
        "rule_id": identity["rule_id"],
        "file_path": identity["file_path"],
        "line_number": 2,
        "disposition": "false_positive",
        "reason": "reviewed safe wrapper",
        "created_at": "2026-09-12T10:00:00Z",
    }
    decision.update(overrides)
    return decision


def _git_repo(path, remote="git@github.com:Example/Project.git"):
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", remote],
        check=True,
    )
    return path


def _proof_requirement_decision(**overrides):
    decision = {
        "decision_id": "proof-decision",
        "fingerprint_version": FINGERPRINT_VERSION,
        "stable_fingerprint": "sha256:" + "a" * 64,
        "context_hash": "sha256:" + "b" * 64,
        "rule_revision": "skylos:1",
        "rule_id": "SKY-Q001",
        "file_path": "app.py",
        "line_number": 1,
        "disposition": "false_positive",
    }
    decision.update(overrides)
    return decision


def test_review_proofs_required_only_for_active_dead_code_v2(monkeypatch, tmp_path):
    selected_bundle = {"value": None}
    monkeypatch.setattr(
        review_decisions, "_identity_project_root", lambda _project_root: tmp_path
    )
    monkeypatch.setattr(
        review_decisions, "_git_remote_identity", lambda _identity_root: None
    )
    monkeypatch.setattr(
        review_decisions,
        "_load_local_bundle",
        lambda *_args, **_kwargs: selected_bundle["value"],
    )

    def required(decision):
        selected_bundle["value"] = {"version": 2, "decisions": [decision]}
        return (
            review_context_required(tmp_path, environ={}, now=NOW),
            review_proofs_required(tmp_path, environ={}, now=NOW),
        )

    assert required(_proof_requirement_decision(category="QUALITY")) == (True, False)
    assert (
        required(_proof_requirement_decision(rule_id="SKY-D215", category="SECURITY"))
        == (True, False)
    )
    assert (
        required(_proof_requirement_decision(rule_id="SKY-U001", category="DEAD_CODE"))
        == (True, True)
    )
    assert required(_proof_requirement_decision(rule_id="SKY-U001")) == (True, True)
    assert required(_proof_requirement_decision(rule_id="SKY-U005")) == (True, False)
    assert (
        required(
            _proof_requirement_decision(
                rule_id="SKY-U001", expires_at="2026-09-12T11:59:59Z"
            )
        )
        == (False, False)
    )


def test_review_state_revision_tracks_projection_changes_only(monkeypatch, tmp_path):
    selected_bundle = {"value": None}
    monkeypatch.setattr(
        review_decisions, "_identity_project_root", lambda _project_root: tmp_path
    )
    monkeypatch.setattr(
        review_decisions, "_git_remote_identity", lambda _identity_root: None
    )
    monkeypatch.setattr(
        review_decisions, "_linked_project_id", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        review_decisions,
        "_load_local_bundle",
        lambda *_args, **_kwargs: selected_bundle["value"],
    )

    decision = _proof_requirement_decision(category="QUALITY")
    selected_bundle["value"] = {"version": 2, "decisions": [decision]}
    original = review_state_revision(tmp_path, environ={}, now=NOW)

    assert original is not None
    decision["reason"] = "a different audit explanation"
    assert review_state_revision(tmp_path, environ={}, now=NOW) == original

    decision["expires_at"] = "2026-09-13T12:00:00Z"
    expiring = review_state_revision(tmp_path, environ={}, now=NOW)
    assert expiring is not None
    assert expiring != original
    assert (
        review_state_revision(
            tmp_path,
            environ={},
            now=NOW + timedelta(days=2),
        )
        is None
    )


def test_review_state_revision_tracks_ambiguity_and_ignores_ci(monkeypatch, tmp_path):
    selected_bundle = {"value": None}
    monkeypatch.setattr(
        review_decisions, "_identity_project_root", lambda _project_root: tmp_path
    )
    monkeypatch.setattr(
        review_decisions, "_git_remote_identity", lambda _identity_root: None
    )
    monkeypatch.setattr(
        review_decisions, "_linked_project_id", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        review_decisions,
        "_load_local_bundle",
        lambda *_args, **_kwargs: selected_bundle["value"],
    )

    first = _proof_requirement_decision(category="QUALITY")
    selected_bundle["value"] = {"version": 2, "decisions": [first]}
    one_revision = review_state_revision(tmp_path, environ={}, now=NOW)
    duplicate = dict(first, decision_id="proof-decision-2")
    selected_bundle["value"] = {"version": 2, "decisions": [first, duplicate]}

    assert review_state_revision(tmp_path, environ={}, now=NOW) != one_revision
    assert (
        review_state_revision(
            tmp_path,
            environ={"CI": "true", "GITHUB_RUN_ID": "123"},
            now=NOW,
        )
        is None
    )


def test_v2_suppression_survives_line_shift_and_keeps_audit_record(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "import os\nENABLED = True\ndef write_report(path):\n"
        "    open(path).write('ok')\n"
    )
    original = annotate_result_identities(_result(source, line=4), tmp_path)
    identity = original["danger"][0]
    bundle = {
        "schema": "skylos.reviewed-findings",
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=4)],
    }

    source.write_text(
        "# unrelated heading\nimport os\nENABLED = True\ndef write_report(path):\n"
        "    open(path).write('ok')\n"
    )
    shifted = _result(source, line=5)
    projected = apply_review_decisions(shifted, bundle, tmp_path, now=NOW)

    assert projected["danger"] == []
    assert projected["analysis_summary"]["danger_count"] == 0
    assert projected["reviewed_findings_summary"]["suppressed_count"] == 1
    assert projected["reviewed_findings"][0]["review_decision"] == {
        "decision_id": "decision-1",
        "disposition": "false_positive",
        "reason": "reviewed safe wrapper",
        "created_at": "2026-09-12T10:00:00Z",
        "match_mode": "v2_exact_context",
    }


def test_security_review_survives_nearby_comment_only_line_shift(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    result = _result(source, line=2)
    identity = annotate_result_identities(result, tmp_path)["danger"][0]
    bundle = {"version": 2, "decisions": [_v2_decision(identity)]}

    source.write_text(
        "def write_report(path):\n"
        "    # explain why this wrapper is safe\n"
        "    open(path).write('ok')\n"
    )
    shifted = _result(source, line=3)
    projected = apply_review_decisions(shifted, bundle, tmp_path, now=NOW)

    assert projected["danger"] == []


def test_changed_security_context_resurfaces_finding(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    identity = annotate_result_identities(_result(source), tmp_path)["danger"][0]
    bundle = {"version": 2, "decisions": [_v2_decision(identity)]}

    source.write_text("def write_report(path):\n    open('/tmp/' + path).write('ok')\n")
    projected = apply_review_decisions(_result(source), bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1
    assert projected["reviewed_findings"] == []


def test_static_agent_label_keeps_native_analyzer_identity(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    native = annotate_result_identities(_result(source), tmp_path)["danger"][0]
    agent_result = _result(source)
    agent_result["danger"][0]["_source"] = "static"
    agent = annotate_result_identities(agent_result, tmp_path)["danger"][0]

    assert agent["stable_fingerprint"] == native["stable_fingerprint"]
    assert agent["context_hash"] == native["context_hash"]


def test_incomplete_v2_record_does_not_fall_back_to_location(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    identity = annotate_result_identities(_result(source), tmp_path)["danger"][0]
    decision = _v2_decision(identity)
    decision.pop("context_hash")

    projected = apply_review_decisions(_result(source), [decision], tmp_path, now=NOW)

    assert len(projected["danger"]) == 1
    assert projected["reviewed_findings"] == []


def test_v2_duplicate_current_identity_is_ambiguous(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    result = _result(source)
    result["danger"].append(dict(result["danger"][0]))
    identity = annotate_result_identities(result, tmp_path)["danger"][0]

    projected = apply_review_decisions(
        result, [_v2_decision(identity)], tmp_path, now=NOW
    )

    assert len(projected["danger"]) == 2
    assert projected["reviewed_findings"] == []
    assert projected["reviewed_findings_summary"]["ambiguous_match_count"] == 2


def test_legacy_low_risk_decision_requires_exact_rule_path_and_line(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def helper():\n    return 1\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 2,
                "severity": "LOW",
                "message": "review this helper",
            }
        ]
    }
    decision = {
        "rule_id": "SKY-Q999",
        "file_path": "app.py",
        "line_number": 2,
        "type": "false_positive",
    }

    matched = apply_review_decisions(result, [decision], tmp_path, now=NOW)
    shifted_result = {"quality": [{**result["quality"][0], "line": 1}]}
    shifted = apply_review_decisions(shifted_result, [decision], tmp_path, now=NOW)

    assert matched["quality"] == []
    assert len(shifted["quality"]) == 1


def test_cloud_wire_null_v2_fields_keep_low_risk_legacy_compatibility(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def helper():\n    return 1\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 2,
                "severity": "LOW",
                "message": "review this helper",
            }
        ]
    }
    cloud_wire_decision = {
        "rule_id": "SKY-Q999",
        "file_path": "app.py",
        "line_number": 2,
        "type": "false_positive",
        "fingerprint_version": None,
        "stable_fingerprint": None,
        "context_hash": None,
        "rule_revision": None,
    }

    projected = apply_review_decisions(result, [cloud_wire_decision], tmp_path, now=NOW)

    assert projected["quality"] == []


def test_partial_non_null_v2_claim_never_falls_back_to_legacy(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def helper():\n    return 1\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 2,
                "severity": "LOW",
                "message": "review this helper",
            }
        ]
    }
    partial = {
        "rule_id": "SKY-Q999",
        "file_path": "app.py",
        "line_number": 2,
        "type": "false_positive",
        "fingerprint_version": FINGERPRINT_VERSION,
        "stable_fingerprint": None,
        "context_hash": None,
        "rule_revision": None,
    }

    projected = apply_review_decisions(result, [partial], tmp_path, now=NOW)

    assert len(projected["quality"]) == 1


def test_legacy_decision_never_suppresses_high_risk_finding(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("open(input()).write('unsafe')\n")
    decision = {
        "rule_id": "SKY-D215",
        "file_path": "app.py",
        "line_number": 1,
        "type": "false_positive",
    }

    projected = apply_review_decisions(
        _result(source, line=1), [decision], tmp_path, now=NOW
    )

    assert len(projected["danger"]) == 1
    assert projected["reviewed_findings"] == []


def test_legacy_decision_treats_padded_high_severity_as_high_risk(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 1,
                "severity": " HIGH ",
                "message": "high risk quality finding",
            }
        ]
    }
    decision = {
        "rule_id": "SKY-Q999",
        "file_path": "app.py",
        "line_number": 1,
        "type": "false_positive",
    }

    projected = apply_review_decisions(result, [decision], tmp_path, now=NOW)

    assert len(projected["quality"]) == 1
    assert projected["reviewed_findings"] == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"file_path": "app.py\n"},
        {"file_path": "app.py\x1f"},
        {"file_path": "app.py\x7f"},
        {"rule_id": "SKY-Q999\n"},
        {"rule_revision": ".skylos:1"},
        {"rule_revision": " skylos:1"},
    ],
)
def test_stored_v2_identity_rejects_noncanonical_contract_fields(tmp_path, overrides):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 1,
                "severity": "LOW",
                "message": "quality finding",
            }
        ]
    }
    identity = annotate_result_identities(result, tmp_path)["quality"][0]
    decision = _v2_decision(identity, **overrides)

    assert active_decisions([decision], tmp_path, now=NOW) == []


def test_risk_acceptance_requires_future_expiry(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    identity = annotate_result_identities(_result(source), tmp_path)["danger"][0]

    permanent = _v2_decision(identity, disposition="risk_accepted", expires_at=None)
    expired = _v2_decision(
        identity, disposition="risk_accepted", expires_at="2026-09-12T11:00:00Z"
    )
    active = _v2_decision(
        identity, disposition="risk_accepted", expires_at="2026-09-13T11:00:00Z"
    )

    assert active_decisions([permanent], tmp_path, now=NOW) == []
    assert active_decisions([expired], tmp_path, now=NOW) == []
    assert len(active_decisions([active], tmp_path, now=NOW)) == 1


def test_fixed_revoked_invalid_and_traversal_decisions_are_inactive(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path).write('ok')\n")
    identity = annotate_result_identities(_result(source), tmp_path)["danger"][0]
    records = [
        _v2_decision(identity, disposition="fixed"),
        _v2_decision(identity, revoked_at="2026-09-12T11:00:00Z"),
        _v2_decision(identity, expires_at="not-a-time"),
        {
            "rule_id": "SKY-D215",
            "file_path": "../app.py",
            "line_number": 2,
            "type": "false_positive",
        },
    ]

    assert active_decisions(records, tmp_path, now=NOW) == []


def test_symlinked_source_cannot_mint_v2_identity(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("open(user_path).write('x')\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    link = repo / "app.py"
    try:
        link.symlink_to(outside)
    except OSError:
        return

    annotated = annotate_result_identities(_result(link, line=1), repo)

    assert "stable_fingerprint" not in annotated["danger"][0]
    assert annotated["danger"][0].get("fingerprint_version") != FINGERPRINT_VERSION


def test_trusted_cloud_cache_is_local_only_even_with_matching_ci_run(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    cache = tmp_path / "operator-cache"
    bundle = {"schema": "skylos.reviewed-findings", "version": 2, "decisions": []}
    env = {"CI": "true", "GITHUB_RUN_ID": "101"}

    path = write_trusted_bundle(
        repo,
        bundle,
        cache_root=cache,
        fetched_at=NOW,
        environ=env,
    )

    assert path is not None
    assert load_trusted_bundle(repo, cache_root=cache, environ={}, now=NOW) == bundle
    assert (
        load_trusted_bundle(
            repo,
            cache_root=cache,
            environ=env,
            now=NOW,
        )
        is None
    )


def test_forged_same_user_cloud_cache_cannot_suppress_in_ci(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "link.json").write_text(
        json.dumps({"project_id": "project-a", "projects": {}})
    )
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    env = {
        "CI": "true",
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "security",
    }
    assert (
        write_trusted_bundle(
            repo,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-a",
                "decisions": [_v2_decision(identity, line_number=1)],
            },
            cache_root=cache,
            fetched_at=NOW,
            environ=env,
        )
        is not None
    )

    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ=env,
        now=NOW,
    )

    assert len(projected["danger"]) == 1
    assert projected.get("reviewed_findings", []) == []


def test_stale_cloud_cache_fails_open_for_local_scan(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "link.json").write_text(
        json.dumps({"project_id": "project-a", "projects": {}})
    )
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    assert (
        write_trusted_bundle(
            repo,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-a",
                "decisions": [_v2_decision(identity, line_number=1)],
            },
            cache_root=cache,
            fetched_at=NOW - timedelta(hours=25),
            environ={},
        )
        is not None
    )

    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1
    assert projected.get("reviewed_findings", []) == []


def test_cloud_cache_rejects_malformed_and_future_fetched_at(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    cache = tmp_path / "cloud-cache"
    bundle = {"schema": REVIEW_SCHEMA, "version": 2, "decisions": []}
    path = write_trusted_bundle(
        repo,
        bundle,
        cache_root=cache,
        fetched_at=NOW,
        environ={},
    )
    assert path is not None
    original = json.loads(path.read_text())

    for invalid in (None, "", "not-a-timestamp", "2026-09-12T12:00:01Z"):
        payload = json.loads(json.dumps(original))
        payload["_local_trust"]["fetched_at"] = invalid
        path.write_text(json.dumps(payload))
        assert (
            load_trusted_bundle(
                repo,
                cache_root=cache,
                environ={},
                now=NOW,
            )
            is None
        )


def test_repo_local_forgery_is_not_a_trusted_cache(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    forged_dir = repo / ".skylos"
    forged_dir.mkdir()
    forged = {
        "version": 1,
        "suppressions": [
            {"rule_id": "SKY-D215", "file_path": "app.py", "line_number": 1}
        ],
    }
    (forged_dir / "suppressions.json").write_text(json.dumps(forged))

    assert load_trusted_bundle(repo, cache_root=tmp_path / "operator-cache") is None


def test_trusted_cache_rejects_cross_repo_copy_and_symlink(tmp_path):
    first = _git_repo(tmp_path / "first", "https://github.com/acme/one.git")
    second = _git_repo(tmp_path / "second", "https://github.com/acme/two.git")
    cache = tmp_path / "operator-cache"
    bundle = {"version": 2, "decisions": []}
    first_path = write_trusted_bundle(first, bundle, cache_root=cache, fetched_at=NOW)
    assert first_path is not None

    second_scope = repository_scope(second)
    assert second_scope is not None
    second_path = (
        cache
        / __import__("hashlib")
        .sha256(
            json.dumps(second_scope, sort_keys=True, separators=(",", ":")).encode()
        )
        .hexdigest()
    )
    second_path = second_path.with_suffix(".json")
    second_path.write_bytes(first_path.read_bytes())
    assert load_trusted_bundle(second, cache_root=cache, now=NOW) is None

    first_path.unlink()
    try:
        first_path.symlink_to(second_path)
    except OSError:
        return
    assert load_trusted_bundle(first, cache_root=cache, now=NOW) is None


def test_invalidate_trusted_cache_removes_only_regular_bound_file(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    cache = tmp_path / "operator-cache"
    path = write_trusted_bundle(
        repo,
        {"version": 2, "decisions": []},
        cache_root=cache,
        fetched_at=NOW,
    )
    assert path is not None and path.exists()
    assert invalidate_trusted_bundle(repo, cache_root=cache) is True
    assert not path.exists()
    assert invalidate_trusted_bundle(repo, cache_root=cache) is False


def test_force_tracked_repo_suppression_cannot_bypass_strict_gate(tmp_path):
    from skylos.cli import _strict_scan_exit_code

    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(user_path).write('unsafe')\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "suppressions.json").write_text(
        json.dumps(
            [
                {
                    "rule_id": "SKY-D215",
                    "file_path": "app.py",
                    "line_number": 1,
                    "type": "false_positive",
                }
            ]
        )
    )
    subprocess.run(
        ["git", "-C", str(repo), "add", "-f", ".skylos/suppressions.json"],
        check=True,
    )
    result = {
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(source),
                "line": 1,
                "severity": "HIGH",
                "message": "unsafe path",
            }
        ]
    }

    projected = apply_trusted_review_decisions(
        result,
        repo,
        cache_root=tmp_path / "operator-cache",
        environ={"CI": "true", "GITHUB_RUN_ID": "44"},
    )

    assert len(projected["danger"]) == 1
    assert projected.get("reviewed_findings", []) == []
    assert (
        _strict_scan_exit_code(
            projected,
            SimpleNamespace(strict=True, gate=False, force=False),
        )
        == 1
    )


def test_security_identity_preserves_semantic_whitespace(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("if allowed:\n    open(path).write('a b')\n")
    identity = annotate_result_identities(_result(source, line=2), tmp_path)["danger"][
        0
    ]
    bundle = {"version": 2, "decisions": [_v2_decision(identity)]}

    source.write_text("if allowed:\nopen(path).write('a b')\n")
    dedented = apply_review_decisions(
        _result(source, line=2), bundle, tmp_path, now=NOW
    )
    assert len(dedented["danger"]) == 1

    source.write_text("if allowed:\n    open(path).write('a  b')\n")
    literal_changed = apply_review_decisions(
        _result(source, line=2), bundle, tmp_path, now=NOW
    )
    assert len(literal_changed["danger"]) == 1


def test_rule_revision_change_resurfaces_finding(tmp_path, monkeypatch):
    import skylos.core.review_decisions as review_decisions

    source = tmp_path / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    original = _result(source, line=1)
    monkeypatch.setattr(review_decisions, "DEFAULT_RULE_REVISION", "rule:7")
    identity = annotate_result_identities(original, tmp_path)["danger"][0]
    bundle = {"version": 2, "decisions": [_v2_decision(identity, line_number=1)]}
    changed = _result(source, line=1)
    monkeypatch.setattr(review_decisions, "DEFAULT_RULE_REVISION", "rule:8")

    projected = apply_review_decisions(changed, bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1


def test_unknown_bundle_schema_cannot_be_laundered_during_merge(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    cache_path = write_trusted_bundle(
        repo,
        {
            "schema": "skylos.reviewed-findings",
            "version": 2,
            "project_id": "project-1",
            "decisions": [_v2_decision(identity, line_number=1)],
        },
        cache_root=cache,
        fetched_at=NOW,
        environ={},
    )
    assert cache_path is not None
    forged_bundle = json.loads(cache_path.read_text())
    forged_bundle["schema"] = "future.untrusted-schema"
    forged_bundle["version"] = 999
    cache_path.write_text(json.dumps(forged_bundle))

    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1


def test_root_synced_decision_applies_when_scanning_subdirectory(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    (repo / ".skylos").mkdir()
    (repo / ".skylos" / "link.json").write_text(
        json.dumps({"project_id": "project-1", "projects": {}})
    )
    source = repo / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    assert (
        write_trusted_bundle(
            repo,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-1",
                "decisions": [_v2_decision(identity, line_number=1)],
            },
            cache_root=cache,
            fetched_at=NOW,
            environ={},
        )
        is not None
    )

    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        source.parent,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert projected["danger"] == []


def test_local_decision_round_trip_is_repo_bound_and_ignored_in_ci(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    decision = _v2_decision(identity, line_number=1)
    local_cache = tmp_path / "local-cache"

    saved = record_local_decision(
        repo, decision, cache_root=local_cache, environ={}, now=NOW
    )
    assert saved["decision_id"] == "decision-1"
    assert len(list_local_decisions(repo, cache_root=local_cache, environ={})) == 1
    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=tmp_path / "cloud-cache",
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )
    assert projected["danger"] == []

    ci_projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=tmp_path / "cloud-cache",
        local_cache_root=local_cache,
        environ={"CI": "true", "GITHUB_RUN_ID": "9", "GITHUB_RUN_ATTEMPT": "1"},
        now=NOW,
    )
    assert len(ci_projected["danger"]) == 1
    assert (
        revoke_local_decision(
            repo, "decision-1", cache_root=local_cache, environ={}, now=NOW
        )
        is True
    )
    assert list_local_decisions(repo, cache_root=local_cache, environ={}) == []


def test_v2_requires_explicit_disposition_strict_line_and_audit_id(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), tmp_path)["danger"][
        0
    ]
    base = _v2_decision(identity, line_number=1)
    malformed = []
    for changes in (
        {"disposition": None, "type": "false_positive"},
        {"line_number": "1"},
        {"decision_id": ""},
        {"revoked_at": ""},
        {"expires_at": ""},
        {"status": "disabled"},
    ):
        record = dict(base)
        record.update(changes)
        malformed.append(record)

    for record in malformed:
        projected = apply_review_decisions(
            _result(source, line=1),
            {"version": 2, "decisions": [record]},
            tmp_path,
            now=NOW,
        )
        assert len(projected["danger"]) == 1


def test_v2_collision_does_not_fall_back_to_legacy(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), tmp_path)["danger"][
        0
    ]
    bundle = {
        "version": 2,
        "decisions": [
            _v2_decision(identity, line_number=1, decision_id="v2-a"),
            _v2_decision(identity, line_number=1, decision_id="v2-b"),
            {
                "rule_id": "SKY-D215",
                "file_path": "app.py",
                "line_number": 1,
                "type": "false_positive",
            },
        ],
    }

    projected = apply_review_decisions(
        _result(source, line=1), bundle, tmp_path, now=NOW
    )

    assert len(projected["danger"]) == 1


def test_review_projection_drops_stale_aggregates(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    result = _result(source, line=1)
    result.update(
        {
            "grade": {"overall": {"letter": "F"}},
            "ai_security_stats": {"total_findings": 1},
            "provenance_summary": {"findings": 1},
        }
    )
    result["analysis_summary"]["by_directory"] = [{"path": ".", "total": 1}]
    identity = annotate_result_identities(result, tmp_path)["danger"][0]

    projected = apply_review_decisions(
        result,
        {"version": 2, "decisions": [_v2_decision(identity, line_number=1)]},
        tmp_path,
        now=NOW,
    )

    assert projected["danger"] == []
    assert "grade" not in projected
    assert "ai_security_stats" not in projected
    assert "provenance_summary" not in projected
    assert "by_directory" not in projected["analysis_summary"]


def test_distant_security_semantic_change_resurfaces_finding(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "def write_report(path):\n"
        "    path = validate_path(path)\n"
        "    marker = 1\n"
        "    marker += 1\n"
        "    marker += 1\n"
        "    open(path).write('unsafe')\n"
    )
    identity = annotate_result_identities(_result(source, line=6), tmp_path)["danger"][
        0
    ]
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=6)],
    }
    source.write_text(
        "def write_report(path):\n"
        "    path = input()\n"
        "    marker = 1\n"
        "    marker += 1\n"
        "    marker += 1\n"
        "    open(path).write('unsafe')\n"
    )

    projected = apply_review_decisions(
        _result(source, line=6), bundle, tmp_path, now=NOW
    )

    assert len(projected["danger"]) == 1


def test_imported_security_dependency_change_resurfaces_finding(tmp_path):
    source = tmp_path / "app.py"
    validator = tmp_path / "validator.py"
    source.write_text(
        "from validator import safe_path\n"
        "def write_report():\n"
        "    open(safe_path(input())).write('unsafe')\n"
    )
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    result = _result(source, line=3)
    identity = annotate_result_identities(result, tmp_path)["danger"][0]
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=3)],
    }

    validator.write_text("def safe_path(value):\n    return value\n")
    projected = apply_review_decisions(result, bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1


def test_unimported_python_change_conservatively_invalidates_security_review(tmp_path):
    source = tmp_path / "app.py"
    validator = tmp_path / "validator.py"
    unrelated = tmp_path / "unrelated.py"
    source.write_text(
        "from validator import safe_path\n"
        "def write_report():\n"
        "    open(safe_path(input())).write('unsafe')\n"
    )
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    unrelated.write_text("VALUE = 'old'\n")
    result = _result(source, line=3)
    identity = annotate_result_identities(result, tmp_path)["danger"][0]
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=3)],
    }

    unrelated.write_text("VALUE = 'new'\n")
    projected = apply_review_decisions(result, bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1
    assert projected["reviewed_findings"] == []


def test_imported_typescript_dependency_change_resurfaces_finding(tmp_path):
    source = tmp_path / "app.ts"
    validator = tmp_path / "validator.ts"
    source.write_text(
        "import { safePath } from './validator';\n"
        "export function writeReport(value: string) {\n"
        "  writeFileSync(safePath(value), 'unsafe');\n"
        "}\n"
    )
    validator.write_text(
        "export function safePath(value: string) { return '/tmp/report'; }\n"
    )
    result = _result(source, line=3)
    identity = annotate_result_identities(result, tmp_path)["danger"][0]
    assert identity["fingerprint_version"] == FINGERPRINT_VERSION
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=3)],
    }

    validator.write_text("export function safePath(value: string) { return value; }\n")
    projected = apply_review_decisions(result, bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1


def test_typescript_dependency_comment_change_keeps_review_identity(tmp_path):
    source = tmp_path / "app.ts"
    validator = tmp_path / "validator.ts"
    source.write_text(
        "import { safePath } from './validator';\n"
        "writeFileSync(safePath(value), 'unsafe');\n"
    )
    validator.write_text(
        "export function safePath(value: string) { return '/tmp/report'; }\n"
    )
    result = _result(source, line=2)
    identity = annotate_result_identities(result, tmp_path)["danger"][0]
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=2)],
    }

    validator.write_text(
        "// documentation only\n"
        "export function safePath(value: string) { return '/tmp/report'; }\n"
    )
    projected = apply_review_decisions(result, bundle, tmp_path, now=NOW)

    assert projected["danger"] == []


def test_unresolved_relative_typescript_dependency_abstains_from_identity(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "import { safePath } from './missing';\n"
        "writeFileSync(safePath(value), 'unsafe');\n"
    )

    annotated = annotate_result_identities(_result(source, line=2), tmp_path)

    assert "stable_fingerprint" not in annotated["danger"][0]


def test_dynamic_typescript_dependency_abstains_from_identity(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "const validator = require(process.env.VALIDATOR);\n"
        "writeFileSync(validator.safePath(value), 'unsafe');\n"
    )

    annotated = annotate_result_identities(_result(source, line=2), tmp_path)

    assert "stable_fingerprint" not in annotated["danger"][0]


def test_go_high_risk_identity_is_bound_to_repository_semantics(tmp_path):
    source = tmp_path / "main.go"
    source.write_text("package main\nfunc main() { writeFile(path) }\n")

    annotated = annotate_result_identities(_result(source, line=2), tmp_path)
    identity = annotated["danger"][0]
    assert identity["fingerprint_version"] == FINGERPRINT_VERSION

    helper = tmp_path / "helper.go"
    helper.write_text("package main\nfunc safe() bool { return true }\n")
    changed = annotate_result_identities(_result(source, line=2), tmp_path)["danger"][0]

    assert identity["stable_fingerprint"] == changed["stable_fingerprint"]
    assert identity["context_hash"] != changed["context_hash"]


def test_distant_semantic_change_resurfaces_high_reliability_finding(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "MODE = 'safe'\n"
        "def connect():\n"
        "    marker = 1\n"
        "    marker += 1\n"
        "    reconnect()\n"
    )
    result = {
        "reliability": [
            {
                "rule_id": "SKY-R999",
                "file": str(source),
                "line": 5,
                "severity": "HIGH",
                "message": "unsafe reconnect",
            }
        ]
    }
    identity = annotate_result_identities(result, tmp_path)["reliability"][0]
    decision = _v2_decision(
        identity,
        line_number=5,
        rule_id="SKY-R999",
    )
    source.write_text(
        "MODE = 'unsafe'\n"
        "def connect():\n"
        "    marker = 1\n"
        "    marker += 1\n"
        "    reconnect()\n"
    )

    projected = apply_review_decisions(
        result, {"version": 2, "decisions": [decision]}, tmp_path, now=NOW
    )

    assert len(projected["reliability"]) == 1


def test_forged_identity_on_unreadable_source_cannot_suppress(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(real, line=1), tmp_path)["danger"][0]
    bundle = {
        "version": 2,
        "decisions": [_v2_decision(identity, line_number=1)],
    }
    link = tmp_path / "forged.py"
    try:
        link.symlink_to(real)
    except OSError:
        return
    forged = _result(link, line=1)
    forged["danger"][0].update(
        {
            key: identity[key]
            for key in (
                "fingerprint_version",
                "stable_fingerprint",
                "context_hash",
                "rule_revision",
            )
        }
    )
    forged["danger"][0]["review_decision"] = {
        "decision_id": "forged",
        "disposition": "false_positive",
    }

    projected = apply_review_decisions(forged, bundle, tmp_path, now=NOW)

    assert len(projected["danger"]) == 1
    assert "stable_fingerprint" not in projected["danger"][0]
    assert "review_decision" not in projected["danger"][0]


def test_cloud_cache_must_match_independently_linked_project(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    assert (
        write_trusted_bundle(
            repo,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-b",
                "decisions": [_v2_decision(identity, line_number=1)],
            },
            cache_root=cache,
            fetched_at=NOW,
            environ={},
        )
        is not None
    )
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "link.json").write_text(
        json.dumps({"project_id": "project-a", "projects": {}})
    )

    projected = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1


def test_cloud_cache_requires_current_project_link(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    link = skylos_dir / "link.json"
    link_payload = json.dumps({"project_id": "project-a", "projects": {}})
    link.write_text(link_payload)
    identity = annotate_result_identities(_result(source, line=1), repo)["danger"][0]
    cache = tmp_path / "cloud-cache"
    assert (
        write_trusted_bundle(
            repo,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-a",
                "decisions": [_v2_decision(identity, line_number=1)],
            },
            cache_root=cache,
            fetched_at=NOW,
            environ={},
        )
        is not None
    )

    link.unlink()
    without_link = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )
    assert len(without_link["danger"]) == 1

    link.write_text(link_payload)
    linked = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )
    assert linked["danger"] == []

    link.unlink()
    unlinked = apply_trusted_review_decisions(
        _result(source, line=1),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )
    assert len(unlinked["danger"]) == 1


def test_nested_cloud_project_prefixes_legacy_project_relative_paths(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    project = repo / "packages" / "a"
    project.mkdir(parents=True)
    source = project / "app.py"
    source.write_text("def helper():\n    return 1\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "link.json").write_text(
        json.dumps(
            {
                "project_id": "project-a",
                "projects": {
                    "packages/a": {
                        "project_id": "project-a",
                        "repo_subpath": "packages/a",
                    }
                },
            }
        )
    )
    cache = tmp_path / "cloud-cache"
    assert (
        write_trusted_bundle(
            project,
            {
                "schema": "skylos.reviewed-findings",
                "version": 2,
                "project_id": "project-a",
                "decisions": [
                    {
                        "decision_id": "legacy-1",
                        "rule_id": "SKY-Q999",
                        "file_path": "app.py",
                        "line_number": 2,
                        "disposition": "false_positive",
                    }
                ],
            },
            cache_root=cache,
            fetched_at=NOW,
            environ={},
        )
        is not None
    )
    result = {
        "quality": [
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 2,
                "severity": "LOW",
                "message": "review helper",
            }
        ]
    }

    projected = apply_trusted_review_decisions(
        result,
        project,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert projected["quality"] == []
    assert projected["reviewed_findings"][0]["review_decision"]["decision_id"] == (
        "legacy-1"
    )


def test_tree_sitter_semantic_hash_distinguishes_javascript_asi():
    from skylos.core.review_decisions import _semantic_source_hash

    with_newline = "function value() { return\nuserInput() }\n"
    same_line = "function value() { return userInput() }\n"

    assert _semantic_source_hash(with_newline, "javascript", ".js") != (
        _semantic_source_hash(same_line, "javascript", ".js")
    )


def test_projection_only_fingerprints_findings_targeted_by_active_decisions(
    tmp_path, monkeypatch
):
    target = tmp_path / "app.py"
    target.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    result = _result(target)
    for index in range(50):
        source = tmp_path / f"helper_{index}.py"
        source.write_text(f"value_{index} = {index}\n")
        result.setdefault("quality", []).append(
            {
                "rule_id": "SKY-Q999",
                "file": str(source),
                "line": 1,
                "severity": "LOW",
                "message": "unrelated quality finding",
            }
        )
    identity = annotate_result_identities(_result(target), tmp_path)["danger"][0]
    calls = []
    real_finding_identity = review_decisions.finding_identity

    def counted_identity(*args, **kwargs):
        calls.append((kwargs["section"], kwargs["default_rule_id"]))
        return real_finding_identity(*args, **kwargs)

    monkeypatch.setattr(review_decisions, "finding_identity", counted_identity)
    projected = apply_review_decisions(
        result,
        [_v2_decision(identity)],
        tmp_path,
        now=NOW,
        include_identities=False,
    )

    assert projected["danger"] == []
    assert len(projected["quality"]) == 50
    assert all("stable_fingerprint" not in item for item in projected["quality"])
    assert calls == [("danger", "SKY-D000")]


def test_trusted_projection_reads_staged_snapshot_instead_of_worktree(tmp_path):
    project = _git_repo(tmp_path / "repo")
    worktree_source = project / "app.py"
    worktree_source.write_text(
        "def write_report(path):\n    safe_wrapper(path)\n",
        encoding="utf-8",
    )
    staged_root = tmp_path / "staged-snapshot"
    staged_root.mkdir()
    staged_source = staged_root / "app.py"
    staged_source.write_text(
        "def write_report(path):\n    open(path, 'w').write('unsafe')\n",
        encoding="utf-8",
    )
    staged_result = _result(staged_source)
    staged_identity = annotate_result_identities(staged_result, staged_root)["danger"][
        0
    ]
    local_cache = tmp_path / "local-review-cache"
    record_local_decision(
        project,
        _v2_decision(staged_identity),
        cache_root=local_cache,
        environ={},
        now=NOW,
    )

    projected_staged = apply_trusted_review_decisions(
        staged_result,
        project,
        analysis_root=staged_root,
        cache_root=tmp_path / "cloud-review-cache",
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )
    projected_worktree = apply_trusted_review_decisions(
        _result(worktree_source),
        project,
        cache_root=tmp_path / "cloud-review-cache",
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )

    assert projected_staged["danger"] == []
    assert len(projected_staged["reviewed_findings"]) == 1
    assert len(projected_worktree["danger"]) == 1
    assert projected_worktree["reviewed_findings"] == []


def test_trusted_projection_rejects_symlink_analysis_root(tmp_path):
    project = _git_repo(tmp_path / "repo")
    source = project / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w')\n", encoding="utf-8")
    linked_root = tmp_path / "linked-analysis-root"
    try:
        linked_root.symlink_to(project, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not allow symlink creation")
    result = _result(source)

    projected = apply_trusted_review_decisions(
        result,
        project,
        analysis_root=linked_root,
        include_identities=True,
        cache_root=tmp_path / "cloud-review-cache",
        local_cache_root=tmp_path / "local-review-cache",
        environ={},
        now=NOW,
    )

    assert projected["danger"] == result["danger"]
    assert "stable_fingerprint" not in projected["danger"][0]
