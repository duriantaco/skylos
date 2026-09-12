from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from io import StringIO

import pytest
from rich.console import Console

import skylos.cli as cli
from skylos.commands import review_cmd
from skylos.config import DEFAULTS
from skylos.core.review_context import build_analysis_review_context
from skylos.core.review_decisions import FINGERPRINT_VERSION


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def _console_capture():
    stream = StringIO()

    def factory():
        return Console(
            file=stream,
            force_terminal=False,
            color_system=None,
            width=180,
        )

    return stream, factory


def _scan_result(source):
    review_context = build_analysis_review_context(
        source.parent,
        source,
        config=DEFAULTS,
        threshold=60,
        exclude_folders=(),
        requested_changed_files=None,
        effective_changed_files=None,
        enable_secrets=True,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
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
        "analysis_summary": {
            "total_files": 1,
            "danger_count": 1,
            "review_context": review_context,
        },
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(source),
                "line": 2,
                "symbol": "write_report",
                "severity": "HIGH",
                "message": "User-controlled output path",
            }
        ],
    }


def _answers(*values):
    iterator = iter(values)
    return lambda _prompt: next(iterator)


def test_interactive_review_records_v2_false_positive(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(_scan_result(source)),
    )
    recorded = []

    def record(_project_root, decision, *, environ, cache_root, now):
        assert cache_root is None
        assert now == NOW
        recorded.append((decision, environ))
        return dict(decision)

    monkeypatch.setattr(
        review_cmd.review_decisions,
        "record_local_decision",
        record,
        raising=False,
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(tmp_path)],
        console_factory=console_factory,
        input_fn=_answers("1", "1", "The wrapper constrains the path"),
        environ={},
        now=NOW,
    )

    assert exit_code == 0
    assert len(recorded) == 1
    decision, passed_env = recorded[0]
    assert passed_env == {}
    assert decision["fingerprint_version"] == FINGERPRINT_VERSION
    assert decision["stable_fingerprint"].startswith("sha256:")
    assert decision["context_hash"].startswith("sha256:")
    assert decision["rule_revision"]
    assert decision["rule_id"] == "SKY-D215"
    assert decision["file_path"] == "app.py"
    assert decision["line_number"] == 2
    assert decision["disposition"] == "false_positive"
    assert decision["reason"] == "The wrapper constrains the path"
    assert decision["created_at"] == "2026-09-12T12:00:00Z"
    assert "expires_at" not in decision
    assert "Recorded false positive" in stream.getvalue()
    assert "relevant code and evidence still match" in stream.getvalue()
    assert decision["decision_id"] in stream.getvalue()


def test_interactive_review_requires_time_bound_for_accepted_risk(
    tmp_path, monkeypatch
):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(_scan_result(source)),
    )
    recorded = []
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "record_local_decision",
        lambda _root, decision, *, environ, cache_root, now: (
            recorded.append(decision) or decision
        ),
        raising=False,
    )
    _stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(tmp_path)],
        console_factory=console_factory,
        input_fn=_answers("1", "2", "Vendor fix is scheduled", "14"),
        environ={},
        now=NOW,
    )

    assert exit_code == 0
    assert recorded[0]["disposition"] == "risk_accepted"
    assert recorded[0]["expires_at"] == "2026-09-26T12:00:00Z"


def test_interactive_review_rejects_unbounded_risk_acceptance(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(_scan_result(source)),
    )

    def record(*_args, **_kwargs):
        pytest.fail("decision must not be written")

    monkeypatch.setattr(
        review_cmd.review_decisions,
        "record_local_decision",
        record,
        raising=False,
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(tmp_path)],
        console_factory=console_factory,
        input_fn=_answers("1", "2", "Temporary exception", "0"),
        environ={},
        now=NOW,
    )

    assert exit_code == 2
    assert "Expiry must be between 1 and 365 days" in stream.getvalue()


def test_review_scan_runtime_failure_is_rendered_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("analyzer worker failed")
        ),
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(tmp_path)],
        console_factory=console_factory,
        environ={},
        now=NOW,
    )

    assert exit_code == 2
    assert "Review scan failed: analyzer worker failed" in stream.getvalue()


def test_review_table_strips_terminal_controls_from_finding_text(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("open(path, 'w').write('ok')\n")
    result = _scan_result(source)
    result["danger"][0]["message"] = "unsafe\x1b]8;;https://evil.invalid\x07link"
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(result),
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(tmp_path)],
        console_factory=console_factory,
        input_fn=_answers("q"),
        environ={},
        now=NOW,
    )

    assert exit_code == 0
    assert "\x1b" not in stream.getvalue()
    assert "\x07" not in stream.getvalue()


def test_review_list_renders_active_and_revoked_decisions(tmp_path, monkeypatch):
    decisions = [
        {
            "decision_id": "active-1",
            "disposition": "false_positive",
            "rule_id": "SKY-D215",
            "file_path": "app.py",
            "line_number": 2,
            "reason": "Safe wrapper",
        },
        {
            "decision_id": "revoked-1",
            "disposition": "risk_accepted",
            "rule_id": "SKY-D212",
            "file_path": "worker.py",
            "line_number": 8,
            "reason": "Old exception",
            "revoked_at": "2026-09-12T12:00:00Z",
        },
    ]
    calls = []

    def list_decisions(root, *, include_revoked, environ, cache_root):
        assert cache_root is None
        calls.append((root, include_revoked, environ))
        return decisions

    monkeypatch.setattr(
        review_cmd.review_decisions,
        "list_local_decisions",
        list_decisions,
        raising=False,
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        ["list", str(tmp_path)],
        console_factory=console_factory,
        environ={},
    )

    assert exit_code == 0
    assert calls == [(tmp_path.resolve(), True, {})]
    output = stream.getvalue()
    assert "active-1" in output
    assert "revoked-1" in output
    assert "false_positive" in output
    assert "revoked" in output


@pytest.mark.parametrize("verb", ["restore", "revoke"])
def test_review_restore_revokes_local_decision(tmp_path, monkeypatch, verb):
    calls = []

    def revoke(root, decision_id, *, environ, cache_root, now):
        assert cache_root is None
        calls.append((root, decision_id, environ))
        return True

    monkeypatch.setattr(
        review_cmd.review_decisions,
        "revoke_local_decision",
        revoke,
        raising=False,
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [verb, "decision-7", str(tmp_path)],
        console_factory=console_factory,
        environ={},
    )

    assert exit_code == 0
    assert calls == [(tmp_path.resolve(), "decision-7", {})]
    assert "Restored finding" in stream.getvalue()


def test_review_authoring_and_revocation_are_rejected_in_ci(tmp_path, monkeypatch):
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: pytest.fail("CI must not start an authoring scan"),
    )
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "revoke_local_decision",
        lambda *_args, **_kwargs: pytest.fail("CI must not change local decisions"),
        raising=False,
    )
    stream, console_factory = _console_capture()
    env = {"CI": "true", "GITHUB_RUN_ID": "123"}

    add_exit = review_cmd.run_review_command(
        [str(tmp_path)], console_factory=console_factory, environ=env
    )
    restore_exit = review_cmd.run_review_command(
        ["restore", "decision-1", str(tmp_path)],
        console_factory=console_factory,
        environ=env,
    )

    assert add_exit == 2
    assert restore_exit == 2
    assert "cannot be created in CI" in stream.getvalue()
    assert "cannot be changed in CI" in stream.getvalue()


def test_review_list_is_empty_in_ci_without_reading_local_state(tmp_path, monkeypatch):
    monkeypatch.setattr(
        review_cmd.review_decisions,
        "list_local_decisions",
        lambda *_args, **_kwargs: pytest.fail("CI must ignore local decisions"),
        raising=False,
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        ["list", str(tmp_path)],
        console_factory=console_factory,
        environ={"CI": "true", "GITHUB_RUN_ID": "123"},
    )

    assert exit_code == 0
    assert "ignored in CI" in stream.getvalue()


def test_review_is_registered_as_top_level_command(monkeypatch):
    calls = []
    monkeypatch.setattr(
        review_cmd,
        "run_review_command",
        lambda argv, *, console_factory: calls.append(argv) or 0,
    )
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "review", "list", "."])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert calls == [["list", "."]]


def test_review_command_local_decision_round_trip_and_ci_isolation(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "remote",
            "add",
            "origin",
            "https://github.com/acme/review-demo.git",
        ],
        check=True,
    )
    source = repo / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    result = _scan_result(source)
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(result),
    )
    local_cache = tmp_path / "operator-local-decisions"
    trusted_cache = tmp_path / "empty-trusted-decisions"
    assert not local_cache.exists()
    assert not trusted_cache.exists()
    stream, console_factory = _console_capture()

    add_exit = review_cmd.run_review_command(
        [str(source)],
        console_factory=console_factory,
        input_fn=_answers("1", "1", "Reviewed safe wrapper"),
        environ={},
        now=NOW,
        trusted_cache_root=trusted_cache,
        local_cache_root=local_cache,
    )
    repeat_exit = review_cmd.run_review_command(
        [str(source)],
        console_factory=console_factory,
        input_fn=lambda _prompt: pytest.fail(
            "an active decision must not be offered for review again"
        ),
        environ={},
        now=NOW,
        trusted_cache_root=trusted_cache,
        local_cache_root=local_cache,
    )
    listed = review_cmd.review_decisions.list_local_decisions(
        repo,
        environ={},
        cache_root=local_cache,
    )
    local_projection = review_cmd.review_decisions.apply_trusted_review_decisions(
        result,
        repo,
        cache_root=tmp_path / "empty-cloud-cache",
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )
    ci_projection = review_cmd.review_decisions.apply_trusted_review_decisions(
        result,
        repo,
        cache_root=tmp_path / "empty-cloud-cache",
        local_cache_root=local_cache,
        environ={"CI": "true", "GITHUB_RUN_ID": "42"},
        now=NOW,
    )

    assert add_exit == 0
    assert repeat_exit == 0
    assert "No findings with stable review identity were found" in stream.getvalue()
    assert len(listed) == 1
    assert listed[0]["language"] == "python"
    assert listed[0]["symbol"] == "write_report"
    assert listed[0]["section"] == "danger"
    assert listed[0]["category"] == "SECURITY"
    assert local_projection["danger"] == []
    assert len(local_projection["reviewed_findings"]) == 1
    assert len(ci_projection["danger"]) == 1
    assert ci_projection.get("reviewed_findings", []) == []

    restore_exit = review_cmd.run_review_command(
        ["restore", listed[0]["decision_id"], str(repo)],
        console_factory=console_factory,
        environ={},
        now=NOW,
        local_cache_root=local_cache,
    )
    restored_projection = review_cmd.review_decisions.apply_trusted_review_decisions(
        result,
        repo,
        cache_root=tmp_path / "empty-cloud-cache",
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )

    assert restore_exit == 0
    assert len(restored_projection["danger"]) == 1
    assert restored_projection.get("reviewed_findings", []) == []


def test_cloud_reviewed_finding_cannot_be_selected_for_duplicate_local_decision(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "remote",
            "add",
            "origin",
            "https://github.com/acme/cloud-reviewed-demo.git",
        ],
        check=True,
    )
    source = repo / "app.py"
    source.write_text("def write_report(path):\n    open(path, 'w').write('ok')\n")
    skylos_dir = repo / ".skylos"
    skylos_dir.mkdir()
    (skylos_dir / "link.json").write_text(
        json.dumps({"project_id": "project-cloud-reviewed-demo", "projects": {}})
    )
    result = _scan_result(source)
    annotated = review_cmd.review_decisions.annotate_result_identities(result, repo)
    identity = annotated["danger"][0]
    decision = {
        key: identity[key]
        for key in (
            "fingerprint_version",
            "stable_fingerprint",
            "context_hash",
            "rule_revision",
            "rule_id",
            "file_path",
        )
    }
    decision.update(
        {
            "decision_id": "cloud-decision-1",
            "line_number": 2,
            "disposition": "false_positive",
            "reason": "Reviewed in Cloud",
            "created_at": "2026-09-12T11:00:00Z",
        }
    )
    cloud_cache = tmp_path / "cloud-cache"
    local_cache = tmp_path / "local-cache"
    stored = review_cmd.review_decisions.write_trusted_bundle(
        repo,
        {
            "schema": review_cmd.review_decisions.REVIEW_SCHEMA,
            "version": review_cmd.review_decisions.REVIEW_SCHEMA_VERSION,
            "project_id": "project-cloud-reviewed-demo",
            "decisions": [decision],
        },
        cache_root=cloud_cache,
        fetched_at=NOW,
        environ={},
    )
    assert stored is not None
    monkeypatch.setattr(
        review_cmd,
        "run_analyze",
        lambda *_args, **_kwargs: json.dumps(result),
    )
    stream, console_factory = _console_capture()

    exit_code = review_cmd.run_review_command(
        [str(source)],
        console_factory=console_factory,
        input_fn=lambda _prompt: pytest.fail(
            "a Cloud-reviewed finding must not be offered for local review"
        ),
        environ={},
        now=NOW,
        trusted_cache_root=cloud_cache,
        local_cache_root=local_cache,
    )

    assert exit_code == 0
    assert "No findings with stable review identity were found" in stream.getvalue()
    assert (
        review_cmd.review_decisions.list_local_decisions(
            repo,
            environ={},
            cache_root=local_cache,
        )
        == []
    )


def test_review_scan_does_not_execute_repository_git_helpers(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text(
        "def write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    (repo / ".gitattributes").write_text(
        "*.py filter=untrusted diff=untrusted\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Skylos Test"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "skylos-test@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "add", "app.py", ".gitattributes"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "remote",
            "add",
            "origin",
            "https://github.com/acme/untrusted-review.git",
        ],
        cwd=repo,
        check=True,
    )

    sentinel = tmp_path / "git-helper-ran"
    helper = tmp_path / "git-helper"
    helper.write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\nexit 1\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)
    for key in (
        "core.fsmonitor",
        "diff.external",
        "diff.untrusted.command",
        "diff.untrusted.textconv",
        "filter.untrusted.clean",
    ):
        subprocess.run(["git", "config", key, str(helper)], cwd=repo, check=True)
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", str(helper))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "diff.external")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(helper))
    source.write_text(
        "# changed locally\ndef write_report(path):\n    open(path, 'w').write('ok')\n",
        encoding="utf-8",
    )
    sentinel.unlink(missing_ok=True)

    findings = review_cmd._scan_reviewable_findings(
        repo,
        repo,
        environ={},
        now=NOW,
        trusted_cache_root=tmp_path / "trusted-cache",
        local_cache_root=tmp_path / "local-cache",
    )

    assert findings
    assert not sentinel.exists()
