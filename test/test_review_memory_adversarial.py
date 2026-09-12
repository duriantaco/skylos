from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

import skylos.core.review_decisions as review_decisions
from skylos.api._findings import _normalize_findings
from skylos.api._payloads import _compact_upload_finding
from skylos.cli import _apply_display_filters
from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)


def _git_repo(path, remote="https://github.com/acme/review-qa.git"):
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", remote],
        check=True,
    )
    return path.resolve()


def _result(source, *, line=1):
    return {
        "danger": [
            {
                "rule_id": "SKY-D215",
                "file": str(source),
                "line": line,
                "symbol": "write_report",
                "severity": "HIGH",
                "message": "unsafe path",
            }
        ],
        "analysis_summary": {"danger_count": 1},
    }


def _decision(identity, **overrides):
    decision = {
        "decision_id": "decision-qa-1",
        "fingerprint_version": identity["fingerprint_version"],
        "stable_fingerprint": identity["stable_fingerprint"],
        "context_hash": identity["context_hash"],
        "rule_revision": identity["rule_revision"],
        "rule_id": identity["rule_id"],
        "file_path": identity["file_path"],
        "line_number": 1,
        "disposition": "false_positive",
        "reason": "reviewed safe wrapper",
        "created_at": "2026-09-12T10:00:00Z",
    }
    decision.update(overrides)
    return decision


def _nested_list(depth):
    value = "leaf"
    for _ in range(depth):
        value = [value]
    return value


def _record_then_corrupt_with_deep_extra(repo, source, cache):
    identity = review_decisions.annotate_result_identities(_result(source), repo)[
        "danger"
    ][0]
    review_decisions.record_local_decision(
        repo,
        _decision(identity),
        cache_root=cache,
        environ={},
        now=NOW,
    )
    path = next(cache.glob("*.json"))
    serialized = read_text_no_symlink(path, max_bytes=1_000_000)
    assert serialized is not None
    payload = json.loads(serialized)
    payload["decisions"][0]["unexpected"] = _nested_list(500)
    assert write_text_no_symlink(path, json.dumps(payload))


def test_deep_local_record_is_inactive_instead_of_suppressing(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    cache = tmp_path / "local-cache"
    _record_then_corrupt_with_deep_extra(repo, source, cache)

    projected = review_decisions.apply_trusted_review_decisions(
        _result(source),
        repo,
        cache_root=tmp_path / "cloud-cache",
        local_cache_root=cache,
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1
    assert projected.get("reviewed_findings", []) == []


def test_deep_local_record_listing_fails_cleanly(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    cache = tmp_path / "local-cache"
    _record_then_corrupt_with_deep_extra(repo, source, cache)

    try:
        listed = review_decisions.list_local_decisions(
            repo,
            include_revoked=True,
            cache_root=cache,
            environ={},
        )
    except ValueError:
        listed = []

    assert listed == []


def test_deep_untrusted_finding_metadata_cannot_crash_projection(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    result = _result(source)
    identity = review_decisions.annotate_result_identities(result, tmp_path)["danger"][
        0
    ]
    result["danger"][0]["metadata"] = {"unexpected": _nested_list(500)}

    projected = review_decisions.apply_review_decisions(
        result,
        [_decision(identity)],
        tmp_path,
        now=NOW,
    )

    assert (
        len(projected.get("danger", [])) + len(projected.get("reviewed_findings", []))
        == 1
    )


def test_deep_cloud_json_fails_open_without_crashing(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    cache = tmp_path / "cloud-cache"
    path = review_decisions.write_trusted_bundle(
        repo,
        {"version": 2, "decisions": []},
        cache_root=cache,
        fetched_at=NOW,
        environ={},
    )
    assert path is not None
    deep_json = "[" * 2_000 + "0" + "]" * 2_000
    path.write_text('{"unexpected":' + deep_json + "}")

    projected = review_decisions.apply_trusted_review_decisions(
        _result(source),
        repo,
        cache_root=cache,
        local_cache_root=tmp_path / "local-cache",
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1


def test_ci_rejects_cloud_cache_even_when_attempt_and_job_match(tmp_path):
    repo = _git_repo(tmp_path / "repo")
    cache = tmp_path / "cloud-cache"
    bundle = {"version": 2, "decisions": []}
    env = {
        "CI": "true",
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_JOB": "security-scan",
    }
    assert (
        review_decisions.write_trusted_bundle(
            repo,
            bundle,
            cache_root=cache,
            fetched_at=NOW,
            environ=env,
        )
        is not None
    )

    for candidate_env in (
        env,
        {**env, "GITHUB_RUN_ATTEMPT": "3"},
        {**env, "GITHUB_JOB": "different-job"},
    ):
        assert (
            review_decisions.load_trusted_bundle(
                repo,
                cache_root=cache,
                environ=candidate_env,
                now=NOW,
            )
            is None
        )


def test_compact_upload_preserves_v2_identity_and_trusted_review_audit():
    finding = {
        "rule_id": "SKY-D215",
        "file_path": "app.py",
        "line_number": 2,
        "message": "unsafe path",
        "severity": "HIGH",
        "fingerprint_version": "skylos-finding-v2",
        "stable_fingerprint": "sha256:" + "a" * 64,
        "context_hash": "sha256:" + "b" * 64,
        "rule_revision": "skylos:4.36.1",
        "language": "python",
        "symbol": "write_report",
        "_skylos_trusted_review": True,
        "review_decision": {
            "decision_id": "decision-1",
            "disposition": "false_positive",
            "match_mode": "v2_exact_context",
        },
    }

    normalized = _normalize_findings(
        [finding],
        "SECURITY",
        None,
        extract_metadata=True,
        analyzer_owned=True,
    )[0]
    compact = _compact_upload_finding(normalized, include_snippet=False)

    assert compact["metadata"] == {
        "fingerprint_version": "skylos-finding-v2",
        "stable_fingerprint": "sha256:" + "a" * 64,
        "context_hash": "sha256:" + "b" * 64,
        "rule_revision": "skylos:4.36.1",
        "language": "python",
        "symbol": "write_report",
        "review_decision": {
            "decision_id": "decision-1",
            "disposition": "false_positive",
            "match_mode": "v2_exact_context",
        },
    }


def test_display_filters_keep_review_summary_counts_consistent():
    result = {
        "danger": [],
        "quality": [],
        "reviewed_findings": [
            {
                "section": "danger",
                "category": "SECURITY",
                "severity": "HIGH",
                "file": "src/keep.py",
            },
            {
                "section": "quality",
                "category": "QUALITY",
                "severity": "LOW",
                "file": "src/drop.py",
            },
        ],
        "reviewed_findings_summary": {
            "suppressed_count": 2,
            "active_decision_count": 2,
        },
        "analysis_summary": {
            "reviewed_findings": {
                "suppressed_count": 2,
                "active_decision_count": 2,
            }
        },
    }

    filtered = _apply_display_filters(
        result,
        severity="high",
        category="security",
        file_filter="keep.py",
    )

    assert len(filtered["reviewed_findings"]) == 1
    assert filtered["reviewed_findings_summary"]["suppressed_count"] == 1
    assert filtered["analysis_summary"]["reviewed_findings"]["suppressed_count"] == 1


@pytest.mark.parametrize("state", ["empty", "expired"])
def test_inactive_cache_does_not_compute_finding_identities(
    tmp_path, monkeypatch, state
):
    repo = _git_repo(tmp_path / "repo")
    source = repo / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    cloud_cache = tmp_path / "cloud-cache"
    local_cache = tmp_path / "local-cache"
    cloud_cache.mkdir()
    local_cache.mkdir()
    if state == "expired":
        identity = review_decisions.annotate_result_identities(_result(source), repo)[
            "danger"
        ][0]
        review_decisions.write_trusted_bundle(
            repo,
            {
                "version": 2,
                "project_id": "project-1",
                "decisions": [
                    _decision(
                        identity,
                        disposition="risk_accepted",
                        expires_at="2026-09-12T11:00:00Z",
                    )
                ],
            },
            cache_root=cloud_cache,
            fetched_at=NOW,
            environ={},
        )
    monkeypatch.setattr(
        review_decisions,
        "annotate_result_identities",
        lambda *_args, **_kwargs: pytest.fail(
            "inactive decision state must not read sources or compute identities"
        ),
    )

    projected = review_decisions.apply_trusted_review_decisions(
        _result(source),
        repo,
        cache_root=cloud_cache,
        local_cache_root=local_cache,
        environ={},
        now=NOW,
    )

    assert len(projected["danger"]) == 1


def test_symlinked_parent_cannot_mint_finding_identity(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    real = repo / "real"
    real.mkdir()
    source = real / "app.py"
    source.write_text("open(path).write('unsafe')\n")
    linked = repo / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")

    annotated = review_decisions.annotate_result_identities(
        _result(linked / "app.py"),
        repo,
    )

    assert "stable_fingerprint" not in annotated["danger"][0]


def test_empty_file_finding_can_receive_review_identity(tmp_path):
    source = tmp_path / "empty_module.py"
    source.write_text("")
    result = {
        "unused_files": [
            {
                "rule_id": "SKY-E002",
                "file": str(source),
                "line": 1,
                "severity": "LOW",
                "category": "DEAD_CODE",
                "message": "Empty Python file",
            }
        ]
    }

    finding = review_decisions.annotate_result_identities(result, tmp_path)[
        "unused_files"
    ][0]

    assert finding["fingerprint_version"] == review_decisions.FINGERPRINT_VERSION
    assert finding["stable_fingerprint"].startswith("sha256:")
    assert finding["context_hash"].startswith("sha256:")


def _assert_python_dependency_change_resurfaces(
    project_root,
    source,
    dependency,
    *,
    line,
    replacement,
):
    result = _result(source, line=line)
    before = review_decisions.annotate_result_identities(result, project_root)[
        "danger"
    ][0]
    assert before["fingerprint_version"] == review_decisions.FINGERPRINT_VERSION
    decision = _decision(before, line_number=line)

    assert write_text_no_symlink(dependency, replacement)
    after = review_decisions.annotate_result_identities(result, project_root)["danger"][
        0
    ]

    assert before["stable_fingerprint"] == after["stable_fingerprint"]
    assert before["context_hash"] != after["context_hash"]
    projected = review_decisions.apply_review_decisions(
        result,
        {"version": 2, "decisions": [decision]},
        project_root,
        now=NOW,
    )
    assert len(projected["danger"]) == 1
    assert projected.get("reviewed_findings", []) == []


def test_python_parent_package_initializer_change_resurfaces_security_finding(
    tmp_path,
):
    package = tmp_path / "pkg"
    package.mkdir()
    initializer = package / "__init__.py"
    initializer.write_text("POLICY = 'strict'\n")
    validator = package / "validator.py"
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    source = tmp_path / "app.py"
    source.write_text(
        "from pkg.validator import safe_path\n"
        "def write_report(value):\n"
        "    open(safe_path(value)).write('unsafe')\n"
    )

    _assert_python_dependency_change_resurfaces(
        tmp_path,
        source,
        initializer,
        line=3,
        replacement="POLICY = 'permissive'\n",
    )


def test_literal_dunder_import_dependency_change_resurfaces_security_finding(
    tmp_path,
):
    validator = tmp_path / "validator.py"
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    source = tmp_path / "app.py"
    source.write_text(
        "validator = __import__('validator')\n"
        "def write_report(value):\n"
        "    open(validator.safe_path(value)).write('unsafe')\n"
    )

    _assert_python_dependency_change_resurfaces(
        tmp_path,
        source,
        validator,
        line=3,
        replacement="def safe_path(value):\n    return value\n",
    )


def test_configured_root_python_dependency_change_resurfaces_security_finding(
    tmp_path,
):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools]\npackage-dir = {"" = "vendor"}\n'
    )
    package = tmp_path / "vendor" / "acme"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    validator = package / "validator.py"
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    source = tmp_path / "app.py"
    source.write_text(
        "import acme.validator\n"
        "def write_report(value):\n"
        "    open(acme.validator.safe_path(value)).write('unsafe')\n"
    )

    _assert_python_dependency_change_resurfaces(
        tmp_path,
        source,
        validator,
        line=3,
        replacement="def safe_path(value):\n    return value\n",
    )


def test_transitive_relative_python_dependency_change_resurfaces_security_finding(
    tmp_path,
):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    validator = package / "validator.py"
    validator.write_text("def safe_path(value):\n    return '/tmp/report'\n")
    bridge = package / "bridge.py"
    bridge.write_text("from .validator import safe_path\n")
    source = package / "app.py"
    source.write_text(
        "from .bridge import safe_path\n"
        "def write_report(value):\n"
        "    open(safe_path(value)).write('unsafe')\n"
    )

    _assert_python_dependency_change_resurfaces(
        tmp_path,
        source,
        validator,
        line=3,
        replacement="def safe_path(value):\n    return value\n",
    )


def test_nonliteral_typescript_import_abstains_from_security_identity(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "const moduleName = process.env.VALIDATOR;\n"
        "const validator = await import(moduleName);\n"
        "writeFileSync(validator.safePath(value), 'unsafe');\n"
    )

    annotated = review_decisions.annotate_result_identities(
        _result(source, line=3),
        tmp_path,
    )

    assert "stable_fingerprint" not in annotated["danger"][0]
    assert "context_hash" not in annotated["danger"][0]
