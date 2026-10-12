"""Exercise authenticated pull, file activation, and custom-rule coverage."""

import json
import subprocess
from pathlib import Path

import pytest

from skylos.cloud import sync
from skylos.cloud import sync_state
from skylos.core import review_decisions


@pytest.fixture
def pull_repo(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/acme/repo.git"],
        check=True,
    )
    creds = tmp_path / "private-cache"
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sync, "GLOBAL_CREDS_DIR", creds)
    monkeypatch.setattr(sync, "_find_repo_root", lambda: repo)
    monkeypatch.setattr(sync, "get_token", lambda: "test-token")
    monkeypatch.setattr(sync.requests, "get", lambda *a, **k: pytest.fail("unexpected network"))
    responses = {
        "/api/sync/whoami": {"project": {"id": "project-a", "name": "A"}},
        "/api/sync/config": {"config": {"complexity_threshold": 7}},
        "/api/sync/suppressions": {
            "project_id": "project-a", "suppressions": [{"rule_id": "SKY-D212"}], "count": 1,
        },
    }
    calls = []

    def get(endpoint, token):
        assert token == "test-token"
        calls.append(endpoint)
        value = responses[endpoint]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(sync, "api_get", get)
    return repo, creds, responses, calls


def _old_files(repo):
    directory = repo / ".skylos"
    directory.mkdir(exist_ok=True)
    expected = {
        "config.yaml": "complexity_threshold: 99\n",
        "suppressions.json": '{"suppressions": [], "count": 0}\n',
    }
    for name, text in expected.items():
        (directory / name).write_text(text)  # skylos: ignore[SKY-D324] pull_repo creates private tmp_path/repo; names are the two literal fixture files
    return expected


def _assert_old_files(repo, expected):
    for name, text in expected.items():
        assert (repo / ".skylos" / name).read_text() == text
    assert not list((repo / ".skylos").glob(".*.tmp"))


def test_suppression_outage_does_not_activate_configuration(pull_repo, capsys):
    repo, creds, responses, _ = pull_repo
    sync.cmd_pull()
    capsys.readouterr()
    expected = _old_files(repo)
    assert list((creds / "reviewed-findings").glob("*.json"))
    responses["/api/sync/suppressions"] = sync.AuthError("suppression endpoint unavailable")
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull(output_format="json")
    assert error.value.code == 1
    _assert_old_files(repo, expected)
    assert not list((creds / "reviewed-findings").glob("*.json"))
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "failed"
    assert report["trusted_suppressions"] == "invalidated"


@pytest.mark.parametrize("endpoint,payload", [
    ("/api/sync/config", []),
    ("/api/sync/config", {"config": None}),
    ("/api/sync/config", {"project_id": "other", "config": {}}),
    ("/api/sync/suppressions", []),
    ("/api/sync/suppressions", {"suppressions": "invalid"}),
    ("/api/sync/suppressions", {"suppressions": ["invalid"]}),
    ("/api/sync/suppressions", {"suppressions": [], "decisions": "invalid"}),
    ("/api/sync/suppressions", {"suppressions": [], "schema": "unknown"}),
    ("/api/sync/suppressions", {"suppressions": [], "version": 999}),
    ("/api/sync/suppressions", {"project_id": "other", "suppressions": []}),
])
def test_invalid_responses_leave_both_files_unchanged(pull_repo, endpoint, payload):
    repo, _, responses, _ = pull_repo
    expected = _old_files(repo)
    responses[endpoint] = payload
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    _assert_old_files(repo, expected)


def test_failed_initial_pull_does_not_create_local_directory(pull_repo):
    repo, _, responses, _ = pull_repo
    responses["/api/sync/suppressions"] = sync.AuthError("offline")
    with pytest.raises(SystemExit):
        sync.cmd_pull()
    assert not (repo / ".skylos").exists()


@pytest.mark.parametrize("filename", ["config.yaml", "suppressions.json"])
def test_symlink_destination_is_refused_without_writing(pull_repo, filename, tmp_path):
    repo, _, _, calls = pull_repo
    directory = repo / ".skylos"
    directory.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("sentinel")
    target = directory / filename
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    assert target.is_symlink()
    assert outside.read_text() == "sentinel"
    assert calls == []


def test_symlinked_skylos_directory_is_refused(pull_repo, tmp_path):
    repo, _, _, calls = pull_repo
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    sentinel = outside / "config.yaml"
    sentinel.write_text("sentinel")
    try:
        (repo / ".skylos").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    assert sentinel.read_text() == "sentinel"
    assert calls == []


def test_second_file_activation_failure_restores_configuration(pull_repo, monkeypatch):
    repo, _, _, _ = pull_repo
    expected = _old_files(repo)
    original = sync_state._SyncDirectory.replace

    def replace(directory, temporary, name):
        if name == "suppressions.json":
            raise OSError("injected second activation failure")
        return original(directory, temporary, name)

    monkeypatch.setattr(sync_state._SyncDirectory, "replace", replace)
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    _assert_old_files(repo, expected)


def test_failed_trust_storage_restores_both_files(pull_repo, monkeypatch):
    repo, _, _, _ = pull_repo
    expected = _old_files(repo)
    monkeypatch.setattr(review_decisions, "write_trusted_bundle", lambda *a, **k: None)
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    _assert_old_files(repo, expected)


def test_failed_trust_storage_removes_newly_activated_files(pull_repo, monkeypatch):
    repo, _, _, _ = pull_repo
    monkeypatch.setattr(review_decisions, "write_trusted_bundle", lambda *a, **k: None)
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    assert not (repo / ".skylos" / "config.yaml").exists()
    assert not (repo / ".skylos" / "suppressions.json").exists()
    assert not list((repo / ".skylos").glob(".*.tmp"))


def test_destination_changed_to_symlink_after_staging_is_refused(
    pull_repo, monkeypatch, tmp_path,
):
    repo, _, _, _ = pull_repo
    _old_files(repo)
    outside = tmp_path / "sentinel"
    outside.write_text("sentinel")
    original = sync_state._SyncDirectory.replace

    def replace(directory, temporary, name):
        if name == "config.yaml":
            target = repo / ".skylos" / name
            target.unlink()
            target.symlink_to(outside)
        return original(directory, temporary, name)

    monkeypatch.setattr(sync_state._SyncDirectory, "replace", replace)
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    assert outside.read_text() == "sentinel"
    assert (repo / ".skylos" / "config.yaml").is_symlink()
    assert not list((repo / ".skylos").glob(".*.tmp"))


def test_directory_swap_after_staging_does_not_write_outside_repo(
    pull_repo, monkeypatch, tmp_path,
):
    repo, _, _, _ = pull_repo
    expected = _old_files(repo)
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    sentinel = outside / "config.yaml"
    sentinel.write_text("sentinel")
    retained = repo / "retained-state"
    original = sync_state._SyncDirectory.replace

    def replace(directory, temporary, name):
        if not directory.anchored:
            pytest.skip("descriptor-anchored race test requires directory descriptors")
        if name == "config.yaml":
            (repo / ".skylos").rename(retained)
            (repo / ".skylos").symlink_to(outside, target_is_directory=True)
        return original(directory, temporary, name)

    monkeypatch.setattr(sync_state._SyncDirectory, "replace", replace)
    with pytest.raises(SystemExit) as error:
        sync.cmd_pull()
    assert error.value.code == 1
    assert sentinel.read_text() == "sentinel"
    for name, text in expected.items():
        assert (retained / name).read_text() == text
    assert not list(retained.glob(".*.tmp"))


def test_unsupported_descriptor_platform_refuses_path_fallback(tmp_path, monkeypatch):
    if sync_state.os.name == "nt":
        pytest.skip("Windows uses native handle-relative sync")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".skylos").mkdir()
    outside = tmp_path / "sentinel"
    outside.write_text("sentinel")
    (repo / ".skylos" / "config.yaml").symlink_to(outside)
    monkeypatch.setattr(sync_state.os, "supports_dir_fd", set())
    with pytest.raises(sync_state.UnsafeSyncPath, match="no-follow directory"):
        with sync_state.activate_sync_files(repo, {"config.yaml": "new"}):
            pass
    assert outside.read_text() == "sentinel"


def test_success_json_is_one_document_and_refreshes_trust(pull_repo, capsys):
    repo, creds, _, calls = pull_repo
    sync.main(["pull", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "synced"
    assert report["dry_run"] is False
    assert report["suppression_count"] == 1
    assert report["trusted_suppressions"] == "refreshed"
    assert (repo / ".skylos" / "config.yaml").exists()
    assert list((creds / "reviewed-findings").glob("*.json"))
    assert calls == ["/api/sync/whoami", "/api/sync/config", "/api/sync/suppressions"]


def test_dry_run_does_not_create_files_or_private_cache(pull_repo, capsys):
    repo, creds, _, calls = pull_repo
    sync.main(["pull", "--dry-run", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "validated"
    assert report["dry_run"] is True
    assert report["trusted_suppressions"] == "unchanged"
    assert not (repo / ".skylos").exists()
    assert not creds.exists()
    assert len(calls) == 3


def test_failed_dry_run_preserves_existing_trust_and_files(pull_repo, capsys):
    repo, creds, responses, _ = pull_repo
    sync.cmd_pull()
    capsys.readouterr()
    expected = _old_files(repo)
    trusted = next((creds / "reviewed-findings").glob("*.json"))
    trusted_before = trusted.read_bytes()
    responses["/api/sync/suppressions"] = sync.AuthError("offline")
    with pytest.raises(SystemExit):
        sync.main(["pull", "--dry-run", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["trusted_suppressions"] == "unchanged"
    assert trusted.read_bytes() == trusted_before
    _assert_old_files(repo, expected)


@pytest.mark.parametrize("arguments", [
    ["--dryrun"], ["--unknown"], ["--format", "csv"], ["--dry"], ["extra"],
])
def test_unknown_pull_arguments_fail_before_auth_or_mutation(monkeypatch, arguments, capsys):
    monkeypatch.setattr(sync, "get_token", lambda: pytest.fail("authentication attempted"))
    with pytest.raises(SystemExit) as error:
        sync.main(["pull", *arguments])
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("payload", [None, [], {}, {"rules": None}, {"rules": ["invalid"]}])
def test_custom_rule_invalid_response_has_unavailable_receipt(monkeypatch, payload):
    monkeypatch.setattr(sync, "get_token", lambda: "token")
    monkeypatch.setattr(sync, "api_get", lambda *a: payload)
    receipt = sync.load_custom_rules()
    assert receipt["status"] == "unavailable"
    assert receipt["rules"] == []
    assert receipt["reason"]


def test_custom_rule_connection_and_failure_are_distinct(monkeypatch):
    monkeypatch.setattr(sync, "get_token", lambda: None)
    assert sync.load_custom_rules() == {"rules": [], "status": "not_connected"}
    monkeypatch.setattr(sync, "get_token", lambda: "token")

    def fail(*args):
        raise sync.AuthError("unavailable")

    monkeypatch.setattr(sync, "api_get", fail)
    assert sync.load_custom_rules() == {
        "rules": [], "status": "unavailable", "reason": "custom_rule_fetch_failed",
        "error_type": "AuthError",
    }


@pytest.mark.parametrize("rules", [[], [{"rule_id": "CUSTOM-AUTH-001"}]])
def test_custom_rule_success_and_legacy_wrapper(monkeypatch, rules):
    monkeypatch.setattr(sync, "get_token", lambda: "token")
    monkeypatch.setattr(sync, "api_get", lambda *a: {"rules": rules})
    assert sync.load_custom_rules() == {"rules": rules, "status": "complete"}
    assert sync.get_custom_rules() == rules
