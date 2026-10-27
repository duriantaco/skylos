"""skylos done: files Skylos's own Cloud commands leave untracked.

``skylos login`` writes ``.skylos/link.json`` and ``skylos sync pull`` writes
``.skylos/config.yaml`` and ``.skylos/suppressions.json`` without committing
them. They are not part of the change being checked, but every committed or
staged edit, and any later edit to the pulled policy, must still be reported.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.cloud import sync, sync_state
from skylos.core import report_context
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import session
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_gate_tampering
from skylos.done.config import DoneConfig, parse_done_config
from skylos.done.engine import run

PROTECTED_LINK = (
    "changes .skylos/link.json, which is protected (.skylos/ in protected_paths)"
)
NOT_PULLED = "; it is not what skylos sync pull last wrote"
NOT_TRUSTED_IN_CI = "; an untracked synced policy file is not trusted in CI"

CALC = "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n"
TESTS = dedent(
    """\
    from app.calc import add, sub


    def test_add():
        assert add(1, 2) == 3


    def test_sub():
        assert sub(3, 1) == 2
    """
)
SKIPPED_TESTS = TESTS.replace(
    "def test_sub():", "import pytest\n\n\n@pytest.mark.skip\ndef test_sub():"
)
PYPROJECT = dedent(
    """\
    [project]
    name = "demo"
    version = "0.1.0"

    [tool.skylos.done]
    test_budget_seconds = 120
    """
)
PULLED_CONFIG = {"config": {"gate": {"enabled": True, "mode": "zero-new"}}}
PULLED_SUPPRESSIONS = {
    "project_id": "project-a",
    "suppressions": [{"rule_id": "SKY-D212"}],
    "count": 1,
}


def _git(root: Path, *args: str) -> str:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgSign=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            *args,
        ],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, rel: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / rel
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    for name in report_context._CI_MARKERS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("SKYLOS_API_URL", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(sync, "GLOBAL_CREDS_DIR", home / ".skylos")
    return home


@pytest.fixture
def repo(tmp_path: Path, home: Path) -> Path:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "remote", "add", "origin", "https://github.com/acme/repo.git")
    _write(root, "app/__init__.py", "")
    _write(root, "app/calc.py", CALC)
    _write(root, "tests/test_calc.py", TESTS)
    _write(root, "pyproject.toml", PYPROJECT)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    return root


@pytest.fixture
def pull(repo: Path, monkeypatch):
    responses = {
        "/api/sync/whoami": {"project": {"id": "project-a", "name": "A"}},
        "/api/sync/config": PULLED_CONFIG,
        "/api/sync/suppressions": PULLED_SUPPRESSIONS,
    }
    monkeypatch.chdir(repo)
    monkeypatch.setattr(sync, "_find_repo_root", lambda: repo)
    monkeypatch.setattr(sync, "get_token", lambda: "test-token")
    monkeypatch.setattr(
        sync.requests, "get", lambda *a, **k: pytest.fail("unexpected network")
    )
    monkeypatch.setattr(sync, "api_get", lambda endpoint, token: responses[endpoint])

    def pull_now():
        sync.cmd_pull()

    return responses, pull_now


def _commit(root: Path, message: str = "change") -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


def _ctx(root: Path) -> CheckContext:
    return CheckContext(open_comparison(root, "main"), DoneConfig())


def _tampering(root: Path) -> list[tuple[str, str]]:
    result = check_gate_tampering(_ctx(root))
    return sorted((finding.file, finding.message) for finding in result.findings)


def _login_link(root: Path) -> None:
    sync._write_link(root, "project-a", project_name="A", org_name="acme", plan="free")


def _record_path(home: Path, root: Path) -> Path:
    key = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()
    return home / ".skylos" / sync_state.SYNC_RECORD_DIR / f"{key}.json"


def test_untracked_cloud_link_is_not_a_settings_change(repo: Path):
    _write(repo, "tests/test_calc.py", SKIPPED_TESTS)
    _commit(repo, "skip a test")
    _login_link(repo)
    assert (repo / ".skylos/link.json").is_file()
    assert "?? .skylos/" in _git(repo, "status", "--porcelain")

    result = run(repo, base_ref="main", run_tests=False)
    by_id = {outcome.result.id: outcome.result for outcome in result.checks}

    assert by_id["gate_tampering"].status == "pass"
    assert by_id["gate_tampering"].findings == []
    assert by_id["test_tampering"].status == "fail"
    assert {f.rule for f in by_id["test_tampering"].findings if f.blocking} == {
        "SKY-A111"
    }
    assert result.verdict == "fail"
    assert result.comparison.head_dirty is False
    assert ".skylos/link.json" not in {c.path for c in result.comparison.changed}


def test_committed_cloud_link_change_is_still_reported(repo: Path):
    _git(repo, "switch", "-q", "main")
    _login_link(repo)
    _commit(repo, "link on main")
    _git(repo, "switch", "-q", "feature")
    _git(repo, "reset", "-q", "--hard", "main")
    sync._write_link(repo, "project-b", project_name="B", org_name="acme")
    _commit(repo, "repoint the link")

    assert _tampering(repo) == [(".skylos/link.json", PROTECTED_LINK)]


@pytest.mark.parametrize("how", ["committed", "staged"])
def test_cloud_link_the_change_adds_is_reported(repo: Path, how: str):
    _login_link(repo)
    if how == "committed":
        _commit(repo, "add the link")
    else:
        _git(repo, "add", ".skylos/link.json")

    assert _tampering(repo) == [(".skylos/link.json", PROTECTED_LINK)]


def test_tracked_cloud_link_the_change_untracks_is_reported(repo: Path):
    _git(repo, "switch", "-q", "main")
    _login_link(repo)
    _commit(repo, "link on main")
    _git(repo, "switch", "-q", "feature")
    _git(repo, "reset", "-q", "--hard", "main")
    _git(repo, "rm", "-q", "--cached", ".skylos/link.json")
    _git(repo, "commit", "-qm", "untrack the link")
    assert (repo / ".skylos/link.json").is_file()

    comparison = open_comparison(repo, "main")
    link = [c for c in comparison.changed if c.path == ".skylos/link.json"]
    assert [c.status for c in link] == ["deleted"]
    assert _tampering(repo) == [(".skylos/link.json", PROTECTED_LINK)]


def test_symlinked_cloud_link_is_reported(repo: Path, tmp_path: Path):
    target = tmp_path / "elsewhere.json"
    target.write_text('{"project_id": "project-a"}\n')
    (repo / ".skylos").mkdir()
    (repo / ".skylos/link.json").symlink_to(target)

    assert _tampering(repo) == [(".skylos/link.json", PROTECTED_LINK)]
    assert open_comparison(repo, "main").head_dirty is True


def test_untracked_files_from_sync_pull_count_only_until_edited(repo: Path, pull):
    _, pull_now = pull
    pull_now()
    assert {p.name for p in (repo / ".skylos").iterdir()} >= {
        "config.yaml",
        "suppressions.json",
    }

    assert _tampering(repo) == []
    assert open_comparison(repo, "main").head_dirty is False

    config = (repo / ".skylos/config.yaml").read_text()
    _write(
        repo, ".skylos/config.yaml", config.replace("enabled: true", "enabled: false")
    )

    assert _tampering(repo) == [
        (
            ".skylos/config.yaml",
            "changes .skylos/config.yaml, which is protected "
            "(.skylos/ in protected_paths)" + NOT_PULLED,
        )
    ]
    assert open_comparison(repo, "main").head_dirty is True


def test_link_and_pulled_files_together_pass(repo: Path, pull):
    _, pull_now = pull
    _login_link(repo)
    pull_now()

    assert check_gate_tampering(_ctx(repo)).status == "pass"


def test_policy_file_claiming_to_come_from_sync_pull_is_reported(repo: Path):
    _write(
        repo,
        ".skylos/config.yaml",
        "# written by skylos sync pull; do not edit\ngate:\n  enabled: false\n",
    )

    assert _tampering(repo) == [
        (
            ".skylos/config.yaml",
            "changes .skylos/config.yaml, which is protected "
            "(.skylos/ in protected_paths)" + NOT_PULLED,
        )
    ]


def test_record_kept_inside_the_repository_is_not_trusted(repo: Path):
    text = "gate:\n  enabled: false\n"
    _write(repo, ".skylos/config.yaml", text)
    key = hashlib.sha256(os.fsencode(repo)).hexdigest()
    forged = {
        "schema": sync_state.SYNC_RECORD_SCHEMA,
        "repository": str(repo),
        "files": {"config.yaml": "sha256:" + hashlib.sha256(text.encode()).hexdigest()},
    }
    _write(repo, f".skylos/synced-files/{key}.json", json.dumps(forged))

    files = [file for file, _ in _tampering(repo)]
    assert files == [".skylos/config.yaml", f".skylos/synced-files/{key}.json"]


def test_record_for_another_checkout_is_not_trusted(repo: Path, home: Path, pull):
    _, pull_now = pull
    pull_now()
    record_path = _record_path(home, repo)
    record = json.loads(record_path.read_text())
    record["repository"] = str(repo.parent / "other-checkout")
    record_path.write_text(json.dumps(record))

    files = [file for file, _ in _tampering(repo)]
    assert files == [".skylos/config.yaml", ".skylos/suppressions.json"]


def test_restoring_an_earlier_pull_is_reported(repo: Path, pull):
    responses, pull_now = pull
    responses["/api/sync/config"] = {"config": {"gate": {"enabled": False}}}
    pull_now()
    earlier = (repo / ".skylos/config.yaml").read_bytes()
    responses["/api/sync/config"] = PULLED_CONFIG
    pull_now()
    assert _tampering(repo) == []

    (repo / ".skylos/config.yaml").write_bytes(earlier)

    assert [file for file, _ in _tampering(repo)] == [".skylos/config.yaml"]


def test_pulled_files_are_reported_in_ci(repo: Path, pull, monkeypatch):
    _, pull_now = pull
    _login_link(repo)
    pull_now()
    monkeypatch.setenv("CI", "true")

    assert _tampering(repo) == [
        (
            f".skylos/{name}",
            f"changes .skylos/{name}, which is protected "
            "(.skylos/ in protected_paths)" + NOT_TRUSTED_IN_CI,
        )
        for name in ("config.yaml", "suppressions.json")
    ]


def test_failed_pull_leaves_restored_files_unrecorded(repo: Path, home: Path):
    record_root = home / ".skylos" / sync_state.SYNC_RECORD_DIR
    first = {"config.yaml": "gate: {}\n", "suppressions.json": "{}\n"}
    with sync_state.activate_sync_files(repo, first, record_root=record_root):
        pass
    for name in first:
        assert sync_state.synced_file_matches(repo, name, record_root=record_root)

    with pytest.raises(RuntimeError, match="trust storage failed"):
        with sync_state.activate_sync_files(
            repo, {"config.yaml": "gate: {enabled: false}\n"}, record_root=record_root
        ):
            raise RuntimeError("trust storage failed")

    assert (repo / ".skylos/config.yaml").read_text() == "gate: {}\n"
    assert not sync_state.synced_file_matches(
        repo, "config.yaml", record_root=record_root
    )
    assert sync_state.synced_file_matches(
        repo, "suppressions.json", record_root=record_root
    )


@pytest.mark.parametrize("blocked", ["file_parent", "symlinked_folder"])
def test_unwritable_record_rolls_back_the_pull(
    repo: Path, tmp_path: Path, blocked: str
):
    _write(repo, ".skylos/config.yaml", "previous\n")
    if blocked == "file_parent":
        blocker = tmp_path / "not-a-folder"
        blocker.write_text("")
        record_root = blocker / "records"
    else:
        (tmp_path / "real-records").mkdir()
        record_root = tmp_path / "records"
        record_root.symlink_to(tmp_path / "real-records", target_is_directory=True)

    with pytest.raises(
        OSError,
        match="Could not (reset the synced file record|record the synced files)",
    ):
        with sync_state.activate_sync_files(
            repo, {"config.yaml": "new\n"}, record_root=record_root
        ):
            pass

    assert (repo / ".skylos/config.yaml").read_text() == "previous\n"
    if blocked == "symlinked_folder":
        assert not list((tmp_path / "real-records").iterdir())


def test_activation_without_a_record_root_keeps_no_record(repo: Path, home: Path):
    with sync_state.activate_sync_files(repo, {"config.yaml": "gate: {}\n"}):
        pass

    assert not (home / ".skylos" / sync_state.SYNC_RECORD_DIR).exists()
    assert [file for file, _ in _tampering(repo)] == [".skylos/config.yaml"]


def _session_tampering(root: Path) -> list[str]:
    comparison = session.open_session_comparison(root, "qa")
    try:
        config = parse_done_config(
            comparison.base_text("pyproject.toml", sha=comparison.config_sha)
        )
        result = check_gate_tampering(CheckContext(comparison, config, run_tests=False))
    finally:
        comparison._index_owner.cleanup()
    return sorted(finding.file for finding in result.findings)


def test_late_session_ignores_untracked_cloud_link(repo: Path):
    session.capture_session(repo, "qa", before_edit=False)
    _login_link(repo)

    assert _session_tampering(repo) == []


def test_session_reports_policy_edits_after_the_pull(repo: Path, pull):
    _, pull_now = pull
    pull_now()
    session.capture_session(repo, "qa")
    _login_link(repo)
    assert _session_tampering(repo) == []

    config = (repo / ".skylos/config.yaml").read_text()
    _write(
        repo, ".skylos/config.yaml", config.replace("enabled: true", "enabled: false")
    )

    assert _session_tampering(repo) == [".skylos/config.yaml"]
