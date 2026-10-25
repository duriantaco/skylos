import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from skylos import api, cli
from skylos.cloud import sync
from skylos.cloud.upload_destination import (
    UploadDestination,
    branch_label,
    destination_lines,
    mismatch_refusal_lines,
    project_label,
    receipt_lines,
    receipt_note,
    resolve_upload_destination,
    should_refuse_upload,
    with_cloud_destination,
)

PROJECT_REPO = "https://github.com/Hatch-Point/hatchpoint-dronecode"
COMMIT = "1acce90" + "0" * 33


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _whoami(repo_url=PROJECT_REPO, project_id="proj-1", name="hatchpoint-dronecode"):
    def lookup(_token):
        return {
            "ok": True,
            "project": {"id": project_id, "name": name, "repo_url": repo_url},
        }

    return lookup


def _git_info(branch="feat/lidar"):
    return lambda: (COMMIT, branch, "someone", {})


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(
        root,
        "remote",
        "add",
        "origin",
        "git@github.com:Hatch-Point/hatchpoint-dronecode.git",
    )
    _git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")
    monkeypatch.chdir(root)
    creds = tmp_path / "home" / ".skylos" / "credentials.json"
    monkeypatch.setattr(api, "GLOBAL_CREDS_FILE", creds)
    monkeypatch.setattr(sync, "GLOBAL_CREDS_FILE", creds)
    monkeypatch.setattr(sync, "GLOBAL_CREDS_DIR", creds.parent)
    for name in (
        "SKYLOS_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITLAB_CI",
    ):
        monkeypatch.delenv(name, raising=False)
    return root


def _saved_default_key(token="tok"):
    sync.save_token(token)


def test_saved_key_for_same_repo_over_ssh_and_https_uploads(repo):
    _saved_default_key()

    dest = resolve_upload_destination(repo, whoami=_whoami(), git_info=_git_info())

    assert dest.key_source == "saved"
    assert dest.project_repo == "github.com/hatch-point/hatchpoint-dronecode"
    assert dest.local_repo == "github.com/hatch-point/hatchpoint-dronecode"
    assert dest.repo_mismatch is False
    assert should_refuse_upload(dest) is False
    assert dest.default_branch is None
    assert dest.on_default_branch is None
    assert destination_lines(dest) == [
        "Skylos Cloud project: hatchpoint-dronecode",
        "  Token:  your saved login token; this repo is not linked (skylos project use links it)",
        "  Branch: feat/lidar @ 1acce90",
    ]


def test_saved_key_for_another_repo_is_refused(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://github.com/acme/other"),
        git_info=_git_info(),
    )

    assert dest.repo_mismatch is True
    assert should_refuse_upload(dest) is True
    assert mismatch_refusal_lines(dest)[0] == (
        "Not uploaded: this repo is github.com/hatch-point/hatchpoint-dronecode, "
        "but your saved login token belongs to project hatchpoint-dronecode "
        "(github.com/acme/other)."
    )


def test_linked_project_for_another_repo_warns_but_uploads(repo):
    sync.save_token("tok", project_id="proj-1", project_name="hatchpoint-dronecode")
    sync._write_link(repo, "proj-1", project_name="hatchpoint-dronecode")

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://github.com/acme/other"),
        git_info=_git_info(),
    )

    assert dest.key_source == "link"
    assert should_refuse_upload(dest) is False
    assert destination_lines(dest)[-1] == (
        "  This token's project is connected to github.com/acme/other, "
        "but this repo is github.com/hatch-point/hatchpoint-dronecode."
    )


def test_env_token_for_another_repo_is_never_refused(repo, monkeypatch):
    monkeypatch.setenv("SKYLOS_TOKEN", "env-token")

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://github.com/acme/other"),
        git_info=_git_info(),
    )

    assert dest.key_source == "env"
    assert dest.repo_mismatch is True
    assert should_refuse_upload(dest) is False


def test_project_without_repository_is_not_a_mismatch(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo, whoami=_whoami(repo_url=None), git_info=_git_info()
    )

    assert dest.project_repo is None
    assert should_refuse_upload(dest) is False


def test_repo_without_origin_is_not_a_mismatch(repo):
    _git(repo, "remote", "remove", "origin")
    _saved_default_key()

    dest = resolve_upload_destination(repo, whoami=_whoami(), git_info=_git_info())

    assert dest.local_repo is None
    assert dest.default_branch is None
    assert should_refuse_upload(dest) is False
    assert branch_label(dest) == "feat/lidar @ 1acce90"


def test_failed_project_lookup_never_invents_a_project_name(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo, whoami=lambda _t: None, git_info=_git_info()
    )

    assert dest.project_name is None
    assert dest.project_id is None
    assert should_refuse_upload(dest) is False
    assert project_label(dest) == (
        "unknown (Skylos Cloud did not name the project for this token)"
    )


def test_hostile_project_fields_are_not_used_in_links_or_text(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(project_id="../../evil", name="evil\x1b[31mname\n"),
        git_info=_git_info(),
    )

    assert dest.project_id is None
    assert dest.project_name == "evil[31mname"
    lines = receipt_lines(dest, {"scan_id": "scan-1"}, "https://skylos.dev")
    assert not any("Scan:" in line or "/dashboard/" in line for line in lines)
    assert not any("Overview:" in line or "evil/" in line for line in lines)
    assert not any(
        "Scan:" in line
        for line in receipt_lines(dest, {"scan_id": "a/../b"}, "https://skylos.dev")
    )


def test_no_key_has_no_destination_and_no_lookup(repo):
    lookup = Mock()

    dest = resolve_upload_destination(repo, whoami=lookup, git_info=_git_info())

    assert dest.key_source == "none"
    lookup.assert_not_called()


def _dest(
    branch="feat/lidar", default="main", project_id="proj-1", source="repository"
):
    return UploadDestination(
        key_source="saved",
        project_id=project_id,
        project_name="hatchpoint-dronecode",
        branch=branch,
        commit=COMMIT,
        default_branch=default,
        default_branch_source=source,
    )


def _reported(
    branch="feat/lidar", default="main", source="repository", project_id="proj-1"
):
    return {
        "destination": {
            "project_id": project_id,
            "branch": branch,
            "default_branch": default,
            "default_branch_source": source,
        }
    }


def test_cloud_reported_destination_sets_branch_default_and_project():
    local = _dest(default=None, project_id=None, source=None)

    reported = with_cloud_destination(local, _reported())

    assert reported.branch == "feat/lidar"
    assert reported.default_branch == "main"
    assert reported.default_branch_source == "repository"
    assert reported.project_id == "proj-1"
    assert reported.on_default_branch is False


def test_cloud_relabelled_branch_wins_over_the_local_branch():
    reported = with_cloud_destination(_dest(default=None), _reported(branch="pr/12"))

    assert branch_label(reported) == "pr/12 @ 1acce90 (not the default branch, main)"


def test_hostile_cloud_destination_values_are_ignored_or_cleaned():
    local = _dest(default=None, project_id=None, source=None)

    reported = with_cloud_destination(
        local,
        {
            "destination": {
                "project_id": "../x",
                "branch": 7,
                "default_branch": "ma\x1bin\n",
                "default_branch_source": "trust-me",
            }
        },
    )

    assert reported.project_id is None
    assert reported.branch == "feat/lidar"
    assert reported.default_branch == "main"
    assert reported.default_branch_source is None
    assert with_cloud_destination(local, {"destination": "main"}) == local


def test_assumed_default_branch_is_called_an_assumption():
    dest = _dest(branch="main", source="assumed")

    assert receipt_note(dest, "verified_ci") == (
        "Skylos Cloud assumed main is the default branch because it could not read "
        "it from GitHub or GitLab."
    )
    lines = receipt_lines(dest, {"success": True}, "https://skylos.dev")
    assert lines[1].startswith(
        "Branch: main @ 1acce90 (the assumed default branch) · Overview: "
    )
    assert receipt_lines(_dest(source="assumed"), {}, "https://skylos.dev")[
        1
    ].startswith("Branch: feat/lidar @ 1acce90 (not the assumed default branch, main)")


def test_server_without_destination_never_guesses_the_default_branch():
    lines = receipt_lines(
        _dest(default=None, source=None),
        {"success": True, "scan_id": "scan-1", "upload_trust": "unverified"},
        "https://skylos.dev",
    )

    assert lines[1].startswith("Branch: feat/lidar @ 1acce90 · Overview: ")
    assert lines[2] == (
        "Skylos Cloud did not report its default branch; only the default branch "
        "sets the project verdict."
    )


def test_upload_result_keeps_only_string_destination_fields():
    result = api._report_upload_success_result(
        {
            "quality_gate": {"passed": True},
            "destination": {
                "project_id": "proj-1",
                "branch": "feat/lidar",
                "default_branch": "main",
                "default_branch_source": "repository",
                "extra": "dropped",
                "pr": 12,
            },
        },
        "scan-1",
        True,
        "pro",
    )

    assert result["destination"] == {
        "project_id": "proj-1",
        "branch": "feat/lidar",
        "default_branch": "main",
        "default_branch_source": "repository",
    }


def test_feature_branch_effects_say_verdict_follows_default_branch():
    assert receipt_note(_dest(), "unverified") == (
        "This is not main: Overview shows its gate when you pick feat/lidar "
        "in the branch menu, but the project verdict follows main only."
    )


def test_default_branch_login_key_upload_says_it_does_not_count():
    assert receipt_note(_dest(branch="main"), "unverified") == (
        "This is main, but a login-token upload is unverified: it does not set the "
        "project verdict or mark issues fixed."
    )


def test_default_branch_ci_upload_can_set_the_verdict():
    assert receipt_note(_dest(branch="main"), "verified_ci") is None
    lines = receipt_lines(
        _dest(branch="main"), {"upload_trust": "verified_ci"}, "https://skylos.dev"
    )
    assert len(lines) == 2


def test_receipt_links_go_to_the_project_scan_overview_and_issues():
    lines = receipt_lines(
        _dest(),
        {"success": True, "scan_id": "scan-1", "upload_trust": "unverified"},
        "https://skylos.dev/",
    )

    assert lines == [
        "",
        "Branch: feat/lidar @ 1acce90 (not the default branch, main) · Overview: "
        "https://skylos.dev/dashboard/projects/proj-1?branch=feat%2Flidar · Issues: "
        "https://skylos.dev/dashboard/projects/proj-1/issues?branch=feat%2Flidar",
        "This is not main: Overview shows its gate when you pick feat/lidar "
        "in the branch menu, but the project verdict follows main only.",
    ]
    assert not any("scans/" in line for line in lines)


def test_login_label_follows_the_saved_default_key(repo):
    sync.save_token("tok-a", project_id="pid-a", project_name="test1", org_name="Org")
    sync.save_token(
        "tok-b", project_id="pid-b", project_name="hatchpoint-dronecode", org_name="Org"
    )

    creds = json.loads(api.GLOBAL_CREDS_FILE.read_text())

    assert creds["token"] == "tok-b"
    assert creds["project_id"] == "pid-b"
    assert creds["project_name"] == "hatchpoint-dronecode"
    assert set(creds["tokens"]) == {"pid-a", "pid-b"}

    sync.save_token("tok-c")
    creds = json.loads(api.GLOBAL_CREDS_FILE.read_text())

    assert creds["token"] == "tok-c"
    assert "project_name" not in creds
    assert "project_id" not in creds
    assert set(creds["tokens"]) == {"pid-a", "pid-b"}


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


_EMPTY_RESULT = {
    "analysis_summary": {"total_files": 1},
    "unused_functions": [],
    "unused_imports": [],
    "unused_variables": [],
    "unused_classes": [],
    "unused_parameters": [],
    "danger": [],
    "quality": [],
    "secrets": [],
}


def _run_main(monkeypatch, argv, destination, upload_response):
    monkeypatch.setattr(cli.sys, "argv", argv)
    monkeypatch.setattr(cli, "_resolve_upload_destination", lambda _root: destination)
    fake_logger = Mock()
    fake_logger.console = Mock()
    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(_EMPTY_RESULT)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli._is_ci", return_value=False),
        patch("skylos.api.get_project_token", return_value="tok"),
        patch("skylos.cli.upload_report", return_value=upload_response) as upload,
    ):
        exit_code = 0
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code
    printed = [
        str(call.args[0])
        for call in fake_logger.console.print.call_args_list
        if call.args
    ]
    return exit_code, upload, printed


def _mismatched_saved_key():
    return UploadDestination(
        key_source="saved",
        project_id="proj-1",
        project_name="hatchpoint-dronecode",
        project_repo="github.com/hatch-point/hatchpoint-dronecode",
        local_repo="github.com/acme/other",
        branch="main",
        commit=COMMIT,
        default_branch="main",
    )


def test_rich_upload_to_another_repos_project_is_refused_before_sending(monkeypatch):
    exit_code, upload, printed = _run_main(
        monkeypatch,
        ["skylos", ".", "--upload", "--no-provenance"],
        _mismatched_saved_key(),
        {"success": True, "scan_id": "scan-1"},
    )

    assert exit_code == 1
    upload.assert_not_called()
    assert any(
        "Not uploaded: this repo is github.com/acme/other" in line for line in printed
    )


def test_json_upload_to_another_repos_project_is_refused_before_sending(
    monkeypatch, capsys
):
    exit_code, upload, _printed = _run_main(
        monkeypatch,
        ["skylos", ".", "--upload", "--json", "--no-provenance"],
        _mismatched_saved_key(),
        {"success": True, "scan_id": "scan-1"},
    )

    assert exit_code == 1
    upload.assert_not_called()
    assert "Not uploaded: this repo is github.com/acme/other" in capsys.readouterr().err


def test_rich_upload_names_project_branch_and_links(monkeypatch):
    exit_code, upload, printed = _run_main(
        monkeypatch,
        ["skylos", ".", "--upload", "--no-provenance"],
        _dest(default=None, source=None),
        {
            "success": True,
            "scan_id": "scan-1",
            "quality_gate_passed": True,
            "upload_trust": "unverified",
            **_reported(),
        },
    )

    assert exit_code == 0
    upload.assert_called_once()
    text = "\n".join(printed)
    assert "Skylos Cloud project: hatchpoint-dronecode" in text
    assert "Where this upload went" not in text
    assert (
        "Branch: feat/lidar @ 1acce90 (not the default branch, main) · Overview: "
        in text
    )
    assert (
        "https://skylos.dev/dashboard/projects/proj-1/issues?branch=feat%2Flidar"
        in text
    )
    assert text.index("Skylos Cloud project") < text.index(" · Overview: ")


def test_failed_upload_prints_no_receipt(monkeypatch):
    exit_code, upload, printed = _run_main(
        monkeypatch,
        ["skylos", ".", "--upload", "--no-provenance"],
        _dest(),
        {"success": False, "error": "Cloud is down"},
    )

    assert exit_code == 1
    upload.assert_called_once()
    assert not any(" · Overview: " in line for line in printed)


def _gitlab_repo(repo):
    _git(repo, "remote", "set-url", "origin", "git@gitlab.com:group/repo.git")


def test_gitlab_repo_differing_only_in_case_is_not_refused(repo):
    _gitlab_repo(repo)
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://gitlab.com/Group/Repo"),
        git_info=_git_info(),
    )

    assert dest.repo_mismatch is False
    assert should_refuse_upload(dest) is False
    assert not any("connected to" in line for line in destination_lines(dest))


def test_gitlab_repo_with_another_path_is_still_refused(repo):
    _gitlab_repo(repo)
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://gitlab.com/group/other-repo"),
        git_info=_git_info(),
    )

    assert should_refuse_upload(dest) is True
    assert mismatch_refusal_lines(dest)[0] == (
        "Not uploaded: this repo is gitlab.com/group/repo, but your saved login token "
        "belongs to project hatchpoint-dronecode (gitlab.com/group/other-repo)."
    )


def test_case_differences_on_another_host_are_still_compared(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://GitHub.com/Hatch-Point/Other"),
        git_info=_git_info(),
    )

    assert should_refuse_upload(dest) is True


def test_hostile_repository_url_is_printed_without_control_characters(
    repo, monkeypatch
):
    _gitlab_repo(repo)
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://gitlab.com/a/b%1b]0;x"),
        git_info=_git_info(),
    )

    assert "\x1b" in dest.project_repo
    assert should_refuse_upload(dest) is True
    refusal = mismatch_refusal_lines(dest)
    assert refusal[0] == (
        "Not uploaded: this repo is gitlab.com/group/repo, but your saved login token "
        "belongs to project hatchpoint-dronecode (gitlab.com/a/b]0)."
    )
    monkeypatch.setenv("SKYLOS_TOKEN", "env-token")
    warned = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://gitlab.com/a/b%1b]0;x"),
        git_info=_git_info(),
    )
    lines = destination_lines(warned)
    assert lines[-1] == (
        "  This token's project is connected to gitlab.com/a/b]0, "
        "but this repo is gitlab.com/group/repo."
    )
    assert should_refuse_upload(warned) is False
    for line in [*refusal, *lines]:
        assert all(char.isprintable() for char in line)


def test_long_repository_identity_is_capped_when_printed(repo):
    _saved_default_key()

    dest = resolve_upload_destination(
        repo,
        whoami=_whoami(repo_url="https://github.com/acme/" + "x" * 500),
        git_info=_git_info(),
    )

    assert len(mismatch_refusal_lines(dest)[0]) < 400


def test_default_branch_receipt_keeps_plain_links():
    lines = receipt_lines(
        _dest(branch="main"),
        {"success": True, "scan_id": "scan-1"},
        "https://skylos.dev",
    )

    assert lines == [
        "",
        "Branch: main @ 1acce90 (the default branch) · Overview: "
        "https://skylos.dev/dashboard/projects/proj-1 · Issues: "
        "https://skylos.dev/dashboard/projects/proj-1/issues",
    ]


def test_unknown_default_branch_receipt_links_name_the_branch():
    lines = receipt_lines(
        _dest(branch="release 2/x&y", default=None, source=None),
        {"success": True, "scan_id": "scan-1"},
        "https://skylos.dev",
    )

    assert lines[1].endswith(
        " · Issues: https://skylos.dev/dashboard/projects/proj-1/issues"
        "?branch=release%202%2Fx%26y"
    )
    assert len(lines) == 3


def test_receipt_without_a_branch_names_no_branch():
    lines = receipt_lines(
        _dest(branch=None),
        {"success": True, "scan_id": "scan-1"},
        "https://skylos.dev",
    )

    assert lines[1].startswith("Branch: unknown branch @ 1acce90 · Overview: ")
    assert lines[1].endswith(
        " · Issues: https://skylos.dev/dashboard/projects/proj-1/issues"
    )


@pytest.mark.parametrize("branch", ["main", "feat/x", None, "feat\x1b[31m\nx"])
@pytest.mark.parametrize("default", ["main", None])
@pytest.mark.parametrize("source", ["repository", "assumed", None])
@pytest.mark.parametrize("trust", ["unverified", "verified_ci", None])
def test_receipt_is_at_most_three_printable_lines(branch, default, source, trust):
    dest = with_cloud_destination(
        _dest(branch="main", default=None, source=None),
        {
            "destination": {
                "branch": branch,
                "default_branch": default,
                "default_branch_source": source,
            }
        },
    )
    lines = receipt_lines(dest, {"upload_trust": trust}, "https://skylos.dev")

    assert len(lines) <= 3
    assert lines[0] == ""
    assert lines[1].startswith("Branch: ")
    assert all(char.isprintable() for line in lines for char in line)
    assert sum("/scans/" in line for line in lines) == 0


def test_upload_contents_line_names_the_symbol_map():
    from skylos.cloud.upload_destination import UPLOAD_CONTENTS_LINE

    assert "a map of your functions and classes" in UPLOAD_CONTENTS_LINE
    assert "which calls which" in UPLOAD_CONTENTS_LINE
    assert UPLOAD_CONTENTS_LINE.endswith("Not your repository.")
