import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import skylos.api as api
from skylos.core import ci_env
from skylos.reporting import provenance
from skylos.security import contracts

SHA_BB = "a" * 40
SHA_MERGE = "b" * 40
SHA_SOURCE = "c" * 40

_CI_PREFIXES = (
    "GITHUB_",
    "BITBUCKET_",
    "SYSTEM_",
    "BUILD_",
    "CI_",
    "CIRCLE",
    "GITLAB_",
    "SKYLOS_",
    "CHANGE_",
    "GIT_",
)
_CI_NAMES = ("JENKINS_URL", "JOB_NAME", "TF_BUILD", "USER")

BITBUCKET_PR_ENV = {
    "CI": "true",
    "BITBUCKET_BUILD_NUMBER": "57",
    "BITBUCKET_COMMIT": SHA_BB,
    "BITBUCKET_PR_ID": "12",
    "BITBUCKET_REPO_FULL_NAME": "acme/service",
    "BITBUCKET_WORKSPACE": "acme",
    "BITBUCKET_REPO_SLUG": "service",
    "BITBUCKET_BRANCH": "feature/login",
    "BITBUCKET_PR_DESTINATION_BRANCH": "develop",
}

AZURE_PR_ENV = {
    "TF_BUILD": "True",
    "BUILD_BUILDID": "901",
    "BUILD_SOURCEVERSION": SHA_MERGE,
    "BUILD_SOURCEBRANCH": "refs/pull/7/merge",
    "BUILD_REPOSITORY_ID": "5f0c6b3e-1111-2222-3333-444455556666",
    "BUILD_REPOSITORY_URI": "https://acme@dev.azure.com/acme/Payments/_git/api",
    "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/",
    "SYSTEM_TEAMPROJECT": "Payments",
    "SYSTEM_PULLREQUEST_PULLREQUESTID": "7",
    "SYSTEM_PULLREQUEST_SOURCECOMMITID": SHA_SOURCE,
    "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/users/dev/fix",
    "SYSTEM_PULLREQUEST_TARGETBRANCH": "refs/heads/main",
}


@pytest.fixture(autouse=True)
def clean_ci_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith(_CI_PREFIXES) or name in _CI_NAMES or name == "CI":
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(api, "_read_git_head", lambda: ("localsha", "local-branch"))
    return monkeypatch


def _set(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


# --- Bitbucket Pipelines ---------------------------------------------------


def test_bitbucket_pr_build_payload(monkeypatch):
    _set(monkeypatch, BITBUCKET_PR_ENV)

    commit, branch, _actor, ci = api.get_git_info()

    assert commit == SHA_BB
    assert branch == "feature/login"
    assert ci == {
        "provider": "bitbucket_pipelines",
        "build_number": "57",
        "commit_sha": SHA_BB,
        "repo_full_name": "acme/service",
        "workspace": "acme",
        "repo_slug": "service",
        "branch": "feature/login",
        "target_branch": "develop",
        "pr_number": 12,
    }


def test_bitbucket_branch_build_has_no_pr_context(monkeypatch):
    env = dict(BITBUCKET_PR_ENV)
    del env["BITBUCKET_PR_ID"]
    del env["BITBUCKET_PR_DESTINATION_BRANCH"]
    env["BITBUCKET_BRANCH"] = "main"
    _set(monkeypatch, env)

    commit, branch, _actor, ci = api.get_git_info()

    assert commit == SHA_BB
    assert branch == "main"
    assert ci["provider"] == "bitbucket_pipelines"
    assert "pr_number" not in ci
    assert "target_branch" not in ci
    assert ci["repo_full_name"] == "acme/service"


def test_bitbucket_detected_by_commit_alone(monkeypatch):
    monkeypatch.setenv("BITBUCKET_COMMIT", SHA_BB)
    provider, meta = api._detect_ci()
    assert provider == "bitbucket_pipelines"
    assert meta["commit_sha"] == SHA_BB


def test_bitbucket_invalid_pr_id_is_dropped(monkeypatch):
    _set(monkeypatch, {**BITBUCKET_PR_ENV, "BITBUCKET_PR_ID": "not-a-number"})
    _commit, _branch, _actor, ci = api.get_git_info()
    assert "pr_number" not in ci


# --- Azure Pipelines -------------------------------------------------------


def test_azure_pr_build_payload(monkeypatch):
    _set(monkeypatch, AZURE_PR_ENV)

    commit, branch, _actor, ci = api.get_git_info()

    # The scanned tree is the merge commit; the PR head travels separately.
    assert commit == SHA_MERGE
    assert branch == "users/dev/fix"
    assert ci == {
        "provider": "azure_pipelines",
        "build_id": "901",
        "commit_sha": SHA_MERGE,
        "source_commit_sha": SHA_SOURCE,
        "collection_uri": "https://dev.azure.com/acme/",
        "team_project": "Payments",
        "repository_id": "5f0c6b3e-1111-2222-3333-444455556666",
        "repository_uri": "https://acme@dev.azure.com/acme/Payments/_git/api",
        "branch": "users/dev/fix",
        "target_branch": "main",
        "pr_number": 7,
    }


def test_azure_ci_build_uses_source_branch(monkeypatch):
    env = {
        key: value
        for key, value in AZURE_PR_ENV.items()
        if not key.startswith("SYSTEM_PULLREQUEST_")
    }
    env["BUILD_SOURCEBRANCH"] = "refs/heads/release/2.0"
    _set(monkeypatch, env)

    commit, branch, _actor, ci = api.get_git_info()

    assert commit == SHA_MERGE
    assert branch == "release/2.0"
    assert ci["provider"] == "azure_pipelines"
    assert ci["branch"] == "release/2.0"
    for key in ("pr_number", "source_commit_sha", "target_branch"):
        assert key not in ci


def test_azure_tag_build_does_not_report_tag_as_branch(monkeypatch):
    _set(
        monkeypatch,
        {
            "TF_BUILD": "True",
            "BUILD_SOURCEVERSION": SHA_MERGE,
            "BUILD_SOURCEBRANCH": "refs/tags/v1.2.3",
        },
    )
    _commit, branch, _actor, ci = api.get_git_info()
    assert "branch" not in ci
    assert branch == "local-branch"


@pytest.mark.parametrize("value", ["True", "true", "TRUE"])
def test_azure_tf_build_true_values(monkeypatch, value):
    monkeypatch.setenv("TF_BUILD", value)
    assert api._detect_ci()[0] == "azure_pipelines"


@pytest.mark.parametrize("value", ["", "False", "0", "yes"])
def test_azure_tf_build_other_values_not_detected(monkeypatch, value):
    monkeypatch.setenv("TF_BUILD", value)
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "7")
    assert api._detect_ci() == (None, {})
    assert api._extract_pr_number(None, {}) is None


# --- Overrides -------------------------------------------------------------


@pytest.mark.parametrize("env", [BITBUCKET_PR_ENV, AZURE_PR_ENV])
def test_explicit_overrides_win(monkeypatch, env):
    _set(monkeypatch, env)
    monkeypatch.setenv("SKYLOS_PR_NUMBER", "404")
    monkeypatch.setenv("SKYLOS_COMMIT", "d" * 40)
    monkeypatch.setenv("SKYLOS_BRANCH", "refs/heads/override")
    monkeypatch.setenv("SKYLOS_ACTOR", "bot")

    commit, branch, actor, ci = api.get_git_info()

    assert commit == "d" * 40
    assert branch == "override"
    assert actor == "bot"
    assert ci["pr_number"] == 404


# --- No leakage between providers -----------------------------------------


def test_bitbucket_ignores_azure_pr_variables(monkeypatch):
    env = dict(BITBUCKET_PR_ENV)
    del env["BITBUCKET_PR_ID"]
    _set(monkeypatch, env)
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "99")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCECOMMITID", SHA_SOURCE)

    _commit, _branch, _actor, ci = api.get_git_info()

    assert ci["provider"] == "bitbucket_pipelines"
    assert "pr_number" not in ci
    assert "source_commit_sha" not in ci


def test_azure_ignores_bitbucket_pr_variables(monkeypatch):
    env = {
        k: v for k, v in AZURE_PR_ENV.items() if k != "SYSTEM_PULLREQUEST_PULLREQUESTID"
    }
    _set(monkeypatch, env)
    monkeypatch.setenv("BITBUCKET_PR_ID", "12")
    monkeypatch.setenv("BITBUCKET_REPO_FULL_NAME", "acme/service")

    _commit, _branch, _actor, ci = api.get_git_info()

    assert ci["provider"] == "azure_pipelines"
    assert "pr_number" not in ci
    assert "repo_full_name" not in ci


def test_github_actions_keeps_priority_and_shape(monkeypatch):
    _set(monkeypatch, {**BITBUCKET_PR_ENV, **AZURE_PR_ENV})
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "e" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/5/merge")

    provider, meta = api._detect_ci()

    assert provider == "github_actions"
    assert set(meta) == {
        "run_id",
        "run_attempt",
        "workflow",
        "actor",
        "repo",
        "ref",
        "sha",
    }
    assert api._extract_pr_number(provider, meta) == 5


def test_jenkins_unchanged_without_new_markers(monkeypatch):
    monkeypatch.setenv("JENKINS_URL", "https://jenkins.example")
    monkeypatch.setenv("BUILD_NUMBER", "3")
    monkeypatch.setenv("CHANGE_ID", "8")
    monkeypatch.setenv("BUILD_SOURCEVERSION", SHA_MERGE)  # no TF_BUILD

    provider, meta = api._detect_ci()

    assert provider == "jenkins"
    assert "commit_sha" not in meta
    assert api._extract_pr_number(provider, meta) == 8


def test_bitbucket_marker_beats_generic_build_number(monkeypatch):
    _set(monkeypatch, BITBUCKET_PR_ENV)
    monkeypatch.setenv("BUILD_NUMBER", "3")
    assert api._detect_ci()[0] == "bitbucket_pipelines"


# --- Upload payload --------------------------------------------------------


@patch("skylos.api.detect_ai_code", return_value={"detected": False})
@patch("skylos.api.SarifExporter")
@patch("skylos.api.get_project_token", return_value="token")
@patch("skylos.api._cli_version", return_value="4.7.0")
@patch("skylos.api.get_git_root", return_value=None)
@patch("requests.post")
def test_upload_payload_carries_azure_ci(
    mock_post, _root, _ver, _token, mock_exporter, _ai, monkeypatch
):
    _set(monkeypatch, AZURE_PR_ENV)
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"scanId": "scan_ci"}
    mock_post.return_value = resp
    mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

    result = api.upload_report({"danger": []}, quiet=True)

    assert result["success"]
    payload = mock_post.call_args.kwargs["json"]
    assert payload["commit_hash"] == SHA_MERGE
    assert payload["branch"] == "users/dev/fix"
    assert payload["ci"]["provider"] == "azure_pipelines"
    assert payload["ci"]["pr_number"] == 7
    assert payload["ci"]["source_commit_sha"] == SHA_SOURCE
    assert payload["ci"]["repository_id"] == AZURE_PR_ENV["BUILD_REPOSITORY_ID"]


# --- --diff base detection -------------------------------------------------


def test_auto_diff_base_bitbucket_pr(monkeypatch):
    _set(monkeypatch, BITBUCKET_PR_ENV)
    assert ci_env.auto_diff_base_ref() == "origin/develop"
    assert ci_env.github_or_ci_base_ref() == "develop"


def test_auto_diff_base_azure_pr(monkeypatch):
    _set(monkeypatch, AZURE_PR_ENV)
    assert ci_env.auto_diff_base_ref() == "origin/main"
    monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/release/3")
    assert ci_env.auto_diff_base_ref() == "origin/release/3"


def test_auto_diff_base_azure_requires_pr_build(monkeypatch):
    env = {
        k: v for k, v in AZURE_PR_ENV.items() if k != "SYSTEM_PULLREQUEST_PULLREQUESTID"
    }
    env["SYSTEM_PULLREQUEST_TARGETBRANCH"] = "refs/heads/develop"
    _set(monkeypatch, env)
    assert ci_env.auto_diff_base_ref() == "origin/main"
    assert ci_env.github_or_ci_base_ref() is None


def test_target_branch_ignored_outside_its_ci(monkeypatch):
    monkeypatch.setenv("BITBUCKET_PR_DESTINATION_BRANCH", "develop")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_PULLREQUESTID", "7")
    monkeypatch.setenv("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/develop")
    assert ci_env.auto_diff_base_ref() == "origin/main"


def test_github_base_ref_semantics_unchanged(monkeypatch):
    _set(monkeypatch, BITBUCKET_PR_ENV)
    monkeypatch.setenv("GITHUB_BASE_REF", "trunk")
    assert ci_env.auto_diff_base_ref() == "origin/trunk"
    assert ci_env.github_or_ci_base_ref() == "trunk"
    # Present-but-empty GITHUB_BASE_REF kept its old `--diff` meaning.
    monkeypatch.setenv("GITHUB_BASE_REF", "")
    assert ci_env.auto_diff_base_ref() == ""
    monkeypatch.delenv("GITHUB_BASE_REF")
    monkeypatch.delenv("BITBUCKET_PR_DESTINATION_BRANCH")
    assert ci_env.auto_diff_base_ref() == "origin/main"


@pytest.mark.parametrize(
    "value",
    ["-x", "--output=/tmp/x", "a..b", "a b", "refs/tags/v1", "main~1", "x.lock", "a:b"],
)
def test_unsafe_target_branch_rejected(monkeypatch, value):
    _set(monkeypatch, {**BITBUCKET_PR_ENV, "BITBUCKET_PR_DESTINATION_BRANCH": value})
    assert ci_env.pr_target_branch() is None
    assert ci_env.auto_diff_base_ref() == "origin/main"


def test_diff_base_callers_use_ci_target(monkeypatch, tmp_path):
    from skylos.cli import _dependency_bump_cli_diff_base

    _set(monkeypatch, BITBUCKET_PR_ENV)

    args = SimpleNamespace(diff_base=None, diff="auto")
    assert _dependency_bump_cli_diff_base(args) == "origin/develop"
    assert provenance._resolve_base_ref() == "origin/develop"

    monkeypatch.setattr(
        contracts, "_git_ref_exists", lambda _root, ref: ref == "origin/develop"
    )
    assert contracts.resolve_diff_base_ref(tmp_path) == "origin/develop"
