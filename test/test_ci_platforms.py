import os
from types import SimpleNamespace

import pytest

from skylos.core import ci_env
from skylos.reporting import provenance

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
    "BUILDKITE",
    "TRAVIS",
    "DRONE",
    "TEAMCITY_",
)
_CI_NAMES = (
    "CI",
    "JENKINS_URL",
    "JENKINS_HOME",
    "TF_BUILD",
    "WORKSPACE",
    "WORKSPACE_TMP",
)

JENKINS_PR = {"JENKINS_URL": "http://ci/", "CHANGE_ID": "42", "CHANGE_TARGET": "develop"}
GITLAB_MR = {
    "GITLAB_CI": "true",
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release/2",
}
BUILDKITE_PR = {
    "BUILDKITE": "true",
    "BUILDKITE_PULL_REQUEST": "17",
    "BUILDKITE_PULL_REQUEST_BASE_BRANCH": "develop",
}
TRAVIS_PR = {"TRAVIS": "true", "TRAVIS_PULL_REQUEST": "5", "TRAVIS_BRANCH": "develop"}
DRONE_PR = {
    "DRONE": "true",
    "DRONE_BUILD_EVENT": "pull_request",
    "DRONE_TARGET_BRANCH": "develop",
}
WOODPECKER_PR = {
    "CI": "woodpecker",
    "CI_PIPELINE_EVENT": "pull_request",
    "CI_COMMIT_TARGET_BRANCH": "develop",
}

@pytest.fixture(autouse=True)
def clean_ci_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith(_CI_PREFIXES) or name in _CI_NAMES:
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _set(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize(
    "env,branch,name",
    [
        (JENKINS_PR, "develop", "Jenkins"),
        (
            {"JENKINS_HOME": "/var/jenkins_home", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            "develop",
            "Jenkins",
        ),
        (
            {"BUILD_TAG": "jenkins-api-PR-7-3", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            "develop",
            "Jenkins",
        ),
        (GITLAB_MR, "release/2", "GitLab CI"),
        (BUILDKITE_PR, "develop", "Buildkite"),
        (TRAVIS_PR, "develop", "Travis CI"),
        (DRONE_PR, "develop", "Drone"),
        (WOODPECKER_PR, "develop", "Woodpecker"),
    ],
)
def test_pr_build_target_is_the_diff_base(monkeypatch, env, branch, name):
    _set(monkeypatch, env)
    assert ci_env.auto_diff_base_ref() == f"origin/{branch}"
    assert ci_env.github_or_ci_base_ref() == branch
    assert ci_env.ci_name() == name


@pytest.mark.parametrize(
    "env,name",
    [
        ({"JENKINS_URL": "http://ci/", "CHANGE_TARGET": "develop"}, "Jenkins"),
        ({"CHANGE_ID": "42", "CHANGE_TARGET": "develop"}, None),
        (
            {"BUILD_TAG": "buildkite-api-7", "CHANGE_ID": "7", "CHANGE_TARGET": "develop"},
            None,
        ),
        ({"JENKINS_HOME": "/var/jenkins_home", "CHANGE_TARGET": "develop"}, "Jenkins"),
        ({"GITLAB_CI": "true"}, "GitLab CI"),
        ({"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "develop"}, None),
        (
            {
                "BUILDKITE": "true",
                "BUILDKITE_PULL_REQUEST": "false",
                "BUILDKITE_PULL_REQUEST_BASE_BRANCH": "develop",
            },
            "Buildkite",
        ),
        (
            {"TRAVIS": "true", "TRAVIS_PULL_REQUEST": "false", "TRAVIS_BRANCH": "feature"},
            "Travis CI",
        ),
        (
            {"DRONE": "true", "DRONE_BUILD_EVENT": "push", "DRONE_TARGET_BRANCH": "feature"},
            "Drone",
        ),
        (
            {
                "CI": "woodpecker",
                "CI_PIPELINE_EVENT": "push",
                "CI_COMMIT_TARGET_BRANCH": "feature",
            },
            "Woodpecker",
        ),
        (
            {
                "CI": "true",
                "CI_PIPELINE_EVENT": "pull_request",
                "CI_COMMIT_TARGET_BRANCH": "develop",
            },
            None,
        ),
        ({}, None),
    ],
)
def test_builds_that_are_not_pull_requests_keep_origin_main(monkeypatch, env, name):
    _set(monkeypatch, env)
    assert ci_env.auto_diff_base_ref() == "origin/main"
    assert ci_env.github_or_ci_base_ref() is None
    assert ci_env.ci_name() == name


@pytest.mark.parametrize(
    "env,variable",
    [
        (JENKINS_PR, "CHANGE_TARGET"),
        (GITLAB_MR, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        (BUILDKITE_PR, "BUILDKITE_PULL_REQUEST_BASE_BRANCH"),
        (TRAVIS_PR, "TRAVIS_BRANCH"),
        (DRONE_PR, "DRONE_TARGET_BRANCH"),
        (WOODPECKER_PR, "CI_COMMIT_TARGET_BRANCH"),
    ],
)
@pytest.mark.parametrize("value", ["-x", "a..b", "$(id)", "refs/tags/v1", "main~1", "a b"])
def test_unsafe_target_branches_are_rejected(monkeypatch, env, variable, value):
    _set(monkeypatch, {**env, variable: value})
    assert ci_env.pr_target_branch() is None
    assert ci_env.auto_diff_base_ref() == "origin/main"


def test_github_base_ref_still_wins_over_other_ci_targets(monkeypatch):
    _set(monkeypatch, JENKINS_PR)
    monkeypatch.setenv("GITHUB_BASE_REF", "trunk")
    assert ci_env.auto_diff_base_ref() == "origin/trunk"
    assert ci_env.github_or_ci_base_ref() == "trunk"


def test_diff_base_callers_use_the_jenkins_target(monkeypatch):
    from skylos.cli import _dependency_bump_cli_diff_base

    _set(monkeypatch, JENKINS_PR)
    assert _dependency_bump_cli_diff_base(SimpleNamespace(diff_base=None, diff="auto")) == (
        "origin/develop"
    )
    assert provenance._resolve_base_ref() == "origin/develop"
