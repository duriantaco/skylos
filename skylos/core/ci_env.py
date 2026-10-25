"""Environment readers for CI providers other than GitHub Actions.

These values are routing hints only. Skylos Cloud re-reads the pull request
from the provider API with its stored connection before it writes anything.
"""

from __future__ import annotations

import os
import re

BITBUCKET_PIPELINES = "bitbucket_pipelines"
AZURE_PIPELINES = "azure_pipelines"

# Conservative subset of git's ref-name rules: the value is interpolated into
# `origin/<branch>...HEAD`, so reject option-like, range-like, or odd input.
_SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/+-]+$")


def _env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def is_bitbucket_pipelines() -> bool:
    return bool(_env("BITBUCKET_BUILD_NUMBER") or _env("BITBUCKET_COMMIT"))


def is_azure_pipelines() -> bool:
    # Azure sets TF_BUILD=True for every script and task on its agents.
    return (_env("TF_BUILD") or "").lower() == "true"


def git_branch_name(value: str | None) -> str | None:
    """Return a plain branch name, or None for tags, PR merge refs, etc."""
    if not value:
        return None
    value = value.strip()
    if value.startswith("refs/heads/"):
        value = value[len("refs/heads/") :]
    elif value.startswith("refs/"):
        return None
    return value or None


def safe_branch_name(value: str | None) -> str | None:
    branch = git_branch_name(value)
    if not branch:
        return None
    if (
        branch.startswith(("-", "/", "."))
        or branch.endswith(("/", ".", ".lock"))
        or ".." in branch
        or "//" in branch
        or not _SAFE_BRANCH_RE.match(branch)
    ):
        return None
    return branch


def bitbucket_pipelines_metadata() -> dict:
    return {
        "build_number": _env("BITBUCKET_BUILD_NUMBER"),
        "commit_sha": _env("BITBUCKET_COMMIT"),
        "repo_full_name": _env("BITBUCKET_REPO_FULL_NAME"),
        "workspace": _env("BITBUCKET_WORKSPACE"),
        "repo_slug": _env("BITBUCKET_REPO_SLUG"),
        "branch": _env("BITBUCKET_BRANCH"),
        "target_branch": _env("BITBUCKET_PR_DESTINATION_BRANCH"),
    }


def azure_pipelines_metadata() -> dict:
    return {
        "build_id": _env("BUILD_BUILDID"),
        # Build.SourceVersion: the merge commit on PR builds.
        "commit_sha": _env("BUILD_SOURCEVERSION"),
        "source_commit_sha": _env("SYSTEM_PULLREQUEST_SOURCECOMMITID"),
        "collection_uri": _env("SYSTEM_COLLECTIONURI"),
        "team_project": _env("SYSTEM_TEAMPROJECT"),
        "repository_id": _env("BUILD_REPOSITORY_ID"),
        "repository_uri": _env("BUILD_REPOSITORY_URI"),
        "branch": git_branch_name(
            _env("SYSTEM_PULLREQUEST_SOURCEBRANCH") or _env("BUILD_SOURCEBRANCH")
        ),
        "target_branch": git_branch_name(_env("SYSTEM_PULLREQUEST_TARGETBRANCH")),
    }


def pr_number_env(provider: str | None) -> str | None:
    if provider == BITBUCKET_PIPELINES:
        return _env("BITBUCKET_PR_ID")
    if provider == AZURE_PIPELINES:
        return _env("SYSTEM_PULLREQUEST_PULLREQUESTID")
    return None


def _is_pr_number(value: str | None) -> bool:
    return bool(value) and value.isdigit()


def is_jenkins() -> bool:
    """Jenkins without a configured URL sets no JENKINS_URL, but every build
    gets JENKINS_HOME and a ``jenkins-<job>-<number>`` BUILD_TAG."""
    return bool(
        _env("JENKINS_URL")
        or _env("JENKINS_HOME")
        or (_env("BUILD_TAG") or "").startswith("jenkins-")
    )


def _jenkins_target() -> str | None:
    if is_jenkins() and _env("CHANGE_ID"):
        return _env("CHANGE_TARGET")
    return None


def _gitlab_target() -> str | None:
    if _env("GITLAB_CI") == "true":
        return _env("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    return None


def _buildkite_target() -> str | None:
    if _env("BUILDKITE") == "true" and _is_pr_number(_env("BUILDKITE_PULL_REQUEST")):
        return _env("BUILDKITE_PULL_REQUEST_BASE_BRANCH")
    return None


def _travis_target() -> str | None:
    if _env("TRAVIS") == "true" and _is_pr_number(_env("TRAVIS_PULL_REQUEST")):
        return _env("TRAVIS_BRANCH")
    return None


def _drone_target() -> str | None:
    if _env("DRONE") == "true" and _env("DRONE_BUILD_EVENT") == "pull_request":
        return _env("DRONE_TARGET_BRANCH")
    return None


def _woodpecker_target() -> str | None:
    if _env("CI") == "woodpecker" and _env("CI_PIPELINE_EVENT") == "pull_request":
        return _env("CI_COMMIT_TARGET_BRANCH")
    return None


_PR_TARGET_READERS = (
    _jenkins_target,
    _gitlab_target,
    _buildkite_target,
    _travis_target,
    _drone_target,
    _woodpecker_target,
)

_CI_MARKERS = (
    ("GitHub Actions", "GITHUB_ACTIONS", "true"),
    ("GitLab CI", "GITLAB_CI", "true"),
    ("CircleCI", "CIRCLECI", "true"),
    ("Buildkite", "BUILDKITE", "true"),
    ("Travis CI", "TRAVIS", "true"),
    ("Drone", "DRONE", "true"),
    ("Woodpecker", "CI", "woodpecker"),
    ("TeamCity", "TEAMCITY_VERSION", None),
)


def ci_name() -> str | None:
    """The CI provider running this process, by its product name."""
    if is_bitbucket_pipelines():
        return "Bitbucket Pipelines"
    if is_azure_pipelines():
        return "Azure Pipelines"
    for name, variable, value in _CI_MARKERS:
        found = _env(variable)
        if found and (value is None or found == value):
            return name
    if is_jenkins():
        return "Jenkins"
    return None


def pr_target_branch() -> str | None:
    """PR target branch from a CI other than GitHub Actions, in a PR build.

    GitHub's GITHUB_BASE_REF is handled by callers so its existing semantics
    stay unchanged; this only covers CIs that GitHub logic never matched.
    Each reader requires its CI's own marker and PR-build signal, so a target
    variable copied into another CI is ignored.
    """
    if is_bitbucket_pipelines():
        branch = safe_branch_name(_env("BITBUCKET_PR_DESTINATION_BRANCH"))
        if branch:
            return branch
    if is_azure_pipelines() and _env("SYSTEM_PULLREQUEST_PULLREQUESTID"):
        branch = safe_branch_name(_env("SYSTEM_PULLREQUEST_TARGETBRANCH"))
        if branch:
            return branch
    for reader in _PR_TARGET_READERS:
        branch = safe_branch_name(reader())
        if branch:
            return branch
    return None


def github_or_ci_base_ref() -> str | None:
    """GITHUB_BASE_REF when non-empty, else another CI's PR target."""
    return os.environ.get("GITHUB_BASE_REF") or pr_target_branch()


def auto_diff_base_ref(default: str = "origin/main") -> str:
    """`--diff` auto base: GitHub first (unchanged), then the other CIs."""
    if "GITHUB_BASE_REF" in os.environ:
        base = os.environ["GITHUB_BASE_REF"]
    else:
        base = pr_target_branch() or default
    if base and not base.startswith("origin/"):
        base = f"origin/{base}"
    return base
