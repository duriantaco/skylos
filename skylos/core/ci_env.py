"""Environment readers for Bitbucket Pipelines and Azure Pipelines.

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


def pr_target_branch() -> str | None:
    """PR target branch from Bitbucket or Azure Pipelines, when in a PR build.

    GitHub's GITHUB_BASE_REF is handled by callers so its existing semantics
    stay unchanged; this only covers CIs that GitHub logic never matched.
    """
    if is_bitbucket_pipelines():
        branch = safe_branch_name(_env("BITBUCKET_PR_DESTINATION_BRANCH"))
        if branch:
            return branch
    if is_azure_pipelines() and _env("SYSTEM_PULLREQUEST_PULLREQUESTID"):
        branch = safe_branch_name(_env("SYSTEM_PULLREQUEST_TARGETBRANCH"))
        if branch:
            return branch
    return None


def github_or_ci_base_ref() -> str | None:
    """GITHUB_BASE_REF when non-empty, else the Bitbucket/Azure PR target."""
    return os.environ.get("GITHUB_BASE_REF") or pr_target_branch()


def auto_diff_base_ref(default: str = "origin/main") -> str:
    """`--diff` auto base: GitHub first (unchanged), then Bitbucket/Azure."""
    if "GITHUB_BASE_REF" in os.environ:
        base = os.environ["GITHUB_BASE_REF"]
    else:
        base = pr_target_branch() or default
    if base and not base.startswith("origin/"):
        base = f"origin/{base}"
    return base
