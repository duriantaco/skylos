"""Whether a human approved a pull request's head commit, read from GitHub.

Used by the risk review when a change has risk classes: they need a human
approval. In GitHub Actions (a token, ``GITHUB_REPOSITORY`` and a
pull-request event), the pull request's reviews are read through the REST
API. An approval counts when, as GitHub itself counts approvals:

* it is the reviewer's latest review that approves, requests changes or was
  dismissed (a later "changes requested" or a dismissal cancels it);
* it was submitted on the head commit the risk review checked: an approval
  of an older commit does not cover what was pushed after it;
* the reviewer is a person: not a GitHub App or bot account (type ``Bot``,
  a login ending in ``[bot]``), not a login listed in ``non_human_logins``;
* the reviewer can write to the repository (author association OWNER,
  MEMBER or COLLABORATOR, confirmed through the collaborator permission
  API): on a public repository anyone can leave an approving review.

Any API error, unexpected response or missing context that should be there
leaves the result undecided; the caller then fails closed.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote

_MAX_EVENT_BYTES = 25 * 1024 * 1024
_MAX_REVIEW_PAGES = 30
_PER_PAGE = 100
_TIMEOUT_SECONDS = 20
_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+")
_SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_LOGIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\[bot\])?")
_DECISIVE = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
_WRITE_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
_WRITE_PERMISSIONS = frozenset({"admin", "maintain", "write"})


class GitHubApiError(Exception):
    """A GitHub API call failed or returned something unexpected."""


@dataclass
class PullRequestContext:
    api_url: str
    repository: str
    number: int
    head_sha: str
    token: str = field(repr=False)


@dataclass
class HumanApproval:
    # "approved": a person with write access approved the head commit;
    # "missing": the reviews were read and none counts;
    # "error": the reviews could not be read or checked (fail closed).
    status: str
    login: str | None = None
    review_id: int | None = None
    detail: str = ""
    ignored: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "login": self.login,
            "review_id": self.review_id,
            "detail": self.detail,
            "ignored": list(self.ignored),
        }


def pull_request_context(
    environ: Mapping[str, str] | None = None,
) -> PullRequestContext | None:
    """The pull request to read reviews for, or None outside a GitHub
    pull-request run. Raises ``GitHubApiError`` when the context is there
    but malformed."""
    env = os.environ if environ is None else environ
    token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN")
    repository = env.get("GITHUB_REPOSITORY")
    event_path = env.get("GITHUB_EVENT_PATH")
    if not (token and repository and event_path):
        return None
    event = _read_event(event_path)
    pull_request = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pull_request, dict):
        return None  # not a pull-request event: nothing to approve
    if not _REPO_RE.fullmatch(repository):
        raise GitHubApiError("GITHUB_REPOSITORY is not owner/name")
    number = pull_request.get("number")
    head_sha = (pull_request.get("head") or {}).get("sha")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GitHubApiError("the event has no pull request number")
    if not isinstance(head_sha, str) or not _SHA_RE.fullmatch(head_sha):
        raise GitHubApiError("the event has no pull request head commit")
    api_url = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    if not api_url.startswith("https://"):
        raise GitHubApiError("GITHUB_API_URL must be an https:// URL")
    return PullRequestContext(api_url, repository, number, head_sha, token)


def _read_event(event_path: str) -> dict:
    try:
        size = os.path.getsize(event_path)
        if size > _MAX_EVENT_BYTES:
            raise GitHubApiError("the GitHub event file is too large")
        with open(event_path, encoding="utf-8") as handle:  # skylos: ignore[SKY-D215] GITHUB_EVENT_PATH is set by the Actions runner; size checked above
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise GitHubApiError("could not read the GitHub event file") from exc
    return data if isinstance(data, dict) else {}


def find_human_approval(
    context: PullRequestContext,
    analysed_head: str,
    *,
    non_human_logins: tuple[str, ...] = (),
    get_json: Callable[[str], object] | None = None,
) -> HumanApproval:
    """Read the pull request's reviews and decide whether a person with
    write access approved ``analysed_head``."""
    if analysed_head != context.head_sha:
        return HumanApproval(
            "error",
            detail=(
                f"checked commit {analysed_head[:12]} is not the pull request head "
                f"{context.head_sha[:12]}; check out the head commit "
                "(actions/checkout with ref: github.event.pull_request.head.sha)"
            ),
        )
    fetch = get_json or _requests_getter(context.token)
    base = f"{context.api_url}/repos/{context.repository}"
    try:
        reviews = _all_reviews(fetch, f"{base}/pulls/{context.number}/reviews")
        latest = _latest_decisive_reviews(reviews)
        ignored: list[str] = []
        candidates = []
        non_human = {login.lower() for login in non_human_logins}
        for login, review in latest.items():
            if review.get("state") != "APPROVED":
                continue
            user = review.get("user") or {}
            commit = review.get("commit_id")
            if (
                user.get("type") == "Bot"
                or login.lower().endswith("[bot]")
                or login.lower() in non_human
            ):
                ignored.append(f"{login} (not a person)")
            elif commit != context.head_sha:
                ignored.append(
                    f"{login} (approved an older commit {str(commit or '')[:7]})"
                )
            elif review.get("author_association") not in _WRITE_ASSOCIATIONS:
                ignored.append(f"{login} (no write access)")
            else:
                candidates.append(review)
        candidates.sort(key=lambda r: r.get("id") or 0, reverse=True)
        for review in candidates:
            login = review["user"]["login"]
            permission = fetch(
                f"{base}/collaborators/{quote(login, safe='')}/permission"
            )
            if not isinstance(permission, dict):
                raise GitHubApiError("unexpected collaborator permission response")
            level = str(permission.get("role_name") or permission.get("permission"))
            if level in _WRITE_PERMISSIONS or permission.get("permission") in _WRITE_PERMISSIONS:
                return HumanApproval(
                    "approved",
                    login=login,
                    review_id=review.get("id"),
                    detail=f"{login} approved {context.head_sha[:12]}",
                    ignored=ignored,
                )
            ignored.append(f"{login} (no write access)")
    except GitHubApiError as exc:
        return HumanApproval("error", detail=f"could not read the reviews: {exc}")
    detail = "no person with write access approved the head commit"
    return HumanApproval("missing", detail=detail, ignored=ignored)


def _all_reviews(fetch, url: str) -> list[dict]:
    reviews: list[dict] = []
    for page in range(1, _MAX_REVIEW_PAGES + 1):
        batch = fetch(f"{url}?per_page={_PER_PAGE}&page={page}")
        if not isinstance(batch, list):
            raise GitHubApiError("unexpected reviews response")
        reviews.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < _PER_PAGE:
            return reviews
    raise GitHubApiError(f"more than {_MAX_REVIEW_PAGES * _PER_PAGE} reviews")


def _latest_decisive_reviews(reviews: list[dict]) -> dict[str, dict]:
    """Each reviewer's latest review that approves, requests changes or was
    dismissed; comments do not change an earlier decision."""
    latest: dict[str, dict] = {}
    ordered = sorted(
        reviews, key=lambda r: (str(r.get("submitted_at") or ""), r.get("id") or 0)
    )
    for review in ordered:
        user = review.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        if not isinstance(login, str) or not _LOGIN_RE.fullmatch(login):
            continue
        if review.get("state") in _DECISIVE:
            latest[login] = review
    return latest


def _requests_getter(token: str) -> Callable[[str], object]:
    import requests

    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "skylos-risk-review",
        }
    )

    def get_json(url: str) -> object:
        try:
            response = session.get(url, timeout=_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            raise GitHubApiError(type(exc).__name__) from exc
        if response.status_code != 200:
            raise GitHubApiError(f"HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubApiError("the response is not JSON") from exc

    return get_json
