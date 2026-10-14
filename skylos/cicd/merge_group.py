"""The risk review on a GitHub merge queue (``merge_group`` events).

A merge queue tests a commit GitHub builds itself: the base branch at
``merge_group.base_sha``, the changes of every pull request ahead in the
queue, then the changes of the queued pull request (named in
``merge_group.head_ref``: ``refs/heads/gh-readonly-queue/<base>/pr-<N>-<sha>``).
Nobody reviews that commit, so an approval cannot be read from it. The
evidence is the same as on a pull request, one level down:

* The merge-group commit is compared with ``base_sha``: exactly the code the
  queue would land, with settings from the base commit. A group with no risk
  class passes, as a pull request with none does.
* Each risk is attributed to the pull request whose part of the group added
  it. The queue keeps one ``gh-readonly-queue/<base>/pr-<M>-<sha>`` branch per
  entry, each built on the previous one, so the branches ahead of this group
  (fetched by ``actions/checkout`` with ``fetch-depth: 0``) cut it into one
  segment per pull request. A multi-PR group is analysed once more per
  segment, with the base commit's settings; a risk that no segment explains
  (a combination such as a very large total diff) belongs to every pull
  request in the group.
* A pull request's risks pass when a person with write access approved its
  current head commit, under the same rules as on the pull request: a person,
  write access confirmed through the API, their latest decisive review, on
  that commit. GitHub removes a pull request from the queue when its head
  changes, so the approved head is the head that was queued.

Why every attributed pull request, not only the queued one: with "Only merge
non-failing pull requests" turned off, GitHub merges a failing entry when a
later group containing it passes, so this group vouches for the entries ahead
of it. Check-run conclusions, commit messages and pull request titles are
never used as evidence: a pull request can set its own, and on GitHub a
required check can be satisfied by any app that reports the same name.

Anything that cannot be established (a ``head_ref`` that names no pull
request, queue branches that do not form one chain, a pull request that is
closed or targets another branch, an API error) leaves the result undecided,
and the caller fails closed.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from skylos.cicd.approval_github import (
    _REPO_RE,
    _SHA_RE,
    GitHubApiError,
    HumanApproval,
    PullRequestContext,
    _read_event,
    _requests_getter,
    find_human_approval,
)
from skylos.core.git_context import GitContext
from skylos.core.git_safety import read_only_git_command

logger = logging.getLogger(__name__)

QUEUE_BRANCH_PREFIX = "gh-readonly-queue/"
_QUEUE_REF_RE = re.compile(
    r"(?:refs/heads/)?gh-readonly-queue/(?P<base>[^\0]+?)/pr-(?P<number>[1-9][0-9]{0,9})"
    r"-(?P<sha>[0-9a-f]{40}(?:[0-9a-f]{24})?)\Z"
)
_BRANCH_RE = re.compile(r"refs/heads/(?P<branch>[^\0]+)\Z")
_REMOTE_PREFIXES = ("refs/remotes/origin/", "refs/heads/")
_MAX_QUEUE_REFS = 500
_WORKTREE_TIMEOUT_SECONDS = 300


class MergeGroupError(Exception):
    """The merge group could not be resolved into pull requests."""


@dataclass
class MergeGroupEvent:
    head_ref: str
    head_sha: str
    base_ref: str
    base_sha: str
    base_branch: str
    number: int | None  # the queued pull request; None when head_ref names none

    def to_dict(self) -> dict:
        return {
            "head_ref": self.head_ref,
            "head_sha": self.head_sha,
            "base_ref": self.base_ref,
            "base_sha": self.base_sha,
            "pull_request": self.number,
        }


@dataclass
class Segment:
    number: int
    start: str
    end: str
    queue_branch: str | None = None


@dataclass
class GroupApproval(HumanApproval):
    merge_group: dict = field(default_factory=dict)


def parse_queue_ref(ref: str) -> tuple[str, int] | None:
    """(base branch, pull request number) of a merge-queue branch name."""
    match = _QUEUE_REF_RE.fullmatch(ref or "")
    if match is None:
        return None
    return match.group("base"), int(match.group("number"))


def merge_group_event(
    environ: Mapping[str, str] | None = None,
) -> MergeGroupEvent | None:
    """The merge group of this GitHub Actions run, or None when the run is not
    a ``merge_group`` event. Raises ``GitHubApiError`` when it is one but the
    event cannot be read or is malformed."""
    env = os.environ if environ is None else environ
    name = env.get("GITHUB_EVENT_NAME")
    if name and name != "merge_group":
        return None
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        if name == "merge_group":
            raise GitHubApiError("the merge_group event file is missing")
        return None
    event = _read_event(path)
    group = event.get("merge_group") if isinstance(event, dict) else None
    if not isinstance(group, dict):
        if name == "merge_group":
            raise GitHubApiError("the event has no merge_group")
        return None
    head_sha, base_sha = group.get("head_sha"), group.get("base_sha")
    head_ref, base_ref = group.get("head_ref"), group.get("base_ref")
    for label, sha in (("head_sha", head_sha), ("base_sha", base_sha)):
        if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
            raise GitHubApiError(f"the merge group has no valid {label}")
    if not isinstance(head_ref, str) or not isinstance(base_ref, str):
        raise GitHubApiError("the merge group has no head_ref or base_ref")
    branch = _BRANCH_RE.fullmatch(base_ref)
    if branch is None:
        raise GitHubApiError("the merge group's base_ref is not a branch")
    parsed = parse_queue_ref(head_ref)
    number = None
    if parsed is not None and parsed[0] == branch.group("branch"):
        number = parsed[1]
    return MergeGroupEvent(
        head_ref=head_ref,
        head_sha=head_sha,
        base_ref=base_ref,
        base_sha=base_sha,
        base_branch=branch.group("branch"),
        number=number,
    )


# ---------------------------------------------------------------------------
# Git: which pull request added what
# ---------------------------------------------------------------------------


def _git(context: GitContext, *args: str) -> str:
    result = context.run(*args)
    if result.returncode != 0:
        raise MergeGroupError(f"git {args[0]} failed")
    return result.stdout


def _is_ancestor(context: GitContext, ancestor: str, descendant: str) -> bool:
    result = context.run("merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        raise MergeGroupError("git merge-base failed")
    return result.returncode == 0


def queue_segments(path: str | Path, event: MergeGroupEvent) -> list[Segment]:
    """The group cut at the queue branches ahead of it, oldest first; the
    last segment belongs to the queued pull request."""
    if event.number is None:
        raise MergeGroupError(
            f"head_ref {event.head_ref!r} does not name a pull request queued "
            f"for {event.base_branch!r}"
        )
    context = GitContext.from_path(path)
    listing = _git(
        context,
        "for-each-ref",
        "--format=%(objectname) %(refname)",
        *(f"{prefix}{QUEUE_BRANCH_PREFIX}" for prefix in _REMOTE_PREFIXES),
    )
    found: dict[int, set[str]] = {}
    names: dict[tuple[int, str], str] = {}
    lines = [line for line in listing.splitlines() if line.strip()]
    if len(lines) > _MAX_QUEUE_REFS:
        raise MergeGroupError("too many merge queue branches to resolve")
    for line in lines:
        sha, _, refname = line.partition(" ")
        short = next(
            (refname[len(p) :] for p in _REMOTE_PREFIXES if refname.startswith(p)),
            None,
        )
        parsed = parse_queue_ref(short or "")
        if parsed is None or parsed[0] != event.base_branch:
            continue
        if not _SHA_RE.fullmatch(sha):
            continue
        number = parsed[1]
        # Only branches whose commit is inside this group: after the base,
        # up to (and including) the merge-group commit.
        if sha == event.base_sha or not _is_ancestor(context, event.base_sha, sha):
            continue
        if not _is_ancestor(context, sha, event.head_sha):
            continue
        found.setdefault(number, set()).add(sha)
        names.setdefault((number, sha), short)

    own = found.pop(event.number, set())
    if own - {event.head_sha}:
        raise MergeGroupError(
            f"the queue branch of #{event.number} does not point at the merge-group commit"
        )
    ahead = []
    for number, shas in found.items():
        if len(shas) != 1:
            raise MergeGroupError(
                f"#{number} has more than one queue branch in this group"
            )
        sha = next(iter(shas))
        if sha == event.head_sha:
            raise MergeGroupError(
                f"#{number} and #{event.number} share the merge-group commit"
            )
        ahead.append((number, sha))
    if len({sha for _, sha in ahead}) != len(ahead):
        raise MergeGroupError("two queue branches point at the same commit")

    def depth(item):
        count = _git(context, "rev-list", "--count", f"{event.base_sha}..{item[1]}")
        return int(count.strip() or 0)

    ordered = sorted(ahead, key=depth)
    for (_, older), (_, newer) in zip(ordered, ordered[1:]):
        if not _is_ancestor(context, older, newer):
            raise MergeGroupError("the queue branches ahead do not form one chain")
    segments = []
    previous = event.base_sha
    for number, sha in ordered:
        segments.append(Segment(number, previous, sha, names.get((number, sha))))
        previous = sha
    segments.append(Segment(event.number, previous, event.head_sha, None))
    return segments


def _risk_key(risk) -> tuple:
    return (risk.cls, risk.rule_id, risk.file)


def _segment_vetoes(path: str | Path, segment: Segment, config_sha: str) -> list:
    """Risks one pull request added on top of the group before it, with the
    queue base commit's settings; analysed in a temporary worktree."""
    from skylos.cicd.approval import analyze_change

    context = GitContext.from_path(path)
    with tempfile.TemporaryDirectory(prefix="skylos-merge-group-") as temporary:
        worktree = Path(temporary) / "segment"

        def git(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                read_only_git_command(list(args)),
                capture_output=True,
                text=True,
                timeout=_WORKTREE_TIMEOUT_SECONDS,
                cwd=str(context.root),
                env=context.env,
            )

        added = git(
            "worktree", "add", "--detach", "--quiet", str(worktree), segment.end
        )
        if added.returncode != 0:
            raise MergeGroupError(
                f"could not check out #{segment.number}'s part of the group"
            )
        try:
            result = analyze_change(str(worktree), segment.start, config_ref=config_sha)
        finally:
            git("worktree", "remove", "--force", str(worktree))
            git("worktree", "prune")
    if not result.complete:
        names = ", ".join(sorted(result.classes_incomplete))
        raise MergeGroupError(
            f"#{segment.number}'s part could not be fully checked ({names})"
        )
    return list(result.vetoes)


def attribute_vetoes(
    vetoes: Sequence,
    segments: Sequence[Segment],
    segment_vetoes: Mapping[int, Sequence] | None = None,
) -> dict[int, list]:
    """{pull request: the group's risks it must answer for}.

    A risk belongs to every segment that reports the same class, rule and
    file. A risk no segment explains, or more risks of a kind than the
    segments report together, belongs to every pull request in the group.
    """
    numbers = [segment.number for segment in segments]
    if len(segments) == 1:
        return {numbers[0]: list(vetoes)}
    per_segment = {
        number: Counter(
            _risk_key(risk) for risk in (segment_vetoes or {}).get(number, ())
        )
        for number in numbers
    }
    group_counts = Counter(_risk_key(risk) for risk in vetoes)
    attributed: dict[int, list] = {number: [] for number in numbers}
    for risk in vetoes:
        key = _risk_key(risk)
        owners = [number for number in numbers if per_segment[number][key]]
        explained = sum(per_segment[number][key] for number in numbers)
        if not owners or explained < group_counts[key]:
            owners = numbers
        for number in owners:
            attributed[number].append(risk)
    return attributed


# ---------------------------------------------------------------------------
# GitHub: did a person approve each pull request's head?
# ---------------------------------------------------------------------------


def _github_settings(environ: Mapping[str, str]) -> tuple[str, str, str]:
    token = environ.get("GITHUB_TOKEN") or environ.get("GH_TOKEN")
    repository = environ.get("GITHUB_REPOSITORY")
    if not token:
        raise GitHubApiError("no GITHUB_TOKEN to read the queued pull requests")
    if not repository or not _REPO_RE.fullmatch(repository):
        raise GitHubApiError("GITHUB_REPOSITORY is not owner/name")
    api_url = (environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    if not api_url.startswith("https://"):
        raise GitHubApiError("GITHUB_API_URL must be an https:// URL")
    return api_url, repository, token


def _pull_request_head(fetch, api_url, repository, number, base_branch) -> str:
    data = fetch(f"{api_url}/repos/{repository}/pulls/{number}")
    if not isinstance(data, dict) or data.get("number") != number:
        raise GitHubApiError(f"unexpected response for pull request #{number}")
    base = (data.get("base") or {}).get("ref")
    if base != base_branch:
        raise GitHubApiError(f"#{number} does not target {base_branch}")
    if data.get("state") != "open" and not data.get("merged_at"):
        raise GitHubApiError(f"#{number} is closed")
    head = (data.get("head") or {}).get("sha")
    if not isinstance(head, str) or not _SHA_RE.fullmatch(head):
        raise GitHubApiError(f"#{number} has no head commit")
    return head


def find_group_approval(
    path: str | Path,
    event: MergeGroupEvent,
    vetoes: Sequence,
    *,
    non_human_logins: tuple[str, ...] = (),
    environ: Mapping[str, str] | None = None,
    get_json: Callable[[str], object] | None = None,
    segment_vetoes: Callable[[Segment], Sequence] | None = None,
) -> GroupApproval:
    """Whether every pull request that added one of ``vetoes`` to the group
    has a person's approval on its head commit."""
    env = os.environ if environ is None else environ
    info = event.to_dict()
    info["pull_requests"] = []
    try:
        segments = queue_segments(path, event)
        info["pull_requests"] = [
            {
                "number": segment.number,
                "from": segment.start,
                "to": segment.end,
                "queue_branch": segment.queue_branch,
                "risks": [],
            }
            for segment in segments
        ]
        per_segment = None
        if len(segments) > 1 and vetoes:
            analyse = segment_vetoes or (
                lambda segment: _segment_vetoes(path, segment, event.base_sha)
            )
            per_segment = {segment.number: analyse(segment) for segment in segments}
        attributed = attribute_vetoes(vetoes, segments, per_segment)
    except (
        MergeGroupError,
        GitHubApiError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        return GroupApproval(
            "error",
            detail=f"could not resolve the merge group: {exc}",
            merge_group=info,
        )

    entries = {entry["number"]: entry for entry in info["pull_requests"]}
    for number, risks in attributed.items():
        entries[number]["risks"] = sorted({risk.cls for risk in risks})
        entries[number]["risk_count"] = len(risks)

    try:
        api_url, repository, token = _github_settings(env)
    except GitHubApiError as exc:
        return GroupApproval("error", detail=str(exc), merge_group=info)
    fetch = get_json or _requests_getter(token)

    approved, missing, errors, ignored = [], [], [], []
    for number, risks in attributed.items():
        if not risks:
            continue
        entry = entries[number]
        try:
            head = _pull_request_head(
                fetch, api_url, repository, number, event.base_branch
            )
        except GitHubApiError as exc:
            entry["approval"] = {"status": "error", "detail": str(exc)}
            errors.append(f"#{number}: {exc}")
            continue
        entry["head_sha"] = head
        context = PullRequestContext(api_url, repository, number, head, token)
        human = find_human_approval(
            context, head, non_human_logins=non_human_logins, get_json=fetch
        )
        entry["approval"] = human.to_dict()
        ignored.extend(f"#{number}: {item}" for item in human.ignored)
        if human.status == "approved":
            approved.append((number, human.login))
        elif human.status == "missing":
            missing.append(number)
        else:
            errors.append(f"#{number}: {human.detail}")

    if errors:
        return GroupApproval(
            "error", detail="; ".join(errors), ignored=ignored, merge_group=info
        )
    if missing:
        listed = ", ".join(f"#{number}" for number in missing)
        return GroupApproval(
            "missing",
            detail=(
                f"no person with write access approved the head commit of {listed}"
            ),
            ignored=ignored,
            merge_group=info,
        )
    login = ", ".join(f"{name} (#{number})" for number, name in approved)
    return GroupApproval(
        "approved",
        login=login,
        detail=f"approved in the merge queue: {login}",
        ignored=ignored,
        merge_group=info,
    )
