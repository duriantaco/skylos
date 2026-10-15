"""skylos cicd risk-review on GitHub merge queues (merge_group events), and the
"nothing in scope" receipt of diff-scoped gate runs. Git is real (temporary
repositories); the GitHub API is mocked."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from skylos.cicd import approval_github, merge_group
from skylos.cicd.approval import Risk
from skylos.cicd.merge_group import (
    MergeGroupError,
    Segment,
    attribute_vetoes,
    merge_group_event,
    parse_queue_ref,
    queue_segments,
)
from skylos.cicd.scope_receipt import report_scope, scope_receipt
from skylos.commands import risk_review_cmd
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect import diff_dependencies

BASE_FILES = {
    "app/__init__.py": "",
    "app/calc.py": "def add(a, b):\n    return a + b\n",
    "README.md": "# demo\n",
    "requirements.txt": "flask==3.0.0\n",
    "pyproject.toml": '[project]\nname = "demo"\nversion = "0.1.0"\n',
}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)


def _commit(root: Path, files: dict[str, str], message: str) -> str:
    _write(root, files)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message, "--allow-empty")
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {"findings": [], "registry_unreachable": False},
    )
    for name in (
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_PATH",
        "GITHUB_EVENT_NAME",
        "GITHUB_BASE_REF",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_OUTPUT",
        "BITBUCKET_PR_DESTINATION_BRANCH",
        "SYSTEM_PULLREQUEST_TARGETBRANCH",
    ):
        monkeypatch.delenv(name, raising=False)


class Queue:
    """A repository shaped like a merge-group checkout: main at the base,
    one queue branch per entry, HEAD at the merge-group commit."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path / "repo"
        self.root.mkdir()
        _git(self.root, "init", "-q", "-b", "main")
        self.base = _commit(self.root, BASE_FILES, "base")
        _git(self.root, "update-ref", "refs/remotes/origin/main", self.base)
        _git(self.root, "switch", "-q", "--detach")
        self.tip = self.base

    def entry(self, number: int, files: dict[str, str], *, ref: bool = True) -> str:
        parent = self.tip
        self.tip = _commit(self.root, files, f"queue #{number}")
        if ref:
            _git(
                self.root,
                "update-ref",
                f"refs/remotes/origin/gh-readonly-queue/main/pr-{number}-{parent}",
                self.tip,
            )
        return self.tip

    def event(self, tmp_path: Path, number: int | None, monkeypatch, *, head_ref=None):
        head_ref = head_ref or (
            f"refs/heads/gh-readonly-queue/main/pr-{number}-{'a' * 40}"
        )
        payload = {
            "action": "checks_requested",
            "merge_group": {
                "head_sha": self.tip,
                "head_ref": head_ref,
                "base_sha": self.base,
                "base_ref": "refs/heads/main",
                "head_commit": {"id": self.tip, "message": "Merge pull request"},
            },
        }
        path = tmp_path / "event.json"
        path.write_text(json.dumps(payload))  # skylos: ignore[SKY-D324] pytest fixture under tmp_path
        monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
        monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        monkeypatch.setenv("GITHUB_REPOSITORY", "acme/web")
        return merge_group_event()


def _review(login, *, commit, rid=1, kind="User", association="MEMBER"):
    return {
        "id": rid,
        "user": {"login": login, "type": kind},
        "state": "APPROVED",
        "commit_id": commit,
        "author_association": association,
        "submitted_at": f"2026-10-13T10:00:{rid:02d}Z",
    }


class FakeGitHub:
    def __init__(self, pulls, reviews, *, fail=None):
        self.pulls = pulls  # number -> head sha (or a full dict)
        self.reviews = reviews  # number -> [review]
        self.fail = fail
        self.urls: list[str] = []

    def __call__(self, url: str):
        self.urls.append(url)
        if self.fail and self.fail in url:
            raise approval_github.GitHubApiError("HTTP 502")
        if "/collaborators/" in url:
            return {"permission": "write"}
        tail = url.split("/pulls/", 1)[1]
        number = int(tail.split("/", 1)[0].split("?", 1)[0])
        if "/reviews" in tail:
            page = int(url.rsplit("page=", 1)[1])
            return self.reviews.get(number, [])[(page - 1) * 100 : page * 100]
        pull = self.pulls[number]
        if isinstance(pull, dict):
            return pull
        return {
            "number": number,
            "state": "open",
            "base": {"ref": "main"},
            "head": {"sha": pull},
        }


def _set_api(monkeypatch, fake):
    monkeypatch.setattr(approval_github, "_requests_getter", lambda token: fake)
    monkeypatch.setattr(merge_group, "_requests_getter", lambda token: fake)
    return fake


def _run(root: Path, capsys, *, base=None, fmt="json"):
    args = argparse.Namespace(path=str(root), base=base, format=fmt)
    code = risk_review_cmd.run_risk_review(args)
    out = capsys.readouterr().out
    return code, (json.loads(out)["approval"] if fmt == "json" else out)


# ---------------------------------------------------------------------------
# event parsing
# ---------------------------------------------------------------------------


def test_queue_ref_names_the_base_and_pull_request():
    sha = "929f8209d40f77f4abc622a499c93a83babdbe64"
    assert parse_queue_ref(f"refs/heads/gh-readonly-queue/main/pr-104-{sha}") == (
        "main",
        104,
    )
    assert parse_queue_ref(f"gh-readonly-queue/release/2.x/pr-7-{sha}") == (
        "release/2.x",
        7,
    )
    for ref in (
        "refs/heads/main",
        f"refs/heads/gh-readonly-queue/main/pr-0-{sha}",
        "refs/heads/gh-readonly-queue/main/pr-7-nothex",
        f"refs/heads/feature/gh-readonly-queue/main/pr-7-{sha}",
    ):
        assert parse_queue_ref(ref) is None


def test_merge_group_event_reads_the_octokit_payload_shape(tmp_path, monkeypatch):
    queue = Queue(tmp_path)
    queue.entry(7, {"README.md": "# demo\nmore\n"})
    event = queue.event(tmp_path, 7, monkeypatch)
    assert event.number == 7 and event.base_branch == "main"
    assert event.base_sha == queue.base and event.head_sha == queue.tip


def test_other_events_are_not_merge_groups(tmp_path, monkeypatch):
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"pull_request": {"number": 1}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    assert merge_group_event() is None
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    assert merge_group_event() is None
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    with pytest.raises(approval_github.GitHubApiError):
        merge_group_event()


def test_a_head_ref_for_another_base_names_no_pull_request(tmp_path, monkeypatch):
    queue = Queue(tmp_path)
    queue.entry(7, {"README.md": "x\n"})
    event = queue.event(
        tmp_path,
        None,
        monkeypatch,
        head_ref=f"refs/heads/gh-readonly-queue/develop/pr-7-{'a' * 40}",
    )
    assert event.number is None


# ---------------------------------------------------------------------------
# segments and attribution
# ---------------------------------------------------------------------------


def test_queue_branches_cut_the_group_into_one_segment_per_pull_request(
    tmp_path, monkeypatch
):
    queue = Queue(tmp_path)
    first = queue.entry(5, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    head = queue.entry(7, {"README.md": "# demo\nmore\n"})
    # A stale queue branch from an earlier attempt is outside the group.
    _git(
        queue.root,
        "update-ref",
        f"refs/remotes/origin/gh-readonly-queue/main/pr-3-{'b' * 40}",
        queue.base,
    )
    event = queue.event(tmp_path, 7, monkeypatch)
    segments = queue_segments(queue.root, event)
    assert [(s.number, s.start, s.end) for s in segments] == [
        (5, queue.base, first),
        (7, first, head),
    ]


def test_queue_branches_that_do_not_form_a_chain_are_ambiguous(tmp_path, monkeypatch):
    queue = Queue(tmp_path)
    queue.entry(5, {"a.txt": "a\n"})
    queue.entry(6, {"b.txt": "b\n"})
    queue.entry(7, {"c.txt": "c\n"})
    event = queue.event(tmp_path, 7, monkeypatch)
    # Point #5's branch at the head too: two pull requests share one commit.
    _git(
        queue.root,
        "update-ref",
        f"refs/remotes/origin/gh-readonly-queue/main/pr-9-{'c' * 40}",
        queue.tip,
    )
    with pytest.raises(MergeGroupError):
        queue_segments(queue.root, event)


def test_attribution_by_segment_and_fallback_to_every_pull_request():
    segments = [Segment(5, "a", "b"), Segment(7, "b", "c")]
    dep = Risk("dependency_changed", None, "requirements.txt", 2, "requests added")
    auth = Risk("auth_removed", "SKY-L021", "app/views.py", 9, "removed")
    big = Risk("large_diff", None, None, None, "changes 900 lines")
    attributed = attribute_vetoes(
        [dep, auth, big],
        segments,
        {5: [dep], 7: [Risk("auth_removed", "SKY-L021", "app/views.py", 4, "removed")]},
    )
    assert attributed == {5: [dep, big], 7: [auth, big]}
    # Two group risks of one kind but only one in the segments: both PRs answer.
    twice = [auth, Risk("auth_removed", "SKY-L021", "app/views.py", 30, "removed")]
    attributed = attribute_vetoes(twice, segments, {5: [], 7: [auth]})
    assert attributed == {5: twice, 7: twice}
    # One segment: the queued pull request answers for everything.
    assert attribute_vetoes([dep], segments[1:]) == {7: [dep]}


# ---------------------------------------------------------------------------
# skylos cicd risk-review on merge_group
# ---------------------------------------------------------------------------


def test_a_group_without_risks_passes_without_reading_github(
    tmp_path, monkeypatch, capsys
):
    queue = Queue(tmp_path)
    queue.entry(7, {"README.md": "# demo\nmore docs\n"})
    queue.event(tmp_path, 7, monkeypatch)
    fake = _set_api(monkeypatch, FakeGitHub({}, {}))
    code, data = _run(queue.root, capsys)
    assert code == 0 and data["verdict"] == "eligible"
    assert data["base"] == queue.base and data["head"] == queue.tip
    assert data["merge_group"]["pull_request"] == 7
    assert data["merge_group"]["base_sha"] == queue.base
    assert fake.urls == []


def test_a_risk_approved_on_the_queued_pull_requests_head_passes(
    tmp_path, monkeypatch, capsys
):
    queue = Queue(tmp_path)
    queue.entry(7, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.event(tmp_path, 7, monkeypatch)
    pr_head = "d" * 40
    fake = _set_api(
        monkeypatch,
        FakeGitHub({7: pr_head}, {7: [_review("alice", commit=pr_head)]}),
    )
    code, data = _run(queue.root, capsys)
    assert code == 0 and data["verdict"] == "human_approved"
    assert data["human_approval"]["login"] == "alice (#7)"
    entry = data["merge_group"]["pull_requests"][0]
    assert entry["number"] == 7 and entry["head_sha"] == pr_head
    assert entry["risks"] == ["dependency_changed"]
    assert entry["approval"]["status"] == "approved"
    assert fake.urls[0] == "https://api.github.com/repos/acme/web/pulls/7"


def test_a_bot_or_stale_approval_does_not_pass_the_queue(tmp_path, monkeypatch, capsys):
    queue = Queue(tmp_path)
    queue.entry(7, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.event(tmp_path, 7, monkeypatch)
    pr_head = "d" * 40
    _set_api(
        monkeypatch,
        FakeGitHub(
            {7: pr_head},
            {
                7: [
                    _review("renovate[bot]", commit=pr_head, rid=1),
                    _review("alice", commit="e" * 40, rid=2),
                ]
            },
        ),
    )
    code, data = _run(queue.root, capsys)
    assert code == 1 and data["verdict"] == "needs_human_approval"
    assert "#7" in data["human_approval"]["detail"]
    code, text = _run(queue.root, capsys, fmt="text")
    assert code == 1
    assert "#7: dependency_changed; no person with write access approved" in text


def test_a_head_ref_without_a_pull_request_cannot_decide(tmp_path, monkeypatch, capsys):
    queue = Queue(tmp_path)
    queue.entry(7, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.event(tmp_path, None, monkeypatch, head_ref="refs/heads/some-branch")
    _set_api(monkeypatch, FakeGitHub({}, {}))
    code, data = _run(queue.root, capsys)
    assert code == 2 and data["verdict"] == "review_check_failed"
    assert "does not name a pull request" in data["human_approval"]["detail"]


@pytest.mark.parametrize(
    "pull, fail",
    [
        ("d" * 40, "/pulls/7"),
        (
            {
                "number": 7,
                "state": "closed",
                "base": {"ref": "main"},
                "head": {"sha": "d" * 40},
            },
            None,
        ),
        (
            {
                "number": 7,
                "state": "open",
                "base": {"ref": "dev"},
                "head": {"sha": "d" * 40},
            },
            None,
        ),
    ],
)
def test_github_errors_and_unexpected_pull_requests_cannot_decide(
    tmp_path, monkeypatch, capsys, pull, fail
):
    queue = Queue(tmp_path)
    queue.entry(7, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.event(tmp_path, 7, monkeypatch)
    _set_api(
        monkeypatch,
        FakeGitHub({7: pull}, {7: [_review("alice", commit="d" * 40)]}, fail=fail),
    )
    code, data = _run(queue.root, capsys)
    assert code == 2 and data["passed"] is False


def test_the_queue_vouches_for_the_pull_request_that_added_the_risk(
    tmp_path, monkeypatch, capsys
):
    queue = Queue(tmp_path)
    queue.entry(5, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.entry(7, {"README.md": "# demo\nmore docs\n"})
    queue.event(tmp_path, 7, monkeypatch)
    heads = {5: "5" * 40, 7: "7" * 40}
    # #7 changed only the README and has no human approval: it needs none.
    _set_api(monkeypatch, FakeGitHub(heads, {5: [_review("alice", commit=heads[5])]}))
    code, data = _run(queue.root, capsys)
    assert code == 0 and data["verdict"] == "human_approved"
    entries = {e["number"]: e for e in data["merge_group"]["pull_requests"]}
    assert entries[5]["risks"] == ["dependency_changed"]
    assert entries[7]["risks"] == [] and "approval" not in entries[7]

    _set_api(monkeypatch, FakeGitHub(heads, {7: [_review("bob", commit=heads[7])]}))
    code, data = _run(queue.root, capsys)
    assert code == 1 and "#5" in data["human_approval"]["detail"]


def test_a_risk_added_by_the_queued_pull_request_needs_its_own_approval(
    tmp_path, monkeypatch, capsys
):
    queue = Queue(tmp_path)
    queue.entry(5, {"README.md": "# demo\nahead\n"})
    queue.entry(7, {"requirements.txt": "flask==3.0.0\nrequests==2.32.0\n"})
    queue.event(tmp_path, 7, monkeypatch)
    heads = {5: "5" * 40, 7: "7" * 40}
    _set_api(monkeypatch, FakeGitHub(heads, {5: [_review("alice", commit=heads[5])]}))
    code, data = _run(queue.root, capsys)
    assert code == 1 and "#7" in data["human_approval"]["detail"]


def test_the_wrong_commit_or_base_never_passes(tmp_path, monkeypatch, capsys):
    queue = Queue(tmp_path)
    middle = queue.entry(7, {"README.md": "# demo\nmore\n"}, ref=False)
    queue.entry(7, {"README.md": "# demo\nmore\nstill more\n"}, ref=False)
    queue.event(tmp_path, 7, monkeypatch)
    _set_api(monkeypatch, FakeGitHub({}, {}))
    # The merge-group commit compared with another base than the queue's.
    code, data = _run(queue.root, capsys, base=middle)
    assert code == 2 and data["error"].startswith("compared with")
    # A workflow that checked out something else than the merge-group commit.
    _git(queue.root, "switch", "-q", "--detach", queue.base)
    _commit(queue.root, {"other.txt": "x\n"}, "elsewhere")
    code, data = _run(queue.root, capsys)
    assert code == 2 and "not the merge-group commit" in data["error"]


def test_merge_group_base_defaults_to_the_event(tmp_path, monkeypatch):
    queue = Queue(tmp_path)
    queue.entry(7, {"README.md": "x\n"})
    event = queue.event(tmp_path, 7, monkeypatch)
    monkeypatch.setenv("GITHUB_BASE_REF", "")
    assert risk_review_cmd._ci_base_ref(event) == queue.base


# ---------------------------------------------------------------------------
# "nothing in scope" receipt
# ---------------------------------------------------------------------------


def _scope_repo(tmp_path: Path, changes: dict[str, str]) -> Path:
    root = tmp_path / "mono"
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    _commit(
        root,
        {
            "apps/api/main.py": "print(1)\n",
            "apps/web/page.tsx": "export const x = 1\n",
            "docs/logo.png": "png",
        },
        "base",
    )
    _git(root, "switch", "-qc", "feature")
    _commit(root, changes, "change")
    return root


def test_a_change_outside_the_scan_path_is_nothing_in_scope(tmp_path):
    root = _scope_repo(tmp_path, {"apps/web/page.tsx": "export const x = 2\n"})
    receipt = scope_receipt(root / "apps" / "api", "main")
    assert receipt.nothing_in_scope
    assert (receipt.changed, receipt.under_path, receipt.checked) == (1, 0, 0)
    assert "none of the 1 changed file(s) is under apps/api" in receipt.line()
    assert "apps/web/page.tsx" in receipt.line()


def test_images_alone_are_nothing_in_scope_but_markdown_is_read(tmp_path):
    root = _scope_repo(tmp_path, {"docs/logo.png": "new", "LICENSE": "MIT\n"})
    receipt = scope_receipt(root, "main")
    assert receipt.nothing_in_scope and receipt.under_path == 2
    # SKY-D260 reads Markdown for hidden instructions: a README change is in scope.
    root = _scope_repo(tmp_path / "md", {"README.md": "# hi\n"})
    assert not scope_receipt(root, "main").nothing_in_scope


def test_report_scope_prints_and_writes_the_step_summary(tmp_path, monkeypatch):
    from io import StringIO

    from rich.console import Console

    root = _scope_repo(tmp_path, {"apps/web/page.tsx": "export const x = 3\n"})
    summary = tmp_path / "summary.md"
    summary.write_text("")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    # GitHub runners set RUNNER_TEMP, and summaries outside it are refused.
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    buffer = StringIO()
    receipt = report_scope(
        root / "apps" / "api", "main", console=Console(file=buffer), summary=True
    )
    assert receipt.nothing_in_scope
    assert "Nothing in scope" in buffer.getvalue()
    assert "**Nothing in scope:**" in summary.read_text()
    # In scope: silent.
    buffer = StringIO()
    report_scope(root, "main", console=Console(file=buffer), summary=True)
    assert buffer.getvalue() == ""


def test_scope_receipt_is_silent_without_git(tmp_path):
    assert scope_receipt(tmp_path, "main") is None
