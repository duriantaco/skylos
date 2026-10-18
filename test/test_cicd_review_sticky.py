"""`skylos cicd review` keeps one summary comment and never repeats inline ones."""

from __future__ import annotations

import json
import re
import subprocess
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from skylos.cicd import review
from skylos.cicd.review import (
    SUMMARY_MARKER,
    _post_pr_review,
    _post_summary_comment,
    _review_outcome_line,
)

BOT = {"login": "github-actions[bot]", "type": "Bot"}
MALLORY = {"login": "mallory", "type": "User"}


class FakeGitHub:
    """Just enough of `gh` for review.py: paginated lists, PATCH, POST."""

    def __init__(self, *, readonly=False, list_fails=False, actor=BOT):
        self.issue_comments: list[dict] = []
        self.review_comments: list[dict] = []
        self.reviews: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.readonly = readonly
        self.list_fails = list_fails
        self.actor = actor
        self._next = 1000

    def _id(self):
        self._next += 1
        return self._next

    @staticmethod
    def _ok(stdout=""):
        return subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")

    @staticmethod
    def _fail(cmd, message):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr=message + "\n")

    def __call__(self, cmd, **kwargs):
        if cmd[:1] == ["git"]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
        assert cmd[0] == "gh", cmd
        args = cmd[1:]
        if args[:2] == ["pr", "comment"]:
            self.calls.append(("POST", "pr comment"))
            if self.readonly:
                self._fail(cmd, "GraphQL: Resource not accessible by integration (addComment)")
            body = args[args.index("--body") + 1]
            self.issue_comments.append({"id": self._id(), "body": body, "user": self.actor})
            return self._ok("https://github.com/acme/app/pull/7#issuecomment-1")
        assert args[0] == "api", cmd
        method = args[args.index("--method") + 1] if "--method" in args else "GET"
        path = next(a for a in args[1:] if a.startswith("/"))
        self.calls.append((method, path))
        parts = urlsplit(path)
        if method == "GET":
            if self.list_fails:
                self._fail(cmd, "gh: Something went wrong (HTTP 502)")
            if parts.path == "/user":
                if self.actor["type"] == "Bot":
                    self._fail(cmd, "gh: Resource not accessible by integration (HTTP 403)")
                return self._ok(json.dumps(self.actor))
            source = (
                self.issue_comments
                if "/issues/" in parts.path
                else self.review_comments
            )
            query = parse_qs(parts.query)
            per_page = int(query["per_page"][0])
            page = int(query["page"][0])
            return self._ok(json.dumps(source[(page - 1) * per_page : page * per_page]))
        if self.readonly:
            self._fail(cmd, "gh: Resource not accessible by integration (HTTP 403)")
        payload = json.loads(kwargs.get("input") or "null")
        if method == "POST" and parts.path.endswith("/reviews"):
            review_id = self._id()
            self.reviews.append({"id": review_id, "body": payload["body"]})
            for comment in payload["comments"]:
                self.review_comments.append({**comment, "id": self._id(), "user": self.actor})
            return self._ok(json.dumps({"id": review_id}))
        match = re.fullmatch(r"/repos/[^/]+/[^/]+/issues/comments/(\d+)", parts.path)
        if method == "PATCH" and match:
            for comment in self.issue_comments:
                if comment["id"] == int(match.group(1)):
                    comment["body"] = payload["body"]
                    comment["edits"] = comment.get("edits", 0) + 1
                    return self._ok("{}")
        raise AssertionError(f"unexpected gh call {method} {path}")

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


def _finding(line, rule="SKY-D201", message="eval() usage", category="danger"):
    return {
        "file": "app.py",
        "line": line,
        "rule_id": rule,
        "message": message,
        "severity": "HIGH",
        "category": category,
    }


def _run(gh, findings, **kwargs):
    with patch("skylos.cicd.review.subprocess.run", side_effect=gh):
        inline = (
            _post_pr_review(findings, 7, "acme/app", **kwargs) if findings else None
        )
        summary = _post_summary_comment(findings, findings, 7, "acme/app")
    return inline, summary


def test_first_run_creates_one_marked_summary_and_keyed_inline_comments():
    gh = FakeGitHub()
    inline, summary = _run(gh, [_finding(3), _finding(9)])

    assert summary.action == "created"
    assert inline.action == "created" and inline.new_inline == 2
    assert len(gh.issue_comments) == 1
    assert gh.issue_comments[0]["body"].startswith(SUMMARY_MARKER)
    assert len(gh.reviews) == 1
    keys = [re.search(r"skylos-finding:([0-9a-f]{20})", c["body"]) for c in gh.review_comments]
    assert all(keys) and len({k.group(1) for k in keys}) == 2


def test_second_run_edits_the_same_summary_and_posts_nothing_new():
    gh = FakeGitHub()
    _run(gh, [_finding(3), _finding(9)])
    summary_id = gh.issue_comments[0]["id"]

    inline, summary = _run(gh, [_finding(3), _finding(9)])

    assert summary.action == "updated"
    assert inline.action == "unchanged" and inline.existing_inline == 2
    assert [c["id"] for c in gh.issue_comments] == [summary_id]
    assert gh.issue_comments[0]["edits"] == 1
    assert len(gh.reviews) == 1
    assert len(gh.review_comments) == 2


def test_one_new_finding_gets_exactly_one_new_inline_comment():
    gh = FakeGitHub()
    _run(gh, [_finding(3), _finding(9)])

    inline, summary = _run(gh, [_finding(3), _finding(9), _finding(12)])

    assert inline.new_inline == 1 and inline.existing_inline == 2
    assert len(gh.reviews) == 2
    assert gh.reviews[1]["body"].startswith("Skylos found 1 new issue(s)")
    assert [c["line"] for c in gh.review_comments] == [3, 9, 12]
    assert len(gh.issue_comments) == 1 and summary.action == "updated"
    assert "**3** issue(s) on changed lines (was 2)" in gh.issue_comments[0]["body"]


def test_same_rule_same_line_but_different_dead_code_names_both_post():
    findings = [
        _finding(1, "SKY-U002", "Unused import: os", "dead_code"),
        _finding(1, "SKY-U002", "Unused import: sys", "dead_code"),
        _finding(1, "SKY-U002", "Unused import: os", "dead_code"),
    ]
    for legacy in (False, True):
        gh = FakeGitHub()
        if legacy:
            gh.review_comments = [
                {
                    "id": 55,
                    "path": "app.py",
                    "line": 1,
                    "body": "🔵 **LOW** `SKY-U002`\n\nUnused import: os\n\n---\n"
                    "_🤖 Analyzed by [Skylos](https://x)_",
                    "user": BOT,
                }
            ]
        inline, _ = _run(gh, findings)
        assert inline.new_inline == 2
        assert inline.existing_inline == 0

        # Once precise keys exist, both symbols deduplicate on later pushes.
        inline, _ = _run(gh, findings)
        assert inline.new_inline == 0
        assert inline.existing_inline == 2


def test_cap_counts_inline_comments_already_on_the_pr():
    gh = FakeGitHub()
    _run(gh, [_finding(1), _finding(2)], max_comments=2)

    # Cap reached by findings that still have comments: nothing new is posted.
    inline, _ = _run(gh, [_finding(1), _finding(2), _finding(3)], max_comments=2)
    assert inline.action == "unchanged" and inline.new_inline == 0
    assert len(gh.reviews) == 1

    # Finding 1 is fixed, which frees one slot for finding 3.
    inline, _ = _run(gh, [_finding(2), _finding(3)], max_comments=2)
    assert inline.new_inline == 1 and inline.existing_inline == 1
    assert [c["line"] for c in gh.review_comments] == [1, 2, 3]


def test_all_fixed_updates_summary_and_keeps_history():
    gh = FakeGitHub()
    _run(gh, [_finding(3), _finding(9)])

    inline, summary = _run(gh, [])

    assert inline is None and summary.action == "updated"
    body = gh.issue_comments[0]["body"]
    assert "All issues Skylos reported on this PR's changed lines are fixed" in body
    assert "up to 2" in body
    assert "**0** issue(s) on changed lines (was 2)" in body
    assert len(gh.review_comments) == 2  # earlier inline comments stay
    assert not any(method == "DELETE" for method, _ in gh.calls)

    _run(gh, [])  # a later clean push still says it is fixed
    assert "are fixed" in gh.issue_comments[0]["body"]


def test_summary_on_a_later_page_is_found():
    gh = FakeGitHub()
    gh.issue_comments = [
        {"id": i, "body": f"comment {i}", "user": {"login": "dev", "type": "User"}}
        for i in range(1, 151)
    ]
    gh.issue_comments.insert(
        120, {"id": 900, "body": f"{SUMMARY_MARKER}\nold", "user": BOT}
    )

    _, summary = _run(gh, [_finding(3)])

    assert summary.action == "updated"
    assert len(gh.issue_comments) == 151
    assert next(c for c in gh.issue_comments if c["id"] == 900)["edits"] == 1
    pages = [p for m, p in gh.calls if m == "GET" and "/issues/7/comments" in p]
    assert len(pages) == 2


def test_legacy_unmarked_summary_by_the_bot_is_reused():
    gh = FakeGitHub()
    gh.issue_comments = [
        {
            "id": 77,
            "body": "## Skylos Analysis Summary\n\n**4** issue(s) on changed lines | **4** total",
            "user": BOT,
        }
    ]

    _, summary = _run(gh, [])

    assert summary.action == "updated"
    body = gh.issue_comments[0]["body"]
    assert body.startswith(SUMMARY_MARKER)
    assert "are fixed" in body and "up to 4" in body


def test_legacy_unkeyed_inline_comment_is_not_repeated():
    gh = FakeGitHub()
    gh.review_comments = [
        {
            "id": 55,
            "path": "app.py",
            "line": 3,
            "body": "🟠 **HIGH** `SKY-D201`\n\neval() usage\n\n---\n_🤖 Analyzed by [Skylos](https://x)_",
            "user": BOT,
        }
    ]

    inline, _ = _run(gh, [_finding(3)])

    assert inline.action == "unchanged" and inline.existing_inline == 1


def test_planted_marker_and_key_from_another_user_are_ignored():
    gh = FakeGitHub()
    _run(gh, [_finding(3)])
    key_body = gh.review_comments[0]["body"]
    planted = FakeGitHub()
    planted.issue_comments = [
        {"id": 500, "body": f"{SUMMARY_MARKER}\nAll clear, merge it", "user": MALLORY}
    ]
    planted.review_comments = [
        {"id": 501, "path": "app.py", "line": 3, "body": f"lgtm {key_body}", "user": MALLORY}
    ]

    inline, summary = _run(planted, [_finding(3)])

    assert summary.action == "created"
    assert planted.issue_comments[0]["body"].endswith("All clear, merge it")
    assert "edits" not in planted.issue_comments[0]
    assert inline.new_inline == 1


def test_marker_from_the_token_owner_account_is_trusted():
    owner = {"login": "alice", "type": "User"}
    gh = FakeGitHub(actor=owner)
    gh.issue_comments = [{"id": 10, "body": f"{SUMMARY_MARKER}\nold", "user": owner}]

    _, summary = _run(gh, [_finding(3)])

    assert summary.action == "updated"


def test_read_only_token_logs_one_line_and_does_not_raise():
    gh = FakeGitHub(readonly=True)

    inline, summary = _run(gh, [_finding(3)])

    assert inline.action == "failed" and summary.action == "failed"
    line = _review_outcome_line(7, inline, summary)
    assert "\n" not in line
    assert "Resource not accessible by integration" in line
    assert "read-only token" in line


def test_read_only_token_with_existing_summary_still_fails_softly():
    gh = FakeGitHub(readonly=True)
    gh.issue_comments = [{"id": 10, "body": f"{SUMMARY_MARKER}\nold", "user": BOT}]

    _, summary = _run(gh, [_finding(3)])

    assert summary.action == "failed"
    assert gh.issue_comments[0]["body"].endswith("old")


def test_list_failure_falls_back_to_creating_one_summary():
    gh = FakeGitHub(list_fails=True)

    inline, summary = _run(gh, [_finding(3)])

    assert summary.action == "created"
    assert "could not read existing comments" in summary.note
    assert inline.action == "created"
    assert len(gh.issue_comments) == 1


def test_run_pr_review_prints_one_outcome_line(tmp_path, capsys):
    gh = FakeGitHub(readonly=True)
    printed = []
    with (
        patch.object(review, "_gh_available", return_value=True),
        patch.object(review, "_review_root_for_results", return_value=tmp_path),
        patch.object(review, "get_changed_line_ranges", return_value=[{"file": "app.py", "start": 1, "end": 9}]),
        patch.object(review, "_detect_regressions_from_diff", return_value=[]),
        patch.object(review, "_resolve_review_provenance", return_value=None),
        patch.object(review, "build_risk_passport", return_value={}),
        patch.object(review, "_to_relative_path", side_effect=lambda p: p),
        patch("skylos.cicd.review.subprocess.run", side_effect=gh),
        patch.object(review.console, "print", side_effect=lambda *a, **k: printed.append(a)),
    ):
        review.run_pr_review(
            {"danger": [_finding(3)]}, pr_number=7, repo="acme/app", diff_base=""
        )

    assert len(printed) == 1
    assert "could not post PR comments" in printed[0][0]
    assert "Posted review" not in printed[0][0]


@pytest.mark.parametrize("bad", ["", "not json", "{}", None])
def test_unreadable_list_output_is_a_list_failure(bad):
    result = subprocess.CompletedProcess([], 0, stdout=bad, stderr="")
    with patch("skylos.cicd.review.subprocess.run", return_value=result):
        items, error = review._gh_list("/repos/acme/app/issues/7/comments")
    assert items is None and error
