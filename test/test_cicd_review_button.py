"""The compact report button links to the current run in the sticky PR summary."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

import pytest

from skylos.cicd.pr_summary import (
    REPORT_BUTTON_URL,
    SummaryInputs,
    brief_lines,
    report_button,
    run_url_from_env,
)
from skylos.cicd.review import SUMMARY_MARKER, _post_summary_comment
from test.test_cicd_review_sticky import FakeGitHub, _finding


class _Tags(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/acme/app/actions/runs/123",
        "https://github.example.com/acme-team/app.js/actions/runs/123",
        "https://github.example.com:8443/acme/app/actions/runs/123",
        "https://github.com/acme/app/actions/runs/12345678901234567890",
    ],
)
def test_report_button_is_a_small_accessible_link_to_the_run(url):
    button = report_button(url)

    assert button is not None
    assert _Tags(button).tags == [
        ("a", {"href": url}),
        (
            "img",
            {
                "src": REPORT_BUTTON_URL,
                "alt": "View Skylos report",
                "width": "192",
                "height": "40",
            },
        ),
    ]
    assert button.endswith("</a>")


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "javascript:alert(1)",
        "http://github.com/acme/app/actions/runs/123",
        "//github.com/acme/app/actions/runs/123",
        "https://user:password@github.com/acme/app/actions/runs/123",
        'https://github.com/acme/app/actions/runs/123" onclick="alert(1)',
        "https://github.com/acme/app/actions/runs/123' onmouseover='alert(1)",
        "https://github.com/acme/app/actions/runs/123\n",
        "https://github.com/acme/app/actions/runs/12\n3",
        "https://github.com/acme/app/actions/runs/12\t3",
        " https://github.com/acme/app/actions/runs/123",
        "https://github.com/acme/app/actions/runs/123?next=other",
        "https://github.com/acme/app/actions/runs/123#fragment",
        "https://github.com/acme/app/actions/runs/123/extra",
        "https://github.com/acme/app/actions/runs/not-a-run",
        "https://github.com/acme/app/actions/runs/123456789012345678901",
        "https://github.com/acme/app/pull/123",
        "https://github.com/acme/actions/runs/123",
        "https://github.com:invalid/acme/app/actions/runs/123",
        "https:///acme/app/actions/runs/123",
    ],
)
def test_missing_or_invalid_run_url_does_not_render_a_button(url):
    assert report_button(url) is None
    assert not any("<a " in line for line in brief_lines(SummaryInputs(run_url=url)))


@pytest.mark.parametrize("with_brief", [False, True])
def test_sticky_summary_keeps_one_button_and_updates_its_run(monkeypatch, with_brief):
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    github = FakeGitHub()
    findings = [_finding(3)]
    first_url = run_url_from_env()
    first_inputs = SummaryInputs(run_url=first_url) if with_brief else None

    with patch("skylos.cicd.review.subprocess.run", side_effect=github):
        first = _post_summary_comment(
            findings, findings, 7, "acme/app", summary_inputs=first_inputs
        )
        comment_id = github.issue_comments[0]["id"]
        assert first_url in github.issue_comments[0]["body"]
        monkeypatch.setenv("GITHUB_RUN_ID", "456")
        second_url = run_url_from_env()
        second_inputs = SummaryInputs(run_url=second_url) if with_brief else None
        second = _post_summary_comment(
            [], [], 7, "acme/app", summary_inputs=second_inputs
        )

    assert first.action == "created"
    assert second.action == "updated"
    assert [comment["id"] for comment in github.issue_comments] == [comment_id]
    comment = github.issue_comments[0]
    assert comment["edits"] == 1
    body = comment["body"]
    assert body.startswith(SUMMARY_MARKER)
    assert "All issues Skylos reported on this PR's changed lines are fixed" in body
    assert first_url not in body
    assert second_url in body
    tags = _Tags(body).tags
    assert [attrs["href"] for tag, attrs in tags if tag == "a"] == [second_url]
    assert [attrs["src"] for tag, attrs in tags if tag == "img"] == [REPORT_BUTTON_URL]
    assert github.writes() == [
        ("POST", "pr comment"),
        ("PATCH", f"/repos/acme/app/issues/comments/{comment_id}"),
    ]


@pytest.mark.parametrize("summary_inputs", [None, SummaryInputs()])
def test_local_summary_without_actions_environment_omits_button(
    monkeypatch, summary_inputs
):
    for name in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"):
        monkeypatch.delenv(name, raising=False)
    github = FakeGitHub()

    with patch("skylos.cicd.review.subprocess.run", side_effect=github):
        result = _post_summary_comment(
            [], [], 7, "acme/app", summary_inputs=summary_inputs
        )

    assert result.action == "created"
    body = github.issue_comments[0]["body"]
    assert body.startswith(SUMMARY_MARKER)
    assert REPORT_BUTTON_URL not in body
    assert not any(tag == "img" for tag, _ in _Tags(body).tags)


def test_button_asset_is_compact_and_self_contained():
    asset = Path(__file__).resolve().parents[1] / "assets/pr-review/view-report-v1.svg"
    svg = ElementTree.parse(asset).getroot()

    assert svg.tag == "{http://www.w3.org/2000/svg}svg"
    assert svg.attrib["width"] == "192"
    assert svg.attrib["height"] == "40"
    assert svg.attrib["viewBox"] == "0 0 192 40"
    assert svg.attrib["shape-rendering"] == "crispEdges"
    assert REPORT_BUTTON_URL.endswith("/assets/pr-review/view-report-v1.svg")
    ids = {element.attrib["id"] for element in svg.iter() if "id" in element.attrib}
    references = []
    for element in svg.iter():
        local_tag = element.tag.rsplit("}", 1)[-1]
        assert local_tag not in {"script", "foreignObject", "image", "style"}
        for name, value in element.attrib.items():
            local_name = name.rsplit("}", 1)[-1]
            assert not local_name.lower().startswith("on")
            assert "url(" not in value
            if local_name == "href":
                assert value.startswith("#")
                assert value[1:] in ids
                references.append(value)
    assert references  # Pixel glyphs are embedded in this SVG.


def test_report_button_source_passes_html_security_scan(capsys):
    from skylos.cicd import pr_summary
    from skylos.rules.danger.danger import scan_ctx

    source = Path(pr_summary.__file__)
    findings = scan_ctx(source.parent, [source])

    assert "Scan failed for" not in capsys.readouterr().err
    assert not [finding for finding in findings if finding["rule_id"] == "SKY-D228"]
