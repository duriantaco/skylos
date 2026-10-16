import json

import pytest

from skylos.commands.badge_cmd import STATIC_BADGE, choose_badge, github_slug
from skylos.core.safe_cache_io import write_text_no_symlink


@pytest.mark.parametrize(
    "url,slug",
    [
        ("git@github.com:acme/pay.git", "acme/pay"),
        ("https://github.com/acme/pay", "acme/pay"),
        ("https://github.com/acme/pay.git", "acme/pay"),
        ("https://x-access-token:abc@github.com/acme/pay.git", "acme/pay"),
        ("ssh://git@github.com/acme/my.repo.git", "acme/my.repo"),
        ("https://gitlab.com/acme/pay.git", None),
        ("https://github.com/acme", None),
        ("", None),
        (None, None),
    ],
)
def test_github_slug(url, slug):
    assert github_slug(url) == slug


def _repo(tmp_path, *, workflow=False, link=None):
    # Pytest's private temp root may have a symlinked system prefix on macOS.
    tmp_path = tmp_path.resolve()
    (tmp_path / ".git").mkdir()
    if workflow:
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        assert write_text_no_symlink(wf / "skylos.yml", "name: Skylos\n")
    if link is not None:
        (tmp_path / ".skylos").mkdir()
        assert write_text_no_symlink(tmp_path / ".skylos" / "link.json", json.dumps(link))
    return tmp_path


def test_linked_cloud_project_gets_the_live_cloud_badge(tmp_path, monkeypatch):
    repo = _repo(tmp_path, workflow=True, link={"project_id": "0205ca69-936b-47d8-a263-62113552ea24"})
    monkeypatch.chdir(repo)
    badge = choose_badge(repo, api_url="https://skylos.dev/", origin="git@github.com:acme/pay.git")
    assert badge["kind"] == "cloud"
    assert badge["markdown"] == (
        "[![Skylos quality gate](https://skylos.dev/api/badge/0205ca69-936b-47d8-a263-62113552ea24)]"
        "(https://skylos.dev/dashboard/projects/0205ca69-936b-47d8-a263-62113552ea24)"
    )


def test_unsafe_project_id_is_ignored(tmp_path, monkeypatch):
    repo = _repo(tmp_path, link={"project_id": "x)](https://evil.example"})
    monkeypatch.chdir(repo)
    assert choose_badge(repo, api_url="https://skylos.dev", origin="")["kind"] == "static"


def test_github_workflow_gets_the_actions_badge(tmp_path, monkeypatch):
    repo = _repo(tmp_path, workflow=True)
    monkeypatch.chdir(repo)
    badge = choose_badge(repo, api_url="https://skylos.dev", origin="git@github.com:acme/pay.git")
    assert badge["kind"] == "github-actions"
    assert badge["markdown"] == (
        "[![Skylos gate](https://github.com/acme/pay/actions/workflows/skylos.yml/badge.svg)]"
        "(https://github.com/acme/pay/actions/workflows/skylos.yml)"
    )


def test_no_workflow_or_non_github_falls_back_to_static(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    badge = choose_badge(repo, api_url="https://skylos.dev", origin="git@github.com:acme/pay.git")
    assert badge["kind"] == "static"
    assert badge["markdown"] == STATIC_BADGE
    assert "logo=python" not in STATIC_BADGE
    assert "skylos cicd init" in badge["note"]
    assert choose_badge(None, api_url="https://skylos.dev")["kind"] == "static"


def test_gitlab_with_workflow_is_static(tmp_path, monkeypatch):
    repo = _repo(tmp_path, workflow=True)
    monkeypatch.chdir(repo)
    assert choose_badge(repo, api_url="https://skylos.dev", origin="https://gitlab.com/a/b.git")["kind"] == "static"


def test_plain_prints_markdown_only(tmp_path, monkeypatch, capsys):
    from skylos.commands.badge_cmd import run_badge_command

    _repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert run_badge_command(["--plain"]) == 0
    assert capsys.readouterr().out == STATIC_BADGE + "\n"
