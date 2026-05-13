from pathlib import Path

from skylos.cloud.project_context import normalize_repo_subpath, repo_subpath_for_project


def test_normalize_repo_subpath():
    assert normalize_repo_subpath("") == ""
    assert normalize_repo_subpath("/apps//api/") == "apps/api"
    assert normalize_repo_subpath("apps\\api") == "apps/api"
    assert normalize_repo_subpath("apps/../api") is None


def test_repo_subpath_for_project_returns_repo_relative_path(tmp_path: Path):
    repo = tmp_path / "repo"
    service = repo / "apps" / "api"
    service.mkdir(parents=True)

    assert repo_subpath_for_project(service, repo) == "apps/api"
    assert repo_subpath_for_project(repo, repo) == ""

