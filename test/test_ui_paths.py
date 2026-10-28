from pathlib import Path

from skylos.ui.paths import shown_path


def test_a_path_inside_the_current_folder_is_relative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".skylos" / "baseline.json"

    assert shown_path(target) == str(Path(".skylos") / "baseline.json")


def test_the_current_folder_itself_shows_its_name(tmp_path, monkeypatch):
    repo = tmp_path / "acme-shop"
    repo.mkdir()
    monkeypatch.chdir(repo)

    assert shown_path(repo) == "acme-shop"


def test_a_path_under_home_starts_with_a_tilde(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)

    assert shown_path(home / ".skylos" / "credentials.json") == str(Path("~") / ".skylos" / "credentials.json")


def test_any_other_path_is_shown_as_given(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = tmp_path / "work"
    other = tmp_path / "other" / "file.json"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)

    assert shown_path(other) == str(other.resolve())
