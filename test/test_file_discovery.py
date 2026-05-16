from pathlib import Path

from skylos.core.file_discovery import discover_source_files, should_exclude_path


def test_should_exclude_path_honors_sonar_style_globs(tmp_path: Path):
    root = tmp_path / "repo"
    generated = root / "src" / "generated" / "client.py"
    dist = root / "dist" / "bundle.js"
    generated.parent.mkdir(parents=True)
    dist.parent.mkdir(parents=True)
    generated.write_text("", encoding="utf-8")
    dist.write_text("", encoding="utf-8")

    assert should_exclude_path(generated, root, ["**/generated/**"])
    assert should_exclude_path(dist, root, ["dist/**"])


def test_discover_source_files_skips_symlinked_file_outside_root(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.py"
    target.write_text("TOKEN = 'outside-secret'\n", encoding="utf-8")
    link = repo / "leak.py"
    try:
        link.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("filesystem does not allow symlink creation")

    files = discover_source_files(repo, [".py"], respect_gitignore=False)

    assert files == []
