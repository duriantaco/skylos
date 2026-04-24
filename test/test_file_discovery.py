from pathlib import Path

from skylos.file_discovery import should_exclude_path


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
