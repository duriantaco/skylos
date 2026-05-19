from types import SimpleNamespace

import pytest

from skylos.ui import nudge


def _scan_args(**overrides):
    values = {
        "json": False,
        "quiet": False,
        "all_checks": False,
        "danger": False,
        "secrets": False,
        "quality": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_nudges_enabled_reads_regular_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos]\nnudges = false\n",
        encoding="utf-8",
    )

    assert nudge._nudges_enabled(tmp_path) is False


def test_nudge_ignores_symlinked_pyproject(tmp_path, monkeypatch):
    outside = tmp_path / "outside.toml"
    outside.write_text("[tool.skylos]\nnudges = false\n", encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    try:
        pyproject.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    monkeypatch.setattr(nudge, "_is_ci", lambda: False)

    result = {"danger": [{"rule_id": "SKY-D201"}]}

    assert (
        nudge.pick_nudge(result, _scan_args(), tmp_path)
        == "[dim]Check LLM defenses:[/dim] [bold]skylos defend .[/bold]"
    )


def test_safe_pyproject_path_rejects_symlink(tmp_path):
    outside = tmp_path / "outside.toml"
    outside.write_text("[tool.skylos]\nnudges = false\n", encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    try:
        pyproject.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        nudge._safe_pyproject_path(tmp_path)


def test_safe_pyproject_path_rejects_non_regular_file(tmp_path):
    (tmp_path / "pyproject.toml").mkdir()

    with pytest.raises(ValueError, match="regular file"):
        nudge._safe_pyproject_path(tmp_path)


def test_nudges_enabled_defaults_true_for_oversized_pyproject(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos]\nnudges = false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(nudge, "NUDGE_PYPROJECT_MAX_BYTES", 4)

    assert nudge._nudges_enabled(tmp_path) is True
