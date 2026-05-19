import pytest

from skylos.commands.scan_cmd import _write_json_output_file


def test_write_json_output_file_writes_regular_file(tmp_path):
    output = tmp_path / "skylos-results.json"

    _write_json_output_file(str(output), '{"ok": true}')

    assert output.read_text(encoding="utf-8") == '{"ok": true}'


def test_write_json_output_file_refuses_symlink_target(tmp_path):
    target = tmp_path / "outside.json"
    target.write_text("keep me", encoding="utf-8")
    output = tmp_path / "skylos-results.json"
    try:
        output.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(OSError, match="symlink"):
        _write_json_output_file(str(output), '{"clobber": true}')

    assert target.read_text(encoding="utf-8") == "keep me"


def test_write_json_output_file_refuses_relative_symlink_parent(tmp_path, monkeypatch):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    output_dir = tmp_path / "reports"
    try:
        output_dir.symlink_to(real_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    monkeypatch.chdir(tmp_path)

    with pytest.raises(OSError, match="symlink"):
        _write_json_output_file("reports/skylos-results.json", '{"clobber": true}')

    assert not (real_dir / "skylos-results.json").exists()
