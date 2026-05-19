from types import SimpleNamespace

import pytest

from skylos.plugins.pytest_unused_fixtures import (
    UnsafeFixtureReportPath,
    UnusedFixturesPlugin,
)


def _plugin(root):
    return UnusedFixturesPlugin(SimpleNamespace(rootpath=root))


def test_fixture_report_writes_default_path_inside_root(tmp_path, monkeypatch):
    monkeypatch.delenv("SKYLOS_UNUSED_FIXTURES_OUT", raising=False)
    plugin = _plugin(tmp_path)

    plugin._write_report_file("{}")

    report = tmp_path / ".skylos_unused_fixtures.json"
    assert report.read_text(encoding="utf-8") == "{}"


def test_fixture_report_writes_nested_path_inside_root(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_UNUSED_FIXTURES_OUT", "reports/fixtures.json")
    plugin = _plugin(tmp_path)

    plugin._write_report_file("{}")

    report = tmp_path / "reports" / "fixtures.json"
    assert report.read_text(encoding="utf-8") == "{}"


def test_fixture_report_rejects_absolute_path_outside_root(tmp_path, monkeypatch):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    monkeypatch.setenv("SKYLOS_UNUSED_FIXTURES_OUT", str(outside))
    plugin = _plugin(tmp_path)

    with pytest.raises(UnsafeFixtureReportPath):
        plugin._write_report_file("{}")

    assert not outside.exists()


def test_fixture_report_rejects_default_symlink(tmp_path, monkeypatch):
    monkeypatch.delenv("SKYLOS_UNUSED_FIXTURES_OUT", raising=False)
    outside = tmp_path.parent / f"{tmp_path.name}-target.json"
    outside.write_text("keep", encoding="utf-8")
    report = tmp_path / ".skylos_unused_fixtures.json"
    try:
        report.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    plugin = _plugin(tmp_path)

    with pytest.raises(UnsafeFixtureReportPath):
        plugin._write_report_file("{}")

    assert outside.read_text(encoding="utf-8") == "keep"


def test_fixture_report_rejects_symlinked_parent(tmp_path, monkeypatch):
    outside = tmp_path.parent / f"{tmp_path.name}-reports"
    outside.mkdir()
    reports = tmp_path / "reports"
    try:
        reports.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    monkeypatch.setenv("SKYLOS_UNUSED_FIXTURES_OUT", "reports/fixtures.json")
    plugin = _plugin(tmp_path)

    with pytest.raises(UnsafeFixtureReportPath):
        plugin._write_report_file("{}")

    assert not (outside / "fixtures.json").exists()
