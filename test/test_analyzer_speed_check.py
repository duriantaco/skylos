from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "analyzer_speed_check.py"
)


def _load_speed_check_module():
    spec = importlib.util.spec_from_file_location("analyzer_speed_check", SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_build_fixture_creates_mixed_language_project(tmp_path):
    speed_check = _load_speed_check_module()

    file_count = speed_check.build_fixture(tmp_path, per_language=2)

    assert file_count == 14
    assert (tmp_path / "pyproject.toml").is_file()
    assert (tmp_path / "package.json").is_file()
    assert (tmp_path / "python" / "module_0.py").is_file()
    assert (tmp_path / "packages" / "lib" / "src" / "file_0.ts").is_file()
    assert (tmp_path / "javascript" / "component_0.jsx").is_file()
    assert (tmp_path / "rust" / "src" / "module_0.rs").is_file()
    assert (tmp_path / "php" / "service_0.php").is_file()


def test_run_speed_check_reports_pass_and_summary(tmp_path, monkeypatch):
    speed_check = _load_speed_check_module()

    def fake_analyze(*args, **kwargs):
        return json.dumps({"unused_functions": [{"name": "unused"}]})

    ticks = iter([0.0, 0.1, 1.0, 1.2, 2.0, 2.3])
    monkeypatch.setattr(speed_check, "analyze", fake_analyze)
    monkeypatch.setattr(speed_check.time, "perf_counter", lambda: next(ticks))

    summary = speed_check.run_speed_check(
        root=tmp_path,
        per_language=1,
        warmups=1,
        iterations=2,
        max_seconds=0.5,
    )

    assert summary["passed"] is True
    assert summary["file_count"] == 9
    assert summary["finding_count"] == 1
    assert summary["median_seconds"] == pytest.approx(0.25)


def test_run_speed_check_fails_when_median_exceeds_budget(tmp_path, monkeypatch):
    speed_check = _load_speed_check_module()

    def fake_analyze(*args, **kwargs):
        return json.dumps({})

    ticks = iter([0.0, 1.0, 2.0, 3.0])
    monkeypatch.setattr(speed_check, "analyze", fake_analyze)
    monkeypatch.setattr(speed_check.time, "perf_counter", lambda: next(ticks))

    summary = speed_check.run_speed_check(
        root=tmp_path,
        per_language=1,
        warmups=0,
        iterations=2,
        max_seconds=0.5,
    )

    assert summary["passed"] is False
    assert summary["median_seconds"] == 1.0
