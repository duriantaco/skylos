from __future__ import annotations

import pytest

from skylos.engines import go_runner
from skylos.engines.go_runner import GoEngineError, resolve_go_engine_bin


def test_resolve_go_engine_bin_accepts_runnable_override(tmp_path, monkeypatch):
    candidate = tmp_path / "skylos-go"
    candidate.write_text("fake", encoding="utf-8")
    monkeypatch.setenv("SKYLOS_GO_BIN", str(candidate))

    class _Proc:
        returncode = 0

    monkeypatch.setattr(go_runner.subprocess, "run", lambda *args, **kwargs: _Proc())

    assert resolve_go_engine_bin() == str(candidate)


def test_resolve_go_engine_bin_rejects_unrunnable_override(tmp_path, monkeypatch):
    candidate = tmp_path / "skylos-go"
    candidate.write_text("fake", encoding="utf-8")
    monkeypatch.setenv("SKYLOS_GO_BIN", str(candidate))

    def _boom(*args, **kwargs):
        raise OSError("exec format error")

    monkeypatch.setattr(go_runner.subprocess, "run", _boom)

    with pytest.raises(GoEngineError):
        resolve_go_engine_bin()


def test_get_go_engine_status_reports_available_binary(monkeypatch):
    monkeypatch.delenv("SKYLOS_GO_BIN", raising=False)
    monkeypatch.setattr(
        go_runner,
        "resolve_go_engine_bin",
        lambda: "/usr/local/bin/skylos-go",
    )

    assert go_runner.get_go_engine_status() == {
        "status": "available",
        "binary": "/usr/local/bin/skylos-go",
        "configured_by": "PATH",
    }


def test_get_go_engine_status_reports_unavailable_reason(monkeypatch):
    monkeypatch.delenv("SKYLOS_GO_BIN", raising=False)

    def _missing():
        raise GoEngineError("Go engine binary not found\nBuild it locally")

    monkeypatch.setattr(go_runner, "resolve_go_engine_bin", _missing)

    assert go_runner.get_go_engine_status() == {
        "status": "unavailable",
        "reason": "Go engine binary not found",
        "configured_by": "discovery",
        "install": go_runner.go_engine_install_hint(),
    }


def test_go_engine_install_steps_match_this_release(monkeypatch):
    monkeypatch.setattr(go_runner.skylos, "__version__", "4.50.0")

    clone, build = go_runner.go_engine_install_steps()

    assert clone == (
        "git clone --depth 1 --branch v4.50.0 "
        "https://github.com/duriantaco/skylos.git skylos-src"
    )
    assert build == (
        "cd skylos-src/skylos/engines/go && go build -trimpath "
        '-o "$HOME/.local/bin/skylos-go" ./cmd/skylos-go'
    )
    hint = go_runner.go_engine_install_hint()
    assert clone in hint and build in hint
    assert "SKYLOS_GO_BIN" in hint
    assert "ghcr.io/duriantaco/skylos:4.50.0" in hint
    assert "GitHub Action" in hint


def test_missing_engine_error_names_the_build_steps(monkeypatch, tmp_path):
    monkeypatch.delenv("SKYLOS_GO_BIN", raising=False)
    monkeypatch.setattr(go_runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(go_runner, "__file__", str(tmp_path / "go_runner.py"))

    with pytest.raises(GoEngineError) as raised:
        go_runner.resolve_go_engine_bin()

    message = str(raised.value)
    assert message.splitlines()[0] == "Go engine binary not found (skylos-go)."
    for step in go_runner.go_engine_install_steps():
        assert step in message
