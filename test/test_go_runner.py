from __future__ import annotations

from pathlib import Path

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
