"""The retired agent-hook installer must honor the new push-only policy."""

import importlib.util
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_eval_hooks.py"
SPEC = importlib.util.spec_from_file_location("_legacy_eval_installer", SCRIPT)
legacy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = legacy
SPEC.loader.exec_module(legacy)


def test_legacy_api_delegates_only_to_push_installation(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(
        legacy.push_installer,
        "install_push",
        lambda *args, **kwargs: called.append((args, kwargs)) or {"push_only": True},
    )
    assert legacy.install_hooks(tmp_path, Path(sys.executable), dry_run=True) == {
        "push_only": True
    }
    assert called == [((tmp_path, Path(sys.executable)), {"dry_run": True})]
    assert not (tmp_path / ".claude").exists() and not (tmp_path / ".codex").exists()


def test_legacy_cli_warns_and_forwards_without_native_callbacks(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(
        legacy.push_installer, "main", lambda argv: called.append(argv) or 0
    )
    assert legacy.main(["--dry-run"]) == 0
    assert called == [["--dry-run"]]
    assert "only Git pre-push" in capsys.readouterr().err
