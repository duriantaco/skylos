import importlib.util
import json
from io import StringIO

import pytest
from rich.console import Console

from skylos.commands import doctor_cmd


@pytest.fixture
def doctor_runtime(monkeypatch):
    monkeypatch.setattr(doctor_cmd, "_dart_available", lambda: True)
    monkeypatch.setattr(doctor_cmd, "_interactive_available", lambda: True)
    monkeypatch.setattr(doctor_cmd, "_ripgrep_available", lambda: True)
    monkeypatch.setattr(doctor_cmd, "_rust_available", lambda: True)
    monkeypatch.setattr(
        doctor_cmd, "_go_engine_status", lambda: {"status": "available"}
    )
    monkeypatch.setattr(
        doctor_cmd,
        "_agent_hooks_report",
        lambda: {"status": "not_installed", "clients": {}},
    )


def _litellm_installed(monkeypatch, installed):
    real_find_spec = importlib.util.find_spec

    def find_spec(name, *args, **kwargs):
        if name == "litellm":
            if installed:
                return object()
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)


def _doctor_text(monkeypatch):
    output = StringIO()
    console = Console(file=output, width=240, color_system=None)
    monkeypatch.setattr(doctor_cmd, "Console", lambda: console)
    monkeypatch.setattr(doctor_cmd, "_print_cloud_status", lambda console: None)
    monkeypatch.setattr(doctor_cmd, "_print_local_status", lambda console: None)
    assert doctor_cmd.run_doctor_command() == 0
    return output.getvalue()


def test_doctor_text_without_litellm_says_llm_support_is_not_installed(
    doctor_runtime, monkeypatch
):
    _litellm_installed(monkeypatch, False)

    printed = _doctor_text(monkeypatch)

    assert "LLM support available" not in printed
    assert "LLM support installed" not in printed
    assert (
        'LLM support not installed (optional, for skylos agent: pip install "skylos[llm]")'
        in printed
    )


def test_doctor_text_with_litellm_says_llm_support_is_installed(
    doctor_runtime, monkeypatch
):
    _litellm_installed(monkeypatch, True)

    printed = _doctor_text(monkeypatch)

    assert "OK  LLM support installed" in printed
    assert "not installed (optional, for skylos agent" not in printed


@pytest.mark.parametrize("installed", [False, True])
def test_doctor_json_reports_the_llm_extra(
    doctor_runtime, monkeypatch, capsys, installed
):
    _litellm_installed(monkeypatch, installed)

    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    if installed:
        assert report["checks"]["llm_support"] == {"status": "available"}
    else:
        assert report["checks"]["llm_support"] == {
            "status": "unavailable",
            "install": 'pip install "skylos[llm]"',
        }


def test_doctor_does_not_count_the_analyzer_module_as_llm_support(monkeypatch):
    _litellm_installed(monkeypatch, False)

    import skylos.llm.analyzer  # noqa: F401

    assert doctor_cmd._llm_available() is False
