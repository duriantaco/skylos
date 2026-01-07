import subprocess
from subprocess import CalledProcessError
import skylos.gatekeeper as gk


class DummyCompleted:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.stderr = ""


def _silence_console(monkeypatch):
    monkeypatch.setattr(gk.console, "print", lambda *a, **k: None)


def test_run_cmd_success(monkeypatch):
    _silence_console(monkeypatch)

    def fake_run(cmd_list, check, capture_output, text):
        assert check is True
        assert capture_output is True
        assert text is True
        return DummyCompleted(stdout=" ok \n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert gk.run_cmd(["git", "status"]) == "ok"


def test_run_cmd_failure_returns_none(monkeypatch):
    _silence_console(monkeypatch)

    def fake_run(*args, **kwargs):
        raise CalledProcessError(1, ["git"], stderr="bad")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert gk.run_cmd(["git", "status"]) is None


def test_get_git_status_empty_when_run_cmd_none(monkeypatch):
    monkeypatch.setattr(gk, "run_cmd", lambda *a, **k: None)
    assert gk.get_git_status() == []


def test_get_git_status_parses_porcelain(monkeypatch):
    monkeypatch.setattr(
        gk,
        "run_cmd",
        lambda *a, **k: " M a.py\n?? new.txt\nA  dir/x.py\n",
    )
    assert gk.get_git_status() == ["a.py", "new.txt", "dir/x.py"]


def test_run_push_success(monkeypatch):
    _silence_console(monkeypatch)
    calls = []

    def fake_run(cmd, check):
        calls.append(cmd)
        return DummyCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    gk.run_push()
    assert calls == [["git", "push"]]


def test_run_push_failure(monkeypatch):
    _silence_console(monkeypatch)

    def fake_run(cmd, check):
        raise CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "run", fake_run)
    gk.run_push()


def test_check_gate_reasons(monkeypatch):
    results = {
        "danger": [{"severity": "CRITICAL"}, {"severity": "LOW"}],
        "secrets": [{"x": 1}],
        "quality": [1, 2, 3],
    }
    config = {
        "gate": {
            "fail_on_critical": True,
            "max_security": 0,
            "max_quality": 2,
        }
    }

    passed, reasons = gk.check_gate(results, config)
    assert passed is False
    assert any("CRITICAL" in r for r in reasons)
    assert any("Secrets" in r for r in reasons)
    assert any("Security issues" in r for r in reasons)
    assert any("Quality issues" in r for r in reasons)


def test_run_gate_interaction_passed_runs_command(monkeypatch):
    _silence_console(monkeypatch)
    monkeypatch.setattr(gk, "check_gate", lambda results, config: (True, []))

    ran = {"cmd": None}

    def fake_run(cmd):
        ran["cmd"] = cmd
        return 0

    monkeypatch.setattr(subprocess, "run", fake_run)

    rc = gk.run_gate_interaction(results={}, config={}, command_to_run=["echo", "hi"])
    assert rc == 0
    assert ran["cmd"] == ["echo", "hi"]


def test_run_gate_interaction_failed_strict(monkeypatch):
    _silence_console(monkeypatch)
    monkeypatch.setattr(gk, "check_gate", lambda results, config: (False, ["nope"]))

    rc = gk.run_gate_interaction(
        results={},
        config={"gate": {"strict": True}},
        command_to_run=None,
    )
    assert rc == 1


def test_run_gate_interaction_failed_can_bypass(monkeypatch):
    _silence_console(monkeypatch)
    monkeypatch.setattr(gk, "check_gate", lambda results, config: (False, ["nope"]))

    monkeypatch.setattr(gk.sys.stdout, "isatty", lambda: True)

    monkeypatch.setattr(gk.Confirm, "ask", lambda *a, **k: True)

    called = {"wizard": 0}
    monkeypatch.setattr(
        gk,
        "start_deployment_wizard",
        lambda: called.__setitem__("wizard", called["wizard"] + 1),
    )

    rc = gk.run_gate_interaction(
        results={}, config={"gate": {"strict": False}}, command_to_run=None
    )
    assert rc == 0
    assert called["wizard"] == 1
