import subprocess
from subprocess import CalledProcessError
import skylos.core.gatekeeper as gk


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


def test_run_gate_interaction_legacy_typeerror_fallback(monkeypatch):
    _silence_console(monkeypatch)

    calls = []

    def fake_check_gate(results, config):
        calls.append((results, config))
        return True, []

    monkeypatch.setattr(gk, "check_gate", fake_check_gate)

    rc = gk.run_gate_interaction(results={}, config={}, provenance=object())

    assert rc == 0
    assert calls == [({}, {})]


def test_run_gate_interaction_relaxed_config_does_not_run_command(monkeypatch):
    result = {
        "danger": [{"severity": "critical", "file": "app.py"}],
        "quality": [],
        "secrets": [],
    }
    calls = []

    monkeypatch.setattr(gk.subprocess, "run", lambda command: calls.append(command))

    rc = gk.run_gate_interaction(
        result=result,
        config={"gate": {"fail_on_critical": False, "max_critical": 999}},
        command_to_run=["deploy"],
    )

    assert rc == 1
    assert calls == []


class FakeProvenance:
    def __init__(self, agent_files):
        self.agent_files = agent_files


def test_check_gate_no_provenance_backward_compat():
    results = {"danger": [], "quality": [], "secrets": []}
    config = {"gate": {"max_critical": 0, "max_high": 5}}
    passed, reasons = gk.check_gate(results, config)
    assert passed is True
    assert reasons == []


def test_check_gate_provenance_none_ignores_agent():
    results = {
        "danger": [{"severity": "high", "file": "ai_file.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_high": 5, "agent": {"max_high": 0}}}
    passed, reasons = gk.check_gate(results, config, provenance=None)
    assert passed is True


def test_check_gate_strict_ignores_advisory_iad_quality():
    results = {
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q802",
                "advisory": True,
                "file": "pkg/helpers.py",
                "line": 1,
            },
            {
                "rule_id": "SKY-Q803",
                "advisory": True,
                "file": "pkg/helpers.py",
                "line": 1,
            },
        ],
        "secrets": [],
    }

    passed, reasons = gk.check_gate(results, {}, strict=True)

    assert passed is True
    assert reasons == []


def test_check_gate_strict_blocks_enforced_iad_quality():
    results = {
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q802",
                "advisory": False,
                "file": "pkg/helpers.py",
                "line": 1,
            }
        ],
        "secrets": [],
    }

    passed, reasons = gk.check_gate(results, {}, strict=True)

    assert passed is False
    assert "Strict mode" in reasons[0]


def test_check_gate_quality_threshold_ignores_advisory_iad_quality():
    results = {
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q803",
                "advisory": True,
                "file": "pkg/helpers.py",
                "line": 1,
            }
        ],
        "secrets": [],
    }
    config = {"gate": {"max_quality": 0}}

    passed, reasons = gk.check_gate(results, config)

    assert passed is True
    assert reasons == []


def test_check_gate_ai_defects_count_against_quality_threshold():
    results = {
        "danger": [],
        "ai_defects": [{"rule_id": "SKY-L012", "file": "app.py", "line": 2}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_quality": 0}}

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert any("quality" in reason for reason in reasons)


def test_check_gate_project_config_cannot_relax_critical_or_secrets():
    danger = [{"severity": "critical", "file": "app.py"}]
    for index in range(10):
        danger.append({"severity": "medium", "file": f"app_{index}.py"})

    quality = []
    for index in range(11):
        quality.append({"rule_id": f"SKY-Q{index}", "file": "app.py"})

    results = {
        "danger": danger,
        "quality": quality,
        "secrets": [{"rule_id": "SKY-S101", "file": "app.py"}],
    }
    config = {
        "gate": {
            "fail_on_critical": False,
            "max_critical": 999,
            "max_high": 999,
            "max_security": 999,
            "max_quality": 999,
            "max_secrets": 999,
        }
    }

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert reasons == [
        "1 critical security issue(s)",
        "1 secrets issues (max: 0)",
    ]


def test_check_gate_project_config_can_relax_non_critical_thresholds():
    danger = []
    for index in range(6):
        danger.append({"severity": "high", "file": f"app_{index}.py"})

    quality = []
    for index in range(11):
        quality.append({"rule_id": f"SKY-Q{index}", "file": "app.py"})

    results = {
        "danger": danger,
        "quality": quality,
        "secrets": [],
    }
    config = {
        "gate": {
            "max_high": 999,
            "max_security": 999,
            "max_quality": 999,
        }
    }

    passed, reasons = gk.check_gate(results, config)

    assert passed is True
    assert reasons == []


def test_check_gate_invalid_project_threshold_types_use_defaults():
    danger = []
    for index in range(11):
        danger.append({"severity": "medium", "file": f"app_{index}.py"})

    quality = []
    for index in range(11):
        quality.append({"rule_id": f"SKY-Q{index}", "file": "app.py"})

    results = {
        "danger": danger,
        "quality": quality,
        "secrets": [{"rule_id": "SKY-S101", "file": "app.py"}],
    }
    config = {
        "gate": {
            "max_security": "999",
            "max_quality": True,
            "max_secrets": "999",
        }
    }

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert reasons == [
        "11 total security issues (max: 10)",
        "11 quality issues (max: 10)",
        "1 secrets issues (max: 0)",
    ]


def test_check_gate_project_config_can_make_thresholds_stricter():
    results = {
        "danger": [{"severity": "high", "file": "app.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_high": 0}}

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert reasons == ["1 high severity issues (max: 0)"]


def test_check_gate_agent_stricter_threshold():
    results = {
        "danger": [{"severity": "high", "file": "ai_file.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "max_high": 5,
            "agent": {"max_high": 0},
        }
    }
    prov = FakeProvenance(agent_files=["ai_file.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("Agent gate" in r and "high" in r for r in reasons)


def test_check_gate_agent_critical():
    results = {
        "danger": [{"severity": "critical", "file": "bot.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "fail_on_critical": False,
            "max_critical": 5,
            "agent": {"max_critical": 0},
        }
    }
    prov = FakeProvenance(agent_files=["bot.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("Agent gate" in r and "critical" in r for r in reasons)


def test_check_gate_agent_human_file_not_affected():
    results = {
        "danger": [{"severity": "high", "file": "human_file.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "max_high": 5,
            "agent": {"max_high": 0},
        }
    }
    prov = FakeProvenance(agent_files=["ai_file.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is True


def test_check_gate_agent_security_threshold():
    results = {
        "danger": [
            {"severity": "medium", "file": "ai.py"},
            {"severity": "low", "file": "ai.py"},
        ],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"agent": {"max_security": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("security" in r for r in reasons)


def test_check_gate_agent_quality():
    results = {
        "danger": [],
        "quality": [{"file": "ai.py", "rule": "complexity"}],
        "secrets": [],
    }
    config = {"gate": {"agent": {"max_quality": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("quality" in r for r in reasons)


def test_check_gate_agent_secrets():
    results = {
        "danger": [],
        "quality": [],
        "secrets": [{"file": "ai.py", "rule": "api_key"}],
    }
    config = {"gate": {"agent": {"max_secrets": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("secret" in r for r in reasons)


def test_check_gate_agent_dead_code():
    results = {
        "danger": [],
        "quality": [],
        "secrets": [],
        "unused_functions": [{"file": "ai.py", "name": "old_fn"}],
    }
    config = {"gate": {"agent": {"max_dead_code": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("dead code" in r for r in reasons)


def test_check_gate_agent_require_defend():
    results = {"danger": [], "quality": [], "secrets": []}
    config = {"gate": {"agent": {"require_defend": True}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("require_defend" in r or "defend" in r.lower() for r in reasons)


def test_check_gate_agent_no_agent_config_skips():
    results = {
        "danger": [{"severity": "critical", "file": "ai.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"fail_on_critical": False, "max_critical": 10}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert reasons == ["1 critical security issue(s)"]


def test_check_gate_agent_no_agent_files_skips():
    results = {
        "danger": [{"severity": "high", "file": "human.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_high": 5, "agent": {"max_high": 0}}}
    prov = FakeProvenance(agent_files=[])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is True


def test_check_gate_agent_file_path_key():
    results = {
        "danger": [{"severity": "high", "file_path": "ai.py"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_high": 5, "agent": {"max_high": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False


def test_check_gate_both_gates_can_fail():
    results = {
        "danger": [
            {"severity": "critical", "file": "ai.py"},
            {"severity": "critical", "file": "human.py"},
        ],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "max_critical": 0,
            "agent": {"max_critical": 0},
        }
    }
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert reasons == [
        "2 critical security issue(s)",
        "Agent gate: 1 critical issue(s) in AI-authored files (max: 0)",
    ]


def test_check_gate_fail_on_critical_skips_max_critical_reason():
    results = {
        "danger": [
            {"severity": "critical", "file": "app.py"},
            {"severity": "high", "file": "app.py"},
        ],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "fail_on_critical": True,
            "max_critical": 0,
            "max_high": 0,
            "max_security": 0,
        }
    }

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert reasons == [
        "1 critical security issue(s)",
        "1 high severity issues (max: 0)",
        "2 total security issues (max: 0)",
    ]
