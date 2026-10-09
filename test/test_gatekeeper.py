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


def test_check_gate_strict_counts_reliability_findings():
    results = {
        "danger": [],
        "reliability": [
            {"rule_id": "SKY-DEP003", "severity": "MEDIUM", "file": "k8s.yml"}
        ],
        "quality": [],
        "secrets": [],
    }

    passed, reasons = gk.check_gate(results, {}, strict=True)

    assert passed is False
    assert reasons == ["Strict mode: 1 issue found"]


def test_check_gate_strict_counts_unused_files():
    results = {
        "unused_files": [
            {"rule_id": "SKY-E003", "file": "src/unused.js", "line": 1}
        ]
    }

    passed, reasons = gk.check_gate(results, {}, strict=True)

    assert passed is False
    assert reasons == ["Strict mode: 1 issue found"]


def test_check_gate_strict_counts_circular_dependencies_but_not_advisory_quality():
    results = {
        "circular_dependencies": [
            {"rule_id": "SKY-CIRC", "cycle": ["pkg.left", "pkg.right"]},
            {"rule_id": "SKY-CIRC", "cycle": ["pkg.other", "pkg.last"]},
        ],
        "quality": [{"rule_id": "SKY-Q802", "advisory": True}],
    }

    passed, reasons = gk.check_gate(results, {}, strict=True)

    assert passed is False
    assert reasons == ["Strict mode: 2 issues found"]


def test_circular_dependencies_do_not_change_ordinary_gate_thresholds():
    results = {
        "circular_dependencies": [
            {"rule_id": "SKY-CIRC", "severity": "HIGH", "cycle": ["left", "right"]}
        ],
    }

    passed, reasons = gk.check_gate(
        results,
        {
            "gate": {
                "max_quality": 0,
                "max_high": 0,
                "max_security": 0,
                "max_dead_code": 0,
            }
        },
    )

    assert passed is True
    assert reasons == []


def test_reliability_does_not_affect_security_thresholds():
    results = {
        "danger": [],
        "reliability": [
            {"rule_id": "SKY-GPU001", "severity": "CRITICAL", "file": "Dockerfile"}
        ],
        "quality": [],
        "secrets": [],
    }
    config = {
        "gate": {
            "max_critical": 0,
            "max_high": 0,
            "max_security": 0,
            "max_reliability": 1,
        }
    }

    passed, reasons = gk.check_gate(results, config)

    assert passed is True
    assert reasons == []


def test_reliability_has_dedicated_gate_threshold():
    results = {
        "danger": [],
        "reliability": [
            {"rule_id": "SKY-GPU001", "severity": "HIGH", "file": "Dockerfile"}
        ],
        "quality": [],
        "secrets": [],
    }

    passed, reasons = gk.check_gate(
        results,
        {"gate": {"max_reliability": 0}},
    )

    assert passed is False
    assert reasons == ["1 reliability issue (max: 0)"]


def test_reliability_blocks_the_default_release_gate():
    results = {
        "danger": [],
        "reliability": [
            {"rule_id": "SKY-GPU001", "severity": "HIGH", "file": "Dockerfile"}
        ],
        "quality": [],
        "secrets": [],
    }

    passed, reasons = gk.check_gate(results, {})

    assert passed is False
    assert reasons == ["1 reliability issue (max: 0)"]


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


def test_check_gate_ai_defects_default_to_quality_threshold_for_compatibility():
    results = {
        "danger": [],
        "ai_defects": [{"rule_id": "SKY-L012", "file": "app.py", "line": 2}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_quality": 0}}

    passed, reasons = gk.check_gate(results, config)

    assert passed is False
    assert reasons == ["1 AI-defect issue (max: 0)"]


def test_check_gate_ai_defects_can_use_dedicated_threshold():
    results = {
        "danger": [],
        "ai_defects": [{"rule_id": "SKY-L012", "file": "app.py", "line": 2}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"max_quality": 0, "max_ai_defects": 1}}

    passed, reasons = gk.check_gate(results, config)

    assert passed is True
    assert reasons == []


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
        "1 critical security issue",
        "1 secret (max: 0)",
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
        "11 security issues (max: 10)",
        "11 quality issues (max: 10)",
        "1 secret (max: 0)",
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
    assert reasons == ["1 high severity issue (max: 0)"]


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


def test_check_gate_agent_matches_absolute_analyzer_paths(tmp_path, monkeypatch):
    import json

    from skylos.analyzer import analyze
    from skylos.reporting.provenance import ProvenanceReport

    source = tmp_path / "pkg" / "ai.py"
    source.parent.mkdir()
    source.write_text('eval("1+1")\n')
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    results = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert any(
        issue["file"] == str(source) and issue["severity"].lower() == "high"
        for issue in results.get("danger", [])
    ), results
    provenance = ProvenanceReport(
        agent_files=["pkg/ai.py"], scan_root=str(tmp_path)
    )

    passed, reasons = gk.check_gate(
        results, {"gate": {"agent": {"max_high": 0}}}, provenance=provenance
    )

    assert passed is False
    agent_reasons = [reason for reason in reasons if reason.startswith("Agent gate:")]
    assert agent_reasons
    assert any(
        issue["file"] == str(source)
        for reason in agent_reasons
        for issue in reason.issues
    )


def test_check_gate_agent_path_matching_uses_provenance_root(tmp_path, monkeypatch):
    from skylos.reporting.provenance import ProvenanceReport

    repo = tmp_path / "repo"
    repo.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    provenance = ProvenanceReport(agent_files=["pkg/ai.py"], scan_root=str(repo))
    local = {"file": str(repo / "pkg/ai.py"), "severity": "high"}
    outside = {"file": str(elsewhere / "pkg/ai.py"), "severity": "high"}
    sibling = {"file": str(repo / "other/ai.py"), "severity": "high"}

    passed, reasons = gk.check_gate(
        {"danger": [local, outside, sibling]},
        {"gate": {"agent": {"max_high": 0}}},
        provenance=provenance,
    )

    assert passed is False
    assert reasons == ["Agent gate: 1 high severity issue in AI-authored files (max: 0)"]
    assert reasons[0].issues == [local]


def test_synced_gate_policy_cannot_be_weakened_by_project_agent_limits(tmp_path):
    from skylos.config import load_config
    from skylos.reporting.provenance import ProvenanceReport

    synced = tmp_path / ".skylos"
    synced.mkdir()
    (synced / "config.yaml").write_text(
        "gate:\n  max_high: 0\n  agent:\n    max_high: 0\n"
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos.gate]\nmax_high = 99\n"
        "[tool.skylos.gate.agent]\nmax_high = 99\n"
    )
    config = load_config(tmp_path)
    issue = {"file": str(tmp_path / "ai.py"), "severity": "high"}

    passed, reasons = gk.check_gate(
        {"danger": [issue]},
        config,
        provenance=ProvenanceReport(agent_files=["ai.py"], scan_root=str(tmp_path)),
    )

    assert passed is False
    assert reasons == [
        "1 high severity issue (max: 0)",
        "Agent gate: 1 high severity issue in AI-authored files (max: 0)",
    ]


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


def test_check_gate_agent_ai_defects():
    results = {
        "danger": [],
        "ai_defects": [{"file": "ai.py", "rule_id": "SKY-L012"}],
        "quality": [],
        "secrets": [],
    }
    config = {"gate": {"agent": {"max_ai_defects": 0}}}
    prov = FakeProvenance(agent_files=["ai.py"])
    passed, reasons = gk.check_gate(results, config, provenance=prov)
    assert passed is False
    assert any("AI-defect" in r for r in reasons)


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
    assert reasons == ["1 critical security issue"]


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
        "2 critical security issues",
        "Agent gate: 1 critical issue in AI-authored files (max: 0)",
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
        "1 critical security issue",
        "1 high severity issue (max: 0)",
        "2 security issues (max: 0)",
    ]


def _workflow_finding(rule_id, line, severity="HIGH", file=".github/workflows/pr.yml"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "message": f"{rule_id} message",
    }


def _security_results(danger):
    return {
        "analysis_summary": {"grade_categories": ["security", "dead_code"]},
        "danger": danger,
    }


def _gate_output(capsys, **kwargs):
    rc = gk.run_gate_interaction(**kwargs)
    return rc, capsys.readouterr().out


def test_passed_gate_names_limits_and_high_issues_let_through(capsys):
    danger = [_workflow_finding(f"SKY-D29{i}", i + 1) for i in range(3)]

    rc, out = _gate_output(capsys, result=_security_results(danger), config={})

    assert rc == 0
    assert (
        "Quality Gate: PASSED: 0 critical (limit 0), 3 high (limit 5), "
        "3 security (limit 10)\n"
    ) in out
    assert (
        "3 high issues are allowed by the default limits. To block them, set "
        "max_high = 0 under [tool.skylos.gate] in pyproject.toml."
    ) in out


def test_passed_gate_hint_uses_singular_for_one_high_issue(capsys):
    rc, out = _gate_output(
        capsys,
        result=_security_results([_workflow_finding("SKY-D290", 2)]),
        config={},
    )

    assert rc == 0
    assert "1 high issue is allowed by the default limits. To block it," in out


def test_passed_gate_has_no_hint_without_high_issues(capsys):
    danger = [_workflow_finding("SKY-D313", 6, severity="LOW")]

    rc, out = _gate_output(capsys, result=_security_results(danger), config={})

    assert rc == 0
    assert "0 critical (limit 0), 0 high (limit 5), 1 security (limit 10)" in out
    assert "allowed by the default limits" not in out


def test_passed_gate_has_no_hint_when_max_high_is_configured(capsys):
    danger = [_workflow_finding("SKY-D290", 2)]

    rc, out = _gate_output(
        capsys,
        result=_security_results(danger),
        config={"gate": {"max_high": 3}},
    )

    assert rc == 0
    assert "1 high (limit 3)" in out
    assert "allowed by the default limits" not in out


def test_passed_gate_invalid_max_high_still_gets_default_hint(capsys):
    rc, out = _gate_output(
        capsys,
        result=_security_results([_workflow_finding("SKY-D290", 2)]),
        config={"gate": {"max_high": "0"}},
    )

    assert rc == 0
    assert "1 high (limit 5)" in out
    assert "allowed by the default limits" in out


def test_passed_gate_lists_other_categories_only_when_something_got_through(capsys):
    results = _security_results([])
    results["analysis_summary"]["grade_categories"].append("quality")
    results["quality"] = [{"rule_id": "SKY-Q301", "file": "a.py", "line": 1}]
    results["secrets"] = []

    rc, out = _gate_output(capsys, result=results, config={})

    assert rc == 0
    assert (
        "PASSED: 0 critical (limit 0), 0 high (limit 5), 0 security (limit 10), "
        "1 quality (limit 10)\n"
    ) in out
    assert "secrets" not in out


def test_passed_gate_says_when_security_was_not_scanned(capsys):
    results = {
        "analysis_summary": {"grade_categories": ["dead_code"]},
        "unused_functions": [{"name": "f", "file": "a.py", "line": 1}],
    }

    rc, out = _gate_output(capsys, result=results, config={})

    assert rc == 0
    assert "Quality Gate: PASSED: security not scanned (add -a)" in out
    assert "critical" not in out


def test_passed_gate_shows_gated_dead_code(capsys):
    results = {
        "analysis_summary": {"grade_categories": ["dead_code"]},
        "unused_functions": [{"name": "f", "file": "a.py", "line": 1}],
    }

    rc, out = _gate_output(
        capsys, result=results, config={"gate": {"max_dead_code": 2}}
    )

    assert rc == 0
    assert "PASSED: 1 dead code (limit 2), security not scanned (add -a)" in out


def test_passed_gate_strict_reports_zero_limits(capsys):
    rc, out = _gate_output(capsys, result=_security_results([]), config={}, strict=True)

    assert rc == 0
    assert "PASSED: 0 critical (limit 0), 0 high (limit 0), 0 security (limit 0)" in out


def test_passed_gate_falls_back_to_result_keys_without_grade_categories(capsys):
    rc, out = _gate_output(capsys, result={"danger": []}, config={})

    assert rc == 0
    assert (
        "PASSED: 0 critical (limit 0), 0 high (limit 5), 0 security (limit 10)" in out
    )


def test_failed_gate_lists_the_issues_behind_each_reason(capsys, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    danger = [
        _workflow_finding(
            "SKY-D290", 2, file=str(tmp_path / ".github/workflows/pr.yml")
        )
    ]

    rc, out = _gate_output(
        capsys,
        result=_security_results(danger),
        config={"gate": {"max_security": 0}},
        strict=False,
        force=True,
    )

    assert rc == 0
    assert "Quality Gate: FAILED\n   • 1 security issue (max: 0)\n" in out
    assert "       SKY-D290  .github/workflows/pr.yml:2  SKY-D290 message\n" in out
    assert str(tmp_path) not in out


def test_failed_gate_shows_ten_issues_then_how_many_more(capsys):
    danger = [_workflow_finding(f"SKY-D{i:03d}", i + 1) for i in range(12)]

    rc, out = _gate_output(
        capsys,
        result=_security_results(danger),
        config={"gate": {"max_high": 99}},
        force=True,
    )

    assert rc == 0
    assert "   • 12 security issues (max: 10)\n" in out
    assert "SKY-D009  .github/workflows/pr.yml:10" in out
    assert "SKY-D010" not in out
    assert "       and 2 more\n" in out


def test_advisory_gate_lists_issues(capsys):
    rc, out = _gate_output(
        capsys,
        result=_security_results([_workflow_finding("SKY-D290", 2)]),
        config={"gate": {"max_high": 0}},
        advisory=True,
    )

    assert rc == 0
    assert "   • 1 high severity issue (max: 0)\n" in out
    assert "SKY-D290  .github/workflows/pr.yml:2  SKY-D290 message" in out


def test_check_gate_reasons_carry_counted_issues():
    critical = _workflow_finding("SKY-D212", 7, severity="CRITICAL", file="app.py")
    high = _workflow_finding("SKY-D290", 2)
    secret = {"rule_id": "SKY-S101", "file": "app.py", "line": 3}

    passed, reasons = gk.check_gate(
        {"danger": [critical, high], "secrets": [secret]},
        {"gate": {"max_high": 0, "max_security": 0}},
    )

    assert passed is False
    assert reasons == [
        "1 critical security issue",
        "1 high severity issue (max: 0)",
        "2 security issues (max: 0)",
        "1 secret (max: 0)",
    ]
    assert [reason.issues for reason in reasons] == [
        [critical],
        [high],
        [critical, high],
        [secret],
    ]


def test_check_gate_reason_plurals():
    results = {
        "danger": [
            {"severity": "medium", "file": "a.py"},
            {"severity": "medium", "file": "b.py"},
        ],
        "secrets": [{"file": "a.py"}, {"file": "b.py"}],
        "dependency_vulnerabilities": [{"file": "requirements.txt"}] * 2,
        "unused_functions": [{"name": "f", "file": "a.py", "line": 1}],
    }

    passed, reasons = gk.check_gate(
        results, {"gate": {"max_security": 1, "max_dead_code": 0}}
    )

    assert passed is False
    assert reasons == [
        "2 security issues (max: 1)",
        "2 secrets (max: 0)",
        "2 dependency vulnerabilities (max: 0)",
        "1 dead code issue (max: 0)",
    ]


def test_check_gate_strict_reason_carries_every_issue():
    secret = {"rule_id": "SKY-S101", "file": "a.py", "line": 1}
    unused = {"name": "f", "type": "function", "file": "a.py", "line": 4}

    passed, reasons = gk.check_gate(
        {"secrets": [secret], "unused_functions": [unused]}, {}, strict=True
    )

    assert passed is False
    assert reasons == ["Strict mode: 2 issues found"]
    assert reasons[0].issues == [secret, unused]
    assert gk._issue_line(unused) == "a.py:4  unused function f"


def test_check_gate_agent_reason_carries_agent_issues():
    ai_issue = {"rule_id": "SKY-D201", "severity": "high", "file": "ai.py", "line": 3}
    results = {"danger": [ai_issue, {"severity": "high", "file": "human.py"}]}
    config = {"gate": {"agent": {"max_high": 0}}}

    passed, reasons = gk.check_gate(
        results, config, provenance=FakeProvenance(agent_files=["ai.py"])
    )

    assert passed is False
    assert reasons == [
        "Agent gate: 1 high severity issue in AI-authored files (max: 0)"
    ]
    assert reasons[0].issues == [ai_issue]


def test_check_gate_invalid_dependency_limit_uses_default():
    results = {"dependency_vulnerabilities": [{"file": "requirements.txt"}]}

    passed, reasons = gk.check_gate(
        results, {"gate": {"max_dependency_vulnerabilities": "99"}}
    )

    assert passed is False
    assert reasons == ["1 dependency vulnerability (max: 0)"]


def test_issue_line_shortens_long_messages():
    first = "Workflow-level permission contents: write is broad."
    issue = {
        "rule_id": "SKY-D291",
        "file": "w.yml",
        "line": 4,
        "message": first
        + " Prefer granting write access only on the job that needs it.",
    }
    long_issue = {"rule_id": "SKY-D290", "message": "word " * 40}

    assert gk._issue_line(issue) == f"SKY-D291  w.yml:4  {first}"
    shortened = gk._issue_line(long_issue)
    assert shortened.endswith("word…")
    assert len(shortened) <= len("SKY-D290  ") + gk.GATE_ISSUE_MESSAGE_CHARS


def test_summary_markdown_lists_issues_as_literal_code():
    reason = gk.GateReason(
        "1 security issue (max: 0)",
        [
            {
                "rule_id": "SKY-D290",
                "file": "[x](http://e)`.yml",
                "line": 2,
                "message": "m",
            }
        ],
    )

    md = gk.build_summary_markdown({}, False, [reason])

    assert "- 1 security issue (max: 0)\n  - `SKY-D290  [x](http://e)'.yml:2  m`" in md


def test_check_gate_custom_quality_threshold_carries_exact_finding():
    finding = {
        "rule_id": "CUSTOM-PAYMENTS-001",
        "file": "payments/api.py",
        "line": 17,
        "message": "Missing payment authorization",
    }

    passed, reasons = gk.check_gate(
        {"custom_rules": [finding]}, {"gate": {"max_quality": 0}}
    )

    assert passed is False
    assert reasons == ["1 quality issue (max: 0)"]
    assert reasons[0].issues == [finding]
    assert "CUSTOM-PAYMENTS-001  payments/api.py:17" in gk._issue_line(finding)


def test_check_gate_custom_quality_limit_does_not_double_count_shared_findings():
    finding = {"rule_id": "CUSTOM-1", "file": "api.py", "line": 3, "col": 4}
    results = {"quality": [finding], "custom_rules": [dict(finding), dict(finding)]}

    assert gk.check_gate(results, {"gate": {"max_quality": 1}}) == (True, [])
    passed, reasons = gk.check_gate(results, {}, strict=True)
    assert passed is False
    assert reasons == ["Strict mode: 1 issue found"]
    assert reasons[0].issues == [finding]
    assert "| Quality | 1 |" in gk.build_summary_markdown(results, passed, reasons)


def test_check_gate_distinct_custom_sinks_on_one_line_stay_separate():
    first = {"rule_id": "CUSTOM-1", "file": "api.py", "line": 3, "col": 4}
    second = {**first, "col": 24}

    passed, reasons = gk.check_gate(
        {"custom_rules": [first, second]}, {"gate": {"max_quality": 1}}
    )

    assert passed is False
    assert reasons == ["2 quality issues (max: 1)"]
    assert reasons[0].issues == [first, second]


def test_check_gate_strict_counts_custom_only_findings():
    finding = {"rule_id": "CUSTOM-1", "file": "api.py", "line": 3}

    passed, reasons = gk.check_gate({"custom_rules": [finding]}, {}, strict=True)

    assert passed is False
    assert reasons == ["Strict mode: 1 issue found"]
    assert reasons[0].issues == [finding]


def test_check_gate_custom_agent_quality_uses_absolute_path_and_provenance_root(
    tmp_path,
):
    from skylos.reporting.provenance import ProvenanceReport

    authored = {"rule_id": "CUSTOM-1", "file": str(tmp_path / "pkg/ai.py"), "line": 3}
    other = {**authored, "file": str(tmp_path / "other/ai.py")}
    results = {"custom_rules": [authored, other]}

    passed, reasons = gk.check_gate(
        results,
        {"gate": {"max_quality": 2, "agent": {"max_quality": 0}}},
        provenance=ProvenanceReport(agent_files=["pkg/ai.py"], scan_root=str(tmp_path)),
    )

    assert passed is False
    assert reasons == ["Agent gate: 1 quality issue in AI-authored files (max: 0)"]
    assert reasons[0].issues == [authored]


def test_check_gate_custom_findings_cannot_claim_builtin_advisory_exemption():
    finding = {"rule_id": "SKY-Q802", "file": "api.py", "advisory": True}
    results = {"quality": [finding], "custom_rules": [dict(finding)]}

    assert gk.check_gate(results, {"gate": {"max_quality": 0}})[0] is False
    passed, reasons = gk.check_gate(results, {}, strict=True)
    assert passed is False
    assert reasons == ["Strict mode: 1 issue found"]
    assert reasons[0].issues == [finding]


def test_summary_markdown_does_not_guess_status_from_default_thresholds():
    findings = [
        {"rule_id": "SKY-D201", "severity": "HIGH", "file": "api.py", "line": line}
        for line in (2, 3, 4)
    ]
    results = {"danger": findings}
    passed, reasons = gk.check_gate(results, {"gate": {"max_high": 2}})

    md = gk.build_summary_markdown(results, passed, reasons)

    assert "| Category | Count |" in md
    assert "| Security (high) | 3 |" in md
    assert "Status" not in md
    assert "| Security (high) | 3 | ✅ |" not in md
    assert "**Result: ❌ FAILED**" in md
    assert "3 high severity issues (max: 2)" in md
    assert "SKY-D201  api.py:4" in md
