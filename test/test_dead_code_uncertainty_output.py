import json
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from skylos import cli
from skylos.analyzer import analyze
from skylos.deadcode.evidence import build_dead_code_evidence
from skylos.ui import nudge
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results
from skylos.visitors.base import Definition


@pytest.mark.parametrize("marker", ["unresolved_receiver", "unresolved_callback"])
def test_retention_reference_is_uncertainty_not_static_use(tmp_path, marker):
    definition = Definition("app.handler", "function", tmp_path / "app.py", 1)
    definition.references = 1
    definition.heuristic_refs[marker] = 1.0

    ledger = build_dead_code_evidence({definition.name: definition})
    entry = ledger.to_dict(tmp_path)["symbols"][0]

    assert entry["classification"] == "uncertain"
    assert entry["decision"]["live_evidence_count"] == 0
    assert entry["decision"]["uncertainty_count"] == 1
    assert {event["kind"] for event in entry["evidence"]} == {"uncertainty"}
    assert entry["evidence"][0]["details"]["retention_reason"] == marker
    assert ledger.summary()["classifications"] == {"uncertain": 1}
    assert list(ledger.summary()["uncertainty_reasons"].values()) == [1]


def test_proven_use_remains_alive_with_uncertain_receiver(tmp_path):
    definition = Definition("app.handler", "function", tmp_path / "app.py", 1)
    definition.references = 1
    definition.heuristic_refs.update(
        {"unresolved_receiver": 1.0, "reachable_from_root": 1.0}
    )

    ledger = build_dead_code_evidence({definition.name: definition})
    entry = ledger.to_dict(tmp_path)["symbols"][0]

    assert entry["classification"] == "alive"
    assert entry["decision"]["live_evidence_count"] == 1
    assert entry["decision"]["uncertainty_count"] == 1
    assert "static_reference" not in {event["kind"] for event in entry["evidence"]}
    assert ledger.summary()["classifications"] == {"alive": 1}
    assert "uncertainty_reasons" not in ledger.summary()


def test_real_static_reference_remains_alive(tmp_path):
    definition = Definition("app.handler", "function", tmp_path / "app.py", 1)
    definition.references = 1

    ledger = build_dead_code_evidence({definition.name: definition})
    entry = ledger.to_dict(tmp_path)["symbols"][0]

    assert entry["classification"] == "alive"
    assert entry["decision"]["uncertainty_count"] == 0
    assert {event["kind"] for event in entry["evidence"]} == {"static_reference"}


@pytest.fixture
def retained_receiver_result(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="receiver-evidence-example"\nversion="0.0.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "class Worker:\n"
        "    def dispatch(self):\n"
        "        external(self)\n"
        "    def handle_refund(self):\n"
        "        return 1\n"
        "    def directly_used(self):\n"
        "        return 2\n"
        "Worker().dispatch()\n"
        "Worker().directly_used()\n",
        encoding="utf-8",
    )
    return json.loads(analyze(str(tmp_path), grep_verify=False, trace_file=False))


def test_retained_receiver_json_reports_uncertainty_and_known_use(
    retained_receiver_result,
):
    result = retained_receiver_result
    entries = {
        entry["qualified_name"]: entry
        for entry in result["dead_code_evidence"]["symbols"]
    }

    assert result["unused_functions"] == []
    assert entries["app.Worker.handle_refund"]["classification"] == "uncertain"
    assert entries["app.Worker.directly_used"]["classification"] == "alive"
    evidence = result["analysis_summary"]["dead_code_evidence"]
    assert evidence["classifications"]["uncertain"] == 1
    assert evidence["uncertainty_reasons"] == {
        "Unresolved receiver may expose this symbol": 1
    }


def test_zero_findings_report_and_badge_disclose_uncertainty(
    retained_receiver_result,
):
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        width=160,
        theme=cli._skylos_console_theme(),
    )
    render_results(console, retained_receiver_result, copy_badge=False)
    logger = Mock(console=console)
    cli.print_badge(0, logger, uncertainty_count=1)

    rendered = " ".join(output.getvalue().split())
    assert "No dead-code candidates found at current settings." in rendered
    assert "Usage remains uncertain for 1 symbol." in rendered
    assert "Unresolved receiver may expose this symbol" in rendered
    assert "0_candidates%2C_1_uncertain-yellow" in rendered
    assert "100% dead-code free" not in rendered
    assert "Dead Code Free" not in rendered
    assert "Dead_Code-Free" not in rendered


@pytest.mark.parametrize("is_tty", [False, True])
def test_public_cli_passes_full_uncertainty_to_closing_summary(
    monkeypatch, retained_receiver_result, capsys, is_tty
):
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", ".", "--no-upload", "--no-clipboard"]
    )
    monkeypatch.setattr(
        cli, "run_analyze", lambda *a, **kw: json.dumps(retained_receiver_result)
    )
    monkeypatch.setattr(cli, "load_config", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "_is_tty", lambda: is_tty)

    cli.main()

    rendered = " ".join(capsys.readouterr().out.split())
    assert "No dead-code candidates found at current settings." in rendered
    assert "Usage remains uncertain for 1 symbol." in rendered
    assert "Unresolved receiver may expose this symbol" in rendered
    assert "100% dead-code free" not in rendered
    assert "Clean codebase" not in rendered


def test_pretty_report_discloses_retained_uncertainty(retained_receiver_result):
    output = StringIO()
    render_pretty_results(Console(file=output, width=160), retained_receiver_result)

    rendered = " ".join(output.getvalue().split())
    assert "Usage remains uncertain for 1 symbol." in rendered
    assert "Unresolved receiver may expose this symbol" in rendered
    assert "No findings to display" in rendered


def test_zero_result_nudge_describes_scan_not_clean_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(nudge, "_is_ci", lambda: False)
    args = SimpleNamespace(all_checks=True, danger=True, secrets=True, quality=True)
    assert "No findings at current settings" in nudge.pick_nudge({}, args, tmp_path)
    uncertain = {
        "analysis_summary": {
            "dead_code_evidence": {"classifications": {"uncertain": 1}}
        }
    }
    picked = nudge.pick_nudge(uncertain, args, tmp_path)
    assert "uncertain usage" in picked
    assert "Clean codebase" not in picked
    assert "skylos badge" not in picked
