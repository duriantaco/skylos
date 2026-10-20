import copy
import hashlib
import json
from io import StringIO

import pytest
from rich.console import Console

from skylos.commands.security_explain import run_explain_command
from skylos.security.trace_report import (
    load_security_findings,
    recorded_trace,
    select_findings,
    source_context,
)
from skylos.ui.security_trace import follow_trace, show_trace


def finding():
    return {
        "rule_id": "SKY-D211",
        "file": "db.py",
        "line": 4,
        "severity": "CRITICAL",
        "message": "Possible SQL injection",
        "metadata": {
            "security_trace": {
                "version": 1,
                "trace_id": "example",
                "status": "partial",
                "receiver": {"status": "unknown"},
                "steps": [
                    {
                        "id": "s",
                        "kind": "source",
                        "message": "request value",
                        "file": "app.py",
                        "line": 8,
                    },
                    {
                        "id": "c",
                        "kind": "call",
                        "message": "argument passed to helper",
                        "file": "app.py",
                        "line": 9,
                    },
                    {
                        "id": "e",
                        "kind": "sink",
                        "message": "SQL execution",
                        "file": "db.py",
                        "line": 4,
                    },
                ],
                "limitations": ["Receiver is unresolved"],
            }
        },
    }


def test_explain_saved_report_filters_and_prints_recorded_locations(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"danger": [finding()]}), encoding="utf-8")
    before = report.read_bytes()
    output = StringIO()
    code = run_explain_command(
        [str(report), "--rule", "SKY-D211", "--file", "db.py", "--line", "4"],
        console_factory=lambda: Console(file=output, width=200),
    )
    assert code == 0
    text = output.getvalue()
    assert "app.py:8" in text and "db.py:4" in text
    assert "Receiver: unknown" in text
    assert "Runtime behavior was not executed or verified" in text
    assert "Unresolved: Receiver is unresolved" in text
    assert report.read_bytes() == before


def test_json_explain_preserves_the_original_proof(tmp_path, capsys):
    report = tmp_path / "report.json"
    row = finding()
    report.write_text(json.dumps({"danger": [row]}), encoding="utf-8")
    assert run_explain_command([str(report), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding"] == row
    assert payload["trace"] == row["metadata"]["security_trace"]


def test_viewer_does_not_invent_a_trace_for_old_reports():
    row = {"rule_id": "SKY-D324", "file": "x.py", "line": 7}
    trace = recorded_trace(row)
    assert trace["status"] == "unknown" and trace["steps"] == []
    assert "no call chain was inferred" in trace["limitations"][0]


def test_report_reader_rejects_malformed_and_symlink_inputs(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("[not json", encoding="utf-8")
    with pytest.raises(ValueError, match="valid JSON"):
        load_security_findings(report)
    link = tmp_path / "link.json"
    link.symlink_to(report)
    with pytest.raises(ValueError, match="regular"):
        load_security_findings(link)


def test_selection_is_exact_by_rule_path_boundary_and_line():
    row = finding()
    row["file"] = "/repo/src/db.py"
    assert select_findings([row], rule="sky-d211", file="src/db.py", line=4) == [row]
    assert select_findings([row], file="b.py") == []
    assert select_findings([row], rule="SKY-D21") == []
    assert select_findings([row], line=5) == []


def test_trace_navigation_follows_calls_back_and_selects_a_step():
    trace = finding()["metadata"]["security_trace"]
    before = copy.deepcopy(trace)
    output = StringIO()
    commands = iter(["next", "next", "back", "step 1", "callers", "step 99", "quit"])
    follow_trace(
        Console(file=output, width=200),
        trace,
        read_command=lambda prompt: next(commands),
    )
    text = output.getvalue()
    assert "[2/3] call app.py:9" in text
    assert "[3/3] sink db.py:4" in text
    assert "Choose a recorded step number" in text
    assert trace == before


def test_navigation_requires_explicit_choice_at_a_recorded_branch():
    trace = finding()["metadata"]["security_trace"]
    trace["edges"] = [
        {"from": "s", "to": "c", "kind": "argument"},
        {"from": "s", "to": "e", "kind": "data"},
    ]
    output = StringIO()
    commands = iter(["next", "step 3", "parents", "back", "quit"])
    follow_trace(
        Console(file=output, width=200),
        trace,
        read_command=lambda prompt: next(commands),
    )
    text = output.getvalue()
    assert "Multiple recorded branches" in text
    assert text.count("[1/3] source app.py:8") == 3


def test_source_view_requires_an_explicit_root_and_matching_digest(tmp_path):
    source = tmp_path / "app.py"
    text = "value = 1\nanswer = value + 1\n"
    source.write_text(text, encoding="utf-8")
    step = {
        "file": "app.py",
        "line": 2,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    with pytest.raises(ValueError, match="explicit --root"):
        source_context({}, step, None)
    assert "> 2: answer = value + 1" in source_context({}, step, tmp_path)
    source.write_text("answer = 99\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Source changed"):
        source_context({}, step, tmp_path)


def test_source_view_rejects_outside_and_symlinked_directory(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("value = 1\n", encoding="utf-8")
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="outside"):
        source_context(
            {}, {"file": "../outside.py", "line": 1, "source_sha256": digest}, root
        )
    link = root / "linked"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        source_context(
            {}, {"file": "linked/outside.py", "line": 1, "source_sha256": digest}, root
        )


def test_source_view_does_not_leak_embedded_credentials_or_terminal_controls(tmp_path):
    source = tmp_path / "app.py"
    key = "sk_" + "live_" + "123456" * 4
    text = "api_key = '" + key + "'\n# \x1b[31m control\n"
    source.write_text(text, encoding="utf-8")
    step = {
        "file": "app.py",
        "line": 1,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    output = "\n".join(source_context({}, step, tmp_path))
    assert key not in output
    assert "\x1b" not in output


def test_explain_help_never_opens_the_report(monkeypatch):
    def no_read(*args, **kwargs):
        pytest.fail("help must not read any report")

    monkeypatch.setattr(
        "skylos.commands.security_explain.load_security_findings", no_read
    )
    with pytest.raises(SystemExit) as error:
        run_explain_command(["--help"])
    assert error.value.code == 0


def test_large_trace_is_explicitly_bounded_without_mutating_report():
    row = finding()
    row["metadata"]["security_trace"]["steps"] *= 100
    before = copy.deepcopy(row)
    trace = recorded_trace(row)
    assert len(trace["steps"]) == 256
    assert trace["status"] == "partial"
    assert "Viewer limited" in trace["limitations"][-1]
    assert row == before


def test_trace_display_neutralizes_untrusted_location_controls():
    row = finding()
    row["line"] = "\x1b[2J4"
    output = StringIO()
    show_trace(Console(file=output, width=200), row, recorded_trace(row))
    assert "\x1b" not in output.getvalue()


def test_source_view_keeps_indentation_after_redaction(tmp_path):
    source = tmp_path / "app.py"
    text = "def example():\n    return 42\n"
    source.write_text(text, encoding="utf-8")
    step = {
        "file": "app.py",
        "line": 2,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    assert "> 2:     return 42" in source_context({}, step, tmp_path)
