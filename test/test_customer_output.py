import copy
import re
from io import StringIO
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from skylos import cli
from skylos.core.gatekeeper import build_summary_markdown, check_gate
from skylos.core.suite import _static_summary, format_suite_table
from skylos.reporting.assessment_display import closing_summary
from skylos.reporting.report_page import render_report
from skylos.reporting.top_risks import add_report_guidance, top_risks
from skylos.rules.guidance import finding_fix, rule_docs_url
from skylos.ui.rich_report import render_results

LISTED = {"version": 1, "listed": True, "reason": "finding"}
HIDDEN_ADVICE = {"version": 1, "listed": False, "reason": "measurement"}
LOW_RISK = {"version": 1, "listed": False, "reason": "low-risk-context"}


def _danger(rule, severity, file, line, **extra):
    return {
        "rule_id": rule,
        "severity": severity,
        "file": file,
        "line": line,
        "message": f"{rule} message",
        "listing": dict(LISTED),
        **extra,
    }


def _result(**overrides):
    result = {
        "danger": [
            _danger("SKY-D218", "MEDIUM", "app/net.py", 3),
            _danger("SKY-D202", "HIGH", "tests/test_exec.py", 10),
            _danger("SKY-D202", "HIGH", "tests/test_exec.py", 20),
            _danger("SKY-D216", "HIGH", "app/fetch.py", 7, confidence=40),
            _danger("SKY-D215", "HIGH", "app/files.py", 5),
            _danger("SKY-D231", "HIGH", "app/main.py", 9, confidence=90),
            _danger("SKY-D212", "CRITICAL", "scripts/run.sh", 4),
            _danger(
                "SKY-D209",
                "HIGH",
                "app/tool.py",
                2,
                listing=dict(LOW_RISK),
                low_risk_context={"reason": "constant-shell-command"},
            ),
        ],
        "ai_defects": [
            {
                "rule_id": "SKY-D223",
                "severity": "MEDIUM",
                "file": f"app/m{index}.py",
                "line": 1,
                "symbol": "cv2",
                "message": "Undeclared import 'cv2' (provided by: opencv-python).",
                "listing": dict(LISTED),
            }
            for index in range(3)
        ],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "HIGH",
                "file": "app/big.py",
                "line": 1,
                "name": "big",
                "value": 40,
                "threshold": 10,
                "kind": "complexity",
                "message": "Cyclomatic complexity is 40 (threshold: 10).",
                "listing": dict(LISTED),
            },
            {
                "rule_id": "SKY-L027",
                "severity": "LOW",
                "file": "app/big.py",
                "line": 2,
                "message": "String literal repeated",
                "listing": dict(HIDDEN_ADVICE),
            },
        ],
        "secrets": [],
        "dependency_vulnerabilities": [],
        "unused_functions": [
            {"name": "old", "file": "app/old.py", "line": 1, "confidence": 90}
        ],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "unused_files": [],
        "suppressed": [],
        "listing_policy_version": 1,
        "advice_visibility": {"omitted_checks": 1},
        "analysis_summary": {
            "total_files": 9,
            "grade_categories": [
                "security",
                "quality",
                "ai_defects",
                "dead_code",
                "dependencies",
                "secrets",
            ],
            "sca_coverage": {"queried_dependency_count": 0},
        },
    }
    result.update(overrides)
    return result


def _rich(result, tmp_path, width=120):
    buffer = StringIO()
    console = Console(
        file=buffer, width=width, color_system=None, theme=cli._skylos_console_theme()
    )
    render_results(console, result, root_path=tmp_path, copy_badge=False, config={})
    return buffer.getvalue()


def test_top_risks_put_blocking_first_then_severity_then_production_then_confidence(
    tmp_path,
):
    rows = top_risks(_result(), project_root=tmp_path, config={}, limit=10)

    order = [(row.rule_id, row.file, row.blocking, row.in_tests) for row in rows]
    assert order[0] == ("SKY-D212", "scripts/run.sh", True, False)
    assert [row.rule_id for row in rows[1:5]] == [
        "SKY-D231",
        "SKY-D215",
        "SKY-D216",
        "SKY-D202",
    ]
    assert rows[4].in_tests is True and rows[4].more == 1
    assert rows.index(next(row for row in rows if row.rule_id == "SKY-D218")) > 4
    assert "SKY-D209" not in {row.rule_id for row in rows}
    assert "SKY-Q301" not in {row.rule_id for row in rows}


def test_a_hidden_finding_that_fails_the_gate_is_still_a_top_risk(tmp_path):
    result = _result()
    result["danger"].append(
        _danger(
            "SKY-D203",
            "CRITICAL",
            "app/ops.py",
            8,
            listing=dict(LOW_RISK),
            low_risk_context={"reason": "constant-shell-command"},
        )
    )

    rows = top_risks(result, project_root=tmp_path, config={})

    assert [(row.rule_id, row.blocking) for row in rows[:2]] == [
        ("SKY-D203", True),
        ("SKY-D212", True),
    ]


def test_one_total_in_the_closing_line_gate_summary_suite_report_and_terminal(
    tmp_path,
):
    result = _result()
    before = copy.deepcopy(result)
    passed, reasons = check_gate(result, {})

    closing = closing_summary(result)
    total = int(re.match(r"Found (\d+) issues", closing).group(1))
    markdown = build_summary_markdown(result, passed, reasons)
    suite = _static_summary(result)
    terminal = _rich(result, tmp_path)
    report = render_report(result, "md", project_root=tmp_path, config={})

    assert total == 12
    assert f"| **Total issues** | **{total}** |" in markdown
    assert "| Quality | 1 |" in markdown
    assert "Not counted: 1 advice finding hidden by default" in markdown
    assert "The gate also counts 1 finding hidden from the list" in markdown
    assert suite["total"] == total and suite["quality"] == 1
    assert (
        f"{total} issues: security 7, AI defects 3, quality 1, dead code 1" in terminal
    )
    assert f"| **Total** | **{total}** |" in report
    assert result == before


def test_a_check_that_did_not_run_is_not_checked_never_zero(tmp_path):
    result = _result()
    passed, reasons = check_gate(result, {})
    report = {"summary": {"static": _static_summary(result)}}

    assert "| Dependency vulnerabilities | not checked |" in build_summary_markdown(
        result, passed, reasons
    )
    assert "Dependencies: not checked" in format_suite_table(report)
    assert "Not checked: dependencies" in _rich(result, tmp_path)

    dead_code_only = _result(
        danger=[],
        ai_defects=[],
        quality=[],
        analysis_summary={"total_files": 1, "grade_categories": ["dead_code"]},
    )
    markdown = build_summary_markdown(dead_code_only, True, [])
    assert "| Security (total) | not checked |" in markdown
    assert "| Dead Code | 1 |" in markdown

    queried = _result()
    queried["analysis_summary"]["sca_coverage"] = {"queried_dependency_count": 4}
    assert "| Dependency vulnerabilities | 0 |" in build_summary_markdown(
        queried, *check_gate(queried, {})
    )


@pytest.mark.parametrize(
    "file, expected, forbidden",
    [
        ("scripts/run.sh", '"$var"', "subprocess"),
        ("app/run.py", "subprocess.run", "eval, source"),
        ("cmd/run.go", "exec.Command", "subprocess"),
        ("web/run.ts", "execFile", "subprocess"),
    ],
)
def test_fix_text_matches_the_language_of_the_finding(file, expected, forbidden):
    fix = finding_fix({"rule_id": "SKY-D212", "file": file})

    assert expected in fix
    assert forbidden not in fix


def test_dead_code_fix_uses_the_language_comment_and_every_rule_has_a_docs_link():
    python_fix = finding_fix({"file": "a.py"}, "unused_functions")
    ts_fix = finding_fix({"rule_id": "SKY-U003", "file": "a.ts"}, "unused_variables")

    assert "# skylos: ignore[SKY-U001]" in python_fix
    assert "// skylos: ignore[SKY-U003]" in ts_fix
    assert rule_docs_url("SKY-D212").endswith("#sky-d212--command-injection")
    assert rule_docs_url("SKY-NOPE") == "https://docs.skylos.dev/rules-reference"


def test_json_guidance_adds_fix_docs_and_the_same_top_risks(tmp_path):
    result = add_report_guidance(_result(), project_root=tmp_path, config={})

    shell = next(row for row in result["danger"] if row["rule_id"] == "SKY-D212")
    assert "subprocess" not in shell["fix"] and "eval" in shell["fix"]
    assert shell["docs_url"] == rule_docs_url("SKY-D212")
    assert result["top_risks"][0]["rule_id"] == "SKY-D212"
    assert result["top_risks"][0]["blocking"] is True
    assert result["issue_summary"]["total"] == 12
    assert result["issue_summary"]["by_category"]["dependencies"] is None
    assert result["issue_summary"]["verdict"]["text"] == "Not ready: 1 blocking issue"


def test_terminal_starts_with_the_verdict_and_top_risks_before_any_table(tmp_path):
    output = _rich(_result(), tmp_path, width=80)
    lines = output.splitlines()

    first_table = next(index for index, line in enumerate(lines) if "┏" in line)
    top = next(index for index, line in enumerate(lines) if "Top risks" in line)
    assert "Not ready: 1 blocking issue" in output[: output.index("Top risks")]
    assert top < first_table
    assert "CRITICAL Command injection SKY-D212 · blocks the gate" in lines[top + 1]
    assert "scripts/run.sh:4" in lines[top + 2]
    assert "Advice priority" not in output and "capped at MEDIUM" not in output
    assert re.search(r"│ HIGH\s+│ Cyclomatic", output)
    assert output.count("3 import sites in 3 files") == 1
    security = output[output.index("─ Security ") :]
    assert security.index("SKY-D212") < security.index("SKY-D218")
    assert security.index("SKY-D218") < security.index("2 findings in test code")


def test_report_states_the_verdict_and_at_most_five_risks_without_external_assets(
    tmp_path,
):
    result = _result()
    result["danger"][0]["file"] = 'app/<img src=x onerror="alert(1)">.py'

    page = render_report(result, "html", project_root=tmp_path, config={})
    markdown = render_report(result, "md", project_root=tmp_path, config={})

    assert "Not ready: 1 blocking issue" in page
    assert "<strong>Not ready: 1 blocking issue</strong>" in page
    assert page.count('<td class="num">') == 5
    assert "<script" not in page and "<link" not in page and "src=x" not in page
    assert "@media print" in page
    assert "**Not ready: 1 blocking issue.**" in markdown
    top_rows = [line for line in markdown.splitlines() if re.match(r"\| \d \|", line)]
    assert len(top_rows) == 5
    assert top_rows[0].startswith("| 1 | CRITICAL | [Command injection]")
    assert "Dependency vulnerabilities: not checked" in markdown
    assert "Skylos " in markdown and "Scanned " in markdown


def test_remediation_dry_run_needs_no_key_and_lists_what_it_would_fix(
    monkeypatch, capsys, tmp_path
):
    (tmp_path / "db.py").write_text(
        "import sqlite3\n"
        "def find(name):\n"
        "    conn = sqlite3.connect('a.db')\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "SkylosLLM", None)
    monkeypatch.setattr("skylos.llm.runtime.llm_extra_importable", lambda: False)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def no_key_lookup(**_kwargs):
        raise AssertionError("a dry run must not look up a model key")

    monkeypatch.setattr(cli, "resolve_llm_runtime", no_key_lookup)
    fixer = MagicMock(side_effect=AssertionError("a dry run must not build a fixer"))
    monkeypatch.setattr("skylos.llm.orchestrator.RemediationAgent._create_fixer", fixer)
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", "agent", "remediate", str(tmp_path), "--dry-run"]
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert exc.value.code == 0
    assert "No OPENAI_API_KEY" not in output
    assert "Dry run" in output and "db.py" in output
