from rich.console import Console

from skylos.ui.terminal_report import collect_pretty_findings, render_pretty_results


def _recording_console() -> Console:
    return Console(record=True, width=120, force_terminal=False)


def test_pretty_renderer_groups_findings_by_file_and_keeps_copyable_locations(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text(
        "def handler(user_id):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n",
        encoding="utf-8",
    )
    result = {
        "analysis_summary": {"total_files": 1},
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "HIGH",
                "message": "SQL injection risk",
                "file": str(source),
                "line": 2,
            }
        ],
    }

    console = _recording_console()
    render_pretty_results(console, result, root_path=tmp_path)
    output = console.export_text()

    assert "Skylos static analysis" in output
    assert "src/app.py · 1 issue" in output
    assert " HIGH  SKY-D211  SQL injection risk" in output
    assert "src/app.py:2" in output
    assert "cursor.execute" in output
    assert "╭" not in output


def test_pretty_renderer_uses_secret_preview_instead_of_source_line(tmp_path):
    source = tmp_path / ".env"
    source.write_text("API_KEY=sk_live_real_secret_value\n", encoding="utf-8")
    result = {
        "analysis_summary": {"total_files": 1},
        "secrets": [
            {
                "provider": "stripe",
                "message": "Stripe key found",
                "preview": "sk_live_****",
                "file": str(source),
                "line": 1,
            }
        ],
    }

    console = _recording_console()
    render_pretty_results(console, result, root_path=tmp_path)
    output = console.export_text()

    assert "sk_live_****" in output
    assert "sk_live_real_secret_value" not in output


def test_collect_pretty_findings_applies_per_category_limit(tmp_path):
    result = {
        "unused_functions": [
            {"name": "old_a", "file": "a.py", "line": 1},
            {"name": "old_b", "file": "b.py", "line": 2},
        ],
        "quality": [
            {"message": "too complex", "file": "c.py", "line": 3},
            {"message": "too nested", "file": "d.py", "line": 4},
        ],
    }

    findings = collect_pretty_findings(result, root_path=tmp_path, limit=1)

    assert [finding.title for finding in findings] == [
        "too complex",
        "Unused function: old_a",
    ]
