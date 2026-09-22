"""The offline comparison entrypoint must never require the hosted service."""

import json

from scripts import jev_compare as cli


def test_comparison_cli_reads_reports_and_writes_new_output(monkeypatch, tmp_path):
    jev = tmp_path / "jev.json"
    scanner = tmp_path / "scanner.json"
    output = tmp_path / "comparison.json"
    jev.write_text('{"benchmark": "jev_dead_code"}', encoding="utf-8")
    scanner.write_text('{"tool": "skylos"}', encoding="utf-8")
    observed = {}

    def fake_compare(jev_report, scanner_summary, manifest, **kwargs):
        observed.update(
            jev=jev_report, scanner=scanner_summary, manifest=manifest, **kwargs
        )
        return {"comparison": "ok"}

    monkeypatch.setattr(cli, "compare_jev_to_scanner", fake_compare)
    assert (
        cli.main(
            [
                "--manifest",
                "manifest.json",
                "--jev-report",
                str(jev),
                "--scanner-summary",
                str(scanner),
                "--threshold",
                "0.9",
                "--arm",
                "neutralized",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert observed == {
        "jev": {"benchmark": "jev_dead_code"},
        "scanner": {"tool": "skylos"},
        "manifest": "manifest.json",
        "threshold": 0.9,
        "arm": "neutralized",
    }
    assert json.loads(output.read_text(encoding="utf-8")) == {"comparison": "ok"}


def test_comparison_cli_refuses_existing_output(monkeypatch, tmp_path, capsys):
    jev = tmp_path / "jev.json"
    scanner = tmp_path / "scanner.json"
    output = tmp_path / "comparison.json"
    jev.write_text("{}", encoding="utf-8")
    scanner.write_text("{}", encoding="utf-8")
    output.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(cli, "compare_jev_to_scanner", lambda *_a, **_k: {})

    assert (
        cli.main(
            [
                "--manifest",
                "manifest.json",
                "--jev-report",
                str(jev),
                "--scanner-summary",
                str(scanner),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert "output already exists" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "keep"
