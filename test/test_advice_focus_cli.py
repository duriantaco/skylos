"""CLI advice switches change human views while retaining raw gate evidence."""

from copy import deepcopy
import json

import pytest

import skylos.cli as cli
from skylos.core import gatekeeper
from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink
from skylos.reporting.finding_types import iter_result_findings


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    assert write_text_no_symlink(
        root / "api.py",
        '__all__ = ["configure"]\n\n'
        "def configure(enabled: bool = False) -> bool:\n"
        "    return enabled\n",
    )
    assert write_text_no_symlink(
        root / "pyproject.toml", "[tool.skylos.gate]\nmax_quality = 0\n"
    )
    monkeypatch.chdir(root)
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("COLUMNS", "240")
    monkeypatch.setattr(
        "skylos.cloud.sync.load_custom_rules",
        lambda: {"rules": [], "status": "not_connected"},
    )

    def no_upload(*args, **kwargs):
        pytest.fail("Advice CLI regression tests must not upload")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    return root


def _run(project, monkeypatch, capsys, *options):
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(project / "api.py"),
            "--quality",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--no-clipboard",
            *options,
        ],
    )
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = exc.code
    output = capsys.readouterr()
    return code, output.out, output.err


def _signature(project):
    return {
        "rule_id": "SKY-L029",
        "severity": "HIGH",
        "type": "function",
        "name": "api.configure.enabled",
        "file": str(project / "api.py"),
        "line": 3,
        "value": "enabled",
        "message": (
            "Boolean parameter 'enabled' permits positional calls, which can obscure "
            "their meaning. Prefer named calls; consider keyword-only arguments when "
            "the public or callback contract permits it."
        ),
        "evidence": {"source": "signature"},
    }


@pytest.mark.parametrize("output_format", ["rich", "pretty", "tree", "llm"])
def test_cli_human_and_saved_reports_share_focus_and_selection(
    output_format, project, monkeypatch, capsys
):
    signature = _signature(project)
    raw = {
        "analysis_summary": {"total_files": 1},
        "quality": [
            signature,
            {
                "rule_id": "SKY-L001",
                "severity": "LOW",
                "file": str(project / "api.py"),
                "line": 4,
                "message": "Concrete defect remains visible",
            },
        ],
    }
    encoded = json.dumps(raw)
    # Exercise actual argument parsing, selection and report writers; detector
    # behavior is checked against real source in the JSON/SARIF case below.
    calls = []

    def analyze(*args, **kwargs):
        # The Rich progress callback is a fresh UI closure for each invocation.
        calls.append(
            deepcopy(
                {
                    key: value
                    for key, value in kwargs.items()
                    if key != "progress_callback"
                }
            )
        )
        return encoded

    monkeypatch.setattr(cli, "run_analyze", analyze)
    format_options = (
        ["--tree"] if output_format == "tree" else ["--format", output_format]
    )
    variants = [
        ("focus-expanded", ["--expand-advice"], False, True),
        ("all-grouped", ["--all-advice"], True, False),
        ("all-expanded", ["--all-advice", "--expand-advice"], True, True),
        ("selected", ["--select", "SKY-L029", "--expand-advice"], True, True),
    ]
    for name, switches, visible, expanded in variants:
        destination = project.parent / f"{output_format}-{name}.txt"
        code, stdout, _stderr = _run(
            project,
            monkeypatch,
            capsys,
            *format_options,
            "--output",
            str(destination),
            *switches,
        )
        assert code == 0
        saved = read_text_no_symlink(destination, max_bytes=100_000)
        assert saved is not None
        for text in (stdout, saved) if output_format != "llm" else (saved,):
            normalized = " ".join(text.split())
            assert ("SKY-L029" in text) is visible
            assert ("permits positional calls" in normalized) is (visible and expanded)
            if visible:
                assert "optional advice findings" not in normalized
                assert "HIGH" in text
            else:
                assert "1 optional advice finding" in normalized
                assert "--all-advice" in text
            assert ("Concrete defect remains visible" in normalized) is (
                name != "selected"
            )
        assert json.dumps(raw) == encoded

    # Presentation switches are never analyzer configuration. Explicit rule
    # selection has its own established analyzer prerequisite contract.
    assert calls[0] == calls[1] == calls[2]


def test_actual_cli_all_advice_keeps_json_sarif_and_gate_inputs_identical(
    project, monkeypatch, capsys
):
    real_check_gate = gatekeeper.check_gate
    gate_inputs = []

    def capture_gate(result, config, **kwargs):
        gate_inputs.append(
            (deepcopy(list(iter_result_findings(result))), deepcopy(config), kwargs)
        )
        return real_check_gate(result, config, **kwargs)

    monkeypatch.setattr(gatekeeper, "check_gate", capture_gate)
    runs = []
    for label, switches in (
        ("focused", []),
        ("all", ["--all-advice", "--expand-advice"]),
    ):
        json_path = project.parent / f"{label}.json"
        sarif_path = project.parent / f"{label}.sarif"
        gate_inputs.clear()
        code, _stdout, stderr = _run(
            project,
            monkeypatch,
            capsys,
            "--format",
            "json",
            "--gate",
            "--output",
            str(json_path),
            "--sarif",
            str(sarif_path),
            *switches,
        )
        assert code == 1
        assert "Quality Gate: FAILED" in stderr
        raw_json = read_text_no_symlink(json_path, max_bytes=1_000_000)
        raw_sarif = read_text_no_symlink(sarif_path, max_bytes=1_000_000)
        assert raw_json is not None and raw_sarif is not None
        report, sarif = json.loads(raw_json), json.loads(raw_sarif)
        signature_rows = [
            row for row in report["quality"] if row["rule_id"] == "SKY-L029"
        ]
        assert len(signature_rows) == 1
        assert "permits positional calls" in signature_rows[0]["message"]
        assert report["gate"]["passed"] is False
        assert any("quality" in reason.lower() for reason in report["gate"]["reasons"])
        sarif_run = sarif["runs"][0]
        assert any(row["ruleId"] == "SKY-L029" for row in sarif_run["results"])
        assert sarif_run["properties"]["gate"] == report["gate"]
        assert gate_inputs
        assert all(
            any(row["rule_id"] == "SKY-L029" for _category, row in rows)
            for rows, _config, _kwargs in gate_inputs
        )
        runs.append((report, sarif, deepcopy(gate_inputs)))

    assert runs[0] == runs[1]
