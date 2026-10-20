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
                assert "MEDIUM" in text
            else:
                assert "1 optional advice finding" in normalized
                assert "--all-advice" in text
            assert ("Concrete defect remains visible" in normalized) is (
                name != "selected"
            )
        assert json.dumps(raw) == encoded

    # --all-advice decides which findings are listed; no other
    # presentation switch reaches the analyzer. Explicit rule selection has
    # its own established analyzer prerequisite contract.
    without_scope = [
        {key: value for key, value in call.items() if key != "all_advice"}
        for call in calls[:3]
    ]
    assert without_scope[0] == without_scope[1] == without_scope[2]
    assert [call.get("all_advice") for call in calls[:3]] == [False, True, True]


def test_actual_cli_json_sarif_and_gate_read_the_same_result(
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
    for label, switches, listed in (
        ("focused", [], False),
        ("all", ["--all-advice", "--expand-advice"], True),
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
        raw_json = read_text_no_symlink(json_path, max_bytes=1_000_000)
        raw_sarif = read_text_no_symlink(sarif_path, max_bytes=1_000_000)
        assert raw_json is not None and raw_sarif is not None
        report, sarif = json.loads(raw_json), json.loads(raw_sarif)
        signature_rows = [
            row for row in report["quality"] if row["rule_id"] == "SKY-L029"
        ]
        sarif_run = sarif["runs"][0]
        # JSON, SARIF and the gate all read the one result.
        assert len(signature_rows) == 1
        assert signature_rows[0]["listing"]["listed"] is listed
        signature_sarif = [
            row for row in sarif_run["results"] if row["ruleId"] == "SKY-L029"
        ]
        assert len(signature_sarif) == 1
        assert signature_sarif[0]["properties"]["listing"]["listed"] is listed
        assert gate_inputs
        assert all(
            next(
                row["listing"]["listed"]
                for _category, row in rows
                if row["rule_id"] == "SKY-L029"
            )
            is listed
            for rows, _config, _kwargs in gate_inputs
        )
        assert sarif_run["properties"]["gate"] == report["gate"]
        assert report["gate"]["passed"] is not listed
        assert code == (1 if listed else 0)
        assert ("Quality Gate: FAILED" in stderr) is listed
        if listed:
            assert report["advice_visibility"]["omitted_checks"] == 0
            assert "permits positional calls" in signature_rows[0]["message"]
        else:
            visibility = report["advice_visibility"]
            assert visibility["reasons"]["boolean_signature"] == 1
            assert visibility["rules"]["SKY-L029"] == 1
            assert visibility["omitted_checks"] == sum(visibility["reasons"].values())


@pytest.mark.parametrize("selection", ["config", "cli"])
def test_named_advice_rule_is_listed_and_enforced_through_actual_cli(
    project, monkeypatch, capsys, selection
):
    switches = ["--select", "SKY-L029"] if selection == "cli" else []
    if selection == "config":
        assert write_text_no_symlink(
            project / "pyproject.toml",
            '[tool.skylos.gate]\nmax_quality=0\nrules=["SKY-L029"]\n',
        )
    path = project.parent / f"named-{selection}.json"
    code, _, _ = _run(
        project,
        monkeypatch,
        capsys,
        "--format",
        "json",
        "--gate",
        "--output",
        str(path),
        *switches,
    )
    report = json.loads(path.read_text())
    finding = next(row for row in report["quality"] if row["rule_id"] == "SKY-L029")
    assert finding["listing"]["listed"] is True
    assert report["gate"]["passed"] is False
    assert code == 1
