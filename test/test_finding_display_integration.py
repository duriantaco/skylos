from __future__ import annotations

import copy
import json
import sys
from io import StringIO

import pytest
from rich.console import Console

from skylos import cli
from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.finding_types import (
    annotate_finding_types,
    summarize_finding_types,
)
from skylos.reporting.grader import compute_grade
from skylos.reporting.result_builder import _attach_grade


def _report():
    result = {
        "quality": [
            {
                "rule_id": "SKY-C304",
                "file": "app.py",
                "line": 1,
                "severity": "HIGH",
                "message": "Long function",
                "name": "first",
            },
            {
                "rule_id": "SKY-C304",
                "file": "app.py",
                "line": 90,
                "severity": "HIGH",
                "message": "Long function",
                "name": "second",
            },
            {
                "rule_id": "SKY-L001",
                "file": "app.py",
                "line": 170,
                "severity": "HIGH",
                "message": "Mutable default",
                "name": "append",
            },
            {
                "rule_id": "SKY-P404",
                "file": "app.py",
                "line": 180,
                "severity": "MEDIUM",
                "message": "Unbounded query",
                "name": "users",
            },
        ],
        "danger": [
            {
                "rule_id": "SKY-D216",
                "file": "http.py",
                "line": 3,
                "severity": "CRITICAL",
                "message": "Possible SSRF",
            }
        ],
        "analysis_summary": {"files_analyzed": 2, "quality_count": 4},
    }
    annotate_finding_types(result)
    result["analysis_summary"]["finding_type_counts"] = summarize_finding_types(result)
    result["analysis_summary"]["grade_scope"] = "all_analyzed_findings"
    result["grade"] = compute_grade(result, 1000)
    return result


def test_display_filter_preserves_scan_grade_and_discloses_scope():
    result = _report()
    before = copy.deepcopy(result)
    filtered = cli._apply_display_filters(result, severity="critical")
    assert filtered["quality"] == []
    assert filtered["grade"] == result["grade"]
    assert filtered["analysis_summary"]["grade_scope"] == "all_analyzed_findings"
    assert filtered["analysis_summary"]["grade_includes_filtered_findings"] is True
    assert filtered["analysis_summary"]["finding_type_counts"] == {
        "defect": 0,
        "review": 1,
        "advice": 0,
        "advice_groups": 0,
    }
    assert result == before


def test_expansion_and_terminal_width_do_not_change_records_grade_or_gate():
    result = _report()
    before = copy.deepcopy(result)
    configuration = {"gate": {"max_quality": 0, "max_critical": 0}}
    decision = check_gate(result, configuration)
    assert decision[0] is False
    for width in (80, 120):
        for expand in (False, True):
            buffer = StringIO()
            cli.render_results(
                Console(
                    file=buffer,
                    width=width,
                    force_terminal=False,
                    theme=cli._skylos_console_theme(),
                ),
                result,
                copy_badge=False,
                expand_advice=expand,
            )
            assert "Advice" in buffer.getvalue()
            assert "Review" in buffer.getvalue()
            assert "Defect" in buffer.getvalue()
            assert result == before
            assert check_gate(result, configuration) == decision


@pytest.mark.parametrize("expanded", [False, True])
def test_cli_json_keeps_every_advice_record(monkeypatch, capsys, tmp_path, expanded):
    result = _report()
    monkeypatch.setenv("SKYLOS_NO_UPLOAD", "1")
    monkeypatch.setenv("SKYLOS_NO_UPDATE_CHECK", "1")
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli, "run_analyze", lambda *args, **kwargs: json.dumps(result))
    argv = [
        "skylos",
        str(tmp_path),
        "--quality",
        "--format",
        "json",
        "--no-upload",
        "--no-clipboard",
        "--no-provenance",
    ]
    if expanded:
        argv.append("--expand-advice")
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["quality"] == result["quality"]
    assert payload["grade"] == result["grade"]
    assert payload["analysis_summary"]["finding_type_counts"] == {
        "defect": 1,
        "review": 2,
        "advice": 2,
        "advice_groups": 1,
    }
    assert "hidden_advisory_quality" not in payload["analysis_summary"]


def test_removed_profile_flag_is_not_a_silent_filter(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(
        sys, "argv", ["skylos", str(tmp_path), "--quality-profile", "focused"]
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_sarif_keeps_canonical_families_outside_the_legacy_export_list(
    monkeypatch, capsys, tmp_path
):
    from skylos.reporting.assessment import compute_assessment

    def row(rule_id, line):
        return {
            "rule_id": rule_id,
            "file": "app.py",
            "line": line,
            "severity": "HIGH",
            "message": f"Finding {rule_id}",
        }

    result = _report()
    result.pop("grade")
    result["unused_exports"] = [row("SKY-U001", 2)]
    result["unused_fixtures"] = [row("SKY-U001", 3)]
    result["circular_dependencies"] = [row("SKY-Q801", 4)]
    result["code_health"] = [row("SKY-Q805", 5)]
    signal = row("SKY-Q802", 6)
    result["architecture_metrics"] = {"advisories": [{"signals": [signal, signal]}]}
    result["assessment"] = compute_assessment(result)
    monkeypatch.setenv("SKYLOS_NO_UPLOAD", "1")
    monkeypatch.setenv("SKYLOS_NO_UPDATE_CHECK", "1")
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli, "run_analyze", lambda *args, **kwargs: json.dumps(result))
    target = tmp_path / "report.sarif"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--quality",
            "--format",
            "json",
            "--no-upload",
            "--no-clipboard",
            "--no-provenance",
            "--sarif",
            str(target),
        ],
    )
    cli.main()
    capsys.readouterr()
    run = json.loads(target.read_text())["runs"][0]
    locations = [
        item["locations"][0]["physicalLocation"]["region"]["startLine"]
        for item in run["results"]
    ]
    assert all(line in locations for line in range(2, 7))
    assert locations.count(6) == 2
    assert len(run["results"]) == 11
    assert all(item["properties"]["severity"] for item in run["results"])
    assert run["properties"]["assessment"]["version"] == 1


def test_full_scan_assessment_includes_findings_from_additional_phases():
    result = {
        "analysis_summary": {},
        "reliability": [
            {"rule_id": "SKY-R201", "severity": "HIGH", "file": "worker.py", "line": 1}
        ],
        "custom_rules": [
            {
                "rule_id": "company-check",
                "severity": "HIGH",
                "file": "app.py",
                "line": 2,
            }
        ],
    }
    _attach_grade(result, [], True, True, False, False, False)
    assert "ai_defects" not in result["assessment"]["scanned_checks"]
    assert "ai_defects" in result["assessment"]["coverage"]["not_assessed"]
    assert "quality" in result["assessment"]["scanned_checks"]
    assert (
        result["assessment"]["risk"]["categories"]["correctness"]["finding_count"] == 2
    )
    assert result["assessment"]["risk"]["status"] == "high"
    assert "grade" not in result


def test_config_reliability_finding_does_not_claim_disabled_ai_phase(tmp_path):
    from skylos.analyzer import analyze

    root = tmp_path.resolve()
    (root / ".skylos").mkdir()
    assert write_text_no_symlink(
        root / ".skylos" / "gpu-targets.yml",
        'version: 1\ntargets:\n  - name: legacy-node\n    vendor: nvidia\n'
        '    driver: "510.47.03"\n',
    )
    assert write_text_no_symlink(
        root / "Dockerfile", "FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04\n"
    )
    assert write_text_no_symlink(root / "app.py", "value = 1\n")

    result = json.loads(
        analyze(str(root), enable_danger=True, enable_ai_defects=False)
    )

    assert any(item["rule_id"] == "SKY-GPU001" for item in result["reliability"])
    assert result["analysis_summary"]["grade_categories"] == ["security", "dead_code"]
    assessment = result["assessment"]
    assert assessment["risk"]["status"] == "high"
    assert assessment["risk"]["categories"]["correctness"]["finding_count"] == 1
    assert "ai_defects" not in assessment["scanned_checks"]
    assert "ai_defects" in assessment["coverage"]["not_assessed"]
    assert "ai_verification_incomplete" not in assessment["coverage"]["reasons"]


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("with_gate", [False, True])
def test_json_gate_records_policy_failure_before_display_filter(
    monkeypatch, capsys, tmp_path, force, with_gate
):
    from skylos.reporting.assessment import compute_assessment

    result = _report()
    result.pop("grade")
    result["assessment"] = compute_assessment(result)
    monkeypatch.setenv("SKYLOS_NO_UPLOAD", "1")
    monkeypatch.setenv("SKYLOS_NO_UPDATE_CHECK", "1")
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli, "run_analyze", lambda *args, **kwargs: json.dumps(result))
    argv = [
        "skylos",
        str(tmp_path),
        "--quality",
        "--format",
        "json",
        "--strict",
        "--category",
        "dead_code",
        "--no-upload",
        "--no-clipboard",
        "--no-provenance",
    ]
    if with_gate:
        argv.append("--gate")
    if force:
        argv.append("--force")
    monkeypatch.setattr(sys, "argv", argv)
    if force:
        cli.main()
    else:
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["quality"] == []
    assert payload["danger"] == []
    if force and not with_gate:
        # Existing standalone --strict --force skips policy evaluation.
        assert "gate" not in payload
        return
    assert payload["gate"]["passed"] is False
    assert payload["gate"]["forced"] is force
    assert payload["gate"]["scope"] == (
        "local_configured_policy" if with_gate else "local_strict_policy"
    )
    assert payload["gate"]["reasons"]
