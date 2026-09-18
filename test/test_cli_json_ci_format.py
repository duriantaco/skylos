"""Regression tests for the `--format json-ci` compact CI/agent output.

`json-ci` omits the top-level `dead_code_evidence` and `definitions` bulk,
which dominates the payload size while almost never being what a CI job
reads. `--format json` must stay exactly as it was.
"""

import json

import pytest

import skylos.cli as cli
from skylos.commands.scan_cmd import _build_ci_json_payload

# Keys that carry the bulk and must not appear in the compact output.
OMITTED_TOP_LEVEL = ("dead_code_evidence", "definitions")

# Everything a CI gate or agent actually reads.
PRESERVED_FINDING_KEYS = (
    "unused_functions",
    "unused_imports",
    "unused_classes",
    "unused_variables",
    "unused_parameters",
    "unused_files",
    "analysis_errors",
    "analysis_summary",
)


def _sample_result():
    """A result shaped like a real scan: findings plus the two bulk blobs."""
    return {
        "definitions": {"mod.a": {"name": "mod.a", "type": "function"}},
        "unused_functions": [
            {
                "name": "helper",
                "full_name": "mod.helper",
                "type": "function",
                "file": "/repo/mod.py",
                "line": 4,
                "confidence": 100,
                "dead_code_evidence": [
                    {"kind": "no_static_references", "role": "supports_dead"}
                ],
                "dead_code_classification": "likely_dead",
            }
        ],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "unused_files": [],
        "analysis_errors": [],
        "dead_code_rescues": [],
        "dead_code_abstentions": [],
        "dead_code_evidence": {
            "classification_policy": "dead-code-evidence-v3",
            "symbols": [
                {"qualified_name": "mod.helper", "classification": "likely_dead"}
            ],
        },
        "analysis_summary": {
            "total_files": 1,
            "total_loc": 5,
            "unused_functions_count": 1,
            "analysis_error_count": 0,
            "dead_code_evidence": {
                "symbol_count": 1,
                "classifications": {"alive": 0, "likely_dead": 1},
                "candidate_decisions": {"reported": 1, "rescued": 0, "abstained": 0},
            },
        },
    }


# --- payload stripping -----------------------------------------------------


def test_omits_top_level_bulk():
    stripped = _build_ci_json_payload(_sample_result())
    for key in OMITTED_TOP_LEVEL:
        assert key not in stripped


def test_preserves_summary_evidence_counts():
    original = _sample_result()
    stripped = _build_ci_json_payload(original)
    assert stripped["analysis_summary"] == original["analysis_summary"]
    assert stripped["analysis_summary"]["dead_code_evidence"][
        "candidate_decisions"
    ] == {
        "reported": 1,
        "rescued": 0,
        "abstained": 0,
    }


def test_preserves_findings():
    original = _sample_result()
    stripped = _build_ci_json_payload(original)

    for key in PRESERVED_FINDING_KEYS:
        assert stripped[key] == original[key], key


def test_preserves_per_finding_evidence():
    """Findings keep their own evidence; only the whole-symbol ledger goes."""
    stripped = _build_ci_json_payload(_sample_result())
    finding = stripped["unused_functions"][0]

    assert finding["dead_code_evidence"]
    assert finding["dead_code_classification"] == "likely_dead"


def test_does_not_mutate_input():
    """Cloud upload and the TUI still need the complete result."""
    original = _sample_result()
    snapshot = json.dumps(original, sort_keys=True)

    _build_ci_json_payload(original)

    assert json.dumps(original, sort_keys=True) == snapshot


def test_preserves_sibling_summary_counts():
    """Top-level trimming must not change any summary counter."""
    stripped = _build_ci_json_payload(_sample_result())
    summary = stripped["analysis_summary"]

    assert summary["total_files"] == 1
    assert summary["total_loc"] == 5
    assert summary["unused_functions_count"] == 1
    assert summary["analysis_error_count"] == 0


def test_handles_missing_summary_gracefully():
    payload = {"unused_functions": []}
    assert _build_ci_json_payload(payload) == payload


def test_handles_non_dict_payload():
    assert _build_ci_json_payload(None) is None
    assert _build_ci_json_payload([]) == []


# --- CLI wiring ------------------------------------------------------------


def test_json_ci_is_an_accepted_format():
    parser = cli._build_main_parser()
    args = parser.parse_args([".", "--format", "json-ci"])
    assert args.format == "json-ci"


def test_json_ci_sets_json_output_flag():
    parser = cli._build_main_parser()
    args = cli._apply_main_output_format(
        parser, parser.parse_args([".", "--format", "json-ci"])
    )
    assert args.json is True
    assert args.json_ci is True


def test_plain_json_does_not_set_json_ci():
    """The default path must be untouched by the new format."""
    parser = cli._build_main_parser()
    args = cli._apply_main_output_format(
        parser, parser.parse_args([".", "--format", "json"])
    )
    assert args.json is True
    assert args.json_ci is False


def test_rich_default_does_not_set_json_ci():
    parser = cli._build_main_parser()
    args = cli._apply_main_output_format(parser, parser.parse_args(["."]))
    assert args.json_ci is False


@pytest.mark.parametrize("value", ["json", "json-ci"])
def test_json_variants_conflict_with_other_machine_flags(value):
    parser = cli._build_main_parser()
    with pytest.raises(SystemExit):
        cli._apply_main_output_format(
            parser, parser.parse_args([".", "--format", value, "--llm"])
        )


def _run_real_cli(
    monkeypatch, capsys, source, output_format, *, output=None, sarif=None
):
    argv = [
        "skylos",
        str(source),
        "--format",
        output_format,
        "--no-provenance",
        "--no-grep-verify",
        "--no-upload",
    ]
    if output is not None:
        argv.extend(("--output", str(output)))
    if sarif is not None:
        argv.extend(("--sarif", str(sarif)))
    monkeypatch.setattr(cli.sys, "argv", argv)

    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0
    return exit_code, capsys.readouterr().out


def test_json_ci_real_scan_only_omits_top_level_bulk(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "sample.py"
    source.write_text(
        "def used():\n    return 1\n\ndef unused():\n    return 2\n\nprint(used())\n",
        encoding="utf-8",
    )

    full_code, full_output = _run_real_cli(monkeypatch, capsys, source, "json")
    ci_code, ci_output = _run_real_cli(monkeypatch, capsys, source, "json-ci")
    full = json.loads(full_output)
    compact = json.loads(ci_output)

    assert full_code == ci_code == 0
    assert all(key in full for key in OMITTED_TOP_LEVEL)
    assert full["analysis_summary"]["dead_code_evidence"]["symbol_count"] > 0
    assert compact == {
        key: value for key, value in full.items() if key not in OMITTED_TOP_LEVEL
    }


def test_json_ci_file_output_keeps_sarif(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "sample.py"
    source.write_text("def unused():\n    return 1\n", encoding="utf-8")
    reports = {}
    sarif_results = {}

    for output_format in ("json", "json-ci"):
        output = tmp_path / f"{output_format}.json"
        sarif = tmp_path / f"{output_format}.sarif"
        exit_code, stdout = _run_real_cli(
            monkeypatch, capsys, source, output_format, output=output, sarif=sarif
        )
        assert exit_code == 0
        assert stdout == ""
        reports[output_format] = json.loads(output.read_text(encoding="utf-8"))
        sarif_results[output_format] = json.loads(sarif.read_text(encoding="utf-8"))[
            "runs"
        ][0]["results"]

    assert reports["json-ci"] == {
        key: value
        for key, value in reports["json"].items()
        if key not in OMITTED_TOP_LEVEL
    }
    assert sarif_results["json-ci"] == sarif_results["json"]


def test_json_ci_incomplete_scan_keeps_exit_two(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")

    full_code, full_output = _run_real_cli(monkeypatch, capsys, source, "json")
    ci_code, ci_output = _run_real_cli(monkeypatch, capsys, source, "json-ci")

    assert full_code == ci_code == 2
    full = json.loads(full_output)
    compact = json.loads(ci_output)
    assert full["analysis_errors"]
    assert compact == {
        key: value for key, value in full.items() if key not in OMITTED_TOP_LEVEL
    }
