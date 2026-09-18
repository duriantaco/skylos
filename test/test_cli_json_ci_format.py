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
            "symbols": [{"qualified_name": "mod.helper", "classification": "likely_dead"}],
        },
        "analysis_summary": {
            "total_files": 1,
            "total_loc": 5,
            "unused_functions_count": 1,
            "analysis_error_count": 0,
            "dead_code_evidence": {
                "symbol_count": 1,
                "classifications": {"alive": 0, "likely_dead": 1},
            },
        },
    }


# --- payload stripping -----------------------------------------------------


def test_omits_top_level_bulk():
    stripped = _build_ci_json_payload(_sample_result())
    for key in OMITTED_TOP_LEVEL:
        assert key not in stripped


def test_omits_summary_level_bulk():
    stripped = _build_ci_json_payload(_sample_result())
    assert "dead_code_evidence" not in stripped["analysis_summary"]


def test_preserves_findings():
    original = _sample_result()
    stripped = _build_ci_json_payload(original)

    for key in PRESERVED_FINDING_KEYS:
        if key == "analysis_summary":
            # The summary is expected to lose its nested bulk; every other
            # count inside it must survive (asserted separately).
            continue
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
    """Dropping the evidence blob must not take the counters with it."""
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
    args = cli._apply_main_output_format(parser, parser.parse_args([".", "--format", "json-ci"]))
    assert args.json is True
    assert args.json_ci is True


def test_plain_json_does_not_set_json_ci():
    """The default path must be untouched by the new format."""
    parser = cli._build_main_parser()
    args = cli._apply_main_output_format(parser, parser.parse_args([".", "--format", "json"]))
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
        cli._apply_main_output_format(parser, parser.parse_args([".", "--format", value, "--llm"]))
