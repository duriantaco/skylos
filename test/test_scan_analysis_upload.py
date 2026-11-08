"""Optional analysis evidence must survive every Cloud report transport."""

import copy
import json
from unittest.mock import patch

import pytest

import skylos.api as api
from skylos.api._scan_analysis import scan_analysis_metadata


def type_check():
    return {
        "status": "fail",
        "complete": True,
        "checker": "tsc",
        "summary": "1 new error",
        "reason": "",
        "seconds": 0.4,
        "error_count": 1,
        "warning_count": 0,
        "project_error_count": 1,
        "out_of_scope_count": 0,
        "counts": {"introduced": 1, "preexisting": 0, "unclassified": 0},
        "comparison": {
            "status": "complete",
            "base": "a" * 40,
            "reason": "same configuration",
            "base_run": True,
        },
        "escape_guard": {"status": "complete", "added": 0},
        "diagnostics": [
            {
                "file": "src/app.ts",
                "line": 7,
                "column": 3,
                "code": "TS2322",
                "severity": "error",
                "origin": "introduced",
                "scope": "selected",
                "message": "Incompatible assignment",
            }
        ],
        "project_root": "/private/never-upload-project-root",
        "executable": "/private/checker",
        "command": ["should-not-upload-command"],
        "setup": "should-not-upload-setup",
        "config_fingerprints": {"pyproject.toml": "private-config-hash"},
    }


def profile():
    function = {
        "file": "skylos/analyzer.py",
        "line": 50,
        "function": "analyze",
        "calls": 1,
        "primitive_calls": 1,
        "self_seconds": 0.02,
        "cumulative_seconds": 0.1,
    }
    return {
        "schema_version": 1,
        "kind": "skylos_analysis",
        "completed": True,
        "wall_seconds": 0.1,
        "phases": [{"name": "security", "seconds": 0.1, "visits": 1}],
        "functions": {"by_cumulative": [function], "by_self": [dict(function)]},
        "notes": ["Profiling adds overhead"],
    }


def prepare(result):
    with (
        patch.object(
            api, "get_git_info", return_value=("a" * 40, "main", "tester", {})
        ),
        patch.object(api, "get_git_root", return_value=None),
        patch.object(api, "detect_ai_code", return_value={"detected": False}),
        patch.object(api, "_load_repo_link", return_value={}),
    ):
        return api._prepare_report_upload(
            {"danger": [], "provenance": {"status": {"ran": False}}, **result},
            analyzer_owned=True,
        )


def test_native_legacy_and_compatibility_uploads_keep_optional_analysis():
    raw = {"type_check": type_check(), "profiling": profile()}
    prepared = prepare(raw)
    expected = scan_analysis_metadata(raw)
    for transport in [
        prepared.metadata,
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
    ]:
        assert transport["type_check"] == expected["type_check"]
        assert transport["profiling"] == expected["profiling"]
        rendered = json.dumps(transport)
        assert "should-not-upload" not in rendered
        assert "/private/never-upload-project-root" not in rendered
        assert "private-config-hash" not in rendered
    assert prepared.core_payload["runs"][0]["results"] == []
    assert raw["type_check"]["command"] == ["should-not-upload-command"]


def test_absent_metadata_keeps_older_transport_shape():
    assert scan_analysis_metadata({}) == {}
    prepared = prepare({})
    for transport in [
        prepared.metadata,
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
    ]:
        assert "type_check" not in transport
        assert "profiling" not in transport


@pytest.mark.parametrize("bad", [None, "failed", ["pass"], 42])
def test_malformed_supplied_check_is_explicit_not_silently_omitted(bad):
    metadata = scan_analysis_metadata({"type_check": bad})
    assert "type_check" in metadata and metadata["type_check"] is None


def test_diagnostic_truncation_is_explicit_and_counts_preserved():
    raw = type_check()
    raw["diagnostics"] *= 503
    raw["error_count"] = 503
    raw["counts"]["introduced"] = 503
    raw["truncated"] = 2
    result = scan_analysis_metadata({"type_check": raw})["type_check"]
    assert len(result["diagnostics"]) == 500
    assert result["truncated"] == 5
    assert result["counts"]["introduced"] == result["error_count"] == 503


def test_profile_rows_and_nonfinite_values_are_bounded_without_claiming_clean():
    raw = profile()
    raw["phases"] *= 102
    raw["functions"]["by_self"] *= 103
    raw["wall_seconds"] = float("nan")
    result = scan_analysis_metadata({"profiling": raw})["profiling"]
    assert len(result["phases"]) == len(result["functions"]["by_self"]) == 100
    assert result["wall_seconds"] is None
    json.dumps(result, allow_nan=False)


def test_projection_is_detached_and_ignores_unknown_nested_private_fields():
    raw = {"type_check": type_check(), "profiling": profile()}
    raw["type_check"]["comparison"]["setup"] = "private-runtime-output"
    expected = copy.deepcopy(raw)
    metadata = scan_analysis_metadata(raw)
    metadata["type_check"]["diagnostics"][0]["message"] = "changed"
    assert raw == expected
    assert "setup" not in metadata["type_check"]["comparison"]


def test_validated_attached_done_receipt_supplies_type_check_fallback():
    metadata = scan_analysis_metadata({}, done_receipt={"type_check": type_check()})
    assert metadata["type_check"]["checker"] == "tsc"
    assert metadata["type_check"]["counts"]["introduced"] == 1
    # A directly requested scan check stays authoritative, even if malformed.
    assert scan_analysis_metadata(
        {"type_check": None}, done_receipt={"type_check": type_check()}
    ) == {"type_check": None}
