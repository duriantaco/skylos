"""Paired framework liveness and real dead-code corpus contracts."""

import copy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import corpus_ci


MANIFEST = Path(__file__).resolve().parents[1] / "corpus" / "manifest.json"

# These source-backed controls are unregistered callbacks or ordinary
# class/field/parameter siblings of the retained framework declarations.
CONTROLS = {
    "flask-route-handler": {"unused_functions": ["catalogue"]},
    "fastapi-depends-route": {"unused_functions": ["read_status"]},
    "celery-task": {"unused_functions": ["multiply"]},
    "pluggy-hookimpl": {"unused_functions": ["render_report"]},
    "pytest-plugin-hooks": {
        "unused_functions": ["serialize_comparison"],
        "unused_parameters": ["render_style"],
    },
    "typer-callback": {"unused_functions": ["configure_display"]},
    "starlette-add-route": {"unused_functions": ["status_page"]},
    "sanic-register-listener": {"unused_functions": ["after_boot"]},
    "django-urlpatterns": {"unused_functions": ["status"]},
    "django-error-handlers": {"unused_variables": ["fallback_callback"]},
    "django-path-converter": {
        "unused_functions": ["DateParser.decode_date", "DateParser.encode_date"],
        "unused_variables": ["date_pattern"],
        "unused_classes": ["DateCodec"],
    },
    "gunicorn-config": {
        "unused_functions": ["on_message"],
        "unused_variables": ["worker_hint"],
    },
    "django-class-based-view": {
        "unused_functions": ["PageRenderer.format_page"],
        "unused_classes": ["PageFormatter"],
    },
    "drf-viewset": {
        "unused_functions": ["ActionPreview.preview"],
        "unused_classes": ["PreviewActions"],
    },
    "drf-serializer": {
        "unused_functions": ["ContactFormatter.normalize_address"],
        "unused_classes": ["ContactRecord"],
        "unused_variables": ["address"],
    },
    "sqlalchemy-model": {
        "unused_classes": ["AuditRow"],
        "unused_variables": ["row_id", "title"],
    },
    "fastapi-pydantic-model": {
        "unused_functions": ["PayloadCleaner.clean_contact", "preview_user"],
        "unused_classes": ["DraftPayload"],
    },
    "pydantic-settings-model": {"unused_classes": ["SettingsSnapshot"]},
    "aiohttp-routes": {
        "unused_functions": ["metadata"],
        "unused_parameters": ["format_style"],
    },
    "attrs-define-fields": {"unused_variables": ["account_id", "display_name"]},
    "marshmallow-schema": {
        "unused_functions": ["ItemLoader.parse_item"],
        "unused_classes": ["PayloadParser"],
    },
    "sqlalchemy-event-listener": {
        "unused_functions": ["connection_closed"],
        "unused_parameters": ["label_style"],
    },
    "flask-add-url-rule": {"unused_functions": ["create_report"]},
}

GROUPED_METHODS = {
    "django-class-based-view": ["PageFormatter.format_page"],
    "django-path-converter": ["DateCodec.decode_date", "DateCodec.encode_date"],
    "drf-serializer": ["ContactRecord.normalize_address"],
    "drf-viewset": ["PreviewActions.preview"],
    "fastapi-pydantic-model": ["DraftPayload.clean_contact"],
    "marshmallow-schema": ["PayloadParser.parse_item"],
}


def _with_controls(case):
    case = copy.deepcopy(case)
    present = case["expect"].setdefault("present", {})
    for category, symbols in CONTROLS[case["id"]].items():
        present[category] = sorted(set(present.get(category, [])) | set(symbols))
    absent = case["expect"].setdefault("absent", {})
    grouped = GROUPED_METHODS.get(case["id"], [])
    if grouped:
        absent["unused_functions"] = sorted(
            set(absent.get("unused_functions", [])) | set(grouped)
        )
    return case


@pytest.mark.parametrize("case_id", sorted(CONTROLS))
def test_framework_controls_report_real_findings_and_detect_dropped_results(
    monkeypatch, case_id
):
    case = next(
        case
        for case in corpus_ci.load_manifest(MANIFEST)["cases"]
        if case["id"] == case_id
    )
    case = _with_controls(case)
    original = corpus_ci._scan_case
    captured = []

    def capture(path, scan=None):
        report = original(path, scan=scan)
        captured.append(report)
        return report

    monkeypatch.setattr(corpus_ci, "_scan_case", capture)
    result = corpus_ci.run_case(case, MANIFEST)
    assert len(captured) == 1
    report = captured[0]
    assert report["analysis_summary"]["total_files"] > 0
    assert not report.get("analysis_errors")
    assert result.get("scored", True) is True
    assert result["failures"] == [], json.dumps(result, indent=2)

    # A scanner that silently drops these real findings must fail the same
    # contract even while every existing false-positive guard remains quiet.
    erased = copy.deepcopy(report)
    controls = CONTROLS[case_id]
    for category, symbols in controls.items():
        erased[category] = [
            finding
            for finding in erased.get(category, [])
            if not (corpus_ci._finding_tokens(finding) & set(symbols))
        ]
    monkeypatch.setattr(corpus_ci, "_scan_case", lambda *args, **kwargs: erased)
    broken = corpus_ci.run_case(case, MANIFEST)
    assert {
        (failure["category"], failure["mode"], failure["expected"])
        for failure in broken["failures"]
    } == {
        (category, "present", symbol)
        for category, symbols in controls.items()
        for symbol in symbols
    }


def test_framework_controls_are_part_of_checked_in_manifest():
    cases = {case["id"]: case for case in corpus_ci.load_manifest(MANIFEST)["cases"]}
    for case_id, categories in CONTROLS.items():
        present = cases[case_id]["expect"]["present"]
        for category, symbols in categories.items():
            assert set(symbols) <= set(present.get(category, [])), (case_id, category)
    for case_id, symbols in GROUPED_METHODS.items():
        absent = cases[case_id]["expect"]["absent"]
        assert set(symbols) <= set(absent.get("unused_functions", [])), case_id
