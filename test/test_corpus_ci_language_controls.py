"""Paired language/framework corpus controls, checked without running fixtures."""

import copy
from pathlib import Path

import pytest

from skylos.benchmarks import corpus_ci


MANIFEST = Path(__file__).resolve().parents[1] / "corpus" / "manifest.json"
CONTROLS = {
    "fastapi-add-api-route": {"unused_functions": ["search_items"]},
    "fastapi-include-router": {"unused_functions": ["status_payload"]},
    "django-management-command": {
        "unused_classes": ["CommandPreview"],
        "unused_functions": ["parse_command"],
    },
    "django-signal-receiver": {"unused_functions": ["on_archive"]},
    "sqlalchemy-listens-for": {
        "unused_functions": ["on_disconnect"],
        "unused_parameters": ["audit_token"],
    },
    "marshmallow-validates-schema": {
        "unused_classes": ["PayloadValidator"],
        "unused_functions": ["validate_record"],
    },
    "python-cached-property": {"unused_functions": ["interval"]},
    "python-property-chain": {"unused_functions": ["label"]},
    "python-type-checking-imports": {"unused_imports": ["decimal"]},
    "python-public-api-exports": {
        "unused_classes": ["RecordDraft"],
        "unused_functions": ["parse_record"],
    },
    "python-pyproject-entrypoint": {"unused_functions": ["inspect_environment"]},
    "django-admin-register": {"unused_classes": ["AdminDraft"]},
    "django-appconfig-ready": {
        "unused_classes": ["StagingConfig"],
        "unused_functions": ["inspect_config"],
    },
    "celery-task-class": {
        "unused_classes": ["TaskDraft"],
        "unused_functions": ["queue_payload"],
    },
    "click-command-subclass": {
        "unused_classes": ["CommandDraft"],
        "dead_code_abstentions": ["format_arguments"],
    },
    "pydantic-computed-field": {
        "unused_classes": ["PreviewRecord"],
        "dead_code_abstentions": ["compose_name"],
    },
    "pydantic-serializer-hooks": {
        "unused_classes": ["SerializationDraft"],
        "unused_functions": ["serialize_title", "serialize_snapshot"],
    },
    "pydantic-model-post-init": {
        "unused_classes": ["ProfileDraft"],
        "unused_functions": ["prepare_profile"],
    },
    "python-enum-members": {"unused_variables": ["SHADE"]},
    "python-abstract-base": {"unused_functions": ["process"]},
    "python-protocol-implementation": {"unused_functions": ["stop"]},
    "sqlalchemy-hybrid-property": {"unused_functions": ["render_name"]},
    "python-unittest-lifecycle": {
        "whitelisted": ["prepare_record"],
        "unused_functions": ["publish_record"],
    },
}


def _case(case_id):
    manifest = corpus_ci.load_manifest(MANIFEST)
    return next(case for case in manifest["cases"] if case["id"] == case_id)


@pytest.mark.parametrize("case_id", CONTROLS)
def test_language_pairs_require_presence_even_when_live_guards_stay_quiet(
    monkeypatch, case_id
):
    case = copy.deepcopy(_case(case_id))
    for category, symbols in CONTROLS[case_id].items():
        assert set(symbols) <= set(case["expect"]["present"][category])
    # This is a valid analyzed source report with no findings. It satisfies the
    # old absence-only labels, but must fail the new finding/policy controls.
    monkeypatch.setattr(
        corpus_ci,
        "_scan_case",
        lambda *args, **kwargs: {
            "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
            "analysis_errors": [],
        },
    )
    result = corpus_ci.run_case(case, MANIFEST)
    failed = {
        (failure["category"], failure["expected"])
        for failure in result["failures"]
        if failure["mode"] == "present"
    }
    assert failed >= {
        (category, symbol)
        for category, symbols in CONTROLS[case_id].items()
        for symbol in symbols
    }
    assert not any(failure["mode"] == "absent" for failure in result["failures"])


@pytest.mark.parametrize(
    "case_id, symbol, category",
    [
        ("click-command-subclass", "format_arguments", "dead_code_abstentions"),
        ("pydantic-computed-field", "compose_name", "dead_code_abstentions"),
        ("python-unittest-lifecycle", "prepare_record", "whitelisted"),
    ],
)
def test_policy_controls_are_separate_from_reported_unused_symbols(
    case_id, symbol, category
):
    case = _case(case_id)
    assert symbol in case["expect"]["present"][category]
    assert symbol in case["expect"]["absent"]["unused_functions"]
    assert symbol not in case["expect"]["present"].get("unused_functions", [])
    assert any(
        names
        for name, names in case["expect"]["present"].items()
        if name.startswith("unused_")
    )


def test_quality_loop_pair_retains_a_positive_and_negative_contract():
    positive = _case("always-false-loop")
    negative = _case("runtime-dependent-loop")
    assert positive["expect"]["present"]["quality"] == ["SKY-UC001", "while_false"]
    assert negative["expect"]["absent"]["quality"] == ["SKY-UC001", "while_false"]
    assert negative["paired_with"] == positive["id"]
    assert positive["scan"]["enable_quality"] is True
    assert negative["scan"]["enable_quality"] is True


def test_model_use_boundary_keeps_unreferenced_sibling_controls(monkeypatch):
    case = _case("pydantic-model-use-boundary")
    assert case["expect"]["absent"]["unused_classes"] == [
        "ProfileModel",
        "RuntimeSettings",
    ]
    assert case["expect"]["present"]["unused_classes"] == [
        "DraftModel",
        "DraftSettings",
    ]
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = corpus_ci.run_case(case, MANIFEST)
    assert result["analysis_status"] == "complete"
    assert result["analyzed_source_count"] == 1
    assert result["failures"] == []
