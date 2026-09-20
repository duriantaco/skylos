import json
from pathlib import Path

import pytest

from skylos.benchmarks.jev_dead_code import (
    CHOICES,
    JEV_ENDPOINT,
    JEV_MODEL,
    JevBenchmarkError,
    build_plan,
    prepare_batches,
    request_jev,
    run_jev_manifest,
    score_predictions,
    validate_response,
)
from skylos.core.safe_cache_io import write_text_no_symlink


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "benchmarks" / "dead_code" / "manifest.json"


def _golden_manifest(tmp_path, *, label_state="frozen", coverage="closed"):
    source = tmp_path / "corpora" / "sample"
    manifests = tmp_path / "manifests"
    source.mkdir(parents=True)
    manifests.mkdir()
    assert write_text_no_symlink(
        source / "app.py",
        "class Worker:\n    def run(self):\n        return 1\n\n"
        "class Retired:\n    def run(self):\n        return 2\n\n"
        "Worker().run()\n",
    )
    manifest = {
        "schema_version": "skylos-golden-benchmark/v1",
        "suite": "dead_code",
        "split": "dev",
        "label_state": label_state,
        "cases": [
            {
                "id": "golden-sample",
                "languages": ["python"],
                "label_coverage": coverage,
                "source": {"local_path": "corpora/sample"},
                "labels": [
                    {
                        "id": "gold-live-run",
                        "expectation": "should_not_report",
                        "category": "live_method",
                        "match": {"path": "app.py", "symbol": "run", "line": 2},
                        "review": {"reason": "GROUND TRUTH: definitely retained"},
                    },
                    {
                        "id": "gold-dead-run",
                        "expectation": "should_report",
                        "category": "unused_method",
                        "match": {"path": "app.py", "symbol": "run", "line": 6},
                        "review": {"reason": "GROUND TRUTH: definitely unused"},
                    },
                ],
            }
        ],
    }
    path = manifests / "dead_code.dev.json"
    assert write_text_no_symlink(path, json.dumps(manifest))
    return path


def _choice_answer(choice="retained", confidence=0.8):
    probabilities = {
        "retained": 0.8,
        "unreferenced": 0.1,
        "insufficient_evidence": 0.1,
    }
    if choice == "unreferenced":
        probabilities = {
            "retained": 0.1,
            "unreferenced": 0.8,
            "insufficient_evidence": 0.1,
        }
    if choice == "insufficient_evidence":
        probabilities = {
            "retained": 0.1,
            "unreferenced": 0.1,
            "insufficient_evidence": 0.8,
        }
    return {
        "type": "choice",
        "choice": choice,
        "probabilities": probabilities,
        "confidence": confidence,
    }


def _response(batch, choice="retained"):
    return {
        "model": JEV_MODEL,
        "answers": {
            question.question_id: _choice_answer(choice)
            for question in batch.questions
        },
        "usage": {"input_tokens": 100, "output_tokens": 10},
    }


def test_checked_in_ground_truth_builds_blind_two_arm_plan():
    plan = build_plan(MANIFEST_PATH)

    assert plan["network_used"] is False
    assert plan["case_count"] == 21
    assert plan["request_count"] == 42
    assert plan["ground_truth_count"] == 124
    assert plan["decision_count"] == 248
    assert plan["unused_count"] == 47
    assert plan["used_count"] == 77
    assert plan["model"] == "jev-1.13.0"
    assert plan["endpoint"] == JEV_ENDPOINT


def test_request_does_not_send_ground_truth_or_manifest_description():
    batch = prepare_batches(MANIFEST_PATH, {"basic-unused-symbols"})[0]
    serialized = json.dumps(batch.payload, sort_keys=True)

    assert '"expected"' not in serialized
    assert "Basic unused functions, classes, imports" not in serialized
    assert "ground_truth" not in serialized
    assert batch.payload["model"] == JEV_MODEL
    assert set(batch.payload["questions"]["q0001"]["criteria"]) == set(CHOICES)


def test_neutralized_arm_removes_obvious_identifier_label_signals():
    original, neutralized = prepare_batches(
        MANIFEST_PATH, {"basic-unused-symbols"}
    )
    original_state = json.dumps(original.payload["state"])
    neutralized_state = json.dumps(neutralized.payload["state"])

    assert original.arm == "original"
    assert neutralized.arm == "neutralized"
    assert "unused_helper" in original_state
    assert "unused_helper" not in neutralized_state
    assert "used_helper" not in neutralized_state
    assert "candidate_" in neutralized_state
    assert any(
        question.symbol == "unused_helper"
        and question.sent_symbol.startswith("candidate_")
        for question in neutralized.questions
    )


def test_framework_metadata_is_included_with_source_state():
    batch = prepare_batches(MANIFEST_PATH, {"java-fxml-controller-callbacks"})[0]
    paths = {item["path"] for item in batch.payload["state"]["repository_files"]}

    assert paths == {"PrintController.java", "view.fxml"}


def test_frozen_golden_manifest_is_blind_and_preserves_join_keys(tmp_path):
    manifest = _golden_manifest(tmp_path)
    plan = build_plan(manifest)
    batch = prepare_batches(manifest)[0]
    serialized = json.dumps(batch.payload, sort_keys=True)

    assert plan["manifest_metadata"] == {
        "format": "skylos-golden-benchmark/v1",
        "split": "dev",
        "label_state": "frozen",
    }
    assert plan["ground_truth_count"] == 2
    assert "GROUND TRUTH" not in serialized
    assert "gold-live-run" not in serialized
    assert "gold-dead-run" not in serialized
    assert {question.line for question in batch.questions} == {2, 6}
    assert {
        value["instructions"]["target"]["line"]
        for value in batch.payload["questions"].values()
    } == {2, 6}

    predictions, _usage = validate_response(_response(batch), batch)
    assert {item["label_id"] for item in predictions} == {
        "gold-live-run",
        "gold-dead-run",
    }


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"label_state": "draft"}, "labels must be frozen"),
        ({"coverage": "partial"}, "must have closed labels"),
    ],
)
def test_golden_manifest_requires_frozen_closed_ground_truth(
    tmp_path, kwargs, message
):
    manifest = _golden_manifest(tmp_path, **kwargs)

    with pytest.raises(JevBenchmarkError, match=message):
        build_plan(manifest)


def test_validate_response_records_probabilities_and_ground_truth_locally():
    batch = prepare_batches(MANIFEST_PATH, {"fastapi-route-used"})[0]
    predictions, usage = validate_response(_response(batch), batch)

    assert usage == {"input_tokens": 100, "output_tokens": 10}
    assert len(predictions) == 3
    assert {item["expected"] for item in predictions} == {"unused", "used"}
    assert {item["predicted"] for item in predictions} == {"used"}
    assert all(item["probabilities"]["retained"] == 0.8 for item in predictions)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda value: value.update(model="jev-latest"), "pinned request"),
        (lambda value: value["answers"].pop("q0001"), "match the request"),
        (
            lambda value: value["answers"]["q0001"]["probabilities"].pop(
                "insufficient_evidence"
            ),
            "requested choices",
        ),
        (
            lambda value: value["answers"]["q0001"].update(confidence=float("nan")),
            "between 0 and 1",
        ),
        (
            lambda value: value["answers"]["q0001"].update(choice="unreferenced"),
            "highest probability",
        ),
    ],
)
def test_validate_response_rejects_untrusted_response_shapes(mutate, message):
    batch = prepare_batches(MANIFEST_PATH, {"fastapi-route-used"})[0]
    response = _response(batch)
    mutate(response)

    with pytest.raises(JevBenchmarkError, match=message):
        validate_response(response, batch)


def test_live_runner_uses_injected_transport_and_never_persists_key():
    seen = []

    def fake_transport(payload, api_key):
        seen.append((payload, api_key))
        question_ids = payload["questions"]
        return {
            "model": JEV_MODEL,
            "answers": {
                question_id: _choice_answer() for question_id in question_ids
            },
            "usage": {"input_tokens": 100, "output_tokens": 10},
        }

    report = run_jev_manifest(
        MANIFEST_PATH,
        api_key="super-secret-key",
        selected_cases={"basic-unused-symbols"},
        transport=fake_transport,
    )

    assert report["status"] == "complete"
    assert len(seen) == 2
    assert all(api_key == "super-secret-key" for _payload, api_key in seen)
    assert "super-secret-key" not in json.dumps(report)
    assert report["source_stored_in_report"] is False
    assert report["ground_truth_sent_to_model"] is False
    assert report["usage"] == {"input_tokens": 200, "output_tokens": 20}
    assert report["latency"]["sample_count"] == 2
    assert report["latency"]["server_constrained_generation_isolated"] is False
    assert (
        report["latency"]["local_contract_validation_seconds"]["p95"]
        is not None
    )


def test_live_runner_stops_and_checkpoints_on_invalid_response():
    checkpoints = []
    calls = 0

    def bad_transport(payload, api_key):
        nonlocal calls
        calls += 1
        return {"model": JEV_MODEL, "answers": {}, "usage": {}}

    report = run_jev_manifest(
        MANIFEST_PATH,
        api_key="secret",
        selected_cases={"basic-unused-symbols"},
        transport=bad_transport,
        checkpoint=checkpoints.append,
    )

    assert calls == 1
    assert report["status"] == "incomplete"
    assert checkpoints[-1] == report
    assert report["batches"][0]["status"] == "error"
    assert "secret" not in json.dumps(report)


def test_threshold_scoring_abstains_before_any_removal_decision():
    predictions = [
        {
            "case_id": "a",
            "question_id": "q1",
            "arm": "original",
            "expected": "unused",
            "predicted": "unused",
            "confidence": 0.95,
            "probabilities": {
                "retained": 0.03,
                "unreferenced": 0.95,
                "insufficient_evidence": 0.02,
            },
        },
        {
            "case_id": "a",
            "question_id": "q2",
            "arm": "original",
            "expected": "used",
            "predicted": "unused",
            "confidence": 0.7,
            "probabilities": {
                "retained": 0.2,
                "unreferenced": 0.7,
                "insufficient_evidence": 0.1,
            },
        },
    ]

    summary = score_predictions(predictions)["arms"]["original"]
    at_08 = next(item for item in summary["thresholds"] if item["threshold"] == 0.8)

    assert at_08["coverage"] == 0.5
    assert at_08["unused_precision"] == 1.0
    assert at_08["unsafe_removal_count"] == 0
    assert at_08["abstentions"] == 1
    assert at_08["abstentions_by_expected"] == {"unused": 0, "used": 1}


def test_request_jev_requires_environment_supplied_key_before_network():
    with pytest.raises(JevBenchmarkError, match="TYPESAFE_API_KEY"):
        request_jev({"model": JEV_MODEL}, "")


def test_request_jev_uses_only_pinned_official_endpoint(monkeypatch):
    import requests

    observed = {}

    class FakeResponse:
        status_code = 200
        content = b'{"model":"jev-1.13.0"}'
        headers = {}

        def json(self):
            return {"model": JEV_MODEL}

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, **kwargs):
            observed["url"] = url
            observed.update(kwargs)
            return FakeResponse()

    monkeypatch.setattr(requests, "Session", FakeSession)
    payload = {"model": JEV_MODEL, "state": "fixture", "questions": {}}

    assert request_jev(payload, "secret") == {"model": JEV_MODEL}
    assert observed["url"] == "https://api.typesafe.ai/v1/systemone"
    assert observed["json"] == payload
    assert observed["allow_redirects"] is False
    assert observed["headers"]["Authorization"] == "Bearer secret"


def test_request_jev_error_does_not_echo_response_or_key(monkeypatch):
    import requests

    class FakeResponse:
        status_code = 401
        content = b'{"error":"secret-value"}'
        headers = {}

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(requests, "Session", FakeSession)

    with pytest.raises(JevBenchmarkError) as caught:
        request_jev({"model": JEV_MODEL}, "secret-value")

    assert str(caught.value) == "Jev API returned HTTP 401"
    assert "secret-value" not in str(caught.value)


def test_manifest_symlink_is_rejected(tmp_path):
    manifest_link = tmp_path / "manifest.json"
    manifest_link.symlink_to(MANIFEST_PATH)

    with pytest.raises(JevBenchmarkError, match="safely read"):
        build_plan(manifest_link)
