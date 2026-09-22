"""Paid Jev benchmark safety and resumability tests (no live requests)."""

import copy
from pathlib import Path

import pytest
import requests

from skylos.benchmarks import _jev_dead_code_report as report_module
from skylos.benchmarks._jev_dead_code_dataset import _digest
from skylos.benchmarks.jev_dead_code import (
    JEV_MODEL,
    JevBenchmarkError,
    MAX_RESPONSE_BYTES,
    format_report,
    request_jev,
    run_jev_manifest,
)


MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/dead_code/manifest.json"
CASE = {"basic-unused-symbols"}


def _answer():
    return {
        "type": "choice",
        "choice": "retained",
        "confidence": 0.8,
        "probabilities": {
            "retained": 0.8,
            "unreferenced": 0.1,
            "insufficient_evidence": 0.1,
        },
    }


def _transport(calls):
    def send(payload, _key):
        calls.append(payload)
        return {
            "model": JEV_MODEL,
            "answers": {question_id: _answer() for question_id in payload["questions"]},
            "usage": {"input_tokens": 100, "output_tokens": 10},
        }

    return send


def _run(**kwargs):
    return run_jev_manifest(
        MANIFEST,
        api_key="injected-test-key",
        selected_cases=CASE,
        **kwargs,
    )


def _resign(report):
    report["report_digest"] = _digest(
        {key: value for key, value in report.items() if key != "report_digest"}
    )


def test_checkpoints_use_prepared_manifest_snapshot(monkeypatch):
    calls = []

    def unexpected(_path):
        raise AssertionError("report must not reread the manifest")

    monkeypatch.setattr(report_module, "manifest_digest", unexpected)
    monkeypatch.setattr(report_module, "manifest_metadata", unexpected)
    checkpoints = []
    result = _run(transport=_transport(calls), checkpoint=checkpoints.append)

    assert len(calls) == 2
    assert result["schema_version"] == 2
    assert result["manifest_digest"] == checkpoints[0]["manifest_digest"]
    assert result["prompt_digest"] == checkpoints[0]["prompt_digest"]
    assert len(result["planned_requests"]) == 2
    assert (
        result["planned_requests"][0]["request_digest"]
        == result["batches"][0]["request_digest"]
    )


def test_budgeted_run_resumes_only_matching_successful_batch():
    calls = []
    partial = _run(transport=_transport(calls), max_new_requests=1)
    assert partial["status"] == "incomplete"
    assert len(calls) == 1
    assert partial["completed_request_count"] == 1

    resumed_calls = []
    resumed = _run(transport=_transport(resumed_calls), resume_report=partial)
    assert resumed["status"] == "complete"
    assert len(resumed_calls) == 1
    assert resumed["batches"][0] == partial["batches"][0]
    assert resumed["usage"] == {"input_tokens": 200, "output_tokens": 20}


def test_omitted_neutralization_is_not_paid_or_counted_as_a_pair():
    calls = []
    report = run_jev_manifest(
        MANIFEST,
        api_key="injected-test-key",
        selected_cases={"fastapi-route-used"},
        transport=_transport(calls),
    )

    assert len(calls) == 1
    assert report["planned_request_count"] == 1
    assert report["neutralization"] == {
        "applied": 0,
        "skipped": 1,
        "not_applicable": 0,
    }
    assert report["summary"]["arms"]["neutralized"]["decision_count"] == 0
    assert report["summary"]["paired"] == {
        "pair_count": 0,
        "unpaired_original_count": 3,
        "same_decision_count": 0,
        "decision_consistency": None,
    }
    assert "not measured (no completed pairs)" in format_report(report)
    assert "omitted=1" in format_report(report)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda value: value.update(schema_version=99), "schema"),
        (lambda value: value.update(requested_model="jev-latest"), "provenance"),
        (lambda value: value.update(endpoint="https://other.invalid"), "provenance"),
        (lambda value: value.update(prompt_digest="wrong"), "provenance"),
        (lambda value: value.update(manifest_digest="wrong"), "provenance"),
        (
            lambda value: value["planned_requests"][1].update(request_digest="wrong"),
            "provenance",
        ),
        (
            lambda value: value["batches"][0]["predictions"][0].update(expected="used"),
            "prediction identity",
        ),
    ],
)
def test_resume_rejects_mismatches_before_network(change, message):
    partial = _run(transport=_transport([]), max_new_requests=1)
    tampered = copy.deepcopy(partial)
    change(tampered)
    _resign(tampered)
    calls = []
    with pytest.raises(JevBenchmarkError, match=message):
        _run(transport=_transport(calls), resume_report=tampered)
    assert calls == []


def test_resume_rejects_corrupted_digest_before_network():
    partial = _run(transport=_transport([]), max_new_requests=1)
    partial["requested_model"] = "jev-latest"
    calls = []
    with pytest.raises(JevBenchmarkError, match="digest"):
        _run(transport=_transport(calls), resume_report=partial)
    assert calls == []


def test_final_failed_batch_is_retried_not_reused():
    def bad(_payload, _key):
        return {"model": JEV_MODEL, "answers": {}, "usage": {}}

    failed = _run(transport=bad)
    assert failed["status"] == "incomplete"
    assert failed["batches"][0]["status"] == "error"
    calls = []
    recovered = _run(transport=_transport(calls), resume_report=failed)
    assert recovered["status"] == "complete"
    assert len(calls) == 2


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_request_budget_must_be_positive_integer(limit):
    with pytest.raises(JevBenchmarkError, match="positive integer"):
        _run(transport=_transport([]), max_new_requests=limit)


def test_expected_digests_are_enforced_before_network():
    calls = []
    with pytest.raises(JevBenchmarkError, match="manifest digest"):
        _run(transport=_transport(calls), expected_manifest_digest="wrong")
    with pytest.raises(JevBenchmarkError, match="prompt digest"):
        _run(transport=_transport(calls), expected_prompt_digest="wrong")
    assert calls == []


def test_http_response_limit_is_enforced_during_streaming(monkeypatch):
    observed = {"chunks": 0, "closed": False}

    class FakeResponse:
        status_code = 200
        headers = {}

        def iter_content(self, **_kwargs):
            for _ in range(100):
                observed["chunks"] += 1
                yield b"x" * 64_000

        @property
        def content(self):
            raise AssertionError("response.content must not be accessed")

        def close(self):
            observed["closed"] = True

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **kwargs):
            assert kwargs["stream"] is True
            return FakeResponse()

    monkeypatch.setattr(requests, "Session", FakeSession)
    with pytest.raises(JevBenchmarkError, match="size limit"):
        request_jev({"model": JEV_MODEL}, "secret")
    assert observed["chunks"] == MAX_RESPONSE_BYTES // 64_000 + 1
    assert observed["closed"] is True


def test_ambiguous_network_failure_is_not_retried(monkeypatch):
    calls = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, _url, **_kwargs):
            calls.append(1)
            raise requests.Timeout("may have reached the service")

    monkeypatch.setattr(requests, "Session", FakeSession)
    with pytest.raises(JevBenchmarkError, match="network error"):
        request_jev({"model": JEV_MODEL}, "secret")
    assert len(calls) == 1
