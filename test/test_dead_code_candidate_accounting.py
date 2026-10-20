"""Reported candidate accounting must agree with supported output kinds."""

import json
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.dead_code_result import dead_code_candidate_decisions
from skylos.reporting.result_builder import _bucket_unused_definitions
from skylos.visitors.base import Definition


@pytest.mark.parametrize(
    "kind, bucket",
    [
        ("function", "unused_functions"),
        ("method", "unused_functions"),
        ("class", "unused_classes"),
        ("type", "unused_classes"),
        ("import", "unused_imports"),
        ("variable", "unused_variables"),
        ("constant", "unused_variables"),
        ("parameter", "unused_parameters"),
    ],
)
def test_supported_candidate_has_output_bucket(tmp_path, kind, bucket):
    definition = Definition("module.candidate", kind, tmp_path / "module.py", 1)
    analyzer = SimpleNamespace(defs={"candidate": definition})
    reported, rescued, abstained = dead_code_candidate_decisions(analyzer, 60, {})
    assert len(reported) == 1
    assert rescued == []
    assert abstained == []
    output = {bucket: []}
    _bucket_unused_definitions(output, reported)
    assert output[bucket] == reported


@pytest.mark.parametrize("kind", ["lambda", "synthetic_scope", "future_kind"])
def test_internal_node_without_output_kind_is_not_reported(tmp_path, kind):
    definition = Definition("module.internal", kind, tmp_path / "module.py", 1)
    analyzer = SimpleNamespace(defs={"internal": definition})
    assert dead_code_candidate_decisions(analyzer, 60, {}) == ([], [], [])
    # Candidate accounting does not mutate the graph or invent liveness.
    assert analyzer.defs["internal"] is definition
    assert definition.references == 0


@pytest.mark.parametrize(
    "source",
    [
        "result = sorted([3, 1], key=lambda item: item)\n",
        "def factory():\n    return lambda item: item + 1\nresult = factory()(1)\n",
        "def apply(callback):\n    return callback(1)\n"
        "result = apply(lambda item: item + 1)\n",
    ],
)
def test_used_lambda_does_not_inflate_reported_count(tmp_path, source):
    source += "\ndef unused_helper():\n    return 42\n"
    assert write_text_no_symlink(tmp_path / "app.py", source)
    output = json.loads(analyze(str(tmp_path), grep_verify=False, trace_file=False))
    emitted = []
    for bucket in (
        "unused_functions",
        "unused_classes",
        "unused_imports",
        "unused_variables",
        "unused_parameters",
    ):
        emitted.extend(output.get(bucket, []))
    decisions = output["analysis_summary"]["dead_code_evidence"]["candidate_decisions"]
    assert decisions["reported"] == len(emitted)
    assert any(item["name"] == "unused_helper" for item in emitted)
    assert all(item["type"] != "lambda" for item in emitted)
