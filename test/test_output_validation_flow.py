"""Regression cases for validation of individual Python LLM outputs.

The fixtures are parsed as source by Skylos; none of the sample applications run.
"""

from textwrap import dedent

import pytest

from skylos.defend.plugins.output_validation import OutputValidationPlugin
from skylos.discover.detector import detect_integrations
from skylos.discover.graph import NodeType


def _checks(tmp_path, body: str):
    source = "import json\nimport openai\n\n" + dedent(body)
    (tmp_path / "app.py").write_text(source)
    integrations, graph = detect_integrations(tmp_path)
    plugin = OutputValidationPlugin()
    return integrations, [
        plugin.check(integration, graph) for integration in integrations
    ]


_CREATE_CALL = """client.chat.completions.create(
        model="gpt-4o-2024-05-13", messages=[{"role": "user", "content": "json"}]
    )"""


def test_graph_links_only_validation_of_the_discovered_response(tmp_path):
    (tmp_path / "app.py").write_text(
        "import json\nimport openai\n\n"
        + dedent(
            f"""
def answer(client, unrelated):
    response = {_CREATE_CALL}
    json.loads(unrelated)
    return response.choices[0].message.content
"""
        )
    )
    integrations, graph = detect_integrations(tmp_path)

    assert len(integrations) == 1
    assert integrations[0].has_output_validation is True
    assert integrations[0].output_flow_status == "unvalidated"
    assert graph.get_nodes_by_type(NodeType.VALIDATION) == []


def test_json_object_get_preserves_structural_validation(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    response = {_CREATE_CALL}
    parsed = json.loads(response.choices[0].message.content)
    return parsed.get("answer")
""",
    )

    assert integrations[0].output_flow_status == "validated"
    assert checks[0].passed is True


def test_json_object_get_with_raw_default_is_not_proven_validated(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed.get("answer", raw)
""",
        )
    )


def test_parsed_output_returned_is_proven_validated(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed
""",
    )

    assert len(integrations) == 1
    assert integrations[0].output_flow_status == "validated"
    assert any(
        evidence.status == "validated"
        and evidence.source_location == integrations[0].location
        and evidence.validation_location
        and evidence.use_location
        and evidence.path[0] == evidence.source_location
        and evidence.path[-1] == evidence.use_location
        for evidence in integrations[0].output_flow_evidence
    )
    assert checks[0].passed is True
    assert checks[0].location in {
        evidence.validation_location
        for evidence in integrations[0].output_flow_evidence
        if evidence.status == "validated"
    }


@pytest.mark.parametrize(
    "body",
    [
        # A validator in the same function proves nothing about the LLM value.
        f"""
def answer(client, config):
    response = {_CREATE_CALL}
    json.loads(config)
    return response.choices[0].message.content
""",
        # A check after the raw value has already been consumed comes too late.
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    print(raw)
    json.loads(raw)
""",
        # Parsing a value and discarding the parsed result leaves raw unvalidated.
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    json.loads(raw)
    return raw
""",
        # There is an executable path that returns the original raw string.
        f"""
def answer(client, strict):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    if strict:
        result = json.loads(raw)
    else:
        result = raw
    return result
""",
    ],
    ids=[
        "unrelated-validator",
        "validation-after-use",
        "ignored-return",
        "branch-bypass",
    ],
)
def test_validation_must_protect_the_used_value_on_every_path(tmp_path, body):
    integrations, checks = _checks(tmp_path, body)

    assert len(integrations) == 1
    assert integrations[0].output_flow_status == "unvalidated"
    assert any(
        evidence.status == "unvalidated"
        and evidence.source_location == integrations[0].location
        and evidence.use_location
        and evidence.path[0] == evidence.source_location
        and evidence.path[-1] == evidence.use_location
        for evidence in integrations[0].output_flow_evidence
    )
    assert checks[0].passed is False
    assert checks[0].location in {
        evidence.use_location
        for evidence in integrations[0].output_flow_evidence
        if evidence.status == "unvalidated"
    }


def test_two_calls_in_one_function_get_independent_validation_decisions(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    first = {_CREATE_CALL}
    parsed = json.loads(first.choices[0].message.content)
    second = {_CREATE_CALL}
    return parsed, second.choices[0].message.content
""",
    )

    assert len(integrations) == 2
    assert [i.output_flow_status for i in integrations] == ["validated", "unvalidated"]
    assert [check.passed for check in checks] == [True, False]


def test_unresolved_helper_cannot_prove_validation(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    normalized = normalize(raw)
    return normalized
""",
    )

    assert len(integrations) == 1
    assert integrations[0].output_flow_status == "unknown"
    assert any(
        evidence.status == "unknown"
        and evidence.source_location == integrations[0].location
        and evidence.use_location
        and evidence.reason
        and evidence.path[0] == evidence.source_location
        and evidence.path[-1] == evidence.use_location
        for evidence in integrations[0].output_flow_evidence
    )
    assert checks[0].passed is False
    assert checks[0].location in {
        evidence.use_location
        for evidence in integrations[0].output_flow_evidence
        if evidence.status == "unknown"
    }
    assert (
        "uncertain" in checks[0].message.lower()
        or "unknown" in checks[0].message.lower()
    )


def test_json_parsing_does_not_make_shell_execution_safe(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
import subprocess

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    subprocess.run(parsed["cmd"], shell=True)
""",
    )

    assert len(integrations) == 1
    assert integrations[0].output_flow_status == "unvalidated"
    assert any(
        evidence.status == "unvalidated"
        and evidence.source_location == integrations[0].location
        and evidence.use_location
        and ("subprocess" in evidence.reason or "shell" in evidence.reason)
        and evidence.path[0] == evidence.source_location
        and evidence.path[-1] == evidence.use_location
        for evidence in integrations[0].output_flow_evidence
    )
    assert checks[0].passed is False
    assert checks[0].location in {
        evidence.use_location
        for evidence in integrations[0].output_flow_evidence
        if evidence.status == "unvalidated"
    }


def test_local_alias_to_shell_sink_still_requires_sink_specific_guard(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
import subprocess

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    runner = subprocess.run
    runner(parsed["cmd"], shell=True)
""",
    )

    assert len(integrations) == 1
    assert integrations[0].output_flow_status == "unvalidated"
    assert any(
        evidence.status == "unvalidated"
        and evidence.use_location
        and ("subprocess" in evidence.reason or "shell" in evidence.reason)
        for evidence in integrations[0].output_flow_evidence
    )
    assert checks[0].passed is False


def _assert_not_proven_validated(integrations, checks):
    assert len(integrations) == 1
    integration = integrations[0]
    check = checks[0]
    assert integration.output_flow_status in {"unvalidated", "unknown"}
    assert check.passed is False
    assert any(
        evidence.status in {"unvalidated", "unknown"}
        and evidence.source_location == integration.location
        and evidence.use_location
        and evidence.path[0] == evidence.source_location
        and evidence.path[-1] == evidence.use_location
        for evidence in integration.output_flow_evidence
    )
    assert check.location in {
        evidence.use_location
        for evidence in integration.output_flow_evidence
        if evidence.status in {"unvalidated", "unknown"}
    }


@pytest.mark.parametrize(
    "body",
    [
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    sent = consume(raw)
    return json.loads(raw)
""",
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    if consume(raw):
        pass
    return json.loads(raw)
""",
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    if raw == "approved":
        pass
    return json.loads(raw)
""",
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    [consume(raw) for _ in range(1)]
    return json.loads(raw)
""",
    ],
    ids=[
        "assigned-call-before-validation",
        "condition-call-before-validation",
        "raw-comparison-before-validation",
        "comprehension-call-before-validation",
    ],
)
def test_early_uses_are_not_covered_by_later_validation(tmp_path, body):
    _assert_not_proven_validated(*_checks(tmp_path, body))


def test_pydantic_model_parameter_shadowing_cannot_prove_schema_check(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
from pydantic import BaseModel

class Reply(BaseModel):
    answer: str

def answer(client, Reply):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = Reply.model_validate_json(raw)
    return parsed
""",
        )
    )


def test_builtins_eval_alias_is_still_a_dangerous_sink(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
import builtins

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    run = builtins.eval
    run(parsed)
""",
    )

    _assert_not_proven_validated(integrations, checks)
    assert integrations[0].output_flow_status == "unvalidated"
    assert any(
        "eval" in evidence.reason
        for evidence in integrations[0].output_flow_evidence
        if evidence.status == "unvalidated"
    )


def test_json_loads_custom_decoder_cannot_prove_validation(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
class IdentityDecoder(json.JSONDecoder):
    def decode(self, value):
        return value

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw, cls=IdentityDecoder)
    return parsed
""",
        )
    )


@pytest.mark.parametrize(
    "body",
    [
        f"""
def answer(client, parser):
    json = parser
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed
""",
        f"""
def identity(value):
    return value

def answer(client):
    json.loads = identity
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed
""",
    ],
    ids=["module-name-rebound", "parser-method-monkeypatched"],
)
def test_replaced_parser_cannot_prove_validation(tmp_path, body):
    _assert_not_proven_validated(*_checks(tmp_path, body))


def test_indexing_a_pair_does_not_validate_both_llm_outputs(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    first = {_CREATE_CALL}
    second = {_CREATE_CALL}
    raw_a = first.choices[0].message.content
    raw_b = second.choices[0].message.content
    pair = (raw_a, raw_b)
    consume(json.loads(pair[0]))
""",
    )

    assert len(integrations) == 2
    assert integrations[1].output_flow_status in {"unvalidated", "unknown"}
    assert checks[1].passed is False
    assert all(
        evidence.status != "validated"
        for evidence in integrations[1].output_flow_evidence
    )


def test_called_nested_closure_using_raw_output_prevents_a_false_pass(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    def leak():
        consume(raw)
    leak()
    return json.loads(raw)
""",
    )

    _assert_not_proven_validated(integrations, checks)


@pytest.mark.parametrize(
    "condition",
    ["consume(raw)", "raw"],
    ids=["call-receives-raw", "raw-truthiness"],
)
def test_ternary_condition_uses_raw_before_both_parsed_branches(tmp_path, condition):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw) if {condition} else json.loads(raw)
    consume(parsed)
""",
    )

    _assert_not_proven_validated(integrations, checks)


@pytest.mark.parametrize(
    "early_use",
    [
        "ignored = [item for item in consume(raw)]",
        "selected = mapping[raw]",
        "yield raw",
        "yield from raw",
    ],
    ids=[
        "comprehension-iterable",
        "subscript-index",
        "yield-value",
        "yield-from-value",
    ],
)
def test_less_obvious_raw_uses_prevent_later_validation_pass(tmp_path, early_use):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client, mapping):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    {early_use}
    parsed = json.loads(raw)
    consume(parsed)
""",
    )

    _assert_not_proven_validated(integrations, checks)


def test_local_json_module_is_not_trusted_as_standard_library_parser(tmp_path):
    # A local json.py can shadow the standard-library module for this application.
    (tmp_path / "json.py").write_text("def loads(value):\n    return value\n")
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed
""",
        )
    )


def test_assignment_override_of_pydantic_model_validator_is_not_trusted(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
from pydantic import BaseModel

class Reply(BaseModel):
    answer: str

def identity(value):
    return value

Reply.model_validate = identity

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = Reply.model_validate(raw)
    return parsed
""",
        )
    )


def test_type_adapter_any_validate_python_cannot_prove_validation(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
from typing import Any
from pydantic import TypeAdapter

def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = TypeAdapter(Any).validate_python(raw)
    return parsed
""",
        )
    )


@pytest.mark.parametrize(
    "alias_assignment",
    [
        "runner = builtins.eval if choose else print",
        "runner, unused = (builtins.eval, print)",
    ],
    ids=["conditional-alias", "tuple-destructured-alias"],
)
def test_eval_alias_shapes_cannot_get_a_validated_pass(tmp_path, alias_assignment):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
import builtins

def answer(client, choose):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    {alias_assignment}
    runner(parsed)
""",
        )
    )


def test_single_source_container_index_preserves_early_raw_use(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    values = [raw]
    consume(values[0])
    return json.loads(raw)
""",
        )
    )


def test_tuple_unpacking_keeps_llm_sources_separate(tmp_path):
    integrations, checks = _checks(
        tmp_path,
        f"""
def answer(client):
    first = {_CREATE_CALL}
    second = {_CREATE_CALL}
    pair = (
        first.choices[0].message.content,
        second.choices[0].message.content,
    )
    raw_a, raw_b = pair
    consume(json.loads(raw_a))
""",
    )

    assert len(integrations) == 2
    assert integrations[1].output_flow_status in {"unvalidated", "unknown"}
    assert checks[1].passed is False
    assert all(
        evidence.status != "validated"
        for evidence in integrations[1].output_flow_evidence
    )


@pytest.mark.parametrize(
    "mutation",
    [
        """
    runner = print
    for item in items:
        runner = builtins.eval
""",
        """
    runner = print
    def switch():
        nonlocal runner
        runner = builtins.eval
    switch()
""",
    ],
    ids=["unsupported-loop-rebind", "nested-nonlocal-rebind"],
)
def test_alias_rebinding_cannot_leave_a_stale_safe_identity(tmp_path, mutation):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
import builtins

def answer(client, items):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
{mutation}    runner(parsed)
""",
        )
    )


def test_parser_module_alias_mutation_invalidates_trusted_loads(tmp_path):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client):
    alias = json
    alias.loads = lambda value: value
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    return parsed
""",
        )
    )


@pytest.mark.parametrize(
    "alias_assignment",
    [
        "runner = eval if choose else print",
        "runner, unused = (eval, print)",
    ],
    ids=["conditional-bare-eval", "destructured-bare-eval"],
)
def test_bare_eval_alias_shapes_cannot_get_a_validated_pass(tmp_path, alias_assignment):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client, choose):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
    parsed = json.loads(raw)
    {alias_assignment}
    runner(parsed)
""",
        )
    )


@pytest.mark.parametrize(
    "nested_definition",
    [
        """
    def nested(value=raw):
        return value
""",
        """
    @decorate(raw)
    def nested():
        pass
""",
    ],
    ids=["default-captures-raw", "decorator-receives-raw"],
)
def test_nested_definition_uses_raw_before_later_parse(tmp_path, nested_definition):
    _assert_not_proven_validated(
        *_checks(
            tmp_path,
            f"""
def answer(client):
    response = {_CREATE_CALL}
    raw = response.choices[0].message.content
{nested_definition}    return json.loads(raw)
""",
        )
    )
