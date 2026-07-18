from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from skylos.agents.evaluation import (
    AgentBehaviorError,
    discover_behavior_contract,
    load_behavior_contract,
    load_behavior_observations,
    starter_behavior_contract_text,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text,
        encoding="utf-8",
    )
    return path


def test_starter_behavior_contract_loads(tmp_path):
    contract_path = _write(
        tmp_path / ".skylos" / "agent-test.yml",
        starter_behavior_contract_text(),
    )

    contract = load_behavior_contract(contract_path, project_root=tmp_path)

    assert contract.version == 1
    assert contract.agent.model == "agent-under-test"
    assert [scenario.scenario_id for scenario in contract.scenarios] == [
        "refund-tool-selection",
        "refund-final-answer",
        "dangerous-tool-denial",
    ]
    assert len(contract.source_digest) == 64
    assert contract.scenarios[0].expectation.assertion_count() == 4
    assert contract.scenarios[1].expectation.assertion_count() == 3


def test_contract_rejects_duplicate_yaml_mapping_keys(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  tools: []
  tools: []
scenarios:
  - id: safe
    prompt: hello
    expect:
      response:
        contains: [hello]
""",
    )

    with pytest.raises(AgentBehaviorError, match="Duplicate contract mapping key"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_repo_controlled_auth_environment(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  endpoint: http://127.0.0.1:8000/v1/chat/completions
  model: test
  auth_env: AWS_SECRET_ACCESS_KEY
scenarios:
  - id: safe
    prompt: hello
    expect:
      response:
        contains: [hello]
""",
    )

    with pytest.raises(AgentBehaviorError, match="agent.auth_env"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_unknown_scenario_tool(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  tools:
    - name: known_tool
      description: Known
      parameters: {type: object}
scenarios:
  - id: unknown-tool
    prompt: hello
    available_tools: [invented_tool]
    expect:
      tools:
        max_calls: 0
""",
    )

    with pytest.raises(AgentBehaviorError, match="unknown tools"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_unknown_or_duplicate_capabilities(tmp_path):
    unknown_path = _write(
        tmp_path / "unknown.yml",
        """version: 1
agent:
  capabilities: [chat, teleport]
scenarios:
  - id: safe
    prompt: hello
    expect: {response: {contains: [hello]}}
""",
    )
    duplicate_path = _write(
        tmp_path / "duplicate.yml",
        """version: 1
agent:
  capabilities: [chat, chat]
scenarios:
  - id: safe
    prompt: hello
    expect: {response: {contains: [hello]}}
""",
    )

    with pytest.raises(AgentBehaviorError, match="unsupported values"):
        load_behavior_contract(unknown_path, project_root=tmp_path)
    with pytest.raises(AgentBehaviorError, match="Duplicate agent capability"):
        load_behavior_contract(duplicate_path, project_root=tmp_path)


def test_contract_rejects_empty_expectation(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent: {}
scenarios:
  - id: empty
    prompt: hello
    expect: {}
""",
    )

    with pytest.raises(AgentBehaviorError, match="at least one assertion"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_non_finite_timeout(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  timeout_seconds: .nan
scenarios:
  - id: safe
    prompt: hello
    expect: {response: {contains: [hello]}}
""",
    )

    with pytest.raises(AgentBehaviorError, match="timeout_seconds must be finite"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_conflicting_tool_rules(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent: {}
scenarios:
  - id: conflict
    prompt: hello
    expect:
      tools:
        required: [delete_database]
        forbidden: [delete_database]
""",
    )

    with pytest.raises(AgentBehaviorError, match="require and forbid"):
        load_behavior_contract(contract_path, project_root=tmp_path)


@pytest.mark.parametrize(
    "expectation, message",
    [
        (
            """response:
        contains: [same]
        excludes: [same]""",
            "contain and exclude",
        ),
        (
            """tools:
        allowed: [lookup]
        forbidden: [lookup]""",
            "allow and forbid",
        ),
        (
            """tools:
        exact_sequence: [lookup]
        forbidden: [lookup]""",
            "sequence and forbid",
        ),
        (
            """tools:
        required: [lookup]
        max_calls: 0""",
            "max_calls cannot be less than required",
        ),
        (
            """tools:
        exact_sequence: [lookup, lookup]
        max_calls: 1""",
            "max_calls cannot be less than exact_sequence",
        ),
        (
            """tools:
        required: [lookup, lookup]
        exact_sequence: [lookup]
        max_calls: 2""",
            "required tools are missing from exact_sequence",
        ),
    ],
)
def test_contract_rejects_contradictory_expectations(
    tmp_path,
    expectation,
    message,
):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        f"""version: 1
agent: {{}}
scenarios:
  - id: conflict
    prompt: hello
    expect:
      {expectation}
""",
    )

    with pytest.raises(AgentBehaviorError, match=message):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_required_tool_unavailable_to_scenario(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  tools:
    - name: lookup
      description: Lookup
      parameters: {type: object}
scenarios:
  - id: unavailable
    prompt: hello
    available_tools: []
    expect:
      tools:
        required: [lookup]
""",
    )

    with pytest.raises(AgentBehaviorError, match="unavailable to the scenario"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_excessive_assertion_volume(tmp_path):
    assertions = "\n".join(f"          - value-{index}" for index in range(251))
    contract_path = _write(
        tmp_path / "agent-test.yml",
        f"""version: 1
agent: {{}}
scenarios:
  - id: excessive
    prompt: hello
    expect:
      response:
        contains:
{assertions}
""",
    )

    with pytest.raises(AgentBehaviorError, match="assertions cannot exceed 250"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_recursive_yaml_alias(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent: {}
scenarios: &scenarios
  - id: recursive
    prompt: hello
    expect:
      response:
        contains: [hello]
    recursive: *scenarios
""",
    )

    with pytest.raises(AgentBehaviorError, match="YAML alias"):
        load_behavior_contract(contract_path, project_root=tmp_path)


def test_contract_rejects_shared_yaml_alias_amplification(tmp_path):
    contract_path = _write(
        tmp_path / "agent-test.yml",
        """version: 1
agent:
  tools:
    - name: lookup
      description: Lookup
      parameters:
        type: object
        shared: &shared
          - one
          - two
        expanded:
          - *shared
          - *shared
scenarios:
  - id: safe
    prompt: hello
    expect:
      tools:
        max_calls: 0
""",
    )

    with pytest.raises(AgentBehaviorError, match="YAML alias"):
        load_behavior_contract(contract_path, project_root=tmp_path)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink not supported")
def test_contract_rejects_symlink(tmp_path):
    target = _write(tmp_path / "real.yml", starter_behavior_contract_text())
    link = tmp_path / "agent-test.yml"
    os.symlink(target, link)

    with pytest.raises(AgentBehaviorError, match="must not be a symlink"):
        load_behavior_contract(link, project_root=tmp_path)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink not supported")
def test_contract_rejects_symlink_parent_directory(tmp_path):
    real_directory = tmp_path / "real"
    contract_path = _write(
        real_directory / "agent-test.yml",
        starter_behavior_contract_text(),
    )
    linked_directory = tmp_path / "linked"
    os.symlink(real_directory, linked_directory)

    with pytest.raises(AgentBehaviorError, match="symlink parent directories"):
        load_behavior_contract(
            linked_directory / contract_path.name,
            project_root=tmp_path,
        )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink not supported")
def test_contract_dirfd_read_rejects_symlink_parent_after_precheck(
    tmp_path,
    monkeypatch,
):
    real_directory = tmp_path / "real"
    contract_path = _write(
        real_directory / "agent-test.yml",
        starter_behavior_contract_text(),
    )
    linked_directory = tmp_path / "linked"
    os.symlink(real_directory, linked_directory)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)

    with pytest.raises(AgentBehaviorError, match="regular non-symlink file"):
        load_behavior_contract(
            linked_directory / contract_path.name,
            project_root=tmp_path,
        )


def test_discover_behavior_contract_walks_to_project_root(tmp_path):
    contract_path = _write(
        tmp_path / ".skylos" / "agent-test.yml",
        starter_behavior_contract_text(),
    )
    nested = tmp_path / "apps" / "api"
    nested.mkdir(parents=True)

    assert discover_behavior_contract(nested) == contract_path


def test_observations_preserve_missing_and_explicit_empty_evidence(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {"id": "missing", "response": "hello"},
                    {
                        "id": "empty",
                        "response": "hello",
                        "tool_calls": [],
                        "refusal": False,
                        "sources": [],
                    },
                ],
            }
        ),
    )

    observations = load_behavior_observations(
        observation_path,
        project_root=tmp_path,
    )

    assert observations["missing"].tool_calls is None
    assert observations["missing"].refusal is None
    assert observations["missing"].sources is None
    assert observations["missing"].response_complete is None
    assert observations["missing"].tool_calls_complete is None
    assert observations["empty"].tool_calls == ()
    assert observations["empty"].refusal is False
    assert observations["empty"].sources == ()


def test_observations_parse_tool_arguments_and_source_objects(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {
                        "id": "refund",
                        "tool_calls": [
                            {
                                "name": "lookup_refund_policy",
                                "arguments": {"policy_id": "refund-policy-v3"},
                            }
                        ],
                        "sources": [
                            {"id": "refund-policy-v3"},
                            {"source": "faq-v2"},
                        ],
                    }
                ],
            }
        ),
    )

    observation = load_behavior_observations(
        observation_path,
        project_root=tmp_path,
    )["refund"]

    assert observation.tool_calls is not None
    assert observation.tool_calls[0].arguments == {"policy_id": "refund-policy-v3"}
    assert observation.sources == ("refund-policy-v3", "faq-v2")


def test_observations_reject_excessive_tool_call_evidence(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {
                        "id": "too-many-calls",
                        "tool_calls": [
                            {"name": "lookup", "arguments": {}} for _ in range(251)
                        ],
                    }
                ],
            }
        ),
    )

    with pytest.raises(AgentBehaviorError, match="tool_calls cannot exceed 250"):
        load_behavior_observations(observation_path, project_root=tmp_path)


def test_observation_rejects_duplicate_scenario_ids(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        '{"version": 1, "scenarios": [{"id": "same"}, {"id": "same"}]}',
    )

    with pytest.raises(AgentBehaviorError, match="Duplicate observation scenario id"):
        load_behavior_observations(observation_path, project_root=tmp_path)


def test_observations_reject_duplicate_json_mapping_keys(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        '{"version": 1, "version": 1, "scenarios": []}',
    )

    with pytest.raises(AgentBehaviorError, match="Duplicate observation mapping key"):
        load_behavior_observations(observation_path, project_root=tmp_path)


def test_observations_reject_excessive_json_nesting_without_crashing(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        "[" * 10_000 + "0" + "]" * 10_000,
    )

    with pytest.raises(AgentBehaviorError, match="Invalid observation JSON"):
        load_behavior_observations(observation_path, project_root=tmp_path)


def test_observation_file_carries_source_provenance(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        '{"version": 1, "scenarios": [{"id": "safe"}]}',
    )

    observations = load_behavior_observations(
        observation_path,
        project_root=tmp_path,
    )

    assert observations.path == observation_path
    assert observations.version == 1
    assert len(observations.source_digest) == 64


def test_observation_rejects_finish_reason_completion_conflict(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {
                        "id": "truncated",
                        "response_complete": True,
                        "finish_reason": "length",
                    }
                ],
            }
        ),
    )

    with pytest.raises(AgentBehaviorError, match="conflicts with finish_reason"):
        load_behavior_observations(observation_path, project_root=tmp_path)


def test_observation_rejects_finish_reason_tool_completion_conflict(tmp_path):
    observation_path = _write(
        tmp_path / "observations.json",
        json.dumps(
            {
                "version": 1,
                "scenarios": [
                    {
                        "id": "truncated",
                        "response_complete": False,
                        "finish_reason": "length",
                        "tool_calls_complete": True,
                    }
                ],
            }
        ),
    )

    with pytest.raises(AgentBehaviorError, match="tool_calls_complete conflicts"):
        load_behavior_observations(observation_path, project_root=tmp_path)
