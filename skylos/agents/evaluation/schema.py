from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


BEHAVIOR_CONTRACT_VERSION = 1
OBSERVATION_SCHEMA_VERSION = 1
BEHAVIOR_RESULT_VERSION = 1
DEFAULT_BEHAVIOR_CONTRACT_PATH = ".skylos/agent-test.yml"
MAX_BEHAVIOR_RESULT_BYTES = 5_000_000


class AgentBehaviorError(ValueError):
    """Raised when an agent behavior contract or observation is invalid."""


@dataclass(frozen=True)
class AgentToolDefinition:
    name: str
    description: str
    parameters: dict[str, Any]

    def openai_dict(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": dict(self.parameters),
            },
        }


@dataclass(frozen=True)
class AgentTarget:
    endpoint: str | None = None
    model: str | None = None
    timeout_seconds: float = 30.0
    capabilities: tuple[str, ...] = ()
    tools: tuple[AgentToolDefinition, ...] = ()

    def tool_map(self) -> dict[str, AgentToolDefinition]:
        return {tool.name: tool for tool in self.tools}


@dataclass(frozen=True)
class RequiredToolCall:
    name: str
    arguments: dict[str, Any] | None = None


@dataclass(frozen=True)
class ResponseExpectation:
    contains: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolExpectation:
    required: tuple[RequiredToolCall, ...] = ()
    allowed: tuple[str, ...] | None = None
    forbidden: tuple[str, ...] = ()
    exact_sequence: tuple[str, ...] | None = None
    max_calls: int | None = None


@dataclass(frozen=True)
class SourceExpectation:
    required: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScenarioExpectation:
    response: ResponseExpectation = ResponseExpectation()
    tools: ToolExpectation = ToolExpectation()
    refusal: bool | None = None
    sources: SourceExpectation = SourceExpectation()

    def assertion_count(self) -> int:
        count = len(self.response.contains) + len(self.response.excludes)
        count += len(self.tools.required) + len(self.tools.forbidden)
        count += len(self.sources.required)
        count += int(self.tools.allowed is not None)
        count += int(self.tools.exact_sequence is not None)
        count += int(self.tools.max_calls is not None)
        count += int(self.refusal is not None)
        return count


@dataclass(frozen=True)
class AgentScenario:
    scenario_id: str
    prompt: str
    expectation: ScenarioExpectation
    system_prompt: str | None = None
    available_tools: tuple[str, ...] | None = None


@dataclass(frozen=True)
class AgentBehaviorContract:
    version: int
    path: Path
    project_root: Path
    source_digest: str
    agent: AgentTarget
    scenarios: tuple[AgentScenario, ...]


@dataclass(frozen=True)
class AgentToolCallObservation:
    name: str
    arguments: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
        }


@dataclass(frozen=True)
class AgentObservation:
    scenario_id: str
    response: str | None = None
    response_complete: bool | None = None
    finish_reason: str | None = None
    tool_calls: tuple[AgentToolCallObservation, ...] | None = None
    tool_calls_complete: bool | None = None
    refusal: bool | None = None
    sources: tuple[str, ...] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "response": self.response,
            "response_complete": self.response_complete,
            "finish_reason": self.finish_reason,
            "tool_calls": (
                None
                if self.tool_calls is None
                else [call.to_dict() for call in self.tool_calls]
            ),
            "tool_calls_complete": self.tool_calls_complete,
            "refusal": self.refusal,
            "sources": None if self.sources is None else list(self.sources),
            "error": self.error,
        }


@dataclass(frozen=True)
class BehaviorObservationSet(Mapping[str, AgentObservation]):
    version: int
    path: Path
    source_digest: str
    observations: dict[str, AgentObservation]

    def __getitem__(self, key: str) -> AgentObservation:
        return self.observations[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.observations)

    def __len__(self) -> int:
        return len(self.observations)


@dataclass(frozen=True)
class BehaviorAssertion:
    assertion: str
    kind: str
    status: str
    message: str
    expected: Any = None
    observed: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertion": self.assertion,
            "kind": self.kind,
            "status": self.status,
            "message": self.message,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class ScenarioEvaluation:
    scenario_id: str
    status: str
    assertions: tuple[BehaviorAssertion, ...]
    observation: AgentObservation | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "status": self.status,
            "assertions": [item.to_dict() for item in self.assertions],
            "observation": (
                None if self.observation is None else self.observation.to_dict()
            ),
        }


@dataclass(frozen=True)
class BehaviorEvaluation:
    status: str
    scenarios: tuple[ScenarioEvaluation, ...]
    summary: dict[str, int]
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "summary": dict(self.summary),
            "coverage": dict(self.coverage),
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
        }
