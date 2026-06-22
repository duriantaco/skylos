from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HarnessTool:
    name: str
    category: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
        }


class HarnessToolRegistry:
    def __init__(self, tools: list[HarnessTool] | None = None):
        self._tools: dict[str, HarnessTool] = {}
        for tool in tools or []:
            self.register_tool(tool)

    def register(
        self,
        name: str,
        *,
        category: str,
        description: str = "",
    ) -> HarnessTool:
        return self.register_tool(
            HarnessTool(
                name=name,
                category=category,
                description=description,
            )
        )

    def register_tool(self, tool: HarnessTool) -> HarnessTool:
        if tool.name in self._tools:
            raise ValueError(f"harness tool already registered: {tool.name}")
        self._tools[tool.name] = tool
        return tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> HarnessTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown harness tool: {name}") from exc

    def list(self) -> list[HarnessTool]:
        return [self._tools[name] for name in sorted(self._tools)]

    def to_dict(self) -> list[dict[str, Any]]:
        return [tool.to_dict() for tool in self.list()]


def default_verification_tool_registry() -> HarnessToolRegistry:
    registry = HarnessToolRegistry()
    registry.register(
        "entry_discovery",
        category="llm",
        description="Discover project-specific entry points.",
    )
    registry.register(
        "deterministic_suppression",
        category="deterministic",
        description="Apply static dead-code suppression checks.",
    )
    registry.register(
        "haiku_prefilter",
        category="llm",
        description="Pre-filter exported symbols with a cheaper verifier.",
    )
    registry.register(
        "batch_verify",
        category="llm",
        description="Verify dead-code candidates in batches.",
    )
    registry.register(
        "graph_verify",
        category="llm",
        description="Verify one candidate with graph context.",
    )
    registry.register(
        "suppression_audit",
        category="llm",
        description="Audit suppressed findings for missed dead code.",
    )
    registry.register(
        "survivor_local_scan",
        category="deterministic",
        description="Find local survivor patterns that can be reclassified.",
    )
    registry.register(
        "survivor_discovery",
        category="deterministic",
        description="Find survivors with heuristic references to challenge.",
    )
    registry.register(
        "survivor_batch_challenge",
        category="llm",
        description="Challenge survivor candidates in batches.",
    )
    registry.register(
        "survivor_challenge",
        category="llm",
        description="Challenge one survivor candidate.",
    )
    return registry
