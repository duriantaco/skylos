from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph
from skylos.defend.result import DefenseResult
from skylos.defend.scoring import SEVERITY_WEIGHTS


class DefensePlugin(ABC):
    id: str = ""
    name: str = ""
    category: str = "defense"
    severity: str = "medium"
    owasp_llm: Optional[str] = None
    description: str = ""
    remediation: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 1)

    @abstractmethod
    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        raise NotImplementedError

    def applies_to(self, integration: LLMIntegration) -> bool:
        return True

    def _pass(self, integration: LLMIntegration, location: str, message: str) -> DefenseResult:
        return DefenseResult(
            plugin_id=self.id,
            passed=True,
            integration_location=integration.location,
            location=location,
            message=message,
            severity=self.severity,
            weight=self.weight,
            category=self.category,
            owasp_llm=self.owasp_llm,
            remediation="",
        )

    def _fail(self, integration: LLMIntegration, location: str, message: str) -> DefenseResult:
        return DefenseResult(
            plugin_id=self.id,
            passed=False,
            integration_location=integration.location,
            location=location,
            message=message,
            severity=self.severity,
            weight=self.weight,
            category=self.category,
            owasp_llm=self.owasp_llm,
            remediation=self.remediation,
        )
