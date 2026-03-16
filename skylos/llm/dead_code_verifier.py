from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class VerificationResult:
    finding: dict
    verdict: Verdict = Verdict.UNCERTAIN
    rationale: str = ""
    original_confidence: int = 0
    adjusted_confidence: int = 0


CONFIDENCE_DELTA = {
    Verdict.TRUE_POSITIVE: +15,
    Verdict.FALSE_POSITIVE: -30,
    Verdict.UNCERTAIN: 0,
}
CONFIDENCE_CAP = 95
CONFIDENCE_FLOOR = 20


def apply_verdict(finding: dict, verdict: Verdict) -> int:
    raw = finding.get("confidence", 60)
    if isinstance(raw, str):
        raw = {"high": 85, "medium": 60, "low": 40}.get(raw.lower(), 60)
    delta = CONFIDENCE_DELTA[verdict]
    return max(CONFIDENCE_FLOOR, min(CONFIDENCE_CAP, raw + delta))


def _parse_confidence(val) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        return {"high": 85, "medium": 60, "low": 40}.get(val.lower(), 60)
    return 60


def _parse_int(val, default=0) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val)
        except ValueError:
            return default
    return default


class DeadCodeVerifierAgent:
    def __init__(self, config=None):
        if config is None:
            from skylos.llm.agents import AgentConfig

            config = AgentConfig()
        self.config = config
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            from skylos.llm.agents import create_llm_adapter

            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def _call_llm(self, system: str, user: str) -> str:
        if getattr(self.config, "stream", True):
            full = ""
            for chunk in self.get_adapter().stream(system, user):
                full += chunk
            return full
        else:
            return self.get_adapter().complete(system, user)

    def test_api_connection(self) -> tuple[bool, str]:
        try:
            response = self.get_adapter().complete(
                "You are a test assistant. Respond with exactly: OK", "Test"
            )

            response_lower = response.lower()
            if (
                "error:" in response_lower
                or "quota" in response_lower
                or "exceeded" in response_lower
            ):
                return False, f"API error: {response}"

            if "ratelimiterror" in response_lower or "unauthorized" in response_lower:
                return False, f"API authentication failed: {response}"

            if len(response.strip()) > 0:
                return True, "API connection successful"

            return False, "API returned empty response"

        except Exception as e:
            error_msg = str(e).lower()
            if (
                "quota" in error_msg
                or "exceeded" in error_msg
                or "ratelimit" in error_msg
            ):
                return False, f"API quota exceeded: {e}"
            elif (
                "unauthorized" in error_msg
                or "authentication" in error_msg
                or "api key" in error_msg
            ):
                return False, f"API authentication failed: {e}"
            else:
                return False, f"API connection failed: {e}"
