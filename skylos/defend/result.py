from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DefenseResult:
    plugin_id: str
    passed: bool
    integration_location: str
    location: str
    message: str
    severity: str  # "critical" | "high" | "medium" | "low"
    weight: int
    category: str  # "defense" or "ops"
    owasp_llm: Optional[str] = None
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "passed": self.passed,
            "integration_location": self.integration_location,
            "location": self.location,
            "message": self.message,
            "severity": self.severity,
            "weight": self.weight,
            "category": self.category,
            "owasp_llm": self.owasp_llm,
            "remediation": self.remediation,
        }


@dataclass
class DefenseScore:
    weighted_score: int
    weighted_max: int
    score_pct: int
    risk_rating: str
    passed: int
    total: int

    def to_dict(self) -> dict:
        return {
            "weighted_score": self.weighted_score,
            "weighted_max": self.weighted_max,
            "score_pct": self.score_pct,
            "risk_rating": self.risk_rating,
            "passed": self.passed,
            "total": self.total,
        }


@dataclass
class OpsScore:
    passed: int
    total: int
    score_pct: int
    rating: str  # "EXCELLENT" | "GOOD" | "FAIR" | "POOR"

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "total": self.total,
            "score_pct": self.score_pct,
            "rating": self.rating,
        }
