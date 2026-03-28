from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DebtAdvisory:
    summary: str
    root_cause: str
    refactor_steps: list[str] = field(default_factory=list)
    remediation_notes: list[str] = field(default_factory=list)
    confidence: str = "medium"
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "root_cause": self.root_cause,
            "refactor_steps": list(self.refactor_steps),
            "remediation_notes": list(self.remediation_notes),
            "confidence": self.confidence,
            "model": self.model,
        }


@dataclass
class DebtSignal:
    fingerprint: str
    dimension: str
    rule_id: str
    severity: str
    file: str
    line: int
    subject: str
    message: str
    metric_value: Any = None
    threshold: Any = None
    source_category: str = "quality"
    points: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "dimension": self.dimension,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "subject": self.subject,
            "message": self.message,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "source_category": self.source_category,
            "points": self.points,
            "evidence": self.evidence,
        }


@dataclass
class DebtHotspot:
    fingerprint: str
    file: str
    score: float
    signal_count: int
    dimension_count: int
    primary_dimension: str
    changed: bool = False
    baseline_status: str = "untracked"
    score_delta: float = 0.0
    signals: list[DebtSignal] = field(default_factory=list)
    advisory: DebtAdvisory | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "file": self.file,
            "score": self.score,
            "signal_count": self.signal_count,
            "dimension_count": self.dimension_count,
            "primary_dimension": self.primary_dimension,
            "changed": self.changed,
            "baseline_status": self.baseline_status,
            "score_delta": self.score_delta,
            "signals": [signal.to_dict() for signal in self.signals],
            "advisory": self.advisory.to_dict() if self.advisory else None,
        }


@dataclass
class DebtScore:
    total_points: float
    normalizer: float
    score_pct: int
    risk_rating: str
    hotspot_count: int
    signal_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_points": self.total_points,
            "normalizer": self.normalizer,
            "score_pct": self.score_pct,
            "risk_rating": self.risk_rating,
            "hotspot_count": self.hotspot_count,
            "signal_count": self.signal_count,
        }


@dataclass
class DebtSnapshot:
    version: str
    timestamp: str
    project: str
    files_scanned: int
    total_loc: int
    score: DebtScore
    hotspots: list[DebtHotspot] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "project": self.project,
            "files_scanned": self.files_scanned,
            "total_loc": self.total_loc,
            "score": self.score.to_dict(),
            "summary": self.summary,
            "hotspots": [hotspot.to_dict() for hotspot in self.hotspots],
        }
