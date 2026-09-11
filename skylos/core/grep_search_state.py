"""Track bounded evidence loss separately from grep's surviving matches."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class GrepSearchResults(dict[str, list[str]]):
    """Raw evidence and whether a search or strategy discarded further hits."""

    def __init__(
        self,
        evidence: Mapping[str, list[str]],
        *,
        truncated_strategies: frozenset[str] | set[str] = frozenset(),
    ) -> None:
        super().__init__(evidence)
        self.truncated_strategies = frozenset(truncated_strategies)


@dataclass
class _EvidenceLimits:
    truncated_strategies: set[str] = field(default_factory=set)


UNCLASSIFIED_STRATEGY = "unclassified"
_ACTIVE_STRATEGY: ContextVar[str] = ContextVar(
    "grep_evidence_strategy", default=UNCLASSIFIED_STRATEGY
)
_ACTIVE_LIMITS: ContextVar[_EvidenceLimits | None] = ContextVar(
    "grep_evidence_limits", default=None
)


@contextmanager
def track_grep_evidence_limits() -> Iterator[_EvidenceLimits]:
    """Keep each concurrent finding's completeness state independent."""
    limits = _EvidenceLimits()
    token = _ACTIVE_LIMITS.set(limits)
    try:
        yield limits
    finally:
        _ACTIVE_LIMITS.reset(token)


@contextmanager
def grep_evidence_strategy(name: str) -> Iterator[None]:
    """Associate discarded raw matches with the strategy that requested them."""
    token = _ACTIVE_STRATEGY.set(name)
    try:
        yield
    finally:
        _ACTIVE_STRATEGY.reset(token)


def grep_probe_limit(limit: int) -> int:
    """Ask for one extra hit to distinguish an exact limit from an overflow."""
    return limit + 1 if _ACTIVE_LIMITS.get() is not None and limit > 0 else limit


def limit_grep_evidence(
    lines: list[str], limit: int, *, strategy: str | None = None
) -> list[str]:
    """Record loss before applying an evidence display/strategy bound."""
    limits = _ACTIVE_LIMITS.get()
    if limits is not None and len(lines) > limit:
        limits.truncated_strategies.add(strategy or _ACTIVE_STRATEGY.get())
    return lines[:limit]


def retain_grep_probe(lines: list[str], limit: int) -> list[str]:
    """Leave legacy searches unchanged; bound and record tracked probes."""
    if _ACTIVE_LIMITS.get() is None:
        return lines
    return limit_grep_evidence(lines, limit)
