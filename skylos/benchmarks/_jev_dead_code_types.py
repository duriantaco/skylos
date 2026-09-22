from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class JevBenchmarkError(RuntimeError):
    """Raised when a Jev benchmark request or response is unsafe or invalid."""


@dataclass(frozen=True)
class JevQuestion:
    question_id: str
    case_id: str
    expected: str
    kind: str
    file: str
    symbol: str
    sent_symbol: str
    line: int | None
    label_id: str | None
    taxonomy: tuple[str, ...]


@dataclass(frozen=True)
class JevBatch:
    case_id: str
    arm: str
    payload: dict[str, Any]
    questions: tuple[JevQuestion, ...]
    request_digest: str
    state_bytes: int
    neutralization: dict[str, str] | None = None
