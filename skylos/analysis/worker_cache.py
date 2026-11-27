"""Storage private to one serial file batch."""

from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecurityUnitCache:
    """A serial scan's reusable, successful Python source indexes."""

    root: Path | None = None
    entries: dict = field(default_factory=dict)
    nodes: int = 0
    chars: int = 0


security_units = ContextVar("skylos_worker_security_units", default=None)
