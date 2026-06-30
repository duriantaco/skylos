from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CONTRACT_SCHEMA_VERSION = 1
DEFAULT_CONTRACT_PATH = ".skylos/ai-contract.yml"


class ContractError(ValueError):
    """Raised when an AI hallucination contract is invalid."""


@dataclass(frozen=True)
class PhantomSymbolsContract:
    names: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyContract:
    reject_nonexistent_packages: bool = False
    reject_impossible_versions: bool = False


@dataclass(frozen=True)
class ApiSurfaceContract:
    reject_unknown_members: bool = False
    reject_unknown_kwargs: bool = False


@dataclass(frozen=True)
class AIContract:
    phantom_symbols: PhantomSymbolsContract = PhantomSymbolsContract()
    dependencies: DependencyContract = DependencyContract()
    api_surface: ApiSurfaceContract = ApiSurfaceContract()


@dataclass(frozen=True)
class RouteContract:
    paths: tuple[str, ...] = ()
    require_any_decorator: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityContract:
    routes: RouteContract = RouteContract()


@dataclass(frozen=True)
class TestsContract:
    high_risk_changes_require_tests: bool = False


@dataclass(frozen=True)
class HallucinationContract:
    version: int
    path: Path
    contract_id: str | None = None
    ai: AIContract = AIContract()
    security: SecurityContract = SecurityContract()
    tests: TestsContract = TestsContract()
