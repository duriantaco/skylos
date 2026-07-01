from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.contracts.schema import (
    AIContract,
    ApiSurfaceContract,
    CONTRACT_SCHEMA_VERSION,
    ContractError,
    DEFAULT_CONTRACT_PATH,
    DependencyContract,
    HallucinationContract,
    PhantomSymbolsContract,
    RouteContract,
    SecurityContract,
    TestsContract,
)
from skylos.core.safe_cache_io import read_text_no_symlink


MAX_CONTRACT_BYTES = 256 * 1024


def starter_contract_text() -> str:
    return """version: 1

ai:
  phantom_symbols:
    names:
      - verify_enterprise_auth
      - sanitize_user_input
    decorators:
      - tenant_admin_required

  dependencies:
    reject_nonexistent_packages: true
    reject_impossible_versions: true

  api_surface:
    reject_unknown_members: true
    reject_unknown_kwargs: true

security:
  routes:
    paths:
      - "apps/api/**"
    require_any_decorator:
      - require_auth
      - login_required
      - jwt_required

tests:
  high_risk_changes_require_tests: true
"""


def load_contract(
    path: str | Path,
    project_root: str | Path | None = None,
) -> HallucinationContract:
    candidate_path = _candidate_contract_path(path, project_root)
    contract_path = _resolve_contract_path_for_read(candidate_path, project_root)

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML is a runtime dependency.
        raise ContractError("PyYAML is required to read contract files") from exc

    source = read_text_no_symlink(
        contract_path,
        max_bytes=MAX_CONTRACT_BYTES,
        encoding="utf-8",
    )
    if source is None:
        raise ContractError(
            "Contract file must be a regular non-symlink file "
            f"no larger than {MAX_CONTRACT_BYTES} bytes"
        )

    try:
        raw = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise ContractError(f"Invalid YAML: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ContractError("Contract must be a YAML mapping")

    return _parse_contract(raw, contract_path)


def validate_contract_file(
    path: str | Path,
    project_root: str | Path | None = None,
) -> HallucinationContract:
    return load_contract(path, project_root=project_root)


def contract_project_config_overrides(
    contract: HallucinationContract | None,
) -> dict[str, Any]:
    if contract is None:
        return {}

    vibe: dict[str, list[str]] = {}
    if contract.ai.phantom_symbols.names:
        vibe["extra_phantom_names"] = list(contract.ai.phantom_symbols.names)
    if contract.ai.phantom_symbols.decorators:
        vibe["extra_phantom_decorators"] = list(contract.ai.phantom_symbols.decorators)
    if not vibe:
        return {}
    return {"vibe": vibe}


def contract_enables_dependency_hallucinations(
    contract: HallucinationContract | None,
) -> bool:
    if contract is None:
        return False
    deps = contract.ai.dependencies
    api = contract.ai.api_surface
    return bool(
        deps.reject_nonexistent_packages
        or deps.reject_impossible_versions
        or api.reject_unknown_members
        or api.reject_unknown_kwargs
    )


def _parse_contract(raw: dict[str, Any], contract_path: Path) -> HallucinationContract:
    _reject_unknown(raw, {"version", "id", "ai", "security", "tests"}, "")
    version = _required_int(raw, "version", "version")
    if version != CONTRACT_SCHEMA_VERSION:
        raise ContractError(
            f"version must be {CONTRACT_SCHEMA_VERSION}, got {version}"
        )

    contract_id = _optional_string(raw.get("id"), "id")
    ai = _parse_ai(_optional_mapping(raw.get("ai"), "ai"))
    security = _parse_security(_optional_mapping(raw.get("security"), "security"))
    tests = _parse_tests(_optional_mapping(raw.get("tests"), "tests"))
    return HallucinationContract(
        version=version,
        path=contract_path,
        contract_id=contract_id,
        ai=ai,
        security=security,
        tests=tests,
    )


def _parse_ai(raw: dict[str, Any]) -> AIContract:
    _reject_unknown(raw, {"phantom_symbols", "dependencies", "api_surface"}, "ai")
    phantom = _parse_phantom_symbols(
        _optional_mapping(raw.get("phantom_symbols"), "ai.phantom_symbols")
    )
    dependencies = _parse_dependencies(
        _optional_mapping(raw.get("dependencies"), "ai.dependencies")
    )
    api_surface = _parse_api_surface(
        _optional_mapping(raw.get("api_surface"), "ai.api_surface")
    )
    return AIContract(
        phantom_symbols=phantom,
        dependencies=dependencies,
        api_surface=api_surface,
    )


def _parse_phantom_symbols(raw: dict[str, Any]) -> PhantomSymbolsContract:
    _reject_unknown(raw, {"names", "decorators"}, "ai.phantom_symbols")
    return PhantomSymbolsContract(
        names=tuple(_string_list(raw.get("names"), "ai.phantom_symbols.names")),
        decorators=tuple(
            _string_list(raw.get("decorators"), "ai.phantom_symbols.decorators")
        ),
    )


def _parse_dependencies(raw: dict[str, Any]) -> DependencyContract:
    _reject_unknown(
        raw,
        {"reject_nonexistent_packages", "reject_impossible_versions"},
        "ai.dependencies",
    )
    return DependencyContract(
        reject_nonexistent_packages=_bool_value(
            raw.get("reject_nonexistent_packages", False),
            "ai.dependencies.reject_nonexistent_packages",
        ),
        reject_impossible_versions=_bool_value(
            raw.get("reject_impossible_versions", False),
            "ai.dependencies.reject_impossible_versions",
        ),
    )


def _parse_api_surface(raw: dict[str, Any]) -> ApiSurfaceContract:
    _reject_unknown(
        raw,
        {"reject_unknown_members", "reject_unknown_kwargs"},
        "ai.api_surface",
    )
    return ApiSurfaceContract(
        reject_unknown_members=_bool_value(
            raw.get("reject_unknown_members", False),
            "ai.api_surface.reject_unknown_members",
        ),
        reject_unknown_kwargs=_bool_value(
            raw.get("reject_unknown_kwargs", False),
            "ai.api_surface.reject_unknown_kwargs",
        ),
    )


def _parse_security(raw: dict[str, Any]) -> SecurityContract:
    _reject_unknown(raw, {"routes"}, "security")
    routes = _parse_routes(_optional_mapping(raw.get("routes"), "security.routes"))
    return SecurityContract(routes=routes)


def _parse_routes(raw: dict[str, Any]) -> RouteContract:
    _reject_unknown(raw, {"paths", "require_any_decorator"}, "security.routes")
    paths = tuple(_string_list(raw.get("paths"), "security.routes.paths"))
    for index, value in enumerate(paths):
        _validate_glob_path(value, f"security.routes.paths[{index}]")
    return RouteContract(
        paths=paths,
        require_any_decorator=tuple(
            _string_list(
                raw.get("require_any_decorator"),
                "security.routes.require_any_decorator",
            )
        ),
    )


def _parse_tests(raw: dict[str, Any]) -> TestsContract:
    _reject_unknown(raw, {"high_risk_changes_require_tests"}, "tests")
    return TestsContract(
        high_risk_changes_require_tests=_bool_value(
            raw.get("high_risk_changes_require_tests", False),
            "tests.high_risk_changes_require_tests",
        )
    )


def _candidate_contract_path(path: str | Path, project_root: str | Path | None) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    root = Path(project_root).expanduser() if project_root is not None else Path.cwd()
    return root / candidate


def _resolve_contract_path_for_read(
    candidate_path: Path,
    project_root: str | Path | None,
) -> Path:
    try:
        if candidate_path.is_symlink():
            raise ContractError("Contract file must not be a symlink")
        contract_path = candidate_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"Contract file not found: {candidate_path}") from exc
    except OSError as exc:
        raise ContractError(f"Could not resolve contract file: {exc}") from exc

    if not contract_path.is_file():
        raise ContractError(f"Contract path is not a file: {contract_path}")
    if project_root is not None:
        try:
            root = Path(project_root).expanduser().resolve(strict=False)
            contract_path.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ContractError("Contract file must stay inside the project") from exc
    return contract_path


def _optional_mapping(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ContractError(f"{field} must be a mapping")
    return value


def _required_int(raw: dict[str, Any], key: str, field: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{field} must be an integer")
    return value


def _optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ContractError(f"{field} must be a list")

    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ContractError(f"{field}[{index}] must be a non-empty string")
        result.append(item.strip())
    return result


def _bool_value(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{field} must be true or false")
    return value


def _reject_unknown(raw: dict[str, Any], allowed: set[str], field: str) -> None:
    for key in raw:
        if key not in allowed:
            prefix = f"{field}." if field else ""
            raise ContractError(f"Unknown contract key: {prefix}{key}")


def _validate_glob_path(value: str, field: str) -> None:
    path = Path(value)
    if path.is_absolute():
        raise ContractError(f"{field} must be relative")
    if any(part == ".." for part in path.parts):
        raise ContractError(f"{field} must stay inside the project")
