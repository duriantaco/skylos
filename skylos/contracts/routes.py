from __future__ import annotations

import ast
import fnmatch
from pathlib import Path
from typing import Any

from skylos.contracts.schema import HallucinationContract
from skylos.core.safe_cache_io import read_text_no_symlink


RULE_ID_CONTRACT_ROUTE_GUARD = "SKY-A105"
VIBE_CONTRACT_GUARDRAIL = "missing_contract_guardrail"
MAX_ROUTE_SOURCE_BYTES = 1_000_000

_ROUTE_METHOD_NAMES = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
    "websocket",
}


def scan_contract_route_guardrails(
    contract: HallucinationContract | None,
    project_root: str | Path,
    *,
    files: list[str | Path] | None = None,
) -> list[dict[str, Any]]:
    if not _contract_has_route_guardrail(contract):
        return []

    assert contract is not None
    root = _safe_resolve(project_root)
    findings: list[dict[str, Any]] = []
    for file_path in _candidate_python_files(root, contract, files=files):
        findings.extend(_scan_python_file(file_path, root, contract))
    return findings


def _contract_has_route_guardrail(
    contract: HallucinationContract | None,
) -> bool:
    if contract is None:
        return False
    routes = contract.security.routes
    return bool(routes.paths and routes.require_any_decorator)


def _candidate_python_files(
    root: Path,
    contract: HallucinationContract,
    *,
    files: list[str | Path] | None,
) -> list[Path]:
    candidates: set[Path] = set()
    if files is not None:
        for raw in files:
            path = _candidate_file_path(root, raw)
            if _is_scannable_python_file(path) and _path_in_contract_scope(
                path,
                root,
                contract,
            ):
                candidates.add(_safe_resolve(path))
        return sorted(candidates)

    for pattern in contract.security.routes.paths:
        candidates.update(_glob_contract_pattern(root, pattern, contract))
    return sorted(candidates)


def _candidate_file_path(root: Path, raw: str | Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    root_candidate = root / path
    if root_candidate.exists():
        return root_candidate
    return Path.cwd() / path


def _glob_contract_pattern(
    root: Path,
    pattern: str,
    contract: HallucinationContract,
) -> set[Path]:
    normalized = _normalize_path(pattern)
    patterns = [normalized]
    if not _has_glob(normalized):
        patterns.append(f"{normalized.rstrip('/')}/**/*.py")
    elif normalized.endswith("/**"):
        patterns.append(f"{normalized.rstrip('/')}/**/*.py")

    matches: set[Path] = set()
    for glob_pattern in patterns:
        try:
            paths = root.glob(glob_pattern)
        except ValueError:
            continue
        for path in paths:
            if _is_scannable_python_file(path) and _path_in_contract_scope(
                path,
                root,
                contract,
            ):
                matches.add(_safe_resolve(path))
    return matches


def _is_scannable_python_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.suffix == ".py"
    except OSError:
        return False


def _path_in_contract_scope(
    path: Path,
    root: Path,
    contract: HallucinationContract,
) -> bool:
    try:
        rel = _normalize_path(_safe_resolve(path).relative_to(root))
    except ValueError:
        return False

    return any(
        _path_matches_pattern(rel, pattern)
        for pattern in contract.security.routes.paths
    )


def _path_matches_pattern(relative_path: str, pattern: str) -> bool:
    normalized = _normalize_path(pattern)
    if fnmatch.fnmatchcase(relative_path, normalized):
        return True
    if normalized.endswith("/**"):
        prefix = normalized[:-3].rstrip("/")
        return relative_path == prefix or relative_path.startswith(f"{prefix}/")
    if not _has_glob(normalized):
        prefix = normalized.rstrip("/")
        return relative_path == prefix or relative_path.startswith(f"{prefix}/")
    return False


def _scan_python_file(
    file_path: Path,
    root: Path,
    contract: HallucinationContract,
) -> list[dict[str, Any]]:
    source = read_text_no_symlink(
        file_path,
        max_bytes=MAX_ROUTE_SOURCE_BYTES,
        encoding="utf-8",
    )
    if source is None:
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []

    required = contract.security.routes.require_any_decorator
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        route_decorators = [
            decorator
            for decorator in node.decorator_list
            if _is_route_decorator(decorator)
        ]
        if not route_decorators:
            continue
        if _has_required_guard(node, required):
            continue

        findings.append(_finding(file_path, root, node, route_decorators, required))
    return findings


def _finding(
    file_path: Path,
    root: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorators: list[ast.AST],
    required: tuple[str, ...],
) -> dict[str, Any]:
    route_label = _route_label(route_decorators[0], node.name)
    required_display = ", ".join(_display_decorator(name) for name in required)
    return {
        "rule_id": RULE_ID_CONTRACT_ROUTE_GUARD,
        "kind": "contract_route_guardrail",
        "severity": "HIGH",
        "type": "route",
        "name": node.name,
        "simple_name": node.name,
        "value": required_display,
        "threshold": 0,
        "message": (
            f"Route '{route_label}' is missing a contract-required guard "
            f"decorator. Add one of: {required_display}."
        ),
        "file": str(file_path),
        "basename": file_path.name,
        "line": node.lineno,
        "col": node.col_offset,
        "category": "ai_defect",
        "defect_type": VIBE_CONTRACT_GUARDRAIL,
        "vibe_category": VIBE_CONTRACT_GUARDRAIL,
        "ai_likelihood": "high",
        "confidence": 90,
        "metadata": {
            "route_path": _route_path(route_decorators[0]),
            "changed_file": _relative_path(file_path, root),
            "required_decorators": list(required),
        },
    }


def _has_required_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    required: tuple[str, ...],
) -> bool:
    required_names = _required_name_set(required)
    for decorator in node.decorator_list:
        if _decorator_matches_required(decorator, required_names):
            return True
        if _is_route_decorator(decorator) and _route_dependency_matches_required(
            decorator,
            required_names,
        ):
            return True
    return False


def _decorator_matches_required(
    decorator: ast.AST,
    required_names: set[str],
) -> bool:
    return bool(_name_variants(_decorator_name(decorator)) & required_names)


def _route_dependency_matches_required(
    decorator: ast.AST,
    required_names: set[str],
) -> bool:
    call = decorator if isinstance(decorator, ast.Call) else None
    if call is None:
        return False
    for keyword in call.keywords:
        if keyword.arg in {"dependencies", "dependency_overrides"}:
            if _node_mentions_required(keyword.value, required_names):
                return True
    return False


def _node_mentions_required(node: ast.AST, required_names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if _name_variants(child.id) & required_names:
                return True
        elif isinstance(child, ast.Attribute):
            if _name_variants(_dotted_name(child)) & required_names:
                return True
        elif isinstance(child, ast.Call):
            if _name_variants(_dotted_name(child.func)) & required_names:
                return True
    return False


def _is_route_decorator(decorator: ast.AST) -> bool:
    name = _decorator_name(decorator)
    method_name = _last_name_part(name)
    if method_name not in _ROUTE_METHOD_NAMES:
        return False
    if "." in name:
        return True
    return method_name in {"route", "api_route"}


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _dotted_name(decorator.func)
    return _dotted_name(decorator)


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _route_label(decorator: ast.AST, fallback: str) -> str:
    path = _route_path(decorator)
    name = _decorator_name(decorator) or "route"
    if path:
        return f"{name} {path}"
    return fallback


def _route_path(decorator: ast.AST) -> str | None:
    call = decorator if isinstance(decorator, ast.Call) else None
    if call is None or not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _required_name_set(required: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    for value in required:
        names.update(_name_variants(value))
    return names


def _name_variants(value: str) -> set[str]:
    raw = value.strip().lstrip("@")
    if not raw:
        return set()
    variants = {raw}
    if raw.endswith("()"):
        variants.add(raw[:-2])
    before_call = raw.split("(", 1)[0].strip()
    if before_call:
        variants.add(before_call)
    for item in list(variants):
        if "." in item:
            variants.add(item.rsplit(".", 1)[-1])
    return {item.strip().lstrip("@") for item in variants if item.strip().lstrip("@")}


def _last_name_part(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _display_decorator(name: str) -> str:
    stripped = name.strip()
    if stripped.startswith("@"):
        return stripped
    return f"@{stripped}"


def _relative_path(path: Path, root: Path) -> str:
    try:
        return _normalize_path(_safe_resolve(path).relative_to(root))
    except ValueError:
        return _normalize_path(path)


def _normalize_path(path: str | Path) -> str:
    return str(path).replace("\\", "/").strip("/")


def _has_glob(pattern: str) -> bool:
    for char in "*?[":
        if char in pattern:
            return True
    return False


def _safe_resolve(path: str | Path) -> Path:
    try:
        return Path(path).expanduser().resolve(strict=False)
    except OSError:
        return Path(path).expanduser()
