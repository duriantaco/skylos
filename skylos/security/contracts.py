from __future__ import annotations

import ast
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

RULE_ID = "SKY-SC001"
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_FASTAPI_ROUTE_DECORATORS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "websocket",
}
_SNIPPET_MAX_LINES = 14
_SNIPPET_MAX_CHARS = 900


@dataclass(frozen=True)
class SecurityContract:
    contract_id: str
    framework: str
    file_path: str
    handler: str
    guards: tuple[str, ...]
    severity: str = "HIGH"
    description: str | None = None


@dataclass(frozen=True)
class RouteSnapshot:
    handler: str
    line: int
    method: str | None
    path: str | None
    guards: tuple[str, ...]
    snippet: str | None


def load_security_contracts(
    config: dict | None, project_root: str | os.PathLike[str]
) -> list[SecurityContract]:
    root = Path(project_root).resolve()
    contracts = []
    raw_contracts = (config or {}).get("security_contracts") or []
    if not isinstance(raw_contracts, list):
        return contracts

    for idx, raw in enumerate(raw_contracts, start=1):
        if not isinstance(raw, dict):
            continue

        framework = str(raw.get("framework") or "fastapi").strip().lower()
        file_path = str(raw.get("file") or raw.get("file_path") or "").strip()
        handler = str(raw.get("handler") or "").strip()
        guards_raw = raw.get("guards") or raw.get("required_guards") or []
        severity = str(raw.get("severity") or "HIGH").strip().upper() or "HIGH"
        description = str(raw.get("description") or "").strip() or None

        if framework != "fastapi" or not file_path or not handler:
            continue
        if not isinstance(guards_raw, list):
            continue

        guards = tuple(
            guard.strip()
            for guard in (str(item) for item in guards_raw)
            if guard.strip()
        )
        if not guards:
            continue

        rel_path = _normalize_rel_path(root, file_path)
        if not rel_path:
            continue
        contract_id = (
            str(raw.get("id") or "").strip()
            or f"{framework}:{rel_path}:{handler}:{idx}"
        )
        contracts.append(
            SecurityContract(
                contract_id=contract_id,
                framework=framework,
                file_path=rel_path,
                handler=handler,
                guards=guards,
                severity=severity if severity in _VALID_SEVERITIES else "HIGH",
                description=description,
            )
        )

    return contracts


def resolve_diff_base_ref(project_root: str | os.PathLike[str]) -> str | None:
    env_base = str(os.getenv("SKYLOS_DIFF_BASE") or "").strip()
    if env_base:
        return env_base

    github_base = str(os.getenv("GITHUB_BASE_REF") or "").strip()
    if github_base:
        candidate = f"origin/{github_base}"
        if _git_ref_exists(project_root, candidate):
            return candidate
        if _git_ref_exists(project_root, github_base):
            return github_base

    return None


def detect_security_contract_regressions(
    project_root: str | os.PathLike[str],
    config: dict | None,
    *,
    changed_files: set[str] | list[str] | tuple[str, ...] | None = None,
) -> list[dict]:
    root = Path(project_root).resolve()
    contracts = load_security_contracts(config, root)
    if not contracts:
        return []

    changed_relpaths = _normalize_changed_files(root, changed_files)
    diff_base = resolve_diff_base_ref(root)
    findings: list[dict] = []

    for contract in contracts:
        if changed_relpaths and contract.file_path not in changed_relpaths:
            continue

        before_source = _read_file_at_ref(root, diff_base or "HEAD", contract.file_path)
        if before_source is None and diff_base:
            before_source = _read_file_at_ref(root, "HEAD", contract.file_path)
        after_path = root / contract.file_path
        after_source = _read_current_file(after_path)

        before_route = _find_fastapi_route(before_source, contract.handler)
        if before_route is None:
            continue

        guarded_in_before = [
            guard
            for guard in contract.guards
            if _guards_include(before_route.guards, guard)
        ]
        if not guarded_in_before:
            continue

        after_route = _find_fastapi_route(after_source, contract.handler)
        missing_guards = [
            guard
            for guard in guarded_in_before
            if after_route is None or not _guards_include(after_route.guards, guard)
        ]
        if not missing_guards:
            continue

        findings.append(
            _make_contract_finding(
                root=root,
                contract=contract,
                before_route=before_route,
                after_route=after_route,
                missing_guards=missing_guards,
            )
        )

    return findings


def _normalize_rel_path(root: Path, file_path: str) -> str | None:
    candidate = Path(file_path)
    resolved = (
        candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    )
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return None


def _normalize_changed_files(
    root: Path, changed_files: set[str] | list[str] | tuple[str, ...] | None
) -> set[str]:
    relpaths: set[str] = set()
    for raw in changed_files or []:
        path = Path(str(raw))
        if path.is_absolute():
            try:
                relpaths.add(path.resolve().relative_to(root).as_posix())
            except ValueError:
                continue
        else:
            relpaths.add(path.as_posix())
    return relpaths


def _read_current_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _read_file_at_ref(
    project_root: str | os.PathLike[str],
    ref: str,
    relpath: str,
) -> str | None:
    if not ref:
        return None
    result = subprocess.run(
        ["git", "show", f"{ref}:{relpath}"],
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    if result.returncode == 0:
        return result.stdout
    return None


def _git_ref_exists(project_root: str | os.PathLike[str], ref: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", ref],
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    return result.returncode == 0


def _find_fastapi_route(source: str | None, handler: str) -> RouteSnapshot | None:
    if not source:
        return None

    try:
        module = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != handler:
            continue

        route_decorators = [
            decorator
            for decorator in node.decorator_list
            if _is_fastapi_route_decorator(decorator)
        ]
        if not route_decorators:
            continue

        method, path = _extract_route_identity(route_decorators[0])
        guards = _collect_route_guards(node, route_decorators)
        snippet = _compact_snippet(ast.get_source_segment(source, node))
        return RouteSnapshot(
            handler=node.name,
            line=max(getattr(node, "lineno", 1), 1),
            method=method,
            path=path,
            guards=guards,
            snippet=snippet,
        )

    return None


def _is_fastapi_route_decorator(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    return node.func.attr in _FASTAPI_ROUTE_DECORATORS


def _extract_route_identity(node: ast.Call) -> tuple[str | None, str | None]:
    method = node.func.attr.upper() if isinstance(node.func, ast.Attribute) else None
    path = None

    if node.args:
        path = _string_literal(node.args[0])
    if path is None:
        for keyword in node.keywords:
            if keyword.arg == "path":
                path = _string_literal(keyword.value)
                break

    return method, path


def _string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _collect_route_guards(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorators: list[ast.Call],
) -> tuple[str, ...]:
    guards: list[str] = []

    for decorator in route_decorators:
        for keyword in decorator.keywords:
            if keyword.arg != "dependencies":
                continue
            if isinstance(keyword.value, (ast.List, ast.Tuple)):
                for item in keyword.value.elts:
                    guard = _extract_depends_guard(item)
                    if guard:
                        guards.append(guard)

    positional_defaults = []
    if fn_node.args.defaults:
        positional_defaults.extend(fn_node.args.defaults)
    if fn_node.args.kw_defaults:
        positional_defaults.extend(
            default for default in fn_node.args.kw_defaults if default is not None
        )

    for default in positional_defaults:
        guard = _extract_depends_guard(default)
        if guard:
            guards.append(guard)

    seen = set()
    ordered = []
    for guard in guards:
        if guard in seen:
            continue
        seen.add(guard)
        ordered.append(guard)
    return tuple(ordered)


def _extract_depends_guard(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if not _call_name_matches(node.func, "Depends"):
        return None
    if not node.args:
        return None
    return _expr_name(node.args[0])


def _call_name_matches(node: ast.AST, expected: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == expected
    if isinstance(node, ast.Attribute):
        return node.attr == expected
    return False


def _expr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _guards_include(actual_guards: tuple[str, ...], expected_guard: str) -> bool:
    expected = expected_guard.strip()
    expected_base = expected.split(".")[-1]
    for actual in actual_guards:
        if actual == expected or actual.split(".")[-1] == expected_base:
            return True
    return False


def _route_label(route: RouteSnapshot | None, handler: str) -> str:
    if route is None:
        return handler
    parts = []
    if route.method:
        parts.append(route.method)
    if route.path:
        parts.append(route.path)
    if parts:
        return " ".join(parts)
    return handler


def _compact_snippet(segment: str | None) -> str | None:
    if not segment:
        return None
    lines = segment.strip().splitlines()
    if len(lines) > _SNIPPET_MAX_LINES:
        lines = lines[:_SNIPPET_MAX_LINES]
        lines.append("...")
    text = "\n".join(lines)
    if len(text) > _SNIPPET_MAX_CHARS:
        text = text[: _SNIPPET_MAX_CHARS - 3] + "..."
    return text


def _make_contract_finding(
    *,
    root: Path,
    contract: SecurityContract,
    before_route: RouteSnapshot,
    after_route: RouteSnapshot | None,
    missing_guards: list[str],
) -> dict:
    route_label = _route_label(after_route or before_route, contract.handler)
    if after_route is None:
        message = (
            f"Security contract '{contract.contract_id}' failed: FastAPI route "
            f"{route_label} disappeared with required guard(s) removed: "
            f"{', '.join(missing_guards)}"
        )
        line = before_route.line
    else:
        message = (
            f"Security contract '{contract.contract_id}' failed: FastAPI route "
            f"{route_label} lost required guard(s): {', '.join(missing_guards)}"
        )
        line = after_route.line

    return {
        "rule_id": RULE_ID,
        "kind": "security_contract",
        "severity": contract.severity,
        "message": message,
        "file": str((root / contract.file_path).resolve()),
        "line": max(line, 1),
        "col": 0,
        "_security_evidence": {
            "contract_id": contract.contract_id,
            "contract_description": contract.description,
            "framework": contract.framework,
            "handler": contract.handler,
            "expected_guards": list(contract.guards),
            "missing_guards": missing_guards,
            "before": {
                "method": before_route.method,
                "path": before_route.path,
                "line": before_route.line,
                "guards": list(before_route.guards),
                "snippet": before_route.snippet,
            },
            "after": (
                {
                    "method": after_route.method,
                    "path": after_route.path,
                    "line": after_route.line,
                    "guards": list(after_route.guards),
                    "snippet": after_route.snippet,
                }
                if after_route is not None
                else None
            ),
        },
    }
