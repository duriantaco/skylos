from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from skylos.contracts import (
    contract_enables_dependency_hallucinations,
    contract_project_config_overrides,
    load_contract,
    scan_contract_route_guardrails,
)
from skylos.core.verify_change_schema import (
    build_verify_change_response,
    parse_line_range,
)

__all__ = [
    "build_verify_change_response",
    "parse_line_range",
    "verify_change_path",
    "verify_change_stdin_payload",
]


def verify_change_path(
    path: str | Path,
    *,
    file: str | Path | None = None,
    line_range: str | tuple[int, int] | None = None,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    project_context: bool = False,
    include_dependency_hallucinations: bool = False,
    contract_path: str | Path | None = None,
    analyze_func=None,
) -> dict[str, Any]:
    target = Path(path).expanduser()
    target_file = _optional_path(file)
    scan_target = _scan_target(target, target_file, project_context=project_context)
    root = _root_for_verify_target(target)
    contract_file = (
        _contract_path_for_verify(contract_path, root) if contract_path else None
    )
    contract = None
    if contract_file is not None:
        contract = load_contract(
            contract_file,
            project_root=_contract_project_root_for_verify(contract_file, root),
        )
    include_deps = include_dependency_hallucinations or contract_enables_dependency_hallucinations(
        contract
    )
    changed_files = _changed_files_for_verify(
        scan_target,
        target_file,
    )

    if analyze_func is None:
        from skylos.analyzer import analyze as analyze_func

    analysis_options = _analysis_options(
        confidence=confidence,
        exclude_folders=exclude_folders,
        include_dependency_hallucinations=include_deps,
        changed_files=changed_files,
        project_config_overrides=contract_project_config_overrides(contract),
    )
    raw_result = analyze_func(str(scan_target), **analysis_options)
    analysis_result = _analysis_result_dict(raw_result)
    _add_contract_route_findings(
        analysis_result,
        contract=contract,
        root=root,
        changed_files=changed_files,
    )

    return build_verify_change_response(
        analysis_result,
        project_root=root,
        target_file=target_file,
        line_range=line_range,
        scan_target=scan_target,
        contract=contract,
    )


def verify_change_stdin_payload(
    payload: dict[str, Any],
    *,
    confidence: int = 60,
    exclude_folders: list[str] | None = None,
    analyze_func=None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("stdin manifest must be a JSON object")

    code = payload.get("code")
    if not isinstance(code, str):
        raise ValueError("stdin manifest must include a string 'code' field")

    manifest_file = _safe_manifest_file(_manifest_value(payload, ("file",), "snippet.py"))
    line_range = _manifest_value(payload, ("line_range", "range"), None)
    include_deps = bool(payload.get("include_dependency_hallucinations", False))
    contract_path = _manifest_value(payload, ("contract_path", "contract"), None)

    with tempfile.TemporaryDirectory(prefix="skylos-verify-") as tmp:
        tmp_root = Path(tmp)
        temp_file = _write_manifest_code(tmp_root, manifest_file, code)

        result = verify_change_path(
            temp_file,
            line_range=line_range,
            confidence=confidence,
            exclude_folders=exclude_folders,
            include_dependency_hallucinations=include_deps,
            contract_path=contract_path,
            analyze_func=analyze_func,
        )

    result["target"]["path"] = _manifest_target_path(payload)
    result["target"]["file"] = _manifest_file_for_output(manifest_file)
    for finding in _result_findings(result):
        finding["range"]["file"] = _manifest_file_for_output(manifest_file)
    return result


def _analysis_options(
    *,
    confidence: int,
    exclude_folders: list[str] | None,
    include_dependency_hallucinations: bool,
    changed_files: list[str] | None,
    project_config_overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    options = {
        "conf": confidence,
        "exclude_folders": exclude_folders,
        "enable_quality": True,
        "enable_danger": False,
        "enable_ai_defects": True,
        "enable_dependency_hallucinations": include_dependency_hallucinations,
        "enable_secrets": False,
        "grep_verify": False,
        "trace_file": False,
    }
    if changed_files:
        options["changed_files"] = changed_files
    if project_config_overrides:
        options["project_config_overrides"] = project_config_overrides
    return options


def _contract_path_for_verify(contract_path: str | Path, root: Path) -> Path:
    raw = Path(contract_path).expanduser()
    if raw.is_absolute():
        return raw

    root_candidate = root / raw
    if root_candidate.exists():
        return root_candidate

    cwd_candidate = Path.cwd() / raw
    if cwd_candidate.exists():
        return cwd_candidate

    return root_candidate


def _contract_project_root_for_verify(
    contract_path: str | Path,
    default_root: Path,
) -> Path:
    try:
        resolved = Path(contract_path).expanduser().resolve(strict=False)
    except OSError:
        return default_root
    if resolved.parent.name == ".skylos":
        return resolved.parent.parent
    try:
        resolved.relative_to(default_root)
    except ValueError:
        return resolved.parent
    return default_root


def _add_contract_route_findings(
    analysis_result: dict[str, Any],
    *,
    contract,
    root: Path,
    changed_files: list[str] | None,
) -> None:
    if contract is None:
        return

    scan_root = _contract_scan_root(contract, root)
    route_findings = scan_contract_route_guardrails(
        contract,
        scan_root,
        files=changed_files,
    )
    if not route_findings:
        return

    existing = analysis_result.get("ai_defects")
    if isinstance(existing, list):
        existing.extend(route_findings)
    else:
        analysis_result["ai_defects"] = route_findings


def _contract_scan_root(contract, default_root: Path) -> Path:
    contract_path = getattr(contract, "path", None)
    if not isinstance(contract_path, Path):
        return default_root
    parent = contract_path.parent
    if parent.name == ".skylos":
        return parent.parent
    return parent


def _changed_files_for_verify(
    scan_target: Path,
    target_file: Path | None,
) -> list[str] | None:
    if target_file is not None:
        if target_file.is_absolute():
            return [str(target_file)]
        return [str(target_file).replace("\\", "/")]
    if scan_target.is_file():
        return [str(scan_target)]
    return None


def _write_manifest_code(root: Path, manifest_file: Path, code: str) -> Path:
    root_resolved = root.resolve()
    temp_file = _contained_manifest_path(root_resolved, manifest_file)
    temp_file.parent.mkdir(parents=True, exist_ok=True)
    _write_new_file_no_follow(temp_file, code)
    return temp_file


def _contained_manifest_path(root: Path, manifest_file: Path) -> Path:
    candidate = (root / manifest_file).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("stdin manifest file must stay inside the temp root") from exc
    return candidate


def _write_new_file_no_follow(path: Path, code: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(path, flags, 0o600)  # skylos: ignore[SKY-D215] contained temp manifest path with no-follow create
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(code)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _scan_target(
    path: Path,
    target_file: Path | None,
    *,
    project_context: bool,
) -> Path:
    if target_file is None:
        return path
    if project_context:
        if path.is_dir():
            return path
    if target_file.is_absolute():
        return target_file
    if path.is_dir():
        return path / target_file
    return target_file


def _safe_manifest_file(value: Any) -> Path:
    raw = str(value).strip()
    if not raw:
        raw = "snippet.py"

    path = Path(raw)
    if path.is_absolute():
        raise ValueError("stdin manifest file must be relative")
    for part in path.parts:
        if part in {"", ".", ".."}:
            raise ValueError("stdin manifest file must not contain traversal segments")
    return path


def _optional_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value).expanduser()


def _root_for_verify_target(target: Path) -> Path:
    if target.is_dir():
        return _project_root(target)
    return _project_root(target.parent)


def _project_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_file():
        candidate = candidate.parent
    try:
        return candidate.resolve()
    except OSError:
        return candidate


def _analysis_result_dict(raw_result: Any) -> dict[str, Any]:
    if isinstance(raw_result, str):
        parsed = json.loads(raw_result)
    else:
        parsed = raw_result

    if isinstance(parsed, dict):
        return parsed
    return {}


def _manifest_value(
    payload: dict[str, Any],
    keys: tuple[str, ...],
    default: Any,
) -> Any:
    for key in keys:
        value = payload.get(key)
        if _has_manifest_value(value):
            return value
    return default


def _has_manifest_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        if value.strip() == "":
            return False
    return True


def _manifest_target_path(payload: dict[str, Any]) -> str:
    value = _manifest_value(payload, ("path",), ".")
    return str(value)


def _manifest_file_for_output(manifest_file: Path) -> str:
    return str(manifest_file).replace("\\", "/")


def _result_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = result.get("findings")
    if isinstance(findings, list):
        return findings
    return []
