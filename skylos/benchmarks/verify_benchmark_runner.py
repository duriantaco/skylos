from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from skylos.benchmarks.verify_benchmark_eval import evaluate_case, expectations

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CASE_FILE_BYTES = 2 * 1024 * 1024


def load_manifest(manifest_path: Path, *, repo_root: Path) -> dict[str, Any]:
    safe_path = _safe_manifest_path(manifest_path, repo_root)
    payload = _read_json_file(safe_path, max_bytes=MAX_MANIFEST_BYTES)
    if not isinstance(payload, dict):
        raise ValueError("verify benchmark manifest must be a JSON object")
    return payload


def manifest_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest.get("version") != 1:
        raise ValueError("verify benchmark manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("verify benchmark manifest must define cases")

    validated_cases: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("verify benchmark cases must be objects")
        validated_cases.append(case)
    return validated_cases


def run_case(
    manifest_root: Path,
    case: dict[str, Any],
    tool_command: str,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    case_path = _case_path(manifest_root, case)
    with tempfile.TemporaryDirectory(prefix="skylos-verify-cases-") as temp_dir:
        temp_root = Path(temp_dir).resolve()
        prepared_path = _prepared_case_path(case_path, temp_root)
        output_path = (temp_root / "tool-output.json").resolve()
        command = _tool_command(tool_command, prepared_path, output_path, case)
        started = time.perf_counter()
        process = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=tool_environment(),
        )
        elapsed = time.perf_counter() - started
        payload = _load_tool_payload(output_path, temp_root, process)

    findings = _findings(payload)
    evaluation = evaluate_case(case, findings)
    return {
        "id": case["id"],
        "title": case.get("title", case["id"]),
        "path": case["path"],
        "elapsed_seconds": elapsed,
        "tool_exit_code": process.returncode,
        "tool_stdout": process.stdout,
        "tool_stderr": process.stderr,
        "finding_count": len(findings),
        "expected_count": len(expectations(case)),
        "matched_count": len(evaluation["matched"]),
        "missed": evaluation["missed"],
        "unexpected": evaluation["unexpected"],
        "forbidden": evaluation["forbidden"],
        "passed": evaluation["passed"],
    }


def tool_environment() -> dict[str, str]:
    env = dict(os.environ)
    if "SKYLOS_JOBS" not in env:
        env["SKYLOS_JOBS"] = "1"
    return env


def _safe_manifest_path(manifest_path: Path, repo_root: Path) -> Path:
    resolved = manifest_path.expanduser().resolve()
    root = repo_root.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("verify benchmark manifest must stay inside the repo") from exc
    return resolved


def _read_json_file(path: Path, *, max_bytes: int) -> Any:
    if path.is_symlink():
        raise ValueError(f"refusing to read symlinked JSON file: {path}")
    if not path.is_file():
        raise ValueError(f"JSON path must be a regular file: {path}")

    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"JSON file is too large for benchmark input: {path}")

    return json.loads(path.read_text(encoding="utf-8"))


def _case_path(manifest_root: Path, case: dict[str, Any]) -> Path:
    rel_path = case.get("path")
    if not isinstance(rel_path, str):
        raise ValueError("verify benchmark case path must be a string")
    if not rel_path.strip():
        raise ValueError("verify benchmark case path must be non-empty")

    root = manifest_root.resolve()
    resolved = (root / rel_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("verify benchmark case path must stay inside manifest root") from exc
    if not resolved.exists():
        raise ValueError(f"verify benchmark case path does not exist: {resolved}")
    return resolved


def _prepared_case_path(case_path: Path, temp_root: Path) -> Path:
    prepared_path = _contained_temp_path(temp_root, case_path.name)
    if case_path.is_dir():
        _copy_case_directory(case_path, prepared_path)
        return prepared_path
    _copy_case_file(case_path, prepared_path)
    return prepared_path


def _contained_temp_path(temp_root: Path, name: str) -> Path:
    prepared_path = (temp_root / name).resolve()
    try:
        prepared_path.relative_to(temp_root)
    except ValueError as exc:
        raise ValueError("prepared benchmark path escaped temp root") from exc
    return prepared_path


def _copy_case_directory(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise ValueError(f"refusing to copy symlinked benchmark directory: {source}")
    if not source.is_dir():
        raise ValueError(f"benchmark case path must be a directory: {source}")
    shutil.copytree(
        source,
        destination,
        ignore=_ignore_generated_dirs,
        symlinks=True,
    )


def _copy_case_file(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise ValueError(f"refusing to copy symlinked benchmark file: {source}")
    if not source.is_file():
        raise ValueError(f"benchmark case path must be a regular file: {source}")
    if source.stat().st_size > MAX_CASE_FILE_BYTES:
        raise ValueError(f"benchmark case file is too large: {source}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _ignore_generated_dirs(
    _directory: str,
    names: list[str],
) -> set[str]:
    ignored = set()
    for name in names:
        if name == ".skylos":
            ignored.add(name)
        if name == "__pycache__":
            ignored.add(name)
        if name == "node_modules":
            ignored.add(name)
    return ignored


def _tool_command(
    tool_command: str,
    case_path: Path,
    output_path: Path,
    case: dict[str, Any],
) -> list[str]:
    scan = case.get("scan")
    if not isinstance(scan, dict):
        scan = {}

    command = [
        tool_command,
        "verify",
        str(case_path),
        "--no-fail",
        "--output",
        str(output_path),
        "--confidence",
        str(int(scan.get("confidence", 60))),
    ]
    _append_scope_args(command, scan)
    return command


def _append_scope_args(command: list[str], scan: dict[str, Any]) -> None:
    file_path = scan.get("file")
    if isinstance(file_path, str):
        command.extend(["--file", file_path])

    line_range = scan.get("range")
    if isinstance(line_range, str):
        command.extend(["--range", line_range])

    if bool(scan.get("project_context", False)):
        command.append("--project-context")

    if bool(scan.get("dependency_hallucinations", False)):
        command.append("--dependency-hallucinations")


def _load_tool_payload(
    output_path: Path,
    temp_root: Path,
    process: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    if output_path.exists():
        safe_output = _safe_tool_output_path(output_path, temp_root)
        payload = _read_json_file(safe_output, max_bytes=MAX_TOOL_OUTPUT_BYTES)
        if isinstance(payload, dict):
            return payload

    return {
        "status": "tool_error",
        "findings": [],
        "tool_exit_code": process.returncode,
        "tool_stdout": process.stdout,
        "tool_stderr": process.stderr,
    }


def _safe_tool_output_path(output_path: Path, temp_root: Path) -> Path:
    resolved = output_path.resolve()
    try:
        resolved.relative_to(temp_root)
    except ValueError as exc:
        raise ValueError("verify benchmark output escaped temp root") from exc
    return resolved


def _findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []

    safe_findings: list[dict[str, Any]] = []
    for finding in findings:
        if isinstance(finding, dict):
            safe_findings.append(finding)
    return safe_findings
