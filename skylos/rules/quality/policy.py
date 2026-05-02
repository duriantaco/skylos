from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SKIP_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _line_for_section(path: Path, marker: str) -> int:
    if not path.exists():
        return 1
    try:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip() == marker:
                return lineno
    except OSError:
        pass
    return 1


def _finding(
    *,
    rule_id: str,
    name: str,
    message: str,
    file: Path,
    line: int = 1,
    severity: str = "LOW",
    value: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "kind": "repo_policy",
        "severity": severity,
        "type": "policy",
        "name": name,
        "simple_name": name,
        "value": value,
        "threshold": 0,
        "message": message,
        "file": str(file),
        "basename": file.name,
        "line": line,
        "col": 0,
    }


def _iter_repo_files(root: Path, filename: str | None = None):
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for item in filenames:
            if filename is None or item == filename:
                yield base / item


def _has_python_sources(root: Path) -> bool:
    return any(path.suffix == ".py" for path in _iter_repo_files(root))


def _has_type_checker_config(root: Path, pyproject: dict[str, Any]) -> bool:
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    return bool(
        tool_cfg.get("mypy")
        or tool_cfg.get("pyright")
        or (root / "mypy.ini").exists()
        or (root / "pyrightconfig.json").exists()
        or (root / "setup.cfg").exists()
        and "mypy" in (root / "setup.cfg").read_text(
            encoding="utf-8", errors="ignore"
        )
    )


def _has_ruff_config(root: Path, pyproject: dict[str, Any]) -> bool:
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    return bool(
        tool_cfg.get("ruff")
        or (root / "ruff.toml").exists()
        or (root / ".ruff.toml").exists()
    )


def _package_scripts_run_tsc(package_json: Path) -> bool:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception:
        return False
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return False
    return any("tsc" in str(command) for command in scripts.values())


def _iter_package_json_files(root: Path):
    for package_json in _iter_repo_files(root, "package.json"):
        yield package_json


def _policy_files(root: Path) -> set[str]:
    files = {
        root / "pyproject.toml",
        root / "mypy.ini",
        root / "pyrightconfig.json",
        root / "ruff.toml",
        root / ".ruff.toml",
        root / ".pre-commit-config.yaml",
        root / ".pre-commit-config.yml",
    }
    files.update(_iter_package_json_files(root))
    return {str(path.resolve()) for path in files}


def _changed_policy_files(root: Path, changed_files: set[str] | None) -> bool:
    if changed_files is None:
        return True
    normalized_changed = {
        str((root / path).resolve())
        if not Path(path).is_absolute()
        else str(Path(path).resolve())
        for path in changed_files
    }
    return bool(normalized_changed & _policy_files(root))


def analyze_repo_policy(
    root: str | Path,
    config: dict[str, Any] | None = None,
    *,
    changed_files: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    if not _changed_policy_files(root_path, changed_files):
        return []

    config = config or {}
    ignore = set(config.get("ignore") or [])
    pyproject_path = root_path / "pyproject.toml"
    pyproject = _read_toml(pyproject_path)
    findings: list[dict[str, Any]] = []

    if "SKY-R101" not in ignore and _has_python_sources(root_path):
        if not _has_type_checker_config(root_path, pyproject):
            findings.append(
                _finding(
                    rule_id="SKY-R101",
                    name="python-type-check-policy",
                    message=(
                        "Python project has no mypy or pyright policy configured. "
                        "Add a checked type policy for public code paths."
                    ),
                    file=pyproject_path if pyproject_path.exists() else root_path,
                    severity="MEDIUM",
                    value="missing_type_checker",
                )
            )

    if "SKY-R102" not in ignore and _has_python_sources(root_path):
        if not _has_ruff_config(root_path, pyproject):
            findings.append(
                _finding(
                    rule_id="SKY-R102",
                    name="python-lint-policy",
                    message="Python project has no Ruff policy configured.",
                    file=pyproject_path if pyproject_path.exists() else root_path,
                    severity="LOW",
                    value="missing_ruff",
                )
            )

    if "SKY-R103" not in ignore:
        tool_cfg = (
            pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
        )
        skylos_cfg = (
            tool_cfg.get("skylos")
            if isinstance(tool_cfg.get("skylos"), dict)
            else {}
        )
        if not isinstance(skylos_cfg.get("gate"), dict):
            findings.append(
                _finding(
                    rule_id="SKY-R103",
                    name="skylos-gate-policy",
                    message="No [tool.skylos.gate] policy is configured for repository quality gates.",
                    file=pyproject_path if pyproject_path.exists() else root_path,
                    line=_line_for_section(pyproject_path, "[tool.skylos]"),
                    severity="LOW",
                    value="missing_skylos_gate",
                )
            )

    if "SKY-R104" not in ignore and not (
        (root_path / ".pre-commit-config.yaml").exists()
        or (root_path / ".pre-commit-config.yml").exists()
    ):
        findings.append(
            _finding(
                rule_id="SKY-R104",
                name="pre-commit-policy",
                message="Repository has no pre-commit policy file.",
                file=root_path,
                severity="LOW",
                value="missing_pre_commit",
            )
        )

    if "SKY-R105" not in ignore:
        for package_json in _iter_package_json_files(root_path):
            package_root = package_json.parent
            if (package_root / "tsconfig.json").exists() and not _package_scripts_run_tsc(
                package_json
            ):
                findings.append(
                    _finding(
                        rule_id="SKY-R105",
                        name="typescript-typecheck-policy",
                        message=(
                            f"{package_json.relative_to(root_path)} has tsconfig.json "
                            "but no npm script that runs tsc."
                        ),
                        file=package_json,
                        severity="LOW",
                        value="missing_tsc_script",
                    )
                )

    return findings
