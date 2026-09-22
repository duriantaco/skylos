from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from skylos.constants import parse_exclude_folders
from skylos.core.file_discovery import should_exclude_path


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


def _iter_repo_files(
    root: Path, exclude_folders: tuple[str, ...], filename: str | None = None
):
    for current_root, dirnames, filenames in os.walk(root):
        base = Path(current_root)
        # Repo policy concerns project code, even when a scan also inspects
        # dependencies. A pyvenv.cfg identifies virtualenv code without
        # assuming every directory named env contains dependencies.
        dirnames[:] = [
            name
            for name in dirnames
            if name != ".ruff_cache"
            and not (base / name / "pyvenv.cfg").is_file()
            and not should_exclude_path(base / name, root, exclude_folders)
        ]
        for item in filenames:
            path = base / item
            if (filename is None or item == filename) and not should_exclude_path(
                path, root, exclude_folders
            ):
                yield path


def _has_python_sources(root: Path, exclude_folders: tuple[str, ...]) -> bool:
    return any(
        path.suffix in {".py", ".pyi", ".pyw"}
        for path in _iter_repo_files(root, exclude_folders)
    )


def _has_type_checker_config(root: Path, pyproject: dict[str, Any]) -> bool:
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    return bool(
        tool_cfg.get("mypy")
        or tool_cfg.get("pyright")
        or (root / "mypy.ini").exists()
        or (root / "pyrightconfig.json").exists()
        or (root / "setup.cfg").exists()
        and "mypy" in (root / "setup.cfg").read_text(encoding="utf-8", errors="ignore")
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


def _iter_package_json_files(root: Path, exclude_folders: tuple[str, ...]):
    for package_json in _iter_repo_files(root, exclude_folders, "package.json"):
        yield package_json


def _policy_files(root: Path, exclude_folders: tuple[str, ...]) -> set[str]:
    files = {
        root / "pyproject.toml",
        root / "mypy.ini",
        root / "pyrightconfig.json",
        root / "ruff.toml",
        root / ".ruff.toml",
        root / ".pre-commit-config.yaml",
        root / ".pre-commit-config.yml",
    }
    files.update(_iter_package_json_files(root, exclude_folders))
    return {str(path.resolve()) for path in files}


def _changed_policy_files(
    root: Path, changed_files: set[str] | None, exclude_folders: tuple[str, ...]
) -> bool:
    if changed_files is None:
        return True
    normalized_changed = {
        str((root / path).resolve())
        if not Path(path).is_absolute()
        else str(Path(path).resolve())
        for path in changed_files
    }
    return bool(normalized_changed & _policy_files(root, exclude_folders))


def analyze_repo_policy(
    root: str | Path,
    config: dict[str, Any] | None = None,
    *,
    changed_files: set[str] | None = None,
    exclude_folders: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    config = config or {}
    if exclude_folders is None:
        effective_excludes = tuple(
            parse_exclude_folders(config_exclude_folders=config.get("exclude"))
        )
    else:
        effective_excludes = tuple(exclude_folders)
    if not _changed_policy_files(root_path, changed_files, effective_excludes):
        return []

    ignore = set(config.get("ignore") or [])
    pyproject_path = root_path / "pyproject.toml"
    pyproject = _read_toml(pyproject_path)
    findings: list[dict[str, Any]] = []

    has_python_sources = (
        "SKY-R101" not in ignore or "SKY-R102" not in ignore
    ) and _has_python_sources(root_path, effective_excludes)

    if "SKY-R101" not in ignore and has_python_sources:
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

    if "SKY-R102" not in ignore and has_python_sources:
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
            tool_cfg.get("skylos") if isinstance(tool_cfg.get("skylos"), dict) else {}
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
        for package_json in _iter_package_json_files(root_path, effective_excludes):
            package_root = package_json.parent
            if (
                package_root / "tsconfig.json"
            ).exists() and not _package_scripts_run_tsc(package_json):
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
