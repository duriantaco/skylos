from __future__ import annotations

import json
import os
import re
import configparser
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from skylos.constants import parse_exclude_folders
from skylos.core.file_discovery import exclusion_matcher
from skylos.core.safe_cache_io import read_project_text_no_symlink


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
    excluded = exclusion_matcher(root, exclude_folders)
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
            and not excluded(base / name)
        ]
        for item in filenames:
            path = base / item
            if (filename is None or item == filename) and not excluded(path):
                yield path


def _has_python_sources(root: Path, exclude_folders: tuple[str, ...]) -> bool:
    return any(
        path.suffix in {".py", ".pyi", ".pyw"}
        for path in _iter_repo_files(root, exclude_folders)
    )


def _has_type_checker_config(root: Path, pyproject: dict[str, Any]) -> bool:
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    return bool(
        isinstance(tool_cfg.get("mypy"), dict)
        or isinstance(tool_cfg.get("pyright"), dict)
        or (root / "mypy.ini").exists()
        or "mypy" in _ini_sections(root, ".mypy.ini")
        or (root / "pyrightconfig.json").exists()
        or "mypy" in _ini_sections(root, "setup.cfg")
    )


def _has_ruff_config(root: Path, pyproject: dict[str, Any]) -> bool:
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    return bool(
        isinstance(tool_cfg.get("ruff"), dict)
        or (root / "ruff.toml").exists()
        or (root / ".ruff.toml").exists()
    )


def _ini_sections(root: Path, filename: str) -> set[str]:
    try:
        source = read_project_text_no_symlink(
            root, root / filename, max_bytes=2_000_000
        )
        if source is None:
            return set()
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.read_string(source)
        return {section.lower() for section in parser.sections()}
    except (OSError, ValueError, RuntimeError, configparser.Error):
        return set()


def _has_python_lint_config(root: Path, pyproject: dict[str, Any]) -> bool:
    if _has_ruff_config(root, pyproject):
        return True
    tool_cfg = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    if any(isinstance(tool_cfg.get(name), dict) for name in ("flake8", "pylint")):
        return True
    pylint_toml = _read_toml(root / "pylintrc.toml")
    pylint_tools = pylint_toml.get("tool")
    if isinstance(pylint_tools, dict) and isinstance(pylint_tools.get("pylint"), dict):
        return True
    if any((root / name).is_file() for name in (".flake8", ".pylintrc", "pylintrc")):
        return True
    for filename in ("setup.cfg", "tox.ini"):
        if any(
            section == "flake8" or section == "pylint" or section.startswith("pylint.")
            for section in _ini_sections(root, filename)
        ):
            return True
    return False


_NEXT_IGNORE_BUILD_ERRORS_RE = re.compile(
    r"(?:['\"]?ignoreBuildErrors['\"]?)\s*:\s*(true|false)\b"
)


def _without_js_comments(source):
    """Ignore parsed comments, preserving regex literals and quoted content."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript
    except ImportError:
        # Preserve the previous conservative interpretation when optional
        # language support is unavailable; do not guess JavaScript tokens.
        return source
    data = source.encode("utf-8")
    try:
        tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(
            data
        )
    except (TypeError, ValueError):
        return source
    if tree.root_node.has_error:
        return None
    result = bytearray(data)
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "comment":
            result[node.start_byte : node.end_byte] = b" " * (
                node.end_byte - node.start_byte
            )
        else:
            pending.extend(node.named_children)
    return result.decode("utf-8")


_NEXT_CONFIG_NAMES = (
    "next.config.js",
    "next.config.mjs",
    "next.config.cjs",
    "next.config.ts",
    "next.config.mts",
    "next.config.cts",
)


def _next_build_checks_typescript(package_root: Path) -> bool:
    config_files = [
        package_root / name
        for name in _NEXT_CONFIG_NAMES
        if (package_root / name).is_file()
    ]
    if len(config_files) > 1:
        return False
    if not config_files:
        return True
    try:
        config_text = config_files[0].read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    if "ignoreBuildErrors" not in config_text:
        return True
    config_text = _without_js_comments(config_text)
    if config_text is None:
        return False
    if "ignoreBuildErrors" not in config_text:
        return True
    # Dynamic settings cannot establish that Next's type check is enabled.
    settings = _NEXT_IGNORE_BUILD_ERRORS_RE.findall(config_text)
    return bool(settings) and all(setting == "false" for setting in settings)


def _script_executables(command, depth=0):
    """Recognize simple executable positions, not tool names in echo/data."""
    if not isinstance(command, str) or depth > 3:
        return []
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    segments, current = [], []
    for token in tokens:
        if token and set(token) <= {";", "&", "|", "\n"}:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    commands = []
    for tokens in segments:
        if tokens and tokens[0] in {"if", "elif", "then", "do", "while", "until", "!"}:
            tokens = tokens[1:]
        while tokens and re.match(r"^[A-Za-z_]\w*=", tokens[0]):
            tokens = tokens[1:]
        if tokens and tokens[0] in {"env", "cross-env", "cross-env-shell"}:
            tokens = tokens[1:]
            while tokens and re.match(r"^[A-Za-z_]\w*=", tokens[0]):
                tokens = tokens[1:]
        if tokens and tokens[0] in {"npx", "bunx"}:
            tokens = tokens[1:]
            if tokens and tokens[0] in {"--no-install", "--yes", "-y"}:
                tokens = tokens[1:]
        elif len(tokens) >= 2 and tokens[:2] in (
            ["npm", "exec"],
            ["pnpm", "exec"],
            ["yarn", "exec"],
        ):
            tokens = tokens[2:]
            if tokens and tokens[0] == "--":
                tokens = tokens[1:]
        elif tokens and tokens[0] in {"yarn", "pnpm", "bun"}:
            tokens = tokens[1:]
        if (
            len(tokens) >= 3
            and tokens[0] in {"sh", "bash", "zsh"}
            and tokens[1] == "-c"
        ):
            commands.extend(_script_executables(tokens[2], depth + 1))
            continue
        commands.append(tokens)
    return commands


def _package_scripts_run_typecheck(package_json: Path) -> bool:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return False
    commands = [
        tokens
        for command in scripts.values()
        for tokens in _script_executables(command)
    ]
    if any(
        tokens
        and tokens[0].replace("\\", "/").rsplit("/", 1)[-1]
        in {"tsc", "vue-tsc", "tsc.cmd", "vue-tsc.cmd"}
        and not {
            "--version",
            "-v",
            "--help",
            "-h",
            "--showConfig",
            "--listFilesOnly",
            "--init",
        }.intersection(tokens[1:])
        and not any(
            token == "--noCheck"
            and (index + 1 == len(tokens) or tokens[index + 1] != "false")
            for index, token in enumerate(tokens)
        )
        for tokens in commands
    ):
        return True
    dependencies = data.get("dependencies")
    dev_dependencies = data.get("devDependencies")
    has_next = any(
        isinstance(group, dict) and "next" in group
        for group in (dependencies, dev_dependencies)
    )
    return bool(
        has_next
        and any(
            len(tokens) >= 2 and tokens[:2] == ["next", "build"] for tokens in commands
        )
        and _next_build_checks_typescript(package_json.parent)
    )


def _iter_package_json_files(root: Path, exclude_folders: tuple[str, ...]):
    for package_json in _iter_repo_files(root, exclude_folders, "package.json"):
        yield package_json


def _policy_files(root: Path, exclude_folders: tuple[str, ...]) -> set[str]:
    files = {
        root / "pyproject.toml",
        root / "mypy.ini",
        root / ".mypy.ini",
        root / "pyrightconfig.json",
        root / "ruff.toml",
        root / ".ruff.toml",
        root / ".pre-commit-config.yaml",
        root / ".pre-commit-config.yml",
    }
    files.update(_iter_package_json_files(root, exclude_folders))
    files.update(
        root / name
        for name in (
            "setup.cfg",
            "tox.ini",
            ".flake8",
            ".pylintrc",
            "pylintrc",
            "pylintrc.toml",
        )
    )
    package_roots = {
        root,
        *(path.parent for path in files if path.name == "package.json"),
    }
    files.update(
        package / name
        for package in package_roots
        for name in ("tsconfig.json", *_NEXT_CONFIG_NAMES)
    )
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
        if not _has_python_lint_config(root_path, pyproject):
            findings.append(
                _finding(
                    rule_id="SKY-R102",
                    name="python-lint-policy",
                    message=(
                        "Python project has no detected Ruff, Flake8 or Pylint "
                        "policy configured."
                    ),
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
        (root_path / ".pre-commit-config.yaml").is_file()
        or (root_path / ".pre-commit-config.yml").is_file()
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
            ).is_file() and not _package_scripts_run_typecheck(package_json):
                findings.append(
                    _finding(
                        rule_id="SKY-R105",
                        name="typescript-typecheck-policy",
                        message=(
                            f"{package_json.relative_to(root_path)} has tsconfig.json "
                            "but no detected npm script that checks TypeScript."
                        ),
                        file=package_json,
                        severity="LOW",
                        value="missing_tsc_script",
                    )
                )

    return findings
