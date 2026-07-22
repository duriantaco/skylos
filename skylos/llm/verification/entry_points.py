"""Repository entry-point discovery for verification."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    read_text_no_symlink,
    save_project_json_cache,
)

logger = logging.getLogger(__name__)
MAX_CONFIG_FILE_BYTES = 50_000

_CONFIG_FILE_CANDIDATES = (
    # Python
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pytest.ini",
    "tox.ini",
    "mkdocs.yml",
    "mkdocs.yaml",
    "conftest.py",
    "manage.py",
    "app.py",
    "wsgi.py",
    "asgi.py",
    # TypeScript/JS
    "package.json",
    "tsconfig.json",
    "tsconfig.*.json",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "vite.config.ts",
    "vite.config.js",
    "webpack.config.js",
    "jest.config.js",
    "jest.config.ts",
    ".eslintrc.json",
    ".eslintrc.js",
    # Go
    "go.mod",
    "go.sum",
    # Java
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    # Rust
    "Cargo.toml",
    "Cargo.lock",
    # Universal
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "Makefile",
    "Procfile",
)


@dataclass
class EntryPoint:
    name: str
    source: str
    reason: str


@dataclass
class RepoFacts:
    config_files: dict[str, str] = field(default_factory=dict)
    pytest_class_patterns: list[str] = field(default_factory=lambda: ["Test"])
    pytest_function_patterns: list[str] = field(default_factory=lambda: ["test"])
    mkdocs_hook_files: set[str] = field(default_factory=set)


ENTRY_POINT_SYSTEM = """\
You are a Python project analyst. Given project configuration files, identify ALL \
entry points — functions or modules that are invoked externally (CLI commands, web \
routes, scheduled tasks, test hooks, plugin registrations).

Return JSON: {"entry_points": [{"name": "qualified.name", "source": "file", "reason": "..."}]}

Only include entry points you can confirm from the config. Do not speculate.\
"""

ENTRY_POINT_USER = """\
Analyze these project configuration files to find entry points that a static \
analyzer might miss.

{config_contents}

Known entry points already detected by static analysis:
{known_entry_points}

Find any ADDITIONAL entry points referenced in these configs that are NOT in the \
known list above. Focus on:
- console_scripts / gui_scripts in pyproject.toml or setup.cfg
- CMD / ENTRYPOINT in Dockerfile
- Celery tasks, APScheduler jobs
- MkDocs hooks registered in mkdocs.yml / mkdocs.yaml
- pytest plugins and fixtures registered in conftest.py
- Click/Typer command groups registered via entry_points
- ASGI/WSGI application references
- GitHub Actions workflow steps that invoke Python
- package.json "main", "bin", "scripts" entries (TypeScript/JS)
- Next.js/Vite/Webpack entry points and page routes
- Go main() functions referenced in go.mod or Dockerfile
- Java main classes in pom.xml/build.gradle, Spring Boot @SpringBootApplication
- Rust binary targets in Cargo.toml [[bin]] sections

JSON response:\
"""


def _gather_config_files(project_root: Path) -> dict[str, str]:
    configs: dict[str, str] = {}
    for pattern in _CONFIG_FILE_CANDIDATES:
        for path in _matching_config_files(project_root, pattern):
            text = _read_config_file(path)
            if text is None:
                continue
            configs[_config_file_name(project_root, pattern, path)] = text
    return configs


def _matching_config_files(project_root: Path, pattern: str) -> Iterator[Path]:
    if "*" in pattern:
        yield from project_root.glob(pattern)
        return
    path = project_root / pattern
    if path.exists():
        yield path


def _read_config_file(path: Path) -> str | None:
    try:
        text = read_text_no_symlink(
            path,
            max_bytes=MAX_CONFIG_FILE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
    except OSError as exc:
        logger.debug("Skipping unreadable config file %s: %s", path, exc)
        return None
    if text is None:
        return None
    if len(text) > 10_000:
        return text[:10_000] + "\n... (truncated)"
    return text


def _config_file_name(project_root: Path, pattern: str, path: Path) -> str:
    if "*" in pattern:
        return str(path.relative_to(project_root))
    return pattern


def _load_pytest_patterns_from_text(raw_value: Any) -> list[str]:
    if isinstance(raw_value, list):
        return [str(v).strip() for v in raw_value if str(v).strip()]
    if isinstance(raw_value, str):
        lines = [
            line.strip().strip('"').strip("'")
            for line in raw_value.splitlines()
            if line.strip()
        ]
        return lines
    return []


def _parse_mkdocs_hook_files(configs: dict[str, str]) -> set[str]:
    hook_files: set[str] = set()
    for name in ("mkdocs.yml", "mkdocs.yaml"):
        text = configs.get(name, "")
        if not text:
            continue
        in_hooks = False
        hooks_indent = 0
        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if stripped == "hooks:":
                in_hooks = True
                hooks_indent = indent
                continue
            if in_hooks:
                if indent <= hooks_indent and not stripped.startswith("- "):
                    in_hooks = False
                    continue
                if stripped.startswith("- "):
                    hook_path = stripped[2:].strip().strip('"').strip("'")
                    if hook_path:
                        hook_files.add(hook_path.replace("\\", "/"))
    return hook_files


def _build_repo_facts(
    project_root: Path,
    *,
    gather_config_files: Callable[[Path], dict[str, str]] | None = None,
) -> RepoFacts:
    import configparser
    import tomllib

    configs = (gather_config_files or _gather_config_files)(project_root)
    facts = RepoFacts(config_files=configs)

    pyproject_path = project_root / "pyproject.toml"
    if pyproject_path.exists():
        try:
            pyproject_text = read_text_no_symlink(
                pyproject_path,
                max_bytes=MAX_CONFIG_FILE_BYTES,
                encoding="utf-8",
            )
            if pyproject_text is None:
                pyproject = {}
            else:
                pyproject = tomllib.loads(pyproject_text)
            ini_options = (
                pyproject.get("tool", {}).get("pytest", {}).get("ini_options", {})
            )
            class_patterns = _load_pytest_patterns_from_text(
                ini_options.get("python_classes")
            )
            function_patterns = _load_pytest_patterns_from_text(
                ini_options.get("python_functions")
            )
            if class_patterns:
                facts.pytest_class_patterns = class_patterns
            if function_patterns:
                facts.pytest_function_patterns = function_patterns
        except (OSError, tomllib.TOMLDecodeError, AttributeError, TypeError) as exc:
            logger.debug("Failed to read pytest settings from pyproject.toml: %s", exc)

    parser = configparser.ConfigParser()
    for cfg_name, section in (
        ("pytest.ini", "pytest"),
        ("tox.ini", "pytest"),
        ("setup.cfg", "tool:pytest"),
    ):
        cfg_path = project_root / cfg_name
        if not cfg_path.exists():
            continue
        try:
            parser.read(cfg_path, encoding="utf-8")
            if not parser.has_section(section):
                continue
            class_patterns = _load_pytest_patterns_from_text(
                parser.get(section, "python_classes", fallback="")
            )
            function_patterns = _load_pytest_patterns_from_text(
                parser.get(section, "python_functions", fallback="")
            )
            if class_patterns:
                facts.pytest_class_patterns = class_patterns
            if function_patterns:
                facts.pytest_function_patterns = function_patterns
        except (OSError, configparser.Error) as exc:
            logger.debug("Failed to read pytest settings from %s: %s", cfg_path, exc)
            continue

    facts.mkdocs_hook_files = _parse_mkdocs_hook_files(configs)
    return facts


def _matches_pytest_pattern(name: str, patterns: list[str]) -> bool:
    import fnmatch

    for pattern in patterns:
        if name.startswith(pattern):
            return True
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatch(name, pattern):
            return True
    return False


def _entry_point_cache_path(project_root: Path) -> Path:
    return project_root / ".skylos" / "cache" / "entry_points.json"


def _config_files_hash(configs: dict[str, str]) -> str:
    import hashlib

    content = json.dumps(configs, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class _EntryPointDiscovery:
    agent: Any
    project_root: Path
    known_entry_points: list[str]
    configs: dict[str, str]
    cache_path: Path
    current_hash: str
    llm_call: Callable[[Any, str, str], str] | None
    log: logging.Logger | None


def discover_entry_points(
    agent: Any,
    project_root: Path,
    known_entry_points: list[str],
    *,
    llm_call: Callable[[Any, str, str], str] | None = None,
    gather_config_files: Callable[[Path], dict[str, str]] | None = None,
    entry_point_cache_path: Callable[[Path], Path] | None = None,
    config_files_hash: Callable[[dict[str, str]], str] | None = None,
    log: logging.Logger | None = None,
) -> list[EntryPoint]:
    configs = (gather_config_files or _gather_config_files)(project_root)
    if not configs:
        return []

    cache_path = (entry_point_cache_path or _entry_point_cache_path)(project_root)
    current_hash = (config_files_hash or _config_files_hash)(configs)
    cached_entry_points = _load_cached_entry_points(
        project_root,
        cache_path,
        current_hash,
        known_entry_points,
    )
    if cached_entry_points is not None:
        return cached_entry_points
    discovery = _EntryPointDiscovery(
        agent=agent,
        project_root=project_root,
        known_entry_points=known_entry_points,
        configs=configs,
        cache_path=cache_path,
        current_hash=current_hash,
        llm_call=llm_call,
        log=log,
    )
    return _discover_uncached_entry_points(discovery)


def _discover_uncached_entry_points(
    discovery: _EntryPointDiscovery,
) -> list[EntryPoint]:
    user = _build_entry_point_prompt(
        discovery.configs,
        discovery.known_entry_points,
    )
    try:
        return _run_uncached_discovery(discovery, user)
    except (
        json.JSONDecodeError,
        RuntimeError,
        ValueError,
        TypeError,
        AttributeError,
    ) as e:
        (discovery.log or logger).warning(f"Entry point discovery failed: {e}")
        return []


def _run_uncached_discovery(
    discovery: _EntryPointDiscovery,
    user: str,
) -> list[EntryPoint]:
    response = _call_entry_point_model(
        discovery.agent,
        user,
        discovery.llm_call,
    )
    if not response:
        return []
    results, all_discovered = _parse_entry_point_response(
        response,
        discovery.known_entry_points,
    )
    _save_entry_point_cache(
        discovery.project_root,
        discovery.cache_path,
        discovery.current_hash,
        all_discovered,
    )
    return results


def _load_cached_entry_points(
    project_root: Path,
    cache_path: Path,
    current_hash: str,
    known_entry_points: list[str],
) -> list[EntryPoint] | None:
    if not cache_path.exists():
        return None
    try:
        cached = load_project_json_cache(project_root, cache_path)
        if cached.get("hash") != current_hash:
            return None
        return [
            EntryPoint(name=ep["name"], source=ep["source"], reason=ep["reason"])
            for ep in cached.get("entry_points", [])
            if ep.get("name") and ep["name"] not in known_entry_points
        ]
    except (
        OSError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        AttributeError,
    ) as exc:
        logger.debug("Ignoring invalid entry point cache %s: %s", cache_path, exc)
        return None


def _build_entry_point_prompt(
    configs: dict[str, str],
    known_entry_points: list[str],
) -> str:
    config_text = [f"=== {name} ===\n{content}\n" for name, content in configs.items()]
    known_text = "\n".join(f"  - {ep}" for ep in known_entry_points[:50]) or "  (none)"
    return ENTRY_POINT_USER.format(
        config_contents="\n".join(config_text),
        known_entry_points=known_text,
    )


def _call_entry_point_model(
    agent: Any,
    user: str,
    llm_call: Callable[[Any, str, str], str] | None,
) -> str:
    if llm_call:
        return llm_call(agent, ENTRY_POINT_SYSTEM, user)
    return agent._call_llm(ENTRY_POINT_SYSTEM, user)


def _parse_entry_point_response(
    response: str,
    known_entry_points: list[str],
) -> tuple[list[EntryPoint], list[dict[str, str]]]:
    data = json.loads(_clean_entry_point_response(response))
    results: list[EntryPoint] = []
    all_discovered: list[dict[str, str]] = []
    for raw_entry_point in data.get("entry_points", []):
        entry_point = _normalized_entry_point(raw_entry_point)
        if entry_point is None:
            continue
        all_discovered.append(entry_point)
        if entry_point["name"] not in known_entry_points:
            results.append(EntryPoint(**entry_point))
    return results, all_discovered


def _clean_entry_point_response(response: str) -> str:
    clean = response.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1]
    if clean.endswith("```"):
        clean = clean.rsplit("```", 1)[0]
    return clean.strip()


def _normalized_entry_point(raw_entry_point: Any) -> dict[str, str] | None:
    name = raw_entry_point.get("name", "")
    if not name:
        return None
    return {
        "name": name,
        "source": raw_entry_point.get("source", "config"),
        "reason": raw_entry_point.get("reason", ""),
    }


def _save_entry_point_cache(
    project_root: Path,
    cache_path: Path,
    current_hash: str,
    entry_points: list[dict[str, str]],
) -> None:
    try:
        payload = {"hash": current_hash, "entry_points": entry_points}
        if not save_project_json_cache(project_root, cache_path, payload):
            raise OSError("unsafe entry point cache path")
    except OSError as exc:
        logger.debug("Failed to write entry point cache %s: %s", cache_path, exc)
