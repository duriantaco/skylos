from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


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
    candidates = [
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
    ]

    configs = {}
    for pattern in candidates:
        if "*" in pattern:
            for p in project_root.glob(pattern):
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    if len(text) > 10_000:
                        text = text[:10_000] + "\n... (truncated)"
                    configs[str(p.relative_to(project_root))] = text
                except Exception:
                    pass
        else:
            p = project_root / pattern
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    if len(text) > 10_000:
                        text = text[:10_000] + "\n... (truncated)"
                    configs[pattern] = text
                except Exception:
                    pass

    return configs


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
            with pyproject_path.open("rb") as handle:
                pyproject = tomllib.load(handle)
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
        except Exception:
            pass

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
        except Exception:
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
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            if cached.get("hash") == current_hash:
                return [
                    EntryPoint(
                        name=ep["name"], source=ep["source"], reason=ep["reason"]
                    )
                    for ep in cached.get("entry_points", [])
                    if ep.get("name") and ep["name"] not in known_entry_points
                ]
        except Exception:
            pass

    config_text = []
    for name, content in configs.items():
        config_text.append(f"=== {name} ===\n{content}\n")

    known_text = "\n".join(f"  - {ep}" for ep in known_entry_points[:50]) or "  (none)"

    user = ENTRY_POINT_USER.format(
        config_contents="\n".join(config_text),
        known_entry_points=known_text,
    )

    try:
        response = (
            llm_call(agent, ENTRY_POINT_SYSTEM, user)
            if llm_call
            else agent._call_llm(ENTRY_POINT_SYSTEM, user)
        )
        if not response:
            return []
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        results = []
        all_discovered = []
        for ep in data.get("entry_points", []):
            name = ep.get("name", "")
            if name:
                all_discovered.append(
                    {
                        "name": name,
                        "source": ep.get("source", "config"),
                        "reason": ep.get("reason", ""),
                    }
                )
                if name not in known_entry_points:
                    results.append(
                        EntryPoint(
                            name=name,
                            source=ep.get("source", "config"),
                            reason=ep.get("reason", ""),
                        )
                    )

        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(
                    {"hash": current_hash, "entry_points": all_discovered}, indent=2
                )
            )
        except Exception:
            pass

        return results

    except (json.JSONDecodeError, Exception) as e:
        (log or logger).warning(f"Entry point discovery failed: {e}")
        return []
