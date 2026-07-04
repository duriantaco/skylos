from __future__ import annotations

import json
import logging
import os
import re
import shlex
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from difflib import SequenceMatcher
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    read_text_no_symlink,
    save_project_json_cache,
)
from skylos.rules.ai_defect.dependency_truth import (
    LEGACY_STATUS_EXISTS,
    DependencyTruthResult,
    DependencyTruthState,
    dependency_truth_cache_key,
    normalize_dependency_truth_state,
)
from skylos.rules.sca.vulnerability_scanner import (
    ECOSYSTEM_GO,
    ECOSYSTEM_NPM,
    ECOSYSTEM_PYPI,
    parse_go_mod,
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)


RULE_ID_DEPENDENCY_HALLUCINATION = "SKY-D222"
RULE_ID_VERSION_HALLUCINATION = "SKY-D225"
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
VIBE_CATEGORY = "dependency_hallucination"
AI_LIKELIHOOD = "high"
STATUS_PRESENT = DependencyTruthState.PRESENT.value
STATUS_EXISTS = LEGACY_STATUS_EXISTS
STATUS_MISSING_PACKAGE = "missing_package"
STATUS_MISSING_VERSION = "missing_version"
STATUS_SUSPICIOUS_EXISTING = "suspicious_existing"
STATUS_PRIVATE_OR_UNVERIFIED = "private_or_unverified"
STATUS_UNKNOWN = "unknown"
VERSION_CACHE_SCHEMA_VERSION = 1
VERSION_CACHE_PATH = Path(".skylos") / "cache" / "dependency_versions.json"
MAX_VERSION_CACHE_BYTES = 5_000_000
MAX_REGISTRY_RESPONSE_BYTES = 1_000_000
MAX_INSTALL_SURFACE_BYTES = 1_000_000
NPM_REGISTRY_ORIGIN = "https://registry.npmjs.org"
GO_PROXY_ORIGIN = "https://proxy.golang.org"
PYPI_JSON_ORIGIN = "https://pypi.org/pypi"
ALLOWED_REGISTRY_HOSTS = {
    "pypi.org",
    "registry.npmjs.org",
    "proxy.golang.org",
}
INSTALL_SURFACE_MAX_DEPTH = 5
INSTALL_SURFACE_SOURCE = "install_surface"
COMMAND_SEPARATORS = {"&&", "||", ";", "|"}
PIP_INSTALL_COMMANDS = {"pip", "pip3", "pipx"}
PYTHON_COMMANDS = {"python", "python3", "py"}
NPM_INSTALL_COMMANDS = {
    "npm": {"install", "i", "add"},
    "pnpm": {"add"},
    "yarn": {"add"},
    "bun": {"add"},
}
PIP_PRIVATE_INDEX_FLAGS = {
    "--extra-index-url",
    "--find-links",
    "--index-url",
    "-f",
    "-i",
}
PIP_VALUE_FLAGS = {
    "-c",
    "--constraint",
    "-e",
    "--editable",
    *PIP_PRIVATE_INDEX_FLAGS,
    "--requirement",
    "-r",
    "--target",
    "-t",
}
NPM_PRIVATE_REGISTRY_FLAGS = {"--registry"}
NPM_VALUE_FLAGS = {
    "--cache",
    "--global-style",
    "--install-strategy",
    "--omit",
    "--only",
    "--prefix",
    *NPM_PRIVATE_REGISTRY_FLAGS,
    "--save-prefix",
    "--tag",
    "--workspace",
    "-w",
}
GO_INSTALL_COMMANDS = {"get", "install"}
POPULAR_PACKAGE_NAMES = {
    ECOSYSTEM_PYPI: {
        "boto3",
        "celery",
        "cryptography",
        "django",
        "fastapi",
        "flask",
        "numpy",
        "pandas",
        "pillow",
        "pytest",
        "pyyaml",
        "requests",
        "sqlalchemy",
        "urllib3",
    },
    ECOSYSTEM_NPM: {
        "axios",
        "express",
        "jest",
        "lodash",
        "next",
        "react",
        "typescript",
        "vue",
        "webpack",
    },
}
PIP_PRIVATE_REGISTRY_ENV_PREFIXES = {
    "PIP_EXTRA_INDEX_URL=",
    "PIP_FIND_LINKS=",
    "PIP_INDEX_URL=",
    "UV_DEFAULT_INDEX=",
    "UV_EXTRA_INDEX_URL=",
    "UV_INDEX_URL=",
}
NPM_PRIVATE_REGISTRY_ENV_PREFIXES = {
    "BUN_CONFIG_REGISTRY=",
    "NPM_CONFIG_REGISTRY=",
    "YARN_NPM_REGISTRY_SERVER=",
}
PIP_EXACT_INSTALL_SPEC_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*"
    r"([0-9][A-Za-z0-9._+-]*)$"
)
MARKDOWN_PROMPT_RE = re.compile(r"^\$\s+")
YAML_RUN_RE = re.compile(r"^(?P<indent>\s*)(?:-\s*)?run\s*:\s*(?P<body>.*)$")
YAML_BLOCK_SCALARS = {"|", "|-", "|+", ">", ">-", ">+"}
DOC_SHELL_FENCE_LABELS = {
    "bash",
    "console",
    "sh",
    "shell",
    "terminal",
    "zsh",
}
GRADLE_DEPENDENCY_BLOCK_RE = re.compile(r"\bdependencies\s*\{")
GRADLE_STRING_DEPENDENCY_RE = re.compile(
    r"""^\s*(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*['"](?P<group>[^:'"]+):(?P<artifact>[^:'"]+):(?P<version>[^:'"]+)['"]"""
)
GRADLE_MAP_DEPENDENCY_RE = re.compile(
    r"""^\s*(?P<scope>implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*group\s*:\s*['"](?P<group>[^'"]+)['"]\s*,\s*name\s*:\s*['"](?P<artifact>[^'"]+)['"]\s*,\s*version\s*:\s*['"](?P<version>[^'"]+)['"]"""
)
AUTHORITATIVE_CACHE_STATES = {
    DependencyTruthState.PRESENT,
    DependencyTruthState.MISSING_PACKAGE,
    DependencyTruthState.MISSING_VERSION,
}

StatusChecker = Callable[[str, str, str, dict[str, Any]], str]

logger = logging.getLogger(__name__)


def scan_manifest_dependency_hallucinations(
    repo_root: str | Path | None,
    *,
    status_checker: StatusChecker | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root = _repo_root(repo_root)
    if root is None:
        return findings

    dependencies = _collect_manifest_dependencies(root)
    if not dependencies:
        return findings

    cache = _load_version_cache(root)
    checker = _status_checker(status_checker)
    cache_changed = False

    unique_dependencies = _unique_dependencies(dependencies)
    for dependency in unique_dependencies:
        status = dependency.get("dependency_truth_state")
        if status is None:
            status = _cached_dependency_status(dependency, cache)
        if status is None:
            status = checker(
                str(dependency["ecosystem"]),
                str(dependency["name"]),
                str(dependency["version"]),
                cache,
            )
            if _record_dependency_status(dependency, cache, status):
                cache_changed = True

        state = normalize_dependency_truth_state(status)
        reason = ""
        if state == DependencyTruthState.PRESENT:
            reason = _suspicious_existing_dependency_reason(
                dependency,
                unique_dependencies,
            )
            if reason:
                state = DependencyTruthState.SUSPICIOUS_EXISTING
        finding = _finding_for_status(dependency, state, reason=reason)
        if finding is not None:
            findings.append(finding)

    if cache_changed:
        _save_version_cache(root, cache)

    return findings


def check_dependency_version_status(
    ecosystem: str,
    name: str,
    version: str,
    cache: dict[str, Any],
) -> str:
    if ecosystem == ECOSYSTEM_PYPI:
        return _check_pypi_version(name, version)
    if ecosystem == ECOSYSTEM_NPM:
        return _check_npm_version(name, version)
    if ecosystem == ECOSYSTEM_GO:
        return _check_go_version(name, version)
    return STATUS_UNKNOWN


def _repo_root(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    try:
        return Path(value).resolve()
    except OSError:
        return Path(value)


def _status_checker(status_checker: StatusChecker | None) -> StatusChecker:
    if status_checker is not None:
        return status_checker
    return check_dependency_version_status


def _collect_manifest_dependencies(root: Path) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    parsers = {
        "requirements.txt": parse_requirements_txt,
        "pyproject.toml": parse_pyproject_toml,
        "package.json": parse_package_json,
        "go.mod": parse_go_mod,
        "Cargo.toml": _parse_cargo_toml,
        "composer.json": _parse_composer_json,
        "Gemfile": _parse_gemfile,
        "pubspec.yaml": _parse_pubspec_yaml,
    }

    for dirpath, dirnames, filenames in os.walk(root):
        _filter_manifest_dirs(dirnames)
        if _manifest_depth(root, dirpath) > 3:
            dirnames.clear()
            continue

        for filename in filenames:
            parser = parsers.get(filename)
            path = Path(dirpath) / filename
            if parser is None:
                parser = _parser_for_manifest_path(path)
            if parser is None:
                continue
            try:
                parsed = parser(path)
                dependencies.extend(
                    _apply_manifest_dependency_context(root, path, parsed)
                )
            except Exception as exc:
                logger.debug("Failed to parse dependency manifest %s: %s", path, exc)

    dependencies.extend(_collect_install_surface_dependencies(root))
    return dependencies


def _apply_manifest_dependency_context(
    root: Path,
    path: Path,
    dependencies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not dependencies:
        return dependencies

    pypi_private = _manifest_has_private_pypi_context(path)
    npm_private_all, npm_private_scopes = _npm_private_registry_context(root, path)
    contextualized: list[dict[str, Any]] = []
    for dependency in dependencies:
        if _pypi_dependency_has_wildcard_pin(dependency):
            continue
        ecosystem = str(dependency.get("ecosystem", ""))
        name = str(dependency.get("name", ""))
        if ecosystem == ECOSYSTEM_PYPI and pypi_private:
            contextualized.append(
                _private_or_unverified_dependency(
                    dependency,
                    reason="manifest uses a private or alternate Python package source",
                )
            )
            continue
        if ecosystem == ECOSYSTEM_NPM and (
            npm_private_all or _npm_name_matches_private_scope(name, npm_private_scopes)
        ):
            contextualized.append(
                _private_or_unverified_dependency(
                    dependency,
                    reason="manifest uses a private or alternate npm registry",
                )
            )
            continue
        contextualized.append(dependency)
    return contextualized


def _pypi_dependency_has_wildcard_pin(dependency: dict[str, Any]) -> bool:
    if str(dependency.get("ecosystem", "")) != ECOSYSTEM_PYPI:
        return False
    snippet = str(dependency.get("snippet", ""))
    return bool(re.search(r"==\s*[0-9][A-Za-z0-9._+-]*\*", snippet))


def _parser_for_manifest_path(path: Path) -> Callable[[Path], list[dict[str, Any]]] | None:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in {"pom.xml", "packages.config"}:
        return _parse_xml_dependencies
    if suffix in {".csproj", ".fsproj", ".vbproj"}:
        return _parse_xml_dependencies
    if name in {"build.gradle", "build.gradle.kts"}:
        return _parse_gradle_dependencies
    return None


def _manifest_has_private_pypi_context(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements_has_private_index(path)
    if name == "pyproject.toml":
        return _pyproject_has_private_source(path)
    return False


def _requirements_has_private_index(path: Path) -> bool:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        if _tokens_have_private_pip_index(tokens):
            return True
    return False


def _pyproject_has_private_source(path: Path) -> bool:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return False
    in_source_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_source_block = line in {
                "[[tool.poetry.source]]",
                "[[tool.pdm.source]]",
            }
            continue
        if not in_source_block:
            continue
        match = re.match(r"""url\s*=\s*['"]([^'"]+)['"]""", line, re.I)
        if match and not _allowed_registry_url(match.group(1)):
            return True
    return False


def _tokens_have_private_pip_index(tokens: list[str]) -> bool:
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token in PIP_PRIVATE_INDEX_FLAGS:
            value = tokens[idx + 1] if idx + 1 < len(tokens) else ""
            if _private_or_unverified_registry_value(value):
                return True
            idx += 2
            continue
        for flag in PIP_PRIVATE_INDEX_FLAGS:
            prefix = f"{flag}="
            if token.startswith(prefix):
                if _private_or_unverified_registry_value(token[len(prefix) :]):
                    return True
            if flag in {"-i", "-f"} and token.startswith(flag) and len(token) > len(flag):
                if _private_or_unverified_registry_value(token[len(flag) :]):
                    return True
        idx += 1
    return False


def _private_or_unverified_registry_value(value: str) -> bool:
    raw = value.strip()
    if not raw:
        return True
    return not _allowed_registry_url(raw)


def _npm_private_registry_context(root: Path, path: Path) -> tuple[bool, set[str]]:
    private_all = False
    private_scopes: set[str] = set()
    for npmrc in _candidate_npmrc_files(root, path):
        text = read_text_no_symlink(
            npmrc,
            max_bytes=MAX_INSTALL_SURFACE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if text is None:
            continue
        file_private_all, file_private_scopes = _parse_npmrc_private_registries(text)
        private_all = private_all or file_private_all
        private_scopes.update(file_private_scopes)
    return private_all, private_scopes


def _candidate_npmrc_files(root: Path, path: Path) -> list[Path]:
    candidates: list[Path] = []
    for base in (root, path.parent):
        npmrc = base / ".npmrc"
        if npmrc not in candidates:
            candidates.append(npmrc)
    return candidates


def _parse_npmrc_private_registries(text: str) -> tuple[bool, set[str]]:
    private_all = False
    private_scopes: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower().startswith("registry="):
            value = line.split("=", 1)[1].strip()
            if _private_or_unverified_registry_value(value):
                private_all = True
            continue
        match = re.match(r"^(@[^:\s]+):registry\s*=\s*(\S+)\s*$", line, re.I)
        if match and _private_or_unverified_registry_value(match.group(2)):
            private_scopes.add(match.group(1).lower())
    return private_all, private_scopes


def _npm_name_matches_private_scope(name: str, private_scopes: set[str]) -> bool:
    raw = name.strip().lower()
    return any(raw.startswith(f"{scope}/") for scope in private_scopes)


def _collect_install_surface_dependencies(root: Path) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        _filter_manifest_dirs(dirnames)
        if _manifest_depth(root, dirpath) > INSTALL_SURFACE_MAX_DEPTH:
            dirnames.clear()
            continue

        for filename in filenames:
            path = Path(dirpath) / filename
            if not _is_install_surface_file(root, path):
                continue
            dependencies.extend(_parse_install_surface_file(path))
    return dependencies


def _parse_cargo_toml(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    in_dependency_section = False
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_dependency_section = line in {
                "[dependencies]",
                "[dev-dependencies]",
                "[build-dependencies]",
            }
            continue
        if not in_dependency_section or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip().strip('"').strip("'")
        cargo = _cargo_dependency_spec(name, value)
        if cargo is None:
            continue
        name, version = cargo
        if not name or version is None:
            continue
        dependencies.append(
            _manifest_dependency(
                path,
                line_no,
                line,
                ecosystem="crates.io",
                name=name,
                version=version,
            )
        )
    return dependencies


def _parse_composer_json(path: Path) -> list[dict[str, Any]]:
    data = _read_json_object(path)
    if not data:
        return []
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    for section in ("require", "require-dev"):
        items = data.get(section)
        if not isinstance(items, dict):
            continue
        for name, spec in items.items():
            if not isinstance(name, str) or name.lower() == "php":
                continue
            version = _pinned_manifest_version(str(spec))
            if version is None:
                continue
            dependencies.append(
                _manifest_dependency(
                    path,
                    _find_line(text, f'"{name}"'),
                    f'"{name}": "{spec}"',
                    ecosystem="Packagist",
                    name=name,
                    version=version,
                )
            )
    return dependencies


def _parse_gemfile(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    pattern = re.compile(
        r"""^\s*gem\s+['"](?P<name>[^'"]+)['"]\s*,\s*['"](?P<spec>[^'"]+)['"]"""
    )
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        match = pattern.match(raw_line)
        if not match:
            continue
        version = _pinned_manifest_version(match.group("spec"))
        if version is None:
            continue
        dependencies.append(
            _manifest_dependency(
                path,
                line_no,
                raw_line.strip(),
                ecosystem="RubyGems",
                name=match.group("name"),
                version=version,
            )
        )
    return dependencies


def _parse_pubspec_yaml(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    in_dependency_section = False
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            in_dependency_section = stripped in {"dependencies:", "dev_dependencies:"}
            continue
        indent = len(line) - len(line.lstrip(" "))
        if not in_dependency_section or indent != 2:
            continue
        if ":" not in stripped:
            continue
        name, spec = stripped.split(":", 1)
        if not name or name == "sdk":
            continue
        spec = spec.strip().strip('"').strip("'")
        version = _pinned_manifest_version(spec)
        if version is None:
            continue
        dependencies.append(
            _manifest_dependency(
                path,
                line_no,
                stripped,
                ecosystem="Pub",
                name=name,
                version=version,
            )
        )
    return dependencies


def _parse_gradle_dependencies(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    for line_no, statement in _gradle_dependency_statements(text):
        dependency = _gradle_dependency_from_statement(path, line_no, statement)
        if dependency is not None:
            dependencies.append(dependency)
    return dependencies


def _gradle_dependency_statements(text: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    in_comment_block = False
    in_dependency_block = False
    dependency_block_depth = 0
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line, in_comment_block = _strip_gradle_comments(raw_line, in_comment_block)
        fragment, in_dependency_block, dependency_block_depth = _gradle_fragment(
            line,
            in_dependency_block=in_dependency_block,
            dependency_block_depth=dependency_block_depth,
        )
        if fragment is None:
            continue
        for statement in _gradle_statement_parts(fragment):
            statements.append((line_no, statement))
    return statements


def _gradle_fragment(
    line: str,
    *,
    in_dependency_block: bool,
    dependency_block_depth: int,
) -> tuple[str | None, bool, int]:
    if not line.strip():
        return None, in_dependency_block, dependency_block_depth
    if not in_dependency_block:
        block_match = GRADLE_DEPENDENCY_BLOCK_RE.search(line)
        if not block_match:
            return None, in_dependency_block, dependency_block_depth
        fragment = line[block_match.end() :]
        depth = 1 + _gradle_brace_delta(fragment)
        return fragment, depth > 0, depth

    depth = dependency_block_depth + _gradle_brace_delta(line)
    return line, depth > 0, depth


def _gradle_statement_parts(fragment: str) -> list[str]:
    parts = [part.strip().rstrip("}") for part in re.split(r";", fragment)]
    return [part for part in parts if part]


def _gradle_dependency_from_statement(
    path: Path,
    line_no: int,
    statement: str,
) -> dict[str, Any] | None:
    match: re.Match[str] | None = None
    version: str | None = None
    for pattern in (GRADLE_STRING_DEPENDENCY_RE, GRADLE_MAP_DEPENDENCY_RE):
        match = pattern.search(statement)
        if match:
            version = _pinned_manifest_version(match.group("version"))
            break
    if not match or version is None:
        return None
    return _manifest_dependency(
        path,
        line_no,
        statement,
        ecosystem="Maven",
        name=f"{match.group('group')}:{match.group('artifact')}",
        version=version,
    )


def _parse_xml_dependencies(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []

    dependencies: list[dict[str, Any]] = []
    if path.name.lower() == "pom.xml":
        dependencies.extend(_parse_pom_dependencies(path, text, root))
    else:
        dependencies.extend(_parse_nuget_dependencies(path, text, root))
    return dependencies


def _parse_pom_dependencies(
    path: Path,
    text: str,
    root: ET.Element,
) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for node in root.iter():
        if _xml_local_name(node.tag) != "dependency":
            continue
        group = _xml_child_text(node, "groupId")
        artifact = _xml_child_text(node, "artifactId")
        version = _xml_child_text(node, "version")
        if not group or not artifact or not version or "${" in version:
            continue
        version = _pinned_manifest_version(version)
        if version is None:
            continue
        dependencies.append(
            _manifest_dependency(
                path,
                _find_line(text, artifact),
                f"{group}:{artifact}:{version}",
                ecosystem="Maven",
                name=f"{group}:{artifact}",
                version=version,
            )
        )
    return dependencies


def _parse_nuget_dependencies(
    path: Path,
    text: str,
    root: ET.Element,
) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for node in root.iter():
        tag = _xml_local_name(node.tag)
        if tag == "PackageReference":
            name = node.attrib.get("Include") or node.attrib.get("Update")
            version = node.attrib.get("Version") or _xml_child_text(node, "Version")
        elif tag == "package":
            name = node.attrib.get("id")
            version = node.attrib.get("version")
        else:
            continue
        if not name or not version:
            continue
        version = _pinned_manifest_version(version)
        if version is None:
            continue
        dependencies.append(
            _manifest_dependency(
                path,
                _find_line(text, name),
                f"{name}@{version}",
                ecosystem="NuGet",
                name=name,
                version=version,
            )
        )
    return dependencies


def _manifest_dependency(
    path: Path,
    line_no: int,
    snippet: str,
    *,
    ecosystem: str,
    name: str,
    version: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "file": str(path),
        "line": line_no,
        "snippet": snippet,
    }


def _read_json_object(path: Path) -> dict[str, Any]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _cargo_dependency_spec(name: str, value: str) -> tuple[str, str] | None:
    stripped = value.strip()
    if stripped.startswith("{"):
        if re.search(r"""\b(?:git|path|registry)\s*=""", stripped):
            return None
        package_name = name
        package_match = re.search(r"""package\s*=\s*['"]([^'"]+)['"]""", stripped)
        if package_match:
            package_name = package_match.group(1)
        version_match = re.search(r"""version\s*=\s*['"]([^'"]+)['"]""", stripped)
        if not version_match:
            return None
        version = _pinned_manifest_version(version_match.group(1))
        if version is None:
            return None
        return package_name, version
    if len(stripped) >= 2 and stripped[0] in {"'", '"'}:
        quote_char = stripped[0]
        end = stripped.find(quote_char, 1)
        if end > 1:
            version = _pinned_manifest_version(stripped[1:end])
            if version is None:
                return None
            return name, version
    return None


def _pinned_manifest_version(spec: str) -> str | None:
    raw = str(spec).strip()
    if not raw:
        return None
    match = re.match(
        r"^(?:==|=|>=|~>|~|\^)?\s*([0-9][A-Za-z0-9._+-]*)\s*$",
        raw,
    )
    if not match:
        return None
    raw = match.group(1)
    if "*" in raw or ".+" in raw or raw.endswith("+"):
        return None
    if not raw or not raw[0].isdigit():
        return None
    return raw


def _strip_gradle_comments(line: str, in_comment_block: bool) -> tuple[str, bool]:
    output = ""
    index = 0
    while index < len(line):
        if in_comment_block:
            end = line.find("*/", index)
            if end == -1:
                return output, True
            index = end + 2
            in_comment_block = False
            continue
        block_start = line.find("/*", index)
        line_start = line.find("//", index)
        if block_start == -1 and line_start == -1:
            output += line[index:]
            break
        if line_start != -1 and (block_start == -1 or line_start < block_start):
            output += line[index:line_start]
            break
        output += line[index:block_start]
        index = block_start + 2
        in_comment_block = True
    return output, in_comment_block


def _gradle_brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def _find_line(text: str, needle: str) -> int:
    if not needle:
        return 1
    for line_no, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return line_no
    return 1


def _xml_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _xml_child_text(node: ET.Element, child_name: str) -> str:
    for child in node:
        if _xml_local_name(child.tag) == child_name and child.text:
            return child.text.strip()
    return ""


def _is_install_surface_file(root: Path, path: Path) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(
        ".dockerfile"
    ):
        return True
    if suffix in {".sh", ".bash", ".zsh", ".ksh", ".bats"}:
        return True
    if suffix in {".md", ".markdown", ".rst", ".txt"}:
        return True
    if suffix in {".yml", ".yaml"}:
        try:
            rel_parts = path.resolve().relative_to(root).parts
        except (OSError, ValueError):
            rel_parts = path.parts
        if len(rel_parts) >= 3 and rel_parts[0] == ".github" and rel_parts[1] in {
            "workflows",
            "actions",
        }:
            return True
        if name in {"action.yml", "action.yaml"}:
            return True
    return False


def _parse_install_surface_file(path: Path) -> list[dict[str, Any]]:
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_INSTALL_SURFACE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return []

    dependencies: list[dict[str, Any]] = []
    for line_no, command in _logical_install_lines(path, text):
        dependencies.extend(_dependencies_from_install_command(path, line_no, command))
    return dependencies


def _logical_install_lines(path: Path, text: str) -> list[tuple[int, str]]:
    kind = _install_surface_kind(path)
    if kind == "dockerfile":
        return _logical_dockerfile_install_lines(text)
    if kind == "yaml":
        return _logical_yaml_run_lines(text)
    if kind == "document":
        return _logical_document_install_lines(text)
    return _logical_shell_install_lines(text)


def _install_surface_kind(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(
        ".dockerfile"
    ):
        return "dockerfile"
    if suffix in {".yml", ".yaml"}:
        return "yaml"
    if suffix in {".md", ".markdown", ".rst", ".txt"}:
        return "document"
    return "shell"


def _logical_shell_install_lines(text: str) -> list[tuple[int, str]]:
    return _logical_commands_from_lines(
        (line for line in enumerate(text.splitlines(), 1)),
        _clean_shell_install_line,
    )


def _logical_dockerfile_install_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    pending: list[str] = []
    start_line = 1
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if pending:
            cleaned = _clean_shell_install_line(stripped)
        else:
            if not stripped.upper().startswith("RUN "):
                continue
            cleaned = _clean_shell_install_line(stripped[4:])
        if not cleaned:
            pending = []
            continue
        if not pending:
            start_line = line_no
        pending.append(cleaned.rstrip("\\").strip())
        if not raw_line.rstrip().endswith("\\"):
            logical.append((start_line, " ".join(pending)))
            pending = []
    if pending:
        logical.append((start_line, " ".join(pending)))
    return logical


def _logical_yaml_run_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    lines = text.splitlines()
    idx = 0
    while idx < len(lines):
        raw_line = lines[idx]
        match = YAML_RUN_RE.match(raw_line)
        if not match:
            idx += 1
            continue

        body = _strip_yaml_scalar_quotes(match.group("body").strip())
        if body in YAML_BLOCK_SCALARS:
            base_indent = len(match.group("indent"))
            block_lines: list[tuple[int, str]] = []
            idx += 1
            while idx < len(lines):
                block_line = lines[idx]
                stripped = block_line.strip()
                indent = len(block_line) - len(block_line.lstrip(" "))
                if stripped and indent <= base_indent:
                    break
                if stripped:
                    block_lines.append((idx + 1, stripped))
                idx += 1
            logical.extend(
                _logical_commands_from_lines(block_lines, _clean_shell_install_line)
            )
            continue

        cleaned = _clean_shell_install_line(body)
        if cleaned:
            logical.append((idx + 1, cleaned))
        idx += 1
    return logical


def _logical_document_install_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    pending_lines: list[tuple[int, str]] = []
    in_shell_fence = False

    for line_no, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        fence = _markdown_fence_label(stripped)
        if fence is not None:
            if in_shell_fence and pending_lines:
                logical.extend(
                    _logical_commands_from_lines(
                        pending_lines,
                        _clean_document_install_line,
                    )
                )
                pending_lines = []
            in_shell_fence = fence in DOC_SHELL_FENCE_LABELS
            continue

        if in_shell_fence:
            pending_lines.append((line_no, raw_line))
            continue

        if MARKDOWN_PROMPT_RE.match(stripped):
            logical.extend(
                _logical_commands_from_lines(
                    [(line_no, raw_line)],
                    _clean_document_install_line,
                )
            )

    if in_shell_fence and pending_lines:
        logical.extend(
            _logical_commands_from_lines(pending_lines, _clean_document_install_line)
        )
    return logical


def _logical_commands_from_lines(
    lines: Any,
    cleaner: Callable[[str], str],
) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    pending: list[str] = []
    start_line = 1
    for line_no, raw_line in lines:
        stripped = cleaner(raw_line)
        if not stripped:
            if pending:
                logical.append((start_line, " ".join(pending)))
                pending = []
            continue

        if not pending:
            start_line = line_no
        pending.append(stripped.rstrip("\\").strip())
        if not raw_line.rstrip().endswith("\\"):
            logical.append((start_line, " ".join(pending)))
            pending = []
    if pending:
        logical.append((start_line, " ".join(pending)))
    return logical


def _clean_shell_install_line(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    if stripped.startswith("#") or stripped.startswith("//"):
        return ""
    return stripped


def _clean_document_install_line(line: str) -> str:
    stripped = _clean_shell_install_line(line)
    if not stripped:
        return ""
    stripped = MARKDOWN_PROMPT_RE.sub("", stripped)
    if stripped.startswith("- "):
        stripped = stripped[2:].strip()
    return stripped


def _markdown_fence_label(stripped: str) -> str | None:
    if not (stripped.startswith("```") or stripped.startswith("~~~")):
        return None
    label = stripped[3:].strip().lower()
    if not label:
        return ""
    return label.split()[0]


def _strip_yaml_scalar_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _dependencies_from_install_command(
    path: Path,
    line_no: int,
    command: str,
) -> list[dict[str, Any]]:
    try:
        tokens = shlex.split(
            _space_shell_command_separators(command),
            comments=True,
            posix=True,
        )
    except ValueError:
        tokens = _space_shell_command_separators(command).split()
    dependencies: list[dict[str, Any]] = []

    idx = 0
    while idx < len(tokens):
        pip_start = _pip_install_args_start(tokens, idx)
        if pip_start is not None:
            dependencies.extend(
                _dependencies_from_pip_args(
                    path,
                    line_no,
                    command,
                    tokens[pip_start:],
                    prefix_tokens=_command_prefix_tokens(tokens, idx),
                )
            )

        npm_start = _npm_install_args_start(tokens, idx)
        if npm_start is not None:
            dependencies.extend(
                _dependencies_from_npm_args(
                    path,
                    line_no,
                    command,
                    tokens[npm_start:],
                    prefix_tokens=_command_prefix_tokens(tokens, idx),
                )
            )

        go_start = _go_install_args_start(tokens, idx)
        if go_start is not None:
            dependencies.extend(
                _dependencies_from_go_args(path, line_no, command, tokens[go_start:])
            )
        idx += 1

    return dependencies


def _space_shell_command_separators(command: str) -> str:
    return re.sub(r"(&&|\|\||;|\|)", r" \1 ", command)


def _pip_install_args_start(tokens: list[str], idx: int) -> int | None:
    token = _lower_token(tokens, idx)
    next_token = _lower_token(tokens, idx + 1)
    if _is_pip_install_command(token, next_token):
        return idx + 2
    if _is_python_module_pip_install(tokens, idx):
        return idx + 4
    if _is_uv_pip_install(tokens, idx):
        return idx + 3
    if token in {"uv", "poetry"} and next_token == "add":
        return idx + 2
    return None


def _is_pip_install_command(token: str, next_token: str) -> bool:
    return token in PIP_INSTALL_COMMANDS and next_token == "install"


def _is_python_module_pip_install(tokens: list[str], idx: int) -> bool:
    return (
        _lower_token(tokens, idx) in PYTHON_COMMANDS
        and _lower_token(tokens, idx + 1) == "-m"
        and _lower_token(tokens, idx + 2) == "pip"
        and _lower_token(tokens, idx + 3) == "install"
    )


def _is_uv_pip_install(tokens: list[str], idx: int) -> bool:
    return (
        _lower_token(tokens, idx) == "uv"
        and _lower_token(tokens, idx + 1) == "pip"
        and _lower_token(tokens, idx + 2) == "install"
    )


def _npm_install_args_start(tokens: list[str], idx: int) -> int | None:
    token = _lower_token(tokens, idx)
    commands = NPM_INSTALL_COMMANDS.get(token)
    if commands is None:
        return None
    if _lower_token(tokens, idx + 1) in commands:
        return idx + 2
    return None


def _go_install_args_start(tokens: list[str], idx: int) -> int | None:
    if _lower_token(tokens, idx) != "go":
        return None
    if _lower_token(tokens, idx + 1) in GO_INSTALL_COMMANDS:
        return idx + 2
    return None


def _lower_token(tokens: list[str], idx: int) -> str:
    if idx < 0 or idx >= len(tokens):
        return ""
    return tokens[idx].lower()


def _dependencies_from_pip_args(
    path: Path,
    line_no: int,
    command: str,
    args: list[str],
    *,
    prefix_tokens: list[str],
) -> list[dict[str, Any]]:
    private_or_unverified = _tokens_have_private_pip_index(
        args
    ) or _tokens_have_private_registry_env(
        prefix_tokens,
        PIP_PRIVATE_REGISTRY_ENV_PREFIXES,
    )
    dependencies: list[dict[str, Any]] = []
    for spec in _package_specs(args, value_flags=PIP_VALUE_FLAGS):
        parsed = _parse_pip_install_spec(spec)
        if parsed is None:
            continue
        name, version = parsed
        dependency = _install_dependency(
            path,
            line_no,
            command,
            ecosystem=ECOSYSTEM_PYPI,
            name=name,
            version=version,
        )
        if private_or_unverified:
            dependency = _private_or_unverified_dependency(
                dependency,
                reason="install command uses a private or alternate Python package source",
            )
        dependencies.append(dependency)
    return dependencies


def _dependencies_from_npm_args(
    path: Path,
    line_no: int,
    command: str,
    args: list[str],
    *,
    prefix_tokens: list[str],
) -> list[dict[str, Any]]:
    private_or_unverified = _tokens_have_private_registry_option(
        args,
        NPM_PRIVATE_REGISTRY_FLAGS,
    ) or _tokens_have_private_registry_env(
        prefix_tokens,
        NPM_PRIVATE_REGISTRY_ENV_PREFIXES,
    )
    dependencies: list[dict[str, Any]] = []
    for spec in _package_specs(args, value_flags=NPM_VALUE_FLAGS):
        parsed = _parse_npm_install_spec(spec)
        if parsed is None:
            continue
        name, version = parsed
        dependency = _install_dependency(
            path,
            line_no,
            command,
            ecosystem=ECOSYSTEM_NPM,
            name=name,
            version=version,
        )
        if private_or_unverified:
            dependency = _private_or_unverified_dependency(
                dependency,
                reason="install command uses a private or alternate npm registry",
            )
        dependencies.append(dependency)
    return dependencies


def _dependencies_from_go_args(
    path: Path,
    line_no: int,
    command: str,
    args: list[str],
) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for spec in _package_specs(args, value_flags=set()):
        parsed = _parse_go_install_spec(spec)
        if parsed is None:
            continue
        name, version = parsed
        dependencies.append(
            _install_dependency(
                path,
                line_no,
                command,
                ecosystem=ECOSYSTEM_GO,
                name=name,
                version=version,
            )
        )
    return dependencies


def _package_specs(args: list[str], *, value_flags: set[str]) -> list[str]:
    specs: list[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in COMMAND_SEPARATORS:
            break
        arg, stop_after = _strip_attached_command_separator(arg)
        if not arg:
            if stop_after:
                break
            idx += 1
            continue
        if arg in value_flags:
            idx += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in value_flags):
            idx += 1
            continue
        if arg.startswith("-"):
            idx += 1
            continue
        if _looks_like_external_reference(arg) or _looks_like_path_or_variable(arg):
            idx += 1
            continue
        specs.append(arg)
        if stop_after:
            break
        idx += 1
    return specs


def _strip_attached_command_separator(arg: str) -> tuple[str, bool]:
    for separator in ("&&", "||", ";", "|"):
        if arg.endswith(separator) and len(arg) > len(separator):
            return arg[: -len(separator)], True
    return arg, False


def _parse_pip_install_spec(spec: str) -> tuple[str, str] | None:
    match = PIP_EXACT_INSTALL_SPEC_RE.match(spec.strip())
    if not match:
        return None
    return match.group(1), match.group(2)


def _command_prefix_tokens(tokens: list[str], command_idx: int) -> list[str]:
    start = command_idx - 1
    while start >= 0 and tokens[start] not in COMMAND_SEPARATORS:
        start -= 1
    return tokens[start + 1 : command_idx]


def _has_option(args: list[str], names: set[str]) -> bool:
    for arg in args:
        if arg in names:
            return True
        if any(arg.startswith(f"{name}=") for name in names):
            return True
        if any(len(name) == 2 and arg.startswith(name) for name in names):
            return True
    return False


def _tokens_have_private_registry_option(args: list[str], names: set[str]) -> bool:
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in names:
            value = args[idx + 1] if idx + 1 < len(args) else ""
            if _private_or_unverified_registry_value(value):
                return True
            idx += 2
            continue
        for name in names:
            prefix = f"{name}="
            if arg.startswith(prefix):
                if _private_or_unverified_registry_value(arg[len(prefix) :]):
                    return True
        idx += 1
    return False


def _tokens_have_private_registry_env(args: list[str], prefixes: set[str]) -> bool:
    upper_prefixes = {prefix.upper() for prefix in prefixes}
    for arg in args:
        upper = arg.upper()
        for prefix in upper_prefixes:
            if not upper.startswith(prefix):
                continue
            value = arg.split("=", 1)[1] if "=" in arg else ""
            if _private_or_unverified_registry_value(value):
                return True
    return False


def _has_env_prefix(args: list[str], prefixes: set[str]) -> bool:
    upper_prefixes = {prefix.upper() for prefix in prefixes}
    for arg in args:
        upper = arg.upper()
        if any(upper.startswith(prefix) for prefix in upper_prefixes):
            return True
    return False


def _parse_npm_install_spec(spec: str) -> tuple[str, str] | None:
    raw = spec.strip()
    split_at = raw.rfind("@")
    if split_at <= 0:
        return None
    name = raw[:split_at]
    version = raw[split_at + 1 :]
    if not name or not version or not version[0].isdigit():
        return None
    if raw.startswith("@") and "/" not in name:
        return None
    return name, version


def _parse_go_install_spec(spec: str) -> tuple[str, str] | None:
    raw = spec.strip()
    split_at = raw.rfind("@")
    if split_at <= 0:
        return None
    name = raw[:split_at]
    version = _go_version(raw[split_at + 1 :]).lstrip("v")
    if not name or not version or not version[0].isdigit():
        return None
    if "/" not in name:
        return None
    return name, version


def _looks_like_external_reference(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://", "git+", "ssh://", "git@"))


def _looks_like_path_or_variable(value: str) -> bool:
    return value.startswith((".", "/", "~", "$", "${")) or value in {"-"}


def _install_dependency(
    path: Path,
    line_no: int,
    command: str,
    *,
    ecosystem: str,
    name: str,
    version: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "file": str(path),
        "line": line_no,
        "snippet": command.strip(),
        "source": INSTALL_SURFACE_SOURCE,
    }


def _private_or_unverified_dependency(
    dependency: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    tagged = dict(dependency)
    tagged["dependency_truth_state"] = STATUS_PRIVATE_OR_UNVERIFIED
    tagged["dependency_truth_source"] = "private_or_unverified_context"
    tagged["dependency_truth_reason"] = reason
    return tagged


def _filter_manifest_dirs(dirnames: list[str]) -> None:
    skipped = {
        ".git",
        ".skylos",
        "node_modules",
        "vendor",
        "dist",
        "build",
    }
    kept = []
    for dirname in dirnames:
        if dirname in skipped:
            continue
        kept.append(dirname)
    dirnames[:] = kept


def _manifest_depth(root: Path, dirpath: str) -> int:
    try:
        relative = Path(dirpath).resolve().relative_to(root)
    except (OSError, ValueError):
        return 0
    if not relative.parts:
        return 0
    return len(relative.parts)


def _unique_dependencies(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for dependency in dependencies:
        key = _dependency_unique_key(dependency)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    return unique


def _dependency_unique_key(dependency: dict[str, Any]) -> str:
    key = _dependency_key(dependency)
    state = normalize_dependency_truth_state(dependency.get("dependency_truth_state"))
    if state == DependencyTruthState.PRIVATE_OR_UNVERIFIED:
        return f"{key}:private_or_unverified"
    return f"{key}:registry"


def _dependency_key(dependency: dict[str, Any]) -> str:
    ecosystem = str(dependency.get("ecosystem", ""))
    name = str(dependency.get("name", ""))
    version = str(dependency.get("version", ""))
    return dependency_truth_cache_key(ecosystem, name, version)


def _legacy_dependency_key(dependency: dict[str, Any]) -> str:
    ecosystem = str(dependency.get("ecosystem", ""))
    name = str(dependency.get("name", ""))
    version = str(dependency.get("version", ""))
    return f"{ecosystem}:{name}:{version}"


def _load_version_cache(root: Path) -> dict[str, Any]:
    payload = load_project_json_cache(
        root,
        VERSION_CACHE_PATH,
        max_bytes=MAX_VERSION_CACHE_BYTES,
    )
    if payload.get("schema_version") != VERSION_CACHE_SCHEMA_VERSION:
        return _empty_version_cache()
    statuses = payload.get("statuses")
    if not isinstance(statuses, dict):
        payload["statuses"] = {}
    return payload


def _save_version_cache(root: Path, cache: dict[str, Any]) -> None:
    if not save_project_json_cache(root, VERSION_CACHE_PATH, cache):
        logger.debug("Failed to save dependency version cache")


def _empty_version_cache() -> dict[str, Any]:
    return {
        "schema_version": VERSION_CACHE_SCHEMA_VERSION,
        "statuses": {},
    }


def _cached_dependency_status(
    dependency: dict[str, Any],
    cache: dict[str, Any],
) -> str | None:
    statuses = cache.get("statuses")
    if not isinstance(statuses, dict):
        return None

    for key in (_dependency_key(dependency), _legacy_dependency_key(dependency)):
        status = statuses.get(key)
        if not isinstance(status, str):
            continue
        state = normalize_dependency_truth_state(status)
        if state in AUTHORITATIVE_CACHE_STATES:
            return state.value
    return None


def _record_dependency_status(
    dependency: dict[str, Any],
    cache: dict[str, Any],
    status: str,
) -> bool:
    state = normalize_dependency_truth_state(status)
    if state not in AUTHORITATIVE_CACHE_STATES:
        return False
    statuses = cache.get("statuses")
    if not isinstance(statuses, dict):
        statuses = {}
        cache["statuses"] = statuses
    statuses[_dependency_key(dependency)] = state.value
    return True


def _finding_for_status(
    dependency: dict[str, Any],
    status: DependencyTruthState | str,
    *,
    reason: str = "",
) -> dict[str, Any] | None:
    state = normalize_dependency_truth_state(status)
    source = "registry+lookalike" if state == DependencyTruthState.SUSPICIOUS_EXISTING else "registry"
    truth = DependencyTruthResult.from_dependency(
        dependency,
        state,
        source=source,
        reason=reason,
    )
    if truth.state == DependencyTruthState.MISSING_PACKAGE:
        return _missing_package_finding(dependency, truth)
    if truth.state == DependencyTruthState.MISSING_VERSION:
        return _missing_version_finding(dependency, truth)
    if truth.state == DependencyTruthState.SUSPICIOUS_EXISTING:
        return _suspicious_existing_finding(dependency, truth)
    return None


def _missing_package_finding(
    dependency: dict[str, Any],
    truth: DependencyTruthResult,
) -> dict[str, Any]:
    ecosystem = str(dependency["ecosystem"])
    name = str(dependency["name"])
    registry = _registry_label(ecosystem)
    message = (
        f"Hallucinated {ecosystem} dependency '{name}'. "
        f"Package does not exist in {registry}."
    )
    return _finding(
        dependency,
        rule_id=RULE_ID_DEPENDENCY_HALLUCINATION,
        severity=SEV_CRITICAL,
        message=message,
        truth=truth,
    )


def _missing_version_finding(
    dependency: dict[str, Any],
    truth: DependencyTruthResult,
) -> dict[str, Any]:
    ecosystem = str(dependency["ecosystem"])
    name = str(dependency["name"])
    version = str(dependency["version"])
    registry = _registry_label(ecosystem)
    message = (
        f"Hallucinated {ecosystem} dependency version '{name}@{version}'. "
        f"Version does not exist in {registry}."
    )
    return _finding(
        dependency,
        rule_id=RULE_ID_VERSION_HALLUCINATION,
        severity=SEV_HIGH,
        message=message,
        truth=truth,
    )


def _suspicious_existing_finding(
    dependency: dict[str, Any],
    truth: DependencyTruthResult,
) -> dict[str, Any]:
    ecosystem = str(dependency["ecosystem"])
    name = str(dependency["name"])
    version = str(dependency["version"])
    reason = truth.reason or "name closely resembles a known dependency"
    message = (
        f"Suspicious existing {ecosystem} dependency '{name}@{version}'. "
        f"{reason}."
    )
    return _finding(
        dependency,
        rule_id=RULE_ID_DEPENDENCY_HALLUCINATION,
        severity=SEV_HIGH,
        message=message,
        truth=truth,
        confidence=72,
    )


def _finding(
    dependency: dict[str, Any],
    *,
    rule_id: str,
    severity: str,
    message: str,
    truth: DependencyTruthResult,
    confidence: int = 86,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(dependency["file"]),
        "line": int(dependency["line"]),
        "col": 0,
        "symbol": f"{dependency['name']}@{dependency['version']}",
        "category": "ai_defect",
        "defect_type": VIBE_CATEGORY,
        "vibe_category": VIBE_CATEGORY,
        "ai_likelihood": AI_LIKELIHOOD,
        "confidence": confidence,
        "metadata": {
            "ecosystem": dependency["ecosystem"],
            "package_name": dependency["name"],
            "package_version": dependency["version"],
            "dependency_source": dependency.get("source", "manifest"),
            **truth.to_metadata(),
        },
    }


def _registry_label(ecosystem: str) -> str:
    if ecosystem == ECOSYSTEM_PYPI:
        return "PyPI"
    if ecosystem == ECOSYSTEM_NPM:
        return "the npm registry"
    if ecosystem == ECOSYSTEM_GO:
        return "the Go module proxy"
    return "the package registry"


def _suspicious_existing_dependency_reason(
    dependency: dict[str, Any],
    _dependencies: list[dict[str, Any]],
) -> str:
    ecosystem = str(dependency.get("ecosystem", ""))
    name = str(dependency.get("name", ""))
    normalized = _dependency_compare_name(ecosystem, name)
    if not normalized:
        return ""

    popular = POPULAR_PACKAGE_NAMES.get(ecosystem, set())
    if normalized in popular:
        return ""

    target = _near_miss_target(normalized, popular)
    if target:
        return f"Name closely resembles popular {ecosystem} package '{target}'"
    return ""


def _near_miss_target(candidate: str, targets: set[str]) -> str:
    if len(candidate) < 5:
        return ""
    for target in sorted(targets):
        if len(target) < 5:
            continue
        if _is_near_miss(candidate, target):
            return target
    return ""


def _dependency_compare_name(ecosystem: str, name: str) -> str:
    raw = name.strip().lower()
    if ecosystem == ECOSYSTEM_NPM and raw.startswith("@"):
        return ""
    return re.sub(r"[-_.]+", "", raw)


def _is_near_miss(candidate: str, target: str) -> bool:
    if candidate == target:
        return False
    if abs(len(candidate) - len(target)) > 1:
        return False
    if _damerau_distance_at_most_one(candidate, target):
        return True
    return SequenceMatcher(None, candidate, target).ratio() >= 0.92


def _damerau_distance_at_most_one(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return _same_length_edit_distance_at_most_one(left, right)
    longer, shorter = (left, right) if len(left) > len(right) else (right, left)
    return _one_extra_character_at_most(longer, shorter)


def _same_length_edit_distance_at_most_one(left: str, right: str) -> bool:
    diffs = [idx for idx, (a, b) in enumerate(zip(left, right)) if a != b]
    if len(diffs) == 1:
        return True
    if len(diffs) != 2:
        return False
    first, second = diffs
    return (
        second == first + 1
        and left[first] == right[second]
        and left[second] == right[first]
    )


def _one_extra_character_at_most(longer: str, shorter: str) -> bool:
    idx_long = 0
    idx_short = 0
    skipped = False
    while idx_long < len(longer) and idx_short < len(shorter):
        if longer[idx_long] == shorter[idx_short]:
            idx_long += 1
            idx_short += 1
            continue
        if skipped:
            return False
        skipped = True
        idx_long += 1
    return True


def _check_pypi_version(name: str, version: str) -> str:
    package_path = _safe_pypi_package_path(name)
    if package_path is None:
        return STATUS_UNKNOWN

    safe_version = quote(version.strip(), safe="")
    version_url = f"{PYPI_JSON_ORIGIN}/{package_path}/{safe_version}/json"
    try:
        _fetch_json(version_url, user_agent="skylos-pypi-dep-scanner/1.0")
        return STATUS_PRESENT
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    package_url = f"{PYPI_JSON_ORIGIN}/{package_path}/json"
    try:
        _fetch_json(package_url, user_agent="skylos-pypi-dep-scanner/1.0")
        return STATUS_MISSING_VERSION
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN


def _check_npm_version(name: str, version: str) -> str:
    package_path = _safe_npm_package_path(name)
    if package_path is None:
        return STATUS_UNKNOWN

    url = f"{NPM_REGISTRY_ORIGIN}/{package_path}"
    try:
        data = _fetch_json(url, user_agent="skylos-npm-dep-scanner/1.0")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    versions = data.get("versions")
    if not isinstance(versions, dict):
        return STATUS_UNKNOWN
    if version in versions:
        return STATUS_PRESENT
    return STATUS_MISSING_VERSION


def _check_go_version(name: str, version: str) -> str:
    module_path = _safe_go_module_path(name)
    if module_path is None:
        return STATUS_UNKNOWN

    go_version = _go_version(version)
    safe_go_version = quote(go_version, safe="")
    info_url = f"{GO_PROXY_ORIGIN}/{module_path}/@v/{safe_go_version}.info"
    try:
        _fetch_text(info_url, user_agent="skylos-go-dep-scanner/1.0")
        return STATUS_PRESENT
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN

    list_url = f"{GO_PROXY_ORIGIN}/{module_path}/@v/list"
    try:
        _fetch_text(list_url, user_agent="skylos-go-dep-scanner/1.0")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return STATUS_MISSING_PACKAGE
        return STATUS_UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return STATUS_UNKNOWN
    return STATUS_MISSING_VERSION


def _go_version(version: str) -> str:
    if version.startswith("v"):
        return version
    return f"v{version}"


def _safe_pypi_package_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("."):
        return None
    if "/" in raw:
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    for char in raw:
        if char.isalnum():
            continue
        if char in ("-", "_", "."):
            continue
        return None
    return quote(raw, safe="")


def _safe_npm_package_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("."):
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    if raw.startswith("@"):
        parts = raw.split("/")
        if len(parts) != 2:
            return None
        if not _safe_npm_name_part(parts[0][1:]):
            return None
        if not _safe_npm_name_part(parts[1]):
            return None
    else:
        if "/" in raw:
            return None
        if not _safe_npm_name_part(raw):
            return None
    return quote(raw, safe="@")


def _safe_npm_name_part(value: str) -> bool:
    if not value:
        return False
    for char in value:
        if char.isalnum():
            continue
        if char in ("-", "_", "."):
            continue
        return False
    return True


def _safe_go_module_path(name: str) -> str | None:
    raw = name.strip()
    if not raw:
        return None
    if raw.startswith("/"):
        return None
    if "\\" in raw:
        return None
    if ".." in raw:
        return None
    parts = raw.split("/")
    encoded_parts = []
    for part in parts:
        if not _safe_go_path_part(part):
            return None
        encoded_parts.append(quote(part, safe=""))
    return "/".join(encoded_parts)


def _safe_go_path_part(value: str) -> bool:
    if not value:
        return False
    for char in value:
        if char.isalnum():
            continue
        if char in ("-", "_", ".", "~"):
            continue
        return False
    return True


def _fetch_json(url: str, *, user_agent: str) -> dict[str, Any]:
    text = _fetch_text(url, user_agent=user_agent)
    data = json.loads(text)
    if isinstance(data, dict):
        return data
    return {}


def _fetch_text(url: str, *, user_agent: str) -> str:
    if not _allowed_registry_url(url):
        raise ValueError("Registry URL host is not allowed")

    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", user_agent)
    with urllib.request.urlopen(  # skylos: ignore[SKY-D216] URL is validated against fixed registry hosts above.
        request,
        timeout=5,
    ) as response:
        raw = response.read(MAX_REGISTRY_RESPONSE_BYTES + 1)
    if len(raw) > MAX_REGISTRY_RESPONSE_BYTES:
        raise ValueError("Registry response exceeds size limit")
    return raw.decode("utf-8", errors="replace")


def _allowed_registry_url(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return False
    if parsed.hostname not in ALLOWED_REGISTRY_HOSTS:
        return False
    if parsed.username:
        return False
    if parsed.password:
        return False
    if parsed.port is not None:
        return False
    return True
