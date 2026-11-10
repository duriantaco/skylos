"""Repository supply-chain posture and the package inventory for uploads.

``dependency_inventory_summary`` lists the packages the scan read (bounded,
sorted, de-duplicated) so Skylos Cloud can match new malware advisories
against repositories after the scan. ``supply_chain_posture`` records how the
repository installs dependencies. Every check is ``pass`` only with evidence
in the repository, ``unknown`` when the files cannot tell, and
``not_applicable`` when the ecosystem or CI system is absent. GitHub Actions
checks are derived from the existing SKY-D292 and SKY-D290 findings.

When ca9 provides ``hardening_settings``, its committed values (cooldowns in
their own units, npm 12 ``allowScripts``, pnpm 11 ``allowBuilds`` and
``strictDepBuilds``) are read first; Skylos's own readers fill the gaps. pnpm
11 and Yarn 4.15 hold new versions for a day by default, pnpm 10+ and npm 12
block dependency install scripts by default, Bun's ``minimumReleaseAge`` is in
seconds, and pip ``--uploaded-prior-to`` counts as a Python cooldown.
``ci_inventory`` and ``agent_hooks`` (see ``ci_agent_inventory``) are added
next to the dependency inventory.
"""

from __future__ import annotations

import json
import fnmatch
import os
import posixpath
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from skylos.core.safe_cache_io import read_text_no_symlink

INVENTORY_SCHEMA = "skylos.dependency_inventory.v1"
POSTURE_SCHEMA = "skylos.supply_chain_posture.v1"
INVENTORY_KEY = "dependency_inventory"
POSTURE_KEY = "supply_chain_posture"
CI_INVENTORY_KEY = "ci_inventory"
AGENT_HOOKS_KEY = "agent_hooks"
CHECKS_KEY = "supply_chain_checks"
SUMMARY_KEYS = (INVENTORY_KEY, POSTURE_KEY, CI_INVENTORY_KEY, AGENT_HOOKS_KEY)
INVENTORY_KEYS = (INVENTORY_KEY, CI_INVENTORY_KEY, AGENT_HOOKS_KEY)
UPLOAD_SUMMARY_KEYS = ("sca_coverage", "custom_rules_coverage", *SUMMARY_KEYS)
MAX_INVENTORY_PACKAGES = 10_000
MAX_POSTURE_PATHS = 10
MAX_CONFIG_BYTES = 1_000_000
MAX_CI_FILES = 200
PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
CHECK_IDS = (
    "lockfile_committed",
    "frozen_install_ci",
    "install_scripts_disabled",
    "release_age_cooldown",
    "actions_pinned",
    "no_pr_target_checkout",
)
ECOSYSTEM_IDS = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "Maven": "maven",
    "NuGet": "nuget",
    "crates.io": "crates.io",
    "Packagist": "packagist",
    "RubyGems": "rubygems",
    "Pub": "pub",
}
NPM_LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lock": "bun",
    "bun.lockb": "bun",
}
PYPI_LOCKFILES = frozenset(
    {"uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pylock.toml"}
)
NPM_MANIFESTS = frozenset({"package.json"})
PYPI_MANIFESTS = frozenset({"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"})
CI_FILE_NAMES = (
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    "Jenkinsfile",
    ".travis.yml",
    ".circleci/config.yml",
    ".buildkite/pipeline.yml",
)
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
)
_NON_INSTALL_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "testdata",
        "test_fixtures",
        "test-fixtures",
        "fixture",
        "fixtures",
        "__fixtures__",
        "example",
        "examples",
        "sample",
        "samples",
        "benchmark",
        "benchmarks",
    }
)


def _non_install_path(path: Path, root: Path) -> bool:
    """A manifest under a test, fixture, example or benchmark folder.

    The posture describes how the project itself installs; those folders
    hold inputs for tests and demos, not installs the project runs.
    """
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        return False
    return any(part.lower() in _NON_INSTALL_DIRS for part in parts)


_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||;|\||\n")
_PYTHON_PIP_RE = re.compile(r"^(?:python[0-9.]*|py)\s+-m\s+pip\s+")
_NPMRC_TRUE_RE = re.compile(
    r"^\s*ignore-scripts\s*=\s*true\s*$", re.IGNORECASE | re.MULTILINE
)
_YARNRC_IGNORE_RE = re.compile(
    r"^\s*ignore-scripts\s+[\"']?true[\"']?\s*$", re.IGNORECASE | re.MULTILINE
)
_NPMRC_AGE_RE = re.compile(
    r"^\s*min-release-age\s*=\s*([0-9]+)", re.IGNORECASE | re.MULTILINE
)
_YAML_KEY_RE = r"^\s*{key}\s*:\s*[\"']?([^\s\"'#]+)"
_TOML_KEY_RE = r"^\s*{key}\s*=\s*[\"']?([^\s\"'#]+)"
_PNPM_VERSION_RE = re.compile(r"^pnpm@(\d+)")
_YARN_VERSION_RE = re.compile(r"^yarn@(\d+)")


def _relative(path: object, root: Path) -> str:
    text = str(path or "")
    try:
        return Path(os.path.relpath(text, root)).as_posix()
    except ValueError:
        return Path(text).as_posix()


def _normalized_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def _inventory_package_source(
    dependency: dict, policy, *, requirements_includes=False
) -> str:
    """Classify recorded source evidence; name/version alone cannot prove it."""
    ecosystem = dependency.get("ecosystem")
    if ecosystem not in {"npm", "PyPI"} or dependency.get("exact") is False:
        return "unknown"
    name = _normalized_name(ecosystem, str(dependency.get("name") or ""))
    version = dependency.get("version")
    if not isinstance(version, str):
        return "unknown"
    if ecosystem == "npm":
        if not re.fullmatch(
            r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
        ):
            return "unknown"
    else:
        try:
            Version(version)
        except InvalidVersion:
            return "unknown"
    target = name.strip().lower().replace("_", "-").replace(".", "-")
    if any(
        fnmatch.fnmatchcase(
            target, pattern.strip().lower().replace("_", "-").replace(".", "-")
        )
        for pattern in policy.internal_packages
    ):
        return "private_registry"
    source = dependency.get("source_kind") or dependency.get("source_type")
    if source is not None and not isinstance(source, str):
        return "unknown"
    if source in {"git", "url", "path", "directory", "workspace", "local", "sdk"}:
        return "non_registry"
    if source == "registry_unspecified":
        return "unknown"
    if source not in {None, "registry", "npm_registry"}:
        return "unknown"
    if requirements_includes and "registry_mode" in dependency:
        # The aggregate requirements record does not retain conflicting index
        # options from every included file; it cannot prove a sole public index.
        return "unknown"
    registry = dependency.get("registry")
    registries = dependency.get("registries")
    if isinstance(registries, list) and len(registries) > 1:
        return "unknown"
    if not isinstance(registry, str) or not registry:
        return "unknown"
    try:
        parsed = urlsplit(registry if "://" in registry else "https://" + registry)
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
            or parsed.query
            or parsed.fragment
        ):
            return "unknown"
        host = (parsed.hostname or "").lower()
    except ValueError:
        return "unknown"
    public_host = "registry.npmjs.org" if ecosystem == "npm" else "pypi.org"
    if host != public_host:
        return "private_registry"
    if parsed.path.rstrip("/") not in ({""} if ecosystem == "npm" else {"", "/simple"}):
        return "unknown"
    if dependency.get("registry_mode") == "merged":
        return "unknown"
    for configured in policy.private_registries:
        configured = str(configured).lower().rstrip("/")
        if configured in {
            host,
            "https://" + host,
            "https://" + host + parsed.path.rstrip("/"),
        }:
            return "private_registry"
    return "public_registry"


def dependency_inventory_summary(inventory, root: str | Path) -> dict:
    """The ``analysis_summary.dependency_inventory`` upload contract."""
    root_path = Path(root).resolve()
    from skylos.supply_chain.policy import load_supply_chain_policy

    policy = load_supply_chain_policy(root_path)
    inventory_receipt = getattr(inventory, "receipt", None) or {}
    requirements_includes = bool(
        inventory_receipt.get("included_requirements_file_count")
    )
    rows: dict[tuple, dict] = {}
    occurrences = getattr(inventory, "occurrences", None)
    if occurrences is None:
        occurrences = list(inventory or [])
    for dependency in occurrences:
        ecosystem = str(dependency.get("ecosystem") or "")
        name = _normalized_name(ecosystem, str(dependency.get("name") or ""))
        version = str(dependency.get("version") or "")
        if not ecosystem or not name or not version:
            continue
        ecosystem_id = ECOSYSTEM_IDS.get(ecosystem, ecosystem.lower())
        file = _relative(dependency.get("file"), root_path)
        lockfile = "lockfile_version" in dependency
        direct = not lockfile or dependency.get("dependency_kind") == "direct"
        dev = dependency.get("dependency_dev") is True
        source = _inventory_package_source(
            dependency, policy, requirements_includes=requirements_includes
        )
        key = (ecosystem_id, name, version, file)
        row = rows.get(key)
        if row is None:
            rows[key] = {
                "ecosystem": ecosystem_id,
                "name": name,
                "version": version,
                "direct": direct,
                "dev": dev,
                "file": file,
                "_lockfile": lockfile,
            }
            if source != "unknown":
                rows[key]["source"] = source
            continue
        row["direct"] = row["direct"] or direct
        row["dev"] = row["dev"] and dev
        if row.get("source", "unknown") != source:
            row.pop("source", None)
    locked: dict[tuple, list[dict]] = {}
    for key, row in rows.items():
        if row["_lockfile"]:
            locked.setdefault(key[:3], []).append(row)
    packages = []
    for key in sorted(rows):
        row = rows[key]
        if row.pop("_lockfile") or key[:3] not in locked:
            packages.append(row)
            continue
        directory = posixpath.dirname(row["file"])
        for lock_row in locked[key[:3]]:
            if posixpath.dirname(lock_row["file"]) == directory:
                lock_row["direct"] = True
    total = len(packages)
    truncated = total > MAX_INVENTORY_PACKAGES
    receipt = getattr(inventory, "receipt", None) or {}
    return {
        "schema": INVENTORY_SCHEMA,
        "complete": receipt.get("status") == "complete" and not truncated,
        "truncated": truncated,
        "total": total,
        "packages": packages[:MAX_INVENTORY_PACKAGES],
    }


def _check(check_id: str, status: str, detail: str, paths=()) -> dict:
    return {
        "id": check_id,
        "status": status,
        "detail": detail[:300],
        "paths": sorted(dict.fromkeys(paths))[:MAX_POSTURE_PATHS],
    }


def _read(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        return read_text_no_symlink(
            path, max_bytes=MAX_CONFIG_BYTES, encoding="utf-8", errors="ignore"
        )
    except (OSError, ValueError):
        return None


_CONFIG_NAMES = frozenset(
    {
        ".npmrc",
        ".yarnrc",
        ".yarnrc.yml",
        "bunfig.toml",
        "pnpm-workspace.yaml",
        "uv.toml",
    }
)
_WALK_NAMES = (
    frozenset(NPM_LOCKFILES)
    | PYPI_LOCKFILES
    | NPM_MANIFESTS
    | PYPI_MANIFESTS
    | _CONFIG_NAMES
)
MAX_WALK_FILES = 5000
MAX_WALK_DIRECTORIES = 10_000


def _is_requirements_file(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _walk_files(root: Path) -> list[Path]:
    found = []
    for directories, (dirpath, dirnames, filenames) in enumerate(os.walk(root), 1):
        if directories > MAX_WALK_DIRECTORIES or len(found) > MAX_WALK_FILES:
            break
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in filenames:
            if filename in _WALK_NAMES or _is_requirements_file(filename):
                found.append(Path(dirpath) / filename)
    return sorted(found)


class _Repository:
    """Files the posture checks read, collected once."""

    def __init__(self, root: Path, inventory):
        self.root = root
        self.inventory = inventory
        files = [
            path for path in _walk_files(root) if not _non_install_path(path, root)
        ]
        self.tracked = _git_tracked(root, files)
        self.untracked_lockfiles = []
        if self.tracked is not None:
            self.untracked_lockfiles = [
                path
                for path in files
                if path not in self.tracked
                and (path.name in NPM_LOCKFILES or path.name in PYPI_LOCKFILES)
                and _has_tracked_manifest(path.parent, self.tracked)
            ]
            files = [path for path in files if path in self.tracked]
        self.files = files
        self.requirements = [path for path in files if _is_requirements_file(path.name)]
        self.npm_lockfiles = [path for path in files if path.name in NPM_LOCKFILES]
        self.pypi_lockfiles = [path for path in files if path.name in PYPI_LOCKFILES]
        self.package_jsons = [
            path
            for path in files
            if path.name == "package.json" and _declares_npm_dependencies(path)
        ]
        self.pypi_manifests = [
            path
            for path in files
            if path.name in PYPI_MANIFESTS and _declares_python_dependencies(path)
        ]
        self.ci_files = _ci_files(root)
        self._ci_text = None

    @property
    def has_npm(self) -> bool:
        return bool(self.npm_lockfiles or self.package_jsons)

    @property
    def has_pypi(self) -> bool:
        return bool(self.pypi_lockfiles or self.pypi_manifests or self.requirements)

    def ecosystems(self) -> list[str]:
        found = []
        if self.has_npm:
            found.append("npm")
        if self.has_pypi:
            found.append("pypi")
        return found

    def ci_text(self) -> dict[Path, str]:
        if self._ci_text is None:
            self._ci_text = {}
            for path in self.ci_files:
                text = _read(path)
                if text is not None:
                    self._ci_text[path] = text
        return self._ci_text

    def rel(self, path: Path) -> str:
        return _relative(path, self.root)

    def npm_managers(self) -> dict[str, list[Path]]:
        managers: dict[str, list[Path]] = {}
        for path in self.npm_lockfiles:
            managers.setdefault(NPM_LOCKFILES[path.name], []).append(path)
        if not managers and self.package_jsons:
            declared = _package_manager(self.package_jsons[0])
            managers[declared or "npm"] = list(self.package_jsons[:1])
        return managers


def _declares_npm_dependencies(path: Path) -> bool:
    text = _read(path)
    if text is None:
        return False
    try:
        data = json.loads(text)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    return any(
        isinstance(data.get(section), dict) and data[section]
        for section in ("dependencies", "devDependencies", "optionalDependencies")
    )


def _declares_python_dependencies(path: Path) -> bool:
    text = _read(path)
    if text is None:
        return False
    if path.name == "pyproject.toml":
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        try:
            data = tomllib.loads(text)
        except ValueError:
            return False
        project = data.get("project")
        poetry = (data.get("tool") or {}).get("poetry")
        if isinstance(project, dict) and project.get("dependencies"):
            return True
        return isinstance(poetry, dict) and bool(poetry.get("dependencies"))
    if path.name == "Pipfile":
        return "[packages]" in text or "[dev-packages]" in text
    return "install_requires" in text


def _package_manager(path: Path) -> str | None:
    text = _read(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("packageManager")
    if not isinstance(value, str):
        return None
    return value.split("@", 1)[0] or None


def _package_manager_major(paths: list[Path], pattern: re.Pattern) -> int | None:
    for path in paths:
        text = _read(path)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not isinstance(data, dict) or not isinstance(
            data.get("packageManager"), str
        ):
            continue
        match = pattern.match(data["packageManager"])
        if match is not None:
            return int(match.group(1))
    return None


def _ci_files(root: Path) -> list[Path]:
    found = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir() and not workflows.is_symlink():
        found.extend(
            sorted(
                path
                for path in workflows.iterdir()
                if path.suffix.lower() in {".yml", ".yaml"} and path.is_file()
            )
        )
    for name in CI_FILE_NAMES:
        path = root / name
        if path.is_file() and not path.is_symlink():
            found.append(path)
    return found[:MAX_CI_FILES]


def _workflow_files(root: Path) -> list[Path]:
    """Workflows GitHub runs: files directly in ``.github/workflows``."""
    workflows = root / ".github" / "workflows"
    return [path for path in _ci_files(root) if path.parent == workflows]


def _git_tracked(root: Path, paths: list[Path]) -> set[Path] | None:
    """Which of ``paths`` Git tracks; None when Git cannot say."""
    from skylos.core.file_discovery import find_git_root
    from skylos.core.git_context import GitContext

    if find_git_root(root) is None:
        return None
    try:
        context = GitContext.from_path(root)
        relative = [context.relative_path(path) for path in paths]
        if not any(relative):
            return set()
        result = context.run("ls-files", "-z")
    except (OSError, ValueError, RuntimeError):
        return None
    except Exception:  # noqa: BLE001 - git failures make the check unknown
        return None
    if result.returncode != 0:
        return None
    tracked = {item for item in result.stdout.split("\0") if item}
    return {path for path, item in zip(paths, relative) if item and item in tracked}


def _has_tracked_manifest(directory: Path, tracked: set[Path]) -> bool:
    return any(
        path.parent == directory
        and (
            path.name in NPM_MANIFESTS
            or path.name in PYPI_MANIFESTS
            or _is_requirements_file(path.name)
        )
        for path in tracked
    )


def _requirements_pinned(path: Path) -> bool:
    text = _read(path)
    if text is None:
        return False
    if "--hash" in text:
        return True
    lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    entries = [line for line in lines if line and not line.startswith("-")]
    return bool(entries) and all("==" in line for line in entries)


def _covered(directory: Path, lock_dirs: set[Path], root: Path) -> bool:
    current = directory
    while True:
        if current in lock_dirs:
            return True
        if current == root or root not in current.parents:
            return False
        current = current.parent


def _lockfile_committed(repo: _Repository) -> dict:
    check_id = "lockfile_committed"
    if not (repo.has_npm or repo.has_pypi):
        return _check(check_id, NOT_APPLICABLE, "no npm or Python dependency manifests")
    npm_dirs = {path.parent for path in repo.npm_lockfiles}
    pypi_dirs = {path.parent for path in repo.pypi_lockfiles}
    pinned_requirements = [
        path for path in repo.requirements if _requirements_pinned(path)
    ]
    pypi_dirs.update(path.parent for path in pinned_requirements)
    missing = [
        path
        for path in repo.package_jsons
        if not _covered(path.parent, npm_dirs, repo.root)
    ]
    missing.extend(
        path
        for path in repo.pypi_manifests
        if not _covered(path.parent, pypi_dirs, repo.root)
    )
    missing.extend(
        path
        for path in repo.requirements
        if path not in pinned_requirements
        and not _covered(path.parent, pypi_dirs, repo.root)
    )
    if missing:
        names = ", ".join(repo.rel(path) for path in missing[:3])
        return _check(
            check_id,
            FAIL,
            f"no lockfile for {names}",
            [repo.rel(path) for path in missing],
        )
    locks = [*repo.npm_lockfiles, *repo.pypi_lockfiles, *pinned_requirements]
    tracked = repo.tracked
    if tracked is None:
        return _check(
            check_id,
            UNKNOWN,
            "lockfiles exist but this is not a Git checkout, so whether they are committed is unknown",
            [repo.rel(path) for path in locks],
        )
    untracked = repo.untracked_lockfiles
    if untracked:
        return _check(
            check_id,
            FAIL,
            f"lockfile not committed: {repo.rel(untracked[0])}",
            [repo.rel(path) for path in untracked],
        )
    return _check(
        check_id,
        PASS,
        f"{len(locks)} lockfile(s) committed",
        [repo.rel(path) for path in locks],
    )


def _segments(text: str):
    for raw in _SEGMENT_SPLIT_RE.split(text):
        segment = raw.strip().strip("-").strip()
        if segment.startswith(("run:", "script:", "sh ", "sh:")):
            segment = segment.split(":", 1)[-1].strip()
        segment = segment.strip("'\"` ")
        if segment:
            yield segment


_VALUE_OPTIONS = frozenset(
    {
        "--prefix",
        "-C",
        "--cwd",
        "--dir",
        "--directory",
        "--workspace",
        "-w",
        "--filter",
        "--registry",
        "--cache",
        "--omit",
        "--include",
        "--loglevel",
        "--project",
        "--python",
        "-p",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--target",
        "-t",
        "--constraint",
        "-c",
        "--group",
        "--extra",
        "--only",
        "--with",
        "--without",
        "-r",
        "--requirement",
    }
)


def _positional(args: list[str]) -> list[str]:
    """Arguments that are not options or the values of options."""
    found = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _VALUE_OPTIONS
            continue
        found.append(arg)
    return found


def _requirement_files(args: list[str]) -> list[str]:
    files = [
        args[index + 1]
        for index, arg in enumerate(args[:-1])
        if arg in {"-r", "--requirement"}
    ]
    files.extend(
        arg.split("=", 1)[1] for arg in args if arg.startswith("--requirement=")
    )
    return files


def _pip_install(args: list[str], flags: set[str], positional: list[str], root: Path):
    """``frozen`` for a pip/uv pip project install, or None for an explicit
    tool install such as ``pip install build``."""
    files = _requirement_files(args)
    project = [
        arg
        for arg in positional[1:]
        if arg in {".", "./"} or arg.startswith((".[", "./"))
    ]
    if not files and not project and "-e" not in flags:
        return None
    if "--require-hashes" in flags:
        return True
    if project or "-e" in flags:
        return False
    return all(_requirements_hashed(root / name) for name in files)


def _install_command(segment: str, root: Path):
    """(manager, frozen, ignore_scripts) for one shell command that installs
    the project's dependencies, or None."""
    segment = re.sub(r"^(?:sudo\s+|corepack\s+)", "", segment)
    segment = _PYTHON_PIP_RE.sub("pip ", segment)
    tokens = [token.strip("'\"") for token in segment.split()]
    if not tokens:
        return None
    manager = tokens[0]
    args = tokens[1:]
    flags = {arg.split("=", 1)[0] for arg in args if arg.startswith("-")}
    positional = _positional(args)
    first = positional[:1]
    ignore_scripts = "--ignore-scripts" in flags
    if manager == "npm" and first in (["ci"], ["clean-install"]):
        return "npm", True, ignore_scripts
    if manager == "npm" and first in (["install"], ["i"]):
        if len(positional) > 1 or {"-g", "--global"} & flags:
            return None
        return "npm", False, ignore_scripts
    if manager == "yarn" and (not positional or positional == ["install"]):
        return (
            "yarn",
            bool({"--frozen-lockfile", "--immutable"} & flags),
            ignore_scripts,
        )
    if manager == "pnpm" and positional in (["install"], ["i"]):
        return "pnpm", "--no-frozen-lockfile" not in flags, ignore_scripts
    if manager == "bun" and positional in (["install"], ["i"], ["ci"]):
        return (
            "bun",
            positional == ["ci"] or "--frozen-lockfile" in flags,
            ignore_scripts,
        )
    if manager in {"pip", "pip3"} and first == ["install"]:
        frozen = _pip_install(args, flags, positional, root)
        if frozen is None:
            return None
        return "pip", frozen, False
    if manager == "uv" and first == ["sync"]:
        return "uv", bool({"--locked", "--frozen"} & flags), False
    if manager == "uv" and positional[:2] in (["pip", "install"], ["pip", "sync"]):
        frozen = _pip_install(args, flags, positional[1:], root)
        if frozen is None:
            return None
        return "uv pip", frozen, False
    if manager == "poetry" and first == ["install"]:
        return "poetry", True, False
    if manager == "poetry" and first == ["update"]:
        return "poetry", False, False
    if manager == "pipenv" and first == ["sync"]:
        return "pipenv", True, False
    if manager == "pipenv" and positional == ["install"]:
        return "pipenv", "--deploy" in flags, False
    return None


def _ci_installs(repo: _Repository) -> list[tuple[Path, str, bool, bool]]:
    installs = []
    for path, text in repo.ci_text().items():
        for segment in _segments(text):
            command = _install_command(segment, repo.root)
            if command is not None:
                installs.append((path, *command))
    return installs


def _requirements_hashed(path: Path) -> bool:
    text = _read(path)
    return text is not None and "--hash" in text


def _yarn_berry(repo: _Repository) -> bool:
    if any(path.name == ".yarnrc.yml" for path in repo.files):
        return True
    major = _package_manager_major(repo.package_jsons, _YARN_VERSION_RE)
    return major is not None and major >= 2


def _frozen_install_ci(repo: _Repository) -> dict:
    check_id = "frozen_install_ci"
    if not (repo.has_npm or repo.has_pypi):
        return _check(check_id, NOT_APPLICABLE, "no npm or Python dependencies")
    if not repo.ci_files:
        return _check(check_id, NOT_APPLICABLE, "no CI configuration found")
    installs = _ci_installs(repo)
    if not installs:
        return _check(
            check_id,
            UNKNOWN,
            "no dependency install command recognised in CI files",
            [repo.rel(path) for path in repo.ci_files],
        )
    berry = _yarn_berry(repo)
    loose = [
        (path, manager)
        for path, manager, frozen, _ in installs
        if not frozen and not (manager == "yarn" and berry)
    ]
    if loose:
        path, manager = loose[0]
        return _check(
            check_id,
            FAIL,
            f"{manager} install in {repo.rel(path)} can change the lockfile; use npm ci, "
            "--frozen-lockfile/--immutable, uv sync --locked or pip --require-hashes",
            [repo.rel(path) for path, _ in loose],
        )
    return _check(
        check_id,
        PASS,
        "every recognised CI install uses the lockfile as is",
        [repo.rel(path) for path, _, _, _ in installs],
    )


def _config_value(paths: list[Path], pattern: str) -> tuple[Path, str] | None:
    expression = re.compile(pattern, re.MULTILINE)
    for path in paths:
        text = _read(path)
        if text is None:
            continue
        match = expression.search(text)
        if match is not None:
            return path, match.group(1)
    return None


def _config_files(repo: _Repository, name: str) -> list[Path]:
    """Config files that apply to the projects found; in a Git checkout only
    committed ones, since a local file does not configure CI installs."""
    directories = {repo.root}
    directories.update(path.parent for path in repo.npm_lockfiles)
    directories.update(path.parent for path in repo.package_jsons[:20])
    found = []
    for directory in sorted(directories):
        path = directory / name
        if not path.is_file():
            continue
        if repo.tracked is not None and path not in repo.tracked:
            continue
        found.append(path)
    return found


class _Facts:
    """Install-hardening settings from ``ca9.api.hardening_settings``.

    A value counts only when the file it came from is committed (or the
    folder is not a Git checkout), like the files the fallback reads.
    """

    def __init__(self, repo: _Repository, settings):
        self.repo = repo
        self.settings = {}
        if isinstance(settings, dict):
            self.settings = settings

    def _source_ok(self, key: str) -> bool:
        sources = self.settings.get("sources")
        if not isinstance(sources, dict):
            return False
        source = sources.get(key)
        if not isinstance(source, str) or not source:
            return False
        path = self.repo.root / source
        if self.repo.tracked is None:
            return path.is_file()
        return path in self.repo.tracked

    def value(self, section: str, key: str):
        table = self.settings.get(section)
        if not isinstance(table, dict) or table.get(key) is None:
            return None
        if not self._source_ok(key):
            return None
        return table[key]

    def source(self, key: str) -> str:
        sources = self.settings.get("sources") or {}
        return str(sources.get(key) or "")


def _hardening_settings(root: Path, api) -> tuple[dict | None, dict]:
    if api is None or not callable(getattr(api, "hardening_settings", None)):
        return None, {
            "status": "unavailable",
            "note": "ca9.api.hardening_settings is unavailable; posture used Skylos's own readers",
        }
    try:
        settings = api.hardening_settings(str(root))
    except Exception as exc:  # noqa: BLE001 - posture falls back to its own readers
        return None, {"status": "failed", "error_type": type(exc).__name__}
    if not isinstance(settings, dict):
        return None, {"status": "failed"}
    return settings, {"status": str(settings.get("status") or "complete")[:20]}


def _number(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", value)
        if match is not None:
            return float(match.group(1))
    return None


def _manager_version(repo: _Repository, name: str) -> tuple[int, int] | None:
    pattern = re.compile(rf"^{name}@(\d+)(?:\.(\d+))?")
    for path in repo.package_jsons:
        text = _read(path)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        if not isinstance(data, dict) or not isinstance(
            data.get("packageManager"), str
        ):
            continue
        match = pattern.match(data["packageManager"])
        if match is not None:
            return int(match.group(1)), int(match.group(2) or 0)
    return None


def _allow_list(facts: _Facts, key: str) -> list[str]:
    value = facts.value("scripts", key)
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _pnpm_scripts(repo: _Repository, facts: _Facts) -> tuple[str, str]:
    workspace = _config_files(repo, "pnpm-workspace.yaml")
    allow_all = facts.value("scripts", "pnpm_dangerously_allow_all_builds")
    if allow_all is None:
        found = _config_value(
            workspace, _YAML_KEY_RE.format(key="dangerouslyAllowAllBuilds")
        )
        if found and found[1].lower() == "true":
            allow_all = True
    if allow_all is True:
        return (
            FAIL,
            "pnpm: dangerouslyAllowAllBuilds runs every dependency build script",
        )
    version = _manager_version(repo, "pnpm")
    npmrc = [
        path
        for path in _config_files(repo, ".npmrc")
        if _NPMRC_TRUE_RE.search(_read(path) or "")
    ]
    if version is None and npmrc:
        return PASS, f"pnpm: ignore-scripts=true in {repo.rel(npmrc[0])}"
    if version is None:
        return (
            UNKNOWN,
            "pnpm version unknown (pnpm 10+ blocks dependency scripts by default)",
        )
    major = version[0]
    if major < 10:
        if npmrc:
            return PASS, f"pnpm {major}: ignore-scripts=true in {repo.rel(npmrc[0])}"
        return FAIL, f"pnpm {major} runs dependency install scripts"
    allowed = _allow_list(facts, "pnpm_allow_builds") or _allow_list(
        facts, "pnpm_only_built_dependencies"
    )
    detail = f"pnpm {major}: dependency build scripts blocked by default"
    if allowed:
        detail += f"; {len(allowed)} allowed (allowBuilds)"
    strict = facts.value("scripts", "pnpm_strict_dep_builds")
    if strict is None:
        found = _config_value(workspace, _YAML_KEY_RE.format(key="strictDepBuilds"))
        if found:
            strict = found[1].lower() != "false"
    if major >= 11 and strict is False:
        detail += "; strictDepBuilds false skips unapproved builds instead of failing"
    return PASS, detail


def _npm_scripts(repo: _Repository, facts: _Facts) -> tuple[str, str] | None:
    if facts.value("scripts", "npm_ignore_scripts") is True:
        return PASS, f"npm: ignore-scripts=true in {facts.source('npm_ignore_scripts')}"
    version = _manager_version(repo, "npm")
    if version is not None and version[0] >= 12:
        detail = f"npm {version[0]}: dependency install scripts off by default"
        allowed = _allow_list(facts, "npm12_allow_scripts")
        if allowed:
            detail += f"; {len(allowed)} allowed (allowScripts)"
        return PASS, detail
    return None


def _install_scripts_disabled(repo: _Repository, facts: _Facts) -> dict:
    check_id = "install_scripts_disabled"
    if not repo.has_npm:
        return _check(
            check_id, NOT_APPLICABLE, "no npm dependencies (npm lifecycle scripts only)"
        )
    installs = [
        item for item in _ci_installs(repo) if item[1] in {"npm", "yarn", "pnpm", "bun"}
    ]
    ci_ignores = bool(installs) and all(item[3] for item in installs)
    npmrc = [
        path
        for path in _config_files(repo, ".npmrc")
        if _NPMRC_TRUE_RE.search(_read(path) or "")
    ]
    failing = []
    unknown = []
    evidence = []
    for manager in sorted(repo.npm_managers()):
        if ci_ignores:
            evidence.append(f"{manager}: CI installs pass --ignore-scripts")
            continue
        if manager == "pnpm":
            status, detail = _pnpm_scripts(repo, facts)
            {PASS: evidence, FAIL: failing, UNKNOWN: unknown}[status].append(detail)
            continue
        if manager == "npm":
            found = _npm_scripts(repo, facts)
            if found is not None:
                evidence.append(found[1])
                continue
        if manager in {"npm", "yarn"} and npmrc:
            evidence.append(f"{manager}: ignore-scripts=true in {repo.rel(npmrc[0])}")
            continue
        if manager == "bun":
            evidence.append("bun: dependency scripts run only for trustedDependencies")
            continue
        if manager == "yarn":
            if _yarn_berry(repo):
                found = _config_value(
                    _config_files(repo, ".yarnrc.yml"),
                    _YAML_KEY_RE.format(key="enableScripts"),
                )
                if found and found[1].lower() == "false":
                    evidence.append(
                        f"yarn: enableScripts false in {repo.rel(found[0])}"
                    )
                    continue
            else:
                yarnrc = [
                    path
                    for path in _config_files(repo, ".yarnrc")
                    if _YARNRC_IGNORE_RE.search(_read(path) or "")
                ]
                if yarnrc:
                    evidence.append(
                        f"yarn: ignore-scripts true in {repo.rel(yarnrc[0])}"
                    )
                    continue
        failing.append(f"{manager} runs dependency install scripts")
    paths = [repo.rel(path) for path in _config_files(repo, ".npmrc")] or [".npmrc"]
    if failing:
        return _check(
            check_id,
            FAIL,
            "; ".join(failing)
            + ": no ignore-scripts=true in .npmrc and CI installs without --ignore-scripts",
            paths,
        )
    if unknown:
        return _check(check_id, UNKNOWN, "; ".join(unknown), paths)
    return _check(check_id, PASS, "; ".join(evidence), paths)


def _positive(value: str) -> bool:
    digits = re.match(r"\d+", value)
    if digits is not None:
        return int(digits.group(0)) > 0
    return bool(value.strip())


BUN_MIN_SECONDS = 3600


def _npm_cooldown(repo: _Repository, facts: _Facts, manager: str):
    """(passed, evidence or hint, path) for one npm-family manager."""
    if manager == "npm":
        days = _number(facts.value("cooldown", "npm_days"))
        if days is not None:
            if days <= 0:
                return False, "npm: min-release-age is 0 (off)", ".npmrc"
            return True, f"npm: min-release-age {days:g} days in .npmrc", ".npmrc"
        found = _config_value(_config_files(repo, ".npmrc"), _NPMRC_AGE_RE.pattern)
        if found and _positive(found[1]):
            return True, f"npm: {repo.rel(found[0])}", ".npmrc"
        return False, "no min-release-age in .npmrc", ".npmrc"
    if manager == "pnpm":
        minutes = _number(facts.value("cooldown", "pnpm_minutes"))
        if minutes is None:
            found = _config_value(
                _config_files(repo, "pnpm-workspace.yaml"),
                _YAML_KEY_RE.format(key="minimumReleaseAge"),
            )
            if found:
                minutes = _number(found[1])
        if minutes is not None and minutes <= 0:
            return False, "pnpm: minimumReleaseAge is 0 (off)", "pnpm-workspace.yaml"
        if minutes is not None:
            return (
                True,
                f"pnpm: minimumReleaseAge {minutes:g} minutes",
                "pnpm-workspace.yaml",
            )
        version = _manager_version(repo, "pnpm")
        if version is not None and version[0] >= 11:
            return (
                True,
                f"pnpm {version[0]}: 1-day minimumReleaseAge by default",
                "package.json",
            )
        return (
            False,
            "no minimumReleaseAge in pnpm-workspace.yaml",
            "pnpm-workspace.yaml",
        )
    if manager == "yarn":
        gate = facts.value("cooldown", "yarn")
        if gate is None:
            found = _config_value(
                _config_files(repo, ".yarnrc.yml"),
                _YAML_KEY_RE.format(key="npmMinimalAgeGate"),
            )
            if found:
                gate = found[1]
        if gate is not None:
            return (
                _positive(str(gate)),
                f"yarn: npmMinimalAgeGate {gate}",
                ".yarnrc.yml",
            )
        version = _manager_version(repo, "yarn")
        if version is not None and version >= (4, 15):
            return (
                True,
                f"yarn {version[0]}.{version[1]}: 1-day npmMinimalAgeGate by default",
                "package.json",
            )
        return False, "no npmMinimalAgeGate in .yarnrc.yml", ".yarnrc.yml"
    seconds = _number(facts.value("cooldown", "bun_seconds"))
    if seconds is None:
        found = _config_value(
            _config_files(repo, "bunfig.toml"),
            _TOML_KEY_RE.format(key="minimumReleaseAge"),
        )
        if found:
            seconds = _number(found[1])
    if seconds is None:
        return False, "no minimumReleaseAge in bunfig.toml", "bunfig.toml"
    if seconds < BUN_MIN_SECONDS:
        return (
            False,
            f"bunfig.toml minimumReleaseAge is in seconds; {seconds:g} s is under an hour",
            "bunfig.toml",
        )
    return (
        True,
        f"bun: minimumReleaseAge {seconds:g} s ({seconds / 86400:.1f} days)",
        "bunfig.toml",
    )


_PIP_PRIOR_RE = re.compile(
    r"--uploaded-prior-to\b|\bPIP_UPLOADED_PRIOR_TO\s*[:=]|^\s*uploaded[-_]prior[-_]to\s*=",
    re.MULTILINE,
)


def _pypi_cooldown(repo: _Repository, facts: _Facts) -> str | None:
    uv = facts.value("cooldown", "uv")
    if uv is not None:
        return f"uv: exclude-newer in {facts.source('uv')}"
    candidates = [
        path
        for path in (repo.root / "pyproject.toml", repo.root / "uv.toml")
        if repo.tracked is None or path in repo.tracked
    ]
    found = _config_value(candidates, _TOML_KEY_RE.format(key="exclude-newer"))
    if found:
        return f"uv: exclude-newer in {repo.rel(found[0])}"
    if facts.value("cooldown", "pip") is not None:
        return f"pip: uploaded-prior-to in {facts.source('pip')}"
    for path in [*repo.requirements, *_config_files(repo, "pip.conf")]:
        if _PIP_PRIOR_RE.search(_read(path) or ""):
            return f"pip: --uploaded-prior-to in {repo.rel(path)}"
    for path, text in repo.ci_text().items():
        if _PIP_PRIOR_RE.search(text):
            return f"pip: --uploaded-prior-to in {repo.rel(path)}"
    return None


def _dependabot_note(repo: _Repository, facts: _Facts) -> str:
    days = _number(facts.value("cooldown", "dependabot_days"))
    if days is None:
        found = [
            repo.root / ".github" / name
            for name in ("dependabot.yml", "dependabot.yaml")
            if (repo.root / ".github" / name).is_file()
        ]
        if not found:
            return ""
        return (
            "; Dependabot's cooldown (3 days by default) delays only its own "
            "pull requests, not installs"
        )
    return (
        f"; Dependabot waits {days:g} days before proposing updates, which "
        "delays only its own pull requests, not installs"
    )


def _release_age_cooldown(repo: _Repository, policy, facts: _Facts) -> dict:
    check_id = "release_age_cooldown"
    if not (repo.has_npm or repo.has_pypi):
        return _check(check_id, NOT_APPLICABLE, "no npm or Python dependencies")
    hours = None
    if policy is not None:
        hours = policy.scan_release_age_hours()
    if hours:
        return _check(
            check_id,
            PASS,
            f"Skylos policy holds versions younger than {hours} hours (min_release_age_hours)",
            ["pyproject.toml"],
        )
    missing = []
    evidence = []
    paths = []
    if repo.has_npm:
        for manager in sorted(repo.npm_managers()):
            passed, text, path = _npm_cooldown(repo, facts, manager)
            paths.append(path)
            if passed:
                evidence.append(text)
            else:
                missing.append(text)
    if repo.has_pypi:
        paths.append("pyproject.toml")
        found = _pypi_cooldown(repo, facts)
        if found:
            evidence.append(found)
        else:
            missing.append(
                "no uv exclude-newer or pip --uploaded-prior-to for Python dependencies"
            )
    if missing:
        return _check(
            check_id, FAIL, "; ".join(missing) + _dependabot_note(repo, facts), paths
        )
    return _check(check_id, PASS, "; ".join(evidence), paths)


def _actions_checks(root: Path, workflow_findings) -> tuple[dict, dict]:
    pinned_id = "actions_pinned"
    target_id = "no_pr_target_checkout"
    workflows = _workflow_files(root)
    if not workflows:
        return (
            _check(pinned_id, NOT_APPLICABLE, "no GitHub Actions workflows"),
            _check(target_id, NOT_APPLICABLE, "no GitHub Actions workflows"),
        )
    errors: list[dict] = []
    findings = workflow_findings
    if findings is None:
        try:
            from skylos.rules.config.cicd.github_actions import (
                scan_github_actions_file,
            )

            findings = []
            for path in workflows:
                findings.extend(
                    scan_github_actions_file(path, root=root, analysis_errors=errors)
                )
        except Exception:  # noqa: BLE001 - a workflow reader failure makes these unknown
            message = "GitHub Actions workflows could not be read"
            return (
                _check(pinned_id, UNKNOWN, message),
                _check(target_id, UNKNOWN, message),
            )
    rel = [_relative(path, root) for path in workflows]
    unpinned = [
        finding
        for finding in findings
        if finding.get("rule_id") == "SKY-D292" and not finding.get("low_risk_context")
    ]
    owned_tags = [
        finding
        for finding in findings
        if finding.get("rule_id") == "SKY-D292" and finding.get("low_risk_context")
    ]
    pr_target = [
        finding
        for finding in findings
        if finding.get("rule_id") == "SKY-D290"
        and _pr_code_trigger(str(finding.get("message") or ""))
    ]
    if unpinned:
        pinned = _check(
            pinned_id,
            FAIL,
            f"{len(unpinned)} action or reusable workflow reference(s) not pinned to a commit SHA (SKY-D292)",
            [_relative(finding.get("file"), root) for finding in unpinned],
        )
    elif errors:
        pinned = _check(
            pinned_id, UNKNOWN, "some workflow files could not be parsed", rel
        )
    else:
        detail = (
            "every third-party action and reusable workflow is pinned to a commit SHA"
        )
        if owned_tags:
            detail += f"; {len(owned_tags)} GitHub-owned action(s) use release tags"
        pinned = _check(pinned_id, PASS, detail, rel)
    if pr_target:
        target = _check(
            target_id,
            FAIL,
            "a pull_request_target or comment-triggered job runs pull request code with privileges (SKY-D290)",
            [_relative(finding.get("file"), root) for finding in pr_target],
        )
    elif errors:
        target = _check(
            target_id, UNKNOWN, "some workflow files could not be parsed", rel
        )
    else:
        target = _check(
            target_id,
            PASS,
            "no privileged workflow runs pull request code",
            rel,
        )
    return pinned, target


def _pr_code_trigger(message: str) -> bool:
    text = message.lower()
    return "pull_request_target" in text or "issue_comment" in text


def supply_chain_posture(
    root: str | Path,
    inventory=None,
    policy=None,
    *,
    workflow_findings=None,
    hardening=None,
) -> dict:
    """The ``analysis_summary.supply_chain_posture`` upload contract.

    ``hardening`` is a ``ca9.api.hardening_settings`` snapshot; its committed
    values are used first and Skylos's own readers fill the gaps.
    """
    root_path = Path(root).resolve()
    repo = _Repository(root_path, inventory)
    facts = _Facts(repo, hardening)
    pinned, target = _actions_checks(root_path, workflow_findings)
    checks = [
        _lockfile_committed(repo),
        _frozen_install_ci(repo),
        _install_scripts_disabled(repo, facts),
        _release_age_cooldown(repo, policy, facts),
        pinned,
        target,
    ]
    return {
        "schema": POSTURE_SCHEMA,
        "ecosystems": repo.ecosystems(),
        "checks": checks,
    }


def posture_line(posture: Any) -> str | None:
    """One short terminal line naming failing checks, or None."""
    if not isinstance(posture, dict):
        return None
    checks = [check for check in posture.get("checks") or [] if isinstance(check, dict)]
    failing = [str(check.get("id")) for check in checks if check.get("status") == FAIL]
    if not failing:
        return None
    return (
        f"Supply-chain posture: {len(failing)} of {len(checks)} checks fail "
        f"({', '.join(failing)}); see supply_chain_posture in --format json"
    )


def build_supply_chain_summary(root: str | Path, scan_result) -> dict:
    """The upload blocks for a finished dependency scan, or {} when the scan
    produced no inventory: ``dependency_inventory``, ``supply_chain_posture``
    and, when ca9 provides them, ``ci_inventory`` and ``agent_hooks``, both
    built from the Git top (``_repository_top``) so a subfolder scan does
    not upload an empty, complete CI list.
    ``supply_chain_checks`` records what ca9 could not provide; it stays local."""
    inventory = getattr(scan_result, "inventory", None)
    if inventory is None:
        return {}
    from skylos.rules.sca import supply_chain
    from skylos.rules.sca.ci_agent_inventory import (
        agent_hooks_block,
        ci_inventory_block,
    )
    from skylos.supply_chain.policy import load_supply_chain_policy

    try:
        policy = load_supply_chain_policy(root)
    except Exception:  # noqa: BLE001 - an unreadable policy leaves the posture without it
        policy = None
    api = supply_chain.load_ca9_api()
    checks: dict[str, Any] = {}
    summary: dict[str, Any] = {
        INVENTORY_KEY: dependency_inventory_summary(inventory, root)
    }
    hardening, checks["hardening_settings"] = _hardening_settings(Path(root), api)
    try:
        summary[POSTURE_KEY] = supply_chain_posture(
            root, inventory, policy, hardening=hardening
        )
    except Exception:  # noqa: BLE001 - posture is reporting; it never fails a scan
        summary[POSTURE_KEY] = {
            "schema": POSTURE_SCHEMA,
            "ecosystems": [],
            "checks": [
                _check(check_id, UNKNOWN, "posture could not be computed")
                for check_id in CHECK_IDS
            ],
        }
    inventory_root = _repository_top(root)
    for key, build in (
        (CI_INVENTORY_KEY, ci_inventory_block),
        (AGENT_HOOKS_KEY, agent_hooks_block),
    ):
        try:
            block, checks[key] = build(inventory_root, api)
        except Exception as exc:  # noqa: BLE001 - inventories never fail a scan
            block, checks[key] = (
                None,
                {"status": "failed", "error_type": type(exc).__name__},
            )
        if block is not None:
            summary[key] = block
        if Path(inventory_root) != Path(root).resolve():
            checks[key]["scope"] = "repository"
    summary[CHECKS_KEY] = checks
    return summary


def _repository_top(root: str | Path) -> Path:
    """The Git top of ``root``, else ``root``: CI workflows and agent configs
    apply to the whole repository, so a subfolder scan reads them there."""
    from skylos.core.file_discovery import find_git_root

    resolved = Path(root).resolve()
    top = find_git_root(resolved)
    if top is None:
        return resolved
    return Path(top).resolve()


__all__ = [
    "AGENT_HOOKS_KEY",
    "CHECKS_KEY",
    "CHECK_IDS",
    "CI_INVENTORY_KEY",
    "INVENTORY_KEY",
    "INVENTORY_KEYS",
    "INVENTORY_SCHEMA",
    "MAX_INVENTORY_PACKAGES",
    "POSTURE_KEY",
    "POSTURE_SCHEMA",
    "SUMMARY_KEYS",
    "UPLOAD_SUMMARY_KEYS",
    "build_supply_chain_summary",
    "dependency_inventory_summary",
    "posture_line",
    "supply_chain_posture",
]
