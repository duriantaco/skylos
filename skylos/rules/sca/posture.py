"""Repository supply-chain posture and the package inventory for uploads.

``dependency_inventory_summary`` lists the packages the scan read (bounded,
sorted, de-duplicated) so Skylos Cloud can match new malware advisories
against repositories after the scan. ``supply_chain_posture`` records how the
repository installs dependencies. Every check is ``pass`` only with evidence
in the repository, ``unknown`` when the files cannot tell, and
``not_applicable`` when the ecosystem or CI system is absent. GitHub Actions
checks are derived from the existing SKY-D292 and SKY-D290 findings.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_text_no_symlink

INVENTORY_SCHEMA = "skylos.dependency_inventory.v1"
POSTURE_SCHEMA = "skylos.supply_chain_posture.v1"
INVENTORY_KEY = "dependency_inventory"
POSTURE_KEY = "supply_chain_posture"
SUMMARY_KEYS = (INVENTORY_KEY, POSTURE_KEY)
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


def dependency_inventory_summary(inventory, root: str | Path) -> dict:
    """The ``analysis_summary.dependency_inventory`` upload contract."""
    root_path = Path(root).resolve()
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
            continue
        row["direct"] = row["direct"] or direct
        row["dev"] = row["dev"] and dev
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
        files = [path for path in _walk_files(root) if not _non_install_path(path, root)]
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


def _install_scripts_disabled(repo: _Repository) -> dict:
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
        if manager in {"npm", "pnpm", "yarn"} and npmrc:
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
        if manager == "pnpm":
            major = _package_manager_major(repo.package_jsons, _PNPM_VERSION_RE)
            allow_all = _config_value(
                _config_files(repo, "pnpm-workspace.yaml"),
                _YAML_KEY_RE.format(key="dangerouslyAllowAllBuilds"),
            )
            if allow_all and allow_all[1].lower() == "true":
                failing.append(
                    f"pnpm: dangerouslyAllowAllBuilds in {repo.rel(allow_all[0])}"
                )
                continue
            if major is None:
                unknown.append(
                    "pnpm version unknown (pnpm 10+ blocks dependency scripts by default)"
                )
                continue
            if major >= 10:
                evidence.append(f"pnpm {major}: dependency scripts blocked by default")
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


def _release_age_cooldown(repo: _Repository, policy) -> dict:
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
            found = None
            if manager == "npm":
                found = _config_value(
                    _config_files(repo, ".npmrc"), _NPMRC_AGE_RE.pattern
                )
                hint = "no min-release-age in .npmrc"
                paths.append(".npmrc")
            elif manager == "pnpm":
                found = _config_value(
                    _config_files(repo, "pnpm-workspace.yaml"),
                    _YAML_KEY_RE.format(key="minimumReleaseAge"),
                )
                hint = "no minimumReleaseAge in pnpm-workspace.yaml"
                paths.append("pnpm-workspace.yaml")
            elif manager == "yarn":
                found = _config_value(
                    _config_files(repo, ".yarnrc.yml"),
                    _YAML_KEY_RE.format(key="npmMinimalAgeGate"),
                )
                hint = "no npmMinimalAgeGate in .yarnrc.yml"
                paths.append(".yarnrc.yml")
            else:
                found = _config_value(
                    _config_files(repo, "bunfig.toml"),
                    _TOML_KEY_RE.format(key="minimumReleaseAge"),
                )
                hint = "no minimumReleaseAge in bunfig.toml"
                paths.append("bunfig.toml")
            if found and _positive(found[1]):
                evidence.append(f"{manager}: {repo.rel(found[0])}")
            else:
                missing.append(hint)
    if repo.has_pypi:
        candidates = [
            path
            for path in (repo.root / "pyproject.toml", repo.root / "uv.toml")
            if repo.tracked is None or path in repo.tracked
        ]
        found = _config_value(candidates, _TOML_KEY_RE.format(key="exclude-newer"))
        paths.append("pyproject.toml")
        if found:
            evidence.append(f"uv: exclude-newer in {repo.rel(found[0])}")
        else:
            missing.append("no uv exclude-newer for Python dependencies")
    if missing:
        return _check(check_id, FAIL, "; ".join(missing), paths)
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
    root: str | Path, inventory=None, policy=None, *, workflow_findings=None
) -> dict:
    """The ``analysis_summary.supply_chain_posture`` upload contract."""
    root_path = Path(root).resolve()
    repo = _Repository(root_path, inventory)
    pinned, target = _actions_checks(root_path, workflow_findings)
    checks = [
        _lockfile_committed(repo),
        _frozen_install_ci(repo),
        _install_scripts_disabled(repo),
        _release_age_cooldown(repo, policy),
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
    """Both upload blocks for a finished dependency scan, or {} when the scan
    produced no inventory."""
    inventory = getattr(scan_result, "inventory", None)
    if inventory is None:
        return {}
    from skylos.supply_chain.policy import load_supply_chain_policy

    try:
        policy = load_supply_chain_policy(root)
    except Exception:  # noqa: BLE001 - an unreadable policy leaves the posture without it
        policy = None
    summary = {"dependency_inventory": dependency_inventory_summary(inventory, root)}
    try:
        summary["supply_chain_posture"] = supply_chain_posture(root, inventory, policy)
    except Exception:  # noqa: BLE001 - posture is reporting; it never fails a scan
        summary["supply_chain_posture"] = {
            "schema": POSTURE_SCHEMA,
            "ecosystems": [],
            "checks": [
                _check(check_id, UNKNOWN, "posture could not be computed")
                for check_id in CHECK_IDS
            ],
        }
    return summary


__all__ = [
    "CHECK_IDS",
    "INVENTORY_KEY",
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
