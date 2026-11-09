"""Base-against-head supply-chain checks for ``--diff`` and pull request scans.

Both sides come from Git: the merge base of the diff base and ``HEAD``, and
the working-tree copies of the files Git tracks (``--diff`` compares the merge
base with the working tree). Untracked files never count, because they do not
configure CI installs. The selected files are copied into temporary folders
and handed to ca9 (``ca9.api``), which never sees the checkout itself:

- ``SKY-SCA-HRD001``: ``hardening_regressions`` between ``hardening_settings``
  of both sides. Packages listed in the base commit's
  ``[tool.skylos.supply_chain.hardening_exceptions]`` with a reason are
  skipped; a pull request cannot add its own exception.
- ``SKY-SCA-UPG001`` / ``SKY-SCA-UPG002``: with ``--review-upgrades``, npm and
  PyPI lockfile version changes are paired base to head (new packages with
  ``old: None``) and passed to ``review_upgrades``; a ``block`` list is UPG001,
  a ``warn``-only list UPG002, whatever the delta kinds.
- ``SKY-SCA-API001``: with ``--review-upgrades``, your lines that use API a
  Python upgrade removed (``upgrade_api_diff``). Advice: never an analysis error.
- ``SKY-D375``: a CI job that publishes packages was added or changed
  (``ci_inventory`` of both sides, line numbers ignored).

When something relevant changed, a ca9 function that is missing or fails (ca9
not installed or too old included), or a hardening comparison that reports
``check_failed``, becomes an analysis error with no file and an "upgrade ca9"
message, so a diff-scoped gate stops as incomplete instead of passing without
the check. This covers the agent and workflow rules of the danger scan and the
dependency checks of ``--sca`` on changed lockfiles. Changed hardening
settings alone with no usable ca9 at all are a receipt note (workflow and
lockfile changes still stop the gate); an engine that lacks or fails the
hardening functions is an error. An
incomplete workflow audit (a reusable workflow from another repository) is
noted in the receipt and shown, not failed.
"""

from __future__ import annotations

import fnmatch
import hashlib
import inspect
import json
import logging
import os
import posixpath
import re
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.sca.lockfile_types import NON_REGISTRY_REASONS
from skylos.rules.config.agent_files import (
    agent_path,
    contained,
    link_candidate,
)

logger = logging.getLogger(__name__)

RULE_HARDENING = "SKY-SCA-HRD001"
RULE_UPGRADE_BLOCK = "SKY-SCA-UPG001"
RULE_UPGRADE_WARN = "SKY-SCA-UPG002"
RULE_UPGRADE_API = "SKY-SCA-API001"
RULE_NEW_SOURCE = "SKY-SCA-SRC004"
RULE_PUBLISH_JOB_CHANGED = "SKY-D375"
DIFF_RULES = frozenset(
    {
        RULE_HARDENING,
        RULE_UPGRADE_BLOCK,
        RULE_UPGRADE_WARN,
        RULE_UPGRADE_API,
        RULE_NEW_SOURCE,
        RULE_PUBLISH_JOB_CHANGED,
    }
)
FINDING_KIND = "supply_chain_diff"
ERROR_KIND = "supply_chain_check_unavailable"
MAX_FILE_BYTES = 2_000_000
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 200_000_000
MAX_LINK_HOPS = 8
REGULAR_MODES = frozenset({"100644", "100755"})
LINK_MODE = "120000"
MAX_SIDE_FILES = 400
MAX_UPGRADE_PAIRS = 100
INTERNAL_SKIP = "internal_package"
PRIVATE_SKIP = "private_registry"
NON_BLOCKING_SKIPS = frozenset({INTERNAL_SKIP, PRIVATE_SKIP})
MAX_REVIEW_PACKAGES = 100_000
MAX_DELTAS = 10
MAX_TEXT = 300
HARDENING_ROOT_FILES = frozenset(
    {
        ".npmrc",
        "package.json",
        "pnpm-workspace.yaml",
        ".yarnrc.yml",
        "bunfig.toml",
        "uv.toml",
        "pyproject.toml",
        "pip.conf",
        "pip.ini",
        "renovate.json",
        "renovate.json5",
        ".renovaterc",
        ".renovaterc.json",
        ".renovaterc.json5",
    }
)
HARDENING_NESTED_FILES = frozenset(
    {
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        ".github/renovate.json",
        ".github/renovate.json5",
        ".gitlab/renovate.json",
        ".gitlab/renovate.json5",
    }
)
_YAML_SUFFIXES = (".yml", ".yaml")
_UPGRADE_PARSERS = {
    "package-lock.json": ("npm", "skylos.rules.sca.npm_lockfile", "parse_package_lock"),
    "npm-shrinkwrap.json": (
        "npm",
        "skylos.rules.sca.npm_lockfile",
        "parse_package_lock",
    ),
    "pnpm-lock.yaml": ("npm", "skylos.rules.sca.pnpm_lockfile", "parse_pnpm_lock"),
    "yarn.lock": ("npm", "skylos.rules.sca.yarn_lockfile", "parse_yarn_lock"),
    "bun.lock": ("npm", "skylos.rules.sca.bun_lockfile", "parse_bun_lock"),
    "uv.lock": ("pypi", "skylos.rules.sca.uv_lockfile", "parse_uv_lock"),
    "poetry.lock": ("pypi", "skylos.rules.sca.poetry_lockfile", "parse_poetry_lock"),
    "Pipfile.lock": ("pypi", "skylos.rules.sca.pipfile_lockfile", "parse_pipfile_lock"),
}
_SOURCE_PARSERS = {
    **{name: entry[1:] for name, entry in _UPGRADE_PARSERS.items()},
    "Cargo.lock": ("skylos.rules.sca.cargo_lockfile", "parse_cargo_lock"),
    "composer.lock": ("skylos.rules.sca.composer_lockfile", "parse_composer_lock"),
    "Gemfile.lock": ("skylos.rules.sca.gemfile_lockfile", "parse_gemfile_lock"),
    "pubspec.lock": ("skylos.rules.sca.pubspec_lockfile", "parse_pubspec_lock"),
}
_PUBLIC_REGISTRIES = {
    "npm": frozenset({"registry.npmjs.org", "registry.yarnpkg.com"}),
    "pypi": frozenset({"pypi.org", "files.pythonhosted.org"}),
}
_SKIP_PARTS = frozenset({"node_modules", ".venv", "venv", "vendor"})
_HEX_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def hardening_path(path: str) -> bool:
    if path in HARDENING_ROOT_FILES or path in HARDENING_NESTED_FILES:
        return True
    pure = PurePosixPath(path)
    if len(pure.parts) == 1:
        return fnmatch.fnmatch(path, "requirements*.txt")
    if len(pure.parts) == 2 and pure.parts[0] == "requirements":
        return pure.suffix == ".txt"
    return ci_path(path) and pure.parts[:2] in (
        (".github", "workflows"),
        (".github", "actions"),
    )


def ci_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.name in {".gitlab-ci.yml", ".gitlab-ci.yaml"} and len(pure.parts) == 1:
        return True
    if not pure.name.endswith(_YAML_SUFFIXES):
        return False
    if pure.parts[:2] == (".github", "workflows"):
        return len(pure.parts) == 3
    return pure.parts[:1] in ((".github",), (".gitlab",))


def upgrade_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.name not in _UPGRADE_PARSERS:
        return False
    return not any(part in _SKIP_PARTS for part in pure.parts[:-1])


def _megabytes(limit: int) -> str:
    return f"{limit // (1024 * 1024)} MB"


def _file_limit(path: str) -> int:
    """Lockfiles and requirements files of big monorepos run to tens of MB;
    other compared files stay small."""
    if dependency_file_path(path):
        return MAX_LOCKFILE_BYTES
    return MAX_FILE_BYTES


def _blob_id(root: Path, path: Path, length: int) -> str | None:
    """Git's object id of an in-repository working-tree file, read in chunks."""
    algorithm = "sha1"
    if length == 64:
        algorithm = "sha256"
    digest = hashlib.new(algorithm)
    try:
        root = root.resolve(strict=True)
        path = path.resolve(strict=True)
        path.relative_to(root)
        size = path.stat().st_size
        digest.update(f"blob {size}\0".encode())
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except (OSError, RuntimeError, ValueError):
        return None
    return digest.hexdigest()


class GitSides:
    """The merge base and the tracked working tree of one repository."""

    def __init__(self, context: GitContext, commit: str, base_paths, head_paths):
        self.context = context
        self.root = Path(context.root)
        self.commit = commit
        self.base_paths = base_paths
        self.head_paths = head_paths
        self._head_set = set(head_paths)
        self._bytes = 0
        self._entries: dict[str, tuple[str, str]] | None = None
        self.unread: dict[str, str] = {}

    def _charge(self, text: str | None) -> str | None:
        if text is None:
            return None
        self._bytes += len(text.encode("utf-8", "ignore"))
        if self._bytes > MAX_TOTAL_BYTES:
            raise ValueError("diff inputs exceed the size limit")
        return text

    def entries(self) -> dict[str, tuple[str, str]]:
        """``path -> (mode, object id)`` of every blob at the merge base."""
        if self._entries is None:
            listing = self.context.run(
                "ls-tree", "-r", "-z", "--full-tree", self.commit
            )
            entries = {}
            if listing.returncode == 0:
                for record in listing.stdout.split("\0"):
                    metadata, separator, name = record.partition("\t")
                    fields = metadata.split()
                    if separator and len(fields) == 3:
                        entries[name] = (fields[0], fields[2])
            self._entries = entries
        return self._entries

    def base_text(self, path: str) -> str | None:
        limit = _file_limit(path)
        entry = self.context.run(
            "ls-tree", "-l", "-z", self.commit, "--", f":(literal){path}"
        )
        if entry.returncode != 0:
            return None
        records = [record for record in entry.stdout.split("\0") if record]
        if len(records) != 1:
            return None
        metadata, separator, name = records[0].partition("\t")
        fields = metadata.split()
        if not separator or name != path or len(fields) != 4:
            return None
        mode, kind, object_id, size = fields
        if mode == LINK_MODE:
            self.unread.setdefault(path, "a symbolic link")
            return None
        if mode not in REGULAR_MODES or kind != "blob":
            self.unread.setdefault(path, "not a regular file at the base")
            return None
        if not size.isdigit() or int(size) > limit:
            self.unread.setdefault(path, f"over {_megabytes(limit)}")
            return None
        blob = self.context.run("cat-file", "blob", object_id)
        if blob.returncode != 0:
            self.unread.setdefault(path, "unreadable at the base")
            return None
        return self._charge(blob.stdout)

    def head_text(self, path: str) -> str | None:
        limit = _file_limit(path)
        text = read_project_text_no_symlink(
            self.root, path, max_bytes=limit, encoding="utf-8"
        )
        if text is None:
            target = self.root / path
            if target.is_symlink():
                self.unread.setdefault(path, "a symbolic link")
            elif target.is_file() and target.stat().st_size > limit:
                self.unread.setdefault(path, f"over {_megabytes(limit)}")
            elif target.exists():
                self.unread.setdefault(path, "not readable as UTF-8 text")
        return self._charge(text)

    def files(self, select: Callable[[str], bool]) -> tuple[dict, dict]:
        base_names = [path for path in self.base_paths if select(path)]
        head_names = [path for path in self.head_paths if select(path)]
        if len(base_names) > MAX_SIDE_FILES or len(head_names) > MAX_SIDE_FILES:
            raise ValueError("too many files to compare")
        base = {}
        for name in base_names:
            text = self.base_text(name)
            if text is not None:
                base[name] = text
        head = {}
        for name in head_names:
            text = self.head_text(name)
            if text is not None:
                head[name] = text
        return base, head

    def unread_changes(self, select: Callable[[str], bool]) -> list[dict]:
        """Selected files ``files`` could not read on a side that has them,
        unless both sides hold the same bytes (Git object ids compared)."""
        found = []
        for path, reason in sorted(self.unread.items()):
            if not select(path) or self._same_on_both_sides(path):
                continue
            found.append({"file": path, "reason": reason})
        return found

    def _same_on_both_sides(self, path: str) -> bool:
        mode, object_id = self.entries().get(path, ("", ""))
        target = self.root / path
        if mode == LINK_MODE and target.is_symlink():
            blob = self.context.run("cat-file", "blob", object_id)
            try:
                written = os.readlink(target)
            except OSError:
                return False
            return blob.returncode == 0 and blob.stdout == written
        if mode not in REGULAR_MODES or target.is_symlink() or not target.is_file():
            return False
        return _blob_id(self.root, target, len(object_id)) == object_id

    def _base_link_target(self, link: str) -> tuple[str | None, str, str]:
        """(target path, problem, written target) of a link at the base."""
        entries = self.entries()
        current = link
        written = ""
        for _hop in range(MAX_LINK_HOPS):
            mode, object_id = entries.get(current, ("", ""))
            if mode != LINK_MODE:
                return current, "", written
            blob = self.context.run("cat-file", "blob", object_id)
            if blob.returncode != 0:
                return None, "is unreadable", written
            target = blob.stdout
            if not written:
                written = target
            if not target or target.startswith("/"):
                return None, "points outside the repository", written
            joined = posixpath.normpath(
                posixpath.join(posixpath.dirname(current), target)
            )
            if joined == ".." or joined.startswith("../"):
                return None, "points outside the repository", written
            current = joined
        return None, "is a link loop", written

    def _base_linked(self, select) -> tuple[dict, dict]:
        entries = self.entries()
        texts: dict[str, str] = {}
        broken: dict[str, tuple[str, str]] = {}
        for link, (mode, _object_id) in sorted(entries.items()):
            if mode != LINK_MODE or not link_candidate(link):
                continue
            target, problem, written = self._base_link_target(link)
            if target is None:
                broken[link] = (problem, written)
                continue
            if entries.get(target, ("",))[0] in REGULAR_MODES:
                if select(link):
                    self._add(texts, link, self.base_text(target))
                continue
            prefix = target + "/"
            if target == ".":
                prefix = ""
            under = [name for name in self.base_paths if name.startswith(prefix)]
            if not under:
                broken[link] = ("points to a missing file", written)
            for name in under:
                client = f"{link}/{name[len(prefix) :]}"
                if select(client) and entries.get(name, ("",))[0] in REGULAR_MODES:
                    self._add(texts, client, self.base_text(name))
        return texts, broken

    def _head_linked(self, select) -> tuple[dict, dict]:
        top = Path(os.path.realpath(self.root))
        texts: dict[str, str] = {}
        broken: dict[str, tuple[str, str]] = {}
        for link in sorted(self.head_paths):
            path = self.root / link
            if not link_candidate(link) or not path.is_symlink():
                continue
            try:
                written = os.readlink(path)
            except OSError:
                written = ""
            target = Path(os.path.realpath(path))
            if not target.exists():
                broken[link] = ("points to a missing file", written)
                continue
            if not contained(target, top):
                broken[link] = ("points outside the repository", written)
                continue
            relative = target.relative_to(top).as_posix()
            if target.is_file():
                if select(link) and relative in self._head_set:
                    self._add(texts, link, self.head_text(relative))
                continue
            prefix = relative + "/"
            if relative == ".":
                prefix = ""
            for name in self.head_paths:
                if not name.startswith(prefix):
                    continue
                client = f"{link}/{name[len(prefix) :]}"
                if select(client):
                    self._add(texts, client, self.head_text(name))
        return texts, broken

    def _add(self, texts: dict, client: str, text: str | None) -> None:
        if text is None or client in texts:
            return
        if len(texts) >= MAX_SIDE_FILES:
            raise ValueError("too many linked files to compare")
        texts[client] = text

    def client_files(self, select) -> tuple[dict, dict, list[dict]]:
        """``files(select)`` plus the configs behind links that stay inside
        the repository, keyed by the path the agent or editor opens, and the
        links on the head side that leave the repository or point nowhere
        and are new or changed since the base."""
        base, head = self.files(select)
        base_linked, base_broken = self._base_linked(select)
        head_linked, head_broken = self._head_linked(select)
        for name, text in base_linked.items():
            base.setdefault(name, text)
        for name, text in head_linked.items():
            head.setdefault(name, text)
        problems = [
            {"file": link, "reason": reason}
            for link, (reason, written) in sorted(head_broken.items())
            if base_broken.get(link) != (reason, written)
        ]
        return base, head, problems


def _lines(result) -> list[str]:
    return [item for item in result.stdout.split("\0") if item]


def open_sides(root: str | Path, base_ref: str) -> GitSides | None:
    """Git sides for ``base_ref``; None outside Git or when the ref is unknown."""
    try:
        context = GitContext.from_path(root)
        head = context.run("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
        base = context.run(
            "rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"
        )
        if head.returncode != 0 or base.returncode != 0:
            return None
        merge = context.run("merge-base", base.stdout.strip(), head.stdout.strip())
        if merge.returncode != 0:
            return None
        commit = merge.stdout.strip()
        if not _HEX_COMMIT.fullmatch(commit):
            return None
        base_tree = context.run(
            "ls-tree", "-r", "-z", "--name-only", "--full-tree", commit
        )
        tracked = context.run("ls-files", "-z", "--cached", "--full-name")
        if base_tree.returncode != 0 or tracked.returncode != 0:
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    except Exception:  # noqa: BLE001 - a Git failure leaves the diff checks unrun
        return None
    return GitSides(context, commit, _lines(base_tree), _lines(tracked))


def _write_tree(directory: Path, files: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return directory


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return []


def _get(value, key: str):
    if isinstance(value, dict):
        return value.get(key)
    return None


def _text(value: object, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


def _api_function(api, name: str):
    if api is None or not hasattr(api, name):
        return None
    function = getattr(api, name)
    if not callable(function):
        return None
    return function


UPGRADE_CA9 = "Upgrade ca9 (pip install -U ca9) and rerun."


def _unavailable(api, receipt: dict, errors: list, check: str, message: str) -> None:
    """A check that cannot run on files the change touched: an analysis
    error, so a diff gate stops as incomplete instead of passing unchecked.
    With no usable ca9 engine at all (not installed, or older than API
    version 1) the message says so."""
    receipt["status"] = "unavailable"
    if api is None:
        receipt["status"] = "engine_unavailable"
        message = f"{message.split(':', 1)[0]}: ca9 is not installed or too old"
    errors.append(_error(check, f"{message}. {UPGRADE_CA9}"))


def _error(check: str, message: str) -> dict:
    return {
        "kind": ERROR_KIND,
        "component": "supply_chain",
        "check": check,
        "message": message[:MAX_TEXT],
        "severity": "HIGH",
    }


def _finding(
    rule_id: str,
    severity: str,
    message: str,
    file: Path,
    line: int,
    metadata: dict,
    *,
    category: str,
    snippet: str = "",
) -> dict:
    return {
        "rule_id": rule_id,
        "kind": FINDING_KIND,
        "category": category,
        "severity": severity,
        "message": message,
        "file": str(file),
        "file_path": str(file),
        "line": max(1, int(line or 1)),
        "line_number": max(1, int(line or 1)),
        "snippet": snippet,
        "metadata": metadata,
    }


def base_hardening_exceptions(sides: GitSides) -> dict[str, str]:
    """``package -> reason`` from the base commit's pyproject.toml."""
    text = sides.base_text("pyproject.toml")
    if not text:
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        data = tomllib.loads(text)
    except ValueError:
        return {}
    table: Any = data
    for key in ("tool", "skylos", "supply_chain", "hardening_exceptions"):
        if not isinstance(table, dict):
            return {}
        table = table.get(key)
    if not isinstance(table, dict):
        return {}
    exceptions = {}
    for package, reason in list(table.items())[:200]:
        if isinstance(reason, str) and reason.strip():
            exceptions[str(package).strip()] = _text(reason, 200)
    return exceptions


def _locate(text: str | None, needle: str) -> int:
    if not text or not needle:
        return 1
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return 1


def hardening_findings(sides: GitSides, api, receipt: dict, errors: list) -> list[dict]:
    settings = _api_function(api, "hardening_settings")
    regressions = _api_function(api, "hardening_regressions")
    base, head = sides.files(hardening_path)
    if base == head:
        receipt["status"] = "unchanged"
        return []
    if api is None:
        receipt["status"] = "engine_unavailable"
        receipt["note"] = f"ca9 is not installed or too old. {UPGRADE_CA9}"
        return []
    if settings is None or regressions is None:
        _unavailable(
            api,
            receipt,
            errors,
            "hardening_regressions",
            "Install hardening settings changed but were not compared: "
            "ca9.api.hardening_settings/hardening_regressions is unavailable",
        )
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="skylos-hardening-") as temp:
            base_settings = settings(str(_write_tree(Path(temp) / "base", base)))
            head_settings = settings(str(_write_tree(Path(temp) / "head", head)))
        items = regressions(base_settings, head_settings)
    except Exception as exc:  # noqa: BLE001 - engine failures stop the gate as incomplete
        receipt["status"] = "failed"
        errors.append(
            _error(
                "hardening_regressions",
                f"Install hardening comparison failed ({type(exc).__name__})",
            )
        )
        return []
    exceptions = base_hardening_exceptions(sides)
    receipt["status"] = "complete"
    receipt["exceptions_applied"] = []
    findings = []
    if not isinstance(items, list):
        items = [items]
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = _text(item.get("kind"), 60)
        detail = _text(item.get("detail"))
        if kind == "check_failed" or not kind:
            receipt["status"] = "failed"
            side = _text(item.get("side"), 10)
            where = ""
            if side in {"base", "head"}:
                where = f" ({side} side)"
            errors.append(
                _error(
                    "hardening_regressions",
                    f"Install hardening comparison failed{where}: "
                    f"{detail or 'no detail'}",
                )
            )
            continue
        package = _text(item.get("package"), 214)
        if package and package in exceptions:
            receipt["exceptions_applied"].append(
                {"kind": kind, "package": package, "reason": exceptions[package]}
            )
            continue
        findings.append(_hardening_finding(sides, item, kind, detail, package, head))
    receipt["regressions"] = len(findings)
    return findings


def _hardening_finding(sides, item, kind, detail, package, head) -> dict:
    path = _text(item.get("path"), 400) or "."
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        path = "."
    line = item.get("line")
    if not isinstance(line, int) or isinstance(line, bool):
        setting = _text(item.get("setting"), 80).split(".")[-1]
        needle = package or str(item.get("head") or "") or setting
        line = _locate(head.get(path), needle)
    metadata = {
        "regression": kind,
        "setting": _text(item.get("setting"), 80),
        "base_value": _text(item.get("base"), 120),
        "head_value": _text(item.get("head"), 120),
        "base_commit": sides.commit,
    }
    if package:
        metadata["package_name"] = package
    message = (
        f"This change weakens install hardening: {detail or kind}. "
        "Cooldowns, script blocking and SHA pins are what stop most malicious "
        "releases; keep the setting, or record a reviewed exception for this "
        "package in [tool.skylos.supply_chain.hardening_exceptions] on the base branch."
    )
    return _finding(
        RULE_HARDENING,
        "HIGH",
        message,
        sides.root / path,
        line,
        metadata,
        category="DEPENDENCY",
        snippet=detail,
    )


def config_coverage(sides: GitSides, api, receipt: dict, errors: list) -> list[dict]:
    """The danger scan reads agent and workflow files through ca9; when one
    of them changed, a missing ca9 function must not look like a clean file.

    Agent configs count as the agent opens them, through links that stay in
    the repository. A new or changed link to an agent folder or config that
    leaves the repository or points nowhere is an analysis error: the agent
    may read it, Skylos cannot, so the diff gate stops as incomplete."""
    needed = []
    base, head, link_problems = sides.client_files(agent_path)
    if base != head or link_problems:
        needed.append("agent_config")
    base, head = sides.files(ci_path)
    if base != head:
        needed.append("audit_workflows")
    receipt["changed"] = needed
    if link_problems:
        receipt["link_problems"] = link_problems[:20]
        for problem in link_problems[:5]:
            errors.append(
                _error(
                    "agent_config",
                    f"Agent config link {problem['file']} {problem['reason']}; the "
                    "agent can follow it but Skylos could not check what it runs",
                )
            )
    missing = [name for name in needed if _api_function(api, name) is None]
    receipt["status"] = "checked"
    if not needed:
        receipt["status"] = "unchanged"
    if missing:
        _unavailable(
            api,
            receipt,
            errors,
            "agent_config",
            "Agent, MCP or workflow files changed but were not checked: "
            + ", ".join(f"ca9.api.{name}" for name in missing)
            + " is unavailable",
        )
    elif "audit_workflows" in needed:
        _workflow_audit_receipt(sides, api, receipt)
    return []


def _workflow_audit_receipt(sides: GitSides, api, receipt: dict) -> None:
    """Note an incomplete audit of the changed workflows (a reusable
    workflow or include from another repository cannot be read). It is
    shown, not a failure: such a call may well predate the change."""
    _base, head = sides.files(ci_path)
    try:
        with tempfile.TemporaryDirectory(prefix="skylos-audit-") as temp:
            result = api.audit_workflows(str(_write_tree(Path(temp) / "head", head)))
    except Exception as exc:  # noqa: BLE001 - the danger scan already reported what it could
        receipt["workflow_audit"] = {
            "complete": False,
            "error_type": type(exc).__name__,
        }
        return
    audit = _get(result, "receipt")
    if not isinstance(audit, dict) or audit.get("complete") is not False:
        return
    reasons = [
        _text(reason, 160)
        for reason in _as_list(audit.get("incomplete_reasons"))[:10]
        if reason
    ]
    unknowns = _as_list(audit.get("unknowns"))
    receipt["workflow_audit"] = {
        "complete": False,
        "incomplete_reasons": reasons,
        "unknowns": len(unknowns),
    }


def dependency_file_path(path: str) -> bool:
    """Lockfiles (and pip requirements files, pip's lock): the files whose
    entries ``--sca`` checks for sources, integrity and age."""
    pure = PurePosixPath(path)
    if any(part in _SKIP_PARTS for part in pure.parts[:-1]):
        return False
    return pure.name in _UPGRADE_PARSERS or fnmatch.fnmatch(
        pure.name, "requirements*.txt"
    )


def dependency_coverage(
    sides: GitSides, api, receipt: dict, errors: list
) -> list[dict]:
    """``--sca`` checks changed lockfiles and requirements files through
    ``ca9.api.evaluate_packages`` (SKY-SCA-SRC001/SRC003/INT001/AGE001); in a
    diff, a missing engine must not read as clean dependency changes."""
    base, head = sides.files(dependency_file_path)
    changed = sorted(
        {name for name in set(base) | set(head) if base.get(name) != head.get(name)}
        | {item["file"] for item in sides.unread_changes(dependency_file_path)}
    )
    receipt["changed"] = len(changed)
    receipt["status"] = "unchanged"
    if not changed:
        return []
    receipt["status"] = "checked"
    if _api_function(api, "evaluate_packages") is None:
        _unavailable(
            api,
            receipt,
            errors,
            "evaluate_packages",
            f"Dependency files changed ({', '.join(changed[:3])}) but supply-chain "
            "checks did not run: ca9.api.evaluate_packages is unavailable",
        )
    return []


UNSUPPORTED_UPGRADE_FILES = {
    "pdm.lock": "pdm.lock is not read by the upgrade review",
    "pylock.toml": "pylock.toml is not read by the upgrade review",
}


def unsupported_upgrade_path(path: str) -> str | None:
    """Why a dependency file's version changes are not reviewed, or None.

    Pins in requirements files (hashed or not), ``pdm.lock`` and
    ``pylock.toml`` are not paired for ``review_upgrades`` yet; a change to
    them is listed as a limitation instead of passing unmentioned."""
    pure = PurePosixPath(path)
    if any(part in _SKIP_PARTS for part in pure.parts[:-1]):
        return None
    if pure.name in UNSUPPORTED_UPGRADE_FILES:
        return UNSUPPORTED_UPGRADE_FILES[pure.name]
    if fnmatch.fnmatch(pure.name, "pylock.*.toml"):
        return UNSUPPORTED_UPGRADE_FILES["pylock.toml"]
    in_folder = len(pure.parts) > 1 and pure.parts[-2] == "requirements"
    if fnmatch.fnmatch(pure.name, "requirements*.txt") or (
        in_folder and pure.suffix == ".txt"
    ):
        return "requirements file pins are not read by the upgrade review"
    return None


def upgrade_limitations(sides: GitSides) -> tuple[list[dict], list[dict]]:
    """(changed lockfiles the review could not read, changed dependency
    files it does not support), each ``{file, reason}``."""
    unread = sides.unread_changes(upgrade_path)
    base, head = sides.files(lambda path: unsupported_upgrade_path(path) is not None)
    unsupported = [
        {"file": name, "reason": unsupported_upgrade_path(name)}
        for name in sorted(set(base) | set(head))
        if base.get(name) != head.get(name)
    ]
    for item in sides.unread_changes(
        lambda path: unsupported_upgrade_path(path) is not None
    ):
        if all(entry["file"] != item["file"] for entry in unsupported):
            unsupported.append(
                {"file": item["file"], "reason": unsupported_upgrade_path(item["file"])}
            )
    return unread, unsupported


class LockfileUnreadable(ValueError):
    """A lockfile side the parser rejected (invalid, or over its limits)."""


def _parse_lockfile(name: str, path: str, text: str) -> list[dict]:
    """Rows with a name and exact version; raises ``LockfileUnreadable``
    when the parser rejects the text, so a change is never read as one
    without versions."""
    ecosystem, module_name, function_name = _UPGRADE_PARSERS[PurePosixPath(name).name]
    import importlib

    parser = getattr(importlib.import_module(module_name), function_name)
    try:
        inventory = parser(Path(path), text=text, max_packages=MAX_REVIEW_PACKAGES)
    except Exception as exc:  # noqa: BLE001 - reported as a lockfile that was not reviewed
        raise LockfileUnreadable(
            f"could not be parsed ({type(exc).__name__})"
        ) from None
    rows = []
    for dependency in getattr(inventory, "dependencies", None) or []:
        if not isinstance(dependency, dict):
            continue
        name_value = str(dependency.get("name") or "")
        version = str(dependency.get("version") or "")
        if name_value and version:
            rows.append({**dependency, "_ecosystem": ecosystem})
    return rows


def _version_key(version: str):
    from packaging.version import InvalidVersion, Version

    try:
        return (1, Version(version), version)
    except InvalidVersion:
        return (0, None, version)


def _normalized(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def _registry_host(ecosystem: str, row: dict) -> str | None:
    registry = str(row.get("registry") or "")
    host = re.sub(r"^[a-z]+://", "", registry).split("/", 1)[0].lower()
    if host in _PUBLIC_REGISTRIES[ecosystem]:
        return host
    return None


def _https(url: object) -> str | None:
    if isinstance(url, str) and url.startswith("https://") and len(url) <= 2000:
        return url
    return None


def _npm_resolved(text: str) -> dict:
    data = json.loads(text)
    packages = _get(data, "packages")
    found = {}
    if isinstance(packages, dict):
        for key, entry in packages.items():
            url = _https(_get(entry, "resolved"))
            if isinstance(key, str) and url:
                found[key] = url
    return found


def _yarn_resolved(text: str) -> dict:
    """``(name, version) -> resolved`` of a Yarn classic lockfile (Yarn Berry
    records no URL)."""
    found = {}
    for block in re.split(r"\n\s*\n", text):
        lines = [
            line for line in block.splitlines() if line and not line.startswith("#")
        ]
        if not lines or lines[0].startswith(" "):
            continue
        spec = lines[0].rstrip(":").split(",")[0].strip().strip('"')
        name = spec.rpartition("@")[0] or spec
        version = url = None
        for line in lines[1:]:
            match = re.match(r'\s+(version|resolved)\s+"?([^"\s]+)"?\s*$', line)
            if match and match.group(1) == "version":
                version = match.group(2)
            elif match:
                url = _https(match.group(2).split("#", 1)[0])
        if name and version and url:
            found[(name, version)] = url
    return found


def _pnpm_resolved(text: str) -> dict:
    """``(name, version) -> resolution.tarball`` of a pnpm lockfile, when
    pnpm recorded one."""
    import yaml

    data = yaml.safe_load(text)
    packages = _get(data, "packages")
    found = {}
    if not isinstance(packages, dict):
        return found
    for key, entry in packages.items():
        url = _https(_get(_get(entry, "resolution"), "tarball"))
        if not isinstance(key, str) or not url:
            continue
        spec = key.lstrip("/").split("(", 1)[0]
        name, _at, version = spec.rpartition("@")
        if name and version:
            found[(name, version)] = url
    return found


_RESOLVED_READERS = {
    "package-lock.json": _npm_resolved,
    "npm-shrinkwrap.json": _npm_resolved,
    "yarn.lock": _yarn_resolved,
    "pnpm-lock.yaml": _pnpm_resolved,
}


def _lock_resolved(path: str, text: str) -> dict:
    """Where the lockfile says each entry is downloaded from (npm: package
    path; Yarn classic and pnpm: ``(name, version)``), so ca9 can skip an
    entry on a private registry and tell a lockfile that points a version at
    another artifact. The PyPI lockfiles list only public-index entries as
    packages (private-index ones are not paired at all) and send none."""
    reader = _RESOLVED_READERS.get(PurePosixPath(path).name)
    if reader is None:
        return {}
    try:
        return reader(text)
    except Exception:  # noqa: BLE001 - the pairs go without a resolved URL
        return {}


def upgrade_pairs(sides: GitSides) -> tuple[list[dict], int]:
    """(pairs, dropped) for lockfile entries that changed base to head.

    A version that is new for a package the base already locked pairs with
    the newest base version; a package the base did not lock (or a lockfile
    the base did not have) pairs with ``old: None`` and is reviewed as newly
    added. Upgrades come first when the cap cuts the list.
    """
    base, head = sides.files(upgrade_path)
    pairs: dict[tuple, dict] = {}
    for path, head_text in sorted(head.items()):
        base_text = base.get(path)
        if base_text == head_text:
            continue
        try:
            base_rows = []
            if base_text is not None:
                base_rows = _parse_lockfile(path, path, base_text)
            head_rows = _parse_lockfile(path, path, head_text)
        except LockfileUnreadable as exc:
            sides.unread.setdefault(path, str(exc))
            continue
        old: dict[tuple, set] = {}
        for row in base_rows:
            key = (row["_ecosystem"], _normalized(row["_ecosystem"], row["name"]))
            old.setdefault(key, set()).add(str(row["version"]))
        resolved = _lock_resolved(path, head_text)
        new: dict[tuple, dict] = {}
        for row in head_rows:
            key = (row["_ecosystem"], _normalized(row["_ecosystem"], row["name"]))
            version = str(row["version"])
            if version in old.get(key, ()):
                continue
            new.setdefault((*key, version), row)
        for (ecosystem, name, version), row in sorted(new.items()):
            previous = None
            if (ecosystem, name) in old:
                previous = max(old[(ecosystem, name)], key=_version_key)
            pair = {
                "ecosystem": ecosystem,
                "name": name,
                "old": previous,
                "new": version,
                "file": path,
                "line": row.get("line") or 1,
            }
            host = _registry_host(ecosystem, row)
            if host:
                pair["registry"] = f"https://{host}"
            integrity = row.get("integrity")
            if isinstance(integrity, str) and integrity.strip():
                pair["integrity"] = integrity.strip()
            url = resolved.get(str(row.get("package_path") or "")) or resolved.get(
                (str(row["name"]), version)
            )
            if url:
                pair["resolved"] = url
            pairs.setdefault((ecosystem, name, previous, version), pair)
    ordered = sorted(pairs.values(), key=lambda pair: pair["old"] is None)
    return ordered[:MAX_UPGRADE_PAIRS], max(0, len(ordered) - MAX_UPGRADE_PAIRS)


def _deltas(value) -> list[dict]:
    deltas = []
    for delta in _as_list(value):
        if not isinstance(delta, dict):
            continue
        line = delta.get("line")
        if not isinstance(line, int) or isinstance(line, bool):
            line = None
        path = _text(delta.get("path"), 300)
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts:
            path = pure.name
        deltas.append(
            {
                "kind": _text(delta.get("kind"), 60),
                "path": path,
                "line": line,
                "snippet": _text(delta.get("snippet"), 200),
                "detail": _text(delta.get("detail"), 200),
            }
        )
        if len(deltas) >= MAX_DELTAS:
            break
    return deltas


POLICY_OPTION_KEYS = ("internal_packages", "private_registries", "trusted_registries")


def _accepts_options(function) -> bool:
    """Whether this ca9's ``review_upgrades`` takes ``options=`` (older
    releases took the pairs only); unknown signatures are assumed to."""
    try:
        parameters = inspect.signature(function).parameters.values()
    except (TypeError, ValueError):
        return True
    for parameter in parameters:
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == "options" and parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False


def _review_options(root: Path) -> dict:
    """The policy's ``internal_packages``, ``private_registries`` and
    ``trusted_registries`` (the base commit's under ``SKYLOS_POLICY_BASE``),
    so ca9 never looks internal packages up on a public registry."""
    from skylos.supply_chain.policy import load_supply_chain_policy

    options: dict[str, Any] = {"max_pairs": MAX_UPGRADE_PAIRS}
    try:
        policy = load_supply_chain_policy(root)
    except Exception:  # noqa: BLE001 - without a readable policy ca9 uses its defaults
        return options
    for key in POLICY_OPTION_KEYS:
        values = list(getattr(policy, key))
        if values:
            options[key] = values
    return options


def upgrade_findings(sides: GitSides, api, receipt: dict, errors: list) -> list[dict]:
    """UPG001 for every ``block`` delta list and UPG002 for ``warn`` lists.

    Mapping is by list, never by kind: ca9 puts an install hook of a newly
    added package in ``warn``. Pairs ca9 skipped (other than internal
    packages and entries the lockfile resolves from a private registry,
    which it must not look up), pairs with no result, pairs over the cap,
    changed lockfiles that could not be read or parsed and an incomplete
    receipt are an analysis error: those changes were not reviewed, so a
    diff gate stops as incomplete. Changed dependency files the review does
    not read (requirements pins, ``pdm.lock``, ``pylock.toml``) are listed
    in ``limitations`` and shown, not failed.
    """
    pairs, dropped = upgrade_pairs(sides)
    unread, unsupported = upgrade_limitations(sides)
    receipt["pairs"] = len(pairs)
    receipt["new_packages"] = sum(1 for pair in pairs if pair["old"] is None)
    if dropped:
        receipt["not_reviewed_over_limit"] = dropped
    if unread or unsupported:
        receipt["limitations"] = (unread + unsupported)[:20]
    if unread:
        errors.append(
            _error(
                "review_upgrades",
                "Changed lockfiles were not reviewed ("
                + ", ".join(f"{item['file']}: {item['reason']}" for item in unread[:3])
                + ")",
            )
        )
    if not pairs and not dropped:
        receipt["status"] = "nothing_to_review"
        if unsupported:
            receipt["status"] = "partial"
        if unread:
            receipt["status"] = "incomplete"
        return []
    review = _api_function(api, "review_upgrades")
    if review is None:
        _unavailable(
            api,
            receipt,
            errors,
            "review_upgrades",
            f"{len(pairs) + dropped} dependency change(s) were not reviewed: "
            "ca9.api.review_upgrades is unavailable",
        )
        return []
    request = [
        {
            key: pair[key]
            for key in (
                "ecosystem",
                "name",
                "old",
                "new",
                "registry",
                "integrity",
                "resolved",
            )
            if key in pair
        }
        for pair in pairs
    ]
    options = _review_options(sides.root)
    takes_options = _accepts_options(review)
    if not takes_options and set(options) & set(POLICY_OPTION_KEYS):
        _unavailable(
            api,
            receipt,
            errors,
            "review_upgrades",
            f"{len(pairs) + dropped} dependency change(s) were not reviewed: this "
            "ca9.api.review_upgrades cannot take internal_packages or registries "
            "from [tool.skylos.supply_chain], so they would be looked up on a "
            "public registry",
        )
        return []
    try:
        if takes_options:
            result = review(request, options=options)
        else:
            result = review(request)
    except Exception as exc:  # noqa: BLE001 - engine failures stop the gate as incomplete
        receipt["status"] = "failed"
        errors.append(
            _error(
                "review_upgrades",
                f"Dependency upgrade review failed ({type(exc).__name__})",
            )
        )
        return []
    located = {
        (pair["ecosystem"], pair["name"], pair["old"] or "", pair["new"]): pair
        for pair in pairs
    }
    findings = []
    reviewed = 0
    skipped: dict[str, int] = {}
    for item in _as_list(_get(result, "results")):
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "").lower()
        key = (
            ecosystem,
            _normalized(ecosystem, str(item.get("name") or "")),
            str(item.get("old") or ""),
            str(item.get("new") or ""),
        )
        pair = located.pop(key, None)
        if pair is None:
            continue
        if item.get("status") != "reviewed":
            reason = _text(item.get("reason"), 60) or "skipped"
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        if item.get("complete") is False:
            skipped["incomplete_result"] = skipped.get("incomplete_result", 0) + 1
            findings.extend(_partial_findings(sides, pair, item))
            continue
        reviewed += 1
        block = _deltas(item.get("block"))
        warn = _deltas(item.get("warn"))
        if block or warn:
            findings.append(_upgrade_finding(sides, pair, block, warn))
    receipt["reviewed"] = reviewed
    receipt["skipped"] = [
        {"reason": reason, "count": count} for reason, count in sorted(skipped.items())
    ]
    if located:
        receipt["no_result"] = len(located)
    engine = _get(result, "receipt")
    engine_complete = isinstance(engine, dict) and engine.get("complete") is True
    if _count(_get(engine, "incomplete_results")):
        engine_complete = False
    receipt["engine_complete"] = engine_complete
    unreviewed = (
        sum(
            count
            for reason, count in skipped.items()
            if reason not in NON_BLOCKING_SKIPS
        )
        + len(located)
        + dropped
    )
    receipt["status"] = "complete"
    if skipped or located or dropped or not engine_complete or unsupported:
        receipt["status"] = "partial"
    if unread:
        receipt["status"] = "incomplete"
    if unreviewed or (not engine_complete and not skipped):
        errors.append(
            _error(
                "review_upgrades",
                f"{max(unreviewed, 1)} of {len(pairs) + dropped} dependency change(s) "
                "were not reviewed (" + _skip_text(skipped, located, dropped) + ")",
            )
        )
    return findings


def _skip_text(skipped: dict, located: dict, dropped: int) -> str:
    parts = [f"{reason}: {count}" for reason, count in sorted(skipped.items())]
    if located:
        parts.append(f"no result: {len(located)}")
    if dropped:
        parts.append(f"over the limit: {dropped}")
    return ", ".join(parts) or "engine receipt incomplete"


def _count(value) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, (list, tuple, dict)):
        return len(value)
    return 0


def _partial_findings(sides, pair, item) -> list[dict]:
    """What an incomplete review still found is reported; the pair itself
    counts as not reviewed."""
    block = _deltas(item.get("block"))
    warn = _deltas(item.get("warn"))
    if block or warn:
        return [_upgrade_finding(sides, pair, block, warn)]
    return []


def _upgrade_finding(sides, pair, block, warn) -> dict:
    rule_id = RULE_UPGRADE_WARN
    severity = "MEDIUM"
    lead = (block or warn)[0]
    added = pair["old"] is None
    if block and not added:
        rule_id = RULE_UPGRADE_BLOCK
        severity = "CRITICAL"
    where = lead["path"] or "the package"
    if lead["line"]:
        where = f"{where}:{lead['line']}"
    label = f"{pair['name']} {pair['old']} -> {pair['new']}"
    if added:
        label = f"newly added {pair['name']} {pair['new']}"
    if block and added:
        message = (
            f"{label} ships {lead['kind']} in {where}. There is no earlier "
            "version in this project to compare against, so this may be how "
            "every release of the package works; read the code before merging."
        )
    elif block:
        message = (
            f"{label} adds {lead['kind']} in {where}: code that runs on install, "
            "interpreter start or import, which compromised releases add. "
            "Do not merge until someone has read the new code; pin the old "
            "version if it cannot be explained."
        )
    else:
        message = (
            f"{label} adds {lead['kind']} in {where}. Review the new code before "
            "merging; it is not proof of a compromise."
        )
    metadata = {
        "ecosystem": pair["ecosystem"],
        "package_name": pair["name"],
        "old_version": pair["old"],
        "package_version": pair["new"],
        "basis": "upgrade",
        "block_deltas": block,
        "warn_deltas": warn,
        "engine": "ca9",
        "base_commit": sides.commit,
    }
    if pair["old"] is None:
        metadata["basis"] = "new_package"
    return _finding(
        rule_id,
        severity,
        message,
        sides.root / pair["file"],
        pair["line"],
        metadata,
        category="DEPENDENCY",
        snippet=lead["snippet"],
    )


def _without_lines(value):
    if isinstance(value, dict):
        return {
            key: _without_lines(item)
            for key, item in sorted(value.items())
            if key != "line"
        }
    if isinstance(value, list):
        return [_without_lines(item) for item in value]
    return value


def _source_lockfile_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if any(part in _SKIP_PARTS for part in pure.parts[:-1]):
        return False
    return pure.name in _SOURCE_PARSERS


def _non_public_sources(path: str, text: str) -> tuple[list[dict], dict]:
    import importlib

    module_name, function_name = _SOURCE_PARSERS[PurePosixPath(path).name]
    parser = getattr(importlib.import_module(module_name), function_name)
    try:
        inventory = parser(Path(path), text=text, max_packages=MAX_REVIEW_PACKAGES)
    except Exception as exc:  # noqa: BLE001 - reported in the check's receipt
        raise LockfileUnreadable(
            f"could not be parsed ({type(exc).__name__})"
        ) from None
    entries = [
        entry
        for entry in inventory.not_checked
        if entry.get("reason") in NON_REGISTRY_REASONS
    ]
    hosts: dict[str, set] = {}
    for record in inventory.source_records:
        host = urlsplit(str(record.get("source_url") or "")).hostname
        if host:
            hosts.setdefault(str(record.get("name")).lower(), set()).add(host.lower())
    return entries, hosts


def _source_entry_name(entry: dict) -> str:
    return str(entry.get("name") or entry.get("package") or "")


def _is_internal_package(name: str, patterns: list) -> bool:
    return any(fnmatch.fnmatchcase(name, str(item).lower()) for item in patterns)


def new_source_findings(sides: GitSides, _api, receipt: dict, _errors: list) -> list[dict]:
    """SKY-SCA-SRC004: a change points a package at a source this repository
    did not use for it. Such packages have no advisory coverage, so an existing
    private dependency stays quiet and a newly introduced one is reviewed."""
    base, head = sides.files(_source_lockfile_path)
    changed = sorted(path for path, text in head.items() if base.get(path) != text)
    receipt["changed"] = len(changed)
    receipt["status"] = "unchanged"
    if not changed:
        return []
    receipt["status"] = "checked"
    known_names: set = set()
    known_hosts: dict[str, set] = {}
    unreadable = []
    for path, text in base.items():
        try:
            entries, hosts = _non_public_sources(path, text)
        except LockfileUnreadable:
            unreadable.append(path)
            continue
        known_names.update(_source_entry_name(entry).lower() for entry in entries)
        for name, values in hosts.items():
            known_hosts.setdefault(name, set()).update(values)
    internal = _review_options(sides.root).get("internal_packages", [])
    findings = []
    for path in changed:
        try:
            entries, hosts = _non_public_sources(path, head[path])
        except LockfileUnreadable:
            unreadable.append(path)
            continue
        seen = set()
        for entry in entries:
            name = _source_entry_name(entry)
            key = name.lower()
            if not key or key in seen or _is_internal_package(key, internal):
                continue
            new_hosts = hosts.get(key, set()) - known_hosts.get(key, set())
            if key in known_names and not new_hosts:
                continue
            seen.add(key)
            findings.append(_new_source_finding(sides, path, entry, name, new_hosts))
    if unreadable:
        receipt["unreadable"] = sorted(set(unreadable))[:10]
    return findings


def _new_source_finding(sides, path, entry, name, new_hosts) -> dict:
    where = f"a {entry.get('source_type')} source"
    if new_hosts:
        where = ", ".join(sorted(new_hosts))
    message = (
        f"{name} in {path} now comes from {where}, which this repository did not "
        "use for it. Advisory databases do not cover it, so Skylos cannot check "
        "it. If it is yours, list it in internal_packages under "
        "[tool.skylos.supply_chain] on the target branch."
    )
    metadata = {
        "package_name": name,
        "package_version": entry.get("version"),
        "source_type": entry.get("source_type"),
        "source_hosts": sorted(new_hosts),
        "basis": "new_source",
        "base_commit": sides.commit,
    }
    return _finding(
        RULE_NEW_SOURCE,
        "HIGH",
        message,
        sides.root / path,
        entry.get("line") or 1,
        metadata,
        category="DEPENDENCY",
    )


def _publish_jobs(inventory) -> dict[tuple, tuple]:
    jobs = {}
    for workflow in _as_list(_get(inventory, "workflows")):
        if not isinstance(workflow, dict):
            continue
        context = {
            key: workflow.get(key)
            for key in ("triggers", "dispatch", "branch_filters", "any_branch")
        }
        for job in workflow.get("jobs") or []:
            if not isinstance(job, dict) or not job.get("publishes"):
                continue
            key = (str(workflow.get("file") or ""), str(job.get("id") or ""))
            jobs[key] = (_without_lines({**job, "_workflow": context}), job)
    return jobs


def publish_job_findings(
    sides: GitSides, api, receipt: dict, errors: list
) -> list[dict]:
    base, head = sides.files(ci_path)
    if base == head:
        receipt["status"] = "unchanged"
        return []
    inventory = _api_function(api, "ci_inventory")
    if inventory is None:
        _unavailable(
            api,
            receipt,
            errors,
            "ci_inventory",
            "CI files changed but publish jobs were not compared: "
            "ca9.api.ci_inventory is unavailable",
        )
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="skylos-ci-") as temp:
            before = inventory(str(_write_tree(Path(temp) / "base", base)))
            after = inventory(str(_write_tree(Path(temp) / "head", head)))
    except Exception as exc:  # noqa: BLE001 - engine failures stop the gate as incomplete
        receipt["status"] = "failed"
        errors.append(
            _error("ci_inventory", f"CI inventory failed ({type(exc).__name__})")
        )
        return []
    old = _publish_jobs(before)
    findings = []
    for (file, job_id), (shape, job) in sorted(_publish_jobs(after).items()):
        previous = old.get((file, job_id))
        if previous is not None and previous[0] == shape:
            continue
        pure = PurePosixPath(file)
        if not file or pure.is_absolute() or ".." in pure.parts:
            continue
        state = "adds"
        if previous is not None:
            state = "modifies"
        registries = sorted(
            {
                _text(publish.get("registry"), 20)
                for publish in job.get("publishes") or []
                if isinstance(publish, dict)
            }
            - {""}
        )
        message = (
            f"This change {state} job '{_text(job_id, 100)}', which publishes to "
            f"{', '.join(registries) or 'a package registry'}. Publish jobs hold "
            "registry credentials; review every changed step, trigger and permission."
        )
        findings.append(
            _finding(
                RULE_PUBLISH_JOB_CHANGED,
                "MEDIUM",
                message,
                sides.root / file,
                job.get("line") or 1,
                {"job": _text(job_id, 100), "change": state, "registries": registries},
                category="SECURITY",
                snippet=f"{job_id}:",
            )
        )
    statuses = {
        str(side.get("status")) for side in (before, after) if isinstance(side, dict)
    }
    receipt["status"] = "complete"
    if statuses - {"complete"}:
        receipt["status"] = "partial"
    receipt["changed_publish_jobs"] = len(findings)
    return findings


def config_base_identities(root: str | Path, base_ref: str, api=None):
    """``(rule, repository-relative path, identity)`` of every SKY-D365-D377
    finding ca9 reports for the merge base's agent configs (as the agent
    opens them, through in-repo links) and CI workflows, copied into a
    temporary folder. A head finding not in this set is new, whatever lines
    moved: a ``runOn: folderOpen`` added to an existing task, or a hook moved
    from ``Stop`` to ``SessionStart``, is a new finding on an unchanged line.
    None when the base cannot be compared (no Git base, ca9 missing or
    failing, too many files)."""
    from skylos.rules.config.agent_files import call_on_copy
    from skylos.rules.config.agent_publish import (
        AGENT_RULES,
        PUBLISH_RULES,
        _call,
        row_identity,
    )
    from skylos.rules.sca import supply_chain

    if api is None:
        api = supply_chain.load_ca9_api()
    sides = open_sides(root, base_ref)
    if sides is None:
        return None
    try:
        agent_base, _head, _problems = sides.client_files(agent_path)
        ci_base, _ci_head = sides.files(ci_path)
    except ValueError:
        return None
    identities: set[tuple[str, str, str]] = set()
    for function, rules, texts in (
        ("agent_config", AGENT_RULES, agent_base),
        ("audit_workflows", PUBLISH_RULES, ci_base),
    ):
        if not texts:
            continue
        if _api_function(api, function) is None:
            return None
        result, problem = call_on_copy(api, function, texts, _call)
        if problem is not None or not isinstance(result, dict):
            return None
        for row in _as_list(result.get("findings")):
            if not isinstance(row, dict):
                continue
            rule = rules.get(str(row.get("signal_type") or ""))
            file = PurePosixPath(str(row.get("file") or "").replace("\\", "/"))
            if rule is None or file.is_absolute() or ".." in file.parts:
                continue
            identities.add((rule[0], file.as_posix(), row_identity(rule[0], row)))
    return identities


def supply_chain_diff_findings(
    root: str | Path,
    base_ref: str,
    *,
    dependencies: bool,
    security: bool,
    review_upgrades: bool,
    ignore=(),
    api=None,
) -> tuple[list[dict], dict, list[dict]]:
    """(findings, receipt, analysis_errors) for one diff-scoped scan."""
    from skylos.rules.sca import supply_chain

    ignore = {str(rule).upper() for rule in ignore or ()}
    receipt: dict[str, Any] = {"engine": "ca9", "checks": {}}
    errors: list[dict] = []
    if api is None:
        api = supply_chain.load_ca9_api()
    sides = open_sides(root, base_ref)
    if sides is None:
        receipt["status"] = "no_git_base"
        return [], receipt, errors
    receipt["base_commit"] = sides.commit
    checks: list[tuple[str, Callable, set]] = []
    if security:
        checks.append(("agent_and_workflow_files", config_coverage, set()))
    if security and RULE_PUBLISH_JOB_CHANGED not in ignore:
        checks.append(
            ("publish_jobs", publish_job_findings, {RULE_PUBLISH_JOB_CHANGED})
        )
    if dependencies:
        checks.append(("dependency_files", dependency_coverage, set()))
    if dependencies and RULE_NEW_SOURCE not in ignore:
        checks.append(("package_sources", new_source_findings, {RULE_NEW_SOURCE}))
    if dependencies and RULE_HARDENING not in ignore:
        checks.append(("hardening", hardening_findings, {RULE_HARDENING}))
    if dependencies and review_upgrades:
        checks.append(
            ("upgrades", upgrade_findings, {RULE_UPGRADE_BLOCK, RULE_UPGRADE_WARN})
        )
    if dependencies and review_upgrades and RULE_UPGRADE_API not in ignore:
        from skylos.rules.sca.upgrade_api_diff import upgrade_api_findings

        checks.append(("upgrade_api", upgrade_api_findings, {RULE_UPGRADE_API}))
    findings: list[dict] = []
    for name, check, rules in checks:
        check_receipt: dict[str, Any] = {}
        receipt["checks"][name] = check_receipt
        try:
            found = check(sides, api, check_receipt, errors)
        except Exception as exc:
            logger.debug("supply-chain diff check %s failed", name, exc_info=True)
            check_receipt["status"] = "failed"
            errors.append(
                _error(name, f"Supply-chain check {name} failed ({type(exc).__name__})")
            )
            continue
        findings.extend(item for item in found if item["rule_id"] in rules - ignore)
    receipt["status"] = "complete"
    if errors:
        receipt["status"] = "incomplete"
    return findings, receipt, errors


__all__ = [
    "DIFF_RULES",
    "ERROR_KIND",
    "FINDING_KIND",
    "RULE_HARDENING",
    "RULE_NEW_SOURCE",
    "RULE_PUBLISH_JOB_CHANGED",
    "RULE_UPGRADE_API",
    "RULE_UPGRADE_BLOCK",
    "RULE_UPGRADE_WARN",
    "config_base_identities",
    "supply_chain_diff_findings",
]
