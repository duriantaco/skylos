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
  PyPI lockfile version changes are paired base to head and passed to
  ``review_upgrades``; block deltas are UPG001, warn-only deltas UPG002.
- ``SKY-D375``: a CI job that publishes packages was added or changed
  (``ci_inventory`` of both sides, line numbers ignored).

When something relevant changed, a ca9 function that is missing or fails, or a
hardening comparison that reports ``check_failed``, becomes an analysis error
with no file, so a diff-scoped gate stops as incomplete instead of passing
without the check. This includes the agent and workflow rules of the danger
scan (SKY-D365-D374). With no ca9 engine installed at all, the receipt says
``engine_unavailable``, as the other supply-chain checks do.
"""

from __future__ import annotations

import fnmatch
import logging
import re
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink

logger = logging.getLogger(__name__)

RULE_HARDENING = "SKY-SCA-HRD001"
RULE_UPGRADE_BLOCK = "SKY-SCA-UPG001"
RULE_UPGRADE_WARN = "SKY-SCA-UPG002"
RULE_PUBLISH_JOB_CHANGED = "SKY-D375"
DIFF_RULES = frozenset(
    {RULE_HARDENING, RULE_UPGRADE_BLOCK, RULE_UPGRADE_WARN, RULE_PUBLISH_JOB_CHANGED}
)
FINDING_KIND = "supply_chain_diff"
ERROR_KIND = "supply_chain_check_unavailable"
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 40_000_000
MAX_SIDE_FILES = 400
MAX_UPGRADE_PAIRS = 100
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


class GitSides:
    """The merge base and the tracked working tree of one repository."""

    def __init__(self, context: GitContext, commit: str, base_paths, head_paths):
        self.context = context
        self.root = Path(context.root)
        self.commit = commit
        self.base_paths = base_paths
        self.head_paths = head_paths
        self._bytes = 0

    def _charge(self, text: str | None) -> str | None:
        if text is None:
            return None
        self._bytes += len(text.encode("utf-8", "ignore"))
        if self._bytes > MAX_TOTAL_BYTES:
            raise ValueError("diff inputs exceed the size limit")
        return text

    def base_text(self, path: str) -> str | None:
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
        if mode not in {"100644", "100755"} or kind != "blob":
            return None
        if not size.isdigit() or int(size) > MAX_FILE_BYTES:
            return None
        blob = self.context.run("cat-file", "blob", object_id)
        if blob.returncode != 0:
            return None
        return self._charge(blob.stdout)

    def head_text(self, path: str) -> str | None:
        text = read_project_text_no_symlink(
            self.root, path, max_bytes=MAX_FILE_BYTES, encoding="utf-8"
        )
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


def _unavailable(api, receipt: dict, errors: list, check: str, message: str) -> None:
    """A check that cannot run: with no ca9 engine at all a receipt note
    (the scan works without ca9, as the other supply-chain checks do); with
    an engine that lacks or fails the function an analysis error."""
    if api is None:
        receipt["status"] = "engine_unavailable"
        receipt["note"] = "ca9 engine is not installed"
        return
    receipt["status"] = "unavailable"
    errors.append(_error(check, message))


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
            errors.append(
                _error(
                    "hardening_regressions",
                    f"Install hardening comparison failed: {detail or 'no detail'}",
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


AGENT_FOLDERS = frozenset(
    {
        ".claude",
        ".gemini",
        ".cursor",
        ".codex",
        ".vscode",
        ".kiro",
        ".roo",
        ".amazonq",
        ".windsurf",
    }
)


def agent_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.name == ".mcp.json" or pure.name.endswith(".code-workspace"):
        return True
    return any(part in AGENT_FOLDERS for part in pure.parts[:-1]) and pure.suffix in {
        ".json",
        ".toml",
    }


def config_coverage(sides: GitSides, api, receipt: dict, errors: list) -> list[dict]:
    """The danger scan reads agent and workflow files through ca9; when one
    of them changed, a missing ca9 function must not look like a clean file."""
    needed = []
    for select, function in (
        (agent_path, "agent_config"),
        (ci_path, "audit_workflows"),
    ):
        base, head = sides.files(select)
        if base != head:
            needed.append(function)
    receipt["changed"] = needed
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
    return []


def _parse_lockfile(name: str, path: str, text: str) -> list[dict]:
    ecosystem, module_name, function_name = _UPGRADE_PARSERS[PurePosixPath(name).name]
    import importlib

    parser = getattr(importlib.import_module(module_name), function_name)
    try:
        inventory = parser(Path(path), text=text)
    except Exception:  # noqa: BLE001 - an unreadable lockfile side has no versions
        return []
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


def upgrade_pairs(sides: GitSides) -> tuple[list[dict], int]:
    """(pairs, dropped) for lockfile versions that changed base to head."""
    base, head = sides.files(upgrade_path)
    pairs: dict[tuple, dict] = {}
    for path, head_text in sorted(head.items()):
        base_text = base.get(path)
        if base_text is None or base_text == head_text:
            continue
        base_rows = _parse_lockfile(path, path, base_text)
        head_rows = _parse_lockfile(path, path, head_text)
        old: dict[tuple, set] = {}
        for row in base_rows:
            key = (row["_ecosystem"], _normalized(row["_ecosystem"], row["name"]))
            old.setdefault(key, set()).add(str(row["version"]))
        new: dict[tuple, dict] = {}
        for row in head_rows:
            key = (row["_ecosystem"], _normalized(row["_ecosystem"], row["name"]))
            version = str(row["version"])
            if key not in old or version in old[key]:
                continue
            new.setdefault((*key, version), row)
        for (ecosystem, name, version), row in sorted(new.items()):
            previous = max(old[(ecosystem, name)], key=_version_key)
            pair = {
                "ecosystem": ecosystem,
                "name": name,
                "old": previous,
                "new": version,
                "file": path,
                "line": row.get("line") or 1,
            }
            registry = str(row.get("registry") or "")
            host = re.sub(r"^[a-z]+://", "", registry).split("/", 1)[0].lower()
            if host in _PUBLIC_REGISTRIES[ecosystem]:
                pair["registry"] = host
            pairs.setdefault((ecosystem, name, previous, version), pair)
    ordered = list(pairs.values())
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


def upgrade_findings(sides: GitSides, api, receipt: dict, errors: list) -> list[dict]:
    pairs, dropped = upgrade_pairs(sides)
    receipt["pairs"] = len(pairs)
    if dropped:
        receipt["not_reviewed_over_limit"] = dropped
    if not pairs:
        receipt["status"] = "nothing_to_review"
        return []
    review = _api_function(api, "review_upgrades")
    if review is None:
        _unavailable(
            api,
            receipt,
            errors,
            "review_upgrades",
            f"{len(pairs)} dependency upgrade(s) were not reviewed: "
            "ca9.api.review_upgrades is unavailable",
        )
        return []
    request = [
        {
            key: pair[key]
            for key in ("ecosystem", "name", "old", "new", "registry")
            if key in pair
        }
        for pair in pairs
    ]
    try:
        result = review(request, options=None)
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
        (pair["ecosystem"], pair["name"], pair["old"], pair["new"]): pair
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
        pair = located.get(key)
        if pair is None:
            continue
        if item.get("status") != "reviewed":
            reason = _text(item.get("reason"), 60) or "skipped"
            skipped[reason] = skipped.get(reason, 0) + 1
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
    missing = len(pairs) - reviewed - sum(skipped.values())
    if missing > 0:
        receipt["no_result"] = missing
    receipt["status"] = "complete"
    if skipped or missing > 0 or dropped:
        receipt["status"] = "partial"
    return findings


def _upgrade_finding(sides, pair, block, warn) -> dict:
    rule_id = RULE_UPGRADE_WARN
    severity = "MEDIUM"
    lead = warn[0]
    if block:
        rule_id = RULE_UPGRADE_BLOCK
        severity = "CRITICAL"
        lead = block[0]
    where = lead["path"] or "the package"
    if lead["line"]:
        where = f"{where}:{lead['line']}"
    label = f"{pair['name']} {pair['old']} -> {pair['new']}"
    if block:
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
        "block_deltas": block,
        "warn_deltas": warn,
        "engine": "ca9",
        "base_commit": sides.commit,
    }
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
    if dependencies and RULE_HARDENING not in ignore:
        checks.append(("hardening", hardening_findings, {RULE_HARDENING}))
    if dependencies and review_upgrades:
        checks.append(
            ("upgrades", upgrade_findings, {RULE_UPGRADE_BLOCK, RULE_UPGRADE_WARN})
        )
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
    "RULE_PUBLISH_JOB_CHANGED",
    "RULE_UPGRADE_BLOCK",
    "RULE_UPGRADE_WARN",
    "supply_chain_diff_findings",
]
