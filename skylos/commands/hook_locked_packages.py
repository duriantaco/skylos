"""The packages a lockfile or requirements install brings in, for the hook.

:func:`read_locked` turns one lockfile-install target (``npm ci``, ``uv
sync``, ``npm install x`` with a lockfile, ``pip install -r ...``) into the
(ecosystem, name, version) keys the malware check queries, plus explicit
"could not verify" and direct-source entries in the install result:

* Every locked entry with a name and version is queried, whatever source it
  records, unless it comes from a declared (trusted or private) registry and
  matches ``internal_packages``. Known public registries and mirrors are
  public. A tarball, git or URL source from anywhere else is also a direct
  source (the ``direct_source`` policy), because its contents need not match
  the name and version it claims.
* Requirements files follow pip: index options never switch the check off;
  only an exclusive private ``--index-url`` keeps ``internal_packages`` names
  private. ``name @ url``, VCS and URL lines are direct sources. Constraint
  pins (``-c``) count as the version of an unpinned requirement.
* A lockfile, manifest or requirements file that an earlier part of the same
  command line may write is "could not verify" and is not read: the hook
  would be checking the old contents.

Nothing here touches the network, and the scan readers' contracts are only
read (``dependencies``, ``source_records``, ``unresolved``, ``not_checked``).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.commands.hook_install_parse import (
    NPM,
    PUBLIC_REGISTRY_HOSTS,
    PYPI,
    InstallTarget,
    registry_host,
)

MAX_LOCKED_PACKAGES = 5000
MAX_DIRECT_ENTRIES = 50
MAX_REQUIREMENTS_TEXT = 5_000_000
OUTCOME_UNCHECKED = "unchecked"

LOCKFILES = {
    "npm": ("npm-shrinkwrap.json", "package-lock.json"),
    "pnpm": ("pnpm-lock.yaml",),
    "yarn": ("yarn.lock",),
    "bun": ("bun.lock",),
    "uv": ("uv.lock",),
    "poetry": ("poetry.lock",),
    "pipenv": ("Pipfile.lock",),
}
_MANIFESTS = {
    "npm": "package.json", "pnpm": "package.json", "yarn": "package.json",
    "bun": "package.json", "uv": "pyproject.toml", "poetry": "pyproject.toml",
    "pipenv": "Pipfile",
}  # fmt: skip
_EXACT_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*"
    r"(?P<version>[0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)
_EXCLUSIVE_INDEX_RE = re.compile(r"^\s*(?:-i|--index-url)(?:\s*=\s*|\s+)(?P<url>\S+)")
_LOCAL_SOURCES = frozenset({"local", "workspace", "path", "directory", "editable", "virtual"})
_USERINFO_RE = re.compile(r"(?<=://)[^/@\s]*@")

Key = tuple[str, str, str]


@dataclass
class Locked:
    target: InstallTarget
    label: str
    keys: list[Key]
    entries: dict[Key, tuple[str, int, str]]
    skipped: int = 0


@dataclass
class LockContext:
    root: Path | None
    trusted: tuple[str, ...]
    internal: tuple[str, ...]
    allowed: set
    package_allowed: Callable[[dict[str, Any], set], bool]


def key(ecosystem: str, name: str, version: str) -> Key:
    if ecosystem == PYPI:
        name = _pep503(name)
    return ecosystem, name, version


def is_internal(ecosystem: str, name: str, patterns: tuple[str, ...]) -> bool:
    if ecosystem == PYPI:
        candidate = _pep503(name)
        return any(fnmatch.fnmatchcase(candidate, _pep503(p)) for p in patterns)
    candidate = name.lower()
    return any(fnmatch.fnmatchcase(candidate, p.lower()) for p in patterns)


def read_locked(target: InstallTarget, ctx: LockContext, result: dict[str, Any]) -> Locked | None:
    if target.lockfile == "requirements":
        return _read_requirements(target, ctx, result)
    base = Path(target.cwd or target.spec)
    names = LOCKFILES.get(target.lockfile, ())
    path = find_lockfile(base, names, ctx.root)
    if path is None:
        _missing_lockfile(target, ctx, base, names, result)
        return None
    label = label_for(path, ctx.root)
    manifest = path.parent / _MANIFESTS.get(target.lockfile, "package.json")
    if _rewritten(target, (path, manifest)):
        _unverified(result, target, label, "an earlier part of this command may rewrite it, "
                    "and Skylos reads it before the command runs")  # fmt: skip
        return None
    try:
        inventory = _parse_lockfile(target.lockfile, path)
    except Exception as exc:  # noqa: BLE001
        reason = str(exc) or type(exc).__name__
        _unverified(result, target, label, f"could not read it ({reason[:120]})")
        return None
    deps: list[tuple[str, str, str, Any, str]] = []
    seen: set[tuple[str, str]] = set()
    for dep in inventory.dependencies:
        deps.append((dep.get("ecosystem"), dep.get("name"), dep.get("version"),
                     dep.get("line"), label))  # fmt: skip
        seen.add((str(dep.get("name")), str(dep.get("version"))))
    direct: list[dict[str, Any]] = []
    for record in getattr(inventory, "source_records", None) or []:
        if not isinstance(record, dict):
            continue
        name, version = str(record.get("name") or ""), str(record.get("version") or "")
        if not name or not version:
            continue
        seen.add((name, version))
        ecosystem = record.get("ecosystem") or target.ecosystem
        if _keep_private(ecosystem, name, record, ctx):
            continue
        deps.append((ecosystem, name, version, record.get("line"), label))
        if not _registry_source(ecosystem, record, ctx):
            direct.append(_direct_entry(target, name, version, record, label))
    for entry in list(inventory.unresolved) + list(inventory.not_checked):
        if not isinstance(entry, dict):
            continue
        name, version = str(entry.get("name") or ""), str(entry.get("version") or "")
        if not name or not version or (name, version) in seen:
            continue
        seen.add((name, version))
        if str(entry.get("source_type") or "") in _LOCAL_SOURCES:
            continue
        reason = str(entry.get("reason") or "")
        if reason == "non_public_registry":
            if ctx.trusted and is_internal(target.ecosystem, name, ctx.internal):
                continue
            deps.append((target.ecosystem, name, version, entry.get("line"), label))
            continue
        deps.append((target.ecosystem, name, version, entry.get("line"), label))
        direct.append(_direct_entry(target, name, version, entry, label))
    result.setdefault("direct", []).extend(direct[:MAX_DIRECT_ENTRIES])
    return _locked_item(target, label, deps, ctx)


def constraint_specs(
    paths: tuple[str, ...], root: Path | None
) -> tuple[dict[str, str], list[str], list[Path]]:
    """Specifier per PEP 503 name from constraints files, the files that could
    not be read, and the files that were read."""
    from packaging.requirements import InvalidRequirement, Requirement

    from skylos.core.python_requirements import read_requirements_tree

    specs: dict[str, str] = {}
    unreadable: list[str] = []
    files: list[Path] = []
    for raw in paths:
        if raw == "$":
            unreadable.append("a constraints file named at run time")
            continue
        if "://" in raw:
            unreadable.append(f"constraints file {_USERINFO_RE.sub('', raw)}")
            continue
        path = Path(raw)
        tree = read_requirements_tree(path, root=_bound(path, root))
        if not tree.files:
            unreadable.append(f"constraints file {label_for(path, root)}")
            continue
        for parsed in tree.files:
            files.append(Path(parsed.path))
        for line in tree.requirements():
            try:
                requirement = Requirement(line.spec)
            except InvalidRequirement:
                continue
            text = str(requirement.specifier)
            if text:
                name = _pep503(requirement.name)
                specs[name] = ",".join(part for part in (specs.get(name), text) if part)
    return specs, unreadable, files


def exact_version(specifier: str) -> str:
    """The version of an ``==X`` / ``===X`` specifier, or ""."""
    match = re.fullmatch(r"\s*===?\s*([0-9][A-Za-z0-9._+!-]*)\s*", specifier or "")
    if match and "*" not in match.group(1):
        return match.group(1)
    return ""


def find_lockfile(base: Path, names: tuple[str, ...], root: Path | None) -> Path | None:
    current = base
    while True:
        for name in names:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if root is None or not _inside(current, root) or _same(current, root):
            return None
        if current.parent == current:
            return None
        current = current.parent


def label_for(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            pass
    return str(path)


def _missing_lockfile(target, ctx, base, names, result) -> None:
    binary = None
    if target.lockfile == "bun":
        binary = find_lockfile(base, ("bun.lockb",), ctx.root)
    expected = base / names[-1]
    if binary is not None:
        _unverified(result, target, binary.name, "bun.lockb is binary; Skylos reads "
                    "only the text bun.lock (bun install --save-text-lockfile)")  # fmt: skip
    elif (target.preceded and not target.named) or _rewritten(target, (expected,)):
        _unverified(result, target, names[-1], f"no {names[-1]} yet; an earlier part "
                    "of this command may write it, and Skylos reads lockfiles before "
                    "the command runs")  # fmt: skip


def _read_requirements(target, ctx, result) -> Locked | None:
    from skylos.core.python_requirements import read_requirements_tree

    path = Path(target.spec).expanduser()
    if not path.is_absolute():
        path = Path(target.cwd or ".") / path
    label = label_for(path, ctx.root)
    if not path.is_file():
        if target.preceded:
            _unverified(result, target, label, "the file does not exist yet; an earlier "
                        "part of this command may write it, and Skylos reads it before "
                        "the command runs")  # fmt: skip
        return None
    tree = read_requirements_tree(path, root=_bound(path, ctx.root))
    if not tree.files:
        _unverified(result, target, label, "could not read it")
        return None
    pins, unreadable, constraint_files = constraint_specs(target.constraints, ctx.root)
    watched = [Path(parsed.path) for parsed in tree.files] + constraint_files
    if _rewritten(target, tuple(watched)):
        _unverified(result, target, label, "an earlier part of this command may rewrite it, "
                    "and Skylos reads it before the command runs")  # fmt: skip
        return None
    for include in tree.unresolved_includes[:3]:
        _unverified(result, target, label, f"includes {include}, which Skylos could not read")
    for item in unreadable[:3]:
        _unverified(result, target, label, f"{item} could not be read")
    if tree.limit_reached:
        _unverified(result, target, label, "includes more files than Skylos follows")
    exclusive = target.exclusive_index or _exclusive_private_index(tree)
    for parsed in tree.files:
        if tree.kinds.get(parsed.path) != "constraint":
            continue
        for line in parsed.requirements:
            match = _EXACT_PIN_RE.match(line.spec)
            if match and not line.url:
                pins.setdefault(_pep503(line.name), "==" + match.group("version"))
    deps = []
    direct = []
    for line in tree.requirements(include_constraints=False):
        file_label = label_for(Path(line.path), ctx.root)
        if line.url:
            if not _local_reference(line.spec):
                direct.append(_requirement_direct(target, line.spec, file_label))
            continue
        match = _EXACT_PIN_RE.match(line.spec)
        version = ""
        if match:
            version = match.group("version")
        else:
            version = exact_version(pins.get(_pep503(line.name), ""))
        if not version:
            continue
        if exclusive and is_internal(PYPI, line.name, ctx.internal):
            continue
        deps.append((PYPI, line.name, version, line.line, file_label))
    for parsed in tree.files:
        for editable in parsed.editables:
            if not _local_reference(editable):
                direct.append(_requirement_direct(target, f"-e {editable}",
                                                  label_for(Path(parsed.path), ctx.root)))  # fmt: skip
    result.setdefault("direct", []).extend(direct[:MAX_DIRECT_ENTRIES])
    return _locked_item(target, label, deps, ctx)


def _exclusive_private_index(tree) -> bool:
    from skylos.commands.hook_install_parse import _is_public_registry
    from skylos.core.safe_cache_io import read_text_no_symlink

    for parsed in tree.files:
        text = read_text_no_symlink(parsed.path, max_bytes=MAX_REQUIREMENTS_TEXT,
                                    encoding="utf-8", errors="ignore")  # fmt: skip
        for line in (text or "").splitlines():
            match = _EXCLUSIVE_INDEX_RE.match(line)
            if match and not _is_public_registry(match.group("url"), PYPI):
                return True
    return False


def _keep_private(ecosystem: str, name: str, record: dict[str, Any], ctx: LockContext) -> bool:
    """A declared registry serving an internal name stays private."""
    if record.get("source_kind") != "url":
        return False
    host = registry_host(str(record.get("source_url") or ""))
    if not host or not _declared(host, ctx.trusted):
        return False
    return is_internal(ecosystem, name, ctx.internal)


def _registry_source(ecosystem: str, record: dict[str, Any], ctx: LockContext) -> bool:
    """A tarball from a public registry or mirror, or from a declared registry."""
    if record.get("source_kind") != "url":
        return False
    host = registry_host(str(record.get("source_url") or ""))
    if not host:
        return False
    return host in PUBLIC_REGISTRY_HOSTS.get(ecosystem, frozenset()) or _declared(host, ctx.trusted)


def _declared(host: str, trusted: tuple[str, ...]) -> bool:
    return any(registry_host(entry) == host for entry in trusted)


def _direct_entry(target, name, version, record, label) -> dict[str, Any]:
    url = _USERINFO_RE.sub("", str(record.get("source_url") or ""))
    kind = str(record.get("source_kind") or record.get("source_type") or "source")
    host = registry_host(url)
    where = host or "an unknown source"
    if kind == "git":
        where = url or "a git repository"
    source = f"{kind} from {where} in {label}"
    if record.get("source_kind") == "url" and host:
        source = f"tarball from {host} in {label}"
    return {"ecosystem": target.ecosystem, "tool": target.tool,
            "spec": f"{name}@{version}", "source": source}  # fmt: skip


def _requirement_direct(target, spec, label) -> dict[str, Any]:
    text = _USERINFO_RE.sub("", spec.strip())[:160]
    return {"ecosystem": PYPI, "tool": target.tool, "spec": text,
            "source": f"direct reference in {label}"}  # fmt: skip


def _local_reference(spec: str) -> bool:
    text = spec.strip()
    if " @ " in text:
        text = text.split(" @ ", 1)[1].strip()
    return text.startswith(("./", "../", "/", ".", "file:", "~")) and "://" not in text[:12]


def _rewritten(target: InstallTarget, paths: tuple[Path, ...]) -> bool:
    if target.writes is None:
        return False
    return any(target.writes.covers(path) for path in paths)


def _locked_item(target, label, deps, ctx: LockContext) -> Locked:
    entries: dict[Key, tuple[str, int, str]] = {}
    for ecosystem, name, version, line, file_label in deps:
        if ecosystem not in (NPM, PYPI) or not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str) or not version:
            continue
        if ctx.package_allowed({"ecosystem": ecosystem, "name": name}, ctx.allowed):
            continue
        if not isinstance(line, int):
            line = 0
        entries.setdefault(key(ecosystem, name, version), (name, line, file_label))
    keys = sorted(entries)
    skipped = max(0, len(keys) - MAX_LOCKED_PACKAGES)
    return Locked(target, label, keys[:MAX_LOCKED_PACKAGES], entries, skipped)


def _parse_lockfile(manager: str, path: Path):
    if manager == "npm":
        from skylos.rules.sca.npm_lockfile import parse_package_lock as parse
    elif manager == "pnpm":
        from skylos.rules.sca.pnpm_lockfile import parse_pnpm_lock as parse
    elif manager == "yarn":
        from skylos.rules.sca.yarn_lockfile import parse_yarn_lock as parse
    elif manager == "bun":
        from skylos.rules.sca.bun_lockfile import parse_bun_lock as parse
    elif manager == "uv":
        from skylos.rules.sca.uv_lockfile import parse_uv_lock as parse
    elif manager == "poetry":
        from skylos.rules.sca.poetry_lockfile import parse_poetry_lock as parse
    else:
        from skylos.rules.sca.pipfile_lockfile import parse_pipfile_lock as parse
    return parse(path, max_packages=MAX_LOCKED_PACKAGES * 4)


def _unverified(result: dict[str, Any], target: InstallTarget, name: str, reason: str) -> None:
    result.setdefault("unverified", []).append(
        {"ecosystem": target.ecosystem, "name": name, "tool": target.tool,
         "reason": reason, "outcome": OUTCOME_UNCHECKED}
    )  # fmt: skip


def _bound(path: Path, root: Path | None) -> Path:
    if root is not None and _inside(path, root):
        return root
    return path.parent


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _same(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


__all__ = [
    "LOCKFILES",
    "MAX_LOCKED_PACKAGES",
    "LockContext",
    "Locked",
    "constraint_specs",
    "exact_version",
    "find_lockfile",
    "is_internal",
    "key",
    "label_for",
    "read_locked",
]
