"""What a shell command installs or runs from a package registry.

The pre-bash hook asks this module, before the command runs, which packages
it would fetch. Each one comes back as an :class:`InstallTarget`:

* ``registry``: a package name (and version) on PyPI, npm, the Go module
  proxy or JSR. The hook checks that it exists.
* ``direct``: code fetched from somewhere a registry check cannot cover: a
  git repository, ``github:user/repo``, a tarball or wheel URL, an archive
  outside the project. The hook applies the ``direct_source`` policy.
* ``dynamic``: the name is only known at run time (``$PKG``, ``$(...)``,
  ``xargs``), or could not be read. The hook applies ``on_unverified``.
* ``local``: a path inside the project, a workspace package, or a binary
  already in ``node_modules/.bin`` (``npx tsc``). Nothing is fetched.
* ``manifest``: installs what a manifest or lockfile names (``npm ci``,
  ``pip install -r requirements.txt``, ``uv sync``). Out of scope for the
  hook; ``skylos . -a`` and ``skylos done`` check manifests.

Covered: pip / ``python -m pip`` / ``uv pip`` / ``uv add`` / ``uv tool`` /
``uvx`` / ``uv run --with`` / poetry / pdm / pipenv / pipx (install, run,
inject); npm (install and aliases, exec, init/create) / npx / pnpm (add,
install, dlx, create) / pnpx / yarn (add, global add, dlx, create) / bun
(add, install, x, create) / bunx; ``go get`` / ``go install`` /
``go run pkg@version``; deno (``npm:``, ``jsr:`` and URL specifiers).

Each target also carries the registries the command line points the tool
at (``--index-url``, ``--registry``, ``NPM_CONFIG_REGISTRY=``, ``GOPROXY=``
and similar); the checker decides whether those are trusted.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from skylos.commands.hook_shell_commands import SimpleCommand, simple_commands

PYPI = "PyPI"
NPM = "npm"
GO = "Go"
JSR = "JSR"

REGISTRY = "registry"
DIRECT = "direct"
DYNAMIC = "dynamic"
LOCAL = "local"
MANIFEST = "manifest"

MAX_TARGETS = 40
# No real package spec is this long; longer ones are "could not read".
MAX_SPEC_CHARS = 512
# Cheap pre-filter: commands without one of these words install nothing.
INSTALL_HINT_RE = re.compile(
    r"(?i)(?<![\w.-])(?:pip[0-9.]*|pipx|pipenv|uvx?|poetry|pdm|npm|npx|pnpm|pnpx|"
    r"yarn|bunx?|go|deno|python[0-9.]*|pypy[0-9.]*|py)(?:\.exe)?(?![\w-])"
)

# Hosts that serve the default public registry: an index flag naming one of
# them changes nothing about what a public-registry check means.
PUBLIC_REGISTRY_HOSTS = {
    PYPI: frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org"}),
    NPM: frozenset(
        {"registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"}
    ),
    GO: frozenset({"proxy.golang.org"}),
    JSR: frozenset({"jsr.io", "npm.jsr.io"}),
}
ARCHIVE_SUFFIXES = (
    ".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar", ".egg",
)  # fmt: skip
_DOWNLOADERS = frozenset({"curl", "wget", "aria2c", "http", "https", "xh", "fetch"})

_PIP_RE = re.compile(r"^pip(?:\d+(?:\.\d+)?)?$")
_PYTHON_RE = re.compile(r"^(?:python|pypy)(?:\d+(?:\.\d+)?)?$|^py$")
_PY_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_PY_SPEC_RE = re.compile(
    rf"^(?P<name>{_PY_NAME})\s*(?:\[(?P<extras>[^\]]*)\])?\s*"
    r"(?P<rest>(?:(?:===|==|~=|>=|<=|!=|>|<)[^;]*)?)\s*(?:;.*)?$",
    re.DOTALL,
)
_PY_DIRECT_RE = re.compile(
    rf"^(?P<name>{_PY_NAME})\s*(?:\[[^\]]*\])?\s*@\s*(?P<url>\S.*)$", re.DOTALL
)
_PY_EXACT_RE = re.compile(r"^\s*(?:===|==)\s*(?P<version>[0-9][A-Za-z0-9._+!-]*)\s*$")
_POETRY_VERSION_RE = re.compile(r"^v?[0-9][A-Za-z0-9._+-]*$")
_VCS_RE = re.compile(r"^(?:git|hg|svn|bzr)\+", re.IGNORECASE)
_URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_NPM_NAME_PART = r"[A-Za-z0-9._~-]+"
_NPM_NAME_RE = re.compile(rf"^(?:@{_NPM_NAME_PART}/)?{_NPM_NAME_PART}$")
_NPM_EXACT_RE = re.compile(
    r"^[=v]?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)
_NPM_ALIAS_RE = re.compile(r"^(?P<alias>(?:@[^/@\s]+/)?[^@\s]+)@npm:(?P<real>.+)$")
_NPM_GIT_SCHEMES = ("git+", "git://", "git@", "ssh://", "github:", "gitlab:",
                    "bitbucket:", "gist:")  # fmt: skip
_NPM_LOCAL_SCHEMES = ("file:", "link:", "workspace:", "portal:", "patch:", "catalog:")
_GITHUB_SHORTHAND_RE = re.compile(r"^[^@%/\s.:-][^:@%/\s]*/[^@\s/%:]+(?:#.*)?$")
_GO_PART_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_HEX_REF_RE = re.compile(r"^[0-9a-f]{6,40}$")


@dataclass(frozen=True)
class InstallTarget:
    ecosystem: str
    kind: str
    tool: str
    spec: str
    name: str = ""
    version: str = ""
    source: str = ""  # direct/dynamic/local: what it is, for messages
    registries: tuple[str, ...] = ()  # command-line registry/index overrides
    runs: bool = False  # a one-shot runner executes it right away
    bin: str = ""  # runner command to look for in node_modules/.bin
    cwd: str = ""


def install_targets(
    command: str, cwd: Path, *, root: Path | None = None
) -> list[InstallTarget]:
    """Packages ``command`` would install or run, run from ``cwd``.

    ``root`` is the project root: local archives outside it count as direct
    sources, and ``node_modules/.bin`` is searched from ``cwd`` up to it.
    """
    commands = simple_commands(command, cwd)
    downloads = any(simple.program.lower() in _DOWNLOADERS for simple in commands)
    targets: list[InstallTarget] = []
    for simple in commands:
        if simple.more_args:
            # xargs appends words read from stdin: an unknown operand.
            simple = replace(
                simple,
                args=[*simple.args, "$XARGS"],
                dynamic=simple.dynamic | {len(simple.args)},
            )
        for target in _command_targets(simple):
            targets.append(_resolve_local(target, simple, root, downloads))
            if len(targets) >= MAX_TARGETS:
                return targets
    return targets


OUTCOME_DYNAMIC = "dynamic"


def split_targets(
    targets: list[InstallTarget],
) -> tuple[list[InstallTarget], dict]:
    """Registry targets (which need a lookup), and the result skeleton with
    every other target already sorted: ``direct`` sources, ``unverified``
    run-time names, and ``local`` / ``manifest`` counts. Needs no network
    and no heavy imports, so the hook can answer most commands here."""
    result: dict = {
        "packages": [],
        "findings": [],
        "unverified": [],
        "direct": [],
        "local": 0,
        "manifest": 0,
    }
    registry: list[InstallTarget] = []
    for target in targets:
        if target.kind == REGISTRY:
            registry.append(target)
        elif target.kind == DIRECT:
            result["direct"].append(
                {**_target_entry(target), "source": target.source or "direct source"}
            )
        elif target.kind == DYNAMIC:
            result["unverified"].append(
                {
                    **_target_entry(target),
                    "reason": target.source or "unknown",
                    "outcome": OUTCOME_DYNAMIC,
                }
            )
        elif target.kind == LOCAL:
            result["local"] += 1
        elif target.kind == MANIFEST:
            result["manifest"] += 1
    return registry, result


def _target_entry(target: InstallTarget) -> dict:
    return {
        "ecosystem": target.ecosystem,
        "name": target.name,
        "spec": target.spec,
        "tool": target.tool,
        "runs": target.runs,
    }


def looks_like_install(command: str) -> bool:
    return bool(command) and bool(INSTALL_HINT_RE.search(command))


# --------------------------------------------------------------------------
# argv scanning
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Arg:
    index: int  # into SimpleCommand.args
    flag: str  # "" for an operand
    value: str | None  # flag value (None: boolean flag) or the operand
    value_index: int = -1  # where the value came from (-1: attached / none)


def _scan(
    args: list[str],
    start: int,
    value_flags: frozenset[str],
    *,
    stop_at_operand: bool = False,
    clusters: bool = True,
    bool_words: bool = False,
    optional_value: frozenset[str] = frozenset(),
) -> Iterator[_Arg]:
    """Flags and operands of ``args[start:]``.

    ``value_flags`` lists the flags that take a value (``--flag value``,
    ``--flag=value``, ``-f value``, ``-fvalue``). With ``clusters``, short
    flags combine (``-qU``, ``-Ur file``). ``bool_words`` lets a boolean
    flag consume a following ``true``/``false`` (npm's option parser).
    ``stop_at_operand`` ends the scan after the first operand (runners: the
    rest belongs to the program they run). ``--`` ends option parsing; the
    words after it are operands.
    """
    index = start
    only_operands = False
    while index < len(args):
        arg = args[index]
        if only_operands or arg == "-" or not arg.startswith("-"):
            yield _Arg(index, "", arg)
            if stop_at_operand:
                return
            index += 1
            continue
        if arg == "--":
            only_operands = True
            index += 1
            continue
        if arg.startswith("--") or not clusters or len(arg) == 2:
            name, has_value, attached = arg.partition("=")
            if has_value:
                yield _Arg(index, name, attached)
                index += 1
                continue
            if name in value_flags:
                if index + 1 < len(args):
                    yield _Arg(index, name, args[index + 1], index + 1)
                index += 2
                continue
            if name in optional_value:
                yield _Arg(index, name, None)
                index += 1
                continue
            yield _Arg(index, name, None)
            index += 1
            if bool_words and index < len(args) and args[index] in {"true", "false"}:
                index += 1
            continue
        # Short-flag cluster: "-qU", "-Ur file", "-rreqs.txt".
        letters = arg[1:]
        consumed = False
        for position, letter in enumerate(letters):
            flag = "-" + letter
            if flag in value_flags:
                rest = letters[position + 1 :]
                if rest:
                    yield _Arg(index, flag, rest.lstrip("="))
                elif index + 1 < len(args):
                    yield _Arg(index, flag, args[index + 1], index + 1)
                    consumed = True
                break
            yield _Arg(index, flag, None)
        index += 2 if consumed else 1


def _values(scanned: Iterable[_Arg], *names: str) -> list[_Arg]:
    wanted = set(names)
    return [arg for arg in scanned if arg.flag in wanted and arg.value is not None]


def _has_flag(scanned: Iterable[_Arg], *names: str) -> bool:
    wanted = set(names)
    return any(arg.flag in wanted for arg in scanned)


def _operands(scanned: Iterable[_Arg]) -> list[_Arg]:
    return [arg for arg in scanned if not arg.flag]


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------


def _command_targets(simple: SimpleCommand) -> list[InstallTarget]:
    program = simple.program.lower()
    program = program.removesuffix(".exe")
    program = program.removesuffix(".cmd")
    if _PIP_RE.match(program):
        return _pip_tool(simple, 0, "pip")
    if _PYTHON_RE.match(program):
        return _python_module(simple)
    handler = _TOOLS.get(program)
    return handler(simple) if handler is not None else []


def _python_module(simple: SimpleCommand) -> list[InstallTarget]:
    """``python -m pip install ...`` (also ``-m pipx`` and ``-m uv``)."""
    args = simple.args
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-m" and index + 1 < len(args):
            module = args[index + 1].lower()
            rest_start = index + 2
            if module == "pip":
                return _pip_tool(simple, rest_start, "python -m pip")
            if module == "pipx":
                return _pipx(simple, rest_start)
            if module == "uv":
                return _uv(simple, rest_start)
            return []
        if arg.startswith("-m") and len(arg) > 2:
            return []  # -mmodule: not one we follow
        if arg in {"-X", "-W", "--check-hash-based-pycs"}:
            index += 2
            continue
        if arg == "-c" or not arg.startswith("-"):
            return []  # inline code or a script
        index += 1
    return []


# -- Python -----------------------------------------------------------------

_PIP_GENERAL_VALUE = frozenset(
    {"--python", "--log", "--log-file", "--proxy", "--retries", "--timeout",
     "--exists-action", "--trusted-host", "--cert", "--client-cert",
     "--cache-dir", "--use-feature", "--use-deprecated", "--keyring-provider",
     "--resume-retries", "--local-log"}
)  # fmt: skip
_PIP_INSTALL_VALUE = _PIP_GENERAL_VALUE | frozenset(
    {"-r", "--requirement", "-c", "--constraint", "--build-constraint",
     "--requirements-from-script", "-e", "--editable", "-t", "--target",
     "--platform", "--python-version", "--implementation", "--abi", "--root",
     "--prefix", "--src", "--upgrade-strategy", "-C", "--config-settings",
     "--progress-bar", "--root-user-action", "--report", "--group",
     "--all-releases", "--only-final", "--no-binary", "--only-binary",
     "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
     "--uploaded-prior-to", "--global-option", "--install-option",
     "--build-option", "--index-strategy"}
)  # fmt: skip
_PIP_INDEX_FLAGS = frozenset({"-i", "--index-url", "--extra-index-url"})
_PIP_ENV_INDEXES = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS")
_UV_ENV_INDEXES = (
    "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX",
    "UV_FIND_LINKS",
)  # fmt: skip


def _pip_tool(simple: SimpleCommand, start: int, tool: str) -> list[InstallTarget]:
    args = simple.args
    scanned = list(_scan(args, start, _PIP_GENERAL_VALUE, stop_at_operand=True))
    operands = _operands(scanned)
    if not operands or operands[0].value.lower() != "install":
        return []
    return _pip_install(simple, operands[0].index + 1, f"{tool} install")


def _pip_install(
    simple: SimpleCommand,
    start: int,
    tool: str,
    *,
    value_flags: frozenset[str] = _PIP_INSTALL_VALUE,
    env_indexes: tuple[str, ...] = _PIP_ENV_INDEXES,
    index_flags: frozenset[str] = _PIP_INDEX_FLAGS,
    editable_flags: tuple[str, ...] = ("-e", "--editable"),
    requirement_flags: tuple[str, ...] = ("-r", "--requirement"),
    style: str = "pip",
) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, value_flags))
    registries = _python_registries(simple, scanned, index_flags, env_indexes)
    no_index = _has_flag(scanned, "--no-index") or bool(simple.env.get("PIP_NO_INDEX"))
    targets: list[InstallTarget] = []
    for arg in _values(scanned, *requirement_flags):
        targets.append(_requirements_target(simple, arg, tool))
    for arg in _values(scanned, *editable_flags):
        targets.append(
            _python_target(simple, arg, tool, registries, style=style, editable=True)
        )
    for arg in _operands(scanned):
        targets.append(_python_target(simple, arg, tool, registries, style=style))
    if no_index:
        targets = [_as_local(t, "--no-index: local files only") for t in targets]
    return targets


def _python_registries(
    simple: SimpleCommand,
    scanned: list[_Arg],
    index_flags: frozenset[str],
    env_indexes: tuple[str, ...],
) -> tuple[str, ...]:
    found: list[str] = []
    for arg in scanned:
        if arg.flag in index_flags and arg.value is not None:
            found.append(_dyn_value(simple, arg))
        elif arg.flag in {"-f", "--find-links"} and arg.value is not None:
            value = _dyn_value(simple, arg)
            if _URL_RE.match(value) or value.startswith("$"):
                found.append(value)
        elif arg.flag in {"--index", "--default-index"} and arg.value is not None:
            # uv: "--index name=url" or a URL.
            value = _dyn_value(simple, arg)
            found.append(value.split("=", 1)[1] if "=" in value else value)
        elif arg.flag == "--pip-args" and arg.value is not None:
            found.extend(_registries_in_pip_args(arg.value))
    for name in env_indexes:
        value = simple.env.get(name, "")
        if value:
            if name.endswith("FIND_LINKS") and not _URL_RE.match(value):
                continue
            found.extend(value.split())
    return tuple(r for r in found if not _is_public_registry(r, PYPI))


def _registries_in_pip_args(value: str) -> list[str]:
    words = value.split()
    found = []
    for index, word in enumerate(words):
        name, has_value, attached = word.partition("=")
        if name in {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}:
            if has_value:
                found.append(attached)
            elif index + 1 < len(words):
                found.append(words[index + 1])
    return found


def _requirements_target(simple: SimpleCommand, arg: _Arg, tool: str) -> InstallTarget:
    value = arg.value or ""
    if _is_dynamic_arg(simple, arg):
        return InstallTarget(
            PYPI, DYNAMIC, tool, value, source="requirements file named at run time"
        )
    if _URL_RE.match(value):
        return InstallTarget(
            PYPI,
            DIRECT,
            tool,
            value,
            source=f"requirements file downloaded from {value}",
        )
    return InstallTarget(PYPI, MANIFEST, tool, value, source="requirements file")


def _python_target(
    simple: SimpleCommand,
    arg: _Arg,
    tool: str,
    registries: tuple[str, ...],
    *,
    style: str = "pip",
    editable: bool = False,
    runs: bool = False,
) -> InstallTarget:
    spec = arg.value or ""
    if _is_dynamic_arg(simple, arg):
        return InstallTarget(
            PYPI, DYNAMIC, tool, spec, source="package named at run time", runs=runs
        )
    return _classify_python(
        spec,
        tool,
        registries,
        style=style,
        editable=editable,
        runs=runs,
        cwd=simple.cwd,
    )


def _classify_python(
    spec: str,
    tool: str,
    registries: tuple[str, ...],
    *,
    style: str = "pip",
    editable: bool = False,
    runs: bool = False,
    cwd: Path | None = None,
) -> InstallTarget:
    raw = spec.strip()
    base = InstallTarget(PYPI, DIRECT, tool, raw, registries=registries, runs=runs,
                         cwd=str(cwd or ""))  # fmt: skip
    if not raw:
        return replace(base, kind=DYNAMIC, source="empty package name")
    if len(raw) > MAX_SPEC_CHARS:
        return replace(base, kind=DYNAMIC, source="could not read the package name")
    direct = _PY_DIRECT_RE.match(raw)
    if direct and not _looks_like_version(direct.group("url")):
        url = direct.group("url").strip()
        return _python_location(base, url, name=direct.group("name"))
    if _VCS_RE.match(raw) or _URL_RE.match(raw) or raw.lower().startswith("file:"):
        return _python_location(base, raw)
    if (
        _looks_like_path(raw)
        or "/" in raw
        or "\\" in raw
        or raw.lower().endswith(ARCHIVE_SUFFIXES)
    ):
        return _python_location(base, raw)
    name, version = _python_name_version(raw, style)
    if name is None:
        if editable:
            return replace(base, kind=LOCAL, source="editable install")
        return replace(base, kind=DYNAMIC, source="could not read the package name")
    if editable:
        # "pip install -e name" is not valid pip; treat as a local path.
        return replace(base, kind=LOCAL, source="editable install")
    return replace(base, kind=REGISTRY, name=name, version=version, source="")


def _python_name_version(raw: str, style: str) -> tuple[str | None, str]:
    text = raw
    if "@" in text:
        name_part, _, version_part = text.partition("@")
        name_part = name_part.strip()
        version_part = version_part.strip()
        match = _PY_SPEC_RE.match(name_part)
        if not match or match.group("rest"):
            return None, ""
        if version_part.lower() == "latest" or not version_part:
            return match.group("name"), ""
        if _POETRY_VERSION_RE.match(version_part):
            return match.group("name"), version_part.lstrip("v")
        return match.group("name"), ""  # ^1.2, ~1.2, >=1: existence only
    match = _PY_SPEC_RE.match(text)
    if not match:
        return None, ""
    exact = _PY_EXACT_RE.match(match.group("rest") or "")
    version = ""
    if exact and "*" not in exact.group("version"):
        # PyPI rejects local version labels ("1.11.0+cu113"); those builds
        # come from another index, so only the public version is checkable.
        version = exact.group("version").split("+", 1)[0]
    return match.group("name"), version


def _python_location(
    base: InstallTarget, location: str, *, name: str = ""
) -> InstallTarget:
    lowered = location.lower()
    if lowered.startswith("file:"):
        return replace(base, kind=LOCAL, source="local file", name=name)
    if _VCS_RE.match(location):
        vcs = location.split("+", 1)[0].lower()
        label = {"git": "git", "hg": "Mercurial", "svn": "Subversion",
                 "bzr": "Bazaar"}.get(vcs, vcs)  # fmt: skip
        return replace(
            base,
            source=f"{label} repository {_strip_url(location.split('+', 1)[1])}",
            name=name,
        )
    if _URL_RE.match(location):
        return replace(base, source=f"URL {_strip_url(location)}", name=name)
    return replace(base, kind=LOCAL, source="local path", name=name)


def _looks_like_version(value: str) -> bool:
    return (
        bool(_POETRY_VERSION_RE.match(value.strip()))
        or value.strip() in {"latest"}
        or value.strip().startswith(("^", "~", ">", "<", "=", "!"))
    )


# -- uv -------------------------------------------------------------------

_UV_GLOBAL_VALUE = frozenset(
    {"--directory", "--project", "--config-file", "--cache-dir", "--color",
     "--python", "-p", "--python-preference", "--allow-insecure-host",
     "--trusted-host"}
)  # fmt: skip
_UV_RESOLVER_VALUE = frozenset(
    {"--index", "--default-index", "-i", "--index-url", "--extra-index-url",
     "-f", "--find-links", "--index-strategy", "--keyring-provider",
     "--resolution", "--prerelease", "--exclude-newer", "--exclude-newer-package",
     "--link-mode", "-C", "--config-setting", "--config-settings-package",
     "--no-build-package", "--no-binary-package", "--refresh-package",
     "--reinstall-package", "-P", "--upgrade-package", "--fork-strategy",
     "--python-platform", "--no-build-isolation-package", "--torch-backend",
     "--build-constraints", "-b", "--overrides", "--excludes"}
)  # fmt: skip
_UV_PIP_INSTALL_VALUE = _UV_GLOBAL_VALUE | _UV_RESOLVER_VALUE | frozenset(
    {"-r", "--requirements", "--requirement", "-e", "--editable", "-c",
     "--constraints", "--constraint", "--extra", "--group", "--target",
     "--prefix", "--python-version", "-t"}
)  # fmt: skip
_UV_ADD_VALUE = _UV_GLOBAL_VALUE | _UV_RESOLVER_VALUE | frozenset(
    {"-r", "--requirements", "-c", "--constraints", "-m", "--marker",
     "--optional", "--group", "--extra", "--package", "--script", "--tag",
     "--branch", "--rev", "--bounds", "--lfs"}
)  # fmt: skip
_UV_TOOL_VALUE = _UV_GLOBAL_VALUE | _UV_RESOLVER_VALUE | frozenset(
    {"--from", "--with", "-w", "--with-editable", "--with-requirements",
     "--with-executables-from", "-c", "--constraints", "--env-file"}
)  # fmt: skip
_UV_RUN_VALUE = _UV_GLOBAL_VALUE | _UV_RESOLVER_VALUE | frozenset(
    {"--with", "-w", "--with-editable", "--with-requirements", "--extra",
     "--group", "--only-group", "--no-group", "--package", "--env-file",
     "--script", "--module", "-m"}
)  # fmt: skip
_UV_INDEX_FLAGS = frozenset({"-i", "--index-url", "--extra-index-url"})


def _uv(simple: SimpleCommand, start: int = 0) -> list[InstallTarget]:
    args = simple.args
    scanned = list(_scan(args, start, _UV_GLOBAL_VALUE, stop_at_operand=True))
    operands = _operands(scanned)
    if not operands:
        return []
    sub = operands[0].value.lower()
    rest = operands[0].index + 1
    if sub == "pip":
        tail = list(_scan(args, rest, _UV_GLOBAL_VALUE, stop_at_operand=True))
        tail_ops = _operands(tail)
        if tail_ops and tail_ops[0].value.lower() == "install":
            return _pip_install(
                simple,
                tail_ops[0].index + 1,
                "uv pip install",
                value_flags=_UV_PIP_INSTALL_VALUE,
                env_indexes=_UV_ENV_INDEXES + _PIP_ENV_INDEXES,
                index_flags=_UV_INDEX_FLAGS,
                requirement_flags=("-r", "--requirements", "--requirement"),
            )
        return []
    if sub == "add":
        return _pip_install(
            simple,
            rest,
            "uv add",
            value_flags=_UV_ADD_VALUE,
            env_indexes=_UV_ENV_INDEXES,
            index_flags=_UV_INDEX_FLAGS,
            editable_flags=(),
            requirement_flags=("-r", "--requirements"),
        )
    if sub == "tool":
        tail = list(_scan(args, rest, _UV_GLOBAL_VALUE, stop_at_operand=True))
        tail_ops = _operands(tail)
        if not tail_ops:
            return []
        action = tail_ops[0].value.lower()
        if action == "run":
            return _uv_tool_run(simple, tail_ops[0].index + 1, "uv tool run")
        if action == "install":
            return _uv_tool_install(simple, tail_ops[0].index + 1)
        return []
    if sub == "run":
        return _uv_run(simple, rest)
    return []


def _uv_with_targets(
    simple: SimpleCommand, scanned: list[_Arg], tool: str, registries: tuple[str, ...]
) -> list[InstallTarget]:
    targets: list[InstallTarget] = []
    for arg in _values(scanned, "--with", "-w"):
        for part in _split_with(arg.value or ""):
            targets.append(
                _python_target(
                    simple, replace(arg, value=part), tool, registries, runs=True
                )
            )
    for arg in _values(scanned, "--with-editable"):
        targets.append(
            _python_target(simple, arg, tool, registries, editable=True, runs=True)
        )
    for arg in _values(scanned, "--with-requirements"):
        targets.append(_requirements_target(simple, arg, tool))
    return targets


def _uv_tool_run(simple: SimpleCommand, start: int, tool: str) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, _UV_TOOL_VALUE, stop_at_operand=True))
    registries = _python_registries(simple, scanned, _UV_INDEX_FLAGS, _UV_ENV_INDEXES)
    targets = _uv_with_targets(simple, scanned, tool, registries)
    sources = _values(scanned, "--from")
    if sources:
        for arg in sources:
            targets.append(
                _python_target(simple, arg, tool, registries, style="uvx", runs=True)
            )
    else:
        operands = _operands(scanned)
        if operands:
            targets.append(
                _python_target(
                    simple, operands[0], tool, registries, style="uvx", runs=True
                )
            )
    if _has_flag(scanned, "--offline", "--no-index"):
        targets = [_as_local(t, "--offline: cached packages only") for t in targets]
    return targets


def _uv_tool_install(simple: SimpleCommand, start: int) -> list[InstallTarget]:
    tool = "uv tool install"
    scanned = list(_scan(simple.args, start, _UV_TOOL_VALUE))
    registries = _python_registries(simple, scanned, _UV_INDEX_FLAGS, _UV_ENV_INDEXES)
    targets = _uv_with_targets(simple, scanned, tool, registries)
    for arg in _values(scanned, "--from"):
        targets.append(_python_target(simple, arg, tool, registries, style="uvx"))
    operands = _operands(scanned)
    if operands and not _values(scanned, "--from"):
        targets.append(
            _python_target(simple, operands[0], tool, registries, style="uvx")
        )
    if _has_flag(scanned, "--editable", "-e"):
        targets = [_as_local(t, "editable install") if t.kind == REGISTRY else t
                   for t in targets]  # fmt: skip
    return targets


def _uv_run(simple: SimpleCommand, start: int) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, _UV_RUN_VALUE, stop_at_operand=True))
    registries = _python_registries(simple, scanned, _UV_INDEX_FLAGS, _UV_ENV_INDEXES)
    targets = _uv_with_targets(simple, scanned, "uv run --with", registries)
    if _has_flag(scanned, "--offline", "--no-index"):
        targets = [_as_local(t, "--offline: cached packages only") for t in targets]
    return targets


def _uvx(simple: SimpleCommand) -> list[InstallTarget]:
    return _uv_tool_run(simple, 0, "uvx")


def _split_with(value: str) -> list[str]:
    """``--with 'a,b>=1,<2,c[x,y]'`` → ["a", "b>=1,<2", "c[x,y]"]: a comma
    starts a new requirement unless it sits inside extras brackets or the
    next part is a version clause."""
    pieces: list[str] = []
    depth = 0
    current = ""
    for char in value:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            pieces.append(current)
            current = ""
            continue
        current += char
    pieces.append(current)
    parts: list[str] = []
    for piece in pieces:
        stripped = piece.strip()
        if parts and (not stripped or stripped[0] in "<>=!~"):
            parts[-1] = f"{parts[-1]},{piece}"
        else:
            parts.append(stripped)
    return [part for part in parts if part]


# -- poetry / pdm / pipenv / pipx --------------------------------------------

_POETRY_VALUE = frozenset(
    {"-G", "--group", "-E", "--extras", "--source", "--python", "--platform",
     "--markers", "-C", "--directory", "-P", "--project"}
)  # fmt: skip
_PDM_VALUE = frozenset(
    {"-G", "--group", "-p", "--project", "-L", "--lockfile", "--venv",
     "-e", "--editable", "-S", "--strategy", "--update-strategy"}
)  # fmt: skip
_PIPENV_VALUE = frozenset(
    {"-e", "--editable", "-r", "--requirements", "--index", "-i",
     "--pypi-mirror", "--python", "--categories", "--extra-pip-args"}
)  # fmt: skip
_PIPX_INSTALL_VALUE = frozenset(
    {"-i", "--index-url", "--pip-args", "--suffix", "--python",
     "--preinstall", "--backend", "--spec"}
)  # fmt: skip
_PIPX_RUN_VALUE = frozenset(
    {"--spec", "-i", "--index-url", "--pip-args", "--python", "--backend"}
)  # fmt: skip


def _subcommand(
    simple: SimpleCommand, value_flags: frozenset[str], start: int = 0
) -> tuple[str, int]:
    scanned = list(_scan(simple.args, start, value_flags, stop_at_operand=True))
    operands = _operands(scanned)
    if not operands:
        return "", len(simple.args)
    return operands[0].value.lower(), operands[0].index + 1


def _poetry(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset({"-C", "--directory", "-P", "--project"}))
    if sub != "add":
        return []
    scanned = list(_scan(simple.args, rest, _POETRY_VALUE))
    configured = bool(_values(scanned, "--source"))
    targets = [
        _python_target(simple, arg, "poetry add", (), style="poetry")
        for arg in _operands(scanned)
    ]
    if configured:
        # A named source from pyproject.toml: the project's own index.
        targets = [replace(t, registries=("configured:the poetry source named by --source",))
                   if t.kind == REGISTRY
                   else t for t in targets]  # fmt: skip
    return targets


def _pdm(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset({"-p", "--project"}))
    if sub != "add":
        return []
    scanned = list(_scan(simple.args, rest, _PDM_VALUE))
    targets = [
        _python_target(simple, arg, "pdm add", (), editable=True)
        for arg in _values(scanned, "-e", "--editable")
    ]
    targets += [
        _python_target(simple, arg, "pdm add", (), style="poetry")
        for arg in _operands(scanned)
    ]
    return targets


def _pipenv(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset({"--python"}))
    if sub != "install":
        return []
    return _pip_install(
        simple,
        rest,
        "pipenv install",
        value_flags=_PIPENV_VALUE,
        index_flags=frozenset({"--index", "-i", "--pypi-mirror"}),
        requirement_flags=("-r", "--requirements"),
    )


def _pipx(simple: SimpleCommand, start: int = 0) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset(), start)
    if sub == "install":
        scanned = list(_scan(simple.args, rest, _PIPX_INSTALL_VALUE))
        registries = _python_registries(
            simple, scanned, _PIP_INDEX_FLAGS, _PIP_ENV_INDEXES
        )
        targets = [
            _python_target(simple, arg, "pipx install", registries)
            for arg in _values(scanned, "--preinstall", "--spec")
        ]
        targets += [
            _python_target(simple, arg, "pipx install", registries)
            for arg in _operands(scanned)
        ]
        if _has_flag(scanned, "-e", "--editable"):
            targets = [_as_local(t, "editable install") if t.kind == REGISTRY else t
                       for t in targets]  # fmt: skip
        return targets
    if sub == "run":
        scanned = list(_scan(simple.args, rest, _PIPX_RUN_VALUE, stop_at_operand=True))
        registries = _python_registries(
            simple, scanned, _PIP_INDEX_FLAGS, _PIP_ENV_INDEXES
        )
        specs = _values(scanned, "--spec")
        if specs:
            return [
                _python_target(simple, arg, "pipx run", registries, runs=True)
                for arg in specs
            ]
        operands = _operands(scanned)
        if not operands:
            return []
        return [_python_target(simple, operands[0], "pipx run", registries, runs=True)]
    if sub == "inject":
        scanned = list(_scan(simple.args, rest, _PIPX_INSTALL_VALUE))
        registries = _python_registries(
            simple, scanned, _PIP_INDEX_FLAGS, _PIP_ENV_INDEXES
        )
        operands = _operands(scanned)[1:]  # the first is the venv name
        return [
            _python_target(simple, arg, "pipx inject", registries) for arg in operands
        ]
    return []


# -- npm family -----------------------------------------------------------

_NPM_VALUE = frozenset(
    {"--prefix", "-C", "--registry", "--cache", "--userconfig",
     "--globalconfig", "--loglevel", "--workspace", "-w", "--tag", "--omit",
     "--include", "--install-strategy", "--save-prefix", "--before",
     "--fetch-retries", "--fetch-retry-factor", "--fetch-retry-mintimeout",
     "--fetch-retry-maxtimeout", "--fetch-timeout", "--os", "--cpu", "--libc",
     "--script-shell", "--otp", "--scope", "--auth-type", "--location",
     "--lockfile-version", "--node-options", "--https-proxy", "--proxy",
     "--cafile", "--ca", "--cert", "--key", "--maxsockets", "--editor",
     "--depth", "--init-module", "--init-author-name", "--init-author-email",
     "--init-author-url", "--init-license", "--init-version", "--min-release-age",
     "--allow-git", "--replace-registry-host", "--node-gyp", "--umask",
     "--color", "--access", "--provenance-file", "--sbom-format", "--diff",
     "--expect-result-count"}
)  # fmt: skip
_NPM_EXEC_VALUE = _NPM_VALUE | frozenset({"--package", "-p", "--call", "-c", "--shell"})
_NPM_INSTALL_ALIASES = frozenset(
    {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
     "isntal", "isntall", "add", "install-test", "it"}
)  # fmt: skip
_NPM_REGISTRY_ENV = (
    "NPM_CONFIG_REGISTRY", "YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY",
    "BUN_CONFIG_REGISTRY",
)  # fmt: skip


def _npm_registries(simple: SimpleCommand, scanned: list[_Arg]) -> tuple[str, ...]:
    found: list[str] = []
    for arg in scanned:
        if arg.value is None:
            continue
        if arg.flag == "--registry" or (
            arg.flag.startswith("--@") and arg.flag.endswith(":registry")
        ):
            found.append(_dyn_value(simple, arg))
    for name, value in simple.env.items():
        upper = name.upper()
        is_registry = upper in _NPM_REGISTRY_ENV or (
            upper.startswith("NPM_CONFIG_") and upper.endswith("REGISTRY")
        )
        if is_registry and value:
            found.append(value)
    return tuple(r for r in found if not _is_public_registry(r, NPM))


def _npm(simple: SimpleCommand) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, 0, _NPM_EXEC_VALUE, stop_at_operand=True,
                         bool_words=True))  # fmt: skip
    operands = _operands(scanned)
    if not operands:
        return []
    sub = operands[0].value.lower()
    rest = operands[0].index + 1
    if sub in _NPM_INSTALL_ALIASES:
        return _npm_install_args(simple, rest, f"npm {sub}", _NPM_VALUE)
    if sub in {"exec", "x"}:
        return _npx_args(simple, rest, "npm exec")
    if sub in {"init", "create", "innit"}:
        return _npm_create(simple, rest, f"npm {sub}", _NPM_VALUE, npm_style=True)
    return []


def _npm_install_args(
    simple: SimpleCommand, start: int, tool: str, value_flags: frozenset[str]
) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, value_flags, bool_words=True))
    registries = _npm_registries(simple, scanned)
    return [_npm_target(simple, arg, tool, registries) for arg in _operands(scanned)]


def _npx(simple: SimpleCommand) -> list[InstallTarget]:
    return _npx_args(simple, 0, "npx")


def _npx_args(simple: SimpleCommand, start: int, tool: str) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, _NPM_EXEC_VALUE, stop_at_operand=True,
                         bool_words=True))  # fmt: skip
    registries = _npm_registries(simple, scanned)
    packages = _values(scanned, "--package", "-p")
    no_install = _has_flag(scanned, "--no", "--no-install", "--offline")
    targets = [
        _npm_target(simple, arg, tool, registries, runs=True) for arg in packages
    ]
    if not packages and not _values(scanned, "--call", "-c"):
        operands = _operands(scanned)
        if operands:
            target = _npm_target(simple, operands[0], tool, registries, runs=True)
            if target.kind == REGISTRY and not target.version:
                target = replace(target, bin=_bin_name(target.name))
            targets.append(target)
    if no_install:
        targets = [_as_local(t, "--no: local packages only") for t in targets]
    return targets


def _npm_create(
    simple: SimpleCommand,
    start: int,
    tool: str,
    value_flags: frozenset[str],
    *,
    npm_style: bool = False,
) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, value_flags, stop_at_operand=True,
                         bool_words=True))  # fmt: skip
    registries = _npm_registries(simple, scanned)
    operands = _operands(scanned)
    if not operands:
        return []  # "npm init": writes package.json, fetches nothing
    arg = operands[0]
    if _is_dynamic_arg(simple, arg):
        return [_npm_target(simple, arg, tool, registries, runs=True)]
    initializer = arg.value or ""
    bare_scope = re.match(r"^(@[^/@\s]+)(?:@(.+))?$", initializer)
    if bare_scope:
        # "npm init @scope" runs @scope/create.
        version = bare_scope.group(2) or ""
        initializer = f"{bare_scope.group(1)}/__scope__" + (
            f"@{version}" if version else ""
        )
    target = _classify_npm(initializer, tool, registries, runs=True)
    if target.kind != REGISTRY:
        return [target]
    package = _create_package_name(target.name)
    spec = f"{package}@{target.version}" if target.version else package
    return [replace(target, name=package, spec=spec)]


def _create_package_name(name: str) -> str:
    """npm init <initializer> → the package npm exec runs."""
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        return (
            f"{scope}/create-{rest}"
            if rest and rest != "__scope__"
            else f"{scope}/create"
        )
    return f"create-{name}"


_PNPM_VALUE = frozenset(
    {"--filter", "-F", "--dir", "-C", "--reporter", "--loglevel", "--registry",
     "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir",
     "--network-concurrency", "--child-concurrency", "--package-import-method",
     "--node-linker", "--resolution-mode", "--save-catalog-name",
     "--allow-build", "--package", "--config", "--workspace-concurrency",
     "--test-pattern", "--changed-files-ignore-pattern", "--cpu", "--os",
     "--libc", "--filter-prod", "--use-node-version"}
)  # fmt: skip
_PNPM_GLOBAL_VALUE = _PNPM_VALUE - {"--package"}


def _pnpm(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, _PNPM_GLOBAL_VALUE)
    if sub in {"add", "install", "i"}:
        return _npm_install_args(simple, rest, f"pnpm {sub}", _PNPM_GLOBAL_VALUE)
    if sub == "dlx":
        return _dlx(simple, rest, "pnpm dlx", _PNPM_VALUE | {"-p"})
    if sub == "create":
        return _npm_create(simple, rest, "pnpm create", _PNPM_GLOBAL_VALUE)
    return []


def _pnpx(simple: SimpleCommand) -> list[InstallTarget]:
    return _dlx(simple, 0, "pnpx", _PNPM_VALUE | {"-p"})


def _dlx(
    simple: SimpleCommand, start: int, tool: str, value_flags: frozenset[str]
) -> list[InstallTarget]:
    """pnpm dlx / yarn dlx: always fetch from the registry, never local."""
    scanned = list(_scan(simple.args, start, value_flags, stop_at_operand=True,
                         bool_words=True))  # fmt: skip
    registries = _npm_registries(simple, scanned)
    packages = _values(scanned, "--package", "-p")
    targets = [
        _npm_target(simple, arg, tool, registries, runs=True) for arg in packages
    ]
    if not packages:
        operands = _operands(scanned)
        if operands:
            targets.append(
                _npm_target(simple, operands[0], tool, registries, runs=True)
            )
    return targets


_YARN_VALUE = frozenset(
    {"--cwd", "--modules-folder", "--cache-folder", "--network-timeout",
     "--mutex", "--registry", "--global-folder", "--link-folder",
     "--use-yarnrc", "--network-concurrency", "--otp", "--package", "-p"}
)  # fmt: skip
_YARN_GLOBAL_VALUE = _YARN_VALUE - {"--package", "-p"}


def _yarn(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, _YARN_GLOBAL_VALUE)
    if sub == "workspace":
        _workspace, rest = _subcommand(simple, _YARN_GLOBAL_VALUE, rest)
        sub, rest = _subcommand(simple, _YARN_GLOBAL_VALUE, rest)
    if sub == "global":
        sub, rest = _subcommand(simple, _YARN_GLOBAL_VALUE, rest)
        if sub != "add":
            return []
    if sub in {"add", "install"}:
        return _npm_install_args(simple, rest, f"yarn {sub}", _YARN_GLOBAL_VALUE)
    if sub == "dlx":
        return _dlx(simple, rest, "yarn dlx", _YARN_VALUE)
    if sub == "create":
        return _npm_create(simple, rest, "yarn create", _YARN_GLOBAL_VALUE)
    return []


_BUN_VALUE = frozenset(
    {"--cwd", "--config", "-c", "--registry", "--filter", "-F", "--backend",
     "--cache-dir", "--network-concurrency", "--concurrent-scripts", "--omit",
     "--linker", "--cpu", "--os", "--minimum-release-age", "--ca", "--cafile",
     "--package", "-p", "--save-text-lockfile"}
)  # fmt: skip
_BUN_GLOBAL_VALUE = _BUN_VALUE - {"--package", "-p"}


def _bun(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, _BUN_GLOBAL_VALUE)
    if sub in {"add", "a", "install", "i"}:
        return _npm_install_args(simple, rest, f"bun {sub}", _BUN_GLOBAL_VALUE)
    if sub == "x":
        return _bunx_args(simple, rest, "bun x")
    if sub == "create":
        return _bun_create(simple, rest)
    return []


def _bunx(simple: SimpleCommand) -> list[InstallTarget]:
    return _bunx_args(simple, 0, "bunx")


def _bunx_args(simple: SimpleCommand, start: int, tool: str) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, _BUN_VALUE, stop_at_operand=True))
    registries = _npm_registries(simple, scanned)
    packages = _values(scanned, "--package", "-p")
    targets = [
        _npm_target(simple, arg, tool, registries, runs=True) for arg in packages
    ]
    if not packages:
        operands = _operands(scanned)
        if operands:
            target = _npm_target(simple, operands[0], tool, registries, runs=True)
            if target.kind == REGISTRY and not target.version:
                target = replace(target, bin=_bin_name(target.name))
            targets.append(target)
    return targets


def _bun_create(simple: SimpleCommand, start: int) -> list[InstallTarget]:
    scanned = list(_scan(simple.args, start, _BUN_GLOBAL_VALUE, stop_at_operand=True))
    operands = _operands(scanned)
    if not operands:
        return []
    arg = operands[0]
    value = arg.value or ""
    if (
        not _is_dynamic_arg(simple, arg)
        and "/" in value
        and not value.startswith(("@", ".", "/", "~"))
    ):
        return [
            InstallTarget(
                NPM,
                DIRECT,
                "bun create",
                value,
                source=f"GitHub repository {value}",
                runs=True,
            )
        ]
    return _npm_create(simple, start, "bun create", _BUN_GLOBAL_VALUE)


def _npm_target(
    simple: SimpleCommand,
    arg: _Arg,
    tool: str,
    registries: tuple[str, ...],
    *,
    runs: bool = False,
) -> InstallTarget:
    spec = arg.value or ""
    if _is_dynamic_arg(simple, arg):
        return InstallTarget(NPM, DYNAMIC, tool, spec,
                             source="package named at run time", runs=runs)  # fmt: skip
    return replace(
        _classify_npm(spec, tool, registries, runs=runs), cwd=str(simple.cwd)
    )


def _classify_npm(
    spec: str, tool: str, registries: tuple[str, ...], *, runs: bool = False
) -> InstallTarget:
    raw = spec.strip()
    base = InstallTarget(NPM, DIRECT, tool, raw, registries=registries, runs=runs)
    if not raw:
        return replace(base, kind=DYNAMIC, source="empty package name")
    if len(raw) > MAX_SPEC_CHARS:
        return replace(base, kind=DYNAMIC, source="could not read the package name")
    alias = _NPM_ALIAS_RE.match(raw)
    if alias:
        real = _classify_npm(alias.group("real"), tool, registries, runs=runs)
        return replace(real, spec=raw)
    lowered = raw.lower()
    if lowered.startswith("jsr:"):
        return _classify_jsr(raw[4:], tool, runs=runs, spec=raw)
    if lowered.startswith(_NPM_GIT_SCHEMES):
        return replace(base, source=_git_source(raw))
    if _URL_RE.match(raw):
        return replace(base, source=f"tarball URL {_strip_url(raw)}")
    if lowered.startswith(_NPM_LOCAL_SCHEMES):
        return replace(base, kind=LOCAL, source="local package")
    if lowered.startswith("exec:"):
        return replace(base, source="package generated by a script (exec:)")
    if _looks_like_path(raw):
        return replace(base, kind=LOCAL, source="local path")
    name, version_spec = _split_npm_name(raw)
    if version_spec is None and lowered.endswith((".tgz", ".tar.gz", ".tar")):
        return replace(base, kind=LOCAL, source="local path")
    if version_spec is None and _GITHUB_SHORTHAND_RE.match(raw):
        return replace(base, source=_git_source(raw))
    if version_spec is not None:
        nested = version_spec.lower()
        if (
            nested.startswith(_NPM_GIT_SCHEMES)
            or _URL_RE.match(version_spec)
            or _GITHUB_SHORTHAND_RE.match(version_spec)
        ):
            source = (
                f"tarball URL {_strip_url(version_spec)}"
                if _URL_RE.match(version_spec)
                else _git_source(version_spec)
            )
            return replace(base, source=source, name=name)
        if nested.startswith(_NPM_LOCAL_SCHEMES) or _looks_like_path(version_spec):
            return replace(base, kind=LOCAL, source="local package", name=name)
        if nested.startswith("npm:"):
            real = _classify_npm(version_spec[4:], tool, registries, runs=runs)
            return replace(real, spec=raw)
        if nested.startswith("jsr:"):
            return _classify_jsr(version_spec[4:], tool, runs=runs, spec=raw)
    if not _NPM_NAME_RE.match(name) or name.startswith((".", "_")):
        return replace(base, kind=DYNAMIC, source="could not read the package name")
    version = ""
    if version_spec:
        exact = _NPM_EXACT_RE.match(version_spec.strip())
        if exact:
            version = exact.group("version")
    return replace(base, kind=REGISTRY, name=name, version=version, source="")


def _split_npm_name(raw: str) -> tuple[str, str | None]:
    split_at = raw.find("@", 1) if raw.startswith("@") else raw.find("@")
    if split_at <= 0:
        return raw, None
    return raw[:split_at], raw[split_at + 1 :]


def _classify_jsr(
    value: str, tool: str, *, runs: bool = False, spec: str = ""
) -> InstallTarget:
    raw = value.strip()
    base = InstallTarget(JSR, REGISTRY, tool, spec or raw, runs=runs)
    if not raw.startswith("@"):
        return replace(base, kind=DYNAMIC, source="could not read the JSR package")
    parts = raw.split("/")
    if len(parts) < 2:
        return replace(base, kind=DYNAMIC, source="could not read the JSR package")
    scope, rest = parts[0], parts[1]
    name, _, version = rest.partition("@")
    full = f"{scope}/{name}"
    if not _NPM_NAME_RE.match(full):
        return replace(base, kind=DYNAMIC, source="could not read the JSR package")
    exact = _NPM_EXACT_RE.match(version) if version else None
    return replace(base, name=full, version=exact.group("version") if exact else "")


def _git_source(spec: str) -> str:
    raw = spec.strip()
    lowered = raw.lower()
    repo, _, ref = raw.partition("#")
    labels = {"github:": "GitHub", "gitlab:": "GitLab", "bitbucket:": "Bitbucket",
              "gist:": "GitHub gist"}  # fmt: skip
    prefix = next((p for p in labels if lowered.startswith(p)), None)
    if prefix is not None:
        text = f"{labels[prefix]} repository {repo[len(prefix) :]}"
    elif _GITHUB_SHORTHAND_RE.match(raw):
        text = f"GitHub repository {repo}"
    else:
        text = f"git repository {_strip_url(repo)}"
    if ref:
        text += f" (ref {ref})"
        if _HEX_REF_RE.match(ref.lower()):
            text += "; a commit ref can name a commit in any fork of the repository"
    return text


# -- go -------------------------------------------------------------------

_GO_VALUE = frozenset(
    {"-C", "-o", "-p", "-tags", "-ldflags", "-gcflags", "-asmflags",
     "-gccgoflags", "-mod", "-modfile", "-pkgdir", "-overlay", "-pgo",
     "-toolexec", "-buildmode", "-compiler", "-installsuffix", "-coverpkg",
     "-covermode", "-exec", "-debug-actiongraph", "-debug-runtime-trace",
     "-debug-trace"}
)  # fmt: skip


def _go(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset({"-C"}))
    if sub not in {"get", "install", "run"}:
        return []
    value_flags = _GO_VALUE | {f"-{flag}" for flag in _GO_VALUE}
    scanned = list(
        _scan(
            simple.args, rest, value_flags, clusters=False, stop_at_operand=sub == "run"
        )
    )
    registries = _go_registries(simple)
    targets: list[InstallTarget] = []
    for arg in _operands(scanned):
        value = arg.value or ""
        tool = f"go {sub}"
        if sub == "run" and "@" not in value:
            continue  # a local package or file
        if _is_dynamic_arg(simple, arg):
            targets.append(InstallTarget(GO, DYNAMIC, tool, value,
                                         source="module named at run time"))  # fmt: skip
            continue
        if sub == "run" and "@" not in value:
            continue  # a local package or file
        target = _classify_go(value, tool, registries, runs=sub == "run")
        if target is not None:
            targets.append(target)
    return targets


def _go_registries(simple: SimpleCommand) -> tuple[str, ...]:
    found = []
    proxy = simple.env.get("GOPROXY", "")
    for entry in re.split(r"[,|]", proxy):
        entry = entry.strip()
        if (
            entry
            and entry not in {"direct", "off"}
            and not _is_public_registry(entry, GO)
        ):
            found.append(entry)
    if simple.env.get("GOSUMDB", "").strip() == "off":
        found.append("GOSUMDB=off (checksum database disabled)")
    if simple.env.get("GOINSECURE") or "-insecure" in simple.env.get("GOFLAGS", ""):
        found.append("GOINSECURE (insecure fetches allowed)")
    return tuple(found)


def _classify_go(
    value: str, tool: str, registries: tuple[str, ...], *, runs: bool
) -> InstallTarget | None:
    raw = value.strip()
    name, _, version = raw.partition("@")
    if not name or name.startswith((".", "/")) or name in {"std", "cmd", "all"}:
        return None
    if name.endswith("/...") or "..." in name:
        name = name.split("/...", 1)[0]
        if not name or name.startswith("."):
            return None
    parts = name.split("/")
    if len(parts) < 2 or "." not in parts[0]:
        return None  # standard library, "go"/"toolchain" pseudo-modules
    if not all(_GO_PART_RE.match(part) for part in parts):
        return InstallTarget(
            GO, DYNAMIC, tool, raw, source="could not read the module path"
        )
    del version  # existence of the module path is what the proxy check answers
    return InstallTarget(GO, REGISTRY, tool, raw, name=name, registries=registries,
                         runs=runs)  # fmt: skip


# -- deno -----------------------------------------------------------------

_DENO_VALUE = frozenset(
    {"--config", "-c", "--import-map", "--lock", "--cert", "--location",
     "--seed", "--name", "-n", "--root", "--ext", "--log-level", "-L",
     "--preload", "--require", "--entrypoint", "--inspect-wait"}
)  # fmt: skip


def _deno(simple: SimpleCommand) -> list[InstallTarget]:
    sub, rest = _subcommand(simple, frozenset({"--config", "-c"}))
    if sub not in {"run", "x", "install", "i", "add", "cache"}:
        return []
    single = sub in {"run", "x"}
    scanned = list(_scan(simple.args, rest, _DENO_VALUE, stop_at_operand=single))
    operands = _operands(scanned)
    if sub in {"install", "i"} and _has_flag(scanned, "-g", "--global"):
        operands = operands[:1]
    targets = []
    for arg in operands:
        value = arg.value or ""
        tool = f"deno {sub}"
        if _is_dynamic_arg(simple, arg):
            targets.append(InstallTarget(NPM, DYNAMIC, tool, value,
                                         source="module named at run time"))  # fmt: skip
            continue
        lowered = value.lower()
        if lowered.startswith("npm:"):
            target = _classify_npm(_strip_subpath(value[4:]), tool, (), runs=single)
            targets.append(replace(target, spec=value))
        elif lowered.startswith("jsr:"):
            targets.append(_classify_jsr(value[4:], tool, runs=single, spec=value))
        elif _URL_RE.match(value):
            targets.append(InstallTarget(NPM, DIRECT, tool, value,
                                         source=f"remote module {_strip_url(value)}",
                                         runs=single))  # fmt: skip
        elif sub == "add" and value.startswith("@"):
            targets.append(_classify_jsr(value, tool, spec=value))
    return targets


def _strip_subpath(spec: str) -> str:
    """npm:pkg@1/sub/path → pkg@1; npm:@s/p/sub → @s/p."""
    parts = spec.split("/")
    keep = 2 if spec.startswith("@") else 1
    return "/".join(parts[:keep])


_TOOLS = {
    "npm": _npm,
    "npx": _npx,
    "pnpm": _pnpm,
    "pnpx": _pnpx,
    "yarn": _yarn,
    "yarnpkg": _yarn,
    "bun": _bun,
    "bunx": _bunx,
    "uv": _uv,
    "uvx": _uvx,
    "poetry": _poetry,
    "pdm": _pdm,
    "pipenv": _pipenv,
    "pipx": _pipx,
    "go": _go,
    "deno": _deno,
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _is_dynamic_arg(simple: SimpleCommand, arg: _Arg) -> bool:
    if arg.value_index >= 0:
        return simple.is_dynamic(arg.value_index)
    return simple.is_dynamic(arg.index)


def _dyn_value(simple: SimpleCommand, arg: _Arg) -> str:
    value = arg.value or ""
    return value if not _is_dynamic_arg(simple, arg) else (value or "$?")


def _is_public_registry(value: str, ecosystem: str) -> bool:
    host = registry_host(value)
    return bool(host) and host in PUBLIC_REGISTRY_HOSTS.get(ecosystem, frozenset())


def registry_host(value: str) -> str:
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        from urllib.parse import urlsplit

        return (urlsplit(raw).hostname or "").lower()
    except ValueError:
        return ""


def _looks_like_path(value: str) -> bool:
    return value.startswith((".", "/", "~", "\\")) or bool(
        _WINDOWS_PATH_RE.match(value)
    )


def _strip_url(value: str) -> str:
    """Drop credentials from a URL before it goes in a message."""
    return re.sub(r"(?<=://)[^/@\s]*@", "", value)


def _bin_name(name: str) -> str:
    return name.rsplit("/", 1)[-1]


def _as_local(target: InstallTarget, source: str) -> InstallTarget:
    if target.kind != REGISTRY:
        return target
    return replace(target, kind=LOCAL, source=source)


def _resolve_local(
    target: InstallTarget, simple: SimpleCommand, root: Path | None, downloads: bool
) -> InstallTarget:
    """Local archives outside the project, or fetched by the same command,
    are direct sources; runner binaries already installed are local."""
    if target.kind == LOCAL:
        location = _local_location(target.spec)
        if location.lower().endswith(ARCHIVE_SUFFIXES):
            if downloads:
                return replace(
                    target, kind=DIRECT,
                    source=f"archive {target.spec} downloaded by the same command",
                )  # fmt: skip
            path = Path(location).expanduser()
            if not path.is_absolute():
                path = simple.cwd / path
            if root is not None and not _inside(path, root):
                return replace(
                    target,
                    kind=DIRECT,
                    source=f"archive outside the project ({target.spec})",
                )
        return target
    if (
        target.kind == REGISTRY
        and target.bin
        and root is not None
        and _has_local_bin(target.bin, simple.cwd, root)
    ):
        return replace(target, kind=LOCAL, source="installed in node_modules/.bin")
    return target


def _local_location(spec: str) -> str:
    """The path in ``name @ file:...``, ``name@file:...`` or ``file:...``."""
    location = spec.strip()
    if " @ " in location:
        location = location.split(" @ ", 1)[1].strip()
    match = re.match(r"^(?:@[^/@]+/)?[^@/:]+@(?P<rest>(?:file|link):.*)$", location)
    if match:
        location = match.group("rest")
    location = re.sub(r"^(?:file|link):(?://)?", "", location, flags=re.IGNORECASE)
    return location


def _inside(path: Path, root: Path) -> bool:
    try:
        resolved = Path(os.path.normpath(str(path)))
        resolved.relative_to(Path(os.path.normpath(str(root))))
        return True
    except ValueError:
        return False


def _has_local_bin(name: str, cwd: Path, root: Path) -> bool:
    """Whether ``npx name`` runs something already on disk, in npm's order
    (libnpmexec): a ``bin`` of the project's own package.json, then
    ``node_modules/.bin`` in this directory or any parent, then the global
    bin directory."""
    if not name or "/" in name or name.startswith("."):
        return False
    start = Path(os.path.normpath(str(cwd)))
    stop = Path(os.path.normpath(str(root)))
    current = start
    for _ in range(64):
        if _inside(current, stop) and _package_json_has_bin(current, name):
            return True
        if _bin_file_exists(current / "node_modules" / ".bin", name):
            return True
        if current.parent == current:
            break
        current = current.parent
    return any(_bin_file_exists(directory, name) for directory in _global_bin_dirs())


def _package_json_has_bin(directory: Path, name: str) -> bool:
    manifest = directory / "package.json"
    try:
        if not manifest.is_file() or manifest.stat().st_size > 1_000_000:
            return False
        import json

        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    bins = data.get("bin")
    if isinstance(bins, dict):
        return name in bins
    if isinstance(bins, str):
        package = str(data.get("name", ""))
        return package.rsplit("/", 1)[-1] == name
    return False


def _bin_file_exists(directory: Path, name: str) -> bool:
    for candidate in (directory / name, directory / f"{name}.cmd"):
        try:
            if candidate.exists():
                return True
        except OSError:
            return False
    return False


def _global_bin_dirs() -> list[Path]:
    """npm's global bin directory: ``$npm_config_prefix/bin``, else the
    directory that holds ``node`` (nvm, Homebrew and the official installers
    put global bins next to node)."""
    import shutil

    found: list[Path] = []
    for key in ("npm_config_prefix", "NPM_CONFIG_PREFIX"):
        prefix = os.environ.get(key)
        if prefix:
            found.append(Path(prefix).expanduser() / ("" if os.name == "nt" else "bin"))
    node = shutil.which("node")
    if node:
        found.append(Path(node).parent)
    return found


__all__ = [
    "DIRECT",
    "DYNAMIC",
    "GO",
    "INSTALL_HINT_RE",
    "JSR",
    "LOCAL",
    "MANIFEST",
    "NPM",
    "OUTCOME_DYNAMIC",
    "PYPI",
    "REGISTRY",
    "InstallTarget",
    "install_targets",
    "looks_like_install",
    "registry_host",
    "split_targets",
]
