from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping, Sequence


_READ_ONLY_CONFIG_OVERRIDES = (
    "core.fsmonitor=false",
    f"core.hooksPath={os.devnull}",
    "core.untrackedCache=false",
    "core.pager=cat",
    "core.sshCommand=false",
    "credential.helper=",
    "protocol.allow=never",
    "diff.external=",
    "diff.trustExitCode=false",
    # ``log.showSignature`` makes ``log``/``show`` hand signed commits to the
    # repository's ``gpg.*.program``; ``%G?`` formats do so unconditionally.
    "log.showSignature=false",
    "gpg.program=",
    "gpg.openpgp.program=",
    "gpg.ssh.program=",
    "gpg.x509.program=",
)


def read_only_git_environment(
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an environment that cannot inject Git configuration or helpers."""

    source = os.environ if environ is None else environ
    environment = {
        key: value for key, value in source.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def read_only_git_command(
    args: Sequence[str],
    *,
    config_overrides: Sequence[str] = (),
    literal_pathspecs: bool = False,
) -> list[str]:
    """Build a Git command with repository-configured execution disabled."""

    command = ["git", "--no-pager", "--no-replace-objects", "--no-optional-locks"]
    if literal_pathspecs:
        command.append("--literal-pathspecs")
    for override in (*_READ_ONLY_CONFIG_OVERRIDES, *config_overrides):
        command.extend(("-c", override))
    command.extend(args)
    return command


# --------------------------------------------------------------------------
# Content-filter / diff-driver neutralization
#
# A clean/smudge/process filter or a diff driver command/textconv cannot be
# disabled by a generic ``-c``: Git selects them by *name* through the
# repository's own ``.gitattributes``. Neutralizing them therefore means
# enumerating every configured driver and setting each one empty. Any command
# that hashes or materializes worktree content (``status``, a worktree
# ``diff``, ``add``, ``stash``, ``checkout-index``) or renders a diff
# (``diff``/``log``/``show``/``blame`` run textconv) must carry these overrides
# in addition to the read-only defaults, or the repository's own commands run.
#
# Verified experimentally (see build-GIT-SAFETY.md): the full override set
# fires zero canaries for all of those commands on a hostile fixture, while
# ``--no-ext-diff`` alone leaves ``diff.<driver>.textconv`` live (and ``blame``
# runs textconv by default).
#
# Only plumbing in ``_CONTENT_FREE_SUBCOMMANDS`` may skip the neutralization:
# it never converts file content. Everything else is guarded by default.
# --------------------------------------------------------------------------

_FILTER_CONFIG_KEY_RE = re.compile(
    r"^filter\.(?P<driver>.+)\.(?:clean|smudge|process|required)$",
    re.IGNORECASE,
)
_DIFF_CONFIG_KEY_RE = re.compile(
    r"^diff\.(?P<driver>.+)\.(?:command|textconv|cachetextconv|trustExitCode)$",
    re.IGNORECASE,
)
_SAFE_FILTER_DRIVER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_MAX_FILTER_DRIVERS = 128
_MAX_FILTER_DRIVER_LENGTH = 128
_MAX_FILTER_CONFIG_OUTPUT = 128_000

_FILTER_CONFIG_REGEX = (
    r"^(filter\..*\.(clean|smudge|process|required)"
    r"|diff\..*\.(command|textconv|cachetextconv|trustExitCode))$"
)

# Plumbing that reads refs, trees, blobs or the index without running any
# filter, diff driver or textconv. Unlisted subcommands are treated as content
# converting, so a new caller is guarded by default.
_CONTENT_FREE_SUBCOMMANDS = frozenset(
    {
        "cat-file",
        "check-attr",
        "check-ignore",
        "config",
        "for-each-ref",
        "ls-files",
        "ls-tree",
        "merge-base",
        "remote",
        "rev-list",
        "rev-parse",
        "show-ref",
        "symbolic-ref",
        "var",
    }
)
# Flags that make otherwise content-free plumbing hash or convert content.
_CONTENT_CONVERTING_FLAGS = frozenset({"--filters", "--textconv", "-m", "--modified"})
_DIFF_RENDERING_SUBCOMMANDS = frozenset({"diff", "log", "show"})


def needs_content_guard(args: Sequence[str]) -> bool:
    """Whether ``args`` may run repository filters, diff drivers or textconv.

    True unless the subcommand is content-free plumbing invoked without a
    content-converting flag. Global options before the subcommand (``-C``)
    count as guarded.
    """

    if not args or args[0] not in _CONTENT_FREE_SUBCOMMANDS:
        return True
    return any(
        arg in _CONTENT_CONVERTING_FLAGS or arg.startswith("--path=")
        for arg in args[1:]
    )


def with_diff_guards(args: Sequence[str]) -> list[str]:
    """``args`` with external diff and textconv disabled where Git honors them.

    ``diff``/``log``/``show`` get ``--no-ext-diff --no-textconv``; ``blame``
    (which runs textconv by default) gets ``--no-textconv``.
    """

    safe_args = list(args)
    if not safe_args:
        return safe_args
    if safe_args[0] in _DIFF_RENDERING_SUBCOMMANDS:
        flags = ("--no-ext-diff", "--no-textconv")
    elif safe_args[0] == "blame":
        flags = ("--no-textconv",)
    else:
        return safe_args
    insert_at = 1
    for flag in flags:
        if flag not in safe_args:
            safe_args.insert(insert_at, flag)
            insert_at += 1
    return safe_args


_FILTER_DRIVER_OVERRIDES = ("clean=", "smudge=", "process=", "required=false")
_DIFF_DRIVER_OVERRIDES = (
    "command=",
    "textconv=",
    "cachetextconv=false",
    "trustExitCode=false",
)


def _configured_driver_keys(
    root: str | os.PathLike[str], env: Mapping[str, str], timeout: float
) -> list[str] | None:
    """Every filter/diff driver config key, or ``None`` when Git cannot say."""

    command = read_only_git_command(
        [
            "config",
            "--includes",
            "--null",
            "--name-only",
            "--get-regexp",
            _FILTER_CONFIG_REGEX,
        ]
    )
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(root),
            env=dict(env),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 1:  # no matching keys configured
        return []
    if result.returncode != 0:
        return None
    if len(result.stdout.encode("utf-8")) > _MAX_FILTER_CONFIG_OUTPUT:
        return None
    return [key for key in result.stdout.split("\0") if key]


def _driver_names(keys: Sequence[str]) -> tuple[set[str], set[str]] | None:
    """(filter drivers, diff drivers), or ``None`` for any unsafe name."""

    filter_drivers: set[str] = set()
    diff_drivers: set[str] = set()
    for key in keys:
        match = _FILTER_CONFIG_KEY_RE.fullmatch(key)
        drivers = filter_drivers
        if match is None:
            match = _DIFF_CONFIG_KEY_RE.fullmatch(key)
            drivers = diff_drivers
        driver = match.group("driver") if match is not None else ""
        if (
            len(driver) > _MAX_FILTER_DRIVER_LENGTH
            or _SAFE_FILTER_DRIVER_RE.fullmatch(driver) is None
        ):
            return None
        drivers.add(driver)
        if len(filter_drivers) + len(diff_drivers) > _MAX_FILTER_DRIVERS:
            return None
    return filter_drivers, diff_drivers


def content_filter_config_overrides(
    root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[str, ...] | None:
    """Overrides that neutralize clean/process filters and diff drivers.

    Returns a (possibly empty) tuple of ``-c`` values that set every
    repository-configured filter and diff driver empty, or ``None`` when the
    repository's filter configuration cannot be inspected safely. ``None`` means
    the caller must refuse any worktree-hashing operation: running it could
    execute a repository-defined filter or diff command.
    """

    keys = _configured_driver_keys(root, read_only_git_environment(environ), timeout)
    names = None if keys is None else _driver_names(keys)
    if names is None:
        return None
    filter_drivers, diff_drivers = names
    return tuple(
        [
            f"filter.{driver}.{setting}"
            for driver in sorted(filter_drivers)
            for setting in _FILTER_DRIVER_OVERRIDES
        ]
        + [
            f"diff.{driver}.{setting}"
            for driver in sorted(diff_drivers)
            for setting in _DIFF_DRIVER_OVERRIDES
        ]
    )


def worktree_safe_git_command(
    args: Sequence[str],
    root: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    extra_overrides: Sequence[str] = (),
    literal_pathspecs: bool = False,
    timeout: float = 10.0,
) -> list[str] | None:
    """A read-only Git command safe to run inside an untrusted repository.

    Builds on :func:`read_only_git_command`, adds the repository's filter and
    diff-driver neutralization unless ``args`` is content-free plumbing, and
    injects ``--no-ext-diff`` / ``--no-textconv`` (see
    :func:`with_diff_guards`). Returns ``None`` when the filter configuration
    cannot be inspected safely; the caller must then refuse the operation
    rather than run git.
    """

    overrides: tuple[str, ...] = ()
    if needs_content_guard(args):
        inspected = content_filter_config_overrides(
            root, environ=environ, timeout=timeout
        )
        if inspected is None:
            return None
        overrides = inspected
    return read_only_git_command(
        with_diff_guards(args),
        config_overrides=(*overrides, *extra_overrides),
        literal_pathspecs=literal_pathspecs,
    )
