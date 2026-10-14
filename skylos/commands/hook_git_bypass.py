"""Shell commands that skip the repository's git hooks.

Agents run ``git commit --no-verify`` (or ``HUSKY=0 git commit``) when a
pre-commit hook fails, and the failing tests land anyway. The pre-bash hook
uses this module to block that. It recognises:

* ``--no-verify`` (and git's unambiguous abbreviations, ``--no-veri``...)
  on ``commit``, ``merge``, ``pull``, ``push``, ``rebase`` and ``am``, and
  ``-n`` on ``commit`` and ``am`` (also inside a short-option cluster such
  as ``-anm``; ``-m``'s value ends the cluster, so ``-amn`` is a message);
* ``git -c core.hooksPath=...``, ``--config-env=core.hooksPath=...`` and the
  ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_<n>`` and ``GIT_CONFIG_PARAMETERS``
  environment forms;
* hook managers' skip switches in the command's environment: ``HUSKY=0``
  and ``HUSKY_SKIP_HOOKS`` (husky), ``SKIP`` and
  ``PRE_COMMIT_ALLOW_NO_CONFIG`` (pre-commit; ``SKIP`` is also overcommit's),
  ``LEFTHOOK=0|false`` and ``LEFTHOOK_EXCLUDE`` (lefthook),
  ``SKIP_SIMPLE_GIT_HOOKS`` (simple-git-hooks), ``OVERCOMMIT_DISABLE``.
  A switch counts only when its manager is in use: its config file or folder
  is at the top of the repository, the hooks directory is inside its folder
  (``.husky``), or an installed hook script names it. A plain
  ``.git/hooks/pre-commit`` never reads ``HUSKY``;
* persistent changes: ``git config core.hooksPath <dir without the
  hooks>``, ``git config --unset core.hooksPath``, and a git alias whose
  value contains ``--no-verify``;
* deleting or un-executable-ing a file in the active hooks directory.

A bypass only counts when a hook it would skip is installed: in a repository
without hooks ``--no-verify`` changes nothing and is allowed.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from skylos.commands.hook_shell_commands import SimpleCommand
from skylos.core.safe_cache_io import read_text_no_symlink

# Hooks that can stop each operation (the gates), and the subset that
# --no-verify skips.
GATE_HOOKS = {
    "commit": ("pre-commit", "prepare-commit-msg", "commit-msg"),
    "merge": ("pre-merge-commit", "prepare-commit-msg", "commit-msg"),
    "pull": ("pre-merge-commit", "prepare-commit-msg", "commit-msg"),
    "push": ("pre-push",),
    "rebase": ("pre-rebase",),
    "am": ("applypatch-msg", "pre-applypatch"),
}
NO_VERIFY_HOOKS = {
    "commit": ("pre-commit", "commit-msg"),
    "merge": ("pre-merge-commit", "commit-msg"),
    "pull": ("pre-merge-commit", "commit-msg"),
    "push": ("pre-push",),
    "rebase": ("pre-rebase",),
    "am": ("applypatch-msg", "pre-applypatch"),
}
ALL_GATE_HOOKS = frozenset(name for names in GATE_HOOKS.values() for name in names)
# git commit short options whose value ends a cluster (-m msg, -mmsg).
_COMMIT_VALUE_LETTERS = frozenset("CcFmt")
_COMMIT_OPTIONAL_LETTERS = frozenset("uS")
_GIT_VALUE_OPTIONS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
     "--config-env", "--exec-path", "--attr-source"}
)  # fmt: skip
_HOOKS_PATH_KEY = "core.hookspath"
_SUBCOMMAND_VALUE_OPTIONS = {
    "commit": frozenset(
        {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c",
         "--reedit-message", "-t", "--template", "--author", "--date",
         "--trailer", "--fixup", "--squash", "--cleanup", "--pathspec-from-file"}
    ),
    "merge": frozenset(
        {"-m", "-F", "--file", "-s", "--strategy", "-X", "--strategy-option",
         "--into-name", "--cleanup"}
    ),
    "pull": frozenset({"-s", "--strategy", "-X", "--strategy-option", "--depth"}),
    "push": frozenset({"-o", "--push-option", "--repo", "--receive-pack", "--exec"}),
    "rebase": frozenset({"--onto", "-s", "--strategy", "-X", "--strategy-option",
                         "-x", "--exec"}),
    "am": frozenset({"--patch-format", "--resolvemsg"}),
}  # fmt: skip
_NULL_PATHS = frozenset({"/dev/null", "nul", "nul:", ""})
_REMOVERS = frozenset({"rm", "unlink", "mv", "shred", "trash"})

HooksLookup = Callable[[Path], "Path | None"]


@dataclass(frozen=True)
class HookBypass:
    how: str  # what the command does, for the message
    operation: str  # commit, push, ... or "config"
    hooks: tuple[str, ...]  # installed hooks it would skip


def hook_bypasses(
    commands: list[SimpleCommand], *, hooks_dir: HooksLookup | None = None
) -> list[HookBypass]:
    """Hook bypasses in ``commands`` that would skip an installed hook."""
    active = _ActiveHooks(hooks_dir or git_hooks_dir)
    found: list[HookBypass] = []
    for simple in commands:
        program = simple.program.lower().removesuffix(".exe")
        if program == "git":
            found.extend(_git_bypasses(simple, active))
        elif program in _REMOVERS or program == "chmod":
            found.extend(_hook_file_removal(simple, program, active))
    return found


@dataclass(frozen=True)
class _Manager:
    files: tuple[str, ...]  # config files or folders at the repository top
    words: tuple[str, ...]  # text an installed hook script of theirs contains
    folder: str | None = None  # a hooks directory inside this folder is theirs


# The hook managers whose environment switches skip hooks. Hook-script words
# are matched case-insensitively.
_MANAGERS = {
    "husky": _Manager((".husky",), ("husky",), folder=".husky"),
    "pre-commit": _Manager(
        (".pre-commit-config.yaml", ".pre-commit-config.yml"),
        ("pre-commit.com", "pre_commit"),
    ),
    "overcommit": _Manager((".overcommit.yml",), ("overcommit",)),
    "lefthook": _Manager(
        tuple(
            f"{prefix}{name}{suffix}"
            for prefix in ("", ".", ".config/")
            for name in ("lefthook", "lefthook-local")
            for suffix in (".yml", ".yaml", ".toml", ".json", ".jsonc")
        ),
        ("lefthook",),
    ),
    "simple-git-hooks": _Manager(
        tuple(
            f"{prefix}simple-git-hooks{suffix}"
            for prefix in ("", ".")
            for suffix in (".json", ".js", ".cjs", ".mjs")
        ),
        ("simple-git-hooks", "skip_simple_git_hooks"),
    ),
}
_SWITCH_MANAGERS = {
    "HUSKY": ("husky",),
    "HUSKY_SKIP_HOOKS": ("husky",),
    "SKIP": ("pre-commit", "overcommit"),
    "PRE_COMMIT_ALLOW_NO_CONFIG": ("pre-commit",),
    "LEFTHOOK": ("lefthook",),
    "LEFTHOOK_EXCLUDE": ("lefthook",),
    "SKIP_SIMPLE_GIT_HOOKS": ("simple-git-hooks",),
    "OVERCOMMIT_DISABLE": ("overcommit",),
}
_SMALL_FILE_BYTES = 1_000_000


class _ActiveHooks:
    """Installed hooks per working directory (one git call per directory)."""

    def __init__(self, lookup: HooksLookup):
        self.lookup = lookup
        self.cache: dict[Path, Path | None] = {}
        self.manager_cache: dict[Path, frozenset[str] | None] = {}

    def directory(self, cwd: Path) -> Path | None:
        if cwd not in self.cache:
            self.cache[cwd] = self.lookup(cwd)
        return self.cache[cwd]

    def managers(self, cwd: Path) -> frozenset[str] | None:
        """Hook managers in use in ``cwd``'s repository; None when the hooks
        directory or an installed hook cannot be read (then every manager is
        assumed)."""
        if cwd not in self.manager_cache:
            directory = self.directory(cwd)
            self.manager_cache[cwd] = (
                None if directory is None else _managers_in_use(cwd, directory)
            )
        return self.manager_cache[cwd]

    def __call__(self, cwd: Path, names: tuple[str, ...]) -> tuple[str, ...]:
        directory = self.directory(cwd)
        if directory is None:
            return names  # unknown: assume the hooks are there
        return tuple(name for name in names if _hook_active(directory, name))


def git_hooks_dir(cwd: Path) -> Path | None:
    """The directory git runs hooks from in ``cwd`` (core.hooksPath aware).

    None when git cannot tell (not a repository, git missing)."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks"],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    out = proc.stdout.strip()
    if proc.returncode != 0 or not out:
        return None
    path = Path(out).expanduser()
    return path if path.is_absolute() else cwd / path


# -- git ------------------------------------------------------------------


def _git_bypasses(simple: SimpleCommand, active) -> list[HookBypass]:
    args = simple.args
    cwd = simple.cwd
    hooks_path_override: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if not arg.startswith("-"):
            break
        name, has_value, attached = arg.partition("=")
        value = attached if has_value else None
        if name in _GIT_VALUE_OPTIONS and not has_value and index + 1 < len(args):
            value = args[index + 1]
            index += 1
        if name == "-C" and value:
            path = Path(value).expanduser()
            cwd = path if path.is_absolute() else cwd / path
        elif name == "-c" and value:
            key, _, setting = value.partition("=")
            if key.strip().lower() == _HOOKS_PATH_KEY:
                hooks_path_override = setting
        elif name == "--config-env" and value:
            key = value.split("=", 1)[0]
            if key.strip().lower() == _HOOKS_PATH_KEY:
                hooks_path_override = "$" + value.split("=", 1)[-1]
        index += 1
    if index >= len(args):
        return []
    sub = args[index].lower()
    rest = args[index + 1 :]
    env_override = _env_hooks_path(simple.env)
    if hooks_path_override is None and env_override is not None:
        hooks_path_override = env_override

    if sub == "config":
        return _git_config(rest, cwd, active)
    if sub not in GATE_HOOKS:
        return []
    found: list[HookBypass] = []
    if _no_verify(sub, rest):
        skipped = active(cwd, NO_VERIFY_HOOKS[sub])
        if skipped:
            found.append(HookBypass("--no-verify", sub, skipped))
    if hooks_path_override is not None and not _keeps_hooks(
        hooks_path_override, cwd, active
    ):
        skipped = active(cwd, GATE_HOOKS[sub])
        if skipped:
            shown = hooks_path_override or "(empty)"
            found.append(HookBypass(f"core.hooksPath={shown}", sub, skipped))
    switches = _env_switches(simple.env)
    skipped = active(cwd, GATE_HOOKS[sub]) if switches else ()
    if skipped:
        in_use = active.managers(cwd)
        for how, variable in switches:
            # HUSKY=0 means nothing to a plain .git/hooks script.
            if in_use is None or in_use.intersection(_SWITCH_MANAGERS[variable]):
                found.append(HookBypass(how, sub, skipped))
    return found


def _managers_in_use(cwd: Path, directory: Path) -> frozenset[str] | None:
    top = _toplevel(cwd) or cwd
    try:
        parts = Path(os.path.normpath(str(directory))).parts
    except (OSError, ValueError):
        parts = ()
    scripts = _hook_scripts_text(directory)
    if scripts is None:
        return None  # an installed hook that cannot be read: assume any manager
    found = set()
    for name, manager in _MANAGERS.items():
        if (
            (manager.folder is not None and manager.folder in parts)
            or any(os.path.lexists(top / file) for file in manager.files)
            or any(word in scripts for word in manager.words)
        ):
            found.add(name)
    package = _small_text(top / "package.json")
    if package is not None and '"simple-git-hooks"' in package:
        found.add("simple-git-hooks")
    return frozenset(found)


def _hook_scripts_text(directory: Path) -> str | None:
    """The installed gate hooks' text, lower-cased; None when one of them is
    a symlink, too large or unreadable."""
    texts = []
    for name in sorted(ALL_GATE_HOOKS):
        if _hook_active(directory, name):
            text = _small_text(directory / name)
            if text is None:
                return None
            texts.append(text.lower())
    return "\n".join(texts)


def _small_text(path: Path) -> str | None:
    # A regular file, never through a symlink, at most 1 MB.
    return read_text_no_symlink(path, max_bytes=_SMALL_FILE_BYTES, errors="replace")


def _no_verify(sub: str, args: list[str]) -> bool:
    """Whether ``git <sub> args`` skips hooks; the last of --verify /
    --no-verify wins, as in git."""
    skip = False
    values = _SUBCOMMAND_VALUE_OPTIONS.get(sub, frozenset())
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            break
        if arg in values:
            index += 1  # the option's value, e.g. -m "--no-verify"
            continue
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if len(name) >= len("--no-veri") and "--no-verify".startswith(name):
                skip = True
            elif len(name) >= len("--veri") and "--verify".startswith(name):
                skip = False
            continue
        if sub == "commit" and arg.startswith("-") and len(arg) > 1:
            letters = arg[1:]
            if _cluster_has_n(letters, sub):
                skip = True
            elif letters[-1] in _COMMIT_VALUE_LETTERS:
                index += 1  # "-am" then the message: never a flag
        elif sub == "am" and arg.startswith("-") and _cluster_has_n(arg[1:], sub):
            skip = True
    return skip


def _cluster_has_n(letters: str, sub: str) -> bool:
    for letter in letters:
        if letter == "n":
            return True
        if sub == "commit" and (
            letter in _COMMIT_VALUE_LETTERS or letter in _COMMIT_OPTIONAL_LETTERS
        ):
            return False  # the rest of the cluster is this option's value
        if sub == "am" and letter in {"C", "p", "S"}:
            return False
    return False


def _env_hooks_path(env: dict[str, str]) -> str | None:
    try:
        count = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
    except ValueError:
        count = 0
    for number in range(min(count, 50)):
        key = env.get(f"GIT_CONFIG_KEY_{number}", "")
        if key.strip().lower() == _HOOKS_PATH_KEY:
            return env.get(f"GIT_CONFIG_VALUE_{number}", "")
    params = env.get("GIT_CONFIG_PARAMETERS", "")
    match = re.search(r"'?core\.hookspath'?\s*=\s*'([^']*)'", params, re.IGNORECASE)
    if match:
        return match.group(1)
    if re.search(r"core\.hookspath", params, re.IGNORECASE):
        return ""
    return None


def _env_switches(env: dict[str, str]) -> list[tuple[str, str]]:
    """(how it reads, variable) for each hook-manager skip switch set."""
    found = []

    def value(name: str) -> str:
        return env.get(name, "").strip()

    if value("HUSKY") == "0":
        found.append(("HUSKY=0", "HUSKY"))
    if value("HUSKY_SKIP_HOOKS") and value("HUSKY_SKIP_HOOKS").lower() not in {
        "0",
        "false",
    }:
        found.append(
            (f"HUSKY_SKIP_HOOKS={value('HUSKY_SKIP_HOOKS')}", "HUSKY_SKIP_HOOKS")
        )
    if value("SKIP"):
        found.append((f"SKIP={value('SKIP')}", "SKIP"))
    if value("PRE_COMMIT_ALLOW_NO_CONFIG"):
        found.append(("PRE_COMMIT_ALLOW_NO_CONFIG", "PRE_COMMIT_ALLOW_NO_CONFIG"))
    if value("LEFTHOOK").lower() in {"0", "false"} and "LEFTHOOK" in env:
        found.append((f"LEFTHOOK={value('LEFTHOOK')}", "LEFTHOOK"))
    if value("LEFTHOOK_EXCLUDE"):
        found.append(
            (f"LEFTHOOK_EXCLUDE={value('LEFTHOOK_EXCLUDE')}", "LEFTHOOK_EXCLUDE")
        )
    if value("SKIP_SIMPLE_GIT_HOOKS") and value("SKIP_SIMPLE_GIT_HOOKS") != "0":
        found.append(("SKIP_SIMPLE_GIT_HOOKS", "SKIP_SIMPLE_GIT_HOOKS"))
    if value("OVERCOMMIT_DISABLE") and value("OVERCOMMIT_DISABLE") != "0":
        found.append(("OVERCOMMIT_DISABLE", "OVERCOMMIT_DISABLE"))
    return found


def _git_config(args: list[str], cwd: Path, active) -> list[HookBypass]:
    """``git config`` writes that switch hooks off for later commands."""
    words: list[str] = []
    flags: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-f", "--file", "--blob", "--type", "--default", "--comment",
                   "--value", "--url"}:  # fmt: skip
            index += 2
            continue
        (flags if arg.startswith("-") else words).append(arg)
        index += 1
    unset = any(flag in {"--unset", "--unset-all"} for flag in flags)
    if words and words[0] in {"set", "unset"}:
        unset = unset or words[0] == "unset"
        words = words[1:]
    if any(
        flag in {"--get", "--get-all", "--get-regexp", "-l", "--list"} for flag in flags
    ):
        return []
    if words and words[0] in {"get", "list", "edit"}:
        return []
    if not words:
        return []
    key = words[0].lower()
    if key == _HOOKS_PATH_KEY:
        if unset:
            directory = active.directory(cwd)
            if directory is not None and _is_default_hooks_dir(directory):
                return []  # no core.hooksPath set: unsetting changes nothing
            current = active(cwd, tuple(sorted(ALL_GATE_HOOKS)))
            if current:
                return [
                    HookBypass("git config --unset core.hooksPath", "config", current)
                ]
            return []
        if len(words) < 2:
            return []  # reads the value
        target = words[1]
        if _keeps_hooks(target, cwd, active):
            return []
        current = active(cwd, tuple(sorted(ALL_GATE_HOOKS)))
        if current:
            return [
                HookBypass(f"git config core.hooksPath {target}", "config", current)
            ]
        return []
    if key.startswith("alias.") and len(words) >= 2:
        value = " ".join(words[1:])
        if re.search(r"(?:^|\s)--no-veri", value) or re.search(
            r"\bcommit\b[^|;&]*\s-[A-Za-z]*n", value
        ):
            current = active(cwd, tuple(sorted(ALL_GATE_HOOKS)))
            if current:
                return [
                    HookBypass(
                        f"git alias {words[0]} with --no-verify", "config", current
                    )
                ]
    return []


def _keeps_hooks(target: str, cwd: Path, active) -> bool:
    """Whether pointing core.hooksPath at ``target`` keeps hooks running:
    true when nothing runs now, or the target holds at least one hook.
    "/dev/null", an empty value, an unknown value or a directory without
    hooks switches them off."""
    if not active(cwd, tuple(sorted(ALL_GATE_HOOKS))):
        return True
    if target.strip().lower() in _NULL_PATHS or target.startswith("$"):
        return False
    path = Path(target).expanduser()
    if not path.is_absolute():
        top = _toplevel(cwd)
        path = (top or cwd) / path
    return any(_hook_active(path, name) for name in ALL_GATE_HOOKS)


def _is_default_hooks_dir(directory: Path) -> bool:
    parts = Path(os.path.normpath(str(directory))).parts
    return len(parts) >= 2 and parts[-2:] == (".git", "hooks")


def _toplevel(cwd: Path) -> Path | None:
    for parent in (cwd, *cwd.parents):
        if (parent / ".git").exists():
            return parent
    return None


def _hook_active(directory: Path, name: str) -> bool:
    path = directory / name
    try:
        info = path.stat()
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode):
        return False
    if os.name != "nt" and not info.st_mode & 0o111:
        return False  # git skips hooks that are not executable
    # husky v9: .husky/_/<hook> is a stub that runs .husky/<hook> if present.
    if directory.name == "_" and directory.parent.name == ".husky":
        return (directory.parent / name).is_file()
    return True


# -- removing hook files ----------------------------------------------------


_CHMOD_FLAGS = frozenset(
    {"-R", "-v", "-f", "-c", "-h", "-H", "-L", "-P", "--recursive", "--verbose",
     "--changes", "--silent", "--quiet"}
)  # fmt: skip


def _may_name_a_hook(operand: str) -> bool:
    lowered = operand.lower()
    return (
        "hook" in lowered or "husky" in lowered or Path(operand).name in ALL_GATE_HOOKS
    )


def _drops_exec(mode: str) -> bool:
    """Whether chmod ``mode`` leaves the owner without execute permission."""
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return not int(mode, 8) & 0o100
    for clause in mode.split(","):
        match = re.fullmatch(r"([ugoa]*)([-=+])([rwxXst]*)", clause)
        if not match:
            continue
        who, op, perms = match.groups()
        if who and "u" not in who and "a" not in who:
            continue
        if op == "-" and "x" in perms:
            return True
        if op == "=" and "x" not in perms and "X" not in perms:
            return True
    return False


def _hook_file_removal(
    simple: SimpleCommand, program: str, active: _ActiveHooks
) -> list[HookBypass]:
    if program == "chmod":
        rest = [arg for arg in simple.args if arg not in _CHMOD_FLAGS]
        if not rest or not _drops_exec(rest[0]):
            return []
        operands = rest[1:]
    else:
        operands = [arg for arg in simple.args if not arg.startswith("-")]
        if program == "mv" and operands:
            operands = operands[:-1]  # the destination
    if not operands:
        return []
    if not any(_may_name_a_hook(operand) for operand in operands):
        return []  # skip the git call for ordinary files
    directory = active.directory(simple.cwd)
    if directory is None:
        return []
    try:
        hooks_root = Path(os.path.normpath(str(directory)))
    except (OSError, ValueError):
        return []
    hit: list[str] = []
    for operand in operands:
        path = Path(operand).expanduser()
        path = Path(
            os.path.normpath(str(path if path.is_absolute() else simple.cwd / path))
        )
        if path == hooks_root:
            hit.extend(n for n in sorted(ALL_GATE_HOOKS) if _hook_active(directory, n))
        elif (
            path.parent == hooks_root
            and path.name in ALL_GATE_HOOKS
            and _hook_active(directory, path.name)
        ):
            hit.append(path.name)
    if not hit:
        return []
    verb = "chmod -x" if program == "chmod" else program
    return [
        HookBypass(
            f"{verb} on the hooks directory", "config", tuple(dict.fromkeys(hit))
        )
    ]


__all__ = ["GATE_HOOKS", "HookBypass", "git_hooks_dir", "hook_bypasses"]
