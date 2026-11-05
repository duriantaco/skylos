"""Files an earlier part of a command line may write before a later part runs.

The install hook reads a lockfile or requirements file before the command
runs. ``curl -o package-lock.json URL && npm ci`` installs what the download
says, not what the hook read. :func:`earlier_writes` collects, for the simple
commands before an install, every file they name or redirect to, every
directory a downloader, copier or archive tool writes into, and whether one of
them rewrites the working tree wholesale (``git checkout``, ``git pull``,
``patch``). The checker then treats any watched file in that set as "could
not verify" instead of reading it.

Naming a file is enough for any program that might write it; read-only
programs (``cat``, ``grep``, ``git diff`` ...) count only through their
redirects. A program that writes a file it does not name (a script) is not
detected.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from skylos.commands.hook_shell_commands import SimpleCommand, is_dynamic_word

_GIT_REWRITES = frozenset(
    {"checkout", "switch", "restore", "pull", "merge", "rebase", "reset", "stash",
     "apply", "am", "cherry-pick", "revert", "clone", "worktree", "submodule"}
)  # fmt: skip
_TREE_WRITERS = frozenset({"patch", "unzip", "tar", "bsdtar", "gtar", "7z", "7za", "ditto"})
_COPIERS = frozenset({"cp", "mv", "install", "ln", "rsync", "scp", "rclone", "gcp", "gmv"})
_DOWNLOADERS = frozenset({"curl", "wget", "aria2c", "http", "https", "xh", "fetch"})
_READ_ONLY = frozenset(
    {"cat", "head", "tail", "less", "more", "bat", "nl", "wc", "ls", "stat", "file",
     "grep", "egrep", "fgrep", "rg", "ag", "diff", "cmp", "md5", "md5sum", "sha1sum",
     "sha256sum", "sha512sum", "shasum", "jq", "du", "realpath", "readlink", "test", "["}
)  # fmt: skip
_GIT_READS = frozenset(
    {"diff", "log", "show", "status", "blame", "ls-files", "cat-file", "rev-parse",
     "grep", "shortlog", "describe"}
)  # fmt: skip


@dataclass(frozen=True)
class Writes:
    files: tuple[str, ...] = ()
    directories: tuple[str, ...] = ()
    rewrites: bool = False

    def covers(self, path: Path) -> bool:
        """Whether ``path`` may have been written."""
        if self.rewrites:
            return True
        target = _normal(path)
        if target in self.files:
            return True
        return any(target == d or target.startswith(d.rstrip(os.sep) + os.sep)
                   for d in self.directories)  # fmt: skip


@dataclass
class _Collector:
    files: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    rewrites: bool = False

    def frozen(self) -> Writes:
        return Writes(tuple(dict.fromkeys(self.files)),
                      tuple(dict.fromkeys(self.directories)), self.rewrites)  # fmt: skip


def earlier_writes(commands: list[SimpleCommand]) -> Writes:
    collector = _Collector()
    for simple in commands:
        _add(collector, simple)
    return collector.frozen()


def _add(collector: _Collector, simple: SimpleCommand) -> None:
    cwd = Path(simple.cwd)
    for target in simple.outputs:
        if is_dynamic_word(target):
            collector.rewrites = True
            continue
        collector.files.append(_resolve(cwd, target))
    program = simple.program.lower()
    if program in _READ_ONLY:
        return
    if program == "git":
        operands = [arg for arg in simple.args if not arg.startswith("-")]
        if operands and operands[0].lower() in _GIT_READS:
            return
    words = []
    for index, arg in enumerate(simple.args):
        if simple.is_dynamic(index):
            continue
        if arg.startswith("-"):
            if "=" in arg:
                words.append(arg.split("=", 1)[1])
            continue
        words.append(arg)
        if "=" in arg:
            words.append(arg.split("=", 1)[1])
    for word in words:
        if word and "://" not in word:
            collector.files.append(_resolve(cwd, word))
    if program == "git":
        operands = [arg for arg in simple.args if not arg.startswith("-")]
        if operands and operands[0].lower() in _GIT_REWRITES:
            collector.rewrites = True
        return
    if program in _TREE_WRITERS:
        collector.rewrites = True
        return
    if program in _DOWNLOADERS:
        if program != "curl" or _curl_names_remote_file(simple.args):
            collector.directories.append(_normal(cwd))
        return
    if program in _COPIERS:
        for word in words:
            if "://" in word:
                continue
            candidate = Path(_resolve(cwd, word))
            if candidate.is_dir() or word.endswith(("/", ".")):
                collector.directories.append(_normal(candidate))


def _curl_names_remote_file(args: list[str]) -> bool:
    for arg in args:
        if arg.startswith("--remote-name") or arg == "--output-dir":
            return True
        if arg.startswith("-") and not arg.startswith("--") and "O" in arg[1:]:
            return True
    return False


def _resolve(cwd: Path, word: str) -> str:
    path = Path(word).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return _normal(path)


def _normal(path: Path) -> str:
    return os.path.normpath(str(path))


__all__ = ["Writes", "earlier_writes"]
