"""Shell commands that write an agent config file without the edit tools.

The pre-edit hook replays edits; a shell command that writes
``.mcp.json``, ``.claude/settings.json`` and the other agent configs gets no
replay, so the pre-bash hook asks before it runs. Counted as a write:

* a redirect (``>``, ``>>``) or a program argument that names a config file,
  including through a glob (``.claude/setting*.json``);
* copies and moves into a config file or folder, or of a file with a config
  name into the folder that holds it (``mv /tmp/x/.mcp.json .``);
* downloads saved under a config name (``curl -o``, ``-O``, ``wget``);
* inline code that names a config file (``python3 -c "open('.mcp.json','w')"``);
* in-place edits (``sed -i``, ``perl -i``), ``git checkout``/``restore`` and
  similar git commands that name a config file or folder, ``git apply``/``am``
  of a patch that touches one (or one Skylos cannot read), ``patch``, and
  archive extraction (``tar x``, ``unzip``), whose contents are not listed.

Read-only programs (``cat``, ``grep``, ``jq``, ``git diff``/``add``/``commit``)
count only through a redirect. A script that writes a config without naming
it is not seen here; the next prompt's config check reports the change.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

from skylos.commands.hook_agent_configs import (
    AGENTS_DIR,
    config_dirs,
    config_files,
    guarded_file,
    read_config,
)

_BENIGN = frozenset({"mkdir", "rm", "rmdir", "touch", "chmod", "chown", "ls", "echo", "printf",
                     "test", "[", "true", "false", "code", "open", "skylos"})  # fmt: skip
_COPIERS = frozenset({"cp", "mv", "install", "ln", "rsync", "scp", "ditto", "gcp", "gmv", "rclone"})
_DOWNLOADERS = frozenset({"curl", "wget", "aria2c", "http", "https", "xh", "fetch"})
_EXTRACTORS = frozenset({"tar", "bsdtar", "gtar", "unzip", "7z", "7za"})
_IN_PLACE = frozenset({"sed", "gsed", "perl", "ruby"})
_GIT_READS = frozenset({"diff", "log", "show", "status", "blame", "ls-files", "cat-file", "rev-parse",
                        "grep", "shortlog", "describe", "add", "commit", "fetch", "push", "branch",
                        "tag", "remote"})  # fmt: skip
_GIT_PATCHES = frozenset({"apply", "am"})
_OUTPUT_OPTIONS = frozenset({"-o", "--output", "--output-document"})
_DOWNLOAD_DIRECTORY_OPTIONS = frozenset({"--output-dir", "-P", "--directory-prefix"})
_COPY_DIRECTORY_OPTIONS = frozenset({"-t", "--target-directory"})
_CONFIG_WORDS = (".mcp.json", "mcp.json", ".claude", ".cursor", ".vscode", ".gemini", ".codex",
                 "tasks.json", "hooks.json", "settings.json", "config.toml")  # fmt: skip
_GLOB = re.compile(r"[*?\[]")
MAX_PATCH_BYTES = 2_000_000


class _Guard:
    def __init__(self, root: Path, home: Path | None):
        self.root = root
        self.home = home
        self.dirs = [_key(path) for path in config_dirs(root, home)]
        self.files = [str(cf.path) for cf in config_files(root, home) if cf.kind != "agent-md"]
        self.files += [str(base / AGENTS_DIR / "*.md") for base in (root, home) if base is not None]

    def file(self, path: Path) -> bool:
        return bool(guarded_file(path, self.root, self.home))

    def directory(self, path: Path) -> bool:
        key = _key(path)
        return any(key == d or key.startswith(d + os.sep) for d in self.dirs)

    def hit(self, word: str, cwd: Path, *, dirs: bool) -> bool:
        if not word or "$" in word or "://" in word:
            return False
        path = _resolve(cwd, word)
        if _GLOB.search(word):
            return any(fnmatch.fnmatch(target, str(path)) for target in self.files)
        return self.file(path) or (dirs and self.directory(path))


def config_writes(commands: list[Any], root: Path, home: Path | None) -> list[str]:
    """What, in ``commands``, writes an agent config file (one item each)."""
    from skylos.commands.hook_shell_writes import _READ_ONLY

    guard = _Guard(root, home)
    found = []
    for simple in commands:
        cwd = Path(simple.cwd)
        found += [str(t) for t in simple.outputs if guard.hit(str(t), cwd, dirs=False)]
        program = _program(simple.program)
        if program in _READ_ONLY or program in _BENIGN:
            continue
        hit = _writer(program, list(simple.args), cwd, guard)
        if hit:
            found.append(hit)
    return list(dict.fromkeys(found))


def _writer(program: str, args: list[str], cwd: Path, guard: _Guard) -> str:
    operands = [a for a in args if not a.startswith("-")]
    if program == "git":
        return _git(operands, cwd, guard)
    if program == "patch":
        return _patches(operands, cwd, "patch")
    if program in _EXTRACTORS:
        return _extract(program, args)
    if program in _COPIERS:
        return _copy(program, args, operands, cwd, guard)
    if program in _DOWNLOADERS:
        return _download(program, args, operands, cwd, guard)
    if program in _IN_PLACE and not any(a.startswith(("-i", "--in-place")) for a in args):
        return ""
    inline = _inline(program, args)
    if inline:
        return inline
    for word in operands + [a[3:] for a in args if a.startswith("of=")]:
        if guard.hit(word, cwd, dirs=False):
            return f"{word} (via {program})"
    return ""


def _git(operands: list[str], cwd: Path, guard: _Guard) -> str:
    if not operands or operands[0] in _GIT_READS:
        return ""
    if operands[0] in _GIT_PATCHES:
        return _patches(operands[1:], cwd, f"git {operands[0]}")
    for word in operands[1:]:
        if guard.hit(word, cwd, dirs=True):
            return f"{word} (via git {operands[0]})"
    return ""


def _patches(files: list[str], cwd: Path, label: str) -> str:
    if not files:
        return f"files from a patch Skylos cannot read (via {label})"
    for name in files:
        text = read_config(_resolve(cwd, name))
        if text is None or len(text) > MAX_PATCH_BYTES:
            return f"files from a patch Skylos cannot read (via {label} {name})"
        if any(word in text for word in _CONFIG_WORDS):
            return f"agent configs (via {label} {name})"
    return ""


def _extract(program: str, args: list[str]) -> str:
    if program == "unzip" and not any(a in ("-l", "-t", "-v", "-Z") for a in args):
        return "files from an archive Skylos cannot list (via unzip)"
    if program in ("7z", "7za") and args[:1] and args[0] in ("x", "e"):
        return f"files from an archive Skylos cannot list (via {program} {args[0]})"
    clusters = [a for a in args if re.fullmatch(r"-[A-Za-z]+", a)] + args[:1]
    if "--extract" in args or "--get" in args or any(re.fullmatch(r"-?[A-Za-z]*x[A-Za-z]*", a) for a in clusters):
        return f"files from an archive Skylos cannot list (via {program} x)"
    return ""


def _copy(program: str, args: list[str], operands: list[str], cwd: Path, guard: _Guard) -> str:
    destination = ""
    for index, arg in enumerate(args):
        option, eq, value = arg.partition("=")
        if option in _COPY_DIRECTORY_OPTIONS:
            destination = value if eq else _at(args, index + 1)
    sources = operands
    if not destination and len(operands) >= 2:
        destination = operands[-1]
        sources = operands[:-1]
    if not destination:
        return ""
    if guard.hit(destination, cwd, dirs=True):
        return f"{destination} (via {program})"
    target = _resolve(cwd, destination)
    for source in sources:
        if guard.hit(str(target / Path(source).name), cwd, dirs=True):
            return f"{destination} (via {program} {source})"
    return ""


def _download(program: str, args: list[str], operands: list[str], cwd: Path, guard: _Guard) -> str:
    folder = cwd
    for index, arg in enumerate(args):
        option, eq, value = arg.partition("=")
        value = value if eq else _at(args, index + 1)
        named = option in _OUTPUT_OPTIONS or (program == "wget" and option == "-O")
        if named and guard.hit(value, cwd, dirs=False):
            return f"{value} (via {program})"
        if option in _DOWNLOAD_DIRECTORY_OPTIONS:
            if guard.hit(value, cwd, dirs=True):
                return f"{value} (via {program})"
            folder = _resolve(cwd, value)
    for url in [a for a in operands if "://" in a]:
        name = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        if name and guard.hit(str(folder / name), cwd, dirs=True):
            return f"{name} (via {program})"
    return ""


def _inline(program: str, args: list[str]) -> str:
    from skylos.commands.hook_mcp import _inline_code

    if not _inline_code([program, *args]):
        return ""
    for arg in args:
        if any(word in arg for word in _CONFIG_WORDS):
            return f"{next(w for w in _CONFIG_WORDS if w in arg)} (via {program} code)"
    return ""


def _resolve(cwd: Path, word: str) -> Path:
    path = Path(word).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return Path(os.path.normpath(str(path)))


def _key(path: Path) -> str:
    from skylos.commands.hook_agent_configs import _path_key

    return _path_key(path)


def _program(word: str) -> str:
    from skylos.commands.hook_mcp import _program as program

    return program(word)


def _at(words: list[str], index: int) -> str:
    if 0 <= index < len(words):
        return words[index]
    return ""


__all__ = ["config_writes"]
