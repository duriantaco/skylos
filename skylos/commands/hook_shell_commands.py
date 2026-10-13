"""The simple commands a shell command line runs, for the pre-bash checks.

The install guard and the hook-bypass guard need the same view of a
command: which programs it runs, with which arguments and which
environment. This module builds it on :mod:`skylos.commands.hook_shell_lex`:

* pipelines, ``;``/``&&``/``||``/``&``/newlines, ``( ... )`` subshells and
  ``cd`` (scoped to the subshell);
* prefixes that run the rest of the words: ``sudo``, ``doas``, ``env``,
  ``command``, ``nohup``, ``time``, ``nice``, ``timeout``, ``stdbuf``,
  ``exec``, ``builtin``, and ``xargs`` (whose further arguments come from
  stdin, so they are unknown);
* environment: ``X=1 cmd``, ``env X=1 cmd`` and ``export X=1`` earlier in
  the same command line;
* nested scripts: ``bash -c '...'`` (also ``sh``/``zsh``/``dash``/``ksh``),
  ``eval ...``, ``$(...)``, backticks and ``<(...)``.

A word that the shell expands at run time (``$VAR``, ``$(...)``, a brace
list) is marked *dynamic*: its value is unknown here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from skylos.commands.hook_shell_lex import (
    LITERAL_DOLLAR,
    SUBSHELL_CLOSE,
    SUBSHELL_OPEN,
    SUBSTITUTION_RE,
    pipelines,
    prepare,
    tokens,
)

MAX_DEPTH = 4
MAX_COMMANDS = 200

_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$", re.DOTALL)
_BRACE_LIST_RE = re.compile(r"\{[^{}\s]*,[^{}\s]*\}")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "}", "done",
     "fi", "esac"}
)  # fmt: skip
# Prefix programs that run the rest of their words, with their own options
# that take a value.
_WRAPPERS = {
    "sudo": frozenset(
        {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user",
         "--group", "--host", "--prompt", "--chdir", "--role", "--type",
         "--other-user", "--command-timeout"}
    ),
    "doas": frozenset({"-u", "-C"}),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset({"-f", "--format", "-o", "--output"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "caffeinate": frozenset({"-t", "-w"}),
}  # fmt: skip
_XARGS_VALUE_OPTIONS = frozenset(
    {"-I", "-i", "-L", "-l", "-n", "-P", "-s", "-d", "-E", "-e", "-a",
     "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace",
     "--max-lines", "--max-chars", "--eof", "--process-slot-var"}
)  # fmt: skip


@dataclass
class SimpleCommand:
    """One program the command line runs, after prefixes are removed."""

    program: str  # basename of the program word, as written
    args: list[str]
    env: dict[str, str] = field(default_factory=dict)
    cwd: Path = field(default_factory=Path)
    # Indexes into ``args`` whose value is only known at run time.
    dynamic: frozenset[int] = frozenset()
    # xargs: more arguments come from stdin.
    more_args: bool = False

    def is_dynamic(self, index: int) -> bool:
        return index in self.dynamic


def simple_commands(command: str, cwd: Path) -> list[SimpleCommand]:
    """Every simple command ``command`` runs, in order, run from ``cwd``."""
    walker = _Walker(cwd)
    walker.parse(command)
    return walker.commands[:MAX_COMMANDS]


def is_dynamic_word(word: str) -> bool:
    """True when the shell would expand ``word`` (variable, substitution,
    brace list): its value is not known before the command runs."""
    if "$" in word or SUBSTITUTION_RE.search(word) or "`" in word:
        return True
    return bool(_BRACE_LIST_RE.search(word))


class _Walker:
    def __init__(self, cwd: Path, depth: int = 0, exported: dict | None = None):
        self.cwd = cwd
        self.depth = depth
        self.exported: dict[str, str] = dict(exported or {})
        self.commands: list[SimpleCommand] = []
        self.subshells: list[tuple[Path, dict[str, str]]] = []
        self.bodies: list[str] = []
        self.parsed_bodies: set[int] = set()

    def parse(self, command: str) -> None:
        text, self.bodies = prepare(command)
        for pipeline in pipelines(tokens(text)):
            for simple in pipeline:
                if len(self.commands) >= MAX_COMMANDS:
                    return
                self._command(list(simple.words))

    # -- one simple command ---------------------------------------------

    def _command(self, words: list[str]) -> None:
        if words == [SUBSHELL_OPEN]:
            self.subshells.append((self.cwd, dict(self.exported)))
            return
        if words == [SUBSHELL_CLOSE]:
            if self.subshells:
                self.cwd, self.exported = self.subshells.pop()
            return
        self._substitutions(words)
        while words and words[0] in _KEYWORDS:
            words.pop(0)
        if words and words[0] in {"for", "case", "select", "function"}:
            return  # loop/case headers run nothing themselves
        env: dict[str, str] = {}
        while words and _ASSIGNMENT_RE.match(words[0]):
            name, value = _ASSIGNMENT_RE.match(words[0]).groups()
            env[name] = _plain(value)
            words.pop(0)
        if not words:
            return  # plain shell assignment; not exported
        self._run(words, env, more_args=False)

    def _run(self, words: list[str], env: dict[str, str], *, more_args: bool) -> None:
        cwd = self.cwd
        while words:
            program = os.path.basename(_plain(words[0]))
            if program == "command":
                if any(word in {"-v", "-V"} for word in words[1:2]):
                    return  # only looks the name up
                words = _skip_options(words[1:], frozenset())
            elif program in _WRAPPERS:
                words = _skip_options(words[1:], _WRAPPERS[program])
            elif program == "timeout":
                options = frozenset({"-s", "--signal", "-k", "--kill-after"})
                words = _skip_options(words[1:], options)[1:]  # then the duration
            elif program == "env":
                words, cwd, split = _env_words(words[1:], env, cwd)
                if split is not None:
                    self._nested(split, cwd)
                    return
            elif program == "xargs":
                words = _skip_options(words[1:], _XARGS_VALUE_OPTIONS)
                more_args = True
            else:
                break
            # Assignments after "env"/"sudo" are environment too.
            while words and _ASSIGNMENT_RE.match(words[0]):
                name, value = _ASSIGNMENT_RE.match(words[0]).groups()
                env[name] = _plain(value)
                words.pop(0)
        if not words:
            return
        program_word = words[0]
        if is_dynamic_word(program_word):
            return  # the program itself is only known at run time
        program = os.path.basename(_plain(program_word))
        args = words[1:]
        if program == "cd":
            self._cd(args)
            return
        if program in {"export", "declare", "typeset", "readonly", "local"}:
            self._export(args)
            return
        if program == "unset":
            for name in args:
                self.exported.pop(name, None)
            return
        if program in _SHELLS:
            script = _shell_script(args)
            if script is not None:
                self._nested(script, cwd)
            return
        if program == "eval":
            self._nested(" ".join(_plain(arg) for arg in args), cwd)
            return
        dynamic = frozenset(i for i, arg in enumerate(args) if is_dynamic_word(arg))
        merged = {**self.exported, **env}
        self.commands.append(
            SimpleCommand(
                program=program,
                args=[_plain(arg) for arg in args],
                env=merged,
                cwd=cwd,
                dynamic=dynamic,
                more_args=more_args,
            )
        )

    # -- helpers ----------------------------------------------------------

    def _substitutions(self, words: list[str]) -> None:
        for word in words:
            for match in SUBSTITUTION_RE.finditer(word):
                number = int(match.group(1))
                if number in self.parsed_bodies or number >= len(self.bodies):
                    continue
                self.parsed_bodies.add(number)
                self._nested(self.bodies[number], self.cwd)

    def _nested(self, script: str, cwd: Path) -> None:
        if self.depth >= MAX_DEPTH or not script.strip():
            return
        child = _Walker(cwd, self.depth + 1, self.exported)
        child.parse(script)
        self.commands.extend(child.commands)

    def _cd(self, args: list[str]) -> None:
        operands = [arg for arg in args if not arg.startswith("-")]
        if not operands or is_dynamic_word(operands[-1]):
            return
        target = Path(_plain(operands[-1])).expanduser()
        self.cwd = target if target.is_absolute() else self.cwd / target

    def _export(self, args: list[str]) -> None:
        for arg in args:
            match = _ASSIGNMENT_RE.match(arg)
            if match:
                self.exported[match.group(1)] = _plain(match.group(2))


def _plain(word: str) -> str:
    return word.replace(LITERAL_DOLLAR, "$")


def _skip_options(words: list[str], value_options: frozenset[str]) -> list[str]:
    index = 0
    while index < len(words) and words[index].startswith("-"):
        word = words[index]
        if word == "--":
            return words[index + 1 :]
        index += 2 if word in value_options else 1
    return words[index:]


def _env_words(
    args: list[str], env: dict[str, str], cwd: Path
) -> tuple[list[str], Path, str | None]:
    """``env [-i] [-u NAME] [-C DIR] [-S STRING] [NAME=VALUE]... CMD``.

    Returns the command words, its directory, and the ``-S`` string to run
    instead (None when there is none)."""
    rest = list(args)
    while rest and rest[0].startswith("-") and rest[0] != "-":
        option = rest.pop(0)
        if option == "--":
            break
        name, has_value, attached = option.partition("=")
        if name in {"-u", "--unset"}:
            value = attached if has_value else (rest.pop(0) if rest else "")
            env.pop(value, None)
        elif name in {"-C", "--chdir"}:
            value = attached if has_value else (rest.pop(0) if rest else "")
            if value and not is_dynamic_word(value):
                path = Path(_plain(value)).expanduser()
                cwd = path if path.is_absolute() else cwd / path
        elif name in {"-S", "--split-string"}:
            value = attached if has_value else (rest.pop(0) if rest else "")
            return [], cwd, " ".join([_plain(value), *(_plain(w) for w in rest)])
    return rest, cwd, None


def _shell_script(args: list[str]) -> str | None:
    """The script of ``bash -c 'script'`` (also ``-lc``, ``-o x -c``)."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-o", "+o", "-O", "+O"}:
            index += 2
            continue
        if arg == "--" or not arg.startswith(("-", "+")):
            return None  # runs a script file
        if not arg.startswith("--") and "c" in arg[1:]:
            rest = [a for a in args[index + 1 :] if a != "--"]
            return _plain(rest[0]) if rest else None
        index += 1
    return None


__all__ = ["SimpleCommand", "is_dynamic_word", "simple_commands"]
