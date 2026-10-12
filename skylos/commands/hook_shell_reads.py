"""Which files and environment variables a shell command prints.

The pre-read hook stops the agent's Read tool from loading a file that holds
a credential. Agents reach the same file through the shell (``cat .env``,
``grep STRIPE .env.production``, ``env``, ``echo $API_KEY``), so the pre-bash
hook asks this module what a command would print and scans that the same way.

It follows the commands agents usually write: pipes, ``&&``/``;``/newlines,
``cd`` (scoped to ``( ... )``), redirects, globs, here-documents,
``$(...)``/backticks/``<(...)``, ``VAR=$(...)`` then ``echo $VAR``,
``source`` and ``export $(cat .env | xargs)``, loops (``for f in .env*``,
``while read ...; done < .env``), ``bash -c``/``eval``, and ``grep -r`` over a
directory (for ``.env*`` files). Each read carries the text the command
prints from it, through ``grep``, ``head``/``tail``, ``cut``, ``sed`` and
``awk`` (see :mod:`skylos.commands.hook_shell_filters`), a redirect to a
file, or a pipe into a program that does not echo its input. So
``cat .env | grep PORT``, ``sed -n '1,40p' app.py`` and
``sed 's/=.*//' .env`` are allowed when what they print holds no secret.

This is a guard for ordinary commands, not a sandbox. A program that opens
the file itself (``python -c``, ``node -e``) is not followed, and a program
this module does not know is assumed not to print what it reads.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import glob
import itertools
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence, Union

from skylos.commands.hook_shell_filters import (
    Line,
    Stage,
    awk_stage,
    cut_stage,
    head_tail_stage,
    hide,
    keep,
    sed_stage,
)
from skylos.commands.hook_shell_grep import (
    GrepOptions,
    grep_filter,
    grep_options,
    prefix_stage,
    prefixes_names,
)
from skylos.commands.hook_shell_lex import (
    LITERAL_DOLLAR,
    SUBSHELL_CLOSE,
    SUBSHELL_OPEN,
    SUBSTITUTION_RE,
    Command,
    pipelines,
    prepare,
    tokens,
)

MAX_DEPTH = 4
MAX_READS = 64
MAX_GLOB_MATCHES = 50
MAX_WALK_ENTRIES = 5000
MAX_WALK_FILES = 20
# A substring this short does not reveal a value: ${TOKEN:0:8}.
MAX_SAFE_SUBSTRING = 8

_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_VARIABLE_RE = re.compile(
    r"\$(?:\{([#!]?)([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
_LOOP_VARIABLE_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# Reserved words that can come before a command on the same line, and the
# ones among them that open a block ("done < .env" closes it).
_KEYWORDS = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!", "{"})
_BLOCK_OPENERS = frozenset({"if", "while", "until", "{"})
_BLOCK_ENDS = frozenset({"done", "fi", "esac", "}"})
# Programs that run the rest of their arguments, with options of their own
# that take a value.
_WRAPPERS = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset(),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
}
# Programs that print the files named on their command line (or stdin).
_FILE_PRINTERS = frozenset(
    {
        "cat", "tac", "nl", "less", "more", "most", "bat", "batcat",
        "strings", "od", "xxd", "hexdump", "hd", "base64", "base32", "basenc",
        "sort", "uniq", "paste", "column", "fold", "fmt", "pr", "rev",
        "expand", "unexpand", "iconv", "jq", "yq", "diff", "colordiff",
        "sdiff", "comm", "join",
    }
)  # fmt: skip
# Of those, programs whose first operand is a filter unless an option gives it.
_SCRIPT_FIRST = {"jq": ("-f", "--from-file"), "yq": ()}
_AWKS = frozenset({"awk", "gawk", "mawk", "nawk"})
# Programs that copy stdin to stdout without naming input files.
_PASS_THROUGH = frozenset({"tee", "tr", "xargs"})
_GREPS = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "ack"})
_WALK_SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
        "target", ".skylos",
    }
)  # fmt: skip
# rg file types that include .env files.
_ENV_TYPES = frozenset({"all", "env", "dotenv"})


@dataclass(frozen=True)
class FileRead:
    """A file whose lines reach the output, through ``stages``.

    ``walked`` marks a file found by a recursive search of a directory.
    """

    path: Path
    stages: tuple[Stage, ...] = ()
    walked: bool = False

    def output(self, lines: Sequence[str]) -> list[Line]:
        return _run_stages(self.stages, lines)


@dataclass(frozen=True)
class EnvRead:
    """Environment variables that reach the output, through ``stages``.

    ``names`` None means every variable. ``style`` is how each variable is
    printed: "plain" (``NAME=value``: env, printenv, set), "declare"
    (``declare -x NAME="value"``: export -p, declare -p) or "value"
    (``echo $NAME``, ``printenv NAME``). ``sourced`` are files loaded into
    the environment earlier in the same command.
    """

    names: frozenset[str] | None
    style: str
    stages: tuple[Stage, ...] = ()
    sourced: tuple[Path, ...] = ()

    def output(self, lines: Sequence[str]) -> list[Line]:
        return _run_stages(self.stages, lines)


Read = Union[FileRead, EnvRead]


@dataclass
class ShellReads:
    files: list[FileRead] = field(default_factory=list)
    env: list[EnvRead] = field(default_factory=list)


def shell_reads(command: str, cwd: Path) -> ShellReads:
    """Files and variables ``command`` would print, run from ``cwd``."""
    parser = _Parser(cwd)
    parser.parse(command)
    reads = parser.reads[:MAX_READS]
    return ShellReads(
        files=[read for read in reads if isinstance(read, FileRead)],
        env=[read for read in reads if isinstance(read, EnvRead)],
    )


def _run_stages(stages: Sequence[Stage], lines: Sequence[str]) -> list[Line]:
    stream: list[Line] = list(enumerate(lines, 1))
    for stage in stages:
        if not stream:
            break
        stream = stage(stream)
    return stream


def _then(read: Read, *stages: Stage) -> Read:
    return dataclasses.replace(read, stages=read.stages + stages)


@dataclass
class _Effect:
    reads: list[Read] = field(default_factory=list)
    # What the command does with piped input on its way to the output;
    # None when the input goes nowhere visible (or is not read at all).
    stdin: Stage | None = None
    # Prints its arguments or input (echo, cat with no file): inside a
    # loop, the loop then prints what it reads.
    echoes: bool = False


@dataclass
class _Call:
    """One simple command, after prefixes such as ``sudo`` are removed."""

    program: str
    args: list[str]
    command: Command
    cwd: Path


class _Parser:
    def __init__(self, cwd: Path, depth: int = 0):
        self.cwd = cwd
        self.depth = depth
        self.reads: list[Read] = []
        self.sourced: list[Path] = []
        # Shell variables: assigned from command substitutions, assigned a
        # literal (the agent already knows it), and loop variables.
        self.variables: dict[str, list[Read]] = {}
        self.literals: set[str] = set()
        self.loop_words: dict[str, list[str]] = {}
        self.blocks: list[bool] = []  # per open block: does it echo?
        self.subshells: list[Path] = []
        self.bodies: list[str] = []

    def parse(self, command: str) -> None:
        text, self.bodies = prepare(command)
        for pipeline in pipelines(tokens(text)):
            self._pipeline(pipeline)

    def _pipeline(self, commands: list[Command]) -> None:
        effects = [self._effect(command) for command in commands]
        for index, effect in enumerate(effects):
            downstream: list[Stage] = []
            for later in effects[index + 1 :]:
                if later.stdin is None:
                    downstream.append(hide)
                    break
                downstream.append(later.stdin)
            self.reads.extend(_then(read, *downstream) for read in effect.reads)

    def _effect(self, command: Command) -> _Effect:
        effect = self._command_effect(command)
        if command.herestrings and effect.stdin is not None:
            # cat <<< "$TOKEN": the word is the command's input.
            fed = self._echo_reads(command.herestrings, self.cwd)[0]
            effect.reads.extend(_then(read, effect.stdin) for read in fed)
        if command.hidden:
            effect.reads = [_then(read, hide) for read in effect.reads]
            effect.stdin = None
        elif effect.echoes and self.blocks:
            self.blocks[-1] = True
        return effect

    def _command_effect(self, command: Command) -> _Effect:
        words = list(command.words)
        if words == [SUBSHELL_OPEN]:
            self.subshells.append(self.cwd)
            return _Effect()
        if words == [SUBSHELL_CLOSE]:
            if self.subshells:
                self.cwd = self.subshells.pop()
            return _Effect()
        while words and words[0] in _KEYWORDS:
            if words[0] in _BLOCK_OPENERS:
                self.blocks.append(False)
            words.pop(0)
        assignments = []
        while words and _ASSIGNMENT_RE.match(words[0]):
            assignments.append(words.pop(0))
        if not words:
            self._assign(assignments, self.cwd)
            return _Effect()
        call = _unwrap(words, command, self.cwd)
        if call is None:
            return _Effect()
        if call.program == "env":  # "env" alone lists the environment
            return self._env_effect(None, "plain")
        if SUBSTITUTION_RE.search(call.program):
            # The shell runs the output as a command; errors echo it back.
            return _Effect(reads=self._substituted([call.program], call.cwd))
        return self._dispatch(call)

    def _dispatch(self, call: _Call) -> _Effect:
        if call.program not in {"echo", "printf"}:
            # Only echo needs to tell '$X' (literal) from $X; scripts such
            # as awk '{print $1}' need their "$" back.
            args = [arg.replace(LITERAL_DOLLAR, "$") for arg in call.args]
            call = dataclasses.replace(call, args=args)
        handler = _HANDLERS.get(call.program)
        if handler is not None:
            return handler(self, call)
        if call.program in _GREPS:
            return self._grep(call)
        if call.program in _AWKS:
            return self._script_filter(call, awk_stage(call.args))
        if call.program == "sed":
            return self._script_filter(call, sed_stage(call.args))
        if call.program in _FILE_PRINTERS:
            return self._printer(call)
        if call.program in _PASS_THROUGH:
            effect = self._file_effect([], keep, call)
            effect.echoes = True
            return effect
        return _Effect()

    # -- handlers ---------------------------------------------------------

    def _cd(self, call: _Call) -> _Effect:
        operands = [arg for arg in call.args if not arg.startswith("-")]
        if operands and _plain(operands[-1]):
            self.cwd = _resolve(call.cwd, operands[-1])
        return _Effect()

    def _source(self, call: _Call) -> _Effect:
        if call.args and _plain(call.args[0]):
            self.sourced.append(_resolve(call.cwd, call.args[0]))
        return _Effect()

    def _shell(self, call: _Call) -> _Effect:
        script = _shell_script(call.args)
        if script is None:
            return _Effect()
        return _Effect(reads=self._nested(script, call.cwd))

    def _eval(self, call: _Call) -> _Effect:
        return _Effect(reads=self._nested(" ".join(call.args), call.cwd))

    def _for(self, call: _Call) -> _Effect:
        """``for NAME in WORDS``: remember the words for ``$NAME``."""
        self.blocks.append(False)
        if len(call.args) >= 2 and call.args[1] == "in":
            self.loop_words[call.args[0]] = call.args[2:]
        return _Effect()

    def _block_end(self, call: _Call) -> _Effect:
        echoes = self.blocks.pop() if self.blocks else True
        if not echoes:
            return _Effect()
        # "while read line; do echo "$line"; done < .env" prints it.
        return self._file_effect([], keep, call)

    def _echo(self, call: _Call) -> _Effect:
        reads, expands = self._echo_reads(call.args, call.cwd)
        return _Effect(reads=reads, echoes=expands)

    def _echo_reads(self, words: Sequence[str], cwd: Path) -> tuple[list[Read], bool]:
        """What printing ``words`` reads, and whether they expand anything
        (``echo found`` prints a constant, ``echo "$line"`` its input)."""
        reads = self._substituted(words, cwd)
        names = set()
        for word in words:
            names.update(_printed_variables(word))
        expands = bool(reads or names)
        names -= self.literals
        for name in sorted(names):
            reads.extend(self.variables.get(name, ()))
        if names:
            reads.append(self._env_read(frozenset(names), "value"))
        return reads, expands

    def _printenv(self, call: _Call) -> _Effect:
        names = frozenset(arg for arg in call.args if not arg.startswith("-"))
        return self._env_effect(names or None, "value" if names else "plain")

    def _env_lister(self, call: _Call) -> _Effect:
        args = call.args
        self._assign([arg for arg in args if _ASSIGNMENT_RE.match(arg)], call.cwd)
        for read in self._substituted(args, call.cwd):
            if isinstance(read, FileRead):  # export $(cat .env | xargs)
                self.sourced.append(read.path)
        operands = [arg for arg in args if not arg.startswith(("-", "+"))]
        if call.program == "set":
            return self._env_effect(None, "plain") if not args else _Effect()
        flags = "".join(arg[1:] for arg in args if arg.startswith("-"))
        if "f" in flags or "F" in flags:
            return _Effect()  # functions, not variables
        if not operands:  # export, export -p, declare -x
            return self._env_effect(None, "declare")
        names = [arg for arg in operands if re.fullmatch(r"[A-Za-z_]\w*", arg)]
        if names and "p" in flags:  # declare -p NAME
            return self._env_effect(frozenset(names), "declare")
        return _Effect()

    def _window(self, call: _Call) -> _Effect:
        stage = head_tail_stage(call.program, call.args)
        operands = _operands(call.args, value_options=frozenset({"-n", "-c"}))
        return self._file_effect(operands, stage, call)

    def _cut(self, call: _Call) -> _Effect:
        value_options = frozenset({"-d", "-f", "-b", "-c"})
        operands = _operands(call.args, value_options=value_options)
        return self._file_effect(operands, cut_stage(call.args), call)

    def _script_filter(self, call: _Call, parsed) -> _Effect:
        if parsed is None:
            return _Effect()  # edits files in place, prints nothing
        stage, operands = parsed
        return self._file_effect(operands, stage, call)

    def _printer(self, call: _Call) -> _Effect:
        operands = _operands(call.args)
        script_options = _SCRIPT_FIRST.get(call.program)
        if script_options is not None and not _has_option(call.args, script_options):
            operands = operands[1:]
        return self._file_effect(operands, keep, call)

    def _grep(self, call: _Call) -> _Effect:
        options, operands = grep_options(call.program, call.args)
        stage = hide if options.quiet else (grep_filter(options) or keep)
        tree = options.searches_tree
        if tree and not operands and not call.command.inputs:
            operands = ["."]
        if not operands and not call.command.inputs:
            return _Effect(stdin=stage)
        found: list[tuple[Path, str, bool]] = []
        reads: list[Read] = []
        for operand in operands or call.command.inputs:
            reads.extend(
                _then(r, stage) for r in self._substituted([operand], call.cwd)
            )
            for path in self._paths(operand, call.cwd):
                if tree and path.is_dir():
                    found.extend(
                        (each, os.path.relpath(each, call.cwd), True)
                        for each in _env_files_under(path, options)
                    )
                else:
                    found.append((path, operand, False))
        named = prefixes_names(options, len(found), any(w for _p, _l, w in found))
        for path, label, walked in found:
            stages = (stage, prefix_stage(label, options)) if named else (stage,)
            reads.append(FileRead(path, stages, walked))
        return _Effect(reads=reads)

    # -- helpers ----------------------------------------------------------

    def _file_effect(self, operands: list[str], stage: Stage, call: _Call) -> _Effect:
        sources = operands or call.command.inputs
        if not sources:
            return _Effect(stdin=stage, echoes=stage is keep)
        reads: list[Read] = []
        for operand in sources:
            for read in self._substituted([operand], call.cwd):
                reads.append(_then(read, stage))
            reads.extend(FileRead(p, (stage,)) for p in self._paths(operand, call.cwd))
        return _Effect(reads=reads, stdin=stage if "-" in operands else None)

    def _paths(self, word: str, cwd: Path) -> list[Path]:
        match = _LOOP_VARIABLE_RE.fullmatch(word)
        if match and match.group(1) in self.loop_words:
            words = self.loop_words[match.group(1)]
            return [path for each in words for path in _expand(each, cwd)]
        return _expand(word, cwd)

    def _nested(self, script: str, cwd: Path) -> list[Read]:
        if self.depth >= MAX_DEPTH:
            return []
        child = _Parser(cwd, self.depth + 1)
        child.sourced = list(self.sourced)
        child.parse(script)
        return child.reads

    def _substituted(self, words: Sequence[str], cwd: Path) -> list[Read]:
        """Reads of the substitutions whose output lands in ``words``."""
        numbers = [
            int(match.group(1))
            for word in words
            for match in SUBSTITUTION_RE.finditer(word)
        ]
        reads: list[Read] = []
        for number in numbers:
            if number < len(self.bodies):
                reads.extend(self._nested(self.bodies[number], cwd))
        return reads

    def _env_read(self, names: frozenset[str] | None, style: str) -> EnvRead:
        return EnvRead(names, style, (), tuple(self.sourced))

    def _env_effect(self, names: frozenset[str] | None, style: str) -> _Effect:
        return _Effect(reads=[self._env_read(names, style)])

    def _assign(self, assignments: Sequence[str], cwd: Path) -> None:
        for assignment in assignments:
            name, _, value = assignment.partition("=")
            reads = self._substituted([value], cwd)
            if reads:
                self.variables[name] = reads
                self.literals.discard(name)
            else:
                self.variables.pop(name, None)
                if "$" not in value:
                    self.literals.add(name)


_HANDLERS: dict[str, Callable[[_Parser, _Call], _Effect]] = {
    "cd": _Parser._cd,
    "pushd": _Parser._cd,
    "source": _Parser._source,
    ".": _Parser._source,
    "eval": _Parser._eval,
    "for": _Parser._for,
    "select": _Parser._for,
    "echo": _Parser._echo,
    "printf": _Parser._echo,
    "printenv": _Parser._printenv,
    "head": _Parser._window,
    "tail": _Parser._window,
    "cut": _Parser._cut,
    **{shell: _Parser._shell for shell in _SHELLS},
    **{
        lister: _Parser._env_lister
        for lister in ("export", "declare", "typeset", "set")
    },
    **{end: _Parser._block_end for end in _BLOCK_ENDS},
}


def _printed_variables(word: str) -> set[str]:
    """Variables whose value ``word`` prints when expanded."""
    names = set()
    for match in _VARIABLE_RE.finditer(word):
        prefix, braced, operation, bare = match.groups()
        if bare:
            names.add(bare)
            continue
        if prefix:  # ${#NAME} is a length, ${!NAME} an indirection
            continue
        if operation.startswith((":+", "+")):
            continue  # prints the alternative, not the value
        substring = re.fullmatch(r":\s*-?\d+\s*:\s*(\d+)", operation)
        if substring and int(substring.group(1)) <= MAX_SAFE_SUBSTRING:
            continue
        names.add(braced)
    return names


def _unwrap(words: list[str], command: Command, cwd: Path) -> _Call | None:
    """Strip ``sudo``, ``env VAR=1``, ``timeout 5`` and similar prefixes.
    None when nothing runs (or ``command -v`` only looks a name up); a
    bare ``env`` comes back as program "env"."""
    while words:
        program = os.path.basename(words[0])
        if program == "command":
            if any(word in {"-v", "-V"} for word in words):
                return None
            words = _skip_options(words[1:], frozenset())
        elif program in _WRAPPERS:
            words = _skip_options(words[1:], _WRAPPERS[program])
        elif program == "timeout":
            options = frozenset({"-s", "--signal", "-k", "--kill-after"})
            words = _skip_options(words[1:], options)[1:]  # then the duration
        elif program == "env":
            rest, cwd = _env_command(words[1:], cwd)
            if not rest:
                return _Call("env", [], command, cwd)
            words = rest
        else:
            return _Call(program, words[1:], command, cwd)
    return None


def _shell_script(args: Sequence[str]) -> str | None:
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
            return rest[0] if rest else None
        index += 1
    return None


def _skip_options(words: list[str], value_options: frozenset[str]) -> list[str]:
    index = 0
    while index < len(words) and words[index].startswith("-"):
        if words[index] == "--":
            return words[index + 1 :]
        index += 2 if words[index] in value_options else 1
    return words[index:]


def _env_command(args: list[str], cwd: Path) -> tuple[list[str], Path]:
    """The command ``env`` runs (empty when it lists the environment)."""
    rest = list(args)
    while rest and rest[0].startswith("-") and rest[0] != "-":
        option = rest.pop(0)
        if option == "--":
            break
        name, has_value, attached = option.partition("=")
        if name not in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}:
            continue
        value = attached if has_value else (rest.pop(0) if rest else "")
        if name in {"-C", "--chdir"} and _plain(value):
            cwd = _resolve(cwd, value)
        elif name in {"-S", "--split-string"}:
            rest = tokens(value) + rest
    while rest and _ASSIGNMENT_RE.match(rest[0]):
        rest.pop(0)
    return rest, cwd


def _operands(
    args: Sequence[str], value_options: frozenset[str] = frozenset()
) -> list[str]:
    operands: list[str] = []
    options_done = False
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif options_done or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            options_done = True
        elif arg in value_options:
            skip = True
    return operands


def _has_option(args: Sequence[str], options: Sequence[str]) -> bool:
    return any(
        arg == option
        or arg.startswith(option + "=")
        or (len(option) == 2 and arg.startswith(option))  # -e's/a/b/'
        for arg in args
        for option in options
    )


def _plain(word: str) -> bool:
    """A literal path: no unexpanded variable or substitution."""
    return (
        bool(word)
        and word != "-"
        and "$" not in word
        and not SUBSTITUTION_RE.search(word)
    )


def _resolve(cwd: Path, word: str) -> Path:
    path = Path(os.path.expanduser(word))
    return path if path.is_absolute() else cwd / path


_BRACE_RE = re.compile(r"\{([^{}]*,[^{}]*)\}")
_HOME_VARIABLE_RE = re.compile(r"\$\{?(PWD|HOME)\}?(?![A-Za-z0-9_])")


def _expand(word: str, cwd: Path) -> list[Path]:
    word = _HOME_VARIABLE_RE.sub(
        lambda m: str(cwd) if m.group(1) == "PWD" else os.path.expanduser("~"), word
    )
    brace = _BRACE_RE.search(word)
    if brace:  # .env{,.production}
        return [
            path
            for option in brace.group(1).split(",")
            for path in _expand(
                word[: brace.start()] + option + word[brace.end() :], cwd
            )
        ][:MAX_GLOB_MATCHES]
    if not _plain(word):
        return []
    expanded = os.path.expanduser(word)
    if any(char in expanded for char in "*?["):
        pattern = (
            expanded
            if os.path.isabs(expanded)
            else os.path.join(glob.escape(str(cwd)), expanded)
        )
        matches = sorted(itertools.islice(glob.iglob(pattern), MAX_GLOB_MATCHES))
        if matches:
            return [Path(match) for match in matches]
    return [_resolve(cwd, expanded)]


def _env_files_under(directory: Path, options: GrepOptions) -> list[Path]:
    """``.env*`` files a recursive search of ``directory`` would print
    from, within a fixed budget."""
    if options.types and not _ENV_TYPES.intersection(options.types):
        return []
    found: list[Path] = []
    seen = 0
    for current, dirs, files in os.walk(directory):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _WALK_SKIP_DIRS
            and not any(fnmatch.fnmatch(d, g) for g in options.exclude_dirs)
        )
        seen += len(dirs) + len(files)
        found.extend(
            Path(current, name)
            for name in sorted(files)
            if name.startswith(".env") and _glob_allows(name, options.globs)
        )
        if seen > MAX_WALK_ENTRIES or len(found) >= MAX_WALK_FILES:
            break
    found = found[:MAX_WALK_FILES]
    if found and options.respects_ignore:
        ignored = _git_ignored(directory, found)
        found = [path for path in found if path not in ignored]
    return found


def _git_ignored(directory: Path, paths: list[Path]) -> set[Path]:
    """The paths Git ignores (none if Git cannot say)."""
    from skylos.core.git_safety import read_only_git_command

    try:
        result = subprocess.run(
            read_only_git_command(["check-ignore", "--stdin", "-z"]),
            input="\0".join(str(path) for path in paths) + "\0",
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(directory),
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode not in {0, 1}:
        return set()
    return {Path(item) for item in result.stdout.split("\0") if item}


def _glob_allows(name: str, globs: Sequence[tuple[str, bool]]) -> bool:
    includes = [pattern for pattern, include in globs if include]
    excludes = [pattern for pattern, include in globs if not include]
    if includes and not any(fnmatch.fnmatch(name, p) for p in includes):
        return False
    return not any(fnmatch.fnmatch(name, p) for p in excludes)
