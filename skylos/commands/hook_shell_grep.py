"""What ``grep``, ``rg``, ``ag`` and ``ack`` print.

Used by :mod:`skylos.commands.hook_shell_reads` so that ``grep PORT .env`` is
allowed when the PORT line holds no secret. When a pattern or an option is
unclear the filter is not built, and the caller assumes every line shows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Sequence

from skylos.commands.hook_shell_filters import Line, Stage, posix_regex

# Short flags that set an option, per tool. Other letters are ignored.
_SHORT_FLAGS = {
    "grep": {
        "c": "quiet", "l": "quiet", "L": "quiet", "q": "quiet",
        "v": "invert", "i": "ignore_case", "y": "ignore_case",
        "F": "fixed", "E": "extended", "P": "perl", "w": "word", "x": "line",
        "r": "recursive", "R": "recursive", "o": "only_matching",
        "H": "with_filename", "h": "no_filename", "n": "line_number",
    },
    "rg": {
        "c": "quiet", "l": "quiet", "q": "quiet", "v": "invert",
        "i": "ignore_case", "S": "smart_case", "F": "fixed", "w": "word",
        "x": "line", ".": "hidden", "o": "only_matching",
        "H": "with_filename", "I": "no_filename", "n": "line_number",
    },
    "ag": {
        "c": "quiet", "l": "quiet", "L": "quiet", "v": "invert",
        "i": "ignore_case", "S": "smart_case", "Q": "fixed", "w": "word",
        "x": "line", "o": "only_matching", "U": "no_ignore",
    },
    "ack": {
        "c": "quiet", "l": "quiet", "L": "quiet", "v": "invert",
        "i": "ignore_case", "Q": "fixed", "w": "word", "x": "line",
        "o": "only_matching", "H": "with_filename", "h": "no_filename",
    },
}  # fmt: skip
# Short options that take a value, per tool.
_SHORT_VALUES = {
    "grep": "ABCefmdD",
    "rg": "ABCefgmtTjMrEd",
    "ag": "ABCGgmp",
    "ack": "ABCgm",
}
_LONG_FLAGS = {
    "--count": "quiet",
    "--count-matches": "quiet",
    "--files": "quiet",
    "--files-with-matches": "quiet",
    "--files-without-match": "quiet",
    "--files-without-matches": "quiet",
    "--quiet": "quiet",
    "--silent": "quiet",
    "--invert-match": "invert",
    "--ignore-case": "ignore_case",
    "--smart-case": "smart_case",
    "--fixed-strings": "fixed",
    "--literal": "fixed",
    "--extended-regexp": "extended",
    "--perl-regexp": "perl",
    "--word-regexp": "word",
    "--line-regexp": "line",
    "--line-regex": "line",
    "--recursive": "recursive",
    "--dereference-recursive": "recursive",
    "--hidden": "hidden",
    "--only-matching": "only_matching",
    "--with-filename": "with_filename",
    "--no-filename": "no_filename",
    "--line-number": "line_number",
    "--no-ignore": "no_ignore",
    "--no-ignore-vcs": "no_ignore",
    "--skip-vcs-ignores": "no_ignore",
}
# Long options that take a value; without "=" it is the next argument.
_LONG_VALUES = frozenset(
    {
        "--regexp", "--file", "--context", "--before-context",
        "--after-context", "--max-count", "--include", "--exclude",
        "--exclude-dir", "--exclude-from", "--label", "--binary-files",
        "--devices", "--directories", "--group-separator", "--glob",
        "--iglob", "--type", "--type-not", "--type-add", "--type-clear",
        "--max-depth", "--maxdepth", "--replace", "--encoding",
        "--max-columns", "--max-filesize", "--sort", "--sortr", "--threads",
        "--colors", "--context-separator", "--path-separator", "--pre",
        "--pre-glob", "--ignore-file", "--engine", "--file-search-regex",
        "--ignore", "--ignore-dir",
    }
)  # fmt: skip
_COLOR_VALUES = frozenset({"never", "auto", "always", "ansi"})


@dataclass
class GrepOptions:
    tool: str = "grep"
    patterns: list[str] = field(default_factory=list)
    pattern_file: bool = False
    quiet: bool = False  # prints counts or file names, not lines
    invert: bool = False
    ignore_case: bool = False
    smart_case: bool = False
    fixed: bool = False
    extended: bool = False
    perl: bool = False
    word: bool = False
    line: bool = False
    only_matching: bool = False
    with_filename: bool = False
    no_filename: bool = False
    line_number: bool = False
    before: int | None = 0  # None: a context we could not read
    after: int | None = 0
    recursive: bool = False  # grep -r: reads hidden and ignored files
    hidden: bool = False  # rg/ag told to search hidden files
    no_ignore: bool = False  # rg/ag told to search ignored files
    unrestricted: int = 0
    globs: list[tuple[str, bool]] = field(default_factory=list)  # (glob, include)
    exclude_dirs: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)

    @property
    def searches_tree(self) -> bool:
        """Whether a directory operand is searched for hidden files."""
        if self.tool == "grep":
            return self.recursive
        if self.tool == "rg":
            return self.hidden or self.unrestricted >= 2
        return self.hidden or self.unrestricted >= 1

    @property
    def respects_ignore(self) -> bool:
        """rg and ag skip files Git ignores unless told otherwise."""
        if self.tool == "grep" or self.no_ignore:
            return False
        return self.unrestricted == 0


def grep_options(program: str, args: Sequence[str]) -> tuple[GrepOptions, list[str]]:
    """Parsed options and the file operands (the pattern removed)."""
    tool = "grep" if program in {"grep", "egrep", "fgrep"} else program
    options = GrepOptions(
        tool=tool,
        extended=program not in {"grep", "fgrep"},
        perl=tool != "grep",
        fixed=program == "fgrep",
        smart_case=program == "ag",
    )
    positional: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            positional.extend(args[index:])
            break
        if arg.startswith("--"):
            index = _long_option(options, arg, args, index)
        elif arg == "-" or not arg.startswith("-"):
            positional.append(arg)
        elif tool == "grep" and re.fullmatch(r"-\d+", arg):
            options.before = options.after = int(arg[1:])
        else:
            index = _short_options(options, arg[1:], args, index)
    if not options.patterns and not options.pattern_file and positional:
        options.patterns.append(positional.pop(0))
    return options, positional


def grep_filter(options: GrepOptions) -> Stage | None:
    """A stage giving what grep prints from its input, or None when every
    line may show unchanged (unknown pattern, pattern file, odd context)."""
    compiled = [_compile(pattern, options) for pattern in options.patterns]
    before, after = options.before, options.after
    if (
        options.pattern_file
        or not compiled
        or any(regex is None for regex in compiled)
        or before is None
        or after is None
    ):
        return None

    def stage(stream: list[Line]) -> list[Line]:
        hits = [
            position
            for position, (_number, text) in enumerate(stream)
            if any(regex.search(text) for regex in compiled) != options.invert
        ]
        if options.only_matching:
            if options.invert:
                return []
            return [
                (stream[p][0], "\n".join(_matches(compiled, stream[p][1])))
                for p in hits
            ]
        keep: set[int] = set()
        for position in hits:
            low = max(0, position - before)
            high = min(len(stream), position + after + 1)
            keep.update(range(low, high))
        return [stream[p] for p in sorted(keep)]

    return stage


def prefixes_names(options: GrepOptions, file_count: int, walked: bool) -> bool:
    """Whether output lines start with the file name."""
    if options.no_filename:
        return False
    return options.with_filename or walked or file_count > 1


def prefix_stage(label: str, options: GrepOptions) -> Stage:
    def stage(stream: list[Line]) -> list[Line]:
        return [
            (n, f"{label}:{n}:{t}" if options.line_number else f"{label}:{t}")
            for n, t in stream
        ]

    return stage


def _matches(compiled: list[re.Pattern], text: str) -> list[str]:
    return [
        m.group(0) for regex in compiled for m in regex.finditer(text) if m.group(0)
    ]


def _long_option(
    options: GrepOptions, arg: str, args: Sequence[str], index: int
) -> int:
    name, has_value, value = arg.partition("=")
    if not has_value and index < len(args):
        if name in _LONG_VALUES or (
            name in {"--color", "--colour"} and args[index] in _COLOR_VALUES
        ):
            value = args[index]
            index += 1
    if name in _LONG_FLAGS:
        setattr(options, _LONG_FLAGS[name], True)
    elif name == "--unrestricted":
        options.unrestricted += 1
    else:
        _set_value(options, name, value)
    return index


def _short_options(
    options: GrepOptions, letters: str, args: Sequence[str], index: int
) -> int:
    flags = _SHORT_FLAGS[options.tool]
    for position, letter in enumerate(letters):
        if letter in _SHORT_VALUES[options.tool]:
            value = letters[position + 1 :]
            if not value:
                value = args[index] if index < len(args) else ""
                index += 1
            _set_value(options, "-" + letter, value)
            return index
        if letter == "u" and options.tool in {"rg", "ag"}:
            options.unrestricted += 1
        elif letter in flags:
            setattr(options, flags[letter], True)
    return index


def _set_value(options: GrepOptions, name: str, value: str) -> None:
    rg = options.tool == "rg"
    if name in {"-e", "--regexp"}:
        options.patterns.append(value)
    elif name in {"-f", "--file"}:
        options.pattern_file = True
    elif name in {"-A", "--after-context"}:
        options.after = _number(value)
    elif name in {"-B", "--before-context"}:
        options.before = _number(value)
    elif name in {"-C", "--context"}:
        options.before = options.after = _number(value)
    elif name in {"--include", "--glob", "--iglob"} or (name == "-g" and rg):
        _add_glob(options, value)
    elif name == "--exclude":
        options.globs.append((value, False))
    elif name == "--exclude-dir":
        options.exclude_dirs.append(value)
    elif name in {"-t", "--type"} and rg:
        options.types.append(value)


def _add_glob(options: GrepOptions, value: str) -> None:
    if value.startswith("!"):
        options.globs.append((value[1:], False))
    else:
        options.globs.append((value, True))


def _number(value: str | None) -> int | None:
    return int(value) if value is not None and value.isdigit() else None


def _compile(pattern: str, options: GrepOptions) -> re.Pattern | None:
    """The pattern as a Python regex, or None when its meaning is unclear."""
    ignore_case = options.ignore_case or (
        options.smart_case and pattern == pattern.lower()
    )
    if options.fixed:
        source = re.escape(pattern)
    else:
        regex = posix_regex(pattern, extended=options.extended, perl=options.perl)
        if regex is None:
            return None
        source = regex.pattern
    if options.word:
        source = rf"(?<![A-Za-z0-9_])(?:{source})(?![A-Za-z0-9_])"
    if options.line:
        source = rf"^(?:{source})$"
    try:
        return re.compile(source, re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None
