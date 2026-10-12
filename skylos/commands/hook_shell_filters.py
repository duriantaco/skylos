"""Text filters for :mod:`skylos.commands.hook_shell_reads`.

Each stage takes the output so far, as (source line number, printed text)
pairs, and returns what the program prints. ``head``/``tail``, ``cut``,
``sed`` and ``awk`` are modelled for the forms agents use to read part of a
file or mask values (``sed -n '10,40p'``, ``sed 's/=.*//'``,
``awk -F= '{print $1}'``, ``cut -d= -f1``). A script outside that subset
passes every line through unchanged, so an unknown filter never hides a
secret.
"""

from __future__ import annotations

import re
from typing import Callable, Sequence

Line = tuple[int, str]
Stage = Callable[[list[Line]], list[Line]]

_POSIX_CLASSES = {
    "alpha": "a-zA-Z",
    "digit": "0-9",
    "alnum": "a-zA-Z0-9",
    "upper": "A-Z",
    "lower": "a-z",
    "space": r"\s",
    "blank": r" \t",
    "xdigit": "0-9A-Fa-f",
    "punct": re.escape("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    "word": r"\w",
}
_LITERAL_ESCAPES = ".[]*^$\\/-'\""
_PERL_ESCAPES = "wWsSdDbB"


def hide(stream: list[Line]) -> list[Line]:
    return []  # skylos: ignore[SKY-L026] the stage that drops all output


def keep(stream: list[Line]) -> list[Line]:
    return stream


# --------------------------------------------------------------------------
# Regular expressions
# --------------------------------------------------------------------------


def posix_regex(
    pattern: str, *, extended: bool, perl: bool = False, ignore_case: bool = False
) -> re.Pattern | None:
    """A POSIX basic/extended (or Perl-style) regex as a Python regex, or
    None when part of it has no clear Python equivalent."""
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            piece = _escape(pattern[index + 1 : index + 2], extended, perl)
            index += 2
        elif char == "[":
            end = _bracket_end(pattern, index)
            piece = None if end is None else _bracket(pattern[index : end + 1])
            index = len(pattern) if end is None else end + 1
        elif not extended and char in "+?|(){}":
            piece = "\\" + char  # literal in a basic regex
            index += 1
        else:
            piece = char
            index += 1
        if piece is None:
            return None
        out.append(piece)
    try:
        return re.compile("".join(out), re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None


def _escape(char: str, extended: bool, perl: bool) -> str | None:
    if not char:
        return None
    if char in _LITERAL_ESCAPES:
        return "\\" + char
    if char in "+?|(){}":
        return "\\" + char if extended else char  # GNU basic-regex operators
    if char in "<>":
        return r"\b"
    if char.isdigit() or char in "wWsSbB" or (perl and char in _PERL_ESCAPES):
        return "\\" + char
    if perl and char in "tn":
        return "\\" + char
    return None


def _bracket_end(pattern: str, start: int) -> int | None:
    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern):
        if pattern.startswith("[:", index):
            close = pattern.find(":]", index + 2)
            if close < 0:
                return None
            index = close + 2
            continue
        if pattern[index] == "]":
            return index
        index += 1
    return None


def _bracket(body: str) -> str | None:
    """A POSIX bracket expression (backslash is literal) for Python."""
    inner = body[1:-1]
    negate = inner.startswith("^")
    if negate:
        inner = inner[1:]
    parts: list[str] = []
    index = 0
    while index < len(inner):
        if inner.startswith("[:", index):
            close = inner.find(":]", index)
            name = inner[index + 2 : close]
            if name not in _POSIX_CLASSES:
                return None
            parts.append(_POSIX_CLASSES[name])
            index = close + 2
            continue
        if inner.startswith(("[.", "[="), index):
            return None
        char = inner[index]
        parts.append("\\" + char if char in "\\[]^" else char)
        index += 1
    return "[" + ("^" if negate else "") + "".join(parts) + "]"


# --------------------------------------------------------------------------
# head, tail, cut
# --------------------------------------------------------------------------


def head_tail_stage(program: str, args: Sequence[str]) -> Stage:
    chars = option_value(args, "-c", "--bytes")
    if chars is not None:
        return _byte_window(program, chars)
    count = _head_tail_count(args) or ""
    from_line = program == "tail" and count.startswith("+")
    digits = count[1:] if from_line else count
    if not digits.isdigit():
        return keep  # "head -n -5", byte counts: assume every line shows
    number = int(digits)
    if from_line:
        return lambda stream: stream[max(number - 1, 0) :]
    if program == "head":
        return lambda stream: stream[:number]
    return lambda stream: stream[-number:] if number else []


def _byte_window(program: str, count: str) -> Stage:
    """``head -c N`` / ``tail -c N``, counting characters as bytes."""
    if not count.isdigit():
        return keep
    limit = int(count)

    def stage(stream: list[Line]) -> list[Line]:
        ordered = stream if program == "head" else list(reversed(stream))
        out, left = [], limit
        for number, text in ordered:
            if left <= 0:
                break
            piece = text[:left] if program == "head" else text[-left:]
            out.append((number, piece))
            left -= len(text) + 1
        return out if program == "head" else list(reversed(out))

    return stage


def _head_tail_count(args: Sequence[str]) -> str | None:
    """The -n count as written ("10" by default), or None for a byte count
    or a count that could not be read."""
    count: str | None = "10"
    for index, arg in enumerate(args):
        if arg in {"-c", "--bytes"} or arg.startswith(("-c", "--bytes=")):
            return None
        if arg in {"-n", "--lines"}:
            count = args[index + 1] if index + 1 < len(args) else None
        elif arg.startswith("--lines="):
            count = arg.split("=", 1)[1]
        elif arg.startswith("-n"):
            count = arg[2:]
        elif re.fullmatch(r"-\d+", arg):
            count = arg[1:]
    return count


def option_value(args: Sequence[str], short: str, long: str) -> str | None:
    value = None
    for index, arg in enumerate(args):
        if arg in {short, long}:
            value = args[index + 1] if index + 1 < len(args) else None
        elif arg.startswith(long + "="):
            value = arg[len(long) + 1 :]
        elif (
            short
            and arg.startswith(short)
            and not arg.startswith("--")
            and len(arg) > 2
        ):
            value = arg[2:]
    return value


def _ranges(spec: str | None) -> list[tuple[int, int]] | None:
    """A cut LIST ("1", "1,3", "2-", "-4") as inclusive 1-based ranges."""
    if not spec:
        return None
    ranges = []
    for item in spec.split(","):
        match = re.fullmatch(r"(\d*)(-?)(\d*)", item)
        if not match or not (match.group(1) or match.group(3)):
            return None
        low = int(match.group(1) or 1)
        high = int(match.group(3)) if match.group(3) else None
        if not match.group(2):
            high = low
        ranges.append((low, high if high is not None else 1 << 30))
    return ranges


def _pick(items: Sequence[str], ranges: list[tuple[int, int]]) -> list[str]:
    return [
        item
        for position, item in enumerate(items, 1)
        if any(low <= position <= high for low, high in ranges)
    ]


def cut_stage(args: Sequence[str]) -> Stage:
    if any(arg == "--complement" for arg in args):
        return keep
    fields = _ranges(option_value(args, "-f", "--fields"))
    chars = _ranges(
        option_value(args, "-c", "--characters") or option_value(args, "-b", "--bytes")
    )
    delimiter = option_value(args, "-d", "--delimiter")
    delimiter = "\t" if delimiter is None else delimiter
    joiner = option_value(args, "", "--output-delimiter")
    only_delimited = any(arg in {"-s", "--only-delimited"} for arg in args)
    if fields is not None and len(delimiter) == 1:
        joined = delimiter if joiner is None else joiner

        def by_field(stream: list[Line]) -> list[Line]:
            out = []
            for number, text in stream:
                if delimiter not in text:
                    if not only_delimited:
                        out.append((number, text))
                    continue
                out.append((number, joined.join(_pick(text.split(delimiter), fields))))
            return out

        return by_field
    if chars is not None:
        return lambda stream: [(n, "".join(_pick(list(t), chars))) for n, t in stream]
    return keep


# --------------------------------------------------------------------------
# sed
# --------------------------------------------------------------------------


class _Unsupported(Exception):
    pass


def sed_stage(args: Sequence[str]) -> tuple[Stage, list[str]] | None:
    """The stage and file operands for a sed command; None when it edits
    files in place (and prints nothing)."""
    quiet = extended = False
    scripts: list[str] = []
    files: list[str] = []
    unknown = False
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg in {"-n", "--quiet", "--silent"}:
            quiet = True
        elif arg in {"-E", "-r", "--regexp-extended"}:
            extended = True
        elif arg == "--in-place" or arg.startswith("--in-place="):
            return None
        elif arg in {"-e", "--expression"} or arg.startswith("--expression="):
            if "=" in arg:
                scripts.append(arg.split("=", 1)[1])
            elif index < len(args):
                scripts.append(args[index])
                index += 1
        elif arg in {"-f", "--file"} or arg.startswith(
            ("--file=", "-z", "--null-data")
        ):
            unknown = True
            index += 1 if arg in {"-f", "--file"} else 0
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            state = _sed_short(arg[1:], args, index)
            if state is None:
                return None
            index, flags, script = state
            quiet |= "n" in flags
            extended |= "E" in flags or "r" in flags
            unknown |= "f" in flags or "z" in flags
            if script is not None:
                scripts.append(script)
        elif arg.startswith("--") and arg != "--":
            continue
        else:
            files.append(arg)
    if not scripts and files:
        scripts.append(files.pop(0))
    if unknown or not scripts:
        return keep, files
    try:
        commands = _sed_parse("\n".join(scripts), extended)
    except _Unsupported:
        return keep, files
    return _sed_runner(commands, quiet), files


def _sed_short(
    letters: str, args: Sequence[str], index: int
) -> tuple[int, str, str | None] | None:
    """Parse a short-option cluster: (next index, flag letters, script)."""
    flags = ""
    for position, letter in enumerate(letters):
        if letter == "i":
            return None  # -i[SUFFIX]: in place
        if letter in "efl":
            value = letters[position + 1 :]
            if not value and index < len(args):
                value = args[index]
                index += 1
            return index, flags + letter, value if letter == "e" else None
        flags += letter
    return index, flags, None


def _sed_parse(script: str, extended: bool) -> list[tuple]:
    commands = []
    index = 0
    while index < len(script):
        char = script[index]
        if char in " \t\n;":
            index += 1
            continue
        first, index = _sed_address(script, index, extended)
        second = None
        if first is not None and script.startswith(",", index):
            second, index = _sed_address(script, index + 1, extended)
            if second is None:
                raise _Unsupported
        while script.startswith(" ", index):
            index += 1
        negate = script.startswith("!", index)
        index += 1 if negate else 0
        if index >= len(script):
            raise _Unsupported
        name = script[index]
        index += 1
        if name in "pdq=":
            commands.append((first, second, negate, name, None))
        elif name == "s":
            substitution, index = _sed_substitution(script, index, extended)
            commands.append((first, second, negate, "s", substitution))
        else:
            raise _Unsupported
    return commands


def _sed_address(script: str, index: int, extended: bool):
    if script.startswith("$", index):
        return ("last",), index + 1
    match = re.match(r"\+?\d+", script[index:])
    if match:
        token = match.group(0)
        kind = "plus" if token.startswith("+") else "line"
        return (kind, int(token.lstrip("+"))), index + len(token)
    if script.startswith("/", index):
        end = _delimited_end(script, index + 1, "/")
        regex = posix_regex(script[index + 1 : end], extended=extended)
        if regex is None:
            raise _Unsupported
        flags = 0
        if script.startswith("I", end + 1):
            regex = re.compile(regex.pattern, re.IGNORECASE)
            flags = 1
        return ("regex", regex), end + 1 + flags
    return None, index


def _delimited_end(script: str, index: int, delimiter: str) -> int:
    while index < len(script):
        if script[index] == "\\":
            index += 2
            continue
        if script[index] == delimiter:
            return index
        index += 1
    raise _Unsupported


def _sed_substitution(script: str, index: int, extended: bool):
    if index >= len(script) or script[index] in "\\\n":
        raise _Unsupported
    delimiter = script[index]
    middle = _delimited_end(script, index + 1, delimiter)
    end = _delimited_end(script, middle + 1, delimiter)
    source = script[index + 1 : middle]
    if delimiter != "/":
        source = source.replace("\\" + delimiter, delimiter)
    flags_match = re.match(r"[gpiI0-9]*", script[end + 1 :])
    flags = flags_match.group(0) if flags_match else ""
    regex = posix_regex(
        source, extended=extended, ignore_case="I" in flags or "i" in flags
    )
    if regex is None:
        raise _Unsupported
    replace = _sed_replacement(script[middle + 1 : end])
    count = int(re.sub(r"\D", "", flags) or 0)
    return (regex, replace, "g" in flags, count, "p" in flags), end + 1 + len(flags)


def _sed_replacement(text: str) -> Callable[[re.Match], str]:
    pieces: list[str | int] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            if following.isdigit():
                pieces.append(int(following))
            else:
                pieces.append("\n" if following == "n" else following)
            index += 2
            continue
        pieces.append(0 if char == "&" else char)
        index += 1

    def render(match: re.Match) -> str:
        return "".join(
            (match.group(p) or "") if isinstance(p, int) else p for p in pieces
        )

    return render


def _sed_runner(commands: list[tuple], quiet: bool) -> Stage:
    def run(stream: list[Line]) -> list[Line]:
        out: list[Line] = []
        active = [False] * len(commands)
        last = len(stream)
        for position, (number, text) in enumerate(stream, 1):
            deleted = False
            for slot, (first, second, negate, name, data) in enumerate(commands):
                hit = _sed_selects(first, second, position, last, text, active, slot)
                if hit == negate:
                    continue
                if name == "p":
                    out.append((number, text))
                elif name == "=":
                    out.append((number, str(position)))
                elif name == "d":
                    deleted = True
                    break
                elif name == "q":
                    if not quiet:
                        out.append((number, text))
                    return out
                else:
                    text = _sed_substitute(text, data, out, number)
            if not quiet and not deleted:
                out.append((number, text))
        return out

    return run


def _sed_selects(first, second, position, last, text, active, slot) -> bool:
    if first is None:
        return True
    if second is None:
        return _sed_matches(first, position, last, text)
    if active[slot]:
        if second[0] == "plus":
            done = position >= active[slot]
        else:
            done = _sed_matches(second, position, last, text) or (
                second[0] == "line" and position >= second[1]
            )
        if done:
            active[slot] = False
        return True
    if _sed_matches(first, position, last, text):
        if second[0] == "plus":
            active[slot] = position + second[1] if second[1] else False
        elif not (second[0] == "line" and second[1] <= position):
            active[slot] = True
        return True
    return False


def _sed_matches(address, position: int, last: int, text: str) -> bool:
    kind = address[0]
    if kind == "last":
        return position == last
    if kind == "line":
        return position == address[1]
    if kind == "regex":
        return bool(address[1].search(text))
    return False


def _sed_substitute(text: str, data, out: list[Line], number: int) -> str:
    regex, replace, every, count, print_it = data
    seen = 0

    def one(match: re.Match) -> str:
        nonlocal seen
        seen += 1
        if every or (count and seen == count) or (not count and seen == 1):
            return replace(match)
        return match.group(0)

    new, made = regex.subn(one, text)
    if made and print_it:
        out.append((number, new))
    return new


# --------------------------------------------------------------------------
# awk
# --------------------------------------------------------------------------

_AWK_COUNT = re.compile(r"(NR|NF)\s*(==|!=|>=|<=|>|<)\s*(\d+)")
_AWK_FIELD_MATCH = re.compile(r"\$(\d+)\s*(!?~)\s*/((?:\\.|[^/\\])*)/")
_AWK_REGEX = re.compile(r"(!?)\s*/((?:\\.|[^/\\])*)/")


def awk_stage(args: Sequence[str]) -> tuple[Stage, list[str]] | None:
    """The stage and file operands for an awk command; None for gawk
    ``-i inplace`` (prints nothing)."""
    separator = None
    script = None
    files: list[str] = []
    unknown = False
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        value = args[index] if index < len(args) else ""
        if arg in {"-F", "--field-separator"}:
            separator, index = value, index + 1
        elif arg.startswith("--field-separator="):
            separator = arg.split("=", 1)[1]
        elif arg.startswith("-F"):
            separator = arg[2:]
        elif arg == "-i" and value == "inplace":
            return None
        elif arg in {"-v", "--assign", "-i", "--include"}:
            index += 1
        elif arg in {"-f", "--file", "-e", "--source"}:
            unknown, index = True, index + 1
        elif arg.startswith("-") and arg != "-":
            continue
        elif script is None:
            script = arg
        elif not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", arg):
            files.append(arg)
    if unknown or script is None:
        return keep, files
    rules = _awk_rules(script)
    split = _awk_splitter(separator)
    if rules is None or split is None:
        return keep, files
    return _awk_runner(rules, split), files


def _awk_splitter(separator: str | None) -> Callable[[str], list[str]] | None:
    if separator is None or separator == " ":
        return str.split
    separator = separator.replace("\\t", "\t")
    if len(separator) == 1:
        return lambda text: text.split(separator)
    regex = posix_regex(separator, extended=True)
    return None if regex is None else regex.split


def _awk_rules(script: str):
    """[(pattern test, actions)] for the supported subset, else None."""
    rules = []
    rest = script.strip()
    while rest:
        brace = rest.find("{")
        if brace < 0:
            pattern, body, rest = rest, "print", ""
        else:
            close = rest.find("}", brace)
            if close < 0:
                return None
            pattern, body = rest[:brace].strip(), rest[brace + 1 : close]
            rest = rest[close + 1 :].strip().lstrip(";").strip()
        if pattern in {"BEGIN", "END"}:
            if "$" in body:  # END { print $0 } prints the last line
                return None
            continue
        test = _awk_pattern(pattern.strip())
        actions = _awk_actions(body)
        if test is None or actions is None:
            return None
        rules.append((test, actions))
    return rules


def _awk_pattern(pattern: str):
    if not pattern:
        return lambda position, text, fields: True
    tests = []
    for part in pattern.split("&&"):
        test = _awk_condition(part.strip())
        if test is None:
            return None
        tests.append(test)
    return lambda position, text, fields: all(t(position, text, fields) for t in tests)


_COMPARE = {
    "==": int.__eq__,
    "!=": int.__ne__,
    ">=": int.__ge__,
    "<=": int.__le__,
    ">": int.__gt__,
    "<": int.__lt__,
}


def _awk_condition(part: str):
    if part == "NF":
        return lambda position, text, fields: bool(fields)
    match = _AWK_COUNT.fullmatch(part)
    if match:
        counter, compare = match.group(1), _COMPARE[match.group(2)]
        value = int(match.group(3))
        if counter == "NF":
            return lambda position, text, fields: compare(len(fields), value)
        return lambda position, text, fields: compare(position, value)
    match = _AWK_FIELD_MATCH.fullmatch(part)
    if match:
        column, negate = int(match.group(1)), match.group(2) == "!~"
        regex = posix_regex(match.group(3), extended=True)
        if regex is None:
            return None
        return lambda position, text, fields: (
            bool(regex.search(_field(text, fields, column))) != negate
        )
    match = _AWK_REGEX.fullmatch(part)
    if match:
        negate = match.group(1) == "!"
        regex = posix_regex(match.group(2), extended=True)
        if regex is None:
            return None
        return lambda position, text, fields: bool(regex.search(text)) != negate
    return None


def _awk_actions(body: str):
    actions = []
    for statement in re.split(r"[;\n]", body):
        statement = statement.strip()
        if not statement:
            continue
        if statement == "next":
            actions.append(None)
            continue
        if statement in {"print", "print $0"}:
            actions.append([[0]])
            continue
        match = re.fullmatch(r"print\s+(.+)", statement)
        if not match:
            return None
        items = []
        for item in match.group(1).split(","):
            terms = re.findall(r'\$\d+|"[^"]*"|\S+', item.strip())
            parsed = []
            for term in terms:
                if re.fullmatch(r"\$\d+", term):
                    parsed.append(int(term[1:]))
                elif term.startswith('"'):
                    parsed.append(term[1:-1])
                else:
                    return None
            items.append(parsed)
        actions.append(items)
    return actions


def _field(text: str, fields: list[str], column: int) -> str:
    if column == 0:
        return text
    return fields[column - 1] if 0 < column <= len(fields) else ""


def _awk_runner(rules, split) -> Stage:
    def run(stream: list[Line]) -> list[Line]:
        out: list[Line] = []
        for position, (number, text) in enumerate(stream, 1):
            fields = split(text)
            for test, actions in rules:
                if not test(position, text, fields):
                    continue
                stop = False
                for items in actions:
                    if items is None:
                        stop = True
                        break
                    printed = " ".join(
                        "".join(
                            term
                            if isinstance(term, str)
                            else _field(text, fields, term)
                            for term in item
                        )
                        for item in items
                    )
                    out.append((number, printed))
                if stop:
                    break
        return out

    return run
