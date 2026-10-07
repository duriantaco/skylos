"""SKY-A118: inline suppressions the change adds to code.

An agent that cannot make a linter, type checker or scanner pass can tell it
to look away instead: ``# noqa``, ``# type: ignore``, ``// eslint-disable``,
``@ts-ignore``, ``//nolint``, ``#[allow(...)]``, ``@SuppressWarnings``. Only
comments and attributes on lines this change added count, and only when the
file now holds more of that suppression than it did at the base, so moved,
reindented and edited lines that kept their suppression are not new.

Test files are left out (they are counted, not reported): tests pass wrong
types on purpose (``@ts-expect-error``, ``# type: ignore``) and pytest
fixtures trip linters. Generated and vendored files are left out too.

Every finding here is advice. A suppression with a reason (text after the
directive, ``-- why`` for ESLint, ``reason = "..."`` in Rust, a comment on
the line above) says so; one without a reason asks for one. A suppression of
a whole file (``@ts-nocheck``, ``# mypy: ignore-errors``, ``/* eslint-disable
*/``) in a file that existed at the base says the file is no longer checked.

Also advice: ``_ = name`` (Python) and ``void name;`` (JS/TS) added where
that is the only use of the variable, which hides an unused-variable warning
instead of removing the variable.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

RULE_SUPPRESSION = "SKY-A118"

# At most this many suppressions are listed; the rest are counted.
MAX_LISTED = 20

_PY_SUFFIXES = (".py", ".pyi")
_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_JS_LIKE_SUFFIXES = (".vue", ".svelte", ".astro")
_GO_SUFFIXES = (".go",)
_RUST_SUFFIXES = (".rs",)
_JVM_SUFFIXES = (".java", ".kt", ".kts")
_CS_SUFFIXES = (".cs",)

_VENDORED_DIRS = frozenset(
    {
        "node_modules",
        "vendor",
        "third_party",
        "third-party",
        "dist",
        "build",
        "generated",
        "__generated__",
        ".venv",
        "venv",
        "site-packages",
        "target",
    }
)
_PLACEHOLDERS = frozenset(
    {
        "todo",
        "fixme",
        "xxx",
        "hack",
        "explanation",
        "reason",
        "why",
        "temp",
        "tmp",
        "ignore",
        "ignored",
        "disable",
        "disabled",
        "fix later",
        "fix",
        "suppress",
        "preserve",
        "@preserve",
    }
)


@dataclass(frozen=True)
class Directive:
    """One suppression as written: ``# noqa: F401`` on line 12."""

    line: int
    name: str  # "noqa", "type: ignore", "eslint-disable-next-line", ...
    tool: str  # who stops reporting: "the linter", "mypy", "ESLint", ...
    rules: tuple[str, ...]  # () when it silences every rule
    scope: str  # "line", "block" or "file"
    reason: str  # "" when none is given
    shown: str  # the directive as quoted in messages

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        return (self.name, self.rules)


@dataclass
class SuppressionOutcome:
    # (rule, file, line, message, blocking)
    findings: list[tuple[str, str, int | None, str, bool]]
    added: int = 0  # new suppressions in non-test code
    unexplained: int = 0  # of those, without a reason
    whole_file: int = 0  # of those, covering a whole file
    in_tests: int = 0  # new suppressions in test files (not listed)
    tricks: int = 0  # `_ = x` / `void x;` added only to use a variable
    files: int = 0  # changed code files read


# ---------------------------------------------------------------------------
# Finding the comments
# ---------------------------------------------------------------------------


def language(path: str) -> str | None:
    name = PurePosixPath(path).name
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return None
    if name.endswith(_PY_SUFFIXES):
        return "py"
    if name.endswith(_JS_SUFFIXES):
        return "js"
    if name.endswith(_JS_LIKE_SUFFIXES):
        return "js-like"
    if name.endswith(_GO_SUFFIXES):
        return "go"
    if name.endswith(_RUST_SUFFIXES):
        return "rust"
    if name.endswith(_JVM_SUFFIXES):
        return "jvm"
    if name.endswith(_CS_SUFFIXES):
        return "cs"
    return None


@dataclass
class _Source:
    lines: list[str]
    # line -> comment texts starting on it (with their delimiters)
    comments: dict[int, list[str]]
    # line -> the code on it, strings blanked and comments removed
    code: dict[int, str]

    def comment_only(self, line: int) -> bool:
        return line in self.comments and not self.code.get(line, "").strip()


def _python_source(text: str) -> _Source:
    lines = _physical_lines(text)
    comments: dict[int, list[str]] = {}
    code: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                comments.setdefault(token.start[0], []).append(token.string)
                row = token.start[0]
                code[row] = (
                    lines[row - 1][: token.start[1]] if row <= len(lines) else ""
                )
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # Unfinished source: a '#' outside quotes on each line.
        comments, code = {}, {}
        for index, line in enumerate(lines, 1):
            column = _hash_column(line)
            if column is not None:
                comments[index] = [line[column:]]
                code[index] = line[:column]
    for index, line in enumerate(lines, 1):
        code.setdefault(index, line)
    return _Source(lines, comments, code)


def _hash_column(line: str) -> int | None:
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            return index
        index += 1
    return None


def _js_source(path: str, text: str) -> _Source:
    from skylos.done.js_inventory import _parse

    root = _parse(path, text)
    if root is None or root.has_error:
        return _c_like_source(text, backtick=True)
    lines = _physical_lines(text)
    data = text.encode("utf-8", errors="surrogatepass")
    comments: dict[int, list[str]] = {}
    spans: dict[int, list[tuple[int, int]]] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            row = node.start_point[0] + 1
            comments.setdefault(row, []).append(
                data[node.start_byte : node.end_byte].decode("utf-8", "replace")
            )
            # Columns of the comment on each line it covers, to cut it out.
            for line in range(node.start_point[0], node.end_point[0] + 1):
                start = node.start_point[1] if line == node.start_point[0] else 0
                end = node.end_point[1] if line == node.end_point[0] else None
                spans.setdefault(line + 1, []).append((start, end or 10**9))
            continue
        stack.extend(node.children)
    code: dict[int, str] = {}
    raw = data.split(b"\n")
    for index, line in enumerate(lines, 1):
        cuts = spans.get(index)
        if not cuts:
            code[index] = line
            continue
        encoded = raw[index - 1] if index - 1 < len(raw) else line.encode()
        kept = bytearray()
        position = 0
        for start, end in sorted(cuts):
            kept += encoded[position:start]
            position = max(position, end)
        kept += encoded[position:] if position < len(encoded) else b""
        code[index] = kept.decode("utf-8", "replace")
    return _Source(lines, comments, code)


def _c_like_source(text: str, *, backtick: bool = False, rust: bool = False) -> _Source:
    """Comments and code of a C-like language, skipping string literals."""
    lines = _physical_lines(text)
    comments: dict[int, list[str]] = {}
    code_chars: dict[int, list[str]] = {}
    line = 1
    index = 0
    size = len(text)

    def emit(chars: str) -> None:
        code_chars.setdefault(line, []).append(chars)

    while index < size:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = size if end == -1 else end
            comments.setdefault(line, []).append(text[index:end])
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = size if end == -1 else end + 2
            body = text[index:end]
            comments.setdefault(line, []).append(body)
            line += body.count("\n")
            index = end
            continue
        if rust and char == "r" and re.match(r'r#*"', text[index : index + 8]):
            hashes = len(re.match(r"r(#*)", text[index:]).group(1))
            closing = '"' + "#" * hashes
            end = text.find(closing, index + 2 + hashes)
            end = size if end == -1 else end + len(closing)
            line += text.count("\n", index, end)
            emit('""')
            index = end
            continue
        if char == '"' or (backtick and char == "`"):
            triple = text.startswith('"""', index)
            closing = '"""' if triple else char
            position = index + len(closing)
            while position < size:
                if text[position] == "\\" and char != "`":
                    position += 2
                    continue
                if text.startswith(closing, position):
                    position += len(closing)
                    break
                if text[position] == "\n" and closing == '"' and not triple:
                    break  # unterminated: stop at the end of the line
                position += 1
            line += text.count("\n", index, min(position, size))
            emit('""')
            index = position
            continue
        if char == "'":
            match = re.match(r"'(?:\\.[^']{0,8}|[^\\'\n])'", text[index : index + 12])
            if match:
                emit("''")
                index += len(match.group(0))
                continue
        emit(char)
        index += 1
    code = {
        number: "".join(code_chars.get(number, ()))
        for number in range(1, len(lines) + 1)
    }
    return _Source(lines, comments, code)


def _source(path: str, kind: str, text: str) -> _Source:
    if kind == "py":
        return _python_source(text)
    if kind == "js":
        return _js_source(path, text)
    return _c_like_source(text, backtick=kind in {"js-like", "go"}, rust=kind == "rust")


# ---------------------------------------------------------------------------
# Reading the directives
# ---------------------------------------------------------------------------

_CODES = r"[A-Za-z]+[0-9]+(?:\s*,\s*[A-Za-z]+[0-9]+)*"
_NAMES = r"[\w.\-/@]+(?:\s*,\s*[\w.\-/@]+)*"

# (name, tool, pattern, scope). Searched anywhere in a Python comment.
_PY_DIRECTIVES = (
    (
        "ruff: noqa",
        "the linter",
        re.compile(
            rf"#\s*(?:ruff|flake8)\s*:\s*noqa\b(?:\s*:\s*(?P<rules>{_CODES}))?", re.I
        ),
        "file",
    ),
    (
        "noqa",
        "the linter",
        re.compile(rf"#\s*noqa\b(?:\s*:\s*(?P<rules>{_CODES}))?", re.I),
        "line",
    ),
    (
        "type: ignore",
        "the type checker",
        re.compile(r"#\s*type\s*:\s*ignore\b(?:\[(?P<rules>[^\]]*)\])?"),
        "line",
    ),
    (
        "pyright: ignore",
        "pyright",
        re.compile(r"#\s*pyright\s*:\s*ignore\b(?:\[(?P<rules>[^\]]*)\])?"),
        "line",
    ),
    (
        "pyright: basic",
        "pyright",
        re.compile(
            r"#\s*pyright\s*:\s*(?P<rules>basic\b|report\w+\s*=\s*(?:false|none)\b)"
        ),
        "file",
    ),
    (
        "mypy: ignore-errors",
        "mypy",
        re.compile(r"#\s*mypy\s*:\s*ignore-errors\b"),
        "file",
    ),
    (
        "mypy: disable-error-code",
        "mypy",
        re.compile(
            r"#\s*mypy\s*:\s*disable-error-code\s*=\s*[\"']?(?P<rules>[\w\-]+(?:\s*,\s*[\w\-]+)*)"
        ),
        "file",
    ),
    (
        "pylint: skip-file",
        "pylint",
        re.compile(r"#\s*pylint\s*:\s*skip-file\b"),
        "file",
    ),
    (
        "pylint: disable",
        "pylint",
        re.compile(
            r"#\s*pylint\s*:\s*disable(?:-next)?\s*=\s*(?P<rules>[\w\-]+(?:\s*,\s*[\w\-]+)*)"
        ),
        "line",
    ),
    (
        "nosec",
        "bandit",
        re.compile(r"#\s*nosec\b(?:\s*:?\s*(?P<rules>B\d{3}(?:\s*,\s*B\d{3})*))?"),
        "line",
    ),
    (
        "pragma: no cover",
        "coverage",
        re.compile(r"#\s*pragma\s*:\s*no\s*(?:cover|branch)\b"),
        "line",
    ),
    (
        "pyre-ignore",
        "Pyre",
        re.compile(r"#\s*pyre-(?:ignore|fixme)\b(?:\[(?P<rules>[^\]]*)\])?"),
        "line",
    ),
    (
        "pytype: disable",
        "pytype",
        re.compile(
            r"#\s*pytype\s*:\s*disable\s*=\s*(?P<rules>[\w\-]+(?:\s*,\s*[\w\-]+)*)"
        ),
        "line",
    ),
)
# Searched anywhere in a comment in every language.
_ANY_DIRECTIVES = (
    ("NOSONAR", "SonarQube", re.compile(r"\bNOSONAR\b"), "line"),
    (
        "nosemgrep",
        "Semgrep",
        re.compile(rf"\bnosem(?:grep)?\b(?:\s*:\s*(?P<rules>{_NAMES}))?"),
        "line",
    ),
    ("gitleaks:allow", "gitleaks", re.compile(r"\bgitleaks:allow\b"), "line"),
    (
        "pragma: allowlist secret",
        "detect-secrets",
        re.compile(r"\bpragma\s*:\s*allowlist\s+(?:nextline\s+)?secret\b"),
        "line",
    ),
    (
        "skylos: ignore",
        "Skylos",
        re.compile(
            r"\bskylos\s*:\s*ignore(?P<start>-start)?\b(?:\[(?P<rules>[^\]]*)\])?"
        ),
        "line",
    ),
    (
        "pragma: no skylos",
        "Skylos",
        re.compile(r"\bpragma\s*:\s*no\s+skylos\b|#\s*noqa\s*:\s*skylos\b"),
        "line",
    ),
)
# JS/TS: the comment must begin with the directive.
_JS_DIRECTIVES = (
    (
        "eslint-disable",
        "ESLint",
        re.compile(
            r"^(?P<name>(?:eslint|oxlint)-disable(?:-next-line|-line)?)(?=\s|$)(?P<rest>.*)",
            re.S,
        ),
        None,
    ),
    (
        "tslint:disable",
        "TSLint",
        re.compile(
            r"^(?P<name>tslint:disable(?:-next-line|-line)?)(?::(?P<rules>[\w\-, ]+))?(?P<rest>.*)",
            re.S,
        ),
        None,
    ),
    (
        "deno-lint-ignore",
        "deno lint",
        re.compile(r"^(?P<name>deno-lint-ignore(?:-file)?)(?=\s|$)(?P<rest>.*)", re.S),
        None,
    ),
    (
        "@ts-ignore",
        "TypeScript",
        re.compile(
            r"^(?P<name>@ts-(?:ignore|expect-error|nocheck))\b(?P<rest>.*)", re.S
        ),
        None,
    ),
    (
        "istanbul ignore",
        "coverage",
        re.compile(
            r"^(?P<name>(?:istanbul|c8|v8)\s+ignore\s+(?:next|if|else|file|start))\b(?P<rest>.*)",
            re.S,
        ),
        None,
    ),
    (
        "biome-ignore",
        "Biome",
        re.compile(
            r"^(?P<name>biome-ignore(?:-all|-start)?)(?=\s|:|$)(?P<rest>.*)", re.S
        ),
        None,
    ),
)
_GO_DIRECTIVES = (
    (
        "nolint",
        "golangci-lint",
        re.compile(r"^//\s*nolint\b(?::(?P<rules>[\w\-]+(?:,[\w\-]+)*))?(?P<rest>.*)"),
        "line",
    ),
    (
        "lint:ignore",
        "staticcheck",
        re.compile(
            r"^//\s*lint:(?P<name>ignore|file-ignore)\s+(?P<rules>\S+)(?P<rest>.*)"
        ),
        "line",
    ),
    (
        "#nosec",
        "gosec",
        re.compile(r"#nosec\b(?:\s+(?P<rules>G\d{3}(?:\s*,\s*G\d{3})*))?(?P<rest>.*)"),
        "line",
    ),
)
_JVM_COMMENT_DIRECTIVES = (
    ("NOPMD", "PMD", re.compile(r"\bNOPMD\b(?P<rest>.*)"), "line"),
    (
        "CHECKSTYLE:OFF",
        "Checkstyle",
        re.compile(r"\bCHECKSTYLE[:.]OFF\b(?::?\s*(?P<rules>\w+))?(?P<rest>.*)", re.I),
        "block",
    ),
)
_RUST_ATTRIBUTE = re.compile(r"#(?P<inner>!?)\[\s*(?P<name>allow|expect)\s*\(")
_JVM_ANNOTATION = re.compile(
    r"@(?P<file>file:)?(?P<name>SuppressWarnings|Suppress|SuppressFBWarnings|SuppressLint)\s*\("
)
_CS_PRAGMA = re.compile(
    r"^\s*#\s*pragma\s+warning\s+disable\b(?P<rules>[^/\n]*)(?P<rest>.*)"
)
_CS_ATTRIBUTE = re.compile(
    r"\[\s*(?:assembly\s*:\s*)?(?:System\.Diagnostics\.CodeAnalysis\.)?SuppressMessage(?:Attribute)?\s*\("
)

_COVER_IDIOMS = re.compile(
    r"^\s*(?:if\s+(?:typing\.)?TYPE_CHECKING\b|if\s+__name__\s*==|raise\s+NotImplementedError\b"
    r"|except\s+ImportError\b|except\s+ModuleNotFoundError\b|\.\.\.|pass\b"
    r"|@(?:typing\.)?overload\b|@(?:abc\.)?abstractmethod\b|def\s+__repr__\b)"
)


# Text every directive above contains: files without any are not parsed.
_HINT_RE = re.compile(
    r"noqa|type\s*:\s*ignore|pyright|mypy\s*:|pylint|nosec|NOSONAR|pragma|nosem"
    r"|gitleaks|skylos|-disable|tslint|@ts-|ignore\s+(?:next|if|else|file|start)"
    r"|biome-ignore|deno-lint|nolint|lint:|allow\s*\(|expect\s*\(|Suppress|NOPMD"
    r"|CHECKSTYLE",
    re.I,
)


def directives(path: str, text: str | None) -> list[Directive]:
    """Every suppression in one file, in line order."""
    kind = language(path)
    if kind is None or not text or not _HINT_RE.search(text):
        return []
    source = _source(path, kind, text)
    found: list[Directive] = []
    for line, texts in sorted(source.comments.items()):
        for comment in texts:
            found += _comment_directives(kind, line, comment, source)
    if kind == "rust":
        found += _rust_attributes(source)
    elif kind == "jvm":
        found += _jvm_annotations(source)
    elif kind == "cs":
        found += _cs_directives(source)
    found = [d for d in found if not _cover_idiom(d, source)]
    return sorted(found, key=lambda d: (d.line, d.name))


def _cover_idiom(directive: Directive, source: _Source) -> bool:
    """``# pragma: no cover`` on ``if TYPE_CHECKING:`` and the like is how
    coverage is told about code that never runs, not a silenced check."""
    if directive.name != "pragma: no cover":
        return False
    return bool(_COVER_IDIOMS.match(source.code.get(directive.line, "")))


def _comment_directives(kind: str, line: int, comment: str, source: _Source):
    found: list[Directive] = []
    spans: list[tuple[int, int]] = []
    table = _ANY_DIRECTIVES
    if kind == "py":
        table = _PY_DIRECTIVES + _ANY_DIRECTIVES
    for name, tool, pattern, scope in table:
        for match in pattern.finditer(comment):
            if any(start <= match.start() < end for start, end in spans):
                continue  # a file-wide directive is not also a line one
            spans.append(match.span())
            if name == "skylos: ignore" and match.group("start"):
                scope_here = "block"
            elif name == "pylint: disable" and source.comment_only(line):
                scope_here = "block"  # applies to the rest of the scope
            elif name == "type: ignore" and _before_code(source, line):
                scope_here = "file"  # mypy: ignores the whole module
            else:
                scope_here = scope
            rules = _split_rules(match.groupdict().get("rules"))
            found.append(
                Directive(
                    line,
                    name,
                    tool,
                    rules,
                    scope_here,
                    "",
                    _shown(match.group(0)),
                )
            )
    if kind in {"js", "js-like"}:
        found += _js_directives(line, comment)
    elif kind == "go":
        found += _go_directives(line, comment)
    elif kind == "jvm":
        found += _jvm_comment_directives(line, comment)
    if not found:
        return []
    # A reason: other words in the comment, or a plain comment just above.
    reason = _leftover(comment, spans) if kind == "py" else ""
    return [
        d
        if d.reason
        else Directive(
            d.line,
            d.name,
            d.tool,
            d.rules,
            d.scope,
            reason or _reason_above(source, line),
            d.shown,
        )
        for d in found
    ]


def _js_directives(line: int, comment: str) -> list[Directive]:
    content = _comment_content(comment)
    for _, tool, pattern, _ in _JS_DIRECTIVES:
        match = pattern.match(content)
        if not match:
            continue
        name = " ".join(match.group("name").split())
        rest = " ".join(match.group("rest").split())
        rules: tuple[str, ...] = ()
        reason = ""
        scope = "line"
        if name.startswith(("eslint-", "oxlint-")):
            parts = re.split(r"\s--(?:\s+|$)", " " + rest, maxsplit=1)
            rules = _split_rules(parts[0])
            reason = parts[1] if len(parts) > 1 else ""
            scope = "line" if name.endswith("line") else "file"
            tool = "oxlint" if name.startswith("oxlint") else "ESLint"
        elif name.startswith("tslint:"):
            rules = _split_rules(match.group("rules"))
            scope = "line" if name.endswith("line") else "file"
        elif name.startswith("deno-lint-ignore"):
            rules = _split_rules(rest.split("--")[0])
            scope = "file" if name.endswith("-file") else "line"
        elif name.startswith("@ts-"):
            reason = rest
            scope = "file" if name == "@ts-nocheck" else "line"
        elif "ignore" in name and name.split()[0] in {"istanbul", "c8", "v8"}:
            reason = rest
            scope = "file" if name.endswith("file") else "line"
        elif name.startswith("biome-ignore"):
            head, _, tail = rest.partition(":")
            rules = _split_rules(head)
            reason = tail
            scope = "file" if name.endswith("-all") else "line"
        reason = _clean_reason(reason)
        shown = name + (" " + ", ".join(rules) if rules else "")
        return [Directive(line, name, tool, rules, scope, reason, shown)]
    return []


def _go_directives(line: int, comment: str) -> list[Directive]:
    found = []
    for name, tool, pattern, scope in _GO_DIRECTIVES:
        match = pattern.search(comment)
        if not match:
            continue
        rules = _split_rules(match.group("rules"))
        rest = match.group("rest") or ""
        if name == "lint:ignore" and match.group("name") == "file-ignore":
            name, scope = "lint:file-ignore", "file"
        if name == "nolint":
            rest = rest.partition("//")[2]
        reason = _clean_reason(rest.replace("--", " "))
        shown = name + (":" + ",".join(rules) if rules and name == "nolint" else "")
        if rules and name != "nolint":
            shown += " " + ",".join(rules)
        found.append(Directive(line, name, tool, rules, scope, reason, shown))
    return found


def _jvm_comment_directives(line: int, comment: str) -> list[Directive]:
    found = []
    for name, tool, pattern, scope in _JVM_COMMENT_DIRECTIVES:
        match = pattern.search(comment)
        if not match:
            continue
        rules = _split_rules(match.groupdict().get("rules"))
        reason = _clean_reason(match.group("rest") or "")
        found.append(Directive(line, name, tool, rules, scope, reason, name))
    return found


def _rust_attributes(source: _Source) -> list[Directive]:
    found = []
    for line in sorted(source.code):
        code = source.code[line]
        for nth, match in enumerate(_RUST_ATTRIBUTE.finditer(code)):
            body = _attribute_arguments(source, line, _RUST_ATTRIBUTE, nth)
            if body is None:
                continue
            reason_match = re.search(r'\breason\s*=\s*"([^"]*)"', body)
            arguments = [
                part.strip()
                for part in re.sub(r'\breason\s*=\s*"[^"]*"', "", body).split(",")
                if part.strip() and "=" not in part
            ]
            name = f"#{match.group('inner')}[{match.group('name')}]"
            reason = _clean_reason(reason_match.group(1) if reason_match else "")
            reason = (
                reason or _trailing_comment(source, line) or _reason_above(source, line)
            )
            found.append(
                Directive(
                    line,
                    name,
                    "the Rust compiler and Clippy",
                    tuple(arguments),
                    "file" if match.group("inner") else "line",
                    reason,
                    f"#{match.group('inner')}[{match.group('name')}({', '.join(arguments)})]",
                )
            )
    return found


def _jvm_annotations(source: _Source) -> list[Directive]:
    found = []
    for line in sorted(source.code):
        code = source.code[line]
        for nth, match in enumerate(_JVM_ANNOTATION.finditer(code)):
            arguments = _attribute_arguments(source, line, _JVM_ANNOTATION, nth)
            if arguments is None:
                continue
            justification = re.search(r'\bjustification\s*=\s*"([^"]*)"', arguments)
            strings = re.findall(
                r'"([^"]*)"',
                re.sub(r'\bjustification\s*=\s*"[^"]*"', "", arguments),
            )
            reason = _clean_reason(justification.group(1) if justification else "")
            reason = (
                reason or _trailing_comment(source, line) or _reason_above(source, line)
            )
            name = "@" + (match.group("file") or "") + match.group("name")
            rules = tuple(s for s in strings if s)
            found.append(
                Directive(
                    line,
                    name,
                    "the compiler and linters",
                    rules,
                    "file" if match.group("file") else "line",
                    reason,
                    name + "(" + ", ".join('"' + rule + '"' for rule in rules) + ")",
                )
            )
    return found


def _cs_directives(source: _Source) -> list[Directive]:
    found = []
    for line, text in enumerate(source.lines, 1):
        match = _CS_PRAGMA.match(text)
        if match:
            rules = _split_rules(match.group("rules"))
            reason = _clean_reason(match.group("rest").lstrip("/")) or _reason_above(
                source, line
            )
            found.append(
                Directive(
                    line,
                    "#pragma warning disable",
                    "the C# compiler",
                    rules,
                    "block",
                    reason,
                    "#pragma warning disable " + ", ".join(rules),
                )
            )
    for line in sorted(source.code):
        if _CS_ATTRIBUTE.search(source.code[line]):
            raw = _attribute_arguments(source, line, _CS_ATTRIBUTE, 0) or ""
            justification = re.search(r'\bJustification\s*=\s*"([^"]*)"', raw)
            rule = re.search(r'"([^"]*)"\s*,\s*"([^"]*)"', raw)
            rules = (rule.group(2),) if rule else ()
            reason = _clean_reason(justification.group(1) if justification else "")
            found.append(
                Directive(
                    line,
                    "SuppressMessage",
                    "code analysis",
                    rules,
                    "line",
                    reason or _reason_above(source, line),
                    "[SuppressMessage]",
                )
            )
    return found


def _attribute_arguments(source: _Source, line: int, pattern, nth: int):
    """The raw text between the parentheses of the ``nth`` match of
    ``pattern`` on ``line`` (an attribute may run over a few lines)."""
    raw = "\n".join(source.lines[line - 1 : line + 5])
    matches = list(pattern.finditer(raw.split("\n", 1)[0]))
    if nth >= len(matches):
        return None
    return _balanced_text(raw, matches[nth].end())


def _balanced_text(text: str, start: int) -> str | None:
    """Text from ``start`` to the parenthesis that closes the one before it,
    skipping string literals."""
    if start < 0:
        return None
    depth = 1
    index = start
    while index < len(text):
        char = text[index]
        if char == '"':
            end = index + 1
            while end < len(text) and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            index = end + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
        index += 1
    return None


def _trailing_comment(source: _Source, line: int) -> str:
    for comment in source.comments.get(line, ()):
        reason = _clean_reason(_comment_content(comment))
        if reason:
            return reason
    return ""


def _before_code(source: _Source, line: int) -> bool:
    """No code before ``line`` and none on it: a module-level comment."""
    if source.code.get(line, "").strip():
        return False
    return not any(source.code.get(n, "").strip() for n in range(1, line))


def _reason_above(source: _Source, line: int) -> str:
    """A plain comment on the line just above (not itself a directive)."""
    above = line - 1
    if not source.comment_only(above):
        return ""
    texts = source.comments.get(above, ())
    joined = " ".join(_comment_content(text) for text in texts)
    if _looks_like_directive(joined):
        return ""
    return _clean_reason(joined)


_DIRECTIVE_WORDS = re.compile(
    r"noqa|type\s*:\s*ignore|pyright\s*:|mypy\s*:|pylint\s*:|nosec|NOSONAR|pragma\s*:"
    r"|eslint-|oxlint-|tslint:|@ts-|istanbul\s+ignore|c8\s+ignore|v8\s+ignore|biome-ignore"
    r"|nolint|lint:|nosemgrep|skylos\s*:|prettier-ignore|deno-lint",
    re.I,
)


def _looks_like_directive(text: str) -> bool:
    return bool(_DIRECTIVE_WORDS.search(text))


def _comment_content(comment: str) -> str:
    text = comment.strip()
    if text.startswith("/*"):
        text = text[2:]
        if text.endswith("*/"):
            text = text[:-2]
        text = "\n".join(part.strip().lstrip("*").strip() for part in text.splitlines())
    elif text.startswith("//"):
        text = text[2:]
    elif text.startswith("#"):
        text = text[1:]
    return text.strip()


def _leftover(comment: str, spans: list[tuple[int, int]]) -> str:
    kept = []
    position = 0
    for start, end in sorted(spans):
        kept.append(comment[position:start])
        position = max(position, end)
    kept.append(comment[position:])
    return _clean_reason(" ".join(kept))


def _clean_reason(text: str | None) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"@preserve\b", " ", text.replace("*/", " "))
    cleaned = " ".join(cleaned.split()).strip(" #/*-:;,.—–")
    if sum(ch.isalpha() for ch in cleaned) < 3:
        return ""
    if cleaned.lower() in _PLACEHOLDERS or re.fullmatch(r"<[^>]*>", cleaned):
        return ""
    return cleaned


def _split_rules(text: str | None) -> tuple[str, ...]:
    if not text:
        return ()
    return tuple(
        part
        for part in (p.strip().strip("\"'") for p in re.split(r"[,\s]+", text))
        if part and part != "--"
    )


def _shown(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------------------
# Which suppressions the change added
# ---------------------------------------------------------------------------


def _normal(line: str) -> str:
    return re.sub(r"\s+", "", line)


def _physical_lines(text: str) -> list[str]:
    """Lines as Git, the tokenizer and tree-sitter number them (``\n`` only:
    ``str.splitlines`` also splits on form feeds and Unicode separators)."""
    return [line.rstrip("\r") for line in text.split("\n")]


def _line_text(lines: list[str], number: int) -> str:
    return lines[number - 1] if 1 <= number <= len(lines) else ""


def is_vendored(path: str) -> bool:
    return bool(_VENDORED_DIRS.intersection(PurePosixPath(path).parts[:-1]))


def new_suppressions(comparison, is_test, is_generated) -> SuppressionOutcome:
    """Suppressions on added lines that the files did not already hold."""
    outcome = SuppressionOutcome(findings=[])
    heads: dict[str, tuple[str, list[Directive], set[int]]] = {}
    bases: dict[str, list[Directive]] = {}
    base_texts: dict[str, str] = {}
    for changed in comparison.changed:
        base_path = changed.base_path
        if base_path and language(base_path):
            text = comparison.base_text(base_path)
            if text:
                base_texts[base_path] = text
                bases[base_path] = directives(base_path, text)
        path = changed.head_path
        if not path or language(path) is None or is_vendored(path):
            continue
        added = comparison.added_lines(changed)
        if not added:
            continue
        text = comparison.head_text(path)
        if not text:
            continue
        outcome.files += 1
        heads[path] = (text, directives(path, text), added)

    # Suppressed lines that left their place: moved or reindented elsewhere.
    pool: Counter = Counter()
    for base_path, found in bases.items():
        lines = _physical_lines(base_texts[base_path])
        for directive in found:
            pool[(directive.key, _normal(_line_text(lines, directive.line)))] += 1
    for path, (text, found, added) in heads.items():
        lines = _physical_lines(text)
        for directive in found:
            if directive.line not in added:
                pool[(directive.key, _normal(_line_text(lines, directive.line)))] -= 1

    base_of = {c.head_path: c.base_path for c in comparison.changed if c.head_path}
    new: list[tuple[str, Directive, bool]] = []
    for path, (text, found, added) in sorted(heads.items()):
        lines = _physical_lines(text)
        base_path = base_of.get(path)
        base_counts = Counter(d.key for d in bases.get(base_path or "", ()))
        head_counts = Counter(d.key for d in found)
        room = {key: head_counts[key] - base_counts[key] for key in head_counts}
        existed = base_path is not None and base_path in base_texts
        for directive in found:
            if directive.line not in added:
                continue
            signature = (directive.key, _normal(_line_text(lines, directive.line)))
            if pool[signature] > 0:
                pool[signature] -= 1
                continue
            if room.get(directive.key, 0) <= 0:
                continue  # an edited line that kept its suppression
            room[directive.key] -= 1
            if is_test(path):
                outcome.in_tests += 1
                continue
            if is_generated(path, text):
                continue
            new.append((path, directive, existed))

    by_line: dict[tuple[str, int], list[tuple[Directive, bool]]] = {}
    for path, directive, existed in new:
        by_line.setdefault((path, directive.line), []).append((directive, existed))
    for (path, line), items in sorted(by_line.items()):
        outcome.added += len(items)
        outcome.unexplained += sum(not d.reason for d, _ in items)
        outcome.whole_file += sum(d.scope == "file" for d, _ in items)
        if len(outcome.findings) < MAX_LISTED:
            outcome.findings.append(
                (
                    RULE_SUPPRESSION,
                    path,
                    line,
                    _message([d for d, _ in items], any(e for _, e in items)),
                    False,
                )
            )
    for path, (text, _, added) in sorted(heads.items()):
        if is_test(path) or is_generated(path, text):
            continue
        for line, message in _unused_tricks(path, text, added):
            outcome.tricks += 1
            if len(outcome.findings) < MAX_LISTED:
                outcome.findings.append((RULE_SUPPRESSION, path, line, message, False))
    return outcome


def _message(found: list[Directive], existed: bool) -> str:
    """``(advice) adds # noqa: F401 with no reason``; a whole-file directive
    also says what is no longer checked."""
    quoted = " and ".join(d.shown for d in found)
    whole_file = next((d for d in found if d.scope == "file"), None)
    reasons = [d.reason for d in found if d.reason]
    text = f"(advice) adds {quoted}"
    text += f' (reason: "{_clip(reasons[0], 60)}")' if reasons else " with no reason"
    if whole_file is not None:
        text += f": {whole_file.tool} {'no longer checks' if existed else 'skips'} this file"
    return text


def _clip(text: str, limit: int = 80) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# `_ = x` and `void x;`: using a variable only to hide that it is unused
# ---------------------------------------------------------------------------


def _unused_tricks(path: str, text: str, added: set[int]) -> list[tuple[int, str]]:
    kind = language(path)
    if kind == "py":
        if "_ =" not in text and "_=" not in text:
            return []
        return _python_tricks(text, added)
    if kind == "js":
        if "void " not in text:
            return []
        return _js_tricks(path, text, added)
    return []


def _python_tricks(text: str, added: set[int]) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    found = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        loads: Counter = Counter()
        local = {a.arg for a in ast.walk(function.args) if isinstance(a, ast.arg)}
        for node in ast.walk(function):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    loads[node.id] += 1
                else:
                    local.add(node.id)
        for statement in ast.walk(function):
            if (
                not isinstance(statement, ast.Assign)
                or statement.lineno not in added
                or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or statement.targets[0].id != "_"
            ):
                continue
            value = statement.value
            names = (
                [value]
                if isinstance(value, ast.Name)
                else list(value.elts)
                if isinstance(value, ast.Tuple)
                else []
            )
            if not names or not all(isinstance(n, ast.Name) for n in names):
                continue
            used = [n.id for n in names]
            if all(n in local and n != "_" and loads[n] == used.count(n) for n in used):
                shown = ", ".join(used)
                found.append(
                    (
                        statement.lineno,
                        f"(advice) _ = {shown} only hides that {shown} is unused",
                    )
                )
    return found


def _js_tricks(path: str, text: str, added: set[int]) -> list[tuple[int, str]]:
    from skylos.done.js_inventory import _parse

    root = _parse(path, text)
    if root is None:
        return []
    found = []
    functions = {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "function",
    }
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in functions:
            continue
        identifiers: Counter = Counter()
        voids = []
        inner = [node]
        while inner:
            current = inner.pop()
            if current is not node and current.type in functions:
                continue  # a nested function has its own names
            if current.type == "identifier":
                identifiers[current.text.decode("utf-8", "replace")] += 1
            if (
                current.type == "expression_statement"
                and current.named_children
                and current.named_children[0].type == "unary_expression"
            ):
                unary = current.named_children[0]
                operator = unary.child_by_field_name("operator")
                argument = unary.child_by_field_name("argument")
                if (
                    operator is not None
                    and operator.type == "void"
                    and argument is not None
                    and argument.type == "identifier"
                ):
                    voids.append((current.start_point[0] + 1, argument.text.decode()))
            inner.extend(current.children)
        for line, name in voids:
            # Declared or a parameter (one mention), and voided (one more).
            if line in added and identifiers[name] == 2:
                found.append(
                    (
                        line,
                        f"(advice) void {name}; only hides that {name} is unused",
                    )
                )
    return found
