"""SKY-A125: the change adds a code-scanning platform's suppression marker.

Quality and security platforms read comments in the code that tell them to
stop reporting a line, a statement, a function, a resource block or a file.
A change that adds one hides a finding from a check that runs somewhere
else, usually without a reason. Syntax checked against each vendor's
documentation on 13 Oct 2026.

SKY-A118 (``skylos done``) already reports linter, type-checker and scanner
comments in Python, JavaScript/TypeScript, Go, Rust, Java/Kotlin and C#,
including ``NOSONAR``, ``nosemgrep`` and ``# nosec``. This rule reports only
what A118 does not:

* markers A118 does not know, in any file with comments: DeepSource
  ``skipcq``, JetBrains/Qodana ``noinspection``, Qlty ``qlty-ignore``,
  CodeScene ``@codescene(disable...)``, CodeQL alert-suppression comments
  ``codeql[...]`` and ``lgtm[...]``, Checkov ``checkov:skip=``, Trivy
  ``trivy:ignore:`` (and its legacy ``tfsec:ignore:``), KICS ``kics-scan``;
* ``NOSONAR`` and ``nosemgrep`` in languages A118 does not read (PHP, Ruby,
  Swift, Scala, Dart, C/C++, shell, Terraform, YAML, SQL and others).

Not covered: Snyk Code's ``deepcode ignore`` (behind a feature flag and not
publicly documented) and Codacy (no marker of its own).

Only markers in comments on added lines count, and only when the file now
holds more of that marker than it did at the base, so moved or reindented
lines are not new. Test, generated and vendored files are left out, and so
are documentation files (Markdown, reStructuredText, plain text), where a
marker is usually being explained rather than used.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from skylos.rules.ai_defect.guardrails.core import (
    RULE_SCANNER_MARKER,
    FileChange,
    GuardrailFinding,
    is_vendored,
    shown,
)

MAX_LISTED = 20


@dataclass(frozen=True)
class Marker:
    name: str  # stable key: the marker's own keyword
    tool: str  # who stops reporting
    pattern: re.Pattern
    scope: str  # "line", "next line", "block" or "file"
    # Only in files SKY-A118 does not read (it reports these itself).
    outside_a118_only: bool = False


_RULE_LIST = r"[\w./\-:]+(?:\s*,\s*[\w./\-:]+)*"

MARKERS: tuple[Marker, ...] = (
    # DeepSource's keyword (below), optionally a colon and codes, in a comment
    # on the line or the line above (DeepSource docs).
    Marker(
        "skipcq",
        "DeepSource",
        re.compile(rf"\bskipcq\b(?:\s*:\s*(?P<rules>{_RULE_LIST}))?"),
        "line or next",
    ),
    # The JetBrains keyword then an inspection id, after "//", "#" or as a
    # docblock tag: the next statement; at the top of a JS/TS file, the whole
    # file (JetBrains docs).
    Marker(
        "noinspection",
        "JetBrains IDEs and Qodana",
        re.compile(
            # An inspection id: CamelCase (PyUnresolvedReferences) or a
            # kebab-case Python id (unused-local); the keyword followed by a
            # plain word, as in prose, is not a directive.
            r"(?<![\w-])@?noinspection\s+(?P<rules>(?:[A-Z]\w+|[a-z]+(?:-[a-z]+)+)"
            r"(?:\s*,\s*(?:[A-Z]\w+|[a-z]+(?:-[a-z]+)+))*)"
        ),
        "next statement",
    ),
    # Qlty's keyword followed by a colon and tool:rule, or by tool:rule in
    # parentheses, a colon and a reason (Qlty docs).
    Marker(
        "qlty-ignore",
        "Qlty",
        re.compile(
            # The documented forms only (a spec after a colon, or a spec in
            # parentheses then a colon); a bare word in prose is not one.
            r"\bqlty-ignore(?:\((?P<long>[^)]*)\)\s*:|\s*:\s*"
            r"(?P<rules>[+\->]?[\w./\-]+(?::[\w./\-]+)?"
            r"(?:[\s,]+[+\->]?[\w./\-]+:[\w./\-]+)*))"
        ),
        "next line",
    ),
    # CodeScene's annotation with "disable" plus quoted rule names, or with
    # "disable-all", in parentheses: the function after it (CodeScene docs;
    # written in lower case there).
    Marker(
        "@codescene(disable)",
        "CodeScene",
        re.compile(
            r"@codescene\s*\(\s*(?P<variant>disable-all|disable)\b(?:\s*:\s*(?P<rules>[^)]*))?\)",
            re.IGNORECASE,
        ),
        "next function",
    ),
    # CodeQL's alert-suppression query (AlertSuppression.qll): the codeql
    # keyword with ids in square brackets covers the next line, the lgtm one
    # the same line. Case-insensitive.
    Marker(
        "codeql[...]",
        "CodeQL alert suppression",
        re.compile(r"(?<![\w-])codeql\s*\[(?P<rules>[^\]]*)\]", re.IGNORECASE),
        "next line",
    ),
    Marker(
        "lgtm[...]",
        "CodeQL alert suppression (LGTM)",
        re.compile(r"(?<![\w-])lgtm\s*\[(?P<rules>[^\]]*)\]", re.IGNORECASE),
        "line",
    ),
    # Checkov's skip comment (its prefix, "skip=", a check id such as
    # CKV_AWS_20, then an optional colon and reason) inside the resource
    # (Checkov docs).
    Marker(
        "checkov:skip",
        "Checkov",
        re.compile(r"\bcheckov:skip=(?P<rules>[A-Za-z0-9_]+)"),
        "block",
    ),
    # Trivy's ignore comment (prefix, "ignore", a check id such as
    # AVD-AWS-0086, colon-separated) next to the resource; the legacy tfsec
    # prefix is still accepted.
    Marker(
        "trivy:ignore",
        "Trivy",
        re.compile(r"\b(?:trivy|tfsec):ignore:(?P<rules>[\w\-*]+)"),
        "block",
    ),
    # KICS's comment keyword with a variant: "ignore-line" (next line),
    # "ignore-block" (next block), "ignore" or "disable=ids" at the top of
    # the file (KICS docs).
    Marker(
        "kics-scan ignore",
        "KICS",
        re.compile(
            r"\bkics-scan\s+(?P<variant>ignore-line|ignore-block|ignore|disable)\b"
            r"(?:\s*=\s*(?P<rules>[\w\-,]+))?"
        ),
        "file",
    ),
    Marker(
        "NOSONAR",
        "SonarQube",
        re.compile(r"\bNOSONAR\b"),
        "line",
        outside_a118_only=True,
    ),
    Marker(
        "nosemgrep",
        "Semgrep",
        re.compile(rf"\bnosem(?:grep)?\b(?:\s*:\s*(?P<rules>{_RULE_LIST}))?"),
        "line or next",
        outside_a118_only=True,
    ),
)
MARKER_HINT_RE = re.compile(
    r"skipcq|noinspection|qlty-ignore|@codescene|codeql\s*\[|lgtm\s*\[|checkov:skip"
    r"|trivy:ignore|tfsec:ignore|kics-scan|NOSONAR|nosem",
    re.IGNORECASE,
)

# Comment syntax by file type.
_HASH = (
    ".rb", ".rake", ".gemspec", ".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1",
    ".psm1", ".yaml", ".yml", ".tf", ".tfvars", ".hcl", ".toml", ".r", ".pl",
    ".pm", ".ex", ".exs", ".cr", ".jl", ".nix", ".cmake", ".coffee", ".tcl",
    ".bicep", ".conf", ".cfg",
)  # fmt: skip
_HASH_NAMES = frozenset(
    {"Dockerfile", "Containerfile", "Makefile", "Gemfile", "Rakefile", "Vagrantfile",
     "Jenkinsfile", "Brewfile", "Podfile", "Fastfile", "CMakeLists.txt"}
)  # fmt: skip
_C_LIKE = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm",
    ".swift", ".scala", ".sc", ".dart", ".groovy", ".gradle", ".proto",
    ".sol", ".zig", ".v", ".jsonc", ".json5", ".css", ".scss", ".less",
    ".java", ".kt", ".kts", ".cs", ".go", ".rs", ".js", ".jsx", ".ts",
    ".tsx", ".mjs", ".cjs", ".mts", ".cts",
)  # fmt: skip
_PHP = (".php", ".phtml", ".inc")
_DASH = (".sql", ".lua", ".hs", ".elm", ".ada", ".adb", ".ads")
_MARKUP = (
    ".html",
    ".htm",
    ".xml",
    ".vue",
    ".svelte",
    ".astro",
    ".jsp",
    ".cshtml",
    ".razor",
)
_DOCS = (".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".org")


def comment_style(path: str) -> str | None:
    pure = PurePosixPath(path)
    name = pure.name
    lower = name.lower()
    if lower.endswith(_DOCS) and name not in _HASH_NAMES:
        return None
    if name in _HASH_NAMES or lower.startswith("dockerfile"):
        return "hash"
    if lower.endswith((".py", ".pyi")):
        return "a118"
    if lower.endswith(_PHP):
        return "php"
    if lower.endswith(_MARKUP):
        return "markup"
    if lower.endswith(_C_LIKE):
        return "c"
    if lower.endswith(_HASH):
        return "hash"
    if lower.endswith(_DASH):
        return "dash"
    return None


def _comments(path: str, text: str) -> dict[int, list[str]]:
    """Comment texts by the line they start on (string literals excluded)."""
    from skylos.done import suppressions as a118

    kind = a118.language(path)
    if kind is not None:
        return a118._source(path, kind, text).comments
    style = comment_style(path)
    if style == "c":
        lower = path.lower()
        if lower.endswith(_SINGLE_QUOTE_STRINGS):
            return _lex_comments(text, hash_comments=False)
        return a118._c_like_source(text, backtick=lower.endswith(".dart")).comments
    if style == "php":
        return _lex_comments(text, hash_comments=True)
    if style == "hash":
        return _line_comments(text, "#")
    if style == "dash":
        return _line_comments(text, "--")
    if style == "markup":
        return _markup_comments(text)
    return {}


# C-like languages whose single quotes delimit strings, not one character.
_SINGLE_QUOTE_STRINGS = (
    ".dart",
    ".groovy",
    ".gradle",
    ".css",
    ".scss",
    ".less",
    ".jsonc",
    ".json5",
)


def _lex_comments(text: str, *, hash_comments: bool) -> dict[int, list[str]]:
    """Comments of a C-like language with '...' and "..." strings (PHP,
    Dart, Groovy, CSS); PHP also has ``#`` line comments (not ``#[``)."""
    comments: dict[int, list[str]] = {}
    line = 1
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if text.startswith("//", index) or (
            hash_comments and char == "#" and not text.startswith("#[", index)
        ):
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
        if char in "\"'`":
            position = index + 1
            while position < size and text[position] != char:
                position += 2 if text[position] == "\\" else 1
            line += text.count("\n", index, min(position, size))
            index = position + 1
            continue
        index += 1
    return comments


def _line_comments(text: str, leader: str) -> dict[int, list[str]]:
    comments: dict[int, list[str]] = {}
    for number, line in enumerate(text.split("\n"), 1):
        column = _leader_column(line, leader)
        if column is not None:
            comments[number] = [line[column:]]
    return comments


def _leader_column(line: str, leader: str) -> int | None:
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif line.startswith(leader, index):
            if (
                leader == "#"
                and index > 0
                and not line[index - 1].isspace()
                and line[index - 1] not in ";("
            ):
                # "a#b" in a shell word or YAML value is not a comment.
                index += 1
                continue
            return index
        index += 1
    return None


def _markup_comments(text: str) -> dict[int, list[str]]:
    comments: dict[int, list[str]] = {}
    for match in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
        line = text.count("\n", 0, match.start()) + 1
        comments.setdefault(line, []).append(match.group(0))
    # Script and style blocks in markup use // and /* */.
    for line, items in _c_style_in_blocks(text).items():
        comments.setdefault(line, []).extend(items)
    return comments


def _c_style_in_blocks(text: str) -> dict[int, list[str]]:
    from skylos.done import suppressions as a118

    found: dict[int, list[str]] = {}
    for match in re.finditer(
        r"<(script|style)\b[^>]*>(.*?)</\1\s*>", text, re.DOTALL | re.IGNORECASE
    ):
        offset = text.count("\n", 0, match.start(2))
        inner = a118._c_like_source(match.group(2), backtick=True).comments
        for line, items in inner.items():
            found.setdefault(line + offset, []).extend(items)
    return found


@dataclass(frozen=True)
class _Found:
    line: int
    marker: Marker
    rules: tuple[str, ...]
    scope: str
    reason: str
    shown: str


def find_markers(path: str, text: str | None) -> list[_Found]:
    """Every A125 marker in one file, in line order."""
    if not text or not MARKER_HINT_RE.search(text):
        return []
    style = comment_style(path)
    if style is None:
        return []
    from skylos.done import suppressions as a118

    read_by_a118 = a118.language(path) is not None
    found: list[_Found] = []
    lines = text.split("\n")
    comments = _comments(path, text)
    for line, texts in sorted(comments.items()):
        for comment in texts:
            for marker in MARKERS:
                if marker.outside_a118_only and read_by_a118:
                    continue
                for match in marker.pattern.finditer(comment):
                    groups = match.groupdict()
                    if marker.name == "@codescene(disable)":
                        rules = tuple(re.findall(r'"([^"]+)"', match.group(0)))
                    else:
                        rules = a118._split_rules(
                            groups.get("rules") or groups.get("long")
                        )
                    marker_line = line + _comment_line_offset(comment, match.start())
                    if marker.name == "NOSONAR" and _comment_only(lines, marker_line):
                        # NOSONAR silences issues on its own line; a comment
                        # line has none (it is prose about the marker).
                        continue
                    scope = _scope(marker, groups.get("variant"), path, lines, line)
                    if marker.name == "qlty-ignore":
                        scope = _qlty_scope(rules, scope)
                        rules = tuple(rule.lstrip("+->") for rule in rules)
                    rest = comment[match.end() :]
                    reason = _reason(marker, rest, comments, line)
                    found.append(
                        _Found(
                            marker_line,
                            marker,
                            rules,
                            scope,
                            reason,
                            " ".join(match.group(0).split()),
                        )
                    )
    return sorted(found, key=lambda item: (item.line, item.marker.name))


_COMMENT_LEADERS = ("//", "#", "/*", "*", "--", "<!--", ";", "%")


def _comment_only(lines: list[str], number: int) -> bool:
    text = lines[number - 1].strip() if 1 <= number <= len(lines) else ""
    if text.startswith(("/*", "<!--")):
        closer = "*/" if text.startswith("/*") else "-->"
        end = text.find(closer)
        # "/* NOSONAR */ code();" still has code on the line.
        return end == -1 or not text[end + len(closer) :].strip()
    return text.startswith(_COMMENT_LEADERS)


def _qlty_scope(rules: tuple[str, ...], default: str) -> str:
    """Qlty: "+rule" opens a region closed by "-rule" (to the end of the file
    when never closed); ">rule" covers only the next line."""
    if any(rule.startswith("+") for rule in rules):
        return "region"
    return default


def _comment_line_offset(comment: str, position: int) -> int:
    return comment.count("\n", 0, position)


def _scope(
    marker: Marker, variant: str | None, path: str, lines: list[str], line: int
) -> str:
    variant = (variant or "").strip()
    if marker.name == "checkov:skip" and _is_dockerfile(path):
        return "file"  # Checkov: in a Dockerfile, the whole file
    if marker.name == "trivy:ignore":
        return "next resource"
    if marker.name == "kics-scan ignore":
        return {"ignore-line": "next line", "ignore-block": "block"}.get(
            variant, "file"
        )
    if (
        marker.name == "noinspection"
        and path.endswith(_JS_TS)
        and _in_leading_comments(lines, line)
    ):
        return "file"  # JetBrains: at the top of a JS/TS file, the whole file
    return marker.scope


def _is_dockerfile(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.startswith(("dockerfile", "containerfile")) or name.endswith(
        ".dockerfile"
    )


_JS_TS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")


def _in_leading_comments(lines: list[str], line: int) -> bool:
    """Only blank lines and comments come before ``line``."""
    for text in lines[: line - 1]:
        stripped = text.strip()
        if stripped and not stripped.startswith(("//", "/*", "*")):
            return False
    return True


def _reason(marker: Marker, rest: str, comments, line: int) -> str:
    from skylos.done import suppressions as a118

    text = rest
    if marker.name == "checkov:skip":
        # The check id, then an optional colon and the reason.
        text = rest.split(":", 1)[1] if rest.startswith(":") else ""
    reason = a118._clean_reason(text.replace("*/", " ").replace("-->", " "))
    if reason:
        return reason
    above = comments.get(line - 1)
    if above:
        joined = " ".join(a118._comment_content(item) for item in above)
        if not MARKER_HINT_RE.search(joined) and not a118._looks_like_directive(joined):
            return a118._clean_reason(joined)
    return ""


_SCOPE_TEXT = {
    "line": "this line",
    "line or next": "this line or the next",
    "next line": "the next line",
    "next statement": "the next statement",
    "next function": "the next function",
    "block": "this resource block",
    "next resource": "the resource or instruction below it",
    "region": "the lines up to a matching -rule (the rest of the file if none)",
    "file": "this whole file",
}


def detect_new_markers(
    changes, is_test, is_generated
) -> tuple[list[GuardrailFinding], int, int]:
    """Findings, files read, markers added in test files (counted, not listed)."""
    findings: list[GuardrailFinding] = []
    files = 0
    in_tests = 0
    for change in changes:
        if change.head_text is None or not change.added_lines:
            continue
        path = change.path
        if comment_style(path) is None or is_vendored(path):
            continue
        files += 1
        head = find_markers(path, change.head_text)
        if not head:
            continue
        base = (
            find_markers(change.base_path or path, change.base_text)
            if change.base_text
            else []
        )
        room = Counter(f.marker.name for f in head)
        room.subtract(Counter(f.marker.name for f in base))
        # Markers on lines that only moved: the same marker on the same line text.
        moved = Counter(
            (f.marker.name, _normal(_line(change.base_text, f.line))) for f in base
        )
        for item in head:
            if item.line not in change.added_lines:
                moved[
                    (item.marker.name, _normal(_line(change.head_text, item.line)))
                ] -= 1
        for item in head:
            if item.line not in change.added_lines:
                continue
            signature = (item.marker.name, _normal(_line(change.head_text, item.line)))
            if moved[signature] > 0:
                moved[signature] -= 1
                continue
            if room[item.marker.name] <= 0:
                continue
            room[item.marker.name] -= 1
            if is_test(path):
                in_tests += 1
                continue
            if is_generated(path, change.head_text):
                continue
            if len(findings) >= MAX_LISTED:
                continue
            findings.append(_finding(change, item))
    return findings, files, in_tests


def _finding(change: FileChange, item: _Found) -> GuardrailFinding:
    what = _SCOPE_TEXT.get(item.scope, "this line")
    rules = f" for {', '.join(item.rules[:3])}" if item.rules else " for every rule"
    message = f"adds {shown(item.shown, 70)}: {item.marker.tool} stops reporting {what}{rules}"
    message += (
        f' (reason: "{item.reason[:60]}")' if item.reason else "; no reason given"
    )
    return GuardrailFinding(
        RULE_SCANNER_MARKER,
        change.path,
        item.line,
        message,
        "scanner_marker_added",
        details={
            "marker": item.marker.name,
            "tool": item.marker.tool,
            "scope": item.scope,
            "rules": list(item.rules),
            "reason": bool(item.reason),
        },
    )


def _line(text: str | None, number: int) -> str:
    if not text:
        return ""
    lines = text.split("\n")
    return lines[number - 1] if 1 <= number <= len(lines) else ""


def _normal(line: str) -> str:
    return re.sub(r"\s+", "", line)
