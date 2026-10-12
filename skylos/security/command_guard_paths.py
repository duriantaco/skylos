from __future__ import annotations

import re
from functools import lru_cache


LOCAL_HOST_RE = re.compile(
    r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/|$)",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s'\"`)$]+", re.I)
GLOB_CHARS = ("*", "?", "[")
# Longer glob patterns are not analysed and count as matching anything.
MAX_GLOB_LENGTH = 256


def is_sensitive_path(value: str) -> bool:
    text = strip_shell_file_marker(value).strip().strip("'\"")
    if not text:
        return False

    lowered = text.lower().replace("\\", "/")
    basename = lowered.rsplit("/", 1)[-1]
    return (
        _is_sensitive_basename(basename)
        or basename.endswith((".key", ".pem", ".p12", ".pfx"))
        or _contains_sensitive_path_marker(lowered)
    )


def is_external_url(value: str) -> bool:
    match = URL_RE.search(value)
    if not match:
        return False
    return LOCAL_HOST_RE.match(match.group(0)) is None


def looks_like_remote_host(token: str) -> bool:
    if token.startswith(("-", "@")):
        return False
    if "@" in token and ":" in token:
        return True
    return ":" in token and not token.startswith(("./", "/", "~"))


def has_external_destination(tokens: list[str]) -> bool:
    for token in tokens[1:]:
        if URL_RE.search(token):
            if is_external_url(token):
                return True
            continue
        if looks_like_remote_host(token):
            return True
    return False


def strip_shell_file_marker(value: str) -> str:
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.startswith("@"):
        value = value[1:]
    return value


def has_glob(value: str) -> bool:
    return any(char in value for char in GLOB_CHARS)


@lru_cache(maxsize=4096)
def glob_could_match(
    pattern: str, literal: str, *, starts: bool = False, contains: bool = False
) -> bool:
    """Whether a path that shell glob ``pattern`` names could equal ``literal``,
    start with it (``starts``), or contain it (``contains``).

    Bash expands ``*``, ``?`` and ``[...]`` in redirect targets; ``*`` and
    ``?`` never match ``/``. Text without glob characters is compared as is.
    Errs towards a match: every bracket expression counts as satisfiable.
    """
    if not has_glob(pattern):
        if contains:
            return literal in pattern
        return pattern.startswith(literal) if starts else pattern == literal
    if len(pattern) > MAX_GLOB_LENGTH:
        return True
    wanted: list[str | None] = list(literal)  # None: any run, "/" included
    if contains:
        wanted.insert(0, None)
    if starts or contains:
        wanted.append(None)
    return _globs_overlap(_glob_tokens(pattern), wanted)


def _globs_overlap(tokens: list, wanted: list[str | None]) -> bool:
    # Dynamic programming from the ends: row[j] says whether tokens[i:] and
    # wanted[j:] can match one common string; ``below`` is the row for i + 1.
    # A ``None`` in ``wanted`` is a run that may end, or absorb a character.
    width = len(wanted)
    below = [False] * (width + 1)
    below[width] = True
    for j in range(width - 1, -1, -1):
        below[j] = wanted[j] is None and below[j + 1]
    for token in reversed(tokens):
        row = [False] * (width + 1)
        if token == "*":
            # "*" matches nothing more, or one more character other than "/".
            row[width] = below[width]
            for j in range(width - 1, -1, -1):
                row[j] = below[j] or (row[j + 1] and wanted[j] != "/")
        else:
            for j in range(width - 1, -1, -1):
                want = wanted[j]
                if want is None:
                    row[j] = row[j + 1] or below[j]
                elif token(want) if callable(token) else token == want:
                    row[j] = below[j + 1]
        if not any(row):
            return False  # no shorter suffix of ``tokens`` can match either
        below = row
    return below[0]


def _glob_tokens(pattern: str) -> list:
    tokens: list = []
    idx = 0
    while idx < len(pattern):
        char = pattern[idx]
        end = _bracket_end(pattern, idx) if char == "[" else -1
        if end > idx:
            tokens.append(_bracket_matcher(pattern[idx + 1 : end]))
            idx = end + 1
            continue
        tokens.append(_one_char if char == "?" else char)
        idx += 1
    return tokens


def _bracket_end(pattern: str, start: int) -> int:
    idx = start + 1
    if pattern[idx : idx + 1] in {"!", "^"}:
        idx += 1
    if pattern[idx : idx + 1] == "]":
        idx += 1  # a leading "]" is a member, not the end
    while idx < len(pattern):
        if pattern[idx] == "]":
            return idx
        if pattern[idx] == "[" and pattern[idx + 1 : idx + 2] in {":", ".", "="}:
            close = pattern.find(pattern[idx + 1] + "]", idx + 2)
            if close != -1:
                idx = close + 2
                continue
        idx += 1
    return -1  # no closing "]": the "[" is literal


def _bracket_matcher(body: str):
    negate = body[:1] in {"!", "^"}
    members = body[1:] if negate else body
    ranges: list[tuple[str, str]] = []
    idx = 0
    while idx < len(members):
        if idx + 2 < len(members) and members[idx + 1] == "-":
            ranges.append((members[idx], members[idx + 2]))
            idx += 3
        else:
            ranges.append((members[idx], members[idx]))
            idx += 1
    # Character classes ("[:alpha:]") and inverted ranges are not modelled.
    if any(marker in members for marker in ("[:", "[.", "[=")) or any(
        low > high for low, high in ranges
    ):
        return _one_char

    def matches(char: str) -> bool:
        inside = any(low <= char <= high for low, high in ranges)
        return char != "/" and inside != negate

    return matches


def _one_char(char: str) -> bool:
    return char != "/"


def _is_sensitive_basename(basename: str) -> bool:
    if basename == ".env" or basename.startswith(".env."):
        return True
    if basename.endswith(".env"):
        return True
    return basename in {
        ".envrc",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "config.json",
        "credentials",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    }


def _contains_sensitive_path_marker(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "/.aws/",
            "/.azure/",
            "/.claude/",
            "/.codex/",
            "/.config/gh/",
            "/.docker/config.json",
            "/.kube/",
            "/.ssh/",
            "/run/secrets/",
            "~/.aws/",
            "~/.azure/",
            "~/.claude/",
            "~/.codex/",
            "~/.config/gh/",
            "~/.docker/config.json",
            "~/.kube/",
            "~/.ssh/",
        )
    )
