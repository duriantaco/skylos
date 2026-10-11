"""Make README.md's relative links and images absolute before a PyPI build.

PyPI shows the README at https://pypi.org/project/skylos/, where a relative
link such as ``./docs/done-gate.md`` or an image such as ``assets/DOG_1.png``
resolves against pypi.org and returns 404. The publish workflow runs this on
the release checkout just before ``python -m build`` and pins every link to the
release tag. The README in the repository keeps its relative links for GitHub.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

# The release job runs this script before installing the Skylos package.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.core.safe_cache_io import write_text_no_symlink  # noqa: E402

REPO_URL = "https://github.com/duriantaco/skylos"
RAW_URL = "https://raw.githubusercontent.com/duriantaco/skylos"
IMAGE_SUFFIXES = (".png", ".gif", ".jpg", ".jpeg", ".svg", ".webp")

_MD_OPEN = re.compile(r"(?<!\\)\]\([ \t]*")
_REFERENCE = re.compile(r"^( {0,3}\[[^\]\n]+\]:[ \t]*)(<[^>\n]+>|[^\s]+)", re.MULTILINE)
_HTML_TAG = re.compile(r"<[a-z](?:[^>\"']|\"[^\"]*\"|'[^']*')*>", re.IGNORECASE)
_HTML_ATTRIBUTE = re.compile(r"([\w:-]+)(\s*=\s*)(['\"])(.*?)\3", re.DOTALL)
_BACKTICKS = re.compile(r"(?<!`)(`+)(?!`)")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*?)[\r\n]*$")
_ABSOLUTE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|//)", re.IGNORECASE)


def is_relative(target: str) -> bool:
    return bool(target) and not _ABSOLUTE.match(target)


def absolutize(target: str, ref: str, *, image: bool = False) -> str:
    """Return ``target`` as an absolute GitHub URL pinned to ``ref``."""
    if not is_relative(target):
        return target
    parts = urlsplit(target)
    path = posixpath.normpath(parts.path.lstrip("/"))
    if path == ".." or path.startswith("../"):
        raise ValueError(f"README link points outside the repository: {target}")
    if path == ".":
        path = "README.md"
    base = (
        RAW_URL
        if image or path.lower().endswith(IMAGE_SUFFIXES)
        else f"{REPO_URL}/blob"
    )
    url = f"{base}/{quote(ref, safe='')}/{quote(path, safe='/%')}"
    return urlunsplit((*urlsplit(url)[:3], parts.query, parts.fragment))


def _destination_end(text: str, start: int) -> int | None:
    """Find a Markdown destination without cutting off nested parentheses."""
    if start < len(text) and text[start] == "<":
        end = text.find(">", start + 1)
        return end + 1 if end != -1 and "\n" not in text[start:end] else None
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            index += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return index
            depth -= 1
        elif char.isspace():
            return index if depth == 0 else None
        index += 1
    return None


def _target(target: str, ref: str, *, image: bool = False) -> str:
    angle = target.startswith("<") and target.endswith(">")
    value = target[1:-1] if angle else target
    value = re.sub(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])", r"\1", value)
    url = absolutize(value, ref, image=image)
    return f"<{url}>" if angle else url


def _image_link(text: str, end: int) -> bool:
    depth = 1
    for index in range(end - 1, -1, -1):
        if index and text[index - 1] == "\\":
            continue
        if text[index] == "]":
            depth += 1
        elif text[index] == "[":
            depth -= 1
            if depth == 0:
                return index > 0 and text[index - 1] == "!"
    return False


def _rewrite_prose(text: str, ref: str) -> str:
    out = []
    last = 0
    for match in _MD_OPEN.finditer(text):
        if match.start() < last:
            continue
        end = _destination_end(text, match.end())
        if end is None or end == match.end():
            continue
        # Require a closing delimiter, optionally following a quoted title.
        if not re.match(r"\s*(?:\"[^\"]*\"|'[^']*'|\([^)]*\))?\s*\)", text[end:]):
            continue
        out.extend(
            (
                text[last : match.end()],
                _target(
                    text[match.end() : end], ref, image=_image_link(text, match.start())
                ),
            )
        )
        last = end
    out.append(text[last:])
    text = "".join(out)
    text = _REFERENCE.sub(lambda m: m[1] + _target(m[2], ref), text)

    def html_tag(match):
        def attribute(m):
            if m[1].lower() not in {"src", "href"}:
                return m[0]
            return (
                m[1]
                + m[2]
                + m[3]
                + _target(m[4], ref, image=m[1].lower() == "src")
                + m[3]
            )

        return _HTML_ATTRIBUTE.sub(attribute, match[0])

    return _HTML_TAG.sub(html_tag, text)


def _rewrite_block(text: str, ref: str) -> str:
    """Preserve code spans, including spans that contain newlines."""
    out = []
    last = 0
    index = 0
    while match := _BACKTICKS.search(text, index):
        closing = next(
            (m for m in _BACKTICKS.finditer(text, match.end()) if m[1] == match[1]),
            None,
        )
        if closing is None:
            index = match.end()
            continue
        out.extend(
            (
                _rewrite_prose(text[last : match.start()], ref),
                text[match.start() : closing.end()],
            )
        )
        last = index = closing.end()
    out.append(_rewrite_prose(text[last:], ref))
    return "".join(out)


def rewrite(text: str, ref: str) -> str:
    """Rewrite README links while preserving fenced blocks and inline code."""
    out: list[str] = []
    prose: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        match = _FENCE.match(line)
        if fence:
            if (
                match
                and match[1][0] == fence[0]
                and len(match[1]) >= len(fence)
                and not match[2].strip()
            ):
                fence = None
            out.append(line)
            continue
        if match and (match[1][0] == "~" or "`" not in match[2]):
            out.append(_rewrite_block("".join(prose), ref))
            prose.clear()
            fence = match[1]
            out.append(line)
        else:
            prose.append(line)
    out.append(_rewrite_block("".join(prose), ref))
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", required=True, help="Release tag, e.g. v4.48.0")
    parser.add_argument("readme", type=Path, nargs="?", default=Path("README.md"))
    args = parser.parse_args(argv)

    text = args.readme.read_text(encoding="utf-8")
    new = rewrite(text, args.ref)
    if not write_text_no_symlink(args.readme, new, encoding="utf-8"):
        raise OSError(f"Could not safely rewrite README: {args.readme}")
    changed = sum(1 for a, b in zip(text.splitlines(), new.splitlines()) if a != b)
    print(f"{args.readme}: pointed {changed} line(s) of relative links at {args.ref}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
