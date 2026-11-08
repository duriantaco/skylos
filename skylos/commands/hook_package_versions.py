"""Which version a package manager would install for an unpinned request.

The install hook checks the version that will actually land, not the one the
agent typed: ``npm install chalk`` installs the ``latest`` dist-tag,
``npm install chalk@^5`` the highest matching version, ``pip install
requests`` the newest final release. These helpers pick that version from
registry metadata the caller already fetched (an npm packument, a PyPI
project document). They never fetch anything, and return ``None`` when the
request cannot be read, so the caller can report "could not check" instead of
guessing.

npm follows ``npm-pick-manifest``: a dist-tag names its version; for a range,
``latest`` wins when it matches, then the highest matching version that is
not deprecated. Ranges use node-semver syntax (``^``, ``~``, x-ranges,
comparators, hyphen ranges, ``||``) with its prerelease rule. PyPI follows
pip: PEP 440 specifiers (poetry's ``^``/``~`` are converted), yanked
releases are skipped, and prereleases only win when nothing final matches.
"""

from __future__ import annotations

import re
from typing import Any

_VERSION_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_PARTIAL_RE = re.compile(
    r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMPARATOR_RE = re.compile(r"^(~>?|\^|[<>]=?|=)?(.*)$")
_HYPHEN_RE = re.compile(r"^(\S+)\s+-\s+(\S+)$")
_OPERATOR_SPACE_RE = re.compile(r"(~>?|\^|[<>]=?|=)\s+")
_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")
_LOWEST_PRE = ("0",)
MAX_RANGE_CHARS = 256

Version = tuple[int, int, int, tuple[str, ...]]
Comparator = tuple[str, Version]


def parse_npm_version(text: str) -> Version | None:
    match = _VERSION_RE.match(text.strip())
    if match is None:
        return None
    pre: tuple[str, ...] = ()
    if match.group(4):
        pre = tuple(match.group(4).split("."))
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), pre


def npm_version_key(version: Version) -> tuple:
    major, minor, patch, pre = version
    if not pre:
        return (major, minor, patch, (1,))
    parts = []
    for ident in pre:
        if ident.isdigit():
            parts.append((0, int(ident), ""))
        else:
            parts.append((1, 0, ident))
    return (major, minor, patch, (0, tuple(parts)))


def parse_npm_range(text: str) -> list[list[Comparator]] | None:
    """OR-of-AND comparator sets for a node-semver range, or None."""
    if len(text) > MAX_RANGE_CHARS:
        return None
    sets: list[list[Comparator]] = []
    for part in text.split("||"):
        comparators = _parse_and_set(part.strip())
        if comparators is None:
            return None
        sets.append(comparators)
    return sets


def npm_satisfies(version: Version, sets: list[list[Comparator]]) -> bool:
    return any(_set_allows(version, comparators) for comparators in sets)


def pick_npm_version(document: dict[str, Any], requested: str) -> str | None:
    """The version npm installs for ``name@requested`` from its packument."""
    versions = document.get("versions")
    tags = document.get("dist-tags")
    if not isinstance(versions, dict) or not isinstance(tags, dict):
        return None
    spec = requested.strip()
    if spec in ("", "*", "latest"):
        return _tagged(tags, versions, "latest")
    sets = parse_npm_range(spec)
    if sets is None:
        if _TAG_RE.match(spec):
            return _tagged(tags, versions, spec)
        return None
    latest = tags.get("latest")
    if isinstance(latest, str) and latest in versions:
        parsed = parse_npm_version(latest)
        if parsed is not None and npm_satisfies(parsed, sets):
            return latest
    matching: list[tuple[tuple, str, bool]] = []
    for raw, manifest in versions.items():
        if not isinstance(raw, str):
            continue
        parsed = parse_npm_version(raw)
        if parsed is None or not npm_satisfies(parsed, sets):
            continue
        deprecated = isinstance(manifest, dict) and bool(manifest.get("deprecated"))
        matching.append((npm_version_key(parsed), raw, deprecated))
    if not matching:
        return None
    current = [item for item in matching if not item[2]]
    pool = current or matching
    return max(pool)[1]


def pick_pypi_version(
    document: dict[str, Any], requested: str, *, pre: bool = False, constraint: str = ""
) -> str | None:
    """The version pip installs for ``name<requested>`` from PyPI's JSON.

    ``pre`` is ``--pre`` (prereleases compete with finals); ``constraint`` is
    the specifier a constraints file adds."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion
    from packaging.version import Version as Pep440

    releases = document.get("releases")
    spec_text = _pep440_specifier(requested.strip())
    if spec_text is None:
        return None
    if not isinstance(releases, dict):
        info = document.get("info")
        if spec_text == "" and not constraint and not pre and isinstance(info, dict) \
                and isinstance(info.get("version"), str):
            return info["version"]
        return None
    candidates: dict[Any, str] = {}
    for raw, files in releases.items():
        if not isinstance(raw, str) or not _has_installable_file(files):
            continue
        try:
            candidates[Pep440(raw)] = raw
        except InvalidVersion:
            continue
    try:
        specifier = SpecifierSet(spec_text)
        if constraint:
            specifier = specifier & SpecifierSet(constraint)
    except InvalidSpecifier:
        return None
    prereleases = None
    if pre:
        prereleases = True
    allowed = list(specifier.filter(candidates, prereleases=prereleases))
    if not allowed:
        return None
    return candidates[max(allowed)]


def _tagged(tags: dict[str, Any], versions: dict[str, Any], tag: str) -> str | None:
    value = tags.get(tag)
    if isinstance(value, str) and value in versions:
        return value
    return None


def _has_installable_file(files: Any) -> bool:
    if not isinstance(files, list):
        return False
    for item in files:
        if isinstance(item, dict) and not item.get("yanked"):
            return True
    return False


def _pep440_specifier(requested: str) -> str | None:
    if not requested:
        return ""
    if requested.startswith("^") or (
        requested.startswith("~") and not requested.startswith("~=")
    ):
        return _poetry_range(requested)
    return requested


def _poetry_range(requested: str) -> str | None:
    operator = requested[0]
    parts = requested[1:].strip().split(".")
    if not parts or not all(part.isdigit() for part in parts) or len(parts) > 3:
        return None
    numbers = [int(part) for part in parts]
    lower = ".".join(str(n) for n in numbers)
    if operator == "^":
        upper = _caret_upper(numbers)
    else:
        upper = _tilde_upper(numbers)
    return f">={lower},<{upper}"


def _caret_upper(numbers: list[int]) -> str:
    for index, value in enumerate(numbers):
        if value != 0 or index == len(numbers) - 1:
            bumped = numbers[:index] + [value + 1]
            return ".".join(str(n) for n in bumped)
    return "1"


def _tilde_upper(numbers: list[int]) -> str:
    if len(numbers) == 1:
        return str(numbers[0] + 1)
    return f"{numbers[0]}.{numbers[1] + 1}"


def _parse_and_set(text: str) -> list[Comparator] | None:
    if text in ("", "*", "x", "X"):
        return []
    hyphen = _HYPHEN_RE.match(text)
    if hyphen:
        return _hyphen(hyphen.group(1), hyphen.group(2))
    collapsed = _OPERATOR_SPACE_RE.sub(r"\1", text)
    comparators: list[Comparator] = []
    for word in collapsed.split():
        parsed = _comparator(word)
        if parsed is None:
            return None
        comparators.extend(parsed)
    return comparators


def _partial(text: str) -> tuple[int | None, int | None, int | None, tuple[str, ...]] | None:
    match = _PARTIAL_RE.match(text)
    if match is None:
        return None
    numbers: list[int | None] = []
    wild = False
    for group in match.groups()[:3]:
        if group is None or group in ("x", "X", "*") or wild:
            wild = True
            numbers.append(None)
        else:
            numbers.append(int(group))
    pre: tuple[str, ...] = ()
    if match.group(4) and numbers[2] is not None:
        pre = tuple(match.group(4).split("."))
    return numbers[0], numbers[1], numbers[2], pre


def _comparator(word: str) -> list[Comparator] | None:
    match = _COMPARATOR_RE.match(word)
    if match is None:
        return None
    operator = match.group(1) or ""
    partial = _partial(match.group(2).lstrip("="))
    if partial is None:
        return None
    major, minor, patch, pre = partial
    if operator in ("~", "~>"):
        return _tilde(major, minor, patch, pre)
    if operator == "^":
        return _caret(major, minor, patch, pre)
    return _primitive(operator, major, minor, patch, pre)


def _primitive(op, major, minor, patch, pre) -> list[Comparator]:
    if op in ("", "="):
        if major is None:
            return []
        if minor is None:
            return [(">=", (major, 0, 0, ())), ("<", (major + 1, 0, 0, _LOWEST_PRE))]
        if patch is None:
            return [(">=", (major, minor, 0, ())), ("<", (major, minor + 1, 0, _LOWEST_PRE))]
        return [("=", (major, minor, patch, pre))]
    if major is None:
        if op in (">", "<"):
            return [("<", (0, 0, 0, _LOWEST_PRE))]
        return []
    if op == ">":
        if minor is None:
            return [(">=", (major + 1, 0, 0, ()))]
        if patch is None:
            return [(">=", (major, minor + 1, 0, ()))]
        return [(">", (major, minor, patch, pre))]
    if op == ">=":
        return [(">=", (major, minor or 0, patch or 0, pre))]
    if op == "<":
        if minor is None:
            return [("<", (major, 0, 0, _LOWEST_PRE))]
        if patch is None:
            return [("<", (major, minor, 0, _LOWEST_PRE))]
        return [("<", (major, minor, patch, pre))]
    if minor is None:
        return [("<", (major + 1, 0, 0, _LOWEST_PRE))]
    if patch is None:
        return [("<", (major, minor + 1, 0, _LOWEST_PRE))]
    return [("<=", (major, minor, patch, pre))]


def _tilde(major, minor, patch, pre) -> list[Comparator]:
    if major is None:
        return []
    if minor is None:
        return [(">=", (major, 0, 0, ())), ("<", (major + 1, 0, 0, _LOWEST_PRE))]
    upper = ("<", (major, minor + 1, 0, _LOWEST_PRE))
    return [(">=", (major, minor, patch or 0, pre)), upper]


def _caret(major, minor, patch, pre) -> list[Comparator]:
    if major is None:
        return []
    if minor is None:
        return [(">=", (major, 0, 0, ())), ("<", (major + 1, 0, 0, _LOWEST_PRE))]
    lower = (">=", (major, minor, patch or 0, pre))
    if major != 0:
        return [lower, ("<", (major + 1, 0, 0, _LOWEST_PRE))]
    if patch is None or minor != 0:
        return [lower, ("<", (0, minor + 1, 0, _LOWEST_PRE))]
    return [lower, ("<", (0, 0, patch + 1, _LOWEST_PRE))]


def _hyphen(low: str, high: str) -> list[Comparator] | None:
    lower = _partial(low)
    upper = _partial(high)
    if lower is None or upper is None:
        return None
    comparators: list[Comparator] = []
    if lower[0] is not None:
        comparators.append((">=", (lower[0], lower[1] or 0, lower[2] or 0, lower[3])))
    major, minor, patch, pre = upper
    if major is None:
        return comparators
    if minor is None:
        comparators.append(("<", (major + 1, 0, 0, _LOWEST_PRE)))
    elif patch is None:
        comparators.append(("<", (major, minor + 1, 0, _LOWEST_PRE)))
    else:
        comparators.append(("<=", (major, minor, patch, pre)))
    return comparators


def _set_allows(version: Version, comparators: list[Comparator]) -> bool:
    key = npm_version_key(version)
    for op, bound in comparators:
        other = npm_version_key(bound)
        if op == "=" and key != other:
            return False
        if op == ">" and not key > other:
            return False
        if op == ">=" and not key >= other:
            return False
        if op == "<" and not key < other:
            return False
        if op == "<=" and not key <= other:
            return False
    if not version[3]:
        return True
    return any(
        bound[3] and bound[:3] == version[:3] and bound[3] != _LOWEST_PRE
        for _op, bound in comparators
    )


__all__ = [
    "npm_satisfies",
    "parse_npm_range",
    "parse_npm_version",
    "pick_npm_version",
    "pick_pypi_version",
]
