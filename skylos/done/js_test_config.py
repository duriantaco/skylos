"""SKY-A112 for Jest and Vitest settings and package.json test scripts.

Reports what a change adds that makes Jest or Vitest run or check less:

- settings that stop selecting test files that existed at the base: new
  ``testPathIgnorePatterns``/``modulePathIgnorePatterns`` (Jest) or
  ``exclude`` (Vitest) entries and narrower ``testMatch``/``testRegex``/
  ``roots``/``rootDir`` (Jest) or ``include``/``dir`` (Vitest). They are
  checked against the repository's files: a pattern that excludes no
  existing test file, a Playwright spec kept out of a unit runner, or build
  output, is not a loosening. Settings Skylos cannot evaluate (a pattern
  syntax it does not read, ``projects``) are compared as lists instead, as
  pytest's ``testpaths`` are; entries removed from ``projects`` count;
- ``passWithNoTests`` turned on in a config or a package.json test script;
- lowered or removed coverage thresholds (the pre-1.0 Vitest
  ``coverage.lines`` keys and ``coverage.thresholds.lines`` are the same);
- a package.json test script that gains a test filter (``-t``, test paths,
  ``--onlyChanged``, ``--shard``, ``--grep`` and the like), can now fail
  quietly (``|| true`` or any new ``||`` fallback) or no longer runs a test
  runner.

Settings come from ``jest.config.*`` or the package.json ``jest`` key, and
from the ``test`` block of ``vitest.config.*`` (or ``vite.config.*`` when
there is no Vitest config), compared per directory so a config moved between
those files is not a change. Config files are read statically: a config
built by a function, spread from another object or reached through values
that cannot be resolved is skipped, never guessed.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import shlex
from collections.abc import Callable
from pathlib import PurePosixPath

from skylos.done.base import Comparison, _git_text
from skylos.done.js_inventory import JS_SUFFIXES

_JEST_CONFIGS = tuple(
    f"jest.config.{ext}" for ext in ("js", "ts", "mjs", "cjs", "mts", "cts", "json")
)
_VITEST_CONFIGS = tuple(
    f"vitest.config.{ext}" for ext in ("ts", "mts", "cts", "js", "mjs", "cjs")
)
_VITE_CONFIGS = tuple(
    f"vite.config.{ext}" for ext in ("ts", "mts", "cts", "js", "mjs", "cjs")
)
_CONFIG_NAMES = frozenset((*_JEST_CONFIGS, *_VITEST_CONFIGS, *_VITE_CONFIGS))
_IGNORE_KEYS = {
    "testPathIgnorePatterns": "skips test paths matching",
    "modulePathIgnorePatterns": "ignores modules matching",
}
# Defaults the runners apply anyway: listing them ignores nothing new.
_JEST_DEFAULT_IGNORES = {"/node_modules/"}
_VITEST_DEFAULT_EXCLUDES = {
    "**/node_modules/**",
    "**/dist/**",
    "**/cypress/**",
    "**/.{idea,git,cache,output,temp}/**",
    "**/{karma,rollup,webpack,vite,vitest,jest,ava,babel,nyc,cypress,tsup,build,"
    "eslint,prettier}.config.*",
}
_THRESHOLD_KEYS = ("lines", "functions", "branches", "statements")
_SWALLOW_RE = re.compile(r"\|\|\s*(?:true|:|exit\s+0)\b|;\s*exit\s+0\s*$", re.M)
_JEST_DEFAULT_TEST_MATCH = [
    "**/__tests__/**/*.?([mc])[jt]s?(x)",
    "**/?(*.)+(spec|test).?([mc])[jt]s?(x)",
]
_VITEST_DEFAULT_INCLUDE = ["**/*.{test,spec}.?(c|m)[jt]s?(x)"]
# Settings that decide which files a runner treats as tests.
_JEST_SELECTION_KEYS = ("rootDir", "roots", "testMatch", "testRegex")
_VITEST_SELECTION_KEYS = ("root", "dir", "include")
# Build output and dependencies: excluding them from a runner drops no test.
_BUILD_DIRS = frozenset(
    {
        "node_modules",
        "dist",
        "build",
        "out",
        "coverage",
        ".next",
        ".nuxt",
        ".output",
        ".svelte-kit",
        ".turbo",
        ".cache",
    }
)
_PLAYWRIGHT_RE = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*)["'](?:@playwright/test|playwright/test"""
    r"""|@playwright/experimental-ct-[\w-]+)["']"""
)
_ROOT = "/__repository__"
# Identity wrappers around a config object.
_DEFINE_CALLS = {"defineConfig", "defineProject"}


class _Unknown:
    """A value that cannot be read statically."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unknown>"


UNKNOWN = _Unknown()


def detect_loosened_js_test_config(comparison: Comparison) -> list:
    from skylos.done.test_config import ConfigFinding

    directories = set()
    for changed in comparison.changed:
        for path in (changed.base_path, changed.head_path):
            if not path or "node_modules" in PurePosixPath(path).parts:
                continue
            name = PurePosixPath(path).name
            if name in _CONFIG_NAMES or name == "package.json":
                directories.add(posixpath.dirname(path))
    findings: list[ConfigFinding] = []
    files = _Files(comparison) if directories else None
    for directory in sorted(directories):
        for path, line, message in (
            *_jest(comparison, directory, files),
            *_vitest(comparison, directory, files),
            *_scripts(comparison, directory),
        ):
            findings.append(ConfigFinding(path, line, message))
    return findings


class _Files:
    """JS/TS files at the base, where each one is at head, and which of
    them a runner may leave out without losing a test."""

    def __init__(self, comparison: Comparison) -> None:
        self.comparison = comparison
        paths = _base_paths(comparison)
        self.known = paths is not None
        self.paths = [
            path
            for path in paths or ()
            if path.endswith(JS_SUFFIXES)
            and "node_modules" not in PurePosixPath(path).parts
        ]
        self.gone = {
            c.base_path
            for c in comparison.changed
            if c.status == "deleted" and c.base_path
        }
        self.moved = {
            c.base_path: c.path
            for c in comparison.changed
            if c.status == "renamed" and c.base_path
        }
        self._playwright: dict[str, bool] = {}

    def dropped(self, directory: str, before, after) -> list[str] | None:
        """Files ``before`` selects that still exist and ``after`` does not
        select, other than Playwright specs and build output; None when
        either selection cannot be evaluated."""
        if not self.known or before is None or after is None:
            return None
        result = []
        for path in self.paths:
            if directory and not path.startswith(directory + "/"):
                continue
            selected = before(path)
            if selected is None:
                return None
            if not selected or path in self.gone:
                continue
            now = after(self.moved.get(path, path))
            if now is None:
                return None
            if not now and not self._exempt(path):
                result.append(path)
        return result

    def _exempt(self, path: str) -> bool:
        if _BUILD_DIRS.intersection(PurePosixPath(path).parts[:-1]):
            return True
        if path not in self._playwright:
            text = self.comparison.base_text(path) or ""
            self._playwright[path] = bool(_PLAYWRIGHT_RE.search(text))
        return self._playwright[path]


def _base_paths(comparison) -> list[str] | None:
    lister = getattr(comparison, "base_paths", None)
    if callable(lister):
        return list(lister())
    context = getattr(comparison, "_context", None)
    if context is None:
        return None
    text = _git_text(context, "ls-tree", "-r", "--name-only", "-z", comparison.base_sha)
    return [path for path in text.split("\0") if path] if text is not None else None


def _dropped_note(dropped: list[str]) -> str:
    return (
        f" ({len(dropped)} existing test file(s) no longer run, e.g. "
        f"{sorted(dropped)[0]!r})"
    )


# ---------------------------------------------------------------------------
# Jest
# ---------------------------------------------------------------------------


def _jest(comparison: Comparison, directory: str, files: _Files | None):
    base = _jest_config(comparison.base_text, directory)
    head = _jest_config(comparison.head_text, directory)
    if base is UNKNOWN or head is UNKNOWN or head is None:
        return []
    if base is None and not _existed(comparison, directory):
        return []
    path, text, after = head
    before = base[2] if base is not None else {}
    if before is UNKNOWN or after is UNKNOWN:
        return []
    findings = []
    findings += _selection_changes(
        "Jest",
        path,
        text,
        before,
        after,
        directory,
        files,
        _jest_selector,
        _JEST_SELECTION_KEYS,
        {
            key: (_JEST_DEFAULT_IGNORES if key == "testPathIgnorePatterns" else set())
            for key in _IGNORE_KEYS
        },
    )
    if after.get("passWithNoTests") is True and before.get("passWithNoTests") in (
        None,
        False,
    ):
        findings.append(
            (
                path,
                _line_of(text, "passWithNoTests"),
                "Jest passWithNoTests turned on: a run that finds no tests passes",
            )
        )
    for where, old, new in _lowered(
        _jest_thresholds(before.get("coverageThreshold")),
        _jest_thresholds(after.get("coverageThreshold")),
    ):
        findings.append(
            (
                path,
                _line_of(text, "coverageThreshold"),
                f"Jest coverageThreshold {where} {old:g} {new}",
            )
        )
    return findings


def _selection_changes(
    runner: str,
    path: str,
    text: str,
    before: dict,
    after: dict,
    directory: str,
    files: _Files | None,
    selector: Callable,
    selection_keys: tuple[str, ...],
    ignore_keys: dict[str, set[str]],
):
    """Findings for settings that stop running existing test files."""
    findings = []
    base_select = selector(before, directory)
    explained: set[str] = set()

    def dropped_with(settings: dict):
        if files is None or base_select is None:
            return None
        return files.dropped(directory, base_select, selector(settings, directory))

    for key, defaults in ignore_keys.items():
        verb = _IGNORE_KEYS.get(key, "skips test files matching")
        label = (
            f"{runner} {key} now {verb}"
            if key in _IGNORE_KEYS
            else f"{runner} exclude now skips test files matching"
        )
        current = before.get(key)
        for pattern in _added_patterns(current, after.get(key), defaults):
            line = _line_of(text, pattern) or _line_of(text, key)
            known = (
                list(defaults)
                if current is None
                else [item for item in current if isinstance(item, str)]
                + (list(defaults) if _DEFAULTS_SPREAD in current else [])
            )
            dropped = dropped_with({**before, key: [*known, pattern]})
            if dropped is None:
                if not _names_build_output(pattern):
                    findings.append((path, line, f"{label} {pattern!r}"))
            elif dropped:
                explained.update(dropped)
                findings.append(
                    (path, line, f"{label} {pattern!r}{_dropped_note(dropped)}")
                )
    for key in selection_keys:
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        message = _restriction(runner, key, old, new)
        settings = {k: v for k, v in before.items() if k != key}
        if key in after:
            settings[key] = new
        dropped = dropped_with(settings)
        line = _line_of(text, key)
        if dropped is None:
            if message:
                findings.append((path, line, message))
        elif dropped:
            explained.update(dropped)
            findings.append(
                (
                    path,
                    line,
                    (
                        message
                        or f"{runner} {key} changed, which changes which tests run"
                    )
                    + _dropped_note(dropped),
                )
            )
    for key in ("projects", "workspace"):
        old, new = before.get(key), after.get(key)
        if isinstance(old, list) and isinstance(new, list):
            removed = sorted(
                {item for item in old if isinstance(item, str)}
                - {item for item in new if isinstance(item, str)}
            )
            if removed:
                findings.append(
                    (
                        path,
                        _line_of(text, key),
                        f"{runner} {key} no longer include "
                        + ", ".join(repr(item) for item in removed),
                    )
                )
    dropped = dropped_with(after)
    if dropped:
        rest = [item for item in dropped if item not in explained]
        if rest:
            findings.append(
                (
                    path,
                    None,
                    f"{runner} settings no longer run existing test files"
                    + _dropped_note(rest),
                )
            )
    return findings


def _restriction(runner: str, key: str, old, new) -> str | None:
    """pytest-``testpaths``-style wording for a narrowed selection setting,
    or None when the change only widens it (judged as lists)."""
    if new is None:
        return None  # back to the default
    if isinstance(new, str) and key in {"rootDir", "root", "dir"}:
        return f"{runner} {key} now limits the test search to {new!r}"
    new_items = [new] if isinstance(new, str) else new
    old_items = [old] if isinstance(old, str) else old
    if not isinstance(new_items, list):
        return f"{runner} {key} changed, which changes which tests run"
    shown = ", ".join(repr(item) for item in new_items)
    if old_items is None:
        return f"{runner} {key} now restricts test files to {shown}"
    if not isinstance(old_items, list):
        return f"{runner} {key} changed, which changes which tests run"
    removed = [item for item in old_items if item not in new_items]
    if removed:
        return f"{runner} {key} no longer includes " + ", ".join(
            repr(item) for item in removed
        )
    return None


def _names_build_output(pattern: str) -> bool:
    parts = {part for part in re.split(r"[/\\]+", pattern) if part}
    return bool(parts) and bool(_BUILD_DIRS.intersection(parts))


def _jest_config(read, directory: str):
    """(path, text, settings) of the Jest config in ``directory``, None when
    there is none, UNKNOWN when it cannot be read statically."""
    found = [
        (path, text)
        for path in (posixpath.join(directory, name) for name in _JEST_CONFIGS)
        if (text := read(path)) is not None
    ]
    if len(found) > 1:
        return UNKNOWN  # Jest refuses to choose between several configs
    if found:
        path, text = found[0]
        settings = (
            _json_object(text) if path.endswith(".json") else _module_config(path, text)
        )
        return UNKNOWN if settings is UNKNOWN else (path, text, settings)
    path = posixpath.join(directory, "package.json")
    text = read(path)
    data = _json_object(text) if text is not None else None
    if data is None or data is UNKNOWN or "jest" not in data:
        return None if data is not UNKNOWN else UNKNOWN
    settings = data["jest"]
    return (path, text, settings) if isinstance(settings, dict) else UNKNOWN


def _jest_thresholds(value) -> dict[str, float] | _Unknown:
    """``{global: {lines: 80}, "./src/": {...}}`` to {"global.lines": 80.0}."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        return UNKNOWN
    result: dict[str, float] = {}
    for scope, numbers in value.items():
        if not isinstance(numbers, dict):
            return UNKNOWN
        for key in _THRESHOLD_KEYS:
            number = numbers.get(key)
            if number is None:
                continue
            if not _is_number(number):
                return UNKNOWN
            result[f"{scope}.{key}"] = float(number)
    return result


# ---------------------------------------------------------------------------
# Vitest
# ---------------------------------------------------------------------------


def _vitest(comparison: Comparison, directory: str, files: _Files | None):
    base = _vitest_config(comparison.base_text, directory)
    head = _vitest_config(comparison.head_text, directory)
    if base is UNKNOWN or head is UNKNOWN or head is None:
        return []
    if base is None and not _existed(comparison, directory):
        return []
    path, text, after = head
    before = base[2] if base is not None else {}
    if before is UNKNOWN or after is UNKNOWN:
        return []
    findings = []
    findings += _selection_changes(
        "Vitest",
        path,
        text,
        before,
        after,
        directory,
        files,
        _vitest_selector,
        _VITEST_SELECTION_KEYS,
        {"exclude": _VITEST_DEFAULT_EXCLUDES},
    )
    if after.get("passWithNoTests") is True and before.get("passWithNoTests") in (
        None,
        False,
    ):
        findings.append(
            (
                path,
                _line_of(text, "passWithNoTests"),
                "Vitest passWithNoTests turned on: a run that finds no tests passes",
            )
        )
    for where, old, new in _lowered(
        _vitest_thresholds(before.get("coverage")),
        _vitest_thresholds(after.get("coverage")),
    ):
        findings.append(
            (
                path,
                _line_of(text, "thresholds") or _line_of(text, "coverage"),
                f"Vitest coverage threshold {where} {old:g} {new}",
            )
        )
    return findings


def _vitest_config(read, directory: str):
    """(path, text, test settings): vitest.config.* wins over vite.config.*."""
    for names in (_VITEST_CONFIGS, _VITE_CONFIGS):
        found = [
            (path, text)
            for path in (posixpath.join(directory, name) for name in names)
            if (text := read(path)) is not None
        ]
        if len(found) > 1:
            return UNKNOWN
        if not found:
            continue
        path, text = found[0]
        config = _module_config(path, text)
        if config is UNKNOWN:
            return UNKNOWN
        settings = config.get("test", {})
        if not isinstance(settings, dict):
            return UNKNOWN
        return path, text, settings
    return None


def _vitest_thresholds(coverage) -> dict[str, float] | _Unknown:
    """``coverage.thresholds`` (and the pre-1.0 ``coverage.lines`` keys)."""
    if coverage is None:
        return {}
    if not isinstance(coverage, dict):
        return UNKNOWN
    result: dict[str, float] = {}
    thresholds = coverage.get("thresholds", {})
    if not isinstance(thresholds, dict):
        return UNKNOWN
    # The pre-1.0 coverage.lines keys moved to coverage.thresholds.lines:
    # the same threshold under either name (the newer one wins).
    sources = [(coverage, "thresholds"), (thresholds, "thresholds")]
    for glob, numbers in thresholds.items():
        if glob in _THRESHOLD_KEYS or glob in {"100", "perFile", "autoUpdate"}:
            continue
        if not isinstance(numbers, dict):
            return UNKNOWN
        sources.append((numbers, f"thresholds[{glob!r}]"))
    for source, prefix in sources:
        values = _threshold_values(source, prefix)
        if values is UNKNOWN:
            return UNKNOWN
        result.update(values)
    return result


def _threshold_values(source: dict, prefix: str):
    """lines/functions/branches/statements numbers, with ``100: true``."""
    flag = source.get("100")
    if flag is UNKNOWN:
        return UNKNOWN
    result = (
        {f"{prefix}.{key}": 100.0 for key in _THRESHOLD_KEYS} if flag is True else {}
    )
    for key in _THRESHOLD_KEYS:
        number = source.get(key)
        if number is None:
            continue
        if not _is_number(number):
            return UNKNOWN
        result[f"{prefix}.{key}"] = float(number)
    return result


# ---------------------------------------------------------------------------
# Which files a runner treats as tests
# ---------------------------------------------------------------------------


def _jest_selector(settings: dict, directory: str):
    """path -> whether Jest runs it as a test file, or None when the
    settings cannot be evaluated (``projects``, unreadable patterns)."""
    if settings.get("projects"):
        return None
    root = _join(directory, settings.get("rootDir", "."))
    if root is None:
        return None
    rooted = _ROOT + ("/" + root if root else "")
    roots = settings.get("roots", ["<rootDir>"])
    if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
        return None
    root_dirs = []
    for value in roots:
        joined = _join(root, value.replace("<rootDir>", "."))
        if joined is None:
            return None
        root_dirs.append(joined)
    regexes = settings.get("testRegex")
    if isinstance(regexes, str):
        regexes = [regexes]
    if regexes:
        if not isinstance(regexes, list):
            return None
        matchers = [_js_regex(item.replace("<rootDir>", rooted)) for item in regexes]
        if any(m is None for m in matchers):
            return None

        def matches(absolute: str, relative: str) -> bool:
            return any(m.search(absolute) for m in matchers)

    else:
        globs = settings.get("testMatch", _JEST_DEFAULT_TEST_MATCH)
        if not isinstance(globs, list):
            return None
        compiled = _glob_set([g.replace("<rootDir>", rooted) for g in globs])
        if compiled is None:
            return None
        positive, negative = compiled

        def matches(absolute: str, relative: str) -> bool:
            # Jest matches absolute paths; a relative pattern is also tried
            # against the path inside rootDir rather than never matching.
            return any(
                g.match(absolute) or g.match(relative) for g in positive
            ) and not any(g.match(absolute) or g.match(relative) for g in negative)

    ignores = []
    for key, defaults in (
        ("testPathIgnorePatterns", ["/node_modules/"]),
        ("modulePathIgnorePatterns", []),
    ):
        values = settings.get(key, defaults)
        if not isinstance(values, list):
            return None
        for value in values:
            if not isinstance(value, str):
                return None
            compiled_ignore = _js_regex(value.replace("<rootDir>", rooted))
            if compiled_ignore is None:
                return None
            ignores.append(compiled_ignore)

    def select(path: str) -> bool:
        if not any(_under(path, root_dir) for root_dir in root_dirs):
            return False
        absolute = f"{_ROOT}/{path}"
        relative = path[len(root) + 1 :] if root else path
        return matches(absolute, relative) and not any(
            ignore.search(absolute) for ignore in ignores
        )

    return select


def _vitest_selector(settings: dict, directory: str):
    """path -> whether Vitest runs it as a test file, or None."""
    if settings.get("projects") or settings.get("workspace"):
        return None
    root = _join(directory, settings.get("root", "."))
    base = _join(root, settings.get("dir", ".")) if root is not None else None
    if base is None:
        return None
    include = settings.get("include", _VITEST_DEFAULT_INCLUDE)
    exclude = settings.get("exclude")
    if exclude is None:
        exclude = sorted(_VITEST_DEFAULT_EXCLUDES)
    if not isinstance(include, list) or not isinstance(exclude, list):
        return None
    if _DEFAULTS_SPREAD in exclude:
        exclude = [
            *(item for item in exclude if item is not _DEFAULTS_SPREAD),
            *sorted(_VITEST_DEFAULT_EXCLUDES),
        ]
    included = _glob_set(include)
    excluded = _glob_set(exclude)
    if included is None or excluded is None or included[1] or excluded[1]:
        return None

    def select(path: str) -> bool:
        if not _under(path, base):
            return False
        relative = path[len(base) + 1 :] if base else path
        return any(g.match(relative) for g in included[0]) and not any(
            g.match(relative) for g in excluded[0]
        )

    return select


def _join(directory: str, value) -> str | None:
    """A repository path for ``value`` relative to ``directory`` ("" is the
    repository root), or None when it is not a string or leaves the
    repository."""
    if not isinstance(value, str) or value.startswith("/"):
        return None
    joined = posixpath.normpath(posixpath.join(directory or ".", value))
    if joined == ".." or joined.startswith("../"):
        return None
    return "" if joined == "." else joined


def _under(path: str, directory: str) -> bool:
    return not directory or path.startswith(directory + "/")


def _js_regex(pattern: str):
    """A JavaScript regular expression as a Python one, or None."""
    try:
        return re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", pattern))
    except (re.error, OverflowError):
        return None


def _glob_set(patterns: list) -> tuple[list, list] | None:
    """(positive, negated) compiled globs, or None when one cannot be read."""
    positive, negative = [], []
    for pattern in patterns:
        if not isinstance(pattern, str):
            return None
        target = negative if pattern.startswith("!") else positive
        compiled = _glob(pattern[1:] if pattern.startswith("!") else pattern)
        if compiled is None:
            return None
        target.append(compiled)
    return positive, negative


def _glob(pattern: str):
    """A picomatch-style glob (``**``, ``*``, ``?``, ``[...]``, ``{a,b}``,
    ``?(...)``/``*(...)``/``+(...)``/``@(...)``) as a regular expression."""
    while pattern.startswith("./"):
        pattern = pattern[2:]
    body = _glob_body(pattern)
    if body is None:
        return None
    try:
        return re.compile(f"^{body}$")
    except re.error:
        return None


def _glob_body(pattern: str) -> str | None:
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        following = pattern[index + 1] if index + 1 < len(pattern) else ""
        if char in "?*+@!" and following == "(":
            end = _closing(pattern, index + 1, "(", ")")
            if end is None or char == "!":
                return None  # !(...) is not read
            options = _split_top(pattern[index + 2 : end], "|")
            bodies = [_glob_body(option) for option in options]
            if any(body is None for body in bodies):
                return None
            group = "(?:" + "|".join(bodies) + ")"
            out.append(group + {"?": "?", "*": "*", "+": "+", "@": ""}[char])
            index = end + 1
        elif char == "*":
            if following == "*":
                after = index + 2
                if pattern[after : after + 1] == "/":
                    out.append("(?:.*/)?")
                    index = after + 1
                else:
                    out.append(".*")
                    index = after
            else:
                out.append("[^/]*")
                index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        elif char == "[":
            end = pattern.find("]", index + 2)
            if end < 0:
                return None
            content = pattern[index + 1 : end]
            if content.startswith("!"):
                content = "^" + content[1:]
            out.append("[" + content.replace("\\", "\\\\") + "]")
            index = end + 1
        elif char == "{":
            end = _closing(pattern, index, "{", "}")
            if end is None:
                return None
            options = _split_top(pattern[index + 1 : end], ",")
            if len(options) < 2:
                return None  # {1..3} ranges and {a} are not read
            bodies = [_glob_body(option) for option in options]
            if any(body is None for body in bodies):
                return None
            out.append("(?:" + "|".join(bodies) + ")")
            index = end + 1
        elif char == "\\" and following:
            out.append(re.escape(following))
            index += 2
        else:
            out.append(re.escape(char))
            index += 1
    return "".join(out)


def _closing(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top(text: str, separator: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in text:
        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


# ---------------------------------------------------------------------------
# package.json test scripts
# ---------------------------------------------------------------------------


def _scripts(comparison: Comparison, directory: str):
    path = posixpath.join(directory, "package.json")
    head_text = comparison.head_text(path)
    head = _json_object(head_text) if head_text is not None else None
    if not isinstance(head, dict):
        return []
    base_text = comparison.base_text(path)
    if base_text is None:
        return []  # a new package: its scripts loosen nothing that ran before
    base = _json_object(base_text)
    if not isinstance(base, dict):
        return []
    before = base.get("scripts") if isinstance(base.get("scripts"), dict) else {}
    after = head.get("scripts") if isinstance(head.get("scripts"), dict) else {}
    findings = []
    for name, script in after.items():
        if not isinstance(script, str):
            continue
        # A new test:* script runs only if something calls it; "test" always does.
        if not (name == "test" or (name.startswith("test:") and name in before)):
            continue
        old = before.get(name) if isinstance(before.get(name), str) else ""
        line = _line_of(head_text, f'"{name}"')
        if _has_flag(script, "--passWithNoTests") and not _has_flag(
            old, "--passWithNoTests"
        ):
            findings.append(
                (
                    path,
                    _line_of(head_text, "--passWithNoTests"),
                    f"package.json script {name!r} now passes with no tests "
                    "(--passWithNoTests)",
                )
            )
        if (_SWALLOW_RE.search(script) and not _SWALLOW_RE.search(old)) or (
            _fallbacks(script) > _fallbacks(old)
        ):
            findings.append(
                (
                    path,
                    line,
                    f"package.json script {name!r} can now fail without failing "
                    "(failure swallowed in the script)",
                )
            )
        old_runs = _Runs(old, before)
        new_runs = _Runs(script, after)
        if old_runs.calls and not new_runs.calls and not new_runs.opaque:
            findings.append(
                (
                    path,
                    line,
                    f"package.json script {name!r} no longer runs a test runner "
                    f"({script.strip()[:60]!r})",
                )
            )
            continue
        for what in _narrowed(old_runs.calls, new_runs.calls):
            findings.append((path, line, f"package.json script {name!r} now {what}"))
    return findings


# Per runner: options that take a value, and the options that select fewer
# tests (pytest -k/--deselect/--lf, in JavaScript runners).
_RUNNER_OPTIONS: dict[str, tuple[frozenset[str], dict[str, str]]] = {
    "jest": (
        frozenset(
            {
                "-c",
                "--config",
                "-t",
                "--testNamePattern",
                "--testPathPattern",
                "--testPathPatterns",
                "--testPathIgnorePatterns",
                "--selectProjects",
                "--ignoreProjects",
                "--shard",
                "--changedSince",
                "-w",
                "--maxWorkers",
                "--testTimeout",
                "--env",
                "--testEnvironment",
                "--reporters",
                "--outputFile",
                "--coverageProvider",
                "--coverageDirectory",
                "--coverageReporters",
                "--collectCoverageFrom",
                "--rootDir",
                "--roots",
                "--seed",
                "--cacheDirectory",
                "--testRunner",
                "--testSequencer",
                "--setupFiles",
                "--setupFilesAfterEnv",
                "--maxConcurrency",
                "--workerIdleMemoryLimit",
            }
        ),
        {
            "-t": "selects tests by name (-t)",
            "--testNamePattern": "selects tests by name (--testNamePattern)",
            "--testPathPattern": "selects test files by path (--testPathPattern)",
            "--testPathPatterns": "selects test files by path (--testPathPatterns)",
            "--testPathIgnorePatterns": "ignores test paths (--testPathIgnorePatterns)",
            "--selectProjects": "runs only some projects (--selectProjects)",
            "--ignoreProjects": "skips projects (--ignoreProjects)",
            "--shard": "runs one shard of the tests (--shard)",
            "--onlyChanged": "runs only tests related to changed files (--onlyChanged)",
            "-o": "runs only tests related to changed files (-o)",
            "--changedSince": "runs only tests related to changed files (--changedSince)",
            "--lastCommit": "runs only tests related to the last commit (--lastCommit)",
            "--findRelatedTests": "runs only tests related to given files (--findRelatedTests)",
            "--onlyFailures": "runs only previously failed tests (--onlyFailures)",
            "-f": "runs only previously failed tests (-f)",
            "--listTests": "lists tests without running them (--listTests)",
            "--roots": "restricts the test search (--roots)",
            "--rootDir": "restricts the test search (--rootDir)",
        },
    ),
    "vitest": (
        frozenset(
            {
                "-c",
                "--config",
                "-r",
                "--root",
                "--dir",
                "-t",
                "--testNamePattern",
                "--project",
                "--shard",
                "--reporter",
                "--outputFile",
                "--environment",
                "--pool",
                "--exclude",
                "--testTimeout",
                "--mode",
                "--maxWorkers",
                "--minWorkers",
                "--retry",
                "--bail",
            }
        ),
        {
            "-t": "selects tests by name (-t)",
            "--testNamePattern": "selects tests by name (--testNamePattern)",
            "--project": "runs only some projects (--project)",
            "--shard": "runs one shard of the tests (--shard)",
            "--changed": "runs only tests related to changed files (--changed)",
            "--dir": "restricts the test search (--dir)",
            "--root": "restricts the test search (--root)",
            "-r": "restricts the test search (-r)",
            "--exclude": "excludes test files (--exclude)",
            "related": "runs only tests related to given files (vitest related)",
            "list": "lists tests without running them (vitest list)",
        },
    ),
    "mocha": (
        frozenset(
            {
                "-r",
                "--require",
                "-R",
                "--reporter",
                "-O",
                "--reporter-option",
                "-t",
                "--timeout",
                "-s",
                "--slow",
                "-u",
                "--ui",
                "--config",
                "--package",
                "--extension",
                "--ignore",
                "--exclude",
                "-g",
                "--grep",
                "-f",
                "--fgrep",
                "--spec",
                "--file",
                "-j",
                "--jobs",
                "--retries",
                "-n",
                "--node-option",
            }
        ),
        {
            "-g": "selects tests by name (-g)",
            "--grep": "selects tests by name (--grep)",
            "-f": "selects tests by name (-f)",
            "--fgrep": "selects tests by name (--fgrep)",
            "-i": "inverts the test selection (-i)",
            "--invert": "inverts the test selection (--invert)",
            "--ignore": "ignores test files (--ignore)",
            "--exclude": "ignores test files (--exclude)",
        },
    ),
    "node": (
        frozenset(
            {
                "--test-name-pattern",
                "--test-skip-pattern",
                "--test-shard",
                "--test-reporter",
                "--test-reporter-destination",
                "--test-concurrency",
                "--test-timeout",
                "--import",
                "--require",
                "-r",
                "--loader",
                "--experimental-loader",
                "--env-file",
                "--conditions",
                "-C",
            }
        ),
        {
            "--test-name-pattern": "selects tests by name (--test-name-pattern)",
            "--test-skip-pattern": "skips tests by name (--test-skip-pattern)",
            "--test-shard": "runs one shard of the tests (--test-shard)",
            "--test-only": "runs only tests marked only (--test-only)",
        },
    ),
    "playwright": (
        frozenset(
            {
                "-c",
                "--config",
                "-g",
                "--grep",
                "-gv",
                "--grep-invert",
                "--project",
                "--shard",
                "--reporter",
                "-j",
                "--workers",
                "--timeout",
                "--retries",
                "--output",
                "--max-failures",
                "--repeat-each",
                "--global-timeout",
                "--trace",
                "--browser",
            }
        ),
        {
            "-g": "selects tests by name (-g)",
            "--grep": "selects tests by name (--grep)",
            "-gv": "skips tests by name (-gv)",
            "--grep-invert": "skips tests by name (--grep-invert)",
            "--project": "runs only some projects (--project)",
            "--shard": "runs one shard of the tests (--shard)",
            "--only-changed": "runs only tests related to changed files (--only-changed)",
            "--last-failed": "runs only previously failed tests (--last-failed)",
            "--list": "lists tests without running them (--list)",
        },
    ),
    "ava": (
        frozenset({"-m", "--match", "--timeout", "-T", "--concurrency", "-c"}),
        {
            "-m": "selects tests by name (-m)",
            "--match": "selects tests by name (--match)",
        },
    ),
}
# Test runners (no filters read for the ones without options above).
_RUNNERS = {
    "jest": "jest",
    "vitest": "vitest",
    "mocha": "mocha",
    "_mocha": "mocha",
    "ava": "ava",
    "tap": "tap",
    "uvu": "uvu",
    "jasmine": "jasmine",
    "karma": "karma",
    "wdio": "wdio",
    "testcafe": "testcafe",
    "web-test-runner": "wtr",
    "wtr": "wtr",
    "turbo": "turbo",
    "nx": "nx",
    "lerna": "lerna",
}
# Commands that run no tests: a test script made of only these runs none.
_NOT_RUNNERS = frozenset(
    {
        "echo",
        "true",
        ":",
        "exit",
        "printf",
        "sleep",
        "tsc",
        "eslint",
        "prettier",
        "biome",
        "rimraf",
        "rm",
        "mkdir",
        "cp",
        "mv",
        "touch",
        "cat",
        "ls",
    }
)
_WRAPPERS = frozenset({"npx", "pnpx", "bunx", "cross-env", "env", "time", "nyc", "c8"})
_PACKAGE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class _Runs:
    """The test runner invocations a package.json script makes, following
    ``npm run``/``pnpm``/``yarn`` and ``run-s``/``run-p`` into other scripts.
    ``opaque`` when it runs a command that may run tests in a way Skylos
    cannot see (``node scripts/test.js``)."""

    def __init__(self, script: str, scripts: dict, depth: int = 0) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.opaque = False
        if script:
            self._script(script, scripts, depth, [])

    def _script(self, script: str, scripts: dict, depth: int, extra: list[str]):
        for _, argv in _commands(script):
            self._command(argv, scripts, depth, extra)

    def _command(self, argv: list[str], scripts: dict, depth: int, extra: list[str]):
        index = 0
        while index < len(argv):
            token = argv[index]
            name = PurePosixPath(token).name
            if _ENV_ASSIGNMENT_RE.match(token):
                index += 1
            elif name in _WRAPPERS:
                index += 1
                while index < len(argv) and argv[index].startswith("-"):
                    index += 1
            elif name == "dotenv":
                index = argv.index("--") + 1 if "--" in argv[index:] else len(argv)
            elif name in {"pnpm", "yarn", "npm"} and argv[index + 1 : index + 2] in (
                ["exec"],
                ["dlx"],
            ):
                index += 2
            else:
                break
        argv = argv[index:]
        if not argv:
            return
        name = PurePosixPath(argv[0]).name
        rest = argv[1:]
        if name in _NOT_RUNNERS:
            return
        if name in _RUNNERS:
            self.calls.append((_RUNNERS[name], [*rest, *extra]))
        elif name == "playwright" and rest[:1] == ["test"]:
            self.calls.append(("playwright", [*rest[1:], *extra]))
        elif name in {"react-scripts", "craco", "rescripts"} and rest[:1] == ["test"]:
            self.calls.append(("jest", [*rest[1:], *extra]))
        elif name in {"bun", "deno"} and rest[:1] == ["test"]:
            self.calls.append((name, [*rest[1:], *extra]))
        elif name in {"node", "tsx", "ts-node"} and "--test" in rest:
            self.calls.append(("node", [*rest, *extra]))
        elif name in {"cypress"} and rest[:1] == ["run"]:
            self.calls.append(("cypress", [*rest[1:], *extra]))
        elif name in _PACKAGE_MANAGERS or name in {"run-s", "run-p", "npm-run-all"}:
            self._delegate(name, rest, scripts, depth, extra)
        elif name == "concurrently":
            for item in rest:
                if not item.startswith("-"):
                    if item.startswith("npm:"):
                        self._run_scripts([item[4:]], scripts, depth, extra)
                    else:
                        self._script(item, scripts, depth + 1, extra)
        else:
            self.opaque = True

    def _delegate(self, name, rest, scripts, depth, extra):
        if "--" in rest:
            split = rest.index("--")
            rest, extra = rest[:split], [*rest[split + 1 :], *extra]
        words = [item for item in rest if not item.startswith("-")]
        if name in {"run-s", "run-p", "npm-run-all"}:
            self._run_scripts(words, scripts, depth, extra)
        elif words[:1] in (["test"], ["t"], ["tst"]):
            self._run_scripts(["test"], scripts, depth, extra)
        elif words[:1] in (["run"], ["run-script"]) and len(words) > 1:
            self._run_scripts(words[1:2], scripts, depth, extra)
        elif name in {"pnpm", "yarn", "bun"} and words and words[0] in scripts:
            self._run_scripts(words[:1], scripts, depth, extra)
        elif words[:1] in (["install"], ["ci"], ["i"], ["build"], ["add"]):
            return
        else:
            self.opaque = True

    def _run_scripts(self, patterns, scripts, depth, extra):
        if depth >= 4:
            self.opaque = True
            return
        for pattern in patterns:
            names = [n for n in scripts if fnmatch.fnmatchcase(n, pattern)]
            if not names:
                self.opaque = True
            for name in names:
                if isinstance(scripts[name], str):
                    self._script(scripts[name], scripts, depth + 1, extra)


def _commands(script: str) -> list[tuple[str | None, list[str]]]:
    """Commands of a shell script, each with the operator before it."""
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = script.split()
    commands: list[tuple[str | None, list[str]]] = []
    current: list[str] = []
    operator = None
    for token in tokens:
        if token and set(token) <= set(";&|()"):
            if current:
                commands.append((operator, current))
                current = []
            operator = token
            continue
        current.append(token)
    if current:
        commands.append((operator, current))
    return commands


def _fallbacks(script: str) -> int:
    """``||`` fallbacks that turn a failure into success (``|| exit 1`` and
    ``|| false`` keep it a failure)."""
    count = 0
    for operator, argv in _commands(script):
        if operator != "||":
            continue
        if argv[:1] == ["false"] or (
            argv[:1] == ["exit"] and argv[1:2] and argv[1] not in {"0"}
        ):
            continue
        count += 1
    return count


def _narrowed(before: list, after: list) -> list[str]:
    """Filters the runners in ``after`` apply that ``before`` did not, as
    "selects tests by name (-t) 'x'"; new or removed test-path arguments."""
    messages = []
    for runner in dict.fromkeys(name for name, _ in after):
        old_flags, old_paths = _filters(runner, before)
        new_flags, new_paths = _filters(runner, after)
        descriptions = _RUNNER_OPTIONS.get(runner, (frozenset(), {}))[1]
        for flag, value in sorted(new_flags - old_flags):
            shown = f" {value!r}" if value else ""
            messages.append(f"{descriptions[flag]}{shown}")
        if any(flag in {"--findRelatedTests", "related"} for flag, _ in new_flags):
            continue  # the paths name source files, reported with the option
        if new_paths and not old_paths:
            messages.append(
                "runs only test files matching "
                + ", ".join(repr(p) for p in sorted(new_paths))
            )
        elif new_paths and old_paths - new_paths:
            messages.append(
                "no longer runs test files matching "
                + ", ".join(repr(p) for p in sorted(old_paths - new_paths))
            )
    return messages


def _filters(runner: str, calls: list) -> tuple[set[tuple[str, str]], set[str]]:
    """(filter options with values, test-path arguments) across one runner's
    invocations."""
    values, descriptions = _RUNNER_OPTIONS.get(runner, (frozenset(), {}))
    flags: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for name, args in calls:
        if name != runner:
            continue
        args = list(args)
        if (
            runner == "vitest"
            and args[:1]
            and args[0]
            in {
                "run",
                "watch",
                "dev",
                "related",
                "bench",
                "list",
            }
        ):
            if args[0] in descriptions:
                flags.add((args[0], ""))
            args = args[1:]
        index = 0
        while index < len(args):
            token = args[index]
            index += 1
            if token == "--":
                paths.update(args[index:])
                break
            if not token.startswith("-"):
                paths.add(token)
                continue
            flag, equals, value = token.partition("=")
            if not equals and flag in values and index < len(args):
                value = args[index]
                index += 1
            elif (
                not equals
                and runner == "vitest"
                and flag.startswith("--")
                and "." in flag
                and index < len(args)
                and not args[index].startswith("-")
            ):
                index += 1  # --coverage.provider v8
            if flag in descriptions:
                flags.add((flag, value))
    return flags, paths


def _existed(comparison: Comparison, directory: str) -> bool:
    """The package in ``directory`` existed at the base (a new package's
    settings are new code, not a loosening)."""
    return comparison.base_text(posixpath.join(directory, "package.json")) is not None


def _has_flag(script: str, flag: str) -> bool:
    try:
        tokens = shlex.split(script)
    except ValueError:
        tokens = script.split()
    return any(token == flag or token.startswith(flag + "=") for token in tokens)


# ---------------------------------------------------------------------------
# Comparing values
# ---------------------------------------------------------------------------


def _added_patterns(before, after, defaults: set[str]) -> list[str]:
    """String entries ``after`` adds to ``before`` (both lists), sorted."""
    if not isinstance(after, list):
        return []
    if before is None:
        known: set[str] = set(defaults)
    elif isinstance(before, list) and all(
        isinstance(item, str) or item is _DEFAULTS_SPREAD for item in before
    ):
        known = {item for item in before if isinstance(item, str)}
        if _DEFAULTS_SPREAD in before:
            known |= defaults
    else:
        return []  # the base list is computed: no confident comparison
    return sorted({item for item in after if isinstance(item, str)} - known)


def _lowered(before, after):
    """(where, old, "lowered to N" / "removed") for each lowered threshold.

    Jest reads a negative threshold as "at most N uncovered"; a change between
    a percentage and a count is not compared.
    """
    if before is UNKNOWN or after is UNKNOWN:
        return []
    result = []
    for where, old in sorted(before.items()):
        new = after.get(where)
        if new is None:
            result.append((where, old, "removed"))
        elif (old >= 0) == (new >= 0) and new < old:
            result.append((where, old, f"lowered to {new:g}"))
    return result


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _json_object(text: str):
    try:
        data = json.loads(text)
    except ValueError:
        return UNKNOWN
    return data if isinstance(data, dict) else UNKNOWN


def _line_of(text: str | None, needle: str | None) -> int | None:
    if not text or not needle:
        return None
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return None


# ---------------------------------------------------------------------------
# Reading a JS/TS config module statically
# ---------------------------------------------------------------------------


class _DefaultsSpread:
    """``...configDefaults.exclude`` inside a Vitest exclude list."""


_DEFAULTS_SPREAD = _DefaultsSpread()


def _module_config(path: str, text: str):
    """The object a config module exports, as Python values, or UNKNOWN."""
    from skylos.done.js_inventory import _parse

    root = _parse(path, text)
    if root is None or root.has_error:
        return UNKNOWN
    exported = []
    for node in root.named_children:
        if node.type == "export_statement" and any(
            child.type == "default" for child in node.children
        ):
            value = node.child_by_field_name("value")
            if value is None:
                return UNKNOWN  # export default function/class
            exported.append(value)
        elif node.type == "expression_statement":
            assignment = node.named_children[0] if node.named_children else None
            if (
                assignment is not None
                and assignment.type == "assignment_expression"
                and _source(assignment.child_by_field_name("left")) == "module.exports"
            ):
                exported.append(assignment.child_by_field_name("right"))
    if len(exported) != 1:
        return UNKNOWN
    reader = _Reader(root)
    value = reader.value(exported[0], unwrap=True)
    return value if isinstance(value, dict) else UNKNOWN


def _source(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


class _Reader:
    """Literal values, with top-level ``const`` names that nothing changes."""

    def __init__(self, root) -> None:
        self.bindings: dict[str, object] = {}
        counts: dict[str, int] = {}
        for node in root.named_children:
            declaration = (
                node.child_by_field_name("declaration")
                if node.type == "export_statement"
                else node
            )
            if declaration is None or declaration.type not in {
                "lexical_declaration",
                "variable_declaration",
            }:
                continue
            for declarator in declaration.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                if name is None or name.type != "identifier":
                    continue
                counts[_source(name)] = counts.get(_source(name), 0) + 1
                self.bindings[_source(name)] = declarator.child_by_field_name("value")
        self.unsafe = {name for name, count in counts.items() if count > 1}
        self.unsafe |= _changed_names(root)

    def value(self, node, *, unwrap: bool = False, depth: int = 0):
        if node is None or depth > 20:
            return UNKNOWN
        kind = node.type
        if kind in {
            "parenthesized_expression",
            "as_expression",
            "satisfies_expression",
            "non_null_expression",
        }:
            inner = node.named_children[0] if node.named_children else None
            return self.value(inner, unwrap=unwrap, depth=depth + 1)
        if kind == "string":
            from skylos.done.js_inventory import _string_value

            return _string_value(node)
        if kind == "template_string":
            from skylos.done.js_inventory import _static_title

            text = _static_title(node)
            return UNKNOWN if text is None else text
        if kind == "number":
            return _number(_source(node))
        if kind == "unary_expression":
            operand = node.child_by_field_name("argument")
            operator = node.child_by_field_name("operator")
            number = self.value(operand, depth=depth + 1)
            if _source(operator) == "-" and _is_number(number):
                return -number
            return UNKNOWN
        if kind == "true":
            return True
        if kind == "false":
            return False
        if kind in {"null", "undefined"}:
            return None
        if kind == "array":
            items = []
            for child in node.named_children:
                if child.type == "comment":
                    continue
                if child.type == "spread_element":
                    spread = child.named_children[0] if child.named_children else None
                    items.append(
                        _DEFAULTS_SPREAD
                        if _source(spread) == "configDefaults.exclude"
                        else UNKNOWN
                    )
                else:
                    items.append(self.value(child, depth=depth + 1))
            return items
        if kind == "object":
            result: dict[str, object] = {}
            for child in node.named_children:
                if child.type == "comment":
                    continue
                if child.type == "pair":
                    key = _key(child.child_by_field_name("key"))
                    if key is None:
                        return UNKNOWN
                    result[key] = self.value(
                        child.child_by_field_name("value"), depth=depth + 1
                    )
                elif child.type == "shorthand_property_identifier":
                    result[_source(child)] = self._binding(_source(child), depth)
                elif child.type == "method_definition":
                    name = child.child_by_field_name("name")
                    result[_source(name)] = UNKNOWN
                else:
                    return UNKNOWN  # a spread: any key may come from elsewhere
            return result
        if kind == "identifier":
            if _source(node) == "undefined":
                return None
            return self._binding(_source(node), depth, unwrap=unwrap)
        if kind == "call_expression" and unwrap:
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if _source(function) in _DEFINE_CALLS and arguments is not None:
                items = [c for c in arguments.named_children if c.type != "comment"]
                if len(items) == 1:
                    return self.value(items[0], unwrap=True, depth=depth + 1)
        return UNKNOWN

    def _binding(self, name: str, depth: int, *, unwrap: bool = False):
        if name in self.unsafe or name not in self.bindings:
            return UNKNOWN
        return self.value(self.bindings[name], unwrap=unwrap, depth=depth + 1)


def _key(node) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        from skylos.done.js_inventory import _string_value

        return _string_value(node)
    if node.type in {"property_identifier", "number"}:
        return _source(node)
    return None  # computed key


def _number(text: str):
    cleaned = text.replace("_", "")
    try:
        if cleaned.lower().startswith(("0x", "0o", "0b")):
            return int(cleaned, 0)
        return float(cleaned) if any(c in cleaned for c in ".eE") else int(cleaned)
    except ValueError:
        return UNKNOWN


def _changed_names(root) -> set[str]:
    """Top-level names a module may change after declaring them: assigned,
    mutated through a member, or handed to a function (other than a
    ``defineConfig``-style identity wrapper)."""
    changed: set[str] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        kind = node.type
        if kind in {"assignment_expression", "augmented_assignment_expression"}:
            name = _root_name(node.child_by_field_name("left"))
            if name:
                changed.add(name)
        elif kind == "update_expression":
            name = _root_name(node.child_by_field_name("argument"))
            if name:
                changed.add(name)
        elif (
            kind == "unary_expression"
            and _source(node.child_by_field_name("operator")) == "delete"
        ):
            name = _root_name(node.child_by_field_name("argument"))
            if name:
                changed.add(name)
        elif kind == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "member_expression":
                name = _root_name(function.child_by_field_name("object"))
                if name:
                    changed.add(name)  # config.exclude.push(...)
            arguments = node.child_by_field_name("arguments")
            if _source(function) not in _DEFINE_CALLS and arguments is not None:
                changed.update(
                    _source(child)
                    for child in arguments.named_children
                    if child.type == "identifier"
                )
        stack.extend(node.named_children)
    # ``module.exports = config`` assigns module, not config.
    changed.discard("module")
    return changed


def _root_name(node) -> str | None:
    while node is not None and node.type in {
        "member_expression",
        "subscript_expression",
        "parenthesized_expression",
        "non_null_expression",
    }:
        node = (
            node.child_by_field_name("object")
            if node.type in {"member_expression", "subscript_expression"}
            else (node.named_children[0] if node.named_children else None)
        )
    if node is not None and node.type == "identifier":
        return _source(node)
    return None
