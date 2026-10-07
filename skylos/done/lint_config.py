"""SKY-A119: linter, type-checker and scanner settings weakened by the change.

An agent can make a linter, type checker or scanner pass by changing what it
checks instead of the code: ignore a rule, exclude a directory, turn
``strict`` off, accept a secret in the baseline. Settings are compared per
tool and per directory, base against head, so moving settings between files
the tool reads together (``setup.cfg`` to ``pyproject.toml``, ``.eslintrc``
to ``eslint.config.js``) is not a change. Only what parses confidently is
compared: a config built at run time (a function, a spread, a variable
Skylos cannot resolve) contributes nothing, and an inherited value Skylos
cannot read is never assumed.

A new exclude or ignore pattern counts only when it matches a file the tool
checks (build output, vendored and generated files never count); one that
matches only test files is advice. ``skipLibCheck`` is not a weakening.
"""

from __future__ import annotations

import configparser
import json
import posixpath
import re
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

RULE_LINT_CONFIG = "SKY-A119"

_PY = (".py", ".pyi")
_JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte")
_CODE = (
    *_PY,
    *_JS,
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".scala",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".sh",
)
# Never source a tool was checking: build output, dependencies, caches.
_NOT_SOURCE_DIRS = frozenset(
    {
        "node_modules",
        "dist",
        "build",
        "out",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".output",
        ".turbo",
        ".vercel",
        "coverage",
        "htmlcov",
        "vendor",
        "third_party",
        "third-party",
        "generated",
        "__generated__",
        ".venv",
        "venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        "site-packages",
        "target",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".git",
        "migrations",
        "storybook-static",
        ".cache",
    }
)
_NOT_SOURCE_SUFFIXES = (
    ".min.js",
    ".d.ts",
    ".d.mts",
    ".d.cts",
    "_pb2.py",
    "_pb2_grpc.py",
    ".generated.ts",
    ".generated.js",
    ".gen.ts",
    ".gen.go",
    ".pb.go",
)
_TEST_DIRS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "__mocks__",
        "__fixtures__",
        "fixtures",
        "e2e",
        "cypress",
        "playwright",
    }
)


@dataclass(frozen=True)
class Weakening:
    file: str
    line: int | None
    message: str
    blocking: bool = True


class _Unknown:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unknown>"


UNKNOWN = _Unknown()


@dataclass
class Policy:
    """What one tool checks, from all its settings files in one place.

    ``added``: key -> entries whose addition weakens (ignored rules, excluded
    paths, allowed findings). ``removed``: key -> entries whose removal
    weakens (selected rules, presets). ``levels``: key -> (rank, shown),
    where a lower rank checks less. ``rules``: (scope, rule) -> (rank,
    shown) for per-rule severities, where 0 is off.
    """

    added: dict[tuple, set[str]] = field(default_factory=dict)
    removed: dict[tuple, set[str]] = field(default_factory=dict)
    levels: dict[tuple, tuple[float, str]] = field(default_factory=dict)
    rules: dict[tuple[str, str], tuple[int, str]] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    # Level keys set in a file rather than implied by ``strict``.
    explicit: set[tuple] = field(default_factory=set)

    def add(self, key: tuple, entries) -> None:
        values = {str(e).strip() for e in entries if str(e).strip()}
        if values:
            self.added.setdefault(key, set()).update(values)

    def require(self, key: tuple, entries) -> None:
        values = {str(e).strip() for e in entries if str(e).strip()}
        if values:
            self.removed.setdefault(key, set()).update(values)

    def level(self, key: tuple, rank: float, shown: str) -> None:
        # Two files setting one level: the weaker one is what runs.
        if key not in self.levels or rank < self.levels[key][0]:
            self.levels[key] = (rank, shown)

    def rule(self, scope: str, name: str, rank: int | None, shown: str) -> None:
        if rank is None:
            return
        key = (scope, name)
        if key not in self.rules or rank < self.rules[key][0]:
            self.rules[key] = (rank, shown)

    def merge(self, other: Policy) -> None:
        for key, values in other.added.items():
            self.added.setdefault(key, set()).update(values)
        for key, values in other.removed.items():
            self.removed.setdefault(key, set()).update(values)
        for key, (rank, shown) in other.levels.items():
            self.level(key, rank, shown)
        for (scope, name), (rank, shown) in other.rules.items():
            self.rule(scope, name, rank, shown)
        self.files += other.files
        self.explicit |= other.explicit

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.levels or self.rules)


# ---------------------------------------------------------------------------
# Which tools read which files
# ---------------------------------------------------------------------------

_ESLINT_FILES = frozenset(
    {
        ".eslintrc",
        ".eslintrc.json",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.yaml",
        ".eslintrc.yml",
        ".eslintignore",
        *(
            f"eslint.config.{suffix}"
            for suffix in ("js", "mjs", "cjs", "ts", "mts", "cts")
        ),
    }
)
_GOLANGCI_FILES = frozenset(
    {".golangci.yml", ".golangci.yaml", ".golangci.toml", ".golangci.json"}
)
_XML_SUPPRESSIONS = re.compile(
    r"(?:checkstyle[-_]?suppressions?|suppressions|spotbugs[-_]?exclude[\w-]*"
    r"|findbugs[-_]?exclude[\w-]*)\.xml$",
    re.I,
)


def tools_for(path: str) -> list[tuple[str, str]]:
    """(tool, group) for each tool that reads ``path``. Files in one group
    are compared together: a tool's files in one directory, or the file
    itself for tools whose files are separate projects (tsconfig)."""
    pure = PurePosixPath(path)
    name = pure.name
    directory = posixpath.dirname(path)
    if "node_modules" in pure.parts:
        return []
    tools: list[tuple[str, str]] = []
    if name == "pyproject.toml":
        tools += [
            (tool, directory)
            for tool in ("ruff", "flake8", "pylint", "mypy", "pyright", "bandit")
        ]
    elif name in {"ruff.toml", ".ruff.toml"}:
        tools.append(("ruff", directory))
    elif name in {"setup.cfg", "tox.ini"}:
        tools += [(tool, directory) for tool in ("flake8", "pylint", "mypy")]
    elif name == ".flake8":
        tools.append(("flake8", directory))
    elif name in {"mypy.ini", ".mypy.ini"}:
        tools.append(("mypy", directory))
    elif name == "pyrightconfig.json":
        tools.append(("pyright", directory))
    elif name in {".pylintrc", "pylintrc"}:
        tools.append(("pylint", directory))
    elif name in {
        ".bandit",
        "bandit.yaml",
        "bandit.yml",
        ".bandit.yaml",
        ".bandit.yml",
    }:
        tools.append(("bandit", directory))
    elif re.fullmatch(r"[tj]sconfig(?:\.[\w.-]+)?\.json", name):
        tools.append(("TypeScript", path))
    elif name in _ESLINT_FILES or name == "package.json":
        tools.append(("ESLint", directory))
    elif name in {"biome.json", "biome.jsonc"}:
        tools.append(("Biome", directory))
    elif name in {"sonar-project.properties", ".sonarcloud.properties"}:
        tools.append(("SonarQube", directory))
    elif name == ".semgrepignore":
        tools.append(("Semgrep", directory))
    elif name in {".gitleaksignore", ".gitleaks.toml", "gitleaks.toml"}:
        tools.append(("gitleaks", directory))
    elif name == ".secrets.baseline":
        tools.append(("detect-secrets", path))
    elif name == ".trivyignore":
        tools.append(("Trivy", directory))
    elif name == "osv-scanner.toml":
        tools.append(("OSV-Scanner", directory))
    elif name == ".snyk":
        tools.append(("Snyk", directory))
    elif name in _GOLANGCI_FILES:
        tools.append(("golangci-lint", directory))
    elif name == "Cargo.toml":
        tools.append(("Cargo lints", path))
    elif name == ".pre-commit-config.yaml":
        tools.append(("pre-commit", directory))
    elif name.endswith((".yml", ".yaml")) and (
        path.startswith(".github/codeql/")
        or re.fullmatch(r"codeql[-_.\w]*\.ya?ml", name)
    ):
        tools.append(("CodeQL", path))
    elif _XML_SUPPRESSIONS.search(name):
        tools.append(("Checkstyle/SpotBugs", path))
    return tools


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class _Repo:
    """The repository's files, to tell whether a new pattern excludes
    anything a tool was checking."""

    paths: list[str]
    existed: set[str]
    is_test: Callable[[str], bool]
    read: Callable[[str], str | None] = lambda path: None
    _cache: dict = field(default_factory=dict)

    def generated(self, path: str) -> bool:
        from skylos.done.answer_sites import _is_generated

        key = ("generated", path)
        if key not in self._cache:
            self._cache[key] = _is_generated(path, self.read(path))
        return self._cache[key]

    def had_code(self, directory: str) -> bool:
        """Whether ``directory`` held any source file at the base."""
        prefix = f"{directory}/" if directory else ""
        return any(p.startswith(prefix) for p in self.sources(_CODE, at_base=True))

    def sources(self, suffixes: tuple[str, ...], *, at_base: bool) -> list[str]:
        key = (suffixes, at_base)
        if key not in self._cache:
            self._cache[key] = [
                p
                for p in self.paths
                if p.endswith(suffixes)
                and (not at_base or p in self.existed)
                and not p.endswith(_NOT_SOURCE_SUFFIXES)
                and not _NOT_SOURCE_DIRS.intersection(PurePosixPath(p).parts[:-1])
            ]
        return self._cache[key]


def detect_weakened_settings(
    comparison, base_paths, head_paths, is_test: Callable[[str], bool]
) -> list[Weakening]:
    groups: dict[tuple[str, str], set[str]] = {}
    for changed in comparison.changed:
        for path in (changed.base_path, changed.head_path):
            if path:
                for tool, group in tools_for(path):
                    groups.setdefault((tool, group), set()).add(path)
    if not groups:
        return []
    base_set = [p for p in base_paths if p]
    head_set = [p for p in head_paths if p]
    by_group: dict[tuple[str, str], tuple[list[str], list[str]]] = {}
    for paths, index in ((base_set, 0), (head_set, 1)):
        for path in paths:
            for key in tools_for(path):
                if key in groups:
                    by_group.setdefault(key, ([], []))[index].append(path)
    repo = _Repo(
        sorted(set(base_set) | set(head_set)),
        set(base_set),
        is_test,
        lambda path: comparison.head_text(path) or comparison.base_text(path),
    )
    findings: list[Weakening] = []
    for (tool, group), changed_paths in sorted(groups.items()):
        base_files, head_files = by_group.get((tool, group), ([], []))
        base_texts = {p: comparison.base_text(p) for p in sorted(set(base_files))}
        head_texts = {p: comparison.head_text(p) for p in sorted(set(head_files))}
        head_texts = {p: t for p, t in head_texts.items() if t is not None}
        base_texts = {p: t for p, t in base_texts.items() if t is not None}
        if base_texts == head_texts:
            continue

        def read_base(path, texts=base_texts):
            if path in texts:
                return texts[path]
            return comparison.base_text(path)

        def read_head(path, texts=head_texts):
            if path in texts:
                return texts[path]
            return comparison.head_text(path)

        before = _policy(tool, group, base_texts, read_base)
        after = _policy(tool, group, head_texts, read_head)
        if before is None or after is None:
            continue  # a file Skylos cannot read: compare nothing
        located = _Locator(head_texts, sorted(changed_paths)[0])
        findings += _compare(tool, group, before, after, repo, located)
    return findings


class _Locator:
    """Where an entry is written at head, for the finding's file and line."""

    def __init__(self, texts: dict[str, str], fallback: str) -> None:
        self.texts = texts
        self.fallback = fallback

    def find(self, *needles: str) -> tuple[str, int | None]:
        for needle in needles:
            if not needle:
                continue
            for path, text in self.texts.items():
                for index, line in enumerate(text.splitlines(), 1):
                    if needle in line:
                        return path, index
        path = (
            self.fallback
            if self.fallback in self.texts
            else next(iter(self.texts), self.fallback)
        )
        return path, None


def _policy(tool, group, texts: dict[str, str], read) -> Policy | None:
    policy = Policy()
    for path, text in sorted(texts.items()):
        part = _PARSERS[tool](path, text, read)
        if part is UNKNOWN:
            return None
        if part is not None:
            part.files.append(path)
            policy.merge(part)
    return policy


# ---------------------------------------------------------------------------
# Comparing
# ---------------------------------------------------------------------------


def _compare(tool, group, before: Policy, after: Policy, repo: _Repo, where: _Locator):
    findings: list[Weakening] = []
    # A tool with no settings here at the base: only files that existed then
    # can be newly excluded, and a rule a new config leaves off was not on.
    fresh = not before.files
    if fresh and not repo.had_code(_scope_directory(tool, group)):
        return findings  # a new package: its first settings weaken nothing

    def report(message: str, *needles: str, blocking: bool = True) -> None:
        path, line = where.find(*needles)
        findings.append(Weakening(path, line, message, blocking))

    def excluded(style, root, pattern, suffixes):
        return _excludes(repo, style, root, pattern, suffixes, at_base=fresh)

    for key, entries in sorted(after.added.items(), key=lambda kv: repr(kv[0])):
        for entry in sorted(entries - before.added.get(key, set())):
            kind = key[1]
            if kind == "rules":
                if _rule_matters(tool, entry, after):
                    report(f"{tool} now {key[2]} {entry}", entry)
            elif kind == "paths":
                _, _, style, root, verb, suffixes = key
                verdict = excluded(style, root, entry, suffixes)
                if verdict is None:
                    continue
                example, tests_only = verdict
                if tests_only:
                    report(
                        f"(advice) {tool} now {verb} {entry!r}, which holds only "
                        f"test files (e.g. {example})",
                        entry,
                        blocking=False,
                    )
                else:
                    report(f"{tool} now {verb} {entry!r} (e.g. {example})", entry)
            elif kind == "file-rules":
                _, _, style, root, pattern, suffixes = key
                verdict = excluded(style, root, pattern, suffixes)
                if verdict is None or not _rule_matters(tool, entry, after):
                    continue
                example, tests_only = verdict
                message = f"{tool} now ignores {entry} in {pattern!r} (e.g. {example})"
                if tests_only:
                    report(
                        f"(advice) {message}, which holds only test files",
                        pattern,
                        blocking=False,
                    )
                else:
                    report(message, pattern, entry)
            elif kind == "modules":
                verdict = excluded("module", "", key[2], _PY)
                if verdict is None:
                    continue
                message = f"{tool} {entry} (e.g. {verdict[0]})"
                if verdict[1]:
                    report(
                        f"(advice) {message}, which holds only test files",
                        key[2],
                        blocking=False,
                    )
                else:
                    report(message, key[2])
            else:  # "items": entries that are their own evidence
                report(f"{tool} now {key[2]} {entry}", *_needles(entry))
    for key, entries in sorted(before.removed.items(), key=lambda kv: repr(kv[0])):
        remaining = after.removed.get(key, set())
        for entry in sorted(entries - remaining):
            if key[1] == "include":
                _removed_include(tool, key, entry, after, repo, report)
            elif _config_format_changed(tool, key, before, after):
                continue  # .eslintrc to eslint.config.js: presets are renamed
            elif not _still_covered(tool, key, entry, remaining):
                report(
                    f"{tool} no longer {key[2]} {entry}",
                    _SETTING_NAMES.get(key[1], key[1]),
                )
    defaults = _LEVEL_DEFAULTS.get(tool, {})
    for key in sorted(set(before.levels) | set(after.levels), key=repr):
        old = before.levels.get(key) or (
            defaults.get(key[1]) if not before.levels else None
        )
        new = after.levels.get(key) or (
            defaults.get(key[1]) if not after.levels else None
        )
        if old is None or new is None or new[0] >= old[0]:
            continue
        if (
            key[1] in _STRICT_FAMILY
            and key not in before.explicit
            and _strict_dropped(key, before, after)
        ):
            continue  # reported once, as strict
        setting = key[1]
        if {old[1], new[1]} <= {"on", "off"}:
            message = f"{tool} {setting} turned {new[1]}"
        else:
            message = f"{tool} {setting} lowered from {old[1]} to {new[1]}"
        report(message, setting)
    off_anywhere = {name for (_, name), (rank, _) in before.rules.items() if rank == 0}
    for (scope, name), (rank, shown) in sorted(after.rules.items()):
        scoped = "" if scope == "*" else f" for {scope}"
        old = before.rules.get((scope, name))
        if old is not None:
            if rank < old[0]:
                verb = (
                    "turned off"
                    if shown in _OFF_NAMES
                    else f"lowered from {old[1]} to {shown}"
                )
                report(f"{tool} rule {name} {verb}{scoped}", name)
        elif rank == 0 and name not in off_anywhere and not fresh and scope != "?":
            verb = "turned off" if shown in _OFF_NAMES else f"set to {shown}"
            report(f"{tool} rule {name} {verb}{scoped}", name)
    return findings


_OFF_NAMES = frozenset({"off", "none", "false", "0"})
# Scanners whose settings cover the whole repository wherever they live.
_REPOSITORY_WIDE = frozenset(
    {
        "CodeQL",
        "detect-secrets",
        "gitleaks",
        "Trivy",
        "OSV-Scanner",
        "Snyk",
        "Semgrep",
        "SonarQube",
        "Checkstyle/SpotBugs",
    }
)


def _scope_directory(tool: str, group: str) -> str:
    """The directory whose code a tool's settings group covers."""
    if tool in _REPOSITORY_WIDE:
        return ""
    if tool in {"TypeScript", "Cargo lints"}:
        return posixpath.dirname(group)  # the group is the settings file
    return group


_SETTING_NAMES = {
    "selected": "select",
    "enabled": "enable",
    "extends": "extends",
    "strict": "strict",
    "hooks": "repos",
    "plugins": "plugins_used",
    "queries": "queries",
    "include": "include",
}


def _needles(entry: str) -> list[str]:
    needles = [entry]
    inside = re.search(r"\(([^()]+)\)$", entry)
    if inside:
        needles.append(inside.group(1))
    needles += sorted(
        (w for w in re.split(r"[\s'\"]+", entry) if len(w) > 3), key=len, reverse=True
    )
    return needles


def _removed_include(tool, key, entry, after: Policy, repo: _Repo, report) -> None:
    """A tsconfig include entry removed: report it when files it covered
    are no longer covered by what remains (no include means everything)."""
    root, suffixes = key[3], key[4]
    remaining = after.removed.get(key) or {"**/*"}
    old = _matcher("anchored", entry)
    if old is None:
        return
    keep = [m for m in (_matcher("anchored", r) for r in remaining) if m is not None]
    prefix = f"{root}/" if root else ""
    lost = [
        p
        for p in repo.sources(suffixes, at_base=True)
        if p.startswith(prefix)
        and old(p[len(prefix) :])
        and not any(m(p[len(prefix) :]) for m in keep)
    ]
    if not lost:
        return
    sources = [p for p in lost if not repo.is_test(p) and not _testish(p)]
    if sources:
        report(f"{tool} no longer includes {entry!r} (e.g. {sources[0]})", "include")
    else:
        report(
            f"(advice) {tool} no longer includes {entry!r}, which holds only test "
            f"files (e.g. {lost[0]})",
            "include",
            blocking=False,
        )


_RUFF_DEFAULT_SELECT = {"E4", "E7", "E9", "F"}


def _rule_matters(tool: str, code: str, after: Policy) -> bool:
    """Ignoring a ruff code no selected rule covers changes nothing."""
    if tool != "ruff":
        return True
    selected = after.removed.get(("ruff", "selected", "selects"), _RUFF_DEFAULT_SELECT)
    return any(s == "ALL" or code.startswith(s) or s.startswith(code) for s in selected)


def _still_covered(tool: str, key: tuple, entry: str, remaining: set[str]) -> bool:
    if tool == "ruff" and key[1] == "selected":
        return any(s == "ALL" or entry.startswith(s) for s in remaining)
    if tool == "ESLint" and key[1] == "extends":
        # "recommended" swapped for "strict" from the same plugin: a swap.
        family = _preset_family(entry)
        return any(_preset_family(other) == family for other in remaining)
    if tool == "pre-commit" and key[1] == "hooks":
        # ruff -> ruff-check: the same hook renamed upstream.
        return any(
            other.startswith(entry) or entry.startswith(other) for other in remaining
        )
    return False


def _config_format_changed(
    tool: str, key: tuple, before: Policy, after: Policy
) -> bool:
    """ESLint presets are named differently in legacy and flat configs, and
    a directory whose config is gone falls under its parent's."""
    if tool != "ESLint" or key[1] != "extends":
        return False
    configs = [f for f in after.files if PurePosixPath(f).name != "package.json"]
    flat_before = any(
        PurePosixPath(f).name.startswith("eslint.config.") for f in before.files
    )
    flat_after = any(
        PurePosixPath(f).name.startswith("eslint.config.") for f in configs
    )
    return (
        not configs
        or (flat_after and not flat_before)
        or (
            flat_after
            and any(PurePosixPath(f).name.startswith(".eslintrc") for f in before.files)
        )
    )


def _preset_family(preset: str) -> str:
    text = preset.replace("plugin:", "").replace("flat/", "")
    text = re.sub(r"\[\s*['\"]?([\w/@-]+)['\"]?\s*\]", r".\1", text)
    return re.split(r"[./]configs?[./]|/|:", text, maxsplit=1)[0]


def _strict_dropped(key: tuple, before: Policy, after: Policy) -> bool:
    strict = (key[0], "strict")
    return (
        strict in before.levels
        and strict in after.levels
        and after.levels[strict][0] < before.levels[strict][0]
    )


# ---------------------------------------------------------------------------
# Path patterns
# ---------------------------------------------------------------------------


def _excludes(
    repo: _Repo, style: str, root: str, pattern: str, suffixes, *, at_base: bool
):
    """(an example file the pattern now leaves out, whether all such files
    are tests), or None when it leaves out nothing the tool checked."""
    matcher = _matcher(style, pattern)
    if matcher is None:
        return None
    hits = []
    prefix = f"{root}/" if root else ""
    for path in repo.sources(suffixes, at_base=at_base):
        if prefix and not path.startswith(prefix):
            continue
        if matcher(path[len(prefix) :]):
            hits.append(path)
    # Generated files ("do not edit") were never the code's to lint.
    hits = [p for p in hits[:200] if not repo.generated(p)]
    if not hits:
        return None
    sources = [p for p in hits if not repo.is_test(p) and not _testish(p)]
    if sources:
        return sources[0], False
    return hits[0], True


def _testish(path: str) -> bool:
    return bool(_TEST_DIRS.intersection(PurePosixPath(path).parts[:-1]))


def _matcher(style: str, pattern: str):
    pattern = pattern.strip()
    if not pattern or pattern.startswith(("!", "#")):
        return None  # a re-include or a comment: never a new exclusion
    if style == "regex":
        try:
            compiled = re.compile(pattern)
        except re.error:
            return None
        return lambda path: compiled.search(path) is not None
    if style == "name-regex":
        try:
            compiled = re.compile(pattern)
        except re.error:
            return None
        return lambda path: any(compiled.match(part) for part in path.split("/"))
    if style == "basename":
        return lambda path: pattern in path.split("/")
    if style == "module":
        prefix = pattern.rstrip("*").rstrip(".")
        wildcard = pattern.endswith("*")

        def module_match(path: str) -> bool:
            module = path.rsplit(".", 1)[0].replace("/", ".")
            module = module.removesuffix(".__init__")
            for candidate in (module, module.split(".", 1)[-1]):
                if candidate == prefix or (
                    wildcard and candidate.startswith(prefix + ".")
                ):
                    return True
            return False

        return module_match
    regex = _glob_regex(pattern, anchored=style == "anchored")
    if regex is None:
        return None
    return lambda path: regex.match(path) is not None


def _glob_regex(pattern: str, *, anchored: bool) -> re.Pattern | None:
    """A gitignore-style glob as a regex over paths relative to its root. A
    pattern without a slash matches at any depth unless ``anchored``; a
    pattern naming a directory matches everything under it."""
    text = pattern.strip()
    if text.startswith("./"):
        text = text[2:]
    rooted = text.startswith("/") or anchored or "/" in text.rstrip("/")
    text = text.strip("/")
    if not text or text in {"**", "*", "**/*"}:
        return re.compile(r".*") if text else None
    out = []
    index = 0
    while index < len(text):
        char = text[index]
        if text.startswith("**/", index):
            out.append(r"(?:.*/)?")
            index += 3
        elif text.startswith("**", index):
            out.append(r".*")
            index += 2
        elif char == "*":
            out.append(r"[^/]*")
            index += 1
        elif char == "?":
            out.append(r"[^/]")
            index += 1
        elif char == "{":
            end = text.find("}", index)
            if end == -1:
                out.append(re.escape(char))
                index += 1
                continue
            options = text[index + 1 : end].split(",")
            out.append("(?:" + "|".join(re.escape(o) for o in options) + ")")
            index = end + 1
        elif char == "[":
            end = text.find("]", index)
            if end == -1:
                out.append(re.escape(char))
                index += 1
                continue
            body = text[index + 1 : end].replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append(f"[{body}]")
            index = end + 1
        else:
            out.append(re.escape(char))
            index += 1
    body = "".join(out)
    try:
        return re.compile(("" if rooted else r"(?:.*/)?") + body + r"(?:/.*)?$")
    except re.error:
        return None


# ---------------------------------------------------------------------------
# Reading settings files
# ---------------------------------------------------------------------------


def _toml(text: str):
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return UNKNOWN


def _yaml(text: str):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return UNKNOWN


def _jsonc(text: str):
    """JSON with comments and trailing commas (tsconfig, biome, eslintrc)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    out = []
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < size and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            out.append(text[index : end + 1])
            index = end + 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = size if end == -1 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = size if end == -1 else end + 2
        else:
            out.append(char)
            index += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    try:
        return json.loads(cleaned)
    except ValueError:
        return UNKNOWN


def _ini(text: str):
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # keep key case
    try:
        parser.read_string(text)
    except configparser.Error:
        return UNKNOWN
    return parser


def _list(value) -> list[str]:
    """A list setting written as a TOML/YAML list or a comma, space or
    newline separated string."""
    if value is None or value is UNKNOWN:
        return []
    if isinstance(value, (list, tuple, set)):
        return [
            str(v).strip()
            for v in value
            if isinstance(v, (str, int, float)) and str(v).strip()
        ]
    if isinstance(value, str):
        return [part for part in re.split(r"[,\s]+", value) if part]
    return []


def _lines_list(value) -> list[str]:
    """Like _list, but entries are separated by commas or newlines only."""
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,\n]+", value) if part.strip()]
    return _list(value)


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "1", "yes", "on"}:
        return True
    if isinstance(value, str) and value.strip().lower() in {"false", "0", "no", "off"}:
        return False
    return None


def _on(value: bool) -> tuple[int, str]:
    return (1, "on") if value else (0, "off")


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _pyproject_tool(text: str, *names: str):
    data = _toml(text)
    if data is UNKNOWN:
        return UNKNOWN
    tool = _dict(_dict(data).get("tool"))
    for name in names:
        if isinstance(tool.get(name), dict):
            return tool[name]
    return None


# -- ruff --------------------------------------------------------------------


def _ruff(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    if name == "pyproject.toml":
        data = _pyproject_tool(text, "ruff")
    else:
        data = _toml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    lint = _dict(data.get("lint"))
    policy = Policy()

    def both(key: str) -> list:
        return [*_list(lint.get(key)), *_list(data.get(key))]

    policy.add(("ruff", "rules", "ignores"), both("ignore") + both("extend-ignore"))
    for key in ("exclude", "extend-exclude"):
        policy.add(
            ("ruff", "paths", "glob", root, "excludes", _PY), _list(data.get(key))
        )
    policy.add(
        ("ruff", "paths", "glob", root, "excludes", _PY), _list(lint.get("exclude"))
    )
    for table in (lint, data):
        for key in ("per-file-ignores", "extend-per-file-ignores"):
            for pattern, codes in _dict(table.get(key)).items():
                policy.add(
                    ("ruff", "file-rules", "glob", root, pattern, _PY), _list(codes)
                )
    selected = both("select") + both("extend-select")
    if selected or "select" in lint or "select" in data:
        policy.require(("ruff", "selected", "selects"), selected)
    else:
        policy.require(("ruff", "selected", "selects"), _RUFF_DEFAULT_SELECT)
    return policy


# -- flake8 ------------------------------------------------------------------


def _flake8(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    if name == "pyproject.toml":
        section = _pyproject_tool(text, "flake8")
        if section is UNKNOWN:
            return UNKNOWN
        options = {k: v for k, v in _dict(section).items()} if section else None
    else:
        parser = _ini(text)
        if parser is UNKNOWN:
            return UNKNOWN
        options = dict(parser.items("flake8")) if parser.has_section("flake8") else None
    if options is None:
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    policy.add(
        ("flake8", "rules", "ignores"),
        _list(options.get("ignore"))
        + _list(options.get("extend-ignore"))
        + _list(options.get("extend_ignore")),
    )
    for key in ("exclude", "extend-exclude", "extend_exclude"):
        policy.add(
            ("flake8", "paths", "glob", root, "excludes", _PY),
            _lines_list(options.get(key)),
        )
    for key in ("per-file-ignores", "per_file_ignores"):
        value = options.get(key)
        pairs = []
        if isinstance(value, str):
            pairs = re.findall(
                r"(\S+?)\s*:\s*([A-Z][A-Z0-9]*(?:\s*,\s*[A-Z][A-Z0-9]*)*)", value
            )
        elif isinstance(value, dict):
            pairs = [(k, ",".join(_list(v))) for k, v in value.items()]
        for pattern, codes in pairs:
            policy.add(
                ("flake8", "file-rules", "glob", root, pattern, _PY), _list(codes)
            )
    return policy


# -- pylint ------------------------------------------------------------------


def _pylint(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    options: dict[str, object] = {}
    if name == "pyproject.toml":
        section = _pyproject_tool(text, "pylint")
        if section is UNKNOWN:
            return UNKNOWN
        if not section:
            return None
        for key, value in section.items():
            if isinstance(value, dict):
                options.update(value)
            else:
                options[key] = value
    else:
        parser = _ini(text)
        if parser is UNKNOWN:
            return UNKNOWN
        sections = [
            s
            for s in parser.sections()
            if name in {".pylintrc", "pylintrc"} or s.lower().startswith("pylint")
        ]
        if not sections:
            return None
        for section in sections:
            options.update(dict(parser.items(section)))
    options = {str(k).lower().replace("_", "-"): v for k, v in options.items()}
    root = posixpath.dirname(path)
    policy = Policy()
    policy.add(("pylint", "rules", "disables"), _list(options.get("disable")))
    policy.require(("pylint", "enabled", "enables"), _list(options.get("enable")))
    policy.add(
        ("pylint", "paths", "basename", root, "ignores", _PY),
        _list(options.get("ignore")),
    )
    policy.add(
        ("pylint", "paths", "regex", root, "ignores", _PY),
        _lines_list(options.get("ignore-paths")),
    )
    policy.add(
        ("pylint", "paths", "name-regex", root, "ignores", _PY),
        _lines_list(options.get("ignore-patterns")),
    )
    floor = _number(options.get("fail-under"))
    if floor is not None:
        policy.level(("pylint", "fail-under"), floor, f"{floor:g}")
    return policy


def _number(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


# -- mypy --------------------------------------------------------------------

_MYPY_STRICT = (
    "warn_unused_configs",
    "disallow_any_generics",
    "disallow_subclassing_any",
    "disallow_untyped_calls",
    "disallow_untyped_defs",
    "disallow_incomplete_defs",
    "check_untyped_defs",
    "disallow_untyped_decorators",
    "warn_redundant_casts",
    "warn_unused_ignores",
    "warn_return_any",
    "no_implicit_reexport",
    "strict_equality",
    "extra_checks",
)
# Flags whose default is on, and flags that only ever add checks.
_MYPY_DEFAULT_ON = ("strict_optional", "no_implicit_optional", "warn_no_return")
_MYPY_EXTRA = (
    "warn_unreachable",
    "disallow_any_explicit",
    "disallow_any_unimported",
    "disallow_any_expr",
    "disallow_any_decorated",
)
_FOLLOW_IMPORTS = {"skip": 0, "silent": 1, "normal": 2, "error": 3}


def _mypy(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    overrides: list[tuple[list[str], dict]] = []
    if name == "pyproject.toml":
        section = _pyproject_tool(text, "mypy")
        if section is UNKNOWN:
            return UNKNOWN
        if not section:
            return None
        options = {k: v for k, v in section.items() if k != "overrides"}
        for item in section.get("overrides") or []:
            if isinstance(item, dict):
                overrides.append((_list(item.get("module")), item))
    else:
        parser = _ini(text)
        if parser is UNKNOWN:
            return UNKNOWN
        if not parser.has_section("mypy") and not any(
            s.startswith("mypy-") for s in parser.sections()
        ):
            return None
        options = dict(parser.items("mypy")) if parser.has_section("mypy") else {}
        for section in parser.sections():
            if section.startswith("mypy-"):
                overrides.append(
                    (_list(section[len("mypy-") :]), dict(parser.items(section)))
                )
    options = {k.replace("-", "_"): v for k, v in options.items()}
    root = posixpath.dirname(path)
    policy = Policy()
    strict = _bool(options.get("strict")) is True
    policy.level(("mypy", "strict"), *_on(strict))
    effective = {}
    for flag in _MYPY_STRICT:
        value = _bool(options.get(flag))
        effective[flag] = strict if value is None else value
        policy.level(("mypy", flag), *_on(effective[flag]))
        if value is not None:
            policy.explicit.add(("mypy", flag))
    for flag in _MYPY_DEFAULT_ON:
        value = _bool(options.get(flag))
        effective[flag] = True if value is None else value
        policy.level(("mypy", flag), *_on(effective[flag]))
    for flag in _MYPY_EXTRA:
        value = _bool(options.get(flag))
        effective[flag] = bool(value)
        policy.level(("mypy", flag), *_on(effective[flag]))
    ignore_errors = _bool(options.get("ignore_errors")) is True
    policy.level(
        ("mypy", "ignore_errors"), *((0, "on") if ignore_errors else (1, "off"))
    )
    follow = str(options.get("follow_imports") or "normal").strip().lower()
    if follow in _FOLLOW_IMPORTS:
        policy.level(("mypy", "follow_imports"), _FOLLOW_IMPORTS[follow], follow)
    policy.add(
        ("mypy", "rules", "ignores error code"),
        _list(options.get("disable_error_code")),
    )
    policy.require(
        ("mypy", "enabled", "reports"), _list(options.get("enable_error_code"))
    )
    exclude = options.get("exclude")
    policy.add(
        ("mypy", "paths", "regex", root, "excludes", _PY),
        [exclude.strip()]
        if isinstance(exclude, str) and "\n" not in exclude.strip()
        else _lines_list(exclude),
    )
    for modules, settings in overrides:
        settings = {k.replace("-", "_"): v for k, v in settings.items()}
        for module in modules:
            key = ("mypy", "modules", module)
            if _bool(settings.get("ignore_errors")) is True:
                policy.add(key, [f"now ignores all errors in {module}"])
            for code in _list(settings.get("disable_error_code")):
                policy.add(key, [f"now ignores error code {code} in {module}"])
            for flag in (*_MYPY_STRICT, *_MYPY_DEFAULT_ON):
                if _bool(settings.get(flag)) is False and effective.get(flag):
                    policy.add(key, [f"turns {flag} off for {module}"])
    return policy


# -- pyright -----------------------------------------------------------------

_PYRIGHT_MODES = {
    "off": 0,
    "basic": 1,
    "standard": 2,
    "strict": 3,
    "recommended": 4,
    "all": 5,
}
_SEVERITY = {
    "none": 0,
    "false": 0,
    "off": 0,
    "hint": 1,
    "information": 1,
    "info": 1,
    "warning": 2,
    "warn": 2,
    "error": 3,
    "true": 3,
}


def _pyright(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    if name == "pyproject.toml":
        data = _pyproject_tool(text, "pyright", "basedpyright")
    else:
        data = _jsonc(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    mode = str(data.get("typeCheckingMode") or "standard").lower()
    if mode in _PYRIGHT_MODES:
        policy.level(("pyright", "typeCheckingMode"), _PYRIGHT_MODES[mode], mode)
    for key, value in data.items():
        if key.startswith("report"):
            shown = (
                str(value).lower()
                if not isinstance(value, bool)
                else str(value).lower()
            )
            policy.rule("*", key, _SEVERITY.get(shown), shown)
    policy.add(
        ("pyright", "paths", "anchored", root, "excludes", _PY),
        _list(data.get("exclude")),
    )
    policy.add(
        ("pyright", "paths", "anchored", root, "ignores", _PY),
        _list(data.get("ignore")),
    )
    policy.require(("pyright", "strict", "checks strictly"), _list(data.get("strict")))
    return policy


# -- bandit ------------------------------------------------------------------


def _bandit(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    if name == "pyproject.toml":
        data = _pyproject_tool(text, "bandit")
    elif name == ".bandit":
        parser = _ini(text)
        if parser is UNKNOWN:
            data = _yaml(text)
        else:
            data = (
                dict(parser.items("bandit")) if parser.has_section("bandit") else None
            )
    else:
        data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    policy.add(("bandit", "rules", "skips"), _list(data.get("skips")))
    for key in ("exclude_dirs", "exclude"):
        policy.add(
            ("bandit", "paths", "glob", root, "excludes", _PY),
            _lines_list(data.get(key)),
        )
    policy.require(("bandit", "enabled", "runs"), _list(data.get("tests")))
    return policy


# -- TypeScript --------------------------------------------------------------

_TS_STRICT_FAMILY = (
    "noImplicitAny",
    "noImplicitThis",
    "alwaysStrict",
    "strictBindCallApply",
    "strictNullChecks",
    "strictFunctionTypes",
    "strictPropertyInitialization",
    "useUnknownInCatchVariables",
    "strictBuiltinIteratorReturn",
)
_TS_CHECKS = (
    "noImplicitReturns",
    "noFallthroughCasesInSwitch",
    "noUncheckedIndexedAccess",
    "exactOptionalPropertyTypes",
    "noImplicitOverride",
    "noPropertyAccessFromIndexSignature",
    "noUnusedLocals",
    "noUnusedParameters",
    "checkJs",
)
# Turned on, these stop checks: on is the weaker setting.
_TS_LAX = (
    "allowUnreachableCode",
    "allowUnusedLabels",
    "suppressImplicitAnyIndexErrors",
    "suppressExcessPropertyErrors",
    "noStrictGenericChecks",
)


def _typescript(path: str, text: str, read) -> Policy | None:
    chain = _tsconfig_chain(path, text, read)
    if chain is UNKNOWN:
        return UNKNOWN
    options: dict = {}
    complete = True
    exclude = include = files = None
    for config_path, data in reversed(chain):
        if data is None:
            complete = False  # a package we cannot read: inherited values unknown
            continue
        options.update(_dict(data.get("compilerOptions")))
        directory = posixpath.dirname(config_path)
        # include/exclude/files are relative to the file that sets them.
        for key in ("exclude", "include", "files"):
            if key in data and isinstance(data[key], list):
                values = [
                    _rebase(directory, posixpath.dirname(path), v)
                    for v in data[key]
                    if isinstance(v, str)
                ]
                if key == "exclude":
                    exclude = values
                elif key == "include":
                    include = values
                else:
                    files = values
    policy = Policy()
    root = posixpath.dirname(path)

    def known(key: str) -> bool:
        return key in options or complete

    strict = _bool(options.get("strict")) is True
    if known("strict"):
        policy.level(("compilerOptions", "strict"), *_on(strict))
    for flag in _TS_STRICT_FAMILY:
        if flag in options or (complete and known("strict")):
            value = _bool(options.get(flag))
            policy.level(
                ("compilerOptions", flag), *_on(strict if value is None else value)
            )
            if value is not None:
                policy.explicit.add(("compilerOptions", flag))
    for flag in _TS_CHECKS:
        if known(flag):
            policy.level(
                ("compilerOptions", flag), *_on(_bool(options.get(flag)) is True)
            )
    for flag in _TS_LAX:
        if known(flag):
            value = _bool(options.get(flag))
            policy.level(
                ("compilerOptions", flag),
                *((0, "on") if value is True else (1, "off")),
            )
    suffixes = (
        _JS
        if _bool(options.get("allowJs")) or _bool(options.get("checkJs"))
        else (".ts", ".tsx", ".mts", ".cts")
    )
    if exclude is not None:
        policy.add(
            ("TypeScript", "paths", "anchored", root, "excludes", suffixes), exclude
        )
    if include is not None or files is not None:
        policy.require(
            ("TypeScript", "include", "includes", root, suffixes),
            [*(include or []), *(files or [])],
        )
    return policy


def _rebase(from_dir: str, to_dir: str, pattern: str) -> str:
    """A pattern relative to ``from_dir``, made relative to ``to_dir``."""
    if from_dir == to_dir or pattern.startswith("/"):
        return pattern
    joined = posixpath.normpath(posixpath.join(from_dir, pattern))
    return posixpath.relpath(joined, to_dir or ".")


def _tsconfig_chain(path: str, text: str, read, depth: int = 0):
    """[(path, data)] from this file up its local ``extends``; data is None
    for a base Skylos cannot read (a package)."""
    data = _jsonc(text)
    if not isinstance(data, dict):
        return UNKNOWN
    chain = [(path, data)]
    if depth >= 5:
        return chain + [(path, None)]
    parents = data.get("extends")
    for parent in (
        parents if isinstance(parents, list) else [parents] if parents else []
    ):
        if not isinstance(parent, str) or not parent.startswith("."):
            chain.append((parent, None))
            continue
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), parent))
        if not target.endswith(".json"):
            target += ".json"
        parent_text = read(target)
        if parent_text is None:
            chain.append((target, None))
            continue
        sub = _tsconfig_chain(target, parent_text, read, depth + 1)
        if sub is UNKNOWN:
            chain.append((target, None))
        else:
            chain += sub
    return chain


# -- ESLint ------------------------------------------------------------------

_ESLINT_SEVERITY = {"off": 0, "warn": 1, "error": 2, 0: 0, 1: 1, 2: 2}
_ESLINT_SHOWN = {0: "off", 1: "warn", 2: "error"}
_PRESET_RE = re.compile(
    r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.configs(?:\.[\w$]+|\[\s*['\"][^'\"]+['\"]\s*\])+"
)


def _eslint(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    root = posixpath.dirname(path)
    policy = Policy()
    if name == ".eslintignore":
        policy.add(
            ("ESLint", "paths", "glob", root, "ignores", _JS), _ignore_lines(text)
        )
        return policy
    if name == "package.json":
        data = _jsonc(text)
        if not isinstance(data, dict):
            return None
        config = data.get("eslintConfig")
        if not isinstance(config, dict):
            return None
        _eslint_dict(config, "*", policy, root)
        return policy
    if name.endswith((".js", ".cjs", ".mjs", ".ts", ".mts", ".cts")):
        return _eslint_module(path, text, policy, root)
    data = _yaml(text) if name.endswith((".yaml", ".yml")) else _jsonc(text)
    if name == ".eslintrc" and not isinstance(data, dict):
        data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    _eslint_dict(data, "*", policy, root)
    return policy


def _ignore_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("#", "!"))
    ]


def _eslint_rank(value):
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, str):
        value = value.strip().lower()
    if isinstance(value, bool) or value not in _ESLINT_SEVERITY:
        return None
    return _ESLINT_SEVERITY[value]


def _eslint_dict(config: dict, scope: str, policy: Policy, root: str) -> None:
    for rule, value in _dict(config.get("rules")).items():
        rank = _eslint_rank(value)
        if rank is not None:
            policy.rule(scope, str(rule), rank, _ESLINT_SHOWN[rank])
    policy.add(
        ("ESLint", "paths", "glob", root, "ignores", _JS),
        _list(config.get("ignorePatterns")),
    )
    extends = config.get("extends")
    policy.require(
        ("ESLint", "extends", "extends"),
        [extends] if isinstance(extends, str) else _list(extends),
    )
    for override in config.get("overrides") or []:
        if isinstance(override, dict):
            files = override.get("files")
            inner = ", ".join(_list(files)) if files else scope
            _eslint_dict(override, inner or scope, policy, root)


def _eslint_module(path: str, text: str, policy: Policy, root: str):
    from skylos.done.js_inventory import _parse
    from skylos.done.js_test_config import UNKNOWN as JS_UNKNOWN
    from skylos.done.js_test_config import _key, _Reader

    tree = _parse(path, text)
    if tree is None or tree.has_error:
        return UNKNOWN
    reader = _Reader(tree)
    stack = [tree]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type == "comment":
            continue
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if (
                function is not None
                and function.text.decode() == "globalIgnores"
                and arguments is not None
            ):
                for child in arguments.named_children:
                    value = reader.value(child)
                    if isinstance(value, list):
                        policy.add(
                            ("ESLint", "paths", "glob", root, "ignores", _JS),
                            [v for v in value if isinstance(v, str)],
                        )
        if node.type not in {"member_expression", "subscript_expression", "object"}:
            continue
        if node.type != "object":
            text_here = node.text.decode("utf-8", "replace")
            parent = node.parent
            if _PRESET_RE.fullmatch(text_here) and (
                parent is None
                or parent.type not in {"member_expression", "subscript_expression"}
            ):
                policy.require(
                    ("ESLint", "extends", "extends"), [re.sub(r"\s+", "", text_here)]
                )
            continue
        pairs = {}
        for child in node.named_children:
            if child.type == "pair":
                key = _key(child.child_by_field_name("key"))
                if key is not None:
                    pairs[key] = child.child_by_field_name("value")
        files = reader.value(pairs["files"]) if "files" in pairs else None
        if files is None:
            scope = "*"
        elif isinstance(files, list) and all(isinstance(f, str) for f in files):
            scope = ", ".join(files)
        elif isinstance(files, str):
            scope = files
        else:
            scope = "?"
        if (
            "rules" in pairs
            and pairs["rules"] is not None
            and pairs["rules"].type == "object"
        ):
            for child in pairs["rules"].named_children:
                if child.type != "pair":
                    continue
                rule = _key(child.child_by_field_name("key"))
                value = reader.value(child.child_by_field_name("value"))
                if rule is None or value is JS_UNKNOWN:
                    continue
                rank = _eslint_rank(value)
                if rank is not None:
                    policy.rule(scope, rule, rank, _ESLINT_SHOWN[rank])
        for key in ("ignores", "ignorePatterns"):
            if key in pairs:
                value = reader.value(pairs[key])
                if isinstance(value, list):
                    policy.add(
                        ("ESLint", "paths", "glob", root, "ignores", _JS),
                        [v for v in value if isinstance(v, str)],
                    )
        if "extends" in pairs:
            value = reader.value(pairs["extends"])
            if isinstance(value, str):
                value = [value]
            if isinstance(value, list):
                policy.require(
                    ("ESLint", "extends", "extends"),
                    [v for v in value if isinstance(v, str)],
                )
    return policy


# -- Biome -------------------------------------------------------------------

_BIOME_SEVERITY = {"off": 0, "info": 1, "warn": 2, "on": 2, "error": 3}


def _biome(path: str, text: str, read) -> Policy | None:
    data = _jsonc(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    _biome_section(data, "*", policy, root)
    for override in data.get("overrides") or []:
        if isinstance(override, dict):
            scope = (
                ", ".join(_list(override.get("include") or override.get("includes")))
                or "?"
            )
            _biome_section(override, scope, policy, root)
    return policy


def _biome_section(data: dict, scope: str, policy: Policy, root: str) -> None:
    linter = _dict(data.get("linter"))
    files = _dict(data.get("files"))
    if scope == "*":
        enabled = _bool(linter.get("enabled"))
        policy.level(("Biome", "linter"), *_on(enabled is not False))
    rules = _dict(linter.get("rules"))
    if scope == "*" and "recommended" in rules:
        policy.level(
            ("Biome", "recommended rules"),
            *_on(_bool(rules.get("recommended")) is not False),
        )
    for group, members in rules.items():
        if not isinstance(members, dict):
            continue
        for rule, value in members.items():
            if rule in {"recommended", "all"}:
                continue
            level = value.get("level") if isinstance(value, dict) else value
            if isinstance(level, str) and level.lower() in _BIOME_SEVERITY:
                policy.rule(
                    scope,
                    f"{group}/{rule}",
                    _BIOME_SEVERITY[level.lower()],
                    level.lower(),
                )
    ignored = _list(files.get("ignore")) + _list(linter.get("ignore"))
    ignored += [
        p[1:]
        for p in _list(files.get("includes")) + _list(linter.get("includes"))
        if p.startswith("!")
    ]
    policy.add(
        ("Biome", "paths", "glob", root, "ignores", _JS),
        [p.lstrip("!") for p in ignored],
    )


# -- SonarQube ---------------------------------------------------------------


def _properties(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    logical = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not logical and (not line or line.startswith(("#", "!"))):
            continue
        if line.endswith("\\") and not line.endswith("\\\\"):
            logical += line[:-1]
            continue
        logical += line
        match = re.match(r"([^=:\s]+)\s*[=:\s]\s*(.*)", logical)
        if match:
            values[match.group(1)] = match.group(2).strip()
        logical = ""
    return values


def _sonar(path: str, text: str, read) -> Policy | None:
    values = _properties(text)
    root = posixpath.dirname(path)
    policy = Policy()
    for key, value in values.items():
        if re.fullmatch(r"sonar\.(?:(?!test\.)[\w-]+\.)?exclusions", key):
            what = (
                "excludes"
                if key == "sonar.exclusions"
                else f"leaves out of {key.split('.')[1]}"
            )
            if key == "sonar.exclusions":
                what = "excludes"
            policy.add(
                ("SonarQube", "paths", "anchored", root, what, _CODE),
                _lines_list(value),
            )
    pairs = {}
    for key, value in values.items():
        match = re.fullmatch(
            r"sonar\.issue\.ignore\.(multicriteria|block|allfile)\.([^.]+)\.(\w+)", key
        )
        if match:
            pairs.setdefault((match.group(1), match.group(2)), {})[match.group(3)] = (
                value
            )
    for (kind, _), fields in pairs.items():
        if kind == "multicriteria":
            entry = (
                f"rule {fields.get('ruleKey', '*')} in {fields.get('resourceKey', '*')}"
            )
        elif kind == "block":
            entry = f"blocks between {fields.get('beginBlockRegexp', '')!r} and {fields.get('endBlockRegexp', '')!r}"
        else:
            entry = f"files matching {fields.get('fileRegexp', '')!r}"
        policy.add(("SonarQube", "items", "ignores"), [entry])
    wait = _bool(values.get("sonar.qualitygate.wait"))
    if wait is not None:
        policy.level(("SonarQube", "sonar.qualitygate.wait"), *_on(wait))
    return policy


# -- line-list ignore files and secret baselines -----------------------------


def _semgrep(path: str, text: str, read) -> Policy | None:
    policy = Policy()
    entries = [e for e in _ignore_lines(text) if not e.startswith(":")]
    policy.add(
        ("Semgrep", "paths", "glob", posixpath.dirname(path), "ignores", _CODE), entries
    )
    return policy


def _gitleaks(path: str, text: str, read) -> Policy | None:
    policy = Policy()
    if PurePosixPath(path).name == ".gitleaksignore":
        policy.add(("gitleaks", "items", "allows the finding"), _ignore_lines(text))
        return policy
    data = _toml(text)
    if data is UNKNOWN:
        return UNKNOWN
    entries = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"allowlist", "allowlists"}:
                    for allow in value if isinstance(value, list) else [value]:
                        for field_name in ("paths", "regexes", "stopwords", "commits"):
                            entries.extend(_list(_dict(allow).get(field_name)))
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(data)
    policy.add(("gitleaks", "items", "allows"), entries)
    extend = _dict(_dict(data).get("extend"))
    if "useDefault" in extend:
        policy.level(
            ("gitleaks", "default rules"), *_on(_bool(extend.get("useDefault")) is True)
        )
    return policy


def _secrets_baseline(path: str, text: str, read) -> Policy | None:
    data = _jsonc(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    policy = Policy()
    accepted = []
    for file, results in _dict(data.get("results")).items():
        for result in results if isinstance(results, list) else []:
            if isinstance(result, dict) and result.get("hashed_secret"):
                accepted.append(
                    f"{result.get('type') or 'secret'} in {file} ({str(result['hashed_secret'])[:12]})"
                )
    policy.add(("detect-secrets", "items", "accepts a"), accepted)
    plugins = [
        p.get("name") for p in data.get("plugins_used") or [] if isinstance(p, dict)
    ]
    policy.require(("detect-secrets", "plugins", "runs"), [p for p in plugins if p])
    return policy


def _trivy(path: str, text: str, read) -> Policy | None:
    policy = Policy()
    entries = [line.split("#")[0].strip() for line in _ignore_lines(text)]
    policy.add(("Trivy", "items", "ignores"), entries)
    return policy


def _osv(path: str, text: str, read) -> Policy | None:
    data = _toml(text)
    if data is UNKNOWN:
        return UNKNOWN
    policy = Policy()
    for item in _dict(data).get("IgnoredVulns") or []:
        if isinstance(item, dict) and item.get("id"):
            policy.add(("OSV-Scanner", "items", "ignores"), [item["id"]])
    for item in _dict(data).get("PackageOverrides") or []:
        if isinstance(item, dict) and item.get("ignore") is True and item.get("name"):
            policy.add(("OSV-Scanner", "items", "ignores package"), [item["name"]])
    return policy


def _snyk(path: str, text: str, read) -> Policy | None:
    data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    policy = Policy()
    policy.add(("Snyk", "items", "ignores"), list(_dict(data.get("ignore")).keys()))
    exclude = _dict(data.get("exclude"))
    for value in exclude.values():
        policy.add(
            ("Snyk", "paths", "glob", posixpath.dirname(path), "excludes", _CODE),
            _list(value),
        )
    return policy


def _codeql(path: str, text: str, read) -> Policy | None:
    data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    policy = Policy()
    policy.add(
        ("CodeQL", "paths", "anchored", "", "ignores", _CODE),
        _list(data.get("paths-ignore")),
    )
    for item in data.get("query-filters") or []:
        if isinstance(item, dict) and isinstance(item.get("exclude"), dict):
            policy.add(
                ("CodeQL", "items", "excludes queries"),
                [json.dumps(item["exclude"], sort_keys=True)],
            )
    disabled = _bool(data.get("disable-default-queries")) is True
    policy.level(("CodeQL", "default queries"), *_on(not disabled))
    queries = [q.get("uses") for q in data.get("queries") or [] if isinstance(q, dict)]
    policy.require(
        ("CodeQL", "queries", "runs queries"),
        [q for q in queries if isinstance(q, str)],
    )
    return policy


# -- golangci-lint -----------------------------------------------------------

_GOLANGCI_DEFAULT = {"none": 0, "fast": 1, "standard": 2, "all": 3}


def _golangci(path: str, text: str, read) -> Policy | None:
    name = PurePosixPath(path).name
    if name.endswith(".toml"):
        data = _toml(text)
    elif name.endswith(".json"):
        data = _jsonc(text)
    else:
        data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    linters = _dict(data.get("linters"))
    issues = _dict(data.get("issues"))
    run = _dict(data.get("run"))
    policy.add(("golangci-lint", "rules", "disables"), _list(linters.get("disable")))
    policy.require(
        ("golangci-lint", "enabled", "enables"), _list(linters.get("enable"))
    )
    if "disable-all" in linters:
        policy.level(
            ("golangci-lint", "disable-all"),
            *((0, "on") if _bool(linters.get("disable-all")) else (1, "off")),
        )
    if "enable-all" in linters:
        policy.level(
            ("golangci-lint", "enable-all"),
            *_on(bool(_bool(linters.get("enable-all")))),
        )
    default = linters.get("default")
    if isinstance(default, str) and default in _GOLANGCI_DEFAULT:
        policy.level(
            ("golangci-lint", "default linters"), _GOLANGCI_DEFAULT[default], default
        )
    elif str(data.get("version", "")).strip("'\"") == "2":
        policy.level(("golangci-lint", "default linters"), 2, "standard")
    exclusions = _dict(linters.get("exclusions"))
    rules = list(issues.get("exclude-rules") or []) + list(
        exclusions.get("rules") or []
    )
    policy.add(
        ("golangci-lint", "items", "excludes issues"),
        [json.dumps(r, sort_keys=True) for r in rules if isinstance(r, dict)],
    )
    policy.add(
        ("golangci-lint", "items", "excludes issues matching"),
        _list(issues.get("exclude")),
    )
    policy.add(
        ("golangci-lint", "items", "applies exclusion preset"),
        _list(exclusions.get("presets")),
    )
    for key in ("exclude-dirs", "exclude-files"):
        policy.add(
            ("golangci-lint", "paths", "regex", root, "excludes", (".go",)),
            _list(issues.get(key)),
        )
    for key in ("skip-dirs", "skip-files"):
        policy.add(
            ("golangci-lint", "paths", "regex", root, "excludes", (".go",)),
            _list(run.get(key)),
        )
    policy.add(
        ("golangci-lint", "paths", "regex", root, "excludes", (".go",)),
        _list(exclusions.get("paths")),
    )
    if "new" in issues:
        policy.level(
            ("golangci-lint", "reporting of existing issues"),
            *_on(_bool(issues.get("new")) is not True),
        )
    return policy


# -- Cargo lints -------------------------------------------------------------

_CARGO_LEVELS = {"allow": 0, "expect": 0, "warn": 1, "deny": 2, "forbid": 3}


def _cargo(path: str, text: str, read) -> Policy | None:
    data = _toml(text)
    if data is UNKNOWN:
        return UNKNOWN
    policy = Policy()
    for prefix, table in (
        ("", _dict(_dict(data).get("lints"))),
        ("workspace ", _dict(_dict(_dict(data).get("workspace")).get("lints"))),
    ):
        if "workspace" in table and not prefix:
            policy.level(
                ("Cargo lints", "workspace lints"),
                *_on(_bool(table.get("workspace")) is True),
            )
        for group, lints in table.items():
            if not isinstance(lints, dict):
                continue
            for lint, value in lints.items():
                level = value.get("level") if isinstance(value, dict) else value
                if isinstance(level, str) and level in _CARGO_LEVELS:
                    name = lint if group == "rust" else f"{group}::{lint}"
                    policy.rule(
                        prefix + "*" if prefix else "*",
                        name,
                        _CARGO_LEVELS[level],
                        level,
                    )
    return policy


# -- pre-commit --------------------------------------------------------------


def _pre_commit(path: str, text: str, read) -> Policy | None:
    data = _yaml(text)
    if data is UNKNOWN:
        return UNKNOWN
    if not isinstance(data, dict):
        return None
    root = posixpath.dirname(path)
    policy = Policy()
    hooks = []
    for repo in data.get("repos") or []:
        for hook in _dict(repo).get("hooks") or []:
            if not isinstance(hook, dict) or not hook.get("id"):
                continue
            stages = _list(hook.get("stages"))
            if stages and set(stages) <= {"manual"}:
                continue  # runs only when asked
            hooks.append(str(hook["id"]))
            exclude = hook.get("exclude")
            if isinstance(exclude, str) and exclude.strip():
                policy.add(
                    (
                        "pre-commit",
                        "paths",
                        "regex",
                        root,
                        f"excludes from {hook['id']}",
                        _CODE,
                    ),
                    [exclude.strip()],
                )
    policy.require(("pre-commit", "hooks", "runs hook"), hooks)
    exclude = data.get("exclude")
    if isinstance(exclude, str) and exclude.strip():
        policy.add(
            ("pre-commit", "paths", "regex", root, "excludes", _CODE), [exclude.strip()]
        )
    ci = _dict(data.get("ci"))
    policy.add(
        ("pre-commit", "items", "skips in pre-commit.ci the hook"),
        _list(ci.get("skip")),
    )
    return policy


# -- Checkstyle / SpotBugs ---------------------------------------------------


def _xml_suppressions(path: str, text: str, read) -> Policy | None:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return UNKNOWN
    policy = Policy()
    entries = []
    for child in root:
        if not isinstance(child.tag, str):
            continue
        entries.append(_canonical_xml(child))
    policy.add(("Checkstyle/SpotBugs", "items", "suppresses"), entries)
    return policy


def _canonical_xml(element) -> str:
    tag = element.tag.split("}")[-1]
    attributes = " ".join(
        f'{k.split("}")[-1]}="{v}"' for k, v in sorted(element.attrib.items())
    )
    inner = "".join(_canonical_xml(c) for c in element if isinstance(c.tag, str))
    head = f"<{tag}{' ' + attributes if attributes else ''}"
    return f"{head}>{inner}</{tag}>" if inner else f"{head}/>"


_PARSERS: dict[str, Callable] = {
    "ruff": _ruff,
    "flake8": _flake8,
    "pylint": _pylint,
    "mypy": _mypy,
    "pyright": _pyright,
    "bandit": _bandit,
    "TypeScript": _typescript,
    "ESLint": _eslint,
    "Biome": _biome,
    "SonarQube": _sonar,
    "Semgrep": _semgrep,
    "gitleaks": _gitleaks,
    "detect-secrets": _secrets_baseline,
    "Trivy": _trivy,
    "OSV-Scanner": _osv,
    "Snyk": _snyk,
    "CodeQL": _codeql,
    "golangci-lint": _golangci,
    "Cargo lints": _cargo,
    "pre-commit": _pre_commit,
    "Checkstyle/SpotBugs": _xml_suppressions,
}

_STRICT_FAMILY = frozenset({*_MYPY_STRICT, *_TS_STRICT_FAMILY})
# What a tool does with no settings at all: compared with when every
# setting is removed, or when settings first appear.
_LEVEL_DEFAULTS: dict[str, dict[str, tuple[float, str]]] = {
    "mypy": {
        "strict": (0, "off"),
        **{flag: (0, "off") for flag in (*_MYPY_STRICT, *_MYPY_EXTRA)},
        **{flag: (1, "on") for flag in _MYPY_DEFAULT_ON},
        "ignore_errors": (1, "off"),
        "follow_imports": (2, "normal"),
    },
    "pyright": {"typeCheckingMode": (2, "standard")},
}
