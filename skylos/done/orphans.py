"""Branch orphans: code a change left with no callers (SKY-A135, A136, A137).

Agents replace a helper and leave the old one, change a call site so a
function in another file loses its last caller, or add a helper plus a test
for it and no production caller. Diff-only tools miss the first case because
the dead code sits on lines the change never touched.

The check analyzes the base and the head with the regular dead-code engine
(the same framework, entry-point and export rules as ``skylos .``), both in a
"production view": test files are left out, so a symbol only tests call
counts as unused. Then:

- SKY-A135: a symbol that existed at the base, was used there and is unused
  at the head. The message names the removed or changed line that called it
  when the diff shows one.
- SKY-A136: a symbol the change added that nothing calls.
- SKY-A137: a symbol the change added that only tests call.

Both trees are copied from Git objects or the working tree into private
temporary folders; nothing in the repository runs. A symbol that was moved
or renamed is not new. Candidates then go through the analyzer's grep
verification (against the head without tests), and a candidate whose name
appears in a file the analyzer could not parse is not judged.
"""

from __future__ import annotations

import ast
import fnmatch
import functools
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    read_project_text_no_symlink,
    save_project_json_cache,
)
from skylos.core.test_paths import is_test_code_path
from skylos.done.base import ChangedFile, Comparison, _git_text, is_runtime_path

logger = logging.getLogger(__name__)

RULE_MADE_DEAD = "SKY-A135"
RULE_NEW_UNUSED = "SKY-A136"
RULE_TEST_ONLY = "SKY-A137"
RULES = (RULE_MADE_DEAD, RULE_NEW_UNUSED, RULE_TEST_ONLY)

# Dead-code confidence a candidate needs. Higher than the scan default (60)
# so symbols the analyzer suspects are framework magic (a 40-point penalty)
# are never reported.
CONFIDENCE = 75
MAX_FILES = 20_000
MAX_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ORPHANS = 200
MAX_TEST_BYTES = 64 * 1024 * 1024
MAX_CACHE_BYTES = 32 * 1024 * 1024

_SYMBOL_CATEGORIES = ("unused_functions", "unused_classes")
_SYMBOL_TYPES = frozenset({"function", "method", "class"})
_DEAD_FILE_RULE = "SKY-E003"
_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")
_LANGUAGE_SUFFIXES = {"go": (".go",), "dart": (".dart",)}
_CACHE_DIR = PurePosixPath(".skylos/cache/done-orphans")
_CACHE_SCHEMA = 1
# A new definition whose body lines were mostly removed elsewhere in the
# change was moved or renamed, not written.
_MOVED_BODY_SHARE = 0.8
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")
_LINE_COMMENT_RE = re.compile(r"^\s*(?://|#|\*|/\*|<!--)")
_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\b|from\b|export\s.*\bfrom\b|use\s|#include\b|require\b)"
    r"|.*\brequire\s*\("
)
_IMPORT = 2  # reference rank of an import line
_GREP_EVIDENCE_PAGE = 5  # grep verification shows at most this many hits
_FILE_TOKEN_RE = re.compile(r"[\w$.-]+")
# Decorators and annotations that wrap or describe a symbol without
# registering it anywhere.
_PLAIN_DECORATORS = frozenset(
    {
        "wraps",
        "lru_cache",
        "cache",
        "cached_property",
        "property",
        "setter",
        "getter",
        "deleter",
        "staticmethod",
        "classmethod",
        "abstractmethod",
        "overload",
        "override",
        "Override",
        "contextmanager",
        "asynccontextmanager",
        "dataclass",
        "total_ordering",
        "final",
        "Final",
        "deprecated",
        "Deprecated",
        "SuppressWarnings",
        "Nullable",
        "NonNull",
        "Nonnull",
        "NotNull",
        "CheckReturnValue",
        "SafeVarargs",
        "Synchronized",
    }
)
_ELSEWHERE_SUFFIXES = frozenset(
    {
        ".html",
        ".htm",
        ".jinja",
        ".jinja2",
        ".j2",
        ".njk",
        ".hbs",
        ".mustache",
        ".vue",
        ".svelte",
        ".astro",
        ".erb",
        ".ejs",
        ".twig",
        ".jsp",
        ".xml",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".sql",
        ".sh",
        ".bash",
        ".ps1",
        ".mk",
        ".gradle",
    }
)
_ELSEWHERE_NAMES = frozenset({"Makefile", "Dockerfile", "Procfile", "justfile"})
_LOCK_FILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
    }
)


class OrphansUnavailable(Exception):
    """The check cannot judge this change (said plainly on the receipt)."""


@dataclass(frozen=True)
class Symbol:
    path: str
    name: str
    kind: str
    line: int
    reasons: tuple[str, ...] = ()
    # Why the analyzer abstained on it ("weak helper function"); empty for a
    # symbol it reports as unused.
    doubt: str = ""

    @property
    def simple(self) -> str:
        return re.split(r"[.:#]", self.name)[-1] or self.name


@dataclass(frozen=True)
class Orphan:
    rule: str
    path: str
    line: int
    message: str
    advice: bool = False  # never blocks: the analyzer was not certain


@dataclass
class OrphanReport:
    orphans: list[Orphan] = field(default_factory=list)
    candidates: int = 0
    not_judged: int = 0
    not_checked: dict[str, str] = field(default_factory=dict)
    unchecked_changed: bool = False
    grep_incomplete: bool = False
    base_cached: bool = False
    base_seconds: float = 0.0
    head_seconds: float = 0.0
    files_analyzed: int = 0
    skipped: str | None = None
    # Symbols that lost their callers but were not judged, as
    # "`name` (path:line)": the summary names them.
    lost_unjudged: list[str] = field(default_factory=list)


@dataclass
class _HeadView:
    dead: dict[tuple[str, str], Symbol]
    dead_files: set[str]
    unparsed: set[str]
    not_checked: dict[str, str]
    items: dict[tuple[str, str], dict] = field(default_factory=dict)
    excluded: tuple[str, ...] = ()
    # Symbols the analyzer abstained on that have no static reference left.
    uncertain: dict[tuple[str, str], Symbol] = field(default_factory=dict)


@dataclass
class _BaseView:
    alive: dict[str, dict[str, tuple[str, int]]]
    alive_files: set[str]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def find_branch_orphans(
    comparison: Comparison, head_paths: list[str], *, trust_cache: bool = True
) -> OrphanReport:
    """Orphans this change left, from base and head production views.

    ``trust_cache=False`` rebuilds the base view from Git objects instead of
    reading ``.skylos/cache/done-orphans/``: anything in the working tree can
    write that cache, so a check that can block never reads it."""
    report = OrphanReport()
    if not _touches_production(comparison):
        report.skipped = "No production code changed"
        return report
    changes = _ChangeMap(comparison)
    with tempfile.TemporaryDirectory(prefix="skylos-done-orphans-") as directory:
        workspace = Path(directory).resolve()
        head_root = workspace / "head"
        started = time.monotonic()
        head_tests = _write_head_snapshot(comparison, head_paths, head_root)
        head = _head_view(_analyze(head_root), head_root)
        report.head_seconds = time.monotonic() - started
        report.files_analyzed = sum(1 for p in head_root.rglob("*") if p.is_file())
        started = time.monotonic()
        base, report.base_cached = _base_view(
            comparison, workspace / "base", trust_cache=trust_cache
        )
        report.base_seconds = time.monotonic() - started
        _judge(comparison, changes, base, head, head_root, head_tests, report)
    return report


def _judge(comparison, changes, base, head, head_root, head_tests, report) -> None:
    report.not_checked = dict(head.not_checked)
    report.unchecked_changed = changes.touches_languages(set(head.not_checked))
    judge = _Judge(comparison, changes, base, head_tests)
    symbols = [s for s in head.dead.values() if judge.reportable(s.path)]
    doubtful = [s for s in head.uncertain.values() if judge.reportable(s.path)]
    files = sorted(p for p in head.dead_files if judge.reportable(p))
    pending = []
    for candidate in judge.classify(symbols, files, doubtful):
        # A symbol the analyzer abstained on is reported only when a line
        # this change removed used it: then it had a caller at the base and
        # has no static reference now.
        if candidate.doubtful and not _lost_callers(judge, candidate)[0]:
            _not_judged(report, candidate)
        else:
            pending.append(candidate)
    report.candidates = len(pending) + report.not_judged
    if not pending:
        return
    # A name the analyzer could not see used (a file it could not parse, a
    # template or config file it does not read) is not judged.
    unseen = _WordIndex.from_files(head_root, head.unparsed)
    unseen |= _WordIndex.from_files(head_root, _elsewhere_files(head_root))
    kept = []
    for candidate in pending:
        if (
            candidate.word in unseen
            or candidate.file_name in unseen
            or judge.decorated(candidate)
        ):
            _not_judged(report, candidate)
        else:
            kept.append(candidate)
    started = time.monotonic()
    survivors = _grep_confirmed(judge, head, head_root, kept, report)
    report.head_seconds += time.monotonic() - started
    report.orphans = judge.describe(survivors)[:MAX_ORPHANS]


def _not_judged(report: OrphanReport, candidate) -> None:
    report.not_judged += 1
    if candidate.rule == RULE_MADE_DEAD:
        report.lost_unjudged.append(
            f"`{candidate.word}` ({candidate.path}:{candidate.line})"
        )


def _grep_confirmed(judge, head, head_root, candidates, report) -> list:
    """Drop candidates grep verification finds a use for, as ``skylos .``
    does, searching the head snapshot (tests left out) for their names only.
    Callees named in a rescued candidate's body are dropped too: the
    analyzer would revive them through the rescued caller."""
    from skylos.core.grep_verify import grep_verify_findings
    from skylos.core.grep_verify_common import grep_verification_scope

    items = []
    for candidate in candidates:
        if candidate.symbol is not None:
            item = dict(head.items[(candidate.symbol.path, candidate.symbol.name)])
            item["_verification_key"] = json.dumps(
                [candidate.path, candidate.symbol.name]
            )
            items.append(item)
    if not items:
        return candidates
    budget = float(os.getenv("SKYLOS_GREP_BUDGET", "120"))
    with grep_verification_scope(str(head_root), head.excluded):
        verdicts = grep_verify_findings(items, str(head_root), time_budget=budget)
    if not getattr(verdicts, "complete", True):
        report.grep_incomplete = True
        for candidate in candidates:
            if candidate.symbol is not None:
                _not_judged(report, candidate)
        return [c for c in candidates if c.symbol is None]
    rescued = [
        c
        for c in candidates
        if c.symbol is not None
        and _used_elsewhere(
            judge, head_root, c, verdicts.get(json.dumps([c.path, c.symbol.name]))
        )
    ]
    revived = {
        word
        for c in rescued
        for line in judge.texts.span_lines(c.symbol)
        for word in _WORD_RE.findall(line)
    }
    survivors = []
    for candidate in candidates:
        if candidate in rescued or (
            candidate.symbol is not None and candidate.word in revived
        ):
            # Grep found the name used. A symbol the analyzer already
            # doubted stays named on the receipt rather than dropped.
            if candidate.doubtful:
                _not_judged(report, candidate)
        else:
            survivors.append(candidate)
    return survivors


def _used_elsewhere(judge, head_root: Path, candidate, verdict) -> bool:
    """A grep rescue counts unless every hit it shows lies inside the
    symbol's own definition: its doctest or a recursive call is not a
    caller. Hits that cannot be read, or a full page of them, still count."""
    if not getattr(verdict, "alive", False):
        return False
    evidence = list(getattr(verdict, "evidence", None) or ())
    if not evidence or len(evidence) >= _GREP_EVIDENCE_PAGE:
        return True
    symbol = candidate.symbol
    own = range(symbol.line, symbol.line + len(judge.texts.span_lines(symbol)))
    for hit in evidence:
        match = re.match(r"^(.*?):(\d+):", str(hit))
        if not match or _relative(match.group(1), head_root) != symbol.path:
            return True
        if int(match.group(2)) not in own:
            return True
    return False


# ---------------------------------------------------------------------------
# What the change did
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Removed:
    base_path: str
    base_line: int
    head_path: str | None
    head_line: int
    text: str


class _ChangeMap:
    """Added head lines and removed base lines, per changed file."""

    def __init__(self, comparison: Comparison) -> None:
        self.root = comparison.root
        self.by_head: dict[str, ChangedFile] = {}
        self.added: dict[str, set[int]] = {}
        self.removed: list[_Removed] = []
        self.line_maps: dict[str, _LineMap] = {}
        for changed in comparison.changed:
            diff = comparison.file_diff(changed)
            if changed.head_path is not None:
                self.by_head[changed.path] = changed
                self.added[changed.path] = comparison.added_lines(changed)
                self.line_maps[changed.path] = _LineMap(diff)
            if changed.base_path is not None:
                head_path = changed.head_path
                self.removed.extend(
                    _Removed(changed.base_path, base_line, head_path, head_line, text)
                    for base_line, head_line, text in removed_lines(diff)
                )
        self._removed_words: set[str] | None = None
        self._removed_text: set[str] | None = None

    def base_line(self, head_path: str, line: int) -> int | None:
        """The base line an unchanged head line came from."""
        line_map = self.line_maps.get(head_path)
        return line if line_map is None else line_map.base_line(line)

    def touches_languages(self, languages: set[str]) -> bool:
        suffixes = tuple(
            s for lang in languages for s in _LANGUAGE_SUFFIXES.get(lang, ())
        )
        return bool(suffixes) and any(
            path.endswith(suffixes) and not is_test_code_path(path, self.root)
            for path in self.by_head
        )

    def removed_words(self) -> set[str]:
        if self._removed_words is None:
            self._removed_words = {
                word for item in self.removed for word in _WORD_RE.findall(item.text)
            }
        return self._removed_words

    def removed_text(self) -> set[str]:
        if self._removed_text is None:
            self._removed_text = {_normalized(item.text) for item in self.removed}
        return self._removed_text


def _touches_production(comparison: Comparison) -> bool:
    """Test files are left out of both analyses, so a change to tests alone
    cannot change what production code calls."""
    return any(
        path and not is_test_code_path(path, comparison.root)
        for changed in comparison.changed
        for path in (changed.path, changed.base_path)
    )


def removed_lines(diff_text: str) -> list[tuple[int, int, str]]:
    """(base line, head line where the removal sits, text) for each removed
    line of a unified diff. Hunk lengths decide where a hunk ends, so source
    lines that start with ``---`` or ``+++`` are read as source."""
    out: list[tuple[int, int, str]] = []
    old_left = new_left = base_no = head_no = 0
    for raw in diff_text.split("\n"):
        if old_left <= 0 and new_left <= 0:
            match = _HUNK_RE.match(raw)
            if match:
                base_no, head_no = int(match.group(1)), int(match.group(3))
                old_left = int(match.group(2) or 1) if match.group(2) != "0" else 0
                new_left = int(match.group(4) or 1) if match.group(4) != "0" else 0
            continue
        marker = raw[:1]
        if marker == "-":
            out.append((base_no, max(head_no, 1), raw[1:]))
            base_no, old_left = base_no + 1, old_left - 1
        elif marker == "+":
            head_no, new_left = head_no + 1, new_left - 1
        elif marker in (" ", ""):
            base_no, head_no = base_no + 1, head_no + 1
            old_left, new_left = old_left - 1, new_left - 1
    return out


class _LineMap:
    """Maps head lines a diff left unchanged to their base lines."""

    def __init__(self, diff_text: str) -> None:
        self.context: dict[int, int] = {}
        self.added: set[int] = set()
        # (first head line after the hunk, head minus base line numbers after it)
        self.hunks: list[tuple[int, int]] = []
        old_left = new_left = base_no = head_no = 0
        for raw in diff_text.split("\n"):
            if old_left <= 0 and new_left <= 0:
                match = _HUNK_RE.match(raw)
                if match:
                    old_start, new_start = int(match.group(1)), int(match.group(3))
                    old_len = int(match.group(2)) if match.group(2) is not None else 1
                    new_len = int(match.group(4)) if match.group(4) is not None else 1
                    # An empty side's start names the line before the hunk.
                    base_no = old_start if old_len else old_start + 1
                    head_no = new_start if new_len else new_start + 1
                    old_left, new_left = old_len, new_len
                    self.hunks.append(
                        (head_no + new_len, (head_no + new_len) - (base_no + old_len))
                    )
                continue
            marker = raw[:1]
            if marker == "-":
                base_no, old_left = base_no + 1, old_left - 1
            elif marker == "+":
                self.added.add(head_no)
                head_no, new_left = head_no + 1, new_left - 1
            elif marker in (" ", ""):
                self.context[head_no] = base_no
                base_no, head_no = base_no + 1, head_no + 1
                old_left, new_left = old_left - 1, new_left - 1

    def base_line(self, line: int) -> int | None:
        if line in self.context:
            return self.context[line]
        if line in self.added:
            return None
        delta = 0
        for after, shift in self.hunks:
            if after <= line:
                delta = shift
        return line - delta


def _normalized(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


def _skippable(path: str) -> bool:
    """Paths left out of both snapshots: unsafe names, Skylos runtime files
    and folders the analyzer excludes by default."""
    from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

    pure = PurePosixPath(path)
    if (
        not path
        or pure.is_absolute()
        or "\\" in path
        or "�" in path
        # Office/editor lock files (~$deck.pptx); a receipt cannot name a
        # path that starts with "~" either.
        or path.startswith("~")
        or is_runtime_path(path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        return True
    return any(
        fnmatch.fnmatchcase(part, pattern)
        for part in pure.parts[:-1]
        for pattern in DEFAULT_EXCLUDE_FOLDERS
    )


def _base_entries(comparison: Comparison) -> list[tuple[str, str, int]]:
    listing = _git_text(
        comparison._context, "ls-tree", "-r", "-l", "-z", comparison.base_sha
    )
    if listing is None:
        raise OrphansUnavailable("the base commit's files could not be listed")
    entries, total = [], 0
    for record in listing.split("\0"):
        header, separator, name = record.partition("\t")
        fields = header.split()
        if not separator or len(fields) != 4:
            continue
        mode, kind, object_id, size = fields
        # Symlinks and submodules stay out of both snapshots.
        if mode not in {"100644", "100755"} or kind != "blob" or not size.isdigit():
            continue
        if _skippable(name) or int(size) > MAX_FILE_BYTES:
            continue
        total += int(size)
        entries.append((name, object_id, int(size)))
        if len(entries) > MAX_FILES or total > MAX_BYTES:
            raise OrphansUnavailable("the repository is too large for this check")
    return entries


def _write_base_snapshot(comparison: Comparison, destination: Path) -> set[str]:
    from skylos.core.pr_impact import ImpactUnavailable, _write_snapshot

    destination.mkdir(parents=True)
    entries = _base_entries(comparison)
    try:
        _write_snapshot(comparison._context, entries, destination)
    except ImpactUnavailable as exc:
        raise OrphansUnavailable("the base commit's files could not be read") from exc
    return _strip_tests(destination, [name for name, _, _ in entries])


def _write_head_snapshot(
    comparison: Comparison, paths: list[str], destination: Path
) -> set[str]:
    destination.mkdir(parents=True)
    written, total = [], 0
    for rel in paths:
        if _skippable(rel):
            continue
        text = read_project_text_no_symlink(
            comparison.root,
            rel,
            max_bytes=MAX_FILE_BYTES,
            encoding="latin-1",
            newline="",
        )
        if text is None:
            continue
        data = text.encode("latin-1")
        total += len(data)
        written.append(rel)
        if len(written) > MAX_FILES or total > MAX_BYTES:
            raise OrphansUnavailable("the repository is too large for this check")
        target = destination.joinpath(*PurePosixPath(rel).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)  # skylos: ignore[SKY-D215,SKY-D324] repo-relative path validated by _skippable, inside a fresh private TemporaryDirectory
    return _strip_tests(destination, written)


def _strip_tests(root: Path, paths: list[str]) -> set[str]:
    """Remove test files so the analysis shows production liveness."""
    tests = {path for path in paths if is_test_code_path(path, root)}
    for path in tests:
        root.joinpath(*PurePosixPath(path).parts).unlink(missing_ok=True)
    return tests


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _analyze(root: Path) -> dict:
    """Dead-code analysis of a snapshot, without grep verification."""
    from skylos.analyzer import Skylos
    from skylos.config import load_config
    from skylos.constants import parse_exclude_folders
    from skylos.core.pr_impact import _snapshot_environment

    analyzer_logger = logging.getLogger("Skylos")
    level = analyzer_logger.level
    # Parse errors are counted on the receipt; the analyzer's own log lines
    # would name private temporary paths.
    analyzer_logger.setLevel(logging.CRITICAL)
    try:
        with _snapshot_environment():
            config = load_config(root)
            exclude = parse_exclude_folders(
                config_exclude_folders=config.get("exclude")
            )
            raw = Skylos().analyze(
                str(root),
                thr=CONFIDENCE,
                exclude_folders=sorted(exclude),
                grep_verify=False,
                grep_cache=False,
                trace_file=False,
                enable_dependency_hallucinations=False,
                skip_generated=not config.get("include_generated", False),
            )
    finally:
        analyzer_logger.setLevel(level)
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise OrphansUnavailable("the dead-code analysis returned no result")
    result["_orphans_excluded"] = sorted(exclude)
    return result


def _relative(value, root: Path) -> str | None:
    if not value:
        return None
    path = Path(str(value))
    for base in (root, root.resolve()):
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _symbol_name(raw, absolute_file) -> str:
    """The analyzer's name for a symbol, without a ``<file>:`` prefix."""
    name = str(raw or "")
    for prefix in {
        str(absolute_file or ""),
        str(Path(str(absolute_file or "")).resolve()),
    }:
        if prefix and name.startswith(prefix + ":"):
            return name[len(prefix) + 1 :]
    return name


def _dead_symbol(item, root: Path, doubt: str = "") -> Symbol | None:
    if not isinstance(item, dict) or str(item.get("type")) not in _SYMBOL_TYPES:
        return None
    path = _relative(item.get("file"), root)
    name = _symbol_name(item.get("full_name") or item.get("name"), item.get("file"))
    line = item.get("line")
    confidence = item.get("confidence")
    if not path or not name or not isinstance(line, int) or line < 1:
        return None
    if not doubt and (
        not isinstance(confidence, (int, float)) or confidence < CONFIDENCE
    ):
        return None
    reasons = item.get("dead_code_reason_tags") or ()
    return Symbol(
        path, name, str(item["type"]), line, tuple(str(r) for r in reasons), doubt
    )


def _head_view(result: dict, root: Path) -> _HeadView:
    dead: dict[tuple[str, str], Symbol] = {}
    items: dict[tuple[str, str], dict] = {}
    for category in _SYMBOL_CATEGORIES:
        for item in result.get(category) or ():
            symbol = _dead_symbol(item, root)
            if symbol is not None:
                dead[(symbol.path, symbol.name)] = symbol
                items[(symbol.path, symbol.name)] = item
    uncertain: dict[tuple[str, str], Symbol] = {}
    for item in result.get("dead_code_abstentions") or ():
        if not _no_references_left(item):
            continue
        symbol = _dead_symbol(item, root, _doubt(item))
        key = (symbol.path, symbol.name) if symbol is not None else None
        if key is not None and key not in dead:
            uncertain[key] = symbol
            items[key] = item
    unparsed, not_checked = set(), {}
    for error in result.get("analysis_errors") or ():
        if not isinstance(error, dict):
            continue
        if error.get("kind") == "language_engine_unavailable":
            language = str(error.get("language") or "unknown")
            not_checked[language] = _engine_reason(language)
        elif path := _relative(error.get("file"), root):
            unparsed.add(path)
    excluded = tuple(result.get("_orphans_excluded") or ())
    return _HeadView(
        dead,
        _dead_files(result, root),
        unparsed,
        not_checked,
        items,
        excluded,
        uncertain,
    )


def _no_references_left(item) -> bool:
    """The analyzer found no static reference to the symbol (it abstained
    for another reason, such as a weak helper name)."""
    if not isinstance(item, dict):
        return False
    references = item.get("references")
    return (
        isinstance(references, int)
        and not isinstance(references, bool)
        and references == 0
    )


def _doubt(item: dict) -> str:
    reasons = [
        str(evidence.get("reason"))
        for evidence in item.get("dead_code_evidence") or ()
        if isinstance(evidence, dict)
        and evidence.get("role") == "uncertainty"
        and evidence.get("reason")
    ]
    return _clip("; ".join(dict.fromkeys(reasons)) or "the analyzer abstained", 80)


def _engine_reason(language: str) -> str:
    if language == "go":
        return "Go (skylos-go engine not installed)"
    if language == "dart":
        return "Dart (Dart support not installed)"
    return f"{language} (analysis engine unavailable)"


def _dead_files(result: dict, root: Path) -> set[str]:
    return {
        path
        for item in result.get("unused_files") or ()
        if isinstance(item, dict)
        and item.get("rule_id") == _DEAD_FILE_RULE
        and (path := _relative(item.get("file"), root))
    }


def _alive_index(result: dict, root: Path) -> dict[str, dict[str, tuple[str, int]]]:
    alive: dict[str, dict[str, tuple[str, int]]] = {}
    definitions = result.get("definitions")
    for entry in (definitions or {}).values() if isinstance(definitions, dict) else ():
        if (
            not isinstance(entry, dict)
            or entry.get("dead_code_classification") != "alive"
        ):
            continue
        kind, line = str(entry.get("type")), entry.get("line")
        path = _relative(entry.get("file"), root)
        if kind not in _SYMBOL_TYPES or not path or not isinstance(line, int):
            continue
        name = _symbol_name(entry.get("name"), entry.get("file"))
        alive.setdefault(path, {})[name] = (kind, line)
    return alive


# ---------------------------------------------------------------------------
# Base view, cached by base commit
# ---------------------------------------------------------------------------


def _base_view(
    comparison: Comparison, root: Path, *, trust_cache: bool = True
) -> tuple[_BaseView, bool]:
    # The cache is local, unauthenticated state: an agent running as the same
    # user can write it (an integrity key would be just as readable). It only
    # speeds up advice; a blocking run recomputes and rewrites it.
    cache_path = _cache_path(comparison)
    cached = _load_base(comparison.root, cache_path) if trust_cache else None
    if cached is not None:
        return cached, True
    _write_base_snapshot(comparison, root)
    result = _analyze(root)
    files = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.suffix in _JS_SUFFIXES
    }
    view = _BaseView(_alive_index(result, root), files - _dead_files(result, root))
    payload = {
        "schema": _CACHE_SCHEMA,
        "base": comparison.base_sha,
        "alive": {
            path: [[name, kind, line] for name, (kind, line) in sorted(names.items())]
            for path, names in sorted(view.alive.items())
        },
        "alive_files": sorted(view.alive_files),
    }
    if not save_project_json_cache(comparison.root, cache_path, payload, indent=None):
        logger.debug("could not save the branch-orphans base cache")
    return view, False


def _cache_path(comparison: Comparison) -> PurePosixPath:
    from skylos import __version__
    from skylos.analyzer import _dart_support_installed
    from skylos.engines.go_runner import get_go_engine_status

    key = json.dumps(
        [
            _CACHE_SCHEMA,
            __version__,
            comparison.base_sha,
            CONFIDENCE,
            get_go_engine_status().get("status"),
            _dart_support_installed(),
        ]
    )
    return _CACHE_DIR / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")


def _load_base(project_root: Path, cache_path: PurePosixPath) -> _BaseView | None:
    data = load_project_json_cache(project_root, cache_path, max_bytes=MAX_CACHE_BYTES)
    if data.get("schema") != _CACHE_SCHEMA:
        return None
    alive_raw, files_raw = data.get("alive"), data.get("alive_files")
    if not isinstance(alive_raw, dict) or not isinstance(files_raw, list):
        return None
    alive: dict[str, dict[str, tuple[str, int]]] = {}
    for path, rows in alive_raw.items():
        if not isinstance(rows, list):
            return None
        for row in rows:
            if not (
                isinstance(row, list)
                and len(row) == 3
                and isinstance(row[0], str)
                and row[1] in _SYMBOL_TYPES
                and isinstance(row[2], int)
            ):
                return None
            alive.setdefault(str(path), {})[row[0]] = (row[1], row[2])
    if not all(isinstance(path, str) for path in files_raw):
        return None
    return _BaseView(alive, set(files_raw))


# ---------------------------------------------------------------------------
# Classifying head candidates
# ---------------------------------------------------------------------------


@dataclass
class _Candidate:
    rule: str
    path: str
    line: int
    word: str  # the name searched for in unparsed files and tests
    symbol: Symbol | None = None  # None for a whole file
    base_path: str | None = None
    base_line: int | None = None

    @property
    def file_name(self) -> str | None:
        """For a whole-file candidate, its name with the extension."""
        return PurePosixPath(self.path).name if self.symbol is None else None

    @property
    def doubtful(self) -> bool:
        return self.symbol is not None and bool(self.symbol.doubt)


class _Judge:
    def __init__(self, comparison, changes, base, head_tests) -> None:
        self.comparison = comparison
        self.changes = changes
        self.base = base
        self.texts = _TextCache(comparison)
        self.tests = _TestReferences(comparison, sorted(head_tests))

    def reportable(self, path: str) -> bool:
        from skylos.done.answer_sites import _is_generated, _is_test_code

        if _is_test_code(path, set()) or is_test_code_path(path, self.comparison.root):
            return False
        return not _is_generated(path, self.texts.head(path))

    def decorated(self, candidate: _Candidate) -> bool:
        """A decorator or annotation that may register the symbol with a
        framework (``@parser.location_loader(...)``, ``@Scheduled``): the
        framework calls it, so its liveness is not judged."""
        if candidate.symbol is None:
            return False
        text = self.texts.head(candidate.path)
        return any(
            name not in _PLAIN_DECORATORS
            for name in _decorators_above(candidate.path, text, candidate.line)
        )

    # -- symbols and files ----------------------------------------------------

    def classify(
        self, symbols: list[Symbol], files: list[str], doubtful=()
    ) -> list[_Candidate]:
        out = [c for path in files if (c := self._file_candidate(path))]
        # A file unused on both sides (a script nothing imports, a folder
        # without package.json) is not reported, but its symbols still are.
        reported_files = {c.path for c in out}
        for symbol in sorted([*symbols, *doubtful], key=lambda s: (s.path, s.line)):
            if symbol.path in reported_files:
                continue  # the whole file is reported
            candidate = self._symbol_candidate(symbol)
            if candidate is None:
                continue
            if symbol.doubt and candidate.rule != RULE_MADE_DEAD:
                continue  # new code the analyzer is unsure about: not judged
            out.append(candidate)
        return out

    def _file_candidate(self, path: str) -> _Candidate | None:
        changed = self.changes.by_head.get(path)
        stem = PurePosixPath(path).stem
        if changed is not None and changed.status == "added":
            return _Candidate(RULE_NEW_UNUSED, path, 1, stem)
        base_path = changed.base_path if changed is not None else path
        if base_path in self.base.alive_files:
            return _Candidate(RULE_MADE_DEAD, path, 1, stem, base_path=base_path)
        return None

    def _symbol_candidate(self, symbol: Symbol) -> _Candidate | None:
        changed = self.changes.by_head.get(symbol.path)
        base_path = symbol.path if changed is None else changed.base_path
        declared_here = changed is not None and symbol.line in self.changes.added.get(
            symbol.path, set()
        )
        if not declared_here:
            # Unchanged declaration: the base definition sits on the base line
            # it came from. Names alone can collide (nested ``wrapper``s).
            base_line = self.changes.base_line(symbol.path, symbol.line)
            match = self._base_match(
                [base_path], symbol, lambda _, line: line == base_line
            )
        elif self._is_new(symbol):
            return _Candidate(
                RULE_NEW_UNUSED, symbol.path, symbol.line, symbol.simple, symbol
            )
        else:
            # Re-declared, moved or edited in place: the base definition of the
            # same name whose declaration line this change removed.
            removed = {(r.base_path, r.base_line) for r in self.changes.removed}
            paths = [base_path] + sorted({path for path, _ in removed})
            match = self._base_match(
                paths, symbol, lambda path, line: (path, line) in removed
            )
        if match is None:
            return None
        found_path, found_line = match
        return _Candidate(
            RULE_MADE_DEAD,
            symbol.path,
            symbol.line,
            symbol.simple,
            symbol,
            found_path,
            found_line,
        )

    def _base_match(self, paths, symbol: Symbol, at) -> tuple[str, int] | None:
        """The base definition, alive at the base, that ``symbol`` continues:
        same kind, same name (or same last name in a renamed module), and a
        base line ``at(path, line)`` accepts."""
        for path in dict.fromkeys(p for p in paths if p):
            names = self.base.alive.get(path, {})
            same = [
                (name, line)
                for name, (kind, line) in names.items()
                if kind == symbol.kind
                and re.split(r"[.:#]", name)[-1] == symbol.simple
                and at(path, line)
            ]
            exact = [(name, line) for name, line in same if name == symbol.name]
            if len(exact or same) == 1:
                return path, (exact or same)[0][1]
        return None

    def _is_new(self, symbol: Symbol) -> bool:
        """Added by this change: the name is in no removed line, and the body
        is mostly new lines that were not removed elsewhere. A body kept as
        unchanged lines or moved from another place is a rename or a move."""
        if symbol.simple in self.changes.removed_words():
            return False
        added = self.changes.added.get(symbol.path, set())
        body = [
            (number, _normalized(text))
            for number, text in enumerate(
                self.texts.span_lines(symbol)[1:], symbol.line + 1
            )
            if len(_normalized(text)) >= 4 and _WORD_RE.search(text)
        ]
        if len(body) < 2:
            return True
        removed = self.changes.removed_text()
        kept = sum(number not in added or text in removed for number, text in body)
        return kept / len(body) < _MOVED_BODY_SHARE

    # -- messages -------------------------------------------------------------

    def describe(self, candidates: list[_Candidate]) -> list[Orphan]:
        orphans = []
        for candidate in candidates:
            if candidate.symbol is None:
                message = self._file_message(candidate)
            elif candidate.rule == RULE_MADE_DEAD:
                message = self._made_dead_message(candidate)
            else:
                message = self._new_symbol_message(candidate)
            rule = candidate.rule
            if rule == RULE_NEW_UNUSED and self._test_reference(candidate):
                rule = RULE_TEST_ONLY
            if candidate.doubtful:
                message += (
                    "; Skylos isn't certain nothing else uses it "
                    f"({candidate.symbol.doubt})"
                )
            orphans.append(
                Orphan(
                    rule, candidate.path, candidate.line, message, candidate.doubtful
                )
            )
        return sorted(orphans, key=lambda o: (RULES.index(o.rule), o.path, o.line))

    def _test_reference(self, candidate: _Candidate) -> tuple[str, int] | None:
        if candidate.symbol is None:
            return self.tests.find_import(candidate.word)
        return self.tests.find(candidate.word)

    def _new_symbol_message(self, candidate: _Candidate) -> str:
        symbol, name = candidate.symbol, f"`{candidate.word}`"
        test = self.tests.find(candidate.word)
        if test is not None:
            return (
                f"{name} was added by this change and only tests call it "
                f"({test[0]}:{test[1]}); no production code does"
            )
        if symbol is not None and "no_reachable_callers" in symbol.reasons:
            return f"{name} was added by this change and its only callers are themselves unused"
        return f"{name} was added by this change and nothing calls it"

    def _made_dead_message(self, candidate: _Candidate) -> str:
        symbol = candidate.symbol
        name = f"`{candidate.word}`"
        span = set(range(symbol.line, symbol.line + len(self.texts.span_lines(symbol))))
        untouched = not (span & self.changes.added.get(symbol.path, set()))
        lead = f"{name} (not touched by this change)" if untouched else name
        callers, uses = _lost_callers(self, candidate)
        if callers:
            first = callers[0]
            where = (
                f"{first.head_path}:{first.head_line} changed"
                if first.head_path
                else f"{first.base_path} was deleted"
            )
            more = f" and {len(callers) - 1} other line(s)" if len(callers) > 1 else ""
            if not uses:
                what = "its last import" if len(callers) == 1 else "its imports"
            else:
                what = "its last caller" if len(callers) == 1 else "its callers"
            message = f"{lead} lost {what} when {where}{more} (`{_clip(first.text)}`)"
        elif "no_reachable_callers" in symbol.reasons:
            message = f"{lead} is still called only by code this change left unused"
        else:
            message = f"{lead} has no production caller after this change"
        test = self.tests.find(candidate.word)
        if test is not None:
            message += f"; only tests call it now ({test[0]}:{test[1]})"
        return message

    def _file_message(self, candidate: _Candidate) -> str:
        test = self.tests.find_import(candidate.word)
        if candidate.rule == RULE_MADE_DEAD:
            removed = _lost_importers(self, candidate)
            message = "Nothing imports this file any more"
            if removed:
                where = (
                    f"{removed.head_path}:{removed.head_line} changed"
                    if removed.head_path
                    else f"{removed.base_path} was deleted"
                )
                message += f": it lost its last importer when {where} (`{_clip(removed.text)}`)"
        elif test is not None:
            return f"This file was added by this change and only tests import it ({test[0]}:{test[1]})"
        else:
            return "This file was added by this change and nothing imports it"
        if test is not None:
            message += f"; only tests import it now ({test[0]}:{test[1]})"
        return message


def _decorators_above(path: str, text: str | None, line: int) -> list[str]:
    """Last name of each decorator or annotation on the definition that
    starts at ``line``: from the syntax tree for Python, otherwise the
    ``@`` lines directly above it and on the declaration line itself."""
    if text is None:
        return []
    if path.endswith(_PY_SUFFIXES):
        names = _python_decorators(text).get(line)
        if names is not None:
            return names
    lines = text.splitlines()
    if not 0 < line <= len(lines):
        return []
    names = re.findall(r"@([\w.]+)", lines[line - 1].split("(", 1)[0])
    for index in range(line - 2, max(line - 30, 0) - 1, -1):
        stripped = lines[index].strip()
        if stripped.startswith("@"):
            names.append(re.match(r"@([\w.]*)", stripped).group(1))
        elif not stripped.startswith(("//", "/*", "*", "#")):
            break
    return [name.rsplit(".", 1)[-1] for name in names if name]


@functools.lru_cache(maxsize=32)
def _python_decorators(text: str) -> dict[int, list[str]]:
    """Decorators that may register a definition: attribute or call forms
    (``@app.route(...)``, ``@bus.subscribe("x")``, ``@receiver(sig)``). A
    bare name (``@login_required``, ``@as_transaction``) wraps the function
    and does not count."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return {}
    found: dict[int, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Name):
                    continue
                target = (
                    decorator.func if isinstance(decorator, ast.Call) else decorator
                )
                if isinstance(target, ast.Attribute):
                    names.append(target.attr)
                elif isinstance(target, ast.Name):
                    names.append(target.id)
                else:
                    names.append("?")
            for start in (node.lineno, *(d.lineno for d in node.decorator_list)):
                found.setdefault(start, names)
    return found


def _clip(text: str, limit: int = 60) -> str:
    text = _normalized(text).replace("`", "'")
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Attribution: which removed line referenced the symbol
# ---------------------------------------------------------------------------


def _lost_callers(judge: _Judge, candidate: _Candidate) -> tuple[list[_Removed], bool]:
    """Removed lines that used the symbol, calls first; when no use was
    removed, the removed imports of it. The flag says which."""
    word = candidate.word
    own_span = _base_span(judge, candidate)
    found: list[tuple[int, _Removed]] = []
    for item in judge.changes.removed:
        if word not in item.text:
            continue
        if item.base_path == candidate.base_path and item.base_line in own_span:
            continue
        rank = judge.texts.reference_rank(item, word)
        if rank is not None:
            found.append((rank, item))
    found.sort(key=lambda pair: (pair[0], pair[1].base_path, pair[1].base_line))
    uses = [item for rank, item in found if rank < _IMPORT]
    if uses:
        return uses, True
    return [item for _, item in found], False


def _base_span(judge: _Judge, candidate: _Candidate) -> range:
    if candidate.base_path is None or candidate.base_line is None:
        return range(0)
    text = judge.texts.base(candidate.base_path)
    end = _span_end(candidate.base_path, text, candidate.base_line)
    return range(candidate.base_line, end + 1)


def _lost_importers(judge: _Judge, candidate: _Candidate) -> _Removed | None:
    pattern = re.compile(rf"(?<![\w$-]){re.escape(candidate.word)}(?![\w$-])")
    for item in judge.changes.removed:
        if (
            item.base_path != candidate.base_path
            and pattern.search(item.text)
            and re.search(r"\b(?:import|require|from|export)\b", item.text)
        ):
            return item
    return None


# ---------------------------------------------------------------------------
# Source text helpers
# ---------------------------------------------------------------------------


class _TextCache:
    def __init__(self, comparison: Comparison) -> None:
        self.comparison = comparison
        self._head: dict[str, str | None] = {}
        self._base: dict[str, str | None] = {}
        self._base_refs: dict[str, tuple | None] = {}

    def head(self, path: str) -> str | None:
        if path not in self._head:
            self._head[path] = self.comparison.head_text(path)
        return self._head[path]

    def base(self, path: str) -> str | None:
        if path not in self._base:
            self._base[path] = self.comparison.base_text(path)
        return self._base[path]

    def span_lines(self, symbol: Symbol) -> list[str]:
        """The lines of a head definition (at least its first line)."""
        text = self.head(symbol.path)
        if text is None:
            return [""]
        lines = text.splitlines()
        end = _span_end(symbol.path, text, symbol.line)
        return lines[symbol.line - 1 : end] or [""]

    def reference_rank(self, item: _Removed, word: str) -> int | None:
        """0 for a call, 1 for another use, 2 for an import, None for none."""
        if item.base_path.endswith(_PY_SUFFIXES):
            found = self._python_refs(item.base_path)
            if found is not None:
                refs, imports = found
                if item.base_line not in refs.get(word, ()):
                    return None
                if item.base_line in imports:
                    return _IMPORT
                return 0 if re.search(rf"\b{re.escape(word)}\s*\(", item.text) else 1
        return _text_reference_rank(item.text, word)

    def _python_refs(self, path: str):
        if path not in self._base_refs:
            self._base_refs[path] = _python_references(self.base(path))
        return self._base_refs[path]


def _text_reference_rank(text: str, word: str) -> int | None:
    if _LINE_COMMENT_RE.match(text):
        return None
    code = re.sub(r"""(["'`])(?:\\.|(?!\1).)*\1""", '""', text)
    code = code.split("//", 1)[0]
    pattern = rf"(?<![\w$]){re.escape(word)}(?![\w$])"
    if _is_declaration(code, word):
        return None
    if not re.search(pattern, code):
        # A string naming the symbol (dispatch tables, getattr) still counts.
        return 1 if re.search(pattern, text) else None
    if _IMPORT_LINE_RE.match(code):
        return _IMPORT
    return 0 if re.search(pattern + r"\s*[(<]", code) else 1


def _is_declaration(code: str, word: str) -> bool:
    """A line that declares ``word`` (Go, Java, JS/TS, PHP, Rust) rather
    than using it: a removed method of the same name is not a caller."""
    name = re.escape(word)
    if re.search(
        rf"\b(?:def|function|func|fn|class|interface|struct|enum|trait|type)\s+"
        rf"(?:\([^)]*\)\s*)?{name}\b",
        code,
    ):
        return True
    # Java/C#/TS member: modifiers and a return type, then name(params) {
    return bool(
        re.match(
            rf"^\s*(?:@\w+\s+)*(?:[\w$<>\[\],.?]+\s+)+{name}\s*\([^;=]*\)\s*"
            rf"(?:throws\s+[\w.,\s]+)?[{{]?\s*$",
            code,
        )
        and not re.match(r"^\s*(?:return|new|throw|await|yield|else)\b", code)
    )


def _python_reference_lines(source: str | None) -> dict[str, set[int]] | None:
    """Lines where each name is used (not defined) in Python source."""
    found = _python_references(source)
    return None if found is None else found[0]


def _python_references(source: str | None):
    """(name -> lines it is used on, lines of import statements)."""
    if source is None:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    refs: dict[str, set[int]] = {}
    imports: set[int] = set()

    def add(name, node) -> set[int]:
        lines = set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        refs.setdefault(name, set()).update(lines)
        return lines

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            add(node.id, node)
        elif isinstance(node, ast.Attribute):
            add(node.attr, node)
        elif isinstance(node, (ast.ImportFrom, ast.Import)):
            for alias in node.names:
                imports |= add(alias.name.split(".")[-1], node)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.isidentifier()
        ):
            add(node.value, node)
    return refs, imports


def _span_end(path: str, text: str | None, line: int) -> int:
    """Last line of the definition that starts at ``line``."""
    if text is None:
        return line
    if path.endswith(_PY_SUFFIXES):
        end = _python_span_end(text, line)
        if end is not None:
            return end
    return _brace_span_end(text.splitlines(), line)


def _python_span_end(text: str, line: int) -> int | None:
    ends = _python_definition_ends(text)
    return None if ends is None else ends.get(line)


@functools.lru_cache(maxsize=32)
def _python_definition_ends(text: str) -> dict[int, int] | None:
    """First line (``def``/``class`` or decorator) -> last line, per definition."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    ends: dict[int, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for start in (node.lineno, *(d.lineno for d in node.decorator_list)):
                ends.setdefault(start, node.end_lineno or node.lineno)
    return ends


def _brace_span_end(lines: list[str], line: int, limit: int = 400) -> int:
    """End of a brace-delimited block starting at ``line`` (Java, Go, JS/TS)."""
    depth, opened = 0, False
    last = min(len(lines), line - 1 + limit)
    for index in range(line - 1, last):
        code = re.sub(r"""(["'`])(?:\\.|(?!\1).)*\1""", '""', lines[index]).split(
            "//", 1
        )[0]
        for char in code:
            if char == "{":
                depth, opened = depth + 1, True
            elif char == "}":
                depth -= 1
        if opened and depth <= 0:
            return index + 1
        if not opened and index - (line - 1) >= 3:
            return line
    return line if not opened else last


class _WordIndex(set):
    """Identifiers and file-name tokens that appear in snapshot files."""

    @classmethod
    def from_files(cls, root: Path, paths) -> _WordIndex:
        index, total = cls(), 0
        for path in paths:
            try:
                text = root.joinpath(*PurePosixPath(path).parts).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
            total += len(text)
            if total > MAX_TEST_BYTES:
                break
            index.update(_WORD_RE.findall(text))
            index.update(_FILE_TOKEN_RE.findall(text))
        return index


def _elsewhere_files(root: Path) -> list[str]:
    """Templates, markup and configuration in the head snapshot: files the
    dead-code engine does not read for references, where code is still
    called by name (a template's script, a YAML handler, an XML bean)."""
    found = []
    for path in root.rglob("*"):
        name = path.name
        if not path.is_file() or name in _LOCK_FILES:
            continue
        if path.suffix.lower() in _ELSEWHERE_SUFFIXES or name in _ELSEWHERE_NAMES:
            found.append(path.relative_to(root).as_posix())
    return sorted(found)


class _TestReferences:
    """Where head test files use a name: the first call or other use, else
    the first import of it (file and line)."""

    def __init__(self, comparison: Comparison, paths: list[str]) -> None:
        self.comparison = comparison
        self.paths = paths
        self._uses: dict[str, tuple[str, int]] | None = None
        self._imported: dict[str, tuple[str, int]] = {}
        self._imports: dict[str, tuple[str, int]] = {}

    def find(self, word: str) -> tuple[str, int] | None:
        self._build()
        return self._uses.get(word) or self._imported.get(word)

    def find_import(self, stem: str) -> tuple[str, int] | None:
        self._build()
        return self._imports.get(stem)

    def _build(self) -> None:
        if self._uses is not None:
            return
        self._uses, total = {}, 0
        for path in self.paths:
            text = self.comparison.head_text(path)
            if text is None:
                continue
            total += len(text)
            if total > MAX_TEST_BYTES:
                break
            self._add(path, text)

    def _add(self, path: str, text: str) -> None:
        found = _python_references(text) if path.endswith(_PY_SUFFIXES) else None
        if found is not None:
            refs, imports = found
            for word, numbers in refs.items():
                uses = numbers - imports
                if uses:
                    self._uses.setdefault(word, (path, min(uses)))
                else:
                    self._imported.setdefault(word, (path, min(numbers)))
        for number, line in enumerate(text.splitlines(), 1):
            is_import = bool(_IMPORT_LINE_RE.match(line))
            if found is None and not _LINE_COMMENT_RE.match(line):
                target = self._imported if is_import else self._uses
                for word in _WORD_RE.findall(line):
                    target.setdefault(word, (path, number))
            if is_import or re.search(r"\b(?:import|require|from)\b", line):
                for word in re.findall(r"[\w$-]+", line):
                    self._imports.setdefault(word, (path, number))
