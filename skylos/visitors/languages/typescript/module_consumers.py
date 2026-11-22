"""Module imports of project files that are not JS/TS sources.

Vue, Svelte and Astro component scripts, inline ``<script type="module">``
blocks of HTML pages and MDX ``import``/``export`` statements load project
modules. Export checks read them as source text with the TS/JS grammar;
nothing is compiled or executed.

Every consumer yields three things:

- ``imports``: raw import records of the parts that parsed (the same shape as
  :attr:`TypeScriptCore.raw_imports`), so their named requests stay exact;
- ``held``: specifiers named by a part that did not parse (an unsupported
  script language, a syntax error, a Marko template). Only the modules those
  specifiers reach are held back as wholly used;
- ``entries``: ``<script type="module" src>`` targets, loaded as entry
  scripts (their whole export surface is public).

Only a consumer whose text cannot be read at all, or a walk past the
inventory budget, leaves ``complete`` false so the caller can abstain.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink

from .mdx_modules import mdx_module_parts

COMPONENT_SUFFIXES = frozenset({".vue", ".svelte", ".astro"})
TEMPLATE_SUFFIXES = frozenset({".marko"})
HTML_SUFFIXES = frozenset({".html", ".htm"})
MDX_SUFFIXES = frozenset({".mdx"})
CONSUMER_SUFFIXES = (
    COMPONENT_SUFFIXES | TEMPLATE_SUFFIXES | HTML_SUFFIXES | MDX_SUFFIXES
)
MAX_WALKED_FILES = 200_000
MAX_CONSUMER_BYTES = 2_000_000
MAX_LARGE_CONSUMER_BYTES = 32_000_000
_SKIPPED_DIRECTORIES = frozenset({".git", ".hg", ".svn", "node_modules"})
SPECIFIER_RE = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)(['"])([^'"\r\n]+)\1"""
)
_SCRIPT_RE = re.compile(
    r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>", re.IGNORECASE | re.DOTALL
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_MODULE_TYPE_RE = re.compile(r"""\btype\s*=\s*["']?module\b""", re.IGNORECASE)
_SRC_RE = re.compile(
    r"""\bsrc\s*=\s*(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s>]+))""",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


@dataclass
class ModuleConsumer:
    path: str
    imports: list = field(default_factory=list)
    held: set = field(default_factory=set)
    entries: set = field(default_factory=set)


@dataclass
class ModuleConsumers:
    consumers: dict = field(default_factory=dict)
    unreadable: list = field(default_factory=list)
    over_budget: bool = False

    @property
    def complete(self) -> bool:
        return not self.unreadable and not self.over_budget


def text_specifiers(text: str) -> set[str]:
    """Literal module specifiers a text names (``from``/``import``/``require``)."""
    return {match.group(2) for match in SPECIFIER_RE.finditer(text)}


def _parse_script(path: str, source: str, *, tsx: bool):
    """Raw import records of one script, or None when it does not parse."""
    from .core import TypeScriptCore

    suffix = ".tsx" if tsx else ".ts"
    core = TypeScriptCore(path + suffix, source.encode("utf-8"))
    core.scan()
    if core.root_node is None or core.root_node.has_error:
        return None
    return [dict(item) for item in core.raw_imports if item.get("source")]


def _component_consumer(consumer: ModuleConsumer, path: Path, text: str) -> None:
    from skylos.deadcode.component_imports import _imports

    records, complete, notes, _blocks = _imports(path, text)
    consumer.imports.extend(item for item in records if item.get("source"))
    if not complete or notes:
        # A block that did not parse (another script language, a syntax
        # error) may name any module its text names.
        consumer.held |= text_specifiers(text)


def _html_consumer(consumer: ModuleConsumer, text: str) -> None:
    text = _HTML_COMMENT_RE.sub(lambda match: "\n" * match.group(0).count("\n"), text)
    for match in _SCRIPT_RE.finditer(text):
        attrs = match.group("attrs")
        if not _MODULE_TYPE_RE.search(attrs):
            continue
        source = _SRC_RE.search(attrs)
        if source is not None:
            value = (
                source.group("double") or source.group("single") or source.group("bare")
            )
            if value and not _URL_RE.match(value):
                consumer.entries.add(value)
            continue
        body = match.group("body")
        if "import" not in body:
            continue
        line = text.count("\n", 0, match.start("body"))
        records = _parse_script(consumer.path, "\n" * line + body, tsx=False)
        if records is None:
            consumer.held |= text_specifiers(body)
        else:
            consumer.imports.extend(records)


def _mdx_consumer(consumer: ModuleConsumer, text: str) -> None:
    blocks, expression_specifiers = mdx_module_parts(text)
    consumer.held |= expression_specifiers
    for start, block in blocks:
        records = _parse_script(consumer.path, "\n" * start + block, tsx=True)
        if records is None:
            consumer.held |= text_specifiers(block)
        else:
            consumer.imports.extend(records)


def read_module_consumer(root: Path, path: Path) -> ModuleConsumer | None:
    """Read one consumer; ``None`` when its text cannot be read."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    text = read_project_text_no_symlink(
        root, relative, max_bytes=MAX_CONSUMER_BYTES, errors="replace"
    )
    if text is None:
        try:
            size = path.stat().st_size
        except OSError:
            return None
        if size <= MAX_CONSUMER_BYTES or size > MAX_LARGE_CONSUMER_BYTES:
            return None
        # A large page or document is read once more as text only: its
        # module statements are still bounded by the same parsers.
        text = read_project_text_no_symlink(
            root, relative, max_bytes=MAX_LARGE_CONSUMER_BYTES, errors="replace"
        )
        if text is None:
            return None
    consumer = ModuleConsumer(str(path))
    suffix = path.suffix.lower()
    if suffix in COMPONENT_SUFFIXES:
        _component_consumer(consumer, path, text)
    elif suffix in HTML_SUFFIXES:
        _html_consumer(consumer, text)
    elif suffix in MDX_SUFFIXES:
        _mdx_consumer(consumer, text)
    else:
        consumer.held |= text_specifiers(text)
    return consumer


def collect_module_consumers(root, exclude_folders=None) -> ModuleConsumers:
    """Read every non-JS/TS module consumer under ``root``."""
    from skylos.core.file_discovery import should_exclude_path

    result = ModuleConsumers()
    root_path = Path(os.path.realpath(str(root)))
    walked = 0
    for directory, subdirectories, names in os.walk(root_path):
        current = Path(directory)
        subdirectories[:] = [
            name
            for name in subdirectories
            if name not in _SKIPPED_DIRECTORIES
            and not (
                exclude_folders
                and should_exclude_path(current / name, root_path, exclude_folders)
            )
        ]
        for name in sorted(names):
            walked += 1
            if walked > MAX_WALKED_FILES:
                result.over_budget = True
                return result
            path = current / name
            if path.suffix.lower() not in CONSUMER_SUFFIXES:
                continue
            consumer = read_module_consumer(root_path, path)
            if consumer is None:
                result.unreadable.append(str(path))
                continue
            if consumer.imports or consumer.held or consumer.entries:
                result.consumers[str(path)] = consumer
    return result


def entry_specifier(value: str) -> str:
    """An HTML ``src`` as a module specifier relative to the page.

    ``/src/main.ts`` is served from the page's root (Vite resolves it against
    the folder of ``index.html``); a bare ``main.ts`` is a relative URL.
    """
    value = re.split(r"[?#]", value, maxsplit=1)[0]
    if value.startswith("/"):
        return "." + value
    if value.startswith("."):
        return value
    return "./" + value
