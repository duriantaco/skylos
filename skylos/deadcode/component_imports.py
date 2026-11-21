"""Static import edges through Vue, Svelte and Astro component scripts.

This reads source data only. It does not execute a component compiler, package
script or framework configuration. Edges belong to the JS/TS source loading a
component, so an unused loader cannot make a whole component tree live.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from copy import deepcopy
from html.parser import HTMLParser
from pathlib import Path

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_project_text_no_symlink

COMPONENT_SUFFIXES = frozenset({".vue", ".svelte", ".astro"})
MAX_COMPONENTS = 256
MAX_COMPONENT_BYTES = 1_000_000
MAX_TOTAL_BYTES = 8_000_000
MAX_COMPONENT_DEPTH = 32
MAX_IMPORT_EDGES = 10_000
_SCRIPT_LANGUAGES = frozenset({"", "js", "javascript", "ts", "typescript", "jsx", "tsx"})
_SCRIPT_TYPES = frozenset({"", "module", "text/javascript", "application/javascript"})
_FRONTMATTER = re.compile(r"\A(?:\ufeff)?---[^\S\r\n]*\r?\n(?P<body>[\s\S]*?)^---[^\S\r\n]*(?:\r?\n|\Z)", re.MULTILINE)


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.blocks = []
        self.current = None
        self.styles = []
        self.style = None
        self.template_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "template":
            self.template_depth += 1
        if tag in {"script", "style"} and not self.template_depth:
            line = self.getpos()[0] + (self.get_starttag_text() or "").count("\n")
            if tag == "script":
                self.current = (dict(attrs), line, [])
            else:
                self.style = (dict(attrs), line, [])

    def handle_data(self, data):
        if self.current is not None:
            self.current[2].append(data)
        elif self.style is not None:
            self.style[2].append(data)

    def handle_endtag(self, tag):
        if tag == "template":
            self.template_depth = max(0, self.template_depth - 1)
        if tag == "script" and self.current is not None:
            attrs, line, body = self.current
            self.blocks.append((attrs, line, "".join(body)))
            self.current = None
        if tag == "style" and self.style is not None:
            attrs, line, body = self.style
            self.styles.append((attrs, line, "".join(body)))
            self.style = None


def _script_blocks(source, suffix):
    blocks, _styles, complete = component_blocks(source, suffix)
    return blocks, complete


def component_blocks(source, suffix):
    """Return top-level script and style blocks with their starting lines.

    Blocks are read as text only; ``complete`` is false for an unclosed block
    or an unterminated Astro frontmatter fence.
    """
    blocks = []
    if suffix == ".astro":
        frontmatter = _FRONTMATTER.match(source)
        if frontmatter:
            blocks.append(({"lang": "ts"}, 1, "\n" + frontmatter.group("body")))
            source = "\n" * source[: frontmatter.end()].count("\n") + source[frontmatter.end() :]
        elif source.lstrip("\ufeff").startswith("---"):
            return [], [], False
    parser = _Scripts()
    parser.feed(source)
    parser.close()
    blocks.extend(parser.blocks)
    return blocks, parser.styles, parser.current is None and parser.style is None


def _component_specifier(specifier):
    if not isinstance(specifier, str) or "?" in specifier or "#" in specifier:
        return False
    return Path(specifier).suffix.lower() in COMPONENT_SUFFIXES


def _rune_module(target):
    """A ``.svelte`` specifier that resolved to a Svelte 5 module script.

    ``import { count } from "./state.svelte"`` loads ``state.svelte.ts`` (or
    ``.js``): an ordinary module, already an edge of its importer, not a
    component whose script needs expanding.
    """
    return target is not None and Path(target).suffix.lower() not in COMPONENT_SUFFIXES


def _safe_component(root, candidate, exclude_folders):
    candidate = Path(candidate).absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if exclude_folders and should_exclude_path(candidate, root, exclude_folders):
        return None
    # The reader rejects links in every path component, not just the leaf.
    text = read_project_text_no_symlink(root, relative, max_bytes=MAX_COMPONENT_BYTES)
    return text


def _imports(path, source):
    """Return exact source import bindings and a bounded parse receipt."""
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    blocks, complete = _script_blocks(source, path.suffix.lower())
    imports = []
    notes = []
    for attrs, start_line, body in blocks:
        lang = (attrs.get("lang") or "").lower()
        script_type = (attrs.get("type") or "").lower()
        if script_type not in _SCRIPT_TYPES:
            continue  # JSON and other data blocks do not import executable code.
        if lang not in _SCRIPT_LANGUAGES:
            complete = False
            notes.append("unsupported_script_language")
            continue
        script_source = attrs.get("src")
        if script_source:
            imports.append({"source": script_source, "names": [], "line": start_line, "consume_all_exports": True})
            continue
        suffix = ".tsx" if lang in {"tsx", "jsx"} else ".ts"
        padded = "\n" * (start_line - 1) + body
        core = TypeScriptCore(str(path) + suffix, padded.encode("utf-8"))
        core.scan()
        parsed = core.root_node is not None and not core.root_node.has_error
        if not parsed:
            complete = False
            notes.append("script_parse_error")
        for raw in core.raw_imports:
            item = deepcopy(raw)
            # Component render expressions can read a namespace outside its
            # script AST. Without a framework binding proof, keep that one
            # namespace conservative rather than claiming unreferenced members.
            if item.get("namespace_members"):
                statement = next((d for d in core.imports if d.get("line") == item.get("line")), None)
                local_names = [str(d.get("name", "")) for d in core.imports if d.get("line") == item.get("line")]
                if statement is not None and any(
                    re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", source.replace(body, ""))
                    for name in local_names if name
                ):
                    item["consume_all_exports"] = True
            if not parsed:
                item["consume_all_exports"] = True
            imports.append(item)
    if not complete and not notes:
        notes.append("unclosed_component_script")
    return imports, complete, notes, len(blocks)


def expand_component_imports(project_root, source_files, raw_imports, *, resolver=None, exclude_folders=None):
    """Return extra graph records keyed by their actual JS/TS loading source.

    The returned receipt describes import extraction only, not full component
    declaration, security or quality analysis. Unsupported source is explicit.
    Callers merge these records after checks that require a literal source
    import declaration; ``component_file`` identifies each original declaration.
    """
    from skylos.deadcode.component_providers import generated_component_provider_limits
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    root = Path(project_root).resolve()
    selected = {str(Path(file).absolute()) for file in source_files}
    cache = {}
    extras = {}
    visited = set()
    counts = Counter()
    issues = generated_component_provider_limits(root, selected, raw_imports)
    total_bytes = 0
    edge_count = 0

    def load(path):
        nonlocal total_bytes
        key = str(path)
        if key in cache:
            return cache[key]
        if len(cache) >= MAX_COMPONENTS:
            issues.append({"file": key, "reason": "component_limit"})
            return None
        text = _safe_component(root, path, exclude_folders)
        if text is None:
            issues.append({"file": key, "reason": "unreadable_or_excluded_component"})
            cache[key] = None
            return None
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_BYTES:
            issues.append({"file": key, "reason": "component_byte_limit"})
            cache[key] = None
            return None
        imports, _complete, notes, blocks = _imports(path, text)
        counts[path.suffix.lower()[1:]] += 1
        counts["script_blocks"] += blocks
        for reason in notes:
            issues.append({"file": key, "reason": reason})
        cache[key] = imports
        return imports

    def visit(component, owner, depth, ancestors):
        nonlocal edge_count
        if depth >= MAX_COMPONENT_DEPTH:
            issues.append({"file": str(component), "reason": "component_depth_limit"})
            return
        if component in ancestors:
            return
        identity = (owner, component)
        if identity in visited:
            return
        if len(visited) >= MAX_IMPORT_EDGES:
            if not any(issue["reason"] == "component_edge_limit" for issue in issues):
                issues.append({"file": str(component), "reason": "component_edge_limit"})
            return
        visited.add(identity)
        entries = load(component)
        if entries is None:
            return
        ancestors = ancestors | {component}
        for raw in entries:
            specifier = raw.get("source", "")
            target = resolve_ts_module(specifier, str(component), resolver)
            if _component_specifier(specifier) and not _rune_module(target):
                if target is None:
                    issues.append({"file": str(component), "reason": "unresolved_component", "source": specifier})
                else:
                    visit(Path(target), owner, depth + 1, ancestors)
                continue
            item = deepcopy(raw)
            if target is not None:
                item["source"] = "./" + os.path.relpath(target, Path(owner).parent).replace(os.sep, "/")
            elif specifier.startswith("."):
                # Preserve the actual module location even when its provider
                # is unavailable; a bridge must not resolve beside the loader.
                absolute = Path(component).parent / specifier
                item["source"] = "./" + os.path.relpath(absolute, Path(owner).parent).replace(os.sep, "/")
            if item.pop("is_reexport", False):
                # A forwarded component API is not an export of its loader.
                # Named forwarding retains only its declared binding; wildcard
                # and namespace forwarding retain the provider conservatively.
                if any(name == "*" or name.startswith("* as ") for name in item.get("names", ())):
                    item["consume_all_exports"] = True
                item.pop("reexport_reference_names", None)
            item["component_file"] = str(component)
            item["component_line"] = item.get("line", 1)
            item["is_component_import"] = True
            edge_count += 1
            if edge_count > MAX_IMPORT_EDGES:
                issues.append({"file": str(component), "reason": "component_edge_limit"})
                return
            extras.setdefault(Path(owner), []).append(item)

    for importer, records in raw_imports.items():
        owner = str(Path(importer).absolute())
        if owner not in selected:
            continue
        for raw in records:
            specifier = raw.get("source", "")
            if not _component_specifier(specifier):
                continue
            target = resolve_ts_module(specifier, owner, resolver)
            if target is None:
                issues.append({"file": owner, "reason": "unresolved_component", "source": specifier})
            elif not _rune_module(target):
                visit(Path(target), owner, 0, set())
    receipt = {
        "status": "incomplete" if issues else "complete" if cache else "not_applicable",
        "complete": not issues,
        "scope": "component_import_graph",
        "component_count": sum(counts[suffix[1:]] for suffix in COMPONENT_SUFFIXES),
        "script_blocks": counts["script_blocks"],
        "import_edges": min(edge_count, MAX_IMPORT_EDGES),
        "languages": {suffix[1:]: counts[suffix[1:]] for suffix in sorted(COMPONENT_SUFFIXES) if counts[suffix[1:]]},
        "issues": issues,
    }
    return extras, receipt


MAX_FRAMEWORK_COMPONENTS = 4096
MAX_FRAMEWORK_COMPONENT_BYTES = 32_000_000

# Component files a framework loads by location, not by import: route pages,
# layouts and auto-registered components. Facts (enabler packages and
# patterns relative to the enabling package.json) cover Astro, SvelteKit,
# Nuxt, vite-plugin-pages, unplugin-vue-router, vite-plugin-vue-layouts,
# unplugin-vue-components and Quasar. A pattern segment starting with ``_``
# is private in Astro.
FRAMEWORK_COMPONENT_ROOTS = (
    (("astro",), ("src/pages/**/*.astro",)),
    (("@sveltejs/kit",), ("src/routes/**/+*.svelte",)),
    (
        ("nuxt", "nuxt-nightly"),
        (
            "app.vue",
            "error.vue",
            "pages/**/*.vue",
            "layouts/**/*.vue",
            "components/**/*.vue",
            "app/app.vue",
            "app/error.vue",
            "app/pages/**/*.vue",
            "app/layouts/**/*.vue",
            "app/components/**/*.vue",
        ),
    ),
    (("vite-plugin-pages", "unplugin-vue-router"), ("src/pages/**/*.vue",)),
    (
        ("vite-plugin-vue-layouts", "vite-plugin-vue-layouts-next", "vite-plugin-vue-meta-layouts"),
        ("src/layouts/**/*.vue",),
    ),
    (("unplugin-vue-components",), ("src/components/**/*.vue", "components/**/*.vue")),
    (("@quasar/app", "@quasar/app-vite", "@quasar/app-webpack"), ("src/App.vue",)),
)


def _pattern_regex(pattern):
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:[^/]+/)*")
            index += 3
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out))


_FRAMEWORK_COMPONENT_REGEXES = tuple(
    (enablers, tuple(_pattern_regex(pattern) for pattern in patterns))
    for enablers, patterns in FRAMEWORK_COMPONENT_ROOTS
)


def framework_component_root(path):
    """The framework loads this component by its location (a page, layout or auto-registered component)."""
    from skylos.visitors.languages.typescript.conventions import (
        _depends_on,
        _enclosing_package_roots,
        _package_data,
    )

    path = os.path.abspath(str(path))
    roots = _enclosing_package_roots(path)
    for index, package_root in enumerate(roots):
        relative = os.path.relpath(path, package_root).replace(os.sep, "/")
        manifests = [_package_data(root) for root in roots[index:]]
        for enablers, regexes in _FRAMEWORK_COMPONENT_REGEXES:
            if not any(regex.fullmatch(relative) for regex in regexes):
                continue
            if "astro" in enablers and any(part.startswith("_") for part in relative.split("/")[2:]):
                continue
            if any(_depends_on(data, name) for data in manifests for name in enablers):
                return True
    return False


def expand_framework_component_imports(project_root, source_files, raw_imports, *, resolver=None, exclude_folders=None):
    """Import records of components the framework loads by location.

    Route pages, layouts and auto-registered components
    (``src/pages/index.astro``, ``+page.svelte``, a Nuxt ``components/``
    file) are loaded by their framework, not by an import, so they are graph
    roots: a module they import is reachable. Records are keyed by the
    component itself, with nested component scripts expanded into it.
    A component only a JS/TS file imports keeps its edges on that loader (see
    :func:`expand_component_imports`), so an unused loader still cannot make
    its component tree live, and an orphan component outside these locations
    stays unused. Budgets abstain silently: a missing root only keeps today's
    findings.
    """
    from skylos.core.file_discovery import discover_source_files
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    root = Path(project_root).resolve()
    try:
        components = discover_source_files(root, COMPONENT_SUFFIXES, exclude_folders=exclude_folders)
    except (OSError, ValueError):
        return {}
    if not components or len(components) > MAX_FRAMEWORK_COMPONENTS:
        return {}
    parsed = {}
    total_bytes = 0
    for path in components:
        real = Path(os.path.realpath(str(path)))
        text = _safe_component(root, real, exclude_folders)
        if text is None:
            continue
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_FRAMEWORK_COMPONENT_BYTES:
            return {}
        parsed[real] = _imports(real, text)[0]

    def component_target(specifier, importer):
        if not _component_specifier(specifier):
            return None
        target = resolve_ts_module(specifier, str(importer), resolver)
        if target is None or _rune_module(target):
            return None
        return Path(os.path.realpath(target))

    extras = {}
    for owner in sorted(parsed):
        if not framework_component_root(owner):
            continue
        records, pending, seen = [], [(owner, 0)], set()
        while pending:
            component, depth = pending.pop()
            if component in seen or depth >= MAX_COMPONENT_DEPTH or component not in parsed:
                continue
            seen.add(component)
            for raw in parsed[component]:
                specifier = raw.get("source", "")
                target = component_target(specifier, component)
                if target is not None:
                    pending.append((target, depth + 1))
                    continue
                resolved = resolve_ts_module(specifier, str(component), resolver)
                if _component_specifier(specifier) and not _rune_module(resolved):
                    continue  # An unresolved component names no module.
                item = deepcopy(raw)
                if resolved is not None:
                    item["source"] = "./" + os.path.relpath(resolved, owner.parent).replace(os.sep, "/")
                elif specifier.startswith("."):
                    absolute = component.parent / specifier
                    item["source"] = "./" + os.path.relpath(absolute, owner.parent).replace(os.sep, "/")
                if item.pop("is_reexport", False):
                    if any(name == "*" or name.startswith("* as ") for name in item.get("names", ())):
                        item["consume_all_exports"] = True
                    item.pop("reexport_reference_names", None)
                item["component_file"] = str(component)
                item["component_line"] = item.get("line", 1)
                item["is_component_import"] = True
                records.append(item)
                if len(records) > MAX_IMPORT_EDGES:
                    return extras
        if records:
            extras[owner] = records
    return extras
