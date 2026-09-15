from __future__ import annotations

import fnmatch
import functools
import json
import os
import re
import shlex
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Concatenate, ParamSpec, TypeVar

import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from skylos.core.file_discovery import should_exclude_path
from skylos.core.js_ast import (
    ImportBinding,
    is_type_only,
    iter_import_clause_bindings,
    member_chain,
)

from .nextjs import (
    NEXTJS_CONVENTION_EXPORTS,
    NEXTJS_CONVENTION_FILES,
    is_nextjs_convention_export,
    is_nextjs_convention_file,
    is_nextjs_pages_api_file,
    is_nextjs_pages_router_file,
)
from .resolve import (
    _find_nearest_tsconfig,
    _parse_tsconfig_references,
    _resolve_path_target,
)
from .safe_glob import (
    MAX_TYPESCRIPT_GLOB_MATCHES,
    resolve_bounded_base,
    safe_glob_paths,
)

_NEXTJS_CONVENTION_EXPORTS = NEXTJS_CONVENTION_EXPORTS
_NEXTJS_CONVENTION_FILES = NEXTJS_CONVENTION_FILES
_is_nextjs_convention_file = is_nextjs_convention_file
_TS_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_TS_JS_ENTRY_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
    "/index.ts",
    "/index.tsx",
    "/index.js",
    "/index.jsx",
    "/index.mts",
    "/index.cts",
    "/index.mjs",
    "/index.cjs",
)
_ENTRY_FILE_SUFFIXES = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
)

_PLAYWRIGHT_CONFIG_FILES = frozenset(
    {
        "playwright.config.ts",
        "playwright.config.js",
        "playwright.config.mts",
        "playwright.config.mjs",
        "tsup.config.ts",
        "tsup.config.mts",
        "tsup.config.js",
        "tsup.config.mjs",
        "tsup.config.cjs",
    }
)

try:
    _ENTRY_TS_LANG: Language | None = Language(tsts.language_typescript())
except Exception:
    _ENTRY_TS_LANG = None

try:
    _ENTRY_TSX_LANG: Language | None = Language(tsts.language_tsx())
except Exception:
    _ENTRY_TSX_LANG = None

_ENTRY_PARSER_CACHE: dict[int, Parser] = {}
_CONFIG_OBJECT_CALLS = frozenset({"defineConfig", "defineProject", "defineWorkspace"})
_RUNNER_CONFIG_TOOLS = frozenset({"vite", "vitest", "playwright", "tsup"})
_SCRIPT_RUNTIME_TOOLS = frozenset(
    {"node", "bun", "deno", "tsx", "ts-node", "ts-node-esm"}
)
_SCRIPT_COMMAND_SEPARATORS = frozenset({"&", "&&", ";", "|", "||"})
_SCRIPT_ENV_WRAPPERS = frozenset({"cross-env", "cross-env-shell", "env"})
_ESBUILD_MODULES = frozenset({"esbuild"})
_ESBUILD_BUILD_METHODS = frozenset({"build", "buildSync", "context"})
_STATIC_HELPER_MODULES = {
    "node:path": "path",
    "path": "path",
    "node:url": "url",
    "url": "url",
}
_STATIC_HELPER_MODULE_NAMES = frozenset(_STATIC_HELPER_MODULES)
_STATIC_HELPER_NAMES = {
    "path": frozenset({"dirname", "join", "resolve"}),
    "url": frozenset({"fileURLToPath"}),
}
_ESBUILD_PROMISE_METHODS = frozenset({"catch", "finally", "then"})
_MAX_ESBUILD_ENTRY_GLOBS = MAX_TYPESCRIPT_GLOB_MATCHES
_MAX_ESBUILD_STATIC_STEPS = MAX_TYPESCRIPT_GLOB_MATCHES * 8
_MAX_ESBUILD_STATIC_DEPTH = 32
_MUTATING_CONTAINER_METHODS = frozenset(
    {
        "copyWithin",
        "fill",
        "pop",
        "push",
        "reverse",
        "shift",
        "sort",
        "splice",
        "unshift",
    }
)
_STRING_FRAGMENT_TYPES = frozenset({"string_fragment", "escape_sequence"})


@dataclass(frozen=True)
class _TsEntryDiscovery:
    file: str
    kind: str
    reason: str
    scope: str


@dataclass
class _EsbuildStaticContext:
    source: bytes
    config_path: str
    default_base_dir: str
    bindings: dict[str, Node]
    direct_calls: dict[str, str]
    namespaces: dict[str, str]
    esbuild_direct: frozenset[str]
    esbuild_namespaces: frozenset[str]
    steps: int = 0
    depth: int = 0

    def visit(self) -> bool:
        """Consume one bounded static-evaluation step."""
        self.steps += 1
        return self.steps <= _MAX_ESBUILD_STATIC_STEPS

    def restart(self) -> None:
        """Give the next top-level build call its own step budget."""
        self.steps = 0


_FoldItem = TypeVar("_FoldItem")
_FoldValue = TypeVar("_FoldValue")
_FoldParams = ParamSpec("_FoldParams")
_StaticFold = Callable[
    Concatenate[_EsbuildStaticContext, _FoldParams], _FoldValue | None
]


def _bounded_static_fold(
    func: _StaticFold[_FoldParams, _FoldValue],
) -> _StaticFold[_FoldParams, _FoldValue]:
    """Keep recursive folding inside the interpreter stack."""

    @functools.wraps(func)
    def wrapper(
        context: _EsbuildStaticContext,
        *args: _FoldParams.args,
        **kwargs: _FoldParams.kwargs,
    ) -> _FoldValue | None:
        if context.depth >= _MAX_ESBUILD_STATIC_DEPTH:
            return None
        context.depth += 1
        try:
            return func(context, *args, **kwargs)
        finally:
            context.depth -= 1

    return wrapper


def _fold_static_values(
    items: Iterable[_FoldItem],
    fold: Callable[[_FoldItem], _FoldValue | None],
) -> list[_FoldValue] | None:
    """Fold every item, abandoning the sequence as soon as one is not static."""
    values: list[_FoldValue] = []
    for item in items:
        value = fold(item)
        if value is None:
            return None
        values.append(value)
    return values


def _resolve_static_binding(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
    fold: Callable[[_EsbuildStaticContext, Node, frozenset[str]], _FoldValue | None],
) -> _FoldValue | None:
    """Fold a module-level `const` through its initializer, refusing cycles."""
    name = _node_text(context.source, node)
    if name in resolving or name not in context.bindings:
        return None
    return fold(context, context.bindings[name], resolving | {name})


def resolve_ts_module(source: str, importer: str, monorepo_resolver=None) -> str | None:
    if not source.startswith("."):
        if monorepo_resolver:
            return monorepo_resolver.resolve(source, importer)
        return None
    base = os.path.dirname(importer)
    target = os.path.normpath(os.path.join(base, source))

    candidates: list[str] = []
    if target.endswith(".js"):
        candidates.extend(
            [
                target[:-3] + ".ts",
                target[:-3] + ".tsx",
                target[:-3] + ".mts",
                target[:-3] + ".cts",
                target,
                target[:-3] + ".jsx",
            ]
        )
    elif target.endswith(".jsx"):
        candidates.extend([target[:-4] + ".tsx", target[:-4] + ".js", target])
    elif target.endswith((".mjs", ".cjs")):
        base_no_ext = target.rsplit(".", 1)[0]
        candidates.extend(
            [
                base_no_ext + ".mts",
                base_no_ext + ".cts",
                base_no_ext + ".ts",
                base_no_ext + ".tsx",
                base_no_ext + ".js",
                base_no_ext + ".jsx",
                target,
            ]
        )
    else:
        candidates.append(target)

    for suffix in _TS_JS_ENTRY_SUFFIXES:
        candidate = target + suffix
        candidates.append(candidate)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            return candidate
    return None


def build_ts_import_graph(ts_raw_imports: dict, defs: dict, monorepo_resolver=None):
    consumed_exports = defaultdict(set)
    wildcard_edges = defaultdict(set)
    importers_of = defaultdict(set)
    consume_all_exports: set[str] = set()

    for importer_file, raw_imports in ts_raw_imports.items():
        for imp in raw_imports:
            resolved = resolve_ts_module(
                imp["source"], str(importer_file), monorepo_resolver
            )
            if resolved:
                importers_of[resolved].add(str(importer_file))
                if imp.get("consume_all_exports"):
                    consume_all_exports.add(resolved)
                for name in imp["names"]:
                    if name == "*":
                        wildcard_edges[str(importer_file)].add(resolved)
                    else:
                        actual_name = (
                            name.split(" as ")[0].strip() if " as " in name else name
                        )
                        consumed_exports[resolved].add(actual_name)
                    target_key = f"{resolved}:{name}"
                    if target_key in defs:
                        defs[target_key].references += 1

    for resolved in consume_all_exports:
        for defn in defs.values():
            if str(defn.filename) != resolved or defn.type == "import":
                continue
            consumed_exports[resolved].add(defn.simple_name)
            defn.references = max(defn.references, 1)

    _resolve_wildcard_consumed(consumed_exports, wildcard_edges, defs)
    _resolve_reexport_aliases(consumed_exports, ts_raw_imports, defs, monorepo_resolver)
    _resolve_namespace_reexports(
        consumed_exports, wildcard_edges, defs, ts_raw_imports, monorepo_resolver
    )

    return consumed_exports, wildcard_edges, importers_of


def _resolve_wildcard_consumed(consumed_exports, wildcard_edges, defs):
    if not wildcard_edges:
        return

    local_defs_by_file = defaultdict(set)
    for defn in defs.values():
        if defn.type != "import":
            local_defs_by_file[str(defn.filename)].add(defn.simple_name)

    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for reexporter, sources in wildcard_edges.items():
            consumed_from_reexporter = consumed_exports.get(reexporter, set())
            if not consumed_from_reexporter:
                continue
            local_names = local_defs_by_file.get(reexporter, set())
            pass_through = consumed_from_reexporter - local_names
            if not pass_through:
                continue
            for source_file in sources:
                source_defs = local_defs_by_file.get(source_file, set())
                for name in pass_through:
                    if name in source_defs:
                        before = len(consumed_exports[source_file])
                        consumed_exports[source_file].add(name)
                        if len(consumed_exports[source_file]) > before:
                            changed = True
                            target_key = f"{source_file}:{name}"
                            if target_key in defs:
                                defs[target_key].references += 1


def _resolve_reexport_aliases(
    consumed_exports, ts_raw_imports, defs, monorepo_resolver=None
):
    reexport_aliases: dict[str, dict[str, str]] = {}

    for importer_file, raw_imports in ts_raw_imports.items():
        for imp in raw_imports:
            resolved = resolve_ts_module(
                imp["source"], str(importer_file), monorepo_resolver
            )
            if not resolved:
                continue
            for name in imp["names"]:
                if " as " in name:
                    original, alias = name.split(" as ", 1)
                    original = original.strip()
                    alias = alias.strip()
                    reexport_aliases.setdefault(str(importer_file), {})[alias] = (
                        original,
                        resolved,
                    )

    if not reexport_aliases:
        return

    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for reexporter, alias_map in reexport_aliases.items():
            consumed_from_reexporter = consumed_exports.get(reexporter, set())
            for alias, (original, source_file) in alias_map.items():
                if alias in consumed_from_reexporter:
                    before = len(consumed_exports[source_file])
                    consumed_exports[source_file].add(original)
                    if len(consumed_exports[source_file]) > before:
                        changed = True
                        target_key = f"{source_file}:{original}"
                        if target_key in defs:
                            defs[target_key].references += 1


def _resolve_namespace_reexports(
    consumed_exports, wildcard_edges, defs, ts_raw_imports, monorepo_resolver=None
):
    local_defs_by_file = defaultdict(set)
    for defn in defs.values():
        if defn.type != "import":
            local_defs_by_file[str(defn.filename)].add(defn.simple_name)

    for reexporter, sources in wildcard_edges.items():
        consumed_from_reexporter = consumed_exports.get(reexporter, set())
        if not consumed_from_reexporter:
            continue

        for source_file in sources:
            for importer_file, raw_imports in ts_raw_imports.items():
                if str(importer_file) != reexporter:
                    continue
                for imp in raw_imports:
                    resolved = resolve_ts_module(
                        imp["source"], str(importer_file), monorepo_resolver
                    )
                    if resolved != source_file:
                        continue
                    if "*" in imp["names"]:
                        ns_names = set()
                        for dk, dv in defs.items():
                            if str(dv.filename) == reexporter and dv.type == "import":
                                ns_names.add(dv.simple_name)
                        for ns_name in ns_names:
                            if ns_name in consumed_from_reexporter:
                                source_defs = local_defs_by_file.get(source_file, set())
                                for name in source_defs:
                                    consumed_exports[source_file].add(name)
                                    target_key = f"{source_file}:{name}"
                                    if target_key in defs:
                                        defs[target_key].references += 1


_VSCODE_EXTENSION_LIFECYCLE_EXPORTS = frozenset({"activate", "deactivate"})


# The automatic/precompile JSX transforms emit calls to these in *user* code,
# so a jsx-runtime module's exports are protocol surface, never dead.
_JSX_RUNTIME_PROTOCOL_EXPORTS = frozenset(
    {"jsx", "jsxs", "jsxDEV", "jsxTemplate", "jsxAttr", "jsxEscape", "Fragment", "JSX"}
)


def demote_unconsumed_ts_exports(defs, consumed_exports, lifecycle_entry_points=None):
    lifecycle_entry_points = {
        os.path.realpath(str(path)) for path in lifecycle_entry_points or ()
    }
    demoted = []
    for _name, defn in defs.items():
        if not defn.is_exported:
            continue
        if not str(defn.filename).endswith(_TS_JS_EXTENSIONS):
            continue
        if defn.type == "import":
            continue
        if str(defn.filename).endswith(".d.ts"):
            continue
        signals = getattr(defn, "framework_signals", ())
        if "ambient declaration" in signals:
            continue
        if "deprecated export" in signals:
            continue
        if "type-only declaration" in signals:
            continue
        if defn.simple_name in _JSX_RUNTIME_PROTOCOL_EXPORTS and os.path.basename(
            str(defn.filename)
        ).startswith(("jsx-runtime.", "jsx-dev-runtime.")):
            continue
        if (
            os.path.realpath(str(defn.filename)) in lifecycle_entry_points
            and defn.simple_name in _VSCODE_EXTENSION_LIFECYCLE_EXPORTS
        ):
            continue

        consumed = consumed_exports.get(str(defn.filename), set())
        if defn.simple_name not in consumed:
            defn.is_exported = False
            demoted.append(defn)
    return demoted


_TEST_SUFFIXES = (
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.jsx",
    ".test.mts",
    ".test.cts",
    ".test.mjs",
    ".test.cjs",
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.mts",
    ".spec.cts",
    ".spec.mjs",
    ".spec.cjs",
)

_CONFIG_FILES = frozenset(
    {
        "vitest.config.ts",
        "vitest.config.mts",
        "vitest.config.js",
        "vitest.config.mjs",
        "jest.config.ts",
        "jest.config.js",
        "jest.config.cjs",
        "tsconfig.ts",
        "source.config.ts",
        "source.config.tsx",
        "source.config.js",
        "source.config.jsx",
        "tailwind.config.ts",
        "tailwind.config.js",
        "tailwind.config.cjs",
        "next.config.ts",
        "next.config.mts",
        "next.config.js",
        "next.config.mjs",
        "postcss.config.ts",
        "postcss.config.js",
        "postcss.config.cjs",
        "eslint.config.ts",
        "eslint.config.mts",
        "eslint.config.js",
        "eslint.config.mjs",
        "vite.config.ts",
        "vite.config.mts",
        "vite.config.js",
        "vite.config.mjs",
        "playwright.config.ts",
        "playwright.config.js",
        "playwright.config.mts",
        "playwright.config.mjs",
    }
)

_VITEPRESS_CONFIG_SUFFIXES = tuple(
    f"/.vitepress/{name}.{extension}"
    for name in ("config", "config/index")
    for extension in ("js", "ts", "mjs", "mts")
)

_TS_ENTRY_FILES = frozenset(
    {
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "index.mts",
        "index.cts",
        "index.mjs",
        "index.cjs",
        "main.ts",
        "main.tsx",
        "main.js",
        "main.jsx",
        "main.mts",
        "main.cts",
        "main.mjs",
        "main.cjs",
        "cli.ts",
        "cli.tsx",
        "cli.js",
        "cli.jsx",
        "cli.mts",
        "cli.cts",
        "cli.mjs",
        "cli.cjs",
    }
)


def _is_ts_entry_or_infra(sf: str) -> bool:
    sf = sf.replace(os.sep, "/")
    if f"/{sf}".endswith(_VITEPRESS_CONFIG_SUFFIXES):
        return True
    if sf.endswith(_TEST_SUFFIXES) or "/__tests__/" in sf:
        return True
    if "/test/" in sf or "/tests/" in sf or "/testdata/" in sf:
        return True
    if "/integration/" in sf:
        return True
    if "/_static/" in sf or "/static/" in sf or "/public/" in sf:
        return True
    if "/bench/" in sf or "/benchmark/" in sf or "/benchmarks/" in sf:
        return True
    if "/perf/" in sf or "/perf-measures/" in sf or "/performance/" in sf:
        return True
    if "/example/" in sf or "/examples/" in sf:
        return True
    if sf.endswith(".d.ts"):
        return True
    if "/scripts/" in sf:
        return True
    basename = os.path.basename(sf)
    if is_nextjs_pages_router_file(sf) or is_nextjs_pages_api_file(sf):
        return True
    if basename in _NEXTJS_CONVENTION_FILES:
        return True
    if basename in _CONFIG_FILES:
        return True
    return False


def _is_ts_dev_or_test_root(sf: str) -> bool:
    sf = sf.replace(os.sep, "/")
    if f"/{sf}".endswith(_VITEPRESS_CONFIG_SUFFIXES):
        return True
    if sf.endswith(_TEST_SUFFIXES) or "/__tests__/" in sf:
        return True
    if "/test/" in sf or "/tests/" in sf or "/testdata/" in sf:
        return True
    if "/integration/" in sf:
        return True
    if "/_static/" in sf or "/static/" in sf or "/public/" in sf:
        return True
    if "/bench/" in sf or "/benchmark/" in sf or "/benchmarks/" in sf:
        return True
    if "/perf/" in sf or "/perf-measures/" in sf or "/performance/" in sf:
        return True
    if "/example/" in sf or "/examples/" in sf:
        return True
    if sf.endswith(".d.ts"):
        return True
    if "/scripts/" in sf:
        return True
    basename = os.path.basename(sf)
    if basename in _CONFIG_FILES or basename in _PLAYWRIGHT_CONFIG_FILES:
        return True
    return False


def _classify_entry_scope(file_path: str, kind: str, reason: str) -> str:
    if reason in {"package-entry", "package-script", "default-root"}:
        if kind == "heuristic" and _is_ts_dev_or_test_root(file_path):
            return "dev"
        return "prod"
    if reason.endswith("-config"):
        return "dev"
    if reason.startswith("vitest-") or reason.startswith("playwright-"):
        return "dev"
    return "prod"


def _resolve_exclude_root(files, project_root: str | None) -> Path | None:
    if project_root:
        return Path(project_root).resolve()

    resolved_files: list[Path] = []
    for file_path in files:
        p = Path(str(file_path))
        try:
            resolved_files.append(p.resolve())
        except OSError:
            continue

    if not resolved_files:
        return None

    try:
        common_root = Path(os.path.commonpath([str(path) for path in resolved_files]))
    except ValueError:
        return None

    if common_root.is_file():
        return common_root.parent.resolve()
    return common_root.resolve()


def _is_excluded_path(path_str: str, exclude_folders, root_path: Path | None) -> bool:
    if not exclude_folders or root_path is None:
        return False

    path = Path(path_str)
    if not path.is_absolute():
        path = root_path / path

    return should_exclude_path(path.resolve(), root_path, exclude_folders)


def _read_json_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _entry_parser_for_path(path: str) -> Parser | None:
    suffix = Path(path).suffix.lower()
    lang = _ENTRY_TSX_LANG if suffix in {".js", ".jsx", ".tsx"} else _ENTRY_TS_LANG
    if lang is None:
        return None

    lang_id = id(lang)
    if lang_id not in _ENTRY_PARSER_CACHE:
        _ENTRY_PARSER_CACHE[lang_id] = Parser(lang)
    return _ENTRY_PARSER_CACHE[lang_id]


def _load_entry_config_ast(path: str) -> tuple[bytes, Node] | tuple[None, None]:
    parser = _entry_parser_for_path(path)
    if parser is None:
        return None, None

    try:
        source = Path(path).read_bytes()
    except OSError:
        return None, None

    tree = parser.parse(source)
    return source, tree.root_node


def _iter_ts_nodes(root_node):
    stack = [root_node]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _string_node_value(source: bytes, node) -> str | None:
    if node is None or node.type != "string":
        return None
    parts = [
        _node_text(source, child)
        for child in node.children
        if child.type in _STRING_FRAGMENT_TYPES
    ]
    if parts:
        return "".join(parts)
    text = _node_text(source, node)
    return text.strip("'\"")


def _pair_key_text(source: bytes, pair_node) -> str | None:
    if pair_node.type != "pair" or len(pair_node.named_children) < 2:
        return None
    key_node = pair_node.named_children[0]
    if key_node.type in {"property_identifier", "identifier"}:
        return _node_text(source, key_node)
    if key_node.type == "string":
        return _string_node_value(source, key_node)
    return None


def _pair_value_node(pair_node):
    if pair_node.type != "pair" or len(pair_node.named_children) < 2:
        return None
    return pair_node.named_children[1]


def _iter_object_pairs(object_node):
    if object_node is None or object_node.type != "object":
        return
    for child in object_node.children:
        if child.type == "pair":
            yield child


def _find_config_root_objects(source: bytes, root_node) -> list:
    objects: list = []
    for node in _iter_ts_nodes(root_node):
        if node.type != "call_expression":
            continue
        function_node = node.child_by_field_name("function")
        if function_node is None:
            continue
        function_name = _node_text(source, function_node)
        if function_name not in _CONFIG_OBJECT_CALLS:
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            continue
        for child in arguments.named_children:
            if child.type == "object":
                objects.append(child)
    if objects:
        return objects

    top_level_objects: list = []
    for node in _iter_ts_nodes(root_node):
        if node.type != "object":
            continue
        parent = node.parent
        if parent is None or parent.type in {
            "program",
            "export_statement",
            "assignment_expression",
            "variable_declarator",
            "parenthesized_expression",
        }:
            top_level_objects.append(node)
    return top_level_objects


def _find_object_path_values(
    source: bytes, objects: list, path: tuple[str, ...]
) -> list:
    current = list(objects)
    for index, segment in enumerate(path):
        next_nodes = []
        for object_node in current:
            if object_node.type != "object":
                continue
            for pair_node in _iter_object_pairs(object_node):
                if _pair_key_text(source, pair_node) != segment:
                    continue
                value_node = _pair_value_node(pair_node)
                if value_node is not None:
                    next_nodes.append(value_node)
        if not next_nodes:
            return []
        if index == len(path) - 1:
            return next_nodes
        current = [node for node in next_nodes if node.type == "object"]
    return []


def _collect_string_literals(source: bytes, node) -> list[str]:
    values: list[str] = []
    if node is None:
        return values
    if node.type == "string":
        value = _string_node_value(source, node)
        if value:
            values.append(value)
        return values
    for child in node.named_children:
        values.extend(_collect_string_literals(source, child))
    return values


def _resolve_relative_entry_file(
    base_dir: str, candidate: str, ts_files: set[str]
) -> str | None:
    resolved = _resolve_path_target(base_dir, candidate)
    if not resolved:
        return None
    real_path = os.path.realpath(resolved)
    if real_path in ts_files:
        return real_path
    return None


def _expand_relative_entry_glob(
    base_dir: str, pattern: str, ts_files: set[str]
) -> set[str]:
    matches: set[str] = set()
    for real_path in safe_glob_paths(
        base_dir,
        pattern,
        allowed_suffixes=set(_ENTRY_FILE_SUFFIXES),
    ):
        if real_path in ts_files:
            matches.add(real_path)
    return matches


def _esbuild_file_inventory(
    base_dir: str, ts_files: set[str]
) -> tuple[tuple[str, str], ...]:
    """Resolve and contain candidate files once for all globs in a config."""
    root = os.path.realpath(base_dir)
    inventory: list[tuple[str, str]] = []
    for path in ts_files:
        real_path = os.path.realpath(path)
        try:
            if os.path.commonpath([real_path, root]) != root:
                continue
        except ValueError:
            continue
        relative_path = os.path.relpath(real_path, root).replace(os.sep, "/")
        inventory.append((real_path, relative_path))
    return tuple(inventory)


def _expand_esbuild_entry_glob(
    base_dir: str,
    pattern: str,
    inventory: tuple[tuple[str, str], ...],
) -> set[str]:
    root = os.path.realpath(base_dir)
    absolute_pattern = (
        os.path.normpath(pattern)
        if os.path.isabs(pattern)
        else os.path.normpath(os.path.join(root, pattern))
    )
    try:
        if os.path.commonpath([absolute_pattern, root]) != root:
            return set()
    except ValueError:
        return set()

    relative_pattern = os.path.relpath(absolute_pattern, root).replace(os.sep, "/")

    matches: set[str] = set()
    for real_path, relative_path in inventory:
        if _esbuild_glob_matches(relative_pattern, relative_path):
            matches.add(real_path)
    return matches


def _esbuild_segment_matches(pattern: str, value: str) -> bool:
    """Match esbuild's `*` wildcard within one path segment in linear time."""

    if "*" not in pattern:
        return pattern == value

    chunks = pattern.split("*")
    first = chunks[0]
    last = chunks[-1]
    if first and not value.startswith(first):
        return False
    if last and not value.endswith(last):
        return False

    cursor = len(first)
    suffix_start = len(value) - len(last) if last else len(value)
    if cursor > suffix_start:
        return False
    for chunk in chunks[1:-1]:
        if not chunk:
            continue
        match_at = value.find(chunk, cursor, suffix_start)
        if match_at < 0:
            return False
        cursor = match_at + len(chunk)
    return cursor <= suffix_start


def _esbuild_glob_matches(pattern: str, value: str) -> bool:
    """Match `*` and directory `**/` without regex backtracking."""

    pattern_segments = pattern.split("/")
    value_segments = value.split("/")
    pattern_index = value_index = 0
    globstar_index = -1
    globstar_value_index = -1

    while value_index < len(value_segments):
        is_globstar = (
            pattern_index < len(pattern_segments) - 1
            and pattern_segments[pattern_index] == "**"
        )
        if is_globstar:
            globstar_index = pattern_index
            globstar_value_index = value_index
            pattern_index += 1
            continue
        if pattern_index < len(pattern_segments) and _esbuild_segment_matches(
            pattern_segments[pattern_index], value_segments[value_index]
        ):
            pattern_index += 1
            value_index += 1
            continue
        if globstar_index < 0:
            return False
        globstar_value_index += 1
        value_index = globstar_value_index
        pattern_index = globstar_index + 1

    while (
        pattern_index < len(pattern_segments) - 1
        and pattern_segments[pattern_index] == "**"
    ):
        pattern_index += 1
    return pattern_index == len(pattern_segments)


def _resolve_config_root_base(
    source: bytes, objects: list, default_base_dir: str
) -> str:
    root_values = _find_object_path_values(source, objects, ("root",))
    for node in root_values:
        for value in _collect_string_literals(source, node):
            bounded = resolve_bounded_base(default_base_dir, value)
            if bounded:
                return bounded
            return os.path.realpath(default_base_dir)
    return os.path.realpath(default_base_dir)


def _literal_entries_from_nodes(
    source: bytes,
    nodes: list,
    base_dir: str,
    ts_files: set[str],
    allow_glob: bool = False,
) -> set[str]:
    matches: set[str] = set()
    for node in nodes:
        for literal in _collect_string_literals(source, node):
            if not literal:
                continue
            if allow_glob and any(char in literal for char in "*?[]"):
                matches.update(_expand_relative_entry_glob(base_dir, literal, ts_files))
                continue
            resolved = _resolve_relative_entry_file(base_dir, literal, ts_files)
            if resolved:
                matches.add(resolved)
    return matches


def _discover_vite_config_entries(
    config_path: str, ts_files: set[str], default_base_dir: str
) -> set[str]:
    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None:
        return set()

    objects = _find_config_root_objects(source, root_node)
    if not objects:
        return set()

    base_dir = _resolve_config_root_base(source, objects, default_base_dir)

    matches: set[str] = set()
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("build", "lib", "entry")),
            base_dir,
            ts_files,
        )
    )
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(
                source, objects, ("build", "rollupOptions", "input")
            ),
            base_dir,
            ts_files,
        )
    )
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("optimizeDeps", "entries")),
            base_dir,
            ts_files,
            allow_glob=True,
        )
    )
    return matches


def _discover_vitest_config_entries(
    config_path: str, ts_files: set[str], default_base_dir: str
) -> set[str]:
    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None:
        return set()

    objects = _find_config_root_objects(source, root_node)
    if not objects:
        return set()

    base_dir = _resolve_config_root_base(source, objects, default_base_dir)

    matches: set[str] = set()
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("test", "include")),
            base_dir,
            ts_files,
            allow_glob=True,
        )
    )
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("test", "setupFiles")),
            base_dir,
            ts_files,
        )
    )
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("test", "globalSetup")),
            base_dir,
            ts_files,
        )
    )
    return matches


def _discover_tsup_config_entries(
    config_path: str, ts_files: set[str], default_base_dir: str
) -> set[str]:
    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None:
        return set()

    objects = _find_config_root_objects(source, root_node)
    if not objects:
        return set()

    base_dir = _resolve_config_root_base(source, objects, default_base_dir)
    return _literal_entries_from_nodes(
        source,
        _find_object_path_values(source, objects, ("entry",)),
        base_dir,
        ts_files,
    )


@dataclass(frozen=True)
class _ValueImportBindings:
    """Local names a single value (non-type) import statement introduces."""

    module: str | None
    named: dict[str, str]
    namespaces: frozenset[str]
    default: str | None


_NO_IMPORT_BINDINGS = _ValueImportBindings(None, {}, frozenset(), None)


def _value_import_bindings(
    source: bytes, statement: Node, modules: frozenset[str]
) -> _ValueImportBindings:
    """Read local bindings from a value import of one of `modules`."""
    if statement.type != "import_statement" or is_type_only(statement):
        return _NO_IMPORT_BINDINGS
    module = _string_node_value(source, statement.child_by_field_name("source"))
    if module not in modules:
        return _NO_IMPORT_BINDINGS
    named: dict[str, str] = {}
    namespaces: set[str] = set()
    default: str | None = None
    for binding in _value_clause_bindings(source, statement):
        if binding.kind == "namespace":
            namespaces.add(binding.local)
        elif binding.kind == "default":
            default = binding.local
        else:
            named[binding.local] = binding.imported
    return _ValueImportBindings(module, named, frozenset(namespaces), default)


def _value_clause_bindings(source: bytes, statement: Node) -> Iterator[ImportBinding]:
    """Yield a statement's bindings, dropping the type-only specifiers."""
    for clause in statement.named_children:
        if clause.type != "import_clause":
            continue
        for binding in iter_import_clause_bindings(source, clause):
            if not binding.type_only:
                yield binding


def _esbuild_const_bindings(source: bytes, statement: Node) -> dict[str, Node]:
    if statement.type != "lexical_declaration" or not any(
        child.type == "const" for child in statement.children
    ):
        return {}
    bindings: dict[str, Node] = {}
    for declarator in statement.named_children:
        if declarator.type != "variable_declarator":
            continue
        name = declarator.child_by_field_name("name")
        value = declarator.child_by_field_name("value")
        if name is not None and name.type == "identifier" and value is not None:
            bindings[_node_text(source, name)] = value
    return bindings


def _esbuild_static_import(
    source: bytes, statement: Node
) -> tuple[dict[str, str], dict[str, str]]:
    """Bind the `node:path` and `node:url` helpers this fold can prove."""
    bindings = _value_import_bindings(source, statement, _STATIC_HELPER_MODULE_NAMES)
    kind = _STATIC_HELPER_MODULES.get(bindings.module or "")
    if kind is None:
        return {}, {}
    helpers = _STATIC_HELPER_NAMES[kind]
    direct_calls = {
        local: f"{kind}.{imported}"
        for local, imported in bindings.named.items()
        if imported in helpers
    }
    namespaces = dict.fromkeys(bindings.namespaces, kind)
    if bindings.default is not None:
        namespaces[bindings.default] = kind
    return direct_calls, namespaces


def _mutating_call_target(source: bytes, call_node: Node) -> Node | None:
    function = call_node.child_by_field_name("function")
    if function is None or function.type != "member_expression":
        return None
    method = function.child_by_field_name("property")
    if method is None or _node_text(source, method) not in _MUTATING_CONTAINER_METHODS:
        return None
    return function


def _esbuild_mutated_bindings(source: bytes, root_node: Node) -> set[str]:
    """Names whose bound container is written to after it is initialized."""
    mutated: set[str] = set()
    for node in _iter_ts_nodes(root_node):
        if node.type == "assignment_expression":
            target = node.child_by_field_name("left")
        elif node.type == "call_expression":
            target = _mutating_call_target(source, node)
        else:
            continue
        if target is None or target.type not in {
            "member_expression",
            "subscript_expression",
        }:
            continue
        root = target.child_by_field_name("object")
        if root is not None and root.type == "identifier":
            mutated.add(_node_text(source, root))
    return mutated


def _esbuild_static_context(
    source: bytes,
    root_node: Node,
    config_path: str,
    default_base_dir: str,
) -> _EsbuildStaticContext | None:
    """Read every module-level binding in one pass; None if esbuild is unused."""
    bindings: dict[str, Node] = {}
    direct_calls: dict[str, str] = {}
    namespaces: dict[str, str] = {}
    esbuild_direct: set[str] = set()
    esbuild_namespaces: set[str] = set()
    for statement in root_node.named_children:
        esbuild = _value_import_bindings(source, statement, _ESBUILD_MODULES)
        esbuild_direct.update(
            local
            for local, imported in esbuild.named.items()
            if imported in _ESBUILD_BUILD_METHODS
        )
        esbuild_namespaces.update(esbuild.namespaces)
        direct, imported_namespaces = _esbuild_static_import(source, statement)
        direct_calls.update(direct)
        namespaces.update(imported_namespaces)
        declaration = statement
        if statement.type == "export_statement":
            declaration = statement.child_by_field_name("declaration") or statement
        bindings.update(_esbuild_const_bindings(source, declaration))
    if not esbuild_direct and not esbuild_namespaces:
        return None
    for name in _esbuild_mutated_bindings(source, root_node):
        bindings.pop(name, None)
    return _EsbuildStaticContext(
        source=source,
        config_path=os.path.realpath(config_path),
        default_base_dir=os.path.realpath(default_base_dir),
        bindings=bindings,
        direct_calls=direct_calls,
        namespaces=namespaces,
        esbuild_direct=frozenset(esbuild_direct),
        esbuild_namespaces=frozenset(esbuild_namespaces),
    )


def _unwrap_esbuild_static_expression(node):
    while node is not None and node.type in {
        "as_expression",
        "parenthesized_expression",
        "satisfies_expression",
    }:
        node = node.child_by_field_name("expression") or (
            node.named_children[0] if node.named_children else None
        )
    return node


def _is_top_level_esbuild_call(source: bytes, call_node) -> bool:
    """Accept only calls that a package script evaluates directly at module load."""
    current = call_node
    while current.parent is not None:
        parent = current.parent
        if parent.type in {"await_expression", "parenthesized_expression"}:
            current = parent
            continue
        if (
            parent.type == "unary_expression"
            and parent.child_by_field_name("argument") == current
            and _node_text(source, parent.child_by_field_name("operator")) == "void"
        ):
            current = parent
            continue
        if (
            parent.type == "member_expression"
            and parent.child_by_field_name("object") == current
        ):
            property_node = parent.child_by_field_name("property")
            chained_call = parent.parent
            if (
                property_node is None
                or property_node.type != "property_identifier"
                or _node_text(source, property_node) not in _ESBUILD_PROMISE_METHODS
                or chained_call is None
                or chained_call.type != "call_expression"
                or chained_call.child_by_field_name("function") != parent
            ):
                return False
            current = chained_call
            continue
        break
    statement = current.parent
    if (
        statement is not None
        and statement.type == "variable_declarator"
        and statement.child_by_field_name("value") == current
    ):
        declaration = statement.parent
        if declaration is None or declaration.type not in {
            "lexical_declaration",
            "variable_declaration",
        }:
            return False
        container = declaration.parent
        if container is not None and container.type == "export_statement":
            container = container.parent
        return container is not None and container.type == "program"
    return (
        statement is not None
        and statement.type == "expression_statement"
        and statement.parent is not None
        and statement.parent.type == "program"
    )


def _is_esbuild_call(
    source: bytes,
    call_node,
    direct_bindings: frozenset[str],
    namespace_bindings: frozenset[str],
) -> bool:
    if not _is_top_level_esbuild_call(source, call_node):
        return False
    function = call_node.child_by_field_name("function")
    if function is None:
        return False
    if function.type == "identifier":
        return _node_text(source, function) in direct_bindings
    if function.type != "member_expression":
        return False
    object_node = function.child_by_field_name("object")
    property_node = function.child_by_field_name("property")
    return (
        object_node is not None
        and object_node.type == "identifier"
        and _node_text(source, object_node) in namespace_bindings
        and property_node is not None
        and _node_text(source, property_node) in _ESBUILD_BUILD_METHODS
    )


def _static_esbuild_call_name(
    context: _EsbuildStaticContext, call_node: Node
) -> str | None:
    function = call_node.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "identifier":
        return context.direct_calls.get(_node_text(context.source, function))
    chain = member_chain(context.source, function)
    if len(chain) != 2:
        return None
    namespace = context.namespaces.get(chain[0])
    if chain[1] in _STATIC_HELPER_NAMES.get(namespace or "", frozenset()):
        return f"{namespace}.{chain[1]}"
    return None


def _is_import_meta_url(source: bytes, node: Node) -> bool:
    unwrapped = _unwrap_esbuild_static_expression(node)
    return (
        unwrapped is not None
        and unwrapped.type == "member_expression"
        and _node_text(source, unwrapped) == "import.meta.url"
    )


def _static_esbuild_identifier_string(
    context: _EsbuildStaticContext,
    node: Node,
    local_strings: dict[str, str] | None,
    resolving: frozenset[str],
) -> str | None:
    name = _node_text(context.source, node)
    if local_strings is not None and name in local_strings:
        return local_strings[name]
    return _resolve_static_binding(
        context,
        node,
        resolving,
        lambda bound, value, seen: _static_esbuild_string(bound, value, None, seen),
    )


def _static_esbuild_template_string(
    context: _EsbuildStaticContext,
    node: Node,
    local_strings: dict[str, str] | None,
    resolving: frozenset[str],
) -> str | None:
    parts: list[str] = []
    for child in node.children:
        if child.type in {"`", "comment"}:
            continue
        if child.type in _STRING_FRAGMENT_TYPES:
            parts.append(_node_text(context.source, child))
            continue
        if child.type != "template_substitution" or len(child.named_children) != 1:
            return None
        value = _static_esbuild_string(
            context,
            child.named_children[0],
            local_strings,
            resolving,
        )
        if value is None:
            return None
        parts.append(value)
    return "".join(parts)


def _static_esbuild_path_call(
    context: _EsbuildStaticContext, call_name: str, values: list[str]
) -> str | None:
    if call_name == "path.dirname" and len(values) == 1:
        return os.path.dirname(values[0])
    if call_name == "path.join" and values:
        # `join` drops empty segments, concatenates, and only then normalizes:
        # the first non-empty segment sets the root and a later absolute one
        # merely extends it. `resolve` is the call that restarts from a root.
        segments = [segment for segment in values if segment]
        if not segments:
            return "."
        head, *rest = segments
        joined = os.path.join(head, *(segment.lstrip("/") for segment in rest))
        if os.sep == "/":
            # posixpath.normpath keeps a doubled leading slash and Node's
            # posix join never emits one. On Windows both keep it, because
            # there it roots a UNC share rather than an ordinary path.
            joined = re.sub("^//+", "/", joined)
        return os.path.normpath(joined)
    if call_name == "path.resolve" and values:
        return os.path.abspath(os.path.join(context.default_base_dir, *values))
    return None


def _static_esbuild_call_string(
    context: _EsbuildStaticContext,
    node: Node,
    local_strings: dict[str, str] | None,
    resolving: frozenset[str],
) -> str | None:
    call_name = _static_esbuild_call_name(context, node)
    arguments = node.child_by_field_name("arguments")
    if call_name is None or arguments is None:
        return None
    argument_nodes = arguments.named_children
    if call_name == "url.fileURLToPath":
        if len(argument_nodes) == 1 and _is_import_meta_url(
            context.source, argument_nodes[0]
        ):
            return context.config_path
        return None
    values = _fold_static_values(
        argument_nodes,
        lambda argument: _static_esbuild_string(
            context, argument, local_strings, resolving
        ),
    )
    if values is None:
        return None
    return _static_esbuild_path_call(context, call_name, values)


@_bounded_static_fold
def _static_esbuild_string(
    context: _EsbuildStaticContext,
    node: Node | None,
    local_strings: dict[str, str] | None = None,
    resolving: frozenset[str] = frozenset(),
) -> str | None:
    node = _unwrap_esbuild_static_expression(node)
    if node is None:
        return None
    if node.type == "string":
        return _string_node_value(context.source, node)
    if not context.visit():
        return None
    if node.type == "identifier":
        return _static_esbuild_identifier_string(
            context, node, local_strings, resolving
        )
    if node.type == "template_string":
        return _static_esbuild_template_string(context, node, local_strings, resolving)
    if node.type == "call_expression":
        return _static_esbuild_call_string(context, node, local_strings, resolving)
    return None


def _static_esbuild_object_child(
    context: _EsbuildStaticContext,
    child: Node,
    resolving: frozenset[str],
) -> dict[str, Node] | None:
    if child.type == "comment":
        return {}
    if child.type == "spread_element" and len(child.named_children) == 1:
        return _static_esbuild_object(context, child.named_children[0], resolving)
    if child.type != "pair":
        return None
    key = _pair_key_text(context.source, child)
    value = _pair_value_node(child)
    if key is None or value is None:
        return None
    return {key: value}


def _static_esbuild_object_properties(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
) -> dict[str, Node] | None:
    children = _fold_static_values(
        node.named_children,
        lambda child: _static_esbuild_object_child(context, child, resolving),
    )
    if children is None:
        return None
    properties: dict[str, Node] = {}
    for child_properties in children:
        properties.update(child_properties)
    return properties


@_bounded_static_fold
def _static_esbuild_object(
    context: _EsbuildStaticContext,
    node: Node | None,
    resolving: frozenset[str] = frozenset(),
) -> dict[str, Node] | None:
    node = _unwrap_esbuild_static_expression(node)
    if node is None or not context.visit():
        return None
    if node.type == "identifier":
        return _resolve_static_binding(context, node, resolving, _static_esbuild_object)
    if node.type == "object":
        return _static_esbuild_object_properties(context, node, resolving)
    return None


def _static_esbuild_map_shape(
    context: _EsbuildStaticContext, node: Node
) -> tuple[Node, Node] | None:
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or function.type != "member_expression" or arguments is None:
        return None
    property_node = function.child_by_field_name("property")
    source_node = function.child_by_field_name("object")
    if property_node is None or source_node is None:
        return None
    if _node_text(context.source, property_node) != "map":
        return None
    if len(arguments.named_children) != 1:
        return None
    return source_node, arguments.named_children[0]


def _static_esbuild_map_callback(
    context: _EsbuildStaticContext, callback: Node
) -> tuple[str, Node] | None:
    if callback.type != "arrow_function":
        return None
    parameters = callback.child_by_field_name(
        "parameters"
    ) or callback.child_by_field_name("parameter")
    body = callback.child_by_field_name("body")
    if parameters is None or body is None:
        return None
    identifiers = [
        child for child in _iter_ts_nodes(parameters) if child.type == "identifier"
    ]
    if len(identifiers) != 1:
        return None
    return _node_text(context.source, identifiers[0]), body


def _static_esbuild_map_entries(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
) -> list[str] | None:
    shape = _static_esbuild_map_shape(context, node)
    if shape is None:
        return None
    source_node, callback = shape
    values = _static_esbuild_entries(context, source_node, resolving)
    callback_parts = _static_esbuild_map_callback(context, callback)
    if values is None or callback_parts is None:
        return None
    parameter, body = callback_parts
    return _fold_static_values(
        values,
        lambda value: _static_esbuild_string(
            context, body, {parameter: value}, resolving
        ),
    )


def _esbuild_array_nodes(node: Node) -> list[Node] | None:
    values: list[Node] = []
    expecting_value = True
    for child in node.children:
        if child.type in {"[", "]", "comment"}:
            continue
        if child.type == ",":
            if expecting_value:
                return None
            expecting_value = True
            continue
        if not expecting_value:
            return None
        values.append(child)
        expecting_value = False
    return values


def _static_esbuild_array_entry(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
) -> str | None:
    value = _static_esbuild_string(context, node, resolving=resolving)
    if value is not None:
        return value
    advanced = _static_esbuild_object(context, node, resolving)
    if advanced is None or set(advanced) != {"in", "out"}:
        return None
    input_path = _static_esbuild_string(
        context, advanced.get("in"), resolving=resolving
    )
    output_path = _static_esbuild_string(
        context, advanced.get("out"), resolving=resolving
    )
    return input_path if input_path is not None and output_path is not None else None


def _static_esbuild_array_entries(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
) -> list[str] | None:
    nodes = _esbuild_array_nodes(node)
    if nodes is None:
        return None
    return _fold_static_values(
        nodes, lambda child: _static_esbuild_array_entry(context, child, resolving)
    )


def _static_esbuild_object_entries(
    context: _EsbuildStaticContext,
    node: Node,
    resolving: frozenset[str],
) -> list[str] | None:
    entry_map = _static_esbuild_object(context, node, resolving)
    if entry_map is None:
        return None
    return _fold_static_values(
        entry_map.values(),
        lambda value: _static_esbuild_string(context, value, resolving=resolving),
    )


@_bounded_static_fold
def _static_esbuild_entries(
    context: _EsbuildStaticContext,
    node: Node | None,
    resolving: frozenset[str] = frozenset(),
) -> list[str] | None:
    node = _unwrap_esbuild_static_expression(node)
    if node is None or not context.visit():
        return None
    if node.type == "identifier":
        return _resolve_static_binding(
            context, node, resolving, _static_esbuild_entries
        )
    if node.type == "call_expression":
        return _static_esbuild_map_entries(context, node, resolving)
    if node.type == "array":
        return _static_esbuild_array_entries(context, node, resolving)
    return _static_esbuild_object_entries(context, node, resolving)


def _discover_esbuild_config_entries(
    config_path: str, ts_files: set[str], default_base_dir: str
) -> set[str]:
    """Discover only statically proven top-level esbuild entry points."""
    suffix = Path(config_path).suffix.lower()
    if suffix in {".cjs", ".cts"}:
        return set()
    if suffix in {".js", ".jsx"} and _read_json_file(
        os.path.join(default_base_dir, "package.json")
    ).get("type") != "module":
        return set()
    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None or root_node.has_error:
        return set()

    static_context = _esbuild_static_context(
        source, root_node, config_path, default_base_dir
    )
    if static_context is None:
        return set()
    direct_bindings = static_context.esbuild_direct
    namespace_bindings = static_context.esbuild_namespaces

    matches: set[str] = set()
    glob_requests: set[tuple[str, str]] = set()
    for node in _iter_ts_nodes(root_node):
        if node.type != "call_expression" or not _is_esbuild_call(
            source, node, direct_bindings, namespace_bindings
        ):
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None or not arguments.named_children:
            continue
        static_context.restart()
        options = _static_esbuild_object(static_context, arguments.named_children[0])
        if options is None or "entryPoints" not in options:
            continue

        base_dir = default_base_dir
        if "absWorkingDir" in options:
            working_dir = _static_esbuild_string(
                static_context, options["absWorkingDir"]
            )
            if working_dir is None:
                continue
            resolved_base = resolve_bounded_base(default_base_dir, working_dir)
            if resolved_base is None:
                continue
            base_dir = resolved_base

        entry_values = _static_esbuild_entries(static_context, options["entryPoints"])
        if entry_values is None:
            continue
        for entry in dict.fromkeys(entry_values):
            if "*" in entry:
                glob_requests.add((os.path.realpath(base_dir), entry))
                continue
            resolved = _resolve_relative_entry_file(base_dir, entry, ts_files)
            if resolved:
                matches.add(resolved)

    inventories: dict[str, tuple[tuple[str, str], ...]] = {}
    for base_dir, _ in glob_requests:
        if base_dir not in inventories:
            inventories[base_dir] = _esbuild_file_inventory(base_dir, ts_files)

    if len(glob_requests) > _MAX_ESBUILD_ENTRY_GLOBS:
        for inventory in inventories.values():
            matches.update(real_path for real_path, _ in inventory)
        return matches

    for base_dir, pattern in glob_requests:
        matches.update(
            _expand_esbuild_entry_glob(base_dir, pattern, inventories[base_dir])
        )
    return matches


def _discover_playwright_config_entries(
    config_path: str, ts_files: set[str]
) -> set[str]:
    source, root_node = _load_entry_config_ast(config_path)
    if source is None or root_node is None:
        return set()

    objects = _find_config_root_objects(source, root_node)
    if not objects:
        return set()

    config_dir = os.path.dirname(config_path)
    test_dir = config_dir
    test_dir_values = _find_object_path_values(source, objects, ("testDir",))
    for node in test_dir_values:
        literals = _collect_string_literals(source, node)
        if literals:
            test_dir = os.path.normpath(os.path.join(config_dir, literals[0]))
            break

    matches: set[str] = {
        real_path
        for real_path in ts_files
        if os.path.commonpath([real_path, os.path.realpath(test_dir)])
        == os.path.realpath(test_dir)
    }

    pattern_values = _find_object_path_values(source, objects, ("testMatch",))
    if pattern_values:
        filtered: set[str] = set()
        patterns: list[str] = []
        for node in pattern_values:
            patterns.extend(_collect_string_literals(source, node))
        for real_path in matches:
            relative = os.path.relpath(real_path, os.path.realpath(test_dir)).replace(
                os.sep, "/"
            )
            if any(
                fnmatch.fnmatch(relative, pattern)
                or fnmatch.fnmatch(os.path.basename(relative), pattern)
                for pattern in patterns
            ):
                filtered.add(real_path)
        matches = filtered

    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("globalSetup",)),
            config_dir,
            ts_files,
        )
    )
    matches.update(
        _literal_entries_from_nodes(
            source,
            _find_object_path_values(source, objects, ("globalTeardown",)),
            config_dir,
            ts_files,
        )
    )
    return matches


def _script_command_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _SCRIPT_COMMAND_SEPARATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _is_environment_assignment(token: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token) is not None


def _unwrap_script_command(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens) and _is_environment_assignment(tokens[index]):
        index += 1
    if index >= len(tokens):
        return []

    command = tokens[index]
    if command in _SCRIPT_ENV_WRAPPERS:
        index += 1
        while index < len(tokens):
            token = tokens[index]
            if _is_environment_assignment(token):
                index += 1
                continue
            if command == "env" and token == "-u" and index + 1 < len(tokens):
                index += 2
                continue
            if token.startswith("-"):
                return []
            break
    if index >= len(tokens):
        return []

    runner = tokens[index]
    if runner in {"bunx", "npx", "pnpx"}:
        index += 1
        if index < len(tokens) and tokens[index].startswith("-"):
            return []
    elif runner == "npm":
        if index + 1 >= len(tokens) or tokens[index + 1] != "exec":
            return tokens[index:]
        index += 2
        if index < len(tokens) and tokens[index] == "--":
            index += 1
    elif runner in {"pnpm", "yarn"}:
        if index + 1 >= len(tokens):
            return []
        subcommand = tokens[index + 1]
        if subcommand == "run":
            return tokens[index:]
        index += 2 if subcommand in {"dlx", "exec"} else 1
        if index < len(tokens) and tokens[index] == "--":
            index += 1
    return tokens[index:]


def _runtime_script_entries(package_root: str, tokens: list[str]) -> set[str]:
    if not tokens:
        return set()
    runtime = tokens[0]
    if runtime not in _SCRIPT_RUNTIME_TOOLS:
        return set()

    args = tokens[1:]
    if runtime == "deno":
        if not args or args[0] != "run":
            return set()
        args = args[1:]
    elif runtime == "bun":
        if args[:1] in (["--hot"], ["--watch"]):
            args = args[1:]
        if args[:1] == ["run"]:
            args = args[1:]
            if args[:1] in (["--hot"], ["--watch"]):
                args = args[1:]
    elif runtime == "tsx" and args[:1] == ["watch"]:
        args = args[1:]

    if args[:1] == ["--"]:
        args = args[1:]
    if not args or args[0].startswith("-"):
        return set()

    candidate = _token_file_candidate(package_root, args[0])
    if candidate and Path(candidate).suffix.lower() in _ENTRY_FILE_SUFFIXES:
        return {os.path.realpath(candidate)}
    return set()


def _token_file_candidate(package_root: str, token: str) -> str | None:
    if not token or token.startswith("-"):
        return None
    cleaned = token.strip().strip("'\"")
    if not cleaned or cleaned.startswith("$") or "://" in cleaned:
        return None

    normalized = cleaned
    if os.path.isabs(normalized):
        candidate = os.path.normpath(normalized)
    else:
        candidate = os.path.normpath(os.path.join(package_root, normalized))
    if os.path.isfile(candidate):
        return candidate
    return None


def _discover_script_entry_candidates(
    package_root: str,
) -> tuple[set[str], set[str], dict[str, tuple[str, str]]]:
    data = _read_json_file(os.path.join(package_root, "package.json"))
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return set(), set(), {}

    direct_files: set[str] = set()
    executable_files: set[str] = set()
    config_files: dict[str, tuple[str, str]] = {}

    for command in scripts.values():
        if not isinstance(command, str):
            continue
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError:
            tokens = command.split()
        if not tokens:
            continue

        segments = _script_command_segments(tokens)
        allow_execution_proof = len(segments) == 1
        for segment in segments:
            for token in segment:
                file_candidate = _token_file_candidate(package_root, token)
                if (
                    file_candidate
                    and Path(file_candidate).suffix.lower() in _ENTRY_FILE_SUFFIXES
                ):
                    direct_files.add(os.path.realpath(file_candidate))

            command_tokens = _unwrap_script_command(segment)
            if not command_tokens:
                continue
            if allow_execution_proof:
                executable_files.update(
                    _runtime_script_entries(package_root, command_tokens)
                )

            tool = command_tokens[0]
            if tool not in _RUNNER_CONFIG_TOOLS:
                continue
            for index, token in enumerate(command_tokens[1:], 1):
                config_path: str | None = None
                if token in {"--config", "-c"} and index + 1 < len(command_tokens):
                    config_path = _token_file_candidate(
                        package_root, command_tokens[index + 1]
                    )
                elif token.startswith("--config="):
                    config_path = _token_file_candidate(
                        package_root, token.split("=", 1)[1]
                    )
                if config_path:
                    config_files[os.path.realpath(config_path)] = (
                        tool,
                        package_root,
                    )

    return direct_files, executable_files, config_files


def _iter_entry_discoveries(
    ts_files: set[str],
    project_root: str | None = None,
    workspace_inventory=None,
    exclude_folders=None,
) -> list[_TsEntryDiscovery]:
    discoveries: list[_TsEntryDiscovery] = []

    for tf in sorted(ts_files):
        if os.path.basename(tf) in _TS_ENTRY_FILES or _is_ts_entry_or_infra(tf):
            reason = "default-root"
            discoveries.append(
                _TsEntryDiscovery(
                    tf,
                    "heuristic",
                    reason,
                    _classify_entry_scope(tf, "heuristic", reason),
                )
            )

    if not project_root and workspace_inventory is None:
        return discoveries

    package_roots = set(_workspace_package_roots(workspace_inventory))
    if workspace_inventory is None or not workspace_inventory.is_monorepo:
        package_roots.update(
            _discover_package_roots_from_files(
                list(ts_files),
                project_root,
                exclude_folders=exclude_folders,
            )
        )
    if project_root and workspace_inventory is not None:
        package_roots.update(
            _discover_referenced_package_roots(
                list(ts_files),
                project_root,
                workspace_inventory,
                exclude_folders=exclude_folders,
            )
        )

    custom_config_tools: dict[str, tuple[str, str]] = {}
    for package_root in package_roots:
        for entry_file in _discover_package_entry_files(str(package_root)):
            if entry_file in ts_files:
                reason = "package-entry"
                discoveries.append(
                    _TsEntryDiscovery(
                        entry_file,
                        "package",
                        reason,
                        _classify_entry_scope(entry_file, "package", reason),
                    )
                )

        script_entries, executable_entries, script_configs = (
            _discover_script_entry_candidates(str(package_root))
        )
        for entry_file in script_entries:
            if entry_file in ts_files:
                reason = "package-script"
                discoveries.append(
                    _TsEntryDiscovery(
                        entry_file,
                        "script",
                        reason,
                        _classify_entry_scope(entry_file, "script", reason),
                    )
                )
                if entry_file not in executable_entries:
                    continue
                esbuild_entries = _discover_esbuild_config_entries(
                    entry_file,
                    ts_files,
                    str(package_root),
                )
                for build_entry in sorted(esbuild_entries):
                    build_reason = "esbuild-derived-root"
                    discoveries.append(
                        _TsEntryDiscovery(
                            build_entry,
                            "config",
                            build_reason,
                            _classify_entry_scope(
                                build_entry,
                                "config",
                                build_reason,
                            ),
                        )
                    )
        custom_config_tools.update(script_configs)

    default_configs: dict[str, tuple[str, str]] = {}
    for package_root in package_roots:
        for config_name in _PLAYWRIGHT_CONFIG_FILES | _CONFIG_FILES:
            candidate = os.path.join(str(package_root), config_name)
            if os.path.isfile(candidate):
                default_configs[os.path.realpath(candidate)] = (
                    "playwright"
                    if os.path.basename(candidate) in _PLAYWRIGHT_CONFIG_FILES
                    else (
                        "vitest"
                        if "vitest" in os.path.basename(candidate)
                        else (
                            "tsup"
                            if os.path.basename(candidate).startswith("tsup.config.")
                            else "vite"
                        )
                    ),
                    str(package_root),
                )

    config_tools = {**default_configs, **custom_config_tools}
    for config_path, (tool, base_dir) in config_tools.items():
        if config_path in ts_files:
            reason = f"{tool}-config"
            discoveries.append(
                _TsEntryDiscovery(
                    config_path,
                    "config",
                    reason,
                    _classify_entry_scope(config_path, "config", reason),
                )
            )
        if tool == "vitest":
            entry_files = _discover_vitest_config_entries(
                config_path, ts_files, base_dir
            )
        elif tool == "playwright":
            entry_files = _discover_playwright_config_entries(config_path, ts_files)
        elif tool == "tsup":
            entry_files = _discover_tsup_config_entries(
                config_path, ts_files, base_dir
            )
        else:
            entry_files = _discover_vite_config_entries(config_path, ts_files, base_dir)
        for entry_file in sorted(entry_files):
            reason = f"{tool}-derived-root"
            discoveries.append(
                _TsEntryDiscovery(
                    entry_file,
                    "config",
                    reason,
                    _classify_entry_scope(entry_file, "config", reason),
                )
            )

    return discoveries


def _iter_package_entry_targets(entry):
    if isinstance(entry, str):
        yield entry
        return
    if isinstance(entry, list):
        for item in entry:
            yield from _iter_package_entry_targets(item)
        return
    if isinstance(entry, dict):
        for value in entry.values():
            yield from _iter_package_entry_targets(value)


def _discover_package_entry_files(package_root: str) -> set[str]:
    data = _read_json_file(os.path.join(package_root, "package.json"))
    if not data:
        return set()

    targets: list[str] = []
    seen_targets: set[str] = set()
    for field in (
        "main",
        "module",
        "types",
        "typings",
        "source",
        "browser",
        "bin",
        "exports",
    ):
        for target in _iter_package_entry_targets(data.get(field)):
            if target in seen_targets:
                continue
            seen_targets.add(target)
            targets.append(target)

    entry_files: set[str] = set()
    for target in targets:
        resolved = _resolve_path_target(package_root, target)
        if resolved:
            entry_files.add(os.path.realpath(resolved))
    return entry_files


def _workspace_package_roots(workspace_inventory) -> list[Path]:
    package_roots: set[Path] = set()
    if (
        workspace_inventory
        and workspace_inventory.root_package
        and workspace_inventory.root_package.has_package_json
    ):
        package_roots.add(workspace_inventory.root_package.root.resolve())
    if workspace_inventory:
        for workspace in workspace_inventory.packages:
            if workspace.has_package_json and (
                "package.json:workspaces" in workspace.discovered_from
                or "pnpm-workspace.yaml" in workspace.discovered_from
            ):
                package_roots.add(workspace.root.resolve())
    return sorted(package_roots, key=lambda path: len(str(path)), reverse=True)


def _discover_package_roots_from_files(
    files, project_root: str | None = None, exclude_folders=None
) -> set[Path]:
    exclude_root = _resolve_exclude_root(files, project_root)
    package_roots: set[Path] = set()

    for file_path in files:
        path = Path(str(file_path)).resolve()
        if _is_excluded_path(str(path), exclude_folders, exclude_root):
            continue
        if path.suffix.lower() not in _TS_JS_EXTENSIONS:
            continue

        current = path.parent
        while True:
            if (current / "package.json").is_file():
                package_roots.add(current)
                break
            parent = current.parent
            if parent == current:
                break
            current = parent

    return package_roots


def _find_owning_package_root(
    file_path: Path, package_roots: list[Path]
) -> Path | None:
    for package_root in package_roots:
        try:
            file_path.relative_to(package_root)
            return package_root
        except ValueError:
            continue
    return None


def _discover_referenced_package_roots(
    files, project_root: str, workspace_inventory, exclude_folders=None
) -> set[Path]:
    project_root_path = Path(project_root).resolve()
    exclude_root = _resolve_exclude_root(files, project_root)
    package_roots = _workspace_package_roots(workspace_inventory)
    if not package_roots:
        return set()

    referenced_roots: set[Path] = set()
    active_tsconfigs: set[str] = set()

    for file_path in {
        Path(str(f)).resolve()
        for f in files
        if str(f).endswith(_TS_JS_EXTENSIONS)
        and not _is_excluded_path(str(f), exclude_folders, exclude_root)
    }:
        owning_package_root = _find_owning_package_root(file_path, package_roots)
        if owning_package_root is None:
            continue
        tsconfig = _find_nearest_tsconfig(str(file_path), project_root)
        if tsconfig:
            active_tsconfigs.add(os.path.realpath(tsconfig))

    for tsconfig in active_tsconfigs:
        for ref_root in _parse_tsconfig_references(tsconfig):
            resolved_root = Path(ref_root).resolve()
            try:
                resolved_root.relative_to(project_root_path)
            except ValueError:
                continue
            if (resolved_root / "package.json").is_file():
                referenced_roots.add(resolved_root)

    return referenced_roots


def _discover_ts_reachability_entry_files(
    files,
    project_root: str | None = None,
    workspace_inventory=None,
    exclude_folders=None,
    include_dev_roots: bool = True,
) -> set[str]:
    exclude_root = _resolve_exclude_root(files, project_root)
    ts_files = {
        os.path.realpath(str(f))
        for f in files
        if str(f).endswith(_TS_JS_EXTENSIONS)
        and not _is_excluded_path(str(f), exclude_folders, exclude_root)
    }
    if not ts_files:
        return set()

    discoveries = _iter_entry_discoveries(
        ts_files,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
    )
    return {
        discovery.file
        for discovery in discoveries
        if discovery.file in ts_files
        and (include_dev_roots or discovery.scope == "prod")
    }


def _has_vscode_extension_metadata(data: dict) -> bool:
    engines = data.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("vscode"), str):
        return True

    activation_events = data.get("activationEvents")
    if isinstance(activation_events, list) and activation_events:
        return True

    contributes = data.get("contributes")
    if isinstance(contributes, dict):
        return any(
            key in contributes
            for key in ("commands", "views", "viewsContainers", "menus")
        )
    return False


def _discover_ts_vscode_lifecycle_entry_files(
    files,
    project_root: str | None = None,
    workspace_inventory=None,
    exclude_folders=None,
) -> set[str]:
    exclude_root = _resolve_exclude_root(files, project_root)
    ts_files = {
        os.path.realpath(str(f))
        for f in files
        if str(f).endswith(_TS_JS_EXTENSIONS)
        and not _is_excluded_path(str(f), exclude_folders, exclude_root)
    }
    if not ts_files:
        return set()

    package_roots = set(_workspace_package_roots(workspace_inventory))
    if workspace_inventory is None or not workspace_inventory.is_monorepo:
        package_roots.update(
            _discover_package_roots_from_files(
                list(ts_files),
                project_root,
                exclude_folders=exclude_folders,
            )
        )
    if project_root and workspace_inventory is not None:
        package_roots.update(
            _discover_referenced_package_roots(
                list(ts_files),
                project_root,
                workspace_inventory,
                exclude_folders=exclude_folders,
            )
        )

    entry_files: set[str] = set()
    for package_root in package_roots:
        data = _read_json_file(os.path.join(str(package_root), "package.json"))
        if not _has_vscode_extension_metadata(data):
            continue
        for entry_file in _discover_package_entry_files(str(package_root)):
            if entry_file in ts_files:
                entry_files.add(entry_file)
    return entry_files


def _is_ts_reachability_root(path: str, entry_files: set[str]) -> bool:
    real_path = os.path.realpath(path)
    return real_path in entry_files


def find_dead_ts_files(
    files,
    exclude_folders,
    importers_of,
    wildcard_edges,
    project_root: str | None = None,
    workspace_inventory=None,
    browser_entry_points=None,
):
    exclude_root = _resolve_exclude_root(files, project_root)
    ts_files = set()
    for f in files:
        sf = str(f)
        if not sf.endswith(_TS_JS_EXTENSIONS):
            continue
        if _is_excluded_path(sf, exclude_folders, exclude_root):
            continue
        if _is_ts_entry_or_infra(sf):
            continue
        ts_files.add(os.path.realpath(sf))

    norm_importers = defaultdict(set)
    for target, importers in importers_of.items():
        real_target = os.path.realpath(target)
        for imp in importers:
            norm_importers[real_target].add(os.path.realpath(imp))
    for reexporter, sources in wildcard_edges.items():
        for src in sources:
            norm_importers[os.path.realpath(src)].add(os.path.realpath(reexporter))

    entry_points = _discover_ts_reachability_entry_files(
        files,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
    )
    entry_points.update(
        os.path.realpath(str(path)) for path in browser_entry_points or ()
    )

    dead_set = set()
    for tf in ts_files - entry_points:
        if not norm_importers.get(tf):
            dead_set.add(tf)

    changed = True
    iterations = 0
    while changed and iterations < 50:
        changed = False
        iterations += 1
        for tf in ts_files - entry_points - dead_set:
            live_importers = norm_importers.get(tf, set()) - dead_set
            if not live_importers:
                dead_set.add(tf)
                changed = True

    dead_files = []
    for tf in sorted(dead_set):
        dead_files.append(
            {
                "rule_id": "SKY-E003",
                "message": "Unused TypeScript/JavaScript file (not imported by any other file)",
                "file": tf,
                "line": 1,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }
        )
    return dead_files


def find_unused_ts_exports(
    demoted_exports,
    wildcard_edges,
    files=None,
    exclude_folders=None,
    project_root: str | None = None,
    workspace_inventory=None,
):
    if not demoted_exports:
        return []

    candidate_files: list[str] = [str(defn.filename) for defn in demoted_exports]
    for reexporter, sources in wildcard_edges.items():
        candidate_files.append(reexporter)
        candidate_files.extend(sources)
    analysis_files = files if files is not None else candidate_files
    entry_points = _discover_ts_reachability_entry_files(
        analysis_files,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
        include_dev_roots=False,
    )

    api_surface = set()
    if wildcard_edges:
        reexported_by = defaultdict(set)
        for reexporter, sources in wildcard_edges.items():
            for src in sources:
                reexported_by[os.path.realpath(src)].add(os.path.realpath(reexporter))

        for src_real in reexported_by:
            visited = set()
            queue = [src_real]
            reaches_entry = False
            while queue:
                current = queue.pop()
                if current in visited:
                    continue
                visited.add(current)
                if _is_ts_reachability_root(current, entry_points):
                    reaches_entry = True
                    break
                for parent in reexported_by.get(current, []):
                    queue.append(parent)
            if reaches_entry:
                api_surface.add(src_real)

    findings = []
    for defn in demoted_exports:
        if defn.references <= 0:
            continue
        fname = str(defn.filename)
        if _is_ts_reachability_root(fname, entry_points):
            continue
        if defn.type == "method":
            continue
        if os.path.realpath(fname) in api_surface:
            continue
        if is_nextjs_convention_export(defn.simple_name, fname):
            continue
        findings.append(
            {
                "rule_id": "SKY-E004",
                "name": defn.simple_name,
                "message": (
                    f"Unnecessary `export` on `{defn.simple_name}` "
                    f"(used internally but not imported by any other file)"
                ),
                "file": fname,
                "line": defn.line,
                "type": defn.type,
                "severity": "LOW",
                "category": "DEAD_CODE",
            }
        )
    return findings
