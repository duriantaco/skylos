"""Unused re-export entries of TS/JS modules, with entry points kept public."""

from __future__ import annotations

import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Query, QueryCursor

from skylos.core.js_ast import is_type_only, iter_import_clause_bindings
from skylos.deadcode.confidence import export_finding_confidence

from .analysis import (
    _TS_JS_EXTENSIONS,
    _TS_PACKAGE_ENTRY_FIELDS,
    _analysed_ts_files,
    _discover_package_roots_from_files,
    _entry_parser_for_path,
    _is_ts_entry_or_infra,
    _iter_entry_discoveries,
    _iter_package_entry_targets,
    _parse_entry_source,
    _read_json_file,
    _resolve_exclude_root,
    _string_node_value,
    resolve_ts_module,
)
from .framework import is_framework_loaded_file
from .resolve import _resolve_path_target

_ALL = "*"
_STAR = "**star**"
_MAX_FILES = 5000
_MAX_FILE_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 64_000_000
_MAX_WALKED_FILES = 200_000
_MAX_DEMAND_ITEMS = 500_000
_MAX_HTML_BYTES = 512 * 1024
_COMPONENT_SUFFIXES = frozenset({".vue", ".svelte", ".astro", ".mdx", ".marko"})
_HTML_SUFFIXES = frozenset({".html", ".htm"})
_SKIPPED_WALK_DIRECTORIES = frozenset({".git", ".hg", ".svn", "node_modules"})
_DECLARATION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "abstract_class_declaration",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
        "function_signature",
        "internal_module",
        "module",
    }
)
_LOAD_QUERY = """
(call_expression arguments: (arguments . (_) @first_argument))
(variable_declarator
  name: (identifier) @required_name
  value: (call_expression function: (identifier) @factory (#eq? @factory "createRequire")))
"""
_SPECIFIER_RE = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)(['"])([^'"\r\n]+)\1"""
)
_INLINE_MODULE_SCRIPT_RE = re.compile(
    r"<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>", re.IGNORECASE | re.DOTALL
)
_MODULE_TYPE_RE = re.compile(r"""\btype\s*=\s*["']?module\b""", re.IGNORECASE)
_SRC_ATTRIBUTE_RE = re.compile(r"\bsrc\s*=", re.IGNORECASE)
_URL_SPECIFIER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_MOCK_METHODS = frozenset({"mock", "doMock", "unmock", "dontMock", "setMock"})
_QUERY_CACHE: dict[int, Query | None] = {}


class _Declined(Exception):
    pass


@dataclass
class _Entry:
    exported: str
    line: int
    kind: str
    target: str | None = None
    original: str = ""
    type_only: bool = False
    local: str = ""


@dataclass
class _Module:
    path: str
    entries: list[_Entry] = field(default_factory=list)
    own_exports: set[str] = field(default_factory=set)
    has_error: bool = False
    commonjs_export: bool = False
    specifiers: set[str] = field(default_factory=set)
    whole_module_loads: set[str] = field(default_factory=set)
    loaded_directories: set[str] = field(default_factory=set)
    dynamic_loads: dict = field(default_factory=dict)


def find_unused_ts_reexports(
    files,
    raw_imports,
    *,
    project_root,
    resolver=None,
    workspace_inventory=None,
    exclude_folders=None,
    browser_entry_points=(),
    analysis_errors=(),
):
    if not project_root or not raw_imports:
        return []
    try:
        return _find(
            files,
            raw_imports,
            project_root=str(project_root),
            resolver=resolver,
            workspace_inventory=workspace_inventory,
            exclude_folders=exclude_folders,
            browser_entry_points=browser_entry_points,
            analysis_errors=analysis_errors,
        )
    except (_Declined, OSError, RecursionError, UnicodeError, ValueError):
        return []


def _find(
    files,
    raw_imports,
    *,
    project_root,
    resolver,
    workspace_inventory,
    exclude_folders,
    browser_entry_points,
    analysis_errors,
):
    exclude_root = _resolve_exclude_root(files, project_root)
    analysed = _analysed_ts_files(files, exclude_folders, exclude_root)
    if not analysed or len(analysed) > _MAX_FILES:
        return []
    error_files = _error_files(analysis_errors)
    modules = _parse_modules(analysed, error_files)
    if not any(module.entries for module in modules.values()):
        return []
    if _has_unparsed_module_consumers(exclude_root, exclude_folders):
        return []

    def resolve(source, importer):
        resolved = resolve_ts_module(source, importer, resolver)
        if resolved is None:
            return None
        return os.path.realpath(resolved)

    unresolved_tails = set()
    demand_seeds = []
    importers = defaultdict(set)
    imports_by_file = {
        os.path.realpath(str(path)): items for path, items in raw_imports.items()
    }
    for importer in sorted(set(imports_by_file) | set(modules)):
        module = modules.get(importer)
        conservative = module is None or module.has_error
        sources = [
            (item.get("source", ""), item) for item in imports_by_file.get(importer, ())
        ]
        if module is not None:
            sources.extend(
                (source, None) for source in sorted(module.whole_module_loads)
            )
        if module is not None and module.has_error:
            recorded = {source for source, _item in sources}
            sources.extend(
                (source, None) for source in sorted(module.specifiers - recorded)
            )
        for source, item in sources:
            if not source:
                continue
            target = resolve(source, importer)
            built = None
            if target is None:
                built = _built_output_source(source, importer)
            if target is None and built is None:
                unresolved_tails.update(_specifier_tails(source))
                continue
            if target is None:
                target = built
            importers[target].add(importer)
            if conservative or item is None or built is not None:
                demand_seeds.append((target, (_ALL,)))
            elif not item.get("is_reexport"):
                demand_seeds.extend(
                    (target, path) for path in _item_paths(item, module, source)
                )
    for module in modules.values():
        for entry in module.entries:
            if entry.kind == "alias" or entry.target is None:
                continue
            resolved = resolve(entry.target, module.path)
            if resolved is None:
                unresolved_tails.update(_specifier_tails(entry.target))
            entry.target = resolved
            if resolved is not None:
                importers[resolved].add(module.path)

    public = _public_modules(
        files,
        analysed,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
        browser_entry_points=browser_entry_points,
    )
    loaded_directories = {
        directory
        for module in modules.values()
        for directory in module.loaded_directories
    }
    public.update(
        path
        for path in analysed
        if any(_inside(path, directory) for directory in loaded_directories)
    )
    demand = _propagate(modules, analysed, public, importers, demand_seeds)
    candidates = {
        path
        for path, module in modules.items()
        if module.entries
        and path not in public
        and importers.get(path)
        and _ALL not in demand[path]
        and not module.commonjs_export
        and not path.endswith(".d.ts")
        and not _is_ts_entry_or_infra(path)
        and not is_framework_loaded_file(path)
        and not _names_module(path, unresolved_tails)
    }
    if not candidates:
        return []
    from .file_references import collect_ts_path_references

    path_roots, path_edges = collect_ts_path_references(
        exclude_root, analysed, candidates, exclude_folders=exclude_folders
    )
    candidates -= set(path_roots)
    candidates -= {target for target, sources in path_edges.items() if sources}
    spelled = {os.path.realpath(str(file)): str(file) for file in files}
    findings = []
    for path in sorted(candidates):
        names = demand[path]
        for entry in modules[path].entries:
            if entry.kind == "star":
                continue
            if entry.exported in names:
                continue
            if _STAR in names and entry.exported != "default":
                continue
            findings.append(_finding(spelled.get(path, path), entry))
    return findings


def _finding(path, entry):
    confidence, factors = export_finding_confidence()
    if entry.kind == "alias":
        message = (
            f"Unused export `{entry.exported}` of `{entry.local}` "
            f"(no file imports it from this module; `{entry.local}` "
            "is exported under another name)"
        )
    elif entry.type_only:
        message = (
            f"Unused type re-export `{entry.exported}` "
            "(no file imports it from this module)"
        )
    else:
        message = (
            f"Unused re-export `{entry.exported}` (no file imports it from this module)"
        )
    return {
        "rule_id": "SKY-E004",
        "confidence": confidence,
        "confidence_factors": factors,
        "name": entry.exported,
        "message": message,
        "file": path,
        "line": entry.line,
        "type": "reexport",
        "severity": "LOW",
        "category": "DEAD_CODE",
    }


def _error_files(analysis_errors):
    paths = set()
    for error in analysis_errors or ():
        if not isinstance(error, dict):
            continue
        file = error.get("file")
        if file and str(file).endswith(_TS_JS_EXTENSIONS):
            paths.add(os.path.realpath(str(file)))
    return paths


def _item_paths(item, module, source):
    if (
        module is not None
        and item.get("consume_all_exports")
        and item.get("names") == ["*"]
        and not item.get("type_only")
    ):
        loads = module.dynamic_loads.get((source, item.get("line")))
        if loads and all(
            names is not None and all(_known_name(name) for name in names)
            for names in loads
        ):
            return [(name,) for names in loads for name in names]
    return _requested_paths(item)


def _requested_paths(item):
    if item.get("consume_all_exports"):
        return [(_ALL,)]
    paths = item.get("export_paths")
    if paths:
        result = []
        for path in paths:
            if not path or not all(_known_name(part) for part in path):
                return [(_ALL,)]
            result.append(tuple(path))
        return result
    result = []
    for value in item.get("names", ()):
        if not _known_name(value):
            return [(_ALL,)]
        original = value.partition(" as ")[0]
        if value == item.get("default_import"):
            original = "default"
        if original == "*":
            return [(_ALL,)]
        result.append((original,))
    return result


def _known_name(name):
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    if name == "*":
        return True
    parts = name.split(" as ")
    return len(parts) <= 2 and all(part == "*" or part.isidentifier() for part in parts)


def _specifier_tails(source):
    if source.startswith("node:") or _URL_SPECIFIER_RE.match(source):
        return set()
    from skylos.rules.ai_defect.js_api_hallucination import _NODE_BUILTINS

    if source in _NODE_BUILTINS:
        return set()
    cleaned = re.split(r"[?#]", source, maxsplit=1)[0].rstrip("/")
    tail = cleaned.rsplit("/", 1)[-1].lstrip("@#~")
    if not tail or tail in {".", ".."}:
        return {"index"}
    return {tail, tail.split(".", 1)[0]}


def _built_output_source(source, importer):
    if not source.startswith(("./", "../")):
        return None
    target = os.path.normpath(os.path.join(os.path.dirname(importer), source))
    candidates = [target]
    for output in ("dist", "out"):
        marker = f"{os.sep}{output}{os.sep}"
        if marker in target:
            candidates.append(target.replace(marker, f"{os.sep}src{os.sep}", 1))
            candidates.append(target.replace(marker, os.sep, 1))
    for candidate in candidates:
        mapped = _resolve_path_target(
            os.path.dirname(candidate), "./" + os.path.basename(candidate)
        )
        if mapped is not None:
            return os.path.realpath(mapped)
    return None


def _names_module(path, tails):
    stem = _file_stem(path)
    if stem in tails:
        return True
    return stem == "index" and Path(path).parent.name in tails


def _propagate(modules, analysed, public, importers, seeds):
    demand = defaultdict(set)
    seen = set()
    pending = deque()

    def request(file, path):
        if file not in analysed or (file, path) in seen:
            return
        seen.add((file, path))
        if len(seen) > _MAX_DEMAND_ITEMS:
            raise _Declined
        demand[file].add(path[0])
        pending.append((file, path))

    for file in public:
        request(file, (_ALL,))
    for path in modules:
        if not importers.get(path):
            request(path, (_ALL,))
    for file, path in seeds:
        request(file, path)
    while pending:
        file, path = pending.popleft()
        module = modules.get(file)
        if module is None:
            continue
        name, *tail = path
        if name in {_ALL, _STAR}:
            for entry in module.entries:
                if name == _STAR and entry.exported == "default":
                    continue
                _forward(entry, (), request)
            continue
        matched = [entry for entry in module.entries if entry.exported == name]
        for entry in matched:
            _forward(entry, tuple(tail), request)
        if matched or name == "default" or name in module.own_exports:
            continue
        for entry in module.entries:
            if entry.kind == "star" and entry.target is not None:
                request(entry.target, path)
    return demand


def _forward(entry, tail, request):
    if entry.target is None or entry.kind == "alias":
        return
    if entry.kind == "star":
        request(entry.target, (_STAR,))
    elif entry.kind == "namespace":
        request(entry.target, tail or (_ALL,))
    else:
        request(entry.target, (entry.original, *tail))


def _public_modules(
    files,
    analysed,
    *,
    project_root,
    workspace_inventory,
    exclude_folders,
    browser_entry_points,
):
    public = {os.path.realpath(str(path)) for path in browser_entry_points or ()}
    conventional = set()
    for discovery in _iter_entry_discoveries(
        analysed,
        project_root=project_root,
        workspace_inventory=workspace_inventory,
        exclude_folders=exclude_folders,
    ):
        if discovery.file not in analysed:
            continue
        if discovery.reason == "default-root" and not _is_ts_entry_or_infra(
            discovery.file
        ):
            conventional.add(discovery.file)
        else:
            public.add(discovery.file)
    package_roots = {
        os.path.realpath(str(root))
        for root in _discover_package_roots_from_files(
            files, project_root, exclude_folders=exclude_folders
        )
    }
    package_roots.add(os.path.realpath(project_root))
    for package_root in package_roots:
        stems = _unresolved_entry_stems(package_root)
        public.update(
            path
            for path in analysed
            if _inside(path, package_root) and _file_stem(path) in stems
        )
    for path in conventional - public:
        directory = os.path.dirname(path)
        if directory in package_roots or (
            os.path.basename(directory) == "src"
            and os.path.dirname(directory) in package_roots
        ):
            public.add(path)
    return public


def _unresolved_entry_stems(package_root):
    manifest = os.path.join(package_root, "package.json")
    if not os.path.isfile(manifest):
        return set()
    data = _read_json_file(manifest)
    if not data:
        raise _Declined
    stems = set()
    for field_name in _TS_PACKAGE_ENTRY_FIELDS:
        for target in _iter_package_entry_targets(data.get(field_name)):
            if "*" in target or _target_resolves(package_root, target):
                continue
            stems.add(_file_stem(target))
    return stems


def _file_stem(path):
    return os.path.basename(path).split(".", 1)[0]


def _target_resolves(package_root, target):
    if _resolve_path_target(package_root, target) is not None:
        return True
    for declaration, runtime in ((".d.mts", ".mjs"), (".d.cts", ".cjs")):
        if target.endswith(declaration):
            converted = target[: -len(declaration)] + runtime
            return _resolve_path_target(package_root, converted) is not None
    return False


def _inside(path, directory):
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


def _has_unparsed_module_consumers(root, exclude_folders):
    if root is None:
        raise _Declined
    from skylos.core.file_discovery import should_exclude_path

    root_path = Path(root)
    walked = 0
    for directory, subdirectories, names in os.walk(root_path):
        current = Path(directory)
        kept = []
        for name in subdirectories:
            if name in _SKIPPED_WALK_DIRECTORIES:
                continue
            if exclude_folders and should_exclude_path(
                current / name, root_path, exclude_folders
            ):
                continue
            kept.append(name)
        subdirectories[:] = kept
        for name in names:
            walked += 1
            if walked > _MAX_WALKED_FILES:
                return True
            suffix = os.path.splitext(name)[1].lower()
            if suffix in _COMPONENT_SUFFIXES:
                return True
            if suffix in _HTML_SUFFIXES and _html_has_inline_module_imports(
                current / name
            ):
                return True
    return False


def _html_has_inline_module_imports(path):
    try:
        if path.stat().st_size > _MAX_HTML_BYTES:
            return True
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    for match in _INLINE_MODULE_SCRIPT_RE.finditer(text):
        attrs = match.group("attrs")
        if not _MODULE_TYPE_RE.search(attrs) or _SRC_ATTRIBUTE_RE.search(attrs):
            continue
        if "import" in match.group("body"):
            return True
    return False


def _parse_modules(analysed, error_files):
    modules = {}
    total = 0
    for path in sorted(analysed):
        size = os.path.getsize(path)
        if size > _MAX_FILE_BYTES:
            raise _Declined
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise _Declined
        source = Path(path).read_bytes()
        parser = _entry_parser_for_path(path)
        if parser is None:
            raise _Declined
        root = _parse_entry_source(parser, source, path).root_node
        module = _Module(path, has_error=root.has_error or path in error_files)
        if module.has_error:
            text = _strip_comments(source.decode("utf-8", errors="replace"))
            module.specifiers = {
                match.group(2) for match in _SPECIFIER_RE.finditer(text)
            }
        _collect_loads(source, root, parser.language, module)
        _collect_exports(source, root, module)
        modules[path] = module
    return modules


def _strip_comments(text):
    return re.sub(r"/\*.*?\*/|(?<![:\\])//[^\n]*", "", text, flags=re.DOTALL)


def _load_query(language):
    key = id(language)
    if key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[key] = Query(language, _LOAD_QUERY)
        except Exception:
            _QUERY_CACHE[key] = None
    return _QUERY_CACHE[key]


def _collect_loads(source, root, language, module):
    query = _load_query(language)
    if query is None:
        raise _Declined
    captures = QueryCursor(query).captures(root)
    loader_names = {"require"}
    for name in captures.get("required_name", ()):
        loader_names.add(_text(source, name))
    directory = os.path.dirname(module.path)
    for first in captures.get("first_argument", ()):
        call = first.parent.parent
        literal = _literal_text(source, first)
        if (
            literal is not None
            and first.type == "string"
            and _is_recorded_load(source, call.child_by_field_name("function"))
        ):
            key = (literal, call.start_point[0] + 1)
            module.dynamic_loads.setdefault(key, []).append(
                _destructured_names(source, call)
            )
            continue
        if literal is not None:
            if literal.startswith(("./", "../")) and not _registers_mock(
                source, call.child_by_field_name("function")
            ):
                module.whole_module_loads.add(literal)
            if _is_directory_loader(source, call.child_by_field_name("function")):
                module.loaded_directories.update(
                    _fragment_paths(directory, [literal], dynamic=False)
                )
            continue
        if not _is_loader(source, call.child_by_field_name("function"), loader_names):
            continue
        fragments = [
            _text(source, node)
            for node in _iter_named(first)
            if node.type == "string_fragment"
        ]
        found = _fragment_paths(directory, fragments, dynamic=True)
        if not found and _mentions_module_directory(source, first):
            found = {directory}
        module.loaded_directories.update(found)


def _is_recorded_load(source, callee):
    if callee is None:
        return False
    if callee.type == "import":
        return True
    return callee.type == "identifier" and _text(source, callee) == "require"


def _destructured_names(source, call):
    value = call
    parent = call.parent
    if parent is not None and parent.type == "await_expression":
        value = parent
        parent = parent.parent
    if (
        parent is None
        or parent.type != "variable_declarator"
        or parent.child_by_field_name("value") != value
    ):
        return None
    pattern = parent.child_by_field_name("name")
    if pattern is None or pattern.type != "object_pattern":
        return None
    names = []
    for child in pattern.named_children:
        name = _pattern_property_name(source, child)
        if name is None:
            return None
        if name:
            names.append(name)
    return names


def _pattern_property_name(source, node):
    if node.type == "comment":
        return ""
    if node.type == "shorthand_property_identifier_pattern":
        return _text(source, node)
    if node.type == "object_assignment_pattern":
        left = node.child_by_field_name("left")
        if left is not None and left.type == "shorthand_property_identifier_pattern":
            return _text(source, left)
        return None
    if node.type == "pair_pattern":
        key = node.child_by_field_name("key")
        if key is not None and key.type == "property_identifier":
            return _text(source, key)
        if key is not None and key.type == "string":
            return _string_node_value(source, key)
    return None


def _literal_text(source, node):
    if node.type == "string":
        return _string_node_value(source, node)
    if node.type == "template_string" and not any(
        child.type == "template_substitution" for child in node.named_children
    ):
        return "".join(
            _text(source, child)
            for child in node.named_children
            if child.type == "string_fragment"
        )
    return None


def _is_loader(source, callee, loader_names):
    if callee is None:
        return False
    if callee.type == "import":
        return True
    if callee.type == "identifier":
        return _text(source, callee) in loader_names
    if callee.type == "call_expression":
        inner = callee.child_by_field_name("function")
        return inner is not None and _text(source, inner) == "createRequire"
    if callee.type == "member_expression":
        property_node = callee.child_by_field_name("property")
        return property_node is not None and _text(source, property_node) in {
            "require",
            "glob",
            "globEager",
            "context",
            "import",
            "importActual",
            "requireActual",
        }
    return False


def _registers_mock(source, callee):
    if callee is None or callee.type != "member_expression":
        return False
    property_node = callee.child_by_field_name("property")
    return property_node is not None and _text(source, property_node) in _MOCK_METHODS


def _is_directory_loader(source, callee):
    if callee is None or callee.type != "member_expression":
        return False
    property_node = callee.child_by_field_name("property")
    object_node = callee.child_by_field_name("object")
    return (
        property_node is not None
        and object_node is not None
        and _text(source, property_node) == "context"
        and _text(source, object_node) == "require"
    )


def _fragment_paths(directory, fragments, *, dynamic):
    found = set()
    for fragment in fragments:
        cleaned = fragment.strip()
        if not cleaned or _URL_SPECIFIER_RE.match(cleaned):
            continue
        candidate = os.path.normpath(os.path.join(directory, cleaned))
        if os.path.isdir(candidate):
            found.add(os.path.realpath(candidate))
        elif dynamic and os.path.isdir(os.path.dirname(candidate)) and "/" in cleaned:
            found.add(os.path.realpath(os.path.dirname(candidate)))
    return found


def _mentions_module_directory(source, node):
    for child in _iter_named(node):
        text = _text(source, child)
        if child.type == "identifier" and text in {"__dirname", "__filename"}:
            return True
        if child.type == "member_expression" and text.startswith("import.meta"):
            return True
    return False


def _iter_named(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.named_children)


def _collect_exports(source, root, module):
    bindings = {}
    declared = set()
    for statement in root.named_children:
        if statement.type == "import_statement":
            for child in statement.named_children:
                if child.type == "import_require_clause":
                    required = _string_node_value(
                        source, child.child_by_field_name("source")
                    )
                    if required is None:
                        raise _Declined
                    module.whole_module_loads.add(required)
            specifier = _string_node_value(
                source, statement.child_by_field_name("source")
            )
            clause = next(
                (
                    child
                    for child in statement.named_children
                    if child.type == "import_clause"
                ),
                None,
            )
            if clause is None or specifier is None or statement.has_error:
                continue
            for binding in iter_import_clause_bindings(source, clause):
                bindings[binding.local] = (specifier, binding)
        elif statement.type not in {"export_statement", "expression_statement"}:
            declared.update(_declared_names(source, statement))
    local_exports = defaultdict(list)
    defaults = []
    exported_declarations = set()
    for statement in root.named_children:
        if statement.type == "expression_statement" and _is_commonjs_export(
            source, statement
        ):
            module.commonjs_export = True
        if statement.type != "export_statement":
            continue
        if any(child.type == "=" for child in statement.children):
            module.commonjs_export = True
            continue
        declaration = statement.child_by_field_name("declaration")
        is_default = any(child.type == "default" for child in statement.children)
        if declaration is not None:
            names = _declared_names(source, declaration)
            declared.update(names)
            if is_default:
                module.own_exports.add("default")
            else:
                module.own_exports.update(names)
                exported_declarations.update(names)
            continue
        value = statement.child_by_field_name("value")
        if is_default:
            module.own_exports.add("default")
            if (
                value is not None
                and value.type == "identifier"
                and not statement.has_error
            ):
                defaults.append((_text(source, value), statement.start_point[0] + 1))
            continue
        target_node = statement.child_by_field_name("source")
        target = _string_node_value(source, target_node)
        statement_type_only = any(child.type == "type" for child in statement.children)
        if statement.has_error:
            module.own_exports.add(_ALL)
            continue
        if target_node is not None:
            if target is None:
                module.own_exports.add(_ALL)
                continue
            _collect_reexport_statement(
                source, statement, target, statement_type_only, module
            )
            continue
        for specifier in _export_specifiers(statement):
            local, exported = _specifier_names(source, specifier)
            if local is None or exported is None:
                module.own_exports.add(_ALL)
                continue
            type_only = statement_type_only or is_type_only(specifier)
            local_exports[local].append(
                (exported, specifier.start_point[0] + 1, type_only)
            )
    for local, exports in local_exports.items():
        if local in bindings:
            specifier, binding = bindings[local]
            for exported, line, type_only in exports:
                _add_import_entry(module, exported, line, type_only, specifier, binding)
            continue
        names = _export_names(local, exports, exported_declarations)
        for exported, line, type_only in exports:
            if local in declared and exported != local and len(names) > 1:
                module.entries.append(
                    _Entry(exported, line, "alias", type_only=type_only, local=local)
                )
            else:
                module.own_exports.add(exported)
    for local, line in defaults:
        if local in bindings:
            specifier, binding = bindings[local]
            _add_import_entry(module, "default", line, False, specifier, binding)
            continue
        names = _export_names(
            local, local_exports.get(local, ()), exported_declarations
        )
        if local in declared and names:
            module.entries.append(_Entry("default", line, "alias", local=local))
    module.own_exports.update(
        entry.exported for entry in module.entries if entry.kind != "alias"
    )


def _export_names(local, exports, exported_declarations):
    names = {exported for exported, _line, _type_only in exports}
    if local in exported_declarations:
        names.add(local)
    return names


def _add_import_entry(module, exported, line, type_only, specifier, binding):
    if binding.kind == "namespace":
        module.entries.append(
            _Entry(exported, line, "namespace", target=specifier, type_only=type_only)
        )
        return
    module.entries.append(
        _Entry(
            exported,
            line,
            "named",
            target=specifier,
            original=binding.imported,
            type_only=type_only or binding.type_only,
        )
    )


def _collect_reexport_statement(source, statement, target, type_only, module):
    for child in statement.children:
        if child.type == "namespace_export":
            alias = next(
                (node for node in child.named_children if node.type == "identifier"),
                None,
            )
            if alias is None:
                module.own_exports.add(_ALL)
                continue
            module.entries.append(
                _Entry(
                    _text(source, alias),
                    alias.start_point[0] + 1,
                    "namespace",
                    target=target,
                    type_only=type_only,
                )
            )
        elif child.type == "*":
            following = child.next_named_sibling
            if following is not None and following.type == "identifier":
                module.entries.append(
                    _Entry(
                        _text(source, following),
                        following.start_point[0] + 1,
                        "namespace",
                        target=target,
                        type_only=type_only,
                    )
                )
            else:
                module.entries.append(
                    _Entry("*", statement.start_point[0] + 1, "star", target=target)
                )
        elif child.type == "export_clause":
            for specifier in child.named_children:
                if specifier.type != "export_specifier":
                    continue
                original, exported = _specifier_names(source, specifier)
                if original is None or exported is None:
                    module.own_exports.add(_ALL)
                    continue
                module.entries.append(
                    _Entry(
                        exported,
                        specifier.start_point[0] + 1,
                        "named",
                        target=target,
                        original=original,
                        type_only=type_only or is_type_only(specifier),
                    )
                )


def _export_specifiers(statement):
    for child in statement.named_children:
        if child.type == "export_clause":
            yield from (
                specifier
                for specifier in child.named_children
                if specifier.type == "export_specifier"
            )


def _specifier_names(source, specifier):
    name_node = specifier.child_by_field_name("name")
    alias_node = specifier.child_by_field_name("alias")
    original = _module_export_name(source, name_node)
    exported = _module_export_name(source, alias_node or name_node)
    return original, exported


def _module_export_name(source, node):
    if node is None:
        return None
    if node.type == "string":
        return _string_node_value(source, node)
    text = _text(source, node)
    if not text or "\\" in text:
        return None
    return text


def _declared_names(source, node):
    if node.type in _DECLARATION_TYPES:
        name = node.child_by_field_name("name")
        if name is not None:
            return {_text(source, name)}
        return set()
    if node.type == "ambient_declaration":
        names = set()
        for child in node.named_children:
            names.update(_declared_names(source, child))
        return names
    if node.type in {"lexical_declaration", "variable_declaration"}:
        names = set()
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            target = declarator.child_by_field_name("name")
            if target is not None:
                names.update(_pattern_names(source, target))
        return names
    return set()


def _pattern_names(source, node):
    if node.type == "identifier":
        return {_text(source, node)}
    names = set()
    for child in node.named_children:
        if child.type in {
            "identifier",
            "shorthand_property_identifier_pattern",
        }:
            names.add(_text(source, child))
        elif child.type not in {"property_identifier", "string", "number"}:
            names.update(_pattern_names(source, child))
    return names


def _is_commonjs_export(source, statement):
    text = _text(source, statement).lstrip()
    return text.startswith(("module.exports", "exports.", "exports["))


def _text(source, node):
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")
