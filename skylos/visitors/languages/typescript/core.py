from __future__ import annotations

import os
import re
from bisect import bisect_right
from pathlib import Path

import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser, Query, QueryCursor

from skylos.visitors.base import Definition
from skylos.visitors.languages.typescript.safe_glob import safe_glob_paths

try:
    TS_LANG: Language | None = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None

try:
    TSX_LANG: Language | None = Language(tsts.language_tsx())
except Exception:
    TSX_LANG = None

_LIFECYCLE_METHODS: set[str] = {
    "constructor",
    "render",
    "connectedCallback",
    "disconnectedCallback",
    "attributeChangedCallback",
    "componentDidMount",
    "componentWillUnmount",
    "componentDidUpdate",
    "shouldComponentUpdate",
    "getDerivedStateFromProps",
    "getDerivedStateFromError",
    "getSnapshotBeforeUpdate",
    "componentDidCatch",
    "ngOnInit",
    "ngOnDestroy",
    "ngOnChanges",
    "ngAfterViewInit",
}

_BUNDLER_PLUGIN_HOOK_METHODS: set[str] = {
    "buildEnd",
    "buildStart",
    "closeBundle",
    "closeWatcher",
    "configurePreviewServer",
    "configureServer",
    "generateBundle",
    "handleHotUpdate",
    "load",
    "moduleParsed",
    "options",
    "renderChunk",
    "renderError",
    "renderStart",
    "resolveDynamicImport",
    "resolveFileUrl",
    "resolveId",
    "transform",
    "watchChange",
    "writeBundle",
}

_ROUTE_ATTACHMENT_METHODS: set[str] = {
    "all",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "route",
    "use",
}

_QUERY_CACHE: dict[tuple[int, str], Query] = {}
_PARSER_CACHE: dict[int, Parser] = {}
_JSX_EXTENSIONS = {".tsx", ".jsx", ".js"}

_DEFS_PATTERN = """
(function_declaration name: (identifier) @func_def)
(class_declaration name: (type_identifier) @class_def)
(interface_declaration name: (type_identifier) @iface_def)
(enum_declaration name: (identifier) @enum_def)
(type_alias_declaration name: (type_identifier) @type_def)
(decorator (identifier) @dec_ident)
(decorator (call_expression function: (identifier) @dec_call))
(method_definition name: (property_identifier) @method_prop_def)
(variable_declarator name: (identifier) @var_def)
(import_statement source: (string) @import_src)
(export_statement source: (string) @export_src)
"""

_DEFS_TS_ONLY_PATTERN = "(method_definition name: (identifier) @method_ident_def)"

_REFS_PATTERN = """
(call_expression function: (identifier) @ref)
(new_expression constructor: (identifier) @ref)
(member_expression property: (property_identifier) @prop_ref)
(arguments (identifier) @ref)
(variable_declarator value: (identifier) @ref)
(array (identifier) @ref)
(return_statement (identifier) @ref)
(binary_expression right: (identifier) @ref)
(binary_expression left: (identifier) @ref)
(assignment_expression right: (identifier) @ref)
(assignment_pattern right: (identifier) @ref)
(update_expression (identifier) @ref)
(spread_element (identifier) @ref)
(member_expression object: (identifier) @ref)
(subscript_expression object: (identifier) @ref)
(subscript_expression index: (identifier) @ref)
(pair value: (identifier) @ref)
(unary_expression (identifier) @ref)
(await_expression (identifier) @ref)
(template_substitution (identifier) @ref)
(for_in_statement right: (identifier) @ref)
(computed_property_name (identifier) @ref)
(augmented_assignment_expression left: (identifier) @ref)
(augmented_assignment_expression right: (identifier) @ref)
(type_query (identifier) @ref)
(nested_type_identifier module: (identifier) @ref)
(public_field_definition value: (identifier) @ref)
(shorthand_property_identifier) @ref
(decorator (identifier) @ref)
(decorator (call_expression function: (identifier) @ref))
(export_specifier name: (identifier) @ref)
(extends_clause (identifier) @ref)
(ternary_expression consequence: (identifier) @ref)
(ternary_expression alternative: (identifier) @ref)
(as_expression (identifier) @ref)
(satisfies_expression (identifier) @ref)
(type_identifier) @type_ref
"""

_REFS_JSX_PATTERN = """
(jsx_expression (identifier) @ref)
(jsx_opening_element name: (identifier) @ref (#match? @ref "^[A-Z]"))
(jsx_self_closing_element name: (identifier) @ref (#match? @ref "^[A-Z]"))
"""

_IMPORTS_PATTERN = """
(import_clause (named_imports (import_specifier name: (identifier) @import_name)))
(import_clause (identifier) @import_name)
(import_clause (namespace_import (identifier) @import_name))
"""

_RAW_IMPORT_FILE_EXTENSIONS = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"}
)
_DYNAMIC_GLOB_METHODS = frozenset({"glob", "globEager"})
_JSDOC_EXTENSIONS = frozenset({".js", ".jsx", ".mjs", ".cjs"})
_JSDOC_TYPE_TAG_RE = re.compile(
    r"@(?:arg|argument|enum|exception|param|prop|property|return|returns|"
    r"satisfies|template|this|throws|type|typedef)\b"
)
_JSDOC_TAG_RE = re.compile(
    r"(?:(?<=/\*\*)|(?<=\s))(?P<tag>@[A-Za-z][\w-]*)"
)
_JSDOC_LINK_TAG_RE = re.compile(r"\{@(?:link|linkcode|linkplain)\b")
_JSDOC_IMPORT_TYPE_RE = re.compile(
    r"(?:[\s({\[<>|&,:?!]|(?<=\.\.\.)|^)"
    r"(?P<keyword>import)\s*\(\s*(?P<quote>['\"])"
    r"(?P<source>[^'\"\r\n]+)(?P=quote)\s*\)"
    r"(?:\s*\.\s*(?P<dot_name>[A-Za-z_$][\w$]*)|"
    r"\s*\[\s*(?P<member_quote>['\"])(?P<bracket_name>[A-Za-z_$][\w$]*)"
    r"(?P=member_quote)\s*\])?"
)
_JSDOC_IMPORT_TAG_BODY_RE = re.compile(
    r"\s+(?:(?P<compound>(?:[A-Za-z_$][\w$]*\s*,\s*)?"
    r"(?:\{[^{}]*\}|\*\s+as\s+[A-Za-z_$][\w$]*))"
    r"\s+from|(?P<default>[A-Za-z_$][\w$]*)[^\S\r\n]+from)"
    r"[^\S\r\n]*(?P<quote>['\"])"
    r"(?P<source>[^'\"\r\n]+)(?P=quote)"
)
_JSDOC_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_JSDOC_NAME_BEFORE_TYPE_RE = re.compile(
    r"(?:\.\.\.)?(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|"
    r"\[[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\])"
)
_JSDOC_NAME_FIRST_TYPE_TAGS = frozenset(
    {"@arg", "@argument", "@param", "@prop", "@property"}
)


def _get_query(lang: Language, key: str, pattern: str) -> Query | None:
    cache_key = (id(lang), key)
    if cache_key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[cache_key] = Query(lang, pattern)
        except Exception:
            _QUERY_CACHE[cache_key] = None
    return _QUERY_CACHE[cache_key]


def _get_parser(lang: Language) -> Parser:
    lang_id = id(lang)
    if lang_id not in _PARSER_CACHE:
        _PARSER_CACHE[lang_id] = Parser(lang)
    return _PARSER_CACHE[lang_id]


class TypeScriptCore:
    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.imports: list[dict[str, str | int]] = []
        self._self_ref_index: (
            dict[str, tuple[tuple[int, ...], tuple[int, ...]]] | None
        ) = None

        self._suffix = Path(str(file_path)).suffix.lower()
        self._uses_jsx_parser = self._suffix in _JSX_EXTENSIONS
        self._is_declaration_file = str(file_path).endswith(".d.ts")

        if self._uses_jsx_parser and TSX_LANG:
            self.lang: Language | None = TSX_LANG
        else:
            self.lang = TS_LANG

        if self.lang:
            self.parser = _get_parser(self.lang)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8")

    def _run_batch(self, key: str, pattern: str) -> dict[str, list]:
        if not self.root_node or not self.lang:
            return {}
        query = _get_query(self.lang, key, pattern)
        if query is None:
            return {}
        try:
            cursor = QueryCursor(query)
            return cursor.captures(self.root_node)
        except Exception:
            return {}

    _SELF_REF_CONTAINERS: set[str] = {
        "function_declaration",
        "class_declaration",
        "type_alias_declaration",
        "interface_declaration",
        "enum_declaration",
        "variable_declarator",
    }

    def _is_self_ref(self, node, name: str) -> bool:
        if self._self_ref_index is None:
            spans_by_name: dict[str, list[tuple[int, int]]] = {}
            if self.root_node is not None:
                for candidate in self._iter_nodes(self.root_node):
                    if candidate.type not in self._SELF_REF_CONTAINERS:
                        continue
                    name_node = candidate.child_by_field_name("name")
                    if name_node is None:
                        continue
                    spans_by_name.setdefault(self._get_text(name_node), []).append(
                        (candidate.start_byte, candidate.end_byte)
                    )

            self._self_ref_index = {}
            for container_name, spans in spans_by_name.items():
                starts: list[int] = []
                prefix_max_ends: list[int] = []
                max_end = -1
                for start, end in sorted(spans):
                    starts.append(start)
                    max_end = max(max_end, end)
                    prefix_max_ends.append(max_end)
                self._self_ref_index[container_name] = (
                    tuple(starts),
                    tuple(prefix_max_ends),
                )

        indexed = self._self_ref_index.get(name)
        if indexed is None:
            return False
        starts, prefix_max_ends = indexed
        position = bisect_right(starts, node.start_byte) - 1
        return position >= 0 and prefix_max_ends[position] >= node.end_byte

    def _add_ref(self, node) -> None:
        name = self._get_text(node)
        if self._is_self_ref(node, name):
            return
        self.refs.append((name, self.file_path))

    def _add_ref_forced(self, node) -> None:
        self.refs.append((self._get_text(node), self.file_path))

    def scan(self) -> None:
        if not self.root_node:
            self.raw_imports: list[dict] = []
            return

        self._defs_captures = self._run_batch("defs", _DEFS_PATTERN)
        ts_only = self._run_batch("defs_ts_only", _DEFS_TS_ONLY_PATTERN)
        for k, v in ts_only.items():
            self._defs_captures.setdefault(k, []).extend(v)
        self._refs_captures = self._run_batch("refs", _REFS_PATTERN)
        if self._uses_jsx_parser:
            jsx_refs = self._run_batch("refs_jsx", _REFS_JSX_PATTERN)
            for k, v in jsx_refs.items():
                self._refs_captures.setdefault(k, []).extend(v)
        self._imports_captures = self._run_batch("imports", _IMPORTS_PATTERN)

        self._scan_defs()
        self._scan_refs()
        self._scan_imports()
        self._scan_raw_imports()
        self._build_call_graph()

    def _scan_defs(self) -> None:
        c = self._defs_captures

        for node in c.get("func_def", []):
            self._add_def(node, "function")

        for node in c.get("class_def", []):
            self._add_def(node, "class")

        for node in c.get("iface_def", []):
            self._add_def(node, "class", extra_signal="type-only declaration")

        for node in c.get("enum_def", []):
            self._add_def(node, "class")

        for node in c.get("type_def", []):
            self._add_def(node, "class", extra_signal="type-only declaration")

        for node in c.get("dec_ident", []):
            class_node = node.parent
            if class_node:
                class_node = class_node.parent
            if class_node and class_node.type == "class_declaration":
                name_node = class_node.child_by_field_name("name")
                if name_node:
                    self._add_ref_forced(name_node)

        for node in c.get("dec_call", []):
            decorator_node = node.parent  # call_expression
            if decorator_node:
                decorator_node = decorator_node.parent  # decorator
            if decorator_node:
                class_node = decorator_node.parent  # class_declaration
            else:
                class_node = None
            if class_node and class_node.type == "class_declaration":
                name_node = class_node.child_by_field_name("name")
                if name_node:
                    self._add_ref_forced(name_node)

        for node in c.get("method_prop_def", []):
            self._add_def(node, "method")
        for node in c.get("method_ident_def", []):
            self._add_def(node, "method")

        for node in c.get("var_def", []):
            var_decl = node.parent  # variable_declarator
            if var_decl:
                value_node = var_decl.child_by_field_name("value")
            else:
                value_node = None
            is_arrow = value_node and value_node.type == "arrow_function"
            if is_arrow:
                self._add_def(node, "function")
            elif self._is_top_level(node):
                self._add_def(node, "variable")

    _TYPE_DEF_PARENTS: set[str] = {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "type_alias_declaration",
    }

    def _scan_refs(self) -> None:
        c = self._refs_captures

        for node in c.get("ref", []):
            self._add_ref(node)

        # `x.foo` / `x[k].foo()` — emit the plain name (so functions/exports
        # attached as properties still resolve) AND a `~.` marker so the
        # analyzer also credits same-named methods on any class, since the
        # receiver type is unknown and dispatch may reach any of them.
        for node in c.get("prop_ref", []):
            name = self._get_text(node)
            if self._is_self_ref(node, name):
                continue
            self.refs.append((name, self.file_path))
            self.refs.append((f"~.{name}", self.file_path))

        for node in c.get("type_ref", []):
            parent = node.parent
            if parent and parent.type in self._TYPE_DEF_PARENTS:
                continue
            self._add_ref(node)

        self._scan_default_parameter_refs()

    def _scan_default_parameter_refs(self) -> None:
        if not self.root_node:
            return
        for node in self._iter_nodes(self.root_node):
            if node.type != "required_parameter":
                continue
            seen_default = False
            for child in node.children:
                if child.type == "=":
                    seen_default = True
                    continue
                if seen_default and child.type == "identifier":
                    self._add_ref(child)

    def _find_containing_class(self, node) -> str | None:
        current = node.parent
        while current:
            if current.type == "class_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return self._get_text(name_node)
            current = current.parent
        return None

    def _has_deprecated_jsdoc(self, node) -> bool:
        current = node
        while current.parent and current.parent.type != "program":
            current = current.parent
        sibling = current.prev_named_sibling
        if sibling is not None and sibling.type == "comment":
            return "@deprecated" in self._get_text(sibling)
        return False

    def _should_skip_method_def(self, node, name: str) -> bool:
        object_node = self._containing_object_literal(node)
        if object_node is not None:
            return not (
                self._is_bundler_plugin_object(object_node)
                and name not in _BUNDLER_PLUGIN_HOOK_METHODS
            )
        return name in _LIFECYCLE_METHODS or name in _BUNDLER_PLUGIN_HOOK_METHODS

    def _qualified_method_name(self, node, name: str) -> str:
        class_name = self._find_containing_class(node)
        if class_name:
            return f"{class_name}.{name}"
        return name

    def _add_def(self, node, type_name: str, extra_signal: str | None = None) -> None:
        name = self._get_text(node)

        if type_name == "method":
            if self._should_skip_method_def(node, name):
                return
            name = self._qualified_method_name(node, name)

        line = node.start_point[0] + 1

        is_ambient = self._is_ambient_declaration(node)
        is_exported = self._is_exported(node) or self._is_declaration_file or is_ambient

        d = Definition(name, type_name, self.file_path, line)
        d.is_exported = is_exported
        if self._is_declaration_file or is_ambient:
            d.framework_signals.append("ambient declaration")
        if extra_signal:
            d.framework_signals.append(extra_signal)
        if is_exported and self._has_deprecated_jsdoc(node):
            d.framework_signals.append("deprecated export")
        if (
            type_name == "function"
            and d.is_exported
            and self._is_route_attachment_function(node)
        ):
            d.references = max(d.references, 1)
            d.framework_signals.append("route attachment export")
        self.defs.append(d)

    def _is_route_attachment_function(self, name_node) -> bool:
        parameters, body = self._function_signature_and_body(name_node)
        if parameters is None or body is None:
            return False

        param_names = self._collect_parameter_names(parameters)
        if not param_names:
            return False

        for call_node in self._iter_nodes(body):
            if call_node.type != "call_expression":
                continue
            function_node = call_node.child_by_field_name("function")
            if function_node is None or function_node.type != "member_expression":
                continue
            object_node = function_node.child_by_field_name("object")
            property_node = function_node.child_by_field_name("property")
            if object_node is None or property_node is None:
                continue
            if self._get_text(object_node) not in param_names:
                continue
            if self._looks_like_route_registration_call(call_node, property_node):
                return True

        return False

    def _function_signature_and_body(self, name_node):
        declaration = name_node.parent
        while declaration:
            if declaration.type == "function_declaration":
                return (
                    declaration.child_by_field_name("parameters"),
                    declaration.child_by_field_name("body"),
                )
            if declaration.type == "variable_declarator":
                value_node = declaration.child_by_field_name("value")
                if value_node and value_node.type == "arrow_function":
                    parameters = value_node.child_by_field_name("parameters")
                    body = value_node.child_by_field_name("body")
                    if parameters is None:
                        for child in value_node.named_children:
                            if child is body:
                                break
                            if child.type in {
                                "identifier",
                                "required_parameter",
                                "formal_parameters",
                            }:
                                parameters = child
                                break
                    return parameters, body
                return None, None
            if declaration.type in {
                "program",
                "class_declaration",
                "method_definition",
            }:
                return None, None
            declaration = declaration.parent
        return None, None

    def _looks_like_route_registration_call(self, call_node, property_node) -> bool:
        method_name = self._get_text(property_node)
        if method_name not in _ROUTE_ATTACHMENT_METHODS:
            return False

        arguments = call_node.child_by_field_name("arguments")
        if arguments is None:
            return False
        args = list(arguments.named_children)
        if not args:
            return False

        first_arg = args[0]
        if first_arg.type == "string":
            route = self._string_literal_value(first_arg) or ""
            return route.startswith("/")

        first_name = self._get_text(first_arg).lower()
        if first_name in {"path", "route", "routepath", "url", "pattern"}:
            return len(args) >= 2

        return False

    def _collect_parameter_names(self, parameters_node) -> set[str]:
        names: set[str] = set()
        stack = [parameters_node]
        while stack:
            node = stack.pop()
            if node.type == "identifier":
                names.add(self._get_text(node))
                continue
            stack.extend(node.named_children)
        return names

    def _is_top_level(self, node) -> bool:
        current = node.parent
        while current:
            if current.type == "program":
                return True
            if current.type in (
                "export_statement",
                "lexical_declaration",
                "variable_declarator",
            ):
                current = current.parent
                continue
            return False
        return False

    def _containing_object_literal(self, node):
        current = node.parent
        while current:
            if current.type == "object":
                return current
            if current.type in {"class_body", "class_declaration", "program"}:
                return None
            current = current.parent
        return None

    def _is_bundler_plugin_object(self, object_node) -> bool:
        has_name = False
        has_hook = False

        for child in object_node.named_children:
            if child.type == "pair" and self._pair_has_string_name(child):
                has_name = True
            elif child.type == "method_definition":
                name_node = child.child_by_field_name("name")
                if (
                    name_node
                    and self._get_text(name_node) in _BUNDLER_PLUGIN_HOOK_METHODS
                ):
                    has_hook = True

            if has_name and has_hook:
                return True

        return False

    def _pair_has_string_name(self, pair_node) -> bool:
        if len(pair_node.named_children) < 2:
            return False

        key_node = pair_node.named_children[0]
        value_node = pair_node.named_children[1]
        if key_node.type not in {"property_identifier", "identifier", "string"}:
            return False

        raw_key = self._get_text(key_node)
        key = raw_key.strip("'\"")
        return key == "name" and value_node.type == "string"

    def _is_exported(self, node) -> bool:
        try:
            current = node.parent
            for _ in range(4):
                if current is None:
                    break
                if "export" in current.type:
                    return True
                current = current.parent
        except Exception:
            pass
        return False

    def _is_ambient_declaration(self, node) -> bool:
        current = node.parent
        while current:
            if current.type == "ambient_declaration":
                return True
            if current.type == "program":
                return False
            current = current.parent
        return False

    def _scan_imports(self) -> None:
        c = self._imports_captures

        for node in c.get("import_name", []):
            if self._is_aliased_import_original(node):
                continue
            name = self._get_text(node)
            line = node.start_point[0] + 1
            d = Definition(name, "import", self.file_path, line)
            self.defs.append(d)
            self.imports.append(
                {"name": name, "file": str(self.file_path), "line": line}
            )
        self._scan_aliased_imports()

    def _is_aliased_import_original(self, node) -> bool:
        parent = node.parent
        if parent is None or parent.type != "import_specifier":
            return False
        identifiers = [child for child in parent.children if child.type == "identifier"]
        return len(identifiers) >= 2 and identifiers[0] == node

    def _scan_aliased_imports(self) -> None:
        if not self.root_node:
            return
        for node in self._iter_nodes(self.root_node):
            if node.type != "import_specifier":
                continue
            identifiers = [
                child for child in node.children if child.type == "identifier"
            ]
            if len(identifiers) < 2:
                continue
            alias_node = identifiers[-1]
            name = self._get_text(alias_node)
            line = alias_node.start_point[0] + 1
            d = Definition(name, "import", self.file_path, line)
            self.defs.append(d)
            self.imports.append(
                {"name": name, "file": str(self.file_path), "line": line}
            )

    def _scan_raw_imports(self) -> None:
        self.raw_imports: list[dict] = []
        self._raw_import_seen: set[tuple] = set()
        c = self._defs_captures

        for src_node in c.get("import_src", []):
            source_path = self._get_text(src_node).strip("'\"")
            import_stmt = src_node.parent
            if import_stmt:
                names = self._extract_import_names_from_stmt(import_stmt)
                raw_import = {
                    "source": source_path,
                    "names": names,
                    "line": src_node.start_point[0] + 1,
                }
                if any(name.startswith("* as ") for name in names):
                    raw_import["consume_all_exports"] = True
                self.raw_imports.append(raw_import)

        for src_node in c.get("export_src", []):
            source_path = self._get_text(src_node).strip("'\"")
            export_stmt = src_node.parent
            if export_stmt:
                names = self._extract_export_names_from_stmt(export_stmt)
                self.raw_imports.append(
                    {
                        "source": source_path,
                        "names": names,
                        "line": src_node.start_point[0] + 1,
                    }
                )

        self._scan_dynamic_raw_imports()
        self._scan_jsdoc_raw_imports()

    def _extract_import_names_from_stmt(self, import_stmt) -> list[str]:
        names = []
        for child in import_stmt.children:
            if child.type == "import_clause":
                for clause_child in child.children:
                    if clause_child.type == "named_imports":
                        for spec in clause_child.children:
                            if spec.type == "import_specifier":
                                name_node = spec.child_by_field_name("name")
                                alias_node = spec.child_by_field_name("alias")
                                if name_node:
                                    name_text = self._get_text(name_node)
                                    if alias_node:
                                        alias_text = self._get_text(alias_node)
                                        names.append(f"{name_text} as {alias_text}")
                                    else:
                                        names.append(name_text)
                    elif clause_child.type == "identifier":
                        names.append(self._get_text(clause_child))
                    elif clause_child.type == "namespace_import":
                        alias_node = next(
                            (
                                ns_child
                                for ns_child in clause_child.children
                                if ns_child.type == "identifier"
                            ),
                            None,
                        )
                        if alias_node is not None:
                            names.append(f"* as {self._get_text(alias_node)}")
                        else:
                            names.append("*")
        return names

    def _extract_export_names_from_stmt(self, export_stmt) -> list[str]:
        names = []
        for child in export_stmt.children:
            if child.type == "export_clause":
                for spec in child.children:
                    if spec.type == "export_specifier":
                        name_node = spec.child_by_field_name("name")
                        alias_node = spec.child_by_field_name("alias")
                        if name_node:
                            name_text = self._get_text(name_node)
                            if alias_node:
                                alias_text = self._get_text(alias_node)
                                names.append(f"{name_text} as {alias_text}")
                            else:
                                names.append(name_text)
            elif child.type == "*":
                next_sib = child.next_named_sibling
                if next_sib and next_sib.type == "identifier":
                    names.append(f"* as {self._get_text(next_sib)}")
                else:
                    names.append("*")
        return names if names else ["*"]

    def _iter_nodes(self, root_node):
        stack = [root_node]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    def _string_literal_value(self, node) -> str | None:
        if node is None or node.type != "string":
            return None
        return self._get_text(node).strip("'\"")

    def _append_raw_import(
        self,
        source_path: str,
        line: int,
        consume_all_exports: bool = False,
        *,
        names: list[str] | None = None,
        type_only: bool = False,
    ) -> None:
        import_names = ["*"] if names is None else list(names)
        key = (
            source_path,
            line,
            consume_all_exports,
            tuple(import_names),
            type_only,
        )
        if key in self._raw_import_seen:
            return
        self._raw_import_seen.add(key)
        raw_import = {
            "source": source_path,
            "names": import_names,
            "line": line,
        }
        if consume_all_exports:
            raw_import["consume_all_exports"] = True
        if type_only:
            raw_import["type_only"] = True
        self.raw_imports.append(raw_import)

    @staticmethod
    def _jsdoc_balanced_ranges(
        comment: str, opening_brace: int, *, stop_at_tag: bool = False
    ) -> tuple[int, list[tuple[int, int]]] | None:
        """Return a balanced type/link end and its unquoted content ranges."""
        depth = 0
        quote: str | None = None
        escaped = False
        range_start: int | None = None
        ranges: list[tuple[int, int]] = []
        template_expression_depths: list[int] = []
        cursor = opening_brace

        while cursor < len(comment):
            char = comment[cursor]
            if escaped:
                escaped = False
                cursor += 1
                continue
            if quote is not None:
                if char == "\\":
                    escaped = True
                elif (
                    quote == "`"
                    and char == "$"
                    and cursor + 1 < len(comment)
                    and comment[cursor + 1] == "{"
                ):
                    depth += 1
                    template_expression_depths.append(depth)
                    quote = None
                    range_start = cursor + 2
                    cursor += 2
                    continue
                elif char == quote:
                    quote = None
                    if depth:
                        range_start = cursor + 1
                cursor += 1
                continue
            if (
                stop_at_tag
                and cursor > opening_brace
                and char == "@"
                and _JSDOC_TAG_RE.match(comment, cursor) is not None
            ):
                return None
            if depth and char in {"'", '"', "`"}:
                if range_start is not None and range_start < cursor:
                    ranges.append((range_start, cursor))
                range_start = None
                quote = char
                cursor += 1
                continue
            if char == "{":
                if depth == 0:
                    range_start = cursor + 1
                depth += 1
                cursor += 1
                continue
            if char != "}" or not depth:
                cursor += 1
                continue
            if template_expression_depths and depth == template_expression_depths[-1]:
                if range_start is not None and range_start < cursor:
                    ranges.append((range_start, cursor))
                template_expression_depths.pop()
                depth -= 1
                quote = "`"
                range_start = None
                cursor += 1
                continue
            depth -= 1
            if depth:
                cursor += 1
                continue
            if range_start is not None and range_start < cursor:
                ranges.append((range_start, cursor))
            return cursor + 1, ranges
        if quote == "`":
            return -1, []
        return None

    @classmethod
    def _jsdoc_tags_and_type_ranges(
        cls, comment: str, *, original_comment: str | None = None
    ):
        """Parse JSDoc tags once, skipping tokens inside types and links."""
        tags = []
        type_ranges: list[tuple[int, int]] = []
        search_position = 0
        seen_typedef = False
        original_comment = original_comment or comment
        newline_offsets = [
            match.start() for match in re.finditer("\n", comment)
        ]
        all_tags = list(_JSDOC_TAG_RE.finditer(comment))
        links = list(_JSDOC_LINK_TAG_RE.finditer(comment))
        tag_index = 0
        link_index = 0

        while search_position < len(comment):
            while (
                tag_index < len(all_tags)
                and all_tags[tag_index].start("tag") < search_position
            ):
                tag_index += 1
            while (
                link_index < len(links)
                and links[link_index].start() < search_position
            ):
                link_index += 1
            tag = all_tags[tag_index] if tag_index < len(all_tags) else None
            link = links[link_index] if link_index < len(links) else None
            if link is not None and (
                tag is None or link.start() < tag.start("tag")
            ):
                balanced_link = cls._jsdoc_balanced_ranges(comment, link.start())
                if balanced_link is None:
                    break
                if balanced_link[0] < 0:
                    break
                search_position = balanced_link[0]
                link_index += 1
                continue
            if tag is None:
                break

            tag_index += 1
            tags.append(tag)
            tag_name = tag.group("tag")
            tag_end = tag.end("tag")
            if tag_name == "@typedef":
                seen_typedef = True
            if _JSDOC_TYPE_TAG_RE.fullmatch(tag_name) is None:
                search_position = tag_end
                continue
            if tag_name in {"@prop", "@property"} and not seen_typedef:
                search_position = tag_end
                continue

            position = tag_end
            while position < len(comment) and comment[position].isspace():
                position += 1
            if (
                tag_name in _JSDOC_NAME_FIRST_TYPE_TAGS
                and position < len(comment)
                and comment[position] != "{"
            ):
                name_match = _JSDOC_NAME_BEFORE_TYPE_RE.match(comment, position)
                if name_match is None:
                    search_position = tag_end
                    continue
                position = name_match.end()
                while position < len(comment) and comment[position].isspace():
                    position += 1
            if position >= len(comment) or comment[position] != "{":
                search_position = tag_end
                continue
            newline_index = bisect_right(newline_offsets, position)
            line_end = (
                newline_offsets[newline_index]
                if newline_index < len(newline_offsets)
                else len(comment)
            )
            if not comment[position + 1 : line_end].strip():
                next_line_start = line_end + 1
                next_line_end = (
                    newline_offsets[newline_index + 1]
                    if newline_index + 1 < len(newline_offsets)
                    else len(comment)
                )
                next_line = original_comment[next_line_start:next_line_end]
                if re.match(r"[^\S\r\n]*\*", next_line):
                    search_position = tag_end
                    continue

            balanced_type = cls._jsdoc_balanced_ranges(
                comment, position, stop_at_tag=True
            )
            if balanced_type is None:
                search_position = tag_end
                continue
            if balanced_type[0] < 0:
                break
            type_end, unquoted_ranges = balanced_type
            type_ranges.extend(unquoted_ranges)
            search_position = type_end

        return tags, type_ranges

    @staticmethod
    def _parse_jsdoc_import_tag_clause(
        clause: str, *, original_clause: str | None = None
    ) -> tuple[list[str], bool] | None:
        """Return imported names and whether the clause consumes the namespace."""
        clause = clause.strip()
        names: list[str] = []
        if not clause.startswith(("{", "*")):
            if "," not in clause:
                if _JSDOC_IDENTIFIER_RE.fullmatch(clause) is None:
                    return None
                return ["default"], False
            default_name, remainder = clause.split(",", 1)
            if _JSDOC_IDENTIFIER_RE.fullmatch(default_name.strip()) is None:
                return None
            default_identifier = re.match(r"[A-Za-z_$][\w$]*", clause)
            if default_identifier is None:
                return None
            remainder_start = clause.index(",") + 1
            while remainder_start < len(clause) and clause[remainder_start].isspace():
                remainder_start += 1
            if original_clause is not None and "*" in original_clause[
                default_identifier.end() : remainder_start
            ]:
                return None
            names.append("default")
            clause = remainder.strip()

        if clause.startswith("*"):
            namespace = re.fullmatch(
                r"\*\s+as\s+[A-Za-z_$][\w$]*", clause
            )
            return (names, True) if namespace is not None else None
        if not (clause.startswith("{") and clause.endswith("}")):
            return None

        contents = clause[1:-1].strip()
        if not contents:
            return names, False
        raw_names = contents.split(",")
        if raw_names[-1].strip() == "":
            raw_names.pop()
        for raw_name in raw_names:
            imported_name = raw_name.strip()
            specifier = re.fullmatch(
                r"(?:type\s+)?(?P<name>[A-Za-z_$][\w$]*)"
                r"(?:\s+as\s+[A-Za-z_$][\w$]*)?",
                imported_name,
            )
            if specifier is None:
                return None
            names.append(specifier.group("name"))
        return names, False

    def _scan_jsdoc_raw_imports(self) -> None:
        if self._suffix not in _JSDOC_EXTENSIONS or not self.root_node:
            return

        for node in self._iter_nodes(self.root_node):
            if node.type != "comment":
                continue
            comment = self._get_text(node)
            if not comment.startswith("/**"):
                continue

            # Preserve offsets while removing the decorative `*` margin so an
            # official multiline `@import { ... } from ...` tag can be parsed.
            normalized_comment = re.sub(
                r"(?m)^(?P<indent>[^\S\r\n]*)\*(?P<space>[^\S\r\n]?)",
                lambda match: " " * len(match.group(0)),
                comment,
            )
            tags, type_ranges = self._jsdoc_tags_and_type_ranges(
                normalized_comment, original_comment=comment
            )
            range_index = 0
            newline_offsets = [
                match.start() for match in re.finditer("\n", comment)
            ]
            for match in _JSDOC_IMPORT_TYPE_RE.finditer(normalized_comment):
                while (
                    range_index < len(type_ranges)
                    and type_ranges[range_index][1] <= match.start()
                ):
                    range_index += 1
                if (
                    range_index >= len(type_ranges)
                    or not type_ranges[range_index][0]
                    <= match.start("keyword")
                    < type_ranges[range_index][1]
                ):
                    continue
                member_name = match.group("dot_name") or match.group("bracket_name")
                line = (
                    node.start_point[0]
                    + bisect_right(newline_offsets, match.start("keyword"))
                    + 1
                )
                self._append_raw_import(
                    match.group("source"),
                    line,
                    consume_all_exports=member_name is None,
                    names=[member_name] if member_name else [],
                    type_only=True,
                )

            for tag in tags:
                if tag.group("tag") != "@import":
                    continue
                match = _JSDOC_IMPORT_TAG_BODY_RE.match(
                    normalized_comment, tag.end("tag")
                )
                if match is None:
                    continue
                group_name = "compound" if match.group("compound") else "default"
                clause = match.group(group_name)
                clause_start, clause_end = match.span(group_name)
                parsed_clause = self._parse_jsdoc_import_tag_clause(
                    clause,
                    original_clause=comment[clause_start:clause_end],
                )
                if parsed_clause is None:
                    continue
                names, consume_all_exports = parsed_clause
                line = (
                    node.start_point[0]
                    + bisect_right(newline_offsets, tag.start("tag"))
                    + 1
                )
                self._append_raw_import(
                    match.group("source"),
                    line,
                    consume_all_exports=consume_all_exports,
                    names=names,
                    type_only=True,
                )

    def _relative_source_for_match(self, matched_path: str) -> str:
        relative = os.path.relpath(matched_path, os.path.dirname(self.file_path))
        normalized = relative.replace(os.sep, "/")
        if normalized.startswith("."):
            return normalized
        return f"./{normalized}"

    def _string_sources_from_node(self, node) -> list[str]:
        if node is None:
            return []
        if node.type == "string":
            value = self._string_literal_value(node)
            return [value] if value else []
        if node.type == "array":
            sources: list[str] = []
            for child in node.named_children:
                value = self._string_literal_value(child)
                if value:
                    sources.append(value)
            return sources
        return []

    def _glob_import_sources(self, node) -> list[str]:
        matches: list[str] = []
        for pattern in self._string_sources_from_node(node):
            if not pattern:
                continue
            base_dir = os.path.dirname(self.file_path)
            for matched in safe_glob_paths(
                base_dir,
                pattern,
                allowed_suffixes=_RAW_IMPORT_FILE_EXTENSIONS,
            ):
                matches.append(
                    self._relative_source_for_match(os.path.realpath(matched))
                )
        return matches

    def _scan_dynamic_raw_imports(self) -> None:
        if not self.root_node:
            return

        for node in self._iter_nodes(self.root_node):
            if node.type != "call_expression":
                continue

            function_node = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")
            if function_node is None or arguments_node is None:
                continue
            if not arguments_node.named_children:
                continue

            first_arg = arguments_node.named_children[0]
            line = node.start_point[0] + 1

            if function_node.type == "import":
                for source_path in self._string_sources_from_node(first_arg):
                    self._append_raw_import(source_path, line, consume_all_exports=True)
                continue

            if (
                function_node.type == "identifier"
                and self._get_text(function_node) == "require"
            ):
                for source_path in self._string_sources_from_node(first_arg):
                    self._append_raw_import(source_path, line, consume_all_exports=True)
                continue

            if function_node.type != "member_expression":
                continue

            object_node = function_node.child_by_field_name("object")
            property_node = function_node.child_by_field_name("property")
            if object_node is None or property_node is None:
                continue

            property_name = self._get_text(property_node)

            if (
                object_node.type == "identifier"
                and self._get_text(object_node) == "require"
                and property_name == "resolve"
            ):
                for source_path in self._string_sources_from_node(first_arg):
                    self._append_raw_import(source_path, line, consume_all_exports=True)
                continue

            if object_node.type != "meta_property":
                continue
            if self._get_text(object_node) != "import.meta":
                continue

            if property_name == "resolve":
                for source_path in self._string_sources_from_node(first_arg):
                    self._append_raw_import(source_path, line, consume_all_exports=True)
                continue

            if property_name in _DYNAMIC_GLOB_METHODS:
                for source_path in self._glob_import_sources(first_arg):
                    self._append_raw_import(source_path, line, consume_all_exports=True)

    def _build_call_graph(self) -> None:
        self.call_pairs: list[tuple[str, str]] = []
        c = self._defs_captures

        for name_node in c.get("func_def", []):
            caller_name = self._get_text(name_node)
            func_node = name_node.parent
            if func_node:
                body = func_node.child_by_field_name("body")
                if body:
                    self._collect_calls_in_body(caller_name, body)

        for name_node in c.get("var_def", []):
            var_decl = name_node.parent
            if var_decl:
                value = var_decl.child_by_field_name("value")
                if value and value.type == "arrow_function":
                    caller_name = self._get_text(name_node)
                    body = value.child_by_field_name("body")
                    if body:
                        self._collect_calls_in_body(caller_name, body)

        for name_node in c.get("method_prop_def", []):
            method_name = self._get_text(name_node)
            class_name = self._find_containing_class(name_node)
            if class_name:
                caller_name = f"{class_name}.{method_name}"
            else:
                caller_name = method_name
            method_node = name_node.parent
            if method_node:
                body = method_node.child_by_field_name("body")
                if body:
                    self._collect_calls_in_body(caller_name, body)

        name_to_def: dict[str, Definition] = {}
        for d in self.defs:
            name_to_def[d.name] = d
            if d.simple_name not in name_to_def:
                name_to_def[d.simple_name] = d

        for caller, callee in self.call_pairs:
            caller_def = name_to_def.get(caller)
            callee_def = name_to_def.get(callee)
            if caller_def and callee_def and caller_def is not callee_def:
                caller_def.calls.add(callee_def.name)
                callee_def.called_by.add(caller_def.name)

    def _collect_calls_in_body(self, caller: str, body_node) -> None:
        stack = [body_node]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                func = node.child_by_field_name("function")
                if func:
                    if func.type == "identifier":
                        self.call_pairs.append((caller, self._get_text(func)))
                    elif func.type == "member_expression":
                        prop = func.child_by_field_name("property")
                        obj = func.child_by_field_name("object")
                        if prop:
                            if obj and self._get_text(obj) == "this":
                                class_name = self._find_containing_class(node)
                                if class_name:
                                    self.call_pairs.append(
                                        (caller, f"{class_name}.{self._get_text(prop)}")
                                    )
                            self.call_pairs.append((caller, self._get_text(prop)))
            for child in node.children:
                stack.append(child)
