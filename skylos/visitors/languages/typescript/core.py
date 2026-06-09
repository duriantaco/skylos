from __future__ import annotations

import os
from pathlib import Path

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_typescript as tsts
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
(member_expression property: (property_identifier) @ref)
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
        current = node.parent
        while current:
            if current.type in self._SELF_REF_CONTAINERS:
                name_node = current.child_by_field_name("name")
                if name_node and self._get_text(name_node) == name:
                    return True
            current = current.parent
        return False

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
            self._add_def(node, "class")

        for node in c.get("enum_def", []):
            self._add_def(node, "class")

        for node in c.get("type_def", []):
            self._add_def(node, "class")

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

    def _add_def(self, node, type_name: str) -> None:
        name = self._get_text(node)

        if type_name == "method":
            if self._is_object_literal_method(node):
                return
            if name in _LIFECYCLE_METHODS:
                return
            if name in _BUNDLER_PLUGIN_HOOK_METHODS:
                return

        if type_name == "method":
            class_name = self._find_containing_class(node)
            if class_name:
                name = f"{class_name}.{name}"

        line = node.start_point[0] + 1

        is_ambient = self._is_ambient_declaration(node)
        is_exported = self._is_exported(node) or self._is_declaration_file or is_ambient

        d = Definition(name, type_name, self.file_path, line)
        d.is_exported = is_exported
        if self._is_declaration_file or is_ambient:
            d.framework_signals.append("ambient declaration")
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

    def _is_object_literal_method(self, node) -> bool:
        current = node.parent
        while current:
            if current.type == "object":
                return True
            if current.type in {"class_body", "class_declaration", "program"}:
                return False
            current = current.parent
        return False

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
            identifiers = [child for child in node.children if child.type == "identifier"]
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
        self._raw_import_seen: set[tuple[str, int, bool]] = set()
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
        self, source_path: str, line: int, consume_all_exports: bool = False
    ) -> None:
        key = (source_path, line, consume_all_exports)
        if key in self._raw_import_seen:
            return
        self._raw_import_seen.add(key)
        self.raw_imports.append(
            {
                "source": source_path,
                "names": ["*"],
                "line": line,
                "consume_all_exports": consume_all_exports,
            }
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
