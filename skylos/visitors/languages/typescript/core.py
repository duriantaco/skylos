from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_typescript as tsts
from skylos.visitor import Definition

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
    "getSnapshotBeforeUpdate",
    "ngOnInit",
    "ngOnDestroy",
    "ngOnChanges",
    "ngAfterViewInit",
}


class TypeScriptCore:
    """
    High level wrapper around a tree-sitter TS parse tree that extracts symbol
    definitions and reference occurrences from a single source file.
    """

    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.imports: list[dict[str, str | int]] = []

        if str(file_path).endswith(".tsx") and TSX_LANG:
            self.lang: Language | None = TSX_LANG
        else:
            self.lang = TS_LANG

        if self.lang:
            self.parser = Parser(self.lang)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8")

    def _run_query(self, pattern: str, capture_name: str) -> list:
        if not self.root_node or not self.lang:
            return []

        try:
            query = Query(self.lang, pattern)
            cursor = QueryCursor(query)
            captures = cursor.captures(self.root_node)

            return captures.get(capture_name, [])

        except Exception:
            return []

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

        self._scan_defs()
        self._scan_refs()
        self._scan_imports()
        self._scan_raw_imports()
        self._build_call_graph()

    def _scan_defs(self) -> None:
        for node in self._run_query(
            "(function_declaration name: (identifier) @def)", "def"
        ):
            self._add_def(node, "function")

        for node in self._run_query(
            "(class_declaration name: (type_identifier) @def)", "def"
        ):
            self._add_def(node, "class")

        for node in self._run_query(
            "(interface_declaration name: (type_identifier) @def)", "def"
        ):
            self._add_def(node, "class")

        for node in self._run_query(
            "(enum_declaration name: (identifier) @def)", "def"
        ):
            self._add_def(node, "class")

        for node in self._run_query(
            "(type_alias_declaration name: (type_identifier) @def)", "def"
        ):
            self._add_def(node, "class")

        for node in self._run_query("(decorator (identifier) @dec)", "dec"):
            class_node = node.parent
            if class_node:
                class_node = class_node.parent
            if class_node and class_node.type == "class_declaration":
                name_node = class_node.child_by_field_name("name")
                if name_node:
                    self._add_ref_forced(name_node)

        for node in self._run_query(
            "(decorator (call_expression function: (identifier) @dec))", "dec"
        ):
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

        for node in self._run_query(
            "(method_definition name: (property_identifier) @def)", "def"
        ):
            self._add_def(node, "method")
        for node in self._run_query(
            "(method_definition name: (identifier) @def)", "def"
        ):
            self._add_def(node, "method")

        for node in self._run_query(
            "(variable_declarator name: (identifier) @def)", "def"
        ):
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

    def _scan_refs(self) -> None:
        call_ref_patterns: list[tuple[str, str]] = [
            ("(call_expression function: (identifier) @ref)", "ref"),
            ("(new_expression constructor: (identifier) @ref)", "ref"),
            ("(member_expression property: (property_identifier) @ref)", "ref"),
        ]

        value_ref_patterns: list[tuple[str, str]] = [
            ("(arguments (identifier) @ref)", "ref"),
            ("(variable_declarator value: (identifier) @ref)", "ref"),
            ("(array (identifier) @ref)", "ref"),
            ("(return_statement (identifier) @ref)", "ref"),
            ("(binary_expression right: (identifier) @ref)", "ref"),
            ("(binary_expression left: (identifier) @ref)", "ref"),
            ("(assignment_expression right: (identifier) @ref)", "ref"),
            ("(spread_element (identifier) @ref)", "ref"),
            ("(member_expression object: (identifier) @ref)", "ref"),
            ("(pair value: (identifier) @ref)", "ref"),
            ("(unary_expression (identifier) @ref)", "ref"),
            ("(template_substitution (identifier) @ref)", "ref"),
        ]

        shorthand_patterns: list[tuple[str, str]] = [
            ("(shorthand_property_identifier) @ref", "ref"),
        ]

        type_ref_patterns: list[tuple[str, str]] = []
        self._scan_type_refs()

        decorator_patterns: list[tuple[str, str]] = [
            ("(decorator (identifier) @ref)", "ref"),
            ("(decorator (call_expression function: (identifier) @ref))", "ref"),
        ]

        export_patterns: list[tuple[str, str]] = [
            ("(export_specifier name: (identifier) @ref)", "ref"),
        ]

        inheritance_patterns: list[tuple[str, str]] = [
            ("(extends_clause (identifier) @ref)", "ref"),
        ]

        all_patterns = (
            call_ref_patterns
            + value_ref_patterns
            + shorthand_patterns
            + type_ref_patterns
            + decorator_patterns
            + export_patterns
            + inheritance_patterns
        )

        for pattern, cap_name in all_patterns:
            for node in self._run_query(pattern, cap_name):
                self._add_ref(node)

    _TYPE_DEF_PARENTS: set[str] = {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "type_alias_declaration",
    }

    def _scan_type_refs(self) -> None:
        for node in self._run_query("(type_identifier) @ref", "ref"):
            parent = node.parent
            if parent and parent.type in self._TYPE_DEF_PARENTS:
                continue
            self._add_ref(node)

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

        if type_name == "method" and name in _LIFECYCLE_METHODS:
            return

        if type_name == "method":
            class_name = self._find_containing_class(node)
            if class_name:
                name = f"{class_name}.{name}"

        line = node.start_point[0] + 1

        is_exported = self._is_exported(node)

        d = Definition(name, type_name, self.file_path, line)
        d.is_exported = is_exported
        self.defs.append(d)

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

    def _scan_imports(self) -> None:
        import_patterns = [
            "(import_clause (named_imports (import_specifier name: (identifier) @name)))",
            "(import_clause (identifier) @name)",
            "(import_clause (namespace_import (identifier) @name))",
        ]

        for pattern in import_patterns:
            for node in self._run_query(pattern, "name"):
                name = self._get_text(node)
                line = node.start_point[0] + 1
                d = Definition(name, "import", self.file_path, line)
                self.defs.append(d)
                self.imports.append(
                    {"name": name, "file": str(self.file_path), "line": line}
                )

    def _scan_raw_imports(self) -> None:
        self.raw_imports: list[dict] = []

        for src_node in self._run_query(
            "(import_statement source: (string) @src)", "src"
        ):
            source_path = self._get_text(src_node).strip("'\"")
            import_stmt = src_node.parent
            if import_stmt:
                names = self._extract_import_names_from_stmt(import_stmt)
                self.raw_imports.append(
                    {
                        "source": source_path,
                        "names": names,
                        "line": src_node.start_point[0] + 1,
                    }
                )

        for src_node in self._run_query(
            "(export_statement source: (string) @src)", "src"
        ):
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

    def _extract_import_names_from_stmt(self, import_stmt) -> list[str]:
        names = []
        for child in import_stmt.children:
            if child.type == "import_clause":
                for clause_child in child.children:
                    if clause_child.type == "named_imports":
                        for spec in clause_child.children:
                            if spec.type == "import_specifier":
                                name_node = spec.child_by_field_name("name")
                                if name_node:
                                    names.append(self._get_text(name_node))
                    elif clause_child.type == "identifier":
                        names.append(self._get_text(clause_child))
                    elif clause_child.type == "namespace_import":
                        names.append("*")
        return names

    def _extract_export_names_from_stmt(self, export_stmt) -> list[str]:
        names = []
        for child in export_stmt.children:
            if child.type == "export_clause":
                for spec in child.children:
                    if spec.type == "export_specifier":
                        name_node = spec.child_by_field_name("name")
                        if name_node:
                            names.append(self._get_text(name_node))
            elif child.type == "*":
                names.append("*")
        return names if names else ["*"]

    def _build_call_graph(self) -> None:
        self.call_pairs: list[tuple[str, str]] = []

        for name_node in self._run_query(
            "(function_declaration name: (identifier) @name)", "name"
        ):
            caller_name = self._get_text(name_node)
            func_node = name_node.parent
            if func_node:
                body = func_node.child_by_field_name("body")
                if body:
                    self._collect_calls_in_body(caller_name, body)

        for name_node in self._run_query(
            "(variable_declarator name: (identifier) @name)", "name"
        ):
            var_decl = name_node.parent
            if var_decl:
                value = var_decl.child_by_field_name("value")
                if value and value.type == "arrow_function":
                    caller_name = self._get_text(name_node)
                    body = value.child_by_field_name("body")
                    if body:
                        self._collect_calls_in_body(caller_name, body)

        for name_node in self._run_query(
            "(method_definition name: (property_identifier) @name)", "name"
        ):
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
