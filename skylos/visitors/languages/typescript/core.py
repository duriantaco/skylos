from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_typescript as tsts
from skylos.visitor import Definition

try:
    TS_LANG: Language | None = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None

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

        if TS_LANG:
            self.parser = Parser(TS_LANG)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8")

    def _run_query(self, pattern: str, capture_name: str) -> list:
        if not self.root_node or not TS_LANG:
            return []

        try:
            query = Query(TS_LANG, pattern)
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
        """Return True if *node* sits inside a definition of the same *name*."""
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
        """Add ref without self-reference filtering (e.g. decorated classes)."""
        self.refs.append((self._get_text(node), self.file_path))

    def scan(self) -> None:
        if not self.root_node:
            return

        self._scan_defs()
        self._scan_refs()
        self._scan_imports()

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

        for node in self._run_query(
            "(decorator (identifier) @dec)", "dec"
        ):
  
            class_node = node.parent
            if class_node:
                class_node = class_node.parent
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
            value_node = var_decl.child_by_field_name("value") if var_decl else None
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

        # --- Inheritance: extends/implements use plain identifier ---
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

    def _add_def(self, node, type_name: str) -> None:
        name = self._get_text(node)

        if type_name == "method" and name in _LIFECYCLE_METHODS:
            return

        line = node.start_point[0] + 1

        is_exported = self._is_exported(node)

        d = Definition(name, type_name, self.file_path, line)
        d.is_exported = is_exported
        self.defs.append(d)

    def _is_top_level(self, node) -> bool:
        """Check if a node is at module (program) scope."""
        current = node.parent
        while current:
            if current.type == "program":
                return True
            if current.type in ("export_statement", "lexical_declaration",
                                "variable_declarator"):
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
