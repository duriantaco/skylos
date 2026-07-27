from __future__ import annotations
from pathlib import Path
from tree_sitter import Language, Query, QueryCursor

from .nextjs import (
    NEXTJS_IMPORTED_CONVENTION_EXPORTS,
    is_nextjs_convention_export,
    is_nextjs_default_export_file,
)

_REACT_WRAPPERS: set[str] = {"memo", "forwardRef"}

# Host-invoked methods for the VS Code contracts exercised by the pinned
# extension samples. Import binding checks below avoid treating local same-name
# interfaces as framework contracts.
_VSCODE_CONTRACT_METHODS: dict[str, frozenset[str]] = {
    "CodeLensProvider": frozenset({"provideCodeLenses", "resolveCodeLens"}),
    "DocumentLinkProvider": frozenset({"provideDocumentLinks", "resolveDocumentLink"}),
    "FileSystemProvider": frozenset(
        {
            "copy",
            "createDirectory",
            "delete",
            "readDirectory",
            "readFile",
            "rename",
            "stat",
            "watch",
            "writeFile",
        }
    ),
    "Pseudoterminal": frozenset({"open", "close", "handleInput", "setDimensions"}),
    "TaskProvider": frozenset({"provideTasks", "resolveTask"}),
    "TextDocumentContentProvider": frozenset({"provideTextDocumentContent"}),
    "TreeDataProvider": frozenset(
        {"getChildren", "getParent", "getTreeItem", "resolveTreeItem"}
    ),
    "TreeDragAndDropController": frozenset({"handleDrag", "handleDrop"}),
}

_QUERY_CACHE: dict[tuple[int, str], Query] = {}

_FW_PATTERN = """
(import_statement source: (string) @import_src)
(import_require_clause source: (string) @import_src)
(export_statement (function_declaration name: (identifier) @export_func_name))
(export_statement (class_declaration name: (type_identifier) @export_class_name))
(export_statement (identifier) @export_default_ident)
(export_statement (lexical_declaration (variable_declarator name: (identifier) @export_var_name)))
(export_specifier name: (identifier) @export_spec_name)
(function_declaration name: (identifier) @func_name)
(variable_declarator name: (identifier) @var_name)
(class_declaration name: (type_identifier) @class_name)
"""


def _get_query(lang: Language, key: str, pattern: str) -> Query | None:
    cache_key = (id(lang), key)
    if cache_key not in _QUERY_CACHE:
        try:
            _QUERY_CACHE[cache_key] = Query(lang, pattern)
        except Exception:
            _QUERY_CACHE[cache_key] = None
    return _QUERY_CACHE[cache_key]


def _run_batch(root_node, lang: Language, key: str, pattern: str) -> dict[str, list]:
    query = _get_query(lang, key, pattern)
    if query is None:
        return {}
    try:
        cursor = QueryCursor(query)
        return cursor.captures(root_node)
    except Exception:
        return {}


class TSFrameworkVisitor:
    def __init__(self) -> None:
        self.is_test_file: bool = False
        self.test_decorated_lines: set[int] = set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()
        self.detected_frameworks: set[str] = set()

    def __getstate__(self) -> dict:
        return {
            "is_test_file": self.is_test_file,
            "test_decorated_lines": self.test_decorated_lines,
            "dataclass_fields": self.dataclass_fields,
            "pydantic_models": self.pydantic_models,
            "class_defs": self.class_defs,
            "first_read_lineno": self.first_read_lineno,
            "framework_decorated_lines": self.framework_decorated_lines,
            "detected_frameworks": self.detected_frameworks,
        }

    def __setstate__(self, state: dict) -> None:
        self.is_test_file = bool(state.get("is_test_file", False))
        self.test_decorated_lines = set(state.get("test_decorated_lines", set()))
        self.dataclass_fields = set(state.get("dataclass_fields", set()))
        self.pydantic_models = set(state.get("pydantic_models", set()))
        self.class_defs = dict(state.get("class_defs", {}))
        self.first_read_lineno = dict(state.get("first_read_lineno", {}))
        self.framework_decorated_lines = set(
            state.get("framework_decorated_lines", set())
        )
        self.detected_frameworks = set(state.get("detected_frameworks", set()))

    def scan(
        self,
        file_path: str,
        root_node,
        source: bytes,
        lang: Language | None,
    ) -> None:
        if root_node is None or lang is None:
            return

        self._source = source
        self._lang = lang
        self._root = root_node
        self._file_path = file_path
        self._basename = Path(file_path).name

        self._captures = _run_batch(root_node, lang, "framework", _FW_PATTERN)

        self._detect_frameworks()
        self._scan_file_conventions()
        self._scan_nextjs_named_exports()
        self._scan_react_patterns()
        self._scan_custom_hooks()
        self._scan_vscode_contract_methods()

    def _get_text(self, node) -> str:
        return self._source[node.start_byte : node.end_byte].decode("utf-8")

    def _line_of(self, node) -> int:
        return node.start_point[0] + 1

    def _detect_frameworks(self) -> None:
        for src_node in self._captures.get("import_src", []):
            raw = self._get_text(src_node).strip("'\"")
            if raw == "next" or raw.startswith("next/"):
                self.detected_frameworks.add("next")
            if raw == "react" or raw.startswith("react/") or raw == "react-dom":
                self.detected_frameworks.add("react")
            if raw == "vscode":
                self.detected_frameworks.add("vscode")

    def _scan_file_conventions(self) -> None:
        if is_nextjs_default_export_file(self._file_path):
            self._mark_default_export()

    def _mark_default_export(self) -> None:
        for node in self._captures.get("export_func_name", []):
            export_stmt = node.parent
            if export_stmt:
                export_stmt = export_stmt.parent  # export_statement
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._captures.get("export_class_name", []):
            export_stmt = node.parent
            if export_stmt:
                export_stmt = export_stmt.parent
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._captures.get("export_default_ident", []):
            export_stmt = node.parent
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                target_name = self._get_text(node)
                self._mark_definition_by_name(target_name)
                return

    def _mark_named_exports(self, names: set[str]) -> None:
        for node in self._captures.get("export_func_name", []):
            if self._get_text(node) in names:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._captures.get("export_var_name", []):
            if self._get_text(node) in names:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._captures.get("export_spec_name", []):
            text = self._get_text(node)
            if text in names:
                self._mark_definition_by_name(text)

    def _mark_definition_by_name(self, name: str) -> None:
        for node in self._captures.get("func_name", []):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._captures.get("var_name", []):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._captures.get("class_name", []):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

    def _scan_nextjs_named_exports(self) -> None:
        for node in self._captures.get("export_func_name", []):
            name = self._get_text(node)
            if (
                name in NEXTJS_IMPORTED_CONVENTION_EXPORTS
                and "next" in self.detected_frameworks
            ) or is_nextjs_convention_export(name, self._file_path):
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._captures.get("export_var_name", []):
            name = self._get_text(node)
            if (
                name in NEXTJS_IMPORTED_CONVENTION_EXPORTS
                and "next" in self.detected_frameworks
            ) or is_nextjs_convention_export(name, self._file_path):
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._captures.get("export_spec_name", []):
            text = self._get_text(node)
            if (
                text in NEXTJS_IMPORTED_CONVENTION_EXPORTS
                and "next" in self.detected_frameworks
            ) or is_nextjs_convention_export(text, self._file_path):
                self._mark_definition_by_name(text)

    def _scan_react_patterns(self) -> None:
        if (
            "react" not in self.detected_frameworks
            and "next" not in self.detected_frameworks
        ):
            return

        for node in self._captures.get("var_name", []):
            var_decl = node.parent
            if not var_decl:
                continue
            value = var_decl.child_by_field_name("value")
            if not value or value.type != "call_expression":
                continue
            func = value.child_by_field_name("function")
            if not func:
                continue

            func_name = None
            if func.type == "identifier":
                func_name = self._get_text(func)
            elif func.type == "member_expression":
                prop = func.child_by_field_name("property")
                if prop:
                    func_name = self._get_text(prop)

            if func_name in _REACT_WRAPPERS:
                self.framework_decorated_lines.add(self._line_of(node))

    def _scan_custom_hooks(self) -> None:
        if (
            "react" not in self.detected_frameworks
            and "next" not in self.detected_frameworks
        ):
            return

        for node in self._captures.get("export_func_name", []):
            if self._get_text(node).startswith("use") and len(self._get_text(node)) > 3:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._captures.get("export_var_name", []):
            if self._get_text(node).startswith("use") and len(self._get_text(node)) > 3:
                self.framework_decorated_lines.add(self._line_of(node))

    def _scan_vscode_contract_methods(self) -> None:
        if "vscode" not in self.detected_frameworks:
            return

        namespace_bindings, named_contract_bindings = (
            self._vscode_contract_import_bindings()
        )
        if not namespace_bindings and not named_contract_bindings:
            return

        for name_node in self._captures.get("class_name", []):
            class_node = name_node.parent
            if class_node is None or class_node.type != "class_declaration":
                continue
            callback_names = self._vscode_class_callback_names(
                class_node,
                namespace_bindings,
                named_contract_bindings,
            )
            class_body = _first_named_child_of_type(class_node, "class_body")
            if class_body is None or not callback_names:
                continue
            self._mark_vscode_callback_methods(class_body, callback_names)

    def _vscode_class_callback_names(
        self,
        class_node,
        namespace_bindings: set[str],
        named_contract_bindings: dict[str, str],
    ) -> set[str]:
        callback_names: set[str] = set()
        heritage = _first_named_child_of_type(class_node, "class_heritage")
        if heritage is None:
            return callback_names

        for clause in _named_children_of_type(heritage, "implements_clause"):
            callback_names.update(
                self._vscode_implemented_callback_names(
                    clause,
                    namespace_bindings,
                    named_contract_bindings,
                )
            )
        return callback_names

    def _vscode_implemented_callback_names(
        self,
        implements_clause,
        namespace_bindings: set[str],
        named_contract_bindings: dict[str, str],
    ) -> set[str]:
        callback_names: set[str] = set()
        for contract_node in implements_clause.named_children:
            contract_name = self._vscode_contract_name(
                contract_node,
                namespace_bindings,
                named_contract_bindings,
            )
            if contract_name is not None:
                callback_names.update(_VSCODE_CONTRACT_METHODS.get(contract_name, ()))
        return callback_names

    def _vscode_contract_name(
        self,
        contract_node,
        namespace_bindings: set[str],
        named_contract_bindings: dict[str, str],
    ) -> str | None:
        contract_text = self._get_text(contract_node).split("<", 1)[0].strip()
        if "." not in contract_text:
            return named_contract_bindings.get(contract_text)

        namespace_name, contract_name = contract_text.rsplit(".", 1)
        if namespace_name in namespace_bindings:
            return contract_name
        return None

    def _mark_vscode_callback_methods(
        self,
        class_body,
        callback_names: set[str],
    ) -> None:
        for member in _named_children_of_type(class_body, "method_definition"):
            method_name_node = member.child_by_field_name("name")
            if method_name_node is None:
                continue
            if self._get_text(method_name_node) in callback_names:
                self.framework_decorated_lines.add(self._line_of(method_name_node))

    def _vscode_contract_import_bindings(self) -> tuple[set[str], dict[str, str]]:
        namespace_bindings: set[str] = set()
        named_contract_bindings: dict[str, str] = {}

        for src_node in self._captures.get("import_src", []):
            if self._get_text(src_node).strip("'\"") != "vscode":
                continue

            import_statement = _ancestor_of_type(src_node, "import_statement")
            if import_statement is None:
                continue
            self._record_vscode_import_bindings(
                import_statement,
                namespace_bindings,
                named_contract_bindings,
            )

        return namespace_bindings, named_contract_bindings

    def _record_vscode_import_bindings(
        self,
        import_statement,
        namespace_bindings: set[str],
        named_contract_bindings: dict[str, str],
    ) -> None:
        for clause in import_statement.named_children:
            if clause.type == "import_require_clause":
                self._record_vscode_namespace_binding(clause, namespace_bindings)
            elif clause.type == "import_clause":
                self._record_vscode_import_clause_bindings(
                    clause,
                    namespace_bindings,
                    named_contract_bindings,
                )

    def _record_vscode_import_clause_bindings(
        self,
        import_clause,
        namespace_bindings: set[str],
        named_contract_bindings: dict[str, str],
    ) -> None:
        for binding in import_clause.named_children:
            if binding.type == "identifier":
                namespace_bindings.add(self._get_text(binding))
            elif binding.type == "namespace_import":
                self._record_vscode_namespace_binding(
                    binding,
                    namespace_bindings,
                )
            elif binding.type == "named_imports":
                self._record_vscode_named_imports(
                    binding,
                    named_contract_bindings,
                )

    def _record_vscode_namespace_binding(
        self,
        node,
        namespace_bindings: set[str],
    ) -> None:
        identifier = _first_named_child_of_type(node, "identifier")
        if identifier is not None:
            namespace_bindings.add(self._get_text(identifier))

    def _record_vscode_named_imports(
        self,
        named_imports,
        named_contract_bindings: dict[str, str],
    ) -> None:
        for specifier in _named_children_of_type(named_imports, "import_specifier"):
            binding = self._vscode_named_import_binding(specifier)
            if binding is not None:
                local_name, contract_name = binding
                named_contract_bindings[local_name] = contract_name

    def _vscode_named_import_binding(self, specifier) -> tuple[str, str] | None:
        name_node = specifier.child_by_field_name("name")
        if name_node is None:
            return None

        contract_name = self._get_text(name_node)
        if contract_name not in _VSCODE_CONTRACT_METHODS:
            return None

        alias_node = specifier.child_by_field_name("alias")
        local_name_node = alias_node if alias_node is not None else name_node
        return self._get_text(local_name_node), contract_name


def _named_children_of_type(node, node_type: str):
    return (child for child in node.named_children if child.type == node_type)


def _first_named_child_of_type(node, node_type: str):
    return next(_named_children_of_type(node, node_type), None)


def _ancestor_of_type(node, node_type: str):
    current = node
    while current is not None and current.type != node_type:
        current = current.parent
    return current
