from __future__ import annotations
from pathlib import Path
from tree_sitter import Language, Query, QueryCursor


_NEXTJS_DEFAULT_EXPORT_FILES: set[str] = {
    "page.tsx",
    "page.jsx",
    "page.ts",
    "page.js",
    "layout.tsx",
    "layout.jsx",
    "layout.ts",
    "layout.js",
    "loading.tsx",
    "loading.jsx",
    "loading.ts",
    "loading.js",
    "error.tsx",
    "error.jsx",
    "error.ts",
    "error.js",
    "not-found.tsx",
    "not-found.jsx",
    "not-found.ts",
    "not-found.js",
    "template.tsx",
    "template.jsx",
    "template.ts",
    "template.js",
    "global-error.tsx",
    "global-error.jsx",
    "global-error.ts",
    "global-error.js",
    "default.tsx",
    "default.jsx",
    "default.ts",
    "default.js",
}

_ROUTE_HANDLER_FILES: set[str] = {"route.ts", "route.js", "route.tsx", "route.jsx"}
_ROUTE_HANDLER_EXPORTS: set[str] = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
}

_MIDDLEWARE_FILES: set[str] = {
    "middleware.ts",
    "middleware.js",
    "middleware.tsx",
    "middleware.jsx",
}
_MIDDLEWARE_EXPORTS: set[str] = {"middleware", "config"}

_INSTRUMENTATION_FILES: set[str] = {
    "instrumentation.ts",
    "instrumentation.js",
    "instrumentation.tsx",
    "instrumentation.jsx",
}
_INSTRUMENTATION_EXPORTS: set[str] = {"register", "onRequestError"}

_NEXTJS_PAGES_ROUTER_EXPORTS: set[str] = {
    "getServerSideProps",
    "getStaticProps",
    "getStaticPaths",
}

_NEXTJS_APP_ROUTER_EXPORTS: set[str] = {
    "generateMetadata",
    "generateStaticParams",
}

_NEXTJS_ROUTE_SEGMENT_CONFIG: set[str] = {
    "metadata",
    "dynamic",
    "runtime",
    "revalidate",
    "fetchCache",
    "dynamicParams",
    "preferredRegion",
}

_ALL_NEXTJS_CONFIG_EXPORTS: set[str] = (
    _NEXTJS_PAGES_ROUTER_EXPORTS
    | _NEXTJS_APP_ROUTER_EXPORTS
    | _NEXTJS_ROUTE_SEGMENT_CONFIG
)

_REACT_WRAPPERS: set[str] = {"memo", "forwardRef"}


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

        self._detect_frameworks()
        self._scan_file_conventions()
        self._scan_nextjs_config_exports()
        self._scan_react_patterns()
        self._scan_custom_hooks()

    def _get_text(self, node) -> str:
        return self._source[node.start_byte : node.end_byte].decode("utf-8")

    def _run_query(self, pattern: str, capture_name: str) -> list:
        try:
            query = Query(self._lang, pattern)
            cursor = QueryCursor(query)
            captures = cursor.captures(self._root)
            return captures.get(capture_name, [])
        except Exception:
            return []

    def _line_of(self, node) -> int:
        return node.start_point[0] + 1

    def _detect_frameworks(self) -> None:
        for src_node in self._run_query(
            "(import_statement source: (string) @src)", "src"
        ):
            raw = self._get_text(src_node).strip("'\"")
            if raw == "next" or raw.startswith("next/"):
                self.detected_frameworks.add("next")
            if raw == "react" or raw.startswith("react/") or raw == "react-dom":
                self.detected_frameworks.add("react")

    def _scan_file_conventions(self) -> None:
        if self._basename in _NEXTJS_DEFAULT_EXPORT_FILES:
            self._mark_default_export()

        if self._basename in _ROUTE_HANDLER_FILES:
            self._mark_named_exports(_ROUTE_HANDLER_EXPORTS)

        if self._basename in _MIDDLEWARE_FILES:
            self._mark_named_exports(_MIDDLEWARE_EXPORTS)
            self._mark_default_export()

        if self._basename in _INSTRUMENTATION_FILES:
            self._mark_named_exports(_INSTRUMENTATION_EXPORTS)

    def _mark_default_export(self) -> None:
        for node in self._run_query(
            "(export_statement (function_declaration name: (identifier) @name))",
            "name",
        ):
            export_stmt = node.parent
            if export_stmt:
                export_stmt = export_stmt.parent  # export_statement
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._run_query(
            "(export_statement (class_declaration name: (type_identifier) @name))",
            "name",
        ):
            export_stmt = node.parent
            if export_stmt:
                export_stmt = export_stmt.parent
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._run_query("(export_statement (identifier) @name)", "name"):
            export_stmt = node.parent
            if export_stmt and "default" in self._get_text(export_stmt)[:30]:
                target_name = self._get_text(node)
                self._mark_definition_by_name(target_name)
                return

    def _mark_named_exports(self, names: set[str]) -> None:
        for node in self._run_query(
            "(export_statement (function_declaration name: (identifier) @name))",
            "name",
        ):
            if self._get_text(node) in names:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._run_query(
            "(export_statement (lexical_declaration (variable_declarator name: (identifier) @name)))",
            "name",
        ):
            if self._get_text(node) in names:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._run_query(
            "(export_specifier name: (identifier) @name)", "name"
        ):
            text = self._get_text(node)
            if text in names:
                self._mark_definition_by_name(text)

    def _mark_definition_by_name(self, name: str) -> None:
        for node in self._run_query(
            "(function_declaration name: (identifier) @name)", "name"
        ):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._run_query(
            "(variable_declarator name: (identifier) @name)", "name"
        ):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

        for node in self._run_query(
            "(class_declaration name: (type_identifier) @name)", "name"
        ):
            if self._get_text(node) == name:
                self.framework_decorated_lines.add(self._line_of(node))
                return

    def _scan_nextjs_config_exports(self) -> None:
        if "next" not in self.detected_frameworks:
            return

        self._mark_named_exports(_ALL_NEXTJS_CONFIG_EXPORTS)

    def _scan_react_patterns(self) -> None:
        if (
            "react" not in self.detected_frameworks
            and "next" not in self.detected_frameworks
        ):
            return

        for node in self._run_query(
            "(variable_declarator name: (identifier) @name)", "name"
        ):
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

        for node in self._run_query(
            "(export_statement (function_declaration name: (identifier) @name))",
            "name",
        ):
            if self._get_text(node).startswith("use") and len(self._get_text(node)) > 3:
                self.framework_decorated_lines.add(self._line_of(node))

        for node in self._run_query(
            "(export_statement (lexical_declaration (variable_declarator name: (identifier) @name)))",
            "name",
        ):
            if self._get_text(node).startswith("use") and len(self._get_text(node)) > 3:
                self.framework_decorated_lines.add(self._line_of(node))
