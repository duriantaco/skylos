from tree_sitter import Language, Parser, QueryCursor
import tree_sitter_typescript as tsts
from skylos.visitor import Definition

try:
    TS_LANG = Language(tsts.language_typescript())
except Exception:
    TS_LANG = None


class TypeScriptCore:
    """
    High level wrapper around a tree-sitter TS parse tree that extracts symbol
    definitions and reference occurrences from a single source file.
    """

    def __init__(self, file_path, source_bytes):
        self.file_path = file_path
        self.source = source_bytes
        self.defs = []
        self.refs = []

        if TS_LANG:
            self.parser = Parser(TS_LANG)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node):
        return self.source[node.start_byte : node.end_byte].decode("utf-8")

    def _run_query(self, pattern, capture_name):
        if not self.root_node or not TS_LANG:
            return []

        try:
            query = TS_LANG.query(pattern)
            cursor = QueryCursor(query)
            captures = cursor.captures(self.root_node)

            return captures.get(capture_name, [])

        except Exception:
            return []

    def scan(self):
        if not self.root_node:
            return

        for node in self._run_query(
            "(function_declaration name: (identifier) @def)", "def"
        ):
            self._add_def(node, "function")

        for node in self._run_query(
            "(class_declaration name: (identifier) @def)", "def"
        ):
            self._add_def(node, "class")

        for node in self._run_query(
            "(method_definition name: (property_identifier) @def)", "def"
        ):
            self._add_def(node, "method")
        for node in self._run_query(
            "(method_definition name: (identifier) @def)", "def"
        ):
            self._add_def(node, "method")

        for node in self._run_query(
            "(variable_declarator name: (identifier) @def value: (arrow_function))",
            "def",
        ):
            self._add_def(node, "function")

        ref_patterns = [
            "(call_expression function: (identifier) @ref)",
            "(new_expression constructor: (identifier) @ref)",
            "(member_expression property: (property_identifier) @ref)",
        ]

        for pattern in ref_patterns:
            for node in self._run_query(pattern, "ref"):
                name = self._get_text(node)
                self.refs.append((name, self.file_path))

    def _add_def(self, node, type_name):
        name = self._get_text(node)
        line = node.start_point[0] + 1

        is_exported = False
        try:
            p = node.parent
            if p and "export" in p.type:
                is_exported = True
        except:
            pass

        d = Definition(name, type_name, self.file_path, line)
        d.is_exported = is_exported
        self.defs.append(d)
