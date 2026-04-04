from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_java as tsj
from skylos.visitor import Definition

try:
    JAVA_LANG: Language | None = Language(tsj.language())
except Exception:
    JAVA_LANG = None

_QUERY_CACHE: dict[tuple[int, str], Query] = {}
_PARSER_CACHE: dict[int, Parser] = {}

_LIFECYCLE_METHODS: set[str] = {
    "main",
    "toString",
    "equals",
    "hashCode",
    "compareTo",
    "clone",
    "finalize",
    "close",
    "run",
    "call",
    "iterator",
    "hasNext",
    "next",
    # Servlet
    "doGet",
    "doPost",
    "doPut",
    "doDelete",
    "init",
    "destroy",
    "service",
    # Spring
    "configure",
    "onApplicationEvent",
    "afterPropertiesSet",
    # JUnit
    "setUp",
    "tearDown",
    # Android
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onCreateView",
    "onViewCreated",
}

_DEFS_PATTERN = """
(class_declaration name: (identifier) @class_def)
(interface_declaration name: (identifier) @iface_def)
(enum_declaration name: (identifier) @enum_def)
(record_declaration name: (identifier) @record_def)
(annotation_type_declaration name: (identifier) @annotation_def)
(method_declaration name: (identifier) @method_def)
(constructor_declaration name: (identifier) @ctor_def)
(field_declaration declarator: (variable_declarator name: (identifier) @field_def))
(import_declaration (scoped_identifier name: (identifier) @import_name))
"""

_REFS_PATTERN = """
(method_invocation name: (identifier) @ref)
(method_reference (identifier) @ref)
(object_creation_expression type: (type_identifier) @ref)
(type_identifier) @type_ref
(field_access field: (identifier) @ref)
(identifier) @ident_ref
"""


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


class JavaCore:
    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.imports: list[dict[str, str | int]] = []
        self.lang: Language | None = JAVA_LANG

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
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "method_declaration",
        "constructor_declaration",
        "field_declaration",
        "annotation_type_declaration",
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

    def _find_containing_class(self, node) -> str | None:
        current = node.parent
        while current:
            if current.type in (
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            ):
                name_node = current.child_by_field_name("name")
                if name_node:
                    return self._get_text(name_node)
            current = current.parent
        return None

    def _is_exported(self, node) -> bool:
        current = node.parent
        while current:
            if current.type in (
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
                "method_declaration",
                "constructor_declaration",
                "field_declaration",
                "annotation_type_declaration",
            ):
                if current.type == "method_declaration":
                    parent = current.parent
                    if parent and parent.type == "interface_body":
                        return True
                modifiers = current.child_by_field_name(
                    "modifiers"
                ) or self._find_child_by_type(current, "modifiers")
                if modifiers:
                    mod_text = self._get_text(modifiers)
                    if "public" in mod_text or "protected" in mod_text:
                        return True
                return False
            current = current.parent
        return False

    def _find_child_by_type(self, node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def _has_annotation(self, node, annotation_name: str) -> bool:
        decl = node.parent
        while decl:
            if decl.type in (
                "class_declaration",
                "method_declaration",
                "field_declaration",
                "constructor_declaration",
            ):
                break
            decl = decl.parent
        if not decl:
            return False
        for child in decl.children:
            if child.type == "modifiers":
                for mod_child in child.children:
                    if mod_child.type == "marker_annotation":
                        name = mod_child.child_by_field_name("name")
                        if name and self._get_text(name) == annotation_name:
                            return True
                    elif mod_child.type == "annotation":
                        name = mod_child.child_by_field_name("name")
                        if name and self._get_text(name) == annotation_name:
                            return True
        return False

    def scan(self) -> None:
        if not self.root_node:
            self.raw_imports: list[dict] = []
            return

        self._defs_captures = self._run_batch("defs", _DEFS_PATTERN)
        self._refs_captures = self._run_batch("refs", _REFS_PATTERN)

        self._scan_defs()
        self._scan_refs()
        self._scan_imports()
        self.raw_imports = []
        self._build_call_graph()

    def _scan_defs(self) -> None:
        c = self._defs_captures

        for node in c.get("class_def", []):
            self._add_def(node, "class")

        for node in c.get("iface_def", []):
            self._add_def(node, "class")

        for node in c.get("enum_def", []):
            self._add_def(node, "class")

        for node in c.get("record_def", []):
            self._add_def(node, "class")

        for node in c.get("annotation_def", []):
            self._add_def(node, "class")

        for node in c.get("method_def", []):
            self._add_def(node, "method")

        for node in c.get("ctor_def", []):
            name = self._get_text(node)
            self.refs.append((name, self.file_path))

        for node in c.get("field_def", []):
            self._add_def(node, "variable")

    def _add_def(self, node, type_name: str) -> None:
        name = self._get_text(node)

        if type_name == "method" and name in _LIFECYCLE_METHODS:
            return

        if type_name == "method":
            if self._has_annotation(node, "Override"):
                return
            if self._has_annotation(node, "Bean"):
                return
            if self._has_annotation(node, "Test"):
                return
            if self._has_annotation(node, "Before"):
                return
            if self._has_annotation(node, "After"):
                return
            if self._has_annotation(node, "BeforeEach"):
                return
            if self._has_annotation(node, "AfterEach"):
                return
            if self._has_annotation(node, "PostConstruct"):
                return
            if self._has_annotation(node, "PreDestroy"):
                return
            if self._has_annotation(node, "EventListener"):
                return
            if self._has_annotation(node, "Scheduled"):
                return
            if self._has_annotation(node, "ExceptionHandler"):
                return

        if type_name == "method":
            for ann in (
                "GetMapping",
                "PostMapping",
                "PutMapping",
                "DeleteMapping",
                "PatchMapping",
                "RequestMapping",
            ):
                if self._has_annotation(node, ann):
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

    def _scan_refs(self) -> None:
        c = self._refs_captures
        seen = set()

        for node in c.get("ref", []):
            name = self._get_text(node)
            if not self._is_self_ref(node, name):
                key = (name, node.start_byte)
                if key not in seen:
                    seen.add(key)
                    self.refs.append((name, self.file_path))

        for node in c.get("type_ref", []):
            parent = node.parent
            if parent and parent.type in (
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
                "annotation_type_declaration",
            ):
                continue
            name = self._get_text(node)
            if not self._is_self_ref(node, name):
                key = (name, node.start_byte)
                if key not in seen:
                    seen.add(key)
                    self.refs.append((name, self.file_path))

        for node in c.get("ident_ref", []):
            name = self._get_text(node)
            if self._is_self_ref(node, name):
                continue
            key = (name, node.start_byte)
            if key not in seen:
                seen.add(key)
                self.refs.append((name, self.file_path))

    def _scan_imports(self) -> None:
        c = self._defs_captures
        for node in c.get("import_name", []):
            name = self._get_text(node)
            line = node.start_point[0] + 1
            d = Definition(name, "import", self.file_path, line)
            self.defs.append(d)
            self.imports.append(
                {"name": name, "file": str(self.file_path), "line": line}
            )

    def _build_call_graph(self) -> None:
        self.call_pairs: list[tuple[str, str]] = []
        c = self._defs_captures

        for name_node in c.get("method_def", []):
            caller_name = self._get_text(name_node)
            class_name = self._find_containing_class(name_node)
            if class_name:
                caller_name = f"{class_name}.{caller_name}"
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
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                if name_node:
                    self.call_pairs.append((caller, self._get_text(name_node)))
            for child in node.children:
                stack.append(child)
