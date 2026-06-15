from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_java as tsj
from skylos.visitors.base import Definition

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

_SERIALIZATION_HOOKS_WITHOUT_ARGS: set[str] = {
    "readObjectNoData",
    "readResolve",
    "writeReplace",
}

_SERIALIZATION_HOOKS_WITH_STREAM: dict[str, str] = {
    "readObject": "ObjectInputStream",
    "writeObject": "ObjectOutputStream",
}

_CLASS_ENTRYPOINT_ANNOTATIONS: set[str] = {
    "ApplicationPath",
    "ApplicationScoped",
    "Component",
    "Configuration",
    "ConfigurationProperties",
    "Controller",
    "ControllerAdvice",
    "DataJpaTest",
    "Dependent",
    "Document",
    "Embeddable",
    "Entity",
    "ExtendWith",
    "Factory",
    "HiltAndroidApp",
    "MappedSuperclass",
    "MessageDriven",
    "MicronautTest",
    "Named",
    "Path",
    "QuarkusTest",
    "Repository",
    "RequestScoped",
    "RestController",
    "RestControllerAdvice",
    "RunWith",
    "Service",
    "SessionScoped",
    "SpringBootApplication",
    "SpringBootTest",
    "Stateful",
    "Stateless",
    "Testcontainers",
    "WebFilter",
    "WebListener",
    "WebMvcTest",
    "WebServlet",
}

_METHOD_ENTRYPOINT_ANNOTATIONS: set[str] = {
    "After",
    "AfterAll",
    "AfterClass",
    "AfterEach",
    "Bean",
    "Before",
    "BeforeAll",
    "BeforeClass",
    "BeforeEach",
    "DeleteMapping",
    "DgsData",
    "DgsMutation",
    "DgsQuery",
    "EventListener",
    "ExceptionHandler",
    "GET",
    "GetMapping",
    "GraphQLMutation",
    "GraphQLQuery",
    "JmsListener",
    "KafkaListener",
    "MessageMapping",
    "MutationMapping",
    "PATCH",
    "POST",
    "PUT",
    "ParameterizedTest",
    "PatchMapping",
    "Path",
    "PostConstruct",
    "PostMapping",
    "PreDestroy",
    "PutMapping",
    "QueryMapping",
    "RabbitListener",
    "RepeatedTest",
    "RequestMapping",
    "Scheduled",
    "SchemaMapping",
    "SubscribeMapping",
    "Test",
    "TestFactory",
    "TestTemplate",
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

    def _find_containing_method(self, node) -> str | None:
        current = node.parent
        while current:
            if current.type == "method_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return self._get_text(name_node)
                return None
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
                        is_public_api = "public" in mod_text or "protected" in mod_text
                        is_entrypoint_static_helper = (
                            "static" in mod_text
                            and self._containing_class_has_main(current)
                        )
                        if is_public_api and not is_entrypoint_static_helper:
                            return True
                    return False
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

    def _containing_class_has_main(self, node) -> bool:
        current = node.parent
        while current:
            if current.type in (
                "class_declaration",
                "enum_declaration",
                "record_declaration",
            ):
                for child in self._walk_nodes(current):
                    if child.type != "method_declaration":
                        continue
                    if self._is_java_main_entrypoint(child):
                        return True
                return False
            current = current.parent
        return False

    def _is_java_main_entrypoint(self, method_node) -> bool:
        name_node = method_node.child_by_field_name("name")
        if name_node is None or self._get_text(name_node) != "main":
            return False

        modifiers = method_node.child_by_field_name(
            "modifiers"
        ) or self._find_child_by_type(method_node, "modifiers")
        if modifiers is None:
            return False
        mod_text = self._get_text(modifiers)
        if "public" not in mod_text or "static" not in mod_text:
            return False

        signature = self._get_text(method_node).split("{", 1)[0]
        normalized = " ".join(signature.replace("\n", " ").split())
        if " void main" not in normalized:
            return False
        if "String" not in normalized:
            return False
        return "[]" in normalized or "..." in normalized

    def _walk_nodes(self, node):
        stack = [node]
        while stack:
            current = stack.pop()
            yield current
            stack.extend(reversed(current.children))

    def _find_child_by_type(self, node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    _ANNOTATED_DECL_TYPES: set[str] = {
        "annotation_type_declaration",
        "class_declaration",
        "enum_declaration",
        "field_declaration",
        "interface_declaration",
        "method_declaration",
        "constructor_declaration",
        "record_declaration",
    }

    def _declaration_for_node(self, node):
        decl = node
        while decl:
            if decl.type in self._ANNOTATED_DECL_TYPES:
                return decl
            decl = decl.parent
        return None

    def _annotation_names(self, node) -> set[str]:
        decl = self._declaration_for_node(node)
        if not decl:
            return set()

        names: set[str] = set()
        for child in decl.children:
            if child.type == "modifiers":
                for mod_child in child.children:
                    if (
                        mod_child.type == "marker_annotation"
                        or "annotation" in mod_child.type
                    ):
                        name = mod_child.child_by_field_name("name")
                        if name:
                            annotation = self._get_text(name)
                            names.add(annotation)
                            names.add(annotation.rsplit(".", 1)[-1])
        return names

    def _has_annotation(self, node, annotation_name: str) -> bool:
        return annotation_name in self._annotation_names(node)

    def _has_any_annotation(self, node, annotation_names: set[str]) -> bool:
        return bool(self._annotation_names(node) & annotation_names)

    def _class_contains_annotated_method(
        self, class_node, annotation_names: set[str]
    ) -> bool:
        for child in self._walk_nodes(class_node):
            if child is class_node:
                continue
            if child.type == "class_declaration":
                continue
            if child.type == "method_declaration" and self._has_any_annotation(
                child, annotation_names
            ):
                return True
        return False

    def _is_java_class_entrypoint(self, name_node) -> bool:
        class_node = self._declaration_for_node(name_node)
        if class_node is None:
            return False
        if self._has_any_annotation(class_node, _CLASS_ENTRYPOINT_ANNOTATIONS):
            return True
        return self._class_contains_annotated_method(
            class_node, _METHOD_ENTRYPOINT_ANNOTATIONS
        )

    def _method_parameter_texts(self, method_node) -> list[str]:
        parameters = method_node.child_by_field_name(
            "parameters"
        ) or self._find_child_by_type(method_node, "formal_parameters")
        if parameters is None:
            return []

        result: list[str] = []
        for child in parameters.children:
            if child.type in {"formal_parameter", "spread_parameter"}:
                result.append(self._get_text(child))
        return result

    def _is_java_serialization_hook(self, name: str, name_node) -> bool:
        method_node = name_node.parent
        if method_node is None or method_node.type != "method_declaration":
            return False

        parameters = self._method_parameter_texts(method_node)
        if name in _SERIALIZATION_HOOKS_WITHOUT_ARGS:
            return len(parameters) == 0

        stream_type = _SERIALIZATION_HOOKS_WITH_STREAM.get(name)
        if stream_type is None or len(parameters) != 1:
            return False
        return stream_type in parameters[0]

    def _is_abstract_method(self, name_node) -> bool:
        method_node = name_node.parent
        if method_node is None or method_node.type != "method_declaration":
            return False

        modifiers = method_node.child_by_field_name(
            "modifiers"
        ) or self._find_child_by_type(method_node, "modifiers")
        if modifiers is None:
            return False
        return "abstract" in self._get_text(modifiers)

    @staticmethod
    def _is_class_like_receiver(name: str) -> bool:
        return bool(name) and name[0].isupper()

    def scan(self) -> None:
        if not self.root_node:
            self.raw_imports: list[dict] = []
            return

        self._defs_captures = self._run_batch("defs", _DEFS_PATTERN)
        self._refs_captures = self._run_batch("refs", _REFS_PATTERN)

        self._scan_defs()
        self._scan_refs()
        self._scan_reflection_refs()
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

        if type_name == "class" and self._is_java_class_entrypoint(node):
            return

        if type_name == "method" and name in _LIFECYCLE_METHODS:
            return

        if type_name == "method" and self._is_java_serialization_hook(name, node):
            return

        if type_name == "method" and self._is_abstract_method(node):
            return

        if type_name == "method":
            if self._has_annotation(node, "Override"):
                return
            if self._has_any_annotation(node, _METHOD_ENTRYPOINT_ANNOTATIONS):
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
                if node.parent and node.parent.type == "method_invocation":
                    object_node = node.parent.child_by_field_name("object")
                    if object_node is not None:
                        object_name = self._get_text(object_node)
                        if (
                            object_name not in {"this", "super"}
                            and self._is_class_like_receiver(object_name)
                        ):
                            qualified_ref = f"{object_name}.{name}"
                            key = (qualified_ref, node.start_byte)
                            if key not in seen:
                                seen.add(key)
                                self.refs.append((qualified_ref, self.file_path))
                            continue

                key = (name, node.start_byte)
                if key not in seen:
                    seen.add(key)
                    self.refs.append((name, self.file_path))
                    if node.parent and node.parent.type == "method_invocation":
                        class_name = self._find_containing_class(node)
                        method_name = self._find_containing_method(node)
                        if class_name and method_name != name:
                            qualified_name = f"{class_name}.{name}"
                            self.refs.append((qualified_name, self.file_path))

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

    def _scan_reflection_refs(self) -> None:
        if self.root_node is None:
            return

        for node in self._walk_nodes(self.root_node):
            if node.type != "method_invocation":
                continue

            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            if name_node is None or object_node is None:
                continue
            if self._get_text(name_node) != "forName":
                continue
            if self._get_text(object_node) != "Class":
                continue

            class_name = self._first_string_argument(node)
            if class_name:
                self.refs.append((class_name, self.file_path))

    def _first_string_argument(self, invocation_node) -> str | None:
        arguments = invocation_node.child_by_field_name(
            "arguments"
        ) or self._find_child_by_type(invocation_node, "argument_list")
        if arguments is None:
            return None

        for child in self._walk_nodes(arguments):
            if child.type != "string_literal":
                continue
            raw = self._get_text(child).strip()
            if len(raw) < 2:
                continue
            if raw[0] not in {'"', "'"} or raw[-1] != raw[0]:
                continue
            value = raw[1:-1].strip()
            if value:
                return value
            return None
        return None

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
                    callee = self._method_invocation_callee_name(node, name_node)
                    if callee:
                        self.call_pairs.append((caller, callee))
            for child in node.children:
                stack.append(child)

    def _method_invocation_callee_name(self, invocation_node, name_node) -> str | None:
        name = self._get_text(name_node)
        object_node = invocation_node.child_by_field_name("object")
        if object_node is None:
            return name

        object_name = self._get_text(object_node)
        if object_name in {"this", "super"}:
            return name
        if self._is_class_like_receiver(object_name):
            return f"{object_name}.{name}"
        return name
