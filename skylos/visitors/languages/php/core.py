from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Parser

try:
    import tree_sitter_php as tsphp
except ImportError:
    tsphp = None

from skylos.visitors.base import Definition

try:
    PHP_LANG: Language | None = (
        Language(tsphp.language_php()) if tsphp is not None else None
    )
except Exception:
    PHP_LANG = None

_PARSER_CACHE: dict[int, Parser] = {}

_MAGIC_METHODS = {
    "__construct",
    "__destruct",
    "__invoke",
    "__toString",
    "__get",
    "__set",
    "__isset",
    "__unset",
    "__sleep",
    "__wakeup",
    "__serialize",
    "__unserialize",
    "__call",
    "__callStatic",
    "__clone",
    "__debugInfo",
}

_PHPUNIT_LIFECYCLE = {
    "setUp",
    "tearDown",
    "setUpBeforeClass",
    "tearDownAfterClass",
}

_IMPORT_EXPR_TYPES = {
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
}


def _get_parser(lang: Language) -> Parser:
    lang_id = id(lang)
    if lang_id not in _PARSER_CACHE:
        _PARSER_CACHE[lang_id] = Parser(lang)
    return _PARSER_CACHE[lang_id]


def _is_test_path(file_path: str | Path) -> bool:
    lower = str(file_path).lower().replace("\\", "/")
    return (
        "/tests/" in lower or lower.endswith("test.php") or lower.endswith("tests.php")
    )


class PhpCore:
    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.imports: list[dict[str, str | int]] = []
        self.raw_imports: list[dict[str, object]] = []
        self.call_pairs: list[tuple[str, str]] = []
        self.test_decorated_lines: set[int] = set()
        self.lang: Language | None = PHP_LANG
        self.is_test_file = _is_test_path(file_path)
        self._seen_refs: set[tuple[str, int]] = set()
        self._unresolved_member_calls: list[tuple[str, str]] = []
        self._trait_names: set[str] = set()
        self._traits_by_owner: dict[str, list[str]] = {}
        self._trait_aliases: dict[str, dict[str, set[str]]] = {}
        self._trait_precedence: dict[str, dict[str, str]] = {}
        self._trait_dispatch_refs: set[int] = set()
        self._trait_dispatch_calls: set[tuple[str, str]] = set()

        if self.lang:
            self.parser = _get_parser(self.lang)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _children_of_type(self, node, type_name: str) -> list:
        return [child for child in node.children if child.type == type_name]

    def _child_by_type(self, node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def _node_name_text(self, node) -> str:
        if node is None:
            return ""
        text = self._get_text(node).strip()
        if node.type == "variable_name":
            return text.lstrip("$")
        return text

    def _qualified_symbol(self, name: str, namespace: str) -> str:
        return f"{namespace}.{name}" if namespace else name

    def _visibility(self, node, *, default_public: bool = True) -> str:
        for child in node.children:
            if child.type == "visibility_modifier":
                return self._get_text(child).strip()
        return "public" if default_public else ""

    def _is_publicish(self, node, *, default_public: bool = True) -> bool:
        return self._visibility(node, default_public=default_public) in {
            "public",
            "protected",
        }

    def _is_magic_or_test_entrypoint(
        self, method_name: str, class_bases: list[str], line: int
    ) -> bool:
        if method_name in _MAGIC_METHODS or method_name in _PHPUNIT_LIFECYCLE:
            self.test_decorated_lines.add(line)
            return True
        if self.is_test_file and method_name.startswith("test"):
            self.test_decorated_lines.add(line)
            return True
        if any(base.endswith("TestCase") for base in class_bases):
            if method_name.startswith("test") or method_name in _PHPUNIT_LIFECYCLE:
                self.test_decorated_lines.add(line)
                return True
        return False

    def _add_ref(
        self,
        name: str,
        start_byte: int,
        *,
        current_callable: str | None,
        unresolved_member: bool = False,
        trait_dispatch: bool = False,
    ) -> None:
        if not name:
            return
        qualified = name.replace("\\", ".").lstrip(".$")
        if not qualified:
            return
        if current_callable and qualified == current_callable and not unresolved_member:
            return
        key = (qualified, start_byte)
        if key in self._seen_refs:
            return
        self._seen_refs.add(key)
        if trait_dispatch:
            self._trait_dispatch_refs.add(len(self.refs))
        self.refs.append((qualified, self.file_path))
        if current_callable:
            if unresolved_member:
                self._unresolved_member_calls.append((current_callable, qualified))
            else:
                self.call_pairs.append((current_callable, qualified))
                if trait_dispatch:
                    self._trait_dispatch_calls.add((current_callable, qualified))

    def _resolve_name(
        self,
        name: str,
        *,
        namespace: str,
        aliases: dict[tuple[str, str], str],
        kind: str = "class",
        start_byte: int,
    ) -> str:
        if not name:
            return ""
        if name.startswith("\\"):
            return name.lstrip("\\").replace("\\", ".")
        parts = name.split("\\")
        if parts[0] == "namespace":
            return self._qualified_symbol(".".join(parts[1:]), namespace)
        alias_kind = "class" if len(parts) > 1 else kind
        alias_name = next(
            (
                alias
                for imported_kind, alias in aliases
                if imported_kind == alias_kind
                and (
                    alias == parts[0]
                    if alias_kind == "const"
                    else alias.casefold() == parts[0].casefold()
                )
            ),
            parts[0],
        )
        target = aliases.get((alias_kind, alias_name))
        if target:
            self._add_ref(alias_name, start_byte, current_callable=None)
            return ".".join([target, *parts[1:]])
        return self._qualified_symbol(".".join(parts), namespace)

    def _member_owner(
        self,
        node,
        *,
        namespace: str,
        current_class: str | None,
        class_bases: list[str],
        aliases: dict[tuple[str, str], str],
    ) -> str | None:
        if node is None:
            return None
        text = self._get_text(node).strip()
        if node.type == "variable_name":
            return current_class if text == "$this" else None
        if node.type == "relative_scope":
            if text in {"self", "static"}:
                return current_class
            if text == "parent" and len(class_bases) == 1:
                return class_bases[0]
            return None
        if node.type == "parenthesized_expression":
            named = node.named_children
            if len(named) == 1:
                return self._member_owner(
                    named[0],
                    namespace=namespace,
                    current_class=current_class,
                    class_bases=class_bases,
                    aliases=aliases,
                )
            return None
        if node.type == "object_creation_expression":
            node = next(
                (
                    child
                    for child in node.children
                    if child.type in {"name", "qualified_name"}
                ),
                None,
            )
            if node is None:
                return None
            text = self._get_text(node)
        elif node.type not in {"name", "qualified_name"}:
            return None
        return self._resolve_name(
            text,
            namespace=namespace,
            aliases=aliases,
            start_byte=node.start_byte,
        )

    def _extract_literal_path(self, node) -> str | None:
        if node is None:
            return None
        if node.type == "string":
            return self._get_text(node).strip("\"'")
        if node.type == "parenthesized_expression":
            for child in node.children:
                if child.type not in {"(", ")"}:
                    return self._extract_literal_path(child)
            return None
        if node.type == "binary_expression":
            parts = []
            for child in node.children:
                if child.type == ".":
                    continue
                child_value = self._extract_literal_path(child)
                if child_value is None:
                    return None
                parts.append(child_value)
            return "".join(parts)
        if node.type == "magic_constant" and self._get_text(node).strip() == "__DIR__":
            return "__DIR__/"
        return None

    def scan(self) -> None:
        if not self.root_node:
            return
        self._scan_block(
            self.root_node,
            namespace="",
            current_class=None,
            current_callable=None,
            class_bases=[],
        )
        self._build_call_graph()

    def _scan_block(
        self,
        node,
        *,
        namespace: str,
        current_class: str | None,
        current_callable: str | None,
        class_bases: list[str],
        aliases: dict[tuple[str, str], str] | None = None,
    ) -> None:
        if aliases is None:
            aliases = {}
        active_namespace = namespace
        for child in node.children:
            if child.type == "namespace_definition":
                ns_node = self._child_by_type(child, "namespace_name")
                child_namespace = self._node_name_text(ns_node).replace("\\", ".")
                body = child.child_by_field_name("body")
                if body is not None:
                    self._scan_block(
                        body,
                        namespace=child_namespace,
                        current_class=None,
                        current_callable=None,
                        class_bases=[],
                        aliases={},
                    )
                else:
                    active_namespace = child_namespace
                    aliases = {}
                continue

            if child.type in {
                "class_declaration",
                "interface_declaration",
                "trait_declaration",
            }:
                self._scan_class_like(
                    child, namespace=active_namespace, aliases=aliases
                )
                continue

            if child.type == "enum_declaration":
                self._scan_enum(child, namespace=active_namespace)
                continue

            if child.type == "const_declaration":
                self._scan_constant_declaration(
                    child,
                    current_class=None,
                    namespace=active_namespace,
                    is_exported=False,
                )
                continue

            if child.type == "function_definition":
                self._scan_function(child, namespace=active_namespace, aliases=aliases)
                continue

            if child.type == "namespace_use_declaration":
                self._scan_use_imports(child, aliases=aliases)
                continue

            if child.type in _IMPORT_EXPR_TYPES:
                self._scan_include_import(child)

            self._scan_refs_in_node(
                child,
                namespace=active_namespace,
                current_class=current_class,
                current_callable=current_callable,
                class_bases=class_bases,
                aliases=aliases,
            )
            self._scan_block(
                child,
                namespace=active_namespace,
                current_class=current_class,
                current_callable=current_callable,
                class_bases=class_bases,
                aliases=aliases,
            )

    def _scan_class_like(
        self, node, *, namespace: str, aliases: dict[tuple[str, str], str]
    ) -> None:
        name_node = self._child_by_type(node, "name")
        class_name = self._node_name_text(name_node)
        if not class_name:
            return
        qualified = self._qualified_symbol(class_name, namespace)
        line = name_node.start_point[0] + 1 if name_node else node.start_point[0] + 1
        class_def = Definition(qualified, "class", self.file_path, line)
        if node.type == "trait_declaration":
            self._trait_names.add(qualified)

        bases: list[str] = []
        for base_clause in self._children_of_type(node, "base_clause"):
            for child in base_clause.children:
                if child.type in {"name", "qualified_name"}:
                    base_name = self._resolve_name(
                        self._node_name_text(child),
                        namespace=namespace,
                        aliases=aliases,
                        start_byte=child.start_byte,
                    )
                    bases.append(base_name)
                    self._add_ref(base_name, child.start_byte, current_callable=None)
        for iface_clause in self._children_of_type(node, "class_interface_clause"):
            for child in iface_clause.children:
                if child.type in {"name", "qualified_name"}:
                    iface_name = self._resolve_name(
                        self._node_name_text(child),
                        namespace=namespace,
                        aliases=aliases,
                        start_byte=child.start_byte,
                    )
                    bases.append(iface_name)
                    self._add_ref(iface_name, child.start_byte, current_callable=None)

        class_def.base_classes = bases
        self.defs.append(class_def)

        declaration_list = self._child_by_type(node, "declaration_list")
        if declaration_list is None:
            return

        for child in declaration_list.children:
            if child.type == "use_declaration":
                self._scan_trait_use(
                    child,
                    current_class=qualified,
                    namespace=namespace,
                    aliases=aliases,
                )
                continue

            if child.type == "property_declaration":
                self._scan_property_declaration(child, current_class=qualified)
                continue

            if child.type == "const_declaration":
                self._scan_constant_declaration(
                    child,
                    current_class=qualified,
                    namespace=namespace,
                    is_exported=self._is_publicish(child, default_public=False),
                )
                continue

            if child.type == "method_declaration":
                self._scan_method(
                    child,
                    namespace=namespace,
                    current_class=qualified,
                    class_bases=bases,
                    aliases=aliases,
                )
                continue

            self._scan_refs_in_node(
                child,
                namespace=namespace,
                current_class=qualified,
                current_callable=None,
                class_bases=bases,
                aliases=aliases,
            )

    def _scan_trait_use(
        self,
        node,
        *,
        current_class: str,
        namespace: str,
        aliases: dict[tuple[str, str], str],
    ) -> None:
        providers = self._traits_by_owner.setdefault(current_class, [])
        for child in node.children:
            if child.type in {"name", "qualified_name"}:
                provider = self._resolve_name(
                    self._node_name_text(child),
                    namespace=namespace,
                    aliases=aliases,
                    start_byte=child.start_byte,
                )
                providers.append(provider)
                self._add_ref(provider, child.start_byte, current_callable=None)

        adaptations = self._child_by_type(node, "use_list")
        if adaptations is None:
            return
        for clause in adaptations.named_children:
            named = clause.named_children
            if not named:
                continue
            source = named[0]
            if source.type == "class_constant_access_expression":
                owner_node, member_node = source.named_children[:2]
                provider = self._resolve_name(
                    self._node_name_text(owner_node),
                    namespace=namespace,
                    aliases=aliases,
                    start_byte=owner_node.start_byte,
                )
                member = self._node_name_text(member_node)
                targets = {f"{provider}.{member}"}
            elif source.type == "name":
                member = self._node_name_text(source)
                targets = {f"{provider}.{member}" for provider in providers}
            else:
                continue
            if clause.type == "use_instead_of_clause" and len(targets) == 1:
                self._trait_precedence.setdefault(current_class, {})[member] = next(
                    iter(targets)
                )
            elif clause.type == "use_as_clause":
                alias_nodes = [child for child in named[1:] if child.type == "name"]
                if alias_nodes:
                    alias = self._node_name_text(alias_nodes[-1])
                    self._trait_aliases.setdefault(current_class, {})[alias] = targets

    def _scan_enum(self, node, *, namespace: str) -> None:
        name_node = self._child_by_type(node, "name")
        enum_name = self._node_name_text(name_node)
        if not enum_name:
            return
        qualified = self._qualified_symbol(enum_name, namespace)
        enum_def = Definition(
            qualified,
            "class",
            self.file_path,
            name_node.start_point[0] + 1,
        )
        enum_def.is_exported = True
        self.defs.append(enum_def)

        declaration_list = self._child_by_type(node, "enum_declaration_list")
        if declaration_list is None:
            return
        for case in self._children_of_type(declaration_list, "enum_case"):
            case_node = self._child_by_type(case, "name")
            case_name = self._node_name_text(case_node)
            if not case_name:
                continue
            d = Definition(
                f"{qualified}.{case_name}",
                "variable",
                self.file_path,
                case_node.start_point[0] + 1,
            )
            d.is_exported = True
            self.defs.append(d)

    def _scan_constant_declaration(
        self,
        node,
        *,
        current_class: str | None,
        namespace: str,
        is_exported: bool,
    ) -> None:
        for const in self._children_of_type(node, "const_element"):
            name_node = self._child_by_type(const, "name")
            const_name = self._node_name_text(name_node)
            if not const_name:
                continue
            if current_class:
                qualified = f"{current_class}.{const_name}"
            else:
                qualified = self._qualified_symbol(const_name, namespace)
            d = Definition(
                qualified,
                "variable",
                self.file_path,
                name_node.start_point[0] + 1,
            )
            d.is_exported = is_exported
            self.defs.append(d)

    def _scan_property_declaration(self, node, *, current_class: str) -> None:
        is_exported = self._is_publicish(node, default_public=False)
        for prop in self._children_of_type(node, "property_element"):
            name_node = self._child_by_type(prop, "variable_name")
            if not name_node:
                continue
            prop_name = self._node_name_text(name_node)
            line = name_node.start_point[0] + 1
            d = Definition(
                f"{current_class}.{prop_name}",
                "variable",
                self.file_path,
                line,
            )
            d.is_exported = is_exported
            self.defs.append(d)

    def _scan_method(
        self,
        node,
        *,
        namespace: str,
        current_class: str,
        class_bases: list[str],
        aliases: dict[tuple[str, str], str],
    ) -> None:
        name_node = self._child_by_type(node, "name")
        method_name = self._node_name_text(name_node)
        if not method_name:
            return
        line = name_node.start_point[0] + 1
        qualified = f"{current_class}.{method_name}"
        implicit_entrypoint = self._is_magic_or_test_entrypoint(
            method_name, class_bases, line
        ) or self._has_test_attribute(node, line)

        d = Definition(qualified, "method", self.file_path, line)
        d.is_exported = self._is_publicish(node) or implicit_entrypoint
        self.defs.append(d)

        params = self._child_by_type(node, "formal_parameters")
        if params is not None:
            for child in params.children:
                if child.type != "property_promotion_parameter":
                    continue
                var_node = self._child_by_type(child, "variable_name")
                if not var_node:
                    continue
                prop_name = self._node_name_text(var_node)
                prop_def = Definition(
                    f"{current_class}.{prop_name}",
                    "variable",
                    self.file_path,
                    var_node.start_point[0] + 1,
                )
                prop_def.is_exported = self._is_publicish(child, default_public=False)
                self.defs.append(prop_def)

        body = self._child_by_type(node, "compound_statement")
        if body is not None:
            self._scan_block(
                body,
                namespace=namespace,
                current_class=current_class,
                current_callable=qualified,
                class_bases=class_bases,
                aliases=aliases,
            )

    def _has_test_attribute(self, node, line: int) -> bool:
        for attr_list in self._children_of_type(node, "attribute_list"):
            for attr in self._descendants_of_type(attr_list, "attribute"):
                name_node = self._child_by_type(attr, "name")
                attr_name = self._node_name_text(name_node)
                if attr_name != "Test" and not attr_name.endswith("\\Test"):
                    continue
                self.test_decorated_lines.add(line)
                return True
        return False

    def _scan_function(
        self, node, *, namespace: str, aliases: dict[tuple[str, str], str]
    ) -> None:
        name_node = self._child_by_type(node, "name")
        func_name = self._node_name_text(name_node)
        if not func_name:
            return
        qualified = self._qualified_symbol(func_name, namespace)
        line = name_node.start_point[0] + 1
        d = Definition(qualified, "function", self.file_path, line)
        d.is_exported = self.is_test_file and func_name.startswith("test")
        self.defs.append(d)

        body = self._child_by_type(node, "compound_statement")
        if body is not None:
            self._scan_block(
                body,
                namespace=namespace,
                current_class=None,
                current_callable=qualified,
                class_bases=[],
                aliases=aliases,
            )

    def _use_aliases(self, node):
        group_prefix = self._node_name_text(self._child_by_type(node, "namespace_name"))
        declaration_kind = (
            self._get_text(node.child_by_field_name("type"))
            if node.child_by_field_name("type")
            else "class"
        )
        for clause in self._descendants_of_type(node, "namespace_use_clause"):
            target_node = (
                clause.child_by_field_name("name")
                or self._child_by_type(clause, "qualified_name")
                or self._child_by_type(clause, "name")
            )
            alias_node = clause.child_by_field_name("alias")
            target = self._node_name_text(target_node)
            if group_prefix:
                target = f"{group_prefix}\\{target}"
            alias = self._node_name_text(alias_node) or target.split("\\")[-1]
            if not alias:
                continue
            type_node = clause.child_by_field_name("type")
            kind = self._get_text(type_node) if type_node else declaration_kind
            yield kind, alias, target.lstrip("\\").replace("\\", ".")

    def _scan_use_imports(self, node, *, aliases: dict[tuple[str, str], str]) -> None:
        names: list[str] = []
        line = node.start_point[0] + 1
        for kind, alias, target in self._use_aliases(node):
            aliases[(kind, alias)] = target
            d = Definition(alias, "import", self.file_path, line)
            self.defs.append(d)
            self.imports.append(
                {"name": alias, "file": str(self.file_path), "line": line}
            )
            names.append(alias)
        if names:
            self.raw_imports.append({"source": "use", "names": names, "line": line})

    def _descendants_of_type(self, node, type_name: str):
        if node.type == type_name:
            yield node
        for child in node.children:
            yield from self._descendants_of_type(child, type_name)

    def _scan_include_import(self, node) -> None:
        expr = None
        for child in node.children:
            if child.type not in {"include", "include_once", "require", "require_once"}:
                expr = child
                break
        source_text = ""
        if expr is not None:
            source_text = (
                self._extract_literal_path(expr) or self._get_text(expr).strip()
            )
        self.raw_imports.append(
            {"source": source_text, "names": [], "line": node.start_point[0] + 1}
        )

    def _scan_refs_in_node(
        self,
        node,
        *,
        namespace: str,
        current_class: str | None,
        current_callable: str | None,
        class_bases: list[str],
        aliases: dict[tuple[str, str], str],
    ) -> None:
        if node.type == "function_call_expression":
            name_node = node.child_by_field_name("function")
            if name_node is None or name_node.type not in {
                "name",
                "qualified_name",
                "relative_name",
            }:
                return
            self._add_ref(
                self._resolve_name(
                    self._node_name_text(name_node),
                    namespace=namespace,
                    aliases=aliases,
                    kind="function",
                    start_byte=name_node.start_byte,
                ),
                node.start_byte,
                current_callable=current_callable,
            )
            return

        if node.type in {"member_call_expression", "scoped_call_expression"}:
            name_node = node.child_by_field_name("name")
            if name_node is None or name_node.type != "name":
                return
            owner_node = node.child_by_field_name(
                "scope" if node.type == "scoped_call_expression" else "object"
            )
            owner = self._member_owner(
                owner_node,
                namespace=namespace,
                current_class=current_class,
                class_bases=class_bases,
                aliases=aliases,
            )
            member = self._node_name_text(name_node)
            if owner and node.type == "scoped_call_expression":
                self._add_ref(owner, owner_node.start_byte, current_callable=None)
            self._add_ref(
                f"{owner}.{member}" if owner else member,
                node.start_byte,
                current_callable=current_callable,
                unresolved_member=owner is None,
                trait_dispatch=current_class in self._trait_names
                and owner == current_class,
            )
            return

        if node.type == "object_creation_expression":
            for child in node.children:
                if child.type in {"name", "qualified_name"}:
                    self._add_ref(
                        self._resolve_name(
                            self._node_name_text(child),
                            namespace=namespace,
                            aliases=aliases,
                            start_byte=child.start_byte,
                        ),
                        node.start_byte,
                        current_callable=None,
                    )
                    break
            return

        if node.type in {
            "member_access_expression",
            "scoped_property_access_expression",
            "class_constant_access_expression",
        }:
            name_node = node.child_by_field_name("name")
            if node.type == "class_constant_access_expression":
                named = node.named_children
                owner_node = named[0] if named else None
                name_node = named[1] if len(named) > 1 else None
            else:
                owner_node = node.child_by_field_name(
                    "scope"
                    if node.type == "scoped_property_access_expression"
                    else "object"
                )
            owner = self._member_owner(
                owner_node,
                namespace=namespace,
                current_class=current_class,
                class_bases=class_bases,
                aliases=aliases,
            )
            member = self._node_name_text(name_node)
            if owner and node.type != "member_access_expression":
                self._add_ref(owner, owner_node.start_byte, current_callable=None)
            self._add_ref(
                f"{owner}.{member}" if owner and member else member,
                node.start_byte,
                current_callable=current_callable,
                unresolved_member=owner is None,
                trait_dispatch=current_class in self._trait_names
                and owner == current_class,
            )
            return

        if node.type in {"base_clause", "class_interface_clause", "use_declaration"}:
            for child in node.children:
                if child.type in {"name", "qualified_name"}:
                    self._add_ref(
                        self._resolve_name(
                            self._node_name_text(child),
                            namespace=namespace,
                            aliases=aliases,
                            start_byte=child.start_byte,
                        ),
                        child.start_byte,
                        current_callable=None,
                    )

    def _build_call_graph(self) -> None:
        name_to_def = {d.name: d for d in self.defs if d.type != "import"}
        classes = {d.name: d for d in self.defs if d.type == "class"}

        def member_targets(name: str, seen: frozenset[str] = frozenset()) -> set[str]:
            if name in name_to_def:
                return {name}
            if name in seen:
                return set()
            owner, separator, member = name.rpartition(".")
            owner_def = classes.get(owner)
            if not separator or owner_def is None:
                return {name}

            next_seen = seen | {name}
            aliases = self._trait_aliases.get(owner, {}).get(member)
            preferred = self._trait_precedence.get(owner, {}).get(member)
            providers = self._traits_by_owner.get(owner, [])
            trait_members = aliases or (
                {preferred}
                if preferred
                else {f"{trait}.{member}" for trait in providers}
            )
            trait_matches: set[str] = set()
            for target in trait_members:
                trait_matches.update(member_targets(target, next_seen))
            uncertain_traits = any(
                target.rpartition(".")[0] not in classes for target in trait_members
            )
            if trait_matches and not uncertain_traits:
                return trait_matches

            inherited_matches: set[str] = set()
            for base in owner_def.base_classes:
                inherited_matches.update(member_targets(f"{base}.{member}", next_seen))
            return trait_matches | inherited_matches

        def uses_trait(owner: str, trait: str, seen: frozenset[str]) -> bool:
            if owner in seen:
                return False
            providers = self._traits_by_owner.get(owner, [])
            return trait in providers or any(
                uses_trait(provider, trait, seen | {owner}) for provider in providers
            )

        def reference_targets(name: str, *, trait_dispatch: bool) -> set[str]:
            if trait_dispatch:
                owner, _, member = name.rpartition(".")
                consumers = [
                    candidate
                    for candidate in classes
                    if candidate not in self._trait_names
                    and uses_trait(candidate, owner, frozenset())
                ]
                if consumers:
                    targets: set[str] = set()
                    for consumer in consumers:
                        targets.update(member_targets(f"{consumer}.{member}"))
                    return targets or {name}
                # A trait body in another file has no known consuming class.
                # Its $this dispatch may resolve to a class override, so keep
                # the receiver uncertain rather than claiming trait ownership.
                return (member_targets(name) or {name}) | {member}
            return member_targets(name) or {name}

        # Class declarations override traits, and traits override inherited
        # members. An unavailable trait provider stays qualified and uncertain.
        self.refs = [
            (target, file)
            for index, (name, file) in enumerate(self.refs)
            for target in sorted(
                reference_targets(
                    name, trait_dispatch=index in self._trait_dispatch_refs
                )
            )
        ]
        resolved_calls = []
        for caller, callee in self.call_pairs:
            is_trait_dispatch = (caller, callee) in self._trait_dispatch_calls
            for target in sorted(
                reference_targets(callee, trait_dispatch=is_trait_dispatch)
            ):
                if is_trait_dispatch and "." not in target:
                    self._unresolved_member_calls.append((caller, target))
                else:
                    resolved_calls.append((caller, target))
        self.call_pairs = resolved_calls
        member_candidates: dict[str, list[Definition]] = {}
        for definition in self.defs:
            if definition.type in {"method", "variable"}:
                member_candidates.setdefault(definition.simple_name, []).append(
                    definition
                )

        def add_edge(caller_def: Definition, callee_def: Definition) -> None:
            if caller_def is not callee_def:
                caller_def.calls.add(callee_def.name)
                callee_def.called_by.add(caller_def.name)

        for caller, callee in self.call_pairs:
            caller_def = name_to_def.get(caller)
            callee_def = name_to_def.get(callee)
            if caller_def and callee_def:
                add_edge(caller_def, callee_def)
            elif (
                caller_def
                and "." in callee
                and callee.rpartition(".")[0] not in classes
            ):
                # Preserve qualified edges to explicit providers in other files.
                caller_def.calls.add(callee)

        # An unresolved receiver provides no basis to choose a declaration by
        # source order. Keep all local candidate members conservatively live.
        for caller, member in self._unresolved_member_calls:
            caller_def = name_to_def.get(caller)
            if caller_def is not None:
                for candidate in member_candidates.get(member, []):
                    add_edge(caller_def, candidate)
