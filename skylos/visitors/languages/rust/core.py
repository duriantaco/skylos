from __future__ import annotations

from pathlib import Path

from tree_sitter import Language, Parser

try:
    import tree_sitter_rust as tsrust
except ImportError:
    tsrust = None

from skylos.visitors.base import Definition

try:
    RUST_LANG: Language | None = (
        Language(tsrust.language()) if tsrust is not None else None
    )
except Exception:
    RUST_LANG = None

_PARSER_CACHE: dict[int, Parser] = {}

_TYPE_ITEM_TYPES = {
    "struct_item",
    "enum_item",
    "trait_item",
    "union_item",
    "type_item",
}

_DEF_CONTAINER_TYPES = {
    *_TYPE_ITEM_TYPES,
    "function_item",
    "function_signature_item",
    "mod_item",
    "impl_item",
    "field_declaration",
}

_IMPLICIT_ENTRYPOINTS = {"main"}
_IMPLICIT_METHODS = {
    "clone",
    "default",
    "drop",
    "fmt",
    "from",
    "into",
    "try_from",
    "as_ref",
    "as_mut",
    "deref",
    "deref_mut",
    "serialize",
    "deserialize",
    "poll",
    "poll_ready",
    "call",
    "call_once",
    "call_mut",
}


def _get_parser(lang: Language) -> Parser:
    lang_id = id(lang)
    if lang_id not in _PARSER_CACHE:
        _PARSER_CACHE[lang_id] = Parser(lang)
    return _PARSER_CACHE[lang_id]


def _is_test_path(file_path: str | Path) -> bool:
    lower = str(file_path).lower().replace("\\", "/")
    return (
        "/tests/" in lower
        or lower.endswith("_test.rs")
        or lower.endswith("/tests.rs")
        or "/benches/" in lower
    )


def _module_namespace_for_path(file_path: str | Path) -> str:
    path = Path(file_path)
    parts = path.with_suffix("").parts
    if "src" not in parts:
        return ""

    src_index = len(parts) - 1 - list(reversed(parts)).index("src")
    module_parts = list(parts[src_index + 1 :])
    if not module_parts:
        return ""

    if module_parts[0] == "bin":
        return ""
    if module_parts[-1] in {"lib", "main", "mod"}:
        module_parts = module_parts[:-1]
    return ".".join(part for part in module_parts if part)


class RustCore:
    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.imports: list[dict[str, str | int]] = []
        self.raw_imports: list[dict[str, object]] = []
        self.call_pairs: list[tuple[str, str]] = []
        self.test_decorated_lines: set[int] = set()
        self.lang: Language | None = RUST_LANG
        self.is_test_file = _is_test_path(file_path)
        self.root_namespace = _module_namespace_for_path(file_path)
        self._seen_refs: set[tuple[str, int]] = set()

        if self.lang:
            self.parser = _get_parser(self.lang)
            self.tree = self.parser.parse(source_bytes)
            self.root_node = self.tree.root_node
        else:
            self.tree = None
            self.root_node = None

    def _get_text(self, node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def _child_by_type(self, node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def _children_of_type(self, node, type_name: str) -> list:
        return [child for child in node.children if child.type == type_name]

    def _node_name_text(self, node) -> str:
        if node is None:
            return ""
        return self._get_text(node).strip()

    def _qualified_symbol(self, name: str, namespace: str) -> str:
        return f"{namespace}.{name}" if namespace else name

    def _is_public(self, node) -> bool:
        visibility = self._child_by_type(node, "visibility_modifier")
        return visibility is not None and self._get_text(visibility).strip() == "pub"

    def _attrs_text(self, attrs: list) -> list[str]:
        return [self._get_text(attr).strip() for attr in attrs]

    def _has_attr_prefix(self, attrs: list, prefixes: tuple[str, ...]) -> bool:
        for attr in self._attrs_text(attrs):
            if attr.startswith(prefixes):
                return True
        return False

    def _is_test_function(self, name: str, attrs: list, line: int) -> bool:
        if self._has_attr_prefix(
            attrs, ("#[test", "#[tokio::test", "#[async_std::test")
        ):
            self.test_decorated_lines.add(line)
            return True
        if self.is_test_file and name.startswith("test_"):
            self.test_decorated_lines.add(line)
            return True
        return False

    def _add_ref(
        self,
        name: str,
        start_byte: int,
        *,
        current_callable: str | None,
        preserve_qualified: bool = False,
    ) -> None:
        if not name:
            return
        normalized = name.replace("::", ".").strip()
        for prefix in ("crate.", "self.", "super."):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break
        ref_name = (
            normalized
            if preserve_qualified and "." in normalized
            else normalized.split(".")[-1]
        )
        if not ref_name or ref_name in {"self", "Self", "crate", "super"}:
            return
        if current_callable and ref_name == current_callable.split(".")[-1]:
            return
        key = (ref_name, start_byte)
        if key in self._seen_refs:
            return
        self._seen_refs.add(key)
        self.refs.append((ref_name, self.file_path))
        if current_callable:
            self.call_pairs.append((current_callable, ref_name))

    def scan(self) -> None:
        if not self.root_node:
            return
        self._scan_block(
            self.root_node,
            namespace=self.root_namespace,
            current_type=None,
            current_callable=None,
            pending_attrs=[],
        )
        self._build_call_graph()

    def _scan_block(
        self,
        node,
        *,
        namespace: str,
        current_type: str | None,
        current_callable: str | None,
        pending_attrs: list,
    ) -> None:
        attrs: list = list(pending_attrs)
        for child in node.children:
            if child.type == "attribute_item":
                attrs.append(child)
                continue

            if child.type == "use_declaration":
                self._scan_use_imports(child)
                attrs = []
                continue

            if child.type == "mod_item":
                self._scan_mod(child, namespace=namespace, attrs=attrs)
                attrs = []
                continue

            if child.type in _TYPE_ITEM_TYPES:
                self._scan_type_item(child, namespace=namespace, attrs=attrs)
                attrs = []
                continue

            if child.type == "impl_item":
                self._scan_impl(child, namespace=namespace, attrs=attrs)
                attrs = []
                continue

            if child.type == "function_item":
                self._scan_function(
                    child,
                    namespace=namespace,
                    current_type=current_type,
                    attrs=attrs,
                    trait_impl=False,
                )
                attrs = []
                continue

            self._scan_refs_in_node(child, current_callable=current_callable)
            self._scan_block(
                child,
                namespace=namespace,
                current_type=current_type,
                current_callable=current_callable,
                pending_attrs=[],
            )
            attrs = []

    def _scan_mod(self, node, *, namespace: str, attrs: list) -> None:
        name_node = self._child_by_type(node, "identifier")
        mod_name = self._node_name_text(name_node)
        if not mod_name:
            return
        qualified = self._qualified_symbol(mod_name, namespace)
        line = name_node.start_point[0] + 1
        d = Definition(qualified, "module", self.file_path, line)
        d.is_exported = self._is_public(node)
        self.defs.append(d)

        decl_list = self._child_by_type(node, "declaration_list")
        if decl_list is not None:
            self._scan_block(
                decl_list,
                namespace=qualified,
                current_type=None,
                current_callable=None,
                pending_attrs=[],
            )
        else:
            candidates = self._external_mod_sources(mod_name)
            self.raw_imports.append(
                {
                    "source": candidates[0],
                    "names": [mod_name],
                    "line": line,
                    "candidates": candidates,
                }
            )

    def _external_mod_sources(self, mod_name: str) -> list[str]:
        current = Path(self.file_path)
        stem = current.stem
        base_dir = (
            current.parent if stem in {"lib", "main", "mod"} else current.parent / stem
        )
        candidate_paths = [
            base_dir / f"{mod_name}.rs",
            base_dir / mod_name / "mod.rs",
        ]

        existing = [path for path in candidate_paths if path.is_file()]
        ordered = existing or candidate_paths

        sources: list[str] = []
        seen: set[str] = set()
        for candidate in ordered:
            try:
                rel = candidate.relative_to(current.parent)
                source = rel.as_posix()
            except ValueError:
                source = candidate.as_posix()
            if source in seen:
                continue
            seen.add(source)
            sources.append(source)
        return sources

    def _scan_type_item(self, node, *, namespace: str, attrs: list) -> None:
        name_node = self._child_by_type(node, "type_identifier")
        name = self._node_name_text(name_node)
        if not name:
            return
        qualified = self._qualified_symbol(name, namespace)
        line = name_node.start_point[0] + 1
        d = Definition(qualified, "class", self.file_path, line)
        d.is_exported = self._is_public(node)
        d.decorators = self._attrs_text(attrs)
        self.defs.append(d)

        decl_list = self._child_by_type(node, "declaration_list")
        if decl_list is not None and node.type == "trait_item":
            self._scan_trait_members(decl_list, current_type=qualified)

    def _scan_trait_members(self, node, *, current_type: str) -> None:
        attrs: list = []
        for child in node.children:
            if child.type == "attribute_item":
                attrs.append(child)
                continue
            if child.type not in {"function_signature_item", "function_item"}:
                attrs = []
                continue
            name_node = self._child_by_type(child, "identifier")
            name = self._node_name_text(name_node)
            if not name:
                attrs = []
                continue
            qualified = f"{current_type}.{name}"
            d = Definition(
                qualified, "method", self.file_path, name_node.start_point[0] + 1
            )
            d.is_exported = True
            d.decorators = self._attrs_text(attrs)
            self.defs.append(d)
            body = self._child_by_type(child, "block")
            if body is not None:
                self._scan_block(
                    body,
                    namespace="",
                    current_type=current_type,
                    current_callable=qualified,
                    pending_attrs=[],
                )
            attrs = []

    def _scan_impl(self, node, *, namespace: str, attrs: list) -> None:
        type_names = self._impl_header_type_names(node)
        if not type_names:
            return

        trait_impl = any(child.type == "for" for child in node.children)
        owner, _owner_start_byte = type_names[-1]
        if not owner:
            return

        for type_name, start_byte in type_names:
            self._add_ref(
                type_name,
                start_byte,
                current_callable=None,
            )

        qualified_owner = self._qualified_symbol(owner, namespace)
        decl_list = self._child_by_type(node, "declaration_list")
        if decl_list is None:
            return

        inner_attrs: list = []
        for child in decl_list.children:
            if child.type == "attribute_item":
                inner_attrs.append(child)
                continue
            if child.type == "function_item":
                self._scan_function(
                    child,
                    namespace=namespace,
                    current_type=qualified_owner,
                    attrs=inner_attrs,
                    trait_impl=trait_impl,
                )
                inner_attrs = []
                continue
            self._scan_refs_in_node(child, current_callable=None)
            inner_attrs = []

    def _impl_header_type_names(self, node) -> list[tuple[str, int]]:
        names: list[tuple[str, int]] = []

        def collect(child) -> None:
            if child.type in {"type_parameters", "type_arguments", "where_clause"}:
                return
            if child.type in {"type_identifier", "identifier"}:
                name = self._node_name_text(child)
                if name and name not in {"Self"}:
                    names.append((name, child.start_byte))
                return
            for grandchild in child.children:
                collect(grandchild)

        for child in node.children:
            if child.type == "declaration_list":
                break
            collect(child)
        return names

    def _scan_function(
        self,
        node,
        *,
        namespace: str,
        current_type: str | None,
        attrs: list,
        trait_impl: bool,
    ) -> None:
        name_node = self._child_by_type(node, "identifier")
        name = self._node_name_text(name_node)
        if not name:
            return
        line = name_node.start_point[0] + 1
        qualified = (
            f"{current_type}.{name}"
            if current_type
            else self._qualified_symbol(name, namespace)
        )

        d = Definition(
            qualified, "method" if current_type else "function", self.file_path, line
        )
        d.is_exported = (
            self._is_public(node)
            or trait_impl
            or name in _IMPLICIT_ENTRYPOINTS
            or (current_type is not None and name in _IMPLICIT_METHODS)
            or self._is_test_function(name, attrs, line)
            or self._has_attr_prefix(attrs, ("#[tokio::main", "#[actix_web::main"))
        )
        d.decorators = self._attrs_text(attrs)
        self.defs.append(d)

        body = self._child_by_type(node, "block")
        if body is not None:
            self._scan_block(
                body,
                namespace=namespace,
                current_type=current_type,
                current_callable=qualified,
                pending_attrs=[],
            )

    def _scan_use_imports(self, node) -> None:
        line = node.start_point[0] + 1
        source = self._get_text(node).strip()
        is_public_reexport = self._is_public(node)
        source = source.removeprefix("use").strip().rstrip(";")
        if "*" in source:
            self.raw_imports.append({"source": source, "names": ["*"], "line": line})
            return

        names: list[str] = []
        for name in self._extract_use_names(node):
            if not name:
                continue
            d = Definition(name, "import", self.file_path, line)
            d.is_exported = is_public_reexport
            self.defs.append(d)
            self.imports.append(
                {"name": name, "file": str(self.file_path), "line": line}
            )
            names.append(name)
        self.raw_imports.append({"source": source, "names": names, "line": line})

    def _extract_use_names(self, node) -> list[str]:
        if node.type == "use_as_clause":
            identifiers = [
                child for child in node.children if child.type == "identifier"
            ]
            if identifiers:
                return [self._get_text(identifiers[-1]).strip()]
        if node.type == "scoped_use_list":
            use_list = self._child_by_type(node, "use_list")
            if use_list is not None:
                return self._extract_use_names(use_list)
        if node.type in {"identifier", "type_identifier"}:
            return [self._get_text(node).strip()]
        if node.type == "scoped_identifier":
            identifiers = [
                child
                for child in node.children
                if child.type in {"identifier", "type_identifier"}
            ]
            if identifiers:
                return [self._get_text(identifiers[-1]).strip()]

        names: list[str] = []
        for child in node.children:
            names.extend(self._extract_use_names(child))
        seen: set[str] = set()
        unique: list[str] = []
        for name in names:
            if name in {"crate", "self", "super"} or name in seen:
                continue
            seen.add(name)
            unique.append(name)
        return unique

    def _scan_refs_in_node(self, node, *, current_callable: str | None) -> None:
        if node.type == "call_expression":
            callee = node.children[0] if node.children else None
            self._add_callee_refs(callee, current_callable=current_callable)
            return

        if node.type == "macro_invocation":
            name_node = self._child_by_type(node, "identifier")
            self._add_ref(
                self._node_name_text(name_node),
                node.start_byte,
                current_callable=current_callable,
            )
            return

        if node.type == "struct_expression":
            name_node = self._child_by_type(node, "type_identifier")
            self._add_ref(
                self._node_name_text(name_node),
                node.start_byte,
                current_callable=current_callable,
            )
            return

        if node.type == "field_expression":
            name_node = self._child_by_type(node, "field_identifier")
            self._add_ref(
                self._node_name_text(name_node),
                node.start_byte,
                current_callable=current_callable,
            )
            return

        if node.type == "type_identifier" and not self._is_definition_name(node):
            self._add_ref(
                self._node_name_text(node),
                node.start_byte,
                current_callable=current_callable,
            )

    def _add_callee_refs(self, callee, *, current_callable: str | None) -> None:
        if callee is None:
            return
        if callee.type == "identifier":
            self._add_ref(
                self._node_name_text(callee),
                callee.start_byte,
                current_callable=current_callable,
            )
            return
        if callee.type == "scoped_identifier":
            full_name = self._node_name_text(callee)
            self._add_ref(
                full_name,
                callee.start_byte,
                current_callable=current_callable,
                preserve_qualified=True,
            )
            names = [
                self._node_name_text(child)
                for child in callee.children
                if child.type in {"identifier", "type_identifier"}
            ]
            for name in names:
                self._add_ref(
                    name, callee.start_byte, current_callable=current_callable
                )
            return
        if callee.type == "field_expression":
            name_node = self._child_by_type(callee, "field_identifier")
            self._add_ref(
                self._node_name_text(name_node),
                callee.start_byte,
                current_callable=current_callable,
            )

    def _is_definition_name(self, node) -> bool:
        parent = node.parent
        if parent is None:
            return False
        if parent.type in _DEF_CONTAINER_TYPES:
            name_node = self._child_by_type(
                parent, "type_identifier"
            ) or self._child_by_type(parent, "identifier")
            return name_node is node
        return False

    def _build_call_graph(self) -> None:
        name_to_def: dict[str, Definition] = {}
        for d in self.defs:
            name_to_def[d.name] = d
            name_to_def.setdefault(d.simple_name, d)

        for caller, callee in self.call_pairs:
            caller_def = name_to_def.get(caller)
            callee_def = name_to_def.get(callee)
            if caller_def and callee_def and caller_def is not callee_def:
                caller_def.calls.add(callee_def.name)
                callee_def.called_by.add(caller_def.name)
