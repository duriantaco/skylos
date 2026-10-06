from __future__ import annotations

import re
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

_ATTR_PATH_REF_RE = re.compile(
    r'(?:default|serialize_with|deserialize_with|with)\s*=\s*"([A-Za-z_][A-Za-z0-9_:]*)"'
)
_RUST_KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
}
_REGISTRATION_MACROS = {
    "generate_handler",
    "tauri::generate_handler",
    "routes",
    "router",
}

_RUST_EXTERNAL_TRAIT_IMPORTS = {
    "Read": {
        "sources": ("std::io",),
        "methods": ("read", "read_exact", "read_to_end", "read_to_string"),
        "associated": (),
    },
    "Write": {
        "sources": ("std::io",),
        "methods": ("flush", "write", "write_all", "write_fmt"),
        "associated": (),
    },
    "BufRead": {
        "sources": ("std::io",),
        "methods": ("consume", "fill_buf", "lines", "read_line", "split"),
        "associated": (),
    },
    "AsyncReadExt": {
        "sources": ("tokio::io",),
        "methods": ("read", "read_exact", "read_to_end", "read_to_string"),
        "associated": (),
    },
    "AsyncWriteExt": {
        "sources": ("tokio::io",),
        "methods": ("flush", "shutdown", "write", "write_all"),
        "associated": (),
    },
    "AsyncBufReadExt": {
        "sources": ("tokio::io",),
        "methods": ("lines", "read_line", "split"),
        "associated": (),
    },
    "StreamExt": {
        "sources": ("futures", "futures::stream", "futures_util", "tokio_stream"),
        "methods": (
            "buffer_unordered",
            "chunks",
            "collect",
            "filter",
            "for_each",
            "map",
            "next",
            "then",
        ),
        "associated": (),
    },
    "TryStreamExt": {
        "sources": ("futures", "futures::stream", "futures_util", "tokio_stream"),
        "methods": ("map_err", "map_ok", "try_collect", "try_for_each", "try_next"),
        "associated": (),
    },
    "Row": {
        "sources": ("sqlx",),
        "methods": ("columns", "get", "try_get", "try_get_raw"),
        "associated": (),
    },
    "Column": {
        "sources": ("sqlx",),
        "methods": ("name", "ordinal", "type_info"),
        "associated": (),
    },
    "TypeInfo": {
        "sources": ("sqlx",),
        "methods": ("is_null", "name", "type_compatible"),
        "associated": (),
    },
    "ValueRef": {
        "sources": ("sqlx",),
        "methods": ("is_null", "to_owned", "type_info"),
        "associated": (),
    },
    "Executor": {
        "sources": ("sqlx",),
        "methods": ("execute", "fetch", "fetch_all", "fetch_one", "fetch_optional"),
        "associated": (),
    },
    "Connection": {
        "sources": ("sqlx",),
        "methods": ("close",),
        "associated": ("connect", "connect_with"),
    },
    "Emitter": {
        "sources": ("tauri",),
        "methods": ("emit", "emit_filter", "emit_str", "emit_to"),
        "associated": (),
    },
    "Manager": {
        "sources": ("tauri",),
        "methods": (
            "app_handle",
            "get_webview_window",
            "manage",
            "path",
            "state",
            "webview_windows",
        ),
        "associated": (),
    },
    "UpdaterExt": {
        "sources": ("tauri_plugin_updater",),
        "methods": ("updater",),
        "associated": (),
    },
    "Watcher": {
        "sources": ("notify",),
        "methods": ("unwatch", "watch"),
        "associated": (),
    },
    "Digest": {
        "sources": ("sha2", "digest"),
        "methods": ("finalize", "update"),
        "associated": ("digest", "new"),
    },
    "Engine": {
        "sources": ("base64",),
        "methods": ("decode", "decode_slice", "encode", "encode_string"),
        "associated": (),
    },
    "FromStr": {
        "sources": ("std::str",),
        "methods": (),
        "associated": ("from_str",),
    },
    "BinExt": {
        "sources": ("gtk::prelude", "gtk4::prelude"),
        "methods": ("child",),
        "associated": (),
    },
    "Cast": {
        "sources": ("glib", "glib::prelude", "gtk::prelude", "gtk4::prelude"),
        "methods": ("downcast", "dynamic_cast", "upcast"),
        "associated": (),
    },
    "GtkWindowExt": {
        "sources": ("gtk::prelude", "gtk4::prelude"),
        "methods": ("set_titlebar",),
        "associated": (),
    },
    "HeaderBarExt": {
        "sources": ("gtk::prelude", "gtk4::prelude"),
        "methods": ("pack_end", "pack_start", "set_show_close_button"),
        "associated": (),
    },
    "BuilderVerifierExt": {
        "sources": ("rustls_platform_verifier",),
        "methods": ("with_platform_verifier",),
        "associated": (),
    },
    "PermissionsExt": {
        "sources": ("std::os::unix::fs",),
        "methods": ("mode", "set_mode"),
        "associated": (),
    },
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
        self.import_aliases: dict[str, set[str]] = {}
        self._module_scoped_callables: set[str] = set()
        self._local_types: set[str] = set()
        self._generic_types: set[str] = set()
        self._deref_types: set[str] = set()
        self._type_aliases: dict[str, tuple[str, object]] = {}
        self._callable_context: dict[str, tuple[str, str | None]] = {}
        self._callable_nodes: dict[str, object] = {}
        self._return_types: dict[str, object] = {}
        self._member_identifier_bytes: set[int] = set()
        self._seen_refs: set[tuple[str, int]] = set()
        self._trait_call_usage: tuple[set[str], set[tuple[str, str]]] | None = None

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

    def _add_attr_refs(self, attrs: list, *, current_callable: str | None) -> None:
        for attr in attrs:
            text = self._get_text(attr).strip()
            if not text:
                continue
            path_match = re.match(
                r"#\[\s*([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)",
                text,
            )
            if path_match:
                path = path_match.group(1)
                if path not in {"cfg", "allow", "warn", "deny", "derive"}:
                    self._add_ref(
                        path,
                        attr.start_byte + path_match.start(1),
                        current_callable=current_callable,
                        preserve_qualified=True,
                    )
            if text.startswith("#[derive"):
                for name in re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", text):
                    self._add_ref(
                        name,
                        attr.start_byte + text.find(name),
                        current_callable=current_callable,
                    )
            if text.startswith("#[serde"):
                for path in _ATTR_PATH_REF_RE.findall(text):
                    self._add_ref(
                        path,
                        attr.start_byte + text.find(path),
                        current_callable=current_callable,
                        preserve_qualified=True,
                    )

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
        if current_callable and (
            ref_name == current_callable
            or (
                not preserve_qualified
                and current_callable in self._module_scoped_callables
                and self._qualified_symbol(
                    ref_name, self._callable_context[current_callable][0]
                )
                == current_callable
            )
        ):
            return
        self._record_ref(ref_name, start_byte, current_callable=current_callable)

        if preserve_qualified:
            return

        for qualified_ref in self.import_aliases.get(ref_name, ()):
            if qualified_ref != ref_name:
                self._record_ref(
                    qualified_ref,
                    start_byte,
                    current_callable=current_callable,
                )

        sibling_ref = self._sibling_ref(ref_name, current_callable=current_callable)
        if sibling_ref and sibling_ref != ref_name:
            self._record_ref(
                sibling_ref,
                start_byte,
                current_callable=current_callable,
            )

    def _record_ref(
        self,
        ref_name: str,
        start_byte: int,
        *,
        current_callable: str | None,
    ) -> None:
        key = (ref_name, start_byte)
        if key in self._seen_refs:
            return
        self._seen_refs.add(key)
        self.refs.append((ref_name, self.file_path))
        if current_callable:
            self.call_pairs.append((current_callable, ref_name))

    def _sibling_ref(
        self, ref_name: str, *, current_callable: str | None
    ) -> str | None:
        if not current_callable or "." in ref_name:
            return None
        if current_callable not in self._module_scoped_callables:
            return None
        namespace = self._callable_context[current_callable][0]
        return f"{namespace}.{ref_name}" if namespace else None

    def scan(self) -> None:
        if not self.root_node:
            return
        self._collect_identity_items(self.root_node, self.root_namespace)
        self._index_callable_context(self.root_node, self.root_namespace, None)
        self._scan_block(
            self.root_node,
            namespace=self.root_namespace,
            current_type=None,
            current_callable=None,
            pending_attrs=[],
        )
        self._build_call_graph()

    def _collect_identity_items(self, node, namespace: str) -> None:
        if node.type == "mod_item":
            namespace = self._qualified_symbol(
                self._node_name_text(node.child_by_field_name("name")), namespace
            )
        if node.type in _TYPE_ITEM_TYPES:
            name = self._node_name_text(node.child_by_field_name("name"))
            if name:
                qualified = self._qualified_symbol(name, namespace)
                self._local_types.add(qualified)
                if node.child_by_field_name("type_parameters") is not None:
                    self._generic_types.add(qualified)
                if node.type == "type_item":
                    self._type_aliases[qualified] = (
                        namespace,
                        node.child_by_field_name("type"),
                    )
        if node.type == "use_declaration":
            source = self._node_name_text(node.child_by_field_name("argument"))
            if "*" in source:
                return
            for local, original in self._extract_use_bindings(node):
                target = self._qualify_use_import(
                    source,
                    local_name=local,
                    original_name=original,
                    namespace=namespace,
                )
                if target:
                    self.import_aliases.setdefault(local, set()).add(target)
            return
        for child in node.named_children:
            self._collect_identity_items(child, namespace)

    def _impl_owner(self, node, namespace: str) -> str | None:
        owner = node.child_by_field_name("type")
        if owner is not None and owner.type == "generic_type":
            owner = owner.child_by_field_name("type")
        if owner is None:
            return None
        return self._resolve_type_name(
            self._node_name_text(owner), None, namespace_override=namespace
        )

    def _index_callable_context(self, node, namespace: str, owner: str | None) -> None:
        """Collect identities before references, independent of declaration order."""
        if node.type == "mod_item":
            namespace = self._qualified_symbol(
                self._node_name_text(node.child_by_field_name("name")), namespace
            )
            owner = None
        elif node.type in _TYPE_ITEM_TYPES:
            name = self._node_name_text(node.child_by_field_name("name"))
            if name and node.type == "trait_item":
                owner = self._qualified_symbol(name, namespace)
        elif node.type == "impl_item":
            type_names = self._impl_header_type_names(node)
            if type_names:
                owner = self._impl_owner(node, namespace)
                if any(child.type == "for" for child in node.children) and any(
                    name in {"Deref", "DerefMut"} for name, _ in type_names[:-1]
                ):
                    self._deref_types.add(owner)
        elif node.type in {"function_item", "function_signature_item"}:
            name = self._node_name_text(node.child_by_field_name("name"))
            qualified = self._qualified_symbol(name, owner or namespace)
            self._callable_context[qualified] = (namespace, owner)
            self._callable_nodes[qualified] = node
            return_type = node.child_by_field_name("return_type")
            if return_type is not None:
                self._return_types[qualified] = return_type
        for child in node.named_children:
            self._index_callable_context(child, namespace, owner)

    def _type_name(
        self,
        node,
        current_callable: str | None,
        *,
        namespace: str | None = None,
        seen_aliases: frozenset[str] = frozenset(),
    ) -> str | None:
        if node is None:
            return None
        if node.type == "generic_type":
            owner = self._type_name(
                node.child_by_field_name("type"),
                current_callable,
                namespace=namespace,
                seen_aliases=seen_aliases,
            )
            # Local generic types only supply exact, declared member targets.
            # External wrappers have no such local declaration evidence.
            return owner if owner in self._generic_types else None
        if node.type in {"reference_type", "bounded_type"}:
            return self._type_name(
                node.child_by_field_name("type"),
                current_callable,
                namespace=namespace,
                seen_aliases=seen_aliases,
            )
        if node.type not in {"identifier", "type_identifier", "scoped_type_identifier"}:
            return None
        return self._resolve_type_name(
            self._node_name_text(node),
            current_callable,
            namespace_override=namespace,
            seen_aliases=seen_aliases,
        )

    def _resolve_type_alias(
        self, name: str, seen_aliases: frozenset[str]
    ) -> str | None:
        alias = self._type_aliases.get(name)
        if alias is None:
            return name
        if name in seen_aliases or len(seen_aliases) >= 12:
            return None
        namespace, rhs = alias
        return self._type_name(
            rhs,
            None,
            namespace=namespace,
            seen_aliases=seen_aliases | {name},
        )

    def _resolve_type_name(
        self,
        name: str,
        current_callable: str | None,
        *,
        namespace_override: str | None = None,
        seen_aliases: frozenset[str] = frozenset(),
    ) -> str | None:
        namespace, owner = self._callable_context.get(
            current_callable, (self.root_namespace, None)
        )
        if namespace_override is not None:
            namespace = namespace_override
        if name in {"Self", "self"}:
            return owner
        parts = name.split("::")
        context_node = self._callable_nodes.get(current_callable)
        while context_node is not None:
            parameters = context_node.child_by_field_name("type_parameters")
            if parameters is not None:
                for parameter in parameters.named_children:
                    if (
                        self._node_name_text(parameter.child_by_field_name("name"))
                        == parts[0]
                    ):
                        return None
            if context_node.type == "impl_item":
                break
            context_node = context_node.parent
        if parts[0] in {"crate", "self", "super"}:
            resolved = [] if parts[0] == "crate" else namespace.split(".")
            while parts and parts[0] in {"crate", "self", "super"}:
                prefix = parts.pop(0)
                if prefix == "super" and resolved:
                    resolved.pop()
            return self._resolve_type_alias(
                ".".join(part for part in [*resolved, *parts] if part), seen_aliases
            )
        aliases = self.import_aliases.get(parts[0], set())
        if len(aliases) > 1:
            return None
        if len(aliases) == 1:
            return self._resolve_type_alias(
                ".".join([next(iter(aliases)), *parts[1:]]), seen_aliases
            )
        relative = self._qualified_symbol(".".join(parts), namespace)
        if relative in self._local_types:
            return self._resolve_type_alias(relative, seen_aliases)
        absolute = ".".join(parts)
        if absolute in self._local_types or len(parts) > 1:
            return self._resolve_type_alias(absolute, seen_aliases)
        # A signature's explicit type remains useful even if its declaration is
        # in another file. Do not substitute an unrelated local owner by name.
        return relative

    def _binding_type(self, name: str, node, current_callable, depth: int):
        scope = node.parent
        while scope is not None:
            if scope.type == "block":
                for child in reversed(scope.named_children):
                    if (
                        child.end_byte > node.start_byte
                        or child.type != "let_declaration"
                    ):
                        continue
                    pattern = child.child_by_field_name("pattern")
                    if pattern is None or not any(
                        item.type == "identifier" and self._node_name_text(item) == name
                        for item in self._iter_nodes(pattern)
                    ):
                        continue
                    if pattern.type != "identifier":
                        return True, None
                    annotation = child.child_by_field_name("type")
                    if annotation is not None:
                        return True, self._type_name(annotation, current_callable)
                    return True, self._receiver_type(
                        child.child_by_field_name("value"), current_callable, depth + 1
                    )
            if scope.type in {"function_item", "closure_expression"}:
                parameters = scope.child_by_field_name("parameters")
                if parameters is not None:
                    for parameter in parameters.named_children:
                        pattern = parameter.child_by_field_name("pattern")
                        if pattern is not None and any(
                            item.type == "identifier"
                            and self._node_name_text(item) == name
                            for item in self._iter_nodes(pattern)
                        ):
                            if pattern.type != "identifier":
                                return True, None
                            return True, self._type_name(
                                parameter.child_by_field_name("type"), current_callable
                            )
                        if (
                            parameter.type == "identifier"
                            and self._node_name_text(parameter) == name
                        ):
                            return True, None
                if scope.type == "function_item":
                    break
            scope = scope.parent
        return False, None

    def _receiver_type(self, node, current_callable: str | None, depth: int = 0):
        if node is None or depth > 12:
            return None
        if node.type in {"identifier", "self"}:
            name = self._node_name_text(node)
            if name in {"self", "Self"}:
                return self._resolve_type_name(name, current_callable)
            found, owner = self._binding_type(name, node, current_callable, depth)
            if found:
                return owner
            owner = self._resolve_type_name(name, current_callable)
            return owner if owner in self._local_types else None
        if node.type == "struct_expression":
            return self._type_name(node.child_by_field_name("name"), current_callable)
        if node.type in {"reference_expression", "parenthesized_expression"}:
            return self._receiver_type(
                node.named_children[-1], current_callable, depth + 1
            )
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            target = self._qualified_callee(callee, current_callable, depth + 1)
            return_type = self._return_types.get(target)
            if return_type is not None:
                return self._type_name(return_type, target)
        return None

    def _qualified_callee(self, node, current_callable: str | None, depth: int = 0):
        if node is None or depth > 12:
            return None
        if node.type == "generic_function":
            return self._qualified_callee(
                node.child_by_field_name("function"), current_callable, depth + 1
            )
        if node.type == "field_expression":
            owner = self._receiver_type(
                node.child_by_field_name("value"), current_callable, depth + 1
            )
            member = self._node_name_text(node.child_by_field_name("field"))
            return self._member_target(owner, member)
        if node.type == "scoped_identifier":
            text = self._node_name_text(node)
            owner_text, separator, member = text.rpartition("::")
            owner = (
                self._resolve_type_name(owner_text, current_callable)
                if separator
                else None
            )
            target = f"{owner}.{member}" if owner else None
            return (
                target
                if owner in self._local_types or target in self._callable_context
                else None
            )
        return None

    def _member_target(self, owner: str | None, member: str) -> str | None:
        if not owner or not member:
            return None
        target = f"{owner}.{member}"
        if (
            owner in self._generic_types or owner in self._deref_types
        ) and target not in self._callable_context:
            return None
        return target

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
                self._scan_use_imports(child, namespace=namespace)
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

            if attrs:
                self._add_attr_refs(attrs, current_callable=current_callable)
                attrs = []

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
        self._add_attr_refs(attrs, current_callable=None)
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

        if node.type == "type_item":
            self._scan_type_alias_rhs(node, namespace=namespace)

        decl_list = self._child_by_type(node, "declaration_list")
        if decl_list is None:
            decl_list = self._child_by_type(node, "field_declaration_list")
        if decl_list is not None and node.type == "trait_item":
            self._scan_trait_members(decl_list, current_type=qualified)
        elif decl_list is not None:
            self._scan_block(
                decl_list,
                namespace=namespace,
                current_type=qualified,
                current_callable=None,
                pending_attrs=[],
            )

    def _scan_type_alias_rhs(self, node, *, namespace: str) -> None:
        seen_equals = False
        for child in node.children:
            if child.type == "=":
                seen_equals = True
                continue
            if not seen_equals:
                continue
            if child.type == ";":
                break
            self._scan_block(
                child,
                namespace=namespace,
                current_type=None,
                current_callable=None,
                pending_attrs=[],
            )

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
            self._scan_signature_refs(
                child,
                namespace="",
                current_type=current_type,
                current_callable=qualified,
            )
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
        self._add_attr_refs(attrs, current_callable=None)
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

        qualified_owner = self._impl_owner(node, namespace)
        if qualified_owner is None:
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
        self._add_attr_refs(attrs, current_callable=None)
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
        if current_type is None:
            self._module_scoped_callables.add(qualified)
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

        self._scan_signature_refs(
            node,
            namespace=namespace,
            current_type=current_type,
            current_callable=qualified,
        )

        body = self._child_by_type(node, "block")
        if body is not None:
            self._scan_block(
                body,
                namespace=namespace,
                current_type=current_type,
                current_callable=qualified,
                pending_attrs=[],
            )

    def _scan_signature_refs(
        self,
        node,
        *,
        namespace: str,
        current_type: str | None,
        current_callable: str,
    ) -> None:
        type_parameters = self._child_by_type(node, "type_parameters")
        if type_parameters is not None:
            self._scan_block(
                type_parameters,
                namespace=namespace,
                current_type=current_type,
                current_callable=current_callable,
                pending_attrs=[],
            )

        parameters = self._child_by_type(node, "parameters")
        if parameters is not None:
            self._scan_block(
                parameters,
                namespace=namespace,
                current_type=current_type,
                current_callable=current_callable,
                pending_attrs=[],
            )

        where_clause = self._child_by_type(node, "where_clause")
        if where_clause is not None:
            self._scan_block(
                where_clause,
                namespace=namespace,
                current_type=current_type,
                current_callable=current_callable,
                pending_attrs=[],
            )

        in_return_type = False
        for child in node.children:
            if child.type == "->":
                in_return_type = True
                continue
            if not in_return_type:
                continue
            if child.type == "block":
                break
            self._scan_block(
                child,
                namespace=namespace,
                current_type=current_type,
                current_callable=current_callable,
                pending_attrs=[],
            )

    def _scan_use_imports(self, node, *, namespace: str) -> None:
        line = node.start_point[0] + 1
        source = self._node_name_text(node.child_by_field_name("argument"))
        is_public_reexport = self._is_public(node)
        if "*" in source:
            self.raw_imports.append({"source": source, "names": ["*"], "line": line})
            return

        names: list[str] = []
        for local_name, original_name in self._extract_use_bindings(node):
            if not local_name:
                continue
            d = Definition(local_name, "import", self.file_path, line)
            d.is_exported = is_public_reexport
            self.defs.append(d)
            self.imports.append(
                {"name": local_name, "file": str(self.file_path), "line": line}
            )
            names.append(local_name)
            qualified_import = self._qualify_use_import(
                source,
                local_name=local_name,
                original_name=original_name,
                namespace=namespace,
            )
            if qualified_import:
                self.import_aliases.setdefault(local_name, set()).add(qualified_import)
            if self._external_trait_import_is_used(
                source,
                local_name=local_name,
                original_name=original_name,
            ):
                self._record_ref(local_name, node.start_byte, current_callable=None)
        self.raw_imports.append({"source": source, "names": names, "line": line})

    def _extract_use_bindings(self, node) -> list[tuple[str, str]]:
        if node.type == "use_as_clause":
            return self._extract_use_as_binding(node)
        if node.type == "scoped_use_list":
            use_list = self._child_by_type(node, "use_list")
            if use_list is not None:
                return self._extract_use_bindings(use_list)
        if node.type in {"identifier", "type_identifier"}:
            name = self._get_text(node).strip()
            return [(name, name)]
        if node.type == "scoped_identifier":
            return self._extract_scoped_leaf_binding(node)

        bindings: list[tuple[str, str]] = []
        for child in node.children:
            bindings.extend(self._extract_use_bindings(child))
        return self._dedupe_use_bindings(bindings)

    def _extract_use_as_binding(self, node) -> list[tuple[str, str]]:
        path = node.child_by_field_name("path")
        alias = node.child_by_field_name("alias")
        if path is not None and alias is not None:
            return [
                (
                    self._node_name_text(alias),
                    self._node_name_text(path).split("::")[-1],
                )
            ]
        identifiers = [child for child in node.children if child.type == "identifier"]
        if len(identifiers) >= 2:
            original = self._get_text(identifiers[0]).strip()
            alias = self._get_text(identifiers[-1]).strip()
            return [(alias, original)]
        if identifiers:
            name = self._get_text(identifiers[-1]).strip()
            return [(name, name)]
        return []

    def _extract_scoped_leaf_binding(self, node) -> list[tuple[str, str]]:
        identifiers = [
            child
            for child in node.children
            if child.type in {"identifier", "type_identifier"}
        ]
        if not identifiers:
            return []
        name = self._get_text(identifiers[-1]).strip()
        return [(name, name)]

    def _dedupe_use_bindings(
        self, bindings: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for local_name, original_name in bindings:
            if local_name in {"crate", "self", "super"} or local_name in seen:
                continue
            seen.add(local_name)
            unique.append((local_name, original_name))
        return unique

    def _qualify_use_import(
        self,
        source: str,
        *,
        local_name: str,
        original_name: str,
        namespace: str | None = None,
    ) -> str | None:
        target = source.strip()
        if "{" in target:
            base = target.split("{", 1)[0].rstrip(":").strip()
            if not base:
                return None
            target = f"{base}::{original_name}"
        else:
            target = target.split(" as ", 1)[0].strip()
        if not target or "::" not in target:
            return None
        parts = [part for part in target.split("::") if part and part != local_name]
        if not parts:
            return None
        if parts[-1] != original_name:
            parts.append(original_name)
        return self._resolve_rust_path(parts, namespace=namespace)

    def _resolve_rust_path(
        self, parts: list[str], *, namespace: str | None = None
    ) -> str | None:
        if not parts:
            return None

        namespace_parts = [
            part
            for part in (self.root_namespace if namespace is None else namespace).split(
                "."
            )
            if part
        ]
        resolved: list[str]
        index = 0

        first = parts[0]
        if first == "crate":
            resolved = []
            index = 1
        elif first == "self":
            resolved = list(namespace_parts)
            index = 1
        elif first == "super":
            resolved = list(namespace_parts)
            while index < len(parts) and parts[index] == "super":
                if resolved:
                    resolved.pop()
                index += 1
        else:
            resolved = list(namespace_parts)

        resolved.extend(parts[index:])
        return ".".join(part for part in resolved if part)

    def _external_trait_import_is_used(
        self,
        source: str,
        *,
        local_name: str,
        original_name: str,
    ) -> bool:
        trait_name = original_name if original_name != "_" else local_name
        spec = _RUST_EXTERNAL_TRAIT_IMPORTS.get(trait_name)
        if not spec:
            return False

        base = self._use_import_base(source)
        if not base:
            return False
        if base.split("::", 1)[0] in {"crate", "self", "super"}:
            return False
        if not self._source_matches_trait_spec(base, spec["sources"]):
            return False

        method_names, associated_calls = self._collect_trait_call_usage()
        if set(spec["methods"]) & method_names:
            return True

        associated_names = set(spec["associated"])
        if associated_names:
            for owner, method in associated_calls:
                if method in associated_names and owner[:1].isupper():
                    return True

        return False

    def _use_import_base(self, source: str) -> str:
        target = source.strip()
        if "{" in target:
            return target.split("{", 1)[0].rstrip(":").strip()
        target = target.split(" as ", 1)[0].strip()
        parts = [part for part in target.split("::") if part]
        if len(parts) <= 1:
            return ""
        return "::".join(parts[:-1])

    def _source_matches_trait_spec(self, base: str, sources: tuple[str, ...]) -> bool:
        return any(
            base == source or base.startswith(f"{source}::") for source in sources
        )

    def _collect_trait_call_usage(self) -> tuple[set[str], set[tuple[str, str]]]:
        if self._trait_call_usage is not None:
            return self._trait_call_usage

        method_names: set[str] = set()
        associated_calls: set[tuple[str, str]] = set()

        if self.root_node is None:
            self._trait_call_usage = (method_names, associated_calls)
            return self._trait_call_usage

        for node in self._iter_nodes(self.root_node):
            method_name = self._trait_method_name_from_node(node)
            if method_name:
                method_names.add(method_name)
                continue

            associated_call = self._trait_associated_call_from_node(node)
            if associated_call is not None:
                associated_calls.add(associated_call)

        self._trait_call_usage = (method_names, associated_calls)
        return self._trait_call_usage

    def _call_parent(self, node):
        parent = node.parent
        if parent is not None and parent.type == "generic_function":
            parent = parent.parent
        return (
            parent if parent is not None and parent.type == "call_expression" else None
        )

    def _trait_method_name_from_node(self, node) -> str | None:
        if node.type != "field_expression" or self._call_parent(node) is None:
            return None
        name_node = self._child_by_type(node, "field_identifier")
        name = self._node_name_text(name_node)
        return name or None

    def _trait_associated_call_from_node(self, node) -> tuple[str, str] | None:
        if node.type != "scoped_identifier" or self._call_parent(node) is None:
            return None
        identifiers = [
            self._node_name_text(child)
            for child in node.children
            if child.type in {"identifier", "type_identifier"}
        ]
        if len(identifiers) < 2:
            return None
        return identifiers[-2], identifiers[-1]

    def _iter_nodes(self, root_node):
        stack = [root_node]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    def _scan_refs_in_node(self, node, *, current_callable: str | None) -> None:
        if node.type == "token_tree":
            # Rust leaves macro arguments as tokens. Keep obvious method-call
            # receivers without interpreting or executing the macro itself.
            children = node.children
            for index in range(2, len(children) - 1):
                member = children[index]
                if (
                    member.type != "identifier"
                    or children[index - 1].type != "."
                    or children[index + 1].type != "token_tree"
                    or not children[index + 1].children
                    or children[index + 1].children[0].type != "("
                ):
                    continue
                owner = self._receiver_type(children[index - 2], current_callable)
                name = self._node_name_text(member)
                self._add_ref(
                    self._member_target(owner, name) or f"~.{name}",
                    member.start_byte,
                    current_callable=current_callable,
                    preserve_qualified=True,
                )
                self._member_identifier_bytes.add(member.start_byte)
            return

        if node.type == "call_expression":
            callee = node.children[0] if node.children else None
            self._add_callee_refs(callee, current_callable=current_callable)
            return

        if node.type == "macro_invocation":
            name_node = self._child_by_type(node, "identifier")
            macro_name = self._node_name_text(name_node)
            self._add_ref(
                macro_name,
                node.start_byte,
                current_callable=current_callable,
            )
            if macro_name in _REGISTRATION_MACROS:
                self._scan_registration_macro_refs(
                    node,
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
            target = self._qualified_callee(node, current_callable)
            name = self._node_name_text(name_node)
            self._add_ref(
                target or f"~.{name}",
                node.start_byte,
                current_callable=current_callable,
                preserve_qualified=True,
            )
            return

        if node.type == "identifier" and self._is_reference_identifier(node):
            if node.start_byte in self._member_identifier_bytes:
                return
            parent = node.parent
            if (
                parent is not None
                and parent.type == "scoped_identifier"
                and parent.child_by_field_name("name") == node
                and self._qualified_callee(parent, current_callable)
            ):
                return
            self._add_ref(
                self._node_name_text(node),
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

    def _scan_registration_macro_refs(
        self, node, *, current_callable: str | None
    ) -> None:
        text = self._get_text(node)
        for match in re.finditer(
            r"\b[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\b", text
        ):
            name = match.group(0)
            if name in _RUST_KEYWORDS or name == self._node_name_text(
                self._child_by_type(node, "identifier")
            ):
                continue
            self._add_ref(
                name,
                node.start_byte + match.start(),
                current_callable=current_callable,
                preserve_qualified=True,
            )

    def _add_callee_refs(self, callee, *, current_callable: str | None) -> None:
        if callee is None:
            return
        if callee.type == "generic_function":
            self._add_callee_refs(
                callee.child_by_field_name("function"),
                current_callable=current_callable,
            )
            return
        if callee.type == "identifier":
            self._add_ref(
                self._node_name_text(callee),
                callee.start_byte,
                current_callable=current_callable,
            )
            return
        if callee.type == "scoped_identifier":
            target = self._qualified_callee(callee, current_callable)
            if target:
                self._add_ref(
                    target,
                    callee.start_byte,
                    current_callable=current_callable,
                    preserve_qualified=True,
                )
                return
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
            target = self._qualified_callee(callee, current_callable)
            name = self._node_name_text(name_node)
            self._add_ref(
                target or f"~.{name}",
                callee.start_byte,
                current_callable=current_callable,
                preserve_qualified=True,
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

    def _is_reference_identifier(self, node) -> bool:
        name = self._node_name_text(node)
        if not name or name in _RUST_KEYWORDS:
            return False
        if self._is_definition_name(node):
            return False
        parent = node.parent
        if parent is None:
            return False
        if parent.type in {
            "use_declaration",
            "field_declaration",
            "field_identifier",
            "let_declaration",
            "parameter",
            "self_parameter",
            "for",
            "visibility_modifier",
        }:
            return False
        if parent.type in _DEF_CONTAINER_TYPES:
            return False
        return True

    def _build_call_graph(self) -> None:
        exact_defs: dict[str, list[Definition]] = {}
        name_to_defs: dict[str, list[Definition]] = {}
        for d in self.defs:
            exact_defs.setdefault(d.name, []).append(d)
            name_to_defs.setdefault(d.simple_name, []).append(d)

        for caller, callee in self.call_pairs:
            callers = exact_defs.get(caller, [])
            callees = exact_defs.get(callee, []) or name_to_defs.get(callee, [])
            caller_def = callers[0] if len(callers) == 1 else None
            callee_def = callees[0] if len(callees) == 1 else None
            if caller_def and callee_def and caller_def is not callee_def:
                caller_def.calls.add(callee_def.name)
                callee_def.called_by.add(caller_def.name)
