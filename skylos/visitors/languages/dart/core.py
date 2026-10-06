from __future__ import annotations

import re
from pathlib import Path

from tree_sitter import Language, Parser

try:
    import tree_sitter_dart_orchard as tsdart
except ImportError:
    tsdart = None

from skylos.visitors.base import Definition

try:
    DART_LANG: Language | None = (
        Language(tsdart.language()) if tsdart is not None else None
    )
except Exception:
    DART_LANG = None

_PARSER_CACHE: dict[int, Parser] = {}

_FLUTTER_BASES = {
    "StatelessWidget",
    "StatefulWidget",
    "State",
    "Widget",
}

_FLUTTER_LIFECYCLE_METHODS = {
    "build",
    "createState",
    "initState",
    "dispose",
    "didChangeDependencies",
    "didUpdateWidget",
    "reassemble",
    "deactivate",
    "activate",
}

_TEST_ENTRYPOINTS = {
    "main",
    "setUp",
    "setUpAll",
    "tearDown",
    "tearDownAll",
}


def _get_parser(lang: Language) -> Parser:
    lang_id = id(lang)
    if lang_id not in _PARSER_CACHE:
        _PARSER_CACHE[lang_id] = Parser(lang)
    return _PARSER_CACHE[lang_id]


def _is_test_path(file_path: str | Path) -> bool:
    lower = str(file_path).lower().replace("\\", "/")
    return "/test/" in lower or lower.endswith("_test.dart")


def _is_private_name(name: str) -> bool:
    return name.startswith("_")


class DartCore:
    def __init__(self, file_path: str, source_bytes: bytes) -> None:
        self.file_path: str = file_path
        self.source: bytes = source_bytes
        self.defs: list[Definition] = []
        self.refs: list[tuple[str, str]] = []
        self.raw_imports: list[dict[str, object]] = []
        self.call_pairs: list[tuple[str, str]] = []
        self.test_decorated_lines: set[int] = set()
        self.lang: Language | None = DART_LANG
        self.is_test_file = _is_test_path(file_path)
        self._seen_refs: set[tuple[str, int]] = set()
        self._call_sites: dict[tuple[int, str | None], tuple] = {}
        self._callable_signatures: dict[str, object] = {}
        self._ambiguous_calls: set[tuple[str | None, str]] = set()
        self._constructors: set[str] = set()

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

    def _name_node(self, node):
        by_field = node.child_by_field_name("name")
        if by_field is not None:
            return by_field
        for child in node.children:
            if child.type in {"identifier", "type_identifier"}:
                return child
        return None

    def _first_descendant_of_type(self, node, type_name: str):
        if node.type == type_name:
            return node
        for child in node.children:
            found = self._first_descendant_of_type(child, type_name)
            if found is not None:
                return found
        return None

    def _descendants_of_type(self, node, type_name: str):
        if node.type == type_name:
            yield node
        for child in node.children:
            yield from self._descendants_of_type(child, type_name)

    def _function_signature_name_node(self, signature):
        name_node = signature.child_by_field_name("name")
        if name_node is not None:
            return name_node
        params = self._child_by_type(signature, "formal_parameter_list")
        candidates = []
        for child in signature.children:
            if child is params:
                break
            if child.type == "identifier":
                candidates.append(child)
        return candidates[-1] if candidates else None

    def _next_body(self, siblings: list, index: int):
        if index + 1 < len(siblings) and siblings[index + 1].type == "function_body":
            return siblings[index + 1]
        return None

    def _add_ref(
        self, name: str, start_byte: int, *, current_callable: str | None
    ) -> None:
        if not name:
            return
        simple = name.split(".")[-1].strip()
        if not simple or simple in {"this", "super", "true", "false", "null"}:
            return
        if current_callable and name == current_callable:
            return
        key = (name, start_byte)
        if key in self._seen_refs:
            return
        self._seen_refs.add(key)
        self.refs.append((name, self.file_path))
        if current_callable:
            self.call_pairs.append((current_callable, name))

    def scan(self) -> None:
        if not self.root_node:
            return
        self._scan_block(self.root_node, current_class=None, current_callable=None)
        self._resolve_call_sites()
        self._build_call_graph()

    def _scan_block(
        self,
        node,
        *,
        current_class: str | None,
        current_callable: str | None,
    ) -> None:
        children = list(node.children)
        index = 0
        while index < len(children):
            child = children[index]

            if child.type == "import_or_export":
                self._scan_import_or_export(child)
                index += 1
                continue

            if child.type == "class_definition":
                self._scan_class(child)
                index += 1
                continue

            if child.type == "enum_declaration":
                self._scan_enum(child)
                index += 1
                continue

            if child.type == "function_signature":
                body = self._next_body(children, index)
                self._scan_function(child, body)
                index += 2 if body is not None else 1
                continue

            if child.type == "static_final_declaration_list":
                self._scan_static_final_declarations(
                    child, current_class=current_class, is_exported=False
                )
                self._scan_refs_in_node(child, current_callable=current_callable)
                index += 1
                continue

            self._scan_refs_in_node(child, current_callable=current_callable)
            self._scan_block(
                child,
                current_class=current_class,
                current_callable=current_callable,
            )
            index += 1

    def _scan_import_or_export(self, node) -> None:
        text = self._get_text(node).strip()
        uri_node = self._first_descendant_of_type(node, "string_literal")
        source = self._get_text(uri_node).strip("\"'") if uri_node is not None else ""
        names: list[str] = []

        for combinator in self._descendants_of_type(node, "combinator"):
            comb_text = self._get_text(combinator).strip()
            if not comb_text.startswith("show "):
                continue
            for ident in self._descendants_of_type(combinator, "identifier"):
                name = self._node_name_text(ident)
                if not name or name in {"show", "hide"}:
                    continue
                names.append(name)
                d = Definition(name, "import", self.file_path, ident.start_point[0] + 1)
                self.defs.append(d)

        if not names and text.startswith("import "):
            prefix_node = None
            match = re.search(r"\bas\s+([A-Za-z_]\w*)", text)
            if match:
                source_name = match.group(1)
                prefix_node = node
            elif source.startswith("package:"):
                source_name = source.split("/")[-1].removesuffix(".dart")
            else:
                source_name = Path(source).stem
            if source_name and source_name not in {".", ""}:
                names.append(source_name)
                line = (
                    prefix_node.start_point[0] + 1
                    if prefix_node
                    else node.start_point[0] + 1
                )
                d = Definition(source_name, "import", self.file_path, line)
                self.defs.append(d)

        self.raw_imports.append(
            {"source": source, "names": names, "line": node.start_point[0] + 1}
        )

    def _scan_class(self, node) -> None:
        name_node = self._name_node(node)
        class_name = self._node_name_text(name_node)
        if not class_name:
            return

        bases: list[str] = []
        for base_node in self._descendants_of_type(node, "type_identifier"):
            if base_node is name_node:
                continue
            parent = base_node.parent
            if parent is not None and parent.type in {
                "superclass",
                "interfaces",
                "mixins",
            }:
                base_name = self._node_name_text(base_node)
                bases.append(base_name)
                self._add_ref(base_name, base_node.start_byte, current_callable=None)

        d = Definition(
            class_name, "class", self.file_path, name_node.start_point[0] + 1
        )
        d.base_classes = bases
        d.is_exported = not _is_private_name(class_name) and any(
            base in _FLUTTER_BASES for base in bases
        )
        self.defs.append(d)

        body = self._child_by_type(node, "class_body")
        if body is None:
            return

        children = list(body.children)
        index = 0
        while index < len(children):
            child = children[index]

            if child.type == "declaration":
                self._scan_class_declaration(child, current_class=class_name)
                index += 1
                continue

            if child.type == "method_signature":
                body_node = self._next_body(children, index)
                self._scan_method(
                    child,
                    body_node,
                    current_class=class_name,
                    class_bases=bases,
                )
                if body_node is not None:
                    index += 2
                else:
                    index += 1
                continue

            index += 1

    def _scan_class_declaration(self, node, *, current_class: str) -> None:
        constructor = self._first_descendant_of_type(node, "constructor_signature")
        if constructor is None:
            constructor = self._first_descendant_of_type(
                node, "constant_constructor_signature"
            )
        if constructor is not None:
            names = self._children_of_type(constructor, "identifier")
            name_node = names[-1] if names else self._name_node(constructor)
            constructor_name = self._node_name_text(name_node) or current_class
            qualified = f"{current_class}.{constructor_name}"
            self._constructors.add(qualified)
            d = Definition(
                qualified,
                "method",
                self.file_path,
                constructor.start_point[0] + 1,
            )
            d.is_exported = not _is_private_name(constructor_name)
            self.defs.append(d)

            params = self._first_descendant_of_type(
                constructor, "formal_parameter_list"
            )
            if params is not None:
                for param in self._descendants_of_type(
                    params, "super_formal_parameter"
                ):
                    ident = self._child_by_type(param, "identifier")
                    if ident is not None:
                        self._add_ref(
                            self._node_name_text(ident),
                            ident.start_byte,
                            current_callable=qualified,
                        )
                for param in self._descendants_of_type(params, "constructor_param"):
                    ident = self._child_by_type(param, "identifier")
                    if ident is not None:
                        self._add_ref(
                            self._node_name_text(ident),
                            ident.start_byte,
                            current_callable=qualified,
                        )
            return

        field_list = self._first_descendant_of_type(node, "initialized_identifier_list")
        if field_list is not None:
            for ident in self._descendants_of_type(field_list, "identifier"):
                field_name = self._node_name_text(ident)
                if not field_name:
                    continue
                d = Definition(
                    f"{current_class}.{field_name}",
                    "variable",
                    self.file_path,
                    ident.start_point[0] + 1,
                )
                d.is_exported = not _is_private_name(field_name)
                self.defs.append(d)

        static_final = self._first_descendant_of_type(
            node, "static_final_declaration_list"
        )
        if static_final is not None:
            self._scan_static_final_declarations(
                static_final,
                current_class=current_class,
                is_exported=True,
            )

    def _scan_method(
        self,
        node,
        body,
        *,
        current_class: str,
        class_bases: list[str],
    ) -> None:
        signature = self._first_descendant_of_type(node, "function_signature")
        if signature is None:
            return
        name_node = self._function_signature_name_node(signature)
        method_name = self._node_name_text(name_node)
        if not method_name:
            return

        qualified = f"{current_class}.{method_name}"
        self._callable_signatures[qualified] = signature
        d = Definition(
            qualified, "method", self.file_path, name_node.start_point[0] + 1
        )
        implicit = self._is_implicit_method(method_name, class_bases, node)
        d.is_exported = implicit or not _is_private_name(method_name)
        if implicit:
            self.test_decorated_lines.add(name_node.start_point[0] + 1)
        self.defs.append(d)

        if body is not None:
            self._scan_refs_in_node(body, current_callable=qualified)
            self._scan_block(
                body,
                current_class=current_class,
                current_callable=qualified,
            )

    def _is_implicit_method(self, name: str, bases: list[str], node) -> bool:
        if name in _FLUTTER_LIFECYCLE_METHODS and any(
            base in _FLUTTER_BASES for base in bases
        ):
            return True
        return False

    def _scan_function(self, signature, body) -> None:
        name_node = self._function_signature_name_node(signature)
        func_name = self._node_name_text(name_node)
        if not func_name:
            return
        self._callable_signatures[func_name] = signature
        d = Definition(
            func_name, "function", self.file_path, name_node.start_point[0] + 1
        )
        d.is_exported = (
            func_name == "main"
            or (self.is_test_file and func_name in _TEST_ENTRYPOINTS)
            or (self.is_test_file and func_name.startswith("test"))
        )
        if d.is_exported:
            self.test_decorated_lines.add(name_node.start_point[0] + 1)
        self.defs.append(d)

        if body is not None:
            self._scan_refs_in_node(body, current_callable=func_name)
            self._scan_block(body, current_class=None, current_callable=func_name)

    def _scan_enum(self, node) -> None:
        name_node = self._name_node(node)
        enum_name = self._node_name_text(name_node)
        if not enum_name:
            return
        d = Definition(enum_name, "class", self.file_path, name_node.start_point[0] + 1)
        d.is_exported = not _is_private_name(enum_name)
        self.defs.append(d)

        body = self._child_by_type(node, "enum_body")
        if body is None:
            return
        for const_node in self._descendants_of_type(body, "enum_constant"):
            ident = self._child_by_type(const_node, "identifier")
            name = self._node_name_text(ident)
            if not name:
                continue
            const_def = Definition(
                f"{enum_name}.{name}",
                "variable",
                self.file_path,
                ident.start_point[0] + 1,
            )
            const_def.is_exported = not _is_private_name(enum_name)
            self.defs.append(const_def)

    def _scan_static_final_declarations(
        self,
        node,
        *,
        current_class: str | None,
        is_exported: bool,
    ) -> None:
        for declaration in self._descendants_of_type(node, "static_final_declaration"):
            ident = self._child_by_type(declaration, "identifier")
            name = self._node_name_text(ident)
            if not name:
                continue
            qualified = f"{current_class}.{name}" if current_class else name
            d = Definition(
                qualified,
                "variable",
                self.file_path,
                ident.start_point[0] + 1,
            )
            d.is_exported = is_exported and not _is_private_name(name)
            self.defs.append(d)

    def _scan_refs_in_node(self, node, *, current_callable: str | None) -> None:
        if node.type == "identifier" and self._is_value_reference(node):
            # Passing a function or method without parentheses is a tear-off,
            # not an unused declaration. Resolve its owner exactly like a call.
            local, _ = self._local_receiver_class(
                self._node_name_text(node), node, current_callable, {}
            )
            if not local:
                self._record_call(node, node.parent, None, current_callable)

        if node.type == "method_invocation":
            function = node.child_by_field_name("function")
            identifiers = (
                list(self._descendants_of_type(function, "identifier"))
                if function is not None
                else []
            )
            if identifiers:
                called = identifiers[-1]
                receiver = None
                if function.type == "unconditional_assignable_selector":
                    receiver = next(
                        (child for child in function.named_children if child != called),
                        None,
                    )
                self._record_call(called, node, receiver, current_callable)

        children = list(node.children)
        for idx, child in enumerate(children):
            next_child = children[idx + 1] if idx + 1 < len(children) else None
            next_next = children[idx + 2] if idx + 2 < len(children) else None

            if child.type == "identifier" and self._selector_is_call(next_child):
                self._record_call(child, node, None, current_callable)

            if (
                child.type == "selector"
                and self._selector_name(child)
            ):
                ident = self._first_descendant_of_type(child, "identifier")
                receiver = children[idx - 1] if idx else None
                if ident is not None:
                    self._record_call(ident, node, receiver, current_callable)

            if (
                child.type == "unconditional_assignable_selector"
                and self._selector_is_call(next_child or next_next)
            ):
                ident = self._child_by_type(child, "identifier")
                receiver = children[idx - 1] if idx else None
                if ident is not None:
                    self._record_call(ident, node, receiver, current_callable)

            self._scan_refs_in_node(child, current_callable=current_callable)

    def _is_value_reference(self, node) -> bool:
        parent = node.parent
        if parent is None:
            return False
        if parent.type in {
            "argument",
            "named_argument",
            "return_statement",
            "function_body",
            "conditional_expression",
            "list_literal",
        }:
            return True
        if parent.type == "initialized_variable_definition":
            return parent.child_by_field_name("name") != node
        if parent.type == "assignment_expression":
            return parent.child_by_field_name("right") == node
        return False

    def _record_call(self, called, node, receiver, current_callable) -> None:
        key = (called.start_byte, current_callable)
        self._call_sites.setdefault(key, (called, node, receiver, current_callable))

    def _receiver_class(self, receiver, node, current_callable, classes):
        if receiver is None:
            return None
        text = self._get_text(receiver).strip()
        current_class = (
            current_callable.rsplit(".", 1)[0]
            if current_callable and "." in current_callable
            else None
        )
        if text == "this":
            return current_class
        if text == "super" and current_class in classes:
            bases = classes[current_class].base_classes
            return bases[0] if len(bases) == 1 and bases[0] in classes else None
        if receiver.type == "method_invocation":
            function = receiver.child_by_field_name("function")
            if function is not None and function.type == "identifier":
                constructor = self._node_name_text(function)
                return constructor if constructor in classes else None
            return None
        if receiver.type != "identifier":
            return None
        found, owner = self._local_receiver_class(text, node, current_callable, classes)
        if found:
            return owner
        return text if text in classes else None

    def _local_receiver_class(self, name, node, current_callable, classes):
        # Search enclosing blocks, so a nearer unknown binding also shadows a
        # known outer binding. Only declared types and final constructor values
        # are used; inferring mutable variables would require control-flow data.
        child = node
        parent = node.parent
        while parent is not None:
            if parent.type == "block":
                for sibling in reversed(parent.named_children):
                    if sibling.start_byte >= child.start_byte:
                        continue
                    if sibling.type != "local_variable_declaration":
                        continue
                    binding = self._child_by_type(
                        sibling, "initialized_variable_definition"
                    )
                    if binding is None:
                        continue
                    ident = self._child_by_type(binding, "identifier")
                    if self._node_name_text(ident) != name:
                        continue
                    type_node = self._child_by_type(binding, "type_identifier")
                    declared = self._node_name_text(type_node)
                    if declared in classes:
                        return True, declared
                    if self._child_by_type(binding, "final_builtin") is not None:
                        initializer = self._child_by_type(binding, "method_invocation")
                        if initializer is not None:
                            return True, self._receiver_class(
                                initializer, initializer, current_callable, classes
                            )
                    return True, None
            child, parent = parent, parent.parent

        signature = self._callable_signatures.get(current_callable)
        if signature is not None:
            params = self._child_by_type(signature, "formal_parameter_list")
            if params is not None:
                for param in self._descendants_of_type(params, "formal_parameter"):
                    ident = self._child_by_type(param, "identifier")
                    if self._node_name_text(ident) == name:
                        declared = self._node_name_text(
                            self._child_by_type(param, "type_identifier")
                        )
                        return True, declared if declared in classes else None
        return False, None

    def _member_target(self, owner, name, classes, definitions, seen=None):
        target = f"{owner}.{name}"
        if target in definitions:
            return target if definitions[target].type == "method" else None
        seen = set() if seen is None else seen
        if owner in seen or owner not in classes:
            return None
        seen.add(owner)
        bases = classes[owner].base_classes
        if not bases:
            return target
        if len(bases) == 1:
            return self._member_target(bases[0], name, classes, definitions, seen)
        # Mixin/interface dispatch is not resolved by this syntax-only pass.
        return None

    def _resolve_call_sites(self) -> None:
        definitions = {d.name: d for d in self.defs}
        classes = {d.name: d for d in self.defs if d.type == "class"}
        for called, node, receiver, current_callable in self._call_sites.values():
            name = self._node_name_text(called)
            target = name
            owner = self._receiver_class(receiver, node, current_callable, classes)
            if receiver is None and name in classes:
                # Constructor calls reference the type, even inside that type.
                owner = None
                constructor = f"{name}.{name}"
                if node.type == "method_invocation" and constructor in self._constructors:
                    self._add_ref(
                        constructor,
                        called.start_byte,
                        current_callable=current_callable,
                    )
            elif receiver is None and current_callable and "." in current_callable:
                owner = current_callable.rsplit(".", 1)[0]
                member = self._member_target(owner, name, classes, definitions)
                # An unqualified name may also refer to a top-level function.
                local, _ = self._local_receiver_class(
                    name, node, current_callable, classes
                )
                if local:
                    self._ambiguous_calls.add((current_callable, name))
                    owner = None
                elif member in definitions:
                    target = member
                else:
                    # Imports and other library files may supply this name;
                    # absence from this class does not make it a class member.
                    owner = None
            elif owner is not None:
                target = self._member_target(owner, name, classes, definitions) or name
            if receiver is not None and owner is None:
                self._ambiguous_calls.add((current_callable, name))
            if (
                owner
                and receiver is not None
                and receiver.type == "identifier"
                and self._node_name_text(receiver) == owner
            ):
                self._add_ref(
                    owner, receiver.start_byte, current_callable=current_callable
                )
            self._add_ref(target, called.start_byte, current_callable=current_callable)
            if owner and target != name and target not in self._constructors:
                # Dart methods dispatch virtually. A declared receiver type is
                # not proof of its runtime subtype; keep known overriding
                # members alive too, including implementations of abstract
                # signatures not present in the symbol inventory. Explicit
                # super calls bypass overrides.
                if receiver is not None and self._get_text(receiver).strip() == "super":
                    continue
                for subclass in classes:
                    if subclass == owner:
                        continue
                    pending = list(classes[subclass].base_classes)
                    seen = set()
                    while pending:
                        base = pending.pop()
                        if base == owner:
                            override = f"{subclass}.{name}"
                            if override in definitions:
                                self._add_ref(
                                    override,
                                    called.start_byte,
                                    current_callable=current_callable,
                                )
                            break
                        if base in classes and base not in seen:
                            seen.add(base)
                            pending.extend(classes[base].base_classes)

    def _selector_is_call(self, node) -> bool:
        if node is None or node.type != "selector":
            return False
        return self._first_descendant_of_type(node, "argument_part") is not None

    def _selector_name(self, node) -> str:
        if node is None or node.type != "selector":
            return ""
        ident = self._child_by_type(node, "identifier")
        if ident is not None:
            return self._node_name_text(ident)
        text = self._get_text(node).strip()
        if text.startswith("."):
            return text[1:]
        return ""

    def _build_call_graph(self) -> None:
        name_to_def: dict[str, Definition] = {}
        simple_to_defs: dict[str, list[Definition]] = {}
        for d in self.defs:
            name_to_def[d.name] = d
            simple_to_defs.setdefault(d.simple_name, []).append(d)

        for caller, callee in self.call_pairs:
            caller_def = name_to_def.get(caller)
            exact = name_to_def.get(callee)
            if (caller, callee) in self._ambiguous_calls:
                callees = simple_to_defs.get(callee, [])
            else:
                callees = (
                    [exact] if exact is not None else simple_to_defs.get(callee, [])
                )
            for callee_def in callees:
                if caller_def and caller_def is not callee_def:
                    caller_def.calls.add(callee_def.name)
                    callee_def.called_by.add(caller_def.name)
