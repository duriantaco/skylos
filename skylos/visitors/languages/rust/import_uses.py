"""Bounded import evidence from conditional attributes and writer macros."""

from __future__ import annotations

from .local_traits import source_value_binding


_BUILTIN_ATTRIBUTES = frozenset(
    {
        "cfg",
        "cfg_attr",
        "derive",
        "doc",
        "allow",
        "warn",
        "deny",
        "forbid",
        "expect",
        "inline",
        "repr",
        "cold",
        "test",
        "must_use",
        "deprecated",
    }
)


class SemanticImportUses:
    def __init__(self, core):
        self.core = core
        self.root = core.root_node
        self._attribute_cache = {}
        self._local_writer_trait = any(
            node.type == "trait_item"
            and any(
                member.type in {"function_item", "function_signature_item"}
                and core._node_name_text(member.child_by_field_name("name"))
                == "write_fmt"
                for body in node.named_children
                if body.type == "declaration_list"
                for member in body.named_children
            )
            for node in core._iter_nodes(self.root)
        )

    def _groups(self, tree):
        groups = [[]]
        for node in tree.children[1:-1]:
            if node.type in {"line_comment", "block_comment"}:
                continue
            if node.type == ",":
                groups.append([])
            else:
                groups[-1].append(node)
        return [group for group in groups if group]

    def _normalized(self, tokens):
        def value(node):
            if node.type in {"line_comment", "block_comment"}:
                return ""
            if not node.children or node.type in {
                "string_literal",
                "raw_string_literal",
                "char_literal",
            }:
                return self.core._get_text(node)
            return "".join(value(child) for child in node.children)

        return "".join(value(token) for token in tokens)

    def _condition(self, tokens):
        normalized = self._normalized(tokens)
        if not tokens:
            return None, frozenset()
        name = self.core._get_text(tokens[0])
        tree = (
            tokens[1] if len(tokens) == 2 and tokens[1].type == "token_tree" else None
        )
        if name in {"all", "any", "not"} and tree is not None:
            parts = [self._condition(group) for group in self._groups(tree)]
            if name == "all":
                if any(truth is False for truth, _ in parts):
                    return False, frozenset()
                terms = frozenset(term for _, group in parts for term in group)
                return (
                    True if all(truth is True for truth, _ in parts) else None
                ), terms
            if name == "any":
                if any(truth is True for truth, _ in parts):
                    return True, frozenset()
                if all(truth is False for truth, _ in parts):
                    return False, frozenset()
            elif len(parts) == 1 and parts[0][0] is not None:
                return not parts[0][0], frozenset()
        if normalized == "true":
            return True, frozenset()
        if normalized == "false":
            return False, frozenset()
        return None, frozenset({normalized})

    def _tokens(self, attribute):
        inner = self.core._child_by_type(attribute, "attribute")
        return list(inner.children) if inner is not None else []

    def _cfg_guards(self, attributes):
        terms = set()
        for attribute in attributes:
            tokens = self._tokens(attribute)
            if (
                len(tokens) == 2
                and self.core._get_text(tokens[0]) == "cfg"
                and tokens[1].type == "token_tree"
            ):
                truth, condition = self._condition(tokens[1].children[1:-1])
                if truth is False:
                    return None
                terms.update(condition)
            elif tokens and self.core._get_text(tokens[0]) == "cfg_attr":
                # A wrapped cfg can remove the entire item. Unknown conditions
                # do not prove that another attribute on that item is applied.
                if self._conditional_cfg_disables(tokens):
                    return None
        return frozenset(terms)

    def _conditional_cfg_disables(self, tokens):
        if not tokens:
            return False
        name = self.core._get_text(tokens[0])
        tree = next((token for token in tokens[1:] if token.type == "token_tree"), None)
        if name == "cfg" and tree is not None:
            truth, _ = self._condition(tree.children[1:-1])
            return truth is not True
        if name != "cfg_attr" or tree is None:
            return False
        groups = self._groups(tree)
        if len(groups) < 2:
            return True
        truth, _ = self._condition(groups[0])
        if truth is False:
            return False
        return any(self._conditional_cfg_disables(group) for group in groups[1:])

    def _preceding_attributes(self, node):
        attributes = []
        previous = node.prev_named_sibling
        while previous is not None:
            if previous.type == "attribute_item":
                attributes.append(previous)
            elif previous.type not in {"line_comment", "block_comment"}:
                break
            previous = previous.prev_named_sibling
        return list(reversed(attributes))

    def _item_attributes(self, node):
        result = [*self._preceding_attributes(node), node]
        following = node.next_named_sibling
        while following is not None:
            if following.type == "attribute_item":
                result.append(following)
            elif following.type not in {"line_comment", "block_comment"}:
                break
            following = following.next_named_sibling
        return result

    def _import_binding(self, name, node):
        while node is not None:
            if node.type in {"block", "declaration_list", "source_file"}:
                matches = []
                unknown_glob = False
                for child in node.named_children:
                    if child.type == "use_declaration":
                        source = self.core._node_name_text(
                            child.child_by_field_name("argument")
                        )
                        unknown_glob |= "*" in source
                        if any(
                            local == name
                            for local, _ in self.core._extract_use_bindings(child)
                        ):
                            matches.append(child.id)
                if matches:
                    return matches[0] if len(matches) == 1 else None
                if unknown_glob:
                    return None
            if node.type == "mod_item":
                break
            node = node.parent
        return None

    def _wrapped_attributes(self, tokens, guards):
        if not tokens:
            return []
        name = self.core._get_text(tokens[0])
        tree = next((token for token in tokens[1:] if token.type == "token_tree"), None)
        if name == "cfg_attr":
            if tree is None:
                return []
            groups = self._groups(tree)
            if len(groups) < 2:
                return []
            truth, condition = self._condition(groups[0])
            if truth is False:
                return []
            result = []
            for group in groups[1:]:
                result.extend(self._wrapped_attributes(group, guards | condition))
            return result
        if name in _BUILTIN_ATTRIBUTES:
            return []
        # Only the actual attribute head is a read: not its condition, prose,
        # metadata keys or strings passed as attribute arguments.
        return [(name.split("::", 1)[0], guards)]

    def _scope_nodes(self, scope):
        pending = [scope]
        remaining = 100_000
        while pending and remaining:
            node = pending.pop()
            remaining -= 1
            if node != scope and node.type == "mod_item":
                continue
            yield node
            pending.extend(reversed(node.named_children))

    def conditional_attribute_used(self, import_node, local_name, import_attrs):
        import_guards = self._cfg_guards(import_attrs)
        if import_guards is None:
            return False
        scope = import_node.parent
        key = (scope.id, local_name, import_guards)
        if key not in self._attribute_cache:
            found = False
            for node in self._scope_nodes(scope):
                if node.type != "attribute_item":
                    continue
                tokens = self._tokens(node)
                if not tokens or self.core._get_text(tokens[0]) != "cfg_attr":
                    continue
                sibling_attrs = self._item_attributes(node)
                guards = self._cfg_guards(sibling_attrs)
                if guards is None:
                    continue
                for name, use_guards in self._wrapped_attributes(tokens, guards):
                    if (
                        name == local_name
                        and self._import_binding(name, node) == import_node.id
                        and import_guards <= use_guards
                    ):
                        found = True
                        break
                if found:
                    break
            self._attribute_cache[key] = found
        return self._attribute_cache[key]

    def _namespace(self, node):
        parts = []
        while node is not None:
            if node.type == "mod_item":
                parts.append(
                    self.core._node_name_text(node.child_by_field_name("name"))
                )
            node = node.parent
        return ".".join(
            part for part in [self.core.root_namespace, *reversed(parts)] if part
        )

    def _canonical_path(self, text, at):
        parts = [
            part.removeprefix("r#")
            for part in text.replace("::", ".").strip(".").split(".")
        ]
        if not parts or not parts[0]:
            return None
        first = parts[0]
        scope = at
        while scope is not None:
            matches = set()
            if scope.type in {"block", "declaration_list", "source_file"}:
                unknown_glob = False
                for child in scope.named_children:
                    if (
                        child.type
                        in {
                            "mod_item",
                            "struct_item",
                            "enum_item",
                            "union_item",
                            "type_item",
                            "trait_item",
                        }
                        and self.core._node_name_text(
                            child.child_by_field_name("name")
                        ).removeprefix("r#")
                        == first
                    ):
                        return None
                    if child.type != "use_declaration":
                        continue
                    source = self.core._node_name_text(
                        child.child_by_field_name("argument")
                    )
                    unknown_glob |= "*" in source
                    for local, original in self.core._extract_use_bindings(child):
                        if local.removeprefix("r#") == first:
                            namespace = (
                                ""
                                if source.startswith(("std::", "core::", "alloc::"))
                                else self._namespace(child)
                            )
                            qualified = self.core._qualify_use_import(
                                source,
                                local_name=local,
                                original_name=original,
                                namespace=namespace,
                            )
                            if qualified:
                                matches.add(qualified)
                if matches:
                    return (
                        ".".join([next(iter(matches)), *parts[1:]])
                        if len(matches) == 1
                        else None
                    )
                if unknown_glob:
                    return None
            scope = scope.parent
        if first in {"std", "core", "alloc"}:
            return (
                ".".join(parts)
                if not self.core._provider_is_shadowed(first, at)
                else None
            )
        if first in {"Vec", "String"}:
            if any(
                name.split(".")[-1].removeprefix("r#") == first
                for name in self.core._local_types
            ) or self.core._provider_is_shadowed(first, at):
                return None
            return ".".join(["std", "vec" if first == "Vec" else "string", *parts])
        return None

    def _type_kind(self, node, at):
        if node is None:
            return None
        if node.type == "reference_type":
            return self._type_kind(node.child_by_field_name("type"), at)
        if node.type == "generic_type":
            base = node.child_by_field_name("type")
            arguments = next(
                (
                    child
                    for child in node.named_children
                    if child.type == "type_arguments"
                ),
                None,
            )
            if (
                arguments is None
                or len(arguments.named_children) != 1
                or self.core._get_text(arguments.named_children[0]) != "u8"
            ):
                return None
            return (
                "io"
                if self._canonical_path(self.core._get_text(base), at)
                in {"std.vec.Vec", "alloc.vec.Vec"}
                else None
            )
        path = self._canonical_path(self.core._get_text(node), at)
        return {
            "std.string.String": "fmt",
            "alloc.string.String": "fmt",
            "std.fs.File": "io",
            "std.io.Stdout": "io",
            "std.io.Stderr": "io",
        }.get(path)

    def _expression_kind(self, node, at, depth=0):
        if node is None or depth > 12:
            return None
        if node.type in {"reference_expression", "parenthesized_expression"}:
            return self._expression_kind(node.named_children[-1], at, depth + 1)
        if node.type == "identifier":
            return self._binding_kind(self.core._get_text(node), node, depth + 1)
        if node.type != "call_expression":
            return None
        function = node.child_by_field_name("function")
        if function is None:
            return None
        text = self.core._get_text(function)
        # Only an explicit byte type argument is supported. Unknown generic
        # targets cannot prove which Write trait supplies write_fmt.
        if "<" in text:
            if "::<u8>" not in text.replace(" ", ""):
                return None
            text = text.replace("::<u8>", "")
        path = self._canonical_path(text, at)
        if path in {
            "std.vec.Vec.new",
            "std.vec.Vec.with_capacity",
            "alloc.vec.Vec.new",
            "alloc.vec.Vec.with_capacity",
        }:
            return "io"
        if path in {
            "std.string.String.new",
            "std.string.String.with_capacity",
            "alloc.string.String.new",
            "alloc.string.String.with_capacity",
        }:
            return "fmt"
        return None

    def _binding_kind(self, name, node, depth=0):
        if depth > 12:
            return None
        binding = source_value_binding(self.core, node, name)
        if binding is False or binding is None:
            return None
        annotation = binding.child_by_field_name("type")
        if annotation is not None:
            return self._type_kind(annotation, node)
        if binding.type != "let_declaration":
            return None
        return self._expression_kind(
            binding.child_by_field_name("value"), node, depth + 1
        )

    def _writer_imports(self, scope, provider):
        result = []
        for child in scope.named_children:
            if child.type != "use_declaration":
                continue
            source = self.core._node_name_text(child.child_by_field_name("argument"))
            base = self._canonical_path(self.core._use_import_base(source), child)
            if base is None and any(
                original.removeprefix("r#") == "Write"
                for _, original in self.core._extract_use_bindings(child)
            ):
                return None
            if base == provider and any(
                original == "Write"
                for _, original in self.core._extract_use_bindings(child)
            ):
                result.append(child.id)
        return result

    def _writer_owner(self, node, provider):
        scope = node.parent
        while scope is not None:
            if scope.type in {"block", "declaration_list", "source_file"}:
                imports = self._writer_imports(scope, provider)
                if imports is None:
                    return None
                if imports:
                    return imports[0] if len(imports) == 1 else None
            if scope.type == "mod_item":
                break
            scope = scope.parent
        return None

    def writer_macro_used(self, import_node, source, original_name):
        if original_name != "Write" or self._local_writer_trait:
            return False
        base = self.core._use_import_base(source)
        provider = self._canonical_path(base, import_node)
        kind = {"std.io": "io", "std.fmt": "fmt", "core.fmt": "fmt"}.get(provider)
        if kind is None:
            return False
        local_macros = {
            self.core._node_name_text(node.child_by_field_name("name"))
            for node in self.core._iter_nodes(self.root)
            if node.type == "macro_definition"
        }
        for node in self.core._trait_scope_nodes(
            import_node.parent, (base, original_name)
        ):
            if node.type != "macro_invocation":
                continue
            if self._writer_owner(node, provider) != import_node.id:
                continue
            path = self.core._get_text(node.named_children[0])
            if path in {"write", "writeln"}:
                if path in local_macros or self.core._provider_is_shadowed(path, node):
                    continue
            elif path not in {
                "std::write",
                "std::writeln",
                "core::write",
                "core::writeln",
            } or self.core._provider_is_shadowed(path.split("::")[0], node):
                continue
            tree = self.core._child_by_type(node, "token_tree")
            groups = self._groups(tree) if tree is not None else []
            if not groups:
                continue
            target = [
                token
                for token in groups[0]
                if token.type not in {"&", "mutable_specifier"}
            ]
            if (
                len(target) == 1
                and target[0].type == "identifier"
                and self._binding_kind(self.core._node_name_text(target[0]), target[0])
                == kind
            ):
                return True
        return False
