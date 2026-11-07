"""Use local trait declarations and exact local receiver types as evidence.

This source-only index deliberately excludes external files, generic impls,
conditional declarations and type inference that the Rust visitor cannot prove.
"""

from __future__ import annotations


_MAX_NODES = 100_000
_MAX_TRAITS = 256
# These methods have unconditional prelude identity conversions. Without a
# compiler's return-type selection, their spelling is not local-trait evidence.
_PRELUDE_CONVERSIONS = frozenset({"into", "try_into"})


def source_value_binding(core, node, name=None):
    """Return a simple binding, False for an opaque binding, or None if absent.

    A closer unsupported binding must stop type lookup. In particular, a tuple,
    loop or match binding cannot inherit a same-spelled outer variable's type.
    """
    name = (core._node_name_text(node) if name is None else name).removeprefix("r#")

    def binds(pattern):
        return name in {
            binding.removeprefix("r#")
            for binding in core._pattern_binding_names(pattern)
        }

    def contains(container):
        return (
            container is not None
            and container.start_byte <= node.start_byte < container.end_byte
        )

    crossed_function = False
    scope = node.parent
    while scope is not None:
        if scope.type in {"block", "declaration_list", "source_file"}:
            if not crossed_function and scope.type == "block":
                for declaration in reversed(scope.named_children):
                    if (
                        declaration.type != "let_declaration"
                        or declaration.end_byte > node.start_byte
                    ):
                        continue
                    pattern = declaration.child_by_field_name("pattern")
                    if binds(pattern):
                        return declaration if pattern.type == "identifier" else False
            for declaration in scope.named_children:
                if declaration.type == "use_declaration":
                    source = core._node_name_text(
                        declaration.child_by_field_name("argument")
                    )
                    if "*" in source or any(
                        local.removeprefix("r#") == name
                        for local, _ in core._extract_use_bindings(declaration)
                    ):
                        return False
                elif (
                    declaration.type
                    in {
                        "const_item",
                        "static_item",
                        "function_item",
                        "mod_item",
                        "struct_item",
                        "enum_item",
                        "union_item",
                        "trait_item",
                        "type_item",
                    }
                    and core._node_name_text(
                        declaration.child_by_field_name("name")
                    ).removeprefix("r#")
                    == name
                ):
                    return False
        elif scope.type in {"function_item", "closure_expression"}:
            parameters = scope.child_by_field_name("parameters")
            if parameters is not None:
                for parameter in parameters.named_children:
                    pattern = (
                        parameter.child_by_field_name("pattern")
                        if parameter.type == "parameter"
                        else parameter
                    )
                    if binds(pattern):
                        return (
                            parameter
                            if parameter.type == "parameter"
                            and pattern.type == "identifier"
                            else False
                        )
            if scope.type == "function_item":
                crossed_function = True
        elif scope.type == "for_expression":
            if contains(scope.child_by_field_name("body")) and binds(
                scope.child_by_field_name("pattern")
            ):
                return False
        elif scope.type == "match_arm":
            pattern = scope.child_by_field_name("pattern")
            guard = (
                pattern.child_by_field_name("condition")
                if pattern is not None
                else None
            )
            if (
                contains(scope.child_by_field_name("value")) or contains(guard)
            ) and binds(pattern):
                return False
        elif scope.type in {"if_expression", "while_expression"}:
            condition = scope.child_by_field_name("condition")
            body = scope.child_by_field_name(
                "consequence" if scope.type == "if_expression" else "body"
            )
            if condition is not None:
                for binding in core._iter_nodes(condition):
                    if binding.type != "let_condition":
                        continue
                    in_scope = contains(body) or (
                        contains(condition) and binding.end_byte <= node.start_byte
                    )
                    if in_scope and binds(binding.child_by_field_name("pattern")):
                        return False
        scope = scope.parent
    return None


class LocalTraitImports:
    def __init__(self, core):
        self.core = core
        self.traits = {}
        self.implementations = {}
        self.competing_implementations = []
        self.opaque_owners = set()
        self.opaque_generic_impl = False
        self.ambiguous = set()
        self.namespaces = {}
        self._usage = {}
        root = core.root_node
        if root is None or root.has_error:
            return
        if not core._closed_macro_scope():
            return
        for count, node in enumerate(core._iter_nodes(root), 1):
            if count > _MAX_NODES:
                return
            if node.type in {
                "macro_definition",
                "attribute_item",
                "inner_attribute_item",
            }:
                return
            if node.type == "mod_item" and node.child_by_field_name("body") is None:
                # A child file can add an inherent or more specific trait impl.
                # This index has no project-wide type context with which to
                # rule that out; it must not rescue imports in that situation.
                return
            if node.type in {
                "struct_item",
                "enum_item",
                "union_item",
                "trait_item",
                "type_item",
                "impl_item",
                "mod_item",
            }:
                parent = node.parent
                while parent is not None:
                    if parent.type in {"function_item", "closure_expression"}:
                        # Function-local type declarations and impls do not
                        # have identities in this file/module-only index.
                        return
                    parent = parent.parent
        pending = [(root, core.root_namespace)]
        implementations = []
        while pending:
            block, namespace = pending.pop()
            self.namespaces[block.id] = namespace
            attributed = False
            for node in block.named_children:
                if node.type == "attribute_item":
                    attributed = True
                    continue
                guarded, attributed = attributed, False
                if guarded:
                    continue
                name = core._node_name_text(node.child_by_field_name("name"))
                if node.type == "mod_item":
                    body = node.child_by_field_name("body")
                    if body is not None:
                        pending.append((body, core._qualified_symbol(name, namespace)))
                elif node.type == "trait_item":
                    if node.child_by_field_name("type_parameters") is not None:
                        continue
                    qualified = core._qualified_symbol(name, namespace)
                    if qualified in self.traits:
                        self.ambiguous.add(qualified)
                        continue
                    body = node.child_by_field_name("body")
                    methods = {}
                    if body is not None:
                        member_attributed = False
                        for member in body.named_children:
                            if member.type == "attribute_item":
                                member_attributed = True
                                continue
                            member_guarded, member_attributed = member_attributed, False
                            if member_guarded:
                                continue
                            if member.type in {
                                "function_signature_item",
                                "function_item",
                            }:
                                parameters = member.child_by_field_name("parameters")
                                if parameters is not None:
                                    for parameter in parameters.named_children:
                                        if parameter.type == "self_parameter":
                                            text = "".join(
                                                core._get_text(parameter).split()
                                            )
                                            mode = {
                                                "self": (),
                                                "mutself": (),
                                                "&self": (False,),
                                                "&mutself": (True,),
                                            }.get(text)
                                            methods[
                                                core._node_name_text(
                                                    member.child_by_field_name("name")
                                                )
                                            ] = mode
                    self.traits[qualified] = methods
                    if len(self.traits) > _MAX_TRAITS:
                        self.traits.clear()
                        return
                elif node.type == "impl_item":
                    implementations.append((node, namespace))
        for node, namespace in implementations:
            trait = node.child_by_field_name("trait")
            receiver = node.child_by_field_name("type")
            if trait is None:
                continue
            if trait.type not in {
                "type_identifier",
                "scoped_type_identifier",
            }:
                shape = self._type_shape(receiver, None, namespace=namespace)
                if shape is not None and shape[0] in core._local_types:
                    self.opaque_owners.add(shape[0])
                else:
                    self.opaque_generic_impl = True
                continue
            name = core._resolve_type_name(
                core._node_name_text(trait), None, namespace_override=namespace
            )
            shape = self._type_shape(receiver, None, namespace=namespace)
            owner, borrows = shape if shape is not None else (None, None)
            generic = node.child_by_field_name("type_parameters") is not None
            if name not in self.traits:
                if owner in core._local_types:
                    self.opaque_owners.add(owner)
                elif generic:
                    self.opaque_generic_impl = True
                continue
            if borrows is None:
                self.opaque_generic_impl = True
                continue
            if generic and owner not in core._local_types:
                owner = None  # Potentially applicable to every concrete type.
            if owner in core._generic_types or owner in core._deref_types:
                continue
            self.competing_implementations.append((name, owner, borrows))
            if (
                name in self.traits
                and name not in self.ambiguous
                and owner in core._local_types
            ):
                self.implementations.setdefault(name, set()).add((owner, borrows))

    def _type_shape(self, node, current_callable, *, namespace=None, depth=0):
        if node is None or depth > 12:
            return None
        if node.type == "reference_type":
            inner = self._type_shape(
                node.child_by_field_name("type"),
                current_callable,
                namespace=namespace,
                depth=depth + 1,
            )
            if inner is None:
                return None
            mutable = any(child.type == "mutable_specifier" for child in node.children)
            return inner[0], (mutable,) + inner[1]
        if node.type not in {"identifier", "type_identifier", "scoped_type_identifier"}:
            return None
        first = self.core._node_name_text(node).split("::", 1)[0]
        scope = node.parent
        while scope is not None:
            if scope.type == "block" and any(
                child.type == "use_declaration"
                and any(
                    local == first
                    for local, _ in self.core._extract_use_bindings(child)
                )
                for child in scope.named_children
            ):
                return None
            scope = scope.parent
        owner = self.core._type_name(node, current_callable, namespace=namespace)
        if owner is None:
            return None
        text = self.core._node_name_text(node)
        scope_namespace = (
            namespace
            if namespace is not None
            else self.core._callable_context.get(
                current_callable, (self.core.root_namespace, None)
            )[0]
        )
        alias = self.core._type_aliases.get(
            self.core._qualified_symbol(text, scope_namespace)
        ) or self.core._type_aliases.get(text)
        if alias is not None:
            return self._type_shape(
                alias[1], current_callable, namespace=alias[0], depth=depth + 1
            )
        return owner, ()

    def _receiver_shape(self, node, current_callable, depth=0):
        if node is None or depth > 12:
            return None
        if node.type == "reference_expression":
            inner = self._receiver_shape(
                node.named_children[-1], current_callable, depth + 1
            )
            if inner is None:
                return None
            mutable = any(child.type == "mutable_specifier" for child in node.children)
            return inner[0], (mutable,) + inner[1]
        if node.type == "parenthesized_expression":
            return self._receiver_shape(
                node.named_children[-1], current_callable, depth + 1
            )
        if node.type == "struct_expression":
            return self._type_shape(node.child_by_field_name("name"), current_callable)
        if node.type != "identifier":
            return None
        binding = source_value_binding(self.core, node)
        if binding is False:
            return None
        if binding is not None:
            annotation = binding.child_by_field_name("type")
            if annotation is not None:
                return self._type_shape(annotation, current_callable)
            if binding.type != "let_declaration":
                return None
            return self._receiver_shape(
                binding.child_by_field_name("value"), current_callable, depth + 1
            )
        owner = self.core._receiver_type(node, current_callable)
        return (owner, ()) if owner in self.core._local_types else None

    def _closed_imports(self, node):
        while node is not None:
            if node.type in {"block", "declaration_list", "source_file"}:
                for child in node.named_children:
                    if child.type != "use_declaration":
                        continue
                    source = self.core._node_name_text(
                        child.child_by_field_name("argument")
                    )
                    identities = self._import_identities(child)
                    if (
                        "*" in source
                        or not identities
                        or any(
                            identity not in self.core._local_types
                            for identity in identities
                        )
                    ):
                        return False
            if node.type == "mod_item":
                break
            node = node.parent
        return True

    def _selected_trait(self, qualified, method, shape):
        owner, borrows = shape
        if owner in self.opaque_owners or self.opaque_generic_impl:
            return False
        candidates = []
        for offset in range(len(borrows) + 1):
            direct = borrows[offset:]
            for candidate in (direct, (False,) + direct, (True,) + direct):
                if candidate not in candidates:
                    candidates.append(candidate)
        selected = []
        for (
            trait,
            implementation_owner,
            implementation_borrows,
        ) in self.competing_implementations:
            if implementation_owner is not None and implementation_owner != owner:
                continue
            methods = self.traits[trait]
            if method not in methods:
                continue
            mode = methods[method]
            if mode is None:
                return False
            receiver = mode + implementation_borrows
            if receiver in candidates:
                selected.append((candidates.index(receiver), trait))
        if not selected:
            return False
        rank = min(item[0] for item in selected)
        return {
            trait for candidate_rank, trait in selected if candidate_rank == rank
        } == {qualified}

    def _namespace(self, node):
        while node is not None:
            if node.id in self.namespaces:
                return self.namespaces[node.id]
            node = node.parent
        return self.core.root_namespace

    def _import_identities(self, node):
        source = self.core._node_name_text(node.child_by_field_name("argument"))
        return [
            self.core._qualify_use_import(
                source,
                local_name=local,
                original_name=original,
                namespace=self._namespace(node),
            )
            for local, original in self.core._extract_use_bindings(node)
        ]

    def is_used(self, qualified, scope):
        if (
            qualified not in self.implementations
            or qualified in self.ambiguous
            or scope is None
        ):
            return False
        key = (qualified, scope.id)
        if key not in self._usage:
            self._usage[key] = self._has_use(qualified, scope)
        return self._usage[key]

    def _has_use(self, qualified, scope):
        # Two aliases of one trait in the same scope do not identify which
        # import supplies a call. Keep the previous result rather than crediting both.
        if (
            sum(
                self._import_identities(child).count(qualified)
                for child in scope.named_children
                if child.type == "use_declaration"
            )
            != 1
        ):
            return False
        core = self.core
        pending = [scope]
        methods = self.traits[qualified]
        owners = self.implementations[qualified]
        while pending:
            node = pending.pop()
            if node != scope:
                if node.type == "mod_item":
                    continue
                if node.type in {"block", "declaration_list"} and any(
                    child.type == "use_declaration"
                    and qualified in self._import_identities(child)
                    for child in node.named_children
                ):
                    continue
            calls = []
            if node.type == "token_tree":
                calls.extend(core._token_tree_method_calls(node))
            if core._trait_method_name_from_node(node):
                calls.append(
                    (
                        node.child_by_field_name("value"),
                        node.child_by_field_name("field"),
                    )
                )
            for receiver, member in calls:
                method = core._node_name_text(member)
                if (
                    method not in methods
                    or methods[method] != (False,)
                    or method in _PRELUDE_CONVERSIONS
                ):
                    continue
                if not self._closed_imports(node):
                    continue
                shape = self._receiver_shape(receiver, core._enclosing_callable(node))
                if shape is None:
                    continue
                owner = shape[0]
                if (
                    any(
                        implementation_owner == owner
                        for implementation_owner, _ in owners
                    )
                    and self._selected_trait(qualified, method, shape)
                    and not core._is_inherent_target(core._member_target(owner, method))
                ):
                    return True
            pending.extend(reversed(node.named_children))
        return False
