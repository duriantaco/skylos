"""Keep repeated Rust import aliases distinct without changing their output name.

The ordinary visitor retains its legacy name references for unique aliases.
Repeated aliases use an internal source-bound reference so reading an inner
binding cannot silently erase an unused outer binding.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256


_PREFIX = "@rust-import:"


def import_definition_key(definition):
    facts = getattr(definition, "rust_reference_facts", None)
    if (
        definition.type == "import"
        and isinstance(facts, dict)
        and facts.get("kind") == "import_binding"
        and facts.get("version") == 1
        and facts.get("distinct_binding") is True
        and isinstance(facts.get("key"), str)
        and facts["key"].startswith(_PREFIX)
    ):
        return f"{definition.filename}:{facts['key']}"
    return None


def is_import_reference(reference):
    return isinstance(reference, str) and reference.startswith(_PREFIX)


def mark_import_reference(definitions, ref_file, reference):
    definition = definitions.get(f"{ref_file}:{reference}")
    if definition is not None and import_definition_key(definition) is not None:
        definition.references += 1


class ImportBindings:
    def __init__(self, core):
        self.core = core
        self.digest = sha256(core.source).hexdigest()
        nodes = [
            node
            for node in core._iter_nodes(core.root_node)
            if node.type == "use_declaration"
            and "*" not in core._node_name_text(node.child_by_field_name("argument"))
        ]
        counts = Counter(
            local.removeprefix("r#")
            for node in nodes
            for local, _ in core._extract_use_bindings(node)
        )
        self.repeated = {name for name, count in counts.items() if count > 1}
        for node in nodes:
            previous = node.prev_named_sibling
            while previous is not None and previous.type in {
                "line_comment",
                "block_comment",
            }:
                previous = previous.prev_named_sibling
            if previous is not None and previous.type == "attribute_item":
                # Feature/attribute expansion can remove or replace a binding.
                # Retain the legacy conservative alias group when its lexical
                # owners cannot be selected from ordinary source alone.
                self.repeated.difference_update(
                    local.removeprefix("r#")
                    for local, _ in core._extract_use_bindings(node)
                )
        self._facts = {}
        for node in nodes:
            for local, _ in core._extract_use_bindings(node):
                name = local.removeprefix("r#")
                self._facts[(node.id, name)] = {
                    "kind": "import_binding",
                    "version": 1,
                    "key": f"{_PREFIX}{self.digest}:{node.start_byte}:{name}",
                    "sha256": self.digest,
                    "start_byte": node.start_byte,
                    "distinct_binding": name in self.repeated,
                }

    def facts(self, node, local):
        return self._facts[(node.id, local.removeprefix("r#"))].copy()

    def source_references(self, node):
        """A use path reads its provider binding, including grouped/raw paths."""
        result = []
        for parts in self._paths(node.child_by_field_name("argument")):
            scope = node.parent
            if parts and parts[0] == "crate":
                scope, parts = self.core.root_node, parts[1:]
            elif parts and parts[0] == "self":
                while scope is not None and scope.type not in {
                    "source_file",
                    "declaration_list",
                }:
                    scope = scope.parent
                parts = parts[1:]
            while parts and parts[0] == "super":
                while scope is not None and scope.type != "mod_item":
                    scope = scope.parent
                scope = scope.parent if scope is not None else None
                parts = parts[1:]
            if not parts or parts[0] not in self.repeated:
                continue
            while scope is not None:
                if scope.type in {"block", "source_file", "declaration_list"}:
                    if any(
                        child.type
                        in {
                            "mod_item",
                            "struct_item",
                            "enum_item",
                            "union_item",
                            "trait_item",
                            "type_item",
                        }
                        and self.core._node_name_text(
                            child.child_by_field_name("name")
                        ).removeprefix("r#")
                        == parts[0]
                        for child in scope.named_children
                    ):
                        break
                    matches = [
                        facts["key"]
                        for child in scope.named_children
                        if child.type == "use_declaration" and child.id != node.id
                        if (facts := self._facts.get((child.id, parts[0]))) is not None
                    ]
                    if matches:
                        result.extend(matches)
                        break
                if scope.type == "mod_item":
                    break
                scope = scope.parent
        return tuple(dict.fromkeys(result))

    def _paths(self, node, prefix=()):
        if node is None:
            return []
        if node.type == "use_as_clause":
            return self._paths(node.child_by_field_name("path"), prefix)
        if node.type == "scoped_use_list":
            base = self._paths(node.child_by_field_name("path"), prefix)
            return [
                path
                for stem in base
                for path in self._paths(node.child_by_field_name("list"), stem)
            ]
        if node.type == "scoped_identifier":
            return [
                (
                    *stem,
                    self.core._node_name_text(
                        node.child_by_field_name("name")
                    ).removeprefix("r#"),
                )
                for stem in self._paths(node.child_by_field_name("path"), prefix)
            ]
        if node.type in {"use_list", "use_wildcard"}:
            return [
                path
                for child in node.named_children
                for path in self._paths(child, prefix)
            ]
        name = self.core._node_name_text(node).removeprefix("r#")
        return [(*prefix, name)] if name else []

    def references(self, name, offset):
        name = name.removeprefix("r#")
        if name not in self.repeated:
            return ()
        root = self.core.root_node
        at = root.descendant_for_byte_range(offset, min(offset + 1, root.end_byte))
        node = at
        macro = False
        type_reference = False
        while node is not None and node.type not in {
            "block",
            "source_file",
            "declaration_list",
        }:
            macro |= node.type in {"macro_invocation", "attribute_item"}
            type_reference |= node.type == "type_identifier"
            node = node.parent
        scope = at
        while scope is not None:
            if scope.type in {"block", "source_file", "declaration_list"}:
                matches = []
                for child in scope.named_children:
                    if child.type == "use_declaration":
                        facts = self._facts.get((child.id, name))
                        if facts is not None:
                            matches.append(facts["key"])
                        continue
                    child_name = self.core._node_name_text(
                        child.child_by_field_name("name")
                    ).removeprefix("r#")
                    if child_name != name:
                        continue
                    if (macro and child.type == "macro_definition") or (
                        not macro
                        and child.type
                        in (
                            {
                                "struct_item",
                                "enum_item",
                                "union_item",
                                "trait_item",
                                "type_item",
                                "mod_item",
                            }
                            if type_reference
                            else {
                                "function_item",
                                "const_item",
                                "static_item",
                                "struct_item",
                                "mod_item",
                            }
                        )
                    ):
                        return ()
                if matches:
                    # Same-scope conditional bindings cannot be selected without
                    # compiler feature configuration; retain all possible owners.
                    return tuple(matches)
            if scope.type == "mod_item":
                break
            scope = scope.parent
        return ()
