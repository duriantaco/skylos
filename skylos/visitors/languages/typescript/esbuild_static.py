"""Bounded, non-executing constant folding for esbuild entry-point options.

This deliberately is not a JavaScript interpreter. Only module constants, plain
data, imported Node path helpers, and pure literal-array maps are understood.
Unknown calls, mutable/escaped data, and dynamic keys remain unknown.
"""

from __future__ import annotations

import os


UNKNOWN = object()
_MAX_STEPS = 20_000
_MAX_DEPTH = 40
_MAX_ITEMS = 1_024
_MAX_STRING = 16_384
_PATH_METHODS = frozenset({"join", "resolve", "dirname"})


def _nodes(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def _unwrap(node):
    while node is not None and node.type in {
        "as_expression",
        "parenthesized_expression",
        "satisfies_expression",
    }:
        node = node.child_by_field_name("expression") or (
            node.named_children[0] if node.named_children else None
        )
    return node


class EsbuildStaticOptions:
    def __init__(
        self, source, root, config_path, working_dir, direct_builds, namespace_builds
    ):
        self.source = source
        self.config_path = os.path.realpath(config_path)
        self.working_dir = working_dir
        self.constants = {}
        self.helpers = {}
        self.namespaces = {}
        self.unsafe = set()
        self.steps = 0
        self.working_directory_changed = False
        self.direct_builds = direct_builds
        self.namespace_builds = namespace_builds
        self._collect_bindings(root)
        self._collect_mutations(root)

    def _text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def _collect_bindings(self, root):
        for statement in root.named_children:
            if statement.type == "import_statement":
                module = self._text(statement.child_by_field_name("source"))[1:-1]
                module = module.removeprefix("node:")
                if module not in {"path", "url"} or self._text(statement).startswith(
                    "import type "
                ):
                    continue
                for clause in statement.named_children:
                    if clause.type != "import_clause":
                        continue
                    for binding in clause.named_children:
                        if binding.type == "identifier":
                            self.namespaces[self._text(binding)] = module
                        elif binding.type == "namespace_import":
                            self.namespaces[self._text(binding.named_children[-1])] = (
                                module
                            )
                        elif binding.type == "named_imports":
                            for specifier in binding.named_children:
                                if specifier.type != "import_specifier" or self._text(
                                    specifier
                                ).startswith("type "):
                                    continue
                                name = self._text(specifier.child_by_field_name("name"))
                                alias = specifier.child_by_field_name("alias")
                                local = self._text(alias) if alias else name
                                if (module == "path" and name in _PATH_METHODS) or (
                                    module == "url" and name == "fileURLToPath"
                                ):
                                    self.helpers[local] = (module, name)
            elif (
                statement.type == "lexical_declaration"
                and statement.children[0].type == "const"
            ):
                for declaration in statement.named_children:
                    name = declaration.child_by_field_name("name")
                    value = declaration.child_by_field_name("value")
                    if name is not None and name.type == "identifier" and value:
                        self.constants[self._text(name)] = value

    def _root_name(self, node):
        node = _unwrap(node)
        while node is not None and node.type in {
            "member_expression",
            "subscript_expression",
        }:
            node = _unwrap(node.child_by_field_name("object"))
        return (
            self._text(node) if node is not None and node.type == "identifier" else None
        )

    def _helper(self, node, local=()):
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "identifier":
            name = self._text(node)
            return (
                self.helpers.get(name)
                if name not in self.unsafe and name not in local
                else None
            )
        if node.type != "member_expression":
            return None
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or obj.type != "identifier" or prop is None:
            return None
        name = self._text(obj)
        module = self.namespaces.get(name)
        method = self._text(prop)
        if name in self.unsafe or name in local:
            return None
        if (module == "path" and method in _PATH_METHODS) or (
            module == "url" and method == "fileURLToPath"
        ):
            return module, method
        return None

    def _is_build(self, node):
        if node is None:
            return False
        if node.type == "identifier":
            return self._text(node) in self.direct_builds
        if node.type == "member_expression":
            return self._text(
                node.child_by_field_name("object")
            ) in self.namespace_builds and self._text(
                node.child_by_field_name("property")
            ) in {"build", "buildSync", "context"}
        return False

    def _references(self, node):
        names = set()
        if node is None:
            return names
        for child in _nodes(node):
            self.steps += 1
            if self.steps > _MAX_STEPS:
                break
            if child.type in {"identifier", "shorthand_property_identifier"}:
                names.add(self._text(child))
        return names

    def _collect_mutations(self, root):
        # Const objects/arrays can still be mutated, including via aliases or
        # arguments to unknown functions. Refuse those graphs, even if a write
        # happens later; this sacrifices some precision instead of inventing roots.
        for node in _nodes(root):
            self.steps += 1
            if self.steps > _MAX_STEPS:
                return
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                self.unsafe.update(self._references(node.child_by_field_name("left")))
                self.unsafe.update(self._references(node.child_by_field_name("right")))
            elif node.type == "update_expression" or (
                node.type == "unary_expression"
                and self._text(node.child_by_field_name("operator")) == "delete"
            ):
                self.unsafe.update(self._references(node))
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name = node.child_by_field_name("name")
                if (
                    value
                    and _unwrap(value).type
                    not in {"call_expression", "await_expression"}
                    and (name is None or self.constants.get(self._text(name)) != value)
                ):
                    self.unsafe.update(self._references(value))
            elif node.type == "return_statement":
                self.unsafe.update(self._references(node))
            elif node.type == "arrow_function":
                body = node.child_by_field_name("body")
                if body is not None and _unwrap(body).type in {
                    "identifier",
                    "object",
                    "array",
                }:
                    self.unsafe.update(self._references(body))
            elif node.type in {"call_expression", "new_expression"}:
                function = node.child_by_field_name("function")
                if self._helper(function) or self._is_build(function):
                    continue
                if function is not None and function.type == "member_expression":
                    if (
                        self._root_name(function) == "process"
                        and self._text(function.child_by_field_name("property"))
                        == "chdir"
                    ):
                        self.working_directory_changed = True
                    if self._text(function.child_by_field_name("property")) == "map":
                        continue
                    name = self._root_name(function)
                    if name:
                        self.unsafe.add(name)
                arguments = node.child_by_field_name("arguments")
                if arguments:
                    self.unsafe.update(self._references(arguments))
        # Undirected dependency propagation also catches shared mutable values
        # hidden inside objects, arrays, or nested aliases passed elsewhere.
        neighbors = {}
        for name, value in self.constants.items():
            if self.steps > _MAX_STEPS:
                return
            if _unwrap(value).type not in {"identifier", "array", "object"}:
                continue
            for dependency in self._references(value):
                neighbors.setdefault(name, set()).add(dependency)
                neighbors.setdefault(dependency, set()).add(name)
        pending = list(self.unsafe)
        while pending:
            for neighbor in neighbors.get(pending.pop(), ()):
                if neighbor not in self.unsafe:
                    self.unsafe.add(neighbor)
                    pending.append(neighbor)

    def evaluate(self, node, *, before=None, local=None, depth=0):
        self.steps += 1
        if self.steps > _MAX_STEPS or depth > _MAX_DEPTH:
            return UNKNOWN
        node = _unwrap(node)
        if node is None:
            return UNKNOWN
        local = {} if local is None else local
        before = node.start_byte if before is None else before

        def value(child, bindings=local):
            return self.evaluate(child, before=before, local=bindings, depth=depth + 1)

        if node.type == "string":
            text = self._text(node)[1:-1]
            return text if "\\" not in text and len(text) <= _MAX_STRING else UNKNOWN
        if node.type == "identifier":
            name = self._text(node)
            if name in local:
                return local[name]
            declaration = self.constants.get(name)
            if (
                name in self.unsafe
                or declaration is None
                or declaration.end_byte >= before
            ):
                return UNKNOWN
            return self.evaluate(
                declaration, before=declaration.start_byte, depth=depth + 1
            )
        if node.type == "template_string":
            parts = []
            for child in node.named_children:
                if child.type == "string_fragment":
                    part = self._text(child)
                elif (
                    child.type == "template_substitution"
                    and len(child.named_children) == 1
                ):
                    part = value(child.named_children[0])
                else:
                    return UNKNOWN
                if not isinstance(part, str):
                    return UNKNOWN
                parts.append(part)
            return "".join(parts) if sum(map(len, parts)) <= _MAX_STRING else UNKNOWN
        if node.type == "array":
            items = []
            expecting_value = True
            for child in node.children:
                if child.type in {"[", "]", "comment"}:
                    continue
                if child.type == ",":
                    if expecting_value:
                        return UNKNOWN
                    expecting_value = True
                    continue
                if not expecting_value:
                    return UNKNOWN
                expecting_value = False
                if child.type == "spread_element":
                    spread = value(child.named_children[0])
                    if not isinstance(spread, list):
                        return UNKNOWN
                    items.extend(spread)
                else:
                    items.append(value(child))
                if len(items) > _MAX_ITEMS:
                    return UNKNOWN
            return items
        if node.type == "object":
            properties = {}
            for child in node.named_children:
                if child.type == "comment":
                    continue
                if child.type == "spread_element":
                    spread = value(child.named_children[0])
                    if not isinstance(spread, dict):
                        return UNKNOWN
                    properties.update(spread)
                elif child.type == "shorthand_property_identifier":
                    name = self._text(child)
                    declaration = self.constants.get(name)
                    if (
                        name in self.unsafe
                        or declaration is None
                        or declaration.end_byte >= before
                    ):
                        properties[name] = UNKNOWN
                    else:
                        properties[name] = self.evaluate(
                            declaration, before=declaration.start_byte, depth=depth + 1
                        )
                elif child.type == "pair":
                    key = child.child_by_field_name("key")
                    if key.type in {"property_identifier", "identifier"}:
                        key = self._text(key)
                    elif key.type == "string":
                        key = value(key)
                    else:
                        return UNKNOWN
                    if not isinstance(key, str) or key == "__proto__":
                        return UNKNOWN
                    properties[key] = value(child.child_by_field_name("value"))
                else:
                    return UNKNOWN
                if len(properties) > _MAX_ITEMS:
                    return UNKNOWN
            return properties
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                return UNKNOWN
            args = [
                child for child in arguments.named_children if child.type != "comment"
            ]
            helper = self._helper(function, local)
            if helper == ("url", "fileURLToPath"):
                if len(args) == 1 and self._text(args[0]) == "import.meta.url":
                    return self.config_path
                return UNKNOWN
            if helper and helper[0] == "path":
                values = [value(arg) for arg in args]
                if not values or not all(isinstance(item, str) for item in values):
                    return UNKNOWN
                method = helper[1]
                if method == "dirname":
                    if len(values) != 1:
                        return UNKNOWN
                    return os.path.dirname(values[0].rstrip(os.sep)) or (
                        os.sep if values[0].startswith(os.sep) else "."
                    )
                if method == "join":
                    result = os.path.normpath(
                        os.sep.join(item for item in values if item)
                    )
                else:
                    result = os.path.normpath(os.path.join(self.working_dir, *values))
                return result if len(result) <= _MAX_STRING else UNKNOWN
            if (
                function is not None
                and function.type == "member_expression"
                and self._text(function.child_by_field_name("property")) == "map"
                and len(args) == 1
                and "Array" not in self.unsafe
            ):
                items = value(function.child_by_field_name("object"))
                arrow = args[0]
                if not isinstance(items, list) or arrow.type != "arrow_function":
                    return UNKNOWN
                parameter = arrow.child_by_field_name("parameter")
                parameters = arrow.child_by_field_name("parameters")
                if (
                    parameter is None
                    and parameters is not None
                    and len(parameters.named_children) == 1
                ):
                    parameter = parameters.named_children[0]
                    if parameter.type == "required_parameter":
                        parameter = parameter.child_by_field_name("pattern")
                body = arrow.child_by_field_name("body")
                if (
                    parameter is None
                    or parameter.type != "identifier"
                    or body is None
                    or body.type == "statement_block"
                    or any(child.type == "async" for child in arrow.children)
                ):
                    return UNKNOWN
                name = self._text(parameter)
                return [value(body, {**local, name: item}) for item in items]
        return UNKNOWN


def esbuild_entry_values(value):
    if isinstance(value, dict):
        entries = list(value.values())
    elif isinstance(value, list):
        entries = []
        for item in value:
            if isinstance(item, dict):
                if set(item) != {"in", "out"} or not isinstance(item["out"], str):
                    return None
                item = item["in"]
            entries.append(item)
    else:
        return None
    return entries if all(isinstance(item, str) for item in entries) else None
