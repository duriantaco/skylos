"""Bounded, non-executing constant folding for esbuild entry-point options.

This deliberately is not a JavaScript interpreter. Only module constants, plain
data, imported Node path helpers, and pure literal-array maps are understood.
Unknown calls, mutable/escaped data, and dynamic keys remain unknown.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict

from skylos.core.js_ast import is_type_only, iter_import_clause_bindings


UNKNOWN = object()
_MAX_STEPS = 20_000
_MAX_DEPTH = 40
_MAX_ITEMS = 1_024
_MAX_STRING = 16_384
_PATH_METHODS = frozenset({"join", "resolve", "dirname"})


def path_dirname(value):
    """Drop the last nonempty component, preserving Node's root spelling."""
    separators = "/" if os.sep == "/" else "/\\"
    root_end = int(bool(value) and value[0] in separators)
    if os.sep == "\\":
        unc = re.match(r"^[\\/]{2}[^\\/]+[\\/]+[^\\/]+", value)
        if unc:
            if unc.end() == len(value):
                return value
            root_end = unc.end() + 1
        elif re.match(r"^[A-Za-z]:", value):
            root_end = 3 if len(value) > 2 and value[2] in separators else 2
    component_end = len(value.rstrip(separators))
    end = max(value.rfind(sep, root_end, component_end) for sep in separators)
    if end < 0:
        return value[:root_end] or "."
    if os.sep == "/" and root_end and end == 1:
        return "//"
    return value[:end]


def path_join(values):
    """Concatenate before normalizing: later rooted segments never reset join."""
    segments = [segment for segment in values if segment]
    if not segments:
        return "."
    joined = os.sep.join(segments)
    unc = None
    if os.sep == "/":
        joined = re.sub("^/+", "/", joined)
    else:
        joined = joined.replace("/", "\\")
        # Non-drive colons have version-dependent normalization and may name
        # streams/devices, not regular entry files. Do not guess their meaning.
        drive_end = 2 if re.match(r"^[A-Za-z]:", joined) else 0
        if ":" in joined[drive_end:]:
            return None
        head = segments[0].replace("/", "\\")
        if head.startswith("\\\\") and len(head) > 2 and head[2] != "\\":
            unc = re.match(r"^\\\\([^\\]+)\\+([^\\]+)", joined)
        if unc:
            joined = "\\\\" + unc.group(1) + "\\" + unc.group(2) + joined[unc.end() :]
        elif joined.startswith("\\\\"):
            joined = "\\" + joined.lstrip("\\")
    result = os.path.normpath(joined)
    if os.sep == "\\":
        drive, tail = os.path.splitdrive(result)
        if drive and not tail:
            result += "\\" if unc else "."
    if joined.endswith(os.sep) and not result.endswith(os.sep):
        result += os.sep
    return result


def path_call(working_dir, call_name, values):
    if call_name == "path.dirname" and len(values) == 1:
        return path_dirname(values[0])
    if call_name == "path.join":
        return path_join(values)
    if call_name == "path.resolve" and values:
        return os.path.normpath(os.path.join(working_dir, *values))
    return None


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
        self.root = root
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
        self._index_bindings(root)
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
                if module not in {"path", "url"} or is_type_only(statement):
                    continue
                for clause in statement.named_children:
                    if clause.type != "import_clause":
                        continue
                    for binding in iter_import_clause_bindings(self.source, clause):
                        if binding.type_only:
                            continue
                        if binding.kind in {"default", "namespace"}:
                            self.namespaces[binding.local] = module
                        elif (
                            module == "path" and binding.imported in _PATH_METHODS
                        ) or (module == "url" and binding.imported == "fileURLToPath"):
                            self.helpers[binding.local] = (module, binding.imported)
            if statement.type == "export_statement":
                statement = statement.child_by_field_name("declaration") or statement
            if statement.type == "lexical_declaration" and any(
                child.type == "const" for child in statement.children
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

    def _walk(self, node):
        if node is None:
            return
        for child in _nodes(node):
            self.steps += 1
            if self.steps > _MAX_STEPS:
                return
            yield child

    def _pattern_names(self, pattern):
        names = set()
        pending = [pattern]
        while pending:
            node = pending.pop()
            self.steps += 1
            if self.steps > _MAX_STEPS:
                break
            if node is None:
                continue
            if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
                names.add(self._text(node))
            elif node.type in {"required_parameter", "optional_parameter"}:
                pending.append(node.child_by_field_name("pattern"))
            elif node.type == "pair_pattern":
                pending.append(node.child_by_field_name("value"))
            elif node.type in {"assignment_pattern", "object_assignment_pattern"}:
                pending.append(node.child_by_field_name("left"))
            elif node.type in {
                "formal_parameters",
                "object_pattern",
                "array_pattern",
                "rest_pattern",
            }:
                pending.extend(node.named_children)
        return names

    def _declaration_scope(self, declaration):
        scope = declaration.parent
        while scope is not None and scope != self.root:
            function_scope = scope.type != "catch_clause" and (
                scope.child_by_field_name("parameters") is not None
                or scope.child_by_field_name("parameter") is not None
            )
            block_scope = scope.type in {
                "statement_block",
                "for_statement",
                "for_in_statement",
                "switch_body",
            }
            if function_scope or (
                block_scope and declaration.type != "variable_declaration"
            ):
                break
            scope = scope.parent
        return scope or self.root

    def _index_bindings(self, root):
        """Keep local parameters and variables separate from module constants."""
        self.scopes = defaultdict(set)
        self.scoped_constants = {}
        for node in self._walk(root):
            parameters = node.child_by_field_name(
                "parameters"
            ) or node.child_by_field_name("parameter")
            if parameters is not None:
                self.scopes[node].update(self._pattern_names(parameters))
            if node.type in {
                "function_declaration",
                "generator_function_declaration",
                "class_declaration",
            }:
                name = node.child_by_field_name("name")
                if name is not None:
                    self.scopes[self._declaration_scope(node)].add(self._text(name))
            if node.type != "variable_declarator" or node.parent is None:
                continue
            declaration = node.parent
            scope = self._declaration_scope(declaration)
            name = node.child_by_field_name("name")
            self.scopes[scope].update(self._pattern_names(name))
            value = _unwrap(node.child_by_field_name("value"))
            if (
                value is not None
                and name is not None
                and name.type == "identifier"
                and any(child.type == "const" for child in declaration.children)
            ):
                self.scoped_constants[(scope, self._text(name))] = value
        self.primitives = set()
        aliases = defaultdict(set)
        for binding, value in self.scoped_constants.items():
            if value.type in {
                "string",
                "template_string",
                "number",
                "true",
                "false",
                "null",
            } or (
                value.type == "call_expression"
                and self._helper(value.child_by_field_name("function")) is not None
            ):
                self.primitives.add(binding)
            elif value.type == "identifier":
                aliases[self._resolve(value, self._text(value))].add(binding)
        pending = list(self.primitives)
        while pending:
            for binding in aliases.get(pending.pop(), ()):
                if binding not in self.primitives:
                    self.primitives.add(binding)
                    pending.append(binding)

    def _resolve(self, node, name):
        current = node
        while current is not None:
            if name in self.scopes.get(current, ()):
                return current, name
            current = current.parent
        return self.root, name

    def _container_references(self, value):
        """Connect shared containers, but not primitive copies or call results."""
        references = set()
        pending = [value]
        while pending:
            node = _unwrap(pending.pop())
            self.steps += 1
            if self.steps > _MAX_STEPS:
                break
            if node is None:
                continue
            name = self._root_name(node)
            if node.type == "shorthand_property_identifier":
                name = self._text(node)
            if name is not None:
                reference = self._resolve(node, name)
                if reference not in self.primitives:
                    references.add(reference)
            elif node.type == "pair":
                pending.append(node.child_by_field_name("value"))
            elif node.type in {"object", "array", "spread_element"}:
                pending.extend(node.named_children)
        return references

    def _helper(self, node, local=()):
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "identifier":
            name = self._text(node)
            return (
                self.helpers.get(name)
                if name not in self.unsafe
                and name not in local
                and self._resolve(node, name)[0] == self.root
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
        if (
            name in self.unsafe
            or name in local
            or self._resolve(obj, name)[0] != self.root
        ):
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
            name = self._text(node)
            return (
                name in self.direct_builds and self._resolve(node, name)[0] == self.root
            )
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            name = self._text(obj)
            return (
                obj is not None
                and obj.type == "identifier"
                and name in self.namespace_builds
                and self._resolve(obj, name)[0] == self.root
                and self._text(node.child_by_field_name("property"))
                in {"build", "buildSync", "context"}
            )
        return False

    def _references(self, node):
        names = set()
        if node is None:
            return names
        for child in self._walk(node):
            if child.type in {"identifier", "shorthand_property_identifier"}:
                binding = self._resolve(child, self._text(child))
                if binding not in self.primitives:
                    names.add(binding)
        return names

    def _collect_mutations(self, root):
        # Const objects/arrays can still be mutated, including via aliases or
        # arguments to unknown functions. Refuse those graphs, even if a write
        # happens later; this sacrifices some precision instead of inventing roots.
        unsafe = set()
        neighbors = defaultdict(set)
        for node in self._walk(root):
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                target = node.child_by_field_name("left")
                name = self._root_name(target)
                if name is not None:
                    unsafe.add(self._resolve(target, name))
                else:
                    unsafe.update(self._references(target))
                unsafe.update(self._references(node.child_by_field_name("right")))
            elif node.type == "update_expression" or (
                node.type == "unary_expression"
                and self._text(node.child_by_field_name("operator")) == "delete"
            ):
                target = node.child_by_field_name("argument")
                name = self._root_name(target)
                if name is not None:
                    unsafe.add(self._resolve(target, name))
            elif node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                name = node.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    local = self._resolve(node, self._text(name))
                    if local not in self.primitives:
                        for dependency in self._container_references(value):
                            neighbors[local].add(dependency)
                            neighbors[dependency].add(local)
                if (
                    value
                    and _unwrap(value).type
                    not in {"call_expression", "await_expression"}
                    and (name is None or self.constants.get(self._text(name)) != value)
                ):
                    unsafe.update(self._references(value))
            elif node.type == "return_statement":
                unsafe.update(self._references(node))
            elif node.type == "arrow_function":
                body = node.child_by_field_name("body")
                if body is not None and _unwrap(body).type in {
                    "identifier",
                    "object",
                    "array",
                }:
                    unsafe.update(self._references(body))
            elif node.type in {"call_expression", "new_expression"}:
                function = node.child_by_field_name("function")
                if self._helper(function) or self._is_build(function):
                    continue
                if function is not None and function.type in {
                    "member_expression",
                    "subscript_expression",
                }:
                    method_node = function.child_by_field_name("property")
                    method = self._text(method_node)
                    if (
                        self._root_name(function) == "process"
                        and self._resolve(function, "process")[0] == root
                        and method == "chdir"
                    ):
                        self.working_directory_changed = True
                    if method == "map":
                        continue
                    name = self._root_name(function)
                    if name:
                        unsafe.add(self._resolve(function, name))
                arguments = node.child_by_field_name("arguments")
                if arguments:
                    unsafe.update(self._references(arguments))
        # Undirected dependency propagation also catches shared mutable values
        # hidden inside objects, arrays, or aliases, without conflating shadows
        # or treating a copied primitive as a shared mutable container.
        pending = list(unsafe)
        while pending:
            for neighbor in neighbors.get(pending.pop(), ()):
                if neighbor not in unsafe:
                    unsafe.add(neighbor)
                    pending.append(neighbor)
        self.unsafe = {name for scope, name in unsafe if scope == root}

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
                if not all(isinstance(item, str) for item in values):
                    return UNKNOWN
                result = path_call(self.working_dir, f"path.{helper[1]}", values)
                return (
                    result
                    if isinstance(result, str) and len(result) <= _MAX_STRING
                    else UNKNOWN
                )
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
                if parameter is None and parameters is not None:
                    parameter_nodes = [
                        child
                        for child in parameters.named_children
                        if child.type != "comment"
                    ]
                    if len(parameter_nodes) == 1:
                        parameter = parameter_nodes[0]
                if parameter is not None and parameter.type in {
                    "required_parameter",
                    "optional_parameter",
                }:
                    if parameter.child_by_field_name("value") is not None:
                        return UNKNOWN
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
