"""Disprove file loading for a small, source-resolved discarded-value shape.

A constructed path normally remains conservative liveness evidence. Only an
unexported immutable binding with no uses, or uses exclusively as arguments to
source-proven empty functions, can refute that evidence. Unknown consumers,
aliases, mutation, shadowing and default-parameter effects preserve it.
"""

from __future__ import annotations

import os

from skylos.core.js_ast import call_arguments, first_call_argument
from skylos.core.safe_cache_io import read_text_no_symlink

_MAX_NODES = 20_000
_JS_SUFFIXES = (
    "",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".tsx",
    ".jsx",
    "/index.js",
    "/index.ts",
)


class DiscardedPathValues:
    def __init__(self, filename, source, root, *, project_root=None, project_files=()):
        self.filename, self.source, self.root = filename, source, root
        self.project_root = os.path.realpath(project_root) if project_root else None
        self.project_files = {os.path.realpath(path) for path in project_files}
        self.nodes = []
        stack = [root]
        while stack and len(self.nodes) <= _MAX_NODES:
            node = stack.pop()
            self.nodes.append(node)
            stack.extend(node.named_children)
        self.complete = not stack and not root.has_error
        self.bindings = {}
        self.functions = {}
        self.providers = {}
        self.provider_methods = {}
        self.stable_path_bindings = None
        self.closed_dependencies = None
        if not self.complete:
            return
        for statement in root.named_children:
            if (
                statement.type == "lexical_declaration"
                and statement.children[0].type == "const"
            ):
                for declaration in statement.named_children:
                    if declaration.type != "variable_declarator":
                        continue
                    name = declaration.child_by_field_name("name")
                    if name is not None and name.type == "identifier":
                        self.bindings[self.text(name)] = declaration
            elif statement.type == "function_declaration" and self.empty_function(
                statement
            ):
                name = statement.child_by_field_name("name")
                if name is not None:
                    self.functions[self.text(name)] = name

    def text(self, node):
        return (
            self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")
            if node
            else ""
        )

    @staticmethod
    def empty_function(node):
        body = node.child_by_field_name("body")
        parameters = node.child_by_field_name("parameters")
        if body is None or body.type != "statement_block" or parameters is None:
            return False
        if any(child.type != "comment" for child in body.named_children):
            return False
        # Defaults, destructuring and rest can execute user code before an empty body.
        return all(
            child.type == "identifier"
            or (
                child.type in {"required_parameter", "optional_parameter"}
                and child.child_by_field_name("pattern") is not None
                and child.child_by_field_name("pattern").type == "identifier"
                and child.child_by_field_name("value") is None
            )
            for child in parameters.named_children
        )

    def occurrences(self, name):
        return [
            node
            for node in self.nodes
            if node.type
            in {
                "identifier",
                "shorthand_property_identifier",
                "shorthand_property_identifier_pattern",
            }
            and self.text(node) == name
        ]

    def _native_require(self):
        for node in self.occurrences("require"):
            parent = node.parent
            if (
                parent is None
                or parent.type != "call_expression"
                or parent.child_by_field_name("function") != node
            ):
                return False
        return True

    def _required_file(self, call):
        if call is None or call.type != "call_expression" or not self._native_require():
            return None
        if self.text(call.child_by_field_name("function")) != "require":
            return None
        arguments = call.child_by_field_name("arguments")
        if len(call_arguments(arguments)) != 1:
            return None
        from .file_references import (
            _static_string,
            path_module_bindings,
            static_path_join,
        )

        argument = first_call_argument(arguments)
        if argument is None:
            return None
        literal = _static_string(self.source, argument)
        if literal is not None:
            if not literal.startswith("."):
                return None
            target = os.path.join(os.path.dirname(self.filename), literal)
        else:
            namespaces, functions = path_module_bindings(self.source, self.root)
            joined = static_path_join(self.source, argument, namespaces, functions)
            if joined is None or not joined[0]:
                return None
            target = os.path.join(os.path.dirname(self.filename), *joined[1])
        if self.project_root is None:
            return None
        for suffix in _JS_SUFFIXES:
            candidate = os.path.realpath(target + suffix)
            if (
                candidate in self.project_files
                and os.path.commonpath([candidate, self.project_root])
                == self.project_root
            ):
                return candidate
        return None

    def _exported_empty_methods(self, filename):
        if filename in self.provider_methods:
            return self.provider_methods[filename]
        self.provider_methods[filename] = set()
        text = read_text_no_symlink(
            filename, max_bytes=256_000, encoding="utf-8", errors="strict"
        )
        if not text:
            return set()
        from .file_references import _parse_js

        source = text.encode("utf-8")
        tree = _parse_js(filename, source)
        if tree is None or tree.root_node.has_error:
            return set()
        statements = [n for n in tree.root_node.named_children if n.type != "comment"]
        # A closed literal export has no imports, top-level effects or later mutation.
        if len(statements) != 1 or statements[0].type != "expression_statement":
            return set()
        children = statements[0].named_children
        if len(children) != 1 or children[0].type != "assignment_expression":
            return set()
        assignment = children[0]
        left = assignment.child_by_field_name("left")
        right = assignment.child_by_field_name("right")
        if (
            source[left.start_byte : left.end_byte] != b"module.exports"
            or right is None
            or right.type != "object"
        ):
            return set()
        methods = set()
        keys = set()
        for member in right.named_children:
            if member.type == "comment":
                continue
            if member.type == "method_definition":
                name, value = member.child_by_field_name("name"), member
                if any(c.type in {"get", "set", "*", "async"} for c in member.children):
                    return set()
            elif member.type == "pair":
                name, value = (
                    member.child_by_field_name("key"),
                    member.child_by_field_name("value"),
                )
                if value is None or value.type not in {
                    "function_expression",
                    "arrow_function",
                }:
                    return set()
            else:
                return set()
            if name is None or name.type != "property_identifier":
                return set()
            key = source[name.start_byte : name.end_byte].decode("utf-8", "replace")
            if key in keys or key == "__proto__":
                return set()
            keys.add(key)
            if not self.empty_function(value):
                return set()
            methods.add(key)
        self.provider_methods[filename] = methods
        return methods

    def _dependencies_are_closed(self):
        if self.closed_dependencies is not None:
            return self.closed_dependencies
        self.closed_dependencies = False
        if not self._native_require():
            return False
        # Another import can patch the singleton export through its own alias.
        # Require a closed, effect-free set of local providers before narrowing.
        from .file_references import _require_specifier, _static_string

        for candidate in self.nodes:
            if candidate.type in {"identifier", "property_identifier"} and self.text(
                candidate
            ) in {"eval", "Function"}:
                return False
            if candidate.type == "import_statement" and _static_string(
                self.source, candidate.child_by_field_name("source")
            ) not in {"path", "node:path"}:
                return False
            if candidate.type != "call_expression":
                continue
            callee = candidate.child_by_field_name("function")
            if self.text(callee) in {"eval", "Function", "import"}:
                return False
            if self.text(callee) != "require":
                continue
            if _require_specifier(self.source, candidate) in {"path", "node:path"}:
                continue
            dependency = self._required_file(candidate)
            if dependency is None or not self._exported_empty_methods(dependency):
                return False
        self.closed_dependencies = True
        return True

    def _provider(self, name):
        if name in self.providers:
            return self.providers[name]
        self.providers[name] = set()
        declaration = self.bindings.get(name)
        if declaration is None:
            return set()
        filename = self._required_file(declaration.child_by_field_name("value"))
        methods = self._exported_empty_methods(filename) if filename else set()
        if not methods:
            return set()
        binding = declaration.child_by_field_name("name")
        for node in self.occurrences(name):
            if node == binding:
                continue
            member = node.parent
            if (
                member is None
                or member.type != "member_expression"
                or member.child_by_field_name("object") != node
            ):
                return set()
            call = member.parent
            if (
                call is None
                or call.type != "call_expression"
                or call.child_by_field_name("function") != member
            ):
                return set()
            if self.text(member.child_by_field_name("property")) not in methods:
                return set()
        self.providers[name] = methods
        return methods

    def _discarding_call(self, call):
        function = call.child_by_field_name("function")
        if function is None:
            return False
        if function.type == "identifier":
            name = self.text(function)
            binding = self.functions.get(name)
            if binding is None:
                return False
            # Reassignment, aliases, exports or shadowing invalidate the local proof.
            return all(
                node == binding
                or (
                    node.parent is not None
                    and node.parent.type == "call_expression"
                    and node.parent.child_by_field_name("function") == node
                )
                for node in self.occurrences(name)
            )
        if function.type == "member_expression":
            owner = function.child_by_field_name("object")
            if owner is not None and owner.type == "identifier":
                return self.text(
                    function.child_by_field_name("property")
                ) in self._provider(self.text(owner))
        return False

    def _ignored_argument(self, node):
        arguments = node.parent
        if arguments is None or arguments.type != "arguments":
            return False
        call = arguments.parent
        return (
            call is not None
            and call.type == "call_expression"
            and self._discarding_call(call)
        )

    def _paths_are_stable(self, namespaces, functions):
        if self.stable_path_bindings is not None:
            return self.stable_path_bindings
        self.stable_path_bindings = False
        if not self._dependencies_are_closed():
            return False
        from .file_references import _require_specifier, _static_string

        for name in namespaces | functions:
            binding = None
            declaration = self.bindings.get(name)
            if (
                declaration is not None
                and _require_specifier(
                    self.source, declaration.child_by_field_name("value")
                )
                in {"path", "node:path"}
                and self._native_require()
            ):
                binding = declaration.child_by_field_name("name")
            else:
                for statement in self.root.named_children:
                    if statement.type != "import_statement" or _static_string(
                        self.source, statement.child_by_field_name("source")
                    ) not in {"path", "node:path"}:
                        continue
                    for candidate in self.occurrences(name):
                        if (
                            statement.start_byte
                            <= candidate.start_byte
                            < statement.end_byte
                        ):
                            if binding is not None:
                                return False
                            binding = candidate
            if binding is None:
                return False
            for use in self.occurrences(name):
                if use == binding:
                    continue
                parent = use.parent
                if name in namespaces:
                    if (
                        parent is None
                        or parent.type != "member_expression"
                        or parent.child_by_field_name("object") != use
                    ):
                        return False
                    if self.text(parent.child_by_field_name("property")) not in {
                        "join",
                        "resolve",
                    }:
                        return False
                    use, parent = parent, parent.parent
                if (
                    parent is None
                    or parent.type != "call_expression"
                    or parent.child_by_field_name("function") != use
                ):
                    return False
        self.stable_path_bindings = True
        return True

    def discards(self, node, namespaces, functions):
        if not self.complete:
            return False
        if not self._paths_are_stable(namespaces, functions):
            return False
        if self._ignored_argument(node):
            return True
        declaration = node.parent
        if (
            declaration is None
            or declaration.type != "variable_declarator"
            or declaration.child_by_field_name("value") != node
        ):
            return False
        name_node = declaration.child_by_field_name("name")
        if name_node is None or name_node.type != "identifier":
            return False
        name = self.text(name_node)
        if self.bindings.get(name) != declaration:
            return False
        return all(
            use == name_node or self._ignored_argument(use)
            for use in self.occurrences(name)
        )
