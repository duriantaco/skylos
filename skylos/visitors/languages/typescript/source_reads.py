"""Bounded Node filesystem reads of repository source used as data.

This adds file/consumer edges, never a directory-wide export exemption. Paths
must be rooted in the project, with a fixed filename and at most one string
parameter directory component. Native imports, lexical scopes and mutation
facts are checked without importing or executing the project.
"""

from __future__ import annotations

import itertools
import os
import re
from collections import defaultdict

from skylos.core.js_ast import is_type_only, iter_import_clause_bindings
from skylos.core.safe_cache_io import read_text_no_symlink

from .esbuild_static import EsbuildStaticOptions, _nodes, _unwrap, path_call
from .file_references import _TS_PARSER, _TSX_PARSER, _MAX_REFERENCE_FILE_BYTES

_SEGMENT = "\x00"
_FUNCTIONS = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    }
)


class _SourceReads:
    def __init__(self, source, root, filename, project_root):
        self.source, self.root = source, root
        self.filename, self.project_root = filename, project_root
        self.nodes = list(_nodes(root))
        self.facts = EsbuildStaticOptions(
            source, root, filename, project_root, set(), set()
        )
        self.invalid = set()
        self.readers = {}
        self._imports()
        self._mutations()
        self.steps = 0

    def text(self, node):
        return self.facts._text(node)

    def _imports(self):
        counts = defaultdict(int)
        for statement in self.root.named_children:
            if statement.type != "import_statement" or is_type_only(statement):
                continue
            module = self.text(statement.child_by_field_name("source"))[1:-1]
            promises = module.endswith("/promises")
            for clause in statement.named_children:
                if clause.type != "import_clause":
                    continue
                for binding in iter_import_clause_bindings(self.source, clause):
                    if binding.type_only:
                        continue
                    counts[binding.local] += 1
                    if module not in {
                        "fs",
                        "node:fs",
                        "fs/promises",
                        "node:fs/promises",
                    }:
                        continue
                    if binding.kind in {"default", "namespace"}:
                        self.readers[binding.local] = ("namespace", promises)
                    elif binding.imported in {"readFile", "readFileSync"}:
                        if not promises or binding.imported == "readFile":
                            self.readers[binding.local] = (binding.imported, promises)
        self.readers = {
            name: reader
            for name, reader in self.readers.items()
            if counts[name] == 1 and name not in self.facts.scopes[self.root]
        }
        self.import_counts = counts

    def _root_name(self, node):
        return self.facts._root_name(node)

    def _native_read(self, node):
        node = _unwrap(node)
        name = self._root_name(node)
        if name not in self.readers or (self.root, name) in self.invalid:
            return False
        if self.facts._resolve(node, name)[0] != self.root:
            return False
        kind, promises = self.readers[name]
        text = self.text(node)
        if kind != "namespace":
            return node.type == "identifier"
        suffix = text[len(name) :]
        allowed = (
            {".readFile"}
            if promises
            else {".readFile", ".readFileSync", ".promises.readFile"}
        )
        return suffix in allowed

    def _mutations(self):
        # Reuse scope identities, but not the bundler helper's broad unknown-
        # call rule: a genuine fs.readFile call is the capability being proved.
        for node in self.nodes:
            if node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                left = node.child_by_field_name("left")
                name = self._root_name(left)
                if name:
                    self.invalid.add(self.facts._resolve(left, name))
            elif node.type == "update_expression":
                argument = node.child_by_field_name("argument")
                name = self._root_name(argument)
                if name:
                    self.invalid.add(self.facts._resolve(argument, name))
        for node in self.nodes:
            if node.type != "identifier" or self.text(node) not in self.readers:
                continue
            name = self.text(node)
            if self.facts._resolve(node, name)[0] != self.root:
                continue
            current = node
            while (
                current.parent is not None
                and current.parent.type == "member_expression"
                and current.parent.child_by_field_name("object") == current
            ):
                current = current.parent
            parent = current.parent
            if parent is not None and parent.type in {
                "import_clause",
                "namespace_import",
                "import_specifier",
            }:
                continue
            if (
                parent is not None
                and parent.type == "call_expression"
                and parent.child_by_field_name("function") == current
            ):
                kind, promises = self.readers[name]
                suffix = self.text(current)[len(name) :]
                # Other read-only filesystem operations do not replace the
                # reader. Capturing a namespace/method or passing it elsewhere
                # can, so those uses invalidate its identity.
                allowed = (
                    {".readFile", ".readdir"}
                    if promises
                    else {
                        ".readFile",
                        ".readFileSync",
                        ".readdir",
                        ".readdirSync",
                        ".promises.readFile",
                        ".promises.readdir",
                    }
                )
                if (kind == "namespace" and suffix in allowed) or (
                    kind != "namespace" and current == node
                ):
                    continue
            self.invalid.add((self.root, name))

    def _cwd(self, node):
        if self.text(node.child_by_field_name("function")) != "process.cwd":
            return False
        if (
            self.facts.working_directory_changed
            or "process" in self.facts.scopes[self.root]
        ):
            return False
        if self.facts._resolve(node, "process")[0] != self.root:
            return False
        for reference in self.nodes:
            if reference.type != "identifier" or self.text(reference) != "process":
                continue
            if self.facts._resolve(reference, "process")[0] != self.root:
                continue
            member = reference.parent
            call = member.parent if member is not None else None
            if not (
                member is not None
                and self.text(member) == "process.cwd"
                and call is not None
                and call.type == "call_expression"
                and call.child_by_field_name("function") == member
            ):
                return False
        return True

    def _path_helper(self, node):
        name = self._root_name(node)
        if (
            not name
            or (self.root, name) in self.invalid
            or self.import_counts[name] != 1
            or name in self.facts.scopes[self.root]
            or self.facts._resolve(node, name)[0] != self.root
        ):
            return None
        helper = self.facts.helpers.get(name)
        namespace = self.facts.namespaces.get(name)
        if helper and helper[0] == "path" and node.type == "identifier":
            method = helper[1]
        elif namespace == "path" and node.type == "member_expression":
            method = self.text(node.child_by_field_name("property"))
            if self.text(node.child_by_field_name("object")) != name:
                return None
        else:
            return None
        if method not in {"join", "resolve", "dirname"}:
            return None
        for reference in self.nodes:
            if reference.type != "identifier" or self.text(reference) != name:
                continue
            if self.facts._resolve(reference, name)[0] != self.root:
                continue
            parent = reference.parent
            if parent is not None and parent.type in {
                "import_clause",
                "namespace_import",
                "import_specifier",
            }:
                continue
            expression = reference
            if namespace == "path":
                if (
                    parent is None
                    or parent.type != "member_expression"
                    or parent.child_by_field_name("object") != reference
                ):
                    return None
                if self.text(parent.child_by_field_name("property")) not in {
                    "join",
                    "resolve",
                    "dirname",
                }:
                    return None
                expression = parent
            parent = expression.parent
            if (
                parent is None
                or parent.type != "call_expression"
                or parent.child_by_field_name("function") != expression
            ):
                return None
        return "path", method

    def _readonly_object(self, binding, declaration):
        for reference in self.nodes:
            if reference.type != "identifier" or self.text(reference) != binding[1]:
                continue
            if self.facts._resolve(reference, binding[1]) != binding:
                continue
            parent = reference.parent
            if (
                parent is not None
                and parent.type == "variable_declarator"
                and parent.child_by_field_name("name") == reference
                and parent.child_by_field_name("value") == declaration
            ):
                continue
            if (
                parent is not None
                and parent.type in {"subscript_expression", "member_expression"}
                and parent.child_by_field_name("object") == reference
            ):
                continue
            return False
        return True

    def values(self, node, *, before, seen=frozenset(), depth=0):
        self.steps += 1
        node = _unwrap(node)
        if node is None or depth > 20 or self.steps > 20_000:
            return set()
        if node.type == "string":
            value = self.text(node)[1:-1]
            return {value} if "\\" not in value and len(value) < 4096 else set()
        if node.type == "identifier":
            name = self.text(node)
            binding = self.facts._resolve(node, name)
            if binding in seen or binding in self.invalid:
                return set()
            value = self.facts.scoped_constants.get(binding)
            if value is not None:
                if value.end_byte >= before or (
                    binding[0] == self.root and name in self.facts.unsafe
                ):
                    return set()
                return self.values(
                    value,
                    before=value.start_byte,
                    seen=seen | {binding},
                    depth=depth + 1,
                )
            scope = binding[0]
            parameters = scope.child_by_field_name("parameters")
            if parameters is not None and scope.type in _FUNCTIONS:
                for parameter in parameters.named_children:
                    pattern = parameter.child_by_field_name("pattern")
                    annotation = parameter.child_by_field_name("type")
                    if (
                        pattern is not None
                        and self.text(pattern) == name
                        and annotation is not None
                        and re.sub(r"\s+", "", self.text(annotation)) == ":string"
                    ):
                        return {_SEGMENT}
            if name in {"__dirname", "__filename"} and binding[0] == self.root:
                return {
                    os.path.dirname(self.filename)
                    if name == "__dirname"
                    else self.filename
                }
            return set()
        if node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            if obj is None or obj.type != "identifier":
                return set()
            name = self.text(obj)
            binding = self.facts._resolve(obj, name)
            value = _unwrap(self.facts.scoped_constants.get(binding))
            if (
                value is None
                or value.type != "object"
                or binding in self.invalid
                or not self._readonly_object(binding, value)
                or value.end_byte >= before
            ):
                return set()
            properties = {}
            for pair in value.named_children:
                if pair.type == "comment":
                    continue
                if pair.type != "pair":
                    return set()
                literal = pair.child_by_field_name("value")
                key = pair.child_by_field_name("key")
                if key is None or key.type not in {"property_identifier", "string"}:
                    return set()
                key = self.text(key)
                if key.startswith(('"', "'")):
                    key = key[1:-1]
                if "\\" in key or key == "__proto__":
                    return set()
                if literal is None or literal.type != "string":
                    return set()
                properties[key] = self.values(literal, before=before, depth=depth + 1)
            index = node.child_by_field_name("index")
            keys = self.values(index, before=before, seen=seen, depth=depth + 1)
            if keys and _SEGMENT not in keys:
                found = set().union(*(properties.get(key, set()) for key in keys))
            else:
                found = set().union(*properties.values())
            return found if len(found) <= 16 else set()
        if node.type == "template_string":
            values = []
            for child in node.named_children:
                if child.type == "string_fragment":
                    values.append({self.text(child)})
                elif (
                    child.type == "template_substitution"
                    and len(child.named_children) == 1
                ):
                    values.append(
                        self.values(
                            child.named_children[0],
                            before=before,
                            seen=seen,
                            depth=depth + 1,
                        )
                    )
                else:
                    return set()
            return self._product(values, lambda parts: "".join(parts))
        if node.type == "call_expression":
            arguments = node.child_by_field_name("arguments")
            args = list(arguments.named_children) if arguments else []
            if self._cwd(node) and not args:
                return {self.project_root}
            helper = self._path_helper(node.child_by_field_name("function"))
            if helper and helper[0] == "path" and helper[1] in {"join", "resolve"}:
                values = [
                    self.values(arg, before=before, seen=seen, depth=depth + 1)
                    for arg in args
                ]
                return self._product(
                    values,
                    lambda parts: path_call(
                        self.project_root, f"path.{helper[1]}", parts
                    ),
                )
        return set()

    @staticmethod
    def _product(values, combine):
        count = 1
        for value in values:
            count *= len(value)
            if count > 64 or not count:
                return set()
        found = set()
        for parts in itertools.product(*values):
            result = combine(parts)
            if not isinstance(result, str) or len(result) >= 4096:
                return set()
            found.add(result)
        return found

    def owner(self, node):
        current = node.parent
        owner = None
        while current is not None and current != self.root:
            if current.type in {
                "public_field_definition",
                "field_definition",
            } and not any(child.type == "static" for child in current.children):
                return False  # instance fields run only after construction
            if current.type in _FUNCTIONS:
                if owner is not None or current.type != "function_declaration":
                    return False
                owner = self.text(current.child_by_field_name("name"))
            if current.type == "if_statement":
                condition = _unwrap(current.child_by_field_name("condition"))
                consequence = current.child_by_field_name("consequence")
                alternative = current.child_by_field_name("alternative")
                in_consequence = (
                    consequence is not None
                    and consequence.start_byte <= node.start_byte < consequence.end_byte
                )
                in_alternative = (
                    alternative is not None
                    and alternative.start_byte <= node.start_byte < alternative.end_byte
                )
                if condition is not None and (
                    (condition.type == "false" and in_consequence)
                    or (condition.type == "true" and in_alternative)
                ):
                    return False
            if current.type in {"while_statement", "for_statement"}:
                condition = _unwrap(current.child_by_field_name("condition"))
                if condition is not None and condition.type == "false":
                    return False
            # An unconditional abrupt statement earlier in the same block
            # makes a following read unreachable; do not invent its edge.
            if current.type == "statement_block":
                for statement in current.named_children:
                    if statement.end_byte > node.start_byte:
                        break
                    if statement.type in {
                        "return_statement",
                        "throw_statement",
                        "break_statement",
                        "continue_statement",
                    }:
                        return False
            current = current.parent
        return owner

    def edges(self, targets, live_functions):
        found = set()
        for call in self.nodes:
            if call.type != "call_expression" or not self._native_read(
                call.child_by_field_name("function")
            ):
                continue
            owner = self.owner(call)
            if owner is False or (owner is not None and owner not in live_functions):
                continue
            arguments = call.child_by_field_name("arguments")
            args = list(arguments.named_children) if arguments else []
            if not args:
                continue
            # Only a read whose value participates in an expression is source
            # data consumption. A discarded read cannot consume exports.
            parent = call.parent
            if parent is not None and parent.type == "await_expression":
                parent = parent.parent
            if parent is not None and parent.type == "expression_statement":
                continue
            for pattern in self.values(args[0], before=call.start_byte):
                if (
                    not pattern.startswith(self.project_root + os.sep)
                    or pattern.count(_SEGMENT) > 1
                ):
                    continue
                if _SEGMENT in os.path.basename(pattern):
                    continue  # no filename wildcard or arbitrary suffix search
                expression = re.compile(
                    re.escape(pattern).replace(re.escape(_SEGMENT), "[^/\\\\]+")
                )
                matches = {target for target in targets if expression.fullmatch(target)}
                if len(matches) <= 256:
                    found.update(matches)
        return found


def collect_ts_source_reads(project_root, js_files, live_functions):
    """Return exact target -> consumer-file edges; caller proves file liveness.

    live_functions maps each source path to the names of source owners with
    observed references. Module-level consumers still depend on their file's
    liveness. Only scanned files inside the project can become targets.
    """
    edges = defaultdict(set)
    project_root = os.path.realpath(project_root)
    targets = {
        os.path.realpath(str(path))
        for path in js_files
        if os.path.commonpath([project_root, os.path.realpath(str(path))])
        == project_root
    }
    for filename in sorted(targets):
        source = read_text_no_symlink(
            filename, max_bytes=_MAX_REFERENCE_FILE_BYTES, encoding="utf-8"
        )
        if not source or "readFile" not in source:
            continue
        parser = _TSX_PARSER if filename.endswith((".tsx", ".jsx")) else _TS_PARSER
        if parser is None:
            continue
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
        if root.has_error:
            continue
        nodes = list(_nodes(root))
        if len(nodes) > 20_000:
            continue
        proof = _SourceReads(data, root, filename, project_root)
        for target in proof.edges(targets, live_functions.get(filename, set())):
            if target != filename:
                edges[target].add(filename)
    return dict(edges)
