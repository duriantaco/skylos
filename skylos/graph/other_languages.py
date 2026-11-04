"""Map Go, Java, Rust and PHP code into the graph.

Each language has a walker with its own table of the tree-sitter node types
that define types, functions and methods and that make calls. The table is
checked against the installed grammar when it is loaded, and a language whose
grammar lacks the core types is reported as not ready. The walker records
definitions, imports, field and local variable types and the calls each
function makes, with their argument counts.

Calls are linked by name afterwards. Each call climbs a ladder of scopes (the
enclosing type, the file, the package or module, the imports) and stops at the
first scope that has a definition with that name and a matching number of
arguments. One candidate is linked; several are left alone as ambiguous; calls
into packages outside the repository are never linked. These links are kept
apart from the resolved Python and TypeScript links.
"""

from __future__ import annotations

import collections
import hashlib
import importlib
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath

from skylos.changemap.risk import is_test_file

LANGUAGE_NAMES = {"go": "Go", "java": "Java", "rust": "Rust", "php": "PHP"}
EXTENSIONS = {".go": "go", ".java": "java", ".rs": "rust", ".php": "php"}
GRAMMARS = {
    "go": ("tree_sitter_go", "language"),
    "java": ("tree_sitter_java", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "php": ("tree_sitter_php", "language_php"),
}
DOC_LIMIT = 300
SIGNATURE_LIMIT = 200
ANY = -1
INHERIT_DEPTH = 6
ALIAS_DEPTH = 4
CHOICES = 6
GO_MOD_LIMIT = 200_000
COMMENTS = frozenset({"comment", "line_comment", "block_comment"})
ROOT = "."
UNKNOWN = ["unknown"]
NONE = ["none"]
SKIP = object()
_STOP = object()
_UNKNOWN = object()


def other_language(path: str) -> str | None:
    return EXTENSIONS.get(PurePosixPath(path).suffix.lower())


def other_module_name(path: str) -> str:
    pure = PurePosixPath(path)
    stem = pure.name
    if "." in stem:
        base, _, extension = stem.rpartition(".")
        stem = f"{base}_{extension}"
    return ".".join(list(pure.parts[:-1]) + [stem])


def _ref_name(ref: list) -> str:
    if ref[0] == "path":
        return ref[1][-1]
    if ref[0] == "pkg":
        return ref[2]
    return ref[1]


def _remember(table: dict, name: str, ref: list) -> None:
    existing = table.get(name)
    if existing is None or existing == ref:
        table[name] = ref
        return
    options = [existing]
    if existing[0] == "any":
        options = list(existing[1])
    if ref not in options and len(options) < CHOICES:
        options.append(ref)
    table[name] = ["any", options]


def _strip_generics(text: str) -> str:
    kept = []
    depth = 0
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">" and depth:
            depth -= 1
        elif not depth:
            kept.append(char)
    return "".join(kept)


def _rust_segments(text: str) -> list[str]:
    cleaned = _strip_generics(text)
    return [part.strip() for part in cleaned.split("::") if part.strip() and part.strip() != "*"]


def _go_default_alias(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return path
    last = parts[-1]
    if re.fullmatch(r"v\d+", last) and len(parts) > 1:
        last = parts[-2]
    last = re.sub(r"\.v\d+$", "", last)
    if last.startswith("go-"):
        last = last[3:]
    if last.endswith("-go"):
        last = last[:-3]
    return last.replace("-", "").replace(".", "")


def _clean_doc(texts: list[str]) -> str:
    lines = []
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            for marker in ("/**", "*/", "///", "//!", "//", "/*"):
                if line.startswith(marker):
                    line = line[len(marker):]
                if line.endswith(marker) and marker in ("*/",):
                    line = line[: -len(marker)]
            line = line.strip()
            if line.startswith("*"):
                line = line[1:].strip()
            lines.append(line)
    paragraph = []
    for line in lines:
        if not line:
            if paragraph:
                break
            continue
        paragraph.append(line)
    found = " ".join(" ".join(paragraph).split())
    if len(found) > DOC_LIMIT:
        return found[: DOC_LIMIT - 3] + "..."
    return found


class _Ctx:
    __slots__ = ("scope", "mods", "type_qual", "member_of", "owner", "locals", "self_name", "test", "namespace", "anonymous")

    def __init__(self, **values):
        for name in self.__slots__:
            setattr(self, name, values.get(name))

    def but(self, **changes) -> _Ctx:
        values = {name: getattr(self, name) for name in self.__slots__}
        values.update(changes)
        return _Ctx(**values)


class _Walker:
    language = ""
    handlers: dict[str, str] = {}
    core: tuple[str, ...] = ()
    fields_used: tuple[str, ...] = ()
    spread: frozenset = frozenset()
    doc_markers: tuple[str, ...] = ("/**",)
    between_doc: frozenset = frozenset()

    def __init__(self, path: str, module: str, source: str, kinds: frozenset):
        self.path = path
        self.module = module
        self.data = source.encode("utf-8", "replace")
        self.symbols: list[dict] = []
        self.refs: list[list] = []
        self.fields: dict[str, dict] = {}
        self.imports: list = []
        self.counts: collections.Counter = collections.Counter()
        self.test_file = self.is_test_path(path)
        self.dispatch = {kind: getattr(self, name) for kind, name in self.handlers.items() if kind in kinds}
        self.setup()

    def setup(self) -> None:
        return None

    def is_test_path(self, path: str) -> bool:
        return is_test_file(path)

    def space(self, ctx: _Ctx) -> str:
        return ""

    def extra_links(self) -> dict:
        return {}

    def text(self, node) -> str:
        return self.data[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def top(self) -> _Ctx:
        return _Ctx(scope=(), mods=(), test=False, anonymous=False)

    def walk(self, root) -> None:
        stack = [(root, self.top())]
        while stack:
            node, ctx = stack.pop()
            handler = self.dispatch.get(node.type)
            inner = ctx
            if handler is not None:
                result = handler(node, ctx)
                if result is SKIP:
                    continue
                if result is not None:
                    inner = result
            for child in reversed(node.named_children):
                stack.append((child, inner))

    def signature(self, node) -> str:
        body = node.child_by_field_name("body")
        end = node.end_byte
        if body is not None:
            end = body.start_byte
        text = self.data[node.start_byte:end].decode("utf-8", "replace")
        if body is None and "{" in text:
            text = text.split("{", 1)[0]
        text = " ".join(text.split())
        if len(text) > SIGNATURE_LIMIT:
            return text[: SIGNATURE_LIMIT - 3] + "..."
        return text

    def is_doc(self, text: str) -> bool:
        return text.startswith(self.doc_markers)

    def doc(self, node) -> str:
        texts: list[str] = []
        current = node.prev_named_sibling
        row = node.start_point[0]
        while current is not None and (current.type in COMMENTS or current.type in self.between_doc):
            if current.end_point[0] < row - 1:
                break
            if current.type in COMMENTS:
                text = self.text(current)
                if not self.is_doc(text):
                    break
                texts.insert(0, text)
            row = current.start_point[0]
            current = current.prev_named_sibling
        return _clean_doc(texts)

    def add(self, node, kind: str, qual_parts: list[str], ctx: _Ctx, *, name: str, args=(0, ANY), decorators=(), test: bool = False, owner_type: str | None = None, doc_node=None, **extra) -> str:
        qual = ".".join(qual_parts)
        self.counts[qual] += 1
        if self.counts[qual] > 1:
            qual = f"{qual}~{self.counts[qual]}"
        full_name = f"{self.module}.{qual}"
        if doc_node is None:
            doc_node = node
        normalised = " ".join(self.text(node).split())
        symbol = {
            "qual": qual,
            "full_name": full_name,
            "kind": kind,
            "start": node.start_point[0] + 1,
            "end": node.end_point[0] + 1,
            "signature": self.signature(node),
            "decorators": list(decorators),
            "doc": self.doc(doc_node),
            "bases": [],
            "attributes": [],
            "code_hash": hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16],
            "is_test": bool(self.test_file or test or ctx.test),
            "simple": name,
            "owner_type": owner_type,
            "mods": list(ctx.mods or ()),
            "space": self.space(ctx),
            "args": [args[0], args[1]],
        }
        symbol.update(extra)
        self.symbols.append(symbol)
        return full_name

    def argc(self, node) -> int:
        if node is None:
            return ANY
        count = 0
        for child in node.named_children:
            if child.type in COMMENTS:
                continue
            if child.type in self.spread or any(inner.type in self.spread for inner in child.named_children):
                return ANY
            count += 1
        return count

    def record(self) -> dict:
        links = {"imports": self.imports, "fields": self.fields, "refs": self.refs}
        links.update(self.extra_links())
        return links


class _GoWalker(_Walker):
    language = "go"
    handlers = {
        "package_clause": "on_package",
        "import_declaration": "on_import",
        "type_spec": "on_type",
        "function_declaration": "on_function",
        "method_declaration": "on_method",
        "func_literal": "on_func_literal",
        "call_expression": "on_call",
        "composite_literal": "on_literal",
        "short_var_declaration": "on_short_var",
        "var_spec": "on_var",
        "range_clause": "on_range",
    }
    core = ("source_file", "function_declaration", "method_declaration", "call_expression", "selector_expression", "identifier", "type_identifier")
    fields_used = ("name", "type", "function", "operand", "field", "arguments", "receiver", "parameters", "path", "left", "right")
    spread = frozenset({"variadic_argument"})
    doc_markers = ("//", "/*")

    def setup(self) -> None:
        self.package_name = ""
        self.aliases: dict[str, str] = {}
        self.package_vars: dict[str, list] = {}

    def is_test_path(self, path: str) -> bool:
        return is_test_file(path) or path.endswith("_test.go")

    def extra_links(self) -> dict:
        return {"package": self.package_name, "aliases": self.aliases, "package_vars": self.package_vars}

    def on_package(self, node, ctx):
        for child in node.named_children:
            if child.type == "package_identifier":
                self.package_name = self.text(child)
        return SKIP

    def on_import(self, node, ctx):
        specs = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == "import_spec":
                specs.append(current)
                continue
            stack.extend(current.named_children)
        for spec in sorted(specs, key=lambda item: item.start_byte):
            path_node = spec.child_by_field_name("path")
            if path_node is None:
                continue
            path = self.text(path_node).strip("\"`")
            name_node = spec.child_by_field_name("name")
            alias = None
            if name_node is not None:
                alias = self.text(name_node)
            self.imports.append({"alias": alias, "path": path})
            if alias in ("_", "."):
                continue
            self.aliases[alias or _go_default_alias(path)] = path
        return SKIP

    def type_ref(self, node) -> list:
        while node is not None and node.type in ("pointer_type", "parenthesized_type"):
            children = node.named_children
            if not children:
                return NONE
            node = children[0]
        if node is None:
            return NONE
        if node.type == "generic_type":
            node = node.child_by_field_name("type")
            if node is None:
                return NONE
        if node.type == "type_identifier":
            return ["name", self.text(node)]
        if node.type == "qualified_type":
            package = node.child_by_field_name("package")
            name = node.child_by_field_name("name")
            if package is not None and name is not None:
                return ["pkg", self.text(package), self.text(name)]
        if node.type == "function_type":
            return ["func", self.result_of(node.child_by_field_name("result"))]
        if node.type in ("slice_type", "array_type"):
            return ["elem", self.type_ref(node.child_by_field_name("element"))]
        if node.type == "map_type":
            return ["elem", self.type_ref(node.child_by_field_name("value"))]
        return NONE

    def on_type(self, node, ctx):
        name_node = node.child_by_field_name("name")
        shape = node.child_by_field_name("type")
        if name_node is None or shape is None or shape.type not in ("struct_type", "interface_type"):
            return SKIP
        name = self.text(name_node)
        anchor = node
        if node.parent is not None and node.parent.type == "type_declaration" and len(node.parent.named_children) == 1:
            anchor = node.parent
        type_id = self.add(node, "class", [name], ctx, name=name, doc_node=anchor)
        table: dict[str, list] = {}
        for listing in shape.named_children:
            if listing.type != "field_declaration_list":
                continue
            for declaration in listing.named_children:
                if declaration.type != "field_declaration":
                    continue
                ref = self.type_ref(declaration.child_by_field_name("type"))
                names = declaration.children_by_field_name("name")
                for name_child in names:
                    table[self.text(name_child)] = ref
                if not names and ref[0] in ("name", "pkg"):
                    table[_ref_name(ref)] = ref
                    self.refs.append([type_id, "inherit", _ref_name(ref), ["type", ref], ANY])
        self.fields[type_id] = table
        return SKIP

    def params(self, node, table: dict) -> tuple[int, int]:
        if node is None:
            return (0, 0)
        count = 0
        variadic = False
        for child in node.named_children:
            if child.type == "parameter_declaration":
                names = child.children_by_field_name("name")
                ref = self.type_ref(child.child_by_field_name("type"))
                for name_child in names:
                    _remember(table, self.text(name_child), ref)
                count += max(1, len(names))
            elif child.type == "variadic_parameter_declaration":
                variadic = True
                name_child = child.child_by_field_name("name")
                if name_child is not None:
                    _remember(table, self.text(name_child), NONE)
        if variadic:
            return (count, ANY)
        return (count, count)

    def result_of(self, result) -> list:
        found = self.results_of(result)
        if found:
            return found[0]
        return NONE

    def results_of(self, result) -> list[list]:
        if result is None:
            return []
        if result.type != "parameter_list":
            return [self.type_ref(result)]
        found = []
        for child in result.named_children:
            if child.type == "parameter_declaration":
                ref = self.type_ref(child.child_by_field_name("type"))
                found.extend([ref] * max(1, len(child.children_by_field_name("name"))))
        return found

    def on_function(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        table: dict[str, list] = {}
        args = self.params(node.child_by_field_name("parameters"), table)
        owner = self.add(node, "function", [name], ctx, name=name, args=args, results=self.results_of(node.child_by_field_name("result")))
        return ctx.but(owner=owner, locals=table, self_name=None, type_qual=None)

    def on_method(self, node, ctx):
        name_node = node.child_by_field_name("name")
        receiver = node.child_by_field_name("receiver")
        if name_node is None or receiver is None:
            return SKIP
        receiver_type = None
        receiver_name = None
        for child in receiver.named_children:
            if child.type != "parameter_declaration":
                continue
            ref = self.type_ref(child.child_by_field_name("type"))
            if ref[0] == "name":
                receiver_type = ref[1]
            names = child.children_by_field_name("name")
            if names:
                receiver_name = self.text(names[0])
        if receiver_type is None:
            return SKIP
        name = self.text(name_node)
        table: dict[str, list] = {}
        args = self.params(node.child_by_field_name("parameters"), table)
        if receiver_name in ("_", ""):
            receiver_name = None
        if receiver_name:
            table[receiver_name] = ["name", receiver_type]
        owner = self.add(node, "method", [receiver_type, name], ctx, name=name, args=args, owner_type=receiver_type, results=self.results_of(node.child_by_field_name("result")))
        return ctx.but(owner=owner, locals=table, self_name=receiver_name, type_qual=receiver_type)

    def on_func_literal(self, node, ctx):
        if ctx.locals is not None:
            self.params(node.child_by_field_name("parameters"), ctx.locals)
        return None

    def receiver(self, operand, ctx: _Ctx) -> list:
        local = ctx.locals or {}
        if operand is not None and operand.type == "identifier":
            name = self.text(operand)
            if ctx.self_name and name == ctx.self_name:
                return ["self"]
            if name in local:
                return ["var", local[name]]
            if name in self.aliases:
                return ["import", self.aliases[name]]
            return ["ident", name]
        if operand is not None and operand.type == "selector_expression":
            base = operand.child_by_field_name("operand")
            field = operand.child_by_field_name("field")
            if base is not None and field is not None and base.type == "identifier":
                base_name = self.text(base)
                if ctx.self_name and base_name == ctx.self_name:
                    return ["field", self.text(field)]
                known = local.get(base_name)
                if known is not None and known != UNKNOWN:
                    return ["member", known, self.text(field)]
                if known is None and base_name in self.aliases:
                    return ["pkgvar", self.aliases[base_name]]
        if operand is not None and operand.type in ("call_expression", "type_assertion_expression", "parenthesized_expression"):
            return ["var", self.value_type(operand, ctx)]
        return ["var", UNKNOWN]

    def on_call(self, node, ctx):
        if ctx.owner is None:
            return None
        function = node.child_by_field_name("function")
        while function is not None and function.type == "parenthesized_expression" and function.named_children:
            function = function.named_children[0]
        if function is None:
            return None
        argc = self.argc(node.child_by_field_name("arguments"))
        if function.type == "identifier":
            name = self.text(function)
            if name not in (ctx.locals or {}):
                self.refs.append([ctx.owner, "call", name, ["bare"], argc])
        elif function.type == "selector_expression":
            field = function.child_by_field_name("field")
            if field is not None:
                qualifier = self.receiver(function.child_by_field_name("operand"), ctx)
                self.refs.append([ctx.owner, "call", self.text(field), qualifier, argc])
        return None

    def on_literal(self, node, ctx):
        if ctx.owner is None:
            return None
        ref = self.type_ref(node.child_by_field_name("type"))
        if ref[0] in ("name", "pkg"):
            self.refs.append([ctx.owner, "new", _ref_name(ref), ["type", ref], ANY])
        return None

    def value_type(self, node, ctx: _Ctx) -> list:
        while node.type == "parenthesized_expression" and node.named_children:
            node = node.named_children[0]
        if node.type == "type_assertion_expression":
            ref = self.type_ref(node.child_by_field_name("type"))
            if ref[0] in ("name", "pkg"):
                return ref
            return NONE
        if node.type == "unary_expression":
            operand = node.child_by_field_name("operand")
            if operand is None:
                return UNKNOWN
            node = operand
        if node.type == "composite_literal":
            ref = self.type_ref(node.child_by_field_name("type"))
            if ref[0] in ("name", "pkg"):
                return ref
            return NONE
        if node.type != "call_expression":
            return UNKNOWN
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None:
            return UNKNOWN
        if function.type == "identifier":
            name = self.text(function)
            if name == "new" and arguments is not None and arguments.named_children:
                first = arguments.named_children[0]
                if first.type == "identifier":
                    return ["name", self.text(first)]
                return self.type_ref(first)
            local = (ctx.locals or {}).get(name)
            if local is not None and local[0] == "func":
                return local[1]
            if local is not None:
                return UNKNOWN
            return ["call", None, name]
        if function.type == "selector_expression":
            operand = function.child_by_field_name("operand")
            field = function.child_by_field_name("field")
            if operand is None or field is None:
                return UNKNOWN
            qualifier = self.receiver(operand, ctx)
            if qualifier[0] == "import":
                return ["call", qualifier[1], self.text(field)]
            base = None
            if qualifier[0] == "self":
                base = ["self"]
            elif qualifier[0] == "var":
                base = qualifier[1]
            elif qualifier[0] == "field":
                base = ["field_of", ["self"], qualifier[1]]
            elif qualifier[0] == "member":
                base = ["field_of", qualifier[1], qualifier[2]]
            if base is not None:
                return ["calls_on", base, self.text(field)]
        return UNKNOWN

    def on_short_var(self, node, ctx):
        if ctx.locals is None:
            return None
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None:
            return None
        targets = left.named_children
        values = []
        if right is not None:
            values = right.named_children
        spread = None
        if len(values) == 1 and len(targets) > 1:
            spread = self.value_type(values[0], ctx)
        for position, target in enumerate(targets):
            if target.type != "identifier":
                continue
            ref = UNKNOWN
            if len(values) == len(targets):
                ref = self.value_type(values[position], ctx)
            elif spread is not None and spread[0] in ("call", "calls_on"):
                ref = ["nth", spread, position]
            _remember(ctx.locals, self.text(target), ref)
        return None

    def on_var(self, node, ctx):
        names = [self.text(child) for child in node.children_by_field_name("name")]
        type_node = node.child_by_field_name("type")
        value = node.child_by_field_name("value")
        values = []
        if value is not None:
            values = value.named_children
        for position, name in enumerate(names):
            ref = UNKNOWN
            if type_node is not None:
                ref = self.type_ref(type_node)
            elif len(values) == len(names):
                ref = self.value_type(values[position], ctx)
            if ctx.owner is not None and ctx.locals is not None:
                _remember(ctx.locals, name, ref)
            elif ctx.owner is None:
                self.package_vars[name] = ref
        return None

    def on_range(self, node, ctx):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or ctx.locals is None:
            return None
        element = UNKNOWN
        if right is not None and right.type == "identifier":
            known = ctx.locals.get(self.text(right))
            if known is not None and known[0] == "elem":
                element = known[1]
        for position, child in enumerate(left.named_children):
            if child.type != "identifier":
                continue
            ref = UNKNOWN
            if position == 1:
                ref = element
            _remember(ctx.locals, self.text(child), ref)
        return None


class _JavaWalker(_Walker):
    language = "java"
    handlers = {
        "package_declaration": "on_package",
        "import_declaration": "on_import",
        "class_declaration": "on_class",
        "interface_declaration": "on_class",
        "enum_declaration": "on_class",
        "record_declaration": "on_class",
        "annotation_type_declaration": "on_class",
        "method_declaration": "on_method",
        "constructor_declaration": "on_constructor",
        "compact_constructor_declaration": "on_constructor",
        "field_declaration": "on_field",
        "local_variable_declaration": "on_local",
        "enhanced_for_statement": "on_for",
        "lambda_expression": "on_lambda",
        "method_invocation": "on_call",
        "object_creation_expression": "on_new",
    }
    core = ("program", "class_declaration", "method_declaration", "method_invocation", "object_creation_expression", "identifier", "type_identifier")
    fields_used = ("name", "body", "object", "arguments", "type", "parameters", "declarator", "superclass", "interfaces")

    def setup(self) -> None:
        self.package = ""

    def is_test_path(self, path: str) -> bool:
        return is_test_file(path) or path.endswith(("Test.java", "Tests.java"))

    def space(self, ctx: _Ctx) -> str:
        return self.package

    def on_package(self, node, ctx):
        for child in node.named_children:
            if child.type in ("scoped_identifier", "identifier"):
                self.package = "".join(self.text(child).split())
        return SKIP

    def on_import(self, node, ctx):
        static = any(child.type == "static" for child in node.children)
        every = any(child.type == "asterisk" for child in node.children)
        for child in node.named_children:
            if child.type in ("scoped_identifier", "identifier"):
                self.imports.append({"static": static, "all": every, "path": "".join(self.text(child).split())})
        return SKIP

    def type_ref(self, node) -> list:
        if node is None:
            return NONE
        if node.type == "generic_type":
            children = [child for child in node.named_children if child.type in ("type_identifier", "scoped_type_identifier")]
            if not children:
                return NONE
            node = children[0]
        if node.type == "type_identifier":
            text = self.text(node)
            if text == "var":
                return UNKNOWN
            return ["name", text]
        if node.type == "scoped_type_identifier":
            return ["path", [part for part in "".join(_strip_generics(self.text(node)).split()).split(".") if part]]
        return NONE

    def annotations(self, node) -> list[str]:
        found = []
        for child in node.named_children:
            if child.type != "modifiers":
                continue
            for item in child.named_children:
                if item.type in ("marker_annotation", "annotation"):
                    name = item.child_by_field_name("name")
                    if name is not None:
                        found.append(self.text(name).rsplit(".", 1)[-1])
        return found

    def bases(self, node) -> list[list]:
        found = []
        for child in node.named_children:
            if child.type not in ("superclass", "super_interfaces", "extends_interfaces"):
                continue
            pending = list(child.named_children)
            while pending:
                item = pending.pop(0)
                if item.type == "type_list":
                    pending = list(item.named_children) + pending
                    continue
                ref = self.type_ref(item)
                if ref[0] in ("name", "path"):
                    found.append(ref)
        return found

    def params(self, node, table: dict) -> tuple[int, int]:
        if node is None:
            return (0, 0)
        count = 0
        variadic = False
        for child in node.named_children:
            if child.type == "formal_parameter":
                count += 1
                name = child.child_by_field_name("name")
                if name is not None:
                    _remember(table, self.text(name), self.type_ref(child.child_by_field_name("type")))
            elif child.type == "spread_parameter":
                variadic = True
                for inner in child.named_children:
                    if inner.type == "variable_declarator":
                        name = inner.child_by_field_name("name")
                        if name is not None:
                            _remember(table, self.text(name), NONE)
        if variadic:
            return (count, ANY)
        return (count, count)

    def on_class(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        scope = list(ctx.scope or ()) + [name]
        type_id = self.add(node, "class", scope, ctx, name=name, decorators=self.annotations(node))
        table = self.fields.setdefault(type_id, {})
        for base in self.bases(node):
            self.refs.append([type_id, "inherit", _ref_name(base), ["type", base], ANY])
        if node.type == "record_declaration":
            parameters = node.child_by_field_name("parameters")
            if parameters is not None:
                for child in parameters.named_children:
                    field = child.child_by_field_name("name")
                    if child.type == "formal_parameter" and field is not None:
                        table[self.text(field)] = self.type_ref(child.child_by_field_name("type"))
        return ctx.but(scope=tuple(scope), type_qual=".".join(scope), owner=type_id, locals={}, anonymous=False, member_of=type_id)

    def method_like(self, node, ctx: _Ctx, name: str):
        table: dict[str, list] = {}
        args = self.params(node.child_by_field_name("parameters"), table)
        if ctx.anonymous or ctx.type_qual is None:
            if ctx.locals is not None:
                ctx.locals.update(table)
            return None
        decorators = self.annotations(node)
        test = any(item == "Test" or item.endswith("Test") for item in decorators)
        owner = self.add(node, "method", list(ctx.scope) + [name], ctx, name=name, args=args, decorators=decorators, test=test, owner_type=ctx.type_qual)
        return ctx.but(owner=owner, locals=table)

    def on_method(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None or node.child_by_field_name("body") is None:
            return SKIP
        return self.method_like(node, ctx, self.text(name_node))

    def on_constructor(self, node, ctx):
        if not ctx.scope:
            return SKIP
        return self.method_like(node, ctx, ctx.scope[-1])

    def on_field(self, node, ctx):
        if ctx.member_of is None or ctx.anonymous:
            return None
        ref = self.type_ref(node.child_by_field_name("type"))
        table = self.fields.setdefault(ctx.member_of, {})
        for declarator in node.children_by_field_name("declarator"):
            name = declarator.child_by_field_name("name")
            if name is not None:
                table[self.text(name)] = ref
        return None

    def on_local(self, node, ctx):
        if ctx.locals is None:
            return None
        ref = self.type_ref(node.child_by_field_name("type"))
        for declarator in node.children_by_field_name("declarator"):
            name = declarator.child_by_field_name("name")
            if name is None:
                continue
            found = ref
            value = declarator.child_by_field_name("value")
            if ref == UNKNOWN and value is not None and value.type == "object_creation_expression":
                found = self.type_ref(value.child_by_field_name("type"))
            _remember(ctx.locals, self.text(name), found)
        return None

    def on_for(self, node, ctx):
        name = node.child_by_field_name("name")
        if ctx.locals is not None and name is not None:
            _remember(ctx.locals, self.text(name), self.type_ref(node.child_by_field_name("type")))
        return None

    def on_lambda(self, node, ctx):
        parameters = node.child_by_field_name("parameters")
        if ctx.locals is None or parameters is None:
            return None
        if parameters.type == "identifier":
            _remember(ctx.locals, self.text(parameters), UNKNOWN)
            return None
        for child in parameters.named_children:
            if child.type == "identifier":
                _remember(ctx.locals, self.text(child), UNKNOWN)
        self.params(parameters, ctx.locals)
        return None

    def receiver(self, target, ctx: _Ctx) -> list:
        if target.type == "this":
            return ["self"]
        if target.type == "super":
            return ["super"]
        if target.type == "identifier":
            name = self.text(target)
            if ctx.locals is not None and name in ctx.locals:
                return ["var", ctx.locals[name]]
            return ["ident", name]
        if target.type == "field_access":
            base = target.child_by_field_name("object")
            field = target.child_by_field_name("field")
            if base is not None and field is not None and base.type == "this":
                return ["field", self.text(field)]
            text = "".join(self.text(target).split())
            if re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+", text):
                return ["path", text.split(".")]
        return ["var", UNKNOWN]

    def on_call(self, node, ctx):
        name = node.child_by_field_name("name")
        if ctx.owner is None or name is None:
            return None
        target = node.child_by_field_name("object")
        qualifier = ["bare"]
        if target is not None:
            qualifier = self.receiver(target, ctx)
        self.refs.append([ctx.owner, "call", self.text(name), qualifier, self.argc(node.child_by_field_name("arguments"))])
        return None

    def on_new(self, node, ctx):
        ref = self.type_ref(node.child_by_field_name("type"))
        if ctx.owner is not None and ref[0] in ("name", "path"):
            self.refs.append([ctx.owner, "new", _ref_name(ref), ["type", ref], ANY])
        if any(child.type == "class_body" for child in node.named_children):
            return ctx.but(anonymous=True)
        return None


class _RustWalker(_Walker):
    language = "rust"
    handlers = {
        "mod_item": "on_mod",
        "struct_item": "on_struct",
        "enum_item": "on_struct",
        "union_item": "on_struct",
        "trait_item": "on_trait",
        "impl_item": "on_impl",
        "function_item": "on_function",
        "function_signature_item": "on_skip",
        "macro_invocation": "on_skip",
        "macro_definition": "on_skip",
        "attribute_item": "on_skip",
        "use_declaration": "on_use",
        "call_expression": "on_call",
        "struct_expression": "on_literal",
        "let_declaration": "on_let",
        "closure_expression": "on_closure",
    }
    core = ("source_file", "function_item", "impl_item", "call_expression", "scoped_identifier", "field_expression", "identifier", "type_identifier")
    fields_used = ("name", "body", "type", "trait", "function", "arguments", "value", "field", "pattern", "parameters", "argument", "path", "alias", "list")
    doc_markers = ("///", "/**")
    between_doc = frozenset({"attribute_item"})

    def setup(self) -> None:
        self.uses: list = []
        self.globs: list = []
        self.impls: list = []

    def extra_links(self) -> dict:
        return {"uses": self.uses, "globs": self.globs, "impls": self.impls}

    def is_doc(self, text: str) -> bool:
        return text.startswith(self.doc_markers) and not text.startswith("////")

    def on_skip(self, node, ctx):
        return SKIP

    def attributes_before(self, node) -> list[str]:
        found = []
        current = node.prev_named_sibling
        while current is not None and current.type in ("attribute_item", "line_comment", "block_comment"):
            if current.type == "attribute_item" and current.named_children:
                found.insert(0, "".join(self.text(current.named_children[0]).split()))
            current = current.prev_named_sibling
        return found

    def type_ref(self, node) -> list:
        while node is not None and node.type in ("reference_type", "pointer_type", "generic_type", "dynamic_type", "abstract_type"):
            inner = node.child_by_field_name("type")
            if inner is None and node.type in ("dynamic_type", "abstract_type"):
                inner = node.child_by_field_name("trait")
            if inner is None:
                return NONE
            node = inner
        if node is None:
            return NONE
        if node.type == "type_identifier":
            text = self.text(node)
            if text == "Self":
                return ["self"]
            return ["name", text]
        if node.type == "scoped_type_identifier":
            segments = _rust_segments(self.text(node))
            if segments:
                return ["path", segments]
        return NONE

    def on_mod(self, node, ctx):
        name = node.child_by_field_name("name")
        if name is None or node.child_by_field_name("body") is None:
            return SKIP
        attributes = self.attributes_before(node)
        test = bool(ctx.test) or any(re.fullmatch(r"cfg\(.*\btest\b.*\)", item) for item in attributes)
        text = self.text(name)
        return ctx.but(scope=tuple(ctx.scope) + (text,), mods=tuple(ctx.mods) + (text,), test=test, type_qual=None, member_of=None, owner=None, locals=None)

    def on_struct(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        type_id = self.add(node, "class", list(ctx.scope) + [name], ctx, name=name, decorators=self.attributes_before(node))
        table: dict[str, list] = {}
        body = node.child_by_field_name("body")
        if body is not None and body.type == "field_declaration_list":
            for declaration in body.named_children:
                field = declaration.child_by_field_name("name")
                if declaration.type == "field_declaration" and field is not None:
                    table[self.text(field)] = self.type_ref(declaration.child_by_field_name("type"))
        self.fields[type_id] = table
        return SKIP

    def on_trait(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        self.add(node, "class", list(ctx.scope) + [name], ctx, name=name, decorators=self.attributes_before(node))
        return ctx.but(scope=tuple(ctx.scope) + (name,), type_qual=name, member_of=name, owner=None, locals=None)

    def on_impl(self, node, ctx):
        ref = self.type_ref(node.child_by_field_name("type"))
        if ref[0] not in ("name", "path"):
            return SKIP
        target = _ref_name(ref)
        trait = node.child_by_field_name("trait")
        if trait is not None:
            trait_ref = self.type_ref(trait)
            if trait_ref[0] in ("name", "path"):
                self.impls.append([list(ctx.mods), ref, trait_ref])
        return ctx.but(scope=tuple(ctx.scope) + (target,), type_qual=target, member_of=target, owner=None, locals=None)

    def params(self, node, table: dict) -> tuple[tuple[int, int], bool]:
        if node is None:
            return (0, 0), False
        count = 0
        has_self = False
        variadic = False
        for child in node.named_children:
            if child.type == "self_parameter":
                has_self = True
            elif child.type == "parameter":
                count += 1
                pattern = child.child_by_field_name("pattern")
                if pattern is not None and pattern.type == "identifier":
                    _remember(table, self.text(pattern), self.type_ref(child.child_by_field_name("type")))
            elif child.type == "variadic_parameter":
                variadic = True
        if variadic:
            return (count, ANY), has_self
        return (count, count), has_self

    def on_function(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        attributes = self.attributes_before(node)
        test = bool(ctx.test) or any(item == "test" or item.endswith("::test") for item in attributes)
        table: dict[str, list] = {}
        args, has_self = self.params(node.child_by_field_name("parameters"), table)
        kind = "function"
        owner_type = None
        if ctx.member_of is not None:
            kind = "method"
            owner_type = ctx.member_of
        qual = list(ctx.scope) + [name]
        owner = self.add(node, kind, qual, ctx, name=name, args=args, decorators=attributes, test=test, owner_type=owner_type, self_param=has_self)
        return ctx.but(owner=owner, locals=table, member_of=None, test=test, scope=tuple(qual))

    def receiver(self, value, ctx: _Ctx) -> list:
        if value is None:
            return ["var", UNKNOWN]
        if value.type == "self":
            return ["self"]
        if value.type == "identifier":
            name = self.text(value)
            if ctx.locals is not None and name in ctx.locals:
                return ["var", ctx.locals[name]]
            return ["var", UNKNOWN]
        if value.type == "field_expression":
            inner = value.child_by_field_name("value")
            field = value.child_by_field_name("field")
            if inner is not None and inner.type == "self" and field is not None and field.type == "field_identifier":
                return ["field", self.text(field)]
        return ["var", UNKNOWN]

    def on_call(self, node, ctx):
        if ctx.owner is None:
            return None
        function = node.child_by_field_name("function")
        if function is not None and function.type == "generic_function":
            function = function.child_by_field_name("function")
        if function is None:
            return None
        argc = self.argc(node.child_by_field_name("arguments"))
        if function.type == "identifier":
            name = self.text(function)
            if ctx.locals is None or name not in ctx.locals:
                self.refs.append([ctx.owner, "call", name, ["bare"], argc])
        elif function.type == "scoped_identifier":
            segments = _rust_segments(self.text(function))
            if len(segments) >= 2:
                qualifier = ["path", segments[:-1]]
                if segments[:-1] == ["Self"]:
                    qualifier = ["self"]
                self.refs.append([ctx.owner, "call", segments[-1], qualifier, argc])
        elif function.type == "field_expression":
            field = function.child_by_field_name("field")
            if field is not None and field.type == "field_identifier":
                qualifier = self.receiver(function.child_by_field_name("value"), ctx)
                self.refs.append([ctx.owner, "call", self.text(field), qualifier, argc])
        return None

    def on_literal(self, node, ctx):
        if ctx.owner is None:
            return None
        ref = self.type_ref(node.child_by_field_name("name"))
        if ref[0] in ("name", "path", "self"):
            name = ctx.type_qual or ""
            if ref[0] != "self":
                name = _ref_name(ref)
            if name:
                self.refs.append([ctx.owner, "new", name, ["type", ref], ANY])
        return None

    def value_type(self, node, ctx: _Ctx) -> list:
        while node.type == "reference_expression":
            inner = node.child_by_field_name("value")
            if inner is None:
                return UNKNOWN
            node = inner
        if node.type == "struct_expression":
            return self.type_ref(node.child_by_field_name("name"))
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "scoped_identifier":
                segments = _rust_segments(self.text(function))
                if len(segments) >= 2 and segments[-2][:1].isupper():
                    if segments[-2] == "Self":
                        return ["self"]
                    if len(segments) == 2:
                        return ["name", segments[-2]]
                    return ["path", segments[:-1]]
        return UNKNOWN

    def on_let(self, node, ctx):
        pattern = node.child_by_field_name("pattern")
        if ctx.locals is None or pattern is None:
            return None
        if pattern.type == "mut_pattern" and pattern.named_children:
            pattern = pattern.named_children[0]
        if pattern.type != "identifier":
            return None
        type_node = node.child_by_field_name("type")
        value = node.child_by_field_name("value")
        ref = UNKNOWN
        if type_node is not None:
            ref = self.type_ref(type_node)
        elif value is not None:
            ref = self.value_type(value, ctx)
        _remember(ctx.locals, self.text(pattern), ref)
        return None

    def on_closure(self, node, ctx):
        parameters = node.child_by_field_name("parameters")
        if ctx.locals is None or parameters is None:
            return None
        for child in parameters.named_children:
            if child.type == "identifier":
                _remember(ctx.locals, self.text(child), UNKNOWN)
            elif child.type == "parameter":
                pattern = child.child_by_field_name("pattern")
                if pattern is not None and pattern.type == "identifier":
                    _remember(ctx.locals, self.text(pattern), self.type_ref(child.child_by_field_name("type")))
        return None

    def on_use(self, node, ctx):
        argument = node.child_by_field_name("argument")
        if argument is None:
            return SKIP
        mods = list(ctx.mods)
        pending = [(argument, [])]
        while pending:
            current, base = pending.pop()
            kind = current.type
            if kind == "use_as_clause":
                path = current.child_by_field_name("path")
                alias = current.child_by_field_name("alias")
                if path is not None and alias is not None:
                    self.uses.append([mods, self.text(alias), base + _rust_segments(self.text(path))])
            elif kind == "scoped_use_list":
                path = current.child_by_field_name("path")
                listing = current.child_by_field_name("list")
                inner = base
                if path is not None:
                    inner = base + _rust_segments(self.text(path))
                if listing is not None:
                    for child in listing.named_children:
                        pending.append((child, inner))
            elif kind == "use_list":
                for child in current.named_children:
                    pending.append((child, base))
            elif kind == "use_wildcard":
                self.globs.append([mods, base + _rust_segments(self.text(current))])
            elif kind in ("identifier", "scoped_identifier", "crate", "self", "super"):
                segments = base + _rust_segments(self.text(current))
                if segments and segments[-1] == "self":
                    segments = segments[:-1]
                if segments:
                    self.uses.append([mods, segments[-1], segments])
        return SKIP


class _PhpWalker(_Walker):
    language = "php"
    handlers = {
        "namespace_definition": "on_namespace",
        "namespace_use_declaration": "on_use",
        "class_declaration": "on_class",
        "interface_declaration": "on_class",
        "trait_declaration": "on_class",
        "enum_declaration": "on_class",
        "method_declaration": "on_method",
        "function_definition": "on_function",
        "property_declaration": "on_property",
        "function_call_expression": "on_function_call",
        "member_call_expression": "on_member_call",
        "nullsafe_member_call_expression": "on_member_call",
        "scoped_call_expression": "on_scoped_call",
        "object_creation_expression": "on_new",
        "assignment_expression": "on_assign",
        "anonymous_function": "on_closure",
        "arrow_function": "on_closure",
    }
    core = ("program", "class_declaration", "method_declaration", "function_definition", "member_call_expression", "function_call_expression", "name")
    fields_used = ("name", "body", "function", "object", "scope", "arguments", "parameters", "type", "left", "right", "alias")
    spread = frozenset({"variadic_unpacking"})

    def setup(self) -> None:
        self.namespace = ""

    def is_test_path(self, path: str) -> bool:
        return is_test_file(path) or path.endswith("Test.php")

    def space(self, ctx: _Ctx) -> str:
        if ctx.namespace is not None:
            return ctx.namespace
        return self.namespace

    def type_ref(self, node) -> list:
        while node is not None and node.type in ("named_type", "optional_type"):
            if not node.named_children:
                return NONE
            node = node.named_children[0]
        if node is None:
            return NONE
        if node.type == "name":
            text = self.text(node)
            if text.lower() in ("self", "static"):
                return ["self"]
            if text.lower() == "parent":
                return ["parent"]
            return ["name", text]
        if node.type == "qualified_name":
            text = "".join(self.text(node).split())
            segments = [part for part in text.split("\\") if part]
            if segments:
                return ["path", segments, text.startswith("\\")]
        return NONE

    def attributes(self, node) -> list[str]:
        found = []
        for child in node.named_children:
            if child.type != "attribute_list":
                continue
            for group in child.named_children:
                for item in group.named_children:
                    if item.type == "attribute" and item.named_children:
                        found.append(self.text(item.named_children[0]).rsplit("\\", 1)[-1])
        return found

    def on_namespace(self, node, ctx):
        name = node.child_by_field_name("name")
        text = ""
        if name is not None:
            text = "".join(self.text(name).split()).strip("\\")
        if node.child_by_field_name("body") is None:
            self.namespace = text
            return SKIP
        return ctx.but(namespace=text)

    def on_use(self, node, ctx):
        kind = "class"
        for child in node.children:
            if child.type in ("function", "const"):
                kind = child.type
        prefix = ""
        group = None
        for child in node.named_children:
            if child.type == "namespace_name":
                prefix = "".join(self.text(child).split()).strip("\\")
            elif child.type == "namespace_use_group":
                group = child
        holder = node
        if group is not None:
            holder = group
        for clause in holder.named_children:
            if not clause.type.startswith("namespace_use"):
                continue
            clause_kind = kind
            for child in clause.children:
                if child.type in ("function", "const"):
                    clause_kind = child.type
            alias_node = clause.child_by_field_name("alias")
            target = None
            for child in clause.named_children:
                if child.type in ("qualified_name", "name") and (alias_node is None or child.start_byte != alias_node.start_byte):
                    target = "".join(self.text(child).split()).strip("\\")
                    break
            if not target:
                continue
            path = target
            if prefix:
                path = f"{prefix}\\{target}"
            alias = path.rsplit("\\", 1)[-1]
            if alias_node is not None:
                alias = self.text(alias_node)
            self.imports.append({"kind": clause_kind, "alias": alias, "path": path})
        return SKIP

    def params(self, node, table: dict, owner_type: str | None = None, owner_id: str | None = None) -> tuple[int, int]:
        if node is None:
            return (0, 0)
        required = 0
        total = 0
        variadic = False
        for child in node.named_children:
            if child.type not in ("simple_parameter", "property_promotion_parameter", "variadic_parameter"):
                continue
            name = child.child_by_field_name("name")
            ref = self.type_ref(child.child_by_field_name("type"))
            if name is not None:
                _remember(table, self.text(name), ref)
            if child.type == "variadic_parameter":
                variadic = True
                continue
            total += 1
            if child.child_by_field_name("default_value") is None:
                required += 1
            if child.type == "property_promotion_parameter" and owner_id is not None and name is not None:
                self.fields.setdefault(owner_id, {})[self.text(name).lstrip("$")] = ref
        if variadic:
            return (required, ANY)
        return (required, total)

    def on_class(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        type_id = self.add(node, "class", [name], ctx, name=name, decorators=self.attributes(node))
        self.fields.setdefault(type_id, {})
        bases = []
        for child in node.named_children:
            if child.type in ("base_clause", "class_interface_clause"):
                bases.extend(child.named_children)
        body = node.child_by_field_name("body")
        if body is not None:
            for item in body.named_children:
                if item.type == "use_declaration":
                    bases.extend(item.named_children)
        for base in bases:
            ref = self.type_ref(base)
            if ref[0] in ("name", "path"):
                self.refs.append([type_id, "inherit", _ref_name(ref), ["type", ref], ANY])
        return ctx.but(type_qual=name, member_of=type_id, owner=type_id, locals={}, scope=(name,))

    def on_method(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None or node.child_by_field_name("body") is None or ctx.type_qual is None:
            return SKIP
        name = self.text(name_node)
        table: dict[str, list] = {}
        args = self.params(node.child_by_field_name("parameters"), table, ctx.type_qual, ctx.member_of)
        owner = self.add(node, "method", [ctx.type_qual, name], ctx, name=name, args=args, decorators=self.attributes(node), owner_type=ctx.type_qual)
        return ctx.but(owner=owner, locals=table)

    def on_function(self, node, ctx):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return SKIP
        name = self.text(name_node)
        table: dict[str, list] = {}
        args = self.params(node.child_by_field_name("parameters"), table)
        owner = self.add(node, "function", [name], ctx, name=name, args=args, decorators=self.attributes(node))
        return ctx.but(owner=owner, locals=table, type_qual=None, member_of=None, scope=(name,))

    def on_property(self, node, ctx):
        if ctx.member_of is None:
            return SKIP
        ref = self.type_ref(node.child_by_field_name("type"))
        table = self.fields.setdefault(ctx.member_of, {})
        for element in node.named_children:
            if element.type != "property_element":
                continue
            for child in element.named_children:
                if child.type == "variable_name":
                    table[self.text(child).lstrip("$")] = ref
        return None

    def on_function_call(self, node, ctx):
        function = node.child_by_field_name("function")
        if ctx.owner is None or function is None:
            return None
        argc = self.argc(node.child_by_field_name("arguments"))
        if function.type == "name":
            self.refs.append([ctx.owner, "call", self.text(function), ["bare"], argc])
        elif function.type == "qualified_name":
            ref = self.type_ref(function)
            if ref[0] == "path":
                self.refs.append([ctx.owner, "call", ref[1][-1], ["path", ref[1][:-1], ref[2]], argc])
        return None

    def receiver(self, target, ctx: _Ctx) -> list:
        if target is not None and target.type == "variable_name":
            text = self.text(target)
            if text == "$this":
                return ["self"]
            if ctx.locals is not None and text in ctx.locals:
                return ["var", ctx.locals[text]]
            return ["var", UNKNOWN]
        if target is not None and target.type in ("member_access_expression", "nullsafe_member_access_expression"):
            inner = target.child_by_field_name("object")
            name = target.child_by_field_name("name")
            if inner is not None and name is not None and inner.type == "variable_name" and self.text(inner) == "$this" and name.type == "name":
                return ["field", self.text(name)]
        return ["var", UNKNOWN]

    def on_member_call(self, node, ctx):
        name = node.child_by_field_name("name")
        if ctx.owner is None or name is None or name.type != "name":
            return None
        qualifier = self.receiver(node.child_by_field_name("object"), ctx)
        self.refs.append([ctx.owner, "call", self.text(name), qualifier, self.argc(node.child_by_field_name("arguments"))])
        return None

    def on_scoped_call(self, node, ctx):
        scope = node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        if ctx.owner is None or scope is None or name is None or name.type != "name":
            return None
        if scope.type == "relative_scope":
            qualifier = ["self"]
            if self.text(scope).lower() == "parent":
                qualifier = ["super"]
        else:
            ref = self.type_ref(scope)
            if ref[0] == "self":
                qualifier = ["self"]
            elif ref[0] == "parent":
                qualifier = ["super"]
            elif ref[0] in ("name", "path"):
                qualifier = ["type", ref]
            else:
                return None
        self.refs.append([ctx.owner, "call", self.text(name), qualifier, self.argc(node.child_by_field_name("arguments"))])
        return None

    def on_new(self, node, ctx):
        if ctx.owner is None:
            return None
        for child in node.named_children:
            if child.type in ("name", "qualified_name"):
                ref = self.type_ref(child)
                if ref[0] in ("name", "path"):
                    self.refs.append([ctx.owner, "new", _ref_name(ref), ["type", ref], ANY])
                break
        return None

    def on_assign(self, node, ctx):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if ctx.locals is None or left is None or right is None or left.type != "variable_name":
            return None
        ref = UNKNOWN
        if right.type == "object_creation_expression":
            for child in right.named_children:
                if child.type in ("name", "qualified_name"):
                    ref = self.type_ref(child)
                    break
        _remember(ctx.locals, self.text(left), ref)
        return None

    def on_closure(self, node, ctx):
        if ctx.locals is not None:
            self.params(node.child_by_field_name("parameters"), ctx.locals)
        return None


WALKERS = {"go": _GoWalker, "java": _JavaWalker, "rust": _RustWalker, "php": _PhpWalker}


@lru_cache(maxsize=None)
def _grammar(language: str):
    spec = GRAMMARS.get(language)
    walker = WALKERS.get(language)
    if spec is None or walker is None:
        return None
    try:
        import tree_sitter

        module = importlib.import_module(spec[0])
        handle = tree_sitter.Language(getattr(module, spec[1])())
    except (ImportError, AttributeError, TypeError, ValueError, OSError):
        return None
    wanted = set(walker.handlers) | set(walker.core)
    kinds = frozenset(kind for kind in wanted if handle.id_for_node_kind(kind, True) is not None)
    if not set(walker.core) <= kinds:
        return None
    if any(handle.field_id_for_name(field) is None for field in walker.fields_used):
        return None
    return handle, kinds


@lru_cache(maxsize=None)
def _parser(language: str):
    import tree_sitter

    return tree_sitter.Parser(_grammar(language)[0])


def grammar_ready(language: str) -> bool:
    return _grammar(language) is not None


def extract_other(path: str, module: str, source: str, digest: str) -> dict:
    language = other_language(path)
    loaded = None
    if language is not None:
        loaded = _grammar(language)
    if loaded is None:
        return {"path": path, "hash": digest, "error": "no grammar for this language"}
    walker = WALKERS[language](path, module, source, loaded[1])
    tree = _parser(language).parse(walker.data)
    walker.walk(tree.root_node)
    return {
        "path": path,
        "hash": digest,
        "module": module,
        "language": language,
        "lines": source.count("\n") + 1,
        "is_test": walker.test_file,
        "symbols": walker.symbols,
        "links": walker.record(),
    }


def _join(base: str, rest: str) -> str:
    if not rest:
        return base
    if base == ROOT:
        return rest
    return f"{base}/{rest}"


def _folder(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    if parent in ("", "."):
        return ROOT
    return parent


def _rust_file_module(path: str) -> tuple[str, list[str]]:
    parts = PurePosixPath(path).parts
    positions = [number for number, part in enumerate(parts[:-1]) if part == "src"]
    if not positions:
        return path, []
    cut = positions[-1]
    rest = list(parts[cut + 1:])
    segments = rest[:-1]
    stem = rest[-1].rsplit(".", 1)[0]
    if stem not in ("lib", "main", "mod"):
        segments.append(stem)
    return "/".join(parts[: cut + 1]), segments


class _Site:
    __slots__ = ("record", "language", "space", "owner", "self_key", "path", "mods", "crate", "module")

    def __init__(self, **values):
        for name in self.__slots__:
            setattr(self, name, values.get(name))


class _Linker:
    def __init__(self, records: list[dict], root=None):
        self.root = None
        if root is not None:
            self.root = Path(root)
        self.records = [record for record in records if isinstance(record.get("links"), dict)]
        self.symbols: dict[str, dict] = {}
        self.record_of: dict[str, dict] = {}
        self.key_of: dict[str, tuple] = {}
        self.types: dict[tuple, list[str]] = collections.defaultdict(list)
        self.members: dict[tuple, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        self.functions: dict[tuple, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        self.file_methods: dict[str, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        self.space_methods: dict[tuple, dict[str, list[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        self.inherit_refs: dict[str, list] = collections.defaultdict(list)
        self.base_cache: dict[tuple, list[tuple]] = {}
        self.extra_bases: dict[tuple, list[tuple]] = collections.defaultdict(list)
        self.go_dirs: dict[str, str] = {}
        self.go_vars: dict[str, dict[str, tuple]] = collections.defaultdict(dict)
        self.rust_modules: set[tuple] = set()
        self.sites: dict[str, _Site] = {}
        for record in self.records:
            self._index(record)
        self.go_modules = self._go_modules()
        self.go_alias_cache: dict[str, dict[str, str]] = {}

    def _space(self, record: dict, symbol: dict) -> str:
        language = record["language"]
        if language == "go":
            return _folder(record["path"])
        if language == "rust":
            crate, segments = _rust_file_module(record["path"])
            return f"{crate}|{'::'.join(segments + list(symbol.get('mods') or ()))}"
        return symbol.get("space") or ""

    def _index(self, record: dict) -> None:
        language = record["language"]
        path = record["path"]
        links = record["links"]
        if language == "go":
            folder = _folder(path)
            if links.get("package"):
                self.go_dirs.setdefault(folder, links["package"])
            else:
                self.go_dirs.setdefault(folder, "")
            for name, ref in (links.get("package_vars") or {}).items():
                self.go_vars[folder][name] = (ref, record)
        if language == "rust":
            crate, segments = _rust_file_module(path)
            self.rust_modules.add((crate, tuple(segments)))
        for symbol in record.get("symbols") or ():
            node_id = symbol["full_name"]
            space = self._space(record, symbol)
            self.symbols[node_id] = symbol
            self.record_of[node_id] = record
            if language == "rust":
                crate, segments = _rust_file_module(path)
                mods = list(symbol.get("mods") or ())
                for size in range(1, len(mods) + 1):
                    self.rust_modules.add((crate, tuple(segments + mods[:size])))
            if symbol["kind"] == "class":
                type_name = symbol["simple"]
                if language == "java":
                    type_name = symbol["qual"].split("~", 1)[0]
                key = (language, space, type_name)
                self.types[key].append(node_id)
                self.key_of[node_id] = key
            elif symbol.get("owner_type"):
                key = (language, space, symbol["owner_type"])
                self.members[key][symbol["simple"]].append(node_id)
                self.file_methods[path][symbol["simple"]].append(node_id)
                self.space_methods[(language, space)][symbol["simple"]].append(node_id)
            else:
                self.functions[(language, space)][symbol["simple"]].append(node_id)
        for ref in links.get("refs") or ():
            if ref[1] == "inherit":
                self.inherit_refs[ref[0]].append(ref[3][1])

    def _go_modules(self) -> list[tuple[str, str]]:
        if self.root is None or not self.go_dirs:
            return []
        base = self.root.resolve()
        checked: dict[str, tuple[str, str] | None] = {}
        found = set()
        for folder in self.go_dirs:
            current = folder
            while True:
                if current not in checked:
                    checked[current] = self._read_go_mod(base, current)
                if checked[current] is not None:
                    found.add(checked[current])
                    break
                if current == ROOT:
                    break
                current = _folder(current)
        return sorted(found, key=lambda item: (-len(item[0]), item[0]))

    def _read_go_mod(self, base: Path, folder: str) -> tuple[str, str] | None:
        candidate = base / "go.mod"
        if folder != ROOT:
            candidate = base / folder / "go.mod"
        try:
            full = candidate.resolve()
            if base not in full.parents or not full.is_file() or full.stat().st_size > GO_MOD_LIMIT:
                return None
            text = full.read_text(encoding="utf-8", errors="replace")  # skylos: ignore[SKY-D325] go.mod inside the repository, resolved under the root and size checked above
        except OSError:
            return None
        match = re.search(r"^\s*module\s+\"?([^\s\"]+)\"?", text, re.MULTILINE)
        if match is None:
            return None
        return match.group(1), folder

    def go_dir(self, import_path: str) -> str | None:
        for module_path, module_dir in self.go_modules:
            if import_path == module_path:
                rest = ""
            elif import_path.startswith(module_path + "/"):
                rest = import_path[len(module_path) + 1:]
            else:
                continue
            folder = _join(module_dir, rest)
            if folder in self.go_dirs:
                return folder
            return None
        if "." not in import_path.split("/", 1)[0]:
            return None
        best = None
        for folder in self.go_dirs:
            if folder == ROOT:
                continue
            if import_path == folder or import_path.endswith("/" + folder):
                if best is None or len(folder) > len(best):
                    best = folder
        return best

    def go_aliases(self, record: dict) -> dict[str, str]:
        cached = self.go_alias_cache.get(record["path"])
        if cached is not None:
            return cached
        aliases: dict[str, str] = {}
        for item in record["links"].get("imports") or ():
            if item.get("alias") in ("_", "."):
                continue
            folder = self.go_dir(item["path"])
            name = item.get("alias")
            if not name and folder is not None and self.go_dirs.get(folder):
                name = self.go_dirs[folder]
            if not name:
                name = _go_default_alias(item["path"])
            aliases[name] = item["path"]
        self.go_alias_cache[record["path"]] = aliases
        return aliases

    def site(self, node_id: str) -> _Site:
        cached = self.sites.get(node_id)
        if cached is not None:
            return cached
        symbol = self.symbols[node_id]
        record = self.record_of[node_id]
        language = record["language"]
        space = self._space(record, symbol)
        self_key = None
        if symbol.get("owner_type"):
            self_key = (language, space, symbol["owner_type"])
        elif symbol["kind"] == "class":
            self_key = self.key_of.get(node_id)
        crate = None
        module: list[str] = []
        if language == "rust":
            crate, segments = _rust_file_module(record["path"])
            module = segments + list(symbol.get("mods") or ())
        found = _Site(record=record, language=language, space=space, owner=node_id, self_key=self_key, path=record["path"], mods=list(symbol.get("mods") or ()), crate=crate, module=module)
        self.sites[node_id] = found
        return found

    def fits(self, candidate: str, argc: int, through: bool) -> bool:
        if argc == ANY:
            return True
        symbol = self.symbols[candidate]
        low, high = symbol.get("args") or [0, ANY]
        if through and symbol.get("self_param"):
            argc -= 1
        return low <= argc and (high == ANY or argc <= high)

    def pick(self, rungs, argc: int, through: bool = False, production: bool = False) -> tuple[str | None, str]:
        for rung in rungs:
            found = rung()
            if found is _STOP:
                return None, "not_found"
            unique = sorted(set(found))
            if production:
                unique = [candidate for candidate in unique if not self.symbols[candidate].get("is_test")]
            if not unique:
                continue
            fitting = [candidate for candidate in unique if self.fits(candidate, argc, through)]
            if len(fitting) == 1:
                return fitting[0], "linked"
            if len(fitting) > 1:
                return None, "ambiguous"
        return None, "not_found"

    def bases(self, key: tuple, depth: int = 0) -> list[tuple]:
        if key in self.base_cache:
            return self.base_cache[key]
        self.base_cache[key] = []
        found: list[tuple] = []
        for type_id in self.types.get(key, ()):
            site = self.site(type_id)
            for ref in self.inherit_refs.get(type_id, ()):
                keys = self.resolve_type(site, ref, depth + 1)
                if isinstance(keys, list):
                    found.extend(other for other in keys if other != key)
        found.extend(self.extra_bases.get(key, ()))
        unique = sorted(set(found))
        self.base_cache[key] = unique
        return unique

    def member(self, key: tuple | None, name: str) -> list[str]:
        if key is None:
            return []
        pending = [(key, 0)]
        seen = {key}
        while pending:
            current, depth = pending.pop(0)
            found = self.members.get(current, {}).get(name)
            if found:
                return list(found)
            if depth >= INHERIT_DEPTH:
                continue
            for base in self.bases(current):
                if base not in seen:
                    seen.add(base)
                    pending.append((base, depth + 1))
        return []

    def inherited(self, key: tuple | None, name: str) -> list[str]:
        if key is None:
            return []
        found = []
        for base in self.bases(key):
            found.extend(self.member(base, name))
        return found

    def field(self, key: tuple | None, name: str) -> tuple[list, _Site] | None:
        if key is None:
            return None
        pending = [key]
        seen = {key}
        while pending:
            current = pending.pop(0)
            for type_id in self.types.get(current, ()):
                table = self.record_of[type_id]["links"].get("fields", {}).get(type_id) or {}
                if name in table:
                    return table[name], self.site(type_id)
            for base in self.bases(current):
                if base not in seen and len(seen) < 20:
                    seen.add(base)
                    pending.append(base)
        return None

    def ids_of(self, keys) -> list[str]:
        if not isinstance(keys, list):
            return []
        return [node_id for key in keys for node_id in self.types.get(key, ())]

    def resolve_type(self, site: _Site, ref: list, depth: int = 0):
        if depth > ALIAS_DEPTH + 2 or not ref:
            return _STOP
        if ref[0] == "none":
            return _STOP
        if ref[0] == "unknown":
            return _UNKNOWN
        if ref[0] == "self":
            if site.self_key is None:
                return _STOP
            return [site.self_key]
        if ref[0] == "any":
            keys = []
            unknown = False
            for option in ref[1]:
                found = self.resolve_type(site, option, depth + 1)
                if found is _UNKNOWN:
                    unknown = True
                elif isinstance(found, list):
                    keys.extend(found)
            if keys:
                return sorted(set(keys))
            if unknown:
                return _UNKNOWN
            return _STOP
        handler = getattr(self, f"{site.language}_type")
        return handler(site, ref, depth)

    def go_type(self, site: _Site, ref: list, depth: int):
        if ref[0] == "name":
            key = ("go", site.space, ref[1])
            if key in self.types:
                return [key]
            return _STOP
        if ref[0] == "pkg":
            path = self.go_aliases(site.record).get(ref[1])
            folder = None
            if path is not None:
                folder = self.go_dir(path)
            key = ("go", folder, ref[2])
            if folder is not None and key in self.types:
                return [key]
            return _STOP
        if ref[0] in ("call", "calls_on"):
            return self.go_result(site, ref, 0, depth)
        if ref[0] == "nth" and isinstance(ref[1], list) and isinstance(ref[2], int):
            return self.go_result(site, ref[1], ref[2], depth)
        if ref[0] == "field_of":
            keys = self.resolve_type(site, ref[1], depth + 1)
            if not isinstance(keys, list):
                return keys
            for key in keys:
                found = self.field(key, ref[2])
                if found is not None:
                    return self.resolve_type(found[1], found[0], depth + 1)
        return _STOP

    def go_callee(self, site: _Site, ref: list, depth: int):
        if ref[0] == "call":
            folder = site.space
            if ref[1] is not None:
                folder = self.go_dir(ref[1])
            if folder is None:
                return _STOP
            found = self.functions.get(("go", folder), {}).get(ref[2], [])
        else:
            keys = self.resolve_type(site, ref[1], depth + 1)
            if not isinstance(keys, list):
                return keys
            found = sorted({m for key in keys for m in self.member(key, ref[2])})
        if len(found) != 1:
            return _UNKNOWN
        return found[0]

    def go_result(self, site: _Site, ref: list, position: int, depth: int):
        callee = self.go_callee(site, ref, depth)
        if callee is _STOP or callee is _UNKNOWN:
            return callee
        results = self.symbols[callee].get("results") or []
        if position >= len(results):
            return _STOP
        return self.resolve_type(self.site(callee), results[position], depth + 1)

    def java_full(self, full: str) -> list[tuple]:
        parts = full.split(".")
        for cut in range(len(parts) - 1, 0, -1):
            key = ("java", ".".join(parts[:cut]), ".".join(parts[cut:]))
            if key in self.types:
                return [key]
        key = ("java", "", full)
        if key in self.types:
            return [key]
        return []

    def java_type(self, site: _Site, ref: list, depth: int):
        package = site.space
        if ref[0] == "path":
            found = self.java_full(".".join(ref[1]))
            if found:
                return found
            head = self.java_type(site, ["name", ref[1][0]], depth + 1)
            if isinstance(head, list) and len(head) == 1:
                key = ("java", head[0][1], ".".join([head[0][2]] + ref[1][1:]))
                if key in self.types:
                    return [key]
            return _STOP
        if ref[0] != "name":
            return _STOP
        name = ref[1]
        if site.self_key is not None:
            chain = site.self_key[2].split(".")
            for size in range(len(chain), 0, -1):
                prefix = ".".join(chain[:size])
                key = ("java", package, f"{prefix}.{name}")
                if key in self.types:
                    return [key]
                if chain[size - 1] == name:
                    return [("java", package, prefix)]
        for item in site.record["links"].get("imports") or ():
            if item.get("static") or item.get("all"):
                continue
            if item["path"] == name or item["path"].endswith("." + name):
                found = self.java_full(item["path"])
                if found:
                    return found
                return _STOP
        key = ("java", package, name)
        if key in self.types:
            return [key]
        found = []
        for item in site.record["links"].get("imports") or ():
            if item.get("all") and not item.get("static"):
                key = ("java", item["path"], name)
                if key in self.types:
                    found.append(key)
        if found:
            return found
        return _STOP

    def rust_alias(self, site: _Site, name: str) -> list[str] | None:
        for mods, alias, segments in site.record["links"].get("uses") or ():
            if list(mods) == site.mods and alias == name:
                return list(segments)
        return None

    def rust_space(self, crate: str, module) -> str:
        return f"{crate}|{'::'.join(module)}"

    def rust_path(self, site: _Site, segments: list[str], depth: int = 0):
        if not segments or depth > ALIAS_DEPTH:
            return None
        crate = site.crate
        head, rest = segments[0], list(segments[1:])
        if head == "crate":
            position: list[str] = []
        elif head == "self":
            position = list(site.module)
        elif head == "super":
            position = list(site.module[:-1])
            while rest and rest[0] == "super":
                position = position[:-1]
                rest = rest[1:]
        elif head == "Self":
            if site.self_key is None or rest:
                return None
            return ("type", [site.self_key])
        else:
            alias = self.rust_alias(site, head)
            if alias is not None and alias != [head]:
                return self.rust_path(site, alias + rest, depth + 1)
            if (crate, tuple(list(site.module) + [head])) in self.rust_modules:
                position = list(site.module) + [head]
            elif ("rust", self.rust_space(crate, site.module), head) in self.types:
                position = list(site.module)
                rest = [head] + rest
            elif (crate, (head,)) in self.rust_modules:
                position = [head]
            else:
                return None
        for number, segment in enumerate(rest):
            if (crate, tuple(position + [segment])) in self.rust_modules:
                position = position + [segment]
                continue
            key = ("rust", self.rust_space(crate, position), segment)
            if key in self.types and number == len(rest) - 1:
                return ("type", [key])
            return None
        return ("module", self.rust_space(crate, position))

    def rust_type(self, site: _Site, ref: list, depth: int):
        if ref[0] == "path":
            found = self.rust_path(site, ref[1])
            if found is not None and found[0] == "type":
                return found[1]
            return _STOP
        if ref[0] != "name":
            return _STOP
        name = ref[1]
        key = ("rust", self.rust_space(site.crate, site.module), name)
        if key in self.types:
            return [key]
        alias = self.rust_alias(site, name)
        if alias is not None:
            found = self.rust_path(site, alias, depth + 1)
            if found is not None and found[0] == "type":
                return found[1]
            return _STOP
        found = []
        for mods, segments in site.record["links"].get("globs") or ():
            if list(mods) != site.mods:
                continue
            module = self.rust_path(site, list(segments), depth + 1)
            if module is not None and module[0] == "module" and ("rust", module[1], name) in self.types:
                found.append(("rust", module[1], name))
        if found:
            return found
        return _STOP

    def php_full(self, full: str):
        namespace, _, name = full.strip("\\").rpartition("\\")
        key = ("php", namespace, name)
        if key in self.types:
            return [key]
        return _STOP

    def php_alias(self, site: _Site, name: str, kind: str) -> str | None:
        for item in site.record["links"].get("imports") or ():
            if item.get("kind") == kind and item.get("alias", "").lower() == name.lower():
                return item["path"]
        return None

    def php_name(self, site: _Site, segments: list[str], absolute: bool) -> str:
        if absolute:
            return "\\".join(segments)
        alias = self.php_alias(site, segments[0], "class")
        if alias is not None:
            return "\\".join([alias] + segments[1:])
        if site.space:
            return "\\".join([site.space] + segments)
        return "\\".join(segments)

    def php_type(self, site: _Site, ref: list, depth: int):
        if ref[0] == "parent":
            return self.bases(site.self_key) or _STOP
        if ref[0] == "path":
            return self.php_full(self.php_name(site, ref[1], ref[2]))
        if ref[0] != "name":
            return _STOP
        alias = self.php_alias(site, ref[1], "class")
        if alias is not None:
            return self.php_full(alias)
        return self.php_full("\\".join([part for part in (site.space, ref[1]) if part]))

    def unknown_rungs(self, site: _Site, name: str) -> list:
        rungs = [lambda: self.file_methods.get(site.path, {}).get(name, [])]
        if site.language != "rust":
            rungs.append(lambda: self.space_methods.get((site.language, site.space), {}).get(name, []))
        return rungs

    def typed_rungs(self, site: _Site, ref: list, name: str) -> list:
        keys = self.resolve_type(site, ref)
        if keys is _UNKNOWN:
            return self.unknown_rungs(site, name)
        if keys is _STOP:
            return [lambda: _STOP]
        return [lambda: [m for key in keys for m in self.member(key, name)]]

    def field_rungs(self, site: _Site, field_name: str, name: str) -> list:
        found = self.field(site.self_key, field_name)
        if found is None:
            return [lambda: _STOP]
        ref, owner_site = found
        return self.typed_rungs(owner_site, ref, name)

    def call_rungs(self, site: _Site, name: str, qualifier: list) -> tuple[list, bool]:
        kind = qualifier[0]
        if kind == "self":
            return [lambda: self.member(site.self_key, name)], False
        if kind == "super":
            return [lambda: self.inherited(site.self_key, name)], False
        if kind == "var":
            return self.typed_rungs(site, qualifier[1], name), False
        if kind == "field":
            return self.field_rungs(site, qualifier[1], name), False
        handler = getattr(self, f"{site.language}_rungs")
        return handler(site, name, qualifier)

    def go_rungs(self, site: _Site, name: str, qualifier: list) -> tuple[list, bool]:
        kind = qualifier[0]
        if kind == "bare":
            return [lambda: self.functions.get(("go", site.space), {}).get(name, [])], False
        if kind in ("import", "pkgvar"):
            folder = self.go_dir(qualifier[1])
            if folder is None:
                return [lambda: _STOP], False
            if kind == "pkgvar":
                return [lambda: self.space_methods.get(("go", folder), {}).get(name, [])], False
            return [lambda: self.functions.get(("go", folder), {}).get(name, [])], False
        if kind == "ident":
            known = self.go_vars.get(site.space, {}).get(qualifier[1])
            if known is not None:
                return self.typed_rungs(self.site_for_record(known[1], site), known[0], name), False
            path = self.go_aliases(site.record).get(qualifier[1])
            folder = None
            if path is not None:
                folder = self.go_dir(path)
            if folder is None:
                return [lambda: _STOP], False
            return [lambda: self.functions.get(("go", folder), {}).get(name, [])], False
        if kind == "member":
            keys = self.resolve_type(site, ["field_of", qualifier[1], qualifier[2]])
            if not isinstance(keys, list):
                return [lambda: _STOP], False
            return [lambda: [m for key in keys for m in self.member(key, name)]], False
        return [lambda: _STOP], False

    def site_for_record(self, record: dict, fallback: _Site) -> _Site:
        for symbol in record.get("symbols") or ():
            return self.site(symbol["full_name"])
        return fallback

    def java_rungs(self, site: _Site, name: str, qualifier: list) -> tuple[list, bool]:
        kind = qualifier[0]
        if kind == "bare":
            rungs = []
            if site.self_key is not None:
                chain = site.self_key[2].split(".")
                for size in range(len(chain), 0, -1):
                    key = ("java", site.space, ".".join(chain[:size]))
                    rungs.append(lambda key=key: self.member(key, name))
            rungs.append(lambda: self.java_static(site, name))
            return rungs, False
        if kind == "ident":
            found = self.field(site.self_key, qualifier[1])
            if found is not None:
                return self.typed_rungs(found[1], found[0], name), False
            keys = self.java_type(site, ["name", qualifier[1]], 0)
            if isinstance(keys, list):
                return [lambda: [m for key in keys for m in self.member(key, name)]], False
            if qualifier[1][:1].isupper():
                return [lambda: _STOP], False
            return self.unknown_rungs(site, name), False
        if kind == "path":
            keys = self.java_type(site, ["path", qualifier[1]], 0)
            if isinstance(keys, list):
                return [lambda: [m for key in keys for m in self.member(key, name)]], False
            return [lambda: _STOP], False
        return [lambda: _STOP], False

    def java_static(self, site: _Site, name: str) -> list[str]:
        found = []
        for item in site.record["links"].get("imports") or ():
            if not item.get("static"):
                continue
            owner = item["path"]
            if not item.get("all"):
                owner, _, member = item["path"].rpartition(".")
                if member != name:
                    continue
            for key in self.java_full(owner):
                found.extend(self.member(key, name))
        return found

    def rust_rungs(self, site: _Site, name: str, qualifier: list) -> tuple[list, bool]:
        kind = qualifier[0]
        here = self.rust_space(site.crate, site.module)
        if kind == "bare":
            rungs = [lambda: self.functions.get(("rust", here), {}).get(name, [])]
            alias = self.rust_alias(site, name)
            if alias is not None and len(alias) > 1:
                rungs.append(lambda: self.rust_member_of_path(site, alias[:-1], alias[-1]))
            rungs.append(lambda: self.rust_globs(site, name))
            return rungs, False
        if kind == "path":
            found = self.rust_path(site, list(qualifier[1]))
            if found is None:
                return [lambda: _STOP], True
            if found[0] == "module":
                return [lambda: self.functions.get(("rust", found[1]), {}).get(name, [])], True
            return [lambda: [m for key in found[1] for m in self.member(key, name)]], True
        return [lambda: _STOP], False

    def rust_member_of_path(self, site: _Site, prefix: list[str], name: str) -> list[str]:
        found = self.rust_path(site, prefix)
        if found is None:
            return []
        if found[0] == "module":
            return self.functions.get(("rust", found[1]), {}).get(name, [])
        return [m for key in found[1] for m in self.member(key, name)]

    def rust_globs(self, site: _Site, name: str) -> list[str]:
        found = []
        for mods, segments in site.record["links"].get("globs") or ():
            if list(mods) != site.mods:
                continue
            module = self.rust_path(site, list(segments))
            if module is not None and module[0] == "module":
                found.extend(self.functions.get(("rust", module[1]), {}).get(name, []))
        return found

    def php_rungs(self, site: _Site, name: str, qualifier: list) -> tuple[list, bool]:
        kind = qualifier[0]
        if kind == "bare":
            rungs = [lambda: self.functions.get(("php", site.space), {}).get(name, [])]
            alias = self.php_alias(site, name, "function")
            if alias is not None:
                namespace, _, target = alias.rpartition("\\")
                rungs.append(lambda: self.functions.get(("php", namespace), {}).get(target, []))
            rungs.append(lambda: self.functions.get(("php", ""), {}).get(name, []))
            return rungs, False
        if kind == "path":
            if not qualifier[1]:
                return [lambda: self.functions.get(("php", ""), {}).get(name, [])], False
            namespace = self.php_name(site, list(qualifier[1]), qualifier[2])
            return [lambda: self.functions.get(("php", namespace), {}).get(name, [])], False
        if kind == "type":
            return self.typed_rungs(site, qualifier[1], name), False
        return [lambda: _STOP], False

    def target_rungs(self, site: _Site, ref: list) -> list:
        keys = self.resolve_type(site, ref)
        if not isinstance(keys, list):
            return [lambda: _STOP]
        return [lambda: self.ids_of(keys)]

    def run(self) -> tuple[list[list[str]], dict]:
        edges = set()
        stats = collections.Counter({"references": 0, "linked": 0, "ambiguous": 0, "not_found": 0})
        for record in self.records:
            for owner, form, name, qualifier, argc in record["links"].get("refs") or ():
                if owner not in self.symbols:
                    continue
                stats["references"] += 1
                site = self.site(owner)
                through = False
                if form == "call":
                    rungs, through = self.call_rungs(site, name, qualifier)
                    edge_kind = "calls"
                else:
                    rungs = self.target_rungs(site, qualifier[1])
                    edge_kind = "creates"
                    if form == "inherit":
                        edge_kind = "inherits"
                target, outcome = self.pick(rungs, argc, through, not self.symbols[owner].get("is_test"))
                stats[outcome] += 1
                if target is None or target == owner or owner.startswith(target + "."):
                    continue
                edges.add((owner, target, edge_kind))
        for type_keys, trait_keys in self.impl_pairs:
            for type_id in self.ids_of(type_keys):
                for trait_id in self.ids_of(trait_keys):
                    if type_id != trait_id:
                        edges.add((type_id, trait_id, "inherits"))
        return [list(edge) for edge in sorted(edges)], dict(sorted(stats.items()))

    def prepare(self) -> None:
        self.impl_pairs: list[tuple[list, list]] = []
        for record in self.records:
            if record["language"] != "rust":
                continue
            crate, segments = _rust_file_module(record["path"])
            for mods, type_ref, trait_ref in record["links"].get("impls") or ():
                module = segments + list(mods)
                site = _Site(record=record, language="rust", space=self.rust_space(crate, module), owner=None, self_key=None, path=record["path"], mods=list(mods), crate=crate, module=module)
                type_keys = self.resolve_type(site, type_ref)
                trait_keys = self.resolve_type(site, trait_ref)
                if isinstance(type_keys, list) and isinstance(trait_keys, list):
                    self.impl_pairs.append((type_keys, trait_keys))
                    for key in type_keys:
                        self.extra_bases[key].extend(trait_keys)


def link_by_name(records: list[dict], root=None) -> tuple[list[list[str]], dict]:
    linker = _Linker(records, root)
    linker.prepare()
    return linker.run()
