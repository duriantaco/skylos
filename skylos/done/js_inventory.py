"""Static inventory of JavaScript and TypeScript tests.

The Jest, Vitest, Mocha, node:test and Playwright Test counterpart of
``inventory.py``. Test files are ``*.test.*`` and ``*.spec.*`` files and files
under ``__tests__/`` (JS, JSX, TS, TSX, MJS, CJS, MTS, CTS), read with the
tree-sitter TypeScript grammars Skylos already uses, so comments and strings
never count as tests.

A test is identified by its file, the titles of the describe blocks around
it and its own title. Only string-literal titles are inventoried: a test
whose title is a template literal with ``${...}``, a variable or any other
expression is skipped. Each test records a hash of its body tokens (so a
moved or renamed test is not a deletion), the skip, todo and
expected-failure markers that apply to it, and how many literal ``.each``
cases it has. Focus (``.only``, ``fit``, ``fdescribe``) is recorded per call:
a focused test stops the other tests in its file from running.
"""

from __future__ import annotations

import difflib
import json
import hashlib
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from skylos.done.inventory import ASSERTION_HELPER_RE, RENAME_SIMILARITY, TestItem

JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
# Parsed with the TSX grammar (JSX allowed); .ts/.mts/.cts use the TypeScript
# grammar, where ``<T>value`` is a type assertion rather than JSX.
_TSX_SUFFIXES = (".js", ".jsx", ".tsx", ".mjs", ".cjs")

# Test and suite functions: (kind, marker). "focus" is recorded separately.
_ROOTS = {
    "it": ("test", None),
    "test": ("test", None),
    "specify": ("test", None),
    "xit": ("test", "skip"),
    "xtest": ("test", "skip"),
    "xspecify": ("test", "skip"),
    "fit": ("test", "focus"),
    "describe": ("describe", None),
    "context": ("describe", None),
    "suite": ("describe", None),
    "xdescribe": ("describe", "skip"),
    "xcontext": ("describe", "skip"),
    "fdescribe": ("describe", "focus"),
}
# Chain members (``it.skip``, ``test.describe.fixme``) and the marker each adds.
_MEMBER_MARKERS = {
    "skip": "skip",
    "fixme": "fixme",
    "todo": "todo",
    "failing": "failing",  # Jest
    "fails": "failing",  # Vitest
    "fail": "failing",  # Playwright
}
_CONDITIONAL = {"skipIf", "runIf"}  # Vitest: it.skipIf(condition)(title, fn)
_EACH = {"each", "for"}
_NEUTRAL = {"concurrent", "sequential", "parallel", "serial", "shuffle"}
# Playwright modifiers called inside a test, describe or file: test.skip().
_MODIFIERS = {"skip", "fixme", "fail"}
# Calls on a test's own context arguments: t.skip() (node:test), ctx.skip()
# (Vitest), and testInfo.skip()/fixme()/fail() (Playwright, second argument).
_FIRST_CONTEXT_CALLS = frozenset({"skip", "todo"})
_INFO_CONTEXT_CALLS = frozenset({"skip", "fixme", "fail"})
_HOOKS = {
    "before",
    "after",
    "beforeEach",
    "afterEach",
    "beforeAll",
    "afterAll",
    "setup",
    "teardown",
    "suiteSetup",
    "suiteTeardown",
}
_FUNCTIONS = {"arrow_function", "function_expression", "function", "generator_function"}
# Functions that bind their own ``this`` (arrow functions do not).
_THIS_BINDERS = {
    "function_expression",
    "function",
    "generator_function",
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
    "class_body",
}
_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
}


@dataclass(frozen=True)
class JsTestItem(TestItem):
    # False for it.todo(title) and for a test declared without a callback:
    # a test that never ran, so removing it deletes nothing.
    has_body: bool = True

    @property
    def local_id(self) -> str:
        return " > ".join((*self.classes, self.name))


@dataclass(frozen=True)
class FocusSite:
    """One ``.only`` (or ``fit``/``fdescribe``/``{ only: true }``) call."""

    path: str
    line: int
    call: str
    scope: tuple[str, ...]  # describe titles around it, then its own title
    body_hash: str


@dataclass
class JsInventory:
    tests: list[JsTestItem] = field(default_factory=list)
    focus: list[FocusSite] = field(default_factory=list)
    clean: bool = True  # parsed without syntax errors

    def extend(self, other: JsInventory) -> None:
        self.tests.extend(other.tests)
        self.focus.extend(other.focus)


def is_js_test_file(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name
    if pure.suffix not in JS_SUFFIXES or name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return False
    if "node_modules" in pure.parts:
        return False
    stem = name[: -len(pure.suffix)]
    return stem.endswith((".test", ".spec")) or "__tests__" in pure.parts[:-1]


def collect_js_tests(path: str, source: str | None) -> JsInventory:
    """Tests and focus calls in one JS/TS test file (empty when it is not one)."""
    if source is None or not is_js_test_file(path):
        return JsInventory()
    root = _parse(path, source)
    if root is None:
        return JsInventory(clean=False)
    collector = _Collector(path, *_assertion_helpers(root), harness=_harness(root))
    collector.walk(root)
    inventory = collector.finish()
    inventory.clean = not root.has_error
    return inventory


def newly_focused(
    base: list[FocusSite],
    head: list[FocusSite],
    renamed_paths: dict[str, str] | None = None,
) -> list[FocusSite]:
    """Focus calls at head that were not there at the base.

    A focus moved to another file or under a renamed describe, with the same
    body, is the same focus. A focus added to a test written in this change
    still counts: it stops the existing tests in the file from running.
    """
    renamed_paths = renamed_paths or {}
    keys = {(renamed_paths.get(site.path, site.path), site.scope) for site in base}
    bodies = {site.body_hash for site in base if site.body_hash}
    return [
        site
        for site in head
        if (site.path, site.scope) not in keys and site.body_hash not in bodies
    ]


def js_non_code_lines(path: str, source: str | None) -> set[int]:
    """Lines holding only a comment, or inside a multi-line string literal."""
    if not source:
        return set()
    root = _parse(path, source)
    if root is None:
        return set()
    # tree-sitter rows end at "\n" and its columns count bytes.
    lines = source.encode("utf-8", errors="surrogatepass").split(b"\n")
    result: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            start, end = node.start_point, node.end_point
            first = lines[start[0]] if start[0] < len(lines) else b""
            if not first[: start[1]].strip():
                result.add(start[0] + 1)
            result.update(range(start[0] + 2, end[0] + 2))
            continue
        if node.type in {"string", "template_string"}:
            if node.end_point[0] > node.start_point[0]:
                result.update(range(node.start_point[0] + 2, node.end_point[0] + 2))
            continue
        stack.extend(node.children)
    return result


# ---------------------------------------------------------------------------
# Feature removal: a deleted test of something this change removed
# ---------------------------------------------------------------------------

_PAGE_SUFFIXES = (".tsx", ".jsx", ".ts", ".js", ".mdx")
_REQUEST_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "fetch"})


class FeatureRemoval:
    """Evidence that a deleted JS/TS test tested something the change removed.

    A deleted test is a feature removal when the code it runs (its callback,
    the hooks of its describe blocks and the file's own helper functions it
    calls) uses a name imported from a deleted module, an export its module
    no longer has, or a member of an imported value its module no longer
    mentions (``api.getLiveness()``); reads a file the change deleted
    (``readFileSync("src/x.tsx")``, also through a top-level constant);
    uses or reads a module whose last use the change removed (``unused``);
    or opens a route whose Next.js page or route file was deleted
    (``page.goto("/x")``). Type-only uses never count.
    """

    def __init__(
        self, base_text, head_text, deleted: set[str], paths=(), unused=None
    ) -> None:
        self.base_text = base_text
        self.head_text = head_text
        # unused(path): the change removed the last use of a module that
        # still exists (see feature_removal.SubjectRemoval.stopped_using).
        self.unused = unused
        # Repository files at the base: workspace package.json files name the
        # local packages a test may import by package name.
        self.paths = paths
        self._workspace: dict[str, tuple[str, dict]] | None = None
        # Deleted non-test files; deleted production modules are a subset.
        self.deleted = {path for path in deleted if not is_js_test_file(path)}
        self.modules = {
            path
            for path in self.deleted
            if path.endswith(JS_SUFFIXES)
            and not {"test", "tests", "__tests__", "__mocks__"}.intersection(
                PurePosixPath(path).parts[:-1]
            )
        }
        self.routes = [
            (route, path)
            for path in self.deleted
            if (route := _route_of(path)) is not None
        ]
        self._exports: dict[tuple[str, bool], tuple | None] = {}
        self._files: dict[str, tuple[object, dict] | None] = {}

    def reason(self, test: TestItem) -> str | None:
        parsed = self._file(test.path)
        if parsed is None:
            return None
        root, info = parsed
        match = next(
            (
                (n, c)
                for n in _descendants(root)
                if n.type == "call_expression"
                and n.start_point[0] + 1 == test.line
                and (c := (_classify(n, harness=info["harness"]) or _classify(n, True)))
                is not None
                and c[0] == "decl"
            ),
            None,
        )
        if match is None:
            return None
        node, classified = match
        callback = classified[1].callback
        if callback is None:
            return None
        bodies = [callback, *_enclosing_hooks(node)]
        seen: set[int] = set()
        while bodies:
            body = bodies.pop()
            if body.id in seen:
                continue
            seen.add(body.id)
            for found in _descendants(body):
                why = self._evidence(test.path, found, info)
                if why:
                    return why
                if found.type == "call_expression":
                    function = found.child_by_field_name("function")
                    if function is not None and function.type == "identifier":
                        bodies.extend(info["functions"].get(_text(function), ()))
        return None

    def _file(self, path: str):
        if path not in self._files:
            source = self.base_text(path)
            root = _parse(path, source) if source else None
            self._files[path] = (
                None
                if root is None
                else (
                    root,
                    {
                        "imports": _import_bindings(path, root),
                        "strings": _top_level_strings(root),
                        "read_paths": _top_level_read_paths(root),
                        "functions": _top_level_functions(root),
                        "harness": _harness(root),
                    },
                )
            )
        return self._files[path]

    def _evidence(self, path: str, node, info) -> str | None:
        kind = node.type
        if kind in {"identifier", "shorthand_property_identifier"}:
            for value in info["read_paths"].get(_text(node), ()):
                why = self._deleted_read(path, value)
                if why:
                    return why
            binding = info["imports"].get(_text(node))
            if binding is not None:
                return self._removed_name(
                    path, _text(node), *binding
                ) or self._unused_module(path, _text(node), binding[0])
        elif kind == "member_expression":
            target = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            binding = (
                info["imports"].get(_text(target))
                if target is not None and target.type == "identifier"
                else None
            )
            if binding is not None and binding[1] == "*" and prop is not None:
                return self._removed_name(
                    path, f"{_text(target)}.{_text(prop)}", binding[0], _text(prop)
                )
            if binding is not None and prop is not None:
                return self._removed_member(path, target, prop, binding[0])
        elif kind in {"string", "template_string"}:
            value = _string_constant(node, info["strings"])
            if value:
                return self._deleted_read(path, value)
        elif kind == "call_expression":
            return self._route(node, info["strings"])
        return None

    def _removed_name(self, path: str, shown: str, spec: str, name: str):
        candidates = self._resolve(path, spec)
        if candidates & self.modules:
            module = sorted(candidates & self.modules)[0]
            return f"uses {shown} from {module}, which was deleted"
        if name == "*":
            return None
        for module in sorted(candidates):
            if self.base_text(module) is None:
                continue
            before = self._module(module, base=True)
            after = self._module(module, base=False)
            if before is None or after is None or before[0] is None or after[0] is None:
                return None
            if name not in before[0] or name in after[0] or name in after[1]:
                return None  # still exported, or still defined in the module
            removed = before[1].get(name)
            if removed is None:
                return None  # re-exported from elsewhere: not removed here
            if any(
                _similar(removed, after[1][added])
                for added in after[0] - before[0]
                if added in after[1]
            ):
                return None  # renamed: the test should follow the new name
            return f"uses {shown}, which {module} no longer has"
        return None

    def _removed_member(self, path: str, target, prop, spec: str):
        """``api.getLiveness()`` where ``api`` is imported by name from a
        repository module that named ``getLiveness`` at the base and does not
        mention it at all at head (an object member or method removed)."""
        name = _text(prop)
        word = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
        for module in sorted(self._resolve(path, spec)):
            before = self.base_text(module)
            if before is None:
                continue
            after = self.head_text(module)
            if after is None or not word.search(before) or word.search(after):
                return None
            return f"uses {_text(target)}.{name}, which {module} no longer has"
        return None

    def _module(self, path: str, *, base: bool):
        """(exported names, definitions) of a module, following ``export *
        from`` into local modules; None when the exports cannot be known."""
        key = (path, base)
        if key in self._exports:
            return self._exports[key]
        self._exports[key] = None  # a cycle of re-exports is unknowable
        read = self.base_text if base else self.head_text
        source = read(path)
        root = _parse(path, source) if source else None
        found = None if root is None or root.has_error else _exports_of(root)
        if found is None:
            return None
        names, stars = found
        definitions = _definitions(root)
        for spec in stars:
            target = next(
                (c for c in sorted(self._resolve(path, spec)) if read(c) is not None),
                None,
            )
            if target is None:
                if base:
                    return None
                continue  # the re-exported module was deleted
            inner = self._module(target, base=base)
            if inner is None:
                return None
            names |= inner[0] - {"default"}
            for name, tokens in inner[1].items():
                definitions.setdefault(name, tokens)
        self._exports[key] = (names, definitions)
        return self._exports[key]

    def _resolve(self, importer: str, spec: str) -> set[str]:
        """Repository paths an import may name: relative and ``@/`` paths, or
        the entry point of a package that lives in this repository."""
        found = _resolve(importer, spec)
        if found or spec.startswith((".", "/", "@/")) or not spec:
            return found
        parts = spec.split("/")
        count = 2 if spec.startswith("@") else 1
        package = self._packages().get("/".join(parts[:count]))
        if package is None:
            return set()
        directory, manifest = package
        subpath = "/".join(parts[count:])
        exports = manifest.get("exports")
        if isinstance(exports, (str, list)) or (
            isinstance(exports, dict)
            and exports
            and not any(str(key).startswith(".") for key in exports)
        ):
            exports = {".": exports}  # "exports": "./index.js" and conditions
        if isinstance(exports, dict):
            entry = exports.get(f"./{subpath}" if subpath else ".")
            targets = _export_targets(entry)
        elif subpath:
            targets = [subpath]
        else:
            targets = [
                manifest[field]
                for field in ("source", "module", "main")
                if isinstance(manifest.get(field), str)
            ] or ["index"]
        result: set[str] = set()
        for target in targets:
            joined = posixpath.normpath(posixpath.join(directory, target))
            if joined != ".." and not joined.startswith("../"):
                result |= _variants(joined)
        return result

    def _packages(self) -> dict[str, tuple[str, dict]]:
        """Package name to (directory, package.json) for the repository's
        own packages."""
        if self._workspace is None:
            self._workspace = {}
            for path in self.paths:
                pure = PurePosixPath(path)
                if pure.name != "package.json" or "node_modules" in pure.parts:
                    continue
                try:
                    manifest = json.loads(self.base_text(path) or "")
                except ValueError:
                    continue
                name = manifest.get("name") if isinstance(manifest, dict) else None
                if isinstance(name, str) and name not in self._workspace:
                    directory = str(pure.parent) if str(pure.parent) != "." else ""
                    self._workspace[name] = (directory, manifest)
        return self._workspace

    def _deleted_read(self, path: str, value: str) -> str | None:
        if "/" not in value or "\n" in value:
            return None
        relative = value[2:] if value.startswith("./") else value
        candidates = (
            posixpath.normpath(relative),
            posixpath.normpath(posixpath.join(posixpath.dirname(path), value)),
        )
        for candidate in candidates:
            if candidate in self.deleted:
                return f"reads {candidate}, which was deleted"
        for candidate in candidates:
            if (
                self.unused is not None
                and candidate.endswith(JS_SUFFIXES)
                and not candidate.startswith("..")
                and self.unused(candidate)
            ):
                return f"reads {candidate}, which the change stopped using"
        return None

    def _unused_module(self, path: str, shown: str, spec: str) -> str | None:
        """A value imported from a repository module whose last use outside
        the tests the change removed."""
        if self.unused is None:
            return None
        for module in sorted(self._resolve(path, spec)):
            if self.base_text(module) is not None:
                if self.unused(module):
                    return f"uses {shown} from {module}, which the change stopped using"
                return None
        return None

    def _route(self, call, strings) -> str | None:
        if not self.routes:
            return None
        function = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        if function is None or arguments is None or arguments.type != "arguments":
            return None
        name = (
            _text(function.child_by_field_name("property"))
            if function.type == "member_expression"
            else _text(function)
        )
        if name != "goto" and name not in _REQUEST_METHODS:
            return None
        items = _args(arguments)
        url = _string_constant(items[0], strings) if items else None
        segments = _url_segments(url)
        if segments is None:
            return None
        for route, page in sorted(self.routes, key=lambda item: item[1]):
            if _route_matches(route, segments):
                return f"opens {url}, whose page {page} was deleted"
        return None


def _enclosing_hooks(node) -> list:
    """Callbacks of ``beforeEach``/``beforeAll`` (and friends) in the describe
    blocks around a test: setup the test depends on."""
    hooks = []
    parent = node.parent
    while parent is not None:
        if parent.type in {"statement_block", "program"}:
            for statement in parent.named_children:
                call = statement.named_children[0] if statement.named_children else None
                if call is None or call.type != "call_expression":
                    continue
                function = call.child_by_field_name("function")
                arguments = call.child_by_field_name("arguments")
                if (
                    function is not None
                    and _text(function).rsplit(".", 1)[-1] in _HOOKS
                    and arguments is not None
                ):
                    hooks.extend(
                        item for item in _args(arguments) if item.type in _FUNCTIONS
                    )
        parent = parent.parent
    return hooks


def _import_bindings(path: str, root) -> dict[str, tuple[str, str]]:
    """Local name to (module specifier, exported name); "*" for a namespace
    or a CommonJS module object. Type-only imports are left out."""
    bindings: dict[str, tuple[str, str]] = {}
    for node in root.named_children:
        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is None or any(child.type == "type" for child in node.children):
                continue
            spec = _string_value(source)
            for clause in node.named_children:
                if clause.type != "import_clause":
                    continue
                for child in clause.named_children:
                    if child.type == "identifier":
                        bindings[_text(child)] = (spec, "default")
                    elif child.type == "namespace_import":
                        for name in child.named_children:
                            if name.type == "identifier":
                                bindings[_text(name)] = (spec, "*")
                    elif child.type == "named_imports":
                        for specifier in child.named_children:
                            if specifier.type != "import_specifier" or any(
                                part.type == "type" for part in specifier.children
                            ):
                                continue
                            name = specifier.child_by_field_name("name")
                            alias = specifier.child_by_field_name("alias")
                            if name is not None:
                                bindings[_text(alias or name)] = (spec, _text(name))
        elif node.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                spec = _require_spec(declarator.child_by_field_name("value"))
                target = declarator.child_by_field_name("name")
                if spec is None or target is None:
                    continue
                if target.type == "identifier":
                    bindings[_text(target)] = (spec, "*")
                elif target.type == "object_pattern":
                    for child in target.named_children:
                        if child.type == "shorthand_property_identifier_pattern":
                            bindings[_text(child)] = (spec, _text(child))
                        elif child.type == "pair_pattern":
                            key = child.child_by_field_name("key")
                            value = child.child_by_field_name("value")
                            if (
                                key is not None
                                and value is not None
                                and value.type == "identifier"
                            ):
                                bindings[_text(value)] = (spec, _text(key))
    return bindings


def _exports_of(root) -> tuple[set[str], list[str]] | None:
    """Names a module exports and the modules it re-exports with ``export *
    from``; None when ``export =``, a computed ``module.exports`` or the like
    makes the list unknowable."""
    names: set[str] = set()
    stars: list[str] = []
    for node in root.named_children:
        if node.type == "export_statement":
            if any(child.type == "default" for child in node.children):
                names.add("default")
                continue
            declaration = node.child_by_field_name("declaration")
            if declaration is not None:
                if declaration.type in {"lexical_declaration", "variable_declaration"}:
                    for declarator in declaration.named_children:
                        target = declarator.child_by_field_name("name")
                        if target is not None:
                            names.update(
                                _text(child)
                                for child in _descendants(target)
                                if child.type
                                in {
                                    "identifier",
                                    "shorthand_property_identifier_pattern",
                                }
                            )
                else:
                    name = declaration.child_by_field_name("name")
                    if name is not None:
                        names.add(_text(name))
                continue
            clause = next(
                (c for c in node.named_children if c.type == "export_clause"), None
            )
            if clause is not None:
                for specifier in clause.named_children:
                    if specifier.type != "export_specifier":
                        continue
                    name = specifier.child_by_field_name("alias") or (
                        specifier.child_by_field_name("name")
                    )
                    if name is not None:
                        names.add(_text(name))
                continue
            namespace = next(
                (c for c in node.named_children if c.type == "namespace_export"), None
            )
            if namespace is not None:
                names.update(
                    _text(c) for c in namespace.named_children if c.type == "identifier"
                )
                continue
            source = node.child_by_field_name("source")
            if source is not None and any(child.type == "*" for child in node.children):
                stars.append(_string_value(source))  # export * from "./x"
                continue
            return None  # export = ...
        elif node.type == "expression_statement" and node.named_children:
            assignment = node.named_children[0]
            if assignment.type != "assignment_expression":
                continue
            left = _text(assignment.child_by_field_name("left"))
            if left == "module.exports":
                exported = _cjs_object(root, assignment.child_by_field_name("right"))
                if exported is None:
                    return None
                for child in exported.named_children:
                    if child.type == "pair":
                        key = child.child_by_field_name("key")
                        if key is None or key.type not in {
                            "property_identifier",
                            "string",
                        }:
                            return None
                        names.add(
                            _string_value(key) if key.type == "string" else _text(key)
                        )
                    elif child.type in {
                        "shorthand_property_identifier",
                        "method_definition",
                    }:
                        name = child.child_by_field_name("name")
                        names.add(_text(name if name is not None else child))
                    elif child.type != "comment":
                        return None
            elif left.startswith(("module.exports.", "exports.")):
                names.add(left.rsplit(".", 1)[-1])
    return names, stars


def _cjs_object(root, value):
    """The object literal ``module.exports`` is set to: written in place, or
    a top-level constant (``const codes = {...}; module.exports = codes``)."""
    if value is None:
        return None
    if value.type == "object":
        return value
    if value.type != "identifier":
        return None
    name = _text(value)
    for node in root.named_children:
        if node.type not in {"lexical_declaration", "variable_declaration"}:
            continue
        for declarator in node.named_children:
            target = declarator.child_by_field_name("name")
            if target is not None and _text(target) == name:
                found = declarator.child_by_field_name("value")
                return found if found is not None and found.type == "object" else None
    return None


def _definitions(root) -> dict[str, list[str]]:
    """Top-level functions, classes and variables (exported or not): name
    to the tokens of the definition."""
    found: dict[str, list[str]] = {}
    for node in root.named_children:
        target = (
            node.child_by_field_name("declaration")
            if node.type == "export_statement"
            else node
        )
        if target is None:
            continue
        if target.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in target.named_children:
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if name is not None and name.type == "identifier":
                    found[_text(name)] = (
                        _body_tokens(value) if value is not None else []
                    )
        elif target.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "abstract_class_declaration",
        }:
            name = target.child_by_field_name("name")
            body = target.child_by_field_name("body")
            if name is not None:
                found[_text(name)] = _body_tokens(body) if body is not None else []
        elif target.type == "expression_statement" and target.named_children:
            assignment = target.named_children[0]
            if (
                assignment.type == "assignment_expression"
                and _text(assignment.child_by_field_name("left")) == "module.exports"
            ):
                # module.exports = { name: value }: each key is a definition.
                exported = _cjs_object(root, assignment.child_by_field_name("right"))
                for child in exported.named_children if exported is not None else ():
                    key = child.child_by_field_name(
                        "key" if child.type == "pair" else "name"
                    )
                    value = child.child_by_field_name(
                        "value" if child.type == "pair" else "body"
                    )
                    if key is not None and value is not None:
                        found.setdefault(
                            _string_value(key) if key.type == "string" else _text(key),
                            _body_tokens(value),
                        )
    return found


def _similar(first: list[str], second: list[str]) -> bool:
    if not first or not second:
        return False
    matcher = difflib.SequenceMatcher(None, first, second, autojunk=False)
    return (
        matcher.real_quick_ratio() >= RENAME_SIMILARITY
        and matcher.quick_ratio() >= RENAME_SIMILARITY
        and matcher.ratio() >= RENAME_SIMILARITY
    )


def _top_level_strings(root) -> dict[str, str]:
    """``const NAME = "literal"`` at the top of a file, assigned once."""
    strings: dict[str, str] = {}
    for node in root.named_children:
        if node.type != "lexical_declaration" or not node.children:
            continue
        if node.children[0].type != "const":
            continue
        for declarator in node.named_children:
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                text = _static_title(value)
                if text is not None:
                    strings[_text(name)] = text
    return strings


def _top_level_read_paths(root) -> dict[str, list[str]]:
    """``const form = await readFile(new URL("../src/Form.tsx", ...))`` at the
    top of a file: name to the path-like strings its value is built from,
    so a test that uses ``form`` reads that file."""
    found: dict[str, list[str]] = {}
    for node in root.named_children:
        if node.type != "lexical_declaration":
            continue
        for declarator in node.named_children:
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None or name.type != "identifier" or value is None:
                continue
            paths = [
                _string_value(child)
                for child in _descendants(value)
                if child.type == "string" and "/" in _string_value(child)
            ]
            if paths and any(
                child.type == "call_expression" for child in _descendants(value)
            ):
                found[_text(name)] = paths
    return found


def _top_level_functions(root) -> dict[str, list]:
    """Top-level function declarations and ``const f = () => ...``: name to
    bodies."""
    functions: dict[str, list] = {}
    for node in root.named_children:
        target = (
            node.child_by_field_name("declaration")
            if node.type == "export_statement"
            else node
        )
        if target is None:
            continue
        if target.type in {"function_declaration", "generator_function_declaration"}:
            name = target.child_by_field_name("name")
            body = target.child_by_field_name("body")
            if name is not None and body is not None:
                functions.setdefault(_text(name), []).append(body)
        elif target.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in target.named_children:
                name = declarator.child_by_field_name("name")
                value = declarator.child_by_field_name("value")
                if (
                    name is not None
                    and name.type == "identifier"
                    and value is not None
                    and value.type in _FUNCTIONS
                ):
                    body = value.child_by_field_name("body")
                    if body is not None:
                        functions.setdefault(_text(name), []).append(body)
    return functions


def _string_constant(node, strings: dict[str, str]) -> str | None:
    """A string literal, or a template whose ``${...}`` are top-level
    string constants."""
    if node is None:
        return None
    if node.type == "string":
        return _string_value(node)
    if node.type == "identifier":
        return strings.get(_text(node))
    if node.type != "template_string":
        return None
    parts = []
    for child in node.named_children:
        if child.type == "string_fragment":
            parts.append(_text(child))
        elif child.type == "escape_sequence":
            parts.append(_unescape(_text(child)))
        elif child.type == "template_substitution":
            inner = child.named_children[0] if child.named_children else None
            value = strings.get(_text(inner)) if inner is not None else None
            if inner is None or inner.type != "identifier" or value is None:
                return None
            parts.append(value)
    return _well_formed("".join(parts))


def _route_of(path: str) -> tuple[str, ...] | None:
    """URL segments of a Next.js app-router page or route handler, or a
    pages-router page (``[id]`` segments are dynamic)."""
    pure = PurePosixPath(path)
    if pure.suffix not in _PAGE_SUFFIXES:
        return None
    parts = pure.parts
    stem = pure.stem
    if "app" in parts and stem in {"page", "route"}:
        index = len(parts) - 1 - parts[::-1].index("app")
        segments = parts[index + 1 : -1]
    elif "pages" in parts and not stem.startswith("_"):
        index = len(parts) - 1 - parts[::-1].index("pages")
        segments = parts[index + 1 : -1] + (() if stem == "index" else (stem,))
    else:
        return None
    return tuple(
        segment
        for segment in segments
        if not (segment.startswith("(") and segment.endswith(")"))
        and not segment.startswith("@")
    )


def _url_segments(url: str | None) -> tuple[str, ...] | None:
    if not url:
        return None
    if "://" in url:
        url = "/" + url.split("://", 1)[1].partition("/")[2]
    if not url.startswith("/"):
        return None
    path = url.split("?", 1)[0].split("#", 1)[0]
    return tuple(segment for segment in path.split("/") if segment)


def _route_matches(route: tuple[str, ...], segments: tuple[str, ...]) -> bool:
    for index, part in enumerate(route):
        if part.startswith("[[...") or part.startswith("[..."):
            return len(segments) >= index + (0 if part.startswith("[[") else 1)
        if index >= len(segments):
            return False
        if not (part.startswith("[") or part == segments[index]):
            return False
    return len(segments) == len(route)


def _require_spec(node) -> str | None:
    if node is None or node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if function is None or _text(function) != "require" or arguments is None:
        return None
    items = _args(arguments)
    if len(items) == 1 and items[0].type == "string":
        return _string_value(items[0])
    return None


def _resolve(importer: str, spec: str) -> set[str]:
    """Repository paths a relative import (or the common ``@/`` alias for
    ``src/`` or the repository root, or for the ``src/`` directory of the
    package the importer lives in) may name."""
    if spec.startswith("@/"):
        bases = {posixpath.normpath("src/" + spec[2:]), posixpath.normpath(spec[2:])}
        parts = importer.split("/")
        if "src" in parts[:-1]:
            package_src = "/".join(parts[: parts.index("src") + 1])
            bases.add(posixpath.normpath(f"{package_src}/{spec[2:]}"))
    elif spec.startswith("."):
        bases = {posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))}
    else:
        return set()
    candidates: set[str] = set()
    for base in bases:
        if base == ".." or base.startswith("../"):
            continue
        candidates |= _variants(base)
    return candidates


def _variants(base: str) -> set[str]:
    """The files an import of ``base`` may load."""
    candidates = {base}
    stem, ext = posixpath.splitext(base)
    if ext in {".js", ".jsx", ".mjs", ".cjs"}:
        # TypeScript ESM imports name the compiled .js file.
        candidates.update(stem + suffix for suffix in (".ts", ".tsx", ".mts", ".cts"))
    candidates.update(base + suffix for suffix in JS_SUFFIXES)
    candidates.update(f"{base}/index{suffix}" for suffix in JS_SUFFIXES)
    return candidates


def _export_targets(entry) -> list[str]:
    """Files a package.json ``exports`` entry names, in condition order,
    without type declarations."""
    if isinstance(entry, str):
        return [] if entry.endswith((".d.ts", ".d.mts", ".d.cts")) else [entry]
    if isinstance(entry, list):
        return [target for item in entry for target in _export_targets(item)]
    if isinstance(entry, dict):
        return [
            target
            for key, value in entry.items()
            if key not in {"types", "typings"}
            for target in _export_targets(value)
        ]
    return []


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse(path: str, source: str):
    """Root node of a JS/TS file, or None when no grammar is available."""
    try:
        from skylos.visitors.languages.typescript.core import (
            TS_LANG,
            TSX_LANG,
            _get_parser,
            _parse_tsx_with_raw_ampersands,
        )
    except ImportError:  # pragma: no cover - tree-sitter is a core dependency
        return None
    data = source.encode("utf-8", errors="surrogatepass")
    jsx = path.endswith(_TSX_SUFFIXES)
    order = [(TSX_LANG, True), (TS_LANG, False)] if jsx else [(TS_LANG, False)]
    first = None
    for language, tsx in order:
        if language is None:
            continue
        parser = _get_parser(language)
        tree = (
            _parse_tsx_with_raw_ampersands(parser, data) if tsx else parser.parse(data)
        )
        if not tree.root_node.has_error:
            return tree.root_node
        first = first or tree.root_node
    return first


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _args(arguments) -> list:
    return [child for child in arguments.named_children if child.type != "comment"]


def _descendants(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _string_value(node) -> str:
    parts = []
    for child in node.children:
        if child.type == "string_fragment":
            parts.append(_text(child))
        elif child.type == "escape_sequence":
            parts.append(_unescape(_text(child)))
    return _well_formed("".join(parts))


def _well_formed(text: str) -> str:
    """Join escaped surrogate pairs (``"\\ud83d\\ude00"``) into one character
    and replace lone surrogates, so the text always encodes as UTF-8."""
    if not any("\ud800" <= char <= "\udfff" for char in text):
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _unescape(sequence: str) -> str:
    body = sequence[1:]
    if body.startswith(("\n", "\r")):
        return ""  # line continuation
    if body[:1] in _ESCAPES and len(body) == 1:
        return _ESCAPES[body]
    if body[:1] in {"u", "x"}:
        digits = body[1:].strip("{}")
        try:
            return chr(int(digits, 16))
        except ValueError:
            return body
    return body


def _static_title(node) -> str | None:
    """A title written as a string literal (no ``${...}``), else None."""
    if node is None:
        return None
    if node.type == "string":
        return _string_value(node)
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.children):
            return None
        return _string_value(node)
    return None


def _callee(node) -> tuple[str, list[tuple[str, object]]] | None:
    """``it.skip.each(table)`` to ("it", [("skip", None), ("each", table)])."""
    members: list[tuple[str, object]] = []
    while node is not None:
        if node.type == "call_expression":
            inner = node.child_by_field_name("function")
            if inner is None or inner.type != "member_expression":
                return None
            prop = inner.child_by_field_name("property")
            if prop is None or prop.type != "property_identifier":
                return None
            members.append((_text(prop), node.child_by_field_name("arguments")))
            node = inner.child_by_field_name("object")
        elif node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None or prop.type != "property_identifier":
                return None
            members.append((_text(prop), None))
            node = node.child_by_field_name("object")
        elif node.type == "identifier":
            members.reverse()
            return _text(node), members
        else:
            return None
    return None


@dataclass
class _Decl:
    kind: str  # "test" or "describe"
    markers: set[str]
    focus: str | None
    params: tuple[bool, int | None]
    title: str | None  # None when computed
    title_text: str
    callback: object | None


def _classify(
    call, subtest_of: str | bool | None = None, harness: frozenset[str] = frozenset()
):
    """("decl", _Decl), ("modifier", marker) or None for other calls.

    With ``subtest_of``, only a node:test subtest counts: ``t.test(title,
    fn)`` on that context name (on any name when it is True). ``harness``
    names the file's own test functions (``t(title, fn)``, see ``_harness``).
    """
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    if function is None or arguments is None or arguments.type != "arguments":
        return None
    decoded = _callee(function)
    if subtest_of is None and decoded and decoded[0] in harness and not decoded[1]:
        decoded = ("test", [])
    if subtest_of is not None:
        if (
            decoded is None
            or decoded[0] in _ROOTS
            or (subtest_of is not True and decoded[0] != subtest_of)
            or not decoded[1]
            or decoded[1][0] != ("test", None)
        ):
            return None
        decoded = ("test", decoded[1][1:])
    if decoded is None or decoded[0] not in _ROOTS:
        return None
    root, members = decoded
    kind, root_marker = _ROOTS[root]
    call_text = ".".join([root, *(name for name, _ in members)])
    markers: set[str] = set()
    focus = call_text if root_marker == "focus" else None
    if root_marker == "skip":
        markers.add("skip")
    params: tuple[bool, int | None] = (False, None)
    names = [name for name, _ in members]
    for index, (name, args) in enumerate(members):
        if name == "describe" and root == "test" and index == 0:
            kind = "describe"  # Playwright: test.describe(...)
        elif name in _MEMBER_MARKERS and args is None:
            markers.add(_MEMBER_MARKERS[name])
        elif name == "only" and args is None:
            focus = call_text
        elif name in _CONDITIONAL and args is not None:
            markers.add(name)
        elif name in _EACH and args is not None:
            params = _combine_params(params, (True, _table_cases(args)))
        elif name in _NEUTRAL and args is None:
            continue
        else:
            return None

    items = _args(arguments)
    if kind == "test" and len(names) == 1 and names[0] in _MODIFIERS:
        if _is_modifier_call(items):
            # test.skip(), test.fixme(condition, reason): a Playwright modifier
            # for the test, describe block or file it is called in.
            return "modifier", f"{names[0]}()"
    title_node = items[0] if items and items[0].type not in _FUNCTIONS else None
    rest = items[1:] if title_node is not None else items
    callback = None
    for item in rest:
        if item.type == "object":
            for key in _option_flags(item):
                if key == "only":
                    focus = focus or "{ only: true }"
                else:
                    markers.add(key)
        elif item.type != "number" and callback is None:
            callback = item
    title = _static_title(title_node)
    if callback is None and (kind == "describe" or not _stringish(title_node)):
        return None
    return "decl", _Decl(
        kind=kind,
        # A test declared without a callback is pending (Mocha) or todo (Vitest).
        markers=(
            markers
            if callback is not None or "todo" in markers
            else markers | {"pending"}
        ),
        focus=focus,
        params=params,
        title=title,
        title_text=_text(title_node) if title_node is not None else "",
        callback=callback,
    )


def _harness(root) -> frozenset[str]:
    """The file's own test functions: a top-level ``function t(name, fn)``
    (or ``const t = (name, fn) => ...``) that calls its second parameter,
    as a hand-written ``node:assert`` runner does. One that catches the
    failure counts only when the file sets the exit code
    (``process.exit``/``process.exitCode``): otherwise a failing test
    could not fail the run."""
    sets_exit = None
    found = set()
    for node in root.named_children:
        for name, function in _top_level_function_nodes(node):
            if name in _ROOTS or name in _HOOKS:
                continue
            params = function.child_by_field_name("parameters")
            names = [
                _text(p)
                for p in (params.named_children if params is not None else ())
                if p.type == "identifier"
                or (p.type == "required_parameter" and p.named_children)
            ]
            names = [n.split(":", 1)[0].strip() for n in names]
            if len(names) < 2:
                continue
            body = function.child_by_field_name("body")
            if body is None or not _calls_name(body, names[1]):
                continue
            if any(n.type == "catch_clause" for n in _descendants(body)):
                if sets_exit is None:
                    text = _text(root)
                    sets_exit = "process.exit" in text
                if not sets_exit:
                    continue
            found.add(name)
    return frozenset(found)


def _top_level_function_nodes(node):
    if node.type in {"function_declaration", "generator_function_declaration"}:
        name = node.child_by_field_name("name")
        if name is not None:
            yield _text(name), node
    elif node.type in {"lexical_declaration", "variable_declaration"}:
        for declarator in node.named_children:
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if (
                name is not None
                and name.type == "identifier"
                and value is not None
                and value.type in _FUNCTIONS
            ):
                yield _text(name), value


def _calls_name(body, name: str) -> bool:
    for node in _descendants(body):
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and function.type == "identifier":
                if _text(function) == name:
                    return True
    return False


def _stringish(node) -> bool:
    return node is not None and node.type in {"string", "template_string"}


def _is_modifier_call(items: list) -> bool:
    """``test.skip()``, ``test.skip(condition[, reason])`` and
    ``test.skip(({ browserName }) => ..., reason)``, not ``test.skip(title, fn)``
    with a literal or computed title (``it.skip(c.name, fn)``)."""
    if not items:
        return True
    first = items[0]
    if first.type in _FUNCTIONS:
        return len(items) >= 2 and _stringish(items[1])
    if any(item.type in _FUNCTIONS for item in items[1:]):
        return False  # (title, fn) or (title, options, fn): a declaration
    return not _stringish(first)


def _option_flags(node):
    """``{ skip: true }``/``{ todo }``/``{ only: true }`` (node:test options)."""
    for child in node.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            name = (
                _string_value(key)
                if key is not None and key.type == "string"
                else _text(key)
            )
            if name in {"skip", "todo", "only"} and value is not None:
                if value.type not in {"false", "null", "undefined"}:
                    yield name
        elif child.type == "shorthand_property_identifier":
            name = _text(child)
            if name in {"skip", "todo", "only"}:
                yield name


def _table_cases(args) -> int | None:
    """Literal case count of an ``.each`` table, else None."""
    if args.type == "template_string":
        # Tagged template table: a header row, then one row per case.
        rows = [row for row in _text(args)[1:-1].splitlines() if row.strip()]
        return len(rows) - 1 if len(rows) > 1 else None
    items = _args(args)
    if len(items) != 1 or items[0].type != "array":
        return None
    elements = [child for child in items[0].named_children if child.type != "comment"]
    if any(child.type == "spread_element" for child in elements):
        return None
    return len(elements)


def _combine_params(first, second) -> tuple[bool, int | None]:
    if not first[0]:
        return second
    if not second[0]:
        return first
    return True, None if first[1] is None or second[1] is None else first[1] * second[1]


def _context_names(callback) -> tuple[dict[str, frozenset[str]], frozenset[str]]:
    """What a test callback receives that can skip it: context objects and
    the calls on them that count (``t.skip()``/``ctx.skip()`` on the first
    parameter, Playwright's ``testInfo.skip()/fixme()/fail()`` on a later
    one), and a destructured ``skip`` function (``({ skip }) => skip()``).

    ``fail`` on the first parameter is Jasmine's ``done.fail(error)``, which
    fails the test rather than expecting a failure.
    """
    if callback is None or callback.type not in _FUNCTIONS:
        return {}, frozenset()
    single = callback.child_by_field_name("parameter")
    if single is not None:
        return {_text(single): _FIRST_CONTEXT_CALLS}, frozenset()
    parameters = callback.child_by_field_name("parameters")
    context: dict[str, frozenset[str]] = {}
    skips: set[str] = set()
    for index, parameter in enumerate(
        parameters.named_children if parameters is not None else ()
    ):
        pattern = parameter.child_by_field_name("pattern") or parameter
        if pattern.type == "identifier":
            context[_text(pattern)] = (
                _FIRST_CONTEXT_CALLS if index == 0 else _INFO_CONTEXT_CALLS
            )
        elif pattern.type == "object_pattern":
            for child in pattern.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    if _text(child) == "skip":
                        skips.add("skip")
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    value = child.child_by_field_name("value")
                    if _text(key) == "skip" and value is not None:
                        if value.type == "identifier":
                            skips.add(_text(value))
    return context, frozenset(skips)


def _body_tokens(node) -> list[str]:
    """Tokens of a test body, without comments or formatting choices
    (quote style, semicolons, trailing commas, parentheses around arrow
    parameters and around JSX)."""
    tokens: list[str] = []
    stack = [(node, "")]
    while stack:
        current, parent = stack.pop()
        kind = current.type
        if kind == "comment":
            continue
        if kind == "string":
            tokens.append('"' + _string_value(current) + '"')
            continue
        if current.child_count == 0:
            text = _text(current)
            if kind == "jsx_text":
                text = " ".join(text.split())
                if not text:
                    continue
            elif text == ";":
                continue
            elif text in {"(", ")"} and parent in {"formal_parameters", "jsx_parens"}:
                continue
            tokens.append(text)
            continue
        label = kind
        if kind == "parenthesized_expression" and any(
            child.type.startswith("jsx_") for child in current.named_children
        ):
            label = "jsx_parens"
        stack.extend((child, label) for child in reversed(current.children))
    return [
        token
        for index, token in enumerate(tokens)
        if not (
            token == ","
            and index + 1 < len(tokens)
            and tokens[index + 1] in {")", "]", "}"}
        )
    ]


class _Scope:
    __slots__ = (
        "kind",
        "parent",
        "titles",
        "markers",
        "modifiers",
        "params",
        "context",
        "skip_names",
        "title",
    )

    def __init__(
        self,
        kind: str,
        parent: _Scope | None,
        titles: tuple[str, ...],
        markers: set[str],
        params: tuple[bool, int | None],
        context: dict[str, frozenset[str]] | None = None,
        skip_names: frozenset[str] = frozenset(),
        title: str = "",
    ) -> None:
        self.title = title
        self.kind = kind
        self.parent = parent
        self.titles = titles
        self.markers = markers
        self.modifiers: set[str] = set()
        self.params = params
        self.context = context or {}
        self.skip_names = skip_names


class _Collector:
    def __init__(
        self,
        path: str,
        helpers: set[str] | None = None,
        defined: set[str] | None = None,
        harness: frozenset[str] = frozenset(),
    ) -> None:
        self.path = path
        self.helpers = helpers or set()
        self.defined = defined or set()
        self.harness = harness
        self.records: list[tuple[_Scope, _Decl, object]] = []
        self.focus: list[FocusSite] = []

    def walk(self, root) -> None:
        file_scope = _Scope("file", None, (), set(), (False, None))
        # (node, scope, the scope whose callback owns ``this`` here)
        stack: list[tuple[object, _Scope, _Scope | None]] = [(root, file_scope, None)]
        while stack:
            node, scope, this_scope = stack.pop()
            if node.type == "comment":
                continue
            if node.type == "call_expression" and self._call(
                node, scope, this_scope, stack
            ):
                continue
            if node.type in _THIS_BINDERS:
                this_scope = None
            stack.extend(
                (child, scope, this_scope) for child in reversed(node.named_children)
            )

    def _call(self, node, scope: _Scope, this_scope, stack) -> bool:
        classified = _classify(node, harness=self.harness)
        subtest = False
        if classified is None and scope.kind == "test":
            # node:test: t.test(title, fn) on the test's context is a subtest.
            context = next(
                (
                    name
                    for name, calls in scope.context.items()
                    if calls is _FIRST_CONTEXT_CALLS
                ),
                None,
            )
            if context is not None:
                classified = _classify(node, context)
                subtest = classified is not None and classified[0] == "decl"
                if not subtest:
                    classified = None
        if classified is None:
            self._runtime_skip(node, scope, this_scope)
            return self._hook(node, scope, this_scope, stack)
        if classified[0] == "modifier":
            scope.modifiers.add(classified[1])
            return True
        decl: _Decl = classified[1]
        own_title = decl.title if decl.title is not None else decl.title_text
        if decl.kind == "describe":
            titles = (*scope.titles, own_title)
        elif subtest:
            titles = (*scope.titles, scope.title)
            decl.focus = None  # only with --test-only; never recorded
        else:
            titles = scope.titles
        context, skip_names = (
            _context_names(decl.callback) if decl.kind == "test" else ({}, frozenset())
        )
        child = _Scope(
            decl.kind,
            scope,
            titles,
            set(decl.markers),
            decl.params,
            context,
            skip_names,
            own_title,
        )
        if decl.kind == "test":
            self.records.append((child, decl, node))
        body = _callback_body(decl.callback)
        if decl.focus:
            self.focus.append(
                FocusSite(
                    self.path,
                    node.start_point[0] + 1,
                    decl.focus,
                    (*scope.titles, own_title),
                    _hash(body) if body is not None else "",
                )
            )
        if decl.callback is not None:
            owner = (
                child
                if decl.callback.type in _FUNCTIONS
                and decl.callback.type != "arrow_function"
                else this_scope
            )
            stack.append((body, child, owner))
        return True

    def _hook(self, node, scope: _Scope, this_scope, stack) -> bool:
        """``beforeEach(function () { this.skip() })`` skips the scope's tests."""
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or arguments.type != "arguments":
            return False
        name = _text(function).rsplit(".", 1)[-1]
        if name not in _HOOKS:
            return False
        for item in reversed(_args(arguments)):
            if item.type in _FUNCTIONS:
                owner = scope if item.type != "arrow_function" else this_scope
                stack.append((_callback_body(item), scope, owner))
            else:
                stack.append((item, scope, this_scope))
        return True

    def _runtime_skip(self, node, scope: _Scope, this_scope) -> None:
        function = node.child_by_field_name("function")
        if function is None:
            return
        test = scope
        while test is not None and test.kind != "test":
            test = test.parent
        if function.type == "member_expression":
            target = function.child_by_field_name("object")
            prop = _text(function.child_by_field_name("property"))
            if target is None:
                return
            if target.type == "this" and prop == "skip" and this_scope is not None:
                this_scope.modifiers.add("skip()")  # Mocha
            elif (
                target.type == "identifier"
                and test is not None
                and prop in test.context.get(_text(target), ())
            ):
                test.modifiers.add(f"{prop}()")  # node:test, Vitest, Playwright
        elif function.type == "identifier" and test is not None:
            if _text(function) in test.skip_names:
                test.modifiers.add("skip()")  # Vitest: ({ skip }) => skip()

    def finish(self) -> JsInventory:
        inventory = JsInventory(focus=self.focus)
        seen: dict[tuple[tuple[str, ...], str], int] = {}
        for scope, decl, node in self.records:
            if decl.title is None:
                continue  # computed title: not inventoried
            markers = set(scope.markers) | scope.modifiers
            params = scope.params
            ancestor = scope.parent
            while ancestor is not None:
                if ancestor.kind == "describe":
                    markers |= {
                        f"describe {m}" for m in ancestor.markers | ancestor.modifiers
                    }
                    params = _combine_params(ancestor.params, params)
                elif ancestor.kind == "test":
                    # A subtest of a skipped test never runs.
                    markers |= {f"parent {m}" for m in ancestor.markers}
                elif ancestor.kind == "file":
                    markers |= {f"file {m}" for m in ancestor.modifiers}
                ancestor = ancestor.parent
            key = (scope.titles, decl.title)
            seen[key] = seen.get(key, 0) + 1
            name = decl.title if seen[key] == 1 else f"{decl.title} [{seen[key]}]"
            body = _callback_body(decl.callback)
            if body is not None:
                tokens = _body_tokens(body)
                dump = " ".join(tokens)
            else:
                dump = ""
            digest_source = dump if body is not None else f"pending\0{decl.title}"
            inventory.tests.append(
                JsTestItem(
                    path=self.path,
                    classes=scope.titles,
                    name=name,
                    line=node.start_point[0] + 1,
                    body_hash=_digest(digest_source),
                    body_dump=dump,
                    markers=frozenset(markers),
                    param_cases=params[1] if params[0] else None,
                    end_line=node.end_point[0] + 1,
                    parametrized=params[0],
                    has_body=body is not None,
                    assertions=_test_assertions(
                        decl.callback, self.helpers, self.defined
                    ),
                    early_returns=_early_returns(
                        decl.callback, self.helpers, self.defined
                    ),
                )
            )
        return inventory


# ---------------------------------------------------------------------------
# Counting assertions
# ---------------------------------------------------------------------------

# ava/tap/uvu-style assertions on a test's context: t.is(), t.deepEqual().
_CONTEXT_ASSERTIONS = frozenset(
    {
        "is",
        "not",
        "deepEqual",
        "notDeepEqual",
        "like",
        "true",
        "false",
        "truthy",
        "falsy",
        "ok",
        "notOk",
        "equal",
        "equals",
        "notEqual",
        "strictEqual",
        "notStrictEqual",
        "same",
        "notSame",
        "strictSame",
        "strictNotSame",
        "throws",
        "throwsAsync",
        "notThrows",
        "notThrowsAsync",
        "rejects",
        "resolves",
        "doesNotThrow",
        "doesNotReject",
        "match",
        "notMatch",
        "regex",
        "notRegex",
        "snapshot",
        "matchSnapshot",
        "fail",
        "error",
        "ifError",
        "has",
        "hasStrict",
        "type",
        "plan",
    }
)
# Chai property assertions: expect(x).to.be.true
_CHAI_TERMINALS = frozenset(
    {
        "true",
        "false",
        "null",
        "undefined",
        "ok",
        "empty",
        "exist",
        "NaN",
        "finite",
        "extensible",
        "sealed",
        "frozen",
        "arguments",
    }
)
# Names the helper pattern matches that are actions, not checks.
_NOT_HELPERS = frozenset({"expect", "check", "uncheck", "setChecked", "isChecked"})
# Testing Library queries that throw when nothing matches.
_THROWING_QUERY_RE = re.compile(r"^(?:getBy|getAllBy|findBy|findAllBy)[A-Z]")
_LITERALS = {
    "true",
    "false",
    "null",
    "undefined",
    "number",
    "string",
    "regex",
}


# Matchers that hold when the value is compared with itself: expect(r).toBe(r).
_REFLEXIVE_MATCHERS = frozenset(
    {
        "toBe",
        "toEqual",
        "toStrictEqual",
        "toMatchObject",
        "toBeGreaterThanOrEqual",
        "toBeLessThanOrEqual",
        "equal",
        "equals",
        "eq",
        "eql",
        "least",
        "most",
        "gte",
        "lte",
    }
)
_REFLEXIVE_OPERATORS = frozenset({"===", "==", ">=", "<="})
# Built-ins that return the same value for the same literal arguments:
# expect(Number(1)).toBe(1) checks nothing.
_PURE_FUNCTIONS = frozenset(
    {
        "Number",
        "String",
        "Boolean",
        "BigInt",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "encodeURI",
        "encodeURIComponent",
        "decodeURI",
        "decodeURIComponent",
    }
)
_PURE_OBJECTS = frozenset(
    {"Math", "JSON", "Number", "String", "Object", "Array", "Promise", "BigInt"}
)
_PURE_CONSTRUCTORS = frozenset(
    {"Number", "String", "Boolean", "Array", "Set", "Map", "Date", "Error", "RegExp"}
)
# Calls in a catch block that pass the failure on.
_PASS_ON = frozenset({"done", "reject", "fail", "next", "callback", "cb"})
_DECLARATIONS = frozenset({"function_declaration", "generator_function_declaration"})
# Code inside these runs only when called; never part of the test's own flow.
_NESTED = _FUNCTIONS | _DECLARATIONS | {"class_declaration", "method_definition"}
_COMPARISONS = {
    "===": lambda a, b: a == b,
    "!==": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
}


def _assertion_helpers(root) -> tuple[set[str], set[str]]:
    """Functions and methods in the file that assert (or throw), directly or
    through each other: a test that calls one still checks something. Also
    returns every function name the file defines: a helper named like an
    assertion (``checkResult``) that is defined here and asserts nothing
    checks nothing."""
    functions: dict[str, list] = {}
    for node in _descendants(root):
        name = body = None
        if node.type in {
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
        }:
            name = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
        elif node.type in {"variable_declarator", "pair"}:
            name = node.child_by_field_name(
                "name" if node.type == "variable_declarator" else "key"
            )
            value = node.child_by_field_name("value")
            if value is not None and value.type in _FUNCTIONS:
                body = value.child_by_field_name("body")
        if (
            name is not None
            and body is not None
            and name.type
            in {
                "identifier",
                "property_identifier",
            }
        ):
            functions.setdefault(_text(name), []).append(body)
    defined = set(functions)
    helpers: set[str] = set()
    for _ in range(5):
        found = {
            name
            for name, bodies in functions.items()
            if name not in helpers
            and any(
                _count_assertions(body, helpers, None, defined, helper=True)
                for body in bodies
            )
        }
        if not found:
            break
        helpers |= found
    return helpers, defined


def _test_assertions(
    callback, helpers: set[str], defined: set[str] | frozenset[str] = frozenset()
) -> int | None:
    """Assertions a test callback makes; None when it cannot be told."""
    if callback is None:
        return None
    if callback.type in _FUNCTIONS:
        body = callback.child_by_field_name("body") or callback
        return _count_assertions(body, helpers, _first_parameter(callback), defined)
    if callback.type == "identifier" and _text(callback) in helpers:
        return 1
    return None


def _early_returns(
    callback, helpers: set[str], defined: set[str] | frozenset[str] = frozenset()
) -> tuple[int, ...]:
    """Lines of ``return`` statements in the test itself (not in a callback
    it passes on) with an assertion after them:
    ``if (process.env.CI) return;``."""
    if callback is None or callback.type not in _FUNCTIONS:
        return ()
    body = callback.child_by_field_name("body")
    if body is None or body.type != "statement_block":
        return ()
    context = _first_parameter(callback)
    last = max(
        (
            node.start_byte
            for node in _descendants(body)
            if (
                node.type == "call_expression"
                and _is_assertion_call(node, helpers, context, defined)
            )
            or (node.type == "member_expression" and _is_property_assertion(node))
        ),
        default=None,
    )
    if last is None:
        return ()
    lines = []
    stack = list(body.named_children)
    while stack:
        node = stack.pop()
        if node.type in _NESTED:
            continue
        if node.type == "return_statement" and node.end_byte <= last:
            lines.append(node.start_point[0] + 1)
        stack.extend(node.named_children)
    return tuple(sorted(lines))


def _first_parameter(callback) -> str | None:
    single = callback.child_by_field_name("parameter")
    if single is not None:
        return _text(single) if single.type == "identifier" else None
    parameters = callback.child_by_field_name("parameters")
    if parameters is None or not parameters.named_children:
        return None
    first = parameters.named_children[0]
    pattern = first.child_by_field_name("pattern") or first
    return _text(pattern) if pattern.type == "identifier" else None


def _count_assertions(
    node,
    helpers: set[str],
    context: str | None,
    defined: set[str] | frozenset[str] = frozenset(),
    *,
    helper: bool = False,
) -> int:
    """``expect(...)`` with a matcher, ``assert``/``assert.*``, assertions on
    the test context (``t.is``), ``expect.assertions``, should.js, throwing
    Testing Library queries and calls to asserting helpers (and, in a
    ``helper``, ``throw``), outside code that cannot run: after ``return`` or
    ``throw`` (also inside ``if (true)``), under ``if (false)``/``if (1 >
    2)``, in a ``try`` whose ``catch`` swallows the failure, in a nested
    function that is never called. A tautology checks nothing:
    ``expect(true).toBe(true)``, ``expect(Number(1)).toBe(1)``,
    ``expect(r).toBe(r)``, ``assert(x === x)``."""
    dead = _uncalled_functions(node)
    count = 0
    stack = [node]
    while stack:
        current = stack.pop()
        kind = current.type
        if kind == "comment" or current.id in dead:
            continue
        if kind == "statement_block":
            for child in current.named_children:
                stack.append(child)
                if _terminates(child):
                    break  # what follows never runs
            continue
        if kind in {"if_statement", "while_statement"}:
            truth = _truth(current.child_by_field_name("condition"))
            if truth is False:
                alternative = current.child_by_field_name("alternative")
                if kind == "if_statement" and alternative is not None:
                    stack.append(alternative)
                continue
            if truth is True and kind == "if_statement":
                consequence = current.child_by_field_name("consequence")
                if consequence is not None:
                    stack.append(consequence)
                continue
        elif kind == "try_statement":
            handler = current.child_by_field_name("handler")
            body = current.child_by_field_name("body")
            if (
                handler is not None
                and body is not None
                and _swallows(handler, helpers, context, defined)
            ):
                # A failed assertion in the try block is caught and dropped.
                stack.extend(
                    child for child in current.named_children if child.id != body.id
                )
                continue
        elif kind == "throw_statement":
            if helper:
                count += 1
        elif kind == "call_expression":
            if _is_assertion_call(current, helpers, context, defined):
                count += 1
        elif kind == "member_expression":
            if _is_property_assertion(current):
                count += 1
        stack.extend(current.named_children)
    return count


def _uncalled_functions(body) -> set[int]:
    """Functions inside ``body`` that never run: a declaration or a
    ``const f = () => ...`` whose name is never used, or a function standing
    alone as a statement."""
    uses: dict[str, int] = {}
    functions = []
    for node in _descendants(body):
        if node.type in {"identifier", "shorthand_property_identifier"}:
            text = _text(node)
            uses[text] = uses.get(text, 0) + 1
        elif node.id != body.id and (
            node.type in _FUNCTIONS or node.type in _DECLARATIONS
        ):
            functions.append(node)
    dead: set[int] = set()
    for node in functions:
        if node.type in _DECLARATIONS:
            name = node.child_by_field_name("name")
            if name is not None and uses.get(_text(name), 0) <= 1:
                dead.add(node.id)
            continue
        child, parent = node, node.parent
        while parent is not None and parent.type == "parenthesized_expression":
            child, parent = parent, parent.parent
        if parent is None:
            continue
        if parent.type == "expression_statement":
            dead.add(node.id)
        elif parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            value = parent.child_by_field_name("value")
            if (
                value is not None
                and value.id == child.id
                and name is not None
                and name.type == "identifier"
                and uses.get(_text(name), 0) <= 1
            ):
                dead.add(node.id)
    return dead


def _terminates(node) -> bool:
    """``return`` and ``throw``, also inside ``if (true)`` or both branches of
    an ``if``: the statements after it never run."""
    kind = node.type
    if kind in {"return_statement", "throw_statement"}:
        return True
    if kind == "statement_block":
        return any(_terminates(child) for child in node.named_children)
    if kind == "if_statement":
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        otherwise = next(
            (
                child
                for child in (
                    alternative.named_children if alternative is not None else ()
                )
                if child.type != "comment"
            ),
            None,
        )
        truth = _truth(node.child_by_field_name("condition"))
        if truth is True:
            return consequence is not None and _terminates(consequence)
        if truth is False:
            return otherwise is not None and _terminates(otherwise)
        return (
            consequence is not None
            and otherwise is not None
            and _terminates(consequence)
            and _terminates(otherwise)
        )
    return False


def _swallows(handler, helpers, context, defined) -> bool:
    """A catch block that neither rethrows nor fails the test."""
    body = handler.child_by_field_name("body")
    if body is None:
        return False
    for node in _descendants(body):
        if node.type == "throw_statement":
            return False
        if node.type == "call_expression":
            if _is_assertion_call(node, helpers, context, defined):
                return False
            function = node.child_by_field_name("function")
            name = _text(function)
            if name.rsplit(".", 1)[-1] in _PASS_ON or (context and name == context):
                return False
    return True


def _is_assertion_call(
    call,
    helpers: set[str],
    context: str | None,
    defined: set[str] | frozenset[str] = frozenset(),
) -> bool:
    function = call.child_by_field_name("function")
    arguments = call.child_by_field_name("arguments")
    args = (
        _args(arguments)
        if arguments is not None and arguments.type == "arguments"
        else []
    )
    if function is None:
        return False
    if function.type == "identifier":
        name = _text(function)
        if name == "assert":
            return not _checks_nothing(args)
        if name in helpers or _THROWING_QUERY_RE.match(name):
            return True
        if name in defined:
            return False  # defined in this file and asserts nothing
        return name not in _NOT_HELPERS and bool(ASSERTION_HELPER_RE.match(name))
    if function.type != "member_expression":
        return False
    names: list[str] = []  # outermost property first
    root = function
    while root.type == "member_expression":
        names.append(_text(root.child_by_field_name("property")))
        root = root.child_by_field_name("object")
    method = names[0]
    if root.type == "call_expression":
        callee = root.child_by_field_name("function")
        if _is_expect(callee):
            subject = _args(root.child_by_field_name("arguments"))
            if not subject or _is_literal(subject[0]) or _is_tautology(subject[0]):
                return False
            return not (
                method in _REFLEXIVE_MATCHERS
                and "not" not in names
                and args
                and _same_value(subject[0], args[0])
            )
        if _text(callee) == "within" and _THROWING_QUERY_RE.match(method):
            return True
    elif root.type == "identifier":
        owner = _text(root)
        if owner == "expect" and names[-1] in {"assertions", "hasAssertions"}:
            return True
        if owner == "assert" or "assert" in names:
            return not _checks_nothing(args)
        if "should" in names:
            return True
        if (
            context
            and owner == context
            and (names[-1] in _CONTEXT_ASSERTIONS or names[-1].startswith("assert"))
        ):
            return not _checks_nothing(args)
        if owner == "screen" and _THROWING_QUERY_RE.match(method):
            return True
    if method in helpers:
        return True
    return (
        method not in defined
        and method not in _NOT_HELPERS
        and bool(ASSERTION_HELPER_RE.match(method))
    )


def _checks_nothing(args: list) -> bool:
    """``assert(true)``, ``assert.equal(1, 1)``, ``assert.equal(x, x)``,
    ``assert(x === x)``."""
    return (
        _all_literal(args)
        or (len(args) >= 2 and _same_value(args[0], args[1]))
        or (bool(args) and _is_tautology(args[0]))
    )


def _is_property_assertion(member) -> bool:
    """``expect(x).to.be.true``: a Chai assertion without a call."""
    parent = member.parent
    if parent is not None and (
        parent.type == "member_expression"
        or (
            parent.type == "call_expression"
            and parent.child_by_field_name("function") == member
        )
    ):
        return False
    terminal = _text(member.child_by_field_name("property"))
    if terminal not in _CHAI_TERMINALS:
        return False
    root = member
    while root.type == "member_expression":
        root = root.child_by_field_name("object")
    if root.type != "call_expression" or not _is_expect(
        root.child_by_field_name("function")
    ):
        return False
    subject = _args(root.child_by_field_name("arguments"))
    return (
        bool(subject) and not _is_literal(subject[0]) and not _is_tautology(subject[0])
    )


def _is_expect(callee) -> bool:
    """``expect``, ``expect.soft``/``expect.poll`` and ``chai.expect``."""
    if callee is None:
        return False
    if callee.type == "identifier":
        return _text(callee) == "expect"
    if callee.type == "member_expression":
        target = callee.child_by_field_name("object")
        return _text(target) == "expect" or (
            _text(callee.child_by_field_name("property")) == "expect"
        )
    return False


def _is_literal(node) -> bool:
    """A value fixed in the source: ``true``, ``1 + 1``, ``[1, "a"]``, ``{}``,
    ``Number("1")``, ``"abc".length``, ``new Set([1])``."""
    if node is None:
        return False
    kind = node.type
    if kind in _LITERALS:
        return True
    if kind == "identifier":
        return _text(node) in {"undefined", "NaN", "Infinity"}
    if kind == "template_string":
        return not any(c.type == "template_substitution" for c in node.children)
    if kind in {
        "parenthesized_expression",
        "unary_expression",
        "binary_expression",
        "array",
        "await_expression",
    }:
        return all(
            _is_literal(child)
            for child in node.named_children
            if child.type != "comment"
        )
    if kind == "object":
        return all(
            child.type == "pair" and _is_literal(child.child_by_field_name("value"))
            for child in node.named_children
            if child.type != "comment"
        )
    if kind == "member_expression":
        target = node.child_by_field_name("object")
        return _is_literal(target) or (
            target is not None
            and target.type == "identifier"
            and _text(target) in _PURE_OBJECTS
        )
    if kind in {"call_expression", "new_expression"}:
        function = node.child_by_field_name(
            "function" if kind == "call_expression" else "constructor"
        )
        arguments = node.child_by_field_name("arguments")
        if function is None or (
            arguments is not None and arguments.type != "arguments"
        ):
            return False
        items = _args(arguments) if arguments is not None else []
        if not all(_is_literal(arg) for arg in items):
            return False
        if function.type == "identifier":
            return _text(function) in (
                _PURE_FUNCTIONS if kind == "call_expression" else _PURE_CONSTRUCTORS
            )
        return kind == "call_expression" and _is_literal(function)
    return False


def _all_literal(args: list) -> bool:
    return bool(args) and all(_is_literal(arg) for arg in args)


def _same_value(first, second) -> bool:
    """The same expression, with no call in it (a call may differ twice)."""
    if any(
        node.type
        in {
            "call_expression",
            "new_expression",
            "await_expression",
            "assignment_expression",
            "augmented_assignment_expression",
            "update_expression",
            "yield_expression",
        }
        for node in _descendants(first)
    ):
        return False
    return _body_tokens(first) == _body_tokens(second)


def _is_tautology(node) -> bool:
    """True whatever it is about: ``x === x``, ``x >= x``."""
    while node is not None and node.type == "parenthesized_expression":
        node = node.named_children[0] if node.named_children else None
    if node is None or node.type != "binary_expression":
        return False
    operator = _text(node.child_by_field_name("operator"))
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return False
    if operator in _REFLEXIVE_OPERATORS:
        return _same_value(left, right)
    if operator in {"||", "&&"}:
        parts = [_is_tautology(side) or _truth(side) is True for side in (left, right)]
        return any(parts) if operator == "||" else all(parts)
    return False


def _truth(node) -> bool | None:
    """The truth of a condition fixed in the source, else None."""
    while node is not None and node.type == "parenthesized_expression":
        node = node.named_children[0] if node.named_children else None
    if node is None:
        return None
    kind = node.type
    if kind == "true":
        return True
    if kind in {"false", "null", "undefined"}:
        return False
    if kind == "identifier" and _text(node) == "undefined":
        return False
    if kind == "number":
        try:
            return float(_text(node).replace("_", "")) != 0
        except ValueError:
            return None
    if kind == "string":
        return bool(_string_value(node))
    if (
        kind == "unary_expression"
        and _text(node.child_by_field_name("operator")) == "!"
    ):
        inner = _truth(node.child_by_field_name("argument"))
        return None if inner is None else not inner
    if kind == "binary_expression":
        operator = _text(node.child_by_field_name("operator"))
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if operator in {"&&", "||"}:
            first = _truth(left)
            if first is None:
                return None
            if (operator == "&&") != first:
                return first  # false && x, true || x
            return _truth(right)
        compare = _COMPARISONS.get({"==": "===", "!=": "!=="}.get(operator, operator))
        a, b = _constant(left), _constant(right)
        if compare is None or a is None or b is None or type(a) is not type(b):
            return None
        return bool(compare(a, b))
    return None


def _constant(node) -> float | str | None:
    """A number or string literal (``-1``, ``"a"``), else None."""
    while node is not None and node.type == "parenthesized_expression":
        node = node.named_children[0] if node.named_children else None
    if node is None:
        return None
    if node.type == "number":
        try:
            return float(_text(node).replace("_", ""))
        except ValueError:
            return None
    if node.type == "string":
        return _string_value(node)
    if node.type == "template_string" and not any(
        child.type == "template_substitution" for child in node.children
    ):
        return _string_value(node)
    if node.type == "unary_expression" and _text(
        node.child_by_field_name("operator")
    ) in {"-", "+"}:
        inner = _constant(node.child_by_field_name("argument"))
        if isinstance(inner, float):
            sign = _text(node.child_by_field_name("operator"))
            return -inner if sign == "-" else inner
    return None


def _callback_body(callback):
    if callback is None:
        return None
    if callback.type in _FUNCTIONS:
        return callback.child_by_field_name("body") or callback
    return callback


def _hash(node) -> str:
    return _digest(" ".join(_body_tokens(node)))


def _digest(text: str) -> str:
    # surrogatepass: hashing must never fail on text the parser handed back.
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
