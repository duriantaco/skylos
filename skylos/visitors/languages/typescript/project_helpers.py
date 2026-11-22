"""Bounded reads of project helper functions in other files.

Two facts are read from a helper that a route imports from the project
(``./x``, ``@/x``, ``~/x``, ``#x``), never from ``node_modules``:

``helper_authenticates`` (SKY-D280): Next.js routes often authenticate
through the project's own helper rather than calling next-auth or Clerk
directly::

    const { auth, error } = await parseRequest(request, schema);
    if (error) return error();

The helper counts as authentication only when its body reaches a recognised
verification: a JWT verify (``jsonwebtoken``, ``jose``), a session lookup of
an auth library (next-auth, Auth.js, Clerk, iron-session, Auth0, Supabase,
Firebase Admin, Lucia, better-auth, Passport) or a password-hash check
(bcrypt, argon2), either directly or through same-file functions and other
project modules it calls.

``helper_returned_parameters`` (request taint): the parameters whose value a
helper returns as a transformed copy (``trunc(str, n)`` returning
``str.substr(0, n) + '...'``). Only string operations, concatenation and
ternaries count; anything else ends taint as before.

Bounds: at most ``_MAX_DEPTH`` nested helper calls, ``_MAX_FUNCTIONS``
function bodies and ``_MAX_FILES`` files per proof, files under
``_MAX_FILE_BYTES``, only files inside the project root. Anything beyond the
bounds, unresolved or dynamic is not a proof.
"""

from __future__ import annotations

import os
import re
from collections import OrderedDict

from skylos.core.safe_cache_io import read_project_text_no_symlink

_MAX_DEPTH = 4
_MAX_FUNCTIONS = 32
_MAX_FILES = 12
_MAX_FILE_BYTES = 256 * 1024
_CACHE_LIMIT = 256

_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "generator_function_declaration",
    }
)
_WRAPPERS = frozenset(
    {
        "as_expression",
        "await_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
        "type_assertion",
    }
)

# module -> functions or methods whose call verifies an identity.
_VERIFIERS: dict[str, frozenset[str]] = {
    "jsonwebtoken": frozenset({"verify"}),
    "jose": frozenset({"jwtVerify", "jwtDecrypt"}),
    "next-auth": frozenset({"getServerSession"}),
    "next-auth/next": frozenset({"getServerSession"}),
    "next-auth/jwt": frozenset({"getToken"}),
    "@clerk/nextjs": frozenset({"auth", "currentUser"}),
    "@clerk/nextjs/server": frozenset({"auth", "currentUser"}),
    "@clerk/backend": frozenset({"verifyToken", "authenticateRequest"}),
    "iron-session": frozenset({"getIronSession", "unsealData"}),
    "@auth0/nextjs-auth0": frozenset({"getSession"}),
    "firebase-admin": frozenset({"verifyIdToken", "verifySessionCookie"}),
    "firebase-admin/auth": frozenset({"verifyIdToken", "verifySessionCookie"}),
    "@supabase/supabase-js": frozenset({"getUser"}),
    "@supabase/ssr": frozenset({"getUser"}),
    "@supabase/auth-helpers-nextjs": frozenset({"getUser", "getSession"}),
    "lucia": frozenset(
        {"validateSession", "validateSessionCookie", "validateBearerToken"}
    ),
    "better-auth": frozenset({"getSession"}),
    "passport": frozenset({"authenticate"}),
    "bcrypt": frozenset({"compare", "compareSync"}),
    "bcryptjs": frozenset({"compare", "compareSync"}),
    "argon2": frozenset({"verify"}),
}

_facts_cache: OrderedDict[tuple[str, int, int], _ModuleFacts | None] = OrderedDict()
_proof_cache: OrderedDict[tuple[str, int, str], bool] = OrderedDict()


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node):
    for _ in range(16):
        if node is None or node.type not in _WRAPPERS:
            return node
        inner = next(
            (
                child
                for child in node.named_children
                if not child.type.endswith("_type")
                and child.type not in {"type_annotation", "type_arguments"}
            ),
            None,
        )
        if inner is None:
            return node
        node = inner
    return node


def _string_value(source: bytes, node) -> str | None:
    if node is None or node.type != "string":
        return None
    text = _text(source, node)
    if len(text) >= 2 and text[0] in "'\"" and text[-1] == text[0]:
        return text[1:-1]
    return None


class _ModuleFacts:
    def __init__(self, path: str, source: bytes, root):
        self.path = path
        self.source = source
        self.imports: dict[str, tuple[str, str]] = {}
        self.functions: dict[str, object] = {}
        self.instances: dict[str, tuple[str, str]] = {}
        self.exports: dict[str, str] = {}
        self.reexports: dict[str, tuple[str, str]] = {}
        self.constants: dict[str, str] = {}
        self._collect(root)

    def _collect(self, root) -> None:
        source = self.source
        for statement in root.named_children:
            node = statement
            exported = False
            if node.type == "export_statement":
                source_node = node.child_by_field_name("source")
                module = _string_value(source, source_node)
                clause = next(
                    (c for c in node.named_children if c.type == "export_clause"),
                    None,
                )
                if clause is not None:
                    for spec in clause.named_children:
                        if spec.type != "export_specifier":
                            continue
                        name = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias") or name
                        if name is None or alias is None:
                            continue
                        if module is not None:
                            self.reexports[_text(source, alias)] = (
                                module,
                                _text(source, name),
                            )
                        else:
                            self.exports[_text(source, alias)] = _text(source, name)
                    continue
                declaration = node.child_by_field_name("declaration")
                if declaration is None:
                    continue
                node = declaration
                exported = True
            if node.type == "import_statement":
                self._import(node)
            elif node.type in {
                "function_declaration",
                "generator_function_declaration",
            }:
                name = node.child_by_field_name("name")
                if name is not None:
                    self.functions[_text(source, name)] = node
                    if exported:
                        self.exports[_text(source, name)] = _text(source, name)
            elif node.type in {"lexical_declaration", "variable_declaration"}:
                for declarator in node.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    name = declarator.child_by_field_name("name")
                    value = _unwrap(declarator.child_by_field_name("value"))
                    if name is None or name.type != "identifier" or value is None:
                        continue
                    bound = _text(source, name)
                    if exported:
                        self.exports[bound] = bound
                    if value.type in _FUNCTION_TYPES:
                        self.functions[bound] = value
                    elif value.type == "call_expression":
                        self._require_or_instance(bound, value)
                    elif _text(source, node).startswith("const"):
                        literal = _string_value(source, value)
                        if (
                            literal is None
                            and value.type == "template_string"
                            and not any(
                                child.type == "template_substitution"
                                for child in value.named_children
                            )
                        ):
                            literal = _text(source, value)[1:-1]
                        if literal is not None:
                            self.constants[bound] = literal

    def _import(self, node) -> None:
        source = self.source
        module = _string_value(source, node.child_by_field_name("source"))
        if module is None:
            return
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    self.imports[_text(source, child)] = (module, "default")
                elif child.type == "namespace_import":
                    for sub in child.named_children:
                        if sub.type == "identifier":
                            self.imports[_text(source, sub)] = (module, "*")
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        if spec.type != "import_specifier":
                            continue
                        name = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias") or name
                        if name is not None and alias is not None:
                            self.imports[_text(source, alias)] = (
                                module,
                                _text(source, name),
                            )

    def _require_or_instance(self, bound: str, call) -> None:
        """``const jwt = require('jsonwebtoken')`` or a client made by an
        imported factory (``const supabase = createClient(...)``)."""
        callee = _unwrap(call.child_by_field_name("function"))
        if callee is None:
            return
        if callee.type == "identifier" and _text(self.source, callee) == "require":
            args = call.child_by_field_name("arguments")
            first = next(iter(args.named_children), None) if args else None
            module = _string_value(self.source, first)
            if module is not None:
                self.imports[bound] = (module, "*")
            return
        root = callee
        while root is not None and root.type in {
            "member_expression",
            "call_expression",
        }:
            root = _unwrap(
                root.child_by_field_name("object")
                if root.type == "member_expression"
                else root.child_by_field_name("function")
            )
        if root is not None and root.type == "identifier":
            binding = self.imports.get(_text(self.source, root))
            if binding is not None:
                self.instances[bound] = binding


def _load_facts(project_root: str, path: str) -> _ModuleFacts | None:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    if stat.st_size > _MAX_FILE_BYTES:
        return None
    key = (path, int(stat.st_mtime_ns), int(stat.st_size))
    if key in _facts_cache:
        _facts_cache.move_to_end(key)
        return _facts_cache[key]
    facts = None
    try:
        text = read_project_text_no_symlink(
            project_root,
            path,
            max_bytes=_MAX_FILE_BYTES,
            errors="surrogateescape",
            newline="",
        )
    except (OSError, UnicodeError, ValueError):
        text = None
    if text is not None:
        source = text.encode("utf-8", errors="surrogateescape")
        from skylos.visitors.languages.typescript.core import TypeScriptCore

        core = TypeScriptCore(path, source)
        root = core.root_node
        if root is not None and not getattr(root, "has_error", False):
            facts = _ModuleFacts(path, source, root)
    _facts_cache[key] = facts
    while len(_facts_cache) > _CACHE_LIMIT:
        _facts_cache.popitem(last=False)
    return facts


def _is_project_module(module: str) -> bool:
    return module.startswith((".", "@/", "~/", "#", "src/"))


def _resolve(project_root: str, importer: str, module: str) -> str | None:
    if not _is_project_module(module):
        return None
    try:
        if module.startswith("."):
            from skylos.visitors.languages.typescript.analysis import (
                resolve_ts_module,
            )

            resolved = resolve_ts_module(module, importer)
        else:
            from skylos.visitors.languages.typescript.resolve import MonorepoResolver

            resolved = MonorepoResolver(project_root).resolve(module, importer)
    except (OSError, RuntimeError, ValueError):
        return None
    if not resolved:
        return None
    target = os.path.realpath(resolved)
    try:
        if os.path.commonpath((project_root, target)) != project_root:
            return None
    except ValueError:
        return None
    if f"{os.sep}node_modules{os.sep}" in target:
        return None
    return target if os.path.isfile(target) else None


def _is_verifier(module: str, exported: str, segments: tuple[str, ...]) -> bool:
    names = _VERIFIERS.get(module)
    if names is None:
        return False
    if exported not in {"*", "default"} and len(segments) == 1:
        return exported in names
    return bool(segments) and segments[-1] in names


def _callee_parts(source: bytes, callee) -> tuple[str | None, tuple[str, ...]]:
    """Root identifier and member names of a callee; calls along the chain
    (``getAuth().verifyIdToken``) are stepped through."""
    segments: list[str] = []
    current = _unwrap(callee)
    for _ in range(16):
        if current is None:
            return None, ()
        if current.type == "identifier":
            return _text(source, current), (_text(source, current), *reversed(segments))
        if current.type == "member_expression":
            prop = current.child_by_field_name("property")
            if prop is None:
                return None, ()
            segments.append(_text(source, prop))
            current = _unwrap(current.child_by_field_name("object"))
        elif current.type == "call_expression":
            current = _unwrap(current.child_by_field_name("function"))
        else:
            return None, ()
    return None, ()


class _Search:
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.functions = 0
        self.files: set[str] = set()
        self.seen: set[tuple[str, str]] = set()

    def module(self, importer: str, module: str) -> _ModuleFacts | None:
        target = _resolve(self.project_root, importer, module)
        if target is None:
            return None
        if target not in self.files and len(self.files) >= _MAX_FILES:
            return None
        self.files.add(target)
        return _load_facts(self.project_root, target)

    def exported(self, facts: _ModuleFacts, name: str, depth: int) -> bool:
        if name in facts.reexports and depth <= _MAX_DEPTH:
            module, imported = facts.reexports[name]
            target = self.module(facts.path, module)
            return target is not None and self.exported(target, imported, depth + 1)
        local = facts.exports.get(name, name)
        if local in facts.imports and depth <= _MAX_DEPTH:
            # ``import { x } from './y'; export { x }``
            module, imported = facts.imports[local]
            target = self.module(facts.path, module)
            return target is not None and self.exported(target, imported, depth + 1)
        return self.function(facts, local, depth)

    def function(self, facts: _ModuleFacts, name: str, depth: int) -> bool:
        key = (facts.path, name)
        if key in self.seen or depth > _MAX_DEPTH:
            return False
        self.seen.add(key)
        function = facts.functions.get(name)
        if function is None:
            return False
        self.functions += 1
        if self.functions > _MAX_FUNCTIONS:
            return False
        body = function.child_by_field_name("body") or function
        stack = [body]
        calls = []
        while stack:
            node = stack.pop()
            if node.type in {"call_expression", "new_expression"}:
                calls.append(node)
            stack.extend(reversed(node.children))
        for call in calls:
            if self._call_verifies(facts, call, depth):
                return True
        return False

    def _call_verifies(self, facts: _ModuleFacts, call, depth: int) -> bool:
        callee = call.child_by_field_name("function") or call.child_by_field_name(
            "constructor"
        )
        root, segments = _callee_parts(facts.source, callee)
        if root is None:
            return False
        members = segments[1:]
        binding = facts.imports.get(root)
        if binding is not None:
            module, exported = binding
            if _is_verifier(module, exported, members or (exported,)):
                return True
            if not _is_project_module(module):
                return False
            if exported == "*" and len(members) == 1:
                function_name = members[0]
            elif not members:
                function_name = exported
            else:
                return False
            target = self.module(facts.path, module)
            return target is not None and self.exported(
                target, function_name, depth + 1
            )
        instance = facts.instances.get(root)
        if instance is not None:
            module, _exported = instance
            names = _VERIFIERS.get(module, frozenset())
            return bool(members) and members[-1] in names
        if not members and root in facts.functions:
            return self.function(facts, root, depth + 1)
        return False


def helper_authenticates(
    project_root: str, importer: str, module: str, exported: str
) -> bool:
    """Whether ``exported`` from ``module`` (as imported by ``importer``)
    reaches a recognised identity verification."""
    if not _is_project_module(module):
        return False
    target = _resolve(project_root, importer, module)
    if target is None:
        return False
    try:
        stamp = os.stat(target).st_mtime_ns
    except OSError:
        return False
    key = (target, stamp, exported)
    if key in _proof_cache:
        _proof_cache.move_to_end(key)
        return _proof_cache[key]
    search = _Search(project_root)
    search.files.add(target)
    facts = _load_facts(project_root, target)
    result = facts is not None and search.exported(facts, exported, 0)
    _proof_cache[key] = result
    while len(_proof_cache) > _CACHE_LIMIT:
        _proof_cache.popitem(last=False)
    return result


_STRING_TRANSFORMS = frozenset(
    {
        "at",
        "charAt",
        "concat",
        "normalize",
        "padEnd",
        "padStart",
        "replace",
        "replaceAll",
        "slice",
        "substr",
        "substring",
        "toLowerCase",
        "toString",
        "toUpperCase",
        "trim",
        "trimEnd",
        "trimStart",
    }
)
_summary_cache: OrderedDict[tuple[str, int, str], frozenset[int]] = OrderedDict()


def nearest_project_root(path: str) -> str | None:
    current = os.path.dirname(os.path.realpath(path))
    for _ in range(32):
        if os.path.isfile(os.path.join(current, "package.json")) or os.path.isfile(
            os.path.join(current, "tsconfig.json")
        ):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
    return None


def _derived(source: bytes, node, name: str, depth: int = 0) -> str:
    """'derived' when ``node`` is a transformed copy of ``name``, 'neutral'
    for literals, '' otherwise."""
    node = _unwrap(node)
    if node is None or depth > 12:
        return ""
    if node.type == "identifier":
        return "derived" if _text(source, node) == name else ""
    if node.type in {"string", "number", "true", "false", "null", "undefined"}:
        return "neutral"
    if node.type == "template_string":
        parts = [
            _derived(source, next(iter(child.named_children), None), name, depth + 1)
            for child in node.named_children
            if child.type == "template_substitution"
        ]
        return _combine(parts) if parts else "neutral"
    if node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        if operator is None or operator.type != "+":
            return ""
        return _combine(
            [
                _derived(source, node.child_by_field_name("left"), name, depth + 1),
                _derived(source, node.child_by_field_name("right"), name, depth + 1),
            ]
        )
    if node.type == "ternary_expression":
        return _combine(
            [
                _derived(source, node.child_by_field_name(field), name, depth + 1)
                for field in ("consequence", "alternative")
            ]
        )
    if node.type == "call_expression":
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None or callee.type != "member_expression":
            return ""
        prop = callee.child_by_field_name("property")
        if prop is None or _text(source, prop) not in _STRING_TRANSFORMS:
            return ""
        return (
            "derived"
            if _derived(source, callee.child_by_field_name("object"), name, depth + 1)
            == "derived"
            else ""
        )
    return ""


def _combine(parts: list[str]) -> str:
    if any(part == "" for part in parts):
        return ""
    return "derived" if "derived" in parts else "neutral"


def _parameter_names(function, source: bytes) -> list[str | None]:
    single = function.child_by_field_name("parameter")
    if single is not None:
        return [_text(source, single) if single.type == "identifier" else None]
    params = function.child_by_field_name("parameters")
    names: list[str | None] = []
    for child in params.named_children if params is not None else []:
        pattern = (
            child.child_by_field_name("pattern")
            if child.type in {"required_parameter", "optional_parameter"}
            else child
        )
        names.append(
            _text(source, pattern)
            if pattern is not None and pattern.type == "identifier"
            else None
        )
    return names


def _returned_parameters(facts: _ModuleFacts, function) -> frozenset[int]:
    source = facts.source
    body = function.child_by_field_name("body")
    if body is None:
        return frozenset()
    returns = []
    assignments: dict[str, list] = {}
    if body.type != "statement_block":
        returns.append(body)
    else:
        stack = [body]
        while stack:
            node = stack.pop()
            if node is not body and node.type in _FUNCTION_TYPES:
                continue
            if node.type == "return_statement":
                value = next(iter(node.named_children), None)
                if value is None:
                    return frozenset()
                returns.append(value)
            elif node.type in {
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                left = _unwrap(node.child_by_field_name("left"))
                if left is not None and left.type == "identifier":
                    assignments.setdefault(_text(source, left), []).append(
                        node.child_by_field_name("right")
                        if node.type == "assignment_expression"
                        else None
                    )
            stack.extend(node.children)
    if not returns:
        return frozenset()
    if re.search(r"&(?:lt|gt|amp|quot|#\d+);", _text(source, body)):
        # An HTML-escaping helper is a sanitizer for some sinks; keep the
        # earlier behaviour of ending taint at it.
        return frozenset()
    result = set()
    for index, name in enumerate(_parameter_names(function, source)):
        if name is None:
            continue
        if any(
            value is None or _derived(source, value, name) != "derived"
            for value in assignments.get(name, ())
        ):
            continue
        if all(_derived(source, value, name) == "derived" for value in returns):
            result.add(index)
    return frozenset(result)


def helper_returned_parameters(
    project_root: str, importer: str, module: str, exported: str
) -> frozenset[int]:
    """Indices of the parameters that ``exported`` from ``module`` returns as
    a transformed copy, or an empty set."""
    target = _resolve(project_root, importer, module)
    if target is None:
        return frozenset()
    try:
        stamp = os.stat(target).st_mtime_ns
    except OSError:
        return frozenset()
    key = (target, stamp, exported)
    if key in _summary_cache:
        _summary_cache.move_to_end(key)
        return _summary_cache[key]
    facts = _load_facts(project_root, target)
    result: frozenset[int] = frozenset()
    if facts is not None:
        local = facts.exports.get(exported, exported)
        function = facts.functions.get(local)
        if function is not None:
            result = _returned_parameters(facts, function)
    _summary_cache[key] = result
    while len(_summary_cache) > _CACHE_LIMIT:
        _summary_cache.popitem(last=False)
    return result


def exported_constant_string(
    project_root: str, importer: str, module: str, exported: str
) -> str | None:
    """The literal an ``export const NAME = '...'`` in a project module holds
    (one re-export hop is followed), or None."""
    if not _is_project_module(module):
        return None
    target = _resolve(project_root, importer, module)
    if target is None:
        return None
    facts = _load_facts(project_root, target)
    if facts is None:
        return None
    if exported in facts.reexports:
        inner_module, inner_name = facts.reexports[exported]
        inner = _resolve(project_root, facts.path, inner_module)
        facts = _load_facts(project_root, inner) if inner is not None else None
        if facts is None:
            return None
        exported = inner_name
    local = facts.exports.get(exported)
    if local is None:
        return None
    return facts.constants.get(local)
