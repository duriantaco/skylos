"""SKY-D228: a Flask or Django view returns request data in an HTML response
without escaping it.

Flask serves a view's ``str`` or ``bytes`` return value, ``make_response(text)``
and ``Response(text)`` as ``text/html`` unless a mimetype, content type or
``Content-Type`` header says otherwise; Django's ``HttpResponse`` defaults to
``text/html`` as well. ``xss_flow`` needs a literal HTML tag in the string, so
a value reflected into plain text (``f"Hello {name}"``) passes it, although a
browser parses a ``<script>`` the attacker sends inside it all the same.

Request data is the Flask ``request`` proxy (and aliases of it), a Flask route
parameter with a text converter, and a Django view's request parameter. Taint
follows assignments, branches (joined, never folded), loops, ``+=``, f-strings,
concatenation, ``%``, ``.format``, slicing and containers, whose constant dict
keys stay precise until the dict is aliased. A call the analysis does not know
returns its arguments' taint and may write it into a mutable argument; a
module-level helper is analysed with its arguments. Only the standard escapes
(``html.escape``, ``markupsafe.escape``, ``markupsafe.Markup.escape``,
``flask.escape``, ``bleach.clean`` and Django's ``escape``,
``conditional_escape`` and ``format_html``), resolved through their imports,
clear it; a project helper is never trusted by its name.

A view is reported only when the body it returns is provably text, so
``jsonify``, templates, dicts and unknown objects are not, and a non-HTML
mimetype, content type or ``Content-Type`` header, or one the analysis cannot
read, keeps the response quiet. FastAPI and Starlette modules are excluded:
their ``str`` return is JSON. Test modules are not reported. The work per
module is bounded by a step budget.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache, reduce
from pathlib import Path

from skylos.rules.danger.calls import _is_test_module
from skylos.rules.danger.module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from skylos.rules.danger.untrusted_sources import (
    REQUEST_ANNOTATIONS,
    REQUEST_NAMES,
    UntrustedSourceIndex,
)

TEXT = "text"
TEXTS = "texts"
MAPPING = "mapping"
DICT = "dict"
REQUEST = "request"
RESPONSE = "response"
NONE = "none"
NUMBER = "number"
OTHER = "other"

HTML = "html"
NOT_HTML = "not-html"
UNKNOWN = "unknown"

FLASK = "flask"
DJANGO = "django"

_MAX_LABELS = 4
_MAX_LOOP_PASSES = 3
_MAX_HELPER_DEPTH = 3
_OPAQUE = "?"
_UNRESOLVED = "unresolved-transform"
_PASS_THROUGH_TEXT = frozenset(
    {
        f"base64.{name}"
        for name in (
            "b64decode",
            "b64encode",
            "urlsafe_b64decode",
            "urlsafe_b64encode",
            "standard_b64decode",
            "standard_b64encode",
            "b32decode",
            "b32encode",
            "b16decode",
            "b16encode",
            "b85decode",
            "b85encode",
            "a85decode",
            "a85encode",
            "decodebytes",
            "encodebytes",
        )
    }
    | {
        "codecs.decode",
        "codecs.encode",
        "urllib.parse.unquote",
        "urllib.parse.unquote_plus",
        "urllib.parse.unquote_to_bytes",
    }
)
_PASS_THROUGH_OBJECTS = frozenset({"json.loads"})
_BRANCHES = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.If,
    ast.IfExp,
    ast.Match,
    ast.Try,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_MAX_FUNCTION_NODES = 20000
_MAX_STEPS = 400000
_MAX_PROJECT_MODULE_BYTES = 1_000_000
_FLASK_APPS = frozenset(
    {
        "flask.Flask",
        "flask.app.Flask",
        "flask.Blueprint",
        "flask.blueprints.Blueprint",
    }
)

_ESCAPES = frozenset(
    {
        "html.escape",
        "markupsafe.escape",
        "markupsafe.Markup.escape",
        "flask.escape",
        "bleach.clean",
        "django.utils.html.escape",
        "django.utils.html.conditional_escape",
    }
)
_FORMAT_ESCAPES = frozenset({"django.utils.html.format_html"})
_MARK_SAFE = frozenset(
    {"markupsafe.Markup", "flask.Markup", "django.utils.safestring.mark_safe"}
)
_MAKE_RESPONSE = frozenset({"flask.make_response"})
_FLASK_RESPONSES = frozenset(
    {
        "flask.Response",
        "flask.wrappers.Response",
        "werkzeug.Response",
        "werkzeug.wrappers.Response",
        "werkzeug.wrappers.response.Response",
    }
)
_DJANGO_RESPONSE_NAMES = (
    "HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseForbidden",
    "HttpResponseGone",
    "HttpResponseNotFound",
    "HttpResponseServerError",
)
_DJANGO_RESPONSES = frozenset(
    {f"django.http.{name}" for name in _DJANGO_RESPONSE_NAMES}
    | {f"django.http.response.{name}" for name in _DJANGO_RESPONSE_NAMES}
    | {"django.shortcuts.HttpResponse"}
)
_JSON_FRAMEWORKS = ("fastapi", "starlette")
_ROUTE_METHODS = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "errorhandler"}
)
_RULE_VARIABLE = re.compile(
    r"<(?:(?P<converter>[A-Za-z_][A-Za-z0-9_]*)(?:\([^)>]*\))?:)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)>"
)
_TEXT_CONVERTERS = frozenset({None, "default", "string", "path", "any"})
_NUMBER_CONVERTERS = frozenset({"int", "float", "uuid"})
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml", "image/svg+xml"})

_REQUEST_FIELDS = {
    FLASK: {
        "mappings": frozenset(
            {"args", "form", "values", "cookies", "headers", "view_args", "environ"}
        ),
        "texts": frozenset(
            {
                "data",
                "query_string",
                "path",
                "full_path",
                "script_root",
                "root_path",
                "url",
                "base_url",
                "url_root",
                "host_url",
                "root_url",
                "host",
                "referrer",
                "remote_user",
                "user_agent",
                "content_type",
                "mimetype",
                "origin",
            }
        ),
        "clean": frozenset(
            {
                "method",
                "endpoint",
                "blueprint",
                "blueprints",
                "url_rule",
                "is_json",
                "is_secure",
                "scheme",
                "content_length",
                "remote_addr",
                "max_content_length",
                "max_form_memory_size",
                "routing_exception",
                "date",
                "trusted_hosts",
            }
        ),
        "text_methods": frozenset({"get_data"}),
    },
    DJANGO: {
        "mappings": frozenset(
            {"GET", "POST", "COOKIES", "META", "headers", "data", "query_params"}
        ),
        "texts": frozenset({"body", "path", "path_info", "content_type"}),
        "clean": frozenset(
            {
                "method",
                "user",
                "session",
                "resolver_match",
                "scheme",
                "encoding",
                "urlconf",
                "auth",
                "site",
                "LANGUAGE_CODE",
                "current_app",
                "upload_handlers",
                "csrf_processing_done",
            }
        ),
        "text_methods": frozenset(
            {
                "get_full_path",
                "get_full_path_info",
                "build_absolute_uri",
                "get_host",
                "get_port",
                "get_signed_cookie",
                "read",
                "readline",
            }
        ),
    },
}
_REQUEST_CLEAN_METHODS = frozenset({"is_secure", "is_ajax", "accepts"})
_MAPPING_TEXT_METHODS = frozenset({"get", "pop", "setdefault", "urlencode"})
_MAPPING_TEXTS_METHODS = frozenset(
    {"getlist", "keys", "values", "items", "lists", "listvalues", "poplist"}
)
_MAPPING_SELF_METHODS = frozenset({"to_dict", "copy", "dict"})
_TEXT_METHODS = frozenset(
    {
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "casefold",
        "title",
        "capitalize",
        "swapcase",
        "replace",
        "format",
        "format_map",
        "join",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "expandtabs",
        "encode",
        "decode",
        "removeprefix",
        "removesuffix",
        "translate",
    }
)
_TEXTS_METHODS = frozenset({"split", "rsplit", "splitlines", "partition", "rpartition"})
_TEXT_NUMBER_METHODS = frozenset(
    {
        "find",
        "rfind",
        "index",
        "rindex",
        "count",
        "startswith",
        "endswith",
        "isalnum",
        "isalpha",
        "isascii",
        "isdecimal",
        "isdigit",
        "isidentifier",
        "islower",
        "isnumeric",
        "isprintable",
        "isspace",
        "istitle",
        "isupper",
    }
)
_LIST_INSERTS = frozenset({"append", "extend", "insert", "add", "appendleft"})
_LIST_ELEMENT_METHODS = frozenset({"pop", "popleft"})
_INSERTING_METHODS = frozenset(
    {"append", "extend", "insert", "add", "update", "setdefault", "appendleft"}
)
_TEXT_BUILTINS = frozenset({"str", "repr", "ascii", "format", "bytes", "bytearray"})
_NUMBER_BUILTINS = frozenset(
    {
        "int",
        "float",
        "bool",
        "len",
        "hash",
        "id",
        "ord",
        "abs",
        "round",
        "complex",
        "isinstance",
        "issubclass",
        "callable",
        "hasattr",
    }
)
_CONTAINER_BUILTINS = frozenset(
    {"list", "tuple", "set", "frozenset", "sorted", "reversed"}
)
_RESPONSE_NEUTRAL_METHODS = frozenset(
    {"set_cookie", "delete_cookie", "set_signed_cookie", "set_etag", "add_etag"}
)
_HEADER_WRITES = frozenset({"set", "add", "setdefault", "__setitem__"})
_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


class _BudgetExceeded(Exception):
    pass


@dataclass(frozen=True)
class _Value:
    """What the analysis knows about a value: its kind, the request data
    that may reach it (``labels``), a literal text (``const``), a dict's
    constant keys (``keys``) and the taint stored under other keys
    (``rest``), and for a response whether it is served as HTML (``html``)
    and its body."""

    kind: str
    labels: frozenset = frozenset()
    const: object = None
    keys: tuple = ()
    rest: frozenset = frozenset()
    html: str = ""
    body: object = None


def _label_order(label: str):
    return (label.startswith(_OPAQUE), label)


def _labels(*groups) -> frozenset:
    merged = frozenset().union(*groups)
    if len(merged) <= _MAX_LABELS:
        return merged
    return frozenset(sorted(merged, key=_label_order)[:_MAX_LABELS])


def _plain(label: str) -> str:
    if label.startswith(_OPAQUE):
        return label[len(_OPAQUE) :]
    return label


def _opaque_labels(labels) -> frozenset:
    return frozenset(_OPAQUE + _plain(label) for label in labels)


def _opaqued(value):
    """``value`` with every label marked as having passed through a call the
    analysis does not resolve: still request data, but possibly escaped."""
    if value is None:
        return None
    return _Value(
        value.kind,
        _opaque_labels(value.labels),
        const=value.const,
        keys=tuple((key, _opaqued(item)) for key, item in value.keys),
        rest=_opaque_labels(value.rest),
        html=value.html,
        body=_opaqued(value.body),
    )


def _all_labels(value: _Value | None) -> frozenset:
    if value is None:
        return frozenset()
    groups = [value.labels, value.rest]
    groups.extend(_all_labels(item) for _, item in value.keys)
    if value.body is not None:
        groups.append(_all_labels(value.body))
    return _labels(*groups)


_CLEAN_TEXT = _Value(TEXT)
_NONE_VALUE = _Value(NONE)
_NUMBER_VALUE = _Value(NUMBER)
_CLEAN_OTHER = _Value(OTHER)
_MUTABLE = frozenset({DICT, TEXTS, OTHER})


def _other(*values) -> _Value:
    return _Value(OTHER, _labels(*(_all_labels(value) for value in values)))


def _opaque(*values) -> _Value:
    return _Value(OTHER, _opaque_labels(_labels(*(_all_labels(v) for v in values))))


def _text(*values) -> _Value:
    return _Value(TEXT, _labels(*(_all_labels(value) for value in values)))


def _texts(*values) -> _Value:
    return _Value(TEXTS, _labels(*(_all_labels(value) for value in values)))


def _with_labels(value: _Value, labels) -> _Value:
    if not labels:
        return value
    if value.kind == DICT:
        return _Value(
            DICT, value.labels, keys=value.keys, rest=_labels(value.rest, labels)
        )
    if value.kind == RESPONSE:
        return _Value(
            RESPONSE, html=UNKNOWN, body=_other(value.body, _Value(OTHER, labels))
        )
    return _Value(value.kind, _labels(value.labels, labels))


def _join_dicts(a: _Value, b: _Value) -> _Value:
    left, right = dict(a.keys), dict(b.keys)
    keys = {}
    for key in set(left) | set(right):
        first = left.get(key)
        second = right.get(key)
        if first is None and a.rest:
            first = _Value(OTHER, a.rest)
        if second is None and b.rest:
            second = _Value(OTHER, b.rest)
        keys[key] = _join(first, second)
    return _dict_value(keys, _labels(a.rest, b.rest), _labels(a.labels, b.labels))


def _join(a: _Value | None, b: _Value | None) -> _Value | None:
    if a is None:
        return b
    if b is None or a == b:
        return a
    if a.kind == NONE:
        return b
    if b.kind == NONE:
        return a
    if a.kind != b.kind:
        return _other(a, b)
    if a.kind == DICT:
        return _join_dicts(a, b)
    if a.kind == RESPONSE:
        html = a.html
        if a.html != b.html:
            html = UNKNOWN
        return _Value(RESPONSE, html=html, body=_join(a.body, b.body))
    const = None
    if a.const == b.const:
        const = a.const
    return _Value(a.kind, _labels(a.labels, b.labels), const=const)


def _dict_value(keys: dict, rest=frozenset(), labels=frozenset()) -> _Value:
    ordered = tuple(sorted(keys.items(), key=lambda item: repr(item[0])))
    return _Value(DICT, labels, keys=ordered, rest=rest)


def _element_of(value: _Value) -> _Value:
    if value.kind in (TEXT, TEXTS, MAPPING):
        return _Value(TEXT, value.labels)
    if value.kind == DICT:
        return _Value(OTHER, _labels(value.rest, value.labels))
    if value.kind in (NONE, NUMBER):
        return _CLEAN_OTHER
    return _other(value)


def _key_of(node: ast.AST, value: _Value):
    """The constant a subscript or dict key spells, as ``(True, key)``."""
    if isinstance(node, ast.Constant) and isinstance(
        node.value, (str, bytes, int, float, bool, type(None))
    ):
        return True, node.value
    if value.kind == TEXT and value.const is not None and not value.labels:
        return True, value.const
    return False, None


def _mimetype_state(value: _Value) -> str:
    if value.kind == TEXT and value.const is not None and not value.labels:
        base = str(value.const).split(";", 1)[0].strip().lower()
        if base in _HTML_TYPES:
            return HTML
        return NOT_HTML
    if _all_labels(value):
        return HTML
    return UNKNOWN


def _join_state(first, second):
    if first is None:
        return second
    if second is None or first == second:
        return first
    return UNKNOWN


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _chain_root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _own_nodes(func: ast.AST):
    stack = list(func.body)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _NESTED_SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _value_roots(value: ast.AST | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (ast.Tuple, ast.List)):
        return [root for element in value.elts for root in _value_roots(element)]
    if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript, ast.Starred)):
        root = _chain_root(value)
        if root:
            return [root]
    return []


def _target_roots(target: ast.AST) -> list[str]:
    if isinstance(target, (ast.Tuple, ast.List)):
        return [root for element in target.elts for root in _target_roots(element)]
    root = _chain_root(target)
    if root:
        return [root]
    return []


def _alias_groups(func: ast.AST) -> dict[str, frozenset[str]]:
    """Names in ``func`` that may refer to the same object (``b = a``,
    ``b = a[0]``, ``a[k] = b``, ``a.append(b)``, ``for b in a``), so a change
    made in place through one is visible through the others."""
    parent: dict[str, str] = {}

    def find(name: str) -> str:
        while parent.setdefault(name, name) != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    def link(names) -> None:
        names = list(names)
        for name in names[1:]:
            parent[find(name)] = find(names[0])

    for node in _own_nodes(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                link(_target_roots(target) + _value_roots(node.value))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            link(_target_roots(node.target) + _value_roots(node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            link(_target_roots(node.target) + _value_roots(node.iter))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            link(_target_roots(node.optional_vars) + _value_roots(node.context_expr))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _INSERTING_METHODS
        ):
            roots = _value_roots(node.func.value)
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                roots.extend(_value_roots(arg))
            link(roots)
    groups: dict[str, set[str]] = {}
    for name in list(parent):
        groups.setdefault(find(name), set()).add(name)
    return {name: frozenset(group) for group in groups.values() for name in group}


def _bound_names(tree: ast.AST) -> dict[str, int]:
    counts: dict[str, int] = {}

    def add(name):
        if name:
            counts[name] = counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(node.name)
        elif isinstance(node, ast.arg):
            add(node.arg)
        elif isinstance(node, ast.alias):
            add(node.asname or node.name.split(".")[0])
        elif isinstance(node, ast.ExceptHandler):
            add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            add(node.name)
        elif isinstance(node, ast.MatchMapping):
            add(node.rest)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                add(name)
    return counts


def _is_generator(func: ast.AST) -> bool:
    return any(
        isinstance(node, (ast.Yield, ast.YieldFrom)) for node in _own_nodes(func)
    )


def _too_large(func: ast.AST) -> bool:
    for count, _ in enumerate(ast.walk(func)):
        if count > _MAX_FUNCTION_NODES:
            return True
    return False


def _combined_kind(kinds):
    if "json" in kinds:
        return "json"
    if kinds == {FLASK}:
        return FLASK
    return None


def _module_file(bases, parts, root: Path):
    """The one project file ``parts`` names under ``bases`` (``a/b.py`` or
    ``a/b/__init__.py``), inside ``root`` and not a symlink; None when there
    is none, more than one, or it is too large."""
    found = set()
    for base in bases:
        stem = base.joinpath(*parts)
        for candidate in (stem.with_name(stem.name + ".py"), stem / "__init__.py"):
            if not parts and candidate.name != "__init__.py":
                continue
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved.is_relative_to(root):
                found.add(resolved)
    if len(found) != 1:
        return None
    path = found.pop()
    try:
        if path.stat().st_size > _MAX_PROJECT_MODULE_BYTES:
            return None
    except OSError:
        return None
    return path


@lru_cache(maxsize=64)
def _parse_project_module(path: str, mtime_ns: int, size: int):
    try:
        with open(path, "rb", opener=_no_follow) as handle:
            source = handle.read(_MAX_PROJECT_MODULE_BYTES + 1)
        if len(source) > _MAX_PROJECT_MODULE_BYTES:
            return None
        return ast.parse(source, filename=path)
    except (OSError, SyntaxError, ValueError, RecursionError):
        return None


def _no_follow(path, flags):
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))


def _route_rules(func: ast.AST, module):
    """Literal rule strings of the Flask route decorators on ``func``; None
    when no decorator registers it as a Flask view."""
    rules = []
    found = False
    for decorator in func.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(
            decorator.func, ast.Attribute
        ):
            continue
        if decorator.func.attr not in _ROUTE_METHODS:
            continue
        rule = None
        if decorator.args:
            rule = decorator.args[0]
        for kw in decorator.keywords:
            if kw.arg == "rule":
                rule = kw.value
        if rule is None or module.view_framework(decorator, func) != FLASK:
            continue
        found = True
        if isinstance(rule, ast.Constant) and isinstance(rule.value, str):
            rules.append(rule.value)
    if not found:
        return None
    return rules


def _params(func: ast.AST) -> list[ast.arg]:
    args = func.args
    return [*args.posonlyargs, *args.args, *args.kwonlyargs]


def _annotation_names(annotation: ast.AST | None) -> set[str]:
    names = set()
    if annotation is None:
        return names
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value.rsplit(".", 1)[-1])
    return names


def _is_request_param(param: ast.arg) -> bool:
    names = _annotation_names(param.annotation)
    if names & REQUEST_ANNOTATIONS:
        return True
    return param.arg in REQUEST_NAMES and param.annotation is None


class _Env:
    __slots__ = ("values",)

    def __init__(self, values=None):
        self.values = dict(values or {})

    def copy(self):
        return _Env(self.values)


def _join_envs(envs):
    live = [env for env in envs if env is not None]
    if not live:
        return None
    if len(live) == 1:
        return live[0].copy()
    names = set()
    for env in live:
        names.update(env.values)
    joined = {}
    for name in names:
        values = [env.values[name] for env in live if name in env.values]
        joined[name] = reduce(_join, values)
    return _Env(joined)


class _LoopFrame:
    __slots__ = ("breaks", "continues")

    def __init__(self):
        self.breaks = []
        self.continues = []


class _Module:
    """Facts shared by every function of one module."""

    def __init__(self, tree, file_path, project_root):
        self.tree = tree
        self.file_path = file_path
        self.project_root = project_root
        self.index = UntrustedSourceIndex(tree)
        self.steps = 0
        self.summaries: dict = {}
        self.in_progress: set = set()
        self.alias_cache: dict = {}
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                modules.add(node.module)
        roots = {name.split(".", 1)[0] for name in modules}
        self.flask = "flask" in roots
        self.json_framework = any(root in roots for root in _JSON_FRAMEWORKS)
        self.django = "django" in roots
        self._parents = None
        self._receivers: dict = {}
        self._project_functions: dict = {}
        self._project_modules: dict = {}
        self._rebinding = None
        self._writes = None
        self._patched = None
        self._counts = None
        self._helpers = None

    def aliases_for(self, func):
        key = id(func)
        if key not in self.alias_cache:
            self.alias_cache[key] = _alias_groups(func)
        return self.alias_cache[key]

    def tick(self):
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise _BudgetExceeded()

    def counts(self) -> dict[str, int]:
        if self._counts is None:
            self._counts = _bound_names(self.tree)
        return self._counts

    def rebinding(self):
        if self._rebinding is None:
            self._rebinding = module_rebinding(
                self.tree, module_name_for(self.file_path)
            )
        return self._rebinding

    def names_are_stable(self, dotted: str) -> bool:
        dynamic, rebound = self.rebinding()
        return not dynamic and not any(part in rebound for part in dotted.split("."))

    def builtin_is_stable(self, name: str) -> bool:
        return not self.counts().get(name) and self.names_are_stable(name)

    def escape_is_trusted(self, dotted: str, qualified: str) -> bool:
        if self._patched is None:
            self._patched = has_mock_api_patching(self.tree)
        if self._writes is None:
            self._writes = attribute_write_names(self.tree)
        names, computed = self._writes
        if self._patched or computed or qualified.rsplit(".", 1)[-1] in names:
            return False
        return self.names_are_stable(dotted)

    def view_framework(self, decorator: ast.Call, func):
        """FLASK when a route decorator registers ``func`` on a Flask app or
        Blueprint, None when it registers it on a FastAPI/Starlette router.
        An unresolved receiver is Flask for ``.route``/``.errorhandler``
        (FastAPI routes use ``.get``/``.post``...); for the other methods it is
        Flask unless the module also imports FastAPI or Starlette."""
        target = decorator.func.value
        kind = None
        if isinstance(target, ast.Name):
            kind = self._receiver_kind(target.id, func)
        if kind == "json":
            return None
        if kind == FLASK or not self.json_framework:
            return FLASK
        if decorator.func.attr in {"route", "errorhandler"}:
            return FLASK
        return None

    def _parent_map(self):
        if self._parents is None:
            self._parents = {
                id(child): parent
                for parent in ast.walk(self.tree)
                for child in ast.iter_child_nodes(parent)
            }
        return self._parents

    def _enclosing_function(self, node):
        parents = self._parent_map()
        scope = parents.get(id(node))
        while scope is not None and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            scope = parents.get(id(scope))
        if isinstance(scope, ast.Module):
            return None
        return scope

    def _receiver_kind(self, name: str, func=None):
        """What ``name`` holds where ``func`` is defined: a parameter of the
        enclosing function takes the kind every call site passes it (one
        level, as in ``init(Flask(__name__))``); otherwise every assignment
        of the name in the module must build the same kind."""
        enclosing = None
        if func is not None:
            enclosing = self._enclosing_function(func)
        if enclosing is not None and name in {p.arg for p in _params(enclosing)}:
            return self._parameter_kind(enclosing, name)
        return self._assigned_kind(name)

    def _assigned_kind(self, name: str):
        if name in self._receivers:
            return self._receivers[name]
        kinds = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = getattr(node, "targets", None) or [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                kinds.add(self._expression_kind(node.value, node, assigned=False))
        self._receivers[name] = _combined_kind(kinds)
        return self._receivers[name]

    def _parameter_kind(self, function, name: str):
        key = (id(function), name)
        if key in self._receivers:
            return self._receivers[key]
        params = [*function.args.posonlyargs, *function.args.args]
        index = next((i for i, p in enumerate(params) if p.arg == name), None)
        kinds = set()
        if self.counts().get(function.name) == 1 and not function.decorator_list:
            for node in ast.walk(self.tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == function.name
                ):
                    continue
                argument = None
                if index is not None and index < len(node.args):
                    argument = node.args[index]
                for kw in node.keywords:
                    if kw.arg == name:
                        argument = kw.value
                kinds.add(self._expression_kind(argument, node, assigned=True))
        self._receivers[key] = _combined_kind(kinds)
        return self._receivers[key]

    def _expression_kind(self, value, node, assigned):
        if isinstance(value, ast.Name) and assigned:
            return self._assigned_kind(value.id)
        if not isinstance(value, ast.Call):
            return None
        dotted = _dotted(value.func)
        if not dotted:
            return None
        scope = self._enclosing_function(node)
        qualified = self.index.resolved_import(scope, dotted) or ""
        if qualified in _FLASK_APPS:
            return FLASK
        if qualified.split(".", 1)[0] in _JSON_FRAMEWORKS:
            return "json"
        return None

    def project_function(self, qualified: str):
        """``(module, function)`` for a plain module-level function defined
        in a project module found statically under the scan root, else None.
        Modules are parsed once, never imported, and capped in size."""
        if qualified in self._project_functions:
            return self._project_functions[qualified]
        result = None
        module_name, _, name = qualified.rpartition(".")
        path = self._project_module_path(module_name)
        if path is not None:
            result = self._function_in(path, name)
        self._project_functions[qualified] = result
        return result

    def relative_function(self, local: str):
        """The project function a module-level ``from .mod import name``
        binds to ``local``, resolved from this file's package directory."""
        key = ("relative", local)
        if key in self._project_functions:
            return self._project_functions[key]
        result = None
        found = [
            (node, alias)
            for node in self.tree.body
            if isinstance(node, ast.ImportFrom) and node.level
            for alias in node.names
            if (alias.asname or alias.name) == local
        ]
        if len(found) == 1 and not self.counts().get(local, 0) > 1:
            node, alias = found[0]
            base = Path(self.file_path).resolve().parent
            for _ in range(node.level - 1):
                base = base.parent
            parts = (node.module or "").split(".") if node.module else []
            path = _module_file([base], parts, self._scan_root())
            if path is not None:
                result = self._function_in(path, alias.name)
        self._project_functions[key] = result
        return result

    def _scan_root(self) -> Path:
        if self.project_root:
            return Path(self.project_root).resolve()
        return Path(self.file_path).resolve().parent

    def _project_module_path(self, module_name: str):
        parts = module_name.split(".")
        if not module_name or not all(part.isidentifier() for part in parts):
            return None
        root = self._scan_root()
        bases = [Path(self.file_path).resolve().parent, root, root / "src"]
        return _module_file(bases, parts, root)

    def _function_in(self, path: Path, name: str):
        if path == Path(self.file_path).resolve():
            return None
        if path not in self._project_modules:
            module = None
            try:
                stat = path.stat()
                tree = _parse_project_module(str(path), stat.st_mtime_ns, stat.st_size)
            except OSError:
                tree = None
            if tree is not None:
                module = _Module(tree, path, self.project_root)
            self._project_modules[path] = module
        module = self._project_modules[path]
        if module is None:
            return None
        helper = module.helpers().get(name)
        if helper is None or not any(helper is node for node in module.tree.body):
            return None
        return module, helper

    def helpers(self) -> dict:
        """Undecorated, non-generator functions bound once in the module, so
        a call by their name always runs that body."""
        if self._helpers is None:
            counts = self.counts()
            self._helpers = {}
            stack = list(self.tree.body)
            while stack:
                node = stack.pop()
                if isinstance(node, (ast.ClassDef, ast.Lambda)):
                    continue
                stack.extend(ast.iter_child_nodes(node))
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not node.decorator_list
                    and counts.get(node.name) == 1
                    and not _is_generator(node)
                ):
                    self._helpers[node.name] = node
        return self._helpers


class _Run:
    """Abstract interpretation of one function body."""

    def __init__(self, module: _Module, func, framework, sink, depth=0):
        self.module = module
        self.func = func
        self.framework = framework
        self.sink = sink
        self.depth = depth
        self.returns: list[_Value] = []
        self.reports: list[tuple[ast.Return, _Value]] = []
        self.loops: list[_LoopFrame] = []
        self.traces: list[list[_Env]] = []
        self.aliases = module.aliases_for(func)

    def run(self, env: _Env) -> _Value:
        end = self._block(self.func.body, env)
        if end is not None:
            self.returns.append(_NONE_VALUE)
        return reduce(_join, self.returns, None) or _NONE_VALUE

    def _resolve(self, node: ast.AST, env: _Env) -> str | None:
        dotted = _dotted(node)
        if not dotted or dotted.split(".", 1)[0] in env.values:
            return None
        return self.module.index.resolved_import(self.func, dotted)

    def _block(self, statements, env):
        """Run ``statements``; every state reached inside a ``try`` body, at
        any depth, is kept for its handlers."""
        for statement in statements:
            if env is None:
                return None
            env = self._statement(statement, env)
            if env is not None:
                for trace in self.traces:
                    trace.append(env.copy())
        return env

    def _statement(self, node, env):
        self.module.tick()
        if isinstance(node, ast.Assign):
            value = self.ev(node.value, env)
            for target in node.targets:
                self._assign(target, value, node.value, env)
            return env
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._assign(node.target, self.ev(node.value, env), node.value, env)
            return env
        if isinstance(node, ast.AugAssign):
            self._augmented(node, env)
            return env
        if isinstance(node, ast.Expr):
            self.ev(node.value, env)
            return env
        if isinstance(node, ast.Return):
            value = _NONE_VALUE
            if node.value is not None:
                value = self.ev(node.value, env)
            self.returns.append(value)
            if self.sink and node.value is not None:
                self._check_return(node, value, env)
            return None
        if isinstance(node, ast.Raise):
            if node.exc is not None:
                self.ev(node.exc, env)
            return None
        if isinstance(node, ast.If):
            self.ev(node.test, env)
            body = self._block(node.body, env.copy())
            orelse = self._block(node.orelse, env.copy())
            return _join_envs([body, orelse])
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self._loop(node, env)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self.ev(item.context_expr, env)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, _opaque(value), None, env)
            return self._block(node.body, env)
        if isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            return self._try(node, env)
        if isinstance(node, ast.Match):
            return self._match(node, env)
        if isinstance(node, ast.Break):
            if self.loops:
                self.loops[-1].breaks.append(env)
            return None
        if isinstance(node, ast.Continue):
            if self.loops:
                self.loops[-1].continues.append(env)
            return None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            env.values[node.name] = _CLEAN_OTHER
            return env
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                env.values.pop(alias.asname or alias.name.split(".")[0], None)
            return env
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.values.pop(target.id, None)
            return env
        if isinstance(node, ast.Assert):
            self.ev(node.test, env)
            return env
        return env

    def _loop(self, node, env):
        frame = _LoopFrame()
        self.loops.append(frame)
        state = env
        try:
            for _ in range(_MAX_LOOP_PASSES):
                body_env = state.copy()
                if isinstance(node, ast.While):
                    self.ev(node.test, body_env)
                else:
                    element = _element_of(self.ev(node.iter, body_env))
                    self._assign(node.target, element, None, body_env)
                end = self._block(node.body, body_env)
                following = _join_envs([end, *frame.continues])
                frame.continues = []
                joined = _join_envs([state, following])
                if joined.values == state.values:
                    break
                state = joined
        finally:
            self.loops.pop()
        normal = state
        if (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and node.test.value is True
        ):
            normal = None
        if normal is not None and node.orelse:
            normal = self._block(node.orelse, normal.copy())
        return _join_envs([normal, *frame.breaks])

    def _try(self, node, env):
        trace = [env.copy()]
        self.traces.append(trace)
        try:
            end = self._block(node.body, env.copy())
        finally:
            self.traces.pop()
        if end is not None and node.orelse:
            end = self._block(node.orelse, end)
        handler_entry = _join_envs(trace)
        ends = [end]
        for handler in node.handlers:
            entry = handler_entry.copy()
            if handler.type is not None:
                self.ev(handler.type, entry)
            if handler.name:
                entry.values[handler.name] = _CLEAN_OTHER
            ends.append(self._block(handler.body, entry))
        result = _join_envs(ends)
        if not node.finalbody:
            return result
        if result is None:
            self._block(node.finalbody, handler_entry.copy())
            return None
        return self._block(node.finalbody, result)

    def _match(self, node, env):
        subject = self.ev(node.subject, env)
        ends = []
        exhaustive = False
        for case in node.cases:
            entry = env.copy()
            pattern = case.pattern
            for part in ast.walk(pattern):
                name = None
                if isinstance(part, (ast.MatchAs, ast.MatchStar)):
                    name = part.name
                elif isinstance(part, ast.MatchMapping):
                    name = part.rest
                if not name:
                    continue
                if (
                    part is pattern
                    and isinstance(part, ast.MatchAs)
                    and part.pattern is None
                ):
                    entry.values[name] = subject
                else:
                    entry.values[name] = _other(subject)
            if case.guard is not None:
                self.ev(case.guard, entry)
            ends.append(self._block(case.body, entry))
            if case.guard is None and _irrefutable(pattern):
                exhaustive = True
                break
        if not exhaustive:
            ends.append(env)
        return _join_envs(ends)

    def _assign(self, target, value, value_node, env):
        if isinstance(target, ast.Name):
            env.values[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elements = target.elts
            starred = any(isinstance(element, ast.Starred) for element in elements)
            if (
                isinstance(value_node, (ast.Tuple, ast.List))
                and not starred
                and len(value_node.elts) == len(elements)
                and not any(isinstance(item, ast.Starred) for item in value_node.elts)
            ):
                for element, item in zip(elements, value_node.elts):
                    self._assign(element, self.ev(item, env), item, env)
                return
            element_value = _element_of(value)
            for element in elements:
                if isinstance(element, ast.Starred):
                    self._assign(element.value, _texts(element_value), None, env)
                else:
                    self._assign(element, element_value, None, env)
            return
        if isinstance(target, ast.Starred):
            self._assign(target.value, _other(value), None, env)
            return
        if isinstance(target, ast.Subscript):
            self._store_item(target, value, env)
            return
        if isinstance(target, ast.Attribute):
            self._store_attribute(target, value, env)

    def _touch(self, name, labels, env, skip=False):
        """An in-place change through ``name``: every name that may share its
        object gains ``labels``, and a response may no longer be HTML."""
        for other in self.aliases.get(name, (name,)):
            if (skip and other == name) or other not in env.values:
                continue
            current = env.values[other]
            if current.kind == RESPONSE:
                env.values[other] = _Value(RESPONSE, html=UNKNOWN, body=current.body)
            elif current.kind in _MUTABLE:
                env.values[other] = _with_labels(current, labels)

    def _set_response(self, name, html, body, env):
        env.values[name] = _Value(RESPONSE, html=html, body=body)
        self._touch(name, frozenset(), env, skip=True)

    def _store_item(self, target: ast.Subscript, value: _Value, env):
        container = target.value
        key_value = self.ev(target.slice, env)
        labels = _labels(_all_labels(value), _all_labels(key_value))
        if isinstance(container, ast.Attribute) and container.attr == "headers":
            root = container.value
            if (
                isinstance(root, ast.Name)
                and env.values.get(root.id, _CLEAN_OTHER).kind == RESPONSE
            ):
                self._header_write(root.id, target.slice, key_value, value, env)
                return
        if isinstance(container, ast.Name) and container.id in env.values:
            current = env.values[container.id]
            if current.kind == RESPONSE:
                self._header_write(container.id, target.slice, key_value, value, env)
                return
            if current.kind == DICT:
                constant, key = _key_of(target.slice, key_value)
                if constant:
                    keys = dict(current.keys)
                    keys[key] = value
                    env.values[container.id] = _dict_value(
                        keys, current.rest, current.labels
                    )
                else:
                    env.values[container.id] = _with_labels(current, labels)
                self._touch(container.id, labels, env, skip=True)
                return
        root = _chain_root(container)
        if root and root in env.values:
            self._touch(root, labels, env)

    def _header_write(self, name, key_node, key_value, value, env):
        response = env.values[name]
        constant, key = _key_of(key_node, key_value)
        if not constant:
            state = UNKNOWN
        elif str(key).lower() != "content-type":
            return
        else:
            state = _mimetype_state(value)
        self._set_response(name, state, response.body, env)

    def _store_attribute(self, target: ast.Attribute, value: _Value, env):
        base = target.value
        if isinstance(base, ast.Name) and base.id in env.values:
            current = env.values[base.id]
            if current.kind == RESPONSE:
                if target.attr in {"mimetype", "content_type"}:
                    self._set_response(
                        base.id, _mimetype_state(value), current.body, env
                    )
                elif target.attr in {"data", "content"}:
                    self._set_response(base.id, current.html, value, env)
                elif target.attr == "headers":
                    self._set_response(base.id, UNKNOWN, current.body, env)
                return
        root = _chain_root(base)
        if root and root in env.values:
            self._touch(root, _all_labels(value), env)

    def _augmented(self, node: ast.AugAssign, env):
        target = node.target
        right = self.ev(node.value, env)
        if isinstance(target, ast.Name):
            current = self.ev(ast.Name(id=target.id, ctx=ast.Load()), env)
            if current.kind in (TEXT, NUMBER, NONE):
                if current.kind == TEXT or right.kind == TEXT:
                    env.values[target.id] = _text(current, right)
                elif current.kind == NUMBER and right.kind == NUMBER:
                    env.values[target.id] = _NUMBER_VALUE
                else:
                    env.values[target.id] = _other(current, right)
                return
            labels = _all_labels(right)
            if current.kind == OTHER and right.kind == TEXT:
                env.values[target.id] = _text(current, right)
            elif current.kind in _MUTABLE:
                env.values[target.id] = _with_labels(current, labels)
            else:
                env.values[target.id] = _other(current, right)
            self._touch(target.id, labels, env, skip=True)
            return
        if isinstance(target, ast.Subscript):
            current = self.ev(target, env)
            self._store_item(target, _join(current, right), env)
            return
        if isinstance(target, ast.Attribute):
            current = self.ev(target, env)
            self._store_attribute(target, _join(current, right), env)

    def ev(self, node: ast.AST | None, env: _Env) -> _Value:
        self.module.tick()
        if node is None:
            return _NONE_VALUE
        handler = getattr(self, f"_ev_{type(node).__name__}", None)
        if handler is None:
            values = [
                self.ev(child, env)
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
            ]
            return _other(*values)
        return handler(node, env)

    def _ev_Constant(self, node, env):
        if isinstance(node.value, str):
            return _Value(TEXT, const=node.value)
        if isinstance(node.value, bytes):
            return _CLEAN_TEXT
        if node.value is None:
            return _NONE_VALUE
        if isinstance(node.value, (bool, int, float, complex)):
            return _NUMBER_VALUE
        return _CLEAN_OTHER

    def _ev_JoinedStr(self, node, env):
        values = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                values.append(self.ev(part.value, env))
                if part.format_spec is not None:
                    values.append(self.ev(part.format_spec, env))
        return _text(*values)

    def _ev_FormattedValue(self, node, env):
        return _text(self.ev(node.value, env))

    def _ev_Name(self, node, env):
        if node.id in env.values:
            return env.values[node.id]
        if self.module.flask:
            qualified = self.module.index.resolved_import(self.func, node.id)
            if qualified == "flask.request":
                return _Value(
                    REQUEST, frozenset({f"request object `{node.id}`"}), const=FLASK
                )
        return _CLEAN_OTHER

    def _ev_Attribute(self, node, env):
        if self.module.flask and self._resolve(node, env) == "flask.request":
            return _Value(
                REQUEST, frozenset({f"request object `{_dotted(node)}`"}), const=FLASK
            )
        if (
            self.module.django
            and node.attr == "request"
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ):
            return _Value(
                REQUEST, frozenset({"request object `self.request`"}), const=DJANGO
            )
        base = self.ev(node.value, env)
        if base.kind == REQUEST:
            return self._request_field(node, base)
        if base.kind == RESPONSE:
            if node.attr in {"data", "content", "text"}:
                return _text(base.body)
            return _CLEAN_OTHER
        if base.kind in (NONE, NUMBER):
            return _CLEAN_OTHER
        return _other(base)

    def _request_field(self, node: ast.Attribute, request: _Value) -> _Value:
        fields = _REQUEST_FIELDS.get(request.const, _REQUEST_FIELDS[FLASK])
        text = _dotted(node) or node.attr
        label = frozenset({f"request data `{text}`"})
        if node.attr in fields["clean"]:
            return _CLEAN_OTHER
        if node.attr in fields["mappings"]:
            return _Value(MAPPING, label)
        if node.attr in fields["texts"]:
            return _Value(TEXT, label)
        return _Value(OTHER, label)

    def _ev_Subscript(self, node, env):
        base = self.ev(node.value, env)
        key_value = self.ev(node.slice, env)
        if base.kind == DICT:
            constant, key = _key_of(node.slice, key_value)
            rest = None
            if base.rest:
                rest = _Value(OTHER, base.rest)
            if constant:
                found = dict(base.keys).get(key)
                return _join(found, rest) or _CLEAN_OTHER
            return _other(base)
        if base.kind in (TEXT, TEXTS, MAPPING):
            return _Value(TEXT, base.labels)
        if base.kind in (NONE, NUMBER):
            return _CLEAN_OTHER
        return _other(base)

    def _ev_BinOp(self, node, env):
        left = self.ev(node.left, env)
        right = self.ev(node.right, env)
        kinds = {left.kind, right.kind}
        if isinstance(node.op, ast.Add) and TEXT in kinds:
            return _text(left, right)
        if isinstance(node.op, ast.Add) and kinds == {TEXTS}:
            return _texts(left, right)
        if isinstance(node.op, ast.Mod) and left.kind == TEXT:
            return _text(left, right)
        if isinstance(node.op, ast.Mult) and TEXT in kinds:
            return _text(left, right)
        if kinds == {NUMBER}:
            return _NUMBER_VALUE
        return _other(left, right)

    def _ev_BoolOp(self, node, env):
        return reduce(_join, (self.ev(value, env) for value in node.values))

    def _ev_IfExp(self, node, env):
        self.ev(node.test, env)
        return _join(self.ev(node.body, env), self.ev(node.orelse, env))

    def _ev_Compare(self, node, env):
        self.ev(node.left, env)
        for comparator in node.comparators:
            self.ev(comparator, env)
        return _NUMBER_VALUE

    def _ev_UnaryOp(self, node, env):
        operand = self.ev(node.operand, env)
        if isinstance(node.op, ast.Not) or operand.kind == NUMBER:
            return _NUMBER_VALUE
        return _other(operand)

    def _ev_Lambda(self, node, env):
        return _CLEAN_OTHER

    def _ev_Await(self, node, env):
        return self.ev(node.value, env)

    def _ev_Starred(self, node, env):
        return self.ev(node.value, env)

    def _ev_NamedExpr(self, node, env):
        value = self.ev(node.value, env)
        self._assign(node.target, value, node.value, env)
        return value

    def _ev_Dict(self, node, env):
        keys = {}
        rest = []
        for key_node, value_node in zip(node.keys, node.values):
            value = self.ev(value_node, env)
            if key_node is None:
                rest.append(_all_labels(value))
                continue
            key_value = self.ev(key_node, env)
            constant, key = _key_of(key_node, key_value)
            if constant:
                keys[key] = value
            else:
                rest.append(_all_labels(value))
                rest.append(_all_labels(key_value))
        return _dict_value(keys, _labels(*rest))

    def _ev_List(self, node, env):
        values = [self.ev(element, env) for element in node.elts]
        if all(value.kind == TEXT for value in values):
            return _texts(*values)
        return _other(*values)

    _ev_Tuple = _ev_List
    _ev_Set = _ev_List

    def _comprehension(self, node, env, elements):
        inner = env.copy()
        for generator in node.generators:
            element = _element_of(self.ev(generator.iter, inner))
            self._assign(generator.target, element, None, inner)
            for condition in generator.ifs:
                self.ev(condition, inner)
        return [self.ev(element, inner) for element in elements]

    def _ev_ListComp(self, node, env):
        values = self._comprehension(node, env, [node.elt])
        if values[0].kind == TEXT:
            return _texts(*values)
        return _other(*values)

    _ev_SetComp = _ev_ListComp
    _ev_GeneratorExp = _ev_ListComp

    def _ev_DictComp(self, node, env):
        return _other(*self._comprehension(node, env, [node.key, node.value]))

    def _ev_Call(self, node: ast.Call, env):
        func = node.func
        qualified = self._resolve(func, env)
        if qualified is not None and qualified.startswith("flask.request."):
            qualified = None
        if qualified is not None:
            known = self._known_call(node, qualified, env)
            if known is not None:
                return known
        if (
            isinstance(func, ast.Attribute)
            and qualified is None
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "headers"
            and isinstance(func.value.value, ast.Name)
            and env.values.get(func.value.value.id, _CLEAN_OTHER).kind == RESPONSE
        ):
            return self._headers_method(node, func.value.value.id, func.attr, env)
        receiver = None
        if isinstance(func, ast.Attribute):
            receiver = self.ev(func.value, env)
        args = [self.ev(arg, env) for arg in node.args]
        keywords = [(kw.arg, self.ev(kw.value, env)) for kw in node.keywords]
        if isinstance(func, ast.Name) and func.id not in env.values:
            builtin = self._builtin_call(func.id, args, keywords)
            if builtin is not None:
                return builtin
            helper = self.module.helpers().get(func.id)
            if helper is not None and qualified is None:
                result = self._helper_call(helper, node, args, keywords)
                if result is not None and not self._resolved_helper(helper):
                    result = _opaqued(result)
                if result is not None:
                    self._writes_into(node, args, keywords, receiver, env)
                    return result
        project = self._project_call(node, qualified, args, keywords, env)
        if project is not None:
            self._writes_into(node, args, keywords, receiver, env)
            return project
        if receiver is not None and qualified is None:
            method = self._method_call(node, func, receiver, args, keywords, env)
            if method is not None:
                return method
        self._writes_into(node, args, keywords, receiver, env)
        return _opaque(*args, *(value for _, value in keywords), receiver)

    def _project_call(self, node, qualified, args, keywords, env):
        """One-level summary of a plain function in another project module,
        imported absolutely or with ``from .mod import name``."""
        found = None
        func = node.func
        if qualified is not None and self.module.names_are_stable(_dotted(func)):
            found = self.module.project_function(qualified)
        elif (
            qualified is None
            and isinstance(func, ast.Name)
            and func.id not in env.values
            and func.id not in self.module.helpers()
        ):
            found = self.module.relative_function(func.id)
        if found is None:
            return None
        module, helper = found
        try:
            result = self._helper_call(helper, node, args, keywords, module)
        except (_BudgetExceeded, RecursionError):
            return None
        if result is not None and not self._resolved_helper(helper):
            result = _opaqued(result)
        return result

    def _resolved_helper(self, helper) -> bool:
        """A helper whose result keeps request data listed: no loop, branch
        or comprehension that could rebuild the value character by character
        (an escaper the analysis cannot read). Calls inside it are judged the
        same way, up to ``_MAX_HELPER_DEPTH`` levels; a deeper, recursive or
        unresolved call leaves its result unresolved."""
        return not any(isinstance(node, _BRANCHES) for node in _own_nodes(helper))

    def _known_call(self, node, qualified, env):
        if qualified in _ESCAPES and self.module.escape_is_trusted(
            _dotted(node.func), qualified
        ):
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                self.ev(arg, env)
            return _CLEAN_TEXT
        if qualified in _FORMAT_ESCAPES and self.module.escape_is_trusted(
            _dotted(node.func), qualified
        ):
            values = [self.ev(arg, env) for arg in node.args]
            for kw in node.keywords:
                self.ev(kw.value, env)
            if not values or any(isinstance(arg, ast.Starred) for arg in node.args[:1]):
                return _text(*values)
            return _text(values[0])
        if qualified in _PASS_THROUGH_TEXT:
            values = [self.ev(arg, env) for arg in node.args]
            return _text(*values, *(self.ev(kw.value, env) for kw in node.keywords))
        if qualified in _PASS_THROUGH_OBJECTS:
            values = [self.ev(arg, env) for arg in node.args]
            return _other(*values, *(self.ev(kw.value, env) for kw in node.keywords))
        if qualified in _MARK_SAFE:
            return _text(*(self.ev(arg, env) for arg in node.args))
        if qualified in _MAKE_RESPONSE:
            return self._make_response(node, env)
        if qualified in _FLASK_RESPONSES:
            return self._constructed_response(
                node, env, ("response", "status", "headers", "mimetype", "content_type")
            )
        if qualified in _DJANGO_RESPONSES:
            return self._constructed_response(
                node, env, ("content", "content_type", "status", "reason", "charset")
            )
        return None

    def _builtin_call(self, name, args, keywords):
        if name not in _TEXT_BUILTINS | _NUMBER_BUILTINS | _CONTAINER_BUILTINS | {
            "dict"
        }:
            return None
        if not self.module.builtin_is_stable(name):
            return None
        named = [value for _, value in keywords]
        if name in _NUMBER_BUILTINS:
            return _NUMBER_VALUE
        if name in _TEXT_BUILTINS:
            return _text(*args, *named)
        if name == "dict":
            if not args and all(key is not None for key, _ in keywords):
                return _dict_value(dict(keywords))
            if len(args) == 1 and args[0].kind == MAPPING and not keywords:
                return args[0]
            return _other(*args, *named)
        if not args and not keywords:
            return _texts()
        if args and all(value.kind in (TEXT, TEXTS, MAPPING) for value in args):
            return _texts(*args, *named)
        return _other(*args, *named)

    def _method_call(
        self, node, func: ast.Attribute, receiver, args, keyword_pairs, env
    ):
        method = func.attr
        receiver_node = func.value
        keywords = {key: value for key, value in keyword_pairs if key is not None}
        others = [*args, *(value for _, value in keyword_pairs)]
        if receiver.kind == REQUEST:
            return self._request_method(func, receiver)
        if receiver.kind == MAPPING:
            return self._mapping_method(node, method, receiver, args, keywords)
        if receiver.kind == TEXT:
            if method == "translate" or (
                method == "replace" and _replaces_markup(node)
            ):
                return _Value(
                    TEXT, _opaque_labels(_all_labels(_text(receiver, *others)))
                )
            if method in _TEXT_METHODS:
                return _text(receiver, *others)
            if method in _TEXTS_METHODS:
                return _texts(receiver, *others)
            if method in _TEXT_NUMBER_METHODS:
                return _NUMBER_VALUE
            return None
        name = None
        if isinstance(receiver_node, ast.Name) and receiver_node.id in env.values:
            name = receiver_node.id
        if receiver.kind == TEXTS and name is not None:
            if method in _LIST_INSERTS:
                self._add_to(name, others, env)
                return _NONE_VALUE
            if method in _LIST_ELEMENT_METHODS:
                return _Value(TEXT, receiver.labels)
            if method in {"index", "count"}:
                return _NUMBER_VALUE
            if method == "copy":
                return receiver
            return None
        if receiver.kind == DICT and name is not None:
            return self._dict_method(
                node, name, method, receiver, args, keyword_pairs, env
            )
        if receiver.kind == RESPONSE and name is not None:
            return self._response_method(name, method, receiver, args, env)
        return None

    def _add_to(self, name, values, env):
        current = env.values[name]
        labels = _labels(*(_all_labels(value) for value in values))
        if current.kind == TEXTS and not all(
            value.kind in (TEXT, TEXTS) for value in values
        ):
            env.values[name] = _other(current, *values)
        else:
            env.values[name] = _with_labels(current, labels)
        self._touch(name, labels, env, skip=True)

    def _request_method(self, func: ast.Attribute, request: _Value) -> _Value:
        fields = _REQUEST_FIELDS.get(request.const, _REQUEST_FIELDS[FLASK])
        label = frozenset({f"request data `{_dotted(func) or func.attr}()`"})
        if func.attr in _REQUEST_CLEAN_METHODS:
            return _NUMBER_VALUE
        if func.attr in fields["text_methods"]:
            return _Value(TEXT, label)
        return _Value(OTHER, label)

    def _numeric_type(self, node: ast.Call) -> bool:
        conversion = None
        if len(node.args) > 2:
            conversion = node.args[2]
        for kw in node.keywords:
            if kw.arg == "type":
                conversion = kw.value
        return (
            isinstance(conversion, ast.Name)
            and conversion.id in {"int", "float", "bool"}
            and self.module.builtin_is_stable(conversion.id)
        )

    def _mapping_method(self, node, method, receiver, args, keywords):
        if method in {"get", "getlist"} and self._numeric_type(node):
            return _NUMBER_VALUE
        if method in _MAPPING_TEXT_METHODS:
            default = None
            if len(args) > 1:
                default = args[1]
            if "default" in keywords:
                default = keywords["default"]
            return _join(_Value(TEXT, receiver.labels), default)
        if method in _MAPPING_TEXTS_METHODS:
            return _Value(TEXTS, receiver.labels)
        if method in _MAPPING_SELF_METHODS:
            return receiver
        return _other(receiver)

    def _dict_method(self, node, name, method, receiver, args, keyword_pairs, env):
        named = [value for _, value in keyword_pairs]
        if method == "get" and node.args:
            constant, key = _key_of(node.args[0], args[0])
            default = None
            if len(args) > 1:
                default = args[1]
            rest = None
            if receiver.rest:
                rest = _Value(OTHER, receiver.rest)
            if constant:
                found = dict(receiver.keys).get(key)
                return _join(_join(found, rest), default) or _NONE_VALUE
            return _join(_other(receiver), default)
        if method == "copy":
            return receiver
        if method in {"keys", "values", "items", "pop", "popitem"}:
            return _other(receiver)
        if method == "clear":
            env.values[name] = _dict_value({}, labels=receiver.labels)
            return _NONE_VALUE
        if (
            method == "update"
            and len(node.args) <= 1
            and all(key is not None for key, _ in keyword_pairs)
            and (not node.args or args[0].kind == DICT)
        ):
            keys = dict(receiver.keys)
            rest = receiver.rest
            if node.args:
                keys.update(dict(args[0].keys))
                rest = _labels(rest, args[0].rest)
            keys.update(dict(keyword_pairs))
            env.values[name] = _dict_value(keys, rest, receiver.labels)
            self._touch(name, _all_labels(env.values[name]), env, skip=True)
            return _NONE_VALUE
        self._add_to(name, [*args, *named], env)
        if method == "setdefault":
            return _other(env.values[name])
        return _other(receiver, *args, *named)

    def _response_method(self, name, method, receiver, args, env):
        if method in _RESPONSE_NEUTRAL_METHODS:
            return _NONE_VALUE
        if method == "set_data" and args:
            self._set_response(name, receiver.html, args[0], env)
            return _NONE_VALUE
        if method == "write":
            self._set_response(name, receiver.html, _text(receiver.body, *args), env)
            return _NONE_VALUE
        if method in {"get_data", "getvalue"}:
            return _text(receiver.body)
        self._set_response(name, UNKNOWN, receiver.body, env)
        return _CLEAN_OTHER

    def _headers_method(self, node, name, method, env):
        args = [self.ev(arg, env) for arg in node.args]
        named = [self.ev(kw.value, env) for kw in node.keywords]
        response = env.values[name]
        if method in _HEADER_WRITES and len(node.args) >= 2 and not node.keywords:
            self._header_write(name, node.args[0], args[0], args[1], env)
            return _NONE_VALUE
        if method in {"get", "getlist", "get_all", "keys", "items", "values"}:
            return _other(*args, *named)
        if method in {"update", "extend"} and len(node.args) == 1 and not node.keywords:
            state = self._headers_state(node.args[0], args[0], env)
            if state is not None:
                self._set_response(name, state, response.body, env)
            return _NONE_VALUE
        self._set_response(name, UNKNOWN, response.body, env)
        return _NONE_VALUE

    def _writes_into(self, node: ast.Call, args, keyword_pairs, receiver, env):
        """An unknown call may store any argument's data into a mutable
        argument or its receiver, and may change a response it is given."""
        operands = [_unstarred(arg) for arg in node.args]
        operands.extend(kw.value for kw in node.keywords)
        values = [*args, *(value for _, value in keyword_pairs)]
        if isinstance(node.func, ast.Attribute):
            operands.append(node.func.value)
            values.append(receiver)
        for index, operand in enumerate(operands):
            root = _chain_root(operand)
            if not root or root not in env.values:
                continue
            labels = _labels(
                *(_all_labels(value) for i, value in enumerate(values) if i != index)
            )
            self._touch(root, _opaque_labels(labels), env)

    def _helper_call(self, helper, node, args, keyword_pairs, module=None):
        """The value a module-level helper returns for these arguments, or
        None when the call cannot be bound to its parameters."""
        if self.depth >= _MAX_HELPER_DEPTH:
            return None
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            return None
        if any(key is None for key, _ in keyword_pairs):
            return None
        arguments = helper.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if len(args) > len(positional) and arguments.vararg is None:
            return None
        bound = {param.arg: value for param, value in zip(positional, args)}
        if arguments.vararg is not None:
            bound[arguments.vararg.arg] = _other(*args[len(positional) :])
        named = {param.arg for param in positional} | {
            param.arg for param in arguments.kwonlyargs
        }
        spill = []
        for key, value in keyword_pairs:
            if key in bound:
                return None
            if key in named:
                bound[key] = value
            elif arguments.kwarg is not None:
                spill.append(value)
            else:
                return None
        if arguments.kwarg is not None:
            bound[arguments.kwarg.arg] = _other(*spill)
        defaulted = positional[len(positional) - len(arguments.defaults) :]
        defaults = {param.arg for param in defaulted}
        for param, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
            if default is not None:
                defaults.add(param.arg)
        for param in [*positional, *arguments.kwonlyargs]:
            if param.arg in bound:
                continue
            if param.arg not in defaults:
                return None
            bound[param.arg] = _CLEAN_OTHER
        key = (
            id(helper),
            self.depth,
            tuple(sorted(bound.items(), key=lambda item: item[0])),
        )
        if key in self.module.summaries:
            return self.module.summaries[key]
        if key in self.module.in_progress:
            return None
        self.module.in_progress.add(key)
        try:
            run = _Run(
                module or self.module, helper, self.framework, False, self.depth + 1
            )
            result = run.run(_Env(bound))
        finally:
            self.module.in_progress.discard(key)
        self.module.summaries[key] = result
        return result

    def _make_response(self, node, env):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or node.keywords:
            values = [self.ev(arg, env) for arg in node.args]
            return _Value(RESPONSE, html=UNKNOWN, body=_other(*values))
        parts = list(node.args)
        if len(parts) == 1 and isinstance(parts[0], ast.Tuple):
            parts = list(parts[0].elts)
        if not parts:
            return _Value(RESPONSE, html=HTML, body=_CLEAN_TEXT)
        body = self.ev(parts[0], env)
        html = HTML
        if body.kind == RESPONSE:
            html = body.html
            body = body.body
        extra = self._extras_state(parts[1:], env)
        if extra is not None:
            html = extra
        return _Value(RESPONSE, html=html, body=body)

    def _constructed_response(self, node, env, names):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            kw.arg is None for kw in node.keywords
        ):
            values = [self.ev(arg, env) for arg in node.args]
            return _Value(RESPONSE, html=UNKNOWN, body=_other(*values))
        given = dict(zip(names, node.args))
        for kw in node.keywords:
            given[kw.arg] = kw.value
        body = _CLEAN_TEXT
        if given.get(names[0]) is not None:
            body = self.ev(given[names[0]], env)
        html = HTML
        if given.get("headers") is not None:
            headers = given["headers"]
            state = self._headers_state(headers, self.ev(headers, env), env)
            if state is not None:
                html = state
        for field in ("mimetype", "content_type"):
            if given.get(field) is not None:
                value = self.ev(given[field], env)
                if value.kind != NONE:
                    html = _mimetype_state(value)
        return _Value(RESPONSE, html=html, body=body)

    def _extras_state(self, extras, env):
        """How the status and headers after a response body set its type:
        None when they give no ``Content-Type``, else HTML, NOT_HTML or
        UNKNOWN (a value that may be a header collection the analysis
        cannot read)."""
        state = None
        for extra in extras:
            value = self.ev(extra, env)
            if value.kind in (NUMBER, NONE):
                continue
            if value.kind == TEXT and value.const is not None:
                continue
            if isinstance(extra, ast.Attribute) and self._resolve(extra, env):
                continue
            found = self._headers_state(extra, value, env)
            if found is None:
                continue
            state = _join_state(state, found)
            if state == UNKNOWN:
                return UNKNOWN
        return state

    def _headers_state(self, node, value, env):
        """The response type a header collection sets, None when it sets
        none, UNKNOWN when it cannot be read."""
        pairs = []
        if isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                if key_node is None:
                    return UNKNOWN
                pairs.append((key_node, value_node))
        elif isinstance(node, (ast.List, ast.Tuple)):
            for item in node.elts:
                if not isinstance(item, (ast.Tuple, ast.List)) or len(item.elts) != 2:
                    return UNKNOWN
                pairs.append((item.elts[0], item.elts[1]))
        elif value.kind == DICT:
            if value.rest:
                return UNKNOWN
            state = None
            for key, item in value.keys:
                if str(key).lower() == "content-type":
                    state = _join_state(state, _mimetype_state(item))
            return state
        else:
            return UNKNOWN
        state = None
        for key_node, value_node in pairs:
            key_value = self.ev(key_node, env)
            constant, key = _key_of(key_node, key_value)
            if not constant:
                return UNKNOWN
            if str(key).lower() == "content-type":
                state = _join_state(state, _mimetype_state(self.ev(value_node, env)))
        return state

    def _check_return(self, node: ast.Return, value: _Value, env):
        body, html = self._served(node.value, value, env)
        if body is None or html != HTML:
            return
        if body.kind != TEXT or not body.labels:
            return
        self.reports.append((node, body))

    def _served(self, node, value, env):
        if (
            isinstance(node, ast.Tuple)
            and node.elts
            and not any(isinstance(item, ast.Starred) for item in node.elts)
        ):
            first = self.ev(node.elts[0], env)
            body, html = self._served(node.elts[0], first, env)
            extra = self._extras_state(node.elts[1:], env)
            if extra is not None:
                html = extra
            return body, html
        if value.kind == RESPONSE:
            return value.body, value.html
        if value.kind == TEXT and self.framework == FLASK:
            return value, HTML
        return None, None


def _replaces_markup(node: ast.Call) -> bool:
    """``s.replace(old, new)`` where ``old`` may be ``<``, ``>`` or ``&``:
    a hand-written escape step the analysis does not evaluate."""
    if not node.args:
        return True
    old = node.args[0]
    if not (isinstance(old, ast.Constant) and isinstance(old.value, (str, bytes))):
        return True
    text = old.value
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return any(char in text for char in "<>&")


def _unstarred(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Starred):
        return node.value
    return node


def _irrefutable(pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable(option) for option in pattern.patterns)
    return False


def _flask_params(func, rules) -> dict[str, _Value]:
    converters: dict[str, set] = {}
    for rule in rules:
        for match in _RULE_VARIABLE.finditer(rule):
            converters.setdefault(match.group("name"), set()).add(
                match.group("converter")
            )
    values = {}
    for param in _params(func):
        found = converters.get(param.arg, set())
        if found & _TEXT_CONVERTERS:
            values[param.arg] = _Value(
                TEXT, frozenset({f"route parameter `{param.arg}` of `{func.name}`"})
            )
        elif found & _NUMBER_CONVERTERS:
            values[param.arg] = _NUMBER_VALUE
        else:
            values[param.arg] = _CLEAN_OTHER
    return values


def _django_params(func) -> dict[str, _Value] | None:
    values = {}
    found = False
    for param in _params(func):
        if param.arg in {"self", "cls"}:
            values[param.arg] = _CLEAN_OTHER
            continue
        if _is_request_param(param):
            found = True
            values[param.arg] = _Value(
                REQUEST, frozenset({f"request object `{param.arg}`"}), const=DJANGO
            )
        else:
            values[param.arg] = _CLEAN_OTHER
    if not found and not _reads_self_request(func):
        return None
    return values


def _reads_self_request(func) -> bool:
    params = _params(func)
    if not params or params[0].arg != "self":
        return False
    return any(
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        for node in _own_nodes(func)
    )


def _view_entries(module: _Module):
    for node in ast.walk(module.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _is_generator(node):
            continue
        if module.flask:
            rules = _route_rules(node, module)
            if rules is not None:
                yield node, FLASK, _flask_params(node, rules)
                continue
        if module.django:
            params = _django_params(node)
            if params is not None:
                yield node, DJANGO, params


def _finding(file_path, func, node: ast.Return, body: _Value, framework: str) -> dict:
    direct = sorted(label for label in body.labels if not label.startswith(_OPAQUE))
    labels = direct or sorted({_plain(label) for label in body.labels})
    view = "Django view"
    if framework == FLASK:
        view = "Flask view"
    step = "reaches the response body without HTML escaping"
    message = (
        f"XSS ({view} returns request data in an HTML response without "
        f"escaping it: {labels[0]})"
    )
    if not direct:
        step = (
            "reaches the response body only through calls the analysis does "
            "not resolve, which may escape it"
        )
        message = (
            f"XSS ({view} returns request data in an HTML response through "
            f"calls that may not escape it: {labels[0]})"
        )
    finding = {
        "rule_id": "SKY-D228",
        "severity": "HIGH",
        "message": message,
        "file": str(file_path),
        "line": node.lineno,
        "col": node.col_offset,
        "symbol": func.name,
        "metadata": {
            "security_evidence": {
                "evidence_kind": "python_response_xss_taint",
                "source": labels[0],
                "sources": labels,
                "sink": f"HTML response body returned by `{func.name}` ({view})",
                "path": [
                    f"untrusted input from {labels[0]}",
                    step,
                    "served as text/html",
                ],
                "guards_seen": [],
                "guards_missing": [
                    "HTML-escape the value (html.escape or markupsafe.escape) "
                    "or return it with a non-HTML mimetype"
                ],
                "analysis_complete": False,
            }
        },
    }
    if not direct:
        finding["low_risk_context"] = {
            "reason": _UNRESOLVED,
            "detail": (
                "request data reaches the HTML body only through a call, method "
                "or helper loop the analysis cannot resolve"
            ),
        }
    return finding


def scan(tree, file_path, findings, *, project_root=None):
    if not isinstance(tree, ast.Module) or _is_test_module(file_path):
        return
    try:
        module = _Module(tree, file_path, project_root)
        if not module.flask and not module.django:
            return
        for func, framework, params in _view_entries(module):
            if _too_large(func):
                continue
            run = _Run(module, func, framework, True)
            try:
                run.run(_Env(params))
            except RecursionError:
                continue
            for node, body in run.reports:
                findings.append(_finding(file_path, func, node, body, framework))
    except _BudgetExceeded:
        return
    except Exception as error:
        print(f"Response XSS analysis failed for {file_path}: {error}", file=sys.stderr)
