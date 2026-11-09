"""Request-taint sinks for TypeScript/JavaScript server handlers.

A bounded, single-file, intra-handler taint analysis. A handler is an Express,
Fastify, Hapi or Next.js pages-API function (``(req, res)``), a Koa or
``getServerSideProps`` function (``ctx``), a NestJS controller method with
``@Body()``/``@Query()``/``@Param()``/``@Headers()`` parameters, a Next.js
App Router ``route`` handler or a Remix ``loader``/``action``. A finding is
produced only when request data reaches:

* SQL query text: ``query``/``execute``/``raw``/``$queryRawUnsafe``/knex
  ``whereRaw``/TypeORM query-builder conditions (SKY-D211)
* ``child_process.exec``/``execSync`` command text (SKY-D212)
* ``fs`` paths, ``res.sendFile``/``res.download`` (SKY-D215)
* the host of an outgoing request: ``fetch``, axios, got, undici, ``http(s)``
  (SKY-D216)
* HTML sent in a response: Express ``res.send``, Koa ``ctx.body`` (SKY-D228)
* a redirect target (SKY-D230)
* a MongoDB/Mongoose query object or ``$where`` (SKY-D238)
* property names of a two-level write or an unguarded recursive merge
  (SKY-D510)

Taint follows local bindings in source order (a later plain assignment in the
same block replaces an earlier value), destructuring, string building and
string methods, ``path.join``/``resolve``, ``new URL``, ``JSON.parse`` and
same-file helper functions. Calls into other modules stop it. Sanitizers are
recognised by what they are, never by their name: numeric coercion, ``path``
module ``basename`` imported from ``path``, a same-file helper whose result
escapes ``<``, and guards whose failing branch returns or throws.

It also reports ``process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`` and
``rejectUnauthorized: false`` (SKY-D210), which need no source evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from skylos.visitors.languages.typescript.child_process_shell import ShellProcessCalls

_MAX_NODES = 200_000
_MAX_LABEL = 80
_MAX_TAINT_DEPTH = 40
_MAX_SUMMARY_DEPTH = 3
_MAX_LEAF_DEPTH = 3

TEXT = "text"
OBJECT = "object"

_CHILD_PROCESS_MODULES = frozenset({"child_process", "node:child_process"})
_EXEC_FUNCS = frozenset({"exec", "execSync"})
_PATH_MODULES = frozenset(
    {
        "path",
        "node:path",
        "path/posix",
        "node:path/posix",
        "path/win32",
        "node:path/win32",
        "upath",
        "pathe",
    }
)
_PATH_BUILDERS = frozenset({"join", "resolve", "normalize", "relative", "format"})
_PATH_NORMALIZERS = frozenset({"join", "resolve", "normalize"})
_FS_MODULES = frozenset(
    {
        "fs",
        "node:fs",
        "fs/promises",
        "node:fs/promises",
        "fs-extra",
        "graceful-fs",
        "original-fs",
    }
)
_FS_PATH_FUNCS = frozenset(
    {
        "readFile",
        "readFileSync",
        "createReadStream",
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "createWriteStream",
        "unlink",
        "unlinkSync",
        "rm",
        "rmSync",
        "rmdir",
        "rmdirSync",
        "readdir",
        "readdirSync",
        "open",
        "openSync",
        "mkdir",
        "mkdirSync",
        "truncate",
        "truncateSync",
        "readJson",
        "readJSON",
        "readJsonSync",
        "writeJson",
        "writeJSON",
        "writeJsonSync",
        "outputFile",
        "outputFileSync",
        "outputJson",
        "outputJsonSync",
        "remove",
        "removeSync",
        "emptyDir",
        "emptyDirSync",
        "ensureFile",
        "ensureFileSync",
    }
)
_FS_TWO_PATH_FUNCS = frozenset(
    {
        "rename",
        "renameSync",
        "copyFile",
        "copyFileSync",
        "cp",
        "cpSync",
        "link",
        "linkSync",
        "symlink",
        "symlinkSync",
        "copy",
        "copySync",
        "move",
        "moveSync",
    }
)
_HTTP_VERBS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)
_FETCH_MODULES = frozenset({"node-fetch", "cross-fetch", "isomorphic-fetch"})
_HTTP_CLIENT_MODULES = frozenset(
    {"axios", "got", "superagent", "request", "needle", "ky", "ky-universal"}
)
_NODE_HTTP_MODULES = frozenset({"http", "https", "node:http", "node:https"})
_URL_CONFIG_KEYS = ("url", "uri", "baseURL", "host", "hostname", "origin")
_REDIRECT_IMPORT_MODULES = frozenset(
    {
        "next/navigation",
        "@remix-run/node",
        "@remix-run/server-runtime",
        "@remix-run/cloudflare",
        "react-router",
        "@sveltejs/kit",
    }
)
_MONGO_MODULES = frozenset(
    {
        "mongoose",
        "mongodb",
        "@nestjs/mongoose",
        "@typegoose/typegoose",
        "mongojs",
        "monk",
    }
)
_MONGO_FILTER_METHODS = frozenset(
    {
        "find",
        "findOne",
        "findOneAndUpdate",
        "findOneAndDelete",
        "findOneAndRemove",
        "findOneAndReplace",
        "updateOne",
        "updateMany",
        "update",
        "deleteOne",
        "deleteMany",
        "remove",
        "replaceOne",
        "countDocuments",
        "count",
        "exists",
        "where",
    }
)
_ORM_OPTION_KEYS = frozenset(
    {"where", "select", "include", "relations", "order", "orderBy", "data"}
)
_MONGO_LOGICAL_KEYS = frozenset({"$and", "$or", "$nor"})
_NEST_MODULES = frozenset({"@nestjs/common", "routing-controllers"})
_NEST_SOURCE_DECORATORS = {
    "Body": OBJECT,
    "Query": OBJECT,
    "Param": TEXT,
    "Params": TEXT,
    "Headers": TEXT,
    "HostParam": TEXT,
    "UploadedFile": TEXT,
    "UploadedFiles": TEXT,
    "QueryParam": OBJECT,
    "QueryParams": OBJECT,
    "BodyParam": OBJECT,
    "HeaderParam": TEXT,
    "CookieParam": TEXT,
}
_NEST_REQUEST_DECORATORS = frozenset({"Req", "Request"})
_NEST_RESPONSE_DECORATORS = frozenset({"Res", "Response"})
_NEST_SANITIZING_PIPES = frozenset(
    {"ParseIntPipe", "ParseFloatPipe", "ParseBoolPipe", "ParseUUIDPipe", "ParseEnumPipe"}
)
_UNTYPED_DTO_NAMES = frozenset(
    {"Record", "Object", "Partial", "Array", "Map", "Readonly", "Any", "Express"}
)

_EXPRESS_FIELDS = {
    "body": OBJECT,
    "query": OBJECT,
    "params": TEXT,
    "headers": TEXT,
    "cookies": OBJECT,
    "signedCookies": OBJECT,
    "files": TEXT,
    "file": TEXT,
    "url": TEXT,
    "originalUrl": TEXT,
    "path": TEXT,
    "hostname": TEXT,
    "host": TEXT,
    "payload": OBJECT,
    "state": TEXT,
}
_STRING_QUERY_FRAMEWORKS = frozenset({"fastify", "hapi", "next-pages"})
_LONE_REQUEST = "express-helper"
_LONE_REQUEST_FIELDS = frozenset(
    {"body", "query", "params", "headers", "cookies", "signedCookies"}
)
_EXPRESS_ACCESSORS = frozenset({"get", "header", "param"})
_FETCH_FIELDS = frozenset(
    {"url", "nextUrl", "headers", "cookies", "body", "referrer", "geo", "ip"}
)
_FETCH_BODY_METHODS = {
    "json": OBJECT,
    "text": TEXT,
    "formData": TEXT,
    "arrayBuffer": TEXT,
    "blob": TEXT,
}
_KOA_REQUEST_FIELDS = {
    "body": OBJECT,
    "query": TEXT,
    "headers": TEXT,
    "header": TEXT,
    "url": TEXT,
    "href": TEXT,
    "path": TEXT,
    "querystring": TEXT,
    "search": TEXT,
    "files": TEXT,
    "host": TEXT,
    "hostname": TEXT,
    "origin": TEXT,
}
_KOA_CONTEXT_FIELDS = frozenset(
    {
        "query",
        "params",
        "headers",
        "header",
        "querystring",
        "url",
        "originalUrl",
        "href",
        "path",
        "search",
        "host",
        "hostname",
        "origin",
        "resolvedUrl",
    }
)
_REQUEST_PARAM_NAMES = frozenset({"req", "request"})
_CONTEXT_PARAM_NAMES = frozenset({"ctx", "context"})
_RESPONSE_NAMES = frozenset({"res", "response", "reply"})
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "all", "use", "options", "head"}
)
_REQUEST_TYPE_RE = re.compile(
    r"\b(?:Request|FastifyRequest|IncomingMessage|NextApiRequest|NextRequest)\b"
)
_CONTEXT_TYPE_RE = re.compile(
    r"\b(?:Context|ParameterizedContext|RouterContext|GetServerSidePropsContext)\b"
)
_NEXT_ROUTE_FILE_RE = re.compile(
    r"(?:^|/)app/(?:.+/)?route\.(?:[cm]?[jt]sx?)$", re.IGNORECASE
)
_NEXT_ROUTE_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
_REMIX_HANDLERS = frozenset({"loader", "action"})

_STRING_METHODS = frozenset(
    {
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toLocaleLowerCase",
        "toLocaleUpperCase",
        "toString",
        "slice",
        "substring",
        "substr",
        "replace",
        "replaceAll",
        "concat",
        "padStart",
        "padEnd",
        "normalize",
        "at",
        "join",
        "split",
        "valueOf",
        "toJSON",
    }
)
_CONTAINER_GETTERS = frozenset({"get", "getAll", "values", "entries", "item"})
_NUMERIC_CALLS = frozenset(
    {"Number", "parseInt", "parseFloat", "Boolean", "BigInt", "isNaN", "isFinite"}
)
_PASSTHROUGH_CALLS = frozenset({"String", "decodeURIComponent", "decodeURI", "unescape"})
_GLOBAL_ENCODERS = {
    "encodeURIComponent": frozenset({"xss", "path", "cmd", "redirect", "ssrf"}),
    "encodeURI": frozenset({"xss"}),
    "escape": frozenset({"xss"}),
}
_HTML_TAG_RE = re.compile(r"<\s*[A-Za-z!/]")
_HTML_START_RE = re.compile(r"^\s*<")
_UNWRAP_TYPES = frozenset(
    {
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "non_null_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function",
        "function_declaration",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_LOOP_TYPES = frozenset(
    {"for_statement", "for_in_statement", "while_statement", "do_statement"}
)
_BLOCK_TYPES = frozenset({"statement_block", "program", "switch_case", "switch_default"})
_EXIT_TYPES = frozenset(
    {"return_statement", "throw_statement", "continue_statement", "break_statement"}
)
_SQL_TEXT_RE = re.compile(
    r"\bselect\b[\s\S]*\bfrom\b|\binsert\s+into\b|\bupdate\b[\s\S]*\bset\b"
    r"|\bdelete\s+from\b|\breplace\s+into\b|\bmerge\s+into\b"
    r"|\b(?:create|drop|alter|truncate)\s+(?:table|index|view|database|schema)\b"
    r"|\bwhere\b[\s\S]*(?:=|<|>|\blike\b|\bin\b|\bis\b|\bbetween\b)"
    r"|\border\s+by\b|\bgroup\s+by\b|\bunion\s+(?:all\s+)?select\b"
    r"|\bcall\s+\w+\s*\(|\bexec(?:ute)?\s+\w+",
    re.IGNORECASE,
)
_SQL_RAW_FRAGMENT_METHODS = frozenset(
    {
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        "whereRaw",
        "orWhereRaw",
        "andWhereRaw",
        "havingRaw",
        "orHavingRaw",
        "orderByRaw",
        "groupByRaw",
        "joinRaw",
        "fromRaw",
    }
)
_SQL_TEXT_METHODS = frozenset(
    {
        "query",
        "execute",
        "exec",
        "prepare",
        "all",
        "get",
        "run",
        "each",
        "raw",
        "unsafe",
        "literal",
    }
)
_QUERY_BUILDER_METHODS = frozenset(
    {
        "where",
        "andWhere",
        "orWhere",
        "having",
        "andHaving",
        "orHaving",
        "orderBy",
        "addOrderBy",
        "groupBy",
        "addGroupBy",
    }
)
_SOURCE_HINT_RE = re.compile(
    rb"\b(?:req|request|ctx|context)\b|@(?:Body|Query|Param|Params|Headers|Req|Request"
    rb"|UploadedFiles?|HostParam|QueryParams?|BodyParam|HeaderParam|CookieParam)\b"
    rb"|\b(?:loader|action)\b"
)
_HOST_CHECK_RE = re.compile(r"\.(?:hostname|host|origin)\b")
_HOST_COMPARE_RE = re.compile(
    r"\.(?:some|every|find|findIndex)\s*\(\s*(?:\(?[\w$,\s]*\)?\s*=>|function\b)"
    r"[\s\S]*(?:===|==|\.endsWith\s*\(|\.startsWith\s*\()"
)
_TLS_ENV = "NODE_TLS_REJECT_UNAUTHORIZED"
_REJECT_UNAUTHORIZED = "rejectUnauthorized"
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass(frozen=True)
class _Taint:
    label: str
    shape: str


@dataclass
class _Fact:
    subject: str
    kind: str
    guard_end: int
    data: Any = None


@dataclass
class _Event:
    pos: int
    node: Any
    value: Any
    mode: str


@dataclass
class _HandlerSpec:
    func: Any
    framework: str
    request_names: dict[str, str] = field(default_factory=dict)
    response_names: set[str] = field(default_factory=set)
    seeded: dict[str, _Taint] = field(default_factory=dict)


@dataclass
class RequestTaintResult:
    findings: list[dict[str, Any]]
    safe_sink_lines: dict[str, set[int]]


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _unwrap(node):
    while node is not None and node.type in _UNWRAP_TYPES:
        inner = None
        for child in node.named_children:
            if child.type not in {"type_annotation", "type_identifier", "comment"}:
                inner = child
                break
        if inner is None:
            break
        node = inner
    return node


def _iter_nodes(root):
    stack = [root]
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > _MAX_NODES:
            return
        yield node
        stack.extend(reversed(node.children))


def _contains(outer, inner) -> bool:
    return (
        outer is not None
        and outer.start_byte <= inner.start_byte
        and inner.end_byte <= outer.end_byte
    )


def _string_value(source: bytes, node) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return _text(source, node)[1:-1]
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return _text(source, node)[1:-1]
    return None


def _member_path(source: bytes, node) -> list[str] | None:
    """Return ['req', 'params', 'x'] for req.params.x / req['params'].x."""
    parts: list[str] = []
    node = _unwrap(node)
    while node is not None:
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None:
                return None
            parts.append(_text(source, prop))
            node = _unwrap(node.child_by_field_name("object"))
        elif node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            value = None
            if index is not None:
                value = _string_value(source, index)
            if value is None:
                value = "*"
            parts.append(value)
            node = _unwrap(node.child_by_field_name("object"))
        elif node.type in {"identifier", "this"}:
            parts.append(_text(source, node))
            parts.reverse()
            return parts
        else:
            return None
    return None


def _chain_root(source: bytes, node):
    """The identifier a call/member chain starts from: ``res`` for
    ``res.status(404).type('txt')``."""
    node = _unwrap(node)
    depth = 0
    while node is not None and depth < 32:
        depth += 1
        if node.type in {"identifier", "this"}:
            return node
        if node.type in {"member_expression", "subscript_expression"}:
            node = _unwrap(node.child_by_field_name("object"))
        elif node.type == "call_expression":
            node = _unwrap(node.child_by_field_name("function"))
        else:
            return None
    return None


def _chain_calls(source: bytes, node) -> list[tuple[str, list]]:
    calls: list[tuple[str, list]] = []
    node = _unwrap(node)
    depth = 0
    while node is not None and depth < 32:
        depth += 1
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None and callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                if prop is not None:
                    calls.append((_text(source, prop), _call_args(node)))
            node = callee
        elif node.type in {"member_expression", "subscript_expression"}:
            node = _unwrap(node.child_by_field_name("object"))
        else:
            break
    return calls


def _callee_last_name(source: bytes, callee) -> str | None:
    callee = _unwrap(callee)
    if callee is None:
        return None
    if callee.type == "identifier":
        return _text(source, callee)
    if callee.type == "member_expression":
        prop = callee.child_by_field_name("property")
        if prop is not None:
            return _text(source, prop)
    return None


def _call_args(call) -> list:
    args = call.child_by_field_name("arguments")
    if args is None or args.type != "arguments":
        return []
    return [c for c in args.named_children if c.type != "comment"]


def _pattern_names(source: bytes, pattern) -> list[str]:
    names: list[str] = []
    for node in _iter_nodes(pattern):
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            parent = node.parent
            if (
                parent is not None
                and parent.type in {"assignment_pattern", "object_assignment_pattern"}
                and parent.child_by_field_name("right") == node
            ):
                continue
            names.append(_text(source, node))
    return names


def _param_nodes(func) -> list:
    params = func.child_by_field_name("parameters")
    if params is None:
        single = func.child_by_field_name("parameter")
        if single is not None:
            return [single]
        return []
    return [c for c in params.named_children if c.type != "comment"]


def _param_pattern(param):
    if param.type in {"identifier", "object_pattern", "array_pattern"}:
        return param
    return param.child_by_field_name("pattern")


def _param_name_and_type(source: bytes, param) -> tuple[str | None, str]:
    if param.type == "identifier":
        return _text(source, param), ""
    pattern = param.child_by_field_name("pattern")
    type_node = param.child_by_field_name("type")
    type_text = ""
    if type_node is not None:
        type_text = _text(source, type_node)
    if pattern is not None and pattern.type == "identifier":
        return _text(source, pattern), type_text
    return None, type_text


def _is_route_callback(source: bytes, func) -> bool:
    parent = func.parent
    if parent is None or parent.type != "arguments":
        return False
    call = parent.parent
    if call is None or call.type != "call_expression":
        return False
    return _callee_last_name(source, call.child_by_field_name("function")) in (
        _ROUTE_METHODS
    )


def _function_name(source: bytes, func) -> str | None:
    name = func.child_by_field_name("name")
    if name is not None:
        return _text(source, name)
    parent = func.parent
    if parent is not None and parent.type == "variable_declarator":
        declared = parent.child_by_field_name("name")
        if declared is not None and declared.type == "identifier":
            return _text(source, declared)
    return None


def _is_exported(func) -> bool:
    node = func.parent
    depth = 0
    while node is not None and depth < 4:
        depth += 1
        if node.type == "export_statement":
            return True
        if node.type not in {"variable_declarator", "lexical_declaration"}:
            return False
        node = node.parent
    return False


def _label(source: bytes, node, prefix: str = "request data") -> str:
    text = " ".join(_text(source, node).split())
    if len(text) > _MAX_LABEL:
        text = text[:_MAX_LABEL] + "..."
    return f"{prefix} `{text}`"


def _subject(source: bytes, node) -> str:
    node = _unwrap(node)
    if node is None:
        return ""
    return re.sub(r"\s+|!(?=[.\[)])", "", _text(source, node)).replace("?.", ".")


def _join(left: _Taint | None, right: _Taint | None) -> _Taint | None:
    if left is None:
        return right
    if right is None:
        return left
    if left.shape == OBJECT or right.shape == OBJECT:
        return _Taint(left.label, OBJECT)
    return left


def _as_text(taint: _Taint | None) -> _Taint | None:
    if taint is None:
        return None
    return _Taint(taint.label, TEXT)


def _always_exits(node) -> bool:
    if node is None:
        return False
    if node.type in _EXIT_TYPES:
        return True
    if node.type == "statement_block":
        return any(_always_exits(child) for child in node.named_children)
    if node.type == "else_clause":
        return any(_always_exits(child) for child in node.named_children)
    if node.type == "if_statement":
        alternative = node.child_by_field_name("alternative")
        return _always_exits(node.child_by_field_name("consequence")) and (
            _always_exits(alternative)
        )
    return False


def _strict_regex(pattern: str, flags: str) -> bool:
    """An anchored allowlist regex (``^[\\w-]+$``, ``^\\d+$``) whose matches
    cannot hold a quote, space, slash, dot or newline."""
    if "m" in flags:
        return False
    if not (pattern.startswith("^") and pattern.endswith("$")) or pattern.endswith("\\$"):
        return False
    body = pattern[1:-1]
    if not body or "|" in body:
        return False
    body = re.sub(r"\\[dw]|\\-|\\_", "", body)
    return re.fullmatch(r"[A-Za-z0-9_\-\[\]+*?{},()]*", body) is not None


class _FileContext:
    def __init__(self, source: bytes, root, file_path: str):
        self.source = source
        self.root = root
        self.file_path = file_path.replace("\\", "/")
        self.imports: dict[str, tuple[str, str]] = {}
        self.declarations: dict[str, int] = {}
        self.functions: dict[str, Any] = {}
        self.const_values: dict[str, Any] = {}
        self.assigned: set[str] = set()
        self.mutated: set[str] = set()
        self.axios_instances: set[str] = set()
        self.http_service_props: set[str] = set()
        self.mongo = False
        self.mongo_sanitized = False
        self.nest = False
        self.next_route_file = bool(_NEXT_ROUTE_FILE_RE.search(self.file_path))
        self.cp_names = _ChildProcessNames()
        self.function_nodes: list = []
        self.summary_memo: dict[tuple, str | None] = {}
        self.merge_memo: dict[int, bool] = {}
        self.summary_active: set[int] = set()
        self._collect()
        self.shell_process_calls = (
            ShellProcessCalls(source, root) if b"child_process" in source else None
        )

    def _declare(self, name: str) -> None:
        self.declarations[name] = self.declarations.get(name, 0) + 1

    def _collect(self) -> None:
        source = self.source
        candidate_functions: dict[str, Any] = {}
        candidate_consts: dict[str, Any] = {}
        for node in _iter_nodes(self.root):
            kind = node.type
            if kind in _FUNCTION_TYPES:
                self.function_nodes.append(node)
            if kind in {"import_statement", "variable_declarator"}:
                self.cp_names.visit(source, node)
            if kind == "import_statement":
                self._import(node)
            elif kind == "variable_declarator":
                name = node.child_by_field_name("name")
                value = _unwrap(node.child_by_field_name("value"))
                if name is None:
                    continue
                for bound in _pattern_names(source, name):
                    self._declare(bound)
                if value is not None:
                    self._require(name, value)
                if name.type == "identifier":
                    bound = _text(source, name)
                    if value is not None and value.type in {
                        "arrow_function",
                        "function_expression",
                        "function",
                    }:
                        candidate_functions[bound] = value
                    parent = node.parent
                    if (
                        value is not None
                        and parent is not None
                        and parent.type == "lexical_declaration"
                        and _text(source, parent).startswith("const")
                    ):
                        candidate_consts[bound] = value
                    if value is not None and self._is_axios_create(value):
                        self.axios_instances.add(bound)
            elif kind in {"function_declaration", "generator_function_declaration"}:
                name = node.child_by_field_name("name")
                if name is not None:
                    bound = _text(source, name)
                    self._declare(bound)
                    candidate_functions[bound] = node
            elif kind in {"class_declaration", "class"}:
                name = node.child_by_field_name("name")
                if name is not None:
                    self._declare(_text(source, name))
            elif kind in {"required_parameter", "optional_parameter"}:
                pattern = node.child_by_field_name("pattern")
                if pattern is not None:
                    for bound in _pattern_names(source, pattern):
                        self._declare(bound)
                type_node = node.child_by_field_name("type")
                if (
                    pattern is not None
                    and pattern.type == "identifier"
                    and type_node is not None
                    and re.search(r"\bHttpService\b", _text(source, type_node))
                ):
                    self.http_service_props.add(_text(source, pattern))
            elif kind in {"formal_parameters"}:
                for child in node.named_children:
                    if child.type in {"identifier", "object_pattern", "array_pattern"}:
                        for bound in _pattern_names(source, child):
                            self._declare(bound)
            elif kind == "arrow_function":
                single = node.child_by_field_name("parameter")
                if single is not None:
                    self._declare(_text(source, single))
            elif kind == "catch_clause":
                param = node.child_by_field_name("parameter")
                if param is not None:
                    for bound in _pattern_names(source, param):
                        self._declare(bound)
            elif kind in {"assignment_expression", "augmented_assignment_expression"}:
                left = _unwrap(node.child_by_field_name("left"))
                if left is not None and left.type == "identifier":
                    self.assigned.add(_text(source, left))
                elif left is not None and left.type in {
                    "member_expression",
                    "subscript_expression",
                }:
                    root = _chain_root(source, left)
                    if root is not None:
                        self.mutated.add(_text(source, root))
            elif kind == "call_expression":
                self._call_facts(node)
        for name, value in candidate_functions.items():
            if self.declarations.get(name, 0) == 1 and name not in self.assigned:
                self.functions[name] = value
        for name, value in candidate_consts.items():
            if self.declarations.get(name, 0) == 1:
                self.const_values[name] = value
        text = source.decode("utf-8", "replace")
        if re.search(r"sanitizeFilter['\"]?\s*[,:]\s*true", text):
            self.mongo_sanitized = True

    def _import(self, node) -> None:
        source_node = node.child_by_field_name("source")
        module = None
        if source_node is not None:
            module = _string_value(self.source, source_node)
        if module is None:
            for child in node.named_children:
                if child.type == "import_require_clause":
                    self._import_require(child)
            return
        if module in _MONGO_MODULES:
            self.mongo = True
        if module in _NEST_MODULES:
            self.nest = True
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    self._bind_import(_text(self.source, child), module, "default")
                elif child.type == "namespace_import":
                    for sub in child.named_children:
                        if sub.type == "identifier":
                            self._bind_import(_text(self.source, sub), module, "*")
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        if spec.type != "import_specifier":
                            continue
                        imported = spec.child_by_field_name("name")
                        alias = spec.child_by_field_name("alias") or imported
                        if imported is None or alias is None:
                            continue
                        self._bind_import(
                            _text(self.source, alias),
                            module,
                            _text(self.source, imported),
                        )

    def _import_require(self, node) -> None:
        name = None
        module = None
        for child in node.named_children:
            if child.type == "identifier":
                name = _text(self.source, child)
            elif child.type == "string":
                module = _string_value(self.source, child)
        if name and module:
            self._bind_import(name, module, "*")
            if module in _MONGO_MODULES:
                self.mongo = True

    def _bind_import(self, local: str, module: str, imported: str) -> None:
        self.imports[local] = (module, imported)
        self._declare(local)

    def _require_module(self, node) -> tuple[str | None, list[str]]:
        node = _unwrap(node)
        members: list[str] = []
        while node is not None and node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None:
                return None, []
            members.append(_text(self.source, prop))
            node = _unwrap(node.child_by_field_name("object"))
        if node is None or node.type != "call_expression":
            return None, []
        callee = node.child_by_field_name("function")
        if callee is None or _text(self.source, callee) != "require":
            return None, []
        args = _call_args(node)
        if not args:
            return None, []
        members.reverse()
        return _string_value(self.source, args[0]), members

    def _require(self, name, value) -> None:
        module, members = self._require_module(value)
        if module is None:
            return
        if module in _MONGO_MODULES:
            self.mongo = True
        if module in _NEST_MODULES:
            self.nest = True
        imported = "*"
        if members:
            imported = members[0]
        if name.type == "identifier":
            self.imports[_text(self.source, name)] = (module, imported)
            return
        if name.type != "object_pattern" or members:
            return
        for child in name.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                local = _text(self.source, child)
                self.imports[local] = (module, local)
            elif child.type == "pair_pattern":
                key = child.child_by_field_name("key")
                val = child.child_by_field_name("value")
                if key is not None and val is not None and val.type == "identifier":
                    self.imports[_text(self.source, val)] = (
                        module,
                        _text(self.source, key),
                    )

    def _is_axios_create(self, value) -> bool:
        value = _unwrap(value)
        if value is None or value.type != "call_expression":
            return False
        callee = _unwrap(value.child_by_field_name("function"))
        path = _member_path(self.source, callee)
        return (
            path is not None
            and len(path) == 2
            and path[1] == "create"
            and self.module_of(path[0]) == "axios"
        )

    def _call_facts(self, node) -> None:
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None:
            return
        path = _member_path(self.source, callee)
        if path is None:
            return
        text = ".".join(path)
        if text == "mongoose.set":
            args = _call_args(node)
            if (
                len(args) >= 2
                and _string_value(self.source, args[0]) == "sanitizeFilter"
                and _unwrap(args[1]) is not None
                and _unwrap(args[1]).type == "true"
            ):
                self.mongo_sanitized = True
        if len(path) == 1 and self.imports.get(path[0], ("", ""))[0] == (
            "express-mongo-sanitize"
        ):
            self.mongo_sanitized = True

    def module_of(self, name: str) -> str | None:
        binding = self.imports.get(name)
        if binding is None or binding[1] not in {"default", "*"}:
            return None
        if self.declarations.get(name, 0) > 1:
            return None
        return binding[0]

    def named_import(self, name: str) -> tuple[str, str] | None:
        binding = self.imports.get(name)
        if binding is None or self.declarations.get(name, 0) > 1:
            return None
        return binding

    def is_global(self, name: str) -> bool:
        return name not in self.declarations and name not in self.assigned

    def object_method(self, owner: str, method: str):
        """The function a same-file ``const owner = { method: (x) => ... }``
        object holds, so a local look-alike of a library sanitizer is followed
        instead of trusted."""
        if owner in self.mutated or owner in self.assigned:
            return None
        value = _unwrap(self.const_values.get(owner))
        if value is None or value.type != "object":
            return None
        for child in value.named_children:
            if child.type == "method_definition":
                name = child.child_by_field_name("name")
                if name is not None and _text(self.source, name) == method:
                    return child
            elif child.type == "pair":
                key = child.child_by_field_name("key")
                function = _unwrap(child.child_by_field_name("value"))
                if (
                    key is not None
                    and _text(self.source, key).strip("'\"") == method
                    and function is not None
                    and function.type in {"arrow_function", "function_expression", "function"}
                ):
                    return function
        return None

    def is_path_module(self, node) -> bool:
        node = _unwrap(node)
        if node is None or node.type != "identifier":
            return False
        return self.module_of(_text(self.source, node)) in _PATH_MODULES

    def string_list(self, node, depth: int = 0) -> frozenset[str] | None:
        node = _unwrap(node)
        if node is None or depth > 3:
            return None
        if node.type == "array":
            values = []
            for child in node.named_children:
                if child.type == "comment":
                    continue
                value = _string_value(self.source, child)
                if value is None:
                    return None
                values.append(value)
            return frozenset(values)
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            args = _call_args(node)
            if ctor is not None and _text(self.source, ctor) == "Set" and len(args) == 1:
                return self.string_list(args[0], depth + 1)
            return None
        if node.type == "identifier":
            name = _text(self.source, node)
            if name in self.mutated or name in self.assigned:
                return None
            value = self.const_values.get(name)
            if value is None:
                return None
            return self.string_list(value, depth + 1)
        return None

    def const_string(self, node, depth: int = 0) -> str | None:
        node = _unwrap(node)
        if node is None or depth > 4:
            return None
        value = _string_value(self.source, node)
        if value is not None:
            return value
        if node.type == "identifier":
            name = _text(self.source, node)
            if name in self.assigned:
                return None
            bound = self.const_values.get(name)
            if bound is None:
                return None
            return self.const_string(bound, depth + 1)
        return None


class _ChildProcessNames:
    def __init__(self):
        self.functions: set[str] = set()
        self.modules: set[str] = set()

    def visit(self, source: bytes, node) -> None:
        if node.type == "import_statement":
            self._import(source, node)
        elif node.type == "variable_declarator":
            self._require(source, node)

    def _import(self, source: bytes, node) -> None:
        module_node = node.child_by_field_name("source")
        if module_node is None or _string_value(source, module_node) not in (
            _CHILD_PROCESS_MODULES
        ):
            return
        for sub in _iter_nodes(node):
            if sub.type == "import_specifier":
                name = sub.child_by_field_name("name")
                alias = sub.child_by_field_name("alias")
                if name is not None and _text(source, name) in _EXEC_FUNCS:
                    self.functions.add(_text(source, alias or name))
            elif sub.type == "namespace_import":
                for child in sub.named_children:
                    if child.type == "identifier":
                        self.modules.add(_text(source, child))
            elif sub.type == "import_clause":
                for child in sub.named_children:
                    if child.type == "identifier":
                        self.modules.add(_text(source, child))

    def _require(self, source: bytes, node) -> None:
        value = _unwrap(node.child_by_field_name("value"))
        name = node.child_by_field_name("name")
        if value is None or name is None or not _is_child_process_require(
            source, value
        ):
            return
        if name.type == "identifier":
            self.modules.add(_text(source, name))
        elif name.type == "object_pattern":
            for child in name.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    if _text(source, child) in _EXEC_FUNCS:
                        self.functions.add(_text(source, child))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if (
                        key is not None
                        and val is not None
                        and _text(source, key) in _EXEC_FUNCS
                        and val.type == "identifier"
                    ):
                        self.functions.add(_text(source, val))

    def is_exec_call(self, source: bytes, call) -> bool:
        callee = _unwrap(call.child_by_field_name("function"))
        if callee is None:
            return False
        if callee.type == "identifier":
            return _text(source, callee) in self.functions
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            obj = _unwrap(callee.child_by_field_name("object"))
            if prop is None or obj is None or _text(source, prop) not in _EXEC_FUNCS:
                return False
            if obj.type == "identifier":
                return _text(source, obj) in self.modules
            return _is_child_process_require(source, obj)
        return False


def _is_child_process_require(source: bytes, node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None or _text(source, callee) != "require":
        return False
    args = _call_args(node)
    return bool(args) and _string_value(source, args[0]) in _CHILD_PROCESS_MODULES


def _has_html_literal(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        for child in node.named_children:
            if child.type == "string_fragment" and _HTML_TAG_RE.search(
                _text(source, child)
            ):
                return True
        return False
    if node.type == "string":
        return bool(_HTML_TAG_RE.search(_text(source, node)))
    if node.type == "binary_expression":
        return _has_html_literal(
            source, node.child_by_field_name("left")
        ) or _has_html_literal(source, node.child_by_field_name("right"))
    return False


def _object_value(source: bytes, node, key: str):
    node = _unwrap(node)
    if node is None or node.type != "object":
        return None
    for child in node.named_children:
        if child.type == "pair":
            k = child.child_by_field_name("key")
            if k is not None and _text(source, k).strip("'\"") == key:
                return child.child_by_field_name("value")
        elif child.type == "shorthand_property_identifier":
            if _text(source, child) == key:
                return child
    return None


def _object_has_key(source: bytes, node, key: str) -> bool:
    return _object_value(source, node, key) is not None


def _decorator_name_and_args(source: bytes, decorator) -> tuple[str | None, list]:
    for child in decorator.named_children:
        if child.type == "call_expression":
            callee = child.child_by_field_name("function")
            return _callee_last_name(source, callee), _call_args(child)
        if child.type in {"identifier", "member_expression"}:
            return _callee_last_name(source, child), []
    return None, []


def _is_dto_type(source: bytes, param) -> bool:
    type_node = param.child_by_field_name("type")
    if type_node is None:
        return False
    named = [c for c in type_node.named_children if c.type != "comment"]
    if len(named) != 1 or named[0].type != "type_identifier":
        return False
    name = _text(source, named[0])
    return name[:1].isupper() and name not in _UNTYPED_DTO_NAMES


def _nest_spec(ctx: _FileContext, func) -> _HandlerSpec | None:
    if func.type != "method_definition" or not ctx.nest:
        return None
    spec = _HandlerSpec(func=func, framework="nest")
    found = False
    for param in _param_nodes(func):
        decorators = [c for c in param.named_children if c.type == "decorator"]
        if not decorators:
            continue
        pattern = param.child_by_field_name("pattern")
        if pattern is None or pattern.type != "identifier":
            continue
        name = _text(ctx.source, pattern)
        for decorator in decorators:
            dec_name, dec_args = _decorator_name_and_args(ctx.source, decorator)
            if dec_name is None:
                continue
            binding = ctx.named_import(dec_name)
            if binding is None or binding[0] not in _NEST_MODULES:
                continue
            if dec_name in _NEST_REQUEST_DECORATORS:
                spec.request_names[name] = "express"
                found = True
            elif dec_name in _NEST_RESPONSE_DECORATORS:
                spec.response_names.add(name)
                found = True
            elif dec_name in _NEST_SOURCE_DECORATORS:
                found = True
                pipes = set()
                for arg in dec_args:
                    inner = _unwrap(arg)
                    if inner is not None and inner.type == "new_expression":
                        inner = inner.child_by_field_name("constructor")
                    if inner is not None and inner.type == "identifier":
                        pipes.add(_text(ctx.source, inner))
                if pipes & _NEST_SANITIZING_PIPES:
                    continue
                shape = _NEST_SOURCE_DECORATORS[dec_name]
                if shape == OBJECT and _is_dto_type(ctx.source, param):
                    shape = TEXT
                spec.seeded[name] = _Taint(
                    _label(ctx.source, param, "request data"), shape
                )
    if not found:
        return None
    return spec


def _next_route_spec(ctx: _FileContext, func) -> _HandlerSpec | None:
    if not ctx.next_route_file or func.type not in {
        "function_declaration",
        "arrow_function",
        "function_expression",
        "function",
    }:
        return None
    name = _function_name(ctx.source, func)
    if name not in _NEXT_ROUTE_METHODS or not _is_exported(func):
        return None
    params = _param_nodes(func)
    spec = _HandlerSpec(func=func, framework="fetch")
    if params:
        req_name, _ = _param_name_and_type(ctx.source, params[0])
        if req_name:
            spec.request_names[req_name] = "fetch"
    if len(params) > 1:
        pattern = _param_pattern(params[1])
        if pattern is not None:
            for bound in _pattern_names(ctx.source, pattern):
                spec.seeded[bound] = _Taint(
                    _label(ctx.source, params[1], "route parameter"), TEXT
                )
    return spec


def _remix_spec(ctx: _FileContext, func) -> _HandlerSpec | None:
    name = _function_name(ctx.source, func)
    if name not in _REMIX_HANDLERS or not _is_exported(func):
        return None
    params = _param_nodes(func)
    if not params:
        return None
    pattern = _param_pattern(params[0])
    if pattern is None or pattern.type != "object_pattern":
        return None
    spec = _HandlerSpec(func=func, framework="fetch")
    for child in pattern.named_children:
        if child.type != "shorthand_property_identifier_pattern":
            continue
        bound = _text(ctx.source, child)
        if bound == "request":
            spec.request_names[bound] = "fetch"
        elif bound == "params":
            spec.seeded[bound] = _Taint(_label(ctx.source, child, "route parameter"), TEXT)
    if not spec.request_names and not spec.seeded:
        return None
    return spec


def _express_spec(ctx: _FileContext, func) -> _HandlerSpec | None:
    params = _param_nodes(func)
    if not params:
        return None
    req_name, req_type = _param_name_and_type(ctx.source, params[0])
    if not req_name:
        return None
    if req_name in _CONTEXT_PARAM_NAMES or _CONTEXT_TYPE_RE.search(req_type or ""):
        spec = _HandlerSpec(func=func, framework="koa")
        spec.request_names[req_name] = "koa"
        spec.response_names.add(req_name)
        return spec
    res_name = "res"
    if len(params) > 1:
        name, _ = _param_name_and_type(ctx.source, params[1])
        if name:
            res_name = name
    typed = bool(_REQUEST_TYPE_RE.search(req_type or ""))
    if (
        not typed
        and len(params) == 1
        and req_name in _REQUEST_PARAM_NAMES
        and re.fullmatch(r"(?::\s*any)?", (req_type or "").strip()) is not None
        and not _is_route_callback(ctx.source, func)
    ):
        spec = _HandlerSpec(func=func, framework=_LONE_REQUEST)
        spec.request_names[req_name] = _LONE_REQUEST
        return spec
    if not (
        typed
        or (req_name in _REQUEST_PARAM_NAMES and len(params) >= 2)
        or (
            _is_route_callback(ctx.source, func)
            and (len(params) >= 2 or req_name in _REQUEST_PARAM_NAMES)
        )
    ):
        return None
    framework = "express"
    if "FastifyRequest" in req_type or res_name == "reply":
        framework = "fastify"
    elif "NextApiRequest" in req_type:
        framework = "next-pages"
    elif "NextRequest" in req_type or (
        re.fullmatch(r":\s*Request", req_type or "") and ctx.is_global("Request")
    ):
        framework = "fetch"
    elif res_name == "h":
        framework = "hapi"
    spec = _HandlerSpec(func=func, framework=framework)
    spec.request_names[req_name] = framework
    spec.response_names.add(res_name)
    return spec


def _handler_spec(ctx: _FileContext, func) -> _HandlerSpec | None:
    for builder in (_nest_spec, _next_route_spec, _remix_spec, _express_spec):
        spec = builder(ctx, func)
        if spec is not None:
            return spec
    return None


class _HandlerTaint:
    def __init__(self, ctx: _FileContext, spec: _HandlerSpec, depth: int = 0):
        self.ctx = ctx
        self.source = ctx.source
        self.spec = spec
        self.func = spec.func
        self.depth = depth
        self.res = next(iter(spec.response_names), "res")
        body = spec.func.child_by_field_name("body")
        self.body = body
        self.nodes = []
        if body is not None:
            self.nodes = list(_iter_nodes(body))
        self.events: dict[str, list[_Event]] = {}
        self.inner_params: list[tuple[Any, set[str]]] = []
        self.if_nodes = []
        self._memo: dict[tuple[int, str], _Taint | None] = {}
        self._active: set[tuple[int, str]] = set()
        self._fact_memo: dict[int, list[_Fact]] = {}
        self._collect()

    def _add_event(self, name: str, pos: int, node, value, mode: str) -> None:
        self.events.setdefault(name, []).append(_Event(pos, node, value, mode))

    def _collect(self) -> None:
        source = self.source
        for node in self.nodes:
            kind = node.type
            if kind == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if name is None:
                    continue
                if name.type == "identifier":
                    self._add_event(_text(source, name), node.end_byte, node, value, "decl")
                else:
                    for bound in _pattern_names(source, name):
                        self._add_event(bound, node.end_byte, node, value, "destructure")
            elif kind == "assignment_expression":
                left = _unwrap(node.child_by_field_name("left"))
                right = node.child_by_field_name("right")
                if left is None:
                    continue
                if left.type == "identifier":
                    self._add_event(_text(source, left), node.end_byte, node, right, "assign")
                elif left.type in {"object_pattern", "array_pattern"}:
                    for bound in _pattern_names(source, left):
                        self._add_event(bound, node.end_byte, node, right, "destructure")
            elif kind == "augmented_assignment_expression":
                left = _unwrap(node.child_by_field_name("left"))
                right = node.child_by_field_name("right")
                if left is not None and left.type == "identifier":
                    self._add_event(_text(source, left), node.end_byte, node, right, "aug")
            elif kind == "for_in_statement":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                operator = node.child_by_field_name("operator")
                mode = "forof"
                if operator is not None and _text(source, operator) == "in":
                    mode = "forin"
                if left is not None and right is not None:
                    for bound in _pattern_names(source, left):
                        self._add_event(bound, right.end_byte, node, right, mode)
            elif kind == "catch_clause":
                param = node.child_by_field_name("parameter")
                if param is not None:
                    for bound in _pattern_names(source, param):
                        self._add_event(bound, param.end_byte, node, None, "decl")
            elif kind in _FUNCTION_TYPES and node.id != self.func.id:
                names: set[str] = set()
                for param in _param_nodes(node):
                    pattern = _param_pattern(param)
                    if pattern is not None:
                        names.update(_pattern_names(source, pattern))
                if names:
                    self.inner_params.append((node, names))
            elif kind == "if_statement":
                self.if_nodes.append(node)

    def _shadowed(self, node, name: str) -> bool:
        for func, names in self.inner_params:
            if name in names and _contains(func, node):
                return True
        return False

    def _is_strong(self, event: _Event, use) -> bool:
        if event.mode not in {"decl", "assign", "destructure"}:
            return False
        node = event.node
        if event.mode == "decl" or (
            event.mode == "destructure" and node.type == "variable_declarator"
        ):
            statement = node.parent
            if statement is None or statement.type not in {
                "lexical_declaration",
                "variable_declaration",
            }:
                return False
        elif node.type == "catch_clause":
            return False
        else:
            statement = node.parent
            while statement is not None and statement.type == "parenthesized_expression":
                statement = statement.parent
            if statement is None or statement.type != "expression_statement":
                return False
        block = statement.parent
        return block is not None and block.type in _BLOCK_TYPES and _contains(block, use)

    def _loops(self, node) -> set[int]:
        ids = set()
        current = node.parent
        while current is not None and current.id != self.func.id:
            if current.type in _LOOP_TYPES:
                ids.add(current.id)
            current = current.parent
        return ids

    def _selected_events(self, name: str, use) -> tuple[list[_Event], bool]:
        events = self.events.get(name, [])
        prior = [e for e in events if e.pos <= use.start_byte]
        prior.sort(key=lambda e: e.pos)
        selected: list[_Event] = []
        strong = False
        for event in reversed(prior):
            selected.append(event)
            if self._is_strong(event, use):
                strong = True
                break
        later = [e for e in events if e.pos > use.start_byte]
        if later:
            use_loops = self._loops(use)
            if use_loops:
                for event in later:
                    if self._loops(event.node) & use_loops:
                        selected.append(event)
        return selected, strong

    def _event_taint(self, event: _Event, kind: str) -> _Taint | None:
        if event.value is None:
            return None
        taint = self.taint(event.value, kind)
        if taint is None:
            return None
        if event.mode == "aug":
            return _as_text(taint)
        if event.mode == "forin":
            return _as_text(taint)
        return taint

    def _identifier_taint(self, node, kind: str) -> _Taint | None:
        name = _text(self.source, node)
        if self._shadowed(node, name):
            return None
        selected, strong = self._selected_events(name, node)
        result = None
        if not strong and name in self.spec.seeded:
            result = self.spec.seeded[name]
        for event in selected:
            result = _join(result, self._event_taint(event, kind))
        return result

    def _source_taint(self, node) -> _Taint | None:
        path = _member_path(self.source, node)
        if not path or len(path) < 2:
            return None
        framework = self.spec.request_names.get(path[0])
        if framework is None or self._shadowed(node, path[0]):
            return None
        label = _label(self.source, node)
        if framework == "koa":
            if path[1] == "request" and len(path) >= 3:
                shape = _KOA_REQUEST_FIELDS.get(path[2])
                if shape is not None:
                    return _Taint(label, shape)
                return None
            if path[1] in _KOA_CONTEXT_FIELDS:
                return _Taint(label, TEXT)
            if path[1] == "req" and len(path) >= 3 and path[2] in {
                "url",
                "headers",
                "rawHeaders",
                "cookies",
            }:
                return _Taint(label, TEXT)
            return None
        if framework == "fetch" and path[1] in _FETCH_FIELDS:
            return _Taint(label, TEXT)
        if framework == _LONE_REQUEST and path[1] not in _LONE_REQUEST_FIELDS:
            return None
        shape = _EXPRESS_FIELDS.get(path[1])
        if shape is None:
            return None
        if framework in _STRING_QUERY_FRAMEWORKS and path[1] in {
            "query",
            "cookies",
            "signedCookies",
        }:
            shape = TEXT
        return _Taint(label, shape)

    def _call_source(self, node, callee, args) -> _Taint | None:
        if callee is None or callee.type != "member_expression":
            return None
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return None
        method = _text(self.source, prop)
        path = _member_path(self.source, obj)
        if not path:
            return None
        framework = self.spec.request_names.get(path[0])
        if framework is None or self._shadowed(node, path[0]):
            return None
        label = _label(self.source, node)
        if len(path) == 1:
            if framework == "fetch":
                shape = _FETCH_BODY_METHODS.get(method)
                if shape is not None:
                    return _Taint(label, shape)
                return None
            if framework == "koa":
                if method == "get" and args:
                    return _Taint(label, TEXT)
                return None
            if method in _EXPRESS_ACCESSORS and args:
                return _Taint(label, TEXT)
            if method in _FETCH_BODY_METHODS and framework not in {
                "express",
                _LONE_REQUEST,
            }:
                return _Taint(label, _FETCH_BODY_METHODS[method])
            return None
        if framework == "koa" and path[1] in {"cookies", "request"} and method == "get":
            return _Taint(label, TEXT)
        return None

    def taint(self, node, kind: str) -> _Taint | None:
        node = _unwrap(node)
        if node is None:
            return None
        key = (node.id, kind)
        if key in self._memo:
            return self._memo[key]
        if key in self._active or len(self._active) > _MAX_TAINT_DEPTH:
            return None
        self._active.add(key)
        try:
            result = self._taint(node, kind)
        finally:
            self._active.discard(key)
        self._memo[key] = result
        return result

    def _taint(self, node, kind: str) -> _Taint | None:
        t = node.type
        if t == "identifier":
            return self._identifier_taint(node, kind)
        if t == "shorthand_property_identifier":
            return self._identifier_taint(node, kind)
        if t in {"member_expression", "subscript_expression"}:
            label = self._source_taint(node)
            if label is not None:
                return label
            obj = node.child_by_field_name("object")
            inner = self.taint(obj, kind)
            if inner is None:
                return None
            if t == "member_expression":
                prop = node.child_by_field_name("property")
                if prop is not None and _text(self.source, prop) == "length":
                    return None
            return inner
        if t == "call_expression":
            return self._call_taint(node, kind)
        if t == "new_expression":
            return self._new_taint(node, kind)
        if t == "template_string":
            result = None
            for child in node.named_children:
                if child.type == "template_substitution":
                    for inner in child.named_children:
                        result = _join(result, self.taint(inner, kind))
            return _as_text(result)
        if t == "binary_expression":
            operator = node.child_by_field_name("operator")
            op = ""
            if operator is not None:
                op = _text(self.source, operator)
            left = self.taint(node.child_by_field_name("left"), kind)
            right = self.taint(node.child_by_field_name("right"), kind)
            if op == "+":
                return _as_text(_join(left, right))
            if op in {"||", "??", "&&"}:
                return _join(left, right)
            return None
        if t == "ternary_expression":
            return _join(
                self.taint(node.child_by_field_name("consequence"), kind),
                self.taint(node.child_by_field_name("alternative"), kind),
            )
        if t == "array":
            result = None
            for child in node.named_children:
                result = _join(result, self.taint(child, kind))
            return result
        if t == "object":
            result = None
            for child in node.named_children:
                if child.type == "pair":
                    result = _join(result, self.taint(child.child_by_field_name("value"), kind))
                elif child.type in {"shorthand_property_identifier", "spread_element"}:
                    result = _join(result, self.taint(child, kind))
            if result is None:
                return None
            return _Taint(result.label, OBJECT)
        if t == "spread_element":
            for child in node.named_children:
                return self.taint(child, kind)
            return None
        if t == "assignment_expression":
            return self.taint(node.child_by_field_name("right"), kind)
        if t == "sequence_expression":
            children = [c for c in node.named_children if c.type != "comment"]
            if children:
                return self.taint(children[-1], kind)
            return None
        return None

    def _new_taint(self, node, kind: str) -> _Taint | None:
        ctor = _unwrap(node.child_by_field_name("constructor"))
        args = _call_args(node)
        if ctor is None or not args:
            return None
        name = _text(self.source, ctor)
        if name == "URL" and self.ctx.is_global("URL"):
            first = self.taint(args[0], kind)
            if first is not None:
                return _as_text(first)
            if len(args) > 1 and self._is_self_url(args[1]):
                return None
            if len(args) > 1:
                return _as_text(self.taint(args[1], kind))
            return None
        if name in {"URLSearchParams", "String"} and self.ctx.is_global(name):
            return _as_text(self.taint(args[0], kind))
        return None

    def _is_self_url(self, node) -> bool:
        node = _unwrap(node)
        path = _member_path(self.source, node)
        if not path or len(path) != 2:
            return False
        framework = self.spec.request_names.get(path[0])
        return framework is not None and path[1] in {"url", "nextUrl", "href", "origin"}

    def _call_taint(self, node, kind: str) -> _Taint | None:
        callee = _unwrap(node.child_by_field_name("function"))
        args = _call_args(node)
        source_taint = self._call_source(node, callee, args)
        if source_taint is not None:
            return source_taint
        if callee is None:
            return None
        if callee.type == "identifier":
            name = _text(self.source, callee)
            if self.ctx.is_global(name):
                if name in _NUMERIC_CALLS:
                    return None
                if name in _PASSTHROUGH_CALLS and args:
                    return _as_text(self.taint(args[0], kind))
                if name in _GLOBAL_ENCODERS and args:
                    if kind in _GLOBAL_ENCODERS[name]:
                        return None
                    return _as_text(self.taint(args[0], kind))
                return None
            function = self.ctx.functions.get(name)
            if function is not None:
                return self._summary_taint(function, args, kind)
            binding = self.ctx.named_import(name)
            if binding is not None and binding[0] in _PATH_MODULES:
                return self._path_call(binding[1], args, kind)
            return None
        if callee.type != "member_expression":
            return None
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return None
        method = _text(self.source, prop)
        if self.ctx.is_path_module(obj):
            return self._path_call(method, args, kind)
        if obj.type == "identifier":
            owner = _text(self.source, obj)
            if owner == "JSON" and self.ctx.is_global("JSON") and args:
                inner = self.taint(args[0], kind)
                if inner is None:
                    return None
                if method == "parse":
                    return _Taint(inner.label, OBJECT)
                if method == "stringify":
                    return _as_text(inner)
                return None
            if owner == "Buffer" and self.ctx.is_global("Buffer") and method == "from":
                if args:
                    return _as_text(self.taint(args[0], kind))
                return None
            if owner == "Object" and self.ctx.is_global("Object"):
                if method in {"assign", "values", "entries", "fromEntries", "keys"}:
                    result = None
                    for arg in args:
                        result = _join(result, self.taint(arg, kind))
                    return result
                return None
            if self.ctx.module_of(owner) in {"url", "node:url"} and method == "parse":
                if args:
                    return _as_text(self.taint(args[0], kind))
                return None
            if self.ctx.module_of(owner) in {"querystring", "node:querystring"}:
                if method == "parse" and args:
                    return _as_text(self.taint(args[0], kind))
                return None
            if self.ctx.module_of(owner) == "qs" and method == "parse" and args:
                inner = self.taint(args[0], kind)
                if inner is None:
                    return None
                return _Taint(inner.label, OBJECT)
        if obj.type == "identifier":
            method_function = self.ctx.object_method(_text(self.source, obj), method)
            if method_function is not None:
                return self._summary_taint(method_function, args, kind)
        receiver = self.taint(obj, kind)
        if method in _STRING_METHODS:
            if method in {"replace", "replaceAll"} and kind == "xss":
                escaping = self._html_replacement(args)
                if escaping is True:
                    return None
                if escaping is False:
                    return _as_text(self.taint(obj, "raw"))
            result = receiver
            if method in {"concat", "join"}:
                for arg in args:
                    result = _join(result, self.taint(arg, kind))
            if method == "split" and result is not None:
                return result
            return _as_text(result)
        if receiver is not None and method in _CONTAINER_GETTERS:
            if method == "get" and receiver.shape == OBJECT:
                return receiver
            return _as_text(receiver)
        return None

    def _path_call(self, method: str, args, kind: str) -> _Taint | None:
        if method == "basename":
            if kind == "path" or not args:
                return None
            return _as_text(self.taint(args[0], kind))
        if method in _PATH_BUILDERS or method in {"dirname", "extname", "toNamespacedPath"}:
            result = None
            for arg in args:
                result = _join(result, self.taint(arg, kind))
            return _as_text(result)
        return None

    def _html_replacement(self, args) -> bool | None:
        """True for a replace that turns ``<`` into an entity, False for one
        that writes a raw ``<`` back, None for any other replace."""
        if len(args) < 2:
            return None
        replacement = self.ctx.const_string(args[1])
        if replacement is None:
            return None
        if "<" in replacement:
            return False
        pattern = _unwrap(args[0])
        if pattern is None or pattern.type not in {"regex", "string"}:
            return None
        if "<" not in _text(self.source, pattern):
            return None
        if pattern.type == "regex":
            flags = pattern.child_by_field_name("flags")
            if flags is None or "g" not in _text(self.source, flags):
                return None
        elif pattern.type == "string":
            return None
        if re.search(r"&lt;|&#0*60;|&#x0*3c;", replacement, re.IGNORECASE):
            return True
        return None

    def _summary_taint(self, function, args, kind: str) -> _Taint | None:
        params = _param_nodes(function)
        seeded: dict[str, _Taint] = {}
        first_label = None
        shapes = []
        for index, param in enumerate(params):
            if index >= len(args):
                break
            pattern = _param_pattern(param)
            if pattern is None or pattern.type != "identifier":
                continue
            arg_taint = self.taint(args[index], kind)
            if arg_taint is None:
                continue
            seeded[_text(self.source, pattern)] = arg_taint
            shapes.append((index, arg_taint.shape))
            if first_label is None:
                first_label = arg_taint.label
        if not seeded or self.depth >= _MAX_SUMMARY_DEPTH:
            return None
        key = (function.id, tuple(shapes), kind)
        if key in self.ctx.summary_memo:
            shape = self.ctx.summary_memo[key]
            if shape is None:
                return None
            return _Taint(first_label, shape)
        if function.id in self.ctx.summary_active:
            return None
        self.ctx.summary_active.add(function.id)
        try:
            spec = _HandlerSpec(func=function, framework="helper", seeded=seeded)
            helper = _HandlerTaint(self.ctx, spec, self.depth + 1)
            result = None
            for expr in helper.return_values():
                result = _join(result, helper.taint(expr, kind))
        finally:
            self.ctx.summary_active.discard(function.id)
        shape = None
        if result is not None:
            shape = result.shape
        self.ctx.summary_memo[key] = shape
        if shape is None:
            return None
        return _Taint(first_label, shape)

    def return_values(self) -> list:
        body = self.body
        if body is None:
            return []
        if body.type != "statement_block":
            return [body]
        values = []
        for node in self.nodes:
            if node.type != "return_statement":
                continue
            if self._inside_inner_function(node):
                continue
            for child in node.named_children:
                if child.type != "comment":
                    values.append(child)
                    break
        return values

    def _inside_inner_function(self, node) -> bool:
        current = node.parent
        while current is not None and current.id != self.func.id:
            if current.type in _FUNCTION_TYPES:
                return True
            current = current.parent
        return False

    def derived_names(self, node, kind: str) -> list[tuple[str, str]]:
        names: list[tuple[str, str]] = []
        seen: set[str] = set()
        for sub in _iter_nodes(node):
            if sub.type != "identifier":
                continue
            name = _text(self.source, sub)
            if name in seen:
                continue
            taint = self.taint(sub, kind)
            if taint is None:
                continue
            seen.add(name)
            names.append((name, taint.label))
            if len(names) >= 4:
                break
        return names

    def facts_at(self, sink) -> list[_Fact]:
        if sink.id in self._fact_memo:
            return self._fact_memo[sink.id]
        facts: list[_Fact] = []
        for node in self.if_nodes:
            if node.start_byte >= sink.start_byte:
                break
            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if condition is None:
                continue
            guarded = False
            if _contains(consequence, sink):
                facts.extend(self._condition_facts(condition, True, node.end_byte))
                guarded = True
            elif alternative is not None and _contains(alternative, sink):
                facts.extend(self._condition_facts(condition, False, node.end_byte))
                guarded = True
            elif (
                node.end_byte <= sink.start_byte
                and _always_exits(consequence)
                and node.parent is not None
                and node.parent.type in _BLOCK_TYPES
                and _contains(node.parent, sink)
            ):
                facts.extend(self._condition_facts(condition, False, node.end_byte))
                guarded = True
            condition_text = _text(self.source, condition)
            if guarded and _HOST_CHECK_RE.search(condition_text) and (
                _HOST_COMPARE_RE.search(condition_text)
            ):
                facts.append(_Fact("", "host_check", node.end_byte, condition_text))
        self._fact_memo[sink.id] = facts
        return facts

    def _condition_facts(self, condition, truth: bool, guard_end: int) -> list[_Fact]:
        node = _unwrap(condition)
        if node is None:
            return []
        if node.type == "unary_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and _text(self.source, operator) == "!":
                return self._condition_facts(
                    node.child_by_field_name("argument"), not truth, guard_end
                )
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            op = ""
            if operator is not None:
                op = _text(self.source, operator)
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if (op == "&&" and truth) or (op == "||" and not truth):
                return self._condition_facts(
                    left, truth, guard_end
                ) + self._condition_facts(right, truth, guard_end)
            if op in {"===", "==", "!==", "!="}:
                equal = op in {"===", "=="}
                return self._comparison_facts(left, right, equal == truth, guard_end)
            if op in {"<", ">=", ">", "<="}:
                return self._index_facts(left, right, op, truth, guard_end)
            return []
        if node.type == "call_expression":
            return self._call_facts(node, truth, guard_end)
        return []

    def _comparison_facts(self, left, right, equal: bool, guard_end: int) -> list[_Fact]:
        left = _unwrap(left)
        right = _unwrap(right)
        if left is None or right is None:
            return []
        for subject, other in ((left, right), (right, left)):
            literal = self.ctx.const_string(other)
            if subject.type == "unary_expression" and literal is not None:
                operator = subject.child_by_field_name("operator")
                argument = subject.child_by_field_name("argument")
                if operator is not None and _text(self.source, operator) == "typeof":
                    if (equal and literal in {"string", "number", "boolean"}) or (
                        not equal and literal == "object"
                    ):
                        return [_Fact(_subject(self.source, argument), "typed", guard_end)]
                    return []
            if literal is not None and equal:
                return [_Fact(_subject(self.source, subject), "in_list", guard_end, {literal})]
            if literal is not None and other.type in {"string", "template_string"}:
                return [
                    _Fact(_subject(self.source, subject), "not_in_list", guard_end, {literal})
                ]
            if subject.type == "call_expression" and other.type in {"number", "unary_expression"}:
                number = _text(self.source, other).replace(" ", "")
                facts = self._indexof_fact(subject, number, equal, guard_end)
                if facts:
                    return facts
            if subject.type == "true" or other.type == "true":
                continue
        if left.type == "call_expression" and right.type in {"true", "false"}:
            truth = (right.type == "true") == equal
            return self._call_facts(left, truth, guard_end)
        return []

    def _index_facts(self, left, right, op: str, truth: bool, guard_end: int) -> list[_Fact]:
        left = _unwrap(left)
        right = _unwrap(right)
        if left is None or right is None or left.type != "call_expression":
            return []
        number = _text(self.source, right).replace(" ", "")
        found = (op == ">=" and number == "0") or (op == ">" and number == "-1")
        missing = (op == "<" and number == "0") or (op == "<=" and number == "-1")
        if not found and not missing:
            return []
        present = (found and truth) or (missing and not truth)
        return self._indexof_presence(left, present, guard_end)

    def _indexof_fact(self, call, number: str, equal: bool, guard_end: int) -> list[_Fact]:
        if number != "-1":
            return []
        return self._indexof_presence(call, not equal, guard_end)

    def _indexof_presence(self, call, present: bool, guard_end: int) -> list[_Fact]:
        callee = _unwrap(call.child_by_field_name("function"))
        args = _call_args(call)
        if callee is None or callee.type != "member_expression" or not args:
            return []
        prop = callee.child_by_field_name("property")
        if prop is None or _text(self.source, prop) != "indexOf":
            return []
        obj = callee.child_by_field_name("object")
        needle = self.ctx.const_string(args[0])
        if needle is not None and ".." in needle and not present:
            return [_Fact(_subject(self.source, obj), "no_dotdot", guard_end)]
        values = self.ctx.string_list(obj)
        if values is not None and present:
            return [_Fact(_subject(self.source, args[0]), "in_list", guard_end, set(values))]
        return []

    def _call_facts(self, call, truth: bool, guard_end: int) -> list[_Fact]:
        callee = _unwrap(call.child_by_field_name("function"))
        args = _call_args(call)
        if callee is None:
            return []
        if callee.type == "identifier":
            name = _text(self.source, callee)
            binding = self.ctx.named_import(name)
            if truth and args and (
                name == "isValidObjectId"
                or (binding is not None and binding[1] in {"isValidObjectId", "isMongoId"})
            ):
                return [_Fact(_subject(self.source, args[0]), "typed", guard_end)]
            return []
        if callee.type != "member_expression":
            return []
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return []
        method = _text(self.source, prop)
        if method == "startsWith" and args:
            prefix = self.ctx.const_string(args[0])
            subject = obj
            normalized = False
            if obj.type == "call_expression":
                inner_callee = _unwrap(obj.child_by_field_name("function"))
                inner_args = _call_args(obj)
                if (
                    inner_callee is not None
                    and inner_callee.type == "member_expression"
                    and self.ctx.is_path_module(inner_callee.child_by_field_name("object"))
                    and inner_args
                ):
                    inner_method = _text(
                        self.source, inner_callee.child_by_field_name("property")
                    )
                    if inner_method == "relative" and len(inner_args) == 2:
                        if prefix is not None and prefix.startswith("..") and not truth:
                            return [
                                _Fact(_subject(self.source, inner_args[1]), "contained", guard_end)
                            ]
                        return []
                    if inner_method in _PATH_NORMALIZERS:
                        subject = inner_args[-1]
                        normalized = True
            kind = "starts"
            if not truth:
                kind = "not_starts"
            data = {
                "prefix": prefix,
                "normalized": normalized,
                "prefix_tainted": self.taint(args[0], "raw") is not None,
            }
            return [_Fact(_subject(self.source, subject), kind, guard_end, data)]
        if method == "endsWith" and args and truth:
            suffix = self.ctx.const_string(args[0])
            if suffix is not None and suffix.startswith(".") and len(suffix) > 3:
                return [_Fact(_subject(self.source, obj), "host_suffix", guard_end, suffix)]
            return []
        if method == "includes" and args:
            needle = self.ctx.const_string(args[0])
            if needle is not None and ".." in needle and not truth:
                return [_Fact(_subject(self.source, obj), "no_dotdot", guard_end)]
            values = self.ctx.string_list(obj)
            if values is not None and truth:
                return [_Fact(_subject(self.source, args[0]), "in_list", guard_end, set(values))]
            if values is not None:
                return [
                    _Fact(_subject(self.source, args[0]), "not_in_list", guard_end, set(values))
                ]
            return []
        if method == "hasOwnProperty" and args and truth:
            return [_Fact(_subject(self.source, args[-1]), "own_key", guard_end)]
        if method == "hasOwn" and len(args) == 2 and truth:
            return [_Fact(_subject(self.source, args[1]), "own_key", guard_end)]
        if method == "call" and len(args) == 2 and truth:
            if _text(self.source, obj).replace(" ", "").endswith("hasOwnProperty"):
                return [_Fact(_subject(self.source, args[1]), "own_key", guard_end)]
        if method == "has" and args and truth:
            values = self.ctx.string_list(obj)
            if values is not None:
                return [_Fact(_subject(self.source, args[0]), "in_list", guard_end, set(values))]
            return []
        if method == "test" and args and obj.type == "regex":
            pattern = obj.child_by_field_name("pattern")
            flags = obj.child_by_field_name("flags")
            pattern_text = ""
            flags_text = ""
            if pattern is not None:
                pattern_text = _text(self.source, pattern)
            if flags is not None:
                flags_text = _text(self.source, flags)
            if truth and _strict_regex(pattern_text, flags_text):
                return [_Fact(_subject(self.source, args[0]), "strict", guard_end)]
            if not truth and re.fullmatch(r"\\\.\\\.", pattern_text):
                return [_Fact(_subject(self.source, args[0]), "no_dotdot", guard_end)]
            return []
        callee_path = _member_path(self.source, callee) or []
        if (
            args
            and truth
            and (
                method in {"isValidObjectId", "isMongoId"}
                or (method == "isValid" and "ObjectId" in callee_path)
            )
        ):
            return [_Fact(_subject(self.source, args[0]), "typed", guard_end)]
        if method in {"isInteger", "isSafeInteger", "isInt", "isUUID", "isNumeric"} and args and truth:
            return [_Fact(_subject(self.source, args[0]), "strict", guard_end)]
        return []

    def reassigned_between(self, name: str, start: int, end: int) -> bool:
        for event in self.events.get(name, []):
            if not start < event.pos <= end:
                continue
            if event.mode == "aug" and self.ctx.const_string(event.value) is not None:
                continue
            return True
        return False

    def tainted_leaves(self, expr, kind: str) -> list:
        leaves: list = []
        stack = [_unwrap(expr)]
        while stack:
            node = _unwrap(stack.pop())
            if node is None or node.type in _FUNCTION_TYPES:
                continue
            if node.type in {"identifier", "shorthand_property_identifier"}:
                if self.taint(node, kind) is not None:
                    leaves.append(node)
                continue
            if node.type in {"member_expression", "subscript_expression"}:
                if self.taint(node, kind) is not None:
                    leaves.append(node)
                continue
            if node.type == "call_expression":
                callee = _unwrap(node.child_by_field_name("function"))
                args = _call_args(node)
                if self._call_source(node, callee, args) is not None:
                    leaves.append(node)
                    continue
                if callee is not None and callee.type == "member_expression":
                    stack.append(callee.child_by_field_name("object"))
                stack.extend(args)
                continue
            stack.extend(node.named_children)
        return leaves

    def all_leaves(self, expr) -> list:
        leaves: list = []
        stack = [_unwrap(expr)]
        while stack:
            node = _unwrap(stack.pop())
            if node is None or node.type in _FUNCTION_TYPES:
                continue
            if node.type in {"identifier", "member_expression", "subscript_expression"}:
                leaves.append(node)
                continue
            if node.type in {"string", "template_string", "number", "true", "false", "null"}:
                if node.type == "template_string":
                    for child in node.named_children:
                        if child.type == "template_substitution":
                            stack.extend(child.named_children)
                continue
            if node.type == "call_expression":
                callee = _unwrap(node.child_by_field_name("function"))
                if callee is not None and callee.type == "member_expression":
                    stack.append(callee.child_by_field_name("object"))
                stack.extend(_call_args(node))
                continue
            stack.extend(node.named_children)
        return leaves

    def leaf_safe(
        self, leaf, kind: str, sink, sink_expr, depth: int = 0, proof_only: bool = False
    ) -> bool:
        subject = _subject(self.source, leaf)
        facts = []
        for fact in self.facts_at(sink):
            if leaf.type == "identifier" and self.reassigned_between(
                subject, fact.guard_end, sink.start_byte
            ):
                continue
            facts.append(fact)
        own = [f for f in facts if f.subject == subject]
        if any(f.kind == "strict" for f in own):
            return True
        if kind in {"sql", "cmd", "xss", "nosql", "redirect"} and any(
            f.kind == "in_list" for f in own
        ):
            return True
        if kind == "nosql" and any(f.kind == "typed" for f in own):
            return True
        if kind == "path" and self._path_fact_safe(leaf, own, sink_expr):
            return True
        if kind in {"ssrf", "redirect"}:
            for base in self._url_bases(leaf):
                if self._host_fact_safe(base, facts, [f for f in facts if f.subject == base]):
                    return True
            root = _chain_root(self.source, leaf)
            if not proof_only and root is not None:
                pattern = re.compile(rf"(?<![\w$.]){re.escape(_text(self.source, root))}\b")
                if any(
                    f.kind == "host_check" and pattern.search(f.data) for f in facts
                ):
                    return True
        if kind == "redirect" and self._relative_redirect_safe(own):
            return True
        if leaf.type == "identifier" and depth < _MAX_LEAF_DEPTH:
            selected, _ = self._selected_events(subject, leaf)
            values = [e.value for e in selected if e.value is not None]
            if values and all(
                self._value_safe(value, kind, sink, sink_expr, depth + 1, proof_only)
                for value in values
            ):
                return True
        return False

    def _value_safe(
        self, value, kind: str, sink, sink_expr, depth: int, proof_only: bool
    ) -> bool:
        if self.taint(value, kind) is None:
            return not proof_only
        leaves = self.tainted_leaves(value, kind)
        if not leaves:
            return False
        return all(
            self.leaf_safe(leaf, kind, sink, sink_expr, depth, proof_only)
            for leaf in leaves
        )

    def _path_fact_safe(self, leaf, own: list[_Fact], sink_expr) -> bool:
        for fact in own:
            if fact.kind == "contained":
                return True
            if (
                fact.kind == "starts"
                and fact.data.get("prefix") not in {"", "/", "."}
                and not fact.data.get("prefix_tainted")
            ):
                if fact.data.get("normalized") or self._is_normalized(leaf):
                    return True
            if fact.kind == "no_dotdot" and self._joined_under_prefix(leaf, sink_expr):
                return True
        return False

    def _is_normalized(self, leaf) -> bool:
        if leaf.type != "identifier":
            return False
        selected, _ = self._selected_events(_text(self.source, leaf), leaf)
        if not selected:
            return False
        for event in selected:
            value = _unwrap(event.value)
            if value is None or value.type != "call_expression" or event.mode != "decl":
                return False
            callee = _unwrap(value.child_by_field_name("function"))
            if (
                callee is None
                or callee.type != "member_expression"
                or not self.ctx.is_path_module(callee.child_by_field_name("object"))
                or _text(self.source, callee.child_by_field_name("property"))
                not in {"resolve", "normalize"}
            ):
                return False
        return True

    def _joined_under_prefix(self, leaf, sink_expr) -> bool:
        if sink_expr is None or _unwrap(sink_expr).id == leaf.id:
            return False
        current = leaf.parent
        while current is not None:
            if current.type == "call_expression":
                callee = _unwrap(current.child_by_field_name("function"))
                if callee is not None and callee.type == "member_expression":
                    if _text(self.source, callee.child_by_field_name("property")) == "resolve":
                        return False
            if current.id == sink_expr.id:
                break
            current = current.parent
        return True

    def _url_bases(self, leaf) -> list[str]:
        """``u.href`` is checked through ``u``: a guard on ``u.hostname``
        covers every serialisation of the same URL object."""
        bases = [_subject(self.source, leaf)]
        node = _unwrap(leaf)
        while node is not None and node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None or _text(self.source, prop) not in {
                "href",
                "toString",
                "pathname",
                "search",
                "hash",
            }:
                break
            node = _unwrap(node.child_by_field_name("object"))
            bases.append(_subject(self.source, node))
        return bases

    def _host_fact_safe(self, subject: str, facts: list[_Fact], own: list[_Fact]) -> bool:
        hosts = {
            subject + ".hostname",
            subject + ".host",
            subject + ".origin",
            "newURL(" + subject + ").hostname",
            "newURL(" + subject + ").host",
            "newURL(" + subject + ").origin",
        }
        for fact in facts:
            if fact.subject in hosts and fact.kind in {"in_list", "host_suffix"}:
                return True
        for fact in own:
            if fact.kind == "starts" and _fixed_host_prefix(fact.data.get("prefix") or ""):
                return True
            if fact.kind == "in_list":
                return True
        return False

    def _relative_redirect_safe(self, own: list[_Fact]) -> bool:
        starts_slash = any(
            f.kind == "starts" and f.data.get("prefix") == "/" for f in own
        )
        rejects_double = any(
            f.kind == "not_starts" and f.data.get("prefix") in {"//", "/\\"} for f in own
        )
        relative_prefix = any(
            f.kind == "starts" and _safe_relative_prefix(f.data.get("prefix") or "")
            for f in own
        )
        return relative_prefix or (starts_slash and rejects_double)

    def static_prefix(self, node, depth: int = 0) -> str:
        node = _unwrap(node)
        if node is None or depth > 6:
            return ""
        value = self.ctx.const_string(node)
        if value is not None:
            return value
        if node.type == "template_string":
            prefix = ""
            for child in node.children:
                if child.type == "`":
                    continue
                if child.type == "template_substitution":
                    inner = next(iter(child.named_children), None)
                    prefix += self.static_prefix(inner, depth + 1)
                    return prefix
                prefix += _text(self.source, child)
            return prefix
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is None or _text(self.source, operator) != "+":
                return ""
            left = node.child_by_field_name("left")
            left_value = self.ctx.const_string(left)
            if left_value is not None:
                return left_value + self.static_prefix(node.child_by_field_name("right"), depth + 1)
            return self.static_prefix(left, depth + 1)
        if node.type == "identifier" and depth < 6:
            selected, strong = self._selected_events(_text(self.source, node), node)
            if strong and len(selected) == 1 and selected[0].mode == "decl":
                return self.static_prefix(selected[0].value, depth + 1)
        return ""


def _fixed_host_prefix(prefix: str) -> bool:
    match = re.match(r"^https?://([^/?#\\]+)([/?#].*)", prefix, re.IGNORECASE)
    return bool(match and match.group(1))


def _safe_relative_prefix(prefix: str) -> bool:
    if not prefix:
        return False
    if prefix[0] in "?#":
        return True
    if prefix.startswith(("./", "../")):
        return True
    if prefix[0] == "/" and len(prefix) > 1 and prefix[1] not in "/\\":
        return True
    return False


def safe_redirect_prefix(prefix: str) -> bool:
    return _fixed_host_prefix(prefix) or _safe_relative_prefix(prefix)


def _evidence(
    taint: _HandlerTaint,
    expr,
    label: str,
    kind: str,
    *,
    sink: str,
    missing_guard: str,
) -> dict[str, Any]:
    path = [
        f"untrusted `{name}` from {origin}"
        for name, origin in taint.derived_names(expr, kind)
    ]
    if not path:
        path = [f"untrusted input from {label}"]
    path.append(f"reaches {sink}")
    return {
        "evidence_kind": "ts_request_taint",
        "framework": taint.spec.framework,
        "source": label,
        "sources": [label],
        "sink": sink,
        "path": path,
        "guards_seen": [],
        "guards_missing": [missing_guard],
        "analysis_complete": False,
    }


def _finding(
    file_path: str,
    node,
    rule_id: str,
    severity: str,
    message: str,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": node.start_point[0] + 1,
        "col": node.start_point[1],
    }
    if evidence is not None:
        finding["security_evidence"] = evidence
    return finding


def _check_tls_env(source: bytes, root, file_path: str) -> list[dict[str, Any]]:
    findings = []
    for node in _iter_nodes(root):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = _unwrap(node.child_by_field_name("right"))
        if left is None or right is None:
            continue
        path = _member_path(source, left)
        if path != ["process", "env", _TLS_ENV]:
            continue
        value = _string_value(source, right)
        if value is None and right.type == "number":
            value = _text(source, right)
        if value is None or value.strip() != "0":
            continue
        findings.append(
            _finding(
                file_path,
                node,
                "SKY-D210",
                "HIGH",
                "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate "
                "verification for every outbound connection in the process",
                None,
            )
        )
    return findings


def _check_reject_unauthorized(
    source: bytes, root, file_path: str
) -> list[dict[str, Any]]:
    """``{ rejectUnauthorized: false }`` in an options object (``https.Agent``,
    ``tls.connect``, ``https.request``, ``pg``'s ``ssl``): certificate
    verification off for that connection."""
    findings = []
    for node in _iter_nodes(root):
        if node.type != "pair":
            continue
        key = node.child_by_field_name("key")
        value = _unwrap(node.child_by_field_name("value"))
        if key is None or value is None or value.type != "false":
            continue
        name = _text(source, key)
        if key.type == "string":
            name = _string_value(source, key)
        if name != _REJECT_UNAUTHORIZED:
            continue
        findings.append(
            _finding(
                file_path,
                node,
                "SKY-D210",
                "HIGH",
                "rejectUnauthorized: false disables TLS certificate "
                "verification for this connection",
                None,
            )
        )
    return findings


class _SinkChecker:
    def __init__(self, ctx: _FileContext, taint: _HandlerTaint, file_path: str):
        self.ctx = ctx
        self.source = ctx.source
        self.taint = taint
        self.file_path = file_path
        self.findings: list[dict[str, Any]] = []
        self.safe_lines: dict[str, set[int]] = {}

    def _safe(self, rule_id: str, node) -> None:
        lines = self.safe_lines.setdefault(rule_id, set())
        lines.add(node.start_point[0] + 1)
        args = node.child_by_field_name("arguments")
        if args is not None:
            lines.add(args.start_point[0] + 1)

    def _report(self, node, rule_id, severity, message, expr, label, kind, sink, guard):
        self.findings.append(
            _finding(
                self.file_path,
                node,
                rule_id,
                severity,
                message,
                _evidence(
                    self.taint,
                    expr,
                    label,
                    kind,
                    sink=sink,
                    missing_guard=guard,
                ),
            )
        )

    def _unguarded(self, expr, kind: str, sink) -> _Taint | None:
        found = self.taint.taint(expr, kind)
        if found is None:
            return None
        leaves = self.taint.tainted_leaves(expr, kind)
        if leaves and all(
            self.taint.leaf_safe(leaf, kind, sink, expr) for leaf in leaves
        ):
            return None
        return found

    def run(self) -> None:
        for node in self.taint.nodes:
            if node.type == "call_expression":
                self._call(node)
            elif node.type == "assignment_expression":
                self._assignment(node)

    def _call(self, node) -> None:
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None:
            return
        args = _call_args(node)
        if self.ctx.cp_names.is_exec_call(self.source, node):
            if args:
                self._command(node, args[0])
            return
        shell_call = (
            self.ctx.shell_process_calls.command_parts(node)
            if self.ctx.shell_process_calls is not None
            else None
        )
        if shell_call is not None:
            method, parts = shell_call
            for part in parts:
                if self._unguarded(part, "cmd", node) is not None:
                    self._command(node, part, method)
                    break
            return
        if not args:
            return
        self._sql(node, callee, args)
        self._fs(node, callee, args)
        self._ssrf(node, callee, args)
        self._redirect(node, callee, args)
        self._response(node, callee, args)
        self._nosql(node, callee, args)
        self._merge(node, callee, args)

    def _command(self, node, first, method: str = "exec") -> None:
        found = self._unguarded(first, "cmd", node)
        if found is None:
            return
        self._report(
            node,
            "SKY-D212",
            "CRITICAL",
            f"Command injection: request data reaches child_process.{method}() "
            "shell command text. Use an argument array with the shell disabled.",
            first,
            found.label,
            "cmd",
            f"child_process.{method}() command",
            "argument array (execFile/spawn) or shell quoting",
        )

    def _receiver_is_http_object(self, obj) -> bool:
        root = _chain_root(self.source, obj)
        if root is None:
            return False
        name = _text(self.source, root)
        return name in self.taint.spec.request_names or name in self.taint.spec.response_names

    def _sql(self, node, callee, args) -> None:
        if callee.type != "member_expression":
            return
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return
        method = _text(self.source, prop)
        if self._receiver_is_http_object(obj) or self._ssrf_target(callee, args):
            return
        if obj.type == "identifier" and _text(self.source, obj) in {
            "Promise",
            "Array",
            "Object",
            "JSON",
            "Math",
            "String",
            "Reflect",
        }:
            return
        query = args[0]
        inner = _unwrap(query)
        if inner is not None and inner.type == "object":
            query = _object_value(self.source, inner, "text") or _object_value(
                self.source, inner, "sql"
            )
            if query is None:
                return
        if method in _SQL_RAW_FRAGMENT_METHODS:
            needs_text = False
        elif method in _SQL_TEXT_METHODS:
            needs_text = True
        elif method in _QUERY_BUILDER_METHODS:
            if not any(
                name == "createQueryBuilder" for name, _ in _chain_calls(self.source, obj)
            ):
                return
            needs_text = False
        else:
            return
        found = self._unguarded(query, "sql", node)
        if found is None:
            return
        if needs_text and not self._looks_like_sql(query):
            return
        receiver = _text(self.source, obj)
        if len(receiver) > 40:
            receiver = receiver[:40] + "..."
        self._report(
            node,
            "SKY-D211",
            "CRITICAL",
            f"SQL injection: request data is built into the query text passed "
            f"to {receiver}.{method}(). Use placeholders with a values array or "
            "a tagged sql template.",
            query,
            found.label,
            "sql",
            f"{receiver}.{method}() query text",
            "parameterized query",
        )

    def _looks_like_sql(self, expr) -> bool:
        pieces: list[str] = []
        self._literal_pieces(expr, pieces, 0)
        text = " ".join(pieces)
        if _SQL_TEXT_RE.search(text):
            return True
        return False

    def _literal_pieces(self, node, pieces: list[str], depth: int) -> None:
        node = _unwrap(node)
        if node is None or depth > 6 or len(pieces) > 64:
            return
        if node.type == "string":
            pieces.append(_text(self.source, node)[1:-1])
            return
        if node.type == "template_string":
            for child in node.named_children:
                if child.type == "string_fragment":
                    pieces.append(_text(self.source, child))
                elif child.type == "template_substitution":
                    for inner in child.named_children:
                        self._literal_pieces(inner, pieces, depth + 1)
            return
        if node.type == "binary_expression":
            self._literal_pieces(node.child_by_field_name("left"), pieces, depth + 1)
            self._literal_pieces(node.child_by_field_name("right"), pieces, depth + 1)
            return
        if node.type == "identifier":
            name = _text(self.source, node)
            for event in self.taint.events.get(name, []):
                if event.value is not None and event.mode in {"decl", "assign", "aug"}:
                    self._literal_pieces(event.value, pieces, depth + 1)
            value = self.ctx.const_values.get(name)
            if value is not None and name not in self.taint.events:
                self._literal_pieces(value, pieces, depth + 1)
            return
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None and callee.type == "member_expression":
                self._literal_pieces(callee.child_by_field_name("object"), pieces, depth + 1)
            for arg in _call_args(node):
                self._literal_pieces(arg, pieces, depth + 1)
            return
        if node.type in {"ternary_expression", "array"}:
            for child in node.named_children:
                self._literal_pieces(child, pieces, depth + 1)

    def _fs_paths(self, callee, args) -> tuple[str, list] | None:
        if callee.type == "identifier":
            name = _text(self.source, callee)
            binding = self.ctx.named_import(name)
            if binding is None or binding[0] not in _FS_MODULES:
                return None
            method = binding[1]
            label = f"{name}()"
        elif callee.type == "member_expression":
            obj = _unwrap(callee.child_by_field_name("object"))
            prop = callee.child_by_field_name("property")
            if obj is None or prop is None:
                return None
            method = _text(self.source, prop)
            path = _member_path(self.source, obj)
            if not path:
                return None
            module = self.ctx.module_of(path[0])
            if module is None and len(path) == 1:
                binding = self.ctx.named_import(path[0])
                if binding is not None and binding[1] == "promises":
                    module = binding[0]
            if module not in _FS_MODULES:
                return None
            if len(path) > 2 or (len(path) == 2 and path[1] != "promises"):
                return None
            label = f"{'.'.join(path)}.{method}()"
        else:
            return None
        if method in _FS_PATH_FUNCS:
            return label, args[:1]
        if method in _FS_TWO_PATH_FUNCS:
            return label, args[:2]
        return None

    def _fs(self, node, callee, args) -> None:
        targets = self._fs_paths(callee, args)
        if targets is None:
            self._send_file(node, callee, args)
            return
        label, paths = targets
        for path_expr in paths:
            found = self._unguarded(path_expr, "path", node)
            if found is None:
                continue
            self._report(
                node,
                "SKY-D215",
                "HIGH",
                f"Path traversal: request data reaches the {label} path without "
                "path.basename or a rejecting containment check",
                path_expr,
                found.label,
                "path",
                f"{label} path",
                "path.basename, or path.resolve plus a startsWith(root) check that rejects",
            )
            return

    def _send_file(self, node, callee, args) -> None:
        if callee.type != "member_expression":
            return
        obj = _unwrap(callee.child_by_field_name("object"))
        prop = callee.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier":
            return
        method = _text(self.source, prop)
        receiver = _text(self.source, obj)
        if method not in {"sendFile", "download"}:
            return
        if receiver not in self.taint.spec.response_names and receiver not in _RESPONSE_NAMES:
            return
        if len(args) > 1 and _object_has_key(self.source, args[1], "root"):
            return
        found = self._unguarded(args[0], "path", node)
        if found is None:
            return
        self._report(
            node,
            "SKY-D215",
            "HIGH",
            f"Path traversal: request data reaches {receiver}.{method}() "
            "without a root option or normalized-prefix check",
            args[0],
            found.label,
            "path",
            f"{receiver}.{method}() path",
            "{ root } option, path.basename, or startsWith check on the resolved path",
        )

    def _config_url(self, node):
        node = _unwrap(node)
        if node is None or node.type != "object":
            return node
        for key in _URL_CONFIG_KEYS:
            value = _object_value(self.source, node, key)
            if value is not None:
                return value
        return None

    def _ssrf_target(self, callee, args):
        if callee.type == "identifier":
            name = _text(self.source, callee)
            if name == "fetch" and self.ctx.is_global("fetch"):
                return "fetch()", args[0]
            if name in self.ctx.axios_instances:
                return f"{name}()", self._config_url(args[0])
            binding = self.ctx.named_import(name)
            if binding is None:
                return None
            module, imported = binding
            if module in _FETCH_MODULES and imported in {"default", "*", "fetch"}:
                return f"{name}()", args[0]
            if module == "undici" and imported in {"fetch", "request", "stream"}:
                return f"{name}()", args[0]
            if module in _HTTP_CLIENT_MODULES and imported in {"default", "*"}:
                if module == "needle" and len(args) > 1 and _string_value(self.source, args[0]):
                    return f"{name}()", args[1]
                return f"{name}()", self._config_url(args[0])
            if module in _NODE_HTTP_MODULES and imported in {"get", "request"}:
                return f"{name}()", self._config_url(args[0])
            return None
        if callee.type != "member_expression":
            return None
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return None
        method = _text(self.source, prop)
        if method not in _HTTP_VERBS and method not in {"stream", "fetch"}:
            return None
        path = _member_path(self.source, obj)
        if not path:
            return None
        label = f"{'.'.join(path)}.{method}()"
        target = args[0]
        if method == "request":
            target = self._config_url(args[0])
        if len(path) == 1:
            module = self.ctx.module_of(path[0])
            if (
                module in _HTTP_CLIENT_MODULES
                or module in _NODE_HTTP_MODULES
                or module == "undici"
                or path[0] in self.ctx.axios_instances
            ):
                if module in _NODE_HTTP_MODULES:
                    target = self._config_url(args[0])
                return label, target
            return None
        if path[0] == "this" and len(path) >= 2 and path[1] in self.ctx.http_service_props:
            if len(path) == 2 or (len(path) == 3 and path[2] == "axiosRef"):
                return label, target
        return None

    def _ssrf(self, node, callee, args) -> None:
        target = self._ssrf_target(callee, args)
        if target is None:
            return
        label, url = target
        if url is None:
            return
        if self._host_fixed(url):
            self._safe("SKY-D216", node)
            return
        found = self.taint.taint(url, "ssrf")
        if found is None:
            if self._all_leaves_guarded(url, "ssrf", node):
                self._safe("SKY-D216", node)
            return
        if self._unguarded(url, "ssrf", node) is None:
            self._safe("SKY-D216", node)
            return
        if not self._host_choosing(url, "ssrf", node):
            return
        self._report(
            node,
            "SKY-D216",
            "HIGH",
            f"SSRF: request data chooses the URL of the {label} request. "
            "Check the host against an allowlist before sending it.",
            url,
            found.label,
            "ssrf",
            f"{label} URL",
            "fixed scheme://host/ prefix or an allowlist check on the parsed hostname",
        )

    def _host_fixed(self, url) -> bool:
        inner = _unwrap(url)
        if inner is not None and inner.type == "new_expression":
            ctor = inner.child_by_field_name("constructor")
            new_args = _call_args(inner)
            if ctor is not None and _text(self.source, ctor) == "URL" and len(new_args) > 1:
                first = self.taint.static_prefix(new_args[0])
                base = self.taint.static_prefix(new_args[1])
                if _safe_relative_prefix(first) and _fixed_host_prefix(base):
                    return True
            return False
        prefix = self.taint.static_prefix(url)
        if not prefix:
            return False
        if _fixed_host_prefix(prefix):
            return True
        lowered = prefix.lower()
        if lowered.startswith(("http://", "https://", "//")) or ":" in lowered.split("/")[0]:
            return False
        return True

    def _all_leaves_guarded(self, expr, kind: str, sink) -> bool:
        leaves = self.taint.all_leaves(expr)
        if not leaves:
            return False
        return all(
            self.taint.leaf_safe(leaf, kind, sink, expr, proof_only=True)
            for leaf in leaves
        )

    def _resolve_single(self, node, depth: int = 0):
        node = _unwrap(node)
        while node is not None and node.type == "identifier" and depth < 4:
            depth += 1
            selected, strong = self.taint._selected_events(_text(self.source, node), node)
            if not strong or len(selected) != 1 or selected[0].mode != "decl":
                return node
            node = _unwrap(selected[0].value)
        return node

    def _is_host_header(self, node) -> bool:
        node = _unwrap(node)
        if node is None:
            return False
        path = _member_path(self.source, node)
        if path and path[0] in self.taint.spec.request_names:
            if path[1:] in (["hostname"], ["host"]):
                return True
            if len(path) == 3 and path[1] in {"headers", "header"}:
                return path[2].lower() in {"host", "x-forwarded-host"}
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            args = _call_args(node)
            if callee is not None and callee.type == "member_expression" and args:
                name = _string_value(self.source, args[0])
                obj_path = _member_path(self.source, callee.child_by_field_name("object"))
                if (
                    name is not None
                    and name.lower() in {"host", "x-forwarded-host"}
                    and obj_path
                    and obj_path[0] in self.taint.spec.request_names
                ):
                    return True
        return False

    def _path_like(self, node, depth: int = 0) -> bool:
        """A value that starts with ``/``: ``req.path``, ``nextUrl.pathname``,
        a Node ``req.url``, or text built from one."""
        node = self._resolve_single(node)
        if node is None or depth > 6:
            return False
        if node.type in {"member_expression", "subscript_expression"}:
            path = _member_path(self.source, node)
            if not path:
                return False
            if path[-1] in {"pathname", "path", "originalUrl"}:
                return True
            framework = self.taint.spec.request_names.get(path[0])
            return (
                len(path) == 2
                and path[1] == "url"
                and framework is not None
                and framework != "fetch"
            )
        if node.type == "template_string":
            for child in node.children:
                if child.type == "`":
                    continue
                if child.type == "template_substitution":
                    inner = next(iter(child.named_children), None)
                    return self._path_like(inner, depth + 1)
                return _text(self.source, child).startswith("/")
            return False
        if node.type == "string":
            return _text(self.source, node)[1:].startswith("/")
        if node.type == "binary_expression":
            return self._path_like(node.child_by_field_name("left"), depth + 1)
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None and callee.type == "member_expression":
                method = _text(self.source, callee.child_by_field_name("property"))
                if method in _STRING_METHODS:
                    return self._path_like(callee.child_by_field_name("object"), depth + 1)
        return False

    def _url_parts(self, node, depth: int = 0) -> list[tuple[str, Any]]:
        node = self._resolve_single(node)
        if node is None or depth > 6:
            return []
        if node.type == "string":
            return [("lit", _text(self.source, node)[1:-1])]
        if node.type == "template_string":
            parts: list[tuple[str, Any]] = []
            for child in node.children:
                if child.type == "`":
                    continue
                if child.type == "template_substitution":
                    inner = next(iter(child.named_children), None)
                    parts.extend(self._url_parts(inner, depth + 1))
                else:
                    parts.append(("lit", _text(self.source, child)))
            return parts
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and _text(self.source, operator) == "+":
                return self._url_parts(
                    node.child_by_field_name("left"), depth + 1
                ) + self._url_parts(node.child_by_field_name("right"), depth + 1)
        return [("expr", node)]

    def _host_choosing(self, expr, kind: str, sink, depth: int = 0) -> bool:
        """Whether request data can decide the host of ``expr``: it starts the
        URL, or fills the authority after ``scheme://`` or after a clean base
        URL. A value that starts with ``/`` after a base only adds a path."""
        node = self._resolve_single(expr)
        if node is None or depth > 4:
            return True
        if node.type in {"member_expression", "call_expression"}:
            base = node
            if node.type == "call_expression":
                callee = _unwrap(node.child_by_field_name("function"))
                if callee is not None and callee.type == "member_expression" and _text(
                    self.source, callee.child_by_field_name("property")
                ) in {"toString", "toJSON", "valueOf"}:
                    base = callee.child_by_field_name("object")
            if base.type == "member_expression" and _text(
                self.source, base.child_by_field_name("property")
            ) in {"href", "toString", "origin"}:
                base = base.child_by_field_name("object")
            resolved = self._resolve_single(base)
            if resolved is not None and resolved.type == "new_expression":
                node = resolved
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            new_args = _call_args(node)
            if ctor is not None and _text(self.source, ctor) == "URL" and new_args:
                if self.taint.taint(new_args[0], kind) is not None and not (
                    self._path_like(new_args[0])
                ):
                    return self._host_choosing(new_args[0], kind, sink, depth + 1)
                if len(new_args) > 1 and not self.taint._is_self_url(new_args[1]):
                    return self.taint.taint(new_args[1], kind) is not None and (
                        self._host_choosing(new_args[1], kind, sink, depth + 1)
                    )
                return False
        state = "start"
        for part_kind, value in self._url_parts(node):
            if part_kind == "lit":
                text = value
                if state == "start":
                    if not text:
                        continue
                    match = re.match(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//|^[/\\]$", text)
                    if match is None:
                        return False
                    state = "authority"
                    text = text[match.end() :]
                if re.search(r"[/?#\\]", text):
                    return False
                continue
            clean = (
                (kind == "redirect" and self._is_host_header(value))
                or self._unguarded(value, kind, sink) is None
            )
            if state == "start":
                if not clean:
                    return True
                state = "authority"
                continue
            if self._path_like(value):
                return False
            if not clean:
                return True
        return False

    def _redirect_target(self, callee, args):
        if callee.type == "identifier":
            name = _text(self.source, callee)
            binding = self.ctx.named_import(name)
            if binding is None or binding[0] not in _REDIRECT_IMPORT_MODULES:
                return None
            if binding[1] not in {"redirect", "permanentRedirect", "redirectDocument"}:
                return None
            return f"{name}()", self._pick_target(args)
        if callee.type != "member_expression":
            return None
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return None
        method = _text(self.source, prop)
        root = _chain_root(self.source, obj)
        if root is None:
            return None
        receiver = _text(self.source, root)
        is_response = receiver in self.taint.spec.response_names
        if method == "redirect":
            if is_response or (
                obj.type == "identifier" and receiver in {"NextResponse", "Response"}
            ):
                return f"{receiver}.redirect()", self._pick_target(args)
            return None
        if not is_response:
            return None
        if method == "location":
            return f"{receiver}.location()", args[0]
        if method in {"setHeader", "set", "header"} and len(args) >= 2:
            name = _string_value(self.source, args[0])
            if name is not None and name.lower() == "location":
                return f"{receiver}.{method}('Location')", args[1]
            return None
        if method == "writeHead" and len(args) >= 2:
            headers = _unwrap(args[-1])
            for key in ("Location", "location"):
                value = _object_value(self.source, headers, key)
                if value is not None:
                    return f"{receiver}.writeHead() Location", value
        return None

    def _pick_target(self, args):
        if len(args) >= 2:
            first = _unwrap(args[0])
            second = _unwrap(args[1])
            if first is not None and first.type == "number":
                return args[1]
            if second is not None and second.type == "number":
                return args[0]
        return args[0]

    def _redirect(self, node, callee, args) -> None:
        target = self._redirect_target(callee, args)
        if target is None:
            return
        label, value = target
        if value is None:
            return
        if self._redirect_prefix_safe(value):
            self._safe("SKY-D230", node)
            return
        found = self.taint.taint(value, "redirect")
        if found is None:
            if self._all_leaves_guarded(value, "redirect", node):
                self._safe("SKY-D230", node)
            return
        if self._unguarded(value, "redirect", node) is None:
            self._safe("SKY-D230", node)
            return
        if not self._host_choosing(value, "redirect", node):
            return
        self._report(
            node,
            "SKY-D230",
            "HIGH",
            f"Open redirect: request data chooses the target of {label}. "
            "Allow only relative paths or a fixed list of destinations.",
            value,
            found.label,
            "redirect",
            f"{label} target",
            "relative-path check that rejects '//' or an allowlist of destinations",
        )

    def _redirect_prefix_safe(self, value) -> bool:
        inner = _unwrap(value)
        if inner is not None and inner.type == "new_expression":
            ctor = inner.child_by_field_name("constructor")
            new_args = _call_args(inner)
            if ctor is not None and _text(self.source, ctor) == "URL" and new_args:
                first = self.taint.static_prefix(new_args[0])
                if self.taint.taint(new_args[0], "redirect") is not None:
                    return safe_redirect_prefix(first)
                if _safe_relative_prefix(first) and len(new_args) > 1:
                    if self.taint._is_self_url(new_args[1]):
                        return True
                    return _fixed_host_prefix(self.taint.static_prefix(new_args[1]))
                return safe_redirect_prefix(first)
            return False
        return safe_redirect_prefix(self.taint.static_prefix(value))

    def _content_type_blocks_html(self, node, receiver_root) -> bool:
        receiver = _text(self.source, receiver_root)
        for name, call_args in _chain_calls(self.source, node.child_by_field_name("function")):
            if self._non_html_type(name, call_args):
                return True
        for other in self.taint.nodes:
            if other.start_byte >= node.start_byte:
                break
            if other.type == "call_expression":
                callee = _unwrap(other.child_by_field_name("function"))
                if callee is None or callee.type != "member_expression":
                    continue
                root = _chain_root(self.source, callee)
                if root is None or _text(self.source, root) != receiver:
                    continue
                for name, call_args in _chain_calls(self.source, other):
                    if self._non_html_type(name, call_args):
                        return True
            elif other.type == "assignment_expression":
                path = _member_path(self.source, other.child_by_field_name("left"))
                if path in ([receiver, "type"], [receiver, "response", "type"]):
                    value = self.ctx.const_string(other.child_by_field_name("right"))
                    if value is not None and not _html_capable(value):
                        return True
        return False

    def _non_html_type(self, method: str, args) -> bool:
        if method in {"type", "contentType"} and args:
            value = self.ctx.const_string(args[0])
            return value is not None and not _html_capable(value)
        if method in {"set", "header", "setHeader"} and args:
            if len(args) >= 2:
                name = _string_value(self.source, args[0])
                value = self.ctx.const_string(args[1])
                if name is not None and name.lower() == "content-type" and value is not None:
                    return not _html_capable(value)
                return False
            headers = _unwrap(args[0])
            for key in ("Content-Type", "content-type"):
                value_node = _object_value(self.source, headers, key)
                if value_node is not None:
                    value = self.ctx.const_string(value_node)
                    return value is not None and not _html_capable(value)
        if method == "writeHead" and len(args) >= 2:
            headers = _unwrap(args[-1])
            for key in ("Content-Type", "content-type"):
                value_node = _object_value(self.source, headers, key)
                if value_node is not None:
                    value = self.ctx.const_string(value_node)
                    return value is not None and not _html_capable(value)
        return False

    def _whole_container(self, expr) -> bool:
        node = _unwrap(expr)
        if node is None:
            return False
        path = _member_path(self.source, node)
        if path is not None and len(path) == 2 and path[0] in self.taint.spec.request_names:
            return True
        if node.type == "identifier":
            name = _text(self.source, node)
            if name in self.taint.spec.seeded and not self.taint.events.get(name):
                return self.taint.spec.seeded[name].shape == OBJECT
            selected, strong = self.taint._selected_events(name, node)
            if strong and len(selected) == 1 and selected[0].mode == "decl":
                return self._whole_container(selected[0].value)
        return False

    def _response(self, node, callee, args) -> None:
        if callee.type != "member_expression":
            return
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            return
        method = _text(self.source, prop)
        if method not in {"send", "write", "end"}:
            return
        root = _chain_root(self.source, obj)
        if root is None:
            return
        receiver = _text(self.source, root)
        if receiver not in self.taint.spec.response_names and receiver not in _RESPONSE_NAMES:
            return
        if self.taint.spec.framework == "koa":
            return
        first = args[0]
        found = self._unguarded(first, "xss", node)
        if found is None:
            return
        html = _has_html_literal(self.source, first) or self._html_binding(first)
        if not html:
            express_send = (
                method == "send"
                and self.taint.spec.framework in {"express", "nest", "next-pages"}
                and receiver in self.taint.spec.response_names
            )
            literal = _unwrap(first)
            if (
                not express_send
                or self._whole_container(first)
                or (literal is not None and literal.type in {"object", "array"})
            ):
                return
        if self._content_type_blocks_html(node, root):
            return
        self._report(
            node,
            "SKY-D228",
            "HIGH",
            f"XSS: request data is sent as HTML with {receiver}.{method}() "
            "without escaping",
            first,
            found.label,
            "xss",
            f"{receiver}.{method}() HTML response",
            "HTML escaping, a non-HTML content type, or a template engine with autoescape",
        )

    def _html_binding(self, expr) -> bool:
        node = _unwrap(expr)
        if node is None or node.type != "identifier":
            return False
        for event in self.taint.events.get(_text(self.source, node), []):
            if event.value is not None and _has_html_literal(self.source, event.value):
                return True
        return False

    def _assignment(self, node) -> None:
        left = _unwrap(node.child_by_field_name("left"))
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        self._koa_body(node, left, right)
        self._two_level_write(node, left, right)

    def _koa_body(self, node, left, right) -> None:
        if self.taint.spec.framework != "koa":
            return
        path = _member_path(self.source, left)
        if path is None or len(path) < 2:
            return
        if path[0] not in self.taint.spec.response_names:
            return
        if path[1:] not in (["body"], ["response", "body"]):
            return
        found = self._unguarded(right, "xss", node)
        if found is None or self._whole_container(right):
            return
        if not (_starts_with_html(self.source, right) or self._starts_tainted(right)):
            return
        root = _chain_root(self.source, left)
        if root is not None and self._content_type_blocks_html(node, root):
            return
        self._report(
            node,
            "SKY-D228",
            "HIGH",
            f"XSS: request data is sent as HTML through {path[0]}.body "
            "without escaping",
            right,
            found.label,
            "xss",
            f"{path[0]}.body HTML response",
            "HTML escaping, a non-HTML ctx.type, or a template engine with autoescape",
        )

    def _starts_tainted(self, expr) -> bool:
        node = _unwrap(expr)
        if node is None:
            return False
        if node.type == "template_string":
            for child in node.children:
                if child.type == "`":
                    continue
                if child.type == "template_substitution":
                    inner = next(iter(child.named_children), None)
                    return self.taint.taint(inner, "xss") is not None
                return False
            return False
        if node.type == "binary_expression":
            return self._starts_tainted(node.child_by_field_name("left"))
        if node.type == "ternary_expression":
            return self._starts_tainted(
                node.child_by_field_name("consequence")
            ) or self._starts_tainted(node.child_by_field_name("alternative"))
        return self.taint.taint(node, "xss") is not None

    def _two_level_write(self, node, left, right) -> None:
        if left.type != "subscript_expression":
            return
        inner = _unwrap(left.child_by_field_name("object"))
        if inner is None or inner.type != "subscript_expression":
            return
        outer_key = left.child_by_field_name("index")
        inner_key = inner.child_by_field_name("index")
        if outer_key is None or inner_key is None:
            return
        if _string_value(self.source, outer_key) is not None:
            return
        found = self.taint.taint(inner_key, "proto")
        if found is None or self._key_guarded(inner_key, node):
            return
        if self._null_prototype_base(inner.child_by_field_name("object")):
            return
        self._report(
            node,
            "SKY-D510",
            "HIGH",
            "Prototype pollution: request data chooses the first property name of "
            "a nested write; '__proto__' makes the second write change "
            "Object.prototype",
            inner_key,
            found.label,
            "proto",
            "obj[key][key2] = value",
            "reject '__proto__', 'constructor' and 'prototype' keys or use a Map",
        )

    def _key_guarded(self, key, sink) -> bool:
        subject = _subject(self.source, key)
        for fact in self.taint.facts_at(sink):
            if fact.subject != subject:
                continue
            if fact.kind in {"in_list", "strict", "own_key", "typed"}:
                return True
            if fact.kind == "not_in_list" and "__proto__" in fact.data:
                return True
        return False

    def _null_prototype_base(self, target) -> bool:
        root = _chain_root(self.source, target)
        if root is None or root.type != "identifier":
            return False
        name = _text(self.source, root)
        values = []
        selected, _ = self.taint._selected_events(name, root)
        for event in selected:
            values.append(event.value)
        if not selected and name in self.ctx.const_values:
            values.append(self.ctx.const_values[name])
        if not values:
            return False
        for value in values:
            text = ""
            if value is not None:
                text = _text(self.source, _unwrap(value)).replace(" ", "")
            if text != "Object.create(null)" and not text.startswith("newMap("):
                return False
        return True

    def _nosql(self, node, callee, args) -> None:
        if not self.ctx.mongo or self.ctx.mongo_sanitized:
            return
        if callee.type != "member_expression":
            return
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None or obj.type == "array":
            return
        if self._receiver_is_http_object(obj):
            return
        method = _text(self.source, prop)
        if method in {"$where"}:
            found = self._unguarded(args[0], "nosql", node)
            if found is not None:
                self._nosql_report(node, args[0], found, method, "$where")
            return
        if method == "distinct":
            if len(args) < 2:
                return
            target = args[1]
        elif method == "aggregate":
            target = self._match_stage(args[0])
            if target is None:
                return
        elif method in _MONGO_FILTER_METHODS:
            target = args[0]
        else:
            return
        result = self._injectable(target, node, 0)
        if result is None:
            return
        found, why = result
        self._nosql_report(node, target, found, method, why)

    def _match_stage(self, pipeline):
        pipeline = _unwrap(pipeline)
        if pipeline is None or pipeline.type != "array":
            return None
        for stage in pipeline.named_children:
            value = _object_value(self.source, stage, "$match")
            if value is not None:
                return value
        return None

    def _injectable(self, expr, sink, depth: int):
        node = _unwrap(expr)
        if node is None or depth > 4:
            return None
        if node.type == "object":
            keys = set()
            for child in node.named_children:
                if child.type == "pair":
                    key = child.child_by_field_name("key")
                    if key is not None:
                        keys.add(_text(self.source, key).strip("'\""))
            if keys & _ORM_OPTION_KEYS:
                return None
            for child in node.named_children:
                if child.type == "spread_element":
                    inner = next(iter(child.named_children), None)
                    found = self._object_taint(inner, sink)
                    if found is not None:
                        return found, "spread into the query object"
                    continue
                if child.type == "shorthand_property_identifier":
                    found = self._object_taint(child, sink)
                    if found is not None:
                        return found, f"value of `{_text(self.source, child)}`"
                    continue
                if child.type != "pair":
                    continue
                key_node = child.child_by_field_name("key")
                value = child.child_by_field_name("value")
                if key_node is None or value is None:
                    continue
                key = _text(self.source, key_node).strip("'\"")
                if key == "$where":
                    found = self._unguarded(value, "nosql", sink)
                    if found is not None:
                        return found, "$where JavaScript"
                    continue
                if key in _MONGO_LOGICAL_KEYS:
                    inner_value = _unwrap(value)
                    if inner_value is not None and inner_value.type == "array":
                        for item in inner_value.named_children:
                            result = self._injectable(item, sink, depth + 1)
                            if result is not None:
                                return result
                    continue
                if key.startswith("$"):
                    continue
                found = self._object_taint(value, sink)
                if found is not None:
                    return found, f"value of `{key}`"
            return None
        if node.type == "identifier" and depth < 4:
            found = self._object_taint(node, sink)
            if found is not None:
                return found, "query object"
            selected, strong = self.taint._selected_events(_text(self.source, node), node)
            for event in selected:
                if event.mode == "decl" and event.value is not None:
                    result = self._injectable(event.value, sink, depth + 1)
                    if result is not None:
                        return result
            return None
        found = self._object_taint(node, sink)
        if found is not None:
            return found, "query object"
        return None

    def _object_taint(self, expr, sink) -> _Taint | None:
        found = self._unguarded(expr, "nosql", sink)
        if found is None or found.shape != OBJECT:
            return None
        return found

    def _nosql_report(self, node, expr, found: _Taint, method: str, why: str) -> None:
        self._report(
            node,
            "SKY-D238",
            "HIGH",
            f"NoSQL injection: request data reaches the {method}() query ({why}); "
            "a JSON body such as {\"$ne\": null} becomes a query operator. "
            "Cast values to strings or validate them first.",
            expr,
            found.label,
            "nosql",
            f"{method}() query filter",
            "String()/typeof check, schema validation, or mongo-sanitize",
        )

    def _merge(self, node, callee, args) -> None:
        if callee.type != "identifier":
            return
        name = _text(self.source, callee)
        function = self.ctx.functions.get(name)
        if function is None or not _is_unsafe_merge(self.ctx, function):
            return
        for arg in args[1:]:
            found = self.taint.taint(arg, "proto")
            if found is None or found.shape != OBJECT:
                continue
            self._report(
                node,
                "SKY-D510",
                "HIGH",
                f"Prototype pollution: request data is merged by {name}(), which "
                "copies keys recursively without rejecting '__proto__' and "
                "'constructor'",
                arg,
                found.label,
                "proto",
                f"{name}() recursive merge",
                "skip '__proto__', 'constructor' and 'prototype' keys or check hasOwnProperty on the target",
            )
            return


def _html_capable(content_type: str) -> bool:
    lowered = content_type.lower()
    return "html" in lowered or "xml" in lowered or "svg" in lowered


def _starts_with_html(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "string":
        return bool(_HTML_START_RE.search(_text(source, node)[1:-1]))
    if node.type == "template_string":
        for child in node.children:
            if child.type == "`":
                continue
            if child.type == "string_fragment":
                return bool(_HTML_START_RE.search(_text(source, child)))
            return False
        return False
    if node.type == "binary_expression":
        return _starts_with_html(source, node.child_by_field_name("left"))
    return False


def _is_unsafe_merge(ctx: _FileContext, function) -> bool:
    if function.id in ctx.merge_memo:
        return ctx.merge_memo[function.id]
    result = _unsafe_merge_shape(ctx, function)
    ctx.merge_memo[function.id] = result
    return result


def _unsafe_merge_shape(ctx: _FileContext, function) -> bool:
    source = ctx.source
    params = []
    for param in _param_nodes(function):
        pattern = _param_pattern(param)
        if pattern is None or pattern.type != "identifier":
            return False
        params.append(_text(source, pattern))
    if len(params) < 2:
        return False
    body = function.child_by_field_name("body")
    if body is None:
        return False
    name = _function_name(source, function)
    body_text = _text(source, body)
    if re.search(r"['\"`](?:__proto__|constructor|prototype)['\"`]", body_text):
        return False
    if re.search(r"hasOwnProperty|Object\.hasOwn\b|Object\.create\(\s*null\s*\)", body_text):
        return False
    keys: set[str] = set()
    for node in _iter_nodes(body):
        if node.type == "for_in_statement":
            left = node.child_by_field_name("left")
            right = _unwrap(node.child_by_field_name("right"))
            if left is None or right is None:
                continue
            right_text = _text(source, right)
            if not any(
                re.fullmatch(rf"(?:Object\.(?:keys|entries)\()?{re.escape(p)}\)?", right_text)
                for p in params
            ):
                continue
            keys.update(_pattern_names(source, left))
    if not keys:
        return False
    recursive = False
    copies = False
    for node in _iter_nodes(body):
        if node.type == "call_expression" and name is not None:
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None and _text(source, callee) == name:
                recursive = True
        if node.type == "assignment_expression":
            left = _unwrap(node.child_by_field_name("left"))
            if left is None or left.type != "subscript_expression":
                continue
            target = _unwrap(left.child_by_field_name("object"))
            index = _unwrap(left.child_by_field_name("index"))
            if (
                target is not None
                and index is not None
                and target.type == "identifier"
                and _text(source, target) in params
                and _text(source, index) in keys
            ):
                copies = True
    return recursive and copies


def _scan(
    root_node, source: bytes, file_path: str
) -> tuple[list[dict[str, Any]], dict[str, set[int]]]:
    ctx = _FileContext(source, root_node, file_path)
    findings: list[dict[str, Any]] = []
    safe_lines: dict[str, set[int]] = {}
    seen: set[tuple[str, int, int]] = set()
    for node in ctx.function_nodes:
        spec = _handler_spec(ctx, node)
        if spec is None:
            continue
        taint = _HandlerTaint(ctx, spec)
        checker = _SinkChecker(ctx, taint, file_path)
        checker.run()
        for rule_id, lines in checker.safe_lines.items():
            safe_lines.setdefault(rule_id, set()).update(lines)
        for finding in checker.findings:
            key = (finding["rule_id"], finding["line"], finding["col"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    for finding in findings:
        lines = safe_lines.get(finding["rule_id"])
        if lines is not None:
            lines.discard(finding["line"])
    if ctx.shell_process_calls is not None and not ctx.shell_process_calls.complete:
        findings.append(
            {
                "rule_id": "SKY-ANALYSIS-INCOMPLETE",
                "severity": "HIGH",
                "kind": "processing_error",
                "message": (
                    "TypeScript child_process shell-option analysis exceeded its "
                    "bounded work budget; a security candidate remains unresolved."
                ),
                "file": str(file_path),
                "line": 1,
                "col": 0,
            }
        )
    return findings, safe_lines


def scan_request_taint(
    root_node, source: bytes, file_path: str, *, is_test_file: bool = False
) -> RequestTaintResult:
    findings: list[dict[str, Any]] = []
    safe_lines: dict[str, set[int]] = {}
    if not is_test_file and _TLS_ENV.encode() in source:
        findings.extend(_check_tls_env(source, root_node, file_path))
    if not is_test_file and _REJECT_UNAUTHORIZED.encode() in source:
        findings.extend(_check_reject_unauthorized(source, root_node, file_path))
    if _SOURCE_HINT_RE.search(source):
        taint_findings, safe_lines = _scan(root_node, source, file_path)
        findings.extend(taint_findings)
    return RequestTaintResult(findings, safe_lines)


def scan_express_taint_sinks(
    root_node, source: bytes, file_path: str, *, is_test_file: bool = False
) -> list[dict[str, Any]]:
    return scan_request_taint(
        root_node, source, file_path, is_test_file=is_test_file
    ).findings


def merge_express_taint_findings(
    findings: list[dict[str, Any]], new_findings: list[dict[str, Any]]
) -> None:
    """Append new findings. A same-line same-rule pattern finding gains the
    request evidence, and the proven severity and message when they rank higher."""
    for finding in new_findings:
        existing = next(
            (
                f
                for f in findings
                if f.get("rule_id") == finding["rule_id"]
                and f.get("line") == finding["line"]
            ),
            None,
        )
        if existing is None:
            findings.append(finding)
            continue
        if "security_evidence" in finding and "security_evidence" not in existing:
            existing["security_evidence"] = finding["security_evidence"]
            if _SEVERITY_RANK.get(finding["severity"], 0) > _SEVERITY_RANK.get(
                existing.get("severity", ""), 0
            ):
                existing["severity"] = finding["severity"]
                existing["message"] = finding["message"]
