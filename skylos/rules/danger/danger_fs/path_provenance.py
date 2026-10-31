"""Caller provenance for Python path findings that rest on a helper parameter.

``path_flow`` checks one file at a time. A path built from a parameter of a
function that is not an entry point gets ``metadata.path_source =
helper_parameter``: its callers may be in another module. This pass reads the
scanned project as source (it never imports or runs it) and follows that
parameter back through imports, assignments, calls, returns, constructor
bindings, aliases and ``functools.partial`` to every call site it can
resolve, then classifies what reaches the path:

``untrusted``
    A resolved chain starts at web request data, a route or MCP tool argument,
    a function a deployment file names as a server or handler entry point,
    standard input, a CGI request variable, a network response or an archive
    member name. The finding stays reported, with that chain as its evidence.
``safe``
    The whole project was scanned, nothing outside it can call the function
    (no callback, dynamic dispatch, external base class, unknown decorator or
    public package API), and every caller passes literals, the module's own
    location, clock or numeric values, temporary paths, test values or
    operator input (CLI arguments, environment, working directory).
``unknown``
    Anything else. Unknown is neither proof of an attack nor proof of safety,
    so the finding is not reported as a vulnerability.

Safe and unknown findings move to ``suppressed``. Every finding gets
``metadata.path_provenance``: the located steps that were followed, origin
first, and the step that stayed unresolved.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from skylos.rules.danger.danger_fs.closed_world import (
    _MAX_BYTES,
    _MAX_FILES,
    _MAX_TOTAL_BYTES,
    _SKIP_DIRS,
    _is_config_file,
    _is_python_source,
    is_helper_parameter_finding,
)
from skylos.rules.danger.danger_fs.path_flow import (
    _allowlist_names,
    _commonpath_elements,
    _test_is_negative,
)
from skylos.rules.danger.module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from skylos.rules.danger.untrusted_sources import (
    REQUEST_ANNOTATIONS,
    REQUEST_NAMES,
    entrypoint_decorator,
)
from skylos.rules.quality._test_code import is_python_test_file

PROVENANCE_VERSION = 1
RESOLVED_CALLER_SOURCE = "resolved_caller"
UNTRUSTED = "untrusted"
OPERATOR = "operator"
SAFE = "safe"
UNKNOWN = "unknown"
INCOMPLETE = "incomplete"
PARAMETER = "parameter"
TRAVERSAL_RULE = "SKY-D215"
ALLOWLIST_CHECK = "is checked against a constant allowlist"
CONTAINMENT_CHECK = "is checked to stay inside a base directory"
_PATH_CONSTRUCTORS = frozenset({"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"})
_REALPATH_FUNCTIONS = frozenset({"os.path.realpath", "posixpath.realpath", "ntpath.realpath"})
_COMMONPATH_FUNCTIONS = frozenset({"os.path.commonpath", "posixpath.commonpath", "ntpath.commonpath"})
SAFE_REASON = (
    "every caller in the project passes a value that cannot carry an attacker "
    "path (literal, module location, clock or number, temporary path, test "
    "value or operator input)"
)
UNKNOWN_REASON = (
    "the path comes from a helper parameter whose callers could not all be "
    "resolved; unknown is not proof of an attack (see metadata.path_provenance)"
)
INCOMPLETE_NOTE = (
    "caller analysis stopped at a limit before every chain was followed; the "
    "finding is kept because an exhausted analysis is not proof of safety"
)

_MAX_CHAINS = 4
_MAX_STEPS = 32
_MAX_CALLER_DEPTH = 32
_MAX_SITES = 512
_MAX_WORK = 400000
_MAX_VALUE_DEPTH = 12
_MAX_PARAM_VALUE_DEPTH = 3
_MAX_FIXPOINT_ROUNDS = 8
_RECURSION_LIMIT = 4000
if sys.version_info >= (3, 11):
    _RECURSION_LIMIT = 12000

_MODULE_DUNDERS = frozenset({"__file__", "__name__", "__package__", "__spec__", "__path__"})
_CLI_DECORATORS = frozenset({"command", "group", "callback", "argument", "option"})
_TOOL_DECORATORS = frozenset({"tool", "resource", "prompt"})
_TRANSPARENT_DECORATORS = frozenset(
    {"builtins.staticmethod", "builtins.classmethod", "builtins.property",
     "functools.lru_cache", "functools.cache", "functools.cached_property",
     "abc.abstractmethod", "typing.overload", "typing.override", "typing.final",
     "typing_extensions.override", "typing_extensions.final",
     "contextlib.contextmanager", "contextlib.asynccontextmanager"}
)  # fmt: skip
_INERT_BASES = frozenset(
    {"builtins.object", "builtins.dict", "builtins.list", "builtins.str",
     "builtins.int", "builtins.float", "builtins.tuple", "builtins.set",
     "builtins.frozenset", "builtins.bytes", "abc.ABC", "typing.Generic",
     "typing.Protocol", "typing.NamedTuple", "typing.TypedDict",
     "typing_extensions.Protocol", "typing_extensions.TypedDict", "enum.Enum",
     "enum.IntEnum", "enum.StrEnum", "enum.Flag", "enum.IntFlag"}
)  # fmt: skip
_CGI_VARIABLES = frozenset(
    {"QUERY_STRING", "PATH_INFO", "PATH_TRANSLATED", "REQUEST_URI",
     "SCRIPT_NAME", "CONTENT_TYPE", "CONTENT_LENGTH", "REQUEST_METHOD",
     "REMOTE_USER", "REMOTE_IDENT", "AUTH_TYPE"}
)  # fmt: skip
_NETWORK_CALLS = frozenset(
    {"requests.get", "requests.post", "requests.put", "requests.patch",
     "requests.delete", "requests.head", "requests.options", "requests.request",
     "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
     "httpx.head", "httpx.options", "httpx.request", "httpx.stream",
     "urllib.request.urlopen", "urllib3.request"}
)  # fmt: skip
_NETWORK_CLIENTS = frozenset(
    {"requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient",
     "aiohttp.ClientSession", "urllib3.PoolManager"}
)  # fmt: skip
_NETWORK_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "urlopen"}
)
_SOCKET_READS = frozenset({"recv", "recvfrom", "recv_into", "recvmsg", "makefile"})
_ARCHIVE_TYPES = frozenset(
    {"zipfile.ZipFile", "tarfile.open", "tarfile.TarFile", "tarfile.TarFile.open",
     "tarfile.TarFile.taropen", "tarfile.TarFile.gzopen", "tarfile.TarFile.bz2open",
     "tarfile.TarFile.xzopen", "py7zr.SevenZipFile", "rarfile.RarFile"}
)  # fmt: skip
_ARCHIVE_MEMBER_METHODS = frozenset(
    {"namelist", "infolist", "getinfo", "getmembers", "getnames", "getmember", "next"}
)
_HTTP_HANDLER_BASES = frozenset(
    {"http.server.BaseHTTPRequestHandler", "http.server.SimpleHTTPRequestHandler",
     "http.server.CGIHTTPRequestHandler", "socketserver.BaseRequestHandler",
     "socketserver.StreamRequestHandler", "socketserver.DatagramRequestHandler"}
)  # fmt: skip
_HTTP_HANDLER_ATTRS = frozenset({"path", "headers", "rfile", "requestline", "raw_requestline", "request"})
_TORNADO_HANDLER_BASES = frozenset({"tornado.web.RequestHandler"})
_TORNADO_ARGUMENT_METHODS = frozenset(
    {"get_argument", "get_arguments", "get_query_argument", "get_query_arguments",
     "get_body_argument", "get_body_arguments", "get_cookie", "decode_argument"}
)  # fmt: skip
_TORNADO_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_SAFE_CALLS = frozenset(
    {"builtins.int", "builtins.float", "builtins.bool", "builtins.len",
     "builtins.hash", "builtins.id", "builtins.ord", "builtins.abs",
     "builtins.round", "builtins.sum", "builtins.range", "time.time",
     "time.time_ns", "time.monotonic", "time.perf_counter", "time.localtime",
     "time.gmtime", "datetime.datetime.now", "datetime.datetime.utcnow",
     "datetime.datetime.today", "datetime.date.today",
     "datetime.datetime.fromtimestamp", "datetime.date.fromtimestamp",
     "os.getpid", "os.getppid", "os.cpu_count", "uuid.uuid1", "uuid.uuid3",
     "uuid.uuid4", "uuid.uuid5", "secrets.token_hex", "secrets.token_urlsafe",
     "random.randint", "random.random", "getpass.getuser", "platform.system",
     "platform.machine", "socket.gethostname"}
)  # fmt: skip
_TEMP_CALLS = frozenset(
    {"tempfile.mkdtemp", "tempfile.gettempdir", "tempfile.mkstemp",
     "tempfile.TemporaryDirectory", "tempfile.NamedTemporaryFile",
     "tempfile.mktemp", "tempfile.gettempdirb"}
)  # fmt: skip
_OPERATOR_CALLS = frozenset({"os.getcwd", "os.getcwdb", "pathlib.Path.cwd", "pathlib.Path.home"})
_SAFE_ATTRIBUTES = frozenset({"sys.executable", "sys.prefix", "sys.base_prefix", "sys.exec_prefix", "os.curdir", "os.sep", "os.pardir"})
_STDIN_CALLS = frozenset({"builtins.input", "builtins.raw_input", "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines"})
_ENV_CALLS = frozenset({"os.getenv", "os.environ.get", "os.getenvb"})
_FORMAT_ONLY_METHODS = frozenset({"strftime", "isoformat", "timestamp"})
_REQUEST_PARSERS = ("flask_restful.reqparse.", "flask_restx.reqparse.", "webargs.")
_TRANSPARENT_CALLS = frozenset(
    {"builtins.str", "builtins.repr", "builtins.format", "builtins.sorted",
     "builtins.list", "builtins.tuple", "builtins.set", "builtins.frozenset",
     "builtins.reversed", "builtins.next", "builtins.iter", "builtins.min",
     "builtins.max", "builtins.dict", "builtins.enumerate", "builtins.zip",
     "os.path.join", "os.path.abspath", "os.path.realpath", "os.path.normpath",
     "os.path.normcase", "os.path.expanduser", "os.path.dirname",
     "os.path.splitext", "os.path.split", "os.path.relpath", "os.path.commonpath",
     "os.path.commonprefix", "os.path.basename", "posixpath.join",
     "posixpath.basename", "posixpath.dirname", "ntpath.basename", "os.fspath",
     "os.fsencode", "os.fsdecode", "pathlib.Path", "pathlib.PurePath",
     "pathlib.PosixPath", "pathlib.WindowsPath", "pathlib.PurePosixPath",
     "pathlib.PureWindowsPath", "glob.glob", "glob.iglob", "os.listdir",
     "os.scandir", "os.walk", "fnmatch.filter", "urllib.parse.unquote",
     "urllib.parse.unquote_plus", "urllib.parse.quote", "urllib.parse.urljoin",
     "urllib.parse.urlparse", "urllib.parse.urlsplit", "urllib.parse.unquote_to_bytes",
     "urllib.request.url2pathname", "ntpath.splitdrive", "os.path.splitdrive",
     "shlex.split", "shlex.quote", "re.sub", "re.split", "re.match", "re.search",
     "re.fullmatch", "re.findall", "copy.copy", "copy.deepcopy",
     "textwrap.dedent", "importlib.resources.files", "importlib.resources.path",
     "os.path.expandvars", "json.loads", "json.load", "yaml.safe_load",
     "yaml.load", "yaml.full_load", "tomllib.loads", "tomllib.load",
     "tomli.loads", "tomli.load", "ast.literal_eval", "base64.b64decode",
     "base64.urlsafe_b64decode", "codecs.decode", "urllib.parse.parse_qs",
     "urllib.parse.parse_qsl"}
)  # fmt: skip
_TRANSPARENT_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "title", "casefold",
     "capitalize", "swapcase", "replace", "format", "format_map", "join",
     "split", "rsplit", "splitlines", "partition", "rpartition", "removeprefix",
     "removesuffix", "encode", "decode", "zfill", "ljust", "rjust", "center",
     "expandtabs", "translate", "joinpath", "resolve", "absolute", "expanduser",
     "with_name", "with_suffix", "with_stem", "relative_to", "as_posix", "glob",
     "rglob", "iterdir", "get", "items", "values", "keys", "copy", "pop",
     "setdefault", "group", "groups", "groupdict", "__fspath__", "__str__"}
)  # fmt: skip
_D215_SANITIZERS = frozenset(
    {"os.path.basename", "posixpath.basename", "ntpath.basename",
     "werkzeug.utils.secure_filename", "werkzeug.secure_filename"}
)  # fmt: skip
_BASENAME_PARTS = frozenset({"name", "stem", "suffix", "suffixes"})
_WEB_FRAMEWORKS = frozenset(
    {"django", "rest_framework", "flask", "quart", "werkzeug", "starlette",
     "fastapi", "aiohttp", "sanic", "bottle", "pyramid", "falcon", "tornado",
     "litestar", "ninja", "cherrypy", "webob", "channels", "connexion",
     "flask_restful", "flask_restx", "responder", "masonite"}
)  # fmt: skip
_DJANGO_VIEW_BASES = ("django.views", "rest_framework.")
_DJANGO_VIEW_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "dispatch",
     "list", "create", "retrieve", "update", "partial_update", "destroy"}
)  # fmt: skip
_DJANGO_URL_FUNCTIONS = frozenset({"django.urls.path", "django.urls.re_path", "django.conf.urls.url", "django.urls.conf.path", "django.urls.conf.re_path"})
_DEPENDENCY_MARKERS = frozenset(
    {"fastapi.Depends", "fastapi.Security", "fastapi.params.Depends",
     "fastapi.params.Security", "fastapi.param_functions.Depends",
     "fastapi.param_functions.Security"}
)  # fmt: skip
_FASTAPI_APPS = frozenset({"fastapi.FastAPI", "fastapi.APIRouter", "fastapi.routing.APIRouter", "fastapi.applications.FastAPI"})
_FASTAPI_ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "api_route", "websocket", "trace"})
_STREAM_REGISTRATIONS = {
    "asyncio.start_server": ("client_connected_cb", 0),
    "asyncio.start_unix_server": ("client_connected_cb", 0),
}
_STREAM_OPENERS = frozenset({"asyncio.open_connection", "asyncio.open_unix_connection"})
_STREAM_READS = frozenset({"read", "readline", "readexactly", "readuntil"})
_SOCKET_INTO = frozenset({"recv_into", "recvfrom_into", "recvmsg_into"})
_TASK_METHODS = frozenset({"delay", "apply_async", "s", "si", "signature"})
_RQ_QUEUES = frozenset({"rq.Queue", "rq.queue.Queue"})
_RQ_METHODS = {"enqueue": 0, "enqueue_call": None, "enqueue_in": 1, "enqueue_at": 1}
_RQ_OPTIONS = frozenset(
    {"job_timeout", "timeout", "result_ttl", "ttl", "failure_ttl", "depends_on",
     "job_id", "at_front", "description", "meta", "retry", "on_success",
     "on_failure", "on_stopped", "pipeline", "func", "args", "kwargs"}
)  # fmt: skip
_DOWNLOADERS = frozenset({"urllib.request.urlretrieve"})
_HASH_DIGEST = re.compile(r"^(?:hashlib|hmac)\.[\w.]*\.hexdigest$")
_PROCESS_LAUNCHES = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.check_call",
     "subprocess.check_output", "subprocess.Popen", "os.system", "os.popen",
     "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl", "os.execlp",
     "os.spawnv", "os.spawnl", "os.spawnvp", "asyncio.create_subprocess_exec",
     "asyncio.create_subprocess_shell"}
)  # fmt: skip
_INDIRECT_CALLERS = {
    "threading.Thread": "target",
    "threading.Timer": "function",
    "multiprocessing.Process": "target",
    "asyncio.to_thread": "first",
}
_EXECUTOR_TYPES = frozenset(
    {"concurrent.futures.ThreadPoolExecutor", "concurrent.futures.ProcessPoolExecutor",
     "concurrent.futures.thread.ThreadPoolExecutor", "multiprocessing.Pool",
     "multiprocessing.pool.ThreadPool"}
)  # fmt: skip
_ROUTE_REGISTRATIONS = {
    "flask.Flask.add_url_rule": ("view_func", 2),
    "flask.Blueprint.add_url_rule": ("view_func", 2),
    "fastapi.FastAPI.add_api_route": ("endpoint", 1),
    "fastapi.APIRouter.add_api_route": ("endpoint", 1),
    "fastapi.FastAPI.add_api_websocket_route": ("endpoint", 1),
    "starlette.routing.Route": ("endpoint", 1),
    "starlette.routing.WebSocketRoute": ("endpoint", 1),
    "django.urls.path": ("view", 1),
    "django.urls.re_path": ("view", 1),
    "django.conf.urls.url": ("view", 1),
    "aiohttp.web.get": ("handler", 1),
    "aiohttp.web.post": ("handler", 1),
    "aiohttp.web.route": ("handler", 2),
}
_TOOL_REGISTRATIONS = {
    "mcp.server.fastmcp.FastMCP.add_tool": ("fn", 0),
    "fastmcp.FastMCP.add_tool": ("fn", 0),
    "mcp.server.fastmcp.FastMCP.tool": ("fn", 0),
    "fastmcp.FastMCP.tool": ("fn", 0),
}
_MUTATING_METHODS = frozenset(
    {"append", "extend", "insert", "update", "setdefault", "add", "__setitem__", "appendleft", "extendleft"}
)
_READ_ONLY_FUNCTIONS = frozenset(
    {"builtins.len", "builtins.sorted", "builtins.list", "builtins.tuple",
     "builtins.set", "builtins.frozenset", "builtins.dict", "builtins.iter",
     "builtins.enumerate", "builtins.zip", "builtins.any", "builtins.all",
     "builtins.min", "builtins.max", "builtins.sum", "builtins.print",
     "builtins.isinstance", "builtins.str", "builtins.repr", "builtins.bool",
     "builtins.reversed", "json.dumps", "copy.deepcopy", "copy.copy"}
)  # fmt: skip
_READ_ONLY_METHODS = frozenset({"get", "keys", "values", "items", "copy", "index", "count", "__contains__", "__getitem__"})
_HARMLESS_CALLS = frozenset({"builtins.callable", "builtins.hasattr", "builtins.isinstance", "builtins.id", "builtins.repr", "builtins.print", "builtins.getattr"})
_FUNCTION_METADATA = frozenset({"__name__", "__qualname__", "__doc__", "__module__", "__wrapped__", "setter", "getter", "deleter"})
_SERVER_WORDS = re.compile(
    r"\b(?:gunicorn|uvicorn|hypercorn|daphne|waitress(?:-serve)?|uwsgi|granian|wsgi|asgi|handler)\b",
    re.I,
)
PUBLIC_IMPORTERS = (
    "is public in an importable package; importers outside the project are not visible"
)
_RUNTIME_ATTRIBUTES = frozenset(
    {"str", "type", "staticmethod", "isalnum", "join", "get", "post", "put",
     "patch", "delete", "head", "options", "__class__",
     "__bases__", "__call__", "__getattribute__", "__code__",
     "__defaults__", "__kwdefaults__", "__globals__", "__dict__",
     "route_class", "router", "dependency_overrides",
     "__signature__", "__annotations__", "__wrapped__"}
)  # fmt: skip
_FRAMEWORK_SETUP_CALLS = frozenset(
    {"include_router", "add_api_route", "middleware", "add_middleware", "mount"}
)
_INERT_MIDDLEWARE = frozenset(
    {f"{package}.middleware.{module}.{name}"
     for package in ("starlette", "fastapi")
     for module, name in (("cors", "CORSMiddleware"), ("gzip", "GZipMiddleware"),
                          ("trustedhost", "TrustedHostMiddleware"),
                          ("httpsredirect", "HTTPSRedirectMiddleware"))}
)  # fmt: skip
_STATIC_APPS = frozenset(
    {"starlette.staticfiles.StaticFiles", "fastapi.staticfiles.StaticFiles"}
)
_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_INERT_ROUTE_OPTIONS = frozenset(
    {"response_model", "status_code", "tags", "summary", "description", "response_description",
     "deprecated", "include_in_schema", "name", "operation_id"}
)  # fmt: skip
_CLOCK_CALLS = frozenset(
    {
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "datetime.datetime.today",
        "datetime.date.today",
    }
)
_NUMERIC_CLOCK_DIRECTIVES = frozenset("YmdHMSfjy")
_PYDANTIC_MODELS = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel"})
_PYDANTIC_FIELDS = frozenset({"pydantic.Field", "pydantic.fields.Field"})
_PYDANTIC_CONFIGS = frozenset({"pydantic.ConfigDict", "pydantic.config.ConfigDict"})
_FASTAPI_BODIES = frozenset(
    {"fastapi.Body", "fastapi.params.Body", "fastapi.param_functions.Body"}
)
_OPTIONAL_TYPES = frozenset({"typing.Optional", "typing_extensions.Optional"})
_UNION_TYPES = frozenset({"typing.Union", "typing_extensions.Union"})
_PLAIN_ANNOTATION_NODES = (ast.Name, ast.Attribute, ast.Subscript, ast.Tuple, ast.List, ast.BinOp,
                           ast.BitOr, ast.Constant, ast.Load)  # fmt: skip
_IMPLICIT_MODULES = frozenset({"sitecustomize", "usercustomize"})
_DYNAMIC_LOADING_PACKAGES = frozenset(
    {"importlib", "importlib_metadata", "runpy", "pkgutil", "pkg_resources", "imp"}
)
_DYNAMIC_LOADING_BUILTINS = frozenset(
    {
        "builtins.__import__",
        "builtins.exec",
        "builtins.eval",
        "builtins.execfile",
        "builtins.globals",
        "builtins.locals",
        "builtins.vars",
    }
)
_DYNAMIC_LOADING_PROTOCOLS = frozenset(
    {
        "import_module",
        "__import__",
        "run_path",
        "run_module",
        "exec_module",
        "load_module",
        "load_source",
        "load_entry_point",
        "iter_entry_points",
        "entry_points",
        "execfile",
    }
)
_MODEL_HOOK_ATTRIBUTES = frozenset(
    {"__init__", "__new__", "__setattr__", "__getattr__", "__getattribute__", "__class__", "__dict__",
     "__fields__", "__validators__", "__get_validators__", "__get_pydantic_core_schema__",
     "__pydantic_validator__", "__pydantic_core_schema__", "__pydantic_fields__", "__pydantic_decorators__",
     "model_config", "model_fields", "model_post_init", "model_validate", "model_construct",
     "default", "default_factory", "annotation"}
)  # fmt: skip


def _extend(chain, step):
    if len(chain) >= _MAX_STEPS:
        return (*chain[: _MAX_STEPS - 1], step)
    return (*chain, step)


def _with_hidden_callers(facts, escapes, step):
    """``facts`` plus an unknown chain for each caller outside the project
    that a proof could not see."""
    for escape in dict.fromkeys(escapes):
        facts.add(_Facts.leaf(UNKNOWN, escape).then(step))
    return facts


class _Facts:
    """Chains of located steps, origin first, grouped by what the origin is."""

    KINDS = (UNTRUSTED, INCOMPLETE, OPERATOR, SAFE, UNKNOWN, PARAMETER)

    def __init__(self):
        self.chains = {kind: [] for kind in self.KINDS}

    @classmethod
    def leaf(cls, kind, step):
        facts = cls()
        facts.chains[kind].append((step,))
        return facts

    def add(self, other):
        for kind in self.KINDS:
            mine = self.chains[kind]
            for chain in other.chains[kind]:
                if len(mine) >= _MAX_CHAINS:
                    break
                if chain not in mine:
                    mine.append(chain)
        return self

    def then(self, step):
        facts = _Facts()
        for kind in self.KINDS:
            facts.chains[kind] = [_extend(chain, step) for chain in self.chains[kind]]
        return facts

    def moved(self, source, target, step):
        """The same facts with ``source`` chains re-filed under ``target``."""
        facts = _Facts()
        for kind in self.KINDS:
            facts.chains[kind] = list(self.chains[kind])
        for chain in self.chains[source]:
            if len(facts.chains[target]) < _MAX_CHAINS:
                facts.chains[target].append(_extend(chain, step))
        facts.chains[source] = []
        return facts

    def empty(self):
        return not any(self.chains.values())


@dataclass(eq=False)
class _Bind:
    kind: str
    node: ast.AST
    value: ast.AST | None
    scope: object
    top_level: bool = False


@dataclass(eq=False)
class _Scope:
    unit: object
    node: ast.AST
    kind: str
    parent: object = None
    binds: dict = field(default_factory=dict)
    globals: set = field(default_factory=set)
    nonlocals: set = field(default_factory=set)

    def add(self, name, bind):
        self.binds.setdefault(name, []).append(bind)


@dataclass(frozen=True)
class _V:
    """A value a receiver or callee may hold: a project function (``fn``),
    class (``cls``), instance (``inst``), module (``mod``), partial
    (``partial``), the ``super()`` proxy, or an external dotted name
    (``ext``, ``extinst`` for a call result, ``extattr`` for its attribute)."""

    kind: str
    unit: object = None
    node: object = None
    name: str = ""
    bound: bool = False
    extra: tuple = ()


@dataclass(eq=False)
class _Site:
    unit: object
    scope: object
    call: ast.AST
    args: list
    keywords: list
    skip_first: bool
    how: str


@dataclass
class _Sites:
    resolved: list = field(default_factory=list)
    possible: list = field(default_factory=list)
    escapes: list = field(default_factory=list)
    entries: list = field(default_factory=list)


def _target_names(target):
    return [node for node in ast.walk(target) if isinstance(node, ast.Name)]


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    return None


_OPERATORS = {ast.Div: "/", ast.Add: "+", ast.Mod: "%", ast.Mult: "*", ast.Sub: "-"}


def _describe(node, depth=0):
    """Identifiers and structure of ``node``; literal contents are withheld."""
    text = _describe_parts(node, depth)
    if len(text) > 60:
        return text[:57] + "..."
    return text


def _describe_parts(node, depth):
    if depth > 4:
        return "..."
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return "<literal>"
    if isinstance(node, ast.Attribute):
        return f"{_describe_parts(node.value, depth + 1)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{_describe_parts(node.func, depth + 1)}(...)"
    if isinstance(node, ast.Subscript):
        return f"{_describe_parts(node.value, depth + 1)}[...]"
    if isinstance(node, ast.BinOp):
        symbol = _OPERATORS.get(type(node.op), "?")
        return f"{_describe_parts(node.left, depth + 1)} {symbol} {_describe_parts(node.right, depth + 1)}"
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    return type(node).__name__


def _step(unit, node, text):
    return f"{unit.rel}:{getattr(node, 'lineno', 0)} {text}"


def _function_params(fn):
    args = fn.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        params.append(args.vararg)
    if args.kwarg:
        params.append(args.kwarg)
    return params


def _decorator_names(fn):
    names = []
    for decorator in getattr(fn, "decorator_list", []) or []:
        target = decorator
        if isinstance(decorator, ast.Call):
            target = decorator.func
        names.append(_dotted(target) or "")
    return names


def _is_static(fn):
    return any(name.rsplit(".", 1)[-1] == "staticmethod" for name in _decorator_names(fn))


def _is_classmethod(fn):
    return any(name.rsplit(".", 1)[-1] == "classmethod" for name in _decorator_names(fn))


def _is_property(fn):
    return any(
        name.rsplit(".", 1)[-1] in {"property", "cached_property"}
        for name in _decorator_names(fn)
    )


def _is_fixture(fn):
    return any(name in {"pytest.fixture", "fixture"} for name in _decorator_names(fn))


def _returned_values(fn):
    """Return and yield values of ``fn``, nested definitions excluded."""
    if isinstance(fn, ast.Lambda):
        return [fn.body]
    values = []
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            values.append(node.value)
        elif isinstance(node, (ast.Yield, ast.YieldFrom)) and node.value is not None:
            values.append(node.value)
        stack.extend(ast.iter_child_nodes(node))
    return values


def _constant_literal(node):
    """A literal whose leaves are constants: str, numbers, containers of them."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_constant_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _constant_literal(key) and _constant_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    return False


def _mutable_literal(node):
    if isinstance(node, (ast.Dict, ast.List, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    if isinstance(node, ast.Call):
        name = _dotted(node.func) or ""
        return name.rsplit(".", 1)[-1] in {"dict", "list", "set", "defaultdict", "OrderedDict", "deque", "Counter", "bytearray"}
    return False


class _Unit:
    """One parsed source file with lexical scopes and binding records."""

    def __init__(self, path, rel, tree, is_test):
        self.path = path
        self.rel = rel
        self.tree = tree
        self.is_test = is_test
        self.parents = {}
        self.node_scope = {}
        self.function_scopes = {}
        self.class_scopes = {}
        self.module = _Scope(self, tree, "module")
        self.calls = []
        self.loads = []
        self.attribute_stores = []
        self.subscript_stores = []
        self.name_mutations = {}
        self.name_escapes = {}
        self.attr_mutations = {}
        self.attr_escapes = {}
        self.star_import = False
        self.module_names = set()
        self._rebinding = None
        self._index()

    def rebinding(self):
        if self._rebinding is None:
            try:
                self._rebinding = module_rebinding(self.tree, module_name_for(self.path), self.parents_map())
            except (RecursionError, ValueError):
                self._rebinding = (True, frozenset())
        return self._rebinding

    def parents_map(self):
        """Every child id mapped to its parent, as ``module_rebinding`` expects."""
        parents = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        return parents

    def _push(self, stack, nodes, scope, top, parent):
        for node in reversed(nodes):
            if node is None:
                continue
            self.parents[id(node)] = parent
            stack.append((node, scope, top))

    def _index(self):
        stack = []
        self._push(stack, self.tree.body, self.module, True, self.tree)
        while stack:
            node, scope, top = stack.pop()
            self.node_scope[id(node)] = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._bind_name(scope, node.name, _Bind("def", node, None, scope, top))
                inner = _Scope(self, node, "function", scope)
                self.function_scopes[id(node)] = inner
                for param in _function_params(node):
                    inner.add(param.arg, _Bind("param", param, None, inner, True))
                annotations = [param.annotation for param in _function_params(node) if param.annotation is not None]
                outer = [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults, *annotations]
                self._push(stack, outer, scope, False, node)
                self._push(stack, node.body, inner, True, node)
                continue
            if isinstance(node, ast.Lambda):
                inner = _Scope(self, node, "lambda", scope)
                self.function_scopes[id(node)] = inner
                for param in _function_params(node):
                    inner.add(param.arg, _Bind("param", param, None, inner, True))
                self._push(stack, [*node.args.defaults, *node.args.kw_defaults], scope, False, node)
                self._push(stack, [node.body], inner, False, node)
                continue
            if isinstance(node, ast.ClassDef):
                self._bind_name(scope, node.name, _Bind("class", node, None, scope, top))
                inner = _Scope(self, node, "class", scope)
                self.class_scopes[id(node)] = inner
                outer = [*node.decorator_list, *node.bases, *[keyword.value for keyword in node.keywords]]
                self._push(stack, outer, scope, False, node)
                self._push(stack, node.body, inner, True, node)
                continue
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                inner = _Scope(self, node, "comprehension", scope)
                for generator in node.generators:
                    for name in _target_names(generator.target):
                        inner.add(name.id, _Bind("comp", generator, generator.iter, inner))
                self._push(stack, list(ast.iter_child_nodes(node)), inner, False, node)
                continue
            self._record(node, scope, top)
            self._push(stack, list(ast.iter_child_nodes(node)), scope, False, node)

    def _binding_scope(self, scope, name):
        current = scope
        while current.kind == "comprehension":
            current = current.parent
        if name in current.globals:
            return self.module
        if name in current.nonlocals:
            parent = current.parent
            while parent is not None and parent.kind not in {"function", "lambda"}:
                parent = parent.parent
            if parent is not None:
                return parent
        return current

    def _bind_name(self, scope, name, bind):
        self._binding_scope(scope, name).add(name, bind)

    def _bind_target(self, target, value, statement, scope, top, kind):
        if isinstance(target, ast.Name):
            self._bind_name(scope, target.id, _Bind(kind, statement, value, scope, top))
        elif isinstance(target, (ast.Tuple, ast.List)):
            pairs = None
            if (
                isinstance(value, (ast.Tuple, ast.List))
                and len(value.elts) == len(target.elts)
                and not any(isinstance(item, ast.Starred) for item in [*value.elts, *target.elts])
            ):
                pairs = list(zip(target.elts, value.elts))
            if pairs is not None:
                for item, item_value in pairs:
                    self._bind_target(item, item_value, statement, scope, top, kind)
            else:
                for item in target.elts:
                    self._bind_target(item, value, statement, scope, top, "unpack")
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, value, statement, scope, top, "unpack")
        elif isinstance(target, ast.Attribute):
            self.attribute_stores.append((target, value, statement, scope))
        elif isinstance(target, ast.Subscript):
            self.subscript_stores.append((target, value, statement, scope))

    def _record(self, node, scope, top):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(target, node.value, node, scope, top, "assign")
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind_target(node.target, node.value, node, scope, top, "assign")
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                self._bind_name(scope, node.target.id, _Bind("augassign", node, node.value, scope, top))
            else:
                self._bind_target(node.target, node.value, node, scope, top, "augassign")
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _target_names(node.target):
                self._bind_name(scope, name.id, _Bind("iter", node, node.iter, scope, top))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in _target_names(item.optional_vars):
                        self._bind_name(scope, name.id, _Bind("with", node, item.context_expr, scope, top))
        elif isinstance(node, ast.NamedExpr):
            self._bind_target(node.target, node.value, node, scope, False, "assign")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self._bind_name(scope, alias.asname, _Bind("import", node, (alias.name, None, 0), scope, top))
                else:
                    head = alias.name.split(".", 1)[0]
                    self._bind_name(scope, head, _Bind("import", node, (head, None, 0), scope, top))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    self.star_import = True
                    continue
                value = (node.module or "", alias.name, node.level or 0)
                self._bind_name(scope, alias.asname or alias.name, _Bind("import", node, value, scope, top))
        elif isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind_name(scope, node.name, _Bind("unknown", node, None, scope, False))
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _target_names(target):
                    self._bind_name(scope, name.id, _Bind("unknown", node, None, scope, False))
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind_name(scope, node.name, _Bind("unknown", node, None, scope, False))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind_name(scope, node.rest, _Bind("unknown", node, None, scope, False))
        elif isinstance(node, ast.Call):
            self.calls.append((node, scope))
            self._record_name_uses(node, scope)
        elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            self.loads.append((node, scope))

    def _record_name_uses(self, call, scope):
        """Calls that can change a local container: ``name.append(v)`` and
        friends, and ``f(name)`` handing it to other code."""
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr in _MUTATING_METHODS:
            if isinstance(func.value, ast.Name):
                self.name_mutations.setdefault(func.value.id, []).append((call, scope))
            elif isinstance(func.value, ast.Attribute):
                self.attr_mutations.setdefault(func.value.attr, []).append((call, scope))
        for argument in [*call.args, *[keyword.value for keyword in call.keywords]]:
            if isinstance(argument, ast.Starred):
                argument = argument.value
            if isinstance(argument, ast.Name):
                self.name_escapes.setdefault(argument.id, []).append((call, scope))
            elif isinstance(argument, ast.Attribute):
                self.attr_escapes.setdefault(argument.attr, []).append((call, scope))

    def scope_of(self, node):
        return self.node_scope.get(id(node), self.module)

    def enclosing_function(self, node):
        scope = self.scope_of(node)
        while scope is not None and scope.kind not in {"function", "lambda"}:
            scope = scope.parent
        return scope

    def lookup(self, scope, name):
        """``(scope, binds)`` Python would read ``name`` from, or None (builtin)."""
        current = scope
        first = True
        while current is not None:
            if current.kind == "class" and not first:
                current = current.parent
                continue
            if name in current.globals:
                binds = self.module.binds.get(name)
                if binds:
                    return self.module, binds
                return None
            if name in current.binds and name not in current.nonlocals:
                return current, current.binds[name]
            first = False
            current = current.parent
        return None

    def ancestors(self, node):
        current = self.parents.get(id(node))
        while current is not None:
            yield current
            current = self.parents.get(id(current))


class _Project:
    """Source of every Python file under the scan root, indexed for lookups."""

    def __init__(self, root, complete):
        self.root = root
        self.complete = complete
        self.truncated = False
        self.skipped = []
        self.limits = []
        self.units = []
        self.by_path = {}
        self.modules = {}
        self.config_lines = []
        self.function_info = {}
        self.class_info = {}
        self.calls_by_name = {}
        self.dynamic_calls = []
        self.computed_calls = []
        self.loads_by_name = {}
        self.attr_stores = {}
        self._value_cache = {}
        self._value_active = set()
        self._mro_cache = {}
        self._subclasses = None
        self._site_cache = {}
        self._param_value_active = set()
        self._import_maps = {}
        self._launch = None
        self._constant_tables = {}
        self._store_cache = {}
        self._returned = {}
        self._module_cache = {}
        self._global_refs = {}
        self.subscript_stores_by_name = {}
        self._sites_active = set()
        self._config_index = None
        self._django_views = {}
        self._framework_units = {}
        self._imports = {}
        self._importers = None
        self._dynamic_loaders = {}

    @classmethod
    def load(cls, root, files=None, complete=True):
        project = cls(root, complete)
        count = 0
        total = 0
        for path in project._candidate_files(files):
            count += 1
            if count > _MAX_FILES:
                project.limits.append("project file budget reached; remaining callers are unknown")
                project.complete = False
                project.truncated = True
                break
            try:
                if path.is_symlink():
                    continue
                size = path.stat().st_size
                if size > _MAX_BYTES:
                    project.limits.append(f"{project._rel(path)} is over the size budget")
                    project.complete = False
                    project._skip_large(path, size)
                    continue
                total += size
                if total > _MAX_TOTAL_BYTES:
                    project.limits.append("project byte budget reached; remaining callers are unknown")
                    project.complete = False
                    project.truncated = True
                    break
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _is_python_source(path, text):
                project._add_python(path, text)
            elif _is_config_file(path):
                rel = project._rel(path)
                for number, line in enumerate(text.splitlines(), 1):
                    project.config_lines.append((rel, number, line))
        project._index()
        return project

    def returned_values(self, fn):
        cached = self._returned.get(id(fn))
        if cached is None:
            cached = _returned_values(fn)
            self._returned[id(fn)] = cached
        return cached

    def _rel(self, path):
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def _candidate_files(self, files):
        if files is not None:
            for path in files:
                yield Path(path)
            return
        for current, dirs, names in os.walk(self.root):
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in _SKIP_DIRS and not (Path(current) / name / "pyvenv.cfg").exists()
            )
            for name in sorted(names):
                path = Path(current) / name
                if path.suffix in {".py", ".pyw"} or not path.suffix or _is_config_file(path):
                    yield path

    def _skip_large(self, path, size):
        """Keep the text of a Python file over the size budget so a caller
        in it is noticed even though it is not indexed."""
        if path.suffix not in {".py", ".pyw", ""}:
            return
        if size > _MAX_BYTES * 32:
            self.truncated = True
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self.truncated = True
            return
        if _is_python_source(path, text):
            self.skipped.append((self._rel(path), text, INCOMPLETE, "is over the size budget"))

    def _add_python(self, path, text):
        try:
            tree = ast.parse(text.lstrip("\ufeff"))
        except (SyntaxError, ValueError):
            self.limits.append(f"{self._rel(path)} could not be parsed")
            self.complete = False
            self.skipped.append((self._rel(path), text, UNKNOWN, "does not parse as Python 3"))
            return
        except (RecursionError, MemoryError):
            self.limits.append(f"{self._rel(path)} is too deeply nested to parse")
            self.complete = False
            self.skipped.append((self._rel(path), text, INCOMPLETE, "is too deeply nested to parse"))
            return
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        is_test = is_python_test_file(resolved, self.root, text)
        try:
            unit = _Unit(resolved, self._rel(resolved), tree, is_test)
        except RecursionError:
            self.limits.append(f"{self._rel(path)} is too deeply nested to index")
            self.complete = False
            self.skipped.append((self._rel(path), text, INCOMPLETE, "is too deeply nested to index"))
            return
        self.units.append(unit)
        self.by_path[resolved] = unit
        unit.module_names = self._module_names(unit)
        for name in unit.module_names:
            self.modules.setdefault(name, []).append(unit)

    def _module_names(self, unit):
        names = set()
        parts = list(Path(unit.rel).parts)
        if parts:
            parts[-1] = Path(parts[-1]).stem
        is_init = unit.path.name == "__init__.py"
        if is_init and parts:
            parts = parts[:-1]
        if parts:
            names.add(".".join(parts))
            if parts[0] == "src" and len(parts) > 1:
                names.add(".".join(parts[1:]))
        package = []
        directory = unit.path.parent
        while (directory / "__init__.py").is_file() and directory != directory.parent:
            package.insert(0, directory.name)
            directory = directory.parent
        if not is_init:
            package.append(unit.path.stem)
        if package:
            names.add(".".join(package))
        names.discard("")
        return names

    def _index(self):
        for unit in self.units:
            for scope in unit.function_scopes.values():
                definer = scope.parent
                owner = None
                if definer is not None and definer.kind == "class":
                    owner = definer.node
                self.function_info[id(scope.node)] = (unit, definer, scope, owner)
            for scope in unit.class_scopes.values():
                self.class_info[id(scope.node)] = (unit, scope.parent, scope)
            for call, scope in unit.calls:
                func = call.func
                key = None
                if isinstance(func, ast.Name):
                    key = func.id
                elif isinstance(func, ast.Attribute):
                    key = func.attr
                if key is None:
                    self.dynamic_calls.append((unit, call, scope))
                else:
                    self.calls_by_name.setdefault(key, []).append((unit, call, scope))
                if (
                    isinstance(func, ast.Name)
                    and func.id == "getattr"
                    and len(call.args) >= 2
                ):
                    self.dynamic_calls.append((unit, call, scope))
                if not unit.is_test and _computed_call(call):
                    self.computed_calls.append((unit, call, scope))
            for node, scope in unit.loads:
                parent = unit.parents.get(id(node))
                if isinstance(parent, ast.Call) and parent.func is node:
                    continue
                key = getattr(node, "id", None)
                if not isinstance(node, ast.Name):
                    key = node.attr
                self.loads_by_name.setdefault(key, []).append((unit, node, scope))
            for target, value, statement, scope in unit.attribute_stores:
                self.attr_stores.setdefault(target.attr, []).append((unit, target, value, statement, scope))
            for target, value, statement, scope in unit.subscript_stores:
                base = target.value
                key = None
                if isinstance(base, ast.Name):
                    key = base.id
                elif isinstance(base, ast.Attribute):
                    key = base.attr
                if key is not None:
                    self.subscript_stores_by_name.setdefault(key, []).append((unit, target, value, statement, scope))
        for unit in self.units:
            for call, scope in unit.calls:
                if isinstance(call.func, (ast.Call, ast.Subscript)):
                    self.dynamic_calls.append((unit, call, scope))

    def import_map(self, unit):
        cached = self._import_maps.get(id(unit))
        if cached is not None:
            return cached
        bindings = {}
        for name, binds in unit.module.binds.items():
            if len(binds) == 1 and binds[0].kind == "import":
                module, member, level = binds[0].value
                if level:
                    continue
                if member is None:
                    bindings[name] = module
                else:
                    bindings[name] = f"{module}.{member}"
        self._import_maps[id(unit)] = bindings
        return bindings

    def _units_at(self, base):
        found = []
        for candidate in (base.with_name(base.name + ".py"), base / "__init__.py"):
            unit = self.by_path.get(candidate)
            if unit is not None:
                found.append(unit)
        return found

    def find_module(self, unit, dotted, level):
        key = (unit.path.parent, dotted, level)
        cached = self._module_cache.get(key)
        if cached is None:
            cached = self._find_module(unit, dotted, level)
            self._module_cache[key] = cached
        return cached

    def _find_module(self, unit, dotted, level):
        if level:
            base = unit.path.parent
            for _ in range(level - 1):
                base = base.parent
            parts = []
            if dotted:
                parts = dotted.split(".")
            if not parts:
                return self._units_at(base.parent / base.name)
            return self._units_at(base.joinpath(*parts))
        if not dotted:
            return []
        found = list(self.modules.get(dotted, []))
        parts = dotted.split(".")
        directory = unit.path.parent
        while True:
            for candidate in self._units_at(directory.joinpath(*parts)):
                if candidate not in found:
                    found.append(candidate)
            if directory == self.root or directory == directory.parent:
                break
            if self.root not in directory.parents:
                break
            directory = directory.parent
        return found

    def imported_units(self, unit):
        """Project modules that loading ``unit`` may execute: every static
        import anywhere in it, the packages on the way, and its own package."""
        cached = self._imports.get(id(unit))
        if cached is not None:
            return cached
        requests = []
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    requests.extend(
                        (".".join(parts[:index]), 0)
                        for index in range(1, len(parts) + 1)
                    )
            elif isinstance(node, ast.ImportFrom):
                parts = []
                if node.module:
                    parts = node.module.split(".")
                requests.append((node.module or "", node.level))
                requests.extend(
                    (".".join(parts[:index]), node.level)
                    for index in range(1, len(parts))
                )
                requests.extend(
                    (".".join([*parts, alias.name]), node.level)
                    for alias in node.names
                    if alias.name != "*"
                )
        found = []
        for dotted, level in requests:
            for target in self.find_module(unit, dotted, level):
                if target is not unit and target not in found:
                    found.append(target)
        directory = unit.path.parent
        while (directory / "__init__.py").is_file() and directory != directory.parent:
            package = self.by_path.get(directory / "__init__.py")
            if package is not None and package is not unit and package not in found:
                found.append(package)
            directory = directory.parent
        self._imports[id(unit)] = found
        return found

    def importers(self, unit):
        if self._importers is None:
            self._importers = {}
            for candidate in self.units:
                for target in self.imported_units(candidate):
                    self._importers.setdefault(id(target), []).append(candidate)
        return self._importers.get(id(unit), [])

    def process_units(self, anchors):
        """Modules that can run in the same process as ``anchors``: whatever
        imports them (a possible entry point, except test modules when the
        anchors are not tests), everything those load, and implicit startup
        modules."""
        include_tests = any(unit.is_test for unit in anchors)
        roots = list(dict.fromkeys(anchors))
        seen = {id(unit) for unit in roots}
        pending = list(roots)
        while pending:
            for parent in self.importers(pending.pop()):
                if id(parent) in seen or (parent.is_test and not include_tests):
                    continue
                seen.add(id(parent))
                roots.append(parent)
                pending.append(parent)
        loaded = {id(unit): unit for unit in roots}
        pending = list(roots)
        while pending:
            for child in self.imported_units(pending.pop()):
                if id(child) not in loaded:
                    loaded[id(child)] = child
                    pending.append(child)
        for unit in self.units:
            if unit.path.stem in _IMPLICIT_MODULES:
                loaded[id(unit)] = unit
        if any(self._loads_dynamically(unit) for unit in loaded.values()):
            return list(self.units)
        return list(loaded.values())

    def _loads_dynamically(self, unit):
        """Loader capabilities, including escaped references, can execute any
        project module. Their invocation spelling does not bound the process."""
        cached = self._dynamic_loaders.get(id(unit))
        if cached is None:
            cached = any(
                self._loader_reference(unit, scope, node) for node, scope in unit.loads
            ) or any(
                isinstance(call.func, ast.Attribute)
                and call.func.attr in _DYNAMIC_LOADING_PROTOCOLS
                for call, _scope in unit.calls
            )
            self._dynamic_loaders[id(unit)] = cached
        return cached

    @staticmethod
    def _loader_identity(name):
        if name in {"builtins", "__builtins__"}:
            return True
        if name.split(".", 1)[0] in _DYNAMIC_LOADING_PACKAGES:
            return True
        return any(
            name == target or name.startswith(target + ".")
            for target in _DYNAMIC_LOADING_BUILTINS
        )

    @staticmethod
    def _literal_global_projection(unit, scope, node):
        if not isinstance(node, ast.Name) or node.id != "globals":
            return None
        if unit.lookup(scope, node.id) is not None:
            return None
        namespace = unit.parents.get(id(node))
        if not isinstance(namespace, ast.Call) or namespace.func is not node:
            return None
        if namespace.args or namespace.keywords:
            return None
        projection = unit.parents.get(id(namespace))
        key = None
        if isinstance(projection, ast.Subscript) and projection.value is namespace:
            key = projection.slice
        elif (
            isinstance(projection, ast.Attribute)
            and projection.value is namespace
            and projection.attr == "get"
        ):
            call = unit.parents.get(id(projection))
            if (
                isinstance(call, ast.Call)
                and call.func is projection
                and 1 <= len(call.args) <= 2
                and not call.keywords
                and (len(call.args) == 1 or isinstance(call.args[1], ast.Constant))
            ):
                key = call.args[0]
        if (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value != "__builtins__"
            and key.value in unit.module.binds
        ):
            return key.value
        return None

    def _loader_reference(self, unit, scope, node):
        """Follow import and reference origins, never ordinary data flow.

        A loader passed to a partial, factory, callback or container is itself
        a visible reference. Reversing arbitrary calls/parameters adds no
        loading authority, and exhausting a scalar-value budget is not one.
        """
        projection = self._literal_global_projection(unit, scope, node)
        pending = [("reference", unit, (scope, node))]
        if projection is not None:
            pending = [("namespace", unit, projection)]
        seen = set()
        while pending:
            kind, source, payload = pending.pop()
            if kind == "reference":
                owner_scope, reference = payload
                key = (kind, id(source), id(owner_scope), id(reference))
            elif kind == "binding":
                owner_scope, bind = payload
                key = (kind, id(source), id(bind))
            else:
                key = (kind, id(source), payload)
            if key in seen:
                continue
            seen.add(key)
            if kind == "namespace":
                binds = []
                if payload is None:
                    binds = [
                        bind for items in source.module.binds.values() for bind in items
                    ]
                else:
                    binds = source.module.binds.get(payload, ())
                    if not binds and source.path.name == "__init__.py":
                        pending.extend(
                            ("namespace", child, None)
                            for child in self._units_at(source.path.parent / payload)
                        )
                pending.extend(
                    ("binding", source, (source.module, bind)) for bind in binds
                )
                continue
            if kind == "binding":
                if bind.kind == "import":
                    module, member, level = bind.value
                    targets = self.find_module(source, module, level)
                    name = module
                    if member is not None:
                        name = f"{module}.{member}"
                    if not level and (module == "builtins" or not targets):
                        if self._loader_identity(name):
                            return True
                    pending.extend(("namespace", target, member) for target in targets)
                elif bind.kind == "assign" and isinstance(
                    bind.value, (ast.Name, ast.Attribute)
                ):
                    pending.append(("reference", source, (bind.scope, bind.value)))
                continue
            if isinstance(reference, ast.Attribute):
                pending.append(("reference", source, (owner_scope, reference.value)))
                continue
            if not isinstance(reference, ast.Name):
                continue
            found = source.lookup(owner_scope, reference.id)
            if found is None:
                if reference.id == "__builtins__" or self._loader_identity(
                    "builtins." + reference.id
                ):
                    return True
                continue
            owner, binds = found
            if (
                owner_scope is source.module
                and owner is owner_scope
                and all(
                    bind.scope is owner
                    and bind.top_level
                    and bind.kind in {"import", "assign", "def", "class"}
                    for bind in binds
                )
                and not any(
                    isinstance(parent, (ast.For, ast.AsyncFor, ast.While))
                    for parent in source.ancestors(reference)
                )
            ):
                position = (reference.lineno, reference.col_offset)
                previous = [
                    bind
                    for bind in binds
                    if (
                        getattr(bind.node, "end_lineno", 0),
                        getattr(bind.node, "end_col_offset", 0),
                    )
                    < position
                ]
                if previous:
                    binds = [
                        max(
                            previous,
                            key=lambda bind: (
                                bind.node.end_lineno,
                                bind.node.end_col_offset,
                            ),
                        )
                    ]
            pending.extend(("binding", source, (owner, bind)) for bind in binds)
        return False

    def values(self, unit, scope, expr, depth=0):
        """Possible run-time values of ``expr``, or None when unknown."""
        if expr is None or depth > _MAX_VALUE_DEPTH:
            return None
        key = (id(expr), id(scope))
        if key in self._value_cache:
            return self._value_cache[key]
        if key in self._value_active:
            return None
        self._value_active.add(key)
        try:
            result = self._values(unit, scope, expr, depth)
        finally:
            self._value_active.discard(key)
        if result is not None or depth == 0:
            self._value_cache[key] = result
        return result

    def _values(self, unit, scope, expr, depth):
        if isinstance(expr, ast.Name):
            return self._name_values(unit, scope, expr, depth)
        if isinstance(expr, ast.Attribute):
            base = self.values(unit, scope, expr.value, depth + 1)
            if base is None:
                return None
            return self.member_values(base, expr.attr, depth + 1)
        if isinstance(expr, ast.Call):
            return self._call_values(unit, scope, expr, depth)
        if isinstance(expr, ast.Subscript):
            return self._element_values(unit, scope, expr.value, depth + 1)
        if isinstance(expr, ast.IfExp):
            return self._union(unit, scope, [expr.body, expr.orelse], depth)
        if isinstance(expr, ast.BoolOp):
            return self._union(unit, scope, expr.values, depth)
        if isinstance(expr, (ast.Await, ast.NamedExpr)):
            return self.values(unit, scope, expr.value, depth + 1)
        if isinstance(expr, ast.Lambda):
            return frozenset({_V("fn", unit, expr, extra=(None,))})
        return None

    def _union(self, unit, scope, nodes, depth):
        result = set()
        for node in nodes:
            values = self.values(unit, scope, node, depth + 1)
            if values is None:
                return None
            result |= values
        return frozenset(result)

    def _name_values(self, unit, scope, expr, depth):
        found = unit.lookup(scope, expr.id)
        if found is None:
            if expr.id in _MODULE_DUNDERS or unit.star_import:
                return None
            return frozenset({_V("ext", name="builtins." + expr.id)})
        owner, binds = found
        result = set()
        for bind in binds:
            values = self.bind_values(unit, owner, bind, depth + 1)
            if values is None:
                return None
            result |= values
        return frozenset(result)

    def bind_values(self, unit, owner, bind, depth):
        if bind.kind == "def":
            cls_node = None
            if owner.kind == "class":
                cls_node = owner.node
            return frozenset({_V("fn", unit, bind.node, extra=(cls_node,))})
        if bind.kind == "class":
            return frozenset({_V("cls", unit, bind.node)})
        if bind.kind == "import":
            return self._import_values(unit, bind, depth)
        if bind.kind in {"assign", "with", "unpack"}:
            return self.values(unit, bind.scope, bind.value, depth + 1)
        if bind.kind == "param":
            return self._param_values(unit, owner, bind, depth)
        return None

    def _param_values(self, unit, owner, bind, depth):
        fn = owner.node
        if isinstance(fn, ast.Lambda):
            return None
        positional = [*fn.args.posonlyargs, *fn.args.args]
        parent = owner.parent
        if (
            parent is not None
            and parent.kind == "class"
            and positional
            and positional[0] is bind.node
            and not _is_static(fn)
        ):
            if _is_classmethod(fn):
                return frozenset({_V("cls", unit, parent.node)})
            return frozenset({_V("inst", unit, parent.node)})
        if depth > _MAX_PARAM_VALUE_DEPTH * 4 or id(fn) in self._param_value_active or id(fn) in self._sites_active:
            return None
        self._param_value_active.add(id(fn))
        try:
            sites = self.call_sites(unit, fn)
            if sites.escapes or sites.possible or sites.entries or not sites.resolved:
                return None
            result = set()
            for site in sites.resolved[:_MAX_SITES]:
                for expr, expr_unit, expr_scope in self.bind_argument(fn, site, bind.node.arg):
                    values = self.values(expr_unit, expr_scope, expr, depth + 4)
                    if values is None:
                        return None
                    result |= values
            return frozenset(result)
        finally:
            self._param_value_active.discard(id(fn))

    def _import_values(self, unit, bind, depth):
        module, member, level = bind.value
        if member is None:
            targets = self.find_module(unit, module, 0)
            if targets:
                return frozenset(_V("mod", target) for target in targets)
            return frozenset({_V("ext", name=module)})
        bases = self.find_module(unit, module, level)
        if bases:
            result = set()
            for base in bases:
                values = self.module_member(base, member, depth + 1)
                if values is None:
                    return None
                result |= values
            return frozenset(result)
        if level:
            return None
        return frozenset({_V("ext", name=f"{module}.{member}")})

    def module_member(self, target, name, depth):
        if depth > _MAX_VALUE_DEPTH:
            return None
        binds = target.module.binds.get(name)
        if binds:
            result = set()
            for bind in binds:
                values = self.bind_values(target, target.module, bind, depth + 1)
                if values is None:
                    return None
                result |= values
            return frozenset(result)
        if target.path.name == "__init__.py":
            submodules = self._units_at(target.path.parent / name)
            if submodules:
                return frozenset(_V("mod", sub) for sub in submodules)
        if target.star_import or target.rebinding()[0]:
            return None
        return frozenset()

    def member_values(self, bases, attr, depth):
        result = set()
        for value in bases:
            found = None
            if value.kind == "mod":
                found = self.module_member(value.unit, attr, depth + 1)
            elif value.kind in {"cls", "inst"}:
                found = self.class_member(value.node, attr, value.kind == "inst", depth + 1)
            elif value.kind == "super":
                found = self.super_member(value.node, attr, depth + 1)
            elif value.kind == "ext":
                found = frozenset({_V("ext", name=f"{value.name}.{attr}")})
            elif value.kind in {"extinst", "extattr"}:
                found = frozenset({_V("extattr", name=f"{value.name}.{attr}")})
            if found is None:
                return None
            result |= found
        return frozenset(result)

    def mro(self, cls_node):
        """Project classes in method-resolution order and external bases."""
        cached = self._mro_cache.get(id(cls_node))
        if cached is not None:
            return cached
        self._mro_cache[id(cls_node)] = ([], ["recursive base"])
        info = self.class_info.get(id(cls_node))
        if info is None:
            result = ([], ["class outside the project"])
            self._mro_cache[id(cls_node)] = result
            return result
        unit, definer, _ = info
        order = [(unit, cls_node)]
        external = []
        for base in cls_node.bases:
            target = base
            if isinstance(base, ast.Subscript):
                target = base.value
            values = self.values(unit, definer, target)
            if values is None:
                external.append(_dotted(target) or "an unresolved base")
                continue
            for value in values:
                if value.kind == "cls":
                    base_order, base_external = self.mro(value.node)
                    for item in base_order:
                        if all(item[1] is not seen[1] for seen in order):
                            order.append(item)
                    external.extend(base_external)
                elif value.kind == "ext":
                    if not self._inert_base(value.name):
                        external.append(value.name)
                else:
                    external.append(_dotted(target) or "an unresolved base")
        result = (order, external)
        self._mro_cache[id(cls_node)] = result
        return result

    @staticmethod
    def _inert_base(name):
        if name in _INERT_BASES:
            return True
        if name.startswith("builtins.") and name.endswith(("Error", "Exception", "Warning")):
            return True
        return False

    def subclasses(self, cls_node):
        if self._subclasses is None:
            self._subclasses = {}
            for info in list(self.class_info.values()):
                node = info[2].node
                order, _ = self.mro(node)
                for _, ancestor in order[1:]:
                    self._subclasses.setdefault(id(ancestor), []).append((info[0], node))
        return self._subclasses.get(id(cls_node), [])

    def class_member(self, cls_node, attr, instance, depth):
        """``attr`` read on the class (``instance`` False) or on an instance:
        the first definition in method-resolution order, plus overrides in
        project subclasses and ``self.<attr>`` assignments for an instance."""
        order, external = self.mro(cls_node)
        result = set()
        found = False
        for unit, cls in order:
            values = self._defined_member(unit, cls, attr, instance, depth)
            if values is None:
                return None
            if values is not False:
                found = True
                result |= values
                break
        if instance:
            for unit, sub in self.subclasses(cls_node):
                values = self._defined_member(unit, sub, attr, instance, depth)
                if values is None:
                    return None
                if values is not False:
                    found = True
                    result |= values
            for unit, scope, value in self.instance_stores(cls_node, attr):
                found = True
                values = self.values(unit, scope, value, depth + 1)
                if values is None:
                    return None
                result |= values
        if not found and external:
            return None
        return frozenset(result)

    def _defined_member(self, unit, cls, attr, instance, depth):
        """Values ``cls`` itself defines for ``attr``; False when it defines
        none, None when one is unknown."""
        result = set()
        found = False
        for statement in cls.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == attr:
                found = True
                if _is_property(statement):
                    if not instance:
                        continue
                    for value in self.returned_values(statement):
                        values = self.values(unit, unit.scope_of(value), value, depth + 1)
                        if values is None:
                            return None
                        result |= values
                    continue
                bound = (instance and not _is_static(statement)) or _is_classmethod(statement)
                result.add(_V("fn", unit, statement, bound=bound, extra=(cls,)))
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = getattr(statement, "targets", None) or [statement.target]
                if statement.value is not None and any(
                    isinstance(target, ast.Name) and target.id == attr for target in targets
                ):
                    found = True
                    values = self.values(unit, unit.class_scopes[id(cls)], statement.value, depth + 1)
                    if values is None:
                        return None
                    result |= values
            elif isinstance(statement, ast.ClassDef) and statement.name == attr:
                found = True
                result.add(_V("cls", unit, statement))
        if not found:
            return False
        return result

    def super_member(self, cls_node, attr, depth):
        order, external = self.mro(cls_node)
        for unit, cls in order[1:]:
            for statement in cls.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == attr:
                    return frozenset({_V("fn", unit, statement, bound=not _is_static(statement), extra=(cls,))})
        if external:
            return None
        return frozenset()

    def instance_stores(self, cls_node, attr):
        """``self.<attr> = value`` assignments in methods of the class, its
        project bases and subclasses: ``(unit, scope, value)``."""
        key = (id(cls_node), attr)
        cached = self._store_cache.get(key)
        if cached is None:
            cached = self._instance_stores(cls_node, attr)
            self._store_cache[key] = cached
        return cached

    def _instance_stores(self, cls_node, attr):
        order, _ = self.mro(cls_node)
        classes = [*order, *self.subclasses(cls_node)]
        stores = []
        for unit, cls in classes:
            for statement in cls.body:
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if _is_static(statement):
                    continue
                params = [*statement.args.posonlyargs, *statement.args.args]
                if not params:
                    continue
                self_name = params[0].arg
                for target, value, _, scope in unit.attribute_stores:
                    if target.attr != attr or value is None:
                        continue
                    if not isinstance(target.value, ast.Name) or target.value.id != self_name:
                        continue
                    function = scope
                    while function is not None and function.kind not in {"function", "lambda"}:
                        function = function.parent
                    if function is not None and function.node is statement:
                        stores.append((unit, scope, value))
        return stores

    def init_of(self, cls_node):
        order, _ = self.mro(cls_node)
        for _, cls in order:
            for statement in cls.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == "__init__":
                    return statement
        return None

    def _call_values(self, unit, scope, call, depth):
        funcs = self.values(unit, scope, call.func, depth + 1)
        if funcs is None:
            return None
        result = set()
        for value in funcs:
            found = None
            if value.kind == "cls":
                found = frozenset({_V("inst", value.unit, value.node)})
            elif value.kind == "fn":
                found = self._return_values(value, depth)
            elif value.kind == "partial":
                found = set()
                for target in value.extra[0]:
                    if target.kind != "fn":
                        found = None
                        break
                    returned = self._return_values(target, depth)
                    if returned is None:
                        found = None
                        break
                    found |= returned
            elif value.kind == "ext":
                found = self._external_call_values(unit, scope, call, value.name, depth)
            elif value.kind in {"extinst", "extattr"}:
                found = frozenset({_V("extinst", name=value.name + "()")})
            if found is None:
                return None
            result |= found
        return frozenset(result)

    def _external_call_values(self, unit, scope, call, name, depth):
        if name == "functools.partial" and call.args:
            targets = self.values(unit, scope, call.args[0], depth + 1)
            if targets is None:
                return None
            return frozenset({_V("partial", unit, call, extra=(targets,))})
        if name == "builtins.getattr" and len(call.args) >= 2:
            return self._getattr_values(unit, scope, call, depth)
        if name in {"importlib.import_module", "builtins.__import__"} and call.args:
            return self._import_module_values(unit, scope, call.args[0])
        if name == "builtins.super":
            function = unit.enclosing_function(call)
            if function is not None and function.parent is not None and function.parent.kind == "class":
                return frozenset({_V("super", unit, function.parent.node)})
            return None
        if name == "builtins.type" and len(call.args) == 1:
            values = self.values(unit, scope, call.args[0], depth + 1)
            if values is None:
                return None
            result = set()
            for value in values:
                if value.kind != "inst":
                    return None
                result.add(_V("cls", value.unit, value.node))
            return frozenset(result)
        return frozenset({_V("extinst", name=name)})

    def _name_pattern(self, unit, expr):
        """A regex for the strings ``expr`` can produce, or None for any."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return re.escape(expr.value)
        if isinstance(expr, ast.Name) and expr.id in {"__name__", "__package__"} and unit.lookup(unit.module, expr.id) is None:
            names = sorted(unit.module_names, key=len, reverse=True)
            if names:
                return "(?:" + "|".join(re.escape(name) for name in names) + ")"
            return None
        if isinstance(expr, ast.JoinedStr):
            parts = []
            for value in expr.values:
                if isinstance(value, ast.Constant):
                    parts.append(re.escape(str(value.value)))
                elif isinstance(value, ast.FormattedValue):
                    part = self._name_pattern(unit, value.value)
                    if part is None:
                        part = ".*"
                    parts.append(part)
            return "".join(parts)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = self._name_pattern(unit, expr.left)
            right = self._name_pattern(unit, expr.right)
            if left is None:
                left = ".*"
            if right is None:
                right = ".*"
            return left + right
        return None

    def _getattr_values(self, unit, scope, call, depth):
        owners = self.values(unit, scope, call.args[0], depth + 1)
        if owners is None:
            return None
        name = call.args[1]
        if isinstance(name, ast.Constant) and isinstance(name.value, str):
            return self.member_values(owners, name.value, depth + 1)
        pattern = self._name_pattern(unit, name) or ".*"
        regex = re.compile(f"^{pattern}$")
        result = set()
        for owner in owners:
            names = self._member_names(owner)
            if names is None:
                return None
            for member in names:
                if regex.match(member):
                    found = self.member_values(frozenset({owner}), member, depth + 1)
                    if found is None:
                        return None
                    result |= found
        return frozenset(result)

    def _member_names(self, owner):
        if owner.kind == "mod":
            return list(owner.unit.module.binds)
        if owner.kind in {"cls", "inst"}:
            order, external = self.mro(owner.node)
            if external:
                return None
            names = []
            for _, cls in [*order, *self.subclasses(owner.node)]:
                for statement in cls.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        names.append(statement.name)
            return names
        return None

    def _import_module_values(self, unit, scope, expr):
        pattern = self._name_pattern(unit, expr)
        if pattern is None:
            return None
        regex = re.compile(f"^{pattern}$")
        result = set()
        for name, units in self.modules.items():
            if regex.match(name):
                for target in units:
                    result.add(_V("mod", target))
        if not result:
            return None
        return frozenset(result)

    def _element_values(self, unit, scope, base, depth):
        if not isinstance(base, ast.Name) or depth > _MAX_VALUE_DEPTH:
            return None
        found = unit.lookup(scope, base.id)
        if found is None:
            return None
        owner, binds = found
        if len(binds) == 1 and binds[0].kind == "import":
            module, member, level = binds[0].value
            targets = self.find_module(unit, module, level)
            if member is None or len(targets) != 1:
                return None
            target = targets[0]
            return self._element_values(target, target.module, ast.Name(id=member, ctx=ast.Load()), depth + 1)
        result = set()
        for bind in binds:
            if bind.kind != "assign":
                return None
            value = bind.value
            if isinstance(value, ast.Dict):
                elements = list(value.values)
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                elements = list(value.elts)
            else:
                return None
            for element in elements:
                values = self.values(unit, bind.scope, element, depth + 1)
                if values is None:
                    return None
                result |= values
        for target, value, _, store_scope in unit.subscript_stores:
            if not isinstance(target.value, ast.Name) or target.value.id != base.id:
                continue
            store_owner = unit.lookup(store_scope, base.id)
            if store_owner is None or store_owner[0] is not owner:
                continue
            values = self.values(unit, store_scope, value, depth + 1)
            if values is None:
                return None
            result |= values
        return frozenset(result)

    def _return_values(self, value, depth):
        node = value.node
        info = self.function_info.get(id(node))
        if info is None:
            return None
        unit = info[0]
        returned = self.returned_values(node)
        if not returned:
            return frozenset()
        result = set()
        for expr in returned:
            values = self.values(unit, unit.scope_of(expr), expr, depth + 1)
            if values is None:
                return None
            result |= values
        return frozenset(result)

    def bind_argument(self, fn, site, name):
        """Expressions a call site passes as parameter ``name`` of ``fn``:
        ``(expr, unit, scope)``; the default when nothing is passed."""
        args = fn.args
        positional = [*args.posonlyargs, *args.args]
        if site.skip_first and positional:
            positional = positional[1:]
        names = [param.arg for param in positional]
        keyword_names = {param.arg for param in [*positional, *args.kwonlyargs]}
        passed = []
        spread = []
        for index, value in enumerate(site.args):
            if isinstance(value, ast.Starred):
                spread.append(value.value)
                continue
            if spread:
                spread.append(value)
                continue
            if index < len(names):
                if names[index] == name:
                    passed.append(value)
            elif args.vararg is not None and args.vararg.arg == name:
                passed.append(value)
        for keyword in site.keywords:
            if keyword.arg is None:
                spread.append(keyword.value)
            elif keyword.arg == name:
                passed.append(keyword.value)
            elif (
                args.kwarg is not None
                and args.kwarg.arg == name
                and keyword.arg not in keyword_names
            ):
                passed.append(keyword.value)
        if passed or spread:
            return [(expr, site.unit, site.scope) for expr in [*passed, *spread]]
        default = _default_of(fn, name)
        info = self.function_info.get(id(fn))
        if default is not None and info is not None:
            return [(default, info[0], info[1])]
        return []

    def call_sites(self, unit, fn):
        cached = self._site_cache.get(id(fn))
        if cached is not None:
            return cached
        if id(fn) in self._sites_active:
            return _Sites(escapes=[_step(unit, fn, "call graph cycle while resolving callers")])
        self._sites_active.add(id(fn))
        try:
            sites = self._call_sites(unit, fn)
        finally:
            self._sites_active.discard(id(fn))
        self._site_cache[id(fn)] = sites
        return sites

    def _call_sites(self, unit, fn):
        sites = _Sites()
        info = self.function_info.get(id(fn))
        owner = None
        definer = None
        if info is not None:
            definer = info[1]
            owner = info[3]
        if isinstance(fn, ast.Lambda):
            parent = unit.parents.get(id(fn))
            if isinstance(parent, ast.Call) and parent.func is fn:
                scope = unit.scope_of(parent)
                sites.resolved.append(_Site(unit, scope, parent, list(parent.args), list(parent.keywords), False, "call"))
                return sites
            keys = self._lambda_names(unit, fn)
            if not keys:
                sites.escapes.append(_step(unit, fn, "a lambda is called through a value whose callers are not visible"))
                return sites
            if definer is not None and definer.kind == "module" and not keys[0].startswith("_") and (unit.path.parent / "__init__.py").is_file() and not unit.is_test:
                sites.escapes.append(_step(unit, fn, f"`{keys[0]}` {PUBLIC_IMPORTERS}"))
            self._collect_sites(unit, fn, owner, keys, sites)
            return sites
        self._decorator_escapes(unit, definer, fn, sites)
        if fn.name.startswith("__") and fn.name.endswith("__") and fn.name != "__init__":
            sites.escapes.append(_step(unit, fn, f"`{fn.name}` is called implicitly by Python"))
        if owner is not None:
            _, external = self.mro(owner)
            if external:
                sites.escapes.append(
                    _step(unit, fn, f"class `{owner.name}` extends `{external[0]}`, which may call `{fn.name}`")
                )
        if self._public_api(unit, fn, owner, definer):
            sites.escapes.append(_step(unit, fn, f"`{fn.name}` {PUBLIC_IMPORTERS}"))
        self._config_entries(unit, fn, owner, definer, sites)
        self._skipped_mentions(fn, sites)
        keys = [fn.name]
        if fn.name == "__init__" and owner is not None:
            keys.append(owner.name)
            for _, sub in self.subclasses(owner):
                keys.append(sub.name)
        self._collect_sites(unit, fn, owner, keys, sites)
        return sites

    def _lambda_names(self, unit, fn):
        """Names a lambda is assigned to (``read = lambda name: ...``)."""
        parent = unit.parents.get(id(fn))
        if isinstance(parent, ast.Assign) and parent.value is fn:
            names = [target.id for target in parent.targets if isinstance(target, ast.Name)]
            if len(names) == len(parent.targets):
                return names
        return []

    def _collect_sites(self, unit, fn, owner, keys, sites):
        definer = None
        info = self.function_info.get(id(fn))
        if info is not None:
            definer = info[1]
        seen_calls = set()
        seen_refs = set()
        index = 0
        while index < len(keys):
            key = keys[index]
            index += 1
            for call_unit, call, scope in self.calls_by_name.get(key, ()):
                if id(call) in seen_calls:
                    continue
                seen_calls.add(id(call))
                self._classify_call(call_unit, scope, call, fn, owner, sites)
            for ref_unit, ref, scope in self.loads_by_name.get(key, ()):
                if id(ref) in seen_refs:
                    continue
                seen_refs.add(id(ref))
                self._classify_ref(ref_unit, scope, ref, fn, owner, sites, keys)
        for call_unit, call, scope in self.dynamic_calls:
            if id(call) in seen_calls:
                continue
            values = self.values(call_unit, scope, call.func)
            if values and self._targets(values, fn, owner):
                seen_calls.add(id(call))
                self._classify_call(call_unit, scope, call, fn, owner, sites)
        for call_unit, call, scope in self.computed_calls:
            if id(call) not in seen_calls and self._computed_call_reaches(call_unit, scope, call, unit, fn, definer):
                sites.escapes.append(
                    _step(call_unit, call, f"`{_describe(call.func)}` picks its target at run time and may call `{_function_label(fn)}`")
                )
        return sites

    def _computed_call_reaches(self, unit, scope, call, fn_unit, fn, definer):
        func = call.func
        if isinstance(func, ast.Call):
            if self.values(unit, scope, func) is not None:
                return False
            pattern = self._name_pattern(unit, func.args[1])
            if pattern is not None and not re.match(f"^{pattern}$", _function_label(fn)):
                return False
            return True
        if isinstance(func, ast.Subscript):
            return unit is fn_unit and definer is not None and definer.kind == "module"
        return True

    def _targets(self, values, fn, owner):
        """The site-building view of ``values`` when one of them calls ``fn``:
        ``(skip_first, prebound_args, prebound_keywords)``, else None."""
        for value in values:
            if value.kind == "fn" and value.node is fn:
                return (value.bound, [], [])
            if value.kind == "partial":
                for target in value.extra[0]:
                    if target.kind == "fn" and target.node is fn:
                        partial_call = value.node
                        return (target.bound, list(partial_call.args[1:]), list(partial_call.keywords))
            if value.kind == "cls" and _function_label(fn) == "__init__" and self.init_of(value.node) is fn:
                return (True, [], [])
        return None

    def _classify_call(self, unit, scope, call, fn, owner, sites):
        values = self.values(unit, scope, call.func)
        if values is None:
            skip = owner is not None and not _is_static(fn) and isinstance(call.func, ast.Attribute)
            sites.possible.append(_Site(unit, scope, call, list(call.args), list(call.keywords), skip, "name"))
            return
        target = self._targets(values, fn, owner)
        if target is None:
            return
        skip, prebound, prebound_keywords = target
        sites.resolved.append(
            _Site(unit, scope, call, [*prebound, *call.args], [*prebound_keywords, *call.keywords], skip, "call")
        )

    def _classify_ref(self, unit, scope, ref, fn, owner, sites, keys):
        parent = unit.parents.get(id(ref))
        values = self.values(unit, scope, ref)
        if values is not None and self._targets(values, fn, owner) is None:
            return
        if values is None and isinstance(ref, ast.Name):
            found = unit.lookup(scope, ref.id)
            if found is not None and all(bind.kind not in {"import", "assign"} for bind in found[1]):
                return
        if unit.is_test:
            return
        if self._harmless_ref(unit, scope, ref, parent):
            return
        if isinstance(parent, ast.Assign) and parent.value is ref:
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    keys.append(target.id)
                elif isinstance(target, ast.Attribute):
                    keys.append(target.attr)
                else:
                    sites.escapes.append(_step(unit, ref, f"`{_function_label(fn)}` is stored in a container; its callers are not visible"))
            return
        bound = owner is not None and not _is_static(fn) and isinstance(ref, ast.Attribute)
        if values is not None:
            bound = self._targets(values, fn, owner)[0]
        if self._task_call(unit, scope, ref, parent, fn, sites):
            return
        if isinstance(parent, ast.Call):
            if self._indirect_call(unit, scope, ref, parent, bound, sites, keys):
                return
            if self._registration(unit, scope, ref, parent, sites):
                return
        if isinstance(parent, ast.keyword):
            call = unit.parents.get(id(parent))
            if isinstance(call, ast.Call):
                if self._indirect_call(unit, scope, ref, call, bound, sites, keys):
                    return
                if self._registration(unit, scope, ref, call, sites):
                    return
        if values is None:
            sites.escapes.append(
                _step(unit, ref, f"`{_describe(ref)}` may be `{_function_label(fn)}` passed as a value; its receiver is not resolved")
            )
            return
        sites.escapes.append(_step(unit, ref, f"`{_function_label(fn)}` is passed as a value; its callers are not visible"))

    def _task_skip(self, fn):
        """Whether ``fn`` is a Celery task, and whether its first parameter is
        the bound task (``bind=True``): None when it is not a task."""
        info = self.function_info.get(id(fn))
        if info is None or info[1] is None:
            return None
        unit = info[0]
        for decorator in getattr(fn, "decorator_list", []) or []:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            values = self.values(unit, info[1], target)
            if not values:
                continue
            if all(
                value.kind in {"ext", "extattr"}
                and value.name.split(".", 1)[0] == "celery"
                and value.name.replace("()", "").rsplit(".", 1)[-1] in {"task", "shared_task"}
                for value in values
            ):
                bound = False
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if keyword.arg == "bind" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            bound = True
                return bound
        return None

    def _task_call(self, unit, scope, ref, parent, fn, sites):
        """``task.delay(...)``, ``task.apply_async(args=..., kwargs=...)`` and
        signatures of a Celery task pass their arguments to the task."""
        if not isinstance(parent, ast.Attribute) or parent.value is not ref or parent.attr not in _TASK_METHODS:
            return False
        call = unit.parents.get(id(parent))
        if not isinstance(call, ast.Call) or call.func is not parent:
            return False
        skip = self._task_skip(fn)
        if skip is None:
            return False
        if parent.attr == "apply_async":
            args, keywords = _packed_arguments(call, "args", "kwargs", 0, 1)
        else:
            args, keywords = list(call.args), list(call.keywords)
        sites.resolved.append(_Site(unit, scope, call, args, keywords, skip, "celery"))
        return True

    def _harmless_ref(self, unit, scope, ref, parent):
        if isinstance(parent, (ast.Compare, ast.UnaryOp)):
            return True
        if isinstance(parent, (ast.If, ast.While, ast.Assert, ast.IfExp)) and parent.test is ref:
            return True
        if isinstance(parent, ast.Attribute) and parent.value is ref and parent.attr in _FUNCTION_METADATA:
            return True
        if isinstance(parent, ast.Delete):
            return True
        if isinstance(parent, ast.Call) and ref in parent.args:
            values = self.values(unit, scope, parent.func)
            if values and all(value.kind == "ext" and value.name in _HARMLESS_CALLS for value in values):
                return True
        return False

    def _indirect_call(self, unit, scope, ref, call, skip, sites, keys):
        values = self.values(unit, scope, call.func)
        if not values:
            return False
        names = {value.name for value in values if value.kind in {"ext", "extattr"}}
        if len(names) != len(values) or len(names) != 1:
            return False
        name = next(iter(names))
        if name == "functools.partial" and call.args and call.args[0] is ref:
            holder = unit.parents.get(id(call))
            if isinstance(holder, ast.Assign) and holder.value is call:
                for target in holder.targets:
                    if isinstance(target, ast.Name):
                        keys.append(target.id)
                    elif isinstance(target, ast.Attribute):
                        keys.append(target.attr)
                return True
            if isinstance(holder, ast.Call) and holder.func is call:
                return True
            return False
        kind = _INDIRECT_CALLERS.get(name)
        receiver = name.rsplit(".", 1)[0].replace("()", "")
        method = name.rsplit(".", 1)[-1]
        if receiver in _RQ_QUEUES and method in _RQ_METHODS:
            return self._enqueue(unit, scope, ref, call, method, skip, sites)
        if kind is None and method == "submit" and receiver in _EXECUTOR_TYPES and call.args and call.args[0] is ref:
            sites.resolved.append(_Site(unit, scope, call, list(call.args[1:]), list(call.keywords), skip, "submit"))
            return True
        if kind is None and method == "run_in_executor" and len(call.args) >= 2 and call.args[1] is ref:
            sites.resolved.append(_Site(unit, scope, call, list(call.args[2:]), [], skip, "run_in_executor"))
            return True
        if kind == "first" and call.args and call.args[0] is ref:
            sites.resolved.append(_Site(unit, scope, call, list(call.args[1:]), list(call.keywords), skip, "to_thread"))
            return True
        if kind in {"target", "function"}:
            supplied = None
            for keyword in call.keywords:
                if keyword.arg == kind and keyword.value is ref:
                    supplied = keyword
            if supplied is None:
                return False
            args = []
            keywords = []
            for keyword in call.keywords:
                if keyword.arg == "args":
                    if isinstance(keyword.value, (ast.Tuple, ast.List)):
                        args.extend(keyword.value.elts)
                    else:
                        args.append(ast.Starred(value=keyword.value, ctx=ast.Load()))
                elif keyword.arg == "kwargs":
                    if isinstance(keyword.value, ast.Dict) and all(key is not None for key in keyword.value.keys):
                        for key, value in zip(keyword.value.keys, keyword.value.values):
                            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                keywords.append(ast.keyword(arg=key.value, value=value))
                            else:
                                keywords.append(ast.keyword(arg=None, value=value))
                    else:
                        keywords.append(ast.keyword(arg=None, value=keyword.value))
            sites.resolved.append(_Site(unit, scope, call, args, keywords, skip, "thread"))
            return True
        return False

    def _enqueue(self, unit, scope, ref, call, method, skip, sites):
        """``queue.enqueue(fn, *args, **kwargs)`` runs ``fn`` with those
        arguments in a worker; RQ's own options are not passed to it."""
        position = _RQ_METHODS[method]
        if position is None:
            supplied = any(keyword.arg == "func" and keyword.value is ref for keyword in call.keywords)
            if not supplied and not (call.args and call.args[0] is ref):
                return False
            args, keywords = _packed_arguments(call, "args", "kwargs", 1, 2)
        else:
            if len(call.args) <= position or call.args[position] is not ref:
                return False
            args = list(call.args[position + 1:])
            keywords = [keyword for keyword in call.keywords if keyword.arg not in _RQ_OPTIONS]
        sites.resolved.append(_Site(unit, scope, call, args, keywords, skip, "rq"))
        return True

    def _registration(self, unit, scope, ref, call, sites):
        values = self.values(unit, scope, call.func)
        if not values:
            return False
        for value in values:
            if value.kind not in {"ext", "extattr", "extinst"}:
                return False
            name = re.sub(r"\(\)", "", value.name)
            if name in _DEPENDENCY_MARKERS and _first_argument(call, "dependency") is ref:
                consumer = self._dependency_consumer(unit, call)
                if consumer is None:
                    return False
                sites.entries.append((UNTRUSTED, _step(unit, call, f"FastAPI dependency of {consumer}; FastAPI fills its parameters from the request")))
                return True
            for table, kind in ((_ROUTE_REGISTRATIONS, "web route"), (_TOOL_REGISTRATIONS, "MCP tool"), (_STREAM_REGISTRATIONS, "network stream handler")):
                spec = table.get(name)
                if spec is None:
                    continue
                keyword, position = spec
                passed = None
                if len(call.args) > position:
                    passed = call.args[position]
                for item in call.keywords:
                    if item.arg == keyword:
                        passed = item.value
                if passed is ref:
                    sites.entries.append((UNTRUSTED, _step(unit, call, f"registered as a {kind} by `{name}`")))
                    return True
        return False

    def _dependency_consumer(self, unit, marker):
        """The FastAPI route (or dependency of one) whose signature or route
        decorator holds the ``Depends(...)`` marker, described; None when the
        marker is not used by a resolved FastAPI route."""
        child = marker
        for node in unit.ancestors(marker):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child in node.body:
                    return None
                if child in node.decorator_list:
                    if self._fastapi_route(unit, node):
                        return f"route `{node.name}`"
                    return None
                if self._fastapi_route(unit, node):
                    return f"route `{node.name}`"
                for kind, step in self.call_sites(unit, node).entries:
                    if kind == UNTRUSTED and "FastAPI dependency" in step:
                        return f"dependency `{node.name}`"
                return None
            if isinstance(node, ast.Call):
                values = self.values(unit, unit.scope_of(node), node.func)
                if values and all(
                    value.kind in {"ext", "extattr"}
                    and (value.name in _FASTAPI_APPS or value.name.replace("()", "").rsplit(".", 1)[0] in _FASTAPI_APPS)
                    for value in values
                ):
                    return f"`{_describe(node)}`"
            child = node
        return None

    def _fastapi_route(self, unit, fn):
        info = self.function_info.get(id(fn))
        if info is None or info[1] is None:
            return False
        for decorator in fn.decorator_list:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            if not isinstance(target, ast.Attribute) or target.attr not in _FASTAPI_ROUTE_METHODS:
                continue
            values = self.values(unit, info[1], target.value)
            if values and all(value.kind == "extinst" and value.name in _FASTAPI_APPS for value in values):
                return True
        return False

    def django_view(self, cls_node):
        """A Django or DRF class-based view that a URL pattern or router
        registers: ``path(..., View.as_view())``, ``router.register(..., ViewSet)``."""
        cached = self._django_views.get(id(cls_node))
        if cached is not None:
            return cached
        self._django_views[id(cls_node)] = ""
        result = ""
        _, external = self.mro(cls_node)
        if any(name.startswith(_DJANGO_VIEW_BASES) for name in external):
            result = self._django_registration(cls_node)
        self._django_views[id(cls_node)] = result
        return result

    def _registers_class(self, unit, scope, expr, cls_node):
        values = self.values(unit, scope, expr)
        if not values:
            return False
        for value in values:
            if value.kind == "cls":
                order, _ = self.mro(value.node)
                if any(cls is cls_node for _, cls in order):
                    return True
        return False

    def _django_registration(self, cls_node):
        for unit, call, scope in self.calls_by_name.get("as_view", ()):
            if not isinstance(call.func, ast.Attribute):
                continue
            if not self._registers_class(unit, scope, call.func.value, cls_node):
                continue
            for holder in list(unit.ancestors(call))[:4]:
                if not isinstance(holder, ast.Call):
                    continue
                values = self.values(unit, unit.scope_of(holder), holder.func)
                if values and all(value.kind == "ext" and value.name in _DJANGO_URL_FUNCTIONS for value in values):
                    return _step(unit, holder, f"`{cls_node.name}.as_view()` is a URL pattern")
        for unit, call, scope in self.calls_by_name.get("register", ()):
            if len(call.args) < 2:
                continue
            values = self.values(unit, scope, call.func)
            if not values or not all(value.kind == "extattr" and value.name.startswith("rest_framework.routers.") for value in values):
                continue
            if self._registers_class(unit, scope, call.args[1], cls_node):
                return _step(unit, call, f"`{cls_node.name}` is registered with a DRF router")
        return ""

    def framework_context(self, unit):
        """The module imports a web framework, so a parameter named
        ``request`` follows that framework's convention."""
        cached = self._framework_units.get(id(unit))
        if cached is None:
            cached = False
            for node in ast.walk(unit.tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    names = [node.module]
                if any(name.split(".", 1)[0] in _WEB_FRAMEWORKS for name in names):
                    cached = True
                    break
            self._framework_units[id(unit)] = cached
        return cached

    def _decorator_escapes(self, unit, definer, fn, sites):
        for decorator in getattr(fn, "decorator_list", []) or []:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            values = None
            if definer is not None:
                values = self.values(unit, definer, target)
            if values and all(value.kind == "ext" and value.name in _TRANSPARENT_DECORATORS for value in values):
                continue
            sites.escapes.append(
                _step(unit, decorator, f"decorated with `{_describe(target)}`; the wrapper's callers are not visible")
            )

    def _public_api(self, unit, fn, owner, definer):
        if unit.is_test or definer is None:
            return False
        if definer.kind not in {"module", "class"}:
            return False
        if definer.kind == "class" and (definer.parent is None or definer.parent.kind != "module"):
            return False
        names = [fn.name]
        if owner is not None:
            names.append(owner.name)
        if any(name.startswith("_") and not (name.startswith("__") and name.endswith("__")) for name in names):
            return False
        return (unit.path.parent / "__init__.py").is_file()

    def _skipped_mentions(self, fn, sites):
        """A file that was not indexed and names the function may call it:
        a size or depth limit keeps the finding (incomplete), a file that does
        not parse leaves it unknown."""
        name = getattr(fn, "name", None)
        if not name or not self.skipped:
            return
        pattern = re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")
        for rel, text, kind, why in self.skipped:
            if not pattern.search(text):
                continue
            step = f"{rel}:0 names `{name}` but {why}, so its calls were not followed"
            if kind == INCOMPLETE:
                sites.entries.append((INCOMPLETE, step))
            else:
                sites.escapes.append(step)

    def _config_line_index(self):
        if self._config_index is None:
            self._config_index = {}
            for position, (_, _, line) in enumerate(self.config_lines):
                for token in set(re.findall(r"[A-Za-z_]\w*", line)):
                    self._config_index.setdefault(token, []).append(position)
        return self._config_index

    def _config_entries(self, unit, fn, owner, definer, sites):
        if definer is None or definer.kind != "module" or not self.config_lines:
            return
        positions = self._config_line_index().get(fn.name)
        if not positions:
            return
        names = set(unit.module_names)
        names.add(unit.path.stem)
        alternatives = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        pattern = re.compile(rf"(?<![\w.-])(?:{alternatives})[:.]{re.escape(fn.name)}(?![\w-])")
        for position in positions:
            rel, number, line = self.config_lines[position]
            if not pattern.search(line):
                continue
            if _SERVER_WORDS.search(line):
                sites.entries.append(
                    (UNTRUSTED, f"{rel}:{number} deployment file names `{fn.name}` as a server or handler entry point")
                )
            else:
                sites.escapes.append(f"{rel}:{number} a config file names `{fn.name}`; its caller is not visible")

    def launches_with_untrusted_arguments(self):
        """A process launch in the project whose arguments carry untrusted
        input: then CLI arguments are not proven to come from the operator."""
        if self._launch is not None:
            return self._launch
        self._launch = ""
        tracer = _Tracer(self, TRAVERSAL_RULE)
        tracer.filename_proofs = False
        for unit in self.units:
            if unit.is_test:
                continue
            for call, scope in unit.calls:
                values = self.values(unit, scope, call.func)
                if not values or not any(value.kind == "ext" and value.name in _PROCESS_LAUNCHES for value in values):
                    continue
                for argument in [*call.args, *[keyword.value for keyword in call.keywords]]:
                    tracer.work = 0
                    facts = tracer.trace(unit, scope, argument)
                    if facts.chains[UNTRUSTED]:
                        self._launch = _step(unit, call, "a process launch passes untrusted arguments")
                        return self._launch
        return self._launch

    def constant_table(self, unit, scope, expr):
        """``expr`` names a module-level literal table of constants that
        nothing in the project can change."""
        if isinstance(expr, ast.Subscript):
            return self.constant_table(unit, scope, expr.value)
        if not isinstance(expr, ast.Name):
            return False
        found = unit.lookup(scope, expr.id)
        if found is None:
            return False
        owner, binds = found
        if owner.kind != "module":
            return False
        if len(binds) == 1 and binds[0].kind == "import":
            module, member, level = binds[0].value
            if member is None:
                return False
            targets = self.find_module(unit, module, level)
            if len(targets) != 1:
                return False
            target = targets[0]
            return self.constant_table(target, target.module, ast.Name(id=member, ctx=ast.Load()))
        if len(binds) != 1 or binds[0].kind != "assign" or binds[0].scope is not owner:
            return False
        key = (id(unit), expr.id)
        if key not in self._constant_tables:
            self._constant_tables[key] = _constant_literal(binds[0].value) and not self._global_changed(unit, expr.id)
        return self._constant_tables[key]

    def _global_changed(self, unit, name):
        """Code may change the module value ``name`` of ``unit``: a write
        through it, an alias, an argument other than a read-only builtin, a
        method other than a read, or a namespace rewrite."""
        dynamic, rebound = unit.rebinding()
        if dynamic or name in rebound or unit.star_import:
            return True
        for ref_unit, ref, scope in self.loads_by_name.get(name, ()):
            if not self._refers_to_global(ref_unit, scope, ref, unit, name):
                continue
            parent = ref_unit.parents.get(id(ref))
            if isinstance(parent, ast.Subscript) and parent.value is ref:
                if not isinstance(parent.ctx, ast.Load):
                    return True
                holder = ref_unit.parents.get(id(parent))
                if isinstance(holder, ast.Attribute) and holder.value is parent:
                    method_call = ref_unit.parents.get(id(holder))
                    if isinstance(method_call, ast.Call) and method_call.func is holder and holder.attr not in _READ_ONLY_METHODS:
                        return True
                continue
            if isinstance(parent, ast.Attribute) and parent.value is ref:
                if not isinstance(parent.ctx, ast.Load):
                    return True
                if parent.attr not in _READ_ONLY_METHODS:
                    return True
                continue
            if isinstance(parent, ast.Call) and ref in parent.args:
                values = self.values(ref_unit, scope, parent.func)
                if values and all(value.kind == "ext" and value.name in _READ_ONLY_FUNCTIONS for value in values):
                    continue
                return True
            if isinstance(parent, (ast.Compare, ast.For, ast.comprehension, ast.JoinedStr, ast.FormattedValue)):
                continue
            if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.keyword, ast.Return, ast.Tuple, ast.List, ast.Dict, ast.Starred, ast.Yield)):
                return True
        for store_unit, target, _, _, scope in self.attr_stores.get(name, ()):
            values = self.values(store_unit, scope, target.value)
            if values is None or any(value.kind == "mod" and value.unit is unit for value in values):
                return True
        return False

    def _refers_to_global(self, ref_unit, scope, ref, unit, name):
        key = (id(ref), id(unit), name)
        cached = self._global_refs.get(key)
        if cached is None:
            cached = self._refers_to_global_uncached(ref_unit, scope, ref, unit, name)
            self._global_refs[key] = cached
        return cached

    def _refers_to_global_uncached(self, ref_unit, scope, ref, unit, name):
        if isinstance(ref, ast.Name):
            found = ref_unit.lookup(scope, name)
            if found is None:
                return False
            owner, binds = found
            if ref_unit is unit and owner is unit.module:
                return True
            for bind in binds:
                if bind.kind == "import":
                    module, member, level = bind.value
                    if member == name and unit in self.find_module(ref_unit, module, level):
                        return True
            return False
        if isinstance(ref, ast.Attribute):
            values = self.values(ref_unit, scope, ref.value)
            if values is None:
                return True
            return any(value.kind == "mod" and value.unit is unit for value in values)
        return False

    def parameter_entry(self, unit, fn, param):
        """What a framework or test runner passes as ``param``: a
        ``(kind, step)`` pair, or None when the function's callers decide."""
        name = param.arg
        label = _function_label(fn)
        if unit.is_test and (label.startswith("test") or _is_fixture(fn)):
            return SAFE, _step(unit, fn, f"test value `{name}` of `{label}`")
        decorator = entrypoint_decorator(fn, self.import_map(unit))
        if decorator:
            last = decorator.rsplit(".", 1)[-1]
            if last in _TOOL_DECORATORS:
                return UNTRUSTED, _step(unit, fn, f"MCP/agent tool argument `{name}` of `{label}` (@{decorator})")
            if last in _CLI_DECORATORS and self._cli_decorator(unit, fn, decorator):
                return OPERATOR, _step(unit, fn, f"CLI parameter `{name}` of `{label}` (@{decorator})")
            return UNTRUSTED, _step(unit, fn, f"route parameter `{name}` of `{label}` (@{decorator})")
        annotation = getattr(param, "annotation", None)
        if annotation is not None:
            for node in ast.walk(annotation):
                annotated = None
                if isinstance(node, ast.Name):
                    annotated = node.id
                elif isinstance(node, ast.Attribute):
                    annotated = node.attr
                if annotated in REQUEST_ANNOTATIONS and self.framework_context(unit):
                    return UNTRUSTED, _step(unit, fn, f"request object `{name}` of `{label}`")
        if name in REQUEST_NAMES and self.framework_context(unit):
            return UNTRUSTED, _step(unit, fn, f"request data `{name}` of `{label}` (web framework module)")
        if name in REQUEST_NAMES and _reads_request_attributes(fn, name):
            return UNTRUSTED, _step(unit, fn, f"request data `{name}` of `{label}` (reads HTTP request fields)")
        info = self.function_info.get(id(fn))
        owner = None
        if info is not None:
            owner = info[3]
        if owner is not None and label in _TORNADO_VERBS and self._class_extends(owner, _TORNADO_HANDLER_BASES):
            return UNTRUSTED, _step(unit, fn, f"URL argument `{name}` of request handler `{owner.name}.{label}`")
        if owner is not None and label in _DJANGO_VIEW_METHODS:
            registration = self.django_view(owner)
            if registration:
                return UNTRUSTED, f"{registration}; `{name}` of `{owner.name}.{label}` comes from the URL or request"
        if unit.is_test and (label.startswith("test") or _is_fixture(fn)):
            return SAFE, _step(unit, fn, f"test value `{name}` of `{label}`")
        return None

    def _cli_decorator(self, unit, fn, decorator):
        """A ``@<group>.command`` decorator is a command line when the group
        resolves to Click/Typer, or the same function also carries Click or
        Typer parameter decorators (``@click.option``) a chat bot would not."""
        root = decorator.split(".", 1)[0]
        if root in {"click", "typer"}:
            return True
        info = self.function_info.get(id(fn))
        if info is None:
            return False
        if self._command_group(unit, info[1], ast.Name(id=root, ctx=ast.Load()), 0):
            return True
        for other in fn.decorator_list:
            target = other
            if isinstance(other, ast.Call):
                target = other.func
            if not isinstance(target, ast.Attribute) or target.attr not in {"option", "argument", "Option", "Argument"}:
                continue
            values = self.values(unit, info[1], target)
            if values and all(
                value.kind == "ext" and value.name in {"click.option", "click.argument", "typer.Option", "typer.Argument"}
                for value in values
            ):
                return True
        return False

    def _command_group(self, unit, scope, expr, depth):
        """``expr`` is a Click or Typer command group: a ``click``/``typer``
        object, or a project function decorated as a group of one."""
        if depth > 6:
            return False
        values = self.values(unit, scope, expr)
        if not values:
            return False
        for value in values:
            if value.kind in {"ext", "extinst", "extattr"}:
                if value.name.split(".", 1)[0] not in {"click", "typer"}:
                    return False
                continue
            if value.kind != "fn" or isinstance(value.node, ast.Lambda):
                return False
            info = self.function_info.get(id(value.node))
            if info is None or info[1] is None:
                return False
            if not self._decorated_as_command(value.unit, info[1], value.node, depth):
                return False
        return True

    def _decorated_as_command(self, unit, scope, fn, depth):
        for decorator in fn.decorator_list:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            if isinstance(target, ast.Attribute) and target.attr in _CLI_DECORATORS:
                if self._command_group(unit, scope, target.value, depth + 1):
                    return True
            values = self.values(unit, scope, target)
            if values and all(
                value.kind in {"ext", "extattr"} and value.name.split(".", 1)[0] in {"click", "typer"}
                for value in values
            ):
                return True
        return False

    def _class_extends(self, cls_node, bases):
        _, external = self.mro(cls_node)
        return any(name in bases for name in external)


def _first_argument(call, keyword):
    if call.args:
        return call.args[0]
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _packed_arguments(call, args_name, kwargs_name, args_position, kwargs_position):
    """Arguments a call packs for a later call: ``args=(...)``,
    ``kwargs={...}`` keywords or positions; spread when not literal."""
    packed_args = None
    packed_kwargs = None
    if len(call.args) > args_position:
        packed_args = call.args[args_position]
    if len(call.args) > kwargs_position:
        packed_kwargs = call.args[kwargs_position]
    for keyword in call.keywords:
        if keyword.arg == args_name:
            packed_args = keyword.value
        elif keyword.arg == kwargs_name:
            packed_kwargs = keyword.value
    args = []
    keywords = []
    if isinstance(packed_args, (ast.Tuple, ast.List)):
        args.extend(packed_args.elts)
    elif packed_args is not None:
        args.append(ast.Starred(value=packed_args, ctx=ast.Load()))
    if isinstance(packed_kwargs, ast.Dict) and all(key is not None for key in packed_kwargs.keys):
        for key, value in zip(packed_kwargs.keys, packed_kwargs.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keywords.append(ast.keyword(arg=key.value, value=value))
            else:
                keywords.append(ast.keyword(arg=None, value=value))
    elif packed_kwargs is not None:
        keywords.append(ast.keyword(arg=None, value=packed_kwargs))
    return args, keywords


def _computed_call(call):
    """A call whose target is picked at run time by name: ``getattr`` with a
    computed name, a namespace lookup, or ``exec``/``eval`` of computed code."""
    func = call.func
    if (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
    ):
        name = func.args[1]
        return not (isinstance(name, ast.Constant) and isinstance(name.value, str))
    if isinstance(func, ast.Subscript):
        base = func.value
        return (
            isinstance(base, ast.Call)
            and isinstance(base.func, ast.Name)
            and base.func.id in {"globals", "locals", "vars"}
        )
    if isinstance(func, ast.Name) and func.id in {"exec", "eval"} and call.args:
        return not isinstance(call.args[0], ast.Constant)
    return False


def _default_of(fn, name):
    args = fn.args
    positional = [*args.posonlyargs, *args.args]
    defaults = list(args.defaults)
    offset = len(positional) - len(defaults)
    for index, param in enumerate(positional):
        if param.arg == name and index >= offset:
            return defaults[index - offset]
    for param, default in zip(args.kwonlyargs, args.kw_defaults):
        if param.arg == name:
            return default
    return None


def _same_facts(left, right):
    return all(
        set(left.chains[kind]) == set(right.chains[kind]) for kind in _Facts.KINDS
    )


def _env_lookup(env, key):
    while env is not None:
        fn_id, site, parent = env
        if fn_id == key:
            return site, parent
        env = parent
    return None


def _env_key(env):
    ids = []
    while env is not None:
        site = env[1]
        call = 0
        if site is not None:
            call = id(site.call)
        ids.append((env[0], call))
        env = env[2]
    return tuple(ids)


class _Tracer:
    """Where the value of a path expression can come from, as located steps."""

    def __init__(self, project, rule):
        self.project = project
        self.rule = rule
        self.work = 0
        self.depth_of = {}
        self.lows = []
        self.cut_targets = set()
        self.provisional = {}
        self.pending = []
        self.fresh = {}
        self.epoch = 0
        self.dirty = False
        self.active_params = []
        self.param_memo = {}
        self.attr_memo = {}
        self.global_memo = {}
        self.local_memo = {}
        self.limited = 0
        self.trace_memo = {}
        self.summary_memo = {}
        self.string_constructor_memo = {}
        self.string_runtime_stable = None
        self.filename_proofs = rule == TRAVERSAL_RULE
        self.filename_runtime_stable = {}
        self.unit_runtime_stable = {}
        self.plain_model_memo = {}

    def _limit(self, unit, node, text):
        self.limited += 1
        return _Facts.leaf(INCOMPLETE, _step(unit, node, text))

    def trace(self, unit, scope, expr, env=None):
        if expr is None:
            return _Facts()
        self.work += 1
        if self.work > _MAX_WORK:
            return self._limit(unit, expr, "analysis budget reached")
        key = ("expr", id(expr), id(scope), _env_key(env))
        return self._memoized(self.trace_memo, key, lambda: self._trace_guarded(unit, scope, expr, env))

    def _trace_guarded(self, unit, scope, expr, env):
        try:
            return self._trace(unit, scope, expr, env)
        except RecursionError:
            return self._limit(unit, expr, "expression too deep to follow")

    def _memoized(self, memo, key, compute):
        """``compute()`` once per key, also inside cycles. A key already being
        computed is a cycle: it reads the latest provisional value of that key.
        The cycle's head recomputes the cycle until no provisional value grows
        (a least fixpoint), then stores every member's value. Nothing is stored
        when an analysis limit was hit."""
        cached = memo.get(key)
        if cached is not None:
            return cached
        depth = self.depth_of.get(key)
        if depth is not None:
            if self.lows:
                self.lows[-1] = min(self.lows[-1], depth)
            self.cut_targets.add(depth)
            return self.provisional.get(key) or _Facts()
        if self.fresh.get(key) == self.epoch and key in self.provisional:
            return self.provisional[key]
        own = len(self.lows)
        limited = self.limited
        outer_dirty = self.dirty
        rounds = 0
        seen = []
        while True:
            mark = len(self.pending)
            if own == 0 or rounds:
                self.epoch += 1
            self.dirty = False
            self.depth_of[key] = own
            self.lows.append(own)
            self.cut_targets.discard(own)
            try:
                result = compute()
            finally:
                low = self.lows.pop()
                del self.depth_of[key]
                if self.lows:
                    self.lows[-1] = min(self.lows[-1], low)
            previous = self.provisional.get(key)
            merged = _Facts()
            if previous is not None:
                merged.add(previous)
            merged.add(result)
            if previous is None or not _same_facts(previous, merged):
                self.dirty = True
            self.provisional[key] = merged
            self.fresh[key] = self.epoch
            if low < own:
                self.pending.append((memo, key))
                self.dirty = self.dirty or outer_dirty
                return merged
            cycle = own in self.cut_targets
            self.cut_targets.discard(own)
            if cycle and self.dirty and rounds < _MAX_FIXPOINT_ROUNDS:
                seen.extend(self.pending[mark:])
                del self.pending[mark:]
                rounds += 1
                continue
            if cycle and self.dirty:
                merged.add(self._limit_text("a cyclic data dependency did not settle"))
            members = self.pending[mark:]
            del self.pending[mark:]
            for member_memo, member_key in members:
                value = self.provisional.get(member_key)
                if value is not None and self.limited == limited:
                    member_memo[member_key] = value
            for _, member_key in [*seen, *members]:
                self.provisional.pop(member_key, None)
                self.fresh.pop(member_key, None)
            self.provisional.pop(key, None)
            self.fresh.pop(key, None)
            if self.limited == limited:
                memo[key] = merged
            self.dirty = outer_dirty
            return merged

    def _limit_text(self, text):
        self.limited += 1
        return _Facts.leaf(INCOMPLETE, text)

    def _union(self, unit, scope, nodes, env):
        facts = _Facts()
        for node in nodes:
            facts.add(self.trace(unit, scope, node, env))
        return facts

    def _trace(self, unit, scope, expr, env):
        if isinstance(expr, ast.Constant):
            return _Facts.leaf(SAFE, _step(unit, expr, "literal"))
        if isinstance(expr, ast.JoinedStr):
            parts = [value.value for value in expr.values if isinstance(value, ast.FormattedValue)]
            if not parts:
                return _Facts.leaf(SAFE, _step(unit, expr, "literal"))
            return self._union(unit, scope, parts, env)
        if isinstance(expr, ast.FormattedValue):
            return self.trace(unit, scope, expr.value, env)
        if isinstance(expr, ast.BinOp):
            return self._union(unit, scope, [expr.left, expr.right], env)
        if isinstance(expr, ast.BoolOp):
            return self._union(unit, scope, expr.values, env)
        if isinstance(expr, ast.IfExp):
            return self._union(unit, scope, [expr.body, expr.orelse], env)
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            if not expr.elts:
                return _Facts.leaf(SAFE, _step(unit, expr, "empty literal"))
            return self._union(unit, scope, expr.elts, env)
        if isinstance(expr, ast.Dict):
            if not expr.values:
                return _Facts.leaf(SAFE, _step(unit, expr, "empty literal"))
            return self._union(unit, scope, expr.values, env)
        if isinstance(expr, (ast.Starred, ast.Await, ast.NamedExpr)):
            return self.trace(unit, scope, expr.value, env)
        if isinstance(expr, ast.Compare):
            return _Facts.leaf(SAFE, _step(unit, expr, "comparison result"))
        if isinstance(expr, ast.UnaryOp):
            if isinstance(expr.op, ast.Not):
                return _Facts.leaf(SAFE, _step(unit, expr, "boolean"))
            return self.trace(unit, scope, expr.operand, env)
        if isinstance(expr, ast.Name):
            return self._name(unit, scope, expr, env)
        if isinstance(expr, ast.Attribute):
            return self._attribute(unit, scope, expr, env)
        if isinstance(expr, ast.Subscript):
            return self._subscript(unit, scope, expr, env)
        if isinstance(expr, ast.Call):
            return self._call(unit, scope, expr, env)
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.trace(unit, unit.scope_of(expr.elt), expr.elt, env)
        if isinstance(expr, ast.DictComp):
            return self.trace(unit, unit.scope_of(expr.value), expr.value, env)
        return _Facts.leaf(UNKNOWN, _step(unit, expr, f"{type(expr).__name__} expression is not followed"))

    def _visible_binds(self, unit, owner, binds, use):
        """Bindings that can reach ``use``: those before it (any, inside a
        loop), and none earlier than the last unconditional one."""
        if owner.kind not in {"function", "lambda"}:
            return binds
        line = getattr(use, "lineno", 0)
        ancestors = set(id(node) for node in unit.ancestors(use))
        in_loop = False
        for node in unit.ancestors(use):
            if node is owner.node:
                break
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.comprehension)):
                in_loop = True
        kept = []
        for bind in binds:
            if bind.kind == "param":
                kept.append(bind)
                continue
            if id(bind.node) in ancestors and not isinstance(bind.node, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)):
                if not in_loop:
                    continue
            if in_loop or getattr(bind.node, "lineno", 0) <= line:
                kept.append(bind)
        if in_loop:
            return kept
        dominating = [
            bind
            for bind in kept
            if bind.kind in {"assign", "unpack", "with"}
            and bind.top_level
            and bind.scope is owner
            and getattr(bind.node, "end_lineno", 0) < line
        ]
        if not dominating:
            return kept
        last = max(dominating, key=lambda bind: bind.node.lineno)
        return [bind for bind in kept if bind.kind != "param" and bind.node.lineno >= last.node.lineno]

    def _name(self, unit, scope, node, env):
        found = unit.lookup(scope, node.id)
        if found is None:
            if node.id == "__file__":
                return _Facts.leaf(SAFE, _step(unit, node, "module location `__file__`"))
            if node.id in _MODULE_DUNDERS:
                return _Facts.leaf(SAFE, _step(unit, node, f"module name `{node.id}`"))
            return _Facts.leaf(UNKNOWN, _step(unit, node, f"`{node.id}` is not bound in the project"))
        owner, binds = found
        if self.filename_proofs:
            guard = self._guard_statement(unit, scope, node, node.id)
            if guard is not None and guard[1][0] == "passes a body-proven filename check":
                if not any(
                    bind.kind != "param"
                    and guard[0].lineno <= getattr(bind.node, "lineno", 0) <= node.lineno
                    for bind in binds
                ):
                    step = _step(
                        unit, node, f"`{node.id}` passes a body-proven filename check"
                    )
                    hidden = (
                        self._filename_equality_guard(unit, scope, guard[0], node.id)
                        or ()
                    )
                    return _with_hidden_callers(_Facts.leaf(SAFE, step), hidden, step)
        binds = self._visible_binds(unit, owner, binds, node)
        facts = _Facts()
        for bind in binds:
            facts.add(self._bind_facts(unit, owner, bind, node.id, env))
        if owner.kind == "module":
            facts.add(self._global_writes(unit, node.id, binds))
        elif owner.kind in {"function", "lambda"}:
            facts.add(self._local_writes(unit, owner, node.id, binds))
        if facts.empty():
            return _Facts.leaf(UNKNOWN, _step(unit, node, f"no binding of `{node.id}` reaches here"))
        return facts

    def _bind_facts(self, unit, owner, bind, name, env):
        kind = bind.kind
        if kind == "param":
            return self._param(unit, owner, bind.node, env)
        if kind in {"assign", "unpack", "augassign"}:
            return self.trace(unit, bind.scope, bind.value, env).then(
                _step(unit, bind.node, f"`{name}` = {_describe(bind.value)}")
            )
        if kind in {"iter", "comp"}:
            return self._iteration(unit, bind.scope, bind.value, env).then(
                _step(unit, bind.node, f"`{name}` iterates {_describe(bind.value)}")
            )
        if kind == "with":
            return self.trace(unit, bind.scope, bind.value, env).then(
                _step(unit, bind.node, f"`{name}` is the context of {_describe(bind.value)}")
            )
        if kind == "import":
            return self._imported(unit, bind, name)
        if kind in {"def", "class"}:
            return _Facts.leaf(UNKNOWN, _step(unit, bind.node, f"`{name}` is a function or class object"))
        return _Facts.leaf(UNKNOWN, _step(unit, bind.node, f"`{name}` is bound in a way that is not followed"))

    def _iteration(self, unit, scope, iterable, env):
        values = self.project.values(unit, scope, iterable)
        if values and all(value.kind == "extinst" and value.name in _ARCHIVE_TYPES for value in values):
            return _Facts.leaf(UNTRUSTED, _step(unit, iterable, f"archive member of `{next(iter(values)).name}`"))
        return self.trace(unit, scope, iterable, env)

    def _imported(self, unit, bind, name):
        module, member, level = bind.value
        if member is None:
            return _Facts.leaf(UNKNOWN, _step(unit, bind.node, f"module object `{name}`"))
        targets = self.project.find_module(unit, module, level)
        if not targets:
            return _Facts.leaf(UNKNOWN, _step(unit, bind.node, f"`{name}` is imported from outside the project"))
        facts = _Facts()
        for target in targets:
            binds = target.module.binds.get(member)
            if not binds:
                facts.add(_Facts.leaf(UNKNOWN, _step(unit, bind.node, f"`{name}` is not a module value of `{target.rel}`")))
                continue
            step = _step(unit, bind.node, f"imports `{member}` from `{target.rel}`")
            for target_bind in binds:
                facts.add(self._bind_facts(target, target.module, target_bind, member, None).then(step))
            facts.add(self._global_writes(target, member, binds).then(step))
        return facts

    def _local_writes(self, unit, owner, name, binds):
        """Values stored into the local container ``name`` of one function,
        directly or through a local alias (``alias = name``): ``x[k] = v``,
        ``x.append(v)``, a socket ``recv_into(x)``. Unknown when a mutable
        literal is handed to other code that may change it."""
        key = (id(owner.node), name)
        if key in self.local_memo:
            return self.local_memo[key]
        facts = _Facts()
        self.local_memo[key] = facts
        names = self._local_aliases(owner, name)
        for target, value, statement, scope in unit.subscript_stores:
            base = target.value
            if not isinstance(base, ast.Name) or base.id not in names:
                continue
            found = unit.lookup(scope, base.id)
            if found is None or found[0] is not owner:
                continue
            facts.add(self.trace(unit, scope, value).then(_step(unit, statement, f"stores into `{base.id}`")))
        for alias in names:
            for call, scope in unit.name_mutations.get(alias, ()):
                found = unit.lookup(scope, alias)
                if found is None or found[0] is not owner:
                    continue
                arguments = [*call.args, *[keyword.value for keyword in call.keywords]]
                facts.add(self._union(unit, scope, arguments, None).then(
                    _step(unit, call, f"`{alias}.{call.func.attr}(...)` adds to it")
                ))
        mutable = any(bind.kind == "assign" and _mutable_literal(bind.value) for bind in binds)
        for alias in names:
            for call, scope in unit.name_escapes.get(alias, ()):
                found = unit.lookup(scope, alias)
                if found is None or found[0] is not owner:
                    continue
                filled = self._filled_from_network(unit, scope, call)
                if filled:
                    facts.add(_Facts.leaf(UNTRUSTED, _step(unit, call, f"network payload written into `{alias}` by `.{filled}()`")))
                    continue
                if not mutable:
                    continue
                values = self.project.values(unit, scope, call.func)
                if values and all(item.kind == "ext" and item.name in _READ_ONLY_FUNCTIONS for item in values):
                    continue
                facts.add(_Facts.leaf(UNKNOWN, _step(unit, call, f"container `{alias}` is passed to `{_describe(call)}`, which may change it")))
        return facts

    def _local_aliases(self, owner, name):
        """``name`` and the local names bound to it (``alias = name``) or that
        it is bound to, transitively."""
        names = {name}
        changed = True
        while changed:
            changed = False
            for other, binds in owner.binds.items():
                for bind in binds:
                    if bind.kind != "assign" or not isinstance(bind.value, ast.Name):
                        continue
                    if bind.value.id in names and other not in names:
                        names.add(other)
                        changed = True
                    elif other in names and bind.value.id not in names and bind.value.id in owner.binds:
                        names.add(bind.value.id)
                        changed = True
        return names

    def _filled_from_network(self, unit, scope, call):
        """``sock.recv_into(buffer)`` fills ``buffer`` with network data."""
        if not isinstance(call.func, ast.Attribute):
            return ""
        method = call.func.attr
        if method not in _SOCKET_INTO and method != "readinto":
            return ""
        values = self.project.values(unit, scope, call.func)
        if values and all(
            value.kind == "extattr" and value.name.replace("()", "").split(".", 1)[0] == "socket"
            for value in values
        ) and method in _SOCKET_INTO:
            return method
        if method == "readinto" and self.trace(unit, scope, call.func.value).chains[UNTRUSTED]:
            return method
        return ""

    def _global_writes(self, unit, name, binds):
        """Values other code writes into module value ``name`` of ``unit``."""
        key = ("global", id(unit), name)
        return self._memoized(self.global_memo, key, lambda: self._global_writes_uncached(unit, name, binds))

    def _global_writes_uncached(self, unit, name, binds):
        facts = _Facts()
        dynamic, rebound = unit.rebinding()
        if dynamic or name in rebound:
            return _Facts.leaf(UNKNOWN, _step(unit, unit.tree, f"module namespace of `{unit.rel}` can be rewritten at run time"))
        mutable = any(bind.kind == "assign" and _mutable_literal(bind.value) for bind in binds)
        for store_unit, target, value, statement, scope in self.project.attr_stores.get(name, ()):
            values = self.project.values(store_unit, scope, target.value)
            if values is not None and not any(item.kind == "mod" and item.unit is unit for item in values):
                continue
            stored = self.trace(store_unit, scope, value).then(_step(store_unit, statement, f"assigns module value `{name}`"))
            if values is None:
                stored = stored.moved(UNTRUSTED, UNKNOWN, _step(store_unit, statement, "receiver not resolved"))
            facts.add(stored)
        if not mutable:
            return facts
        for ref_unit, ref, scope in self.project.loads_by_name.get(name, ()):
            if not self.project._refers_to_global(ref_unit, scope, ref, unit, name):
                continue
            parent = ref_unit.parents.get(id(ref))
            if isinstance(parent, ast.Subscript) and parent.value is ref and isinstance(parent.ctx, ast.Store):
                continue
            if isinstance(parent, ast.Attribute) and parent.value is ref:
                call = ref_unit.parents.get(id(parent))
                if isinstance(call, ast.Call) and call.func is parent and parent.attr in _MUTATING_METHODS:
                    facts.add(
                        self._union(ref_unit, scope, [*call.args, *[keyword.value for keyword in call.keywords]], None).then(
                            _step(ref_unit, call, f"`{name}.{parent.attr}(...)` adds to it")
                        )
                    )
                    continue
                if parent.attr in _READ_ONLY_METHODS or parent.attr in _MUTATING_METHODS:
                    continue
            if isinstance(parent, ast.Call) and ref in parent.args:
                values = self.project.values(ref_unit, scope, parent.func)
                if values and all(item.kind == "ext" and item.name in _READ_ONLY_FUNCTIONS for item in values):
                    continue
                facts.add(_Facts.leaf(UNKNOWN, _step(ref_unit, parent, f"mutable module value `{name}` is passed to other code")))
            elif isinstance(parent, ast.Assign) and parent.value is ref:
                facts.add(_Facts.leaf(UNKNOWN, _step(ref_unit, parent, f"mutable module value `{name}` is aliased")))
        for store_unit, target, value, statement, scope in self.project.subscript_stores_by_name.get(name, ()):
            if not self.project._refers_to_global(store_unit, scope, target.value, unit, name):
                continue
            facts.add(self.trace(store_unit, scope, value).then(_step(store_unit, statement, f"stores into `{name}`")))
        return facts

    def _param(self, unit, owner, param, env):
        fn = owner.node
        name = param.arg
        binding = _env_lookup(env, id(fn))
        if binding is not None and binding[0] is None:
            return _Facts.leaf(PARAMETER, name)
        if binding is not None:
            site, parent_env = binding
            facts = _Facts()
            step = _step(site.unit, site.call, f"call `{_describe(site.call)}` binds `{name}`")
            for expr, expr_unit, expr_scope in self.project.bind_argument(fn, site, name):
                facts.add(self.trace(expr_unit, expr_scope, expr, parent_env).then(step))
            if facts.empty():
                return _Facts.leaf(SAFE, step)
            return facts
        positional = [*fn.args.posonlyargs, *fn.args.args]
        parent = owner.parent
        if parent is not None and parent.kind == "class" and positional and positional[0] is param and not _is_static(fn):
            return _Facts.leaf(UNKNOWN, _step(unit, fn, f"the object `{name}` itself"))
        entry = self.project.parameter_entry(unit, fn, param)
        if entry is not None:
            return _Facts.leaf(entry[0], entry[1])
        return self._callers(unit, fn, name)

    def _callers(self, unit, fn, name):
        key = ("param", id(fn), name)
        if key not in self.param_memo and key not in self.depth_of and len(self.active_params) >= _MAX_CALLER_DEPTH:
            return self._limit(unit, fn, f"caller depth limit ({_MAX_CALLER_DEPTH}) reached")
        self.active_params.append(key)
        try:
            return self._memoized(self.param_memo, key, lambda: self._callers_uncached(unit, fn, name))
        finally:
            self.active_params.pop()

    def _callers_uncached(self, unit, fn, name):
        sites = self.project.call_sites(unit, fn)
        facts = _Facts()
        for kind, step in sites.entries:
            facts.add(_Facts.leaf(kind, step))
        for step in sites.escapes:
            facts.add(_Facts.leaf(UNKNOWN, step))
        if len(sites.resolved) > _MAX_SITES:
            facts.add(self._limit(unit, fn, f"`{_function_label(fn)}` has more than {_MAX_SITES} resolved callers"))
        for site in sites.resolved[:_MAX_SITES]:
            facts.add(self._site_facts(fn, site, name))
        if len(sites.possible) > _MAX_SITES:
            facts.add(_Facts.leaf(UNKNOWN, _step(unit, fn, f"`{_function_label(fn)}` has more than {_MAX_SITES} unresolved possible callers")))
        for site in sites.possible[:_MAX_SITES]:
            unresolved = _step(site.unit, site.call, f"the receiver of `{_describe(site.call)}` is not resolved")
            facts.add(self._site_facts(fn, site, name).moved(UNTRUSTED, UNKNOWN, unresolved).moved(INCOMPLETE, UNKNOWN, unresolved))
        if not sites.resolved and not sites.possible and not sites.entries and not sites.escapes:
            facts.add(_Facts.leaf(UNKNOWN, _step(unit, fn, f"no call of `{_function_label(fn)}` in the scanned project")))
        return facts

    def _site_facts(self, fn, site, name):
        step = _step(site.unit, site.call, f"call `{_describe(site.call)}` binds `{name}`")
        facts = _Facts()
        for expr, expr_unit, expr_scope in self.project.bind_argument(fn, site, name):
            traced = self.trace(expr_unit, expr_scope, expr)
            if traced.chains[UNTRUSTED]:
                check = self._guarded(site, expr)
                if check is not None:
                    reason, status = check
                    traced = traced.moved(UNTRUSTED, status, _step(site.unit, site.call, f"`{_describe(expr)}` {reason} first"))
            facts.add(traced.then(step))
        if facts.empty():
            return _Facts.leaf(SAFE, _step(site.unit, site.call, f"call `{_describe(site.call)}` passes nothing as `{name}`"))
        return facts

    def _guarded(self, site, expr):
        """How ``expr`` is checked before the call, or None: a name checked
        against a constant allowlist (``if name not in ALLOWED: return``, or
        the call inside ``if name in ALLOWED:``) or a resolved path checked to
        stay inside a base directory (``path.relative_to(base)``,
        ``if not path.is_relative_to(base): return``), and not rebound between
        the check and the call, so the checked value is the one that reaches
        it."""
        if not isinstance(expr, ast.Name):
            return None
        unit = site.unit
        scope = site.scope
        guarded = self._guard_statement(unit, scope, site.call, expr.id)
        if guarded is None:
            return None
        guard, check = guarded
        found = unit.lookup(scope, expr.id)
        if found is None:
            return None
        guard_line = guard.lineno
        call_line = site.call.lineno
        loop = self._enclosing_loop(unit, site.call, guard)
        for bind in found[1]:
            if bind.kind == "param":
                continue
            line = getattr(bind.node, "lineno", 0)
            if guard_line <= line <= call_line:
                return None
            if loop is not None and loop.lineno <= line <= getattr(loop, "end_lineno", line):
                return None
        return check

    @staticmethod
    def _enclosing_loop(unit, call, guard):
        """The innermost loop around the call that also holds the guard."""
        guard_ancestors = set(id(node) for node in unit.ancestors(guard))
        for node in unit.ancestors(call):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return None
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)) and id(node) in guard_ancestors:
                return node
        return None

    def _guard_statement(self, unit, scope, call, name):
        """``(statement, how it checks name)`` for the check that runs
        before ``call``, or None."""
        child = call
        for node in unit.ancestors(call):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                return self._guard_in(unit, scope, node.body, child, name)
            if isinstance(node, ast.Lambda):
                return None
            if isinstance(node, ast.If) and child in node.body:
                check = self._branch_check(unit, scope, node.test, name)
                if check is not None:
                    return node, check
            for block in ("body", "orelse", "finalbody"):
                statements = getattr(node, block, None)
                if isinstance(statements, list) and child in statements:
                    guard = self._guard_in(unit, scope, statements, child, name)
                    if guard is not None:
                        return guard
            child = node
        return None

    def _branch_check(self, unit, scope, test, name):
        """How ``test`` holding checks ``name`` for the body of its ``if``."""
        if not _test_is_negative(test) and name in self._allowlisted(unit, scope, test):
            return ALLOWLIST_CHECK, SAFE
        status = self._contained(unit, scope, test, True, name)
        if status is not None:
            return self._containment_reason(status), status
        return None

    def _guard_in(self, unit, scope, statements, child, name):
        found = None
        for statement in statements:
            if statement is child:
                return found
            check = self._statement_check(unit, scope, statement, name)
            if check is not None:
                found = (statement, check)
        return found

    def _statement_check(self, unit, scope, statement, name):
        """How ``statement`` stops the code after it unless ``name`` passed a
        check, or None."""
        if isinstance(statement, ast.If) and self._guard_terminates(unit, scope, statement.body):
            if (
                self.filename_proofs
                and self._filename_equality_guard(unit, scope, statement, name)
                is not None
            ):
                return "passes a body-proven filename check", SAFE
            if _test_is_negative(statement.test) and name in self._allowlisted(unit, scope, statement.test):
                return ALLOWLIST_CHECK, SAFE
            status = self._contained(unit, scope, statement.test, False, name)
            if status is not None:
                return self._containment_reason(status), status
            return None
        if isinstance(statement, ast.Assert):
            return self._branch_check(unit, scope, statement.test, name)
        status = self._raises_outside_base(unit, scope, statement, name)
        if status is not None:
            return self._containment_reason(status), status
        if not isinstance(statement, ast.Try) or not statement.handlers:
            return None
        for handler in statement.handlers:
            if not self._guard_terminates(unit, scope, handler.body):
                return None
        for inner in statement.body:
            status = self._raises_outside_base(unit, scope, inner, name)
            if status is not None:
                return self._containment_reason(status), status
        return None

    def _guard_terminates(self, unit, scope, body):
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            return self._external_call(
                unit, scope, last.value,
                {"flask.abort", "werkzeug.exceptions.abort", "sys.exit", "os._exit", "builtins.exit"},
            )
        return False

    def _raises_outside_base(self, unit, scope, statement, name):
        """``statement`` is ``path.relative_to(base)`` on its own or as an
        assigned value: it raises ValueError unless the resolved ``path`` is
        inside ``base``."""
        value = None
        if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
            value = statement.value
        if not isinstance(value, ast.Call):
            return None
        return self._containment_call(unit, scope, value, name, {"relative_to"})

    def _contained(self, unit, scope, test, holds, name):
        """``test`` coming out ``holds`` proves the resolved path ``name``
        stays inside a base directory."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._contained(unit, scope, test.operand, not holds, name)
        if isinstance(test, ast.BoolOp):
            needs_every_part = isinstance(test.op, ast.Or) == holds
            status = None
            for value in test.values:
                part = self._contained(unit, scope, value, holds, name)
                if part is None:
                    if needs_every_part:
                        return None
                    continue
                if part == SAFE and not needs_every_part:
                    return SAFE
                if status is None or part == UNKNOWN:
                    status = part
            return status
        if isinstance(test, ast.Compare):
            return self._commonpath_check(unit, scope, test, holds, name)
        if not holds or not isinstance(test, ast.Call):
            return None
        return self._containment_call(unit, scope, test, name, {"is_relative_to", "startswith"})

    def _commonpath_check(self, unit, scope, test, holds, name):
        """``os.path.commonpath([path, base]) == base`` (or ``!=`` failing)."""
        if len(test.ops) != 1 or not isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
            return None
        if isinstance(test.ops[0], ast.Eq) != holds:
            return None
        pairs = ((test.left, test.comparators[0]), (test.comparators[0], test.left))
        for call, comparator in pairs:
            if not isinstance(call, ast.Call) or len(call.args) != 1 or call.keywords:
                continue
            if not self._external_call(unit, scope, call, _COMMONPATH_FUNCTIONS):
                continue
            elements = _commonpath_elements(call)
            if len(elements) != 2:
                continue
            for index, element in enumerate(elements):
                if not self._checked_path_name(unit, scope, element, name):
                    continue
                base = elements[1 - index]
                if not self._same_path_expression(unit, scope, base, comparator):
                    continue
                return self._base_status(unit, scope, base)
        return None

    def _containment_call(self, unit, scope, call, name, methods):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in methods:
            return None
        if len(call.args) != 1 or not self._checked_path_name(unit, scope, call.func.value, name):
            return None
        method = call.func.attr
        for keyword in call.keywords:
            if method != "relative_to" or keyword.arg != "walk_up":
                return None
            if not isinstance(keyword.value, ast.Constant) or keyword.value.value is not False:
                return None
        form = self._path_form(unit, scope, call.func.value)
        if method == "startswith":
            if form != "resolved_string":
                return None
            return self._prefix_status(unit, scope, call.args[0])
        if form != "resolved_path":
            return None
        return self._base_status(unit, scope, call.args[0])

    @staticmethod
    def _containment_reason(status):
        if status == UNKNOWN:
            return CONTAINMENT_CHECK + "; configured closure-root callers are only partly resolved"
        return CONTAINMENT_CHECK

    def _base_status(self, unit, scope, base):
        facts = self.trace(unit, scope, base)
        if facts.chains[UNTRUSTED] or facts.chains[INCOMPLETE]:
            return None
        if facts.chains[UNKNOWN] or facts.chains[PARAMETER] or facts.empty():
            if self._configured_closure_root(unit, scope, base):
                return UNKNOWN
            return None
        return SAFE

    def _configured_closure_root(self, unit, scope, base):
        """An immutable Path captured before a handler, with a proven configured caller.

        This proves the root's configuration role, not complete caller coverage:
        unresolved public/dynamic callers remain UNKNOWN in the finding record.
        """
        if self._path_form(unit, scope, base) not in {"path", "resolved_path", "resolved_string"}:
            return False
        while isinstance(base, ast.Call):
            operand = self._string_operand(unit, scope, base)
            if operand is not base:
                base = operand
            elif isinstance(base.func, ast.Attribute) and base.func.attr in {"resolve", "absolute", "as_posix"}:
                base = base.func.value
            else:
                return False
        if not isinstance(base, ast.Name):
            return False
        found = unit.lookup(scope, base.id)
        if found is None:
            return False
        owner, binds = found
        if owner is scope or owner.kind != "function":
            return False
        assignments = []
        for bind in binds:
            if bind.kind != "param":
                assignments.append(bind)
        if len(assignments) != 1:
            return False
        bind = assignments[0]
        if bind.kind != "assign" or bind.scope is not owner or not bind.top_level:
            return False
        if getattr(bind.node, "end_lineno", 0) >= getattr(scope.node, "lineno", 0):
            return False
        constructor = bind.value
        while isinstance(constructor, ast.Call) and isinstance(constructor.func, ast.Attribute):
            if constructor.func.attr not in {"resolve", "absolute"}:
                break
            constructor = constructor.func.value
        if not isinstance(constructor, ast.Call) or len(constructor.args) != 1 or constructor.keywords:
            return False
        if not self._external_call(unit, owner, constructor, _PATH_CONSTRUCTORS):
            return False
        argument = constructor.args[0]
        if not isinstance(argument, ast.Name):
            return False
        parameter = None
        for candidate in _function_params(owner.node):
            if candidate.arg == argument.id:
                parameter = candidate
                break
        if parameter is None:
            return False
        for site in self.project.call_sites(unit, owner.node).resolved[:_MAX_SITES]:
            for expr, expr_unit, expr_scope in self.project.bind_argument(owner.node, site, parameter.arg):
                facts = self.trace(expr_unit, expr_scope, expr)
                if facts.chains[UNTRUSTED] or facts.chains[INCOMPLETE]:
                    continue
                if self._configuration_evidence(expr_unit, expr_scope, expr):
                    return True
        return False

    def _configuration_evidence(self, unit, scope, expr, depth=0):
        """A literal suffix cannot make an otherwise unknown root configured."""
        if depth > _MAX_VALUE_DEPTH:
            return False
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Div, ast.Add)):
            return self._configuration_evidence(unit, scope, expr.left, depth + 1) and self._configuration_evidence(unit, scope, expr.right, depth + 1)
        if isinstance(expr, ast.Name):
            found = unit.lookup(scope, expr.id)
            if found is not None:
                binds = self._visible_binds(unit, found[0], found[1], expr)
                assignments = []
                for bind in binds:
                    if bind.kind == "assign":
                        assignments.append(bind)
                if assignments:
                    for bind in assignments:
                        if not self._configuration_evidence(unit, bind.scope, bind.value, depth + 1):
                            return False
                    return True
        if isinstance(expr, ast.Call):
            if self._external_call(unit, scope, expr, _PATH_CONSTRUCTORS) and expr.args:
                for argument in expr.args:
                    if not self._configuration_evidence(unit, scope, argument, depth + 1):
                        return False
                return True
            if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"resolve", "absolute", "as_posix"}:
                return self._configuration_evidence(unit, scope, expr.func.value, depth + 1)
        if isinstance(expr, ast.Attribute) and expr.attr == "parent":
            return self._configuration_evidence(unit, scope, expr.value, depth + 1)
        facts = self.trace(unit, scope, expr)
        return bool(facts.chains[SAFE] or facts.chains[OPERATOR])

    def _external_call(self, unit, scope, call, names):
        values = self.project.values(unit, scope, call.func)
        if not values:
            return False
        for value in values:
            if value.kind != "ext" or value.name not in names:
                return False
            if self._external_rebound(value.name):
                return False
        return True

    def _external_rebound(self, name):
        for member in name.split(".")[1:]:
            for store_unit, target, _, _, store_scope in self.project.attr_stores.get(member, ()):
                owners = self.project.values(store_unit, store_scope, target.value)
                for owner in owners or ():
                    if owner.kind not in {"ext", "extinst", "extattr"}:
                        continue
                    qualified = owner.name + "." + target.attr
                    if name == qualified or name.startswith(qualified + "."):
                        return True
        return False

    def _string_operand(self, unit, scope, node):
        if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
            if self._external_call(unit, scope, node, {"builtins.str", "os.fspath"}):
                return node.args[0]
        return node

    def _checked_path_name(self, unit, scope, node, name):
        operand = self._string_operand(unit, scope, node)
        if not isinstance(operand, ast.Name) or operand.id != name:
            return False
        return self._path_form(unit, scope, node) in {"resolved_path", "resolved_string"}

    def _same_path_expression(self, unit, scope, left, right):
        left = self._string_operand(unit, scope, left)
        right = self._string_operand(unit, scope, right)
        return ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)

    def _prefix_status(self, unit, scope, prefix, depth=0):
        """A string prefix must end at a directory separator, not a sibling's name."""
        if depth > _MAX_VALUE_DEPTH:
            return None
        if isinstance(prefix, ast.Constant) and isinstance(prefix.value, str):
            if prefix.value.endswith("/"):
                return SAFE
            return None
        if isinstance(prefix, ast.BinOp) and isinstance(prefix.op, ast.Add):
            separator = prefix.right
            literal_separator = isinstance(separator, ast.Constant) and separator.value == "/"
            values = self.project.values(unit, scope, separator)
            system_separator = bool(values) and not self._external_rebound("os.sep")
            for value in values or ():
                if value.kind != "ext" or value.name != "os.sep":
                    system_separator = False
            if literal_separator or system_separator:
                return self._base_status(unit, scope, prefix.left)
            return None
        if isinstance(prefix, ast.Name):
            found = unit.lookup(scope, prefix.id)
            if found is not None:
                binds = self._visible_binds(unit, found[0], found[1], prefix)
                if len(binds) == 1 and binds[0].kind == "assign":
                    bind = binds[0]
                    return self._prefix_status(unit, bind.scope, bind.value, depth + 1)
        return None

    def _path_form(self, unit, scope, node, depth=0):
        """Prove the receiver is a real pathlib path or a canonical path string."""
        if depth > _MAX_VALUE_DEPTH:
            return None
        if isinstance(node, ast.Name):
            found = unit.lookup(scope, node.id)
            if found is None:
                return None
            binds = self._visible_binds(unit, found[0], found[1], node)
            form = None
            for bind in binds:
                if bind.kind != "assign":
                    return None
                current = self._path_form(unit, bind.scope, bind.value, depth + 1)
                if current is None or form is not None and current != form:
                    return None
                form = current
            return form
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if self._path_form(unit, scope, node.left, depth + 1) in {"path", "resolved_path"}:
                return "path"
            return None
        if not isinstance(node, ast.Call):
            return None
        if self._external_call(unit, scope, node, _PATH_CONSTRUCTORS):
            return "path"
        if self._external_call(unit, scope, node, _REALPATH_FUNCTIONS):
            if len(node.args) == 1:
                return "resolved_string"
            return None
        operand = self._string_operand(unit, scope, node)
        if operand is not node:
            form = self._path_form(unit, scope, operand, depth + 1)
            if form in {"resolved_path", "resolved_string"}:
                return "resolved_string"
            return None
        if not isinstance(node.func, ast.Attribute):
            return None
        form = self._path_form(unit, scope, node.func.value, depth + 1)
        if form not in {"path", "resolved_path"}:
            return None
        if node.func.attr == "resolve":
            for constructor in _PATH_CONSTRUCTORS:
                if self._external_rebound(constructor + ".resolve"):
                    return None
            return "resolved_path"
        if node.func.attr == "absolute" and not node.args and not node.keywords:
            return form
        if node.func.attr == "as_posix" and form == "resolved_path" and not node.args and not node.keywords:
            return "resolved_string"
        return None

    def _allowlisted(self, unit, scope, test):
        """Names ``test`` checks for membership in a collection of constants
        that nothing can change: a literal, or a constant module table."""
        names = set()
        for node in ast.walk(test):
            if not isinstance(node, ast.Compare) or not _allowlist_names(node):
                continue
            collection = node.comparators[0]
            if isinstance(collection, ast.Call) and isinstance(collection.func, ast.Attribute):
                collection = collection.func.value
            if _constant_literal(collection) or self.project.constant_table(unit, scope, collection):
                names |= _allowlist_names(node)
        return names

    def _attribute(self, unit, scope, node, env):
        source = self._attribute_source(unit, scope, node)
        if source is not None:
            return _Facts.leaf(source[0], _step(unit, node, source[1]))
        base = node.value
        owner_class = self._self_class(unit, scope, base)
        if owner_class is not None:
            return self._instance_attribute(unit, owner_class, node.attr, node)
        values = self.project.values(unit, scope, base)
        if values:
            if all(value.kind == "mod" for value in values):
                facts = _Facts()
                for value in values:
                    facts.add(self._module_value(value.unit, node.attr, node, unit))
                return facts
            if all(value.kind in {"inst", "cls"} for value in values):
                facts = _Facts()
                for value in values:
                    facts.add(self._instance_attribute(unit, value.node, node.attr, node))
                return facts
        if node.attr in _BASENAME_PARTS and self.rule == TRAVERSAL_RULE and self._path_object(values):
            return _Facts.leaf(SAFE, _step(unit, node, f"`.{node.attr}` keeps only the final path component"))
        return self.trace(unit, scope, base, env).then(_step(unit, node, f"attribute `.{node.attr}`"))

    @staticmethod
    def _path_object(values):
        if not values:
            return False
        return all(
            value.kind in {"extinst", "extattr"} and value.name.startswith("pathlib.")
            for value in values
        )

    def _module_value(self, target, name, node, unit):
        binds = target.module.binds.get(name)
        if not binds:
            return _Facts.leaf(UNKNOWN, _step(unit, node, f"`{name}` is not a module value of `{target.rel}`"))
        facts = _Facts()
        for bind in binds:
            facts.add(self._bind_facts(target, target.module, bind, name, None))
        facts.add(self._global_writes(target, name, binds))
        return facts.then(_step(unit, node, f"reads `{target.rel}` value `{name}`"))

    def _self_class(self, unit, scope, base):
        if not isinstance(base, ast.Name):
            return None
        found = unit.lookup(scope, base.id)
        if found is None:
            return None
        owner, binds = found
        if len(binds) != 1 or binds[0].kind != "param" or owner.kind != "function":
            return None
        fn = owner.node
        positional = [*fn.args.posonlyargs, *fn.args.args]
        parent = owner.parent
        if parent is None or parent.kind != "class" or not positional or positional[0] is not binds[0].node:
            return None
        if _is_static(fn):
            return None
        return parent.node

    def _instance_attribute(self, unit, cls_node, attr, node):
        key = ("attr", id(cls_node), attr)
        facts = self._memoized(self.attr_memo, key, lambda: self._instance_attribute_uncached(cls_node, attr))
        return facts.then(_step(unit, node, f"attribute `.{attr}` of `{cls_node.name}`"))

    def _instance_attribute_uncached(self, cls_node, attr):
        project = self.project
        order, external = project.mro(cls_node)
        classes = [*order, *project.subclasses(cls_node)]
        facts = _Facts()
        found = False
        for cls_unit, cls in classes:
            class_scope = cls_unit.class_scopes[id(cls)]
            for statement in cls.body:
                if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                    targets = getattr(statement, "targets", None) or [statement.target]
                    if any(isinstance(target, ast.Name) and target.id == attr for target in targets):
                        found = True
                        facts.add(self.trace(cls_unit, class_scope, statement.value).then(
                            _step(cls_unit, statement, f"class attribute `{cls.name}.{attr}`")
                        ))
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name == attr:
                    found = True
                    if not _is_property(statement):
                        facts.add(_Facts.leaf(UNKNOWN, _step(cls_unit, statement, f"`{attr}` is a method object")))
                        continue
                    for value in self.project.returned_values(statement):
                        facts.add(self.trace(cls_unit, cls_unit.scope_of(value), value).then(
                            _step(cls_unit, statement, f"property `{cls.name}.{attr}` returns it")
                        ))
            if self._dataclass_field(cls, attr):
                found = True
                facts.add(self._dataclass_field_facts(cls_unit, cls, attr))
        for store_unit, scope, value in project.instance_stores(cls_node, attr):
            found = True
            facts.add(self.trace(store_unit, scope, value).then(_step(store_unit, value, f"assigns `self.{attr}`")))
        own = set(id(value) for _, _, value in project.instance_stores(cls_node, attr))
        targets = set(id(cls) for _, cls in classes)
        for store_unit, target, value, statement, scope in project.attr_stores.get(attr, ()):
            if id(value) in own or value is None:
                continue
            values = project.values(store_unit, scope, target.value)
            if values is None:
                stored = self.trace(store_unit, scope, value).then(_step(store_unit, statement, f"may assign `.{attr}`"))
                facts.add(stored.moved(UNTRUSTED, UNKNOWN, _step(store_unit, statement, "receiver not resolved")))
                found = True
                continue
            if any(item.kind in {"inst", "cls"} and id(item.node) in targets for item in values):
                found = True
                facts.add(self.trace(store_unit, scope, value).then(_step(store_unit, statement, f"assigns `.{attr}`")))
        facts.add(self._attribute_container_writes(cls_node, attr, targets))
        for cls_unit, cls in classes:
            for call, scope in cls_unit.calls:
                if not (isinstance(call.func, ast.Name) and call.func.id == "setattr" and len(call.args) >= 2):
                    continue
                name = call.args[1]
                if isinstance(name, ast.Constant) and name.value != attr:
                    continue
                if cls.lineno <= getattr(call, "lineno", 0) <= getattr(cls, "end_lineno", 0):
                    facts.add(_Facts.leaf(UNKNOWN, _step(cls_unit, call, f"`setattr` may set `.{attr}`")))
        if external:
            facts.add(_Facts.leaf(UNKNOWN, _step(order[0][0], cls_node, f"external base `{external[0]}` may set `.{attr}`")))
        if not found:
            facts.add(_Facts.leaf(UNKNOWN, _step(order[0][0], cls_node, f"no assignment to `.{attr}` of `{cls_node.name}` in the project")))
        return facts

    def _attribute_container_writes(self, cls_node, attr, targets):
        """Items stored into ``<instance>.<attr>``: ``obj.attr[k] = v``,
        ``obj.attr.append(v)``; unknown when it is handed to other code."""
        project = self.project
        facts = _Facts()

        def owner_matches(unit, scope, holder):
            values = project.values(unit, scope, holder)
            if values is None:
                return None
            return any(item.kind in {"inst", "cls"} and id(item.node) in targets for item in values)

        for store_unit, target, value, statement, scope in project.subscript_stores_by_name.get(attr, ()):
            base = target.value
            if not isinstance(base, ast.Attribute):
                continue
            matches = owner_matches(store_unit, scope, base.value)
            if matches is False:
                continue
            stored = self.trace(store_unit, scope, value).then(_step(store_unit, statement, f"stores into `.{attr}`"))
            if matches is None:
                stored = stored.moved(UNTRUSTED, UNKNOWN, _step(store_unit, statement, "receiver not resolved"))
            facts.add(stored)
        for unit in project.units:
            for call, scope in unit.attr_mutations.get(attr, ()):
                matches = owner_matches(unit, scope, call.func.value.value)
                if matches is False:
                    continue
                arguments = [*call.args, *[keyword.value for keyword in call.keywords]]
                added = self._union(unit, scope, arguments, None).then(
                    _step(unit, call, f"`.{attr}.{call.func.attr}(...)` adds to it")
                )
                if matches is None:
                    added = added.moved(UNTRUSTED, UNKNOWN, _step(unit, call, "receiver not resolved"))
                facts.add(added)
            for call, scope in unit.attr_escapes.get(attr, ()):
                arguments = [*call.args, *[keyword.value for keyword in call.keywords]]
                for argument in arguments:
                    if isinstance(argument, ast.Starred):
                        argument = argument.value
                    if not isinstance(argument, ast.Attribute) or argument.attr != attr:
                        continue
                    if owner_matches(unit, scope, argument.value) is False:
                        continue
                    values = project.values(unit, scope, call.func)
                    if values and all(item.kind == "ext" and item.name in _READ_ONLY_FUNCTIONS for item in values):
                        continue
                    if not self._mutable_attribute(cls_node, attr):
                        continue
                    facts.add(_Facts.leaf(UNKNOWN, _step(unit, call, f"`.{attr}` is passed to `{_describe(call)}`, which may change it")))
        return facts

    def _mutable_attribute(self, cls_node, attr):
        for _, _, value in self.project.instance_stores(cls_node, attr):
            if _mutable_literal(value):
                return True
        order, _ = self.project.mro(cls_node)
        for _, cls in order:
            for statement in cls.body:
                if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                    targets = getattr(statement, "targets", None) or [statement.target]
                    if any(isinstance(target, ast.Name) and target.id == attr for target in targets):
                        if _mutable_literal(statement.value):
                            return True
        return False

    @staticmethod
    def _dataclass_field(cls, attr):
        if not any(name.rsplit(".", 1)[-1] in {"dataclass", "define", "frozen", "attrs", "s"} for name in _decorator_names(cls)):
            return False
        return any(
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == attr
            for statement in cls.body
        )

    def _dataclass_field_facts(self, cls_unit, cls, attr):
        fields = [
            statement
            for statement in cls.body
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
        ]
        names = [statement.target.id for statement in fields]
        position = names.index(attr)
        facts = _Facts()
        default = fields[position].value
        if default is not None:
            facts.add(self.trace(cls_unit, cls_unit.class_scopes[id(cls)], default).then(
                _step(cls_unit, fields[position], f"default of field `{attr}`")
            ))
        keys = [cls.name]
        seen = set()
        for key in keys:
            for call_unit, call, scope in self.project.calls_by_name.get(key, ()):
                if id(call) in seen:
                    continue
                seen.add(id(call))
                values = self.project.values(call_unit, scope, call.func)
                if values is None:
                    continue
                if not any(value.kind == "cls" and value.node is cls for value in values):
                    continue
                passed = []
                for index, argument in enumerate(call.args):
                    if isinstance(argument, ast.Starred):
                        passed.append(argument.value)
                    elif index == position:
                        passed.append(argument)
                for keyword in call.keywords:
                    if keyword.arg is None or keyword.arg == attr:
                        passed.append(keyword.value)
                for argument in passed:
                    facts.add(self.trace(call_unit, scope, argument).then(
                        _step(call_unit, call, f"`{cls.name}(...)` sets field `{attr}`")
                    ))
        return facts

    def _request_chain(self, unit, scope, dotted):
        """``dotted`` reads a request object by the framework naming
        convention (``request.args``, ``self.request.GET``). A ``request``
        name bound by an assignment or loop is followed instead."""
        segments = dotted.split(".")
        hits = [index for index, segment in enumerate(segments[:-1]) if segment in REQUEST_NAMES]
        if not hits or not self.project.framework_context(unit):
            return False
        if hits[0] > 0:
            return True
        found = unit.lookup(scope, segments[0])
        if found is None:
            return True
        for bind in found[1]:
            if bind.kind == "import":
                module, member, _ = bind.value
                qualified = module
                if member:
                    qualified = f"{module}.{member}"
                if qualified.startswith("urllib"):
                    return False
            elif bind.kind != "param":
                return False
            else:
                function = bind.scope.node
                if unit.is_test and (_function_label(function).startswith("test") or _is_fixture(function)):
                    return False
        return True

    @staticmethod
    def _request_object(name):
        segments = name.replace("()", "").split(".")
        if segments[0] not in _WEB_FRAMEWORKS:
            return False
        return any(segment in REQUEST_NAMES for segment in segments[1:])

    def _attribute_source(self, unit, scope, node):
        dotted = _dotted(node)
        if dotted and self._request_chain(unit, scope, dotted):
            return UNTRUSTED, f"request data `{dotted}`"
        values = self.project.values(unit, scope, node)
        if values and len(values) == 1:
            value = next(iter(values))
            if value.kind in {"ext", "extattr"} and self._request_object(value.name):
                return UNTRUSTED, f"request data `{dotted or value.name}`"
            if value.kind == "ext":
                name = value.name
                if name == "sys.argv" or name.startswith("sys.argv."):
                    return OPERATOR, "CLI arguments `sys.argv`"
                if name == "os.environ":
                    return OPERATOR, "process environment `os.environ`"
                if name == "sys.stdin" or name.startswith("sys.stdin."):
                    return UNTRUSTED, "standard input `sys.stdin`"
                if name in _SAFE_ATTRIBUTES:
                    return SAFE, f"interpreter location `{name}`"
        base = node.value
        owner_class = self._self_class(unit, scope, base)
        if owner_class is not None:
            if node.attr in _HTTP_HANDLER_ATTRS and self.project._class_extends(owner_class, _HTTP_HANDLER_BASES):
                return UNTRUSTED, f"HTTP request `self.{node.attr}` of `{owner_class.name}`"
            if node.attr in {"path_args", "path_kwargs"} and self.project._class_extends(owner_class, _TORNADO_HANDLER_BASES):
                return UNTRUSTED, f"URL arguments `self.{node.attr}` of `{owner_class.name}`"
            if node.attr in {"kwargs", "args"} and self.project.django_view(owner_class):
                return UNTRUSTED, f"URL arguments `self.{node.attr}` of Django view `{owner_class.name}`"
        return None

    def _subscript(self, unit, scope, node, env):
        base_values = self.project.values(unit, scope, node.value)
        if base_values and all(value.kind == "ext" and value.name == "os.environ" for value in base_values):
            return self._environment(unit, node, node.slice)
        if self.project.constant_table(unit, scope, node.value):
            return _Facts.leaf(SAFE, _step(unit, node, f"entry of constant table `{_describe(node.value)}`"))
        return self.trace(unit, scope, node.value, env).then(_step(unit, node, f"item of `{_describe(node.value)}`"))

    def _environment(self, unit, node, key):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if key.value in _CGI_VARIABLES or key.value.startswith("HTTP_"):
                return _Facts.leaf(UNTRUSTED, _step(unit, node, f"CGI request variable `{key.value}`"))
            return _Facts.leaf(OPERATOR, _step(unit, node, f"environment variable `{key.value}`"))
        return _Facts.leaf(UNKNOWN, _step(unit, node, "environment variable chosen at run time"))

    def _call(self, unit, scope, node, env):
        func = node.func
        values = self.project.values(unit, scope, func)
        names = set()
        if values:
            for value in values:
                if value.kind in {"ext", "extattr"}:
                    names.add(value.name)
        source = self._call_source(unit, scope, node, names)
        if source is not None:
            return source
        if values and all(value.kind in {"fn", "partial", "cls"} for value in values):
            facts = _Facts()
            for value in values:
                if value.kind == "fn":
                    facts.add(self._returns(unit, scope, node, value, [], [], env))
                elif value.kind == "partial":
                    for target in value.extra[0]:
                        if target.kind != "fn":
                            facts.add(_Facts.leaf(UNKNOWN, _step(unit, node, "partial of an unresolved callable")))
                            continue
                        partial_call = value.node
                        facts.add(self._returns(unit, scope, node, target, list(partial_call.args[1:]), list(partial_call.keywords), env))
                else:
                    facts.add(self._constructor_facts(unit, scope, node, value, env))
            return facts
        arguments = [*node.args, *[keyword.value for keyword in node.keywords]]
        if names and names <= {"builtins.open", "io.open", "codecs.open"} and node.args:
            if self._downloaded(unit, scope, node.args[0], 0):
                return _Facts.leaf(UNTRUSTED, _step(unit, node, "content of a file downloaded from the network"))
            return _Facts.leaf(UNKNOWN, _step(unit, node, f"content of the file opened by `{_describe(node)}`"))
        if names and names <= _D215_SANITIZERS and self.rule == TRAVERSAL_RULE:
            return _Facts.leaf(SAFE, _step(unit, node, f"`{_describe(node)}` keeps only the final path component"))
        if names and names <= _TRANSPARENT_CALLS:
            if not arguments:
                return _Facts.leaf(SAFE, _step(unit, node, f"`{_describe(node)}` without arguments"))
            return self._union(unit, scope, arguments, env).then(_step(unit, node, f"passes through `{_describe(node)}`"))
        if isinstance(func, ast.Attribute):
            receiver = self.trace(unit, scope, func.value, env)
            if func.attr in _FORMAT_ONLY_METHODS:
                if not arguments:
                    return _Facts.leaf(SAFE, _step(unit, node, f"`.{func.attr}()` formats a date or time"))
                return self._union(unit, scope, arguments, env).then(_step(unit, node, f"`.{func.attr}()` formats a date or time"))
            if func.attr in _TRANSPARENT_METHODS and not (values and any(value.kind == "fn" for value in values)):
                return _Facts().add(receiver).add(self._union(unit, scope, arguments, env)).then(
                    _step(unit, node, f"passes through `.{func.attr}()`")
                )
            if receiver.chains[UNTRUSTED]:
                return receiver.then(_step(unit, node, f"derived by `.{func.attr}()`"))
        return _Facts.leaf(UNKNOWN, _step(unit, node, f"return value of `{_describe(node)}` is not followed"))

    def _constructor_facts(self, unit, scope, node, value, env):
        unpacked = any(isinstance(argument, ast.Starred) for argument in node.args)
        if not unpacked and self._default_string_constructor(value):
            argument = (
                node.args[0]
                if node.args
                else next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "object"
                    ),
                    None,
                )
            )
            if argument is None and (node.args or node.keywords):
                return _Facts.leaf(
                    UNKNOWN,
                    _step(unit, node, "string constructor arguments are not resolved"),
                )
            if argument is None:
                return _Facts.leaf(
                    SAFE, _step(unit, node, "empty string subclass instance")
                )
            return self.trace(unit, scope, argument, env).then(
                _step(
                    unit,
                    node,
                    f"default `str` constructor of `{value.node.name}` preserves its argument",
                )
            )
        return _Facts.leaf(
            UNKNOWN, _step(unit, node, f"object of class `{value.node.name}`")
        )

    def _default_string_constructor(self, value, depth=0):
        """Only plain, unmodified subclasses of the real builtin ``str``.

        Calling an arbitrary class does not preserve argument bytes: a custom
        ``__new__``, metaclass or decorator can return a fixed value or an IO
        wrapper. Follow a bounded single-base chain with inert class bodies
        instead of treating every user constructor as a string conversion.
        """
        key = id(value.node)
        if depth >= _MAX_VALUE_DEPTH:
            return False
        if key in self.string_constructor_memo:
            return self.string_constructor_memo[key]
        self.string_constructor_memo[key] = False
        cls = value.node
        if not self._plain_string_class(cls):
            return False
        if self.string_runtime_stable is None:
            self.string_runtime_stable = True
            for unit in self.project.units:
                writes, computed = attribute_write_names(unit.tree)
                if (
                    computed
                    or writes
                    & {
                        "str",
                        "__new__",
                        "__init__",
                        "__bases__",
                        "__class__",
                        "__call__",
                        "__init_subclass__",
                        "__mro_entries__",
                        "__set_name__",
                    }
                    or has_mock_api_patching(unit.tree)
                    or unit.rebinding()[0]
                ):
                    self.string_runtime_stable = False
                    break
                for call, scope in unit.calls:
                    arguments = [
                        *call.args,
                        *[keyword.value for keyword in call.keywords],
                    ]
                    if all(_constant_literal(argument) for argument in arguments):
                        continue
                    targets = self.project.values(unit, scope, call.func)
                    if targets and all(
                        (
                            target.kind == "fn"
                            and not getattr(target.node, "decorator_list", ())
                        )
                        or (
                            target.kind == "cls"
                            and not target.node.decorator_list
                            and not target.node.keywords
                            and not self.project.mro(target.node)[1]
                        )
                        or (
                            target.kind == "ext"
                            and (
                                target.name
                                in {
                                    "builtins.str",
                                    "builtins.type",
                                    "builtins.len",
                                    "builtins.open",
                                    "io.open",
                                    "os.open",
                                    "os.fspath",
                                    "pathlib.Path",
                                    "pathlib.PurePath",
                                    "pathlib.PosixPath",
                                    "pathlib.WindowsPath",
                                }
                                or (
                                    target.name == "builtins.isinstance"
                                    and self._inert_string_type_check(unit, scope, call)
                                )
                            )
                            and not self._external_rebound(target.name)
                        )
                        for target in targets
                    ):
                        continue
                    # An unknown consumer may use type(instance) to replace
                    # its class's constructor, even without receiving the
                    # class itself. Literal arguments cannot expose it.
                    self.string_runtime_stable = False
                    break
                if not self.string_runtime_stable:
                    break
        if not self.string_runtime_stable:
            return False
        for unit in self.project.units:
            for ref, scope in unit.loads:
                targets = self.project.values(unit, scope, ref)
                if not targets or not any(
                    target.kind == "cls" and target.node is cls for target in targets
                ):
                    continue
                parent = unit.parents.get(id(ref))
                if isinstance(parent, ast.Call) and parent.func is ref:
                    continue
                if (
                    isinstance(parent, ast.ClassDef)
                    and ref in parent.bases
                    and self._plain_string_class(parent)
                ):
                    continue
                if (
                    isinstance(parent, ast.Assign)
                    and parent.value is ref
                    and all(isinstance(target, ast.Name) for target in parent.targets)
                    and all(
                        (found := unit.lookup(scope, target.id)) is not None
                        and len(found[1]) == 1
                        for target in parent.targets
                    )
                ):
                    continue
                if (
                    isinstance(parent, ast.AnnAssign)
                    and parent.value is ref
                    and isinstance(parent.target, ast.Name)
                    and (found := unit.lookup(scope, parent.target.id)) is not None
                    and len(found[1]) == 1
                ):
                    continue
                return False
        base = cls.bases[0]
        bases = self.project.values(value.unit, value.unit.scope_of(base), base)
        if not bases:
            return False
        for parent in bases:
            if parent.kind == "ext" and parent.name == "builtins.str":
                if self._external_rebound(parent.name):
                    return False
            elif parent.kind != "cls" or not self._default_string_constructor(
                parent, depth + 1
            ):
                return False
        self.string_constructor_memo[key] = True
        return True

    def _inert_string_type_check(self, unit, scope, call):
        if len(call.args) != 2 or call.keywords:
            return False
        tested = call.args[1]
        types = tested.elts if isinstance(tested, ast.Tuple) else [tested]
        for expr in types:
            values = self.project.values(unit, scope, expr)
            if not values or any(
                value.kind != "ext"
                or value.name not in {"builtins.str", "os.PathLike"}
                or self._external_rebound(value.name)
                for value in values
            ):
                return False
        return bool(types)

    @staticmethod
    def _plain_string_class(cls):
        if cls.decorator_list or cls.keywords or len(cls.bases) != 1:
            return False
        return all(
            isinstance(statement, ast.Pass)
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            )
            for statement in cls.body
        )

    def _downloaded(self, unit, scope, expr, depth):
        """``expr`` names a file a downloader wrote (``urlretrieve``)."""
        if depth > 4:
            return False
        if isinstance(expr, ast.Call):
            values = self.project.values(unit, scope, expr.func)
            if values and all(value.kind == "ext" and value.name in _DOWNLOADERS for value in values):
                return True
            if values and all(value.kind == "ext" and value.name in {"builtins.str", "pathlib.Path", "os.fspath"} for value in values) and expr.args:
                return self._downloaded(unit, scope, expr.args[0], depth + 1)
            return False
        if isinstance(expr, ast.Subscript):
            return self._downloaded(unit, scope, expr.value, depth + 1)
        if not isinstance(expr, ast.Name):
            return False
        found = unit.lookup(scope, expr.id)
        if found is None:
            return False
        return any(
            bind.kind in {"assign", "unpack"} and self._downloaded(unit, bind.scope, bind.value, depth + 1)
            for bind in found[1]
        )

    def _call_source(self, unit, scope, node, names):
        func = node.func
        for name in names:
            if name in _STDIN_CALLS:
                return _Facts.leaf(UNTRUSTED, _step(unit, node, f"standard input `{name}()`"))
            if name in _ENV_CALLS:
                if node.args:
                    facts = self._environment(unit, node, node.args[0])
                    if len(node.args) > 1:
                        facts.add(self.trace(unit, scope, node.args[1]))
                    return facts
                return _Facts.leaf(UNKNOWN, _step(unit, node, "environment variable chosen at run time"))
            if name in _NETWORK_CALLS:
                return _Facts.leaf(UNTRUSTED, _step(unit, node, f"network response from `{name}()`"))
            parts = name.rsplit(".", 1)
            if len(parts) == 2:
                receiver, method = parts
                receiver = receiver.replace("()", "")
                if receiver in _NETWORK_CLIENTS and method in _NETWORK_METHODS:
                    return _Facts.leaf(UNTRUSTED, _step(unit, node, f"network response from `{receiver}.{method}()`"))
                if receiver.startswith("socket.") and method in _SOCKET_READS:
                    return _Facts.leaf(UNTRUSTED, _step(unit, node, f"network payload from `.{method}()`"))
                if receiver in _ARCHIVE_TYPES and method in _ARCHIVE_MEMBER_METHODS:
                    return _Facts.leaf(UNTRUSTED, _step(unit, node, f"archive member name from `{receiver}.{method}()`"))
                if receiver in _STREAM_OPENERS and method in _STREAM_READS:
                    return _Facts.leaf(UNTRUSTED, _step(unit, node, f"network payload from a `{receiver}` stream `.{method}()`"))
            if _HASH_DIGEST.match(name.replace("()", "")):
                return _Facts.leaf(SAFE, _step(unit, node, f"hex digest from `{name.replace('()', '')}`"))
            if name in _OPERATOR_CALLS:
                return _Facts.leaf(OPERATOR, _step(unit, node, f"working directory `{name}()`"))
            if name in _SAFE_CALLS:
                return _Facts.leaf(SAFE, _step(unit, node, f"`{name}()` returns a number, clock value or identifier"))
            if name in _TEMP_CALLS:
                facts = _Facts.leaf(SAFE, _step(unit, node, f"temporary path from `{name}()`"))
                return facts.add(self._union(unit, scope, [*node.args, *[keyword.value for keyword in node.keywords]], None))
        if isinstance(func, ast.Attribute) and func.attr in {"parse_args", "parse_known_args"}:
            return self._parsed_arguments(unit, scope, node)
        dotted = _dotted(func)
        if dotted and self._request_chain(unit, scope, dotted):
            return _Facts.leaf(UNTRUSTED, _step(unit, node, f"request data `{dotted}()`"))
        if any(self._request_object(name) for name in names):
            return _Facts.leaf(UNTRUSTED, _step(unit, node, f"request data `{dotted or _describe(node)}()`"))
        if isinstance(func, ast.Attribute):
            owner_class = self._self_class(unit, scope, func.value)
            if (
                owner_class is not None
                and func.attr in _TORNADO_ARGUMENT_METHODS
                and self.project._class_extends(owner_class, _TORNADO_HANDLER_BASES)
            ):
                return _Facts.leaf(UNTRUSTED, _step(unit, node, f"request argument `self.{func.attr}()`"))
        return None

    def _parsed_arguments(self, unit, scope, node):
        """``parse_args()`` of an argparse parser is the operator's command
        line; a request parser (flask-restful ``reqparse``) parses the HTTP
        request; any other parser is unknown."""
        parsers = self.project.values(unit, scope, node.func.value)
        if parsers and all(
            value.kind in {"extinst", "extattr"} and value.name.startswith(_REQUEST_PARSERS)
            for value in parsers
        ):
            return _Facts.leaf(UNTRUSTED, _step(unit, node, f"request arguments `{_describe(node)}`"))
        if parsers and all(
            value.kind in {"extinst", "extattr"} and value.name.startswith("argparse.")
            for value in parsers
        ):
            return _Facts.leaf(OPERATOR, _step(unit, node, f"CLI arguments `{_describe(node)}`"))
        if parsers and all(value.kind == "inst" for value in parsers):
            if all(self._extends_argparse(value.node) for value in parsers):
                return _Facts.leaf(OPERATOR, _step(unit, node, f"CLI arguments `{_describe(node)}`"))
        return _Facts.leaf(UNKNOWN, _step(unit, node, f"`{_describe(node)}` is not a proven command-line parser"))

    def _extends_argparse(self, cls_node):
        _, external = self.project.mro(cls_node)
        return bool(external) and all(name.startswith("argparse.") for name in external)

    def _returns(self, unit, scope, call, value, prebound, prebound_keywords, env):
        """What a resolved call returns: the callee's summary, with each
        parameter that reaches a return replaced by what this call passes."""
        fn = value.node
        info = self.project.function_info.get(id(fn))
        if info is None:
            return _Facts.leaf(UNKNOWN, _step(unit, call, f"`{_describe(call)}` is not resolved"))
        escapes = []
        if self.filename_proofs and self._filename_call(
            unit, scope, call, value, prebound, prebound_keywords, env, escapes
        ):
            step = _step(
                unit,
                call,
                "resolved helper produces only filename-component characters",
            )
            return _with_hidden_callers(_Facts.leaf(SAFE, step), escapes, step)
        summary = self._summary(fn, info[0])
        facts = _Facts()
        for kind in _Facts.KINDS:
            if kind != PARAMETER:
                facts.chains[kind] = list(summary.chains[kind])
        site = _Site(unit, scope, call, [*prebound, *call.args], [*prebound_keywords, *call.keywords], value.bound, "call")
        tails = {}
        for chain in summary.chains[PARAMETER]:
            tails.setdefault(chain[0], chain[1:])
        for name, tail in tails.items():
            step = _step(unit, call, f"call `{_describe(call)}` binds `{name}`")
            passed = _Facts()
            for expr, expr_unit, expr_scope in self.project.bind_argument(fn, site, name):
                passed.add(self.trace(expr_unit, expr_scope, expr, env))
            if passed.empty():
                passed = _Facts.leaf(SAFE, step)
            else:
                passed = passed.then(step)
            for item in tail:
                passed = passed.then(item)
            facts.add(passed)
        return facts

    @staticmethod
    def _filename_literal(node):
        # Deliberately exclude dots as well as separators/drive syntax. This
        # proves a component, not that its directory entries cannot be links.
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and all(
            char.isalnum() or char in "-_" for char in node.value
        )

    def _filename_filter(self, node, parameter):
        """A literal str.join over one checked character at a time.

        This is a body proof, not a helper-name allowlist. Its caller must
        separately prove native string input: user objects/str subclasses may
        override iteration or isalnum and cannot establish this proof.
        """
        if not (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and self._filename_literal(node.func.value)
            and len(node.args) == 1 and not node.keywords
        ):
            return False
        generator = node.args[0]
        if not isinstance(generator, (ast.GeneratorExp, ast.ListComp)) or len(generator.generators) != 1:
            return False
        iterator = generator.generators[0]
        if iterator.is_async or iterator.ifs or not isinstance(iterator.target, ast.Name):
            return False
        if not isinstance(iterator.iter, ast.Name) or iterator.iter.id != parameter:
            return False
        item = generator.elt
        if not isinstance(item, ast.IfExp) or not self._filename_literal(item.orelse):
            return False
        char = iterator.target.id
        if not isinstance(item.body, ast.Name) or item.body.id != char:
            return False

        def checked(test):
            if isinstance(test, ast.BoolOp):
                # Keep the supported language small: unknown predicates may
                # invoke custom code, even when another conjunct looks safe.
                return all(checked(part) for part in test.values)
            if isinstance(test, ast.Call):
                return (
                    isinstance(test.func, ast.Attribute) and test.func.attr == "isalnum"
                    and isinstance(test.func.value, ast.Name) and test.func.value.id == char
                    and not test.args and not test.keywords
                )
            if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.In):
                if not isinstance(test.left, ast.Name) or test.left.id != char:
                    return False
                allowed = test.comparators[0]
                if isinstance(allowed, ast.Constant):
                    return self._filename_literal(allowed)
                return isinstance(allowed, (ast.Tuple, ast.List, ast.Set)) and all(
                    self._filename_literal(part) for part in allowed.elts
                )
            return False

        # Unknown predicates could mutate the iterator/locals or invoke custom
        # behavior. Do not infer safety from only a familiar-looking subtest.
        return checked(item.test) and all(
            isinstance(part, (ast.BoolOp, ast.Call, ast.Compare, ast.Attribute, ast.Name,
                              ast.Load, ast.Constant, ast.Tuple, ast.List, ast.Set, ast.In,
                              ast.And, ast.Or))
            for part in ast.walk(item.test)
        )

    def _filename_body(self, unit, fn):
        if not isinstance(fn, ast.FunctionDef):
            return None
        args = fn.args
        positional = [*args.posonlyargs, *args.args]
        if len(positional) != 1 or args.vararg or args.kwarg or args.kwonlyargs:
            return None
        if any(not self._external_call(unit, unit.scope_of(decorator), ast.Call(
            func=decorator, args=[], keywords=[]
        ), {"builtins.staticmethod"}) for decorator in fn.decorator_list):
            return None
        body = list(fn.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body.pop(0)
        if len(body) != 2 or not isinstance(body[0], ast.Assign) or not isinstance(body[1], ast.Return):
            return None
        assignment = body[0]
        if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
            return None
        parameter = positional[0].arg
        if not self._filename_filter(assignment.value, parameter):
            return None
        returned = body[1].value
        if isinstance(returned, ast.BoolOp) and isinstance(returned.op, ast.Or) and len(returned.values) == 2:
            fallback = returned.values[1]
            if not self._filename_literal(fallback) and not self._filename_clock(
                unit, fallback
            ):
                return None
            returned = returned.values[0]
        if not isinstance(returned, ast.Name) or returned.id != assignment.targets[0].id:
            return None
        return parameter

    def _filename_runtime_is_stable(self, anchors):
        """No module that can share a process with ``anchors`` may patch
        names, builtins or the web framework the filename proof relies on."""
        key = frozenset(id(unit) for unit in anchors)
        stable = self.filename_runtime_stable.get(key)
        if stable is None:
            stable = all(
                self._unit_runtime_is_stable(unit)
                for unit in self.project.process_units(anchors)
            )
            self.filename_runtime_stable[key] = stable
        return stable

    def _unit_runtime_is_stable(self, unit):
        stable = self.unit_runtime_stable.get(id(unit))
        if stable is not None:
            return stable
        writes, computed = attribute_write_names(unit.tree)
        dynamic, rebound = unit.rebinding()
        stable = not (
            computed
            or dynamic
            or rebound
            or has_mock_api_patching(unit.tree)
            or writes & _RUNTIME_ATTRIBUTES
            or self._writes_project_namespace(unit)
        )
        for call, scope in unit.calls:
            if not stable:
                break
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in _FRAMEWORK_SETUP_CALLS
            ):
                stable = self._inert_framework_setup(unit, scope, call)
            elif self._external_call(unit, scope, call, {"fastapi.FastAPI"}):
                stable = not call.args and all(
                    keyword.arg in {"title", "description", "version"}
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                    for keyword in call.keywords
                )
        self.unit_runtime_stable[id(unit)] = stable
        return stable

    def _writes_project_namespace(self, unit):
        """An attribute write, delete or ``setattr`` on a project module or
        class (``import app; app.clean = ...``), or through ``sys.modules``."""
        for node in ast.walk(unit.tree):
            receiver = None
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                receiver = node.value
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
            ):
                if node.args:
                    receiver = node.args[0]
            if receiver is None or (
                isinstance(receiver, ast.Name) and receiver.id in {"self", "cls"}
            ):
                continue
            scope = unit.scope_of(node)
            for part in ast.walk(receiver):
                if isinstance(part, ast.Attribute) and part.attr == "modules":
                    owners = self.project.values(unit, scope, part)
                    if owners is None or any(
                        value.name == "sys.modules" for value in owners
                    ):
                        return True
            owners = self.project.values(unit, scope, receiver)
            if owners and any(value.kind in {"mod", "cls"} for value in owners):
                return True
        return False

    def _inert_framework_setup(self, unit, scope, call):
        """Framework CORS/compression/host middleware and static file mounts
        never call route functions, so they cannot change route arguments."""
        if call.func.attr == "add_middleware":
            component = _first_argument(call, "middleware_class")
            values = self.project.values(unit, scope, component)
            return bool(values) and all(
                value.kind == "ext"
                and value.name in _INERT_MIDDLEWARE
                and not self._external_rebound(value.name)
                for value in values
            )
        if call.func.attr != "mount":
            return False
        application = None
        if len(call.args) >= 2:
            application = call.args[1]
        for keyword in call.keywords:
            if keyword.arg == "app":
                application = keyword.value
        return isinstance(application, ast.Call) and self._external_call(
            unit, scope, application, _STATIC_APPS
        )

    def _clock_format(self, unit, scope, node):
        """The literal format of ``datetime.now()``-style ``strftime``, or None."""
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "strftime"
        ):
            return None
        if len(node.args) != 1 or node.keywords:
            return None
        text = node.args[0]
        if not isinstance(text, ast.Constant) or not isinstance(text.value, str):
            return None
        clock = node.func.value
        if not isinstance(clock, ast.Call) or clock.args or clock.keywords:
            return None
        if not self._external_call(unit, scope, clock, _CLOCK_CALLS):
            return None
        return text.value

    def _filename_clock(self, unit, node):
        """A clock rendered only with numeric directives and filename characters."""
        text = self._clock_format(unit, unit.scope_of(node), node)
        if text is None:
            return False
        index = 0
        while index < len(text):
            char = text[index]
            if char == "%":
                if (
                    index + 1 >= len(text)
                    or text[index + 1] not in _NUMERIC_CLOCK_DIRECTIVES
                ):
                    return False
                index += 2
                continue
            if not (char.isascii() and (char.isalnum() or char in "-_")):
                return False
            index += 1
        return True

    def _native_string(
        self, unit, scope, node, env=None, active=frozenset(), escapes=None
    ):
        """Only proved native strings, never a helper annotation by itself.

        With an ``escapes`` list, callers outside the project (a public
        function in an importable package) are recorded there for the caller
        to keep as unknown; every caller the project shows is still proved."""
        key = (id(node), id(scope))
        if key in active or len(active) >= 24:
            return False
        active = active | {key}
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if self._clock_format(unit, scope, node) is not None:
            return True
        if isinstance(node, ast.BoolOp):
            return all(
                self._native_string(unit, scope, part, env, active, escapes)
                for part in node.values
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {
                "strip",
                "lstrip",
                "rstrip",
                "lower",
                "upper",
                "replace",
            }:
                return (
                    self._native_string(
                        unit, scope, node.func.value, env, active, escapes
                    )
                    and all(
                        isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                        for arg in node.args
                    )
                    and not node.keywords
                )
        if isinstance(node, ast.Attribute):
            return self._validated_str_field(unit, scope, node, env, active, escapes)
        if not isinstance(node, ast.Name):
            return False
        found = unit.lookup(scope, node.id)
        if found is None:
            return False
        owner, binds = found
        binds = self._visible_binds(unit, owner, binds, node)
        if not binds:
            return False
        for bind in binds:
            if bind.kind == "assign":
                if not self._native_string(
                    unit, bind.scope, bind.value, env, active, escapes
                ):
                    return False
                continue
            if bind.kind != "param" or owner.kind != "function":
                return False
            fn, parameter = owner.node, bind.node
            if self._native_type_guard(unit, owner, node, binds):
                continue
            binding = _env_lookup(env, id(fn))
            if binding is not None and binding[0] is not None:
                site, parent_env = binding
                values = list(self.project.bind_argument(fn, site, parameter.arg))
                if not values or not all(
                    self._native_string(u, s, expr, parent_env, active, escapes)
                    for expr, u, s in values
                ):
                    return False
                continue
            # FastAPI validates a native str path/query parameter. Merely
            # annotating an arbitrary helper (or an unknown request model) is
            # not runtime type evidence. Reject custom decorators/dependencies.
            annotation = self.project.values(unit, owner, parameter.annotation)
            native_annotation = annotation and all(
                value.kind == "ext" and value.name == "builtins.str"
                for value in annotation
            )
            framework_escape = None
            if native_annotation:
                framework_escape = self._framework_route_escape(unit, fn)
            framework_parameter = framework_escape is not None
            default = _default_of(fn, parameter.arg)
            if default is not None and not (
                isinstance(default, ast.Constant) and isinstance(default.value, str)
            ):
                framework_parameter = False
            sites = self.project.call_sites(unit, fn)
            route_escape = None
            if framework_parameter:
                route_escape = framework_escape
            if (
                not self._hidden_callers(sites, route_escape, escapes)
                or len(sites.resolved) > _MAX_SITES
            ):
                return False
            if not framework_parameter and (sites.entries or not sites.resolved):
                return False
            for site in sites.resolved:
                values = list(self.project.bind_argument(fn, site, parameter.arg))
                if not values or not all(
                    self._native_string(u, s, expr, None, active, escapes)
                    for expr, u, s in values
                ):
                    return False
        return True

    @staticmethod
    def _hidden_callers(sites, route_escape, escapes):
        """Accept callers the project cannot show only when they are importers
        outside the project or calls on an unresolved receiver, and only when
        the caller keeps them as unknown evidence (as the tracer does)."""
        hidden = [step for step in sites.escapes if step != route_escape]
        if (
            not all(step.endswith(PUBLIC_IMPORTERS) for step in hidden)
            or len(sites.possible) > _MAX_SITES
        ):
            return False
        hidden.extend(
            _step(
                site.unit,
                site.call,
                f"the receiver of `{_describe(site.call)}` is not resolved",
            )
            for site in sites.possible
        )
        if not hidden:
            return True
        if escapes is None:
            return False
        escapes.extend(hidden)
        return True

    def _framework_route_escape(self, unit, fn):
        """The escape step of a plain FastAPI route decorator, or None."""
        decorators = fn.decorator_list
        if (
            len(decorators) != 1
            or self._external_rebound("builtins.str")
            or self._external_rebound("fastapi.FastAPI")
        ):
            return None
        decorator = decorators[0]
        if not isinstance(decorator, ast.Call) or not isinstance(
            decorator.func, ast.Attribute
        ):
            return None
        if decorator.func.attr not in _ROUTE_VERBS or len(decorator.args) != 1:
            return None
        if not isinstance(decorator.args[0], ast.Constant) or not isinstance(
            decorator.args[0].value, str
        ):
            return None
        if any(
            keyword.arg not in _INERT_ROUTE_OPTIONS for keyword in decorator.keywords
        ):
            return None
        applications = self.project.values(
            unit, unit.scope_of(decorator), decorator.func.value
        )
        if not applications or not all(
            value.kind == "extinst" and value.name == "fastapi.FastAPI"
            for value in applications
        ):
            return None
        return _step(
            unit,
            decorator,
            f"decorated with `{_describe(decorator.func)}`; the wrapper's callers are not visible",
        )

    def _validated_str_field(self, unit, scope, node, env, active, escapes):
        """``model.field`` of a request model whose field FastAPI validates as
        ``str`` (or None), on an instance only FastAPI or a no-argument
        constructor created."""
        if not isinstance(node.ctx, ast.Load) or not isinstance(node.value, ast.Name):
            return False
        models = self._validated_models(unit, scope, node.value, env, active, escapes)
        return bool(models) and all(
            self._plain_str_field(model, node.attr) for model in models
        )

    def _validated_models(self, unit, scope, expr, env, active, escapes):
        key = ("model", id(expr), id(scope))
        if key in active or len(active) >= 24:
            return None
        active = active | {key}
        if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):
            models = []
            for part in expr.values:
                found = self._validated_models(unit, scope, part, env, active, escapes)
                if found is None:
                    return None
                models.extend(found)
            return models
        if isinstance(expr, ast.Call):
            if expr.args or expr.keywords:
                return None
            values = self.project.values(unit, scope, expr.func)
            if not values or not all(value.kind == "cls" for value in values):
                return None
            return [value.node for value in values]
        if not isinstance(expr, ast.Name):
            return None
        found = unit.lookup(scope, expr.id)
        if found is None:
            return None
        owner, binds = found
        binds = self._visible_binds(unit, owner, binds, expr)
        if not binds:
            return None
        models = []
        for bind in binds:
            if bind.kind == "assign":
                inner = self._validated_models(
                    unit, bind.scope, bind.value, env, active, escapes
                )
            elif bind.kind == "param" and owner.kind == "function":
                inner = self._validated_model_parameter(
                    unit, owner, bind.node, env, active, escapes
                )
            else:
                return None
            if inner is None:
                return None
            models.extend(inner)
        return models

    def _validated_model_parameter(self, unit, owner, parameter, env, active, escapes):
        fn = owner.node
        binding = _env_lookup(env, id(fn))
        if binding is not None and binding[0] is not None:
            site, parent_env = binding
            return self._bound_models(
                fn, [site], parameter.arg, parent_env, active, escapes
            )
        sites = self.project.call_sites(unit, fn)
        if len(sites.resolved) > _MAX_SITES:
            return None
        route = self._framework_route_escape(unit, fn)
        models = []
        if route is not None:
            models = self._request_models(unit, owner, fn, parameter)
            if models is None:
                return None
        elif sites.entries or not sites.resolved:
            return None
        if not self._hidden_callers(sites, route, escapes):
            return None
        if not sites.resolved:
            return models
        direct = self._bound_models(
            fn, sites.resolved, parameter.arg, None, active, escapes
        )
        if direct is None:
            return None
        return models + direct

    def _bound_models(self, fn, sites, name, env, active, escapes):
        models = []
        for site in sites:
            values = list(self.project.bind_argument(fn, site, name))
            if not values:
                return None
            for expr, expr_unit, expr_scope in values:
                found = self._validated_models(
                    expr_unit, expr_scope, expr, env, active, escapes
                )
                if found is None:
                    return None
                models.extend(found)
        return models

    def _request_models(self, unit, owner, fn, parameter):
        """Model classes FastAPI builds for a JSON body parameter."""
        default = _default_of(fn, parameter.arg)
        if default is not None and not (
            isinstance(default, ast.Constant) and default.value is None
        ):
            if not isinstance(default, ast.Call) or not self._external_call(
                unit, unit.scope_of(default), default, _FASTAPI_BODIES
            ):
                return None
            arguments = [
                *default.args,
                *(keyword.value for keyword in default.keywords),
            ]
            if any(
                keyword.arg in {None, "default_factory"} for keyword in default.keywords
            ):
                return None
            if not all(isinstance(argument, ast.Constant) for argument in arguments):
                return None
            initial = _first_argument(default, "default")
            if (
                initial is not None
                and initial.value is not None
                and initial.value is not Ellipsis
            ):
                return None
        members = self._annotation_members(unit, owner, parameter.annotation)
        if not members:
            return None
        models = []
        for member in members:
            values = self.project.values(unit, owner, member)
            if not values or not all(
                value.kind == "cls" and self._plain_model(value.node)
                for value in values
            ):
                return None
            models.extend(value.node for value in values)
        return models

    def _annotation_members(self, unit, scope, annotation):
        """Non-None members of ``X``, ``X | None``, ``Optional[X]`` or ``Union[...]``."""
        if annotation is None:
            return None
        if isinstance(annotation, ast.Constant) and annotation.value is None:
            return []
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            left = self._annotation_members(unit, scope, annotation.left)
            right = self._annotation_members(unit, scope, annotation.right)
            if left is None or right is None:
                return None
            return left + right
        if isinstance(annotation, ast.Subscript):
            values = self.project.values(unit, scope, annotation.value)
            if not values or len(values) != 1:
                return None
            generic = next(iter(values))
            if generic.kind != "ext" or self._external_rebound(generic.name):
                return None
            items = [annotation.slice]
            if generic.name in _UNION_TYPES and isinstance(annotation.slice, ast.Tuple):
                items = list(annotation.slice.elts)
            elif (
                generic.name not in _OPTIONAL_TYPES and generic.name not in _UNION_TYPES
            ):
                return None
            members = []
            for item in items:
                found = self._annotation_members(unit, scope, item)
                if found is None:
                    return None
                members.extend(found)
            return members
        if isinstance(annotation, (ast.Name, ast.Attribute)):
            return [annotation]
        return None

    def _plain_model(self, cls_node, active=frozenset()):
        """A pydantic model class with only declared fields and a literal
        configuration: no methods, validators, decorators, metaclass or
        writes to the class that could replace validated values."""
        cached = self.plain_model_memo.get(id(cls_node))
        if cached is not None:
            return cached
        if id(cls_node) in active:
            return False
        info = self.project.class_info.get(id(cls_node))
        plain = (
            info is not None
            and not cls_node.decorator_list
            and not cls_node.keywords
            and len(cls_node.bases) == 1
        )
        if plain:
            unit, definer, scope = info
            values = self.project.values(unit, definer, cls_node.bases[0])
            plain = bool(values)
            for value in values or ():
                if value.kind == "ext":
                    plain = (
                        plain
                        and value.name in _PYDANTIC_MODELS
                        and not self._external_rebound(value.name)
                    )
                elif value.kind == "cls":
                    plain = plain and self._plain_model(
                        value.node, active | {id(cls_node)}
                    )
                else:
                    plain = False
            plain = plain and all(
                self._plain_model_statement(unit, scope, statement)
                for statement in cls_node.body
            )
            plain = plain and not self._class_written(cls_node)
        self.plain_model_memo[id(cls_node)] = plain
        return plain

    def _inert_model_annotation(self, unit, scope, node):
        """Every validated field must have a known, callback-free schema."""
        scalars = {
            "builtins.str",
            "builtins.int",
            "builtins.float",
            "builtins.bool",
            "builtins.bytes",
            "typing.Any",
            "typing_extensions.Any",
        }
        containers = {
            "builtins.list",
            "builtins.dict",
            "builtins.set",
            "builtins.tuple",
            "builtins.frozenset",
            "typing.List",
            "typing.Dict",
            "typing.Set",
            "typing.Tuple",
            "typing.FrozenSet",
            "typing.Sequence",
            "typing.Mapping",
            "typing.MutableMapping",
            "typing.MutableSequence",
            "collections.abc.Sequence",
            "collections.abc.Mapping",
        }
        if isinstance(node, ast.Constant):
            return node.value is None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._inert_model_annotation(
                unit, scope, node.left
            ) and self._inert_model_annotation(unit, scope, node.right)
        root = node.value if isinstance(node, ast.Subscript) else node
        values = self.project.values(unit, scope, root)
        if not values or not all(
            value.kind == "ext" and not self._external_rebound(value.name)
            for value in values
        ):
            return False
        names = {value.name for value in values}
        if not isinstance(node, ast.Subscript):
            return names <= scalars | containers
        items = (
            list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]
        )
        if names <= {"typing.Literal", "typing_extensions.Literal"}:
            return all(isinstance(item, ast.Constant) for item in items)
        if not names <= containers | _OPTIONAL_TYPES | _UNION_TYPES:
            return False
        return all(
            isinstance(item, ast.Constant)
            and item.value is Ellipsis
            or self._inert_model_annotation(unit, scope, item)
            for item in items
        )

    @staticmethod
    def _inert_model_default(node):
        if _constant_literal(node):
            return True
        return (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, (ast.USub, ast.UAdd))
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, (int, float))
        )

    def _plain_model_statement(self, unit, scope, statement):
        if isinstance(statement, ast.Pass):
            return True
        if isinstance(statement, ast.Expr):
            return isinstance(statement.value, ast.Constant) and isinstance(
                statement.value.value, str
            )
        if isinstance(statement, ast.AnnAssign):
            if not isinstance(statement.target, ast.Name) or not statement.simple:
                return False
            if not all(
                isinstance(part, _PLAIN_ANNOTATION_NODES)
                for part in ast.walk(statement.annotation)
            ):
                return False
            if not self._inert_model_annotation(unit, scope, statement.annotation):
                return False
            value = statement.value
            if value is None or self._inert_model_default(value):
                return True
            if not isinstance(value, ast.Call) or not self._external_call(
                unit, scope, value, _PYDANTIC_FIELDS
            ):
                return False
            if any(
                keyword.arg in {None, "default_factory"} for keyword in value.keywords
            ):
                return False
            arguments = [*value.args, *(keyword.value for keyword in value.keywords)]
            return all(self._inert_model_default(argument) for argument in arguments)
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(
                statement.targets[0], ast.Name
            ):
                return False
            if statement.targets[0].id != "model_config":
                return False
            value = statement.value
            if (
                not isinstance(value, ast.Call)
                or value.args
                or not self._external_call(unit, scope, value, _PYDANTIC_CONFIGS)
            ):
                return False
            return all(
                keyword.arg is not None and isinstance(keyword.value, ast.Constant)
                for keyword in value.keywords
            )
        return False

    def _model_local_function(self, value):
        if value.kind != "fn" or not isinstance(
            value.node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return False
        info = self.project.function_info.get(id(value.node))
        if info is None:
            return False
        unit, definer, _scope, _owner = info
        allowed = {"builtins.staticmethod", "builtins.classmethod"}
        return all(
            not isinstance(decorator, ast.Call)
            and self._external_call(
                unit, definer, ast.Call(func=decorator, args=[], keywords=[]), allowed
            )
            for decorator in value.node.decorator_list
        )

    def _model_transfer_context(self, unit, node, parent, parents):
        """Syntax that only transfers authority; opaque protocols are effects."""
        if parent is None:
            return True
        if isinstance(parent, ast.Attribute) and parent.value is node:
            return True
        if isinstance(parent, ast.Call):
            if parent.func is not node:
                return True
            targets = self.project.values(unit, unit.scope_of(node), node)
            return bool(targets) and all(
                self._model_local_function(value) for value in targets
            )
        if isinstance(parent, ast.keyword):
            return isinstance(parents.get(id(parent)), ast.Call)
        if isinstance(parent, ast.Assign) and parent.value is node:
            return unit.scope_of(parent).kind in {"function", "lambda"} and all(
                isinstance(target, ast.Name)
                and target.id not in self._declared_outer_names(unit.scope_of(parent))
                for target in parent.targets
            )
        if isinstance(parent, (ast.AnnAssign, ast.NamedExpr)) and parent.value is node:
            return (
                unit.scope_of(parent).kind in {"function", "lambda"}
                and isinstance(parent.target, ast.Name)
                and parent.target.id
                not in self._declared_outer_names(unit.scope_of(parent))
            )
        if isinstance(parent, (ast.arg, ast.AnnAssign)) and parent.annotation is node:
            return True
        if (
            isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
            and parent.returns is node
        ):
            return True
        if isinstance(parent, ast.ClassDef) and node in parent.bases:
            base_values = self.project.values(unit, unit.scope_of(node), node)
            if base_values and all(
                value.kind == "ext" and value.name in _PYDANTIC_MODELS
                for value in base_values
            ):
                return (
                    not parent.decorator_list
                    and not parent.keywords
                    and len(parent.bases) == 1
                )
            info = self.project.class_info.get(id(parent))
            return (
                bool(info)
                and not parent.decorator_list
                and not parent.keywords
                and len(parent.bases) == 1
                and all(
                    self._plain_model_statement(info[0], info[2], item)
                    for item in parent.body
                )
            )
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.BitOr):
            if not self._model_annotation_context(parent, parents):
                return False
            members = self._annotation_members(unit, unit.scope_of(parent), parent)
            return bool(members) and all(
                isinstance(member, (ast.Name, ast.Attribute))
                and bool(self.project.values(unit, unit.scope_of(member), member))
                and all(
                    value.kind == "cls"
                    and not value.node.decorator_list
                    and not value.node.keywords
                    or value.kind == "ext"
                    and value.name
                    in {
                        "builtins.str",
                        "builtins.int",
                        "builtins.float",
                        "builtins.bool",
                        "builtins.bytes",
                    }
                    for value in self.project.values(
                        unit, unit.scope_of(member), member
                    )
                )
                for member in members
            )
        if isinstance(parent, ast.Subscript):
            if not self._model_annotation_context(parent, parents):
                return False
            values = self.project.values(unit, unit.scope_of(parent), parent.value)
            return (
                parent.slice is node
                and bool(values)
                and all(
                    value.kind == "ext"
                    and value.name
                    in _OPTIONAL_TYPES
                    | _UNION_TYPES
                    | {
                        "builtins.list",
                        "builtins.tuple",
                        "builtins.dict",
                        "typing.List",
                        "typing.Tuple",
                        "typing.Dict",
                        "typing.Sequence",
                    }
                    and not self._external_rebound(value.name)
                    for value in values
                )
            )
        if isinstance(parent, ast.Compare):
            return all(
                isinstance(operator, (ast.Is, ast.IsNot)) for operator in parent.ops
            )
        if isinstance(parent, ast.UnaryOp):
            return isinstance(parent.op, ast.Not)
        if isinstance(parent, ast.Dict):
            return node in parent.values
        return isinstance(
            parent,
            (
                ast.BoolOp,
                ast.IfExp,
                ast.Await,
                ast.NamedExpr,
                ast.Return,
                ast.List,
                ast.Tuple,
                ast.Starred,
                ast.If,
                ast.While,
                ast.Assert,
                ast.Expr,
            ),
        )

    @staticmethod
    def _declared_outer_names(scope):
        return scope.globals | scope.nonlocals

    @staticmethod
    def _model_annotation_context(node, parents):
        current = node
        while current is not None:
            parent = parents.get(id(current))
            if (
                isinstance(parent, (ast.arg, ast.AnnAssign))
                and parent.annotation is current
            ):
                return True
            if (
                isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                and parent.returns is current
            ):
                return True
            if isinstance(parent, ast.stmt):
                return False
            current = parent
        return False

    @staticmethod
    def _model_api_authorities():
        return _PYDANTIC_MODELS | {
            "builtins",
            "__builtins__",
            "pydantic",
            "pydantic.main",
            "typing",
            "typing_extensions",
            "fastapi",
        }

    def _pydantic_instance_class(self, cls_node, active=frozenset()):
        if id(cls_node) in active:
            return False
        info = self.project.class_info.get(id(cls_node))
        if info is None:
            return False
        unit, definer, _scope = info
        for base in cls_node.bases:
            for value in self.project.values(unit, definer, base) or ():
                if value.kind == "ext" and value.name in _PYDANTIC_MODELS:
                    return True
                if value.kind == "cls" and self._pydantic_instance_class(
                    value.node, active | {id(cls_node)}
                ):
                    return True
        return False

    def _model_effects(self, cls_node):
        units = self._model_process_ids(cls_node)
        memo = getattr(self, "model_unit_effect_memo", None)
        if memo is None:
            memo = self.model_unit_effect_memo = {}
        domain_memo = getattr(self, "model_domain_effect_memo", None)
        if domain_memo is None:
            domain_memo = self.model_domain_effect_memo = {}
        if units not in domain_memo:
            effects = []
            for unit in self.project.units:
                if id(unit) not in units:
                    continue
                if id(unit) not in memo:
                    memo[id(unit)] = self._unit_model_effects(unit)
                effects.extend(memo[id(unit)])
            domain_memo[units] = tuple(effects)
        return domain_memo[units]

    def _unit_model_effects(self, unit):
        """Attribute writes and storage capabilities, without executing models.

        A namespace or an opaque operation receives the whole instance, so its
        possible writes are unrestricted. Known attribute protocols retain a
        literal field name; aliases resolve through the shared project graph.
        """
        effects = []
        writers = {
            "builtins.setattr",
            "builtins.delattr",
            "builtins.object.__setattr__",
            "builtins.object.__delattr__",
            "builtins.type.__setattr__",
            "builtins.type.__delattr__",
        }
        framework_decorators = {
            id(decorator)
            for fn in ast.walk(unit.tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and self._framework_route_escape(unit, fn) is not None
            for decorator in fn.decorator_list
        }
        parents = unit.parents_map()
        for node in ast.walk(unit.tree):
            self.model_effect_build_work = (
                getattr(self, "model_effect_build_work", 0) + 1
            )
            if self.model_effect_build_work > 1000000:
                self.model_effects_incomplete = True
                return tuple(effects)
            if isinstance(node, ast.expr) and not isinstance(
                getattr(node, "ctx", ast.Load()), (ast.Store, ast.Del)
            ):
                parent = parents.get(id(node))
                if not self._model_transfer_context(unit, node, parent, parents):
                    kind = True
                    if isinstance(parent, ast.Call) and parent.func is node:
                        kind = "constructor"
                    effects.append((unit, unit.scope_of(node), node, None, kind))
            if not isinstance(node, ast.Attribute):
                continue
            scope = unit.scope_of(node)
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                effects.append((unit, scope, node.value, node.attr, False))
            elif isinstance(node.ctx, ast.Load):
                owners = self.project.values(unit, scope, node.value)
                if owners and all(
                    value.kind == "ext"
                    and value.name in self._model_api_authorities() - _PYDANTIC_MODELS
                    for value in owners
                ):
                    continue
                parent = parents.get(id(node))
                readonly = (
                    node.attr in {"model_dump", "model_dump_json", "dict", "json"}
                    and isinstance(parent, ast.Call)
                    and parent.func is node
                    and all(
                        self._inert_model_default(argument) for argument in parent.args
                    )
                    and all(
                        keyword.arg is not None
                        and self._inert_model_default(keyword.value)
                        for keyword in parent.keywords
                    )
                )
                effects.append(
                    (
                        unit,
                        scope,
                        node.value,
                        node.attr,
                        "read" if readonly else True,
                    )
                )
        for call, scope in unit.calls:
            targets = self.project.values(unit, scope, call.func)
            if targets and all(
                target.kind == "ext" and target.name in writers for target in targets
            ):
                if (
                    len(call.args) >= 2
                    and not any(
                        isinstance(argument, ast.Starred) for argument in call.args
                    )
                    and not call.keywords
                ):
                    field = call.args[1]
                    name = None
                    if isinstance(field, ast.Constant) and isinstance(field.value, str):
                        name = field.value
                    effects.append((unit, scope, call.args[0], name, False))
                    continue
            readonly = targets and all(
                target.kind == "ext"
                and target.name in _HARMLESS_CALLS - {"builtins.getattr"}
                for target in targets
            )
            local = (
                targets
                and all(self._model_local_function(target) for target in targets)
                and not any(isinstance(arg, ast.Starred) for arg in call.args)
                and all(keyword.arg is not None for keyword in call.keywords)
            )
            if readonly or local:
                continue
            if id(call) in framework_decorators:
                continue
            for argument in [
                *call.args,
                *(keyword.value for keyword in call.keywords),
            ]:
                effects.append((unit, scope, argument, None, True))
        return tuple(effects)

    def _inert_instance_class(self, cls_node, active=frozenset()):
        """Only a known ordinary constructor can exclude a different model.

        A decorated class or an overridden constructor can return an instance
        of another class, so its apparent class identity is not exclusion proof.
        """
        if id(cls_node) in active:
            return False
        memo = getattr(self, "inert_model_class_memo", None)
        if memo is None:
            memo = self.inert_model_class_memo = {}
        if id(cls_node) in memo:
            return memo[id(cls_node)]
        memo[id(cls_node)] = False
        info = self.project.class_info.get(id(cls_node))
        if (
            info is None
            or cls_node.decorator_list
            or cls_node.keywords
            or len(cls_node.bases) > 1
        ):
            return False
        unit, definer, scope = info
        if not all(
            self._plain_model_statement(unit, scope, item) for item in cls_node.body
        ):
            return False
        for base in cls_node.bases:
            values = self.project.values(unit, definer, base)
            if not values:
                return False
            for value in values:
                if value.kind == "cls":
                    if not self._inert_instance_class(
                        value.node, active | {id(cls_node)}
                    ):
                        return False
                elif value.kind != "ext" or value.name not in _PYDANTIC_MODELS | {
                    "builtins.object"
                }:
                    return False
        process = self._model_process_ids(cls_node)
        for source, owner, receiver, name, capability in self._model_effects(cls_node):
            if id(source) not in process:
                continue
            if capability is True or not capability:
                owners = self.project.values(source, owner, receiver)
                if owners and any(
                    value.kind == "cls" and value.node is cls_node for value in owners
                ):
                    return False
        memo[id(cls_node)] = True
        return True

    @staticmethod
    def _merge_model_types(parts):
        classes = set()
        complete = bool(parts)
        for found, known in parts:
            classes.update(found)
            complete = complete and known
        return frozenset(classes), complete

    def _model_function_authorities(self, unit):
        memo = getattr(self, "model_function_authority_memo", None)
        if memo is None:
            memo = self.model_function_authority_memo = {}
        if id(unit) not in memo:
            authorities = {"builtins"}
            for binds in unit.module.binds.values():
                for bind in binds:
                    if bind.kind not in {"class", "import"}:
                        continue
                    for value in (
                        self.project.bind_values(unit, unit.module, bind, 0) or ()
                    ):
                        if value.kind == "cls" and self._pydantic_instance_class(
                            value.node
                        ):
                            authorities.add(value.node)
                        elif (
                            value.kind == "ext"
                            and value.name in self._model_api_authorities()
                        ):
                            authorities.add(value.name)
            memo[id(unit)] = frozenset(authorities)
        return memo[id(unit)]

    def _model_receiver_types(self, unit, scope, expr, active=frozenset()):
        if active:
            return self._model_receiver_type_facts(unit, scope, expr, active)
        memo = getattr(self, "model_type_memo", None)
        if memo is None:
            memo = self.model_type_memo = {}
        key = (id(unit), id(scope), id(expr))
        if key not in memo:
            result = self._model_receiver_type_facts(unit, scope, expr, active)
            if not result[1]:
                return result
            memo[key] = result
        return memo[key]

    def _model_receiver_type_facts(self, unit, scope, expr, active):
        """Possible instance/class capabilities, plus whether all are known.

        Unknown writes can reach any model. For an opaque escape we additionally
        require a model capability, following local arguments and containers.
        """
        self.model_type_work = getattr(self, "model_type_work", 0) + 1
        if self.model_type_work > 500000:
            self.model_effects_incomplete = True
            return frozenset(), False
        key = (id(expr), id(scope))
        if expr is None:
            return frozenset(), False
        if key in active:
            self.model_effects_incomplete = True
            return frozenset(), False
        if len(active) >= 24:
            self.model_effects_incomplete = True
            return frozenset(), False
        active = active | {key}
        values = self.project.values(unit, scope, expr)
        name_binding = (
            unit.lookup(scope, expr.id) if isinstance(expr, ast.Name) else None
        )
        follow_name = name_binding is not None and any(
            bind.kind in {"assign", "unpack", "param"} for bind in name_binding[1]
        )
        if (
            values
            and not follow_name
            and all(
                value.kind == "ext" and value.name in self._model_api_authorities()
                for value in values
            )
        ):
            return frozenset(value.name for value in values), False
        if (
            values
            and not follow_name
            and all(value.kind in {"cls", "inst"} for value in values)
        ):
            classes = frozenset(value.node for value in values)
            complete = all(self._inert_instance_class(value.node) for value in values)
            if not complete and isinstance(expr, ast.Call):
                returned = []
                for value in values:
                    if value.kind != "inst":
                        continue
                    for constructor in (
                        self.project.class_member(value.node, "__new__", False, 0) or ()
                    ):
                        if constructor.kind == "fn":
                            returned.extend(
                                self._model_receiver_types(
                                    constructor.unit,
                                    constructor.unit.scope_of(result),
                                    result,
                                    active,
                                )
                                for result in _returned_values(constructor.node)
                            )
                found, _known = self._merge_model_types(returned)
                classes = classes | found
            return classes, complete
        if values and not follow_name and all(value.kind == "fn" for value in values):
            captured = []
            for value in values:
                captured.append((self._model_function_authorities(value.unit), False))
                fn_scope = value.unit.function_scopes.get(id(value.node))
                if fn_scope is None:
                    continue
                for default in [
                    *value.node.args.defaults,
                    *(item for item in value.node.args.kw_defaults if item is not None),
                ]:
                    captured.append(
                        self._model_receiver_types(
                            value.unit, value.unit.scope_of(default), default, active
                        )
                    )
                annotations = [
                    argument.annotation
                    for argument in [
                        *value.node.args.posonlyargs,
                        *value.node.args.args,
                        *value.node.args.kwonlyargs,
                    ]
                    if argument.annotation is not None
                ]
                if getattr(value.node, "returns", None) is not None:
                    annotations.append(value.node.returns)
                for annotation in annotations:
                    captured.append(
                        self._model_receiver_types(
                            value.unit,
                            value.unit.scope_of(annotation),
                            annotation,
                            active,
                        )
                    )
                body = value.node.body
                if not isinstance(body, list):
                    body = [body]
                for statement in body:
                    for item in ast.walk(statement):
                        if not isinstance(item, ast.Name) or not isinstance(
                            item.ctx, ast.Load
                        ):
                            continue
                        binding = value.unit.lookup(value.unit.scope_of(item), item.id)
                        if (
                            binding is not None
                            and binding[0] is not fn_scope
                            and binding[0].kind in {"function", "lambda"}
                        ):
                            captured.append(
                                self._model_receiver_types(
                                    value.unit, value.unit.scope_of(item), item, active
                                )
                            )
            return self._merge_model_types(captured)
        if isinstance(expr, ast.Constant):
            return frozenset(), True
        if isinstance(expr, (ast.Starred, ast.Await, ast.NamedExpr)):
            return self._model_receiver_types(unit, scope, expr.value, active)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return self._merge_model_types(
                [
                    self._model_receiver_types(unit, scope, item, active)
                    for item in expr.elts
                ]
            )
        if isinstance(expr, ast.Dict):
            return self._merge_model_types(
                [
                    self._model_receiver_types(unit, scope, item, active)
                    for item in [*expr.keys, *expr.values]
                    if item is not None
                ]
            )
        if isinstance(expr, ast.Subscript):
            return self._model_receiver_types(unit, scope, expr.value, active)
        if isinstance(expr, ast.BoolOp):
            return self._merge_model_types(
                [
                    self._model_receiver_types(unit, scope, item, active)
                    for item in expr.values
                ]
            )
        if isinstance(expr, ast.IfExp):
            return self._merge_model_types(
                [
                    self._model_receiver_types(unit, scope, item, active)
                    for item in (expr.body, expr.orelse)
                ]
            )
        if isinstance(expr, ast.Call):
            targets = self.project.values(unit, scope, expr.func)
            if targets and all(
                target.kind == "fn"
                and isinstance(target.node, (ast.FunctionDef, ast.AsyncFunctionDef))
                for target in targets
            ):
                return self._merge_model_types(
                    [
                        self._model_receiver_types(
                            target.unit, target.unit.scope_of(value), value, active
                        )
                        for target in targets
                        for value in _returned_values(target.node)
                    ]
                )
        if isinstance(expr, ast.Name):
            found = unit.lookup(scope, expr.id)
            if found is None:
                return frozenset(), False
            owner, binds = found
            parts = []
            for bind in binds:
                if bind.kind in {"assign", "unpack"}:
                    parts.append(
                        self._model_receiver_types(unit, bind.scope, bind.value, active)
                    )
                elif bind.kind == "param" and owner.kind == "function":
                    members = self._annotation_members(
                        unit, owner, bind.node.annotation
                    )
                    classes = set()
                    for member in members or ():
                        for value in self.project.values(unit, owner, member) or ():
                            if value.kind == "cls":
                                classes.add(value.node)
                            elif (
                                value.kind == "ext"
                                and value.name in self._model_api_authorities()
                            ):
                                classes.add(value.name)
                    sites = self.project.call_sites(unit, owner.node)
                    parameters = []
                    if values and all(
                        value.kind in {"cls", "inst"} for value in values
                    ):
                        parameters.append(
                            (
                                frozenset(value.node for value in values),
                                all(
                                    self._inert_instance_class(value.node)
                                    for value in values
                                ),
                            )
                        )
                    if values and all(value.kind == "fn" for value in values):
                        for value in values:
                            parameters.append(
                                (self._model_function_authorities(value.unit), False)
                            )
                    for site in sites.resolved:
                        for argument, source, caller in self.project.bind_argument(
                            owner.node, site, bind.node.arg
                        ):
                            parameters.append(
                                self._model_receiver_types(
                                    source, caller, argument, active
                                )
                            )
                    if classes:
                        parameters.append(
                            (
                                frozenset(classes),
                                self._framework_route_escape(unit, owner.node)
                                is not None
                                and all(
                                    not isinstance(cls, str)
                                    and self._inert_instance_class(cls)
                                    for cls in classes
                                ),
                            )
                        )
                    parts.append(self._merge_model_types(parameters))
                else:
                    parts.append((frozenset(), False))
            return self._merge_model_types(parts)
        return frozenset(), False

    def _model_types_overlap(self, classes, cls_node, capability=False):
        if any(isinstance(candidate, str) for candidate in classes):
            return True
        if capability and any(
            self._pydantic_instance_class(candidate) for candidate in classes
        ):
            return True
        target = {id(base) for _unit, base in self.project.mro(cls_node)[0]}
        return any(
            target & {id(base) for _unit, base in self.project.mro(candidate)[0]}
            for candidate in classes
        )

    def _model_process_ids(self, cls_node):
        memo = getattr(self, "model_process_memo", None)
        if memo is None:
            memo = self.model_process_memo = {}
        unit = self.project.class_info[id(cls_node)][0]
        if id(unit) not in memo:
            memo[id(unit)] = frozenset(
                id(source) for source in self.project.process_units((unit,))
            )
        return memo[id(unit)]

    def _project_attribute_writes(self, cls_node):
        memo = getattr(self, "model_write_memo", None)
        if memo is None:
            memo = self.model_write_memo = {}
        if getattr(self, "model_effects_incomplete", False):
            return frozenset({None})
        if id(cls_node) in memo:
            return memo[id(cls_node)]
        effects = self._model_effects(cls_node)
        if getattr(self, "model_effects_incomplete", False):
            return frozenset({None})
        names = set()
        process = self._model_process_ids(cls_node)
        for unit, scope, receiver, name, capability in effects:
            if id(unit) not in process:
                continue
            classes, complete = self._model_receiver_types(unit, scope, receiver)
            if getattr(self, "model_effects_incomplete", False):
                names.add(None)
                break
            related = self._model_types_overlap(classes, cls_node, bool(capability))
            if capability:
                if not related:
                    continue
                if capability == "read" and complete:
                    continue
                if capability == "constructor":
                    values = self.project.values(unit, scope, receiver)
                    if values and all(
                        value.kind == "cls"
                        and not value.node.decorator_list
                        and not value.node.keywords
                        for value in values
                    ):
                        continue
                if (
                    name is not None
                    and all(not isinstance(candidate, str) for candidate in classes)
                    and all(
                        any(
                            isinstance(statement, ast.AnnAssign)
                            and isinstance(statement.target, ast.Name)
                            and statement.target.id == name
                            for _source, base in self.project.mro(candidate)[0]
                            for statement in base.body
                        )
                        for candidate in classes
                    )
                ):
                    continue
                names.add(None)
            elif related or not complete:
                names.add(name)
        memo[id(cls_node)] = frozenset(names)
        return memo[id(cls_node)]

    def _class_written(self, cls_node):
        writes = self._project_attribute_writes(cls_node)
        if None in writes or writes & _MODEL_HOOK_ATTRIBUTES:
            return True
        ancestors = {id(base) for _source, base in self.project.mro(cls_node)[0]}
        process = self._model_process_ids(cls_node)
        for source, scope, receiver, _name, capability in self._model_effects(cls_node):
            if id(source) not in process or capability:
                continue
            owners = self.project.values(source, scope, receiver)
            if owners and any(
                value.kind == "cls"
                and id(value.node) in ancestors
                or value.kind == "ext"
                and value.name in self._model_api_authorities()
                for value in owners
            ):
                return True
        return False

    def _plain_str_field(self, cls_node, attr):
        """``attr`` is declared as ``str``/``Optional[str]`` with a literal or
        ``Field`` default, and no code in the project assigns that attribute."""
        if (
            attr.startswith("_")
            or attr.startswith("model_")
            or not self._plain_model(cls_node)
        ):
            return False
        declaration = None
        owner_unit = None
        owner_scope = None
        for unit, candidate in self.project.mro(cls_node)[0]:
            for statement in candidate.body:
                if (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id == attr
                ):
                    declaration = statement
                    owner_unit = unit
                    owner_scope = self.project.class_info[id(candidate)][2]
                    break
            if declaration is not None:
                break
        if declaration is None or self._attribute_assigned(cls_node, attr):
            return False
        members = self._annotation_members(
            owner_unit, owner_scope, declaration.annotation
        )
        if not members or len(members) != 1:
            return False
        kinds = self.project.values(owner_unit, owner_scope, members[0])
        if not kinds or not all(
            value.kind == "ext" and value.name == "builtins.str" for value in kinds
        ):
            return False
        value = declaration.value
        if isinstance(value, ast.Call):
            value = _first_argument(value, "default")
        return value is None or (
            isinstance(value, ast.Constant)
            and (
                value.value is None
                or value.value is Ellipsis
                or isinstance(value.value, str)
            )
        )

    def _attribute_assigned(self, cls_node, attr):
        writes = self._project_attribute_writes(cls_node)
        return None in writes or attr in writes

    def _native_type_guard(self, unit, owner, use, binds):
        """A dominating exact type check; isinstance permits str overrides."""
        for statement in owner.node.body:
            if getattr(statement, "lineno", 0) >= use.lineno:
                break
            if not isinstance(statement, ast.If) or not self._guard_terminates(unit, owner, statement.body):
                continue
            test = statement.test
            if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.IsNot):
                continue
            call, expected = test.left, test.comparators[0]
            if not isinstance(call, ast.Call) or len(call.args) != 1 or call.keywords:
                continue
            if not isinstance(call.args[0], ast.Name) or call.args[0].id != use.id:
                continue
            if not self._external_call(unit, owner, call, {"builtins.type"}):
                continue
            values = self.project.values(unit, owner, expected)
            if not values or not all(value.kind == "ext" and value.name == "builtins.str" for value in values):
                continue
            if self._external_rebound("builtins.str"):
                continue
            if not any(
                bind.kind != "param" and statement.lineno <= getattr(bind.node, "lineno", 0) <= use.lineno
                for bind in binds
            ):
                return True
        return False

    def _filename_call(
        self,
        unit,
        scope,
        call,
        value,
        prebound=(),
        prebound_keywords=(),
        env=None,
        escapes=None,
    ):
        if not self.project.complete:
            return False
        fn = value.node
        info = self.project.function_info.get(id(fn))
        if info is None or not self._filename_runtime_is_stable((unit, info[0])):
            return False
        parameter = self._filename_body(info[0], fn)
        if parameter is None:
            return False
        site = _Site(
            unit,
            scope,
            call,
            [*prebound, *call.args],
            [*prebound_keywords, *call.keywords],
            value.bound,
            "call",
        )
        arguments = list(self.project.bind_argument(fn, site, parameter))
        return bool(arguments) and all(
            self._native_string(u, s, expr, env, frozenset(), escapes)
            for expr, u, s in arguments
        )

    def _filename_equality_guard(self, unit, scope, statement, name):
        """Hidden-caller steps (possibly none) when ``statement`` rejects
        ``name`` unless it equals a body-proven filename, else None."""
        test = statement.test
        if (
            not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.NotEq)
        ):
            return None
        for candidate, original in (
            (test.left, test.comparators[0]),
            (test.comparators[0], test.left),
        ):
            if not isinstance(original, ast.Name) or original.id != name:
                continue
            call = candidate
            if isinstance(candidate, ast.Name) and candidate.id != name:
                call = self._single_assigned_value(unit, scope, candidate, statement)
            if not isinstance(call, ast.Call):
                continue
            escapes = []
            if not self._native_string(
                unit, scope, original, None, frozenset(), escapes
            ):
                continue
            values = self.project.values(unit, scope, call.func)
            if values and all(
                value.kind == "fn"
                and self._filename_call(unit, scope, call, value, escapes=escapes)
                for value in values
            ):
                return tuple(dict.fromkeys(escapes))
        return None

    @staticmethod
    def _single_assigned_value(unit, scope, use, statement):
        """The value of a local assigned exactly once, unconditionally,
        before ``statement``."""
        found = unit.lookup(scope, use.id)
        if found is None:
            return None
        owner, binds = found
        if owner.kind != "function" or len(binds) != 1:
            return None
        bind = binds[0]
        if bind.kind != "assign" or not bind.top_level or bind.scope is not owner:
            return None
        if (
            not isinstance(bind.node, ast.Assign)
            or getattr(bind.node, "end_lineno", 0) >= statement.lineno
        ):
            return None
        return bind.value

    def _summary(self, fn, fn_unit):
        """Return provenance of ``fn`` once: parameters that reach a return
        stay placeholders (``parameter`` chains) for each call to fill in."""
        key = ("summary", id(fn))
        return self._memoized(self.summary_memo, key, lambda: self._summary_uncached(fn, fn_unit))

    def _summary_uncached(self, fn, fn_unit):
        env = (id(fn), None, None)
        returned = self.project.returned_values(fn)
        name = getattr(fn, "name", "lambda")
        if not returned:
            return _Facts.leaf(SAFE, _step(fn_unit, fn, f"`{name}` returns None"))
        facts = _Facts()
        for expr in returned:
            facts.add(self.trace(fn_unit, fn_unit.scope_of(expr), expr, env).then(
                _step(fn_unit, expr, f"`{name}` returns {_describe(expr)}")
            ))
        return facts


def _locate_operand(unit, location):
    line = location.get("line")
    col = location.get("col")
    end_line = location.get("end_line")
    end_col = location.get("end_col")
    for node in ast.walk(unit.tree):
        if not isinstance(node, ast.expr):
            continue
        if (
            getattr(node, "lineno", None) == line
            and getattr(node, "col_offset", None) == col
            and getattr(node, "end_lineno", None) == end_line
            and getattr(node, "end_col_offset", None) == end_col
        ):
            return node
    return None


def _sink_step(unit, finding, operand):
    rule = finding.get("rule_id")
    sink = {
        "SKY-D215": "filesystem path operation",
        "SKY-D324": "filesystem write",
        "SKY-D325": "filesystem read",
    }.get(rule, "filesystem path")
    return _step(unit, operand, f"path `{_describe(operand)}` reaches the {sink}")


def _strip_location(step):
    return re.sub(r"^\S+:\d+ ", "", step)


def _untrusted_message(finding, source):
    rule = finding.get("rule_id")
    message = str(finding.get("message") or "")
    if rule == "SKY-D215":
        served = re.search(r"(\w+)\(\) serves a path", message)
        where = "this filesystem path"
        if served:
            where = f"the path {served.group(1)}() serves"
        return (
            f"Possible path traversal: {source} reaches {where} through project "
            "callers with no containment check; resolve it and check it stays "
            "under the base directory."
        )
    if rule == "SKY-D324":
        return (
            f"Possible symlink-following write: {source} reaches this path through "
            "project callers; reject symlinks or open with O_NOFOLLOW and check containment."
        )
    if "unbounded" in message:
        return (
            f"Possible symlink-following or unbounded read: {source} reaches this "
            "path through project callers; require a regular in-root file and a size cap."
        )
    return (
        f"Possible symlink-following read: {source} reaches this path through "
        "project callers; require a regular in-root file."
    )


def _function_label(fn):
    return getattr(fn, "name", "<lambda>")


def _function_name(unit, operand):
    scope = unit.enclosing_function(operand)
    names = []
    while scope is not None and scope.kind != "module":
        if scope.kind in {"function", "class"}:
            names.append(getattr(scope.node, "name", "<lambda>"))
        scope = scope.parent
    names.reverse()
    return ".".join(names) or "<module>"


def _provenance_record(status, function, facts, project, limits):
    record = {
        "version": PROVENANCE_VERSION,
        "status": status,
        "function": function,
        "complete_project": bool(project.complete),
    }
    for kind in _Facts.KINDS:
        chains = facts.chains[kind]
        if chains and kind != PARAMETER:
            record[kind] = [list(chain) for chain in chains]
    if limits:
        record["limits"] = list(limits)
    return record


def _evidence(chain, finding):
    rule = finding.get("rule_id")
    sink = {
        "SKY-D215": "filesystem path operation",
        "SKY-D324": "filesystem write",
        "SKY-D325": "filesystem read",
    }.get(rule, "filesystem path")
    steps = [_strip_location(step) for step in chain]
    source = steps[0]
    return {
        "evidence_kind": "python_path_taint",
        "source": source,
        "sources": [source],
        "sink": sink,
        "path": [f"untrusted input from {source}", *steps[1:]],
        "guards_seen": [],
        "guards_missing": ["resolved-path containment check against a fixed base"],
        "analysis_complete": False,
    }


def _scan_root(scan_path, project_root):
    if project_root is not None:
        return Path(project_root), None, True
    paths = scan_path
    if not isinstance(paths, (list, tuple)):
        paths = [paths]
    resolved = []
    for item in paths:
        try:
            resolved.append(Path(item).resolve())
        except (OSError, RuntimeError, TypeError):
            return None, None, False
    if not resolved:
        return None, None, False
    if len(resolved) == 1 and resolved[0].is_dir():
        return resolved[0], None, False
    files = []
    for item in resolved:
        if item.is_dir():
            return Path(os.path.commonpath([str(path) for path in resolved])), None, False
        files.append(item)
    common = Path(os.path.commonpath([str(path.parent) for path in files]))
    return common, files, False


_CONVENTION_SOURCES = (
    re.compile(r"^route parameter `[^`]+` of `[^`]+` \(@(?:[\w]+\.)*(?:command|group|callback|argument|option)\)$"),
    re.compile(r"^request data `(?:request|req)\b"),
)
PATH_RULES_TRACED = frozenset({"SKY-D215", "SKY-D324", "SKY-D325"})


def _convention_finding(finding):
    """A path finding whose only sources are naming conventions that need
    project context: a ``@<name>.command`` decorator (a Click group or a chat
    bot?) or a parameter called ``request``/``req``."""
    if finding.get("rule_id") not in PATH_RULES_TRACED:
        return False
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("path_operand"), dict):
        return False
    evidence = metadata.get("security_evidence")
    if not isinstance(evidence, dict):
        return False
    sources = evidence.get("sources") or [evidence.get("source")]
    sources = [source for source in sources if source]
    if not sources:
        return False
    return all(
        isinstance(source, str) and any(pattern.match(source) for pattern in _CONVENTION_SOURCES)
        for source in sources
    )


def _unsourced_finding(finding):
    """A path finding with no source at all: an interpolated or derived path
    in a function without parameters, reported with empty evidence."""
    if finding.get("rule_id") not in PATH_RULES_TRACED:
        return False
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("path_operand"), dict):
        return False
    return not metadata.get("security_evidence") and not metadata.get("path_source")


def needs_provenance(finding):
    return (
        is_helper_parameter_finding(finding)
        or _convention_finding(finding)
        or _unsourced_finding(finding)
    )


def resolve_helper_parameter_findings(findings, *, scan_path, project_root, suppressed):
    """Findings with each helper-parameter path finding, and each one whose
    only source is a naming convention, classified by resolved callers.
    Untrusted and incomplete ones stay reported; safe and unknown ones move to
    ``suppressed`` with ``metadata.path_provenance``."""
    candidates = [finding for finding in findings if needs_provenance(finding)]
    if not candidates:
        return findings
    root, files, complete = _scan_root(scan_path, project_root)
    if root is None:
        return findings
    previous_limit = sys.getrecursionlimit()
    if previous_limit < _RECURSION_LIMIT:
        sys.setrecursionlimit(_RECURSION_LIMIT)
    try:
        return _resolve(findings, root, files, complete, suppressed)
    finally:
        sys.setrecursionlimit(previous_limit)


def _resolve(findings, root, files, complete, suppressed):
    project = _Project.load(root, files, complete)
    tracers = {}
    kept = []
    for finding in findings:
        if not needs_provenance(finding):
            kept.append(finding)
            continue
        try:
            verdict = _classify(project, tracers, finding)
        except (RecursionError, MemoryError, ValueError, TypeError, AttributeError, KeyError, IndexError) as error:
            verdict = _failed_verdict(finding, project, type(error).__name__)
        if verdict is None:
            kept.append(finding)
            continue
        status, record, chain = verdict
        updated = dict(finding)
        metadata = dict(updated.get("metadata") or {})
        metadata["path_provenance"] = record
        updated["metadata"] = metadata
        if status == UNTRUSTED:
            evidence = _evidence(chain, finding)
            metadata["path_source"] = RESOLVED_CALLER_SOURCE
            metadata["security_evidence"] = evidence
            updated["message"] = _untrusted_message(finding, evidence["source"])
            kept.append(updated)
            continue
        if status == INCOMPLETE:
            kept.append(updated)
            continue
        updated["category"] = "danger"
        if status == SAFE:
            updated["reason"] = SAFE_REASON
        else:
            updated["reason"] = UNKNOWN_REASON
        suppressed.append(updated)
    return kept


def _failed_verdict(finding, project, error):
    """An analysis error is not proof of safety: the finding stays reported."""
    facts = _Facts.leaf(
        INCOMPLETE,
        f"{finding.get('file')}:{finding.get('line')} caller analysis stopped with {error}",
    )
    record = _provenance_record(INCOMPLETE, str(finding.get("symbol") or ""), facts, project, [INCOMPLETE_NOTE])
    return INCOMPLETE, record, None


def _classify(project, tracers, finding):
    try:
        path = Path(str(finding.get("file", ""))).resolve()
    except (OSError, RuntimeError):
        return None
    unit = project.by_path.get(path)
    metadata = finding.get("metadata") or {}
    location = metadata.get("path_operand")
    limits = list(project.limits)
    operand = None
    if unit is not None and isinstance(location, dict):
        operand = _locate_operand(unit, location)
    if operand is None:
        facts = _Facts.leaf(UNKNOWN, f"{finding.get('file')}:{finding.get('line')} path operand is not located in the indexed source")
        return UNKNOWN, _provenance_record(UNKNOWN, str(finding.get("symbol") or ""), facts, project, limits), None
    rule = finding.get("rule_id")
    tracer = tracers.get(rule)
    if tracer is None:
        tracer = _Tracer(project, rule)
        tracers[rule] = tracer
    tracer.work = 0
    facts = tracer.trace(unit, unit.scope_of(operand), operand).then(_sink_step(unit, finding, operand))
    if tracer.work > _MAX_WORK:
        limits.append("analysis budget reached for this finding")
    if project.truncated:
        facts.add(_Facts.leaf(INCOMPLETE, "project index budget reached; files after it were not read"))
    status = UNKNOWN
    if facts.chains[UNTRUSTED]:
        status = UNTRUSTED
    elif facts.chains[INCOMPLETE]:
        status = INCOMPLETE
        limits.append(INCOMPLETE_NOTE)
    elif facts.chains[UNKNOWN] or facts.empty():
        status = UNKNOWN
    else:
        launch = ""
        if facts.chains[OPERATOR]:
            launch = project.launches_with_untrusted_arguments()
        if launch:
            facts.add(_Facts.leaf(UNKNOWN, launch).then("CLI arguments are not proven to come from the operator"))
            status = UNKNOWN
        elif project.complete:
            status = SAFE
        else:
            limits.append("the scan covers part of the project; callers outside it are not visible")
    if facts.empty():
        facts.add(_Facts.leaf(UNKNOWN, _sink_step(unit, finding, operand)))
    chain = None
    if facts.chains[UNTRUSTED]:
        chain = facts.chains[UNTRUSTED][0]
    record = _provenance_record(status, _function_name(unit, operand), facts, project, limits)
    return status, record, chain


_HTTP_REQUEST_FIELDS = frozenset(
    {
        "GET",
        "POST",
        "FILES",
        "COOKIES",
        "META",
        "args",
        "form",
        "files",
        "values",
        "json",
        "get_json",
        "data",
        "headers",
        "cookies",
        "query_params",
        "path_params",
        "match_info",
        "rel_url",
        "query",
        "body",
    }
)


def _reads_request_attributes(fn, name):
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr in _HTTP_REQUEST_FIELDS
            and isinstance(node.value, ast.Name)
            and node.value.id == name
        ):
            return True
    return False
