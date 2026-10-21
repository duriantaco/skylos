from __future__ import annotations
import ast
import re
import sys
from skylos.rules.danger.taint import TaintVisitor, PATH_SANITIZERS
from skylos.rules.danger.module_namespace import attribute_write_names
from skylos.rules.danger.danger_fs.closed_world import HELPER_PARAMETER_SOURCE
from skylos.rules.danger.danger_fs.pytest_paths import literal_path_parameters
from skylos.security.receiver_resolution import ReceiverResolver
from skylos.rules.danger.danger_fs.path_open_modes import PathOpenModes
from skylos.rules.danger.danger_fs.open_read_evidence import UpdateHandleReads
from skylos.rules.danger.untrusted_sources import (
    is_traversal_safe_value,
    UntrustedSourceIndex,
    entrypoint_decorator,
)


SYMLINK_WRITE_RULE = "SKY-D324"
SYMLINK_READ_RULE = "SKY-D325"
ARCHIVE_EXTRACTION_RULE = "SKY-D326"
OS_OPEN_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
OS_OPEN_EXCLUSIVE_FLAGS = {"O_CREAT", "O_EXCL"}
PYTEST_TMP_FIXTURE_NAMES = {"tmp_path", "tmpdir"}
FIRST_PATH_PARAMETERS = {
    "open": "file",
    "os.open": "path",
    "os.unlink": "path",
    "os.remove": "path",
    "os.mkdir": "path",
    "os.rmdir": "path",
    "os.makedirs": "name",
    "shutil.copy": "src",
    "shutil.copy2": "src",
    "shutil.copytree": "src",
    "shutil.move": "src",
    "shutil.rmtree": "path",
}


# Framework helpers that serve a file from a caller-supplied filesystem path.
# Value: (keyword name, position) of the argument that must not be tainted.
# Flask/Werkzeug ``send_from_directory`` joins its ``path`` argument with
# ``safe_join``, so only a tainted ``directory`` is a traversal there.
FILE_RESPONSE_SINKS = {
    "starlette.responses.FileResponse": ("path", 0),
    "fastapi.responses.FileResponse": ("path", 0),
    "flask.send_file": ("path_or_file", 0),
    "flask.helpers.send_file": ("path_or_file", 0),
    "werkzeug.utils.send_file": ("path_or_file", 0),
    "flask.send_from_directory": ("directory", 0),
    "flask.helpers.send_from_directory": ("directory", 0),
    "werkzeug.utils.send_from_directory": ("directory", 0),
}
# Calls whose result is a path, not an open file / buffer.
_PATH_PRODUCING_CALLS = frozenset(
    {
        "os.path.join",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.normpath",
        "os.path.expanduser",
        "os.fspath",
        "str",
        "Path",
        "PurePath",
        "PosixPath",
        "pathlib.Path",
        "pathlib.PurePath",
        "pathlib.PosixPath",
    }
)
_PATH_PRODUCING_METHODS = frozenset(
    {"joinpath", "resolve", "absolute", "expanduser", "with_name", "with_suffix",
     "format"}
)  # fmt: skip
# Calls that produce file objects / buffers rather than paths.
_FILE_OBJECT_CALLEES = frozenset(
    {"BytesIO", "StringIO", "open", "TemporaryFile", "NamedTemporaryFile",
     "SpooledTemporaryFile", "urlopen", "fdopen"}
)  # fmt: skip
# A containment check only means something on a normalized path: without it
# ``/base/../etc`` still "starts with" / "is relative to" ``/base``.
_NORMALIZER_CALLEES = frozenset({"resolve", "realpath", "abspath", "normpath"})
_TERMINATING_CALLEES = frozenset({"abort", "exit", "_exit"})
# Source labels (from ``untrusted_sources``) that name the program's operator
# rather than a remote party. Whoever runs a CLI or sets its environment
# already controls the filesystem it reads, so a path they pass is not a
# traversal or symlink attack surface.
_OPERATOR_SOURCE_MARKERS = (
    "os.environ",
    "os.getenv",
    "sys.argv",
    "CLI arguments",
    "CLI parameter",
)


class _HelperParameterEvidence(dict):
    """No source evidence: the path comes from a helper parameter whose
    callers may be in another module. The analyzer can prove otherwise for a
    complete repository scan (``closed_world``)."""


_FROM_PARAMETER = "the path comes from a function parameter whose callers are not visible"


def _helper_parameter_message(rule_id, message):
    """The finding rests on a parameter, not on input Skylos saw: say so
    instead of "untrusted" or "attacker-controlled"."""
    if rule_id == "SKY-D215":
        served = re.match(r"Possible path traversal: untrusted path served by (\w+)\(\)", message)
        where = f"{served.group(1)}() serves a path" if served else "a filesystem call uses a path"
        return (
            f"Possible path traversal: {where} from a function parameter whose "
            "callers are not visible, with no containment check; if a caller can "
            "pass user input, resolve it and check it stays under the base directory."
        )
    if rule_id == "SKY-D324":
        return (
            f"Possible symlink-following write: {_FROM_PARAMETER}; if a caller can "
            "pass user input, reject symlinks or open with O_NOFOLLOW and check containment."
        )
    if rule_id == "SKY-D325":
        if "unbounded" in message:
            return (
                f"Possible symlink-following or unbounded read: {_FROM_PARAMETER}; if a "
                "caller can pass user input, require a regular in-root file and a size cap."
            )
        return (
            f"Possible symlink-following read: {_FROM_PARAMETER}; if a caller can pass "
            "user input, require a regular in-root file."
        )
    return message


def _path_operand_location(path_expr):
    """Where the path operand sits, so a repository pass can find the same
    expression again (``path_provenance``)."""
    line = getattr(path_expr, "lineno", None)
    col = getattr(path_expr, "col_offset", None)
    if type(line) is not int or type(col) is not int:
        return None
    return {
        "line": line,
        "col": col,
        "end_line": getattr(path_expr, "end_lineno", line),
        "end_col": getattr(path_expr, "end_col_offset", col),
    }


def _mark_helper_parameter(finding, evidence, path_expr=None):
    location = _path_operand_location(path_expr)
    if location is not None:
        finding.setdefault("metadata", {})["path_operand"] = location
    if isinstance(evidence, _HelperParameterEvidence):
        finding.setdefault("metadata", {})["path_source"] = HELPER_PARAMETER_SOURCE
        finding["message"] = _helper_parameter_message(finding["rule_id"], finding["message"])


# Fix 3 support: a file handle read only in bounded chunks.
_STREAMING_CONSUMERS = frozenset({"shutil.copyfileobj", "hashlib.file_digest"})
_HARMLESS_HANDLE_METHODS = frozenset({"seek", "tell", "close", "readinto", "fileno"})


def _constant_size(node, constants):
    """A positive int known without running the program: a literal, constant
    arithmetic (``1 << 20``, ``64 * 1024``) or a module constant of one."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value if node.value > 0 else None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.LShift, ast.Mult, ast.Add)):
        left = _constant_size(node.left, constants)
        right = _constant_size(node.right, constants)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.LShift):
            return left << right if right < 64 else None
        return left * right if isinstance(node.op, ast.Mult) else left + right
    return None


def _module_constant_sizes(module):
    """Module names bound exactly once, at top level, to a constant size."""
    counts, values = {}, {}
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            counts[node.id] = counts.get(node.id, 0) + 1
    for statement in module.body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            size = _constant_size(statement.value, {})
            if size is not None:
                values[statement.targets[0].id] = size
    return {name: size for name, size in values.items() if counts.get(name) == 1}


def _handle_reads_bounded(target, body, constants):
    """Every use of the ``with`` handle ``target`` in ``body`` reads a bounded
    amount: ``read(<constant>)``, ``readinto``, a ``partial(fh.read,
    <constant>)``, or ``shutil.copyfileobj`` / ``hashlib.file_digest``. Any
    other use (``read()``, ``readline()``, line iteration, passing or
    returning the handle, rebinding it) may read the whole file."""
    if not isinstance(target, ast.Name):
        return False
    name = target.id
    parents = {}
    for statement in body:
        for parent in ast.walk(statement):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
    uses = [
        node
        for statement in body
        for node in ast.walk(statement)
        if isinstance(node, ast.Name) and node.id == name
    ]
    if not uses:
        return False
    for use in uses:
        if not isinstance(use.ctx, ast.Load):
            return False
        parent = parents.get(use)
        if isinstance(parent, ast.Attribute) and parent.value is use:
            call = parents.get(parent)
            if parent.attr in _HARMLESS_HANDLE_METHODS:
                continue
            if parent.attr != "read":
                return False
            if isinstance(call, ast.Call) and call.func is parent:
                if len(call.args) == 1 and not call.keywords and _constant_size(call.args[0], constants):
                    continue
                return False
            if (
                isinstance(call, ast.Call)
                and _qualified_name(call) in {"functools.partial", "partial"}
                and len(call.args) == 2
                and call.args[0] is parent
                and _constant_size(call.args[1], constants)
            ):
                continue
            return False
        if (
            isinstance(parent, ast.Call)
            and parent.args
            and parent.args[0] is use
            and _qualified_name(parent) in _STREAMING_CONSUMERS
        ):
            continue
        return False
    return True


def _callee_last(node):
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _names_in(node):
    return {sub.id for sub in ast.walk(node) if isinstance(sub, ast.Name)}


def _is_constant_collection(node):
    if isinstance(node, ast.Name):
        return node.id.isupper()
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return all(isinstance(elt, ast.Constant) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(isinstance(key, ast.Constant) for key in node.keys)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "keys"
        and not node.args
    ):
        return _is_constant_collection(node.func.value)
    return False


_CONTAINMENT_METHODS = frozenset({"is_relative_to", "relative_to", "startswith"})


def _unwrap_str_call(node):
    if isinstance(node, ast.Call) and _callee_last(node) == "str" and node.args:
        return node.args[0]
    return node


def _commonpath_elements(call):
    if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
        return list(call.args[0].elts)
    return []


def _allowlist_names(compare):
    """``name in ALLOWED`` / ``name not in {"a", "b"}`` vouches for ``name``."""
    if (
        len(compare.ops) == 1
        and isinstance(compare.ops[0], (ast.In, ast.NotIn))
        and isinstance(compare.left, ast.Name)
        and _is_constant_collection(compare.comparators[0])
    ):
        return {compare.left.id}
    return set()


def _test_is_negative(test):
    """True when the branch body runs if the check *failed*."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return True
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        return isinstance(test.ops[0], (ast.NotEq, ast.NotIn, ast.IsNot))
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return all(_test_is_negative(value) for value in test.values)
    return False


def _body_terminates(body):
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return _callee_last(last.value) in _TERMINATING_CALLEES
    return False


def _qualified_name(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(func, ast.Name):
        return func.id
    return None


def _is_interpolated_string(node):
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _expr_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _node_mentions(node, names):
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
        if isinstance(child, ast.Attribute) and child.attr in names:
            return True
        if isinstance(child, ast.Constant) and child.value in names:
            return True
    return False


def _string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_mode(node, default="r", *, bound_method=False):
    mode = None
    mode_position = 0 if bound_method else 1
    if len(node.args) > mode_position:
        mode = _string_value(node.args[mode_position])
    for kw in node.keywords or []:
        if kw.arg == "mode":
            mode = _string_value(kw.value)
            break
    return mode or default


def _bound_argument(node, position, keyword_name):
    if len(node.args) > position:
        return node.args[position]
    for keyword in node.keywords or []:
        if keyword.arg == keyword_name:
            return keyword.value
    return None


def _mode_writes(mode):
    return any(char in mode for char in ("w", "a", "x", "+"))


def _bit_or_leaves(node):
    """Operands of an ``A | B | C`` expression of plain names, or None."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _bit_or_leaves(node.left)
        right = _bit_or_leaves(node.right)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(node, (ast.Name, ast.Attribute)):
        return [node]
    return None


def _exclusive_create_modes(modes):
    """Every possible mode is ``x``: like ``O_CREAT | O_EXCL`` it creates a
    new file and fails on an existing one, a symlink included."""
    return bool(modes) and all("x" in mode for mode in modes)


def _archive_call_name(node):
    """``extract`` or ``extractall`` of an archive. ``ZipFile.extract`` and
    ``TarFile.extract`` require a member, so a call that cannot pass one
    (BeautifulSoup's ``tag.extract()``) is another API."""
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in {"extract", "extractall"}:
        return None
    if node.func.attr == "extract":
        if not node.args and not any(
            keyword.arg in {"member", None} for keyword in node.keywords
        ):
            return None
        # ZIP/TAR extraction supports these keyword names. An incompatible
        # keyword proves this is another API (for example image features).
        if any(
            keyword.arg is not None
            and keyword.arg
            not in {"member", "path", "pwd", "set_attrs", "numeric_owner", "filter"}
            for keyword in node.keywords
        ):
            return None
    return node.func.attr


def _unpack_filter_is_safe(node):
    """``shutil.unpack_archive(..., filter="data")`` (or ``"tar"``) rejects
    members that leave the destination or link outside it."""
    for keyword in node.keywords:
        if keyword.arg == "filter":
            return isinstance(keyword.value, ast.Constant) and keyword.value.value in {"data", "tar"}
    return False


def _is_path_constructor_call(node):
    if not isinstance(node, ast.Call):
        return False
    name = _expr_name(node.func)
    return name in {
        "Path",
        "PurePath",
        "PosixPath",
        "WindowsPath",
        "pathlib.Path",
        "pathlib.PurePath",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
    }


def _is_path_name_projection(node):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "name"
        and _is_path_constructor_call(node.value)
    )


def _is_probable_test_file(file_path):
    normalized = str(file_path).replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "/test/" in f"/{normalized}/"
        or "/tests/" in f"/{normalized}/"
    )


def _is_operator_source(label):
    return any(marker in label for marker in _OPERATOR_SOURCE_MARKERS)


def _is_pytest_fixture_function(fn: ast.AST):
    for decorator in getattr(fn, "decorator_list", []) or []:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _expr_name(target) in {"pytest.fixture", "fixture"}:
            return True
    return False


class _PathFlowChecker(TaintVisitor):
    resolve_sanitizer_imports = True
    PATHLIB_SINK_METHODS = {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "unlink",
        "mkdir",
        "rmdir",
        "rename",
        "replace",
    }
    PATHLIB_READ_METHODS = {"read_bytes", "read_text"}
    PATHLIB_WRITE_METHODS = {"write_bytes", "write_text"}
    # Reporting policy for D215/D324/D325: suppress only proven operator paths.
    # Unknown helper parameters may be supplied by a route in another module,
    # even when the file lives under tests/. Fixture and literal parameter
    # proofs live in the taint flow. Subclasses can exercise raw flow instead.
    REPORT_ONLY_UNTRUSTED_SOURCES = True

    def __init__(self, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.path_like_stack = [{}]
        self.basename_sanitized_stack = [{}]
        self.symlink_sensitive_stack = [{}]
        self.os_open_write_flags_stack = [{}]
        self.os_open_exclusive_stack = [{}]
        self.safety_stack = [
            {
                "symlink_guard": False,
                "nofollow": False,
                "regular_file": False,
                "bounded_read": False,
                "containment": False,
                "archive_member_guard": False,
            }
        ]
        self._emitted = set()
        self._literal_pytest_paths = {}
        self.import_aliases = {}
        self.untrusted_sources = UntrustedSourceIndex(None)
        self.normalized_stack = [set()]
        self.validated_stack = [set()]
        self.file_object_stack = [set()]
        self.branch_validated = []
        # ids of open() calls whose ``with`` handle is only read in bounded chunks
        self._bounded_opens = set()
        self._constant_sizes = {}
        self.receiver_resolver = None
        self._receiver_proofs = {}
        self.path_open_modes = None
        self.update_handle_reads = None
        self._attribute_writes = (frozenset(), True)

    def visit_Module(self, node):
        self.untrusted_sources = UntrustedSourceIndex(node, follow_local_calls=True)
        try:
            self._attribute_writes = attribute_write_names(node)
        except RecursionError:
            self._attribute_writes = (frozenset(), True)
        try:
            self.receiver_resolver = ReceiverResolver(node, self.file_path)
        except Exception:
            # Optional receiver evidence must never remove an existing warning.
            self.receiver_resolver = None
        try:
            self.path_open_modes = PathOpenModes(node, self.receiver_resolver)
        except Exception:
            self.path_open_modes = None
        self._constant_sizes = _module_constant_sizes(node)
        try:
            self.update_handle_reads = UpdateHandleReads(node, self.receiver_resolver)
        except Exception:
            self.update_handle_reads = None
        if _is_probable_test_file(self.file_path):
            self._literal_pytest_paths = literal_path_parameters(node)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                self.import_aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".", 1)[0]
                self.import_aliases[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for alias in node.names:
                if alias.name == "*":
                    continue
                self.import_aliases[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )
        self.generic_visit(node)

    def _canonical_call_name(self, node):
        qn = _qualified_name(node)
        if not qn:
            return None
        head, _, rest = qn.partition(".")
        base = self.import_aliases.get(head)
        if base is None:
            return None
        return f"{base}.{rest}" if rest else base

    def _push(self):
        super()._push()
        self.normalized_stack.append(set())
        self.validated_stack.append(set())
        self.file_object_stack.append(set())
        self.path_like_stack.append({})
        self.basename_sanitized_stack.append({})
        self.symlink_sensitive_stack.append({})
        self.os_open_write_flags_stack.append({})
        self.os_open_exclusive_stack.append({})
        self.safety_stack.append(
            {
                "symlink_guard": False,
                "nofollow": False,
                "regular_file": False,
                "bounded_read": False,
                "containment": False,
                "archive_member_guard": False,
            }
        )

    def _pop(self):
        super()._pop()
        for stack in (
            self.normalized_stack,
            self.validated_stack,
            self.file_object_stack,
        ):
            if len(stack) > 1:
                stack.pop()
        if self.path_like_stack:
            self.path_like_stack.pop()
        if self.basename_sanitized_stack:
            self.basename_sanitized_stack.pop()
        if self.symlink_sensitive_stack:
            self.symlink_sensitive_stack.pop()
        if self.os_open_write_flags_stack:
            self.os_open_write_flags_stack.pop()
        if self.os_open_exclusive_stack:
            self.os_open_exclusive_stack.pop()
        if self.safety_stack:
            self.safety_stack.pop()

    def _set_path_like(self, name, path_like):
        if not self.path_like_stack:
            self.path_like_stack.append({})
        self.path_like_stack[-1][name] = bool(path_like)

    def _get_path_like(self, name):
        for env in reversed(self.path_like_stack):
            if name in env:
                return env[name]
        return False

    def _set_basename_sanitized(self, name, basename_sanitized):
        if not self.basename_sanitized_stack:
            self.basename_sanitized_stack.append({})
        self.basename_sanitized_stack[-1][name] = bool(basename_sanitized)

    def _get_basename_sanitized(self, name):
        for env in reversed(self.basename_sanitized_stack):
            if name in env:
                return env[name]
        return False

    def _set_symlink_sensitive(self, name, symlink_sensitive):
        if not self.symlink_sensitive_stack:
            self.symlink_sensitive_stack.append({})
        self.symlink_sensitive_stack[-1][name] = bool(symlink_sensitive)

    def _get_symlink_sensitive(self, name):
        for env in reversed(self.symlink_sensitive_stack):
            if name in env:
                return env[name]
        return False

    def _set_os_open_write_flags(self, name, write_flags):
        if not self.os_open_write_flags_stack:
            self.os_open_write_flags_stack.append({})
        self.os_open_write_flags_stack[-1][name] = bool(write_flags)

    def _get_os_open_write_flags(self, name):
        for env in reversed(self.os_open_write_flags_stack):
            if name in env:
                return env[name]
        return False

    def _set_os_open_exclusive(self, name, exclusive):
        if not self.os_open_exclusive_stack:
            self.os_open_exclusive_stack.append({})
        self.os_open_exclusive_stack[-1][name] = bool(exclusive)

    def _get_os_open_exclusive(self, name):
        for env in reversed(self.os_open_exclusive_stack):
            if name in env:
                return env[name]
        return False

    def _taint_params(self, fn: ast.AST):
        super()._taint_params(fn)
        args = []
        if hasattr(fn, "args") and fn.args:
            args.extend(getattr(fn.args, "posonlyargs", []) or [])
            args.extend(getattr(fn.args, "args", []) or [])
            args.extend(getattr(fn.args, "kwonlyargs", []) or [])

            if fn.args.vararg:
                args.append(fn.args.vararg)
            if fn.args.kwarg:
                args.append(fn.args.kwarg)

        for arg in args:
            name = getattr(arg, "arg", None)
            if not name or name in {"self", "cls"}:
                continue
            if self._is_pytest_tmp_fixture_param(name, fn):
                self._set(name, False)
                self._set_path_like(name, True)
                self._set_basename_sanitized(name, False)
                self._set_symlink_sensitive(name, False)
            else:
                self._set_path_like(name, False)
                if name in self._literal_pytest_paths.get(fn, ()):
                    self._set(name, False)

    def _is_pytest_tmp_fixture_param(self, name: str, fn: ast.AST) -> bool:
        if name not in PYTEST_TMP_FIXTURE_NAMES:
            return False
        if not _is_probable_test_file(self.file_path):
            return False
        function_name = getattr(fn, "name", "")
        return function_name.startswith("test_") or _is_pytest_fixture_function(fn)

    def _is_path_like_expr(self, node):
        if _is_path_constructor_call(node):
            return True
        if isinstance(node, ast.Name):
            return self._get_path_like(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._is_path_like_expr(node.left) or self._is_path_like_expr(
                node.right
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {
                "absolute",
                "expanduser",
                "joinpath",
                "resolve",
                "with_name",
                "with_suffix",
            }:
                return self._is_path_like_expr(node.func.value)
        return False

    def _is_symlink_sensitive_expr(self, node):
        if node is None:
            return False
        if _is_path_name_projection(node):
            path_call = node.value
            return any(
                self.is_tainted(arg) or self._is_symlink_sensitive_expr(arg)
                for arg in path_call.args
            )
        if isinstance(node, ast.Name):
            return self._get_symlink_sensitive(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._is_symlink_sensitive_expr(
                node.left
            ) or self._is_symlink_sensitive_expr(node.right)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._is_symlink_sensitive_expr(node.value)
        if isinstance(node, ast.Call):
            if _is_path_constructor_call(node):
                return any(self._is_symlink_sensitive_expr(arg) for arg in node.args)
            if isinstance(node.func, ast.Attribute):
                return self._is_symlink_sensitive_expr(node.func.value)
        return False

    def _is_basename_sanitized_expr(self, node):
        if _is_path_name_projection(node):
            return True
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "name"
            and isinstance(node.value, ast.Call)
        ):
            qn = _qualified_name(node.value)
            if qn in {"PurePath", "pathlib.PurePath"}:
                return True
        if isinstance(node, ast.Name):
            return self._get_basename_sanitized(node.id)
        return False

    def is_tainted(self, node):
        if _is_path_name_projection(node) or is_traversal_safe_value(node):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        if isinstance(node, ast.Subscript):
            # A remote key can select a path from a mutable mapping. Even a
            # literal module dictionary may be changed through another module
            # or an indirect method call before this lookup.
            return super().is_tainted(node) or self.is_tainted(node.slice)
        if isinstance(node, ast.Call):
            qn = _qualified_name(node)
            if qn in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
                return True
        return super().is_tainted(node)

    def visit_Assign(self, node):
        self._record_safety_tokens(node)
        t = self.is_tainted(node.value)
        path_like = self._is_path_like_expr(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
                self._set_path_like(tgt.id, path_like)
                self._set_basename_sanitized(
                    tgt.id, self._is_basename_sanitized_expr(node.value)
                )
                self._set_symlink_sensitive(
                    tgt.id, self._is_symlink_sensitive_expr(node.value)
                )
                self._set_os_open_write_flags(
                    tgt.id, _node_mentions(node.value, OS_OPEN_WRITE_FLAGS)
                )
                self._set_os_open_exclusive(
                    tgt.id, self._exclusive_create_flags(node.value)
                )
        self.generic_visit(node)
        for tgt in node.targets:
            self._track_serving_facts(tgt, node.value)

    def visit_AnnAssign(self, node):
        self._record_safety_tokens(node)
        if node.value:
            t = self.is_tainted(node.value)
            path_like = self._is_path_like_expr(node.value)
            if isinstance(node.target, ast.Name):
                self._set(node.target.id, t)
                self._set_path_like(node.target.id, path_like)
                self._set_basename_sanitized(
                    node.target.id, self._is_basename_sanitized_expr(node.value)
                )
                self._set_symlink_sensitive(
                    node.target.id, self._is_symlink_sensitive_expr(node.value)
                )
                self._set_os_open_write_flags(
                    node.target.id, _node_mentions(node.value, OS_OPEN_WRITE_FLAGS)
                )
                self._set_os_open_exclusive(
                    node.target.id, self._exclusive_create_flags(node.value)
                )
        self.generic_visit(node)
        if node.value is not None:
            self._track_serving_facts(node.target, node.value)

    def visit_AugAssign(self, node):
        self._record_safety_tokens(node)
        self.generic_visit(node)

    def visit_If(self, node):
        self._record_safety_tokens(node.test)
        names = self._validation_names(node.test)
        if not names:
            self.generic_visit(node)
            return
        self.visit(node.test)
        if _test_is_negative(node.test):
            self._visit_block(node.body)
            self._visit_block(node.orelse, names)
            if _body_terminates(node.body):
                self._current_validated().update(names)
        else:
            self._visit_block(node.body, names)
            self._visit_block(node.orelse)

    def visit_Assert(self, node):
        names = self._validation_names(node.test)
        self.generic_visit(node)
        if names and not _test_is_negative(node.test):
            self._current_validated().update(names)

    def _visit_block(self, statements, validated=None):
        if validated:
            self.branch_validated.append(set(validated))
        try:
            for statement in statements:
                self.visit(statement)
        finally:
            if validated:
                self.branch_validated.pop()

    # -- containment / allowlist facts for file-serving sinks ---------------

    def _current_validated(self):
        return self.validated_stack[-1]

    def _is_validated_name(self, name):
        if name in self._current_validated():
            return True
        return any(name in names for names in self.branch_validated)

    def _is_normalized_expr(self, node):
        """The whole value is a normalized path, not just one part of it."""
        node = _unwrap_str_call(node)
        if isinstance(node, ast.Call):
            return _callee_last(node) in _NORMALIZER_CALLEES
        if isinstance(node, ast.Name):
            return node.id in self.normalized_stack[-1]
        return False

    def _track_serving_facts(self, target, value):
        if not isinstance(target, ast.Name):
            return
        name = target.id
        self._current_validated().discard(name)
        for names in self.branch_validated:
            names.discard(name)
        if self._is_normalized_expr(value):
            self.normalized_stack[-1].add(name)
        else:
            self.normalized_stack[-1].discard(name)
        if _callee_last(value) in _FILE_OBJECT_CALLEES:
            self.file_object_stack[-1].add(name)
        else:
            self.file_object_stack[-1].discard(name)

    def _validation_names(self, test):
        """Names a containment or allowlist check in ``test`` vouches for."""
        names = set()
        for sub in ast.walk(test):
            if isinstance(sub, ast.Call):
                names |= self._containment_call_names(sub)
            elif isinstance(sub, ast.Compare):
                names |= _allowlist_names(sub)
        return names

    def _containment_call_names(self, call):
        if _callee_last(call) == "commonpath":
            elements = _commonpath_elements(call)
            return {
                name
                for element in elements
                if self._is_normalized_expr(element)
                for name in _names_in(element)
            }
        if not isinstance(call.func, ast.Attribute):
            return set()
        if call.func.attr not in _CONTAINMENT_METHODS:
            return set()
        receiver = _unwrap_str_call(call.func.value)
        if not self._is_normalized_expr(receiver):
            return set()
        return _names_in(receiver)

    def _is_path_argument(self, node):
        if isinstance(node, ast.Name):
            return node.id not in self.file_object_stack[-1]
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.JoinedStr)):
            return True
        if isinstance(node, ast.BinOp):
            return isinstance(node.op, (ast.Div, ast.Add, ast.Mod))
        if isinstance(node, ast.Call):
            if _qualified_name(node) in _PATH_PRODUCING_CALLS:
                return True
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _PATH_PRODUCING_METHODS
            ):
                return True
            qn = _qualified_name(node) or ""
            if qn in PATH_SANITIZERS:
                return True
            # request.args.get("p"), os.environ.get("P"), os.getenv("P"), input()
            head = qn.split(".", 1)[0]
            return head in {"request", "req"} or qn in {
                "os.getenv",
                "os.environ.get",
                "input",
            }
        return False

    def _path_is_contained(self, node):
        tainted_names = [
            name
            for name in sorted(_names_in(node))
            if self._get(name) and not self._get_basename_sanitized(name)
        ]
        if not tainted_names:
            return False
        if not all(self._is_validated_name(name) for name in tainted_names):
            return False
        # A check on one path variable does not validate new request input
        # appended at the sink, even when the variable itself is contained.
        direct_sources = self.untrusted_sources.for_function(
            self._current_function()
        ).direct_sources_in(node)
        return not any(not _is_operator_source(source) for source in direct_sources)

    def _flag_file_response(self, node, canonical):
        keyword, position = FILE_RESPONSE_SINKS[canonical]
        path_expr = _bound_argument(node, position, keyword)
        if path_expr is None or not self._is_path_argument(path_expr):
            return
        if not self.is_tainted(path_expr):
            return
        if self._path_is_contained(path_expr):
            return
        sink_name = canonical.rsplit(".", 1)[-1]
        sink = f"filesystem path served by {sink_name}()"
        evidence = self._untrusted_path_evidence(path_expr, sink, traversal=True)
        if evidence is None:
            return
        self._emit_path_traversal(
            node,
            path_expr,
            f"Possible path traversal: untrusted path served by {sink_name}(); "
            "resolve it and check it stays under the base directory.",
            sink,
            evidence,
        )

    def _current_safety(self):
        if not self.safety_stack:
            self._push()
        return self.safety_stack[-1]

    def _mark_safety(self, key):
        self._current_safety()[key] = True

    def _record_safety_tokens(self, node):
        if _node_mentions(node, {"O_NOFOLLOW"}):
            self._mark_safety("nofollow")
        if _node_mentions(node, {"is_symlink", "readlink", "lstat", "S_ISLNK"}):
            self._mark_safety("symlink_guard")
        if _node_mentions(node, {"S_ISREG", "is_file", "fstat"}):
            self._mark_safety("regular_file")
        if _node_mentions(node, {"st_size", "MAX_BYTES", "MAX_FILE", "MAX_SIDE"}):
            self._mark_safety("bounded_read")
        if _node_mentions(node, {"resolve", "relative_to", "is_relative_to"}):
            self._mark_safety("containment")
        if _node_mentions(
            node,
            {
                "issym",
                "islnk",
                "is_symlink",
                "is_absolute",
                "normpath",
                "commonpath",
                "relative_to",
            },
        ):
            self._mark_safety("archive_member_guard")

    def _has_symlink_write_guard(self):
        safety = self._current_safety()
        return (
            safety["symlink_guard"]
            or safety["nofollow"]
            or safety["regular_file"]
            or safety["containment"]
        )

    def _has_symlink_read_path_guard(self):
        safety = self._current_safety()
        return (
            safety["symlink_guard"]
            or safety["nofollow"]
            or safety["regular_file"]
            or safety["containment"]
        )

    def _has_symlink_read_guard(self):
        safety = self._current_safety()
        return self._has_symlink_read_path_guard() and (
            safety["bounded_read"] or safety["regular_file"]
        )

    def _has_archive_guard(self):
        return self._current_safety()["archive_member_guard"]

    def _path_needs_symlink_protection(self, node):
        return (
            _is_interpolated_string(node)
            or self.is_tainted(node)
            or self._is_symlink_sensitive_expr(node)
        )

    def _locally_bound(self, name):
        return any(name in env for env in self.env_stack)

    def _os_flag(self, leaf):
        """The ``os`` module flag a name or attribute is, or None: an
        unshadowed ``os`` import, not a parameter or local of the same name,
        and no attribute write that could replace it."""
        flag = None
        if isinstance(leaf, ast.Attribute) and isinstance(leaf.value, ast.Name):
            if self.import_aliases.get(leaf.value.id) == "os" and not self._locally_bound(leaf.value.id):
                flag = leaf.attr
        elif isinstance(leaf, ast.Name):
            qualified = self.import_aliases.get(leaf.id, "")
            parts = qualified.split(".")
            if len(parts) == 2 and parts[0] == "os" and not self._locally_bound(leaf.id):
                flag = parts[1]
        if flag is None:
            return None
        names, computed = self._attribute_writes
        if computed or flag in names:
            return None
        return flag

    def _exclusive_create_flags(self, node):
        """``os.O_CREAT | os.O_EXCL``: the open fails on any existing final
        component, a symlink included, so it never follows one."""
        leaves = _bit_or_leaves(node)
        if leaves is None:
            return False
        flags = set()
        for leaf in leaves:
            flag = self._os_flag(leaf)
            if flag is not None:
                flags.add(flag)
        return OS_OPEN_EXCLUSIVE_FLAGS <= flags

    def _os_open_is_exclusive(self, node):
        flags = _bound_argument(node, 1, "flags")
        if flags is None:
            return False
        if self._exclusive_create_flags(flags):
            return True
        if isinstance(flags, ast.Name):
            return self._get_os_open_exclusive(flags.id)
        return False

    def _os_open_uses_write_flags(self, node):
        flags = _bound_argument(node, 1, "flags")
        if flags is None:
            return False
        if _node_mentions(flags, OS_OPEN_WRITE_FLAGS):
            return True
        if isinstance(flags, ast.Name):
            return self._get_os_open_write_flags(flags.id)
        return False

    def _add_finding(self, node, rule_id, severity, message, evidence=None, path_expr=None):
        key = (rule_id, getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if key in self._emitted:
            return
        self._emitted.add(key)
        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "file": str(self.file_path),
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": self._current_symbol(),
        }
        if evidence:
            finding["metadata"] = {"security_evidence": evidence}
        _mark_helper_parameter(finding, evidence, path_expr)
        self._attach_receiver_proof(node, finding)
        self.findings.append(finding)

    def _attach_receiver_proof(self, node, finding):
        proof = self._receiver_proofs.get(id(node))
        if proof is not None:
            finding.setdefault("metadata", {})["receiver_resolution"] = proof

    def _method_path_operand(self, node):
        """A proven wrapper's file argument differs from a Path receiver.

        Unknown implementations retain the old conservative check. Only a
        resolved non-Path implementation with no filesystem effect is skipped.
        """
        proof = self._receiver_proofs.get(id(node))
        if self.receiver_resolver is not None:
            try:
                proof = self.receiver_resolver.resolve_call(node)
            except Exception:
                proof = None
        if not isinstance(proof, dict):
            proof = {
                "status": "unknown",
                "effects": {"filesystem": "unknown", "database": "unknown"},
                "limitations": ["Receiver resolution unavailable."],
            }
        self._receiver_proofs[id(node)] = proof
        if proof.get("status") != "resolved" or not proof.get("receiver_is_non_path"):
            return node.func.value, True
        effect = proof.get("effects", {}).get("filesystem")
        if effect == "none":
            return None, True
        if effect == "wrapped_path_argument":
            index = proof.get("path_argument_index")
            if type(index) is int and 0 <= index < len(node.args):
                return node.args[index], False
            name = proof.get("path_argument_name")
            if isinstance(name, str):
                for keyword in node.keywords:
                    if keyword.arg == name:
                        return keyword.value, False
        return node.func.value, True

    def _source_evidence(self, node, path_expr, sink):
        return self.untrusted_sources.evidence(
            self._current_function(),
            path_expr,
            sink=sink,
            missing_guard="resolved-path containment check against a fixed base",
            evidence_kind="python_path_taint",
        )

    def _has_open_world_parameter(self, path_expr, facts):
        """A helper's parameters may have callers outside this source file."""
        function = self._current_function()
        if function is None or entrypoint_decorator(function):
            return False
        args = getattr(function, "args", None)
        if args is None:
            return False
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg:
            params.append(args.vararg)
        if args.kwarg:
            params.append(args.kwarg)
        params = [param for param in params if param.arg not in {"self", "cls"}]
        if not params:
            return False
        # A direct operator source is independent of unused helper parameters.
        # A derived name cannot establish that independence with this index.
        direct = facts.direct_sources_in(path_expr)
        if direct and all(_is_operator_source(source) for source in direct):
            used_params = {param.arg for param in params} & _names_in(path_expr)
            if not used_params:
                return False
        return True

    def _untrusted_path_evidence(self, path_expr, sink, *, traversal=False):
        """Evidence for an unsafe path; None only when its source is proven safe.

        Every function parameter is tainted for flow tracking, but a helper
        that opens the path it was handed may be called from a remote entry
        point in another module. Keep findings when the source is unknown;
        suppress only paths proven to come from the program operator."""
        evidence = self._source_evidence(None, path_expr, sink)
        if not self.REPORT_ONLY_UNTRUSTED_SOURCES:
            return evidence if evidence is not None else {}
        facts = self.untrusted_sources.for_function(self._current_function())
        all_sources = (
            facts.traversal_sources_in(path_expr)
            if traversal
            else facts.sources_in(path_expr)
        )
        remote_sources = [
            source for source in all_sources if not _is_operator_source(source)
        ]
        if remote_sources:
            if evidence is None:
                return {}
            evidence["sources"] = (
                remote_sources
                + [source for source in all_sources if _is_operator_source(source)]
            )[:4]
            if evidence["source"] != remote_sources[0]:
                evidence["source"] = remote_sources[0]
                evidence["path"] = [
                    f"untrusted input from {remote_sources[0]}",
                    f"reaches {sink}",
                ]
            return evidence
        if self._has_open_world_parameter(path_expr, facts):
            return _HelperParameterEvidence()
        if evidence is None:
            return {}
        return None

    def _emit_path_traversal(self, node, path_expr, message, sink, evidence=None):
        finding = {
            "rule_id": "SKY-D215",
            "severity": "HIGH",
            "message": message,
            "file": str(self.file_path),
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": self._current_symbol(),
        }
        if evidence is None:
            evidence = self._source_evidence(node, path_expr, sink)
        if evidence:
            finding["metadata"] = {"security_evidence": evidence}
        _mark_helper_parameter(finding, evidence, path_expr)
        self._attach_receiver_proof(node, finding)
        self.findings.append(finding)

    def _flag_if_tainted_path(self, node, path_expr):
        is_interp = _is_interpolated_string(path_expr)
        is_tainted = self.is_tainted(path_expr)

        if not (is_interp or is_tainted):
            return
        if self._path_is_contained(path_expr):
            return
        sink = "filesystem path operation"
        evidence = self._untrusted_path_evidence(path_expr, sink, traversal=True)
        if evidence is None:
            return
        self._emit_path_traversal(
            node,
            path_expr,
            "Possible path traversal: tainted filesystem path",
            sink,
            evidence,
        )

    def _flag_symlink_write_if_unsafe(self, node, path_expr):
        if not self._path_needs_symlink_protection(path_expr):
            return
        if self._has_symlink_write_guard():
            return
        evidence = self._untrusted_path_evidence(path_expr, "filesystem write")
        if evidence is None:
            return
        self._add_finding(
            node,
            SYMLINK_WRITE_RULE,
            "HIGH",
            "Possible symlink-following write on attacker-controlled path; reject symlinks or open with O_NOFOLLOW and containment checks.",
            evidence,
            path_expr,
        )

    def visit_With(self, node):
        self._record_bounded_handles(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node):
        self._record_bounded_handles(node)
        self.generic_visit(node)

    def _record_bounded_handles(self, node):
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and _handle_reads_bounded(
                item.optional_vars, node.body, self._constant_sizes
            ):
                self._bounded_opens.add(id(item.context_expr))

    def _flag_symlink_read_if_unsafe(self, node, path_expr):
        if not self._path_needs_symlink_protection(path_expr):
            return
        bounded = id(node) in self._bounded_opens
        if self._has_symlink_read_guard() or (
            bounded and self._has_symlink_read_path_guard()
        ):
            return
        evidence = self._untrusted_path_evidence(path_expr, "filesystem read")
        if evidence is None:
            return
        message = (
            "Possible symlink-following read on attacker-controlled path; require a regular in-root file."
            if bounded
            else "Possible symlink-following or unbounded read on attacker-controlled path; require a regular in-root file and a size cap."
        )
        self._add_finding(node, SYMLINK_READ_RULE, "MEDIUM", message, evidence, path_expr)

    def _flag_archive_extract_if_unsafe(self, node):
        if self._has_archive_guard():
            return
        self._add_finding(
            node,
            ARCHIVE_EXTRACTION_RULE,
            "HIGH",
            "Unsafe archive extraction can write through traversal paths or symlink members; validate members before extraction.",
        )

    def _flag_open_operations(self, node, path_expr, *, bound_method=False):
        modes = None
        if self.path_open_modes is not None:
            try:
                modes = self.path_open_modes.modes(node, bound_method=bound_method)
            except Exception:
                modes = None
        if _exclusive_create_modes(modes):
            return
        may_read = modes is None
        may_write = modes is None
        if modes is not None:
            literal_update_mode = "+" in _call_mode(node, bound_method=bound_method)
            for mode in modes:
                if "r" in mode and "+" not in mode:
                    may_read = True
                if "+" in mode:
                    # Unobserved reads do not prove a resolved name or
                    # expression is write-only. Keep its existing read check;
                    # literal update modes only add a demonstrated read.
                    if not literal_update_mode or self._update_handle_is_read(node):
                        may_read = True
                if _mode_writes(mode):
                    may_write = True
        if may_write:
            self._flag_symlink_write_if_unsafe(node, path_expr)
        if may_read:
            self._flag_symlink_read_if_unsafe(node, path_expr)

    def _update_handle_is_read(self, node):
        if self.update_handle_reads is None:
            return False
        try:
            return self.update_handle_reads.observed(node)
        except Exception:
            return False

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)
        method_sink = isinstance(node.func, ast.Attribute) and node.func.attr in {
            *self.PATHLIB_WRITE_METHODS, *self.PATHLIB_READ_METHODS, "open"
        }
        method_operand = None
        bound_path_method = True
        if method_sink:
            method_operand, bound_path_method = self._method_path_operand(node)
        archive_method = _archive_call_name(node)
        first_path = None
        if qn in FIRST_PATH_PARAMETERS:
            first_path = _bound_argument(node, 0, FIRST_PATH_PARAMETERS[qn])

        if archive_method:
            self._flag_archive_extract_if_unsafe(node)

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self.PATHLIB_SINK_METHODS
            and self._is_path_like_expr(node.func.value)
            and (not method_sink or method_operand is not None)
        ):
            self._flag_if_tainted_path(node, node.func.value)

        if first_path is not None:
            self._flag_if_tainted_path(node, first_path)

        canonical = self._canonical_call_name(node)
        if canonical == "shutil.unpack_archive" and not _unpack_filter_is_safe(node):
            self._flag_archive_extract_if_unsafe(node)
        if canonical in FILE_RESPONSE_SINKS:
            self._flag_file_response(node, canonical)

        if method_sink:
            operand = method_operand
            if operand is None:
                self._record_safety_tokens(node)
                self.generic_visit(node)
                return
            if node.func.attr in self.PATHLIB_WRITE_METHODS:
                self._flag_symlink_write_if_unsafe(node, operand)
            elif node.func.attr in self.PATHLIB_READ_METHODS:
                self._flag_symlink_read_if_unsafe(node, operand)
            elif node.func.attr == "open":
                self._flag_open_operations(
                    node, operand, bound_method=bound_path_method
                )

        if qn == "open" and first_path is not None:
            self._flag_open_operations(node, first_path)

        if qn == "os.open" and first_path is not None:
            if (
                not _node_mentions(node, {"O_NOFOLLOW"})
                and not self._current_safety()["nofollow"]
                and not self._os_open_is_exclusive(node)
            ):
                if self._os_open_uses_write_flags(node):
                    self._flag_symlink_write_if_unsafe(node, first_path)
                else:
                    self._flag_symlink_read_if_unsafe(node, first_path)

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "relative_to"
            and self._is_normalized_expr(node.func.value)
        ):
            # Path.relative_to raises ValueError outside the base.
            self._current_validated().update(_names_in(node.func.value))

        self._record_safety_tokens(node)
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _PathFlowChecker(file_path, findings, sanitizers=PATH_SANITIZERS)
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
