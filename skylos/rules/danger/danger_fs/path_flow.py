from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor, PATH_SANITIZERS
from skylos.rules.danger.danger_fs.pytest_paths import literal_path_parameters
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex


SYMLINK_WRITE_RULE = "SKY-D324"
SYMLINK_READ_RULE = "SKY-D325"
ARCHIVE_EXTRACTION_RULE = "SKY-D326"
OS_OPEN_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
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


def _call_mode(node, default="r"):
    mode = None
    if len(node.args) >= 2:
        mode = _string_value(node.args[1])
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


def _archive_call_name(node):
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in {"extract", "extractall"}:
        return None
    return node.func.attr


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


def _is_pytest_fixture_function(fn: ast.AST):
    for decorator in getattr(fn, "decorator_list", []) or []:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _expr_name(target) in {"pytest.fixture", "fixture"}:
            return True
    return False


class _PathFlowChecker(TaintVisitor):
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

    def __init__(self, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.path_like_stack = [{}]
        self.basename_sanitized_stack = [{}]
        self.symlink_sensitive_stack = [{}]
        self.os_open_write_flags_stack = [{}]
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

    def visit_Module(self, node):
        self.untrusted_sources = UntrustedSourceIndex(node)
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

    def _is_fixed_base_with_sanitized_name(self, node):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
            return False
        if not self._is_basename_sanitized_expr(node.right):
            return False
        return (
            self._is_path_like_expr(node.left)
            and not self.is_tainted(node.left)
            and not self._is_symlink_sensitive_expr(node.left)
        )

    def is_tainted(self, node):
        if _is_path_name_projection(node):
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
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
        return all(self._is_validated_name(name) for name in tainted_names)

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
        # File-serving helpers are only reported with a real untrusted source
        # (entry-point parameter, request.*, input(), argv, environment); a
        # wrapper that forwards its own parameter is not a finding.
        evidence = self._source_evidence(node, path_expr, sink)
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

    def _has_symlink_read_guard(self):
        safety = self._current_safety()
        path_guard = (
            safety["symlink_guard"]
            or safety["nofollow"]
            or safety["regular_file"]
            or safety["containment"]
        )
        return path_guard and (safety["bounded_read"] or safety["regular_file"])

    def _has_archive_guard(self):
        return self._current_safety()["archive_member_guard"]

    def _path_needs_symlink_protection(self, node):
        return (
            _is_interpolated_string(node)
            or self.is_tainted(node)
            or self._is_symlink_sensitive_expr(node)
        )

    def _os_open_uses_write_flags(self, node):
        flags = _bound_argument(node, 1, "flags")
        if flags is None:
            return False
        if _node_mentions(flags, OS_OPEN_WRITE_FLAGS):
            return True
        if isinstance(flags, ast.Name):
            return self._get_os_open_write_flags(flags.id)
        return False

    def _add_finding(self, node, rule_id, severity, message):
        key = (rule_id, getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": self._current_symbol(),
            }
        )

    def _source_evidence(self, node, path_expr, sink):
        return self.untrusted_sources.evidence(
            self._current_function(),
            path_expr,
            sink=sink,
            missing_guard="resolved-path containment check against a fixed base",
            evidence_kind="python_path_taint",
        )

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
        if evidence is not None:
            finding["metadata"] = {"security_evidence": evidence}
        self.findings.append(finding)

    def _flag_if_tainted_path(self, node, path_expr):
        is_interp = _is_interpolated_string(path_expr)
        is_tainted = self.is_tainted(path_expr)

        if is_interp or is_tainted:
            self._emit_path_traversal(
                node,
                path_expr,
                "Possible path traversal: tainted filesystem path",
                "filesystem path operation",
            )

    def _flag_symlink_write_if_unsafe(self, node, path_expr):
        if not self._path_needs_symlink_protection(path_expr):
            return
        if self._has_symlink_write_guard():
            return
        self._add_finding(
            node,
            SYMLINK_WRITE_RULE,
            "HIGH",
            "Possible symlink-following write on attacker-controlled path; reject symlinks or open with O_NOFOLLOW and containment checks.",
        )

    def _flag_symlink_read_if_unsafe(self, node, path_expr):
        if self._is_fixed_base_with_sanitized_name(path_expr):
            return
        if not self._path_needs_symlink_protection(path_expr):
            return
        if self._has_symlink_read_guard():
            return
        self._add_finding(
            node,
            SYMLINK_READ_RULE,
            "MEDIUM",
            "Possible symlink-following or unbounded read on attacker-controlled path; require a regular in-root file and a size cap.",
        )

    def _flag_archive_extract_if_unsafe(self, node):
        if self._has_archive_guard():
            return
        self._add_finding(
            node,
            ARCHIVE_EXTRACTION_RULE,
            "HIGH",
            "Unsafe archive extraction can write through traversal paths or symlink members; validate members before extraction.",
        )

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name(node)
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
        ):
            self._flag_if_tainted_path(node, node.func.value)

        if first_path is not None:
            self._flag_if_tainted_path(node, first_path)

        canonical = self._canonical_call_name(node)
        if canonical in FILE_RESPONSE_SINKS:
            self._flag_file_response(node, canonical)

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.PATHLIB_WRITE_METHODS:
                self._flag_symlink_write_if_unsafe(node, node.func.value)
            elif node.func.attr in self.PATHLIB_READ_METHODS:
                self._flag_symlink_read_if_unsafe(node, node.func.value)
            elif node.func.attr == "open":
                mode = _call_mode(node)
                if _mode_writes(mode):
                    self._flag_symlink_write_if_unsafe(node, node.func.value)
                else:
                    self._flag_symlink_read_if_unsafe(node, node.func.value)

        if qn == "open" and first_path is not None:
            mode = _call_mode(node)
            if _mode_writes(mode):
                self._flag_symlink_write_if_unsafe(node, first_path)
            else:
                self._flag_symlink_read_if_unsafe(node, first_path)

        if qn == "os.open" and first_path is not None:
            if (
                not _node_mentions(node, {"O_NOFOLLOW"})
                and not self._current_safety()["nofollow"]
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
