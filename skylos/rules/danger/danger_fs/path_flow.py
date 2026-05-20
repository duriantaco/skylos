from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor, PATH_SANITIZERS


SYMLINK_WRITE_RULE = "SKY-D324"
SYMLINK_READ_RULE = "SKY-D325"
ARCHIVE_EXTRACTION_RULE = "SKY-D326"
OS_OPEN_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}


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


class _PathFlowChecker(TaintVisitor):
    FILE_OPEN_FUNCS = {"open"}
    OS_FILE_FUNCS = {"open", "unlink", "remove", "mkdir", "rmdir", "makedirs"}
    SHUTIL_FUNCS = {"copy", "copy2", "copytree", "move", "rmtree"}
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

    def _push(self):
        super()._push()
        self.path_like_stack.append({})
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
        if self.path_like_stack:
            self.path_like_stack.pop()
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
            if name and name not in {"self", "cls"}:
                self._set_path_like(name, False)

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
                self._set_symlink_sensitive(
                    tgt.id, self._is_symlink_sensitive_expr(node.value)
                )
                self._set_os_open_write_flags(
                    tgt.id, _node_mentions(node.value, OS_OPEN_WRITE_FLAGS)
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._record_safety_tokens(node)
        if node.value:
            t = self.is_tainted(node.value)
            path_like = self._is_path_like_expr(node.value)
            if isinstance(node.target, ast.Name):
                self._set(node.target.id, t)
                self._set_path_like(node.target.id, path_like)
                self._set_symlink_sensitive(
                    node.target.id, self._is_symlink_sensitive_expr(node.value)
                )
                self._set_os_open_write_flags(
                    node.target.id, _node_mentions(node.value, OS_OPEN_WRITE_FLAGS)
                )
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._record_safety_tokens(node)
        self.generic_visit(node)

    def visit_If(self, node):
        self._record_safety_tokens(node.test)
        self.generic_visit(node)

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
        if len(node.args) < 2:
            return False
        flags = node.args[1]
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

    def _flag_if_tainted_path(self, node, path_expr):
        is_interp = _is_interpolated_string(path_expr)
        is_tainted = self.is_tainted(path_expr)

        if is_interp or is_tainted:
            self.findings.append(
                {
                    "rule_id": "SKY-D215",
                    "severity": "HIGH",
                    "message": "Possible path traversal: tainted filesystem path",
                    "file": str(self.file_path),
                    "line": node.lineno,
                    "col": node.col_offset,
                    "symbol": self._current_symbol(),
                }
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

        if archive_method:
            self._flag_archive_extract_if_unsafe(node)

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self.PATHLIB_SINK_METHODS
            and self._is_path_like_expr(node.func.value)
        ):
            self._flag_if_tainted_path(node, node.func.value)

        if qn and qn in self.FILE_OPEN_FUNCS and node.args:
            self._flag_if_tainted_path(node, node.args[0])

        if qn and "." in qn:
            mod, func = qn.split(".", 1)
            if mod == "os" and func in self.OS_FILE_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

            if mod == "shutil" and func in self.SHUTIL_FUNCS and node.args:
                self._flag_if_tainted_path(node, node.args[0])

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

        if qn and qn in self.FILE_OPEN_FUNCS and node.args:
            mode = _call_mode(node)
            if _mode_writes(mode):
                self._flag_symlink_write_if_unsafe(node, node.args[0])
            else:
                self._flag_symlink_read_if_unsafe(node, node.args[0])

        if qn == "os.open" and node.args:
            if not _node_mentions(node, {"O_NOFOLLOW"}) and not self._current_safety()[
                "nofollow"
            ]:
                if self._os_open_uses_write_flags(node):
                    self._flag_symlink_write_if_unsafe(node, node.args[0])
                else:
                    self._flag_symlink_read_if_unsafe(node, node.args[0])

        self._record_safety_tokens(node)
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _PathFlowChecker(file_path, findings, sanitizers=PATH_SANITIZERS)
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
