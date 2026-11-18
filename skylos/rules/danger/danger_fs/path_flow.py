from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path
from string import Formatter

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.danger.danger_fs.atomic_open_proof import AtomicOpenProofs
from skylos.rules.danger.danger_fs.closed_world import HELPER_PARAMETER_SOURCE
from skylos.rules.danger.danger_fs.filename_match import (
    filename_match_subject,
    names_when,
    native_text_name,
    validated_return,
)
from skylos.rules.danger.danger_fs.open_read_evidence import UpdateHandleReads
from skylos.rules.danger.danger_fs.path_open_modes import PathOpenModes
from skylos.rules.danger.danger_fs.prefix_separator import (
    AMBIGUOUS_BINDING,
    binding_value,
    bound_names,
    ends_with_separator,
    module_level_imports,
    scope_bindings,
)
from skylos.rules.danger.danger_fs.prefix_separator import (
    dotted as prefix_dotted,
)
from skylos.rules.danger.danger_fs.pytest_paths import literal_path_parameters
from skylos.rules.danger.import_proof import provider_binding_is_stable
from skylos.rules.danger.module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from skylos.rules.danger.taint import PATH_SANITIZERS, TaintVisitor
from skylos.rules.danger.untrusted_sources import (
    UntrustedSourceIndex,
    entrypoint_decorator,
    is_traversal_safe_value,
)
from skylos.security.receiver_resolution import ReceiverResolver

SYMLINK_WRITE_RULE = "SKY-D324"
SYMLINK_READ_RULE = "SKY-D325"
ARCHIVE_EXTRACTION_RULE = "SKY-D326"
ARCHIVE_CONSTRUCTORS = {
    "zipfile.ZipFile": "zip",
    "zipfile.PyZipFile": "zip",
    "tarfile.open": "tar",
    "tarfile.TarFile": "tar",
    "tarfile.TarFile.open": "tar",
}
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


class _OperatorContextEvidence(dict):
    """A process input is a candidate until its actual launch context is traced."""


_FROM_PARAMETER = (
    "the path comes from a function parameter whose callers are not visible"
)


def _helper_parameter_message(rule_id, message):
    """The finding rests on a parameter, not on input Skylos saw: say so
    instead of "untrusted" or "attacker-controlled"."""
    if rule_id == "SKY-D215":
        served = re.match(
            r"Possible path traversal: untrusted path served by (\w+)\(\)", message
        )
        where = (
            f"{served.group(1)}() serves a path"
            if served
            else "a filesystem call uses a path"
        )
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
        finding["message"] = _helper_parameter_message(
            finding["rule_id"], finding["message"]
        )
    elif isinstance(evidence, _OperatorContextEvidence):
        finding.setdefault("metadata", {})["path_source"] = "operator_context"
        finding["message"] = (
            "Filesystem path review: the operand comes from process input; "
            "its command-line, environment or working-directory launch context "
            "must be checked before treating it as trusted."
        )


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
    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.LShift, ast.Mult, ast.Add)
    ):
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
                if (
                    len(call.args) == 1
                    and not call.keywords
                    and _constant_size(call.args[0], constants)
                ):
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


def polarity_names(test, holds, call_names, compare_names=None):
    """Names checked by ``test`` when it evaluates to ``holds``: membership
    (``in``/``not in``) through ``compare_names``, true calls through
    ``call_names`` (also as a side of a holding ``==``, as in
    ``commonpath([p, base]) == base``), combined by the logic of ``not``,
    ``and`` and ``or``."""
    if compare_names is None:
        compare_names = _allowlist_names
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return polarity_names(test.operand, not holds, call_names, compare_names)
    if isinstance(test, ast.BoolOp):
        parts = [
            polarity_names(value, holds, call_names, compare_names)
            for value in test.values
        ]
        if not parts:
            return set()
        if isinstance(test.op, ast.And) == holds:
            return set().union(*parts)
        return set.intersection(*parts)
    if isinstance(test, ast.Compare):
        names = compare_names(test)
        if names:
            if isinstance(test.ops[0], ast.NotIn) == holds:
                return set()
            return set(names)
        if len(test.ops) != 1 or not isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
            return set()
        if isinstance(test.ops[0], ast.Eq) != holds:
            return set()
        found = set()
        for side in (test.left, test.comparators[0]):
            for part in ast.walk(side):
                if isinstance(part, ast.Call):
                    found |= set(call_names(part))
        return found
    if isinstance(test, ast.Call) and holds:
        return set(call_names(test))
    return set()


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


def _class_method_spans(module):
    spans = []
    for node in ast.walk(module):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = {
            item.name
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        bases = tuple(_expr_name(base) or "" for base in node.bases)
        spans.append(
            (node.lineno, getattr(node, "end_lineno", node.lineno), methods, bases)
        )
    return tuple(spans)


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
            return isinstance(keyword.value, ast.Constant) and keyword.value.value in {
                "data",
                "tar",
            }
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
        self.archive_kind_stack = [{}]
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
        self.atomic_open_proofs = None
        self._native_open_refs = frozenset()
        self._native_getattr_refs = frozenset()
        self.update_handle_reads = None
        self._attribute_writes = (frozenset(), True)
        self._class_methods = ()
        self._non_archive_imports_uncertain = True
        self._import_parents = {}
        self._builtin_string_refs = frozenset()
        self._path_parents = {}
        self._module_rebound = frozenset()
        self._module_bindings = {}
        self._module_import_aliases = {}
        self._global_names = frozenset()
        self._function_bindings = {}
        self._function_import_aliases = {}
        self._module_functions = {}
        self._filename_validators = {}

    def visit_Module(self, node):
        self.untrusted_sources = UntrustedSourceIndex(node, follow_local_calls=True)
        self._builtin_string_refs = builtin_references(node, {"str"})
        self._native_open_refs = builtin_references(node, {"open"})
        self._native_getattr_refs = builtin_references(node, {"getattr"})
        self._module_rebound = frozenset(bound_names(node))
        self._module_bindings = scope_bindings(node)
        self._module_import_aliases = module_level_imports(node)
        self._module_functions = {
            statement.name: statement
            for statement in node.body
            if isinstance(statement, ast.FunctionDef)
        }
        self._filename_validators = {}
        self._global_names = frozenset(
            name
            for item in ast.walk(node)
            if isinstance(item, ast.Global)
            for name in item.names
        )
        self._import_parents = {
            id(child): parent
            for parent in ast.walk(node)
            for child in ast.iter_child_nodes(parent)
        }
        self._path_parents = self._import_parents
        self._non_archive_imports_uncertain = module_rebinding(
            node, module_name_for(self.file_path)
        )[0] or has_mock_api_patching(node)
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
        try:
            self.atomic_open_proofs = AtomicOpenProofs(
                node, self.path_open_modes, self._native_atomic_provider
            )
        except Exception:
            self.atomic_open_proofs = None
        self._constant_sizes = _module_constant_sizes(node)
        self._class_methods = _class_method_spans(node)
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
        self.archive_kind_stack.append({})
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
        if self.archive_kind_stack:
            self.archive_kind_stack.pop()
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

    def _set_archive_kind(self, name, kind):
        if not self.archive_kind_stack:
            self.archive_kind_stack.append({})
        self.archive_kind_stack[-1][name] = kind

    def _archive_kind(self, expr):
        """``zip`` or ``tar`` when ``expr`` is built by the standard archive
        constructors, directly or through a local binding; otherwise None."""
        if isinstance(expr, ast.Name):
            for env in reversed(self.archive_kind_stack):
                if expr.id in env:
                    return env[expr.id]
            return None
        if not isinstance(expr, ast.Call):
            return None
        return ARCHIVE_CONSTRUCTORS.get(self._canonical_call_name(expr) or "")

    def _non_archive_import_scope_supported(self, node):
        child = node
        current = self._import_parents.get(id(child))
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return child in current.body
            if isinstance(
                current,
                (
                    ast.ClassDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                return False
            child, current = current, self._import_parents.get(id(current))
        return True

    def _archive_call_target(self, node):
        """Whose ``extract``/``extractall`` this is: ``zip``, ``tar``,
        ``project`` (a method the project defines) or ``unknown``."""
        # OpenTelemetry extracts a tracing context, not archive members. The
        # exemption needs the imported API and rejects rebinding/monkeypatching.
        writes, computed = self._attribute_writes
        if (
            node.func.attr == "extract"
            and self._non_archive_import_scope_supported(node)
            and not self._non_archive_imports_uncertain
            and not computed
            and "extract" not in writes
            and self.untrusted_sources.resolved_import(
                self._current_function(), _qualified_name(node) or ""
            )
            == "opentelemetry.propagate.extract"
        ):
            return "project"
        kind = self._archive_kind(node.func.value)
        if kind:
            return kind
        if self._calls_own_class_method(node):
            return "project"
        proof = self._receiver_proof(node)
        if proof.get("status") == "resolved" and proof.get("file"):
            return "project"
        return "unknown"

    def _calls_own_class_method(self, node):
        """``self.extract(...)`` inside a class that defines ``extract`` and
        does not inherit from an archive class."""
        receiver = node.func.value
        if not (isinstance(receiver, ast.Name) and receiver.id in ("self", "cls")):
            return False
        line = getattr(node, "lineno", 0)
        owner = None
        for start, end, methods, bases in self._class_methods:
            if start <= line <= end and (owner is None or start > owner[0]):
                owner = (start, end, methods, bases)
        if owner is None or node.func.attr not in owner[2]:
            return False
        return not any(base.endswith(("TarFile", "ZipFile")) for base in owner[3])

    def _archive_extraction_is_reportable(self, node):
        """``zipfile`` strips absolute paths and ``..`` from member names and
        never creates links, and a project's own ``extract`` method is not
        archive extraction. A tar archive or an unresolved receiver without
        a safe ``filter`` can write outside the destination."""
        target = self._archive_call_target(node)
        if target in ("zip", "project"):
            return False
        return not _unpack_filter_is_safe(node)

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

    def _is_sanitizer_call(self, node):
        if not super()._is_sanitizer_call(node):
            return self._is_project_containment_call(node)
        name = self.untrusted_sources.resolved_import(
            self._current_function(), _qualified_name(node)
        )
        if name and name.endswith(".safe_join"):
            # safe_join constrains the suffix to its directory. It cannot
            # make a request-selected base directory safe.
            if any(kw.arg is None for kw in node.keywords):
                return False
            base = _bound_argument(node, 0, "directory")
            return base is not None and not self.is_tainted(base)
        return True

    def _is_project_containment_call(self, node):
        """A call to a project function whose body proves every path it
        returns is contained (or does not carry the tainted arguments)."""
        if not isinstance(node, ast.Call) or self.untrusted_sources is None:
            return False
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            return False
        if not any(self.is_tainted(arg) for arg in node.args) and not any(
            self.is_tainted(keyword.value) for keyword in node.keywords
        ):
            return False
        cache = self.__dict__.setdefault("_project_function_cache", {})
        key = (id(node), id(self._current_function()))
        if key not in cache:
            cache[key] = self._project_function(node)
        located = cache[key]
        if located is None:
            return False
        file_path, target = located
        parameters = [
            argument.arg for argument in (*target.args.posonlyargs, *target.args.args)
        ]
        known = set(_function_arguments(target))
        tainted = set()
        for index, arg in enumerate(node.args):
            if index >= len(parameters):
                return False
            if self.is_tainted(arg):
                tainted.add(parameters[index])
        for keyword in node.keywords:
            if keyword.arg not in known:
                return False
            if self.is_tainted(keyword.value):
                tainted.add(keyword.arg)
        if not tainted:
            return False
        return _prove_containment(
            file_path,
            target.name,
            frozenset(tainted),
            getattr(self, "project_root", None),
        )

    def _project_function(self, node):
        """(file, def) for a call to a unique module-level function of this
        module or of a project module it imports."""
        module = getattr(self.untrusted_sources, "module", None)
        dotted = _qualified_name(node)
        if not dotted or not _helper_namespace_is_stable(
            module, dotted, self.file_path
        ):
            return None
        head = dotted.split(".", 1)[0]
        # A module definition does not identify a caller's local parameter,
        # assignment or enclosing closure binding with the same spelling.
        if any(head in scope_bindings(scope) for scope in self._function_stack):
            return None
        if isinstance(node.func, ast.Name) and module is not None:
            local = _unique_module_function(module, node.func.id, self.file_path)
            if local is not None:
                return self.file_path, local
        if not dotted or not self._import_names_are_stable(dotted):
            return None
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), dotted
        )
        if not resolved or "." not in resolved:
            return None
        if not _helper_namespace_is_stable(module, resolved, self.file_path):
            return None
        module_name, _, function_name = resolved.rpartition(".")
        file_path = _module_file(getattr(self, "project_root", None), module_name)
        if file_path is None:
            return None
        tree = _parsed_module(file_path, getattr(self, "project_root", None))
        target = (
            _unique_module_function(tree, function_name, file_path)
            if tree is not None
            else None
        )
        return (file_path, target) if target is not None else None

    def is_tainted(self, node):
        if _is_path_name_projection(node) or is_traversal_safe_value(node):
            return False
        if isinstance(node, ast.Call) and self._is_filename_validator_call(node):
            return False
        # Process inputs remain candidates until repository provenance checks
        # their launcher. stdin also needs its existing application-context
        # check rather than the local visitor's operator assumption.
        sources = self.untrusted_sources.for_function(
            self._current_function()
        ).sources_in(node)
        if any(
            "sys.stdin" in source or _is_operator_source(source) for source in sources
        ):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            # A request model may be selected with ``payload or Default()``.
            # Losing that arm here removes the sink before provenance can
            # check the model's actual callers and string-domain guarantees.
            return any(self.is_tainted(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
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
        archive_kind = self._archive_kind(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._set(tgt.id, t)
                self._set_path_like(tgt.id, path_like)
                self._set_archive_kind(tgt.id, archive_kind)
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
        when_true = self._validation_names(node.test, True)
        when_false = self._validation_names(node.test, False)
        if not when_true and not when_false:
            self.generic_visit(node)
            self._clear_filename_matched(node)
            return
        self.visit(node.test)
        self._visit_block(node.body, when_true)
        self._visit_block(node.orelse, when_false)
        if when_false and _body_terminates(node.body):
            self._current_validated().update(when_false)
        self._clear_filename_matched(node)

    def _clear_filename_matched(self, node):
        """After a top-level ``if`` that rejects every value but one made of
        filename characters, that name cannot carry a separator or dot."""
        function = self._current_function()
        if (
            function is None
            or node.orelse
            or not any(statement is node for statement in function.body)
            or not _body_terminates(node.body)
        ):
            return
        for name in self._filename_matched(node.test, function):
            self._set(name, False)

    def _scope_binding(self, function, name):
        if function is not None:
            key = id(function)
            bindings = self._function_bindings.get(key)
            if bindings is None:
                bindings = scope_bindings(function)
                self._function_bindings[key] = bindings
            if name in bindings:
                values = bindings[name]
                if len(values) == 1:
                    return values[0]
                return None
        if name in self._global_names:
            return None
        values = self._module_bindings.get(name)
        if values and len(values) == 1:
            return values[0]
        return None

    def _filename_matched(self, test, function):
        # A helper's regex import belongs to that helper, even while its
        # return value is being checked from another function's call site.
        imports = {}
        if function is not None:
            key = id(function)
            imports = self._function_import_aliases.get(key)
            if imports is None:
                imports = module_level_imports(function)
                self._function_import_aliases[key] = imports
        module_call_functions = set()

        def binding(name):
            value = self._scope_binding(function, name)
            module_values = self._module_bindings.get(name)
            if (
                isinstance(value, ast.Call)
                and module_values
                and len(module_values) == 1
                and value is module_values[0]
            ):
                # filename_match_subject also asks canonical() about the
                # factory of a bound compiled pattern. That call was written
                # at module level, so helper-local imports do not describe it.
                module_call_functions.add(id(value.func))
            return value

        def canonical(node):
            if id(node) in module_call_functions:
                return self._prefix_module_canonical(node)
            name = prefix_dotted(node)
            if name is not None:
                head, _, rest = name.partition(".")
                if head in imports and head not in self._module_rebound:
                    base = imports[head]
                    return f"{base}.{rest}" if rest else base
            return self._prefix_scope_canonical(node, function)

        def call_names(call):
            subject = filename_match_subject(call, binding, canonical)
            if isinstance(subject, ast.Name) and native_text_name(
                subject.id, function, binding
            ):
                return {subject.id}
            return set()

        return names_when(test, False, call_names)

    def _is_filename_validator_call(self, node):
        """A call to a same-module function that only returns a name it
        proved to be filename characters."""
        if not isinstance(node.func, ast.Name) or len(node.args) != 1 or node.keywords:
            return False
        name = node.func.id
        helper = self._module_functions.get(name)
        if helper is None or name in self._global_names:
            return False
        if (
            "*" in self._module_bindings
            or len(self._module_bindings.get(name, ())) != 1
        ):
            return False
        function = self._current_function()
        if function is not None:
            key = id(function)
            bindings = self._function_bindings.get(key)
            if bindings is None:
                bindings = scope_bindings(function)
                self._function_bindings[key] = bindings
            if name in bindings:
                return False
        known = self._filename_validators.get(name)
        if known is None:
            known = self._filename_validators[name] = validated_return(
                helper,
                lambda test: self._filename_matched(test, helper),
                _body_terminates,
            )
        return known

    def visit_Assert(self, node):
        names = self._validation_names(node.test, True)
        self.generic_visit(node)
        if names:
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

    def _validation_names(self, test, holds):
        """Names a containment or allowlist check vouches for when ``test``
        evaluates to ``holds``. ``a or b`` holding proves only what both
        prove; ``a and b`` failing likewise."""
        return polarity_names(
            self._inline_bound_checks(test), holds, self._containment_call_names
        )

    def _inline_bound_checks(self, test):
        """``common = os.path.commonpath([...])`` then ``if common != base``:
        read the comparison through a name bound once to a containment call,
        when every name that call reads is itself bound once (a later
        rebinding of the checked path must not inherit the check)."""
        function = self._current_function()
        if function is None:
            return test
        bindings = self._function_bindings.get(id(function))
        if bindings is None:
            bindings = scope_bindings(function)
            self._function_bindings[id(function)] = bindings

        def bound_check(node):
            if not isinstance(node, ast.Name):
                return None
            values = bindings.get(node.id)
            if not values or len(values) != 1 or not isinstance(values[0], ast.Call):
                return None
            call = values[0]
            if not self._containment_call_names(call):
                return None
            for name in _names_in(call):
                if len(bindings.get(name, ())) > 1:
                    return None
            return call

        def rewrite(node):
            # Only the shapes polarity_names reads; everything else is shared.
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                operand = rewrite(node.operand)
                return (
                    node
                    if operand is node.operand
                    else ast.UnaryOp(op=node.op, operand=operand)
                )
            if isinstance(node, ast.BoolOp):
                values = [rewrite(value) for value in node.values]
                if all(new is old for new, old in zip(values, node.values)):
                    return node
                return ast.BoolOp(op=node.op, values=values)
            if isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                replaced = [bound_check(side) or side for side in sides]
                if all(new is old for new, old in zip(replaced, sides)):
                    return node
                return ast.Compare(
                    left=replaced[0], ops=node.ops, comparators=replaced[1:]
                )
            return node

        return rewrite(test)

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
        if call.func.attr == "startswith" and not self._separator_prefix(call):
            return set()
        receiver = _unwrap_str_call(call.func.value)
        if not self._is_normalized_expr(receiver):
            return set()
        return _names_in(receiver)

    def _separator_prefix(self, call):
        """``startswith`` proves containment only for a prefix that ends at a
        separator: ``/srv/files2`` also starts with ``/srv/files``."""
        if len(call.args) != 1 or call.keywords:
            return False
        return ends_with_separator(
            call.args[0],
            self._prefix_binding,
            self._prefix_canonical,
            self._prefix_module_binding,
            self._prefix_module_canonical,
        )

    def _prefix_module_binding(self, name):
        """The module-level value of ``name``: a tuple's members belong to the
        scope that declared them, not to the scope doing the check."""
        if name in self._global_names:
            return AMBIGUOUS_BINDING
        return binding_value(self._module_bindings.get(name))

    def _prefix_binding(self, name):
        function = self._current_function()
        if function is not None:
            key = id(function)
            bindings = self._function_bindings.get(key)
            if bindings is None:
                bindings = scope_bindings(function)
                self._function_bindings[key] = bindings
            if name in bindings:
                return binding_value(bindings[name])
        if name in self._global_names:
            return AMBIGUOUS_BINDING
        return binding_value(self._module_bindings.get(name))

    def _prefix_canonical(self, node):
        return self._prefix_scope_canonical(node, self._current_function())

    def _prefix_scope_canonical(self, node, function):
        name = prefix_dotted(node)
        if name is None:
            return None
        if function is not None:
            key = id(function)
            bindings = self._function_bindings.get(key)
            if bindings is None:
                bindings = scope_bindings(function)
                self._function_bindings[key] = bindings
            if name.split(".", 1)[0] in bindings:
                return None
        return self._prefix_module_canonical(node)

    def _prefix_module_canonical(self, node):
        name = prefix_dotted(node)
        if name is None:
            return None
        head, _, rest = name.partition(".")
        if head in self._module_rebound or "*" in self._module_rebound:
            return None
        base = self._module_import_aliases.get(head)
        if base is None:
            return None
        if rest:
            return f"{base}.{rest}"
        return base

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

    def _native_atomic_expression(self, expression, qualified):
        name = _expr_name(expression)
        if not name:
            return False
        if qualified == "builtins.open" and id(expression) in self._native_open_refs:
            resolved = qualified
        elif (
            qualified == "builtins.getattr"
            and id(expression) in self._native_getattr_refs
        ):
            resolved = qualified
        else:
            if not self._import_names_are_stable(name):
                return False
            resolved = self.untrusted_sources.resolved_import(
                self._current_function(), name
            )
        return resolved == qualified and self._native_atomic_provider(qualified)

    def _native_atomic_provider(self, qualified):
        return provider_binding_is_stable(
            qualified,
            self.untrusted_sources.module,
            self.file_path,
            getattr(self, "project_root", None),
        )

    def _has_symlink_write_guard(self, node):
        proof = self.atomic_open_proofs
        return proof is not None and (
            proof.nofollow(node, self._native_atomic_expression)
            or proof.exclusive(node, self._native_atomic_expression)
        )

    def _has_symlink_read_guard(self, node):
        proof = self.atomic_open_proofs
        return (
            proof is not None
            and proof.nofollow(node, self._native_atomic_expression)
            and proof.bounded_descriptor_read(node, self._native_atomic_expression)
        )

    def _native_path_receiver(self, expression, depth=0):
        if depth > 16 or self.path_open_modes is None:
            return False
        if isinstance(expression, ast.Name):
            value = self.path_open_modes._binding(expression)
            return value is not None and self._native_path_receiver(value, depth + 1)
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
            return (
                isinstance(expression.right, ast.Constant)
                and type(expression.right.value) is str
                and self._native_path_receiver(expression.left, depth + 1)
            )
        if isinstance(expression, ast.Call):
            return any(
                self._native_atomic_expression(expression.func, qualified)
                for qualified in (
                    "pathlib.Path",
                    "pathlib.PosixPath",
                    "pathlib.WindowsPath",
                )
            )
        return False

    def _native_exclusive_mode(self, node, bound_method):
        if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            return False
        if not bound_method:
            opener = _bound_argument(node, 7, "opener")
            if opener is not None and not (
                isinstance(opener, ast.Constant) and opener.value is None
            ):
                return False
            return any(
                self._native_atomic_expression(node.func, provider)
                for provider in ("builtins.open", "io.open", "_io.open")
            )
        if not all(
            self._native_atomic_provider(provider)
            for provider in ("io.open", "pathlib.io.open")
        ):
            return False
        modes = (
            self.path_open_modes.modes(node, bound_method=True)
            if self.path_open_modes is not None
            else None
        )
        if (
            not modes
            or any("b" not in mode for mode in modes)
            and not all(
                self._native_atomic_provider(provider)
                for provider in ("io.text_encoding", "pathlib.io.text_encoding")
            )
        ):
            return False
        return (
            isinstance(node.func, ast.Attribute)
            and self._native_path_receiver(node.func.value)
            and all(
                provider_binding_is_stable(
                    qualified,
                    self.untrusted_sources.module,
                    self.file_path,
                    getattr(self, "project_root", None),
                )
                for qualified in (
                    "pathlib.Path",
                    "pathlib.PosixPath",
                    "pathlib.WindowsPath",
                )
            )
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
            if self.import_aliases.get(
                leaf.value.id
            ) == "os" and not self._locally_bound(leaf.value.id):
                flag = leaf.attr
        elif isinstance(leaf, ast.Name):
            qualified = self.import_aliases.get(leaf.id, "")
            parts = qualified.split(".")
            if (
                len(parts) == 2
                and parts[0] == "os"
                and not self._locally_bound(leaf.id)
            ):
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
        return (
            self.atomic_open_proofs is not None
            and self.atomic_open_proofs.exclusive(node, self._native_atomic_expression)
        )

    def _os_open_directions(self, node):
        if self.atomic_open_proofs is not None:
            native_flags = self.atomic_open_proofs.facts(
                node, self._native_atomic_expression
            )
            if native_flags is not None:
                return native_flags.directions()
        # Unknown providers and flags cannot establish either direction absent.
        return True, True

    def _os_open_is_directory_read(self, node):
        """A proven O_DIRECTORY descriptor cannot consume file contents.

        This restricts the opened object type, not the path: traversal checks
        still apply. Unknown flags and getattr(..., 0) fallbacks establish no
        directory guarantee, and spelling a flag never proves its provider.
        """
        flags = _bound_argument(node, 1, "flags")
        leaves = _bit_or_leaves(flags)
        if not leaves:
            return False
        resolved = {self._os_flag(leaf) for leaf in leaves}
        if not {"O_DIRECTORY", "O_RDONLY"} <= resolved:
            return False
        if not resolved <= {"O_DIRECTORY", "O_RDONLY", "O_CLOEXEC"}:
            return False
        names = [(node.func, "os.open")]
        names.extend((leaf, f"os.{self._os_flag(leaf)}") for leaf in leaves)
        for expression, qualified in names:
            name = _expr_name(expression)
            if not name or not self._import_names_are_stable(name):
                return False
            if (
                self.untrusted_sources.resolved_import(self._current_function(), name)
                != qualified
            ):
                return False
            if not provider_binding_is_stable(
                qualified,
                self.untrusted_sources.module,
                self.file_path,
                getattr(self, "project_root", None),
            ):
                return False
        return True

    def _add_finding(
        self, node, rule_id, severity, message, evidence=None, path_expr=None
    ):
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

    def _receiver_proof(self, node):
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
        return proof

    def _method_path_operand(self, node):
        """A proven wrapper's file argument differs from a Path receiver.

        Unknown implementations retain the old conservative check. Only a
        resolved non-Path implementation with no filesystem effect is skipped.
        """
        proof = self._receiver_proof(node)
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
        if all_sources and all(_is_operator_source(source) for source in all_sources):
            return _OperatorContextEvidence(evidence or {})
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
        if self._portable_filename(path_expr):
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

    def _portable_filename(self, expr):
        """A final filename with actual string-method separator removal.

        This deliberately proves only the sink's operand. Treating a cleaned
        component as globally safe would hide a later URL decode. Dot segments
        require a fixed affix, and portable paths must remove drive colons and
        both separators. Symlink rules still examine the original source.
        """
        original = expr
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
            and isinstance(expr.func.value, ast.Constant)
            and isinstance(expr.func.value.value, str)
            and not any(isinstance(arg, ast.Starred) for arg in expr.args)
            and all(kw.arg is not None for kw in expr.keywords)
        ):
            named = {kw.arg: kw.value for kw in expr.keywords}
            parts = []
            position = 0
            try:
                for literal, field, spec, conversion in Formatter().parse(
                    expr.func.value.value
                ):
                    parts.append(ast.Constant(value=literal))
                    if field is None:
                        continue
                    if spec or conversion:
                        return False
                    if field == "":
                        value = expr.args[position]
                        position += 1
                    elif field.isdecimal():
                        value = expr.args[int(field)]
                    elif field.isidentifier():
                        value = named[field]
                    else:
                        return False
                    parts.append(ast.FormattedValue(value=value, conversion=-1))
            except (ValueError, IndexError, KeyError):
                return False
            expr = ast.JoinedStr(values=parts)
        if not isinstance(expr, ast.JoinedStr):
            return False
        separators = (
            {"/"} if self._posix_filename_branch(original) else {"/", "\\", ":"}
        )
        literals = [
            part.value for part in expr.values if isinstance(part, ast.Constant)
        ]
        if any(
            not isinstance(text, str) or any(char in text for char in separators)
            for text in literals
        ):
            return False
        if not any(char != "." for text in literals for char in text):
            return False

        def removed(value, depth=0):
            if depth > 8 or not isinstance(value, ast.Call) or value.keywords:
                return None
            method = value.func
            if not isinstance(method, ast.Attribute) or method.attr != "replace":
                return None
            if (
                isinstance(method.value, ast.Name)
                and method.value.id == "str"
                and id(method.value) in self._builtin_string_refs
            ):
                # Unbound str.replace uses the real descriptor even for a str
                # subclass that overrides its own .replace method.
                if len(value.args) != 3:
                    return None
                prior = removed(value.args[0], depth + 1) or set()
                old, new = value.args[1:]
            else:
                if len(value.args) != 2:
                    return None
                prior = removed(method.value, depth + 1)
                if prior is None:
                    return None
                old, new = value.args
            if not (
                isinstance(old, ast.Constant)
                and old.value in {"/", "\\", ":"}
                and isinstance(new, ast.Constant)
                and isinstance(new.value, str)
                and not any(char in new.value for char in "/\\:")
            ):
                return None
            return prior | {old.value}

        formatted = [
            part for part in expr.values if isinstance(part, ast.FormattedValue)
        ]
        return (
            bool(formatted)
            and all(
                part.conversion == -1
                and part.format_spec is None
                and (removed(part.value) or set()) >= separators
                for part in formatted
            )
            and provider_binding_is_stable(
                "builtins.str.replace",
                self.untrusted_sources.module,
                self.file_path,
                getattr(self, "project_root", None),
            )
        )

    def _posix_filename_branch(self, expr):
        """Only an actual stdlib platform guard establishes POSIX semantics."""
        current = expr
        while id(current) in self._path_parents:
            parent = self._path_parents[id(current)]
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            if isinstance(parent, ast.If) and current in parent.body:
                test = parent.test
                if (
                    isinstance(test, ast.Compare)
                    and len(test.ops) == 1
                    and isinstance(test.ops[0], ast.Eq)
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "posix"
                ):
                    name = _expr_name(test.left)
                    resolved = self.untrusted_sources.resolved_import(
                        self._current_function(), name
                    )
                    if (
                        resolved == "os.name"
                        and self._import_names_are_stable(name)
                        and self._sanitizer_is_unpatched("os.name")
                        and provider_binding_is_stable(
                            "os.name",
                            self.untrusted_sources.module,
                            self.file_path,
                            getattr(self, "project_root", None),
                        )
                    ):
                        return True
            current = parent
        return False

    def _flag_symlink_write_if_unsafe(self, node, path_expr):
        if not self._path_needs_symlink_protection(path_expr):
            return
        if self._has_symlink_write_guard(node):
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
            if isinstance(item.optional_vars, ast.Name):
                self._set_archive_kind(
                    item.optional_vars.id, self._archive_kind(item.context_expr)
                )
            if isinstance(item.context_expr, ast.Call) and _handle_reads_bounded(
                item.optional_vars, node.body, self._constant_sizes
            ):
                self._bounded_opens.add(id(item.context_expr))

    def _flag_symlink_read_if_unsafe(self, node, path_expr):
        if not self._path_needs_symlink_protection(path_expr):
            return
        bounded = id(node) in self._bounded_opens
        if self._has_symlink_read_guard(node):
            return
        evidence = self._untrusted_path_evidence(path_expr, "filesystem read")
        if evidence is None:
            return
        message = (
            "Possible symlink-following read on attacker-controlled path; require a regular in-root file."
            if bounded
            else "Possible symlink-following or unbounded read on attacker-controlled path; require a regular in-root file and a size cap."
        )
        self._add_finding(
            node, SYMLINK_READ_RULE, "MEDIUM", message, evidence, path_expr
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

    def _flag_open_operations(self, node, path_expr, *, bound_method=False):
        modes = None
        if self.path_open_modes is not None:
            try:
                modes = self.path_open_modes.modes(node, bound_method=bound_method)
            except Exception:
                modes = None
        exclusive = _exclusive_create_modes(modes) and self._native_exclusive_mode(
            node, bound_method
        )
        if exclusive and not any("+" in mode for mode in modes):
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
        if may_write and not exclusive:
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
        if self.atomic_open_proofs is None:
            return self._visit_call(node)
        with self.atomic_open_proofs.operation(node):
            return self._visit_call(node)

    def _visit_call(self, node: ast.Call):
        qn = _qualified_name(node)
        canonical = self._canonical_call_name(node)
        if canonical in FIRST_PATH_PARAMETERS or canonical in {
            "builtins.open",
            "io.open",
            "_io.open",
        }:
            resolved = self.untrusted_sources.resolved_import(
                self._current_function(), qn or ""
            )
            if resolved == canonical:
                qn = (
                    "open"
                    if canonical in {"builtins.open", "io.open", "_io.open"}
                    else canonical
                )
        method_sink = isinstance(node.func, ast.Attribute) and node.func.attr in {
            *self.PATHLIB_WRITE_METHODS,
            *self.PATHLIB_READ_METHODS,
            "open",
        }
        method_operand = None
        bound_path_method = True
        if method_sink:
            method_operand, bound_path_method = self._method_path_operand(node)
        archive_method = _archive_call_name(node)
        first_path = None
        if qn in FIRST_PATH_PARAMETERS:
            first_path = _bound_argument(node, 0, FIRST_PATH_PARAMETERS[qn])

        if archive_method and self._archive_extraction_is_reportable(node):
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
            writes, readonly = self._os_open_directions(node)
            if writes and not self._os_open_is_exclusive(node):
                self._flag_symlink_write_if_unsafe(node, first_path)
            facts = (
                self.atomic_open_proofs.facts(node, self._native_atomic_expression)
                if self.atomic_open_proofs is not None
                else None
            )
            write_only = (
                facts is not None
                and "O_WRONLY" in facts.required
                and "O_RDWR" not in facts.possible
            )
            reads = (
                not write_only
                and self.atomic_open_proofs is not None
                and (
                    self.atomic_open_proofs.descriptor_read_observed(
                        node, self._canonical_call_name, self._update_handle_is_read
                    )
                    or self.atomic_open_proofs.uncertain_descriptor_read(
                        node,
                        self._native_atomic_expression,
                        self._canonical_call_name,
                        self._update_handle_is_read,
                    )
                )
            )
            metadata_only = (
                self.atomic_open_proofs is not None
                and self.atomic_open_proofs.descriptor_metadata_only(
                    node, self._native_atomic_expression
                )
            )
            if (
                (reads or readonly)
                and not metadata_only
                and not self._os_open_is_directory_read(node)
            ):
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


class _ContainmentProbeChecker(_PathFlowChecker):
    """Visits module-level statements and the target function only."""

    def visit_FunctionDef(self, node):
        if node is self._probe_target:
            return super().visit_FunctionDef(node)
        return None

    def visit_AsyncFunctionDef(self, node):
        if node is self._probe_target:
            return super().visit_AsyncFunctionDef(node)
        return None

    def visit_ClassDef(self, node):
        return None

    def _taint_params(self, fn):
        super()._taint_params(fn)
        if fn is self._probe_target:
            for argument in _function_arguments(fn):
                if argument not in self._probe_tainted:
                    self._set(argument, False)

    def visit_Return(self, node):
        if self._current_function() is self._probe_target:
            value = node.value
            self._probe_returns.append(
                value is None
                or not self.is_tainted(value)
                or self._path_is_contained(value)
            )
        self.generic_visit(node)


def _function_arguments(fn):
    arguments = fn.args
    names = [
        argument.arg
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    ]
    if arguments.vararg:
        names.append(arguments.vararg.arg)
    if arguments.kwarg:
        names.append(arguments.kwarg.arg)
    return names


# Project helpers proven to return only contained paths:
# (root, path, name, tainted params) -> bool. In-progress keys read as False.
_CONTAINMENT_PROOFS: dict = {}
_CONTAINMENT_ACTIVE: set = set()
_CONTAINMENT_MAX_ACTIVE = 4
_PARSED_HELPER_MODULES: dict = {}
# A long-lived process (editor, MCP server) scans again after edits: the
# analyzer clears these per run, and parsed files are keyed by their stat.
_MAX_CACHED_ENTRIES = 4096
_MAX_HELPER_BYTES = 2_000_000


def reset_containment_proofs() -> None:
    _CONTAINMENT_PROOFS.clear()
    _CONTAINMENT_ACTIVE.clear()
    _PARSED_HELPER_MODULES.clear()
    _UNIQUE_FUNCTIONS.clear()
    _HELPER_NAMESPACES.clear()


def _bounded(cache):
    if len(cache) >= _MAX_CACHED_ENTRIES:
        cache.clear()
    return cache


def _parsed_module(path, project_root):
    """Parse only bounded, regular project sources without following symlinks."""
    if not project_root:
        return None
    try:
        root = Path(project_root).resolve(strict=True)
        candidate = Path(os.path.abspath(path))
        candidate.relative_to(root)
        # Check before cache hits too: replacing a helper with a symlink must
        # not reuse a proof from the previous, regular project source.
        if candidate.resolve(strict=True) != candidate:
            return None
        stat = candidate.stat()
    except (OSError, RuntimeError, ValueError):
        return None
    key = (
        str(root),
        str(candidate),
        stat.st_mtime_ns,
        stat.st_ctime_ns,
        stat.st_size,
        stat.st_ino,
        stat.st_dev,
    )
    cached = _PARSED_HELPER_MODULES.get(key)
    if cached is None:
        try:
            source = read_project_text_no_symlink(
                root, candidate, max_bytes=_MAX_HELPER_BYTES
            )
            cached = (
                ast.parse(source, filename=str(candidate))
                if source is not None
                else False
            )
        except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
            cached = False
        _bounded(_PARSED_HELPER_MODULES)[key] = cached
    return cached or None


_UNIQUE_FUNCTIONS: dict = {}
_HELPER_NAMESPACES: dict = {}
_CALLABLE_REPLACEMENT_ATTRIBUTES = frozenset(
    {"__code__", "__defaults__", "__kwdefaults__", "__call__"}
)


def _helper_namespace_is_stable(tree, dotted, file_path=None):
    """Source-visible namespace or callable mutation invalidates body proofs.

    Attribute writes are checked independent of receiver spelling, so an
    alias to a function or project module cannot hide its replacement.
    """
    if not isinstance(tree, ast.Module):
        return False
    cache_key = (id(tree), str(file_path))
    entry = _HELPER_NAMESPACES.get(cache_key)
    if entry is None or entry[0] is not tree:
        dynamic, rebound = module_rebinding(
            tree, module_name_for(file_path) if file_path else None
        )
        attributes, computed = attribute_write_names(tree)
        global_names = {
            name
            for node in ast.walk(tree)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        entry = (
            tree,
            dynamic or computed or has_mock_api_patching(tree),
            rebound | attributes | global_names,
            attributes,
        )
        _bounded(_HELPER_NAMESPACES)[cache_key] = entry
    return (
        not entry[1]
        and not set(dotted.split(".")) & entry[2]
        and not _CALLABLE_REPLACEMENT_ATTRIBUTES & entry[3]
    )


def _unique_module_function(tree, name, file_path=None):
    """The one module-level ``def name`` that nothing else in the module
    rebinds; None for anything ambiguous."""
    index = _UNIQUE_FUNCTIONS.get(id(tree))
    if index is None or index[0] is not tree:
        defs = {}
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.setdefault(statement.name, []).append(statement)
        bindings = scope_bindings(tree)
        unique = {
            key: nodes[0]
            for key, nodes in defs.items()
            if len(nodes) == 1
            and len(bindings.get(key, ())) == 1
            and not nodes[0].decorator_list
            and _helper_namespace_is_stable(tree, key, file_path)
        }
        index = (tree, unique)
        _bounded(_UNIQUE_FUNCTIONS)[id(tree)] = index
    return index[1].get(name)


def _module_file(project_root, dotted):
    if not project_root or not dotted:
        return None
    base = os.path.join(str(project_root), *dotted.split("."))
    for candidate in (base + ".py", os.path.join(base, "__init__.py")):
        if os.path.isfile(candidate):
            return candidate
    return None


# A proof that cannot finish is not a proof: the call stays unsanitized.
_PROOF_ERRORS = (
    RecursionError, MemoryError, ValueError, TypeError, AttributeError,
    KeyError, IndexError, OSError, SyntaxError,
)  # fmt: skip
_CONTAINMENT_CALLEES = frozenset(
    {"commonpath", "relative_to", "is_relative_to", "startswith"}
)


def _checks_containment(function):
    """Cheap syntax filter before a full probe: the body calls a
    containment check itself."""
    callees = {
        _callee_last(node) for node in ast.walk(function) if isinstance(node, ast.Call)
    }
    return bool(callees & _CONTAINMENT_CALLEES) and bool(callees & _NORMALIZER_CALLEES)


def _own_returns(function):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Return):
            yield node
            continue
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(ast.iter_child_nodes(node))


def _module_import_aliases(tree, file_path, project_root):
    """name -> dotted module or ``module.attr`` for module-level imports."""
    aliases = {}
    package = None
    if project_root:
        relative = os.path.relpath(os.path.dirname(str(file_path)), str(project_root))
        package = "" if relative == "." else relative.replace(os.sep, ".")
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(statement, ast.ImportFrom):
            module = statement.module or ""
            if statement.level:
                if package is None:
                    continue
                parts = package.split(".") if package else []
                if statement.level - 1 > len(parts):
                    continue
                base = parts[: len(parts) - (statement.level - 1)]
                module = ".".join([*base, module] if module else base)
            for alias in statement.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
    return aliases


def _resolve_helper_call(call, tree, file_path, project_root, scope=None):
    """(file, def) for ``f(...)``, ``mod.f(...)`` or ``pkg.mod.f(...)`` that
    names a unique module-level project function."""
    func = call.func
    dotted = _qualified_name(call)
    if not dotted or not _helper_namespace_is_stable(tree, dotted, file_path):
        return None
    head = dotted.split(".", 1)[0]
    if scope is not None and head in scope_bindings(scope):
        return None
    if isinstance(func, ast.Name):
        local = _unique_module_function(tree, func.id, file_path)
        if local is not None:
            return str(file_path), local
    head, _, rest = dotted.partition(".")
    if len(scope_bindings(tree).get(head, ())) != 1:
        return None
    target = _module_import_aliases(tree, file_path, project_root).get(head)
    if target is None:
        return None
    resolved = f"{target}.{rest}" if rest else target
    if not _helper_namespace_is_stable(tree, resolved, file_path):
        return None
    module_name, _, function_name = resolved.rpartition(".")
    helper_file = _module_file(project_root, module_name)
    if helper_file is None:
        return None
    helper_tree = _parsed_module(helper_file, project_root)
    helper = (
        _unique_module_function(helper_tree, function_name, helper_file)
        if helper_tree
        else None
    )
    return (helper_file, helper) if helper is not None else None


def _prove_wrapper(file_path, tree, function, tainted, project_root):
    """Every return passes only parameters and literals straight into a
    project function that is itself proven for the tainted parameters."""
    returns = list(_own_returns(function))
    if not returns:
        return False
    parameters = set(_function_arguments(function))
    for node in returns:
        call = node.value
        if not isinstance(call, ast.Call):
            return False
        if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return False
        for value in [*call.args, *(keyword.value for keyword in call.keywords)]:
            if not (
                isinstance(value, ast.Constant)
                or (isinstance(value, ast.Name) and value.id in parameters)
            ):
                return False
            if (
                isinstance(value, ast.Name)
                and len(scope_bindings(function).get(value.id, ())) != 1
            ):
                return False
        located = _resolve_helper_call(call, tree, file_path, project_root, function)
        if located is None:
            return False
        helper_file, helper = located
        helper_parameters = [
            argument.arg for argument in (*helper.args.posonlyargs, *helper.args.args)
        ]
        known = set(_function_arguments(helper))
        passed = set()
        for index, value in enumerate(call.args):
            if index >= len(helper_parameters):
                return False
            if isinstance(value, ast.Name) and value.id in tainted:
                passed.add(helper_parameters[index])
        for keyword in call.keywords:
            if keyword.arg not in known:
                return False
            if isinstance(keyword.value, ast.Name) and keyword.value.id in tainted:
                passed.add(keyword.arg)
        if passed and not _prove_containment(
            helper_file, helper.name, frozenset(passed), project_root
        ):
            return False
    return True


def _prove_containment(file_path, name, tainted, project_root):
    """Whether ``name`` (module-level in ``file_path``) returns only paths
    that are untainted or contained when exactly ``tainted`` params are."""
    key = (str(project_root), str(file_path), name, tainted)
    cached = _CONTAINMENT_PROOFS.get(key)
    if cached is not None:
        return cached
    _bounded(_CONTAINMENT_PROOFS)
    # Fewer tainted parameters cannot taint a return more, so a proof with
    # every parameter tainted holds for each subset.
    tree = _parsed_module(file_path, project_root)
    target = (
        _unique_module_function(tree, name, file_path) if tree is not None else None
    )
    if target is None:
        _CONTAINMENT_PROOFS[key] = False
        return False
    everything = frozenset(_function_arguments(target))
    if tainted != everything and _prove_containment(
        file_path, name, everything, project_root
    ):
        _CONTAINMENT_PROOFS[key] = True
        return True
    if (
        key in _CONTAINMENT_ACTIVE
        or len(_CONTAINMENT_ACTIVE) >= _CONTAINMENT_MAX_ACTIVE
    ):
        return False
    if not _checks_containment(target):
        _CONTAINMENT_ACTIVE.add(key)
        try:
            verdict = _prove_wrapper(file_path, tree, target, tainted, project_root)
        except _PROOF_ERRORS:
            verdict = False
        finally:
            _CONTAINMENT_ACTIVE.discard(key)
        _CONTAINMENT_PROOFS[key] = verdict
        return verdict
    _CONTAINMENT_ACTIVE.add(key)
    try:
        probe = _ContainmentProbeChecker(str(file_path), [], sanitizers=PATH_SANITIZERS)
        probe.project_root = project_root
        probe._probe_target = target
        probe._probe_tainted = tainted
        probe._probe_returns = []
        probe.visit(tree)
        verdict = bool(probe._probe_returns) and all(probe._probe_returns)
    except _PROOF_ERRORS:
        verdict = False
    finally:
        _CONTAINMENT_ACTIVE.discard(key)
    _CONTAINMENT_PROOFS[key] = verdict
    return verdict


def scan(tree, file_path, findings, *, project_root=None):
    try:
        checker = _PathFlowChecker(file_path, findings, sanitizers=PATH_SANITIZERS)
        checker.project_root = project_root
        checker.visit(tree)
    except Exception as e:
        print(f"Path traversal analysis failed for {file_path}: {e}", file=sys.stderr)
