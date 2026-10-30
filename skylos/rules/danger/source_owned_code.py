"""Narrow proof that ``exec``/``eval`` runs the project's own source code.

Tests and tools often run one function of a module without importing the
module: they parse ``SOURCE.read_text()``, where ``SOURCE`` is
``Path(__file__).resolve().parents[1] / "app" / "core.py"``, pick the
function's node, wrap it in an empty ``ast.Module`` and call
``exec(compile(module, ...), namespace)``. The code that runs is the
project's checked-in source; running it is no more dangerous than importing
it.

A call is proved only when every step from the source file to the code object
is modelled here: a path built from the module's own ``__file__`` and literal
segments that names an existing ``.py`` file inside the project root (symlinks
resolved, outside virtualenv and vendor folders); ``read_text`` on it;
``ast.parse``; selecting, copying or regrouping the parsed nodes; an empty
``ast.Module``/``ast.ClassDef`` shell around them; clearing fields with empty
values; ``compile``; and ``exec``/``eval`` with a fresh namespace dict.
Module path constants bound once and undecorated module functions are
followed with the argument kinds of each call.

Anything else leaves the call reported: parameters, environment, input,
configuration, string variables, literal code, synthesized nodes, an unknown
call, comparison, closure or store that could reach a parsed node, a rebound
or patched name the proof reads, a namespace that may be the module's own, or
a repository module shadowing ``ast``/``copy``/``pathlib``. Proof is per
module: one ``exec``/``eval`` that is not proved (``exec(user_code, {})``)
keeps every call in the module reported, because it could patch ``ast`` or
``pathlib`` before the others run. A complete, bounded project source snapshot
must also rule out source-file mutations, escaped filesystem capabilities,
reader/parser overrides and dynamic loading in other modules. Unknown effects
in the loader itself leave the call reported. No target code is executed.
"""

from __future__ import annotations

import ast
import os

from .builtin_bindings import builtin_references
from .danger_fs.closed_world import _SKIP_DIRS
from .module_namespace import attribute_write_names, module_name_for, module_rebinding
from .untrusted_sources import UntrustedSourceIndex
from .project_source import project_source_snapshot

_TREE = "tree"
_MODULE = "module"
_EMPTY = "empty"
_TEXT = "text"
_CODE = "code"
_DATA = "data"
_PATH = "path"
_PARENTS = "parents"
_UNKNOWN_PATH = "unknown_path"
_NODES = frozenset({_TREE, _MODULE})
_CODE_RUNNERS = frozenset({"exec", "eval"})
_COMPILE_MODES = frozenset({"exec", "eval", "single"})
_PATH_CLASSES = frozenset({"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"})
_SHELLS = frozenset({"ast.Module", "ast.Interactive", "ast.Expression", "ast.ClassDef"})
_NODE_ITERATORS = frozenset({"ast.walk", "ast.iter_child_nodes"})
_READ_ONLY_AST = frozenset(
    {"ast.dump", "ast.unparse", "ast.get_docstring", "ast.get_source_segment"}
)
_COPIES = frozenset({"copy.deepcopy", "copy.copy"})
_SEQUENCES = frozenset({"list", "tuple", "iter", "reversed", "enumerate"})
_READS = frozenset({"len", "hasattr", "repr", "bool", "any", "all", "str"})
_EXCEPTIONS = frozenset({"AssertionError", "ValueError", "TypeError", "RuntimeError"})
_BUILTIN_NAMES = frozenset(
    {"compile", "next", "isinstance", "getattr", "dict", "open", "input"}
    | _CODE_RUNNERS
    | _SEQUENCES
    | _READS
    | _EXCEPTIONS
)
_PATH_READS = frozenset(
    {
        "read_text",
        "read_bytes",
        "exists",
        "is_file",
        "is_dir",
        "stat",
        "lstat",
        "as_posix",
        "is_absolute",
    }
)
_FILE_WRITES = frozenset(
    {
        "write_text",
        "write_bytes",
        "write",
        "writelines",
        "truncate",
        "touch",
        "unlink",
        "rename",
        "replace",
        "rmdir",
        "mkdir",
        "symlink_to",
        "hardlink_to",
        "chmod",
        "lchmod",
        "chown",
    }
)
_FILE_FUNCTIONS = frozenset(
    {
        "open",
        "os.open",
        "io.open",
        "builtins.open",
        "os.replace",
        "os.rename",
        "os.renames",
        "os.remove",
        "os.unlink",
        "os.truncate",
        "os.symlink",
        "os.link",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
    }
)
_DYNAMIC_LOADS = frozenset(
    {
        "__import__",
        "builtins.__import__",
        "importlib.import_module",
        "importlib.reload",
        "importlib.util.spec_from_file_location",
        "importlib.machinery.SourceFileLoader",
        "runpy.run_module",
        "runpy.run_path",
        "imp.load_source",
        "imp.load_module",
    }
)
_PROJECT_READS = frozenset({"os.environ.get", "os.getenv"})
_LIST_GROWTH = frozenset({"append", "extend", "insert"})
_LIST_METHODS = frozenset(
    {"append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse"}
    | {"copy", "index", "count"}
)
_SCALAR_FIELDS = frozenset(
    {"name", "id", "attr", "arg", "module", "asname", "level", "kind", "lineno"}
    | {"col_offset", "end_lineno", "end_col_offset", "type_comment", "simple"}
    | {"conversion", "is_async"}
)
_RELIED_DUNDERS = frozenset(
    {"__truediv__", "__rtruediv__", "__fspath__", "__getattribute__", "__getattr__"}
    | {"__new__", "__init__", "__deepcopy__", "__copy__", "__iter__", "__getitem__"}
    | {"__class__", "__dict__", "__str__", "__eq__", "__bool__", "__len__"}
)
_PATCH_FORMS = frozenset({"object", "dict", "multiple", "stopall"})
_PATCH_OPTIONS = frozenset({"spec", "create", "spec_set", "autospec", "new_callable"})
_ATTRIBUTE_SETTERS = frozenset({"setattr", "delattr"})
_ITEM_SETTERS = frozenset({"setitem", "delitem"})
_SHADOWABLE = ("ast", "copy", "pathlib")
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_TRY = (ast.Try, ast.TryStar)
_MAX_HELPER_DEPTH = 8
_MAX_STEPS = 200_000
_MAX_LOOP_PASSES = 4


class _Unproven(Exception):
    pass


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_path(kind) -> bool:
    return isinstance(kind, tuple) and kind[0] == _PATH


def _is_str(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_none(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _segments(literal: str) -> list[str] | None:
    parts = literal.split("/")
    for part in parts:
        if part in {"", ".", ".."} or any(mark in part for mark in ("\\", ":", "\0")):
            return None
    return parts


def _join(left, right):
    if left == right:
        return left
    if {left, right} <= _NODES | {_EMPTY}:
        return _TREE
    return None


def _parameters(args: ast.arguments) -> list[ast.arg]:
    found = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg is not None:
        found.append(args.vararg)
    if args.kwarg is not None:
        found.append(args.kwarg)
    return found


def _argument(call: ast.Call, position: int, keyword: str):
    if len(call.args) > position:
        return call.args[position]
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _local_names(node) -> frozenset[str]:
    """Names bound in a function's own scope (comprehension targets count,
    which only makes lookups of a same-named global more conservative)."""
    names = {argument.arg for argument in _parameters(node.args)}
    if isinstance(node, ast.Lambda):
        return frozenset(names)
    declared: set[str] = set()
    stack = list(node.body)
    while stack:
        child = stack.pop()
        if isinstance(child, _SCOPES):
            if not isinstance(child, ast.Lambda):
                names.add(child.name)
            continue
        if isinstance(child, (ast.Global, ast.Nonlocal)):
            declared.update(child.names)
        elif isinstance(child, ast.Name) and not isinstance(child.ctx, ast.Load):
            names.add(child.id)
        elif isinstance(child, ast.alias) and child.name != "*":
            names.add(child.asname or child.name.split(".", 1)[0])
        elif isinstance(child, ast.ExceptHandler) and child.name:
            names.add(child.name)
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.add(child.rest)
        stack.extend(ast.iter_child_nodes(child))
    return frozenset(names - declared)


def _free_loads(node) -> set[str]:
    """Names a nested scope reads from outside itself (over-approximated)."""
    if isinstance(node, ast.Lambda):
        bound = {argument.arg for argument in _parameters(node.args)}
        body = [node.body]
    elif isinstance(node, _FUNCTIONS):
        bound = set(_local_names(node))
        body = list(node.body)
    else:
        bound = set()
        body = list(node.body)
    direct: set[str] = set()
    nested: set[str] = set()
    stack = body
    while stack:
        child = stack.pop()
        if isinstance(child, _SCOPES):
            nested |= _free_loads(child)
            if isinstance(node, ast.ClassDef) and not isinstance(child, ast.Lambda):
                bound.add(child.name)
            if isinstance(child, ast.Lambda):
                stack.extend(child.args.defaults)
            elif isinstance(child, _FUNCTIONS):
                stack.extend(child.decorator_list)
                stack.extend(child.args.defaults)
            else:
                stack.extend(child.decorator_list)
                stack.extend(child.bases)
            continue
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            direct.add(child.id)
        elif isinstance(child, ast.Name) and isinstance(node, ast.ClassDef):
            bound.add(child.id)
        stack.extend(ast.iter_child_nodes(child))
    if isinstance(node, ast.ClassDef):
        return (direct - bound) | nested
    return (direct | nested) - bound


def _has_nested_nonlocal(node) -> bool:
    return any(isinstance(child, ast.Nonlocal) for child in ast.walk(node))


def _binding_counts(tree: ast.Module) -> dict[str, int]:
    counts: dict[str, int] = {}

    def add(name):
        counts[name] = counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            add(node.id)
        elif isinstance(node, ast.arg):
            add(node.arg)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            add(node.name)
        elif isinstance(node, ast.alias):
            add(node.asname or node.name.split(".", 1)[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                add(name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest)
    return counts


def _fresh_mapping(expr, scope, counts) -> bool:
    if isinstance(expr, (ast.Dict, ast.DictComp)):
        return True
    if isinstance(expr, ast.Call):
        return (
            isinstance(expr.func, ast.Name)
            and expr.func.id == "dict"
            and not counts.get("dict")
        )
    if not isinstance(expr, ast.Name) or not isinstance(scope, _FUNCTIONS):
        return False
    if expr.id in {argument.arg for argument in _parameters(scope.args)}:
        return False
    values = []
    for node in ast.walk(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and expr.id in node.names:
            return False
        if isinstance(node, ast.Name) and node.id == expr.id:
            if isinstance(node.ctx, ast.Load):
                continue
            values.append(node)
    if not values:
        return False
    for target in values:
        statement = next(
            (
                node
                for node in ast.walk(scope)
                if isinstance(node, (ast.Assign, ast.AnnAssign))
                and any(target is part for part in _assigned(node))
            ),
            None,
        )
        if statement is None or statement.value is None:
            return False
        if not isinstance(statement.value, (ast.Dict, ast.DictComp, ast.Call)):
            return False
        if not _fresh_mapping(statement.value, scope, counts):
            return False
    return True


def _assigned(statement) -> list[ast.AST]:
    if isinstance(statement, ast.Assign):
        return list(statement.targets)
    return [statement.target]


def _isolated_code_calls(tree, parents, counts) -> frozenset[int]:
    """``exec``/``eval`` calls whose globals mapping is a new dict."""
    found = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _CODE_RUNNERS
        ):
            continue
        if any(isinstance(arg, ast.Starred) for arg in node.args[:2]):
            continue
        namespace = _argument(node, 1, "globals")
        if namespace is None:
            continue
        scope = parents.get(id(node))
        while scope is not None and not isinstance(scope, (*_SCOPES, ast.Module)):
            scope = parents.get(id(scope))
        if _fresh_mapping(namespace, scope, counts):
            found.add(id(node))
    return frozenset(found)


def _patched_names(tree, parents) -> frozenset[str] | None:
    """Leaf names a mock/monkeypatch call may replace, or None if computed."""
    names: set[str] = set()
    words = {"patch"} | _ATTRIBUTE_SETTERS | _ITEM_SETTERS
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            word = node.id
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            word = node.attr
        else:
            continue
        if word not in words:
            continue
        parent = parents.get(id(node))
        called = isinstance(parent, ast.Call) and parent.func is node
        if word == "patch":
            if called:
                target = _argument(parent, 0, "target")
                if not _is_str(target):
                    return None
                names.add(target.value.rsplit(".", 1)[-1])
                continue
            call = parents.get(id(parent))
            if not (
                isinstance(parent, ast.Attribute)
                and parent.attr in _PATCH_FORMS
                and isinstance(call, ast.Call)
                and call.func is parent
            ):
                return None
            if parent.attr == "object":
                attribute = _argument(call, 1, "attribute")
                if not _is_str(attribute):
                    return None
                names.add(attribute.value)
            elif parent.attr == "multiple":
                if any(item.arg is None for item in call.keywords):
                    return None
                names.update(
                    item.arg for item in call.keywords if item.arg not in _PATCH_OPTIONS
                )
            elif parent.attr == "dict":
                target = _argument(call, 0, "in_dict")
                if _dotted(target) != "os.environ" and not (
                    _is_str(target) and target.value == "os.environ"
                ):
                    return None
            continue
        if not called:
            return None
        if isinstance(node, ast.Name) and word in _ATTRIBUTE_SETTERS:
            continue
        if word in _ATTRIBUTE_SETTERS:
            target = _argument(parent, 0, "target")
            if _is_str(target) and "." in target.value:
                names.add(target.value.rsplit(".", 1)[-1])
                continue
        name = _argument(parent, 1, "name")
        if not _is_str(name):
            return None
        names.add(name.value)
    return frozenset(names)


class _Frame:
    def __init__(self, function, local_names, outer_names, collect):
        self.function = function
        self.local_names = local_names
        self.outer_names = outer_names
        self.collect = collect
        self.env: dict[str, object] = {}
        self.scopes: list[dict[str, object]] = []
        self.escaped = False
        self.returns: list[object] = []
        self.candidates: set[int] = set()
        self.owned_names: set[str] = set()
        self.leaked: set[str] = set()
        self.closure_loads: set[str] = set()
        self.breaks: list[list[dict]] = []
        self.continues: list[list[dict]] = []


class _Proof:
    def __init__(self, tree: ast.Module, file_path, project_root):
        self.tree = tree
        self.file = os.path.abspath(str(file_path))
        self.root = os.path.realpath(str(project_root))
        self.parents = {
            id(child): parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        self.counts = _binding_counts(tree)
        self.isolated = _isolated_code_calls(tree, self.parents, self.counts)
        self.imports = UntrustedSourceIndex(tree)
        self.builtins = builtin_references(
            tree, _BUILTIN_NAMES, isolated_code_calls=self.isolated
        )
        self.constants: dict[str, ast.AST] = {}
        self.helpers: dict[str, ast.FunctionDef] = {}
        self.classes = {}
        for statement in tree.body:
            if isinstance(statement, ast.FunctionDef):
                if (
                    not statement.decorator_list
                    and self.counts.get(statement.name) == 1
                ):
                    self.helpers[statement.name] = statement
            elif isinstance(statement, ast.ClassDef):
                self.classes[statement.name] = statement
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = _assigned(statement)
                if (
                    statement.value is not None
                    and len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and self.counts.get(targets[0].id) == 1
                ):
                    self.constants[targets[0].id] = statement.value
        self.constant_kinds: dict[str, object] = {}
        self.constant_active: set[str] = set()
        self.summaries: dict[tuple, tuple] = {}
        self.active: set[tuple] = set()
        self.file_checks: dict[str, bool] = {}
        self.used_globals: set[str] = set()
        self.used_attrs: set[str] = set()
        self.audit_targets = None
        self.file_unsafe = False
        self.steps = 0

    def run(self) -> frozenset[int]:
        runners = {
            id(node)
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _CODE_RUNNERS
        }
        if not runners <= self.isolated or not self._module_is_static():
            return frozenset()
        owners = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and id(node) in self.isolated:
                owner = self.parents.get(id(node))
                while owner is not None and not isinstance(
                    owner, (*_SCOPES, ast.Module)
                ):
                    owner = self.parents.get(id(owner))
                if isinstance(owner, (*_FUNCTIONS, ast.Module)):
                    owners[id(owner)] = owner
        proven: set[int] = set()
        for owner in owners.values():
            function = owner
            if isinstance(owner, ast.Module):
                function = None
            frame = self._top_frame(function)
            self._run(frame, owner.body)
            if not frame.escaped:
                proven |= frame.candidates
        if (
            proven != runners
            or not self._names_are_stable()
            or not self._project_is_stable()
        ):
            return frozenset()
        return frozenset(proven)

    def _project_is_stable(self):
        trees, complete = project_source_snapshot(self.root)
        if not complete:
            return False
        targets = frozenset(
            os.path.realpath(path) for path, owned in self.file_checks.items() if owned
        )
        saw_current = False
        project_written = set()
        project_reads = set(self.used_attrs)
        for path, tree in trees.items():
            own = os.path.realpath(path) == os.path.realpath(self.file)
            if own:
                if ast.dump(tree, include_attributes=False) != ast.dump(
                    self.tree, include_attributes=False
                ):
                    return False
                saw_current = True
                tree = self.tree
            isolated = frozenset()
            if own:
                isolated = self.isolated
            dynamic, _ = module_rebinding(
                tree, module_name_for(path), isolated_code_calls=isolated
            )
            written, computed = attribute_write_names(tree)
            patched = _patched_names(
                tree,
                {
                    id(child): parent
                    for parent in ast.walk(tree)
                    for child in ast.iter_child_nodes(parent)
                },
            )
            if dynamic or computed or patched is None:
                return False
            project_written.update(written | patched)
            if (self.used_attrs | _RELIED_DUNDERS) & (written | patched):
                return False
            audit = _Proof(tree, path, self.root)
            audit.audit_targets = targets
            module_frame = _Frame(None, frozenset(audit.constants), frozenset(), False)
            audit._run(module_frame, tree.body)
            for function in ast.walk(tree):
                if isinstance(function, _FUNCTIONS):
                    audit._run(audit._top_frame(function), function.body)
                elif isinstance(function, ast.ClassDef):
                    audit._run(
                        _Frame(None, frozenset(), frozenset(), False), function.body
                    )
            if audit.file_unsafe:
                return False
            project_reads.update(audit.used_attrs)
        return saw_current and not project_reads & project_written

    def _source_path(self, kind):
        if kind == _UNKNOWN_PATH:
            return True
        if not _is_path(kind):
            return False
        path = os.path.realpath(kind[1])
        return any(_inside(target, path) for target in self.audit_targets)

    def _filesystem_call(self, frame, node, name):
        values = [self._value(frame, arg) for arg in node.args]
        values.extend(self._value(frame, kw.value) for kw in node.keywords)
        if name in {"open", "os.open", "io.open", "builtins.open"}:
            mode = _argument(node, 1, "mode")
            readonly = name != "os.open" and (
                mode is None or (_is_str(mode) and mode.value in {"r", "rt", "rb"})
            )
            if readonly and not any(kw.arg in {"opener", None} for kw in node.keywords):
                return None
            destinations = values[:1]
        elif name in {
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
            "shutil.move",
            "os.replace",
            "os.rename",
            "os.renames",
            "os.symlink",
            "os.link",
        }:
            destinations = values[:2]
        else:
            destinations = values[:1]
        if not destinations or any(
            not _is_path(value) or self._source_path(value) for value in destinations
        ):
            self.file_unsafe = True
        return None

    def _module_is_static(self) -> bool:
        if not _inside(os.path.realpath(self.file), self.root):
            return False
        if self.counts.get("__file__"):
            return False
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                return False
        directory = os.path.dirname(os.path.realpath(self.file))
        while _inside(directory, self.root):
            for name in _SHADOWABLE:
                if os.path.exists(
                    os.path.join(directory, name + ".py")
                ) or os.path.exists(os.path.join(directory, name, "__init__.py")):
                    return False
            if directory == self.root:
                break
            directory = os.path.dirname(directory)
        return True

    def _names_are_stable(self) -> bool:
        dynamic, rebound = module_rebinding(
            self.tree,
            module_name_for(self.file),
            self.parents,
            isolated_code_calls=self.isolated,
        )
        if dynamic:
            return False
        written, computed = attribute_write_names(self.tree)
        patched = _patched_names(self.tree, self.parents)
        if computed or patched is None:
            return False
        relied = self.used_globals | self.used_attrs
        if relied & (rebound | patched) or self.used_attrs & written:
            return False
        return not _RELIED_DUNDERS & (written | patched)

    def _top_frame(self, function):
        if function is None:
            return _Frame(None, frozenset(), frozenset(), True)
        outer: set[str] = set()
        parent = self.parents.get(id(function))
        while parent is not None:
            if isinstance(parent, (*_FUNCTIONS, ast.Lambda)):
                outer |= _local_names(parent)
            parent = self.parents.get(id(parent))
        frame = _Frame(function, _local_names(function), frozenset(outer), True)
        for argument in _parameters(function.args):
            frame.env[argument.arg] = None
        return frame

    def _run(self, frame, body):
        if frame.function is not None and any(
            _has_nested_nonlocal(child) for child in frame.function.body
        ):
            frame.escaped = True
            return
        self._block(frame, body)
        if frame.closure_loads & frame.owned_names or frame.leaked & frame.owned_names:
            frame.escaped = True

    def _step(self):
        self.steps += 1
        if self.steps > _MAX_STEPS:
            raise _Unproven

    def _escape(self, frame, kind, expr=None):
        if self.audit_targets is not None and (_is_path(kind) or kind == _UNKNOWN_PATH):
            self.file_unsafe = True
        if kind in _NODES:
            frame.escaped = True
        elif kind == _EMPTY:
            for name in self._aliases(expr):
                frame.leaked.add(name)

    def _aliases(self, expr) -> set[str]:
        if isinstance(expr, ast.Name):
            return {expr.id}
        if isinstance(expr, ast.Starred):
            return self._aliases(expr.value)
        if isinstance(expr, ast.NamedExpr):
            return {expr.target.id} | self._aliases(expr.value)
        if isinstance(expr, ast.BoolOp):
            return set().union(*(self._aliases(value) for value in expr.values))
        if isinstance(expr, ast.IfExp):
            return self._aliases(expr.body) | self._aliases(expr.orelse)
        return set()

    def _consume(self, frame, expr):
        if expr is None:
            return None
        kind = self._value(frame, expr)
        self._escape(frame, kind, expr)
        return kind

    def _join_all(self, frame, kinds):
        result = kinds[0]
        for kind in kinds[1:]:
            result = _join(result, kind)
        if result is None and any(kind in _NODES for kind in kinds):
            frame.escaped = True
        return result

    def _join_envs(self, frame, envs):
        merged = {}
        for key in set().union(*envs):
            kinds = [env[key] for env in envs if key in env]
            merged[key] = self._join_all(frame, kinds)
        return merged

    def _value(self, frame, node):
        self._step()
        method = getattr(self, "_v_" + type(node).__name__, None)
        if method is not None:
            return method(frame, node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._consume(frame, child)
        return None

    def _v_Constant(self, frame, node):
        if self.audit_targets is not None and isinstance(node.value, str):
            text = node.value
            if text and os.path.isabs(text):
                kind = (_PATH, os.path.realpath(text))
                if self._source_path(kind):
                    return kind
            elif text:
                normalized = os.path.normpath(text)
                for target in self.audit_targets:
                    directory = target
                    while _inside(directory, self.root):
                        if directory.endswith(os.sep + normalized) or normalized == ".":
                            return _UNKNOWN_PATH
                        if directory == self.root:
                            break
                        directory = os.path.dirname(directory)
        return _DATA

    def _v_Name(self, frame, node):
        name = node.id
        if self.audit_targets is not None:
            resolved = self._resolved(frame, name)
            if resolved in _FILE_FUNCTIONS | _DYNAMIC_LOADS or (
                name == "open" and id(node) in self.builtins
            ):
                self.file_unsafe = True
        for scope in reversed(frame.scopes):
            if name in scope:
                return scope[name]
        if name in frame.local_names:
            return frame.env.get(name)
        if name in frame.outer_names:
            return None
        return self._global(name)

    def _global(self, name):
        if name == "__file__":
            self.used_globals.add(name)
            return (_PATH, self.file)
        value = self.constants.get(name)
        if value is None:
            return None
        self.used_globals.add(name)
        if name in self.constant_kinds:
            return self.constant_kinds[name]
        if name in self.constant_active:
            return None
        self.constant_active.add(name)
        frame = _Frame(None, frozenset(), frozenset(), False)
        kind = self._value(frame, value)
        self.constant_active.discard(name)
        if frame.escaped or kind in _NODES or kind == _EMPTY:
            kind = None
        self.constant_kinds[name] = kind
        return kind

    def _shadowed(self, frame, name) -> bool:
        if any(name in scope for scope in frame.scopes):
            return True
        return name in frame.local_names or name in frame.outer_names

    def _resolved(self, frame, dotted):
        root = dotted.split(".", 1)[0]
        if any(root in scope for scope in frame.scopes):
            return None
        resolved = self.imports.resolved_import(frame.function, dotted)
        if resolved is not None:
            self.used_globals.add(root)
        return resolved

    def _v_Attribute(self, frame, node):
        base = self._value(frame, node.value)
        attr = node.attr
        if self.audit_targets is not None:
            dotted = _dotted(node)
            resolved = None
            if dotted is not None:
                resolved = self._resolved(frame, dotted)
            if resolved in _FILE_FUNCTIONS | _DYNAMIC_LOADS:
                self.file_unsafe = True
            if base == _UNKNOWN_PATH:
                self.file_unsafe = True
            elif self._source_path(base) and attr not in {
                "parent",
                "parents",
                "name",
                "stem",
                "suffix",
                "suffixes",
            }:
                self.file_unsafe = True
        if _is_path(base):
            if attr == "parent":
                self.used_attrs.add(attr)
                return (_PATH, os.path.dirname(base[1]))
            if attr == "parents":
                self.used_attrs.add(attr)
                return (_PARENTS, base[1])
            return None
        if base in _NODES:
            if (attr.startswith("__") and attr.endswith("__")) or attr in _LIST_METHODS:
                frame.escaped = True
                return None
            if attr in _SCALAR_FIELDS:
                return _DATA
            return _TREE
        if base == _EMPTY:
            self._escape(frame, base, node.value)
        return None

    def _v_Subscript(self, frame, node):
        base = self._value(frame, node.value)
        self._consume(frame, node.slice)
        if isinstance(base, tuple) and base[0] == _PARENTS:
            if (
                isinstance(node.slice, ast.Constant)
                and type(node.slice.value) is int
                and node.slice.value >= 0
            ):
                self.used_attrs.add("__getitem__")
                path = base[1]
                for _ in range(node.slice.value + 1):
                    path = os.path.dirname(path)
                return (_PATH, path)
            return None
        if base in _NODES:
            return _TREE
        return None

    def _v_BinOp(self, frame, node):
        left = self._value(frame, node.left)
        if isinstance(node.op, ast.Div) and _is_path(left) and _is_str(node.right):
            parts = _segments(node.right.value)
            if parts is None:
                return None
            self.used_attrs.add("__truediv__")
            return (_PATH, os.path.join(left[1], *parts))
        right = self._value(frame, node.right)
        owned = _NODES | {_EMPTY}
        if isinstance(node.op, ast.Add) and left in owned and right in owned:
            return _TREE
        self._escape(frame, left, node.left)
        self._escape(frame, right, node.right)
        return None

    def _v_Compare(self, frame, node):
        operands = [node.left, *node.comparators]
        kinds = [self._value(frame, operand) for operand in operands]
        for index, operator in enumerate(node.ops):
            if isinstance(operator, (ast.Is, ast.IsNot)):
                continue
            pair = (
                (operands[index], kinds[index]),
                (operands[index + 1], kinds[index + 1]),
            )
            if any(kind is None for _, kind in pair):
                for operand, kind in pair:
                    self._escape(frame, kind, operand)
        return _DATA

    def _merge(self, frame, pairs):
        result = self._join_all(frame, [kind for _, kind in pairs])
        for expr, kind in pairs:
            if kind != _EMPTY:
                continue
            if result in _NODES:
                self._promote(frame, expr)
            else:
                self._escape(frame, kind, expr)
        if result == _EMPTY:
            return None
        return result

    def _v_BoolOp(self, frame, node):
        return self._merge(
            frame, [(value, self._value(frame, value)) for value in node.values]
        )

    def _v_IfExp(self, frame, node):
        self._value(frame, node.test)
        pairs = [
            (value, self._value(frame, value)) for value in (node.body, node.orelse)
        ]
        return self._merge(frame, pairs)

    def _v_UnaryOp(self, frame, node):
        if isinstance(node.op, ast.Not):
            self._value(frame, node.operand)
            return _DATA
        self._consume(frame, node.operand)
        return None

    def _v_NamedExpr(self, frame, node):
        kind = self._value(frame, node.value)
        self._assign(frame, node.target, kind, node.value)
        return kind

    def _v_List(self, frame, node):
        return self._sequence(frame, node)

    def _v_Tuple(self, frame, node):
        return self._sequence(frame, node)

    def _sequence(self, frame, node):
        if not node.elts:
            return _EMPTY
        items = []
        for element in node.elts:
            target = element
            if isinstance(element, ast.Starred):
                target = element.value
            items.append((target, self._value(frame, target)))
        if all(kind in _NODES | {_EMPTY} for _, kind in items):
            for target, kind in items:
                if kind == _EMPTY:
                    self._promote(frame, target)
            return _TREE
        for target, kind in items:
            self._escape(frame, kind, target)
        return None

    def _promote(self, frame, expr):
        for name in self._aliases(expr):
            if name in frame.local_names:
                frame.env[name] = _TREE
                frame.owned_names.add(name)
            else:
                frame.escaped = True

    def _v_Lambda(self, frame, node):
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            self._consume(frame, default)
        frame.closure_loads |= _free_loads(node)
        return None

    def _v_ListComp(self, frame, node):
        element = self._comprehension(frame, node, [node.elt])[0]
        if element in _NODES | {_EMPTY}:
            return _TREE
        return None

    def _v_GeneratorExp(self, frame, node):
        return self._v_ListComp(frame, node)

    def _v_SetComp(self, frame, node):
        for kind in self._comprehension(frame, node, [node.elt]):
            self._escape(frame, kind)
        return None

    def _v_DictComp(self, frame, node):
        for kind in self._comprehension(frame, node, [node.key, node.value]):
            self._escape(frame, kind)
        return None

    def _comprehension(self, frame, node, elements):
        scope: dict[str, object] = {}
        frame.scopes.append(scope)
        try:
            for generator in node.generators:
                iterated = self._value(frame, generator.iter)
                element = None
                if iterated in _NODES:
                    element = _TREE
                self._bind_scope(frame, scope, generator.target, element)
                for condition in generator.ifs:
                    self._value(frame, condition)
            return [self._value(frame, element) for element in elements]
        finally:
            frame.scopes.pop()

    def _bind_scope(self, frame, scope, target, kind):
        if isinstance(target, ast.Name):
            scope[target.id] = kind
            if kind in _NODES:
                frame.owned_names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                if isinstance(item, ast.Starred):
                    item = item.value
                self._bind_scope(frame, scope, item, kind)
        else:
            self._assign(frame, target, kind)

    def _v_Call(self, frame, node):
        func = node.func
        if (
            self.audit_targets is not None
            and isinstance(func, ast.Name)
            and func.id == "__import__"
        ):
            self.file_unsafe = True
        if isinstance(func, ast.Name):
            name = func.id
            if not self._shadowed(frame, name):
                if id(func) in self.builtins:
                    self.used_globals.add(name)
                    return self._builtin_call(frame, node, name)
                helper = self.helpers.get(name)
                if helper is not None:
                    self.used_globals.add(name)
                    return self._helper_call(frame, node, helper)
                if self.audit_targets is not None and self._plain_constructor(name):
                    for argument in node.args:
                        self._consume(frame, argument)
                    for item in node.keywords:
                        self._consume(frame, item.value)
                    return _DATA
            resolved = self._resolved(frame, name)
            if resolved is not None:
                return self._library_call(frame, node, resolved)
            return self._unknown_call(frame, node)
        if isinstance(func, ast.Attribute):
            dotted = _dotted(func)
            if dotted is not None:
                resolved = self._resolved(frame, dotted)
                if resolved is not None:
                    return self._library_call(frame, node, resolved)
            receiver = self._value(frame, func.value)
            return self._method_call(frame, node, receiver)
        return self._unknown_call(frame, node)

    def _unknown_call(self, frame, node):
        if self.audit_targets is None:
            frame.escaped = True
        else:
            self.file_unsafe = True
        self._consume(frame, node.func)
        for argument in node.args:
            self._consume(frame, argument)
        for item in node.keywords:
            self._consume(frame, item.value)
        return None

    def _plain_constructor(self, name):
        cls = self.classes.get(name)
        if (
            cls is None
            or self.counts.get(name) != 1
            or cls.bases
            or cls.keywords
            or cls.decorator_list
        ):
            return False
        for statement in cls.body:
            if isinstance(statement, _FUNCTIONS):
                if (
                    statement.name in {"__init__", "__new__"}
                    or statement.decorator_list
                ):
                    return False
            elif not isinstance(statement, ast.Pass) and not (
                isinstance(statement, ast.Expr) and _is_str(statement.value)
            ):
                return False
        return True

    def _consume_rest(self, frame, node, used):
        for argument in node.args:
            if argument not in used:
                self._consume(frame, argument)
        for item in node.keywords:
            if item.value not in used:
                self._consume(frame, item.value)

    def _positional(self, node, count) -> bool:
        return (
            len(node.args) == count
            and not node.keywords
            and not any(isinstance(arg, ast.Starred) for arg in node.args)
        )

    def _builtin_call(self, frame, node, name):
        if self.audit_targets is not None and name == "input":
            for argument in node.args:
                self._consume(frame, argument)
            return _DATA
        if self.audit_targets is not None and name == "open":
            return self._filesystem_call(frame, node, name)
        if name in _EXCEPTIONS or name == "dict":
            for argument in node.args:
                kind = self._consume(frame, argument)
                if name == "dict" and kind is None:
                    frame.escaped = True
            for item in node.keywords:
                self._consume(frame, item.value)
            return _DATA
        if name == "compile":
            return self._compile(frame, node)
        if name in _CODE_RUNNERS:
            return self._run_code(frame, node)
        if name == "next" and self._positional(node, 1):
            kind = self._value(frame, node.args[0])
            if kind in _NODES:
                return _TREE
            frame.escaped = True
            return None
        if name == "isinstance" and self._positional(node, 2):
            kind = self._value(frame, node.args[0])
            if not self._type_expression(frame, node.args[1]):
                self._consume(frame, node.args[1])
                self._escape(frame, kind, node.args[0])
            return _DATA
        if name == "getattr" and 2 <= len(node.args) <= 3 and not node.keywords:
            return self._getattr(frame, node)
        if name in _SEQUENCES and node.args and not node.keywords:
            if isinstance(node.args[0], ast.Starred):
                return self._unknown_call(frame, node)
            kind = self._value(frame, node.args[0])
            for extra in node.args[1:]:
                self._consume(frame, extra)
            if kind in _NODES:
                return _TREE
            frame.escaped = True
            return None
        if name in _READS and not node.keywords:
            kinds = [self._value(frame, argument) for argument in node.args]
            if any(kind is None for kind in kinds):
                frame.escaped = True
            if name == "str" and len(kinds) == 1:
                if _is_path(kinds[0]) or kinds[0] in {_DATA, _TEXT}:
                    return _DATA
                return None
            return _DATA
        return self._unknown_call(frame, node)

    def _type_expression(self, frame, node) -> bool:
        if isinstance(node, ast.Tuple):
            return all(self._type_expression(frame, element) for element in node.elts)
        dotted = _dotted(node)
        if dotted is None or "." not in dotted:
            return False
        resolved = self._resolved(frame, dotted)
        if resolved is None or not resolved.startswith("ast."):
            return False
        return isinstance(getattr(ast, resolved[4:], None), type)

    def _getattr(self, frame, node):
        kind = self._value(frame, node.args[0])
        name = node.args[1]
        if self.audit_targets is not None and _is_str(name):
            capabilities = {
                value.rsplit(".", 1)[-1] for value in _FILE_FUNCTIONS | _DYNAMIC_LOADS
            }
            if name.value in capabilities | _FILE_WRITES:
                self.file_unsafe = True
        default = None
        if len(node.args) == 3:
            default = node.args[2]
        if not _is_str(name) or (
            name.value.startswith("__") and name.value.endswith("__")
        ):
            self._escape(frame, kind, node.args[0])
            self._consume(frame, name)
            self._consume(frame, default)
            return None
        if kind not in _NODES:
            frame.escaped = True
            self._consume(frame, default)
            return None
        if default is not None:
            default_kind = self._value(frame, default)
            if default_kind != _EMPTY and not _is_none(default):
                self._escape(frame, default_kind, default)
                return None
        if name.value in _SCALAR_FIELDS:
            return _DATA
        return _TREE

    def _compile(self, frame, node):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            item.arg is None for item in node.keywords
        ):
            return self._unknown_call(frame, node)
        source = _argument(node, 0, "source")
        if source is None:
            return self._unknown_call(frame, node)
        mode = _argument(node, 2, "mode")
        flags = _argument(node, 3, "flags")
        constant_options = [
            _argument(node, 4, "dont_inherit"),
            _argument(node, 5, "optimize"),
        ]
        kind = self._value(frame, source)
        metadata = {source}
        filename = _argument(node, 1, "filename")
        if filename is not None and _is_str(filename):
            metadata.add(filename)
        self._consume_rest(frame, node, metadata)
        if not (_is_str(mode) and mode.value in _COMPILE_MODES):
            return None
        if flags is not None and not (
            isinstance(flags, ast.Constant) and flags.value == 0
        ):
            return None
        if any(
            option is not None and not isinstance(option, ast.Constant)
            for option in constant_options
        ):
            return None
        if kind in {_MODULE, _TEXT}:
            return _CODE
        return None

    def _run_code(self, frame, node):
        if not node.args or isinstance(node.args[0], ast.Starred):
            return self._unknown_call(frame, node)
        source = node.args[0]
        kind = self._value(frame, source)
        self._consume_rest(frame, node, {source})
        if frame.collect and kind in {_CODE, _TEXT} and id(node) in self.isolated:
            frame.candidates.add(id(node))
        return None

    def _library_call(self, frame, node, resolved):
        leaf = resolved.rsplit(".", 1)[-1]
        if self.audit_targets is not None and resolved in _PROJECT_READS:
            self.used_attrs.update(resolved.split(".")[1:])
            for argument in node.args:
                self._value(frame, argument)
            for item in node.keywords:
                self._value(frame, item.value)
            return _DATA
        if self.audit_targets is not None and resolved in _DYNAMIC_LOADS:
            self.file_unsafe = True
            return None
        if self.audit_targets is not None and resolved in _FILE_FUNCTIONS:
            return self._filesystem_call(frame, node, resolved)
        if resolved in _PATH_CLASSES and self._positional(node, 1):
            kind = self._value(frame, node.args[0])
            self.used_attrs.add(leaf)
            if _is_path(kind):
                return kind
            if self.audit_targets is not None:
                return _UNKNOWN_PATH
            return None
        if resolved == "ast.parse":
            return self._parse(frame, node)
        if resolved == "ast.fix_missing_locations" and self._positional(node, 1):
            self.used_attrs.add(leaf)
            kind = self._value(frame, node.args[0])
            if kind in _NODES:
                return kind
            return None
        if resolved in _NODE_ITERATORS and self._positional(node, 1):
            self.used_attrs.add(leaf)
            if self._value(frame, node.args[0]) in _NODES:
                return _TREE
            return None
        if resolved in _READ_ONLY_AST:
            self.used_attrs.add(leaf)
            for argument in node.args:
                self._value(frame, argument)
            for item in node.keywords:
                self._value(frame, item.value)
            return _DATA
        if resolved in _COPIES and self._positional(node, 1):
            self.used_attrs.add(leaf)
            kind = self._value(frame, node.args[0])
            if kind in _NODES:
                return kind
            if kind == _EMPTY:
                return _EMPTY
            return None
        if resolved in _SHELLS:
            return self._shell(frame, node, resolved)
        return self._unknown_call(frame, node)

    def _parse(self, frame, node):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            item.arg is None for item in node.keywords
        ):
            return self._unknown_call(frame, node)
        source = _argument(node, 0, "source")
        if source is None:
            return self._unknown_call(frame, node)
        mode = _argument(node, 2, "mode")
        kind = self._value(frame, source)
        metadata = {source}
        filename = _argument(node, 1, "filename")
        if filename is not None and _is_str(filename):
            metadata.add(filename)
        self._consume_rest(frame, node, metadata)
        if mode is not None and not (_is_str(mode) and mode.value in _COMPILE_MODES):
            return None
        if kind != _TEXT:
            return None
        self.used_attrs.add("parse")
        return _MODULE

    def _shell(self, frame, node, resolved):
        fields = getattr(getattr(ast, resolved[4:], None), "_fields", ())
        if len(node.args) > len(fields) or any(
            isinstance(arg, ast.Starred) for arg in node.args
        ):
            return self._unknown_call(frame, node)
        values = dict(zip(fields, node.args))
        for item in node.keywords:
            if item.arg is None or item.arg in values or item.arg not in fields:
                return self._unknown_call(frame, node)
            values[item.arg] = item.value
        valid = "body" in values
        kinds = {}
        for field, expr in values.items():
            if field == "name":
                valid = valid and _is_str(expr)
                continue
            kind = self._value(frame, expr)
            kinds[field] = (expr, kind)
            if kind not in _NODES | {_EMPTY} and not _is_none(expr):
                valid = False
        if not valid:
            for expr, kind in kinds.values():
                self._escape(frame, kind, expr)
            return None
        for expr, kind in kinds.values():
            if kind == _EMPTY:
                self._promote(frame, expr)
        self.used_attrs.add(resolved[4:])
        if resolved == "ast.ClassDef":
            return _TREE
        return _MODULE

    def _method_call(self, frame, node, receiver):
        attr = node.func.attr
        if self.audit_targets is not None:
            if receiver == _UNKNOWN_PATH:
                self.file_unsafe = True
            elif attr in _FILE_WRITES and not _is_path(receiver):
                self.file_unsafe = True
        if _is_path(receiver):
            return self._path_method(frame, node, receiver[1], attr)
        if self.audit_targets is None and receiver not in _NODES | {_EMPTY}:
            frame.escaped = True
        elif self.audit_targets is not None and receiver not in _NODES | {_EMPTY}:
            self.file_unsafe = True
        if receiver in _NODES | {_EMPTY}:
            if attr in _LIST_GROWTH and node.args and not node.keywords:
                if not any(isinstance(arg, ast.Starred) for arg in node.args):
                    return self._grow(frame, node, receiver, attr)
            if receiver in _NODES:
                frame.escaped = True
            else:
                self._escape(frame, receiver, node.func.value)
        for argument in node.args:
            self._consume(frame, argument)
        for item in node.keywords:
            self._consume(frame, item.value)
        return None

    def _grow(self, frame, node, receiver, attr):
        element = node.args[-1]
        if attr == "insert":
            if len(node.args) != 2:
                return self._unknown_call(frame, node)
            self._consume(frame, node.args[0])
        elif len(node.args) != 1:
            return self._unknown_call(frame, node)
        kind = self._value(frame, element)
        if kind in _NODES | {_EMPTY}:
            if kind == _EMPTY:
                self._promote(frame, element)
            target = node.func.value
            if receiver == _EMPTY:
                self._promote(frame, target)
            return _DATA
        self._escape(frame, kind, element)
        if receiver in _NODES:
            frame.escaped = True
        elif isinstance(node.func.value, ast.Name):
            if node.func.value.id in frame.local_names:
                frame.env[node.func.value.id] = None
        return _DATA

    def _path_method(self, frame, node, path, attr):
        arguments = [*node.args, *(item.value for item in node.keywords)]
        literal = all(isinstance(argument, ast.Constant) for argument in arguments)
        if any(item.arg is None for item in node.keywords):
            literal = False
        if attr in {"resolve", "absolute"} and literal and not node.args:
            if all(item.arg == "strict" for item in node.keywords):
                self.used_attrs.add(attr)
                if attr == "resolve":
                    return (_PATH, os.path.realpath(path))
                return (_PATH, os.path.abspath(path))
        if attr == "joinpath" and literal and not node.keywords:
            parts = []
            for argument in node.args:
                if not _is_str(argument) or _segments(argument.value) is None:
                    return None
                parts.extend(_segments(argument.value))
            self.used_attrs.add(attr)
            return (_PATH, os.path.join(path, *parts))
        if attr == "with_name" and self._positional(node, 1) and _is_str(node.args[0]):
            parts = _segments(node.args[0].value)
            if parts is None or len(parts) != 1:
                return None
            self.used_attrs.add(attr)
            return (_PATH, os.path.join(os.path.dirname(path), parts[0]))
        if attr in {"read_text", "read_bytes"} and literal and self._owned_file(path):
            self.used_attrs.add(attr)
            return _TEXT
        if self.audit_targets is not None:
            if attr in _PATH_READS:
                return _DATA
            if self._source_path((_PATH, path)):
                self.file_unsafe = True
        for argument in arguments:
            self._consume(frame, argument)
        return None

    def _owned_file(self, path) -> bool:
        if path in self.file_checks:
            return self.file_checks[path]
        real = os.path.realpath(path)
        owned = (
            path.endswith(".py")
            and real.endswith(".py")
            and _inside(real, self.root)
            and os.path.isfile(real)
        )
        if owned:
            relative = os.path.relpath(real, self.root).split(os.sep)
            owned = not any(part in _SKIP_DIRS for part in relative[:-1])
        self.file_checks[path] = owned
        return owned

    def _helper_call(self, frame, node, helper):
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            item.arg is None for item in node.keywords
        ):
            return self._unknown_call(frame, node)
        if isinstance(helper, ast.AsyncFunctionDef) or any(
            isinstance(child, (ast.Yield, ast.YieldFrom)) for child in ast.walk(helper)
        ):
            return self._unknown_call(frame, node)
        arguments = helper.args
        positional = [*arguments.posonlyargs, *arguments.args]
        keywords = {
            argument.arg for argument in [*arguments.args, *arguments.kwonlyargs]
        }
        kinds: dict[str, object] = {}
        passed = []
        for index, argument in enumerate(node.args):
            kind = self._value(frame, argument)
            passed.append((argument, kind))
            if index < len(positional):
                kinds[positional[index].arg] = kind
            elif arguments.vararg is not None:
                self._escape(frame, kind, argument)
            else:
                return self._unknown_call(frame, node)
        for item in node.keywords:
            kind = self._value(frame, item.value)
            passed.append((item.value, kind))
            if item.arg in keywords and item.arg not in kinds:
                kinds[item.arg] = kind
            elif arguments.kwarg is not None:
                self._escape(frame, kind, item.value)
            else:
                return self._unknown_call(frame, node)
        for argument, kind in passed:
            if kind == _EMPTY:
                self._escape(frame, kind, argument)
        for parameter, default in self._defaults(helper):
            if parameter not in kinds:
                kinds[parameter] = self._default_kind(default)
        key = (id(helper), tuple(sorted(kinds.items(), key=lambda item: item[0])))
        summary = self._summary(helper, key, kinds)
        if summary is None or summary[1]:
            for argument, kind in passed:
                self._escape(frame, kind, argument)
            return None
        if summary[0] == _EMPTY:
            return None
        return summary[0]

    def _defaults(self, helper):
        arguments = helper.args
        positional = [*arguments.posonlyargs, *arguments.args]
        pairs = list(
            zip(
                positional[len(positional) - len(arguments.defaults) :],
                arguments.defaults,
            )
        )
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
            if default is not None:
                pairs.append((argument, default))
        return [(argument.arg, default) for argument, default in pairs]

    def _default_kind(self, default):
        frame = _Frame(None, frozenset(), frozenset(), False)
        kind = self._value(frame, default)
        if frame.escaped or kind in _NODES or kind == _EMPTY:
            return None
        return kind

    def _summary(self, helper, key, kinds):
        if key in self.summaries:
            return self.summaries[key]
        if key in self.active or len(self.active) >= _MAX_HELPER_DEPTH:
            return None
        self.active.add(key)
        try:
            frame = _Frame(helper, _local_names(helper), frozenset(), False)
            for argument in _parameters(helper.args):
                kind = kinds.get(argument.arg)
                frame.env[argument.arg] = kind
                if kind in _NODES:
                    frame.owned_names.add(argument.arg)
            self._run(frame, helper.body)
            result = _DATA
            if frame.returns:
                result = self._join_all(frame, frame.returns)
        finally:
            self.active.discard(key)
        summary = (result, frame.escaped)
        self.summaries[key] = summary
        return summary

    def _block(self, frame, body):
        for statement in body:
            self._statement(frame, statement)

    def _states(self, frame, body):
        states = [dict(frame.env)]
        for statement in body:
            self._statement(frame, statement)
            states.append(dict(frame.env))
        return states

    def _statement(self, frame, node):
        self._step()
        if isinstance(node, ast.Expr):
            self._value(frame, node.value)
        elif isinstance(node, ast.Assign):
            kind = self._value(frame, node.value)
            for target in node.targets:
                self._assign(frame, target, kind, node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                kind = self._value(frame, node.value)
                self._assign(frame, node.target, kind, node.value)
            elif isinstance(node.target, ast.Name):
                frame.env.pop(node.target.id, None)
        elif isinstance(node, ast.AugAssign):
            self._augmented(frame, node)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self._delete(frame, target)
        elif isinstance(node, ast.Return):
            self._return(frame, node)
        elif isinstance(node, (ast.Raise, ast.Assert)):
            for child in ast.iter_child_nodes(node):
                self._consume(frame, child)
        elif isinstance(node, ast.If):
            self._value(frame, node.test)
            before = dict(frame.env)
            self._block(frame, node.body)
            after_body = frame.env
            frame.env = before
            self._block(frame, node.orelse)
            frame.env = self._join_envs(frame, [after_body, frame.env])
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            iterated = self._value(frame, node.iter)
            element = None
            if iterated in _NODES:
                element = _TREE
            self._loop(frame, node, None, node.target, element)
        elif isinstance(node, ast.While):
            self._loop(frame, node, node.test, None, None)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._consume(frame, item.context_expr)
                if item.optional_vars is not None:
                    self._assign(frame, item.optional_vars, None)
            frame.env = self._join_envs(frame, self._states(frame, node.body))
        elif isinstance(node, _TRY):
            self._try(frame, node)
        elif isinstance(node, ast.Match):
            self._match(frame, node)
        elif isinstance(node, _SCOPES):
            self._definition(frame, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                self._assign(frame, ast.Name(id=bound, ctx=ast.Store()), None)
        elif isinstance(node, ast.Break) and frame.breaks:
            frame.breaks[-1].append(dict(frame.env))
        elif isinstance(node, ast.Continue) and frame.continues:
            frame.continues[-1].append(dict(frame.env))
        elif not isinstance(
            node, (ast.Pass, ast.Global, ast.Nonlocal, ast.Break, ast.Continue)
        ):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._consume(frame, child)
                elif isinstance(child, ast.stmt):
                    frame.escaped = True

    def _return(self, frame, node):
        if node.value is None or _is_none(node.value):
            return
        kind = self._value(frame, node.value)
        if kind == _EMPTY:
            self._escape(frame, kind, node.value)
        frame.returns.append(kind)

    def _loop(self, frame, node, test, target, element):
        frame.breaks.append([])
        frame.continues.append([])
        head = dict(frame.env)
        stable = False
        for _ in range(_MAX_LOOP_PASSES):
            frame.env = dict(head)
            if test is not None:
                self._value(frame, test)
            if target is not None:
                self._assign(frame, target, element)
            self._block(frame, node.body)
            merged = self._join_envs(frame, [head, frame.env, *frame.continues[-1]])
            if merged == head:
                stable = True
                break
            head = merged
        exits = frame.breaks.pop()
        frame.continues.pop()
        if not stable:
            frame.escaped = True
        frame.env = dict(head)
        self._block(frame, node.orelse)
        frame.env = self._join_envs(frame, [frame.env, *exits])

    def _try(self, frame, node):
        states = self._states(frame, node.body)
        raised = self._join_envs(frame, states)
        self._block(frame, node.orelse)
        outcomes = [frame.env]
        for handler in node.handlers:
            frame.env = dict(raised)
            self._consume(frame, handler.type)
            if handler.name:
                self._assign(frame, ast.Name(id=handler.name, ctx=ast.Store()), None)
            outcomes.extend(self._states(frame, handler.body))
        frame.env = self._join_envs(frame, [*outcomes, raised])
        self._block(frame, node.finalbody)

    def _match(self, frame, node):
        subject = self._value(frame, node.subject)
        if subject in _NODES:
            frame.escaped = True
        before = dict(frame.env)
        outcomes = [before]
        for case in node.cases:
            frame.env = dict(before)
            for child in ast.walk(case.pattern):
                name = getattr(child, "name", None) or getattr(child, "rest", None)
                if isinstance(name, str):
                    self._assign(frame, ast.Name(id=name, ctx=ast.Store()), None)
            if case.guard is not None:
                self._value(frame, case.guard)
            self._block(frame, case.body)
            outcomes.append(frame.env)
        frame.env = self._join_envs(frame, outcomes)

    def _definition(self, frame, node):
        if isinstance(node, ast.ClassDef):
            expressions = [*node.decorator_list, *node.bases]
            expressions.extend(item.value for item in node.keywords)
        else:
            expressions = [*node.decorator_list, *node.args.defaults]
            expressions.extend(default for default in node.args.kw_defaults if default)
        for expression in expressions:
            self._consume(frame, expression)
        frame.closure_loads |= _free_loads(node)
        self._assign(frame, ast.Name(id=node.name, ctx=ast.Store()), None)

    def _assign(self, frame, target, kind, value=None):
        if isinstance(target, ast.Name):
            if target.id in frame.local_names:
                frame.env[target.id] = kind
                if kind in _NODES:
                    frame.owned_names.add(target.id)
                if (
                    kind == _EMPTY
                    and value is not None
                    and not isinstance(value, (ast.List, ast.Tuple))
                ):
                    self._escape(frame, kind, value)
                    frame.env[target.id] = None
            else:
                self._escape(frame, kind, value)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            element = None
            if kind in _NODES:
                element = _TREE
            for item in target.elts:
                if isinstance(item, ast.Starred):
                    self._assign(frame, item.value, element)
                else:
                    self._assign(frame, item, element)
            if kind == _EMPTY:
                self._escape(frame, kind, value)
            return
        if isinstance(target, ast.Starred):
            self._assign(frame, target.value, kind, value)
            return
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            base = self._value(frame, target.value)
            if isinstance(target, ast.Subscript):
                self._consume(frame, target.slice)
            if base in _NODES | {_EMPTY}:
                if kind in _NODES or (value is not None and _is_none(value)):
                    return
                if kind == _EMPTY and value is not None:
                    self._promote(frame, value)
                    return
                if base in _NODES:
                    frame.escaped = True
                else:
                    self._escape(frame, base, target.value)
                return
            self._escape(frame, kind, value)
            return
        frame.escaped = True

    def _augmented(self, frame, node):
        target = node.target
        right = self._value(frame, node.value)
        if isinstance(target, ast.Name):
            current = self._v_Name(frame, target)
        else:
            current = self._value(frame, target)
        owned = _NODES | {_EMPTY}
        result = None
        if isinstance(node.op, ast.Add) and current in owned and right in owned:
            result = _TREE
        else:
            self._escape(frame, current, target)
            self._escape(frame, right, node.value)
        if isinstance(target, ast.Name):
            self._assign(frame, target, result)
        elif isinstance(target, ast.Subscript):
            self._consume(frame, target.slice)

    def _delete(self, frame, target):
        if isinstance(target, ast.Name):
            frame.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._delete(frame, item)
        elif isinstance(target, ast.Attribute):
            self._value(frame, target.value)
        elif isinstance(target, ast.Subscript):
            self._value(frame, target.value)
            self._consume(frame, target.slice)


def _mentions_code_runner(tree) -> bool:
    runner = False
    location = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            runner = runner or node.func.id in _CODE_RUNNERS
        elif isinstance(node, ast.Name) and node.id == "__file__":
            location = True
        if runner and location:
            return True
    return False


def source_owned_code_calls(tree, file_path=None, project_root=None) -> frozenset[int]:
    """Ids of ``exec``/``eval`` calls proved to run the project's own source."""
    if not isinstance(tree, ast.Module) or not file_path or not project_root:
        return frozenset()
    if not _mentions_code_runner(tree):
        return frozenset()
    try:
        return _Proof(tree, file_path, project_root).run()
    except (_Unproven, RecursionError, OSError, ValueError):
        return frozenset()
