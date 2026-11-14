"""Path traversal defences that do not hold.

The anchor is the code's own defence against ``..``: writing one shows the
author treats the value as untrusted. Two well-known failures are reported
when the defended value then reaches a filesystem operation in the same
function and no stronger check is present:

* ``value.replace("../", "")`` removes the sequence once, so ``....//``
  still leaves ``../`` behind;
* ``..`` is rejected or removed, but the value is then joined onto a base
  directory, where an absolute path replaces the base.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.danger_fs.prefix_separator import (
    SEPARATOR_NAMES,
    bound_names,
    dotted,
    ends_with_separator,
    module_level_imports,
    scope_bindings,
)

RULE_ID = "SKY-D378"
SEVERITY = "MEDIUM"
SINGLE_PASS_STRIP = "single_pass_strip"
ABSOLUTE_PATH = "absolute_path"

_FUNCTION_SINKS = frozenset(
    {
        "open",
        "io.open",
        "os.open",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "os.mkdir",
        "os.makedirs",
        "os.rename",
        "os.replace",
        "os.listdir",
        "os.scandir",
        "os.chmod",
        "os.chown",
        "os.symlink",
        "os.link",
        "os.truncate",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "send_file",
        "flask.send_file",
        "FileResponse",
    }
)
_METHOD_SINKS = frozenset(
    {
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "mkdir",
        "rmdir",
        "touch",
        "iterdir",
    }
)
_JOIN_FUNCTIONS = frozenset(
    {"os.path.join", "posixpath.join", "ntpath.join", "path.join", "join"}
)
_PATH_CLASSES = frozenset(
    {"Path", "PurePath", "PosixPath", "PurePosixPath", "WindowsPath", "PureWindowsPath"}
)
_CONTAINMENT_CALLS = frozenset(
    {"is_relative_to", "relative_to", "commonpath", "safe_join"}
)
_NORMALIZERS = frozenset({"realpath", "resolve", "abspath", "normpath"})
_CHARACTER_PREFIX_CALLS = frozenset({"commonprefix"})
_NAME_ONLY_CALLS = frozenset({"basename", "secure_filename"})
_ABSOLUTE_CALLS = frozenset({"isabs", "is_absolute"})
_LEADING_STRIPS = frozenset({"lstrip", "strip", "removeprefix"})
_SEPARATORS = ("/", "\\")
_PROBES = frozenset(
    {
        "exists",
        "lexists",
        "isfile",
        "isdir",
        "islink",
        "is_file",
        "is_dir",
        "is_symlink",
        "getsize",
    }
)
_PLAIN_TEXT_METHODS = frozenset(
    {"startswith", "endswith", "find", "count", "index", "lower", "upper", "strip"}
)
_TERMINATORS = (ast.Raise, ast.Return, ast.Continue, ast.Break)


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _last_name(call):
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _text(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _names_in(node):
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _dot_dot_text(text):
    """True for a text that is only dots and separators and holds ``..``."""
    if text is None or ".." not in text:
        return False
    return all(char in "./\\" for char in text)


def _scope_nodes(scope):
    """Nodes of one function or module body, without nested definitions."""
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _strip_call(node):
    """``(subject, removed)`` for ``subject.replace(<dots and separators>, "")``."""
    if not isinstance(node, ast.Call) or node.keywords or len(node.args) != 2:
        return None
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "replace":
        return None
    removed = _text(node.args[0])
    if not _dot_dot_text(removed) or _text(node.args[1]) != "":
        return None
    return func.value, removed


def _rejected_names(test):
    """Names a condition checks for ``..``: ``".." in name``,
    ``name.startswith("..")``, ``name.find("..")``, ``name.count("..")``."""
    names = set()
    for node in ast.walk(test):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
                continue
            right = node.comparators[0]
            if _dot_dot_text(_text(node.left)) and isinstance(right, ast.Name):
                names.add(right.id)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"startswith", "find", "count", "index"}:
                continue
            if not isinstance(node.func.value, ast.Name) or len(node.args) != 1:
                continue
            if _dot_dot_text(_text(node.args[0])):
                names.add(node.func.value.id)
    return names


class _Module:
    """What the module binds: plain constants and trusted path imports."""

    def __init__(self, tree):
        self.rebound = bound_names(tree)
        self.bindings = scope_bindings(tree)
        self.globals = {
            name
            for node in ast.walk(tree)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        self.imports = module_level_imports(tree)

    def binding(self, name):
        """The module-level value of ``name``, for a tuple whose members were
        written where the module binds them."""
        if name in self.globals:
            return None
        values = self.bindings.get(name)
        if values and len(values) == 1:
            return values[0]
        return None

    def canonical(self, node):
        name = dotted(node)
        if name is None:
            return None
        head, _, rest = name.partition(".")
        if head in self.rebound:
            return None
        base = self.imports.get(head)
        if base is None:
            return None
        if rest:
            return f"{base}.{rest}"
        return base


class _Scope:
    def __init__(self, scope, module):
        self.module = module
        self.own = scope_bindings(scope)
        self.nodes = sorted(
            _scope_nodes(scope),
            key=lambda node: (
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
            ),
        )
        self.calls = [node for node in self.nodes if isinstance(node, ast.Call)]
        self.assignments = [
            node
            for node in self.nodes
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        ]

    def loop_strips(self):
        """Removed texts whose removal repeats until none is left."""
        texts = set()
        for node in self.nodes:
            if isinstance(node, ast.While):
                for inner in ast.walk(node.test):
                    text = _text(inner)
                    if _dot_dot_text(text):
                        texts.add(text)
        return texts

    def contained(self):
        normalized = False
        prefix_checked = False
        for call in self.calls:
            name = _last_name(call)
            if name in _CONTAINMENT_CALLS or name in _NAME_ONLY_CALLS:
                return True
            if name in _NORMALIZERS:
                normalized = True
            if name == "startswith" and self.separator_prefix(call):
                prefix_checked = True
        for node in self.nodes:
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "name"
                and isinstance(node.value, ast.Call)
            ):
                return True
        return normalized and prefix_checked

    def binding(self, name):
        if name in self.own:
            values = self.own[name]
            if len(values) == 1:
                return values[0]
            return None
        if name in self.module.globals:
            return None
        values = self.module.bindings.get(name)
        if values and len(values) == 1:
            return values[0]
        return None

    def separator_prefix(self, call):
        if len(call.args) != 1 or call.keywords:
            return False
        return ends_with_separator(
            call.args[0], self.binding, self.module.canonical, self.module.binding
        )

    def absolute_handled(self, name):
        for call in self.calls:
            last = _last_name(call)
            if last in _ABSOLUTE_CALLS:
                return True
            func = call.func
            if not isinstance(func, ast.Attribute):
                continue
            if not isinstance(func.value, ast.Name) or func.value.id != name:
                continue
            if func.attr in _LEADING_STRIPS:
                return True
            if func.attr == "startswith" and call.args and self.separator(call.args[0]):
                return True
        for node in self.nodes:
            if not isinstance(node, ast.Compare):
                continue
            left = node.left
            if (
                isinstance(left, ast.Subscript)
                and isinstance(left.value, ast.Name)
                and left.value.id == name
                and any(self.separator(item) for item in node.comparators)
            ):
                return True
        return False

    def separator(self, node):
        if isinstance(node, ast.Tuple):
            return any(self.separator(item) for item in node.elts)
        if _text(node) in _SEPARATORS:
            return True
        return (
            _dotted(node) in {"os.sep", "os.path.sep", "os.altsep", "sep"}
            or self.module.canonical(node) in SEPARATOR_NAMES
        )

    def otherwise_validated(self, names):
        """True when a condition checks a tracked name in some other way: a
        call that takes it, a membership test against a collection, or a
        pattern. Probes such as ``os.path.exists`` are not checks."""
        for node in self.nodes:
            test = None
            if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
                test = node.test
            if test is None:
                continue
            for inner in ast.walk(test):
                if isinstance(inner, ast.Call):
                    if (
                        self.dot_dot_call(inner)
                        or _last_name(inner) in _PROBES
                        or _last_name(inner) in _CHARACTER_PREFIX_CALLS
                    ):
                        continue
                    arguments = [
                        *inner.args,
                        *[keyword.value for keyword in inner.keywords],
                    ]
                    if any(names & _names_in(argument) for argument in arguments):
                        return True
                    func = inner.func
                    if (
                        isinstance(func, ast.Attribute)
                        and names & _names_in(func.value)
                        and func.attr not in _PLAIN_TEXT_METHODS
                    ):
                        return True
                elif isinstance(inner, ast.Compare) and len(inner.ops) == 1:
                    if not isinstance(inner.ops[0], (ast.In, ast.NotIn)):
                        continue
                    if isinstance(inner.left, ast.Name) and inner.left.id in names:
                        return True
        return False

    def dot_dot_call(self, call):
        func = call.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and len(call.args) == 1
            and _dot_dot_text(_text(call.args[0]))
        )

    def joined_after_base(self, node, names):
        """True when a tracked name is joined after another path part."""
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                called = _dotted(inner.func)
                last = _last_name(inner)
                later = inner.args[1:]
                if called in _JOIN_FUNCTIONS or last in _PATH_CLASSES:
                    if any(names & _names_in(argument) for argument in later):
                        return True
                if last == "joinpath" and any(
                    names & _names_in(argument) for argument in inner.args
                ):
                    return True
            elif isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Div):
                if names & _names_in(inner.right):
                    return True
        return False

    def sink_argument(self, call):
        """The path expression a filesystem call operates on, or None."""
        called = _dotted(call.func)
        if called in _FUNCTION_SINKS:
            if call.args:
                return call.args[0]
            for keyword in call.keywords:
                if keyword.arg in {
                    "file",
                    "path",
                    "src",
                    "dst",
                    "name",
                    "path_or_file",
                }:
                    return keyword.value
            return None
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr in _METHOD_SINKS:
            if isinstance(func.value, ast.Name) and func.value.id in {
                "os",
                "io",
                "shutil",
            }:
                return None
            return func.value
        return None


def _defences(scope):
    """``(line, kind, name, removed)`` for each ``..`` defence in the scope."""
    found = []
    loops = scope.loop_strips()
    for node in scope.nodes:
        if isinstance(node, (ast.If, ast.Assert)):
            for name in sorted(_rejected_names(node.test)):
                found.append((node.lineno, "reject", name, None))
    for node in scope.assignments:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        for inner in ast.walk(node.value):
            stripped = _strip_call(inner)
            if stripped is None or stripped[1] in loops:
                continue
            found.append((node.lineno, "strip", target.id, stripped[1]))
    return found


def _inline_strips(scope, call, loops):
    argument = scope.sink_argument(call)
    if argument is None:
        return None
    for inner in ast.walk(argument):
        stripped = _strip_call(inner)
        if stripped is not None and stripped[1] not in loops:
            return stripped[1]
    return None


def _bypass(removed):
    return removed[:1] + removed + removed[1:]


def _single_pass(removed):
    return any(separator in removed for separator in _SEPARATORS)


def _finding(file_path, symbol, call, kind, message, defence_line):
    return {
        "rule_id": RULE_ID,
        "severity": SEVERITY,
        "message": message,
        "file": file_path,
        "line": call.lineno,
        "col": call.col_offset,
        "symbol": symbol,
        "metadata": {"path_defence": {"kind": kind, "line": defence_line}},
    }


def _strip_message(removed, line):
    return (
        f"Incomplete path traversal defence: `{removed}` is removed only once on line {line}, so input "
        f"like `{_bypass(removed)}` still leaves `{removed}` in the path that reaches this file operation. "
        "Resolve the path and check that it stays inside the base directory."
    )


def _absolute_message(name, line):
    return (
        f"Incomplete path traversal defence: `..` in `{name}` is handled on line {line}, but `{name}` is "
        "then joined onto a base directory, and an absolute path replaces the base. Resolve the joined "
        "path and check that it stays inside the base directory."
    )


def _check_scope(scope_node, symbol, file_path, findings, module):
    scope = _Scope(scope_node, module)
    if not scope.calls:
        return
    loops = scope.loop_strips()
    defences = _defences(scope)
    inline = [call for call in scope.calls if _inline_strips(scope, call, loops)]
    if not defences and not inline:
        return
    if scope.contained():
        return
    reported = set()
    for call in inline:
        removed = _inline_strips(scope, call, loops)
        if not _single_pass(removed):
            continue
        findings.append(
            _finding(
                file_path,
                symbol,
                call,
                SINGLE_PASS_STRIP,
                _strip_message(removed, call.lineno),
                call.lineno,
            )
        )
        reported.add(call.lineno)
    for line, how, name, removed in defences:
        tracked = {name}
        joined = False
        emitted = False
        for node in scope.nodes:
            node_line = getattr(node, "lineno", 0)
            if node_line < line:
                continue
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                if node_line == line and how == "strip":
                    continue
                if tracked & _names_in(node.value):
                    if scope.joined_after_base(node.value, tracked):
                        joined = True
                    tracked.add(node.targets[0].id)
                continue
            if not isinstance(node, ast.Call) or emitted:
                continue
            argument = scope.sink_argument(node)
            if argument is None or not tracked & _names_in(argument):
                continue
            if node.lineno in reported:
                emitted = True
                continue
            if how == "strip" and _single_pass(removed):
                findings.append(
                    _finding(
                        file_path,
                        symbol,
                        node,
                        SINGLE_PASS_STRIP,
                        _strip_message(removed, line),
                        line,
                    )
                )
                reported.add(node.lineno)
                emitted = True
                continue
            if not joined and not scope.joined_after_base(argument, tracked):
                continue
            if scope.absolute_handled(name) or scope.otherwise_validated(tracked):
                emitted = True
                continue
            findings.append(
                _finding(
                    file_path,
                    symbol,
                    node,
                    ABSOLUTE_PATH,
                    _absolute_message(name, line),
                    line,
                )
            )
            reported.add(node.lineno)
            emitted = True


def _mentions_dot_dot(node):
    return any(_dot_dot_text(_text(inner)) for inner in ast.walk(node))


def scan(tree, file_path, findings):
    file_path = str(file_path)
    try:
        if not _mentions_dot_dot(tree):
            return
        module = _Module(tree)
        _check_scope(tree, "<module>", file_path, findings, module)
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and _mentions_dot_dot(node):
                _check_scope(node, node.name, file_path, findings, module)
    except RecursionError:
        return
