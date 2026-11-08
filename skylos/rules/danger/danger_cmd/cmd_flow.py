from __future__ import annotations
import ast
import shlex
import sys
from skylos.rules.danger.project_source import project_source_snapshot
from skylos.rules.danger.import_proof import _effects
from skylos.rules.danger.taint import TaintVisitor, CMD_SANITIZERS
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex
from skylos.rules.danger.callable_bindings import callable_names


# The bounded whole-command proof must remain valid under another neutral
# prefix. A literal program suffix that could become a code interpreter or a
# shell wrapper cannot provide that guarantee. This narrows a safety proof;
# it is not an independent interpreter detector.
_CODE_COMMANDS = frozenset(
    {
        "eval", "exec", "source", "sh", "bash", "dash", "ash", "ksh", "zsh",
        "csh", "tcsh", "fish", "python", "python2", "python3", "pypy", "pypy3",
        "perl", "ruby", "node", "nodejs", "php", "lua", "luajit", "awk",
        "gawk", "mawk", "nawk", "sed", "tclsh", "wish", "pwsh", "powershell",
        "osascript", "R", "Rscript", "env", "sudo", "doas", "command", "builtin",
        "busybox", "timeout", "nice", "nohup", "setsid", "chroot", "xargs", "find",
    }
)  # fmt: skip


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

    return None


SHELL_STRING_CALLS = {
    "os.system": "os.system",
    "os.popen": "os.popen",
    "subprocess.getoutput": "subprocess.getoutput",
    "subprocess.getstatusoutput": "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell": "asyncio.create_subprocess_shell",
    "asyncio.subprocess.create_subprocess_shell": "asyncio.create_subprocess_shell",
}

_EXEC_PROGRAM_POSITIONS = {
    **{
        f"os.{name}": 0
        for name in (
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "posix_spawn",
            "posix_spawnp",
        )
    },
    **{
        f"os.{name}": 1
        for name in (
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
        )
    },
}

_ARGV_LIST_CALLS = frozenset(
    {
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.posix_spawn",
        "os.posix_spawnp",
    }
)

_SHELL_PROGRAMS = frozenset({"sh", "bash", "dash", "ksh", "zsh", "ash", "csh", "tcsh"})

_FALSY_SHELL_VALUES = (False, None, 0)


def _module_import_aliases(tree) -> dict[str, str]:
    """Local names bound by imports anywhere in the module. A name that is
    also bound another way, or imported from two places, is left out."""
    aliases: dict[str, str | None] = {}
    if tree is None:
        return {}

    def bind(name, target):
        if name in aliases and aliases[name] != target:
            aliases[name] = None
        else:
            aliases[name] = target

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bind(alias.asname, alias.name)
                else:
                    top = alias.name.split(".", 1)[0]
                    bind(top, top)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    bind(alias.asname or alias.name, f"{node.module}.{alias.name}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in aliases:
                aliases[node.name] = None
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            if node.id in aliases:
                aliases[node.id] = None
        elif isinstance(node, ast.arg) and node.arg in aliases:
            aliases[node.arg] = None
    return {name: target for name, target in aliases.items() if target}


def _constant_text(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_shell_program(node) -> bool:
    text = _constant_text(node)
    if text is None:
        return False
    return text.rsplit("/", 1)[-1] in _SHELL_PROGRAMS


def _shell_may_be_enabled(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg != "shell":
            continue
        if isinstance(kw.value, ast.Constant):
            return kw.value.value not in _FALSY_SHELL_VALUES
        return True
    return False


def _shell_is_literal_true(node: ast.Call) -> bool:
    return any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in node.keywords
    )


def _command_argument(node: ast.Call, keywords=("args", "cmd", "command")):
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in keywords:
            return kw.value
    return None


class _CmdFlowChecker(TaintVisitor):
    resolve_sanitizer_imports = True
    OS_SYSTEM = "os.system"
    SUBPROC_PREFIX = "subprocess."

    def __init__(self, file_path, findings, sanitizers=None, tree=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.import_aliases = _module_import_aliases(tree)
        self._shell_values = [{}]

    def _resolved_name(self, node: ast.Call) -> str | None:
        qn = _qualified_name(node)
        if not qn:
            return None
        imported = self.untrusted_sources.resolved_import(self._current_function(), qn)
        if imported:
            return imported
        head, separator, rest = qn.partition(".")
        target = self.import_aliases.get(head)
        if target is None:
            return qn
        if separator:
            return f"{target}.{rest}"
        return target

    def _report(self, node, message, with_symbol=True):
        finding = {
            "rule_id": "SKY-D212",
            "severity": "CRITICAL",
            "message": message,
            "file": str(self.file_path),
            "line": node.lineno,
            "col": node.col_offset,
        }
        if with_symbol:
            finding["symbol"] = self._current_symbol()
        self.findings.append(finding)

    def _shell_script_is_tainted(self, argv) -> bool:
        """``["sh", "-c", script]``: the element after ``-c`` is a shell
        script."""
        if not argv or not _is_shell_program(argv[0]):
            return False
        for index, element in enumerate(argv[1:-1], start=1):
            if _constant_text(element) == "-c":
                return self._shell_is_tainted(argv[index + 1])
        return False

    def _exec_argv(self, node: ast.Call, name: str, position: int):
        if name in _ARGV_LIST_CALLS:
            if len(node.args) > position + 1:
                argv = node.args[position + 1]
                if isinstance(argv, (ast.List, ast.Tuple)):
                    return [node.args[position], *argv.elts[1:]]
            return None
        return [node.args[position], *node.args[position + 2 :]]

    def _check_exec_family(self, node: ast.Call, name: str) -> None:
        position = _EXEC_PROGRAM_POSITIONS.get(name)
        if position is None or len(node.args) <= position:
            return
        program = node.args[position]
        if self.is_tainted(program):
            self._report(
                node,
                f"Possible command injection ({name}): tainted program path.",
            )
            return
        argv = self._exec_argv(node, name, position)
        if argv and self._shell_script_is_tainted(argv):
            self._report(
                node,
                f"Possible command injection ({name}): tainted script passed to a shell with -c.",
            )

    def _check_pty_spawn(self, node: ast.Call) -> None:
        argv = _command_argument(node, ("argv",))
        if argv is None:
            return
        if isinstance(argv, (ast.List, ast.Tuple)):
            if not argv.elts:
                return
            if self.is_tainted(argv.elts[0]):
                self._report(
                    node, "Possible command injection (pty.spawn): tainted program."
                )
            elif self._shell_script_is_tainted(argv.elts):
                self._report(
                    node,
                    "Possible command injection (pty.spawn): tainted script passed to a shell with -c.",
                )
            return
        if self.is_tainted(argv):
            self._report(
                node, "Possible command injection (pty.spawn): tainted command."
            )

    def _check_argv_shell_script(self, node: ast.Call, name: str) -> bool:
        if name.startswith("asyncio.") and "create_subprocess_exec" in name:
            argv = list(node.args)
        else:
            command = _command_argument(node, ("args",))
            if not isinstance(command, (ast.List, ast.Tuple)):
                return False
            argv = command.elts
        if not self._shell_script_is_tainted(argv):
            return False
        self._report(
            node,
            f"Possible command injection ({name}): tainted script passed to a shell with -c.",
        )
        return True

    def _push(self):
        super()._push()
        self._shell_values.append({})

    def _pop(self):
        self._shell_values.pop()
        super()._pop()

    def visit_Module(self, node):
        self.untrusted_sources = UntrustedSourceIndex(node)
        self._object_factories = self._source_object_factories(node)
        self.generic_visit(node)

    def is_tainted(self, node):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted(item) for item in node.elts)
        return super().is_tainted(node)

    def _taint_params(self, fn):
        super()._taint_params(fn)
        for name, tainted in self.env_stack[-1].items():
            self._shell_values[-1][name] = [("tainted" if tainted else "unknown", None)]

    def _shell_parts(self, node):
        depth = getattr(self, "_parts_depth", 0)
        if depth >= 64:
            return [("tainted", None)]
        self._parts_depth = depth + 1
        try:
            return self._shell_parts_impl(node)
        except RecursionError:
            return [("tainted", None)]
        finally:
            self._parts_depth = depth

    def _shell_parts_impl(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [("text", node.value)]
        if isinstance(node, ast.Name):
            for values in reversed(self._shell_values):
                if node.id in values:
                    return values[node.id]
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
            if (
                isinstance(node.elts[0], ast.Constant)
                and isinstance(node.elts[0].value, str)
                and node.elts[0].value
            ):
                if any(
                    self._sensitive_parts(self._shell_parts(value))
                    for value in node.elts
                ):
                    return [("argv-fixed", None)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._shell_parts(node.left) + self._shell_parts(node.right)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if value.conversion != -1 or value.format_spec is not None:
                        parts.extend(self._unproved_parts(value.value))
                    else:
                        parts.extend(self._shell_parts(value.value))
                else:
                    parts.extend(self._shell_parts(value))
            return parts
        if isinstance(node, ast.Call) and self._is_sanitizer_call(node):
            name = self.untrusted_sources.resolved_import(
                self._current_function(), _qualified_name(node)
            )
            arguments = [*node.args, *[kw.value for kw in node.keywords]]
            if any(
                self._contains_kind(self._shell_parts(value), {"object"})
                for value in arguments
            ):
                return [("tainted", None)]
            if len(node.args) == 1 and not node.keywords:
                try:
                    value = ast.literal_eval(node.args[0])
                    if name == "shlex.quote" and isinstance(value, str):
                        return [("text", shlex.quote(value))]
                    if (
                        name == "shlex.join"
                        and isinstance(value, (list, tuple))
                        and all(isinstance(item, str) for item in value)
                    ):
                        return [("text", shlex.join(value))]
                except (ValueError, TypeError, RecursionError):
                    pass
            if any(
                self._sensitive_parts(self._shell_parts(arg)) for arg in node.args
            ) or any(
                self._sensitive_parts(self._shell_parts(kw.value))
                for kw in node.keywords
            ):
                if (
                    name == "shlex.join"
                    and node.args
                    and self._contains_kind(
                        self._shell_parts(node.args[0]), {"argv-fixed"}
                    )
                ):
                    return [("joined", None)]
                return [("quoted", None)]
            return [("unknown", None)]
        if isinstance(node, ast.Call):
            name = _qualified_name(node)
            imported = (
                self.untrusted_sources.resolved_import(self._current_function(), name)
                if name
                else None
            )
            arguments = [*node.args, *[kw.value for kw in node.keywords]]
            resolved_objects = _effects(self.untrusted_sources.module).refs(node.func)
            if (
                imported in self._object_factories
                or bool(resolved_objects & self._object_factories)
                or name == "type"
                or imported == "types.new_class"
                or self._contains_kind(self._shell_parts(node.func), {"object"})
                or any(
                    self._contains_kind(self._shell_parts(value), {"object"})
                    for value in arguments
                )
            ):
                return [("object", None)]
        return self._unproved_parts(node)

    def _unproved_parts(self, node):
        if self.is_tainted(node):
            return [("tainted", None)]
        # An unsupported formatting/call operation must not carry the quote
        # proof into a different context. Preserve the source, conservatively.
        children = []
        if isinstance(node, ast.Call):
            children = [*node.args, *[kw.value for kw in node.keywords]]
            if isinstance(node.func, ast.Attribute):
                children.append(node.func.value)
        elif isinstance(node, ast.BinOp):
            children = [node.left, node.right]
        elif isinstance(node, (ast.Subscript, ast.Attribute)):
            children = [node.value]
        if any(self._sensitive_parts(self._shell_parts(child)) for child in children):
            return [("tainted", None)]
        return [("unknown", None)]

    def _sensitive_parts(self, parts):
        return self._contains_kind(
            parts,
            {"quoted", "joined", "tainted", "object", "argv-fixed", "safe-command"},
        )

    def _contains_kind(self, parts, wanted):
        pending = [parts]
        seen = set()
        budget = 4096
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            for kind, value in current:
                budget -= 1
                if budget < 0:
                    return True
                if kind in wanted:
                    return True
                if kind == "choice":
                    pending.extend(value)
        return False

    def _bounded_parts(self, parts):
        pending = [(parts, 0)]
        seen = set()
        budget = 512
        while pending:
            current, depth = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            budget -= len(current)
            if depth > 24 or budget < 0:
                if self._neutral_command_proof(parts):
                    return [("safe-command", None)]
                return [
                    ("tainted" if self._sensitive_parts(parts) else "unknown", None)
                ]
            for kind, value in current:
                if kind == "choice":
                    pending.extend((alternative, depth + 1) for alternative in value)
        return parts

    @staticmethod
    def _neutral_text(value):
        return (
            bool(value)
            and value.isascii()
            and all(char.isalnum() or char == "_" for char in value)
        )

    def _simple_quoted_command(self, parts):
        prefix = []
        quoted = False
        for kind, value in parts:
            if kind == "quoted":
                quoted = True
            elif (
                kind == "text"
                and value.isascii()
                and all(char.isalnum() or char in "_./- \t" for char in value)
            ):
                if not quoted:
                    prefix.append(value)
            else:
                return False
        text = "".join(prefix)
        if not quoted or not text or text[0].isspace():
            return False
        words = text.split()
        if not words or (len(words) == 1 and not text[-1].isspace()):
            return False
        program = words[0].rsplit("/", 1)[-1].rstrip("0123456789.")
        if not program or any(word.endswith(program) for word in _CODE_COMMANDS):
            return False
        return not self._unsafe_shell_parts(parts)

    def _neutral_command_proof(self, parts):
        """A bounded proof for a complete command, never a reusable sanitizer.

        Shared branch tails are inspected once. Only neutral literal prefixes
        and suffixes preserve this whole-command proof. A new quote, separator,
        whitespace context, opaque operation or unquoted branch rejects it.
        """
        pending = [(parts, False)]
        results = {}
        visiting = set()
        budget = 512
        while pending:
            current, expanded = pending.pop()
            key = id(current)
            if key in results:
                continue
            if expanded:
                results[key] = all(results.get(id(value), False) for value in expanded)
                continue
            if key in visiting:
                return False
            visiting.add(key)
            budget -= len(current) + 1
            if budget < 0:
                return False
            structured = [
                (index, kind, value)
                for index, (kind, value) in enumerate(current)
                if kind in {"choice", "safe-command"}
            ]
            if not structured:
                results[key] = self._simple_quoted_command(current)
                continue
            if len(structured) != 1:
                results[key] = False
                continue
            index, kind, alternatives = structured[0]
            if any(
                other != "text" or not self._neutral_text(value)
                for offset, (other, value) in enumerate(current)
                if offset != index
            ):
                results[key] = False
                continue
            if kind == "safe-command":
                results[key] = True
                continue
            if not alternatives:
                results[key] = False
                continue
            pending.append((current, alternatives))
            pending.extend(
                (value, False) for value in alternatives if id(value) not in results
            )
        return results.get(id(parts), False)

    @staticmethod
    def _same_parts(left, right):
        if left is right:
            return True
        return len(left) == len(right) and all(
            a[0] == b[0] and a[0] != "choice" and a[1] == b[1]
            for a, b in zip(left, right)
        )

    def _source_object_factories(self, tree):
        """Follow source-visible constructor/helper origins, not class names elsewhere."""
        from pathlib import Path

        modules = [("", tree)]
        root = getattr(self, "project_root", None)
        if root:
            trees, complete = project_source_snapshot(root)
            if complete:
                for path, parsed in trees.items():
                    name = list(
                        Path(path).relative_to(Path(root)).with_suffix("").parts
                    )
                    if name[-1] == "__init__":
                        name.pop()
                    modules.append(
                        (
                            ".".join(name),
                            tree
                            if Path(path).resolve() == Path(self.file_path).resolve()
                            else parsed,
                        )
                    )
        factories = set()
        helpers = []
        for module, parsed in modules:
            imports = UntrustedSourceIndex(parsed)
            for node in ast.walk(parsed):
                if not isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                name = module + "." + node.name if module else node.name
                if isinstance(node, ast.ClassDef):
                    factories.add(name)
                    factories.add(f"@class:{id(node)}")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    helpers.append((module, name, node, imports))
        for _ in range(32):
            before = len(factories)
            for module, name, function, imports in helpers:
                for node in ast.walk(function):
                    if not isinstance(node, ast.Return):
                        continue
                    called = (
                        _qualified_name(node.value)
                        if isinstance(node.value, ast.Call)
                        else None
                    )
                    resolved = (
                        imports.resolved_import(function, called) if called else None
                    )
                    refs = _effects(imports.module).refs(
                        node.value.func
                        if isinstance(node.value, ast.Call)
                        else node.value
                    )
                    if (
                        resolved in factories
                        or refs & factories
                        or called == "type"
                        or resolved == "types.new_class"
                    ):
                        factories.add(name)
                        factories.add(f"@function:{id(function)}")
            if len(factories) == before:
                break
        return factories

    def visit_Assign(self, node):
        parts = self._bounded_parts(self._shell_parts(node.value))
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._shell_values[-1][target.id] = parts
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and isinstance(node.target, ast.Name):
            self._shell_values[-1][node.target.id] = self._bounded_parts(
                self._shell_parts(node.value)
            )
        super().visit_AnnAssign(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            if isinstance(node.op, ast.Add):
                parts = self._shell_parts(node.target) + self._shell_parts(node.value)
            else:
                parts = self._unproved_parts(node.value)
            self._set(
                node.target.id,
                self.is_tainted(node.target) or self.is_tainted(node.value),
            )
            self._shell_values[-1][node.target.id] = self._bounded_parts(parts)
        self.generic_visit(node)

    def _state(self):
        return (
            [dict(values) for values in self.env_stack],
            [dict(values) for values in self._shell_values],
        )

    def _restore(self, state):
        self.env_stack = [dict(values) for values in state[0]]
        self._shell_values = [dict(values) for values in state[1]]

    def _merge_states(self, states):
        env = []
        shell = []
        for depth in range(len(states[0][0])):
            names = set().union(*(state[0][depth] for state in states))
            env.append(
                {
                    name: any(state[0][depth].get(name) for state in states)
                    for name in names
                }
            )
            names |= set().union(*(state[1][depth] for state in states))
            values = {}
            for name in names:
                alternatives = []
                for state in states:
                    value = state[1][depth].get(name)
                    if value is None:
                        value = [
                            (
                                "tainted" if state[0][depth].get(name) else "unknown",
                                None,
                            )
                        ]
                    if not any(self._same_parts(value, old) for old in alternatives):
                        alternatives.append(value)
                values[name] = self._bounded_parts(
                    alternatives[0]
                    if len(alternatives) == 1
                    else [("choice", alternatives)]
                )
            shell.append(values)
        self.env_stack, self._shell_values = env, shell

    def visit_If(self, node):
        self.visit(node.test)
        before = self._state()
        for statement in node.body:
            self.visit(statement)
        body = self._state()
        self._restore(before)
        for statement in node.orelse:
            self.visit(statement)
        self._merge_states([body, self._state()])

    def _visit_loop(self, node):
        self.visit(
            node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test
        )
        before = self._state()
        if isinstance(node, (ast.For, ast.AsyncFor)):
            for target in ast.walk(node.target):
                if isinstance(target, ast.Name):
                    self._set(target.id, self.is_tainted(node.iter))
                    self._shell_values[-1][target.id] = [
                        ("tainted" if self._get(target.id) else "unknown", None)
                    ]
        for statement in node.body:
            self.visit(statement)
        self._merge_states([before, self._state()])
        for statement in node.orelse:
            self.visit(statement)

    visit_For = _visit_loop
    visit_AsyncFor = _visit_loop
    visit_While = _visit_loop

    def _shell_is_tainted(self, node):
        parts = self._bounded_parts(self._shell_parts(node))
        return self._sensitive_parts(parts) and self._unsafe_shell_parts(parts)

    def _unsafe_shell_parts(self, parts):
        if self._contains_kind(parts, {"safe-command"}):
            return not self._neutral_command_proof(parts)
        # Explicit continuations keep model depth independent of Python's call
        # stack. Exhaustion is a failed safety proof, never a scanner abort.
        pending = [(parts, (None, False, False, False, True, True, False))]
        budget = 8192
        while pending:
            parts, state = pending.pop()
            (
                quote,
                escaped,
                unknown,
                comment,
                word_start,
                command_needed,
                unsupported,
            ) = state
            for index, (kind, text) in enumerate(parts):
                budget -= 1
                if budget < 0:
                    return True
                if kind == "choice":
                    state = (
                        quote,
                        escaped,
                        unknown,
                        comment,
                        word_start,
                        command_needed,
                        unsupported,
                    )
                    pending.extend(
                        (alternative + parts[index + 1 :], state)
                        for alternative in text
                    )
                    break
                if kind in {"tainted", "object", "argv-fixed"}:
                    return True
                if kind == "unknown":
                    unknown = True
                    continue
                if kind in {"quoted", "joined"}:
                    if (
                        quote is not None
                        or escaped
                        or unknown
                        or comment
                        or unsupported
                    ):
                        return True
                    if command_needed and kind != "joined":
                        return True
                    command_needed = False
                    word_start = False
                    continue
                for offset, char in enumerate(text):
                    budget -= 1
                    if budget < 0:
                        return True
                    if comment:
                        if char == "\n":
                            comment = False
                            word_start = True
                            command_needed = True
                    elif escaped:
                        escaped = False
                        word_start = False
                    elif char == "\\" and quote != "'":
                        escaped = True
                    elif quote is None and char in {"'", '"'}:
                        quote = char
                        word_start = False
                        command_needed = False
                    elif char == quote:
                        quote = None
                    elif quote is None:
                        if char == "#" and word_start:
                            comment = True
                        else:
                            if char == "`" or text[offset : offset + 2] in {"$(", "<<"}:
                                unsupported = True
                            if char in ";|&\n":
                                command_needed = True
                            elif not char.isspace():
                                command_needed = False
                            word_start = char.isspace() or char in ";|&()"
        return False

    def visit_Call(self, node):
        legacy = self._resolved_name(node)
        for qn in callable_names(
            node,
            legacy,
            self.untrusted_sources.module,
            self.file_path,
            getattr(self, "project_root", None),
        ):
            self._check_call(node, qn)
        self.generic_visit(node)

    def _check_call(self, node, qn):
        if not qn:
            return

        shell_call = SHELL_STRING_CALLS.get(qn)
        if shell_call is not None:
            command = _command_argument(node)
            if command is not None and self._shell_is_tainted(command):
                self._report(
                    node,
                    f"Possible command injection ({shell_call}): tainted input.",
                )

        if qn.endswith(".exec_command") and node.args:
            if self._shell_is_tainted(node.args[0]):
                self._report(
                    node,
                    "Possible command injection (ssh exec_command): tainted input.",
                )

        if qn in _EXEC_PROGRAM_POSITIONS:
            self._check_exec_family(node, qn)

        if qn == "pty.spawn":
            self._check_pty_spawn(node)

        if qn.startswith("asyncio.") and qn.endswith("create_subprocess_exec"):
            self._check_argv_shell_script(node, qn)

        if qn.startswith(self.SUBPROC_PREFIX) and shell_call is None:
            command = _command_argument(node, ("args",))
            executable_tainted = any(
                kw.arg == "executable" and self.is_tainted(kw.value)
                for kw in node.keywords
            )
            command_tainted = command is not None and self._shell_is_tainted(command)
            if _shell_is_literal_true(node):
                if command_tainted or executable_tainted:
                    self._report(
                        node,
                        "Possible command injection (subprocess shell=True): tainted input.",
                        with_symbol=False,
                    )
            elif _shell_may_be_enabled(node):
                if command_tainted or executable_tainted:
                    self._report(
                        node,
                        "Possible command injection (subprocess with a non-constant shell= value): tainted input.",
                    )
            else:
                self._check_argv_shell_script(node, qn)


def scan(tree, file_path, findings, *, project_root=None):
    try:
        checker = _CmdFlowChecker(
            file_path, findings, sanitizers=CMD_SANITIZERS, tree=tree
        )
        checker.project_root = project_root
        checker.visit(tree)
    except Exception as e:
        print(f"CMD flow failed for {file_path}: {e}", file=sys.stderr)
