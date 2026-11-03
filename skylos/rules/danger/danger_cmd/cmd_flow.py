from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor, CMD_SANITIZERS


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
    def __init__(self, file_path, findings, sanitizers=None, tree=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.import_aliases = _module_import_aliases(tree)

    def _resolved_name(self, node: ast.Call) -> str | None:
        qn = _qualified_name(node)
        if not qn:
            return None
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
                return self.is_tainted(argv[index + 1])
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

    def visit_Call(self, node):
        qn = self._resolved_name(node)
        if not qn:
            self.generic_visit(node)
            return

        shell_call = SHELL_STRING_CALLS.get(qn)
        if shell_call is not None:
            command = _command_argument(node)
            if command is not None and self.is_tainted(command):
                self._report(
                    node,
                    f"Possible command injection ({shell_call}): tainted input.",
                )

        if qn.endswith(".exec_command") and node.args:
            if self.is_tainted(node.args[0]):
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

        if qn.startswith("subprocess.") and shell_call is None:
            if _shell_is_literal_true(node):
                if self.is_tainted(node):
                    self._report(
                        node,
                        "Possible command injection (subprocess shell=True): tainted input.",
                        with_symbol=False,
                    )
            elif _shell_may_be_enabled(node):
                command = _command_argument(node, ("args",))
                if command is not None and self.is_tainted(command):
                    self._report(
                        node,
                        "Possible command injection (subprocess with a non-constant shell= value): tainted input.",
                    )
            else:
                self._check_argv_shell_script(node, qn)

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _CmdFlowChecker(
            file_path, findings, sanitizers=CMD_SANITIZERS, tree=tree
        )
        checker.visit(tree)
    except Exception as e:
        print(f"CMD flow failed for {file_path}: {e}", file=sys.stderr)
