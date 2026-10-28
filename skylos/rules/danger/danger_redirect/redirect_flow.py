from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


REDIRECT_FUNCS = {"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}

REQUEST_ARGS_ATTRS = {"args", "params", "query", "GET"}

# Route builders return a path (or an absolute URL) on the application's own
# host. User values passed to them only fill path/query parameters, so the
# redirect target cannot leave the site.
INTERNAL_URL_BUILDERS = {"url_for", "reverse", "reverse_lazy", "url_path_for"}


def _is_internal_url_builder(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in INTERNAL_URL_BUILDERS
    if isinstance(func, ast.Attribute):
        return func.attr in INTERNAL_URL_BUILDERS
    return False


def _starts_with_internal_url(node):
    """``url_for(...)``, or a string that begins with one (``url_for(...) + '?q=' + x``)."""
    if _is_internal_url_builder(node):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _starts_with_internal_url(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        return isinstance(first, ast.FormattedValue) and _is_internal_url_builder(
            first.value
        )
    return False


def _is_request_args_get(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "get":
        return False
    val = func.value
    if (
        isinstance(val, ast.Attribute)
        and val.attr in REQUEST_ARGS_ATTRS
        and isinstance(val.value, ast.Name)
        and val.value.id == "request"
    ):
        return True
    return False


class _RedirectFlowChecker(TaintVisitor):
    def __init__(self, file_path, findings):
        super().__init__(file_path, findings)
        self._exception_states = []
        self._loop_states = []

    def _visit_block(self, statements):
        """Return whether the block has a path reaching its next statement."""
        for statement in statements:
            continues = self.visit(statement)
            for states in self._exception_states:
                states.append(self._copy_env(self.env_stack))
            if continues is False:
                return False
        return True

    def _visit_function(self, node):
        # Each function has its own flow; a return must not stop its enclosing
        # module or function from being scanned.
        for expression in node.decorator_list + node.args.defaults:
            self.visit(expression)
        for expression in node.args.kw_defaults:
            if expression is not None:
                self.visit(expression)
        self._push()
        outer_exceptions = self._exception_states
        outer_loops = self._loop_states
        self._exception_states = []
        self._loop_states = []
        self._symbol_stack.append(node.name)
        self._function_stack.append(node)
        self._taint_params(node)
        self._visit_block(node.body)
        self._function_stack.pop()
        self._symbol_stack.pop()
        self._pop()
        self._exception_states = outer_exceptions
        self._loop_states = outer_loops

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Return(self, node):
        self.generic_visit(node)
        return False

    def visit_Raise(self, node):
        self.generic_visit(node)
        return False

    def visit_Break(self, node):
        if self._loop_states:
            self._loop_states[-1].append(self._copy_env(self.env_stack))
        return False

    visit_Continue = visit_Break

    def is_tainted(self, node):
        if _starts_with_internal_url(node):
            return False
        if isinstance(node, ast.IfExp):
            return self.is_tainted(node.body) or self.is_tainted(node.orelse)
        if isinstance(node, ast.BoolOp):
            return any(self.is_tainted(value) for value in node.values)
        return super().is_tainted(node)

    @staticmethod
    def _copy_env(env):
        return [scope.copy() for scope in env]

    @staticmethod
    def _merge_env(states):
        # A name missing in a local scope can still resolve to an outer binding.
        # Keep that inherited taint when only one branch creates a local name.
        merged = []
        for index in range(len(states[0])):
            names = set().union(*(state[index] for state in states))
            scope = {}
            for name in names:
                scope[name] = any(
                    next(
                        (
                            part[name]
                            for part in reversed(state[: index + 1])
                            if name in part
                        ),
                        False,
                    )
                    for state in states
                )
            merged.append(scope)
        return merged

    def _narrow_literal_guard(self, test, truth):
        """Only equality with immutable literal values proves a target bounded.

        A netloc check or leading slash alone is not browser redirect safety,
        and a check on one expression does not validate a later request read.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._narrow_literal_guard(test.operand, not truth)
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            return
        left, right, op = test.left, test.comparators[0], test.ops[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            if isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                left, right = right, left
            bounded = isinstance(right, ast.Constant) and isinstance(right.value, str)
            matches = truth if isinstance(op, ast.Eq) else not truth
        elif isinstance(op, (ast.In, ast.NotIn)):
            bounded = isinstance(right, (ast.Tuple, ast.List, ast.Set)) and all(
                isinstance(value, ast.Constant) and isinstance(value.value, str)
                for value in right.elts
            )
            matches = truth if isinstance(op, ast.In) else not truth
        else:
            return
        if isinstance(left, ast.Name) and bounded and matches:
            self._set(left.id, False)

    def visit_If(self, node):
        self.visit(node.test)
        entry = self._copy_env(self.env_stack)
        continuing = []
        for truth, statements in ((True, node.body), (False, node.orelse)):
            self.env_stack = self._copy_env(entry)
            self._narrow_literal_guard(node.test, truth)
            if self._visit_block(statements):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing) if continuing else entry
        return bool(continuing)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item)
        # An unknown context manager can suppress an exception from any body
        # statement, including a rejected target. Do not leak that proof out.
        states = [self._copy_env(self.env_stack)]
        self._exception_states.append(states)
        self._visit_block(node.body)
        self._exception_states.pop()
        self.env_stack = self._merge_env(states)

    visit_AsyncWith = visit_With

    def _visit_loop(self, node):
        expression = node.test if isinstance(node, ast.While) else node.iter
        self.visit(expression)
        entry = self._copy_env(self.env_stack)
        if isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(
            node.target, ast.Name
        ):
            self._set(node.target.id, self.is_tainted(node.iter))
        exits = []
        self._loop_states.append(exits)
        self._visit_block(node.body)
        self._loop_states.pop()
        # Zero iterations and break/continue both retain possible values.
        self.env_stack = self._merge_env([entry, self.env_stack, *exits])
        if node.orelse:
            before_else = self._copy_env(self.env_stack)
            self._visit_block(node.orelse)
            self.env_stack = self._merge_env([before_else, self.env_stack])

    visit_For = _visit_loop
    visit_AsyncFor = _visit_loop
    visit_While = _visit_loop

    def visit_Try(self, node):
        exceptional = [self._copy_env(self.env_stack)]
        self._exception_states.append(exceptional)
        normal = self._visit_block(node.body)
        self._exception_states.pop()
        continuing = []
        if normal and self._visit_block(node.orelse):
            continuing.append(self._copy_env(self.env_stack))
        for handler in node.handlers:
            self.env_stack = self._merge_env(exceptional)
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._set(handler.name, True)
            if self._visit_block(handler.body):
                continuing.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(continuing or exceptional)
        final_continues = self._visit_block(node.finalbody)
        return bool(continuing) and final_continues

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        entry = self._copy_env(self.env_stack)
        states = [entry]
        for case in node.cases:
            self.env_stack = self._copy_env(entry)
            for pattern in ast.walk(case.pattern):
                if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
                    self._set(pattern.name, self.is_tainted(node.subject))
            if case.guard is not None:
                self.visit(case.guard)
            if self._visit_block(case.body):
                states.append(self._copy_env(self.env_stack))
        self.env_stack = self._merge_env(states)

    def visit_Call(self, node):
        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name in REDIRECT_FUNCS and node.args:
            url_arg = node.args[0]

            if _is_request_args_get(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D230",
                        "severity": "HIGH",
                        "message": (
                            "Possible open redirect: request parameter passed to "
                            "redirect via .get() — default value does not prevent "
                            "attacker-supplied input."
                        ),
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
            elif _starts_with_internal_url(url_arg):
                pass
            elif self.is_tainted(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D230",
                        "severity": "HIGH",
                        "message": "Possible open redirect: user-controlled URL passed to redirect.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _RedirectFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"Redirect flow analysis failed for {file_path}: {e}", file=sys.stderr)
