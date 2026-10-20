import ast
from pathlib import Path
from skylos.rules.base import SkylosRule
from skylos.rules.quality._scope import is_non_production_function_scope

RULE_ID = "SKY-Q301"
COGNITIVE_RULE_ID = "SKY-Q306"

_COMPLEX_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.IfExp,
)


def _irrefutable_pattern(pattern: ast.AST) -> bool:
    """A wildcard/capture, possibly wrapped in ``as`` or an alternative.

    Structural/value patterns may fail. An irrefutable pattern does not add a
    decision; its guard, if any, remains a separate decision.
    """
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable_pattern(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable_pattern(part) for part in pattern.patterns)
    return False


def _func_complexity(fn_node: ast.AST) -> int:
    c = 1

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, _):
            return

        def visit_AsyncFunctionDef(self, _):
            return

        def visit_ClassDef(self, _):
            return

        def visit_Lambda(self, _):
            return

        def generic_visit(self, node):
            nonlocal c

            if isinstance(node, _COMPLEX_NODES):
                c += 1

            if isinstance(node, ast.BoolOp):
                c += max(len(node.values) - 1, 0)

            if isinstance(node, ast.Try):
                c += len(getattr(node, "handlers", []) or [])

            if hasattr(ast, "TryStar") and isinstance(node, ast.TryStar):
                c += len(getattr(node, "handlers", []) or [])

            if hasattr(ast, "Match") and isinstance(node, ast.Match):
                cases = getattr(node, "cases", []) or []
                # A match without a wildcard/capture has an additional path
                # where no case matches. Do not assume its last case is else.
                c += sum(not _irrefutable_pattern(case.pattern) for case in cases)
                for case in cases:
                    if getattr(case, "guard", None) is not None:
                        c += 1

            if isinstance(node, ast.comprehension):
                c += 1
                c += len(node.ifs)

            for child in ast.iter_child_nodes(node):
                self.visit(child)

    v = Visitor()
    for stmt in fn_node.body:
        v.visit(stmt)
    return c


def _func_length(node):
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)

    if start is None:
        return 0

    if end is None:
        end = start
        for child in ast.walk(node):
            ln = getattr(child, "lineno", None)
            if ln is not None and ln > end:
                end = ln

    return max(end - start + 1, 0)


class ComplexityRule(SkylosRule):
    rule_id = "SKY-Q301"
    name = "Cyclomatic Complexity"

    def __init__(self, threshold=10):
        self.threshold = threshold

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if is_non_production_function_scope(context):
            return None

        complexity = _func_complexity(node)

        if complexity <= self.threshold:
            return None

        # A complexity number is not an exploitable defect, so it tops out at
        # HIGH; CRITICAL is reserved for verified, exploitable issues.
        if complexity < 15:
            severity = "WARN"
        else:
            severity = "HIGH"

        length = _func_length(node)
        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "complexity",
                "severity": severity,
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": complexity,
                "threshold": self.threshold,
                "length": length,
                "message": f"Cyclomatic complexity is {complexity} (threshold: {self.threshold}). Consider splitting branches.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
            }
        ]


def _is_docstring(stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _is_wrapper_shape(function, nested) -> bool:
    """Whether ``function`` only defines ``nested`` and returns a name.

    This is the decorator/factory shape whose inner function does not add a
    nesting level. A leading docstring and ``pass`` statements carry no logic,
    so they do not break the shape; any other statement does.
    """
    for index, stmt in enumerate(function.body):
        if stmt is nested or isinstance(stmt, ast.Pass):
            continue
        if index == 0 and _is_docstring(stmt):
            continue
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name):
            continue
        return False
    return True


def _cognitive_complexity(fn_node: ast.AST, *, contributions=None) -> int:
    """Measure structural nesting and logical-operator sequences.

    Only the measured function's body is scored: its decorators, defaults and
    annotations run in the enclosing scope. Statement bodies add nesting;
    condition/iterator expressions do not. A nested function's decorators,
    defaults and annotations are scored at the enclosing level and its body one
    level deeper, except for simple wrappers. A lambda body is one level deeper
    than the lambda. A class starts an independent nesting scope.
    """
    total = 0
    owner = fn_node

    def increase(points):
        nonlocal total
        total += points
        if contributions is not None:
            key = (
                getattr(owner, "lineno", 0),
                getattr(owner, "end_lineno", 0),
                getattr(owner, "name", "<lambda>"),
                type(owner).__name__,
            )
            contributions[key] = contributions.get(key, 0) + points

    def _process(node, nesting: int, function=None, is_elif: bool = False):
        nonlocal owner

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if function is None:
                body_nesting = 0
            elif _is_wrapper_shape(function, node):
                body_nesting = nesting
            else:
                body_nesting = nesting + 1
            body_ids = {id(stmt) for stmt in node.body}
            for child in ast.iter_child_nodes(node):
                if id(child) not in body_ids:
                    # Decorators, defaults and annotations are evaluated where
                    # the def statement runs, in the enclosing scope.
                    _process(child, nesting, function)
            previous_owner = owner
            owner = node
            for body_child in node.body:
                _process(body_child, body_nesting, node)
            owner = previous_owner
            return

        if isinstance(node, ast.Lambda):
            # Defaults are evaluated where the lambda is created; the body is
            # a nested function, which increases nesting.
            _process(node.args, nesting, function)
            previous_owner = owner
            owner = node
            _process(node.body, nesting + 1, function)
            owner = previous_owner
            return

        if isinstance(node, ast.ClassDef):
            previous_owner = owner
            owner = node
            for child in ast.iter_child_nodes(node):
                _process(child, 0)
            owner = previous_owner
            return

        if isinstance(node, ast.If):
            if is_elif:
                increase(1)
            else:
                increase(1 + nesting)

            inner_nesting = nesting + 1

            _process(node.test, nesting, function)

            for body_child in node.body:
                _process(body_child, inner_nesting, function)

            if node.orelse:
                # An explicit ``else: if`` has another body level. Only an
                # actual elif shares the parent if's indentation.
                if (
                    len(node.orelse) == 1
                    and isinstance(node.orelse[0], ast.If)
                    and node.orelse[0].col_offset == node.col_offset
                ):
                    _process(node.orelse[0], nesting, function, is_elif=True)
                else:
                    increase(1)
                    for else_child in node.orelse:
                        _process(else_child, inner_nesting, function)
            return

        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            increase(1 + nesting)
            if isinstance(node, ast.While):
                _process(node.test, nesting, function)
            else:
                _process(node.target, nesting, function)
                _process(node.iter, nesting, function)
            for body_child in node.body:
                _process(body_child, nesting + 1, function)
            if node.orelse:
                increase(1)
                for else_child in node.orelse:
                    _process(else_child, nesting + 1, function)
            return

        if isinstance(node, ast.BoolOp):
            operators = []
            operands = []

            def collect(expr):
                if isinstance(expr, ast.BoolOp):
                    for index, value in enumerate(expr.values):
                        if index:
                            operators.append(type(expr.op))
                        collect(value)
                else:
                    operands.append(expr)

            collect(node)
            previous = None
            for operator in operators:
                if operator is not previous:
                    increase(1)
                previous = operator
            # Only contiguous Boolean expressions share a sequence. Boolean
            # expressions inside calls or other operands get their own visit.
            for operand in operands:
                _process(operand, nesting, function)
            return

        if isinstance(node, ast.IfExp):
            increase(1 + nesting)
            _process(node.test, nesting + 1, function)
            _process(node.body, nesting + 1, function)
            _process(node.orelse, nesting + 1, function)
            return

        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            for handler in getattr(node, "handlers", []) or []:
                increase(1 + nesting)
                if handler.type is not None:
                    _process(handler.type, nesting, function)
                for h_child in handler.body:
                    _process(h_child, nesting + 1, function)
            for body_child in getattr(node, "body", []) or []:
                _process(body_child, nesting, function)
            for fb_child in getattr(node, "finalbody", []) or []:
                _process(fb_child, nesting, function)
            if node.orelse:
                increase(1)
            for else_child in getattr(node, "orelse", []) or []:
                _process(else_child, nesting + 1, function)
            return

        if hasattr(ast, "Match") and isinstance(node, ast.Match):
            increase(1 + nesting)
            _process(node.subject, nesting, function)
            for case in getattr(node, "cases", []) or []:
                # A guard is a condition inside the match, like the case body.
                if case.guard is not None:
                    _process(case.guard, nesting + 1, function)
                for case_child in case.body:
                    _process(case_child, nesting + 1, function)
            return

        for child in ast.iter_child_nodes(node):
            _process(child, nesting, function)

    for stmt in getattr(fn_node, "body", []) or []:
        _process(stmt, 0, fn_node)

    return total


class CognitiveComplexityRule(SkylosRule):
    rule_id = COGNITIVE_RULE_ID
    name = "Cognitive Complexity"

    def __init__(self, threshold=15):
        self.threshold = threshold
        self._containing_functions = {}

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._containing_functions = {}
            pending = [(node, None)]
            while pending:
                current, containing = pending.pop()
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._containing_functions[current] = containing
                    containing = current
                pending.extend(
                    (child, containing) for child in ast.iter_child_nodes(current)
                )
            return None
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if is_non_production_function_scope(context):
            return None

        complexity = _cognitive_complexity(node)

        if complexity <= self.threshold:
            return None

        contributions = {}
        _cognitive_complexity(node, contributions=contributions)
        containing = self._containing_functions.get(node)
        scope = {
            "version": 1,
            "end_line": node.end_lineno,
            "own_score": contributions.get(
                (node.lineno, node.end_lineno, node.name, type(node).__name__), 0
            ),
            "nested_contributions": [
                {
                    "line": line,
                    "end_line": end,
                    "name": name,
                    "kind": kind,
                    "score": score,
                }
                for (line, end, name, kind), score in sorted(contributions.items())
                if (line, end, name, kind)
                != (node.lineno, node.end_lineno, node.name, type(node).__name__)
            ],
        }
        if containing is not None:
            scope["containing_function"] = {
                "line": containing.lineno,
                "name": containing.name,
            }

        # Capped at HIGH: complexity is not an exploitable defect.
        if complexity <= 30:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        mod = context.get("mod", "")
        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "complexity",
                "severity": severity,
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": complexity,
                "cognitive_scope": scope,
                "threshold": self.threshold,
                "message": f"Cognitive complexity is {complexity} (threshold: {self.threshold}). Consider simplifying nested logic.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
            }
        ]
