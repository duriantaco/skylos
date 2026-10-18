import ast
from skylos.rules.quality.complexity import (
    CognitiveComplexityRule,
    _cognitive_complexity,
)


def _calc(code: str) -> int:
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return _cognitive_complexity(node)
    raise ValueError("No function found")


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_module"}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestCognitiveVsCyclomatic:
    def test_flat_if_elif_chain_low_cognitive_high_cyclomatic(self):
        code = """
def classify(x):
    if x == 1:
        return "one"
    elif x == 2:
        return "two"
    elif x == 3:
        return "three"
    elif x == 4:
        return "four"
    elif x == 5:
        return "five"
    elif x == 6:
        return "six"
    elif x == 7:
        return "seven"
    elif x == 8:
        return "eight"
    else:
        return "other"
"""
        score = _calc(code)
        assert score == 9, f"Flat if/elif chain should be exactly 9, got {score}"

    def test_deeply_nested_high_cognitive_moderate_cyclomatic(self):
        """Deeply nested if-in-if-in-for: high cognitive, moderate cyclomatic."""
        code = """
def process(items):
    for item in items:
        if item.valid:
            if item.ready:
                if item.approved:
                    return item.value
"""
        score = _calc(code)
        assert score == 10, f"Deeply nested code should be exactly 10, got {score}"


class TestNestingPenalty:
    def test_nesting_adds_penalty(self):
        code = """
def f():
    if a:
        if b:
            if c:
                pass
"""
        score = _calc(code)
        assert score == 6

    def test_no_nesting_penalty_for_flat(self):
        code = """
def f():
    if a:
        pass
    if b:
        pass
    if c:
        pass
"""
        score = _calc(code)
        assert score == 3


class TestNestedFunctionResets:
    def test_nested_function_resets_depth(self):
        code = """
def outer():
    if a:
        def inner():
            if b:
                pass
"""
        score_outer = _calc(code)
        # The inner function retains the enclosing if depth and adds a
        # function nesting level: outer if +1, inner if +3.
        assert score_outer == 4


class TestBooleanOperators:
    def test_and_or_increment(self):
        code = """
def f():
    if a and b:
        pass
"""
        score = _calc(code)
        assert score == 2

    def test_multiple_bool_ops(self):
        code = """
def f():
    if a and b and c:
        pass
"""
        score = _calc(code)
        assert score == 2

    def test_or_operator(self):
        code = """
def f():
    if a or b:
        pass
"""
        score = _calc(code)
        assert score == 2

    def test_bool_ops_no_nesting_penalty(self):
        code = """
def f():
    x = a and (b or c) and d
"""
        score = _calc(code)
        assert score == 3


class TestElseIncrement:
    def test_else_adds_one(self):
        code = """
def f():
    if a:
        pass
    else:
        if b:
            pass
"""
        score = _calc(code)
        assert score == 4

    def test_elif_adds_one(self):
        code = """
def f():
    if a:
        pass
    elif b:
        pass
"""
        score = _calc(code)
        assert score == 2


class TestLoops:
    def test_for_loop(self):
        code = """
def f():
    for x in items or fallback:
        pass
    else:
        if ready:
            pass
"""
        score = _calc(code)
        assert score == 5

    def test_nested_for_loops(self):
        code = """
def f():
    for x in items:
        for y in other:
            pass
"""
        score = _calc(code)
        assert score == 3

    def test_while_loop(self):
        code = """
def f():
    while True:
        pass
    else:
        if ready:
            pass
"""
        score = _calc(code)
        assert score == 4


class TestExceptHandlers:
    def test_except_adds_increment_and_nesting(self):
        code = """
def f():
    try:
        pass
    except ValueError:
        pass
    else:
        if ready:
            pass
"""
        score = _calc(code)
        assert score == 4

    def test_nested_except(self):
        code = """
def f():
    if a:
        try:
            pass
        except ValueError:
            pass
"""
        score = _calc(code)
        assert score == 3


class TestTernary:
    def test_ternary_expression(self):
        code = """
def f():
    x = (a if inner_condition else b) if condition else c
"""
        score = _calc(code)
        assert score == 3


class TestRuleIntegration:
    def test_below_threshold_no_finding(self):
        code = """
def simple():
    if a:
        pass
"""
        rule = CognitiveComplexityRule(threshold=15)
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_above_threshold_reports(self):
        code = """
def complex_func():
    for item in items:
        if item.a:
            if item.b:
                if item.c:
                    for sub in item.children:
                        if sub.valid:
                            if sub.ready:
                                pass
"""
        rule = CognitiveComplexityRule(threshold=5)
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q306"
        assert "Cognitive complexity" in findings[0]["message"]

    def test_severity_medium(self):
        rule = CognitiveComplexityRule(threshold=1)
        code = """
def f():
    if a:
        if b:
            if c:
                pass
"""
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_severity_high(self):
        lines = ["def f():"]
        for i in range(8):
            indent = "    " * (i + 1)
            lines.append(f"{indent}if x{i}:")
        lines.append("    " * 9 + "pass")
        code = "\n".join(lines)
        rule = CognitiveComplexityRule(threshold=1)
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_extreme_cognitive_complexity_is_never_critical(self):
        lines = ["def f():"]
        for i in range(12):
            indent = "    " * (i + 1)
            lines.append(f"{indent}if x{i}:")
        lines.append("    " * 13 + "pass")
        rule = CognitiveComplexityRule(threshold=1)
        findings = check_code(rule, "\n".join(lines))
        assert len(findings) == 1
        assert findings[0]["value"] > 50
        assert findings[0]["severity"] == "HIGH"

    def test_async_function(self):
        code = """
async def handler():
    for item in items:
        if item.a:
            if item.b:
                if item.c:
                    for sub in item.children:
                        if sub.valid:
                            pass
"""
        rule = CognitiveComplexityRule(threshold=5)
        findings = check_code(rule, code)
        assert len(findings) == 1


class TestMatchStatement:
    def test_match_increments(self):
        code = """
def f():
    match command:
        case "start":
            pass
        case "stop":
            pass
"""
        try:
            score = _calc(code)
            # match: +1
            assert score >= 1
        except SyntaxError:
            pass  # Python < 3.10


class TestMatchConditions:
    def test_match_subject_boolean_sequence_counts(self):
        code = """
def f(x):
    match (a or b):
        case 1:
            pass
"""
        # match +1, subject `or` +1.
        assert _calc(code) == 2

    def test_match_guard_boolean_sequence_counts(self):
        code = """
def f(x):
    match x:
        case 1 if a and b:
            pass
        case _:
            pass
"""
        # match +1, guard `and` +1.
        assert _calc(code) == 2

    def test_match_guard_is_inside_the_match(self):
        code = """
def f(x):
    match x:
        case 1 if (p if q else r):
            pass
"""
        # match +1 (nesting 0), guard ternary +2 (nesting 1).
        assert _calc(code) == 3


class TestLambdaNesting:
    def test_lambda_increases_nesting(self):
        code = """
def f():
    if a:
        fn = lambda x: x if x > 0 else -x
"""
        # Cognitive Complexity spec: a lambda is a nested function, so its
        # body is one level deeper. if +1 (nesting 0), ternary +3 (nesting 2).
        score = _calc(code)
        assert score == 4

    def test_nested_lambdas_each_add_nesting(self):
        code = """
def f():
    g = lambda a: (lambda b: b if b else a)
"""
        # ternary inside two lambdas: +1 + nesting 2.
        assert _calc(code) == 3

    def test_lambda_default_is_scored_at_enclosing_level(self):
        code = """
def f():
    if a:
        g = lambda v=(p if q else r): v
"""
        # if +1; the default is evaluated where the lambda is created: +2.
        assert _calc(code) == 3

    def test_lambda_boolean_sequence_has_no_nesting_cost(self):
        code = """
def f():
    return sorted(xs, key=lambda v: v.a or v.b)
"""
        assert _calc(code) == 1


class TestFunctionSignatureScope:
    def test_own_decorators_defaults_and_annotations_are_not_scored(self):
        code = """
@option(callback=lambda c, p, v: v or c.default)
@option(callback=lambda c, p, v: v if v else c.default)
def f(x=1 if FLAG else 2) -> (A if B else C):
    pass
"""
        assert _calc(code) == 0

    def test_rule_ignores_decorator_callbacks(self):
        decorators = "\n".join(
            "@click.option(callback=lambda c, p, v: v or c.default)"
            for _ in range(4)
        )
        body = "\n".join(f"    if x{i}:\n        pass" for i in range(15))
        code = f"{decorators}\ndef cmd():\n{body}\n"
        # Body is 15 flat ifs: exactly at the threshold, not above it.
        findings = check_code(CognitiveComplexityRule(threshold=15), code)
        assert findings == []

    def test_nested_def_signature_scored_at_enclosing_level(self):
        code = """
def outer():
    if a:
        @deco(x if y else z)
        def inner(p=q or r):
            if b:
                pass
        inner()
"""
        # if a +1; decorator ternary at nesting 1: +2; default `or` +1;
        # inner body is at nesting 2: if b +3.
        assert _calc(code) == 7


class TestDecoratorWrapperShape:
    def test_leading_docstring_keeps_wrapper_shape(self):
        code = '''
def deco(fn):
    """Doc."""
    @wraps(fn)
    def inner(*a):
        if a:
            for x in a:
                pass
        return fn(*a)
    return inner
'''
        # inner body at nesting 0: if +1, for +2.
        assert _calc(code) == 3

    def test_pass_keeps_wrapper_shape(self):
        code = """
def deco(fn):
    pass
    def inner():
        if a:
            pass
    return inner
"""
        assert _calc(code) == 1

    def test_other_statements_break_wrapper_shape(self):
        code = '''
def deco(fn):
    """Doc."""
    import functools
    def inner():
        if a:
            pass
    return inner
'''
        # The import is real code: inner body at nesting 1, if +2.
        assert _calc(code) == 2

    def test_non_leading_string_breaks_wrapper_shape(self):
        code = '''
def deco(fn):
    def inner():
        if a:
            pass
    """not a docstring"""
    return inner
'''
        assert _calc(code) == 2
