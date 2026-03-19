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
        assert score_outer == 2


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
        assert score == 3

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
    x = a and b or c
"""
        score = _calc(code)
        assert score == 2


class TestElseIncrement:
    def test_else_adds_one(self):
        code = """
def f():
    if a:
        pass
    else:
        pass
"""
        score = _calc(code)
        assert score == 2

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
    for x in items:
        pass
"""
        score = _calc(code)
        assert score == 1

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
"""
        score = _calc(code)
        assert score == 1


class TestExceptHandlers:
    def test_except_adds_increment_and_nesting(self):
        code = """
def f():
    try:
        pass
    except ValueError:
        pass
"""
        score = _calc(code)
        assert score == 1

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
    x = a if condition else b
"""
        score = _calc(code)
        assert score == 1


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


class TestLambdaResets:
    def test_lambda_resets_nesting(self):
        code = """
def f():
    if a:
        fn = lambda x: x if x > 0 else -x
"""
        score = _calc(code)
        assert score == 2
