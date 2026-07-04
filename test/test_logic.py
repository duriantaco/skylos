import ast
from skylos.rules.quality.logic import (
    MutableDefaultRule,
    BareExceptRule,
    DangerousComparisonRule,
    DuplicateBranchRule,
    BroadExceptionRule,
)


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    findings = []
    context = {"filename": filename, "mod": "test_module"}

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestMutableDefaultRule:
    def test_list_default(self):
        code = """
def bad(x=[]): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L001"
        assert "Mutable default" in findings[0]["message"]

    def test_dict_default(self):
        code = """
def bad(x={}): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_set_default(self):
        code = """
def bad(x={1}): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_valid_default(self):
        code = """
def good(x=None, y=1, z='s'): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_kwonly_defaults(self):
        code = """
def bad(*, x=[]): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_async_function(self):
        code = """
async def bad(x=[]): 
    pass
"""
        rule = MutableDefaultRule()
        findings = check_code(rule, code)
        assert len(findings) == 1


class TestBareExceptRule:
    def test_bare_except(self):
        code = """
try:
    pass
except:
    pass
"""
        rule = BareExceptRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L002"
        assert "Bare 'except:'" in findings[0]["message"]

    def test_specific_except(self):
        code = """
try:
    pass
except ValueError:
    pass
"""
        rule = BareExceptRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_tuple_except(self):
        code = """
try:
    pass
except (ValueError, TypeError):
    pass
"""
        rule = BareExceptRule()
        findings = check_code(rule, code)
        assert len(findings) == 0


class TestDangerousComparisonRule:
    def test_compare_true(self):
        code = """
if x == True: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L003"
        assert "should use 'is'" in findings[0]["message"]

    def test_compare_false(self):
        code = """
if x == False: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_compare_none(self):
        code = """
if x == None: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_compare_not_eq(self):
        code = """
if x != None: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_valid_comparison(self):
        code = """
if x == 1: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_is_none(self):
        code = """
if x is None: 
    pass
"""
        rule = DangerousComparisonRule()
        findings = check_code(rule, code)
        assert len(findings) == 0


class TestDuplicateBranchRule:
    def test_duplicate_elif_condition(self):
        code = """
def reconcile_account(event):
    if event["kind"] == "credit":
        return event["amount"]
    elif event["kind"] == "debit":
        return -event["amount"]
    elif event["kind"] == "fee":
        return -event["amount"]
    elif event["kind"] == "fee":
        return -event["amount"]
    return 0
"""
        rule = DuplicateBranchRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q305"
        assert findings[0]["name"] == "reconcile_account"
        assert findings[0]["value"] == "duplicate_condition"

    def test_duplicate_branch_body(self):
        code = """
def resolve_status(order):
    if order.is_cancelled:
        status = "closed"
        return status
    elif order.is_refunded:
        status = "closed"
        return status
    return "open"
"""
        rule = DuplicateBranchRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q305"
        assert findings[0]["value"] == "duplicate_body"

    def test_duplicate_if_else_body(self):
        code = """
def render_status(enabled):
    if enabled:
        label = "active"
        return label.upper()
    else:
        label = "active"
        return label.upper()
"""
        rule = DuplicateBranchRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-Q305"
        assert findings[0]["name"] == "render_status"
        assert findings[0]["value"] == "duplicate_body"

    def test_separate_functions_do_not_match_each_other(self):
        code = """
def first(flag):
    if flag:
        return "same"
    return "different"

def second(flag):
    if flag:
        return "same"
    return "different"
"""
        rule = DuplicateBranchRule()
        findings = check_code(rule, code)
        assert findings == []

    def test_nested_function_is_separate_scope(self):
        code = """
def outer(flag):
    if flag:
        return "outer"

    def inner(value):
        if value == 1:
            result = "same"
            return result
        elif value == 2:
            result = "same"
            return result
        return "other"

    return inner(1)
"""
        rule = DuplicateBranchRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["name"] == "inner"


class TestBroadExceptionRule:
    def test_exception_pass(self):
        code = """
try:
    pass
except Exception:
    pass
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"
        assert "broad" in findings[0]["message"]

    def test_exception_continue(self):
        code = """
for i in range(5):
    try:
        pass
    except Exception:
        continue
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"

    def test_exception_return(self):
        code = """
def foo():
    try:
        pass
    except Exception:
        return
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"

    def test_exception_return_none(self):
        code = """
def foo():
    try:
        pass
    except Exception:
        return None
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1

    def test_exception_return_empty_constructor(self):
        code = """
def foo():
    try:
        pass
    except Exception:
        return dict()
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"

    def test_base_exception_pass(self):
        code = """
try:
    pass
except BaseException:
    pass
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"
        assert "broad" in findings[0]["message"]

    def test_specific_exception(self):
        code = """
try:
    pass
except ValueError:
    pass
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_tuple_exception(self):
        code = """
try:
    pass
except (ValueError, TypeError):
    pass
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_tuple_with_broad_exception(self):
        code = """
try:
    pass
except (Exception, ValueError):
    pass
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L030"

    def test_exception_with_logging(self):
        code = """
try:
    pass
except Exception as e:
    logging.error(e)
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 0

    def test_exception_with_raise(self):
        code = """
try:
    pass
except Exception:
    raise
"""
        rule = BroadExceptionRule()
        findings = check_code(rule, code)
        assert len(findings) == 0
