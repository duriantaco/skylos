import ast
from skylos.rules.quality.logic import (
    MutableDefaultRule,
    BareExceptRule,
    DangerousComparisonRule,
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
