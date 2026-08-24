import ast
from types import SimpleNamespace

import pytest

from skylos.rules.quality.logic import (
    BareExceptRule,
    BroadExceptionRule,
    DangerousComparisonRule,
    DuplicateBranchRule,
    MutableDefaultRule,
    RepeatedMutableAliasRule,
)
from skylos.rules.quality.logic_foundation import _proven_sequence_fact


def check_tree(rule, tree, filename="test.py"):
    findings = []
    context = {"filename": filename, "mod": "test_module"}

    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


def check_code(rule, code, filename="test.py"):
    return check_tree(rule, ast.parse(code), filename)


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


class TestRepeatedMutableAliasRule:
    @pytest.mark.parametrize(
        "expression",
        [
            "[{}] * count",
            "count * [[]]",
            "[{1}, {}] * count",
            "[({},)] * count",
            "[[item for item in source]] * count",
            "[[0] * columns] * rows",
            "[[{}] * 1] * rows",
            "[({},) * 1] * rows",
            "[{}] * (1 + 1)",
            "[{}] * (1 << 1)",
            "([{}] * 1) * rows",
            "rows * ([{}] * 1)",
            "(({},) * 1) * rows",
            "([{}] + []) * rows",
            "([{}] * bool(value)) * rows",
            "([{}] * (value > 0)) * rows",
            "([{}] * (not value)) * rows",
            "([1] * columns + [{}]) * rows",
            "[[] + []] * rows",
            "[(({},) + ())] * rows",
            "[*[{}]] * rows",
            "(*[{}],) * rows",
        ],
    )
    def test_mutable_elements_are_repeated_by_identity(self, expression):
        findings = check_code(RepeatedMutableAliasRule(), expression)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-L034"
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["value"] == "mutable_alias"
        assert findings[0]["line"] == 1
        assert findings[0]["col"] == 0
        assert "mutable elements across repetitions" in findings[0]["message"]

    @pytest.mark.parametrize(
        "expression",
        [
            "[0] * count",
            "[None, 'safe'] * count",
            "[shared] * count",
            "[{}] * 1",
            "[{}] * 0",
            "[{}] * -1",
            "False * [{}]",
            "[{}] * 1.5",
            "[{}] * (2 - 1)",
            "[{}] * ~0",
            "[{}] * (+4 // 3)",
            "[{}] * (3 & 1)",
            "[{}] * (4 / 2)",
            "[{}] * (1 << 0)",
            "[{}] * (value > 0)",
            "[{}] * bool(value)",
            "[((0,) * columns)] * rows",
            "[({},) * 0] * rows",
            "([{}] * 0) * rows",
            "[{} for _ in range(count)]",
            "[*[]] * rows",
            "[*[1, 2]] * rows",
            "(*[],) * rows",
            "(*[1],) * rows",
            "[*{}] * rows",
            "[*{1: 2}] * rows",
            "[*{1, 2}] * rows",
        ],
    )
    def test_safe_or_ambiguous_repetition_is_not_flagged(self, expression):
        assert check_code(RepeatedMutableAliasRule(), expression) == []

    def test_exact_bool_parameter_cannot_repeat_more_than_once(self):
        code = """
def maybe_item(include: bool):
    return [{}] * include
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_incompatible_bool_default_invalidates_boolean_count_proof(self):
        code = """
def repeated(count: bool = 2):
    return [{}] * count
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    @pytest.mark.parametrize("constructor", ["dict", "list", "set"])
    def test_builtin_mutable_constructor_elements_are_flagged(self, constructor):
        findings = check_code(RepeatedMutableAliasRule(), f"[{constructor}()] * count")

        assert len(findings) == 1

    @pytest.mark.parametrize("constructor", ["dict", "list", "set"])
    def test_shadowed_mutable_constructor_names_are_not_flagged(self, constructor):
        code = f"""
def repeated(count, {constructor}):
    return [{constructor}()] * count
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    @pytest.mark.parametrize("constructor", ["dict", "list", "set"])
    def test_module_shadowed_constructor_names_are_not_flagged(self, constructor):
        code = f"""
{constructor} = lambda: object()
items = [{constructor}()] * count
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_module_constructor_call_before_shadow_uses_builtin(self):
        code = """
items = [dict()] * count
dict = lambda: object()
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_class_constructor_call_before_shadow_uses_builtin(self):
        code = """
class Values:
    items = [dict()] * count
    dict = lambda: object()
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_function_constructor_call_keeps_lexical_shadowing(self):
        code = """
def repeated(count):
    items = [dict()] * count
    dict = lambda: object()
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    @pytest.mark.parametrize("constructor", ["dict", "list", "set"])
    def test_nested_constructor_binding_does_not_shadow_builtin(self, constructor):
        code = (
            f"def helper({constructor}):\n    return {constructor}\n"
            f"items = [{constructor}()] * count\n"
        )

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_wide_literal_budget_does_not_hide_mutable_tail(self):
        expression = "[" + ", ".join(["0"] * 130 + ["{}"]) + "] * count"

        assert len(check_code(RepeatedMutableAliasRule(), expression)) == 1

    @pytest.mark.parametrize("padding", ["()", "(0,)"])
    def test_wide_structural_siblings_do_not_hide_nested_mutable_tail(self, padding):
        expression = "[" + ", ".join([padding] * 130 + ["({},)"]) + "] * count"

        assert len(check_code(RepeatedMutableAliasRule(), expression)) == 1

    @pytest.mark.parametrize("padding", ["()", "(0,)"])
    def test_wide_nested_siblings_do_not_hide_mutable_head(self, padding):
        nested = "(" + ", ".join(["({},)"] + [padding] * 130) + ")"

        assert len(check_code(RepeatedMutableAliasRule(), f"[{nested}] * count")) == 1

    def test_nested_unsafe_repetition_is_not_reported_twice(self):
        findings = check_code(RepeatedMutableAliasRule(), "([{}] * 2) * rows")

        assert len(findings) == 1

    def test_shadowed_bool_annotation_is_not_trusted(self):
        code = """
bool = int

def repeated(count: bool):
    return [{}] * count
"""

        findings = check_code(RepeatedMutableAliasRule(), code)

        assert len(findings) == 1

    def test_reassigned_bool_parameter_is_not_treated_as_a_boolean_count(self):
        code = """
def repeated(count: bool):
    count = 2
    return [{}] * count
"""

        findings = check_code(RepeatedMutableAliasRule(), code)

        assert len(findings) == 1

    def test_bool_parameter_captured_by_nested_function_stays_safe(self):
        code = """
def outer(include: bool):
    def inner():
        return [{}] * include
    return inner
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_bool_parameter_captured_by_nested_class_stays_safe(self):
        code = """
def outer(include: bool):
    class Inner:
        values = [{}] * include
    return Inner
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_method_closure_skips_same_named_class_attribute(self):
        code = """
def outer(include: bool):
    class Inner:
        include = 2

        def values(self):
            return [{}] * include
    return Inner
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_nested_local_binding_shadows_captured_bool_parameter(self):
        code = """
def outer(include: bool):
    def inner():
        include = 2
        return [{}] * include
    return inner
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_nonlocal_bool_parameter_load_stays_safe_without_a_write(self):
        code = """
def outer(include: bool):
    def inner():
        nonlocal include
        return [{}] * include
    return inner
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_nonlocal_write_invalidates_captured_bool_parameter(self):
        code = """
def outer(include: bool):
    def inner():
        nonlocal include
        include = 2
        return [{}] * include
    return inner
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_comprehension_walrus_invalidates_containing_bool_parameter(self):
        code = """
def repeated(count: bool, source):
    [(count := 2) for _ in source]
    return [{}] * count
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_exact_bool_parameter_preserves_nested_repeat_fact(self):
        code = """
def repeated(include: bool, rows: int):
    return ([{}] * include) * rows
"""

        findings = check_code(RepeatedMutableAliasRule(), code)

        assert len(findings) == 1
        assert findings[0]["line"] == 3

    @pytest.mark.parametrize(
        "binding",
        [
            "import package as count",
            "from package import size as count",
            "try:\n        pass\n    except Exception as count:\n        pass",
            "match value:\n        case count:\n            pass",
            "def count():\n        pass",
            "class count:\n        pass",
        ],
    )
    def test_non_name_bindings_invalidate_bool_parameter(self, binding):
        code = f"""
def repeated(count: bool, value=None):
    {binding}
    return [{{}}] * count
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_wildcard_import_prevents_trusting_bool_annotation(self):
        code = """
from values import *

def repeated(count: bool):
    return [{}] * count
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_bool_type_parameter_prevents_trusting_bool_annotation(self):
        tree = ast.parse("""
def repeated(count: bool):
    return [{}] * count
""")
        tree.body[0].type_params = [SimpleNamespace(name="bool")]

        assert len(check_tree(RepeatedMutableAliasRule(), tree)) == 1

    def test_shadowed_bool_call_is_not_trusted(self):
        code = """
bool = lambda value: 2
items = [{}] * bool(source)
"""

        findings = check_code(RepeatedMutableAliasRule(), code)

        assert len(findings) == 1

    def test_module_bool_call_before_shadow_uses_builtin(self):
        code = """
items = [{}] * bool(source)
bool = lambda value: 2
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_class_bool_call_before_shadow_uses_builtin(self):
        code = """
class Values:
    items = [{}] * bool(source)
    bool = lambda value: 2
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_function_bool_call_keeps_lexical_shadowing(self):
        code = """
def repeated(source):
    items = [{}] * bool(source)
    bool = lambda value: 2
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_generator_body_does_not_assume_earlier_builtin_constructor(self):
        code = """
values = ([dict()] * count for _ in source)
dict = lambda: object()
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_same_statement_walrus_shadow_is_not_treated_as_later(self):
        code = """
items = [dict()] * count if (dict := lambda: object()) else []
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_same_statement_bool_walrus_is_not_treated_as_builtin(self):
        code = """
items = [{}] * bool(source) if (bool := lambda value: 2) else []
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    def test_loop_binding_can_precede_call_on_a_later_iteration(self):
        code = """
for source in values:
    items = [{}] * bool(source)
    bool = lambda value: 2
"""

        assert len(check_code(RepeatedMutableAliasRule(), code)) == 1

    @pytest.mark.parametrize(
        "nested_binding",
        [
            "def helper(bool):\n    return bool",
            "class Helper:\n    bool = 2",
        ],
    )
    def test_nested_bool_binding_does_not_shadow_module_builtin(self, nested_binding):
        code = f"{nested_binding}\nitems = [{{}}] * bool(source)\n"

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_class_bool_attribute_does_not_shadow_builtin_inside_method(self):
        code = """
class Helper:
    bool = 2

    def values(self, source):
        return [{}] * bool(source)
"""

        assert check_code(RepeatedMutableAliasRule(), code) == []

    def test_deep_sequence_fact_fails_closed_without_recursion(self):
        expression: ast.AST = ast.List(elts=[], ctx=ast.Load())
        for _ in range(20_000):
            expression = ast.BinOp(
                left=expression,
                op=ast.Add(),
                right=ast.List(elts=[], ctx=ast.Load()),
            )

        assert _proven_sequence_fact(expression, {}) is None


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
