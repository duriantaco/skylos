import ast
import pytest
from skylos.rules.quality.logic import MutableDefaultRule


@pytest.fixture
def rule():
    return MutableDefaultRule()


@pytest.fixture
def context():
    return {"filename": "test.py"}


def parse_and_get_func(code):
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


class TestMutableDefaultRule:
    def test_empty_list_literal(self, rule, context):
        node = parse_and_get_func("def foo(items=[]): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1
        assert result[0]["rule_id"] == "SKY-L001"

    def test_empty_dict_literal(self, rule, context):
        node = parse_and_get_func("def foo(cache={}): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_empty_set_literal(self, rule, context):
        node = parse_and_get_func("def foo(items={1, 2}): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_list_constructor(self, rule, context):
        node = parse_and_get_func("def foo(items=list()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_dict_constructor(self, rule, context):
        node = parse_and_get_func("def foo(cache=dict()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_set_constructor(self, rule, context):
        node = parse_and_get_func("def foo(items=set()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_defaultdict_constructor(self, rule, context):
        node = parse_and_get_func("def foo(cache=defaultdict(list)): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_ordereddict_constructor(self, rule, context):
        node = parse_and_get_func("def foo(cache=OrderedDict()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_counter_constructor(self, rule, context):
        node = parse_and_get_func("def foo(counts=Counter()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_deque_constructor(self, rule, context):
        node = parse_and_get_func("def foo(queue=deque()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_list_comprehension(self, rule, context):
        node = parse_and_get_func("def foo(items=[x for x in range(3)]): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_dict_comprehension(self, rule, context):
        node = parse_and_get_func("def foo(cache={k: v for k, v in []}): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_set_comprehension(self, rule, context):
        node = parse_and_get_func("def foo(items={x for x in range(3)}): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_kwonly_mutable_default(self, rule, context):
        node = parse_and_get_func("def foo(*, items=[]): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_multiple_mutable_defaults(self, rule, context):
        node = parse_and_get_func("def foo(a=[], b={}, c=list()): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 3

    def test_async_function(self, rule, context):
        node = parse_and_get_func("async def foo(items=[]): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1

    def test_none_default_ok(self, rule, context):
        node = parse_and_get_func("def foo(items=None): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_int_default_ok(self, rule, context):
        node = parse_and_get_func("def foo(count=0): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_string_default_ok(self, rule, context):
        node = parse_and_get_func("def foo(name='default'): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_tuple_default_ok(self, rule, context):
        node = parse_and_get_func("def foo(items=(1, 2, 3)): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_frozenset_default_ok(self, rule, context):
        node = parse_and_get_func("def foo(items=frozenset()): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_no_defaults_ok(self, rule, context):
        node = parse_and_get_func("def foo(a, b, c): pass")
        result = rule.visit_node(node, context)
        assert result is None

    def test_mixed_defaults_only_flags_mutable(self, rule, context):
        node = parse_and_get_func("def foo(a=1, b=[], c='str'): pass")
        result = rule.visit_node(node, context)
        assert result is not None
        assert len(result) == 1