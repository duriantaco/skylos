"""Tests for LCOM (Lack of Cohesion of Methods) metric - SKY-Q702."""

import ast
import pytest
from skylos.rules.quality.cohesion import LCOMRule, analyze_cohesion, _UnionFind


# ── Helper ──

def _parse(code: str) -> ast.ClassDef:
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            return node
    raise ValueError("No class found")


# ── UnionFind ──

class TestUnionFind:
    def test_basic_union(self):
        uf = _UnionFind()
        uf.make_set("a")
        uf.make_set("b")
        uf.make_set("c")
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")
        assert uf.find("a") != uf.find("c")

    def test_components(self):
        uf = _UnionFind()
        for x in "abcde":
            uf.make_set(x)
        uf.union("a", "b")
        uf.union("c", "d")
        comps = uf.components()
        assert len(comps) == 3  # {a,b}, {c,d}, {e}

    def test_path_compression(self):
        uf = _UnionFind()
        for x in "abcd":
            uf.make_set(x)
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("c", "d")
        # After find with path compression, all should point to root
        root = uf.find("d")
        assert uf.find("a") == root
        assert uf.find("b") == root
        assert uf.find("c") == root


# ── analyze_cohesion ──

class TestAnalyzeCohesion:
    def test_single_method_returns_none(self):
        node = _parse("""
class Foo:
    def bar(self):
        self.x = 1
""")
        result = analyze_cohesion(node)
        assert result is None  # < 2 methods

    def test_perfectly_cohesive(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self.x = 0
        self.y = 0

    def update(self):
        self.x += 1
        self.y += 1

    def reset(self):
        self.x = 0
        self.y = 0
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1  # All methods share x and y

    def test_completely_uncohesive(self):
        node = _parse("""
class Foo:
    def method_a(self):
        self.x = 1

    def method_b(self):
        self.y = 2

    def method_c(self):
        self.z = 3
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 3  # Three disconnected groups

    def test_self_calls_connect_methods(self):
        node = _parse("""
class Foo:
    def method_a(self):
        self.x = 1

    def method_b(self):
        self.y = 2
        self.method_a()
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1  # Connected via self.method_a()

    def test_static_methods_excluded(self):
        node = _parse("""
class Foo:
    def instance_a(self):
        self.x = 1

    def instance_b(self):
        self.x = 2

    @staticmethod
    def static_one():
        return 42
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["method_count"] == 2  # Static excluded

    def test_classmethod_cls_attrs(self):
        node = _parse("""
class Foo:
    @classmethod
    def create(cls):
        cls.count = 0

    @classmethod
    def increment(cls):
        cls.count += 1
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1  # Both access cls.count

    def test_property_backing_attribute(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self._value = 0

    @property
    def value(self):
        return self._value

    def set_value(self, v):
        self._value = v
""")
        result = analyze_cohesion(node)
        assert result is not None
        # __init__, value property, and set_value all share _value
        assert result["lcom4"] == 1

    def test_dataclass_exemption(self):
        node = _parse("""
@dataclass
class Config:
    host: str
    port: int

    def url(self):
        return f"http://{self.host}:{self.port}"

    def is_secure(self):
        return self.port == 443
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["is_dataclass"] is True

    def test_lcom5_normalized(self):
        node = _parse("""
class Foo:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert 0.0 <= result["lcom5"] <= 1.0

    def test_cohesion_groups_reported(self):
        node = _parse("""
class Foo:
    def group1_a(self):
        self.x = 1

    def group1_b(self):
        self.x = 2

    def group2_a(self):
        self.y = 3

    def group2_b(self):
        self.y = 4
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 2
        assert len(result["cohesion_groups"]) == 2

    def test_init_groups_dunders(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self.name = ""
        self.value = 0

    def __str__(self):
        return self.name

    def unrelated(self):
        self.other = True
""")
        result = analyze_cohesion(node)
        assert result is not None
        # __init__ and __str__ should be connected (share self.name)
        # unrelated is separate
        assert result["lcom4"] == 2


# ── LCOMRule ──

class TestLCOMRule:
    def test_cohesive_class_no_finding(self):
        code = """
class Cohesive:
    def __init__(self):
        self.x = 0

    def get(self):
        return self.x

    def set(self, v):
        self.x = v
"""
        rule = LCOMRule()
        node = _parse(code)
        result = rule.visit_node(node, {"filename": "test.py"})
        assert result is None  # LCOM4 = 1, below threshold

    def test_uncohesive_class_generates_finding(self):
        code = """
class Uncohesive:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2

    def c(self):
        self.z = 3
"""
        rule = LCOMRule(low_threshold=2)
        node = _parse(code)
        result = rule.visit_node(node, {"filename": "test.py"})
        assert result is not None
        assert len(result) == 1
        finding = result[0]
        assert finding["rule_id"] == "SKY-Q702"
        assert finding["lcom4"] == 3
        assert "cohesion_groups" in finding

    def test_dataclass_exempted(self):
        code = """
@dataclass
class Config:
    a: int
    b: str
    c: float

    def method_a(self):
        return self.a

    def method_b(self):
        return self.b

    def method_c(self):
        return self.c
"""
        rule = LCOMRule(low_threshold=2, high_threshold=4)
        node = _parse(code)
        result = rule.visit_node(node, {"filename": "test.py"})
        # Dataclass with LCOM4=3 should be exempted (threshold+2 = 6)
        assert result is None
