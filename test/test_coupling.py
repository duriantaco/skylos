"""Tests for CBO (Coupling Between Objects) metric - SKY-Q701."""

import ast
import pytest
from skylos.rules.quality.coupling import CBORule, analyze_coupling, _extract_type_names


# ── Helper ──

def _parse(code: str) -> ast.AST:
    return ast.parse(code)


# ── _extract_type_names ──

class TestExtractTypeNames:
    def test_simple_name(self):
        tree = ast.parse("x: MyClass")
        ann = tree.body[0].annotation
        names = _extract_type_names(ann)
        assert "MyClass" in names

    def test_builtin_excluded(self):
        tree = ast.parse("x: int")
        ann = tree.body[0].annotation
        names = _extract_type_names(ann)
        assert "int" not in names

    def test_optional_union(self):
        tree = ast.parse("x: int | MyClass")
        ann = tree.body[0].annotation
        names = _extract_type_names(ann)
        assert "MyClass" in names
        assert "int" not in names

    def test_none(self):
        names = _extract_type_names(None)
        assert names == set()


# ── analyze_coupling ──

class TestAnalyzeCoupling:
    def test_no_classes(self):
        tree = _parse("x = 1\ndef foo(): pass")
        result = analyze_coupling(tree, "test.py")
        assert result["classes"] == {}

    def test_single_isolated_class(self):
        code = """
class Foo:
    def bar(self):
        return 1
"""
        result = analyze_coupling(_parse(code), "test.py")
        assert "Foo" in result["classes"]
        assert result["classes"]["Foo"]["efferent_coupling"] == 0
        assert result["classes"]["Foo"]["afferent_coupling"] == 0

    def test_inheritance_coupling(self):
        code = """
class Base:
    pass

class Child(Base):
    pass
"""
        result = analyze_coupling(_parse(code), "test.py")
        child = result["classes"]["Child"]
        assert "Base" in child["breakdown"]["inheritance"]
        assert child["efferent_coupling"] >= 1

    def test_type_hint_coupling(self):
        code = """
class Config:
    pass

class App:
    def setup(self, config: Config) -> None:
        pass
"""
        result = analyze_coupling(_parse(code), "test.py")
        app = result["classes"]["App"]
        assert "Config" in app["breakdown"]["type_hints"]

    def test_instantiation_coupling(self):
        code = """
class Logger:
    pass

class App:
    def __init__(self):
        self.logger = Logger()
"""
        result = analyze_coupling(_parse(code), "test.py")
        app = result["classes"]["App"]
        assert "Logger" in app["breakdown"]["instantiation"]

    def test_attribute_access_coupling(self):
        code = """
class Config:
    HOST = "localhost"

class App:
    def get_host(self):
        return Config.HOST
"""
        result = analyze_coupling(_parse(code), "test.py")
        app = result["classes"]["App"]
        assert "Config" in app["breakdown"]["attribute_access"]

    def test_afferent_coupling(self):
        code = """
class Shared:
    pass

class A(Shared):
    pass

class B(Shared):
    pass
"""
        result = analyze_coupling(_parse(code), "test.py")
        shared = result["classes"]["Shared"]
        assert shared["afferent_coupling"] >= 2

    def test_instability_calculation(self):
        code = """
class A:
    pass

class B:
    pass

class C(A):
    def foo(self, b: B):
        pass
"""
        result = analyze_coupling(_parse(code), "test.py")
        c = result["classes"]["C"]
        # C depends on A and B (Ce=2), nobody depends on C (Ca=0)
        assert c["efferent_coupling"] >= 2
        assert c["instability"] > 0.5

    def test_coupling_graph(self):
        code = """
class A:
    pass

class B(A):
    pass
"""
        result = analyze_coupling(_parse(code), "test.py")
        graph = result["coupling_graph"]
        assert "A" in graph["B"]


# ── CBORule ──

class TestCBORule:
    def test_low_coupling_no_finding(self):
        code = """
class Foo:
    def bar(self):
        return 1
"""
        rule = CBORule(low_threshold=4)
        tree = _parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                result = rule.visit_node(node, {"filename": "/tmp/test_cbo.py"})
                assert result is None

    def test_high_coupling_generates_finding(self):
        # Create a class that depends on many others
        code = """
class A: pass
class B: pass
class C: pass
class D: pass
class E: pass
class F: pass

class BigClass(A):
    def m1(self, b: B) -> C:
        d = D()
        E.something
        return F()
"""
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            fname = f.name

        try:
            rule = CBORule(low_threshold=3)
            tree = _parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "BigClass":
                    result = rule.visit_node(node, {"filename": fname})
                    assert result is not None
                    assert len(result) == 1
                    finding = result[0]
                    assert finding["rule_id"] == "SKY-Q701"
                    assert finding["name"] == "BigClass"
                    assert finding["efferent_coupling"] >= 4
                    assert "coupling_breakdown" in finding
        finally:
            os.unlink(fname)
