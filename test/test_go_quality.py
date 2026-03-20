import pytest

try:
    from tree_sitter import Parser, Language
    import tree_sitter_go as tsgo

    GO_LANG = Language(tsgo.language())
    HAS_GO_TS = True
except Exception:
    HAS_GO_TS = False

from skylos.visitors.languages.go.quality import scan_go_quality


def _scan(code: str) -> list[dict]:
    if not HAS_GO_TS:
        pytest.skip("tree-sitter-go not available")
    source = code.encode("utf-8")
    parser = Parser(GO_LANG)
    tree = parser.parse(source)
    return scan_go_quality(tree.root_node, source, "test.go")


class TestGoComplexity:
    def test_simple_function_no_finding(self):
        code = """
package main

func simple() int {
    return 1
}
"""
        findings = _scan(code)
        assert not any(f["rule_id"] == "SKY-Q301" for f in findings)

    def test_complex_function(self):
        code = """
package main

func complex(x int) string {
    if x > 0 {
        if x > 10 {
            return "big"
        } else if x > 5 {
            return "medium"
        }
    }
    for i := 0; i < x; i++ {
        if i%2 == 0 {
            continue
        }
        switch i {
        case 1:
            return "one"
        case 2:
            return "two"
        case 3:
            return "three"
        default:
            return "other"
        }
    }
    if x == 0 && x != -1 {
        return "zero"
    }
    return "negative"
}
"""
        findings = _scan(code)
        complexity_findings = [f for f in findings if f["rule_id"] == "SKY-Q301"]
        assert len(complexity_findings) == 1
        assert "complex" in complexity_findings[0]["message"]

    def test_bool_ops_add_complexity(self):
        code = """
package main

func check(a, b, c, d, e, f, g, h, i, j, k bool) bool {
    if a && b {
        return true
    }
    if c || d {
        return true
    }
    if e && f && g {
        return true
    }
    if h || i || j || k {
        return true
    }
    return false
}
"""
        findings = _scan(code)
        complexity_findings = [f for f in findings if f["rule_id"] == "SKY-Q301"]
        assert len(complexity_findings) == 1


class TestGoNesting:
    def test_shallow_nesting_no_finding(self):
        code = """
package main

func shallow() {
    if true {
        x := 1
        _ = x
    }
}
"""
        findings = _scan(code)
        assert not any(f["rule_id"] == "SKY-Q302" for f in findings)

    def test_deep_nesting(self):
        code = """
package main

func deep() {
    if true {
        for i := 0; i < 10; i++ {
            if i > 0 {
                switch i {
                    case 1:
                        if true {
                            if true {
                                _ = i
                            }
                        }
                }
            }
        }
    }
}
"""
        findings = _scan(code)
        nesting_findings = [f for f in findings if f["rule_id"] == "SKY-Q302"]
        assert len(nesting_findings) == 1


class TestGoParams:
    def test_few_params_no_finding(self):
        code = """
package main

func small(a int, b string) {}
"""
        findings = _scan(code)
        assert not any(f["rule_id"] == "SKY-C303" for f in findings)

    def test_too_many_params(self):
        code = """
package main

func tooMany(a int, b int, c int, d int, e int, f int) {}
"""
        findings = _scan(code)
        param_findings = [f for f in findings if f["rule_id"] == "SKY-C303"]
        assert len(param_findings) == 1
        assert "6 parameters" in param_findings[0]["message"]


class TestGoFunctionLength:
    def test_short_function_no_finding(self):
        code = """
package main

func short() {
    x := 1
    _ = x
}
"""
        findings = _scan(code)
        assert not any(f["rule_id"] == "SKY-C304" for f in findings)

    def test_long_function(self):
        lines = ["package main", "", "func long() {"]
        for i in range(60):
            lines.append(f"    x{i} := {i}")
        lines.append("}")
        code = "\n".join(lines)
        findings = _scan(code)
        length_findings = [f for f in findings if f["rule_id"] == "SKY-C304"]
        assert len(length_findings) == 1


class TestGoMethodDeclaration:
    def test_method_analyzed(self):
        lines = ["package main", "", "type Foo struct{}", "", "func (f *Foo) bar() {"]
        for i in range(55):
            lines.append(f"    x{i} := {i}")
        lines.append("}")
        code = "\n".join(lines)
        findings = _scan(code)
        length_findings = [f for f in findings if f["rule_id"] == "SKY-C304"]
        assert len(length_findings) == 1
        assert "bar" in length_findings[0]["message"]


class TestNoTreeSitterFallback:
    def test_returns_empty_without_lang(self):
        findings = scan_go_quality(None, b"", "test.go", lang=None)
        assert findings == []
