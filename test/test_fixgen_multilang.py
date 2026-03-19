from __future__ import annotations

import textwrap
from skylos.fixgen import (
    _check_brace_balance,
    _find_brace_block_end,
    _validate_file,
)


class TestFindBraceBlockEnd:
    def test_simple_function(self):
        lines = [
            "function foo() {",
            "  return 1;",
            "}",
        ]
        assert _find_brace_block_end(lines, 0) == 2

    def test_nested_braces(self):
        lines = [
            "function bar() {",
            "  if (x) {",
            "    return 1;",
            "  }",
            "  return 2;",
            "}",
        ]
        assert _find_brace_block_end(lines, 0) == 5

    def test_single_line(self):
        lines = ["function baz() { return 1; }"]
        assert _find_brace_block_end(lines, 0) == 0

    def test_class_with_methods(self):
        lines = [
            "class Foo {",
            "  bar() {",
            "    return 1;",
            "  }",
            "  baz() {",
            "    return 2;",
            "  }",
            "}",
        ]
        assert _find_brace_block_end(lines, 0) == 7

    def test_go_func(self):
        lines = [
            "func main() {",
            '  fmt.Println("hello")',
            "}",
        ]
        assert _find_brace_block_end(lines, 0) == 2

    def test_rust_fn(self):
        lines = [
            "fn main() {",
            '    println!("hello");',
            "}",
        ]
        assert _find_brace_block_end(lines, 0) == 2

    def test_start_beyond_end(self):
        lines = ["fn foo() {}"]
        assert _find_brace_block_end(lines, 5) == 5

    def test_unbalanced_fallback(self):
        lines = [
            "function foo() {",
            "  // missing closing brace",
        ]
        assert _find_brace_block_end(lines, 0) == 1


class TestCheckBraceBalance:
    def test_balanced(self):
        assert _check_brace_balance("test.java", "class Foo { void bar() { } }") == []

    def test_unbalanced_open(self):
        errors = _check_brace_balance("test.java", "class Foo { void bar() { }")
        assert len(errors) == 1
        assert "Unclosed" in errors[0]

    def test_unbalanced_close(self):
        errors = _check_brace_balance("test.java", "class Foo { } }")
        assert len(errors) == 1
        assert "Unbalanced" in errors[0]

    def test_parens_and_brackets(self):
        assert (
            _check_brace_balance("test.java", "int[] a = new int[]{1, 2, (3)};") == []
        )

    def test_empty_content(self):
        assert _check_brace_balance("test.java", "") == []


class TestValidateFilePython:
    def test_valid_python(self):
        assert _validate_file("test.py", "x = 1\ny = 2\n") == []

    def test_invalid_python(self):
        errors = _validate_file("test.py", "def foo(\n")
        assert len(errors) == 1
        assert "syntax error" in errors[0].lower()

    def test_pyi_file(self):
        assert _validate_file("stubs.pyi", "def foo(x: int) -> str: ...\n") == []


class TestValidateFileJava:
    def test_valid_java(self):
        code = textwrap.dedent("""\
            public class Foo {
                public void bar() {
                    System.out.println("hello");
                }
            }
        """)
        assert _validate_file("Foo.java", code) == []

    def test_invalid_java(self):
        code = textwrap.dedent("""\
            public class Foo {
                public void bar() {
                    System.out.println("hello");
            }
        """)
        errors = _validate_file("Foo.java", code)
        assert len(errors) == 1


class TestValidateFileUnknown:
    def test_unknown_extension(self):
        assert _validate_file("data.csv", "a,b,c") == []

    def test_no_extension(self):
        assert _validate_file("Makefile", "all:\n\techo hi") == []
