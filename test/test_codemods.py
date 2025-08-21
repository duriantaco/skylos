import textwrap
from skylos.codemods import (
    remove_unused_import_cst,
    remove_unused_function_cst,
)

def _line_no(code: str, startswith: str) -> int:
    for i, line in enumerate(code.splitlines(), start=1):
        if line.lstrip().startswith(startswith):
            return i
    raise AssertionError(f"Line starting with {startswith!r} not found")

def test_remove_simple_import_entire_line():
    code = "import os\nprint(1)\n"
    ln = _line_no(code, "import os")
    new, changed = remove_unused_import_cst(code, "os", ln)
    assert changed is True
    assert "import os" not in new
    assert "print(1)" in new

def test_remove_one_name_from_multi_import():
    code = "import os, sys\n"
    ln = _line_no(code, "import os, sys")
    new, changed = remove_unused_import_cst(code, "os", ln)
    assert changed is True
    assert new.strip() == "import sys"

def test_remove_from_import_keeps_other_names():
    code = "from a import b, c\n"
    ln = _line_no(code, "from a import")
    new, changed = remove_unused_import_cst(code, "b", ln)
    assert changed is True
    assert new.strip() == "from a import c"

def test_remove_from_import_with_alias_uses_bound_name():
    code = "from a import b as c, d\n"
    ln = _line_no(code, "from a import")
    new, changed = remove_unused_import_cst(code, "c", ln)
    assert changed is True
    assert new.strip() == "from a import d"

def test_parenthesized_multiline_from_import_preserves_formatting():
    code = textwrap.dedent(
        """\
        from x.y import (
            a,
            b,  # keep me
            c,
        )
        use = b
        """
    )
    ln = _line_no(code, "from x.y import")
    new, changed = remove_unused_import_cst(code, "a", ln)
    assert changed is True
    assert "a," not in new
    assert "b,  # keep me" in new
    assert "c," in new

def test_import_star_is_noop():
    code = "from x import *\n"
    ln = _line_no(code, "from x import *")
    new, changed = remove_unused_import_cst(code, "*", ln)
    assert changed is False
    assert new == code

def test_dotted_import_requires_bound_leftmost_segment():
    code = "import pkg.sub\n"
    ln = _line_no(code, "import pkg.sub")
    new, changed = remove_unused_import_cst(code, "pkg", ln)
    assert changed is True
    assert "import pkg.sub" not in new

    new2, changed2 = remove_unused_import_cst(code, "sub", ln)
    assert changed2 is False
    assert new2 == code

def test_import_idempotency():
    code = "import os, sys\n"
    ln = _line_no(code, "import os, sys")
    new, changed = remove_unused_import_cst(code, "os", ln)
    assert changed is True
    new2, changed2 = remove_unused_import_cst(new, "os", ln)
    assert changed2 is False
    assert new2 == new

def test_remove_simple_function_block():
    code = textwrap.dedent(
        """\
        def unused():
            x = 1
            return x

        def used():
            return 42
        """
    )
    ln = _line_no(code, "def unused")
    new, changed = remove_unused_function_cst(code, "unused", ln)
    assert changed is True
    assert "def unused" not in new
    assert "def used" in new

def test_remove_decorated_function_removes_decorators_too():
    code = textwrap.dedent(
        """\
        @dec1
        @dec2(arg=1)
        def target():
            return 1

        def other():
            return 2
        """
    )
    ln = _line_no(code, "def target")
    new, changed = remove_unused_function_cst(code, "target", ln)
    assert changed is True
    assert "@dec1" not in new and "@dec2" not in new
    assert "def target" not in new
    assert "def other" in new

def test_remove_async_function():
    code = textwrap.dedent(
        """\
        async def coro():
            return 1

        def ok():
            return 2
        """
    )
    ln = _line_no(code, "async def coro")
    new, changed = remove_unused_function_cst(code, "coro", ln)
    assert changed is True
    assert "async def coro" not in new
    assert "def ok" in new

def test_function_wrong_line_noop():
    code = "def f():\n    return 1\n"
    ln = 999
    new, changed = remove_unused_function_cst(code, "f", ln)
    assert changed is False
    assert new == code

def test_function_idempotency():
    code = "def g():\n    return 1\n"
    ln = _line_no(code, "def g")
    new, changed = remove_unused_function_cst(code, "g", ln)
    assert changed is True
    new2, changed2 = remove_unused_function_cst(new, "g", ln)
    assert changed2 is False
    assert new2 == new