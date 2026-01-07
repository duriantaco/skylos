import textwrap
from skylos.codemods import (
    remove_unused_import_cst,
    remove_unused_function_cst,
    comment_out_unused_import_cst,
    comment_out_unused_function_cst,
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



def test_comment_out_simple_function_block_wraps_lines():
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
    new, changed = comment_out_unused_function_cst(code, "unused", ln)

    assert changed is True
    assert _has_uncommented_line(new, "def unused") is False
    assert _has_uncommented_line(new, "def used") is True

    assert "SKYLOS DEADCODE START" in new
    assert "SKYLOS DEADCODE END" in new

    assert _has_commented_line(new, "def unused():") is True
    assert _has_commented_line(new, "return x") is True


def test_comment_out_async_function_block():
    code = textwrap.dedent(
        """\
        async def coro():
            return 1

        def ok():
            return 2
        """
    )
    ln = _line_no(code, "async def coro")
    new, changed = comment_out_unused_function_cst(code, "coro", ln)

    assert changed is True
    assert _has_uncommented_line(new, "async def coro") is False
    assert _has_uncommented_line(new, "def ok") is True

    assert _has_commented_line(new, "async def coro():") is True



def test_comment_out_function_custom_marker_is_used():
    code = "def f():\n    return 1\n"
    ln = _line_no(code, "def f")
    new, changed = comment_out_unused_function_cst(code, "f", ln, marker="MYMARK")

    assert changed is True
    assert "MYMARK START" in new
    assert "MYMARK END" in new



def test_comment_out_function_wrong_line_noop():
    code = "def f():\n    return 1\n"
    ln = 999
    new, changed = comment_out_unused_function_cst(code, "f", ln)

    assert changed is False
    assert new == code


def test_comment_out_simple_import_entire_line_becomes_block():
    code = "import os\nprint(1)\n"
    ln = _line_no(code, "import os")
    new, changed = comment_out_unused_import_cst(code, "os", ln)

    assert changed is True
    assert _has_uncommented_line(new, "import os") is False
    assert _has_uncommented_line(new, "print(1)") is True

    assert "SKYLOS DEADCODE START" in new
    assert "SKYLOS DEADCODE END" in new
    assert _has_commented_line(new, "import os") is True


def test_comment_out_one_name_from_multi_import_keeps_other_and_adds_comment_line():
    code = "import os, sys\n"
    ln = _line_no(code, "import os, sys")
    new, changed = comment_out_unused_import_cst(code, "os", ln)

    assert changed is True
    assert _has_uncommented_line(new, "import sys") is True
    assert _has_uncommented_line(new, "import os") is False

    assert "# SKYLOS DEADCODE:" in new
    assert _has_commented_line(new, "import os") is True



def test_comment_out_from_import_keeps_other_names_and_adds_comment_line():
    code = "from a import b, c\n"
    ln = _line_no(code, "from a import")
    new, changed = comment_out_unused_import_cst(code, "b", ln)

    assert changed is True
    assert _has_uncommented_line(new, "from a import c") is True
    assert _has_uncommented_line(new, "from a import b") is False

    assert "# SKYLOS DEADCODE:" in new
    assert _has_commented_line(new, "from a import b") is True



def test_comment_out_from_import_with_alias_matches_bound_name():
    code = "from a import b as c, d\n"
    ln = _line_no(code, "from a import")
    new, changed = comment_out_unused_import_cst(code, "c", ln)

    assert changed is True
    assert "from a import d" in new
    assert "# SKYLOS DEADCODE:" in new
    assert "from a import b as c" in new


def test_comment_out_import_star_is_noop():
    code = "from x import *\n"
    ln = _line_no(code, "from x import *")
    new, changed = comment_out_unused_import_cst(code, "*", ln)

    assert changed is False
    assert new == code


def test_comment_out_parenthesized_multiline_from_import_removes_one_and_preserves_others():
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
    new, changed = comment_out_unused_import_cst(code, "a", ln)

    assert changed is True
    assert "a," not in new
    assert "b,  # keep me" in new
    assert "c," in new

    assert "# SKYLOS DEADCODE:" in new
    assert "from x.y import a" in new


def test_comment_out_multiline_from_import_target_line_inside_block():
    code = textwrap.dedent(
        """\
        from x.y import (
            a,
            b,
        )
        """
    )

    target_line = _line_no(code, "a,")
    new, changed = comment_out_unused_import_cst(code, "a", target_line)

    assert changed is True
    assert "a," not in new
    assert "b," in new


def test_comment_out_dotted_import_requires_bound_leftmost_segment():
    code = "import pkg.sub\n"
    ln = _line_no(code, "import pkg.sub")

    new, changed = comment_out_unused_import_cst(code, "pkg", ln)
    assert changed is True
    assert _has_uncommented_line(new, "import pkg.sub") is False
    assert "# import pkg.sub" in new

    new2, changed2 = comment_out_unused_import_cst(code, "sub", ln)
    assert changed2 is False
    assert new2 == code


def test_comment_out_idempotency_import():
    code = "import os\n"
    ln = _line_no(code, "import os")

    new, changed = comment_out_unused_import_cst(code, "os", ln)
    assert changed is True

    new2, changed2 = comment_out_unused_import_cst(new, "os", ln)
    assert changed2 is False
    assert new2 == new


def test_comment_out_idempotency_function():
    code = "def f():\n    return 1\n"
    ln = _line_no(code, "def f")

    new, changed = comment_out_unused_function_cst(code, "f", ln)
    assert changed is True

    new2, changed2 = comment_out_unused_function_cst(new, "f", ln)
    assert changed2 is False
    assert new2 == new

def _has_uncommented_line(code: str, startswith: str) -> bool:
    for line in code.splitlines():
        s = line.lstrip()
        if s.startswith("#"):
            continue
        if s.startswith(startswith):
            return True
    return False


def _has_commented_line(code: str, contains: str) -> bool:
    for line in code.splitlines():
        s = line.lstrip()
        if not s.startswith("#"):
            continue
        if contains in s:
            return True
    return False
