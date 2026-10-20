"""An explicit unresolved mode must not be mistaken for default read mode."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger_fs.path_open_modes import PathOpenModes
from skylos.rules.danger.danger_fs.path_flow import scan
from test.fixture_paths import write_fixture


def _modes(source, *, bound=False):
    tree = ast.parse(textwrap.dedent(source))
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None)
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name == "open":
            calls.append(node)
    assert len(calls) == 1
    return PathOpenModes(tree).modes(calls[0], bound_method=bound)


@pytest.mark.parametrize("source", ["open(path)", "open(file=path)", "path.open()"])
def test_absent_mode_defaults_to_read(source):
    assert _modes(source, bound=source.startswith("path.")) == {"r"}


@pytest.mark.parametrize(
    "mode", ["r", "rb", "w", "wb", "a", "x", "r+", "r+b", "wb+", "a+", "x+t"]
)
def test_literal_mode_preserves_its_read_write_semantics(mode):
    assert _modes("open(path, " + repr(mode) + ")") == {mode}


@pytest.mark.parametrize(
    "source, expected",
    [
        ("open(path, 'w' if text else 'wb')", {"w", "wb"}),
        ("open(path, mode='w' if text else 'r')", {"w", "r"}),
        ("path.open('w' if text else 'wb')", {"w", "wb"}),
        ("path.open(mode='r+b')", {"r+b"}),
    ],
)
def test_actual_mode_expression_and_keyword_are_resolved(source, expected):
    assert _modes(source, bound=source.startswith("path.")) == expected


def test_single_dominating_assignments_and_aliases_are_followed():
    source = """
    def save(path, text):
        original = 'w' if text else 'wb'
        mode = original
        return open(path, mode)
    """
    assert _modes(source) == {"w", "wb"}


def test_module_literal_binding_without_namespace_stability_stays_unknown():
    assert _modes("MODE = 'wb'\ndef save(path):\n    return open(path, MODE)") is None


def test_annotated_mode_assignment_is_resolved():
    assert _modes(
        "def save(path):\n    mode: str = 'wb'\n    return open(path, mode)"
    ) == {"wb"}


def test_same_line_dominating_assignment_uses_column_order():
    assert _modes("def save(path): mode = 'wb'; return open(path, mode)") == {"wb"}


@pytest.mark.parametrize("text_branch", [True, False])
def test_single_assignment_dominates_its_nested_if_branch_use(text_branch):
    if text_branch:
        target = "if text:\n            return open(path, mode)"
    else:
        target = "if text:\n            pass\n        else:\n            return open(path, mode)"
    source = (
        "def save(path, text):\n"
        "    if eligible(path):\n"
        "        mode = 'w' if text else 'wb'\n"
        "        " + target + "\n"
    )
    assert _modes(source) == {"w", "wb"}


@pytest.mark.parametrize(
    "source",
    [
        "open(path, supplied_mode)",
        "open(path, mode=None)",
        "open(path, mode='')",
        "open(path, mode='rw')",
        "open(path, mode='read')",
        "open(path, mode='wbb')",
        "open(path, mode='rbt')",
        "open(path, mode='w' if text else supplied_mode)",
        "open(path, *arguments)",
        "open(path, 'w', *arguments)",
        "open(path, **keywords)",
        "open(path, 'w', mode='r')",
        "def save(path, mode='w'):\n    return open(path, mode)",
        "def save(path):\n    open(path, mode)\n    mode = 'w'",
        "def save(path):\n    mode = 'w'\n    mode = supplied\n    return open(path, mode)",
        "def save(path):\n    if condition:\n        mode = 'w'\n    return open(path, mode)",
        "def save(path):\n    for item in items:\n        mode = 'w'\n    return open(path, mode)",
        "def save(path):\n    with manager:\n        mode = 'w'\n    return open(path, mode)",
        "def save(path):\n    if condition:\n        mode = 'w'\n    else:\n        return open(path, mode)",
        "def save(path):\n    try:\n        mode = 'w'\n        fail()\n    except Exception:\n        return open(path, mode)",
        "def save(path):\n    for item in items:\n        mode = 'w'\n    else:\n        return open(path, mode)",
        "def save(path):\n    if condition:\n        mode = 'w'\n    if condition:\n        return open(path, mode)",
        "def save(path):\n    mode = 'w'\n    if condition:\n        mode = 'r'\n    return open(path, mode)",
        "def save(path):\n    mode = 'w'\n    for mode in modes:\n        pass\n    return open(path, mode)",
        "def save(path):\n    mode = 'w'\n    with manager as mode:\n        pass\n    return open(path, mode)",
        "def save(path):\n    mode = 'w'\n    mode += supplied\n    return open(path, mode)",
        "def save(path):\n    mode = 'w'\n    def change():\n        nonlocal mode\n        mode = supplied\n    change()\n    return open(path, mode)",
        "MODE = 'w'\ndef change():\n    global MODE\n    MODE = supplied\ndef save(path):\n    return open(path, MODE)",
        "def save(path):\n    mode = 'w'\n    locals()['mode'] = supplied\n    return open(path, mode)",
        "MODE = 'w'\ndef save(path):\n    globals()['MODE'] = supplied\n    return open(path, MODE)",
    ],
)
def test_unknown_or_non_dominating_explicit_modes_stay_unknown(source):
    assert _modes(source) is None


def test_unrelated_dynamic_loader_does_not_reclassify_known_write_mode():
    source = """
    def load_plugin(name):
        return __import__(name)
    def save(path, text):
        mode = 'w' if text else 'wb'
        return open(path, mode)
    """
    assert _modes(source) == {"w", "wb"}


@pytest.mark.parametrize(
    "source, expected",
    [
        ("open(path, 'w', **kwargs)", {"w"}),
        ("open(path, 'r', **kwargs)", {"r"}),
        ("open(path, **kwargs)", None),
        ("open(path, mode='w', **kwargs)", {"w"}),
        ("open(path, **kwargs, mode='w')", {"w"}),
        ("open(path, **kwargs, mode='w' if text else 'wb')", {"w", "wb"}),
        (
            "def save(path, kwargs):\n    mode = 'w'\n    open(path, mode=mode, **kwargs)",
            {"w"},
        ),
        (
            "def save(path, kwargs):\n    mode = 'w'\n    open(path, **kwargs, mode=mode)",
            None,
        ),
    ],
)
def test_keyword_expansion_cannot_override_a_captured_explicit_mode(source, expected):
    assert _modes(source) == expected


def test_nested_conditional_write_mode_is_captured_before_expanding_keywords():
    source = """
    def save(path, text, **kwargs):
        if eligible(path):
            mode = 'w' if text else 'wb'
            if text:
                return open(path, mode, **kwargs)
    """
    assert _modes(source) == {"w", "wb"}


def test_class_namespace_is_not_a_bare_method_name_closure():
    source = """
    class Writer:
        MODE = 'w'
        def save(self, path):
            return open(path, MODE)
    """
    assert _modes(source) is None


@pytest.mark.parametrize(
    "source",
    [
        "mode = 'w'\nopen(path, mode)",
        """
        MODE = 'w'
        namespace = globals
        namespace()['MODE'] = 'r'
        def save(path):
            return open(path, MODE)
        """,
        """
        import sys
        MODE = 'w'
        setattr(sys.modules[__name__], 'MODE', 'r')
        def save(path):
            return open(path, MODE)
        """,
        """
        import sys
        MODE = 'w'
        def change():
            setattr(sys.modules[__name__], 'MODE', 'r')
            return 1
        def save(path):
            return open(path, buffering=change(), mode=MODE)
        """,
        """
        def outer(path):
            mode = 'w'
            def save():
                return open(path, mode)
            return save()
        """,
    ],
)
def test_shared_namespace_modes_do_not_establish_operations(source):
    assert _modes(source) is None


@pytest.mark.parametrize(
    "capture",
    [
        "def captured():\n    return mode",
        "captured = lambda: mode",
        "def nested():\n    def captured():\n        return mode\n    return captured",
    ],
)
def test_captured_local_mode_does_not_claim_closure_cell_stability(capture):
    source = (
        "def save(path, callback):\n    mode = 'w'\n"
        + textwrap.indent(capture, "    ")
        + "\n    return open(path, mode)\n"
    )
    assert _modes(source) is None


@pytest.mark.parametrize(
    "nested",
    [
        "def inner():\n    mode = 'r'\n    return mode",
        "def inner(mode):\n    return mode",
        "inner = lambda mode: mode",
        "def inner():\n    mode = 'r'\n    def captured():\n        return mode\n    return captured",
    ],
)
def test_nested_own_mode_binding_does_not_invalidate_unrelated_outer_mode(nested):
    source = (
        "def save(path):\n    mode = 'w'\n"
        + textwrap.indent(nested, "    ")
        + "\n    return open(path, mode)\n"
    )
    assert _modes(source) == {"w"}


@pytest.mark.parametrize(
    "operation",
    [
        "namespace = locals\nnamespace()['mode'] = 'r'",
        "namespace = vars\nnamespace()['mode'] = 'r'",
        "namespace = globals\nnamespace()['mode'] = 'r'",
        "execute = exec\nexecute(\"mode = 'r'\")",
        "evaluate = eval\nevaluate(expression)",
        "frame = inspect.currentframe()\nframe.f_locals['mode'] = 'r'",
        "frame = sys._getframe()\nframe.f_locals['mode'] = 'r'",
    ],
)
def test_reflective_namespace_aliases_and_frame_access_leave_mode_unknown(operation):
    source = (
        "import inspect\nimport sys\n"
        "def save(path, expression):\n    mode = 'w'\n"
        + textwrap.indent(operation, "    ")
        + "\n    return open(path, mode)\n"
    )
    assert _modes(source) is None


def _scan_rules(tmp_path, source):
    source = textwrap.dedent(source)
    write_fixture(tmp_path, "pyproject.toml", "[project]\nname = 'open-mode-proof'\n")
    path = write_fixture(tmp_path, "service.py", source)
    findings = []
    scan(ast.parse(source), path, findings)
    rules = set()
    for finding in findings:
        if finding["symbol"] == "operate":
            rules.add(finding["rule_id"])
    return rules


@pytest.mark.parametrize(
    "mode, expected",
    [
        ("'w' if text else 'wb'", {"SKY-D215", "SKY-D324"}),
        ("'r' if text else 'rb'", {"SKY-D215", "SKY-D325"}),
        ("'r' if text else 'wb'", {"SKY-D215", "SKY-D324", "SKY-D325"}),
        ("'r+'", {"SKY-D215", "SKY-D324", "SKY-D325"}),
        ("supplied_mode", {"SKY-D215", "SKY-D324", "SKY-D325"}),
    ],
)
def test_scanner_uses_possible_operations_instead_of_defaulting_to_read(
    tmp_path, mode, expected
):
    source = (
        "def operate(path, text, supplied_mode):\n    mode = "
        + mode
        + "\n    return open(path, mode)\n"
    )
    assert _scan_rules(tmp_path, source) == expected


def test_scanner_absent_mode_keeps_default_read_finding(tmp_path):
    assert _scan_rules(tmp_path, "def operate(path):\n    return open(path)\n") == {
        "SKY-D215",
        "SKY-D325",
    }


@pytest.mark.parametrize(
    "call, expected",
    [
        ("open(path, 'w', **kwargs)", {"SKY-D215", "SKY-D324"}),
        ("open(path, 'r', **kwargs)", {"SKY-D215", "SKY-D325"}),
        ("open(path, **kwargs)", {"SKY-D215", "SKY-D324", "SKY-D325"}),
    ],
)
def test_scanner_distinguishes_fixed_modes_from_keyword_supplied_modes(
    tmp_path, call, expected
):
    source = "def operate(path, **kwargs):\n    return " + call + "\n"
    assert _scan_rules(tmp_path, source) == expected


def test_scanner_nested_conditional_write_mode_with_keyword_expansion(tmp_path):
    source = """
    def operate(path, text, **kwargs):
        if eligible(path):
            mode = 'w' if text else 'wb'
            if text:
                return open(path, mode, **kwargs)
    """
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324"}


@pytest.mark.parametrize("text_branch", [True, False])
def test_scanner_conditional_suite_mode_stays_write_in_both_actual_branches(
    tmp_path, text_branch
):
    if text_branch:
        target = "if text:\n            return open(path, mode)"
    else:
        target = "if text:\n            pass\n        else:\n            return open(path, mode)"
    source = (
        "def operate(path, text):\n"
        "    if eligible(path):\n"
        "        mode = 'w' if text else 'wb'\n"
        "        " + target + "\n"
    )
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324"}


@pytest.mark.parametrize(
    "source",
    [
        """
        MODE = 'w'
        namespace = globals
        namespace()['MODE'] = 'r'
        def operate(path):
            return open(path, MODE)
        """,
        """
        import sys
        MODE = 'w'
        setattr(sys.modules[__name__], 'MODE', 'r')
        def operate(path):
            return open(path, MODE)
        """,
        """
        import sys
        MODE = 'w'
        def change():
            setattr(sys.modules[__name__], 'MODE', 'r')
            return 1
        def operate(path):
            return open(path, buffering=change(), mode=MODE)
        """,
    ],
)
def test_scanner_namespace_mutations_keep_possible_read_and_write_checks(
    tmp_path, source
):
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324", "SKY-D325"}


@pytest.mark.parametrize(
    "operation",
    [
        "captured.__closure__[0].cell_contents = 'r'",
        "callback(captured)",
    ],
)
def test_scanner_captured_mode_mutation_keeps_possible_read_and_write_checks(
    tmp_path, operation
):
    source = (
        "def operate(path, callback):\n"
        "    mode = 'w'\n"
        "    def captured():\n"
        "        return mode\n"
        "    " + operation + "\n"
        "    return open(path, mode)\n"
    )
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324", "SKY-D325"}


def test_scanner_nested_local_mode_keeps_outer_write_mode_precision(tmp_path):
    source = """
    def operate(path):
        mode = 'w'
        def inner():
            mode = 'r'
            return mode
        inner()
        return open(path, mode)
    """
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324"}


@pytest.mark.parametrize(
    "operation",
    [
        "namespace = locals\nnamespace()['mode'] = 'r'",
        "frame = inspect.currentframe()\nframe.f_locals['mode'] = 'r'",
        "frame = sys._getframe()\nframe.f_locals['mode'] = 'r'",
    ],
)
def test_scanner_explicit_frame_mutation_keeps_possible_read_and_write_checks(
    tmp_path, operation
):
    source = (
        "import inspect\nimport sys\n"
        "def operate(path):\n    mode = 'w'\n"
        + textwrap.indent(operation, "    ")
        + "\n    return open(path, mode)\n"
    )
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324", "SKY-D325"}


def test_scanner_frame_namespace_in_helper_cannot_refute_caller_read(tmp_path):
    source = """
    import sys
    def change():
        sys._getframe(1).f_locals['mode'] = 'r'
    def operate(path):
        mode = 'w'
        change()
        return open(path, mode)
    """
    assert _scan_rules(tmp_path, source) == {"SKY-D215", "SKY-D324", "SKY-D325"}
