"""Package API exports must not hide unread function-local bindings."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture

_NAMESPACE_RECALL = pytest.mark.xfail(
    strict=True,
    reason="Namespace imports retain prior implicit exports; sharper recall deferred",
)


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _scan(root):
    return json.loads(analyze(str(root), conf=60, grep_verify=True))


def _variables(result):
    return {
        finding.get("full_name") or finding["name"]
        for finding in result.get("unused_variables", [])
    }


def test_package_function_local_is_not_an_implicit_export(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        PUBLIC_SETTING = 3

        def run():
            forgotten_pipeline = object()
            return 0
        """,
    )

    result = _scan(tmp_path)

    assert "pkg.run.forgotten_pipeline" in _variables(result)
    assert "pkg.PUBLIC_SETTING" not in _variables(result)
    entry = next(
        item
        for item in result["dead_code_evidence"]["symbols"]
        if item["qualified_name"] == "pkg.run.forgotten_pipeline"
    )
    assert not any(
        event.get("details", {}).get("root_kind") == "public_export"
        for event in entry["evidence"]
    )


@pytest.mark.xfail(
    strict=True,
    reason="Explicit __all__ local-name collisions are outside implicit export fix",
)
def test_module_all_does_not_export_a_function_local_with_the_same_name(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        __all__ = ["STATE", "run"]
        STATE = 3

        def run():
            STATE = object()
            return 0
        """,
    )

    variables = _variables(_scan(tmp_path))

    assert "pkg.run.STATE" in variables
    assert "pkg.STATE" not in variables


def test_package_method_local_is_not_a_public_class_field(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        class Client:
            public_setting = 3

            def run(self):
                forgotten_pipeline = object()
                self.result = 4
                return self.result
        """,
    )

    variables = _variables(_scan(tmp_path))

    assert "pkg.Client.run.forgotten_pipeline" in variables
    assert "pkg.Client.public_setting" not in variables
    assert "pkg.Client.result" not in variables


def test_used_and_closed_over_package_locals_stay_live(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        def make_reader():
            retained_value = 3

            def read():
                nonlocal retained_value
                retained_value += 1
                return retained_value

            return read
        """,
    )

    assert "pkg.make_reader.retained_value" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize("expression", ["locals()", "vars()", "eval(source)"])
def test_package_dynamic_local_namespace_stays_live(tmp_path, expression):
    _write(
        tmp_path,
        "pkg/__init__.py",
        f"""
        def evaluate(source):
            retained_value = object()
            return {expression}
        """,
    )

    assert "pkg.evaluate.retained_value" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize(
    ("imports", "expression"),
    [
        (
            "import inspect as frame_tools",
            "frame_tools.currentframe().f_locals[source]",
        ),
        (
            "from inspect import currentframe as frame",
            "frame().f_locals[source]",
        ),
        ("from builtins import eval as evaluate", "evaluate(source)"),
        ("from builtins import locals as local_values", "local_values()[source]"),
        ("from builtins import vars as local_values", "local_values()[source]"),
        ("from builtins import exec as execute", "execute(source)"),
        ("import sys as runtime", "runtime._getframe().f_locals[source]"),
        ("from sys import _getframe as frame", "frame().f_locals[source]"),
    ],
)
def test_package_aliased_introspection_keeps_local_values(
    tmp_path, imports, expression
):
    _write(
        tmp_path,
        "pkg/__init__.py",
        f"""
        {imports}

        def exported(source):
            retained_value = object()
            return {expression}
        """,
    )

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize(
    "binding",
    [
        "def frame():\n    return 0\n",
        pytest.param(
            "from inspect import currentframe as frame\nframe = lambda: 0\n",
            marks=_NAMESPACE_RECALL,
        ),
    ],
)
def test_local_frame_lookalikes_do_not_hide_unread_values(tmp_path, binding):
    _write(
        tmp_path,
        "pkg/__init__.py",
        binding
        + "\ndef exported():\n    forgotten_value = object()\n    return frame()\n",
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@_NAMESPACE_RECALL
def test_nested_frame_binding_shadows_an_import_alias(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from inspect import currentframe as frame

        def exported():
            def frame():
                return 0
            forgotten_value = object()
            return frame()
        """,
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


def test_global_assignment_in_a_package_function_remains_an_api_binding(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        STATE = 0

        def run():
            global STATE
            STATE = 1
            return STATE
        """,
    )

    assert "pkg.STATE" not in _variables(_scan(tmp_path))


def test_module_namespace_colliding_with_another_files_function_stays_exported(
    tmp_path,
):
    _write(tmp_path, "pkg/__init__.py", "def tools():\n    return 1\n")
    _write(tmp_path, "pkg/tools/__init__.py", "PUBLIC_SETTING = 3\n")

    assert "pkg.tools.PUBLIC_SETTING" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize("parameter", ["frame", "*frame", "**frame"])
@_NAMESPACE_RECALL
def test_frame_parameter_shadows_an_import_alias(tmp_path, parameter):
    _write(
        tmp_path,
        "pkg/__init__.py",
        "from inspect import currentframe as frame\n"
        + f"\ndef exported({parameter}):\n    forgotten_value = object()\n    return frame()\n",
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@_NAMESPACE_RECALL
def test_another_functions_frame_import_does_not_rescue_a_local(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        def get_frame():
            from inspect import currentframe as frame
            return frame()

        def exported():
            forgotten_value = object()
            return frame()
        """,
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@_NAMESPACE_RECALL
def test_vars_with_an_object_does_not_read_function_locals(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from builtins import vars as object_fields

        def exported(value):
            forgotten_value = object()
            return object_fields(value)
        """,
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@pytest.mark.parametrize(
    "imports",
    [
        "from inspect import currentframe as frame",
        "frame = None\n    from inspect import currentframe as frame",
    ],
)
def test_function_local_frame_import_keeps_read_values(tmp_path, imports):
    _write(
        tmp_path,
        "pkg/__init__.py",
        "def exported(frame=None, source=None):\n    "
        + imports
        + "\n    retained_value = object()\n    return frame().f_locals[source]\n",
    )

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))


def test_closure_import_alias_keeps_read_values(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        def make_reader():
            from inspect import currentframe as frame
            def exported(source):
                retained_value = object()
                return frame().f_locals[source]
            return exported
        """,
    )

    assert "pkg.make_reader.exported.retained_value" not in _variables(_scan(tmp_path))


def test_explicit_global_frame_alias_keeps_read_values(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from inspect import currentframe as frame
        def exported(source):
            global frame
            retained_value = object()
            return frame().f_locals[source]
        """,
    )

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))


@_NAMESPACE_RECALL
def test_closure_parameter_shadows_module_frame_alias(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from inspect import currentframe as frame
        def make_reader(frame):
            def exported():
                forgotten_value = object()
                return frame()
            return exported
        """,
    )

    assert "pkg.make_reader.exported.forgotten_value" in _variables(_scan(tmp_path))


@_NAMESPACE_RECALL
def test_later_function_assignment_shadows_module_frame_alias(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from inspect import currentframe as frame
        def exported():
            forgotten_value = object()
            value = frame()
            frame = lambda: 0
            return value, frame
        """,
    )

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@pytest.mark.parametrize("local", [False, True])
@_NAMESPACE_RECALL
def test_another_import_can_replace_a_frame_provider(tmp_path, local):
    imports = "from inspect import currentframe as frame\nfrom other import frame\n"
    body = "forgotten_value = object()\nreturn frame()\n"
    if local:
        source = "def exported():\n" + textwrap.indent(imports + body, "    ")
    else:
        source = imports + "\ndef exported():\n" + textwrap.indent(body, "    ")
    _write(tmp_path, "pkg/__init__.py", source)

    assert "pkg.exported.forgotten_value" in _variables(_scan(tmp_path))


@pytest.mark.parametrize(
    ("filename", "source", "expected_reported"),
    [
        pytest.param(
            "module.py",
            'from builtins import eval as evaluate\n\ndef entry():\n    quiet_value = object()\n    return evaluate("1 + 1", {}, {})\n\nentry()\n',
            True,
            id="eval-explicit",
        ),
        pytest.param(
            "module.py",
            'from builtins import exec as evaluate\n\ndef entry():\n    quiet_value = object()\n    evaluate("answer = 3", {}, {})\n    return 0\n\nentry()\n',
            True,
            id="exec-explicit",
        ),
        pytest.param(
            "module.py",
            "from builtins import locals as local_values\n\ndef entry():\n    quiet_value = object()\n    reader = lambda: local_values()\n    return reader()\n\nentry()\n",
            True,
            id="lambda-locals",
        ),
        pytest.param(
            "module.py",
            "from inspect import currentframe as frame\n\ndef entry():\n    quiet_value = object()\n    reader = lambda: frame().f_locals\n    return reader()\n\nentry()\n",
            True,
            id="lambda-frame",
        ),
        pytest.param(
            "pkg/__init__.py",
            'import os\nif os.getenv("CHOICE"):\n    from inspect import currentframe as frame\nelse:\n    from types import SimpleNamespace as frame\n\ndef exported(key):\n    quiet_value = object()\n    return frame().f_locals.get(key)\n',
            False,
            id="conditional-frame",
        ),
        pytest.param(
            "pkg/__init__.py",
            "try:\n    from inspect import currentframe as frame\nexcept ImportError:\n    from types import SimpleNamespace as frame\n\ndef exported(key):\n    quiet_value = object()\n    return frame().f_locals.get(key)\n",
            False,
            id="fallback-frame",
        ),
        pytest.param(
            "module.py",
            "from inspect import currentframe as frame\n\ndef entry():\n    quiet_value = object()\n    return frame()\n\ndef replacement():\n    return 0\n\nframe = replacement\nentry()\n",
            True,
            id="replaced-module",
        ),
    ],
)
def test_independent_alias_precision_controls(
    tmp_path, filename, source, expected_reported
):
    _write(tmp_path, filename, source)

    variables = _variables(_scan(tmp_path))

    assert any(name.endswith(".quiet_value") for name in variables) is expected_reported


def test_plain_module_all_keeps_its_existing_local_policy(tmp_path):
    _write(
        tmp_path,
        "module.py",
        """
        from inspect import currentframe as frame

        __all__ = ["STATE", "entry"]
        STATE = 3

        def entry(key):
            STATE = object()
            return frame().f_locals[key]

        entry("STATE")
        """,
    )

    assert "module.entry.STATE" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("prefix", [True, False])
def test_conditional_fake_binding_preserves_a_possible_frame_reader(
    tmp_path, local, prefix
):
    real_import = "from inspect import currentframe as frame\n"
    if prefix:
        bindings = real_import + "if choice:\n    frame = lambda: None\n"
    else:
        bindings = (
            "if choice:\n    " + real_import + "else:\n    frame = lambda: None\n"
        )
    body = "quiet_value = object()\nreturn frame().f_locals[key]\n"
    if local:
        source = "def exported(choice, key):\n" + textwrap.indent(
            bindings + body, "    "
        )
    else:
        source = (
            "import os\nchoice = os.getenv('CHOICE')\n"
            + bindings
            + "\ndef exported(key):\n"
            + textwrap.indent(body, "    ")
        )
    _write(tmp_path, "pkg/__init__.py", source)

    assert "pkg.exported.quiet_value" not in _variables(_scan(tmp_path))


@pytest.mark.parametrize(
    ("files", "target", "expected_reported"),
    [
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom inspect import currentframe as frame\ndef entry():\n    quiet_value = object()\n    class Holder:\n        namespace = frame().f_locals\n    return Holder\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-class-body-frame",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom sys import _getframe as frame\ndef entry():\n    quiet_value = object()\n    return frame(1).f_locals\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-getframe-other-depth",
        ),
        pytest.param(
            {
                "pkg/__init__.py": "from inspect import currentframe as frame\ndef entry():\n    quiet_value = object()\n    def reader(namespace=frame().f_locals):\n        return namespace\n    return reader\nentry()\n"
            },
            "quiet_value",
            False,
            id="package-nested-default-reads-parent",
        ),
        pytest.param(
            {
                "pkg/__init__.py": 'import os\nif os.getenv("CONFIG_STYLE"):\n    def Service():\n        quiet_value = object()\n        return 0\nelse:\n    class Service:\n        PUBLIC_SETTING = object()\n'
            },
            "PUBLIC_SETTING",
            False,
            id="class-function-owner-collision",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom inspect import currentframe as frame\ndef entry():\n    quiet_value = object()\n    return (frame().f_locals for _ in range(1))\nlist(entry())\n'
            },
            "quiet_value",
            True,
            id="package-generator-frame",
        ),
        pytest.param(
            {
                "module.py": "from inspect import currentframe as frame\ndef entry():\n    quiet_value = object()\n    return (frame().f_locals for _ in range(1))\nlist(entry())\n"
            },
            "quiet_value",
            True,
            id="module-generator-frame",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nimport inspect as readers\ndef entry():\n    quiet_value = object()\n    return readers.currentframe()\nentry()\n',
                "inspect.py": "def currentframe():\n    return 0\n",
            },
            "quiet_value",
            True,
            id="package-inspect-shadow",
        ),
        pytest.param(
            {
                "module.py": "import inspect as readers\ndef entry():\n    quiet_value = object()\n    return readers.currentframe()\nentry()\n",
                "inspect.py": "def currentframe():\n    return 0\n",
            },
            "quiet_value",
            True,
            id="module-inspect-shadow",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom builtins import eval as evaluate\n\ndef entry():\n    quiet_value = object()\n    return evaluate("1 + 1", {}, {})\n\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-all-eval-explicit",
        ),
        pytest.param(
            {
                "pkg/__init__.py": 'from builtins import eval as evaluate\n\ndef entry():\n    __quiet_value = object()\n    return evaluate("1 + 1", {}, {})\n\nentry()\n'
            },
            "__quiet_value",
            True,
            id="package-dunder-eval-explicit",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom builtins import exec as evaluate\n\ndef entry():\n    quiet_value = object()\n    evaluate("answer = 3", {}, {})\n    return 0\n\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-all-exec-explicit",
        ),
        pytest.param(
            {
                "pkg/__init__.py": 'from builtins import exec as evaluate\n\ndef entry():\n    __quiet_value = object()\n    evaluate("answer = 3", {}, {})\n    return 0\n\nentry()\n'
            },
            "__quiet_value",
            True,
            id="package-dunder-exec-explicit",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom builtins import locals as local_values\n\ndef entry():\n    quiet_value = object()\n    reader = lambda: local_values()\n    return reader()\n\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-all-lambda-locals",
        ),
        pytest.param(
            {
                "pkg/__init__.py": "from builtins import locals as local_values\n\ndef entry():\n    __quiet_value = object()\n    reader = lambda: local_values()\n    return reader()\n\nentry()\n"
            },
            "__quiet_value",
            True,
            id="package-dunder-lambda-locals",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom inspect import currentframe as frame\n\ndef entry():\n    quiet_value = object()\n    reader = lambda: frame().f_locals\n    return reader()\n\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-all-lambda-frame",
        ),
        pytest.param(
            {
                "pkg/__init__.py": "from inspect import currentframe as frame\n\ndef entry():\n    __quiet_value = object()\n    reader = lambda: frame().f_locals\n    return reader()\n\nentry()\n"
            },
            "__quiet_value",
            True,
            id="package-dunder-lambda-frame",
        ),
        pytest.param(
            {
                "pkg/__init__.py": '__all__ = ["entry"]\nfrom inspect import currentframe as frame\n\ndef entry():\n    quiet_value = object()\n    return frame()\n\ndef replacement():\n    return 0\n\nframe = replacement\nentry()\n'
            },
            "quiet_value",
            True,
            id="package-all-replaced-module",
        ),
        pytest.param(
            {
                "pkg/__init__.py": "from inspect import currentframe as frame\n\ndef entry():\n    __quiet_value = object()\n    return frame()\n\ndef replacement():\n    return 0\n\nframe = replacement\nentry()\n"
            },
            "__quiet_value",
            True,
            id="package-dunder-replaced-module",
        ),
    ],
)
def test_independent_export_boundary_controls(
    tmp_path, files, target, expected_reported
):
    for filename, source in files.items():
        _write(tmp_path, filename, source)

    variables = _variables(_scan(tmp_path))

    assert any(name.endswith("." + target) for name in variables) is expected_reported


@pytest.mark.parametrize(
    "source",
    [
        "def exported(key):\n    retained_value = object()\n    return frame().f_locals[key]\n\nfrom inspect import currentframe as frame\n",
        "from inspect import currentframe as frame\n\ndef exported(key):\n    retained_value = object()\n    reader = frame\n    return reader().f_locals[key]\n",
    ],
    ids=["late-module-import", "reader-value-alias"],
)
def test_namespace_reader_import_order_and_value_alias(tmp_path, source):
    _write(tmp_path, "pkg/__init__.py", source)

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))


def test_module_namespace_reader_value_alias_keeps_old_export_compatibility(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        from inspect import currentframe as imported_frame
        frame = imported_frame

        def exported(key):
            retained_value = object()
            return frame().f_locals[key]
        """,
    )

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))


def test_module_namespace_module_alias_keeps_old_export_compatibility(tmp_path):
    _write(
        tmp_path,
        "pkg/__init__.py",
        """
        import inspect as imported_frames
        frames = imported_frames

        def exported(key):
            retained_value = object()
            return frames.currentframe().f_locals[key]
        """,
    )

    assert "pkg.exported.retained_value" not in _variables(_scan(tmp_path))
