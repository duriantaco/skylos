"""Liveness needs a reachable owner and source evidence, not matching words.

Fixture projects are parsed by the analyzer. Their code is never imported or
executed by these tests.
"""

import ast
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.python_proofs import deprecation_facts, proven_lazy_exports
from test.fixture_paths import write_fixture


def _scan(root, sources, *, confidence=60, grep=False):
    for relative, source in sources.items():
        write_fixture(root, relative, textwrap.dedent(source).lstrip(), overwrite=True)
    return json.loads(
        analyze(str(root), conf=confidence, grep_verify=grep, grep_cache=False)
    )


def _names(result, bucket):
    return {item.get("full_name", item["name"]) for item in result.get(bucket, ())}


@pytest.mark.parametrize("grep", [False, True])
def test_deprecated_parameter_does_not_hide_unused_function(tmp_path, grep):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        import warnings

        def parse_input(value, legacy=False):
            if legacy:
                warnings.warn("legacy=True is deprecated", DeprecationWarning)
            return str(value)
    """
        },
        grep=grep,
    )
    assert "app.parse_input" in _names(result, "unused_functions")
    finding = next(
        item for item in result["unused_functions"] if item["name"] == "parse_input"
    )
    assert finding["confidence"] == 90
    assert "deprecated_api" not in finding.get("confidence_factors", ())


@pytest.mark.parametrize(
    "body",
    [
        'if value:\n        warnings.warn("old argument", DeprecationWarning)\n    return value',
        'def inner():\n        warnings.warn("old inner", DeprecationWarning)\n    return value',
        'other.warn("anything", DeprecationWarning)\n    return value',
        'warnings.warn("not a deprecated API", RuntimeWarning)\n    return value',
    ],
)
def test_warning_lookalikes_do_not_deprecate_function(tmp_path, body):
    result = _scan(
        tmp_path,
        {"app.py": "import warnings\n\ndef candidate(value):\n    " + body + "\n"},
    )
    assert "app.candidate" in _names(result, "unused_functions")


@pytest.mark.parametrize(
    "source",
    [
        'import warnings as w\ndef candidate():\n    w.warn("use new API", DeprecationWarning)\n',
        'from warnings import warn as alert\nfrom builtins import FutureWarning as Category\ndef candidate():\n    alert("use new API", category=Category)\n',
        'def candidate():\n    import warnings\n    warnings.warn("use new API", DeprecationWarning)\n',
        'from warnings import deprecated\n@deprecated("use new API")\ndef candidate():\n    return 1\n',
        'def candidate():\n    """Deprecated: use the replacement."""\n    return 1\n',
        'def candidate():\n    """Old entry point kept for backwards compatibility."""\n    return 1\n',
    ],
)
def test_proved_deprecated_api_still_has_confidence_cap(tmp_path, source):
    result = _scan(tmp_path, {"app.py": source}, confidence=40)
    finding = next(
        item for item in result["unused_functions"] if item["name"] == "candidate"
    )
    assert finding["confidence"] == 40
    assert "deprecated_api" in finding["confidence_factors"]


@pytest.mark.parametrize(
    "source",
    [
        'def warn(message, category):\n    return message, category\nwarn("not a warning", DeprecationWarning)\ndef candidate():\n    return 1\n',
        'import warnings\nDeprecationWarning = RuntimeWarning\ndef candidate():\n    warnings.warn("still current", DeprecationWarning)\n',
        'import warnings\ndef candidate(warnings):\n    warnings.warn("still current", DeprecationWarning)\n',
        'import warnings\nwarnings.warn = print\ndef candidate():\n    warnings.warn("still current", DeprecationWarning)\n',
        'def deprecated(message):\n    return lambda fn: fn\n@deprecated("unrelated decorator")\ndef candidate():\n    return 1\n',
        'def candidate():\n    """This current API is not backwards compatible."""\n    return 1\n',
        'if False:\n    import warnings\n    warnings.warn("unreachable", DeprecationWarning)\ndef candidate():\n    return 1\n',
    ],
)
def test_unproved_deprecation_does_not_hide_candidate(tmp_path, source):
    result = _scan(tmp_path, {"app.py": source})
    assert "app.candidate" in _names(result, "unused_functions")


def test_local_warning_provider_is_not_the_stdlib(tmp_path):
    result = _scan(
        tmp_path,
        {
            "warnings.py": "def warn(*args):\n    return args\n",
            "app.py": 'import warnings\ndef candidate():\n    warnings.warn("text", DeprecationWarning)\n',
        },
    )
    assert "app.candidate" in _names(result, "unused_functions")


def test_aliased_pep702_decorator_is_resolved(tmp_path):
    path = write_fixture(
        tmp_path,
        "app.py",
        'from typing_extensions import deprecated as old_api\n@old_api("use new API")\ndef candidate():\n    return 1\n',
        overwrite=True,
    )
    _module, functions = deprecation_facts(str(path))
    assert (3, "candidate") in functions


def test_deprecation_cache_notices_new_provider_shadow(tmp_path):
    path = write_fixture(
        tmp_path,
        "app.py",
        'import warnings\ndef candidate():\n    warnings.warn("use new API", DeprecationWarning)\n',
        overwrite=True,
    )
    assert (2, "candidate") in deprecation_facts(str(path))[1]
    write_fixture(
        tmp_path, "warnings.py", "def warn(*args):\n    return args\n", overwrite=True
    )
    assert (2, "candidate") not in deprecation_facts(str(path))[1]


def test_literal_module_metadata_before_warning_preserves_deprecation(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        import warnings
        __version__ = "1.0"
        FEATURES = ("compatibility",)
        warnings.warn("This module is deprecated", DeprecationWarning)
        def candidate():
            return 1
    """
        },
    )
    assert "app.candidate" not in _names(result, "unused_functions")


def test_arbitrary_effect_before_warning_is_not_leading_deprecation(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        import warnings
        value = configure()
        warnings.warn("This option is deprecated", DeprecationWarning)
        def candidate():
            return 1
    """
        },
    )
    assert "app.candidate" in _names(result, "unused_functions")


@pytest.mark.parametrize(
    "document,hidden",
    [
        (
            "Old function for backwards compatibility; do not use this, use register_command.",
            True,
        ),
        (
            "Legacy method for backwards compatibility. Use register_command instead.",
            True,
        ),
        (
            "Current function supports backwards compatibility for old input files.",
            False,
        ),
        (
            "Old function for backwards compatibility, still supported for normal use.",
            False,
        ),
    ],
)
def test_retired_compatibility_entry_needs_explicit_retirement(
    tmp_path, document, hidden
):
    result = _scan(
        tmp_path,
        {"app.py": f'def legacy_entry():\n    """{document}"""\n    return 1\n'},
    )
    assert ("app.legacy_entry" not in _names(result, "unused_functions")) == hidden


def test_calling_current_function_removes_the_dead_code_trigger(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        import warnings
        def candidate(value, legacy=False):
            if legacy:
                warnings.warn("old argument", DeprecationWarning)
            return value
        candidate("current")
    """
        },
    )
    assert "app.candidate" not in _names(result, "unused_functions")


@pytest.mark.parametrize("grep", [False, True])
def test_dead_subclass_loader_cannot_rescue_class(tmp_path, grep):
    result = _scan(
        tmp_path,
        {
            "base.py": "class Plugin:\n    pass\ndef unused_loader():\n    return Plugin.__subclasses__()\n",
            "unloaded.py": "from base import Plugin\nclass NeverImported(Plugin):\n    pass\n",
        },
        confidence=0,
        grep=grep,
    )
    assert "unloaded.NeverImported" in _names(result, "unused_classes")
    assert "base.unused_loader" in _names(result, "unused_functions")


@pytest.mark.parametrize("called,loaded", [(False, True), (True, False), (True, True)])
def test_subclass_discovery_needs_both_reachable_owner_and_loading(
    tmp_path, called, loaded
):
    source = "from base import Plugin\n"
    source += "def discover():\n"
    if loaded:
        source += "    import extensions\n"
    source += "    return Plugin.__subclasses__()\n"
    if called:
        source += "discover()\n"
    result = _scan(
        tmp_path,
        {
            "base.py": "class Plugin:\n    pass\n",
            "app.py": source,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert ("extensions.Extension" not in _names(result, "unused_classes")) == (
        called and loaded
    )


def test_unknown_import_does_not_load_every_subclass(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": "class Plugin:\n    pass\n",
            "app.py": """
            import importlib
            from base import Plugin
            def discover(path):
                importlib.import_module(path)
                return Plugin.__subclasses__()
            discover(input())
        """,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" in _names(result, "unused_classes")


def test_custom_subclasses_method_is_not_builtin_discovery(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": """
            class Plugin:
                @classmethod
                def __subclasses__(cls):
                    return []
            import extensions
            Plugin.__subclasses__()
        """,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" in _names(result, "unused_classes")


@pytest.mark.parametrize("call_before_class", [False, True])
def test_local_subclass_order_is_relative_to_actual_discovery_call(
    tmp_path, call_before_class
):
    prefix = (
        "class Base:\n    pass\ndef discover():\n    return Base.__subclasses__()\n"
    )
    child = "class Extension(Base):\n    pass\n"
    call = "print(discover())\n"
    source = prefix + (call + child if call_before_class else child + call)
    result = _scan(tmp_path, {"app.py": source})
    assert ("app.Extension" in _names(result, "unused_classes")) == call_before_class


@pytest.mark.parametrize("conditional", [False, True])
def test_imported_package_loads_only_unconditional_submodules(tmp_path, conditional):
    import_line = "import plugins.extension\n"
    if conditional:
        import_line = "if False:\n    import plugins.extension\n"
    result = _scan(
        tmp_path,
        {
            "base.py": "class Base:\n    pass\n",
            "app.py": "from base import Base\nimport plugins\nprint(Base.__subclasses__())\n",
            "plugins/__init__.py": import_line,
            "plugins/extension.py": "from base import Base\nclass Extension(Base):\n    pass\n",
        },
    )
    assert (
        "plugins.extension.Extension" in _names(result, "unused_classes")
    ) == conditional


@pytest.mark.parametrize(
    "replacement",
    [
        "Plugin.__subclasses__ = lambda: []",
        'setattr(Plugin, "__subclasses__", lambda: [])',
    ],
)
def test_replaced_subclass_method_is_not_discovery(tmp_path, replacement):
    result = _scan(
        tmp_path,
        {
            "base.py": f"class Plugin:\n    pass\nimport extensions\n{replacement}\nPlugin.__subclasses__()\n",
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" in _names(result, "unused_classes")


def test_custom_metaclass_cannot_fabricate_builtin_discovery(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": """
            class Meta(type):
                def __subclasses__(cls):
                    return []
            class Plugin(metaclass=Meta):
                pass
            import extensions
            Plugin.__subclasses__()
        """,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" in _names(result, "unused_classes")


def test_unrelated_dead_import_does_not_load_subclass(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": "class Plugin:\n    pass\n",
            "app.py": """
            from base import Plugin
            def unused_importer():
                import extensions
            def discover():
                return Plugin.__subclasses__()
            discover()
        """,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" in _names(result, "unused_classes")


def test_discovery_of_one_imported_module_does_not_rescue_another(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": "class Plugin:\n    pass\n",
            "app.py": """
            import importlib
            import inspect
            from base import Plugin
            def discover():
                module = importlib.import_module("extensions")
                found = []
                for value in module.__dict__.values():
                    if inspect.isclass(value) and issubclass(value, Plugin):
                        found.append(value)
                return found
            discover()
        """,
            "extensions.py": "from base import Plugin\nclass Extension(Plugin):\n    pass\n",
            "unloaded.py": "from base import Plugin\nclass Unloaded(Plugin):\n    pass\n",
        },
        confidence=0,
    )
    assert "extensions.Extension" not in _names(result, "unused_classes")
    assert "unloaded.Unloaded" in _names(result, "unused_classes")


@pytest.mark.parametrize("grep", [False, True])
def test_lazy_getattr_and_unrelated_word_do_not_keep_import(tmp_path, grep):
    result = _scan(
        tmp_path,
        {
            "app.py": """
        import os
        LABEL = "os"
        def __getattr__(name):
            raise AttributeError(name)
    """
        },
        grep=grep,
    )
    assert "os" in _names(result, "unused_imports")


@pytest.mark.parametrize(
    "getter",
    [
        "def __getattr__(name):\n    return None\n",
        "def __getattr__(name):\n    module, attr = _LAZY[name]\n    return None\n",
        "def __getattr__(name):\n    raise AttributeError(name)\n    module, attr = _LAZY[name]\n    return getattr(__import__(module, fromlist=[attr]), attr)\n",
    ],
)
def test_lazy_table_without_returned_lookup_does_not_keep_import(tmp_path, getter):
    result = _scan(
        tmp_path,
        {
            "pkg/__init__.py": 'from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pkg.mod import Thing\n__all__ = []\n_LAZY = {"Thing": ("pkg.mod", "Thing")}\n'
            + getter,
            "pkg/mod.py": "class Thing:\n    pass\n",
        },
    )
    assert "pkg.mod.Thing" in _names(result, "unused_imports")


@pytest.mark.parametrize("guard", ['name == "Thing"', "name in __all__"])
def test_returned_lazy_lookup_with_matching_guard_keeps_import(tmp_path, guard):
    result = _scan(
        tmp_path,
        {
            "pkg/__init__.py": f"""import importlib
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pkg.mod import Thing
__all__ = ["Thing"]
def __getattr__(name):
    if {guard}:
        return getattr(importlib.import_module("pkg.mod"), name)
    raise AttributeError(name)
""",
            "pkg/mod.py": "class Thing:\n    pass\n",
        },
    )
    assert "pkg.mod.Thing" not in _names(result, "unused_imports")


def test_lazy_table_target_must_match_import_provider(tmp_path):
    result = _scan(
        tmp_path,
        {
            "pkg/__init__.py": """
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from pkg.old import Thing
            __all__ = []
            _LAZY = {"Thing": ("pkg.new", "Thing")}
            def __getattr__(name):
                module, attr = _LAZY[name]
                return getattr(__import__(module, fromlist=[attr]), attr)
        """,
            "pkg/old.py": "class Thing:\n    pass\n",
            "pkg/new.py": "class Thing:\n    pass\n",
        },
    )
    assert "pkg.old.Thing" in _names(result, "unused_imports")


@pytest.mark.parametrize("guard", ['name == "Thing"', "name in __all__"])
def test_lazy_guard_proof_returns_the_actual_target(tmp_path, guard):
    source = f"""import importlib
__all__ = ["Thing"]
def __getattr__(name):
    if {guard}:
        return getattr(importlib.import_module("pkg.mod"), name)
    raise AttributeError(name)
"""
    assert proven_lazy_exports(ast.parse(source), str(tmp_path / "app.py")) == {
        "Thing": "pkg.mod.Thing"
    }


@pytest.mark.parametrize(
    "mutation",
    [
        '_LAZY["Thing"] = ("pkg.other", "Other")',
        "rewrite(_LAZY)",
        "other = _LAZY",
    ],
)
def test_mutated_or_escaped_lazy_table_is_not_proof(tmp_path, mutation):
    source = f"""_LAZY = {{"Thing": ("pkg.mod", "Thing")}}
{mutation}
def __getattr__(name):
    module, attr = _LAZY[name]
    return getattr(__import__(module, fromlist=[attr]), attr)
"""
    assert proven_lazy_exports(ast.parse(source), str(tmp_path / "app.py")) == {}


def test_dotted_builtin_import_without_fromlist_returns_parent_module(tmp_path):
    source = """_LAZY = {"Thing": ("pkg.mod", "Thing")}
def __getattr__(name):
    module, attr = _LAZY[name]
    return getattr(__import__(module), attr)
"""
    assert proven_lazy_exports(ast.parse(source), str(tmp_path / "app.py")) == {}


def test_local_importlib_provider_does_not_prove_lazy_export(tmp_path):
    write_fixture(
        tmp_path,
        "importlib.py",
        "def import_module(name):\n    return None\n",
        overwrite=True,
    )
    source = """import importlib
def __getattr__(name):
    if name == "Thing":
        return getattr(importlib.import_module("pkg.mod"), name)
    raise AttributeError(name)
"""
    assert proven_lazy_exports(ast.parse(source), str(tmp_path / "app.py")) == {}


@pytest.mark.parametrize(
    "getter",
    [
        """def __getattr__(name):
    if name == "Thing":
        module = importlib.import_module("pkg.mod")
        return getattr(module, name)
    raise AttributeError(name)
""",
        """def __getattr__(name):
    try:
        module, attr = _LAZY[name]
    except KeyError:
        raise AttributeError(name) from None
    return getattr(importlib.import_module(module), attr)
""",
    ],
)
def test_source_owned_lazy_lookup_can_use_temporary_or_keyerror_guard(tmp_path, getter):
    source = (
        'import importlib\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pkg.mod import Thing\n__all__ = []\n_LAZY = {"Thing": ("pkg.mod", "Thing")}\n'
        + getter
    )
    result = _scan(
        tmp_path, {"pkg/__init__.py": source, "pkg/mod.py": "class Thing:\n    pass\n"}
    )
    assert "pkg.mod.Thing" not in _names(result, "unused_imports")


def test_lookalike_lazy_import_temporary_cannot_hide_mismatched_import(tmp_path):
    source = """import importlib
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pkg.mod import Thing
__all__ = []
def __getattr__(name):
    if name == "Thing":
        module = importlib.import_module("pkg.other")
        return getattr(module, name)
    raise AttributeError(name)
"""
    result = _scan(
        tmp_path,
        {
            "pkg/__init__.py": source,
            "pkg/mod.py": "class Thing:\n    pass\n",
            "pkg/other.py": "class Thing:\n    pass\n",
        },
    )
    assert "pkg.mod.Thing" in _names(result, "unused_imports")
