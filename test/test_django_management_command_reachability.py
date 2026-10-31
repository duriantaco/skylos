"""A proven command handle roots its actual helpers, not nearby dead code."""

import json
import textwrap

import pytest

from skylos.analyzer import Skylos


_MODULE = "shop.management.commands.audit"
_PATH = "shop/management/commands/audit.py"
_HELPERS = "def prepare(): return 1\ndef abandoned(): return 2\n"
_PROVIDER = "from django.core.management.base import BaseCommand\n"
_ROOT_REASON = "dead_code_liveness:django_web_management_command_handle"


def _scan(tmp_path, sources):
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(source), encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(
            str(tmp_path),
            thr=80,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    unused = {
        item["full_name"]
        for bucket in ("unused_functions", "unused_methods", "unused_classes")
        for item in result.get(bucket, [])
    }
    definitions = {definition.name: definition for definition in analyzer.defs.values()}
    return unused, definitions


def _command(tmp_path, code, extra=None, path=_PATH):
    return _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/management/__init__.py": "",
            "shop/management/commands/__init__.py": "",
            path: code,
            **(extra or {}),
        },
    )


@pytest.mark.parametrize(
    "body, helpers, live, dead",
    [
        ("return prepare()", _HELPERS, ["prepare"], ["abandoned"]),
        (
            "def prepare(): return 1\ndef abandoned(): return 2\nreturn prepare()",
            "",
            ["Command.handle.prepare"],
            ["Command.handle.abandoned"],
        ),
        (
            "def prepare(): return 1\ndef run(): return prepare()\nreturn run()",
            "",
            ["Command.handle.prepare", "Command.handle.run"],
            [],
        ),
        (
            "def prepare(): return 1\nselected = prepare\nreturn selected()",
            "",
            ["Command.handle.prepare"],
            [],
        ),
        (
            "return analyze_games_queryset()",
            "class GameDiscontinuityAnalyzer:\n"
            "    def run(self): return 1\n"
            "def analyze_games_queryset(): return GameDiscontinuityAnalyzer().run()\n"
            "def abandoned(): return 2\n",
            ["analyze_games_queryset", "GameDiscontinuityAnalyzer"],
            ["abandoned"],
        ),
    ],
    ids=[
        "module-helper",
        "nested-helper",
        "nested-chain",
        "nested-alias",
        "constructor-chain",
    ],
)
def test_discovered_handle_roots_only_its_called_helpers(
    tmp_path, body, helpers, live, dead
):
    source = (
        _PROVIDER
        + helpers
        + "class Command(BaseCommand):\n"
        + "    def handle(self, *args, **options):\n"
        + textwrap.indent(body, "        ")
        + "\n"
    )
    unused, definitions = _command(tmp_path, source)
    assert not ({f"{_MODULE}.{name}" for name in live} & unused)
    assert {f"{_MODULE}.{name}" for name in dead} <= unused
    handle = definitions[f"{_MODULE}.Command.handle"]
    assert handle.heuristic_refs.get(_ROOT_REASON) == 1.0
    assert handle.heuristic_refs.get("framework_root") == 1.0


@pytest.mark.parametrize("imported", [False, True])
def test_management_discovery_selects_the_effective_inherited_handle(
    tmp_path, imported
):
    parent = (
        _PROVIDER
        + _HELPERS
        + "class Parent(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
    )
    source = "class Command(Parent):\n    pass\n"
    extra = {}
    owner = _MODULE
    if imported:
        source = "from parent import Parent\n" + source
        extra["parent.py"] = parent
        owner = "parent"
    else:
        source = parent + source
    unused, definitions = _command(tmp_path, source, extra)
    assert f"{owner}.prepare" not in unused
    assert f"{owner}.abandoned" in unused
    assert definitions[f"{owner}.Parent.handle"].heuristic_refs.get(_ROOT_REASON) == 1.0


def test_management_export_alias_and_unrelated_constructor_do_not_lose_identity(
    tmp_path,
):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Unrelated:\n    def __init__(self): raise RuntimeError()\n"
        + "class Actual(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "Command = Actual\n"
    )
    unused, definitions = _command(tmp_path, source)
    assert f"{_MODULE}.prepare" not in unused
    assert f"{_MODULE}.abandoned" in unused
    assert (
        definitions[f"{_MODULE}.Actual.handle"].heuristic_refs.get(_ROOT_REASON) == 1.0
    )


@pytest.mark.parametrize(
    "setup, tail, path, extra",
    [
        ("class BaseCommand: pass\n", "", _PATH, {}),
        (_PROVIDER + "class Local: pass\nBaseCommand = Local\n", "", _PATH, {}),
        (_PROVIDER, "\nCommand = object()\n", _PATH, {}),
        (_PROVIDER, "\nCommand.handle = lambda self: None\n", _PATH, {}),
        (_PROVIDER, "", "shop/ordinary.py", {}),
        (_PROVIDER, "", "shop/management/commands/_audit.py", {}),
        (_PROVIDER, "", _PATH, {"django.py": "class BaseCommand: pass\n"}),
    ],
    ids=[
        "lookalike",
        "rebound-base",
        "rebound-export",
        "rebound-handle",
        "wrong-location",
        "private-module",
        "shadowed-django",
    ],
)
def test_invalid_discovery_never_roots_the_original_handle(
    tmp_path, setup, tail, path, extra
):
    source = (
        setup
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + tail
    )
    unused, definitions = _command(tmp_path, source, extra, path)
    module = path.removesuffix(".py").replace("/", ".")
    assert f"{module}.prepare" in unused
    assert not definitions[f"{module}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


def test_replaced_handle_through_attribute_protocol_receives_no_new_root(tmp_path):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "setattr(Command, 'handle', lambda self: None)\n"
    )
    _, definitions = _command(tmp_path, source)
    # Existing reflection uncertainty may retain helpers; it does not prove
    # Django invokes the replaced original method.
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


@pytest.mark.parametrize(
    "tail",
    [
        "change = setattr\nchange(Command, 'handle', lambda self: None)\n",
        "from external_plugin import install\ninstall(Command)\n",
    ],
    ids=["writer-alias", "opaque-class-escape"],
)
def test_command_namespace_escape_does_not_establish_dispatch(tmp_path, tail):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + tail
    )
    _, definitions = _command(tmp_path, source)
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


@pytest.mark.parametrize(
    "override",
    [
        "def __init__(self): raise RuntimeError()",
        "def __new__(cls): return object()",
        "def __getattribute__(self, name): return lambda: None",
        "def __getattr__(self, name): return input()",
    ],
    ids=["raising-init", "factory-new", "attribute-hook", "unmodeled-fallback-hook"],
)
def test_constructor_and_lookup_overrides_do_not_establish_new_handle_root(
    tmp_path, override
):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n"
        + textwrap.indent(override, "    ")
        + "\n    def handle(self, *args, **options): return prepare()\n"
    )
    _, definitions = _command(tmp_path, source)
    # Unknown dispatch is not proof that Django reaches this particular body.
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


def test_inherited_constructor_override_also_declines_new_handle_root(tmp_path):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Parent(BaseCommand):\n    def __new__(cls): return object()\nclass Command(Parent):\n    def handle(self, *args, **options): return prepare()\n"
    )
    _, definitions = _command(tmp_path, source)
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


def test_uncalled_command_method_does_not_root_its_helper(tmp_path):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return 0\n    def unused(self): return prepare()\n"
    )
    unused, definitions = _command(tmp_path, source)
    assert f"{_MODULE}.prepare" in unused
    assert not definitions[f"{_MODULE}.Command.unused"].heuristic_refs.get(_ROOT_REASON)


def test_true_dead_analysis_island_stays_reported_beside_a_real_command(tmp_path):
    source = (
        _PROVIDER
        + "class GameDiscontinuityAnalyzer:\n    pass\ndef analyze_games_queryset(): return GameDiscontinuityAnalyzer()\nclass Command(BaseCommand):\n    def handle(self, *args, **options): return 0\n"
    )
    unused, _ = _command(tmp_path, source)
    assert {
        f"{_MODULE}.analyze_games_queryset",
        f"{_MODULE}.GameDiscontinuityAnalyzer",
    } <= unused


@pytest.mark.parametrize(
    "tail",
    [
        "namespace = globals()\nnamespace['Command'] = object\n",
        "globals()['Command'] = object\n",
        "import sys\nsys.modules[__name__].Command = object\n",
        "import sys\nnamespace = vars(sys.modules[__name__])\nnamespace['Command'] = object\n",
    ],
    ids=["globals-alias", "globals-direct", "module-object", "module-vars"],
)
def test_module_namespace_replacement_cannot_root_old_command(tmp_path, tail):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + tail
    )
    unused, definitions = _command(tmp_path, source)
    assert f"{_MODULE}.prepare" in unused
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)


def test_export_module_namespace_is_checked_for_an_imported_command(tmp_path):
    parent = (
        _PROVIDER
        + _HELPERS
        + "class Actual(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
    )
    source = (
        "from parent import Actual\nCommand = Actual\nglobals()['Command'] = object\n"
    )
    unused, definitions = _command(tmp_path, source, {"parent.py": parent})
    assert "parent.prepare" in unused
    assert not definitions["parent.Actual.handle"].heuristic_refs.get(_ROOT_REASON)


def test_source_ancestor_namespace_cannot_establish_a_new_handle_root(tmp_path):
    parent = (
        _PROVIDER
        + _HELPERS
        + "class Parent(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "globals()['prepare'] = object\n"
    )
    source = "from parent import Parent\nclass Command(Parent):\n    pass\n"
    _, definitions = _command(tmp_path, source, {"parent.py": parent})
    assert not definitions["parent.Parent.handle"].heuristic_refs.get(_ROOT_REASON)


def test_direct_readonly_module_metadata_keeps_command_proof(tmp_path):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "module_name = globals().get('__name__')\n"
    )
    unused, definitions = _command(tmp_path, source)
    assert f"{_MODULE}.prepare" not in unused
    assert (
        definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON) == 1.0
    )


@pytest.mark.parametrize(
    "tail, replaced",
    [
        ("Command.handle.__code__ = replacement.__code__\n", True),
        ("selected = Command.handle\nselected.__code__ = replacement.__code__\n", True),
        ("selected = Command.handle\nmethod_name = selected.__code__.co_name\n", False),
    ],
    ids=["replaced-code", "aliased-replaced-code", "readonly-code-metadata"],
)
def test_command_helpers_require_the_original_handle_body(tmp_path, tail, replaced):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "def replacement(self, *args, **options): return None\n"
        + tail
    )
    unused, definitions = _command(tmp_path, source)
    if not replaced:
        assert f"{_MODULE}.prepare" not in unused
    # Function-object uncertainty already retained helpers on original main.
    # Mutation cannot additionally prove entry into this particular body.
    assert (
        bool(definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON))
        is not replaced
    )


def test_escaped_handle_alias_does_not_supply_a_stable_body(tmp_path):
    source = (
        _PROVIDER
        + _HELPERS
        + "class Command(BaseCommand):\n    def handle(self, *args, **options): return prepare()\n"
        + "from external_plugin import install\nselected = Command.handle\ninstall(selected)\n"
    )
    _, definitions = _command(tmp_path, source)
    assert not definitions[f"{_MODULE}.Command.handle"].heuristic_refs.get(_ROOT_REASON)
