"""L027 rejects proven declaration syntax and retains actual repeated values."""

import ast
import json
import textwrap

import pytest

from test.fixture_paths import write_fixture

from skylos.audit.redaction import REDACTION
from skylos.rules.quality.logic_maintainability import (
    BooleanTrapRule,
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
)


def findings(source):
    return (
        DuplicateStringLiteralRule().visit_node(
            ast.parse(textwrap.dedent(source)), {"filename": "app.py"}
        )
        or []
    )


@pytest.mark.parametrize(
    "method", ["add_argument", "addoption", "_addoption", "add_base_argument"]
)
@pytest.mark.parametrize(
    "action", ["store_true", "store_false", "store_const", "append", "count", "extend"]
)
def test_standard_parser_action_tokens_are_not_magic_strings(method, action):
    source = "\n".join(
        f"parser.{method}('--{flag}', action={action!r})"
        for flag in ("one", "two", "three")
    )
    assert findings(source) == []


def test_parser_wrappers_with_explicit_destinations_share_the_contract():
    source = "\n".join(
        f"group.add_argument(dest={flag!r}, action='store_true')"
        for flag in ("one", "two", "three")
    )
    assert findings(source) == []


def test_repeated_destinations_stay_until_parser_contract_is_proved():
    source = "\n".join(
        f"parser.add_argument('--{flag}', dest='request_type')"
        for flag in ("json", "form", "multipart")
    )
    assert findings(source)[0]["value"] == 3


@pytest.mark.parametrize(
    "expression",
    [
        "consume('--flag', dest='Repeated application value')",
        "parser.add_argument('--flag', default='Repeated application value')",
    ],
)
def test_cli_destination_proof_does_not_exclude_other_roles(expression):
    assert findings("\n".join([expression] * 3))[0]["value"] == 3


def test_cli_destinations_do_not_hide_ordinary_repeated_values_in_other_functions():
    source = (
        "\n".join(
            f"parser.add_argument('--{flag}', dest='request_type')"
            for flag in ("json", "form", "multipart")
        )
        + "\n"
        + "\n".join(
            f"def runtime_{index}(): return consume('request_type')"
            for index in range(3)
        )
    )
    (finding,) = findings(source)
    assert finding["value"] == 6


@pytest.mark.parametrize("method", ["add_argument", "addoption", "option"])
@pytest.mark.parametrize("form", ["local_function", "local_method", "unknown_method"])
def test_destination_values_on_same_named_custom_apis_remain(method, form):
    if form == "local_function":
        prefix = f"def {method}(value, *, dest): return value + dest\n"
        receiver = method
    elif form == "local_method":
        prefix = f"class Collector:\n    def {method}(self, value, *, dest): return value + dest\napi = Collector()\n"
        receiver = f"api.{method}"
    else:
        prefix = ""
        receiver = f"unknown_api.{method}"
    source = prefix + "\n".join(
        f"def call_{index}(): return {receiver}('--flag{index}', dest='application_value')"
        for index in range(3)
    )
    (finding,) = findings(source)
    assert finding["name"] == "application_value"
    assert finding["value"] == 3


@pytest.mark.parametrize(
    "prefix, marker",
    [
        ("from typing import overload", "overload"),
        ("import typing as hints", "hints.overload"),
        ("from typing_extensions import overload as overloaded", "overloaded"),
    ],
)
def test_overload_defaults_matching_one_concrete_callable_are_counted_once(
    prefix, marker
):
    source = (
        prefix
        + f"\n@{marker}\ndef render(value: int, theme='shared template'): ...\n@{marker}\ndef render(value: str, theme='shared template'): ...\ndef render(value, theme='shared template'):\n    return theme\n"
    )
    assert findings(source) == []


def test_overload_collapse_retains_actual_runtime_repetition_across_callables():
    source = "from typing import overload\n@overload\ndef first(value:int, theme='shared template'): ...\n@overload\ndef first(value:str, theme='shared template'): ...\ndef first(value, theme='shared template'):\n    return theme\ndef second(theme='shared template'):\n    return theme\ndef third(theme='shared template'):\n    return theme\n"
    (finding,) = findings(source)
    assert finding["value"] == 3


@pytest.mark.parametrize(
    "prefix, marker, implementation",
    [
        (
            "def overload(fn): return fn",
            "overload",
            "def render(value, theme='shared template'):\n    return theme\n",
        ),
        (
            "from typing import overload\noverload=custom",
            "overload",
            "def render(value, theme='shared template'):\n    return theme\n",
        ),
        ("from typing import overload", "overload", ""),
    ],
)
def test_unknown_or_incomplete_overload_contracts_remain_eligible(
    prefix, marker, implementation
):
    source = (
        prefix
        + f"\n@{marker}\ndef render(value:int, theme='shared template'): ...\n@{marker}\ndef render(value:str, theme='shared template'): ...\n@{marker}\ndef render(value:bytes, theme='shared template'): ...\n"
        + implementation
    )
    assert findings(source)[0]["value"] >= 3


def test_overload_defaults_for_other_parameters_are_not_removed():
    source = "from typing import overload\n@overload\ndef render(value:int, first='shared template', second='shared template'): ...\n@overload\ndef render(value:str, first='shared template', second='shared template'): ...\ndef render(value, **kwargs):\n    return value\n"
    assert findings(source)[0]["value"] == 4


def test_project_local_typing_provider_cannot_authorize_default_collapse(tmp_path):
    (tmp_path / "typing.py").write_text("def overload(fn): return fn\n")
    source = "from typing import overload\n@overload\ndef render(value:int, theme='shared template'): ...\n@overload\ndef render(value:str, theme='shared template'): ...\ndef render(value, theme='shared template'):\n    return theme\n"
    filename = tmp_path / "app.py"
    filename.write_text(source)
    (finding,) = DuplicateStringLiteralRule().visit_node(
        ast.parse(source), {"filename": str(filename), "project_root": str(tmp_path)}
    )
    assert finding["value"] == 3


@pytest.mark.parametrize(
    "expression",
    [
        "consume('--flag', action='store_true')",
        "parser.add_argument('--flag', action='custom_action')",
        "parser.add_argument(action='store_true')",
        "consume('store_true')",
        "parser.add_argument('--flag', default='store_true')",
    ],
)
def test_unknown_calls_actions_defaults_and_incomplete_declarations_remain(expression):
    result = findings("\n".join([expression] * 3))
    relevant = [row for row in result if row["name"] != "--flag"]
    assert len(relevant) == 1
    assert relevant[0]["value"] == 3


def test_excluding_action_slots_does_not_exclude_ordinary_uses_of_the_same_value():
    result = findings("""
        parser.add_argument('--one', action='store_true')
        parser.add_argument('--two', action='store_true')
        parser.add_argument('--three', action='store_true')
        def first(): return consume('store_true')
        def second(): return consume('store_true')
        def third(): return consume('store_true')
    """)
    assert len(result) == 1
    assert result[0]["value"] == 3
    assert result[0]["literal_context"]["distinct_function_count"] == 3


@pytest.mark.parametrize("keyword", ["help", "short_help", "help_group", "metavar"])
def test_cli_documentation_slots_are_metadata_not_logic(keyword):
    source = "\n".join(
        f"@click.option('--{flag}', {keyword}='Timeout in seconds waiting for reply.')"
        f"\ndef {flag}(): pass"
        for flag in ("one", "two", "three")
    )
    assert findings(source) == []


def test_repeated_actual_errors_remain_even_when_cli_metadata_matches():
    result = findings("""
        @click.option('--one', help='Not connected to broker. Please retry...')
        def one():
            raise RuntimeError('Not connected to broker. Please retry...')
        def two():
            raise RuntimeError('Not connected to broker. Please retry...')
        def three():
            raise RuntimeError('Not connected to broker. Please retry...')
    """)
    assert len(result) == 1
    assert result[0]["value"] == 3
    assert result[0]["name"] == "Not connected to broker. Please retry..."


@pytest.mark.parametrize(
    "collection", ["{'task_identifier'}", "['task_identifier']", "('task_identifier',)"]
)
def test_constructor_wrapped_declaration_collections_are_declarative(collection):
    source = "from celery.utils.dispatch import Signal\n" + "\n".join(
        f"{name} = Signal(providing_args={collection})"
        for name in ("before", "after", "failed")
    )
    assert findings(source) == []


@pytest.mark.parametrize(
    "provider",
    ["celery.utils.dispatch", "celery.utils.dispatch.signal", "django.dispatch"],
)
def test_signal_field_contract_requires_the_resolved_provider(provider):
    source = f"from {provider} import Signal\n" + "\n".join(
        f"event_{index} = Signal(providing_args={{'task_identifier'}})"
        for index in range(3)
    )
    assert findings(source) == []
    unknown = source.replace(f"from {provider} import Signal\n", "")
    assert findings(unknown)[0]["value"] == 3


@pytest.mark.parametrize(
    "prefix, expression",
    [
        ("", "send_all(['Repeated application error'])"),
        (
            "def send_all(messages):\n    for message in messages:\n        send(message)\n",
            "send_all(['Repeated application error'])",
        ),
        ("", "some.Structure(some_mapping={'key': 'Repeated application error'})"),
        (
            "from types import MappingProxyType\n",
            "consume(MappingProxyType({'key': 'Repeated application error'}))",
        ),
        (
            "from collections import OrderedDict\n",
            "OrderedDict([('key', consume('Repeated application error'))])",
        ),
    ],
)
def test_unknown_or_procedural_collection_wrappers_retain_real_repeated_data(
    prefix, expression
):
    source = prefix + "\n".join(
        f"delivery_{index} = {expression}" for index in range(3)
    )
    relevant = [
        row for row in findings(source) if row["name"] == "Repeated application error"
    ]
    assert len(relevant) == 1
    assert relevant[0]["value"] == 3


@pytest.mark.parametrize(
    "prefix, expression",
    [
        (
            "from types import MappingProxyType\n",
            "MappingProxyType({'key': 'task_identifier'})",
        ),
        (
            "from collections import OrderedDict\n",
            "OrderedDict([('key', 'task_identifier')])",
        ),
        ("import collections as coll\n", "coll.deque(['task_identifier'])"),
        ("import builtins as core\n", "core.frozenset(['task_identifier'])"),
    ],
)
def test_import_proven_collection_wrappers_keep_catalog_role(prefix, expression):
    source = prefix + "\n".join(f"catalog_{index} = {expression}" for index in range(3))
    assert findings(source) == []


def test_local_collections_and_non_collection_constructor_values_remain():
    assert (
        findings("""
        def run():
            first = Signal(providing_args={'task_identifier'})
            second = Signal(providing_args={'task_identifier'})
            third = Signal(providing_args={'task_identifier'})
    """)[0]["value"]
        == 3
    )
    assert (
        findings("""
        first = factory('task_identifier')
        second = factory('task_identifier')
        third = factory('task_identifier')
    """)[0]["value"]
        == 3
    )


@pytest.mark.parametrize(
    "provider",
    [
        "from operator import itemgetter as selector",
        "from operator import attrgetter as selector",
        "import operator as operations\nselector = operations.itemgetter",
    ],
)
def test_only_resolved_operator_selector_imports_are_contracts(provider):
    # Assigning aliases is deliberately not import proof. The first two cases
    # are proven imports; the last case remains an ordinary unknown callable.
    result = findings(
        provider + "\n" + "\n".join(["consume(selector('hostname'))"] * 3)
    )
    assert bool(result) is ("selector =" in provider)


def test_operator_module_aliases_and_multiple_field_positions_are_supported():
    assert (
        findings("""
        import operator as op
        first = op.itemgetter('hostname', 'task_identifier')
        second = op.itemgetter('hostname', 'task_identifier')
        third = op.itemgetter('hostname', 'task_identifier')
    """)
        == []
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "from somewhere import itemgetter",
        "def itemgetter(value): return value",
        "from operator import itemgetter\nitemgetter = custom_selector",
        "from operator import itemgetter\ndef run(itemgetter):\n    pass",
    ],
)
def test_unknown_or_rebound_selector_functions_stay_visible(prefix):
    result = findings(
        prefix + "\n" + "\n".join(["consume(itemgetter('hostname'))"] * 3)
    )
    # A shadowing parameter in a different scope must not invalidate a valid
    # module import. Actual rebinding or an unknown provider invalidates it.
    assert bool(result) is not ("def run(itemgetter)" in prefix)


@pytest.mark.parametrize(
    "provider", ["gettext", "django.utils.translation", "flask_babel"]
)
def test_imported_localization_msgids_stay_literal_for_catalog_extraction(provider):
    source = f"from {provider} import gettext as _\n" + "\n".join(
        ["consume(_('Enter a valid value.'))"] * 3
    )
    assert findings(source) == []


def test_localization_context_plural_positions_are_not_arbitrary_arguments():
    assert (
        findings("""
        import gettext as catalog
        catalog.npgettext('noun', 'One useful object', 'Many useful objects', count)
        catalog.npgettext('noun', 'One useful object', 'Many useful objects', count)
        catalog.npgettext('noun', 'One useful object', 'Many useful objects', count)
    """)
        == []
    )
    result = findings("""
        from gettext import pgettext
        pgettext('Repeated context', 'First unique message')
        pgettext('Repeated context', 'Second unique message')
        pgettext('Repeated context', 'Third unique message')
    """)
    assert result[0]["name"] == "Repeated context"


@pytest.mark.parametrize(
    "prefix",
    [
        "def _(message): return message",
        "from gettext import gettext as _\n_ = consume",
        "from gettext import gettext as _\ndef run(_):\n    consume(_('A repeated error message.'))\n    consume(_('A repeated error message.'))\n    consume(_('A repeated error message.'))",
    ],
)
def test_unknown_or_shadowed_translation_calls_are_not_assumed_to_be_gettext(prefix):
    source = prefix
    if "def run" not in source:
        source += "\n" + "\n".join(["consume(_('A repeated error message.'))"] * 3)
    assert findings(source)[0]["value"] == 3


def test_uniform_class_field_catalog_does_not_imply_shared_runtime_value():
    assert (
        findings("""
        class First: name = 'external_dialect'
        class Second: name = 'external_dialect'
        class Third: name = 'external_dialect'
    """)
        == []
    )


def test_declared_name_plus_repeated_defaults_keeps_the_consistency_finding():
    result = findings("""
        class ColumnSplitter: name = 'column'
        def split(kind='column'): pass
        def split_column(): return split(kind='column')
    """)
    assert result[0]["name"] == "column"
    assert result[0]["value"] == 3


@pytest.mark.parametrize(
    "source",
    [
        "class First: name = 'shared_value'\nclass Second: title = 'shared_value'\nclass Third: label = 'shared_value'",
        "class First:\n    name = 'shared_value'\n    name = 'shared_value'\n    name = 'shared_value'",
    ],
)
def test_different_class_fields_and_reassigned_fields_remain(source):
    assert findings(source)[0]["value"] == 3


def test_private_attributes_settings_and_dynamic_dispatch_values_remain():
    result = findings("""
        def one(value, settings):
            getattr(value, '__pending__', None)
            settings.getfloat('UPLOAD_TIMEOUT')
            dispatch('response')
        def two(value, settings):
            setattr(value, '__pending__', None)
            settings.getfloat('UPLOAD_TIMEOUT')
            dispatch('response')
        def three(value, settings):
            hasattr(value, '__pending__')
            settings.getfloat('UPLOAD_TIMEOUT')
            dispatch('response')
    """)
    assert {row["name"] for row in result} == {
        "__pending__",
        "UPLOAD_TIMEOUT",
        "response",
    }


def test_secret_redaction_survives_context_classification():
    result = findings("\n".join(["consume('AbCdEf1234_5678.XyZ9012-abcdefgh')"] * 3))
    assert result[0]["name"] == REDACTION
    assert "AbCdEf" not in json.dumps(result)


@pytest.mark.parametrize("constructor", ["Column", "Table", "column", "table"])
def test_imported_schema_declaration_names_are_structural_keys(constructor):
    assert (
        findings(
            f"from sqlalchemy import {constructor} as declare\n"
            + "\n".join(["declare('external_field_name', datatype)"] * 3)
        )
        == []
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "from application import Column",
        "def Column(value, datatype): return value",
        "from sqlalchemy import Column\nColumn = custom",
    ],
)
def test_unknown_same_named_constructors_and_rebindings_remain(prefix):
    assert (
        findings(
            prefix + "\n" + "\n".join(["Column('external_field_name', datatype)"] * 3)
        )[0]["value"]
        == 3
    )


def test_query_bindings_and_non_name_schema_arguments_remain():
    result = findings("""
        from sqlalchemy import Column, bindparam
        Column('unique_one', datatype, comment='A repeated actual value')
        Column('unique_two', datatype, comment='A repeated actual value')
        Column('unique_three', datatype, comment='A repeated actual value')
        bindparam('external_field_name')
        bindparam('external_field_name')
        bindparam('external_field_name')
    """)
    assert {row["name"] for row in result} == {
        "A repeated actual value",
        "external_field_name",
    }


def test_sqlalchemy_cast_string_is_sql_data_not_a_typing_type_expression():
    result = findings("""
        from sqlalchemy import cast
        cast('A_SQL_LITERAL', String)
        cast('A_SQL_LITERAL', String)
        cast('A_SQL_LITERAL', String)
    """)
    assert result[0]["name"] == "A_SQL_LITERAL"
    assert result[0]["value"] == 3
    assert (
        findings("""
        from typing import cast
        cast('A_SQL_LITERAL', value)
        cast('A_SQL_LITERAL', value)
        cast('A_SQL_LITERAL', value)
    """)
        == []
    )


def test_matching_api_member_names_do_not_substitute_for_provider_identity():
    # Source can reference arbitrary exports; never assume a contract merely
    # because a known package happens to export an identically named callable.
    for provider, member, expression in [
        ("sqlalchemy", "gettext", "gettext('Repeated application data')"),
        ("gettext", "Column", "Column('Repeated application data')"),
        ("collections", "attrgetter", "attrgetter('Repeated application data')"),
    ]:
        result = findings(
            f"from {provider} import {member}\n" + "\n".join([expression] * 3)
        )
        assert result[0]["value"] == 3


@pytest.mark.parametrize(
    "provider, member",
    [("gettext", "gettext"), ("operator", "attrgetter"), ("sqlalchemy", "Column")],
)
@pytest.mark.parametrize("layout", ["root", "src", "source_directory"])
@pytest.mark.parametrize("package", [False, True])
def test_local_modules_cannot_prove_external_literal_contracts(
    tmp_path, provider, member, layout, package
):
    source_dir = tmp_path / "app"
    source_dir.mkdir()
    provider_dir = {
        "root": tmp_path,
        "src": tmp_path / "src",
        "source_directory": source_dir,
    }[layout]
    provider_dir.mkdir(exist_ok=True)
    if package:
        local = provider_dir / provider
        local.mkdir()
        local = local / "__init__.py"
    else:
        local = provider_dir / f"{provider}.py"
    write_fixture(tmp_path, local.relative_to(tmp_path),
                  f"def {member}(value):\n    return transform(value)\n")
    source = f"from {provider} import {member}\n" + "\n".join(
        f"def handler_{index}(): return {member}('Repeated application error')"
        for index in range(3)
    )
    filename = source_dir / "client.py"
    filename.write_text(source)
    (finding,) = DuplicateStringLiteralRule().visit_node(
        ast.parse(source),
        {"filename": str(filename), "project_root": str(tmp_path)},
    )
    assert finding["name"] == "Repeated application error"
    assert finding["value"] == 3


def test_external_contract_still_holds_with_safe_project_context(tmp_path):
    source = "from gettext import gettext\n" + "\n".join(
        f"def handler_{index}(): return gettext('Repeated application error')"
        for index in range(3)
    )
    filename = tmp_path / "client.py"
    filename.write_text(source)
    assert not DuplicateStringLiteralRule().visit_node(
        ast.parse(source),
        {"filename": str(filename), "project_root": str(tmp_path)},
    )


def test_custom_membership_on_a_dict_subclass_is_not_a_mapping_key_contract():
    source = """
        class Predicate(dict):
            def __contains__(self, value):
                return send_to_backend(value)
        def run():
            predicate = Predicate()
            first = 'Repeated application error' in predicate
            second = 'Repeated application error' in predicate
            third = 'Repeated application error' in predicate
            return first, second, third
    """
    (finding,) = findings(source)
    assert finding["value"] == 3


def test_relative_schema_imports_resolve_only_from_regular_package_markers(tmp_path):
    package = tmp_path / "sqlalchemy"
    nested = package / "dialects" / "dialect_impl"
    nested.mkdir(parents=True)
    for directory in [package, package / "dialects", nested]:
        (directory / "__init__.py").write_text("")
    source = "from ... import Column\n" + "\n".join(
        ["Column('external_field_name', datatype)"] * 3
    )
    assert (
        DuplicateStringLiteralRule().visit_node(
            ast.parse(source),
            {"filename": str(nested / "schema.py"), "project_root": str(tmp_path)},
        )
        is None
    )
    # No marker: do not assume a coincidentally named namespace is sqlalchemy.
    (package / "__init__.py").unlink()
    assert (
        len(
            DuplicateStringLiteralRule().visit_node(
                ast.parse(source),
                {"filename": str(nested / "schema.py"), "project_root": str(tmp_path)},
            )
        )
        == 1
    )


def test_dict_key_identity_is_indexed_instead_of_rescanning_sibling_keys():
    class IndexedKeys(list):
        def __contains__(self, value):
            raise AssertionError("L027 must not linearly rescan every dict key")

    tree = ast.parse(
        "def run():\n    data = {'one': 'repeated_value', 'two': 'repeated_value', 'three': 'repeated_value'}"
    )
    dictionary = next(node for node in ast.walk(tree) if isinstance(node, ast.Dict))
    dictionary.keys = IndexedKeys(dictionary.keys)
    result = DuplicateStringLiteralRule().visit_node(tree, {"filename": "app.py"})
    assert result[0]["name"] == "repeated_value"
    assert result[0]["value"] == 3


def test_returns_in_match_cases_are_counted_in_the_owning_function():
    tree = ast.parse("""
def classify(value):
    match value:
        case 1: return 'one'
        case 2: return 'two'
        case 3: return 'three'
        case 4: return 'four'
        case 5: return 'five'
        case _: return 'other'
""")
    result = TooManyReturnsRule().visit_node(tree.body[0], {"filename": "app.py"})
    assert result[0]["value"] == 6


def test_match_count_respects_nested_scope_and_all_existing_control_flow():
    tree = ast.parse("""
def classify(value):
    match value:
        case 1:
            def nested(): return 'nested'
            class Inner:
                def run(self): return 'method'
            callback = lambda: 'value'
            if value: return 'outer'
        case _:
            try:
                if value: return 'guard'
            except ValueError:
                return 'error'
            else:
                return 'success'
            finally:
                if value: return 'cleanup'
    return 'fallback'
""")
    result = TooManyReturnsRule().visit_node(tree.body[0], {"filename": "app.py"})
    assert result[0]["value"] == 6


def test_nested_match_returns_do_not_change_the_enclosing_function_metric():
    tree = ast.parse("""
def outer():
    def inner(value):
        match value:
            case 1: return 'one'
            case 2: return 'two'
            case 3: return 'three'
            case 4: return 'four'
            case 5: return 'five'
            case _: return 'other'
    return inner
""")
    assert TooManyReturnsRule().visit_node(tree.body[0], {"filename": "app.py"}) is None


@pytest.mark.parametrize(
    "constructor", ["dict()", "{key: value for key, value in pairs}"]
)
def test_proven_mapping_constructor_and_comprehension_keys_are_structural(constructor):
    assert (
        findings(
            f"def run(pairs):\n    values = {constructor}\n"
            "    values.get('external_field')\n"
            "    values.setdefault('external_field', None)\n"
            "    values.pop('external_field', None)\n"
        )
        == []
    )


@pytest.mark.parametrize(
    "prefix,constructor",
    [
        ("import builtins as runtime", "runtime.dict()"),
        ("from collections import defaultdict as factory", "factory(list)"),
        ("from collections import OrderedDict as factory", "factory()"),
        ("from collections import UserDict as factory", "factory()"),
        ("class Fields(dict): pass", "Fields()"),
        ("class Fields(dict): pass\nclass Child(Fields): pass", "Child()"),
    ],
)
def test_resolved_standard_mapping_and_local_subclass_constructors(prefix, constructor):
    assert (
        findings(
            prefix
            + f"\ndef run():\n    values = {constructor}\n"
            + "    values.get('external_field')\n" * 3
        )
        == []
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "def dict(): return custom",
        "dict = custom_factory",
        "class Fields(dict):\n    def get(self, value): return value\ndict = Fields",
        "__builtins__['dict'] = custom_factory",
        "globals()['dict'] = custom_factory",
    ],
)
def test_shadowed_or_mutated_mapping_factories_cannot_hide_findings(prefix):
    assert (
        findings(
            prefix
            + "\ndef run():\n    values = dict()\n"
            + "    values.get('external_field')\n" * 3
        )[0]["value"]
        == 3
    )


@pytest.mark.parametrize(
    "body",
    [
        "def get(self, value): return value",
        "get = custom_get",
        "def __new__(cls): return custom",
        "def __getattribute__(self, name): return custom",
    ],
)
def test_custom_mapping_method_dispatch_remains_unknown(body):
    assert (
        findings(
            "class Fields(dict):\n    "
            + body
            + "\ndef run():\n    values = Fields()\n"
            + "    values.get('external_field')\n" * 3
        )[0]["value"]
        == 3
    )


@pytest.mark.parametrize(
    "body, setup",
    [
        ("def __init__(self): self.get = custom_get", ""),
        ("def configure(self): self.get = custom_get", "    values.configure()\n"),
        (
            "def configure(self): setattr(self, 'get', custom_get)",
            "    values.configure()\n",
        ),
    ],
)
def test_behavioral_mapping_subclasses_cannot_prove_unchanged_lookup(body, setup):
    source = (
        "class Fields(dict):\n    "
        + body
        + "\ndef run():\n    values = Fields()\n"
        + setup
        + "    values.get('Repeated application error')\n" * 3
    )
    assert findings(source)[0]["value"] == 3


@pytest.mark.parametrize(
    "mutation",
    [
        "UserDict.get = custom_get",
        "mutate(UserDict)",
        "alias = UserDict\nalias.get = custom_get",
        "UserDict.__dict__['get'] = custom_get",
        "registry = {'kind': UserDict}\nregistry['kind'].get = custom_get",
        "registry = [UserDict]\nregistry[0].get = custom_get",
    ],
)
def test_mutated_or_escaped_imported_mapping_classes_do_not_prove_lookup(mutation):
    source = (
        "from collections import UserDict\n"
        + mutation
        + "\ndef run():\n    values = UserDict()\n"
        + "    values.get('Repeated application error')\n" * 3
    )
    assert findings(source)[0]["value"] == 3


def test_unrelated_imported_exports_do_not_invalidate_an_unchanged_schema_call():
    source = "from sqlalchemy import Column, Integer\n" + "\n".join(
        ["Column('external_field_name', Integer)"] * 3
    )
    assert findings(source) == []


def test_mutating_one_import_alias_invalidates_its_other_provider_aliases():
    source = """
        from collections import UserDict
        import collections as mappings
        UserDict.get = custom_get
        def run():
            values = mappings.UserDict()
            values.get('Repeated application error')
            values.get('Repeated application error')
            values.get('Repeated application error')
    """
    assert findings(source)[0]["value"] == 3


@pytest.mark.parametrize(
    "mutation",
    [
        "Fields.get = custom_get",
        "mutate(Fields)",
        "alias = Fields\nalias.get = custom_get",
        "registry = {'kind': Fields}",
    ],
)
def test_escaped_or_monkeypatched_local_mapping_classes_are_not_identity_proof(
    mutation,
):
    assert (
        findings(
            "class Fields(dict): pass\n"
            + mutation
            + "\ndef run():\n    values = Fields()\n"
            + "    values.get('external_field')\n" * 3
        )[0]["value"]
        == 3
    )


def test_instance_method_rebinding_invalidates_local_mapping_proof():
    assert (
        findings("""
        class Fields(dict): pass
        def run():
            values = Fields()
            values.get = custom_get
            values.get('external_field')
            values.get('external_field')
            values.get('external_field')
    """)[0]["value"]
        == 3
    )


def test_subclass_initialization_hooks_can_replace_the_mapping_contract():
    assert (
        findings("""
        class Base(dict):
            def __init_subclass__(cls): cls.get = custom_get
        class Child(Base): pass
        def run():
            values = Child()
            values.get('external_field')
            values.get('external_field')
            values.get('external_field')
    """)[0]["value"]
        == 3
    )


def test_unknown_reassignment_still_invalidates_mapping_proof():
    assert (
        findings("""
        def run():
            values = dict()
            values = custom_api()
            values.get('external_field')
            values.get('external_field')
            values.get('external_field')
    """)[0]["value"]
        == 3
    )


def test_mapping_membership_has_the_same_key_semantics_as_subscripts():
    assert (
        findings("""
        def run(**fields):
            if 'external_field' in fields: consume(fields)
            if 'external_field' not in fields: consume(fields)
            if 'external_field' in fields: consume(fields)
    """)
        == []
    )
    assert (
        findings("""
        def run(protocol):
            if protocol == 'external_field': consume(protocol)
            if protocol != 'external_field': consume(protocol)
            if 'external_field' in protocol: consume(protocol)
    """)[0]["value"]
        == 3
    )


def test_public_reflection_names_with_static_attribute_evidence_are_selectors():
    assert (
        findings("""
        def run(value):
            if hasattr(value, 'resolve_expression'): value.resolve_expression()
            if hasattr(value, 'resolve_expression'): value.resolve_expression()
            return getattr(value, 'resolve_expression', None)
    """)
        == []
    )


def test_class_method_declarations_supply_reflection_contract_evidence():
    assert (
        findings("""
        class Renderable:
            def render_output(self): pass
        def run(value):
            hasattr(value, 'render_output')
            hasattr(value, 'render_output')
            getattr(value, 'render_output', None)
    """)
        == []
    )


@pytest.mark.parametrize("name", ["__thing", "__pending__", "_private_field"])
def test_owned_private_names_remain_even_with_direct_attribute_access(name):
    assert (
        findings(
            f"def run(value):\n    value.{name}\n"
            + f"    getattr(value, {name!r}, None)\n" * 3
        )[0]["value"]
        == 3
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "def getattr(value, name, default): return default",
        "from arbitrary_api import getattr",
        "from builtins import getattr\ngetattr = custom_reader",
        "__builtins__['getattr'] = custom_reader",
    ],
)
def test_unknown_or_mutated_reflection_apis_remain_visible(prefix):
    assert (
        findings(
            prefix
            + "\ndef run(value):\n    value.resolve_expression\n"
            + "    getattr(value, 'resolve_expression', None)\n" * 3
        )[0]["value"]
        == 3
    )


def test_reflection_without_a_static_contract_remains_visible():
    assert (
        findings("""
        def run(value):
            hasattr(value, 'unknown_contract')
            hasattr(value, 'unknown_contract')
            getattr(value, 'unknown_contract', None)
    """)[0]["value"]
        == 3
    )


@pytest.mark.parametrize(
    "operation",
    [
        "setattr",
        "delattr",
        "object.__setattr__",
        "object.__getattribute__",
        "object.__delattr__",
    ],
)
def test_builtin_field_operations_use_declared_public_slots(operation):
    arguments = (
        ", True" if operation.endswith("setattr__") or operation == "setattr" else ""
    )
    assert (
        findings(
            "class Record:\n    __slots__ = ('external_field',)\n"
            + "def update(value):\n"
            + f"    {operation}(value, 'external_field'{arguments})\n" * 3
        )
        == []
    )


def test_bound_object_setattr_alias_is_a_public_field_selector():
    assert (
        findings("""
        _SET = object.__setattr__
        class Record:
            __slots__ = ('external_field',)
            def update(self):
                setter = _SET.__get__(self)
                setter('external_field', True)
                _SET.__get__(self)('external_field', True)
                object.__setattr__.__get__(self)('external_field', False)
    """)
        == []
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "object = arbitrary_object\n_SET = object.__setattr__",
        "_SET = object.__setattr__\n_SET = arbitrary_setter",
        "_SET = object.__setattr__\ndef rebind():\n    global _SET\n    _SET = arbitrary_setter",
        "from arbitrary_api import _SET",
        "if condition:\n    _SET = object.__setattr__",
    ],
)
def test_unknown_rebound_or_conditional_bound_setters_keep_values(prefix):
    result = findings(
        prefix
        + "\nclass Record:\n    __slots__ = ('external_field',)\n"
        + "    def update(self):\n        setter = _SET.__get__(self)\n"
        + "        setter('external_field', True)\n" * 3
    )
    assert result[0]["value"] >= 3


@pytest.mark.parametrize("field", ["__thing", "__pending__", "_private_field"])
def test_owned_private_bound_setter_names_still_report(field):
    result = findings(
        "_SET = object.__setattr__\n"
        + f"class Record:\n    __slots__ = ({field!r},)\n"
        + "    def update(self):\n        setter = _SET.__get__(self)\n"
        + f"        setter({field!r}, True)\n" * 3
    )
    assert result[0]["value"] >= 3


def test_declared_field_does_not_suppress_independent_application_values():
    result = findings("""
        class Record:
            __slots__ = ('external_field',)
        def a(value):
            setattr(value, 'external_field', True)
            return consume('external_field')
        def b(): return consume('external_field')
        def c(): return consume('external_field')
    """)
    assert result[0]["value"] >= 3


@pytest.mark.parametrize("parameter", ["setattr", "object", "_SET"])
def test_field_operation_parameters_shadow_builtin_or_module_alias_proof(parameter):
    operation = {
        "setattr": "setattr(value, 'external_field', True)",
        "object": "object.__setattr__(value, 'external_field', True)",
        "_SET": "_SET.__get__(value)('external_field', True)",
    }[parameter]
    result = findings(
        "_SET = object.__setattr__\n"
        + "class Record:\n    __slots__ = ('external_field',)\n"
        + f"def update(value, {parameter}):\n"
        + f"    {operation}\n" * 3
    )
    assert result[0]["value"] >= 3


@pytest.mark.parametrize(
    "expression",
    [
        "'%s.%s' % (module, member)",
        "'%s[%s]' % (module, member)",
        "'{}.{}'.format(module, member)",
        "'{module}.{member}'.format(module=module, member=member)",
    ],
)
def test_punctuation_only_format_skeletons_are_expression_structure(expression):
    assert (
        findings("def run(module, member):\n" + f"    consume({expression})\n" * 3)
        == []
    )


@pytest.mark.parametrize(
    "expression",
    [
        "'Unable to load %s' % member",
        "'Unable to load {}'.format(member)",
        "'[progress.description]{task.description}'.format(task=task)",
        "'%s.%s'",
    ],
)
def test_meaningful_message_templates_and_bare_strings_still_report(expression):
    assert (
        findings("def run(member, task):\n" + f"    consume({expression})\n" * 3)[0][
            "value"
        ]
        == 3
    )


def boolean_findings(source):
    tree = ast.parse(textwrap.dedent(source))
    rule = BooleanTrapRule()
    context = {"filename": "app.py"}
    rule.visit_node(tree, context)
    return [
        finding
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for finding in (rule.visit_node(node, context) or [])
    ]


def test_boolean_trap_retains_real_private_bare_literal_call_evidence():
    result = boolean_findings("""
        def _private(path, enabled=False): return path
        _private('path', True)
    """)
    assert len(result) == 1
    assert result[0]["name"] == "_private.enabled"
    assert "True at line" in result[0]["message"]


def test_boolean_trap_private_named_calls_and_keyword_only_apis_stay_clear():
    assert (
        boolean_findings("""
        def _private(path, enabled=False): return path
        def public(path, *, enabled=False): return path
        _private('path', enabled=True)
        public('path', enabled=True)
    """)
        == []
    )


def test_boolean_trap_public_signature_is_preserved_without_inventing_call_evidence():
    result = boolean_findings("""
        def public(path, enabled=False): return path
        public('path', enabled=True)
    """)
    assert len(result) == 1
    assert "permits positional calls" in result[0]["message"]
    assert "called positionally with" not in result[0]["message"]
