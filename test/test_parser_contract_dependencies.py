"""Native parser dependency fixtures are attested statically, never executed."""

import ast

import pytest

from skylos.security.parser_contracts import (
    native_environment_reader_is_intact,
    native_parser_producer_is_intact,
)
from test.fixture_paths import write_fixture


def _native(tmp_path, qualified, source="", patch=None):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="fixture"\n')
    if patch is not None:
        source = "import patcher\n" + source
        write_fixture(tmp_path, "patcher.py", patch)
    path = write_fixture(tmp_path, "app.py", source)
    return native_parser_producer_is_intact(
        qualified, ast.parse(source, filename=str(path)), path, tmp_path
    )


@pytest.mark.parametrize(
    "qualified",
    [
        "argparse.ArgumentParser",
        "os.getenv",
        "os.environ.get",
        "builtins.float",
        "argparse.ArgumentTypeError",
        "math.isfinite",
    ],
)
def test_native_producer_dependencies_are_intact(tmp_path, qualified):
    assert _native(tmp_path, qualified)


@pytest.mark.parametrize(
    "patch",
    [
        "import os,foreign\nos.environ=foreign.mapping",
        "import os,foreign\nos._Environ.__getitem__=foreign.read",
        "import collections.abc,foreign\ncollections.abc.Mapping.get=foreign.read",
        "import os,foreign\nforeign.consume(os.environ)",
    ],
)
def test_environment_wrapper_depends_on_mapping_identity(tmp_path, patch):
    assert not _native(tmp_path, "os.getenv", patch=patch)


@pytest.mark.parametrize(
    "patch",
    [
        "import argparse,foreign\nargparse._StoreAction.__call__=foreign.inject",
        "from argparse import _StoreAction as Action\nimport foreign\nAction.__call__=foreign.inject",
        "import argparse,foreign\nargparse._ActionsContainer.add_argument=foreign.inject",
        "import argparse,foreign\nargparse.Namespace.__getattribute__=foreign.read",
        "import argparse,foreign\nargparse._AttributeHolder.__getattribute__=foreign.read",
        "import argparse,foreign\nargparse.ArgumentParser.parse_args=foreign.parse",
        "import argparse,foreign\nforeign.consume(argparse._StoreAction)",
        "import builtins,foreign\nbuiltins.setattr=foreign.inject",
        "import sys,foreign\nsys.argv=foreign.values",
        "import re,foreign\nre._compiler.compile=foreign.compile",
        "import re,foreign\ncompiler=re._compiler\ncompiler.compile=foreign.compile",
    ],
)
def test_parser_wrapper_depends_on_default_action_and_storage(tmp_path, patch):
    assert not _native(tmp_path, "argparse.ArgumentParser", patch=patch)


def test_unknown_producer_has_no_native_contract(tmp_path):
    assert not _native(tmp_path, "foreign.ArgumentParser")


def test_unrelated_local_alias_rebinding_does_not_mutate_action_provider(tmp_path):
    assert _native(
        tmp_path,
        "argparse.ArgumentParser",
        patch="from argparse import _StoreAction as Local\nimport foreign\nLocal=foreign.Action",
    )


@pytest.mark.parametrize(
    "expression",
    ["os.environ['FETCH_URL']", "env['FETCH_URL']", "os.environ.get('FETCH_URL')"],
)
def test_literal_environment_text_is_not_whole_mapping_escape(tmp_path, expression):
    assert _native(
        tmp_path,
        "os.getenv",
        "import os, requests\nfrom os import environ as env\n"
        "requests.get(" + expression + ")\n",
    )


@pytest.mark.parametrize(
    "expression", ["os.environ", "os.environ[key]", "os.environ.get('KEY', os.environ)"]
)
def test_mapping_escape_or_dynamic_protocol_read_is_not_text_projection(
    tmp_path, expression
):
    assert not _native(
        tmp_path,
        "os.getenv",
        "import os,foreign\nforeign.consume(" + expression + ")\n",
    )


def test_environment_text_projection_does_not_hide_imported_custom_getter(tmp_path):
    assert not _native(
        tmp_path,
        "os.getenv",
        "import os, requests\nrequests.get(os.environ['FETCH_URL'])\n",
        patch="import os,foreign\nos._Environ.__getitem__=foreign.read",
    )


def test_environment_reader_api_is_independent_of_parser_mutations(tmp_path):
    source = (
        "import os, argparse, foreign\nargparse._StoreAction.__call__=foreign.inject\n"
    )
    path = write_fixture(tmp_path, "app.py", source)
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="fixture"\n')
    assert native_environment_reader_is_intact(
        ast.parse(source, filename=str(path)), path, tmp_path
    )
