"""Native generic subscriptions retain provider identity and escape tracking."""

import ast

import pytest

from skylos.rules.danger.import_proof import provider_binding_is_stable
from test.fixture_paths import write_fixture


def _stable(tmp_path, source, extra=None):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="fixture"\n')
    for name, text in (extra or {}).items():
        write_fixture(tmp_path, name, text)
    path = write_fixture(tmp_path, "app.py", source)
    return provider_binding_is_stable(
        "pathlib.Path", ast.parse(source, filename=str(path)), path, tmp_path
    )


@pytest.mark.parametrize(
    "subscription",
    [
        "dict[Literal['base','head'], Path]",
        "list[Path]",
        "tuple[Path, ...]",
        "dict[str, tuple[Path, ...]]",
        "builtins.dict[str, Path]",
        "Mapping[str, Path]",
    ],
)
def test_native_builtin_generic_read_is_not_a_class_escape(tmp_path, subscription):
    assert _stable(
        tmp_path,
        "import builtins\nfrom builtins import dict as Mapping\n"
        "from pathlib import Path\nfrom typing import Literal\n"
        f"houses: {subscription} = {{}}\n",
    )


@pytest.mark.parametrize(
    "change",
    [
        "dict=foreign.generic\nhouses: dict[str,Path]={}",
        "builtins.dict=foreign.generic\nhouses: dict[str,Path]={}",
        "builtins.dict=foreign.generic\nhouses: builtins.dict[str,Path]={}",
        "Path.__class_getitem__=foreign.generic\nhouses: list[Path]={}",
        "foreign.consume(dict[str,Path])",
        "alias=dict[str,Path]\nforeign.consume(alias)",
        "def export():\n    return dict[str,Path]",
        "foreign.consume(Path)",
    ],
)
def test_unknown_subscription_mutated_provider_and_generic_alias_escape_remain_visible(
    tmp_path, change
):
    assert not _stable(
        tmp_path, "import builtins, foreign\nfrom pathlib import Path\n" + change + "\n"
    )


@pytest.mark.parametrize(
    "patch",
    [
        "import builtins,foreign\nbuiltins.dict=foreign.generic\n",
        "import app,foreign\napp.dict=foreign.generic\n",
        "import app,foreign\napp.Mapping=foreign.generic\n",
    ],
)
def test_imported_provider_or_module_binding_patch_invalidates_generic_read(
    tmp_path, patch
):
    assert not _stable(
        tmp_path,
        "import patcher\nfrom pathlib import Path\n"
        "from builtins import dict as Mapping\n"
        "houses: dict[str,Path]={}\nother: Mapping[str,Path]={}\n",
        {"patcher.py": patch},
    )


def test_project_builtin_provider_cannot_supply_native_generic_semantics(tmp_path):
    assert not _stable(
        tmp_path,
        "import builtins\nfrom pathlib import Path\n"
        "houses: builtins.dict[str,Path]={}\n",
        {"builtins.py": "import foreign\ndict=foreign.generic\n"},
    )


def test_deep_operator_tree_with_provider_is_not_literal_scalar_data(tmp_path):
    expression = "(" * 40 + "foreign.value + Path" + " + 1)" * 40
    assert not _stable(
        tmp_path, "import foreign\nfrom pathlib import Path\nWIDTH=" + expression + "\n"
    )
