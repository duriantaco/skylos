import ast
import json
import sys
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.base import Visitor


pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12),
    reason="PEP 695 syntax requires Python 3.12+",
)


def _reference_names(code: str) -> set[str]:
    visitor = Visitor("sample", "sample.py")
    visitor.visit(ast.parse(code))
    return {name for name, _filename in visitor.refs}


def test_issue_641_class_bounds_keep_imports_live(tmp_path):
    (tmp_path / "contract.py").write_text(
        """
from typing import Protocol


class ParentClass[Inputs](Protocol):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "manager.py").write_text(
        """
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import NamedTuple
    from contract import ParentClass


class Manager[ParentType: ParentClass[NamedTuple]]:
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "manager_runtime.py").write_text(
        """
import os

from typing import NamedTuple
from contract import ParentClass


class Manager[ParentType: ParentClass[NamedTuple]]:
    pass


print(Manager.__type_params__[0].__bound__)
""",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    unused_imports = {
        (Path(item["file"]).name, item["simple_name"])
        for item in result.get("unused_imports", [])
    }

    issue_imports = {
        ("manager.py", "NamedTuple"),
        ("manager.py", "ParentClass"),
        ("manager_runtime.py", "NamedTuple"),
        ("manager_runtime.py", "ParentClass"),
    }
    assert unused_imports.isdisjoint(issue_imports)
    assert ("manager_runtime.py", "os") in unused_imports


def test_generic_function_bounds_and_annotations_use_their_own_type_params():
    refs = _reference_names(
        """
from bounds import AsyncBound, SyncBound
from external import T, U


def convert[T: SyncBound](value: T) -> T:
    return value


async def convert_async[U: AsyncBound](value: U) -> U:
    return value
"""
    )

    assert "bounds.SyncBound" in refs
    assert "bounds.AsyncBound" in refs
    assert "external.T" not in refs
    assert "external.U" not in refs


def test_generic_class_scope_shadows_imports_but_not_bound_names():
    refs = _reference_names(
        """
from bounds import GenericBase, ItemBound
from external import T


class Container[T: ItemBound](GenericBase[T]):
    item: T
"""
    )

    assert "bounds.ItemBound" in refs
    assert "bounds.GenericBase" in refs
    assert "external.T" not in refs


def test_generic_type_alias_scope_shadows_imports():
    refs = _reference_names(
        """
from bounds import AliasBound, Wrapper
from external import T


type Alias[T: AliasBound] = Wrapper[T]
"""
    )

    assert "bounds.AliasBound" in refs
    assert "bounds.Wrapper" in refs
    assert "external.T" not in refs


def test_generic_definition_defaults_and_decorators_use_outer_scope():
    refs = _reference_names(
        """
from external import ClassT, FunctionT


def decorate(value):
    return lambda target: target


@decorate(ClassT)
class Container[ClassT]:
    pass


def transform[FunctionT](value=FunctionT):
    return value
"""
    )

    assert "external.ClassT" in refs
    assert "external.FunctionT" in refs


def test_quoted_type_parameter_bound_is_an_annotation_reference():
    refs = _reference_names(
        """
from bounds import ForwardBound


class Container[T: "ForwardBound"]:
    pass
"""
    )

    assert "bounds.ForwardBound" in refs


def test_type_parameter_default_is_an_annotation_reference():
    if sys.version_info >= (3, 13):
        refs = _reference_names(
            """
from defaults import DefaultType


class Container[T = DefaultType]:
    pass
"""
        )
    else:
        tree = ast.parse(
            """
from defaults import DefaultType


class Container[T]:
    pass
"""
        )
        type_param = tree.body[1].type_params[0]
        type_param.default_value = ast.copy_location(
            ast.Name(id="DefaultType", ctx=ast.Load()),
            type_param,
        )

        visitor = Visitor("sample", "sample.py")
        visitor.visit(tree)
        refs = {name for name, _filename in visitor.refs}

    assert "defaults.DefaultType" in refs
